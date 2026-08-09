---
name: iec61850-network-load-monitor
description: Complete build spec for recreating the IEC 61850 Network Load Monitor — a Python tool that captures raw Ethernet frames, classifies substation-automation protocols (GOOSE/SV/R-GOOSE/PTP/MMS/DNP3/IEC104/Modbus), detects HSR/PRP redundancy and VLAN tagging, and reports live throughput/link-load in a CLI (rich) and a desktop GUI (Tkinter).
---

# IEC 61850 Network Load Monitor — recreation guide

This document is a self-contained spec for rebuilding this project from
scratch with any capable LLM/coding agent, without access to the original
repository. It captures the architecture, every byte-level parsing rule, the
CLI/GUI behavior, and the packaging steps. Follow it top to bottom; each
section has enough detail to implement independently.

## 1. What the tool does

A network-load/protocol analyser purpose-built for IEC 61850 substation
automation networks. It:

- Captures raw Ethernet frames on a NIC (or reads an existing `.pcap`/`.pcapng`
  file).
- Classifies each frame by protocol, VLAN tag(s), 802.1Q CoS/PCP, and
  HSR/PRP redundancy lane.
- For GOOSE / Sampled Values / R-GOOSE, decodes the application header
  (AppID, GOOSE-ID/SVID, stNum/noASDU, confRev, simulation flag) by hand-
  rolled ASN.1 BER parsing — no external ASN.1 library.
- For MMS / DNP3 / IEC104 / Modbus TCP (unicast, port-identified protocols),
  confirms the well-known port against the protocol's actual framing
  signature before classifying (a port match alone is not trusted).
- Aggregates everything else (ARP, LLDP, RSTP, NTP, IPv4/IPv6, R-SV, GSSE,
  unclassified) into a single "Other" row.
- Computes bits/second and percentage of a configurable link speed, in a
  rolling time window.
- Ships two independent front ends over one shared engine module: a
  terminal UI (`rich`) and a desktop UI (`tkinter`, stdlib only).
- Runs without root by falling back from a raw AF_PACKET socket to
  Wireshark's `dumpcap` helper.
- Packages to a single file per front end via PyInstaller — Windows `.exe`
  and Linux x86-64 binary — with no Python install required on the target
  machine.

License: GPL-2.0-only (forced by depending on `scapy`, which is GPL-2.0).

## 2. Project layout

```
monitor.py              # capture engine + protocol parser + CLI (rich)      ~1500 lines
monitor_gui.py           # Tkinter desktop UI, imports engine from monitor.py ~900 lines
requirements.txt         # scapy>=2.5.0 / rich>=13.0.0
network-monitor.spec     # PyInstaller spec for the CLI exe
network-monitor-gui.spec # PyInstaller spec for the GUI exe (console=False)
README.md
LICENSE                  # GPL-2.0-only
CHANGELOG.md
docs/screenshots/
test-captures/           # sample .pcapng files for manual testing
```

`monitor_gui.py` imports directly from `monitor.py`:
`LICENSE_NAME, PROTO_ORDER, SOFTWARE_NAME, __version__, _fmt_bits, _iter_pcap,
_list_interfaces, load_pcap_stats, parse_frame`. There is no separate
"library" package — the CLI module doubles as the shared engine, and the GUI
is a thin consumer of it. Keep this single-shared-module design: it avoids
duplicating the parser between front ends and keeps behavior identical.

## 3. Dependencies

- **scapy** (`>=2.5.0`) — used only for: `AsyncSniffer` (live raw-socket
  capture), `get_if_list()` / `get_windows_if_list()` (interface
  enumeration), and `PcapReader` (offline file reading). All actual protocol
  parsing is hand-written on raw `bytes`, deliberately bypassing scapy's own
  dissectors for speed and control.
- **rich** (`>=13.0.0`) — CLI table/panel/progress-bar rendering only, in
  `monitor.py`.
- **tkinter** — Python stdlib, used only by `monitor_gui.py` (`ttk.Treeview`
  for the results grid, `Toplevel` dialogs for pcap-load progress and
  Excel-style column filters). On Debian/Ubuntu this needs the OS package
  `python3-tk` (not installable via pip).
- Everything else (`argparse`, `socket`, `struct`, `threading`, `subprocess`,
  `csv`, `collections.defaultdict`) is stdlib.

`requirements.txt`:
```
scapy>=2.5.0
rich>=13.0.0
```

## 4. Constants: EtherTypes, ports, protocol tables

```python
ET_VLAN  = 0x8100   # IEEE 802.1Q
ET_QINQ  = 0x88A8   # 802.1ad QinQ
ET_GOOSE = 0x88B8   # IEC 61850-8-1 GOOSE
ET_SV    = 0x88BA   # IEC 61850-9-2 Sampled Values
ET_GSSE  = 0x88B9   # legacy GSSE (UCA 2.0)
ET_PTP   = 0x88F7   # IEEE 1588 PTP
ET_HSR   = 0x892F   # IEC 62439-3 HSR in-frame tag
ET_IPV4  = 0x0800
ET_IPV6  = 0x86DD
ET_ARP   = 0x0806
ET_LLDP  = 0x88CC
PRP_SUF  = 0x88FB   # PRP Redundancy Control Trailer suffix (last 2 bytes of frame)

PORT_MMS      = 102     # ISO/COTP-encapsulated MMS (RFC 1006) — IEC 61850-8-1
PORT_MODBUS   = 502     # Modbus TCP
PORT_IEC104   = 2404    # IEC 60870-5-104
PORT_DNP3     = 20000   # DNP3, TCP or UDP

L2_PROTO = {  # direct EtherType -> name, Layer-2 only
    ET_GOOSE: "GOOSE", ET_SV: "Sampled Values", ET_GSSE: "GSSE",
    ET_PTP: "PTP", ET_LLDP: "LLDP", ET_ARP: "ARP",
}

# Protocols that CAN get an individual detail row; everything else (and any
# of these when its flag is off) folds into "Other". Fixed display order.
FEATURED_PROTOS = frozenset({
    "GOOSE", "Sampled Values", "R-GOOSE", "PTP", "MMS", "DNP3", "IEC104", "Modbus TCP",
})
PROTO_ORDER = ["GOOSE", "Sampled Values", "R-GOOSE", "PTP", "MMS", "DNP3", "IEC104", "Modbus TCP"]
DISPLAY_ORDER = PROTO_ORDER + ["Other"]

LINK_MBPS = 100                              # default
LINK_BYTES_S = LINK_MBPS * 1_000_000 / 8     # bits->bytes/s
```

Version/about strings (used in `--version`, GUI About box, window title):
```python
SOFTWARE_NAME = "IEC 61850 Network Load Monitor"
__version__   = "0.0.5"
LICENSE_NAME  = "GPL-2.0-only"
```

## 5. Frame classification algorithm — `parse_frame(data: bytes) -> tuple`

Single entry point used by both live capture and pcap-file loading. Input is
the **raw Ethernet frame bytes** (from `bytes(scapy_packet)` or a raw pcap
record). Output is a 9-tuple:

```
(protocol_name, vlan_label, cos_label, redundancy_label,
 sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim)
```

`sv_*` fields are populated only for GOOSE/SV/R-GOOSE frames; `"-"` for
everything else. Reject frames shorter than 14 bytes (minimum Ethernet
header) up front — return an all-`"Other"`/`"-"` row for them.

Two small byte helpers used throughout:

```python
def _u16(data, off):
    return (data[off] << 8) | data[off + 1]

def _ber_len(data, off):
    """BER length octet(s): short form (<0x80) is the length itself;
    long form has high bit set, low 7 bits = number of following length
    bytes, big-endian. Returns (length, bytes_consumed)."""
    if off >= len(data): return 0, 0
    b = data[off]
    if b < 0x80: return b, 1
    n = b & 0x7F
    if off + 1 + n > len(data): return 0, 1 + n
    return int.from_bytes(data[off+1:off+1+n], "big"), 1 + n
```

Parsing sequence, starting at Ethernet offset 12 (past the two 6-byte MAC
addresses):

### 5.1 VLAN / QinQ tags (loop, not just once)

```
off = 12
etype = u16(data, off); off += 2
vlan_tags = []   # list of (vlan_id, pcp)
while etype in (0x8100, 0x88A8) and off + 4 <= len(data):
    pcp     = (data[off] >> 5) & 0x7          # top 3 bits of TCI
    vlan_id = ((data[off] & 0x0F) << 8) | data[off+1]   # low 12 bits
    vlan_tags.append((vlan_id, pcp))
    etype = u16(data, off + 2)                # embedded EtherType/next tag
    off  += 4
```
This naturally handles QinQ (two stacked tags) because it loops. Displayed
VLAN label = comma-joined vlan_ids; CoS label = comma-joined PCPs; `"-"` if
no tags.

### 5.2 HSR in-frame tag (IEC 62439-3 §5), EtherType `0x892F`

Only checked if the current `etype == 0x892F` after VLAN unwrapping. Layout
of the 6 bytes following EtherType:
```
2 bytes  Path(4-bit high nibble) + LSDUsize(12-bit low)
2 bytes  SeqNr
2 bytes  Embedded EtherType   <- the real inner protocol
```
```
if etype == 0x892F and off + 6 <= len(data):
    path  = (data[off] >> 4) & 0xF
    label = {0xA: "A", 0xB: "B"}.get(path, hex(path))
    redund = f"HSR-{label}"
    etype  = u16(data, off + 4)   # embedded EtherType
    off   += 6
```

### 5.3 PRP Redundancy Control Trailer (IEC 62439-3 §4)

PRP has no in-frame tag before the payload — instead a 6-byte trailer sits
at the **end** of the frame, only present when HSR wasn't already detected:
```
2 bytes  SeqNr
2 bytes  LanId(4-bit high nibble) + LSDUsize(12-bit low)
2 bytes  suffix = 0x88FB
```
```
if redund is None and len(data) >= 6 and u16(data, len(data)-2) == 0x88FB:
    lan_id = (data[-4] >> 4) & 0xF
    label  = {0xA: "A", 0xB: "B"}.get(lan_id, hex(lan_id))
    redund = f"PRP-{label}"
```
Note PRP does **not** change `etype`/`off` — the payload EtherType at this
point is whatever it already resolved to (PRP wraps a normal frame, it
doesn't nest a new EtherType the way HSR does).

### 5.4 Payload classification by final `etype`

```
if etype in L2_PROTO:
    proto = L2_PROTO[etype]
    if etype == 0x88BA: sv_* = _parse_sv_payload(data, off)
    elif etype == 0x88B8: sv_* = _parse_goose_payload(data, off)
elif etype == 0x0800:      # IPv4
    proto, app_off = _classify_ipv4(data, off)
    if proto == "R-GOOSE" and app_off >= 0:
        sv_* = _parse_rgoose_payload(data, app_off)
elif etype == 0x86DD:
    proto = "IPv6"
elif etype <= 1500:
    # IEEE 802.3 length field (not an EtherType). DSAP=SSAP=0x42 -> STP/RSTP/MSTP BPDU (LLC SAP).
    proto = "RSTP" if off+2<=len(data) and data[off]==0x42 and data[off+1]==0x42 else "Other"
else:
    proto = "Other"
```

### 5.5 GOOSE APDU parser — `_parse_goose_payload(data, off)`

8-byte APDU header at `off`:
```
[0-1] AppID   u16
[2-3] Length  u16 (unused beyond presence)
[4-5] Res1    bit15 of byte[off+4] = Simulation flag
[6-7] Res2    reserved
```
Then `goosePdu` as ASN.1 BER, tag `0x61` (APPLICATION 1):
```
80 <len> <str>   gocbRef [0] VisibleString   (fallback goID)
83 <len> <str>   goID    [3] VisibleString   (optional, preferred if present)
85 <len> <int>   stNum   [5] INTEGER
88 <len> <int>   confRev [8] INTEGER
```
Algorithm: verify byte at `off` (post 8-byte header) is `0x61`; consume its
BER length to get `end`; then loop `off` to `end` reading `tag = data[off]`,
`len,consumed = ber_len(data, off+1)`, extracting values for tags
`0x80/0x83/0x85/0x88` by decoding the value bytes as ASCII (strings) or
big-endian unsigned int (integers), advancing `off += 1 + consumed + len`
each iteration, ignoring unknown tags. Return
`(f"0x{appid:04X}", goid_or_gocbref_fallback, stnum, confrev, sim)`, all
`"-"` for any field not found, and all-`"-"` (except appid maybe present) if
the `0x61` tag check fails.

### 5.6 Sampled Values APDU parser — `_parse_sv_payload(data, off)`

Same 8-byte header shape as GOOSE (AppID, Length, Res1-with-sim-bit, Res2).
Then `savPdu` BER tag `0x60` (APPLICATION 0):
```
80 <len> <int>        noASDU    [0] IMPLICIT INTEGER
A2 <len>              seqOfAsdu [2]
  30 <len>            ASDU SEQUENCE (first ASDU only is inspected)
    80 <len> <str>    svID    [0] IMPLICIT VisibleString
    83 <len> <int>    confRev [3] IMPLICIT INTEGER
```
Walk the top level for tags `0x80` (noASDU, integer) and `0xA2`
(seqOfAsdu). Inside `0xA2`, if the first byte is `0x30` (SEQUENCE), step
into it and walk for `0x80` (svID string) and `0x83` (confRev int) — only
the first ASDU is decoded, matching how GOOSE/SV are used in the field
(single-ASDU is by far the common case; decoding every ASDU in a multi-ASDU
stream is out of scope). Return
`(f"0x{appid:04X}", svid, noasdu, confrev, sim)`.

### 5.7 R-GOOSE (routable GOOSE, IEC 61850-8-2) — inside IPv4/UDP

`_classify_ipv4(data, ip_off)` returns `(protocol_name, udp_payload_offset)`
(`-1` offset unless it's R-GOOSE/R-SV). Called only when the L2 etype is
IPv4. Details:

```python
def _classify_ipv4(data, ip_off):
    if ip_off + 20 > len(data): return "IPv4", -1
    frag_off = ((data[ip_off+6] & 0x1F) << 8) | data[ip_off+7]
    if frag_off != 0: return "IPv4", -1        # skip non-first fragments (no L4 header)
    ip_proto = data[ip_off+9]
    ihl      = (data[ip_off] & 0x0F) * 4       # IHL in 32-bit words -> bytes
    t_off    = ip_off + ihl
    dst1     = data[ip_off+16]                  # first octet of dest IP

    if ip_proto == 6 and t_off+4 <= len(data):  # TCP
        sport, dport = u16(data,t_off), u16(data,t_off+2)
        payload = b""
        if t_off+13 <= len(data):
            doff = (data[t_off+12] >> 4) & 0xF   # TCP data offset, 32-bit words
            if doff >= 5:
                payload = data[t_off + doff*4:]
        if 102   in (sport,dport) and _looks_like_mms(payload):     return "MMS", -1
        if 2404  in (sport,dport) and _looks_like_iec104(payload):  return "IEC104", -1
        if 502   in (sport,dport) and _looks_like_modbus(payload):  return "Modbus TCP", -1
        if 20000 in (sport,dport) and _looks_like_dnp3(payload):    return "DNP3", -1

    elif ip_proto == 17 and t_off+4 <= len(data):  # UDP
        sport, dport = u16(data,t_off), u16(data,t_off+2)
        if 123 in (sport,dport): return "NTP", -1
        if 20000 in (sport,dport) and _looks_like_dnp3(data[t_off+8:]): return "DNP3", -1
        multicast = (dst1 & 0xF0) == 0xE0     # 224.0.0.0/4
        if multicast:
            dst2 = data[ip_off+17]
            udp_payload_off = t_off + 8
            # heuristic sub-range split (site-configurable in real deployments):
            #   224.0.1.x -> R-GOOSE (IEC 61850-8-2), 224.0.2.x -> R-SV (IEC 61850-9-3)
            return ("R-SV" if dst2 >= 2 else "R-GOOSE"), udp_payload_off

    return "IPv4", -1
```

`_parse_rgoose_payload(data, udp_off)`: R-GOOSE wraps a `goosePdu` inside a
vendor-varying Session PDU header, so instead of a fixed offset, **scan** for
the `goosePdu` tag byte `0x61` within `udp_off+4 .. udp_off+128`, accepting a
candidate only if its BER length looks sane (`0 < pdu_len < 0x8000`) *and*
the very next byte is `0x80` (the gocbRef tag that always opens a goosePdu
body) — this rejects false-positive `0x61` bytes elsewhere in the session
header. AppID sits exactly 4 bytes before the accepted `0x61`. Once found,
walk the goosePdu body the same way as L2 GOOSE for tags `0x80`
(gocbRef), `0x83` (goID), `0x85` (stNum), `0x88` (confRev), plus one
R-GOOSE-specific addition: tag `0x87` = simulation `[7] BOOLEAN` (L2 GOOSE
instead reads sim from the Res1 header bit — R-GOOSE has no such header
field since its APDU header is only 4 bytes: AppID + Length, no
Reserved1/Reserved2). Default `sim = "no"` if tag `0x87` absent. Return
`(appid_hex, goid_or_gocbref, stnum, confrev, sim)`, or all-`"-"` if no
`0x61` candidate is found in the scan window.

### 5.8 Unicast SCADA protocol signature checks

Port match is only a *hint* — each is confirmed by parsing the payload's own
framing before trusting the port:

```python
def _looks_like_mms(payload):       # TPKT (RFC1006) header
    return len(payload) >= 4 and payload[0]==0x03 and payload[1]==0x00 and u16(payload,2) >= 4

def _looks_like_iec104(payload):    # IEC 60870-5-104 APCI
    return len(payload) >= 2 and payload[0]==0x68 and 4 <= payload[1] <= 253

def _looks_like_modbus(payload):    # Modbus MBAP header
    if len(payload) < 8: return False
    protocol_id = u16(payload,2); length = u16(payload,4); func_code = payload[7]
    return protocol_id == 0 and 2 <= length <= 253 and func_code != 0

def _looks_like_dnp3(payload):      # DNP3 data-link start bytes
    return len(payload) >= 3 and payload[0]==0x05 and payload[1]==0x64 and payload[2] >= 5
```

If the port matches but the signature check fails, the frame stays
classified as plain `"IPv4"` (folds into "Other") — never force-classified
by port alone.

## 6. Traffic filter (`FrameFilter` / `--vlan` `--redundancy` `--appid`
`--goid` `--svid`)

A predicate over four independent, all-optional constraints: `vlans`,
`redundancy`, `appids`, `svids` — each is either `None` (no constraint) or a
`frozenset` of allowed tokens. Within one field, values OR; across fields,
AND. Filtering happens **before counting** — non-matching frames never touch
packet/byte totals, the live table, or the session summary.

```python
class FrameFilter:
    __slots__ = ("vlans", "redundancy", "appids", "svids")
    def __init__(self, vlans=None, redundancy=None, appids=None, svids=None):
        self.vlans, self.redundancy, self.appids, self.svids = vlans, redundancy, appids, svids

    def is_empty(self):
        return not (self.vlans or self.redundancy or self.appids or self.svids)

    def matches(self, vlan, redund, appid, svid):
        if self.vlans is not None:
            tags = set(vlan.split(", ")) if vlan != "-" else set()
            if not tags & self.vlans: return False
        if self.redundancy is not None:
            if not _redundancy_tokens(redund) & self.redundancy: return False
        if self.appids is not None and appid not in self.appids: return False
        if self.svids is not None and svid.upper() not in self.svids: return False
        return True
```

`_redundancy_tokens("HSR-A") == {"hsr", "hsr-a"}`, `_redundancy_tokens("-")
== {"none"}` — this lets `--redundancy hsr` match either lane while
`--redundancy hsr-a` matches only lane A. Valid redundancy tokens:
`{hsr, prp, none, hsr-a, hsr-b, prp-a, prp-b}` — validate against this set
at parse time and `sys.exit()` with a clear message on anything else.

`--appid` values are parsed as hex (`int(v, 16)`, accepting with or without
`0x` prefix) and normalized to `f"0x{n:04X}"` for comparison against the
classifier's own `sv_appid` format. `--goid`/`--svid` both populate the same
`svids` set (OR'd) and are matched uppercased, since a frame is either
GOOSE or SV, never both, so filtering "this GOOSE ID or that SVID" on the
same column is unambiguous. `--vlan` matches against **any** tag in a
multi-tag (QinQ) stack, not just the outermost.

## 7. Capture backends

Try, in order:
1. **Raw AF_PACKET socket** — works if the process has root or
   `CAP_NET_RAW`. Detect by attempting to actually open one and catching the
   failure, not by checking `os.geteuid()==0` (capabilities can grant this
   without root):
   ```python
   def _has_raw_socket():
       try:
           s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
           s.close(); return True
       except (PermissionError, AttributeError, OSError):
           return False   # AttributeError: AF_PACKET doesn't exist on Windows at all
   ```
   If available, capture via `scapy.all.AsyncSniffer(iface=iface, prn=callback, store=False)`.
2. **`dumpcap`** (bundled with Wireshark) — works without root if the user is
   in the `wireshark` group (Linux) or Npcap's admin-only restriction is
   disabled (Windows). Locate it with `shutil.which("dumpcap")`, falling
   back on Windows to `%ProgramFiles%\Wireshark\dumpcap.exe`,
   `%ProgramFiles(x86)%\...`, `%ProgramW6432%\...`, and finally the registry
   keys `HKLM\SOFTWARE\Wireshark` / `HKLM\SOFTWARE\WOW6432Node\Wireshark`
   (`InstallDir` value), since the Wireshark installer does not add itself
   to `PATH` by default.
   Launch as a subprocess writing pcap to stdout:
   `dumpcap -i <iface> -w - -F pcap -q`, `stdout=PIPE, stderr=DEVNULL`.
   Read frames from the pipe with a hand-rolled pcap-record reader (§7.1) —
   **not** scapy's `PcapReader`, for performance (§7.1 explains why).
3. If neither is available: print a platform-specific actionable error and
   exit non-zero (don't silently do nothing). Windows message: install
   Wireshark, run elevated, or uncheck Npcap's admin-only restriction.
   Linux message: `sudo`, or install `wireshark-common` + join the
   `wireshark` group.

### 7.1 Fast pcap stream reader — bypass scapy for the dumpcap path

scapy's `PcapReader` builds a full `Packet` object per frame (~220 µs
overhead) even though the consumer immediately calls `bytes(pkt)` and
discards the object. Reading the raw pcap record format directly costs ~1 µs
per packet — a ~200× win, which matters at Sampled Values rates (thousands
of packets/sec). Implement a generator that:

1. Reads the 24-byte global pcap header once, checks the magic number to
   determine endianness and accept both microsecond and nanosecond variants:
   ```python
   _PCAP_LE = {0xa1b2c3d4, 0xa1b23c4d}   # little-endian: µs, ns
   _PCAP_BE = {0xd4c3b2a1, 0x4d3cb2a1}   # big-endian: µs, ns
   ```
   (dumpcap's own output is nanosecond pcap, magic `0xa1b23c4d`; the record
   layout is otherwise identical to classic pcap — only timestamp units
   differ, and timestamps are ignored entirely here.)
2. Loops reading the 16-byte per-record header (`ts_sec, ts_frac, incl_len,
   orig_len`, all `u32`), then reads exactly `incl_len` bytes of frame data,
   yielding it.
3. Uses `stream.read(n)` (a `BufferedReader`, guaranteed to return exactly
   `n` bytes across multiple internal syscalls if needed) rather than
   `readinto()` — required because dumpcap's stdout is a pipe, where a
   single read syscall can return a partial record header.
4. Stops cleanly (no exception) on short/EOF reads at any point.

The GUI's live-capture path reuses this exact same generator
(`_iter_pcap`), imported from `monitor.py` — do not reimplement it.

### 7.2 Batched lock-free accumulation

Both the CLI's dumpcap reader thread and the GUI's engine accumulate parsed
frames into **thread-local** dicts and only take the shared lock to merge a
batch, flushing after **200 packets or 100 ms**, whichever comes first
(`_PCAP_BATCH = 200`, `_PCAP_FLUSH_SEC = 0.10`). This keeps per-packet
overhead lock-free at high rates while bounding update latency at low
traffic rates (an idle network shouldn't have to wait 200 packets to see
anything move). The raw-socket path (`AsyncSniffer`'s `prn` callback) is
low-rate enough that it takes the lock per packet directly — no batching
needed there.

## 8. Rolling statistics model

Two-window design, shared across CLI and GUI (though each keeps its own
copy of the state — no cross-process sharing):

- `_cur`: accumulates the *live* window (`dict[protocol] -> dict[key] ->
  byte_count`), reset every rotation.
- `_disp`: a snapshot of the *last completed* window — what's actually
  rendered. This avoids the display racing a window that's still filling.
- `_session_stats`: cumulative totals for the **entire run**, never reset by
  rotation. Needed because at the moment a run ends, the just-current window
  may show zero traffic for a bursty protocol (MMS/DNP3/IEC104/Modbus can go
  quiet for 10-60s between exchanges) even though it carried plenty of
  traffic earlier — without this there'd be nothing to show in a final
  summary. Both the CLI (on Ctrl-C/duration timeout) and the GUI (on Stop)
  swap the displayed table to `_session_stats` for one final render once
  capture ends, labeled "session total (Ns)".
- `_last_active` / `_last_active_at`: the last **non-empty** window per
  protocol, plus its wall-clock time. Used so a sparse protocol's row stays
  visible between bursts (rendered dim/muted, bits/s forced to `0.000`,
  `%` column replaced with `idle {Ns}s`) instead of disappearing the instant
  its window is empty — disappearing would look identical to "never
  detected", which is misleading.

`key` for the inner dict is an 8-tuple:
`(vlan, cos, redund, appid, svid, noasdu, confrev, sim)` — i.e. every column
except protocol and the computed rate — so multiple distinct VLAN/AppID/etc
combinations of the *same* protocol get separate rows, each summing its own
byte count.

Window rotation (CLI: background thread sleeping `args.refresh` seconds;
GUI: `root.after(1000, ...)` tick) does, under lock:
```python
_disp = {p: dict(keys) for p, keys in _cur.items()}
_win_dur = max(now - _win_start, 0.001)
_win_start = now
_cur = defaultdict(lambda: defaultdict(int))
for p, keys in _disp.items():
    if keys:
        _last_active[p] = keys
        _last_active_at[p] = now
```

## 9. Offline pcap/pcapng loading — `load_pcap_stats(path, progress_cb, filt)`

Used by `--pcap FILE` (CLI) and "Open pcap/pcapng..." (GUI). Steps:

1. **Validate the file's magic bytes before doing anything else** — read the
   first 4 bytes and require one of the classic-pcap magics
   (`\xa1\xb2\xc3\xd4`, `\xd4\xc3\xb2\xa1`, `\xa1\xb2\x3c\x4d`,
   `\x4d\x3c\xb2\xa1`) or the pcapng magic (`\x0a\x0d\x0d\x0a`); raise
   `ValueError` otherwise. This is a deliberate security control, not just
   validation: without it, scapy's `PcapReader` would transparently inflate
   a gzip-wrapped file (magic `\x1f\x8b`) with no size cap, so a small
   malicious `.gz` given a `.pcap` extension could decompress into an
   effectively unbounded stream — a decompression-bomb vector. Plain
   pcap/pcapng have no such amplification (bytes read == bytes on disk), so
   rejecting anything else up front closes that path without limiting
   legitimate large captures. Check this on the file's real header, never
   on its extension or a file-picker's type filter — the GUI's "Capture
   files" filter is explicitly documented as a convenience only.
2. Read every frame with scapy's `PcapReader(path)` (this path can afford
   scapy's per-packet object overhead — offline loading isn't latency
   sensitive the way live capture is), classify with the same `parse_frame`,
   apply the same `FrameFilter` if given, and accumulate into a `StatsMap`.
3. Track `t_min`/`t_max` packet timestamps; the returned `duration_s = max(t_max
   - t_min, 0.001)` stands in for a live window's elapsed time when computing
   rates/percentages.
4. Call `progress_cb(pkts, total_bytes, percent)` every 2000 packets (`_PCAP_PROGRESS_EVERY`)
   and once more at the end with `percent=100.0`. `percent` is based on the
   reader's byte position in the file (`reader.f.tell() / file_size * 100`),
   not on decoded packet bytes — large files can take tens of seconds since
   scapy builds a `Packet` object per frame here.
5. Return `(stats, duration_s, packet_count, byte_count)`.

## 10. CLI (`monitor.py`, built on `rich`)

### 10.1 Argument surface (`argparse`)

```
monitor.py [interface] [-d/--duration SEC] [-s/--speed MBPS] [-r/--refresh SEC]
           [-l/--list] [-V/--version] [--pcap FILE]
           [--goose] [--sv] [--rgoose] [--ptp] [--mms] [--dnp3] [--iec104] [--modbus] [--all]
           [--vlan ID[,ID...]] [--redundancy VALUE[,VALUE...]]
           [--appid HEX[,HEX...]] [--goid ID[,ID...]] [--svid ID[,ID...]]
```
Defaults: `interface="eth0"`, `duration=10.0` (`0` = run forever),
`speed=100` Mb/s, `refresh=1.0` s. `--all` is exactly the union of all eight
per-protocol detail flags. Use `RawDescriptionHelpFormatter` with a long
`epilog` documenting protocol identification rules, table columns, capture
backends, filter semantics, and worked examples (the original's epilog runs
~90 lines — port it verbatim as documentation, it's load-bearing help text
for operators, not decorative).

### 10.2 Startup flow

1. Parse args, build the `FrameFilter`.
2. `--list`: enumerate interfaces and exit (see §10.4 for Windows label
   handling).
3. `--pcap FILE`: run `load_pcap_stats` inside a `rich.progress.Progress`
   bar (`Loading {name}` + bar + percent + `{pkts} packets ({size})`
   detail), print one static panel, exit — no live loop.
4. Otherwise: resolve the interface name/label to scapy's raw id, pick a
   capture backend (§7), print a one-line "Starting capture..." banner
   (interface, link speed, window size, duration, backend), start capture,
   start the window-rotation thread, install `SIGINT`/`SIGTERM` handlers
   that stop capture and exit cleanly, arm a `threading.Timer` for
   `--duration` if nonzero, then run a `rich.live.Live` loop redrawing the
   panel at `max(2.0, 2/refresh)` Hz until the capture backend reports
   `running == False` (either the duration timer fired, or Ctrl-C set the
   stop event). After the loop, do one final render swapped to
   `_session_stats` (§8) — this is the important "final numbers, not just
   whatever the last live window happened to hold" behavior; don't print a
   second table below it, replace the same panel in place.

### 10.3 Panel rendering (`_build_panel`)

A `rich.table.Table` (`box.SIMPLE_HEAVY`, expand=True) with columns:
`Protocol, VLAN, CoS, Redundancy, AppID, SVID/GOID, noASDU/stNum, confRev,
Sim, bits/s, %` (styles: cyan/yellow/blue/magenta/green/white/white/cyan/
white/white/white respectively; several `justify="center"` or `"right"`).
For each protocol in `PROTO_ORDER` that's in the `enabled` set: emit one row
per distinct key combination (sorted), color `Sim=yes` bold red, color
`Redundancy != "-"` bold magenta, color the `%` cell bold-red >70%,
bold-yellow >40%, else plain. If the protocol had >1 sub-row, add a `Sum
<protocol>` subtotal row. If a protocol is `enabled` but has zero rows in
`_disp` while present in `_last_active`, emit its last-known rows dimmed
with `bits/s=0.000` and `%` replaced by `idle {Ns}s` instead. Everything not
individually enabled sums into one `"Other"` row (only if its rate > 0).
Finish with a `table.add_section()` divider and a bold `TOTAL` row, colored
by the same 70%/40% thresholds. Panel title shows tool name, interface,
link speed, current clock time; subtitle/footer shows total packets, total
bytes, uptime `HH:MM:SS`, window duration in ms, and — if any filter is
active — a `filter <summary>` suffix from `FrameFilter.summary()`.

Byte/bit formatting: `_fmt_bytes` uses binary units (1024-based, B/KB/MB/GB/TB,
1 decimal); `_fmt_bits` uses SI units (1000-based, bit/s /Kbit/s /Mbit/s
/Gbit/s, **3** decimals — deliberately more precision than the byte
formatter since load percentages need it).

**Windows console note**: use plain ASCII only in any string that might
render on a Windows console — no `∑` (use `"Sum "` prefix), no `∞` (use
`"forever"`)/`"infinity"` text. Windows' legacy `cp1252` console codepage
can't encode those characters and `rich`'s Windows renderer crashes instead
of substituting a `?`. This bit the original project once; keep it fixed.

### 10.4 Interface enumeration

```python
def _list_interfaces():
    if sys.platform.startswith("win"):
        from scapy.arch.windows import get_windows_if_list
        # build label "<description> (<name>)" -> raw scapy id, since raw
        # Windows NPF device paths/GUIDs are unreadable to a human
    else:
        names = get_if_list()
        return names, {n: n for n in names}
```
`_resolve_iface(user_input, mapping)`: accept either the friendly label or
the raw scapy id; return `None` (→ print available interfaces and exit 1)
if neither matches.

## 11. GUI (`monitor_gui.py`, Tkinter/ttk)

Single-window app (`1480x540` default), `ttk.Style().theme_use("clam")`.
Structure top to bottom:

1. **Menu bar**: `Help → About` (message box with name/version/license).
2. **Toolbar row 1**: Interface combobox (readonly, populated from
   `_list_interfaces()`, widened to fit the longest label up to 70 chars),
   Link speed entry (Mb/s, default `100`), Duration entry (seconds, default
   `10`, `0 = ∞`), **▶ Start** / **■ Stop** buttons (Stop starts disabled),
   separator, **⬇ Export CSV** button.
3. **Toolbar row 2**: "Detail:" label + one `Checkbutton` per entry in
   `PROTO_ORDER` (unchecked by default — same semantics as the CLI's
   `--goose` etc, toggle re-renders immediately from the last snapshot, no
   waiting for the next tick), separator, **Open pcap/pcapng...** button,
   separator, **Clear Filters** button.
4. **Table**: `ttk.Treeview(columns=_COLS, show="headings", selectmode="none")`
   with the same 11 columns as the CLI. Row height computed from the actual
   font metrics (`font.metrics("linespace") + 8`) — the ttk default ignores
   font size and causes overlapping text otherwise. `Protocol` and
   `SVID/GOID` columns stretch to fill extra width; all others stay
   content-width. Two row tags only: `subtot` (grey `#888888`, used for both
   `Sum <proto>` rows and idle rows) and `total` (bold font); everything
   else is plain, undecorated text — no per-cell color coding in the GUI
   (unlike the CLI's rich colors).
5. **Status bar**: single-line label at the bottom, updated with backend
   name, packet/byte totals, and uptime while capturing, or the load result
   summary after opening a pcap file.

### 11.1 Excel-style column filters

Five columns get a clickable header filter: `Protocol, VLAN, Redundancy,
AppID, SVID/GOID`. Clicking the header opens a `Toplevel` positioned just
under it, containing a scrollable checklist of every distinct value seen so
far in that column this run (`_seen_values[col]`, grown on every redraw), a
"(Select All)" master checkbox, and OK/Clear/Cancel. State: `_col_filter[col]`
is `None` (no filter — show everything) or a `set` of allowed values. OK
sets it to `None` if every value is checked (equivalent to no filter, avoids
carrying a stale-looking "filtered" state that filters nothing) or to the
chosen subset otherwise; Clear resets to `None`; Cancel discards. Filtering
re-renders immediately from `self._last_snap` — it never waits for a new
capture tick, same principle as the Detail toggles. An active filter marks
its header with a trailing `" ▾"`. "Clear Filters" resets all five at once.
These filters apply **only to what's displayed** (post-hoc, on already-
captured in-memory data); they're a different mechanism from the CLI's
`--vlan`/`--redundancy`/`--appid`/`--goid`/`--svid` flags, which drop frames
*before* they're ever counted. The GUI does not expose the CLI's pre-count
filters at all — this asymmetry is intentional: the GUI's use case is
interactive post-hoc drill-down on an already-running/loaded capture, the
CLI's is scripted/unattended capture where dropping unwanted data early
saves memory and keeps output focused.

### 11.2 Capture engine (`_CaptureEngine`)

Mirrors the CLI's backend selection (§7) exactly, batched the same way
(§7.2, `_BATCH_PKTS=200`/`_BATCH_SEC=0.10`), but delivers batches to the UI
via a plain callback (`on_batch(list[(proto, key, size)])`) invoked from the
capture/reader thread — the callback takes `self._lock` and merges into
`self._cur`/`self._session_stats`, exactly mirroring `_flush_batch` in the
CLI. The UI's own `root.after(1000, self._refresh)` tick (not a separate
rotation thread — Tkinter must only be touched from the main thread) reads
and rotates `_cur` under lock, then calls `_redraw`.

On Stop: cancel the duration timer and the refresh `after` callback, call
`engine.stop()` (terminates the dumpcap subprocess or stops the
`AsyncSniffer`), then poll every 100ms up to 50 tries (~5s) via
`_await_drain` waiting for `engine.running` to go `False` before showing the
final session-summary render — same rationale as the CLI's final swap to
`_session_stats`: dumpcap buffers, so a burst captured moments ago may still
be in flight through the pipe, and redrawing immediately on Stop would
under-report it. The 50-try bound exists so a backend that fails to exit
can't hang the UI forever.

### 11.3 Offline pcap loading

"Open pcap/pcapng..." → `filedialog.askopenfilename` (filter
`*.pcap *.pcapng *.cap`, but see §9 — the real gate is the magic-byte check
inside `load_pcap_stats`, not this extension filter) → stops any running
live capture first → spawns a **background thread** running
`load_pcap_stats(path, on_progress)` (must not block the Tk main loop for a
large file) → progress callbacks marshal back onto the main thread via
`root.after(0, ...)` to update a modal `_PcapLoadDialog` (a `Toplevel` with
a determinate `ttk.Progressbar` + `"{pct}%  {pkts} packets ({size})"` label,
`grab_set()` so it's modal, close button disabled while loading) → on
completion, close the dialog, redraw the table from the loaded stats, and
set the status bar to a one-line summary (packets, total bytes, duration).

### 11.4 CSV export

Read every currently-visible `Treeview` row's `values` back out (so export
respects whatever Detail/column filters are currently applied — it exports
what's on screen, not the raw underlying stats) into `csv.DictWriter` with
the same 11 column headers, default filename
`network_monitor_{YYYYMMDD_HHMMSS}.csv`. Empty table → info dialog, no file
dialog.

### 11.5 Column auto-fit

After every redraw, resize every column to `max(header_width, widest_cell_width)
+ 20px` using `tkfont.Font.measure()` — keeps columns readable without manual
resizing as content changes (AppID/SVID values, idle labels, etc, vary a lot
in width).

### 11.6 Windows `--noconsole` build safety

Install `root.report_callback_exception` to show unhandled Tkinter-callback
exceptions in a `messagebox.showerror` with the full traceback
(`traceback.format_exception`). This matters specifically because the
Windows GUI binary is built with `--noconsole` (§12) — there is no stderr
for Tk's default exception handler to write to, so without this override a
bug in any button/callback would silently do nothing instead of surfacing
an error.

## 12. Packaging (PyInstaller)

Two one-file builds per platform, same dependency bundling throughout. The
Windows builds come from a Windows Python environment (or via Wine
cross-build on Linux, as the original project does):

```
pyinstaller --onefile --name network-monitor --collect-all scapy --collect-all rich ^
    --hidden-import scapy.layers.all --hidden-import scapy.contrib.all monitor.py

pyinstaller --onefile --name network-monitor-gui --noconsole --collect-all scapy --collect-all rich ^
    --hidden-import scapy.layers.all --hidden-import scapy.contrib.all monitor_gui.py
```

`--collect-all scapy`/`rich` is required because both pull in data files /
plugins PyInstaller's default import scanner won't discover on its own; the
two `--hidden-import`s cover scapy's dynamically-loaded layer/contrib
modules specifically. The GUI build adds `--noconsole` (no terminal window)
— see §11.6 for why that requires the Tk exception-handler override. Commit
the generated `.spec` files (`network-monitor.spec`,
`network-monitor-gui.spec`) so rebuilds are reproducible without
re-deriving the PyInstaller flags; they're plain Python (`Analysis`/`PYZ`/
`EXE`) using `PyInstaller.utils.hooks.collect_all('scapy')` and
`collect_all('rich')` to populate `datas`/`binaries`/`hiddenimports`, with
`console=True` for the CLI spec and `console=False` for the GUI spec —
otherwise identical.

Runtime capture-driver requirement on the target Windows machine regardless
of which exe: Wireshark (bundles **Npcap**) must be installed, and either
run the exe elevated or uncheck Npcap's "Restrict Npcap driver's access to
Administrators only" during its install/reconfigure.

### 12.1 Linux builds and the glibc constraint

The Linux builds run the *same two spec files* — nothing platform-specific
in them — but **must not** be built on the developer's own distribution.
PyInstaller does not bundle glibc: the frozen binary dynamically links
against whatever glibc the build machine has, and glibc guarantees only
backwards compatibility. A binary built on glibc 2.42 therefore aborts at
startup on a glibc 2.36 machine with `GLIBC_2.4x not found`, while the
reverse works fine. The rule is to build against the **oldest** glibc you
intend to support, which then covers every newer target for free — not to
build on the newest and hope.

The original project pins this to a `debian:12` container (glibc 2.36),
driven by `build-linux.sh`, which covers Debian 12, Ubuntu 24.04 (glibc
2.39) and anything newer. The container needs `python3-tk` present at
*build* time or PyInstaller silently omits tkinter and the GUI binary dies
on launch; `binutils` supplies the `objdump` PyInstaller uses to scan
shared-library dependencies. Debian's system Python is externally managed,
so the build installs into a venv. Verify a build by checking no symbol
exceeds the baseline (`objdump -T <binary> | grep -o 'GLIBC_[0-9.]*' | sort
-uV | tail -1`) — these come out at `GLIBC_2.14`.

Two runtime notes specific to the Linux binaries, both of which look like
build defects and are not:

- **The GUI does not bundle fonts.** Tk uses the system's fonts, so on a
  minimal image with no font package installed it fails at startup with
  `failed to allocate font due to internal system font engine problem`.
  Installing any font package (e.g. `fonts-dejavu-core`) resolves it; real
  desktop installs already have one.
- **No Npcap equivalent is needed.** Live capture uses the raw AF_PACKET
  socket, so it needs root or `CAP_NET_RAW` on the binary, falling back to
  `dumpcap` for users in the `wireshark` group (§ the backend fallback
  above). Offline `--pcap` parsing needs no privileges.

PyInstaller embeds build timestamps, so builds are not byte-reproducible;
publish the hash of the artifact you actually ship rather than treating it
as a property of the source.

## 13. Licensing

GPL-2.0-only for the whole project, **because** it directly imports and
redistributes `scapy` (itself GPL-2.0-only) — this is not a free choice,
it's inherited. `rich` (MIT) and its transitive deps (`Pygments`
BSD-2-Clause, `markdown-it-py`/`mdurl` MIT) impose no extra restriction.
PyInstaller's bootloader is GPL-2.0-or-later but carries an explicit
bootloader exception permitting proprietary-looking compiled output — cite
this if asked why a GPL build tool doesn't force the *output* binary itself
to be redistributed with source, separately from the scapy inheritance
which does apply here regardless. Document this reasoning in the README (a
"Third-party licenses" table mapping each dependency to license/role) so
downstream users understand *why* GPL applies rather than just seeing a
LICENSE file.

## 14. Suggested build order for a from-scratch recreation

1. `parse_frame` and its helpers (§5) — pure functions, unit-testable
   against hand-crafted byte strings without any capture backend at all.
   Get GOOSE/SV/HSR/PRP/VLAN parsing correct first; this is the part with
   the most protocol-spec detail and the highest cost of getting subtly
   wrong.
2. `FrameFilter` (§6) and `load_pcap_stats` (§9) — lets you validate the
   parser end-to-end against real `.pcap`/`.pcapng` fixtures (capture some
   with Wireshark, or use any publicly available IEC 61850 sample captures)
   before writing any live-capture or UI code at all.
3. Capture backends (§7) and the rolling-window stats model (§8) — the
   concurrency-sensitive part; test under real or synthetic traffic at a
   realistic Sampled Values rate (thousands of pkt/s) to validate the
   batching/locking design actually keeps up.
4. CLI (`rich`) front end (§10).
5. GUI (`tkinter`) front end (§11), importing the engine module rather than
   duplicating any of it.
6. PyInstaller packaging (§12) last, once both front ends work from source.

## 15. Testing notes

There is no automated test suite in the original project — verification was
manual, against real `.pcap`/`.pcapng` captures (kept in `test-captures/` in
the original repo) run through `--pcap` and eyeballed against Wireshark's
own dissection of the same file for ground truth on AppID/goID/stNum/confRev
values. If recreating this with test coverage in mind, prioritize: (a) unit
tests for `parse_frame` against hand-built byte sequences covering each
EtherType/HSR/PRP/VLAN/QinQ combination and malformed/truncated inputs
(BER length parsing in particular has several off-by-one edge cases around
truncated buffers — `_ber_len`, and every `off + ln <= len(data)` guard in
the GOOSE/SV/R-GOOSE walkers, exist specifically to never index past the
end of a short/corrupt frame); (b) an integration test loading a known
sample `.pcap` through `load_pcap_stats` and asserting exact packet/byte
counts per protocol.
