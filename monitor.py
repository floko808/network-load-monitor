#!/usr/bin/env python3
"""
IEC 61850 Network Load Monitor
-------------------------------
Captures raw Ethernet frames on a network interface and classifies
traffic by protocol, VLAN, and redundancy scheme (HSR/PRP).

Supported protocols
  Detailed rows     : GOOSE (0x88B8), Sampled Values (0x88BA), PTP/IEEE-1588
                      (0x88F7), R-GOOSE (UDP multicast) — off by default,
                      see --goose/--sv/--rgoose/--ptp
  Redundancy        : HSR – IEC 62439-3 (EtherType 0x892F in-frame tag)
                      PRP – IEC 62439-3 (RCT trailer, last 2 bytes 0x88FB)
  VLAN              : IEEE 802.1Q (0x8100), QinQ (0x88A8)
  Other (aggregated): GSSE, MMS, NTP, R-SV, LLDP, RSTP, ARP, IPv4, IPv6,
                      unclassified

Load percentage is calculated against a configurable link speed
(default 100 Mb/s).

Capture backends (tried in order):
  1. Raw socket  – requires root or CAP_NET_RAW
  2. dumpcap     – no root needed if user is in the 'wireshark' group

Usage
  python3 monitor.py [INTERFACE] [--speed MBPS] [--refresh SEC]
  sudo python3 monitor.py [INTERFACE] ...   # always works
"""

import argparse
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable, Dict, Iterator, List, Optional, Tuple

# ── dependency check ─────────────────────────────────────────────────────────
try:
    from scapy.all import AsyncSniffer, get_if_list
    from scapy.utils import PcapReader
except ImportError:
    sys.exit("scapy not found – install with:  pip install scapy")

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    sys.exit("rich not found – install with:  pip install rich")


# ── network interfaces ───────────────────────────────────────────────────────

def _list_interfaces() -> Tuple[List[str], Dict[str, str]]:
    """Return (display labels, label -> scapy interface id).

    On Windows, scapy's raw interface identifiers are unreadable (NPF device
    paths / GUIDs), so pair each with its NIC description via
    get_windows_if_list() for a label the user can actually recognize.
    """
    if sys.platform.startswith("win"):
        try:
            from scapy.arch.windows import get_windows_if_list

            labels: List[str] = []
            mapping: Dict[str, str] = {}
            for entry in get_windows_if_list():
                name = entry.get("name") or ""
                desc = entry.get("description") or name
                if not name and not desc:
                    continue
                label = f"{desc} ({name})" if desc and name and desc != name else (desc or name)
                labels.append(label)
                mapping[label] = name or desc
            if labels:
                return labels, mapping
        except Exception:
            pass
    try:
        names = get_if_list()
    except Exception:
        names = []
    return names, {n: n for n in names}


def _resolve_iface(name: str, mapping: Dict[str, str]) -> Optional[str]:
    """Resolve a user-supplied interface — either a friendly label or the raw
    scapy id — to the raw id scapy/dumpcap actually need. Returns None if it
    matches neither."""
    if name in mapping:
        return mapping[name]
    if name in mapping.values():
        return name
    return None


# ── about / version ───────────────────────────────────────────────────────────
SOFTWARE_NAME = "IEC 61850 Network Load Monitor"
__version__   = "0.0.1"
LICENSE_NAME  = "GPL-2.0-only"


# ── EtherType / protocol constants ───────────────────────────────────────────
ET_VLAN  = 0x8100
ET_QINQ  = 0x88A8
ET_GOOSE = 0x88B8
ET_SV    = 0x88BA
ET_GSSE  = 0x88B9
ET_PTP   = 0x88F7
ET_HSR   = 0x892F   # IEC 62439-3 HSR tag
ET_IPV4  = 0x0800
ET_IPV6  = 0x86DD
ET_ARP   = 0x0806
ET_LLDP  = 0x88CC
PRP_SUF  = 0x88FB   # PRP Redundancy Control Trailer suffix

# Direct EtherType → protocol name mapping (Layer-2 only)
L2_PROTO: Dict[int, str] = {
    ET_GOOSE: "GOOSE",
    ET_SV:    "Sampled Values",
    ET_GSSE:  "GSSE",
    ET_PTP:   "PTP",
    ET_LLDP:  "LLDP",
    ET_ARP:   "ARP",
}

# Protocols that CAN be shown individually in the table; all others (and any of
# these not currently enabled — see --goose/--sv/--rgoose/--ptp) are aggregated
# as "Other". Fixed display order for the detailed rows.
FEATURED_PROTOS: frozenset = frozenset({"GOOSE", "Sampled Values", "R-GOOSE", "PTP"})
PROTO_ORDER: List[str] = ["GOOSE", "Sampled Values", "R-GOOSE", "PTP"]
DISPLAY_ORDER: List[str] = ["GOOSE", "Sampled Values", "R-GOOSE", "PTP", "Other"]

# Default link speed
LINK_MBPS: int    = 100
LINK_BYTES_S: float = LINK_MBPS * 1_000_000 / 8   # 12 500 000 B/s


# ── frame parser ─────────────────────────────────────────────────────────────

def _u16(data: bytes, off: int) -> int:
    return (data[off] << 8) | data[off + 1]


def _ber_len(data: bytes, off: int) -> Tuple[int, int]:
    """Parse a BER-encoded length field. Returns (length, bytes_consumed)."""
    if off >= len(data):
        return 0, 0
    b = data[off]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    if off + 1 + n > len(data):
        return 0, 1 + n
    return int.from_bytes(data[off + 1: off + 1 + n], "big"), 1 + n


def _parse_sv_payload(data: bytes, off: int) -> Tuple[str, str, str, str, str]:
    """
    Decode an IEC 61850-9-2 SV APDU starting at *off*.
    Returns (appid_hex, svid, noasdu_str, confrev_str, sim_str).

    APDU header layout (8 bytes):
      [0-1] AppID   – stream identifier
      [2-3] Length  – total APDU length
      [4-5] Res1    – bit 15 = Simulation flag (IEC 61850-9-2 §A.3)
      [6-7] Res2    – reserved, 0x0000
    Followed by savPdu encoded as ASN.1 BER:
      60 <len>                savPdu  [APPLICATION 0]
        80 <len> <int>        noASDU  [0] IMPLICIT INTEGER
        A2 <len>              seqOfAsdu [2]
          30 <len>            ASDU SEQUENCE
            80 <len> <str>    svID    [0] IMPLICIT VisibleString
            83 <len> <int>    confRev [3] IMPLICIT INTEGER
    """
    if off + 8 > len(data):
        return "-", "-", "-", "-", "-"
    appid = _u16(data, off)
    sim   = "yes" if (data[off + 4] & 0x80) else "no"
    off  += 8   # past AppID + Length + Res1 + Res2

    if off >= len(data) or data[off] != 0x60:   # savPdu tag
        return f"0x{appid:04X}", "-", "-", "-", sim
    off += 1
    pdu_len, c = _ber_len(data, off); off += c
    end = min(off + pdu_len, len(data))

    noasdu  = "-"
    svid    = "-"
    confrev = "-"
    while off < end:
        if off >= len(data):
            break
        tag = data[off]; off += 1
        ln, c = _ber_len(data, off); off += c

        if tag == 0x80:   # noASDU [0] IMPLICIT INTEGER
            if off + ln <= len(data):
                noasdu = str(int.from_bytes(data[off: off + ln], "big"))

        elif tag == 0xA2:  # seqOfAsdu [2] – walk first ASDU for svID and confRev
            a = off
            a_end = min(off + ln, len(data))
            if a < a_end and data[a] == 0x30:
                a += 1
                a_ln, a_c = _ber_len(data, a); a += a_c
                asdu_end = min(a + a_ln, a_end)
                while a < asdu_end:
                    if a >= len(data):
                        break
                    a_tag = data[a]; a += 1
                    a_vl, a_c = _ber_len(data, a); a += a_c
                    if a_tag == 0x80:   # svID [0] IMPLICIT VisibleString
                        if a + a_vl <= len(data):
                            svid = data[a: a + a_vl].decode("ascii", errors="replace")
                    elif a_tag == 0x83:  # confRev [3] IMPLICIT INTEGER
                        if a + a_vl <= len(data):
                            confrev = str(int.from_bytes(data[a: a + a_vl], "big"))
                    a += a_vl

        off += ln

    return f"0x{appid:04X}", svid, noasdu, confrev, sim


def _parse_goose_payload(data: bytes, off: int) -> Tuple[str, str, str, str, str]:
    """
    Decode an IEC 61850-8-1 GOOSE APDU starting at *off*.
    Returns (appid_hex, goid, stnum_str, confrev_str, sim_str).

    APDU header layout (8 bytes):
      [0-1] AppID   – stream identifier
      [2-3] Length  – total APDU length
      [4-5] Res1    – bit 15 = Simulation flag
      [6-7] Res2    – reserved, 0x0000
    Followed by goosePdu encoded as ASN.1 BER:
      61 <len>              goosePdu [APPLICATION 1]
        80 <len> <str>      gocbRef  [0] VisibleString  (fallback for goID)
        83 <len> <str>      goID     [3] VisibleString  (optional)
        85 <len> <int>      stNum    [5] INTEGER
        88 <len> <int>      confRev  [8] INTEGER
    """
    if off + 8 > len(data):
        return "-", "-", "-", "-", "-"
    appid = _u16(data, off)
    sim   = "yes" if (data[off + 4] & 0x80) else "no"
    off  += 8   # past AppID + Length + Res1 + Res2

    if off >= len(data) or data[off] != 0x61:   # goosePdu tag
        return f"0x{appid:04X}", "-", "-", "-", sim
    off += 1
    pdu_len, c = _ber_len(data, off); off += c
    end = min(off + pdu_len, len(data))

    gocbref = "-"
    goid    = "-"
    stnum   = "-"
    confrev = "-"
    while off < end:
        if off >= len(data):
            break
        tag = data[off]; off += 1
        ln, c = _ber_len(data, off); off += c

        if tag == 0x80:   # gocbRef [0] VisibleString — used as fallback if goID absent
            if off + ln <= len(data):
                gocbref = data[off: off + ln].decode("ascii", errors="replace")
        elif tag == 0x83:  # goID [3] VisibleString
            if off + ln <= len(data):
                goid = data[off: off + ln].decode("ascii", errors="replace")
        elif tag == 0x85:  # stNum [5] INTEGER
            if off + ln <= len(data):
                stnum = str(int.from_bytes(data[off: off + ln], "big"))
        elif tag == 0x88:  # confRev [8] INTEGER
            if off + ln <= len(data):
                confrev = str(int.from_bytes(data[off: off + ln], "big"))

        off += ln

    # goID is optional; fall back to gocbRef so the cell is never empty
    return f"0x{appid:04X}", (goid if goid != "-" else gocbref), stnum, confrev, sim


def parse_frame(data: bytes) -> Tuple[str, str, str, str, str, str, str, str, str]:
    """
    Classify a raw Ethernet frame.
    Returns (protocol_name, vlan_label, cos_label, redundancy_label,
             sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim).

    sv_* fields are populated only for Sampled Values frames; '-' otherwise.
    CoS is the 3-bit PCP (Priority Code Point) field from the 802.1Q TCI.
    For QinQ frames, both PCPs are reported as "outer/inner".
    """
    if len(data) < 14:
        return "Other", "-", "-", "-", "-", "-", "-", "-", "-"

    off   = 12
    etype = _u16(data, off);  off += 2
    vlan_tags: List[Tuple[int, int]] = []   # (vlan_id, pcp)
    redund: str | None = None

    # ── 802.1Q / QinQ VLAN tags ──────────────────────────────────────────
    # TCI byte layout:  [PCP(3b) | DEI(1b) | VID-high(4b)] [VID-low(8b)]
    while etype in (ET_VLAN, ET_QINQ) and off + 4 <= len(data):
        pcp     = (data[off] >> 5) & 0x7
        vlan_id = ((data[off] & 0x0F) << 8) | data[off + 1]
        vlan_tags.append((vlan_id, pcp))
        etype = _u16(data, off + 2)
        off  += 4

    # ── HSR in-frame tag (IEC 62439-3 §5) ───────────────────────────────
    # Layout of the 6 bytes after EtherType 0x892F:
    #   2 bytes  Path (4-bit high nibble) + LSDUsize (12-bit low)
    #   2 bytes  SeqNr
    #   2 bytes  Embedded EtherType  ← actual protocol
    # Path nibble: 0xA = LAN A, 0xB = LAN B
    if etype == ET_HSR and off + 6 <= len(data):
        path  = (data[off] >> 4) & 0xF
        label = {0xA: "A", 0xB: "B"}.get(path, hex(path))
        redund = f"HSR-{label}"
        etype  = _u16(data, off + 4)
        off   += 6

    # ── PRP Redundancy Control Trailer (IEC 62439-3 §4) ──────────────────
    # The 6-byte RCT sits at the end of the frame:
    #   2 bytes  SeqNr
    #   2 bytes  LanId (4-bit high nibble) + LSDUsize (12-bit low)
    #   2 bytes  PRP_SUF = 0x88FB
    # LanId nibble: 0xA = LAN A, 0xB = LAN B
    if redund is None and len(data) >= 6 and _u16(data, len(data) - 2) == PRP_SUF:
        lan_id = (data[-4] >> 4) & 0xF
        label  = {0xA: "A", 0xB: "B"}.get(lan_id, hex(lan_id))
        redund = f"PRP-{label}"

    # ── classify payload ─────────────────────────────────────────────────
    sv_appid = sv_svid = sv_noasdu = sv_confrev = sv_sim = "-"
    if etype in L2_PROTO:
        proto = L2_PROTO[etype]
        if etype == ET_SV:
            sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim = _parse_sv_payload(data, off)
        elif etype == ET_GOOSE:
            sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim = _parse_goose_payload(data, off)
    elif etype == ET_IPV4:
        proto, app_off = _classify_ipv4(data, off)
        if proto == "R-GOOSE" and app_off >= 0:
            sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim = _parse_rgoose_payload(data, app_off)
    elif etype == ET_IPV6:
        proto = "IPv6"
    elif etype <= 1500:
        # IEEE 802.3 frame — etype is the length field, not an EtherType.
        # DSAP=0x42/SSAP=0x42 is the LLC SAP for STP/RSTP/MSTP BPDUs.
        proto = "RSTP" if off + 2 <= len(data) and data[off] == 0x42 and data[off + 1] == 0x42 else "Other"
    else:
        proto = "Other"

    vlan_label = ", ".join(str(v)   for v, _ in vlan_tags) if vlan_tags else "-"
    cos_label  = ", ".join(str(pcp) for _, pcp in vlan_tags) if vlan_tags else "-"
    return proto, vlan_label, cos_label, redund or "-", sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim


def _classify_ipv4(data: bytes, ip_off: int) -> Tuple[str, int]:
    """
    Identify MMS, NTP, R-GOOSE, R-SV inside an IPv4 packet.
    Returns (protocol_name, udp_payload_offset).
    udp_payload_offset is the byte offset to the UDP payload; -1 otherwise.
    """
    if ip_off + 20 > len(data):
        return "IPv4", -1

    # Non-first fragments carry no transport header — skip them.
    frag_off = ((data[ip_off + 6] & 0x1F) << 8) | data[ip_off + 7]
    if frag_off != 0:
        return "IPv4", -1

    ip_proto  = data[ip_off + 9]
    ihl       = (data[ip_off] & 0x0F) * 4
    t_off     = ip_off + ihl
    dst1      = data[ip_off + 16]   # first byte of destination IP

    if ip_proto == 6 and t_off + 4 <= len(data):           # TCP
        sport = _u16(data, t_off)
        dport = _u16(data, t_off + 2)
        if 102 in (sport, dport):
            return "MMS", -1    # ISO/COTP-encapsulated MMS (RFC 1006)

    elif ip_proto == 17 and t_off + 4 <= len(data):        # UDP
        sport = _u16(data, t_off)
        dport = _u16(data, t_off + 2)
        if 123 in (sport, dport):
            return "NTP", -1    # Network Time Protocol (RFC 5905)

        multicast = (dst1 & 0xF0) == 0xE0  # 224.0.0.0/4
        if multicast:
            # Heuristic split based on IP multicast sub-group:
            #   IEC 61850-8-2 R-GOOSE uses 224.0.1.x range
            #   IEC 61850-9-3 R-SV    uses 224.0.2.x range
            # (configurable in practice; adjust ranges to site config)
            dst2            = data[ip_off + 17]
            udp_payload_off = t_off + 8   # skip 8-byte UDP header
            return ("R-SV" if dst2 >= 2 else "R-GOOSE"), udp_payload_off

    return "IPv4", -1


def _parse_rgoose_payload(data: bytes, udp_off: int) -> Tuple[str, str, str, str, str]:
    """
    Parse an IEC 61850-8-2 R-GOOSE UDP payload.
    Returns (appid_hex, goid, stnum_str, confrev_str, sim_str).

    R-GOOSE wraps the goosePdu inside a Session PDU whose header size varies
    by implementation. We locate the goosePdu tag (0x61) by scanning and
    validating that its BER body opens with the gocbRef tag (0x80).

    The R-GOOSE APDU header preceding the goosePdu is only 4 bytes:
      AppID  (2 bytes)   ← 4 bytes before 0x61
      Length (2 bytes)   ← 2 bytes before 0x61
    There is no Reserved1/Reserved2 (unlike L2 GOOSE). The simulation flag
    is read from goosePdu field [7] BOOLEAN (tag 0x87) instead.
    """
    if udp_off + 5 > len(data):
        return "-", "-", "-", "-", "-"

    # Locate the goosePdu tag 0x61 with structural validation
    limit = min(udp_off + 128, len(data))
    pdu_off = -1
    for i in range(udp_off + 4, limit):
        if data[i] != 0x61:
            continue
        pdu_len, c = _ber_len(data, i + 1)
        inner = i + 1 + c
        if inner < len(data) and data[inner] == 0x80 and 0 < pdu_len < 0x8000:
            pdu_off = i
            break

    if pdu_off < 0 or pdu_off - 4 < udp_off:
        return "-", "-", "-", "-", "-"

    # AppID is exactly 4 bytes before the goosePdu tag
    appid = _u16(data, pdu_off - 4)

    # Walk the goosePdu body
    off = pdu_off + 1
    pdu_len, c = _ber_len(data, off); off += c
    end = min(off + pdu_len, len(data))

    gocbref = "-"
    goid    = "-"
    stnum   = "-"
    confrev = "-"
    sim     = "no"
    while off < end:
        if off >= len(data):
            break
        tag = data[off]; off += 1
        ln, c = _ber_len(data, off); off += c

        if tag == 0x80:    # gocbRef [0] VisibleString
            if off + ln <= len(data):
                gocbref = data[off: off + ln].decode("ascii", errors="replace")
        elif tag == 0x83:  # goID [3] VisibleString
            if off + ln <= len(data):
                goid = data[off: off + ln].decode("ascii", errors="replace")
        elif tag == 0x85:  # stNum [5] INTEGER
            if off + ln <= len(data):
                stnum = str(int.from_bytes(data[off: off + ln], "big"))
        elif tag == 0x87:  # simulation [7] BOOLEAN
            if off + ln <= len(data) and ln >= 1:
                sim = "yes" if data[off] != 0x00 else "no"
        elif tag == 0x88:  # confRev [8] INTEGER
            if off + ln <= len(data):
                confrev = str(int.from_bytes(data[off: off + ln], "big"))

        off += ln

    return f"0x{appid:04X}", (goid if goid != "-" else gocbref), stnum, confrev, sim


# ── fast pcap stream reader ───────────────────────────────────────────────────
# Replaces scapy's PcapReader for the dumpcap path.
# scapy creates a Python object per frame (≈220 µs overhead) even though we
# immediately call bytes(pkt) and discard the object.  Reading the raw pcap
# record directly costs ≈1 µs/pkt — a 200× improvement at high packet rates.
#
# dumpcap emits nanosecond-resolution pcap (magic 0xa1b23c4d / 0x4d3cb2a1).
# The on-wire record layout is identical to standard pcap; only the timestamp
# units differ (we ignore timestamps entirely).

_PCAP_LE = {0xa1b2c3d4, 0xa1b23c4d}   # little-endian µs and ns magic
_PCAP_BE = {0xd4c3b2a1, 0x4d3cb2a1}   # big-endian variants
_PCAP_BATCH     = 200    # flush shared stats after this many packets …
_PCAP_FLUSH_SEC = 0.10   # … or after this many seconds, whichever comes first


def _iter_pcap(stream) -> Iterator[bytes]:
    """Yield raw frame bytes from a live pcap byte-stream without scapy.

    Uses BufferedReader.read(n) which is guaranteed to return exactly n bytes
    (issuing multiple syscalls internally if needed) — safe on pipe streams
    where a single readinto() call may return a partial record header.
    """
    hdr = stream.read(24)
    if len(hdr) < 24:
        return
    mag_le = struct.unpack_from('<I', hdr)[0]
    mag_be = struct.unpack_from('>I', hdr)[0]
    if   mag_le in _PCAP_LE: endian = '<'
    elif mag_be in _PCAP_BE: endian = '>'
    else:                     return
    while True:
        rec = stream.read(16)           # pcap record header: ts_s, ts_us/ns, incl_len, orig_len
        if len(rec) < 16:
            break
        incl_len = struct.unpack_from(endian + 'I', rec, 8)[0]
        data = stream.read(incl_len)
        if len(data) < incl_len:
            break
        yield data


def _flush_batch(local_cur: dict, local_protos: set,
                 pkts: int, total_bytes: int) -> None:
    """Merge a thread-local batch into the shared current window under lock."""
    global _total_packets, _total_bytes
    with _lock:
        for proto, keys in local_cur.items():
            for key, sz in keys.items():
                _cur[proto][key] += sz
        _session_protos.update(local_protos)
        _total_packets += pkts
        _total_bytes   += total_bytes


# ── capture backend ──────────────────────────────────────────────────────────

def _find_dumpcap() -> Optional[str]:
    """Locate dumpcap, falling back to Wireshark's usual Windows install
    locations since its installer does not add itself to PATH by default."""
    exe = shutil.which("dumpcap")
    if exe:
        return exe
    if not sys.platform.startswith("win"):
        return None
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(var)
        if base:
            candidate = os.path.join(base, "Wireshark", "dumpcap.exe")
            if os.path.isfile(candidate):
                return candidate
    try:
        import winreg
        for hive, subkey in (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wireshark"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Wireshark"),
        ):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    install_dir = winreg.QueryValueEx(key, "InstallDir")[0]
                candidate = os.path.join(install_dir, "dumpcap.exe")
                if os.path.isfile(candidate):
                    return candidate
            except OSError:
                continue
    except ImportError:
        pass
    return None


def _has_raw_socket() -> bool:
    """Return True if the process can open an AF_PACKET raw socket."""
    # AF_PACKET is Linux-only; Windows has no such attribute at all (raises
    # AttributeError, not PermissionError) so it must be caught here too.
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.close()
        return True
    except (PermissionError, AttributeError, OSError):
        return False


class _DumpcapCapture:
    """
    Capture backend using dumpcap (bundled with Wireshark).
    Works without root when the user is in the 'wireshark' group.
    """

    def __init__(self, iface: str, dumpcap_path: str = "dumpcap") -> None:
        self._iface        = iface
        self._dumpcap_path = dumpcap_path
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self.running  = False

    def start(self) -> None:
        self._proc = subprocess.Popen(
            [self._dumpcap_path, "-i", self._iface, "-w", "-", "-F", "pcap", "-q"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.running = True

        def _reader() -> None:
            # Thread-local accumulators — no lock per packet.
            # Flush into shared state after _PCAP_BATCH packets OR _PCAP_FLUSH_SEC
            # seconds, whichever comes first.  This keeps latency bounded at low
            # traffic rates (e.g. quiescent network) while staying lock-free at
            # high rates (e.g. Sampled Values at 4000 pkt/s).
            local_cur: dict = defaultdict(lambda: defaultdict(int))
            local_protos: set = set()
            local_pkts  = 0
            local_bytes = 0
            last_flush  = time.monotonic()
            try:
                for data in _iter_pcap(self._proc.stdout):  # type: ignore[arg-type]
                    if not self.running:
                        break
                    size   = len(data)
                    result = parse_frame(data)
                    proto  = result[0]
                    key    = result[1:]
                    local_cur[proto][key] += size
                    local_protos.add(proto)
                    local_pkts  += 1
                    local_bytes += size
                    now = time.monotonic()
                    if local_pkts >= _PCAP_BATCH or now - last_flush >= _PCAP_FLUSH_SEC:
                        _flush_batch(local_cur, local_protos, local_pkts, local_bytes)
                        local_cur    = defaultdict(lambda: defaultdict(int))
                        local_protos = set()
                        local_pkts   = 0
                        local_bytes  = 0
                        last_flush   = now
            except Exception:
                pass
            finally:
                if local_pkts:
                    _flush_batch(local_cur, local_protos, local_pkts, local_bytes)
                self.running = False

        self._thread = threading.Thread(target=_reader, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass


# ── rolling statistics ────────────────────────────────────────────────────────
# Two-window design: _cur accumulates live; _disp holds the last complete window.

StatsMap = Dict[str, Dict[Tuple[str, str, str, str, str, str, str, str], int]]

_lock        = threading.Lock()
_cur:  StatsMap = defaultdict(lambda: defaultdict(int))
_disp: StatsMap = {}
_win_dur: float = 1.0       # actual duration of the last completed window
_win_start: float = time.monotonic()

_session_protos: set = set()   # protocol names seen at any point this session

_total_packets = 0
_total_bytes   = 0
_start_time    = time.monotonic()


def _rotate_window() -> None:
    global _cur, _disp, _win_dur, _win_start
    now = time.monotonic()
    with _lock:
        _disp      = {p: dict(keys) for p, keys in _cur.items()}
        _win_dur   = max(now - _win_start, 0.001)
        _win_start = now
        _cur       = defaultdict(lambda: defaultdict(int))


def _on_packet(pkt) -> None:
    global _total_packets, _total_bytes
    data = bytes(pkt)
    size = len(data)
    proto, vlan, cos, redund, sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim = parse_frame(data)
    with _lock:
        _cur[proto][(vlan, cos, redund, sv_appid, sv_svid, sv_noasdu, sv_confrev, sv_sim)] += size
        _session_protos.add(proto)
        _total_packets += 1
        _total_bytes   += size


# ── offline pcap / pcapng file loader ─────────────────────────────────────────

_PCAP_PROGRESS_EVERY = 2000   # packets between progress_cb calls


def load_pcap_stats(
    path: str, progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Tuple[StatsMap, float, int, int]:
    """Read every frame from a pcap or pcapng file and classify it exactly like
    a live capture would. Returns (stats, duration_s, packet_count, byte_count),
    where duration_s spans the file's first to last packet timestamp (used in
    place of a live window duration for the rate/% columns).

    scapy's PcapReader builds a full Packet object per frame, so large files
    take a while (tens of seconds for 100k+ packets); progress_cb(pkts,
    total_bytes), if given, is called every _PCAP_PROGRESS_EVERY packets so a
    caller can show the load is actually progressing.
    """
    stats: StatsMap = defaultdict(lambda: defaultdict(int))
    pkts = total_bytes = 0
    t_min: Optional[float] = None
    t_max: Optional[float] = None

    with PcapReader(path) as reader:
        for pkt in reader:
            data   = bytes(pkt)
            size   = len(data)
            result = parse_frame(data)
            stats[result[0]][result[1:]] += size
            pkts        += 1
            total_bytes += size
            ts = float(pkt.time)
            if t_min is None or ts < t_min:
                t_min = ts
            if t_max is None or ts > t_max:
                t_max = ts
            if progress_cb is not None and pkts % _PCAP_PROGRESS_EVERY == 0:
                progress_cb(pkts, total_bytes)

    duration = max((t_max - t_min) if t_min is not None else 0.0, 0.001)
    return {p: dict(k) for p, k in stats.items()}, duration, pkts, total_bytes


# ── display helpers ───────────────────────────────────────────────────────────

def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _fmt_bits(bps: float) -> str:
    """Format bits per second with 3 decimal places and SI prefix."""
    if bps < 1_000:
        return f"{bps:.3f} bit/s"
    elif bps < 1_000_000:
        return f"{bps / 1_000:.3f} Kbit/s"
    elif bps < 1_000_000_000:
        return f"{bps / 1_000_000:.3f} Mbit/s"
    return f"{bps / 1_000_000_000:.3f} Gbit/s"


def _build_panel(iface: str, enabled: frozenset) -> Panel:
    """Construct the full rich renderable for one display refresh.

    enabled — protocols (subset of FEATURED_PROTOS) to break out into their own
    detailed rows; everything else (including a disabled featured protocol)
    is folded into the aggregated "Other" row.
    """
    with _lock:
        snap    = {p: dict(keys) for p, keys in _disp.items()}
        win_dur = _win_dur
        t_pkts  = _total_packets
        t_bytes = _total_bytes

    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
        show_edge=True,
        padding=(0, 1),
    )
    table.add_column("Protocol",      style="bold cyan",  no_wrap=True, min_width=16)
    table.add_column("VLAN",          style="yellow",     no_wrap=True, min_width=8)
    table.add_column("CoS",           style="blue",       no_wrap=True, justify="center", min_width=5)
    table.add_column("Redundancy",    style="magenta",    no_wrap=True, min_width=9)
    table.add_column("AppID",         style="green",      no_wrap=True, justify="center", min_width=8)
    table.add_column("SVID/GOID",     style="white",      no_wrap=True, min_width=14)
    table.add_column("noASDU/stNum",  style="white",      no_wrap=True, justify="center", min_width=13)
    table.add_column("confRev",       style="cyan",       no_wrap=True, justify="center", min_width=8)
    table.add_column("Sim",           style="white",      no_wrap=True, justify="center", min_width=5)
    table.add_column("bits/s",        style="white",      no_wrap=True, justify="right",  min_width=16)
    table.add_column("%",             style="white",      no_wrap=True, justify="right",  min_width=8)

    grand_total = 0.0

    for proto in PROTO_ORDER:
        if proto not in enabled or proto not in snap:
            continue
        sub_rows = [
            (vlan, cos, redund, appid, svid, noasdu, confrev, sim, bcount / win_dur)
            for (vlan, cos, redund, appid, svid, noasdu, confrev, sim), bcount
            in sorted(snap[proto].items())
        ]
        proto_total  = sum(r for *_, r in sub_rows)
        grand_total += proto_total

        for vlan, cos, redund, appid, svid, noasdu, confrev, sim, rate in sub_rows:
            pct         = rate / LINK_BYTES_S * 100.0
            redund_text = Text(redund, style="bold magenta" if redund != "-" else "white")
            sim_text    = Text(sim,    style="bold red"     if sim == "yes" else "white")
            pct_color   = "bold red" if pct > 70 else "bold yellow" if pct > 40 else "white"
            table.add_row(
                proto, vlan, cos, redund_text, appid, svid, noasdu, confrev, sim_text,
                _fmt_bits(rate * 8),
                Text(f"{pct:.3f}%", style=pct_color),
            )

        if len(sub_rows) > 1:
            sub_pct = proto_total / LINK_BYTES_S * 100.0
            # Plain ASCII label: Windows' legacy console codepage (cp1252) can't
            # encode '∑' and rich's Windows renderer crashes rather than substituting.
            table.add_row(
                f"  Sum {proto}", "", "", "", "", "", "", "", "",
                _fmt_bits(proto_total * 8),
                f"{sub_pct:.3f}%",
            )

    # All protocols that aren't individually enabled aggregated into "Other"
    other_rate = sum(
        bcount / win_dur
        for proto, keys in snap.items()
        if proto not in enabled
        for bcount in keys.values()
    )
    grand_total += other_rate
    if other_rate > 0:
        other_pct = other_rate / LINK_BYTES_S * 100.0
        table.add_row(
            "Other", "-", "-", "-", "-", "-", "-", "-", "-",
            _fmt_bits(other_rate * 8),
            f"{other_pct:.3f}%",
        )

    # ── grand TOTAL row ───────────────────────────────────────────────────
    table.add_section()
    total_pct   = grand_total / LINK_BYTES_S * 100.0
    total_color = "bold red" if total_pct > 70 else "bold yellow" if total_pct > 40 else "bold green"
    table.add_row(
        "[bold white]TOTAL[/bold white]",
        "", "", "", "", "", "", "", "",
        f"[bold]{_fmt_bits(grand_total * 8)}[/bold]",
        Text(f"{total_pct:.3f}%", style=total_color),
    )

    uptime  = int(time.monotonic() - _start_time)
    h, rem  = divmod(uptime, 3600)
    m, s    = divmod(rem, 60)

    title = (
        f"[bold cyan]IEC 61850 Network Load Monitor[/bold cyan]  "
        f"iface [yellow]{iface}[/yellow]  "
        f"link [green]{LINK_MBPS} Mb/s[/green]  "
        f"[dim]{datetime.now():%H:%M:%S}[/dim]"
    )
    footer = (
        f"[dim]packets {t_pkts:,}  "
        f"total {_fmt_bytes(float(t_bytes))}  "
        f"uptime {h:02d}:{m:02d}:{s:02d}  "
        f"window {win_dur*1000:.0f} ms[/dim]"
    )
    return Panel(table, title=title, subtitle=footer, border_style="blue")


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    global LINK_MBPS, LINK_BYTES_S, _start_time, _disp, _win_dur, _total_packets, _total_bytes

    parser = argparse.ArgumentParser(
        prog="monitor.py",
        description=f"{SOFTWARE_NAME} v{__version__} – Layer 2 protocol analyser "
                    f"(License: {LICENSE_NAME})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PROTOCOLS WITH DETAILED BREAKDOWN (off by default — see --goose/--sv/--rgoose/--ptp)
  GOOSE          EtherType 0x88B8  – Generic Object Oriented Substation Event
  Sampled Values EtherType 0x88BA  – Process-bus current/voltage samples
  R-GOOSE        UDP multicast     – Routable GOOSE (IEC 61850-8-2)
  PTP            EtherType 0x88F7  – IEEE 1588 Precision Time Protocol

EVERYTHING ELSE — always aggregated into a single "Other" row
  R-SV, GSSE, MMS, NTP, LLDP, RSTP, ARP, IPv4, IPv6, and any unclassified
  traffic are still recognized internally but have no per-protocol row;
  they only ever contribute to "Other"'s combined rate.

REDUNDANCY DETECTION
  HSR-A / HSR-B  In-frame tag EtherType 0x892F (IEC 62439-3 §5)
                 Path nibble 0xA = LAN A, 0xB = LAN B
  PRP-A / PRP-B  Redundancy Control Trailer suffix 0x88FB (IEC 62439-3 §4)
                 LanId nibble 0xA = LAN A, 0xB = LAN B

TABLE COLUMNS
  Protocol     Classified protocol name (GOOSE/SV/R-GOOSE/PTP individually
               when enabled; all others summarised as "Other")
  VLAN         802.1Q / QinQ VLAN id(s), or '-'
  CoS          IEEE 802.1Q PCP (Priority Code Point) value, or '-'
  Redundancy   HSR-A/B or PRP-A/B if detected, else '-'
  AppID        Application Identifier (hex) — GOOSE and SV
  SVID/GOID    SV stream ID  or  GOOSE goID (falls back to gocbRef)
  noASDU/stNum Number of ASDUs (SV)  or  Status Number (GOOSE)
  confRev      Configuration revision — GOOSE and SV
  Sim          Simulation flag: yes (red) = simulated, no = real
  bits/s       Throughput in the last window, SI-prefixed, 3 decimal places
  %%           Load as percentage of configured link speed

  Sum rows   Per-protocol subtotal (shown when a protocol spans
             multiple VLAN / redundancy combinations)
  TOTAL      Grand sum of all traffic

CAPTURE BACKENDS (tried in order)
  raw socket  Requires root or CAP_NET_RAW
  dumpcap     No root needed if user is in the 'wireshark' group

EXAMPLES
  python3 monitor.py                        # eth0, 10 s, 100 Mb/s
  python3 monitor.py eth0 -d 30             # capture for 30 seconds
  python3 monitor.py eth1 -s 1000 -d 0     # 1 Gb/s link, run forever
  python3 monitor.py eth0 -r 2 -d 60       # 2 s window, 60 s capture
  python3 monitor.py --list                 # show available interfaces
  python3 monitor.py eth0 --goose --sv      # break out GOOSE and SV detail
  python3 monitor.py --pcap capture.pcapng --goose --ptp
""",
    )
    parser.add_argument(
        "interface", nargs="?", default="eth0",
        help="Network interface to capture on  (default: eth0)",
    )
    parser.add_argument(
        "-d", "--duration", type=float, default=10.0, metavar="SEC",
        help="Stop after this many seconds; 0 = run forever  (default: 10)",
    )
    parser.add_argument(
        "-s", "--speed", type=int, default=100, metavar="MBPS",
        help="Link speed in Mb/s used for load %% calculation  (default: 100)",
    )
    parser.add_argument(
        "-r", "--refresh", type=float, default=1.0, metavar="SEC",
        help="Statistics window / display refresh in seconds  (default: 1.0)",
    )
    parser.add_argument(
        "-l", "--list", action="store_true",
        help="List available network interfaces and exit",
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"{SOFTWARE_NAME} v{__version__}\nLicense: {LICENSE_NAME}",
        help="Show version and license, then exit",
    )
    parser.add_argument(
        "--pcap", metavar="FILE",
        help="Load a .pcap/.pcapng file and print a static summary instead of "
             "capturing live traffic (INTERFACE is ignored)",
    )
    parser.add_argument(
        "--goose", action="store_true",
        help="Show detailed GOOSE breakdown (off by default; folded into 'Other')",
    )
    parser.add_argument(
        "--sv", action="store_true",
        help="Show detailed Sampled Values breakdown (off by default)",
    )
    parser.add_argument(
        "--rgoose", action="store_true",
        help="Show detailed R-GOOSE breakdown (off by default)",
    )
    parser.add_argument(
        "--ptp", action="store_true",
        help="Show detailed PTP breakdown (off by default)",
    )
    args = parser.parse_args()

    enabled_protos: frozenset = frozenset(
        name for name, flag in (
            ("GOOSE", args.goose),
            ("Sampled Values", args.sv),
            ("R-GOOSE", args.rgoose),
            ("PTP", args.ptp),
        ) if flag
    )

    console = Console()

    if args.list:
        labels, _ = _list_interfaces()
        console.print("[bold]Available interfaces:[/bold]")
        for label in labels:
            console.print(f"  {label}")
        return

    LINK_MBPS    = args.speed
    LINK_BYTES_S = LINK_MBPS * 1_000_000 / 8

    if args.pcap:
        try:
            stats, duration, pkts, total_bytes = load_pcap_stats(args.pcap)
        except Exception as exc:
            console.print(f"[bold red]Error:[/bold red] failed to read {args.pcap}: {exc}")
            sys.exit(1)
        _disp          = stats
        _win_dur       = duration
        _total_packets = pkts
        _total_bytes   = total_bytes
        _start_time    = time.monotonic() - duration
        console.print(_build_panel(args.pcap, enabled_protos))
        return

    labels, iface_map = _list_interfaces()
    iface = _resolve_iface(args.interface, iface_map)
    if iface is None:
        console.print(
            f"[bold red]Error:[/bold red] interface [yellow]{args.interface}[/yellow] "
            f"not found.\nAvailable: {', '.join(labels)}"
        )
        sys.exit(1)
    # Friendly label for display (panel title, status line); iface (raw scapy
    # id, e.g. an NPF device path on Windows) is what the capture backend needs.
    label = next((k for k, v in iface_map.items() if v == iface), iface)

    # ── select capture backend ────────────────────────────────────────────
    dumpcap_path = _find_dumpcap()
    if _has_raw_socket():
        backend      = "raw socket"
        use_dumpcap  = False
    elif dumpcap_path:
        backend      = "dumpcap"
        use_dumpcap  = True
    elif sys.platform.startswith("win"):
        console.print(
            "[bold red]Error:[/bold red] no capture method available.\n"
            "  Install Wireshark (provides dumpcap) and run as Administrator,\n"
            "  or uncheck 'Restrict Npcap driver's access to Administrators only'\n"
            "  in the Npcap installer to capture without elevation."
        )
        sys.exit(1)
    else:
        console.print(
            "[bold red]Error:[/bold red] no capture method available.\n"
            "  Option 1: run with sudo\n"
            "  Option 2: install wireshark and add yourself to the 'wireshark' group"
        )
        sys.exit(1)

    # Plain ASCII: Windows' legacy console codepage (cp1252) can't encode '∞'
    # and rich's Windows renderer crashes rather than substituting.
    dur_label = "forever" if args.duration == 0 else f"{args.duration:.0f}s"
    console.print(
        f"[bold]Starting capture on [cyan]{label}[/cyan]  "
        f"link [green]{LINK_MBPS} Mb/s[/green]  "
        f"window [white]{args.refresh}s[/white]  "
        f"duration [white]{dur_label}[/white]  "
        f"backend [dim]{backend}[/dim] …[/bold]"
    )

    _start_time = time.monotonic()

    # ── start capture ─────────────────────────────────────────────────────
    if use_dumpcap:
        cap = _DumpcapCapture(iface, dumpcap_path)
        try:
            cap.start()
        except Exception as exc:
            console.print(f"[red]dumpcap failed: {exc}[/red]")
            sys.exit(1)
        is_running = lambda: cap.running  # noqa: E731
        stop_cap   = cap.stop
    else:
        sniffer = AsyncSniffer(iface=iface, prn=_on_packet, store=False)
        try:
            sniffer.start()
        except Exception as exc:
            console.print(f"[red]Capture failed: {exc}[/red]")
            sys.exit(1)
        is_running = lambda: sniffer.running  # noqa: E731
        stop_cap   = sniffer.stop

    # Background thread that rotates the statistics window
    stop_evt = threading.Event()

    def _rotator() -> None:
        while not stop_evt.is_set():
            time.sleep(args.refresh)
            _rotate_window()

    rotator = threading.Thread(target=_rotator, daemon=True)
    rotator.start()

    def _shutdown(sig=None, frame=None) -> None:
        stop_evt.set()
        stop_cap()
        console.print("\n[yellow]Capture stopped.[/yellow]")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Optional duration timer – fires _shutdown after args.duration seconds
    if args.duration > 0:
        dur_timer = threading.Timer(args.duration, _shutdown)
        dur_timer.daemon = True
        dur_timer.start()

    # Live display – refreshes at 2× the window rate so updates feel responsive
    refresh_hz = max(2.0, 1.0 / args.refresh * 2)
    with Live(console=console, refresh_per_second=refresh_hz, screen=False) as live:
        while is_running():
            live.update(_build_panel(label, enabled_protos))
            time.sleep(min(0.5, args.refresh / 2))


if __name__ == "__main__":
    main()
