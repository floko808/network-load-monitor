# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) once it
reaches 1.0.0 — until then, `0.0.x` bumps may include new features, not just
fixes.

## [Unreleased]

Nothing further is planned — the project is archived as of 2026-08-08 with
v0.0.5 as its final release. See the note at the top of the README.

Post-archive packaging only, no code changes: Linux x86-64 binaries for the
CLI and GUI were built from the v0.0.5 source and added to the existing
v0.0.5 release, alongside `build-linux.sh` which reproduces them. They are
built in a Debian 12 container so they run on Debian 12, Ubuntu 24.04 and
newer glibc-based distributions; verified on both. Until now `dist/` held
Windows `.exe`s only and the README said Linux had no compiled binary.

## [0.0.5] - 2026-07-29

### Added
- Traffic filtering by VLAN, redundancy (HSR/PRP), AppID, GOOSE ID, and SVID.
  CLI: `--vlan`, `--redundancy`, `--appid`, `--goid`, `--svid` (comma-separated
  for multiple values, OR'd within a flag and AND'd across flags); matching
  frames are dropped before they're counted, so totals and the session
  summary reflect only the filtered traffic. GUI: the Protocol/VLAN/
  Redundancy/AppID/SVID-GOID column headers each get an Excel-style filter
  dropdown, adjustable live during a capture or after it has stopped (or
  after loading a pcap file) without needing to recapture or reload, plus a
  "Clear Filters" button.

## [0.0.4] - 2026-07-21

### Fixed
- CLI printed the results table twice at the end of a live capture — the
  live view's final frame, followed by a separate "session total" panel
  underneath it. The live table's own last update now shows the session
  total directly, so there's a single table that refreshes at the
  configured `--refresh` rate throughout and settles on the session total
  when the capture stops, instead of two.

### Security
- `--pcap` / "Open pcap/pcapng..." now validates a file's magic bytes itself
  before handing it to scapy, instead of relying only on scapy's own header
  parsing. In particular this explicitly refuses gzip-wrapped input, which
  scapy would otherwise transparently inflate — since inflation happens
  before any size is known, a small malicious `.gz` could otherwise expand
  into an arbitrarily large stream. Plain pcap/pcapng are read byte-for-byte
  with no such amplification, so this closes the one decompression-bomb-style
  vector without limiting legitimate large captures. The GUI's file-picker
  extension filter was always cosmetic (it has an "All files" option); the
  real gate is this header check, run regardless of what the file is named.

### Changed
- README: added a second CLI screenshot (`docs/screenshots/cli-screenshot-unicast.svg`),
  rendered against a real capture with actual MMS/DNP3/Modbus TCP traffic, so
  those detailed rows are no longer undocumented by example.

## [0.0.3] - 2026-07-20

### Fixed
- MMS/DNP3/IEC104/Modbus TCP rows disappearing between bursts. These
  protocols are unicast and often bursty (e.g. an MMS report control
  block's integrity period) rather than continuous like GOOSE/SV, so a
  protocol could go quiet for many refresh windows between exchanges and
  its row would simply vanish — easy to mistake for "not detected" even
  though it was captured moments earlier. A protocol's row now stays
  visible (bits/s reset to 0, labeled `idle Ns`) until its next exchange
  refreshes it, in both CLI and GUI.
- A race in the `dumpcap` capture backend (CLI and GUI) where stopping a
  capture could silently discard the last in-flight batch of packets.
  `dumpcap` buffers its output before writing to the pipe, so a burst
  captured seconds ago may still be flushed-but-unread when the capture is
  told to stop; the reader now drains everything still in flight before
  reporting the capture as stopped, instead of abandoning it mid-read.
- Live captures had no way to answer "how much MMS (or any bursty
  protocol) traffic did this run actually have" — the live view only ever
  showed the current rolling window's rate, which could easily be 0 at the
  exact moment the capture ended even though real traffic occurred earlier
  in the run. A session-wide cumulative total is now tracked throughout
  the capture and shown once it stops: the CLI prints an additional
  "session total" summary panel, and the GUI's table settles on the
  session totals after Stop (waiting for the backend to finish draining
  first, for the same buffering reason as above).

### Changed
- README and CLI `--help` now note that MMS/DNP3/IEC104/Modbus are bursty
  rather than continuous, and recommend a longer `--duration` (or `0` to
  run until stopped) so a capture reliably spans at least one full cycle.

## [0.0.2] - 2026-07-18

### Added
- Detection of four unicast TCP/UDP protocols, each confirmed by parsing its
  actual framing — not just a well-known port match — so unrelated traffic
  on the same port isn't misclassified:
  - **MMS** (TCP port 102) — verified via the TPKT (RFC 1006) header
  - **DNP3** (TCP or UDP port 20000) — verified via the data-link sync bytes
  - **IEC104** (TCP port 2404, IEC 60870-5-104) — verified via the APCI start byte
  - **Modbus TCP** (TCP port 502) — verified via the MBAP header
- `--mms`, `--dnp3`, `--iec104`, `--modbus` CLI flags and matching GUI detail
  checkboxes to break each of these out of the aggregated "Other" row, same
  as the existing GOOSE/SV/R-GOOSE/PTP toggles.
- `--all` CLI flag to enable every supported protocol's detailed breakdown
  at once.
- Live percentage readout while loading a `.pcap`/`.pcapng` file: a `rich`
  progress bar on the CLI, a modal progress dialog on the GUI. Both are
  driven by the reader's actual position in the file on disk, not decoded
  packet count, so the percentage is accurate regardless of packet size
  distribution.

### Changed
- GUI's default window width increased (1280→1480 px) to fit the four
  additional protocol-detail checkboxes without overflowing.
- README: protocol table, CLI reference, GUI walkthrough, and third-party
  license section (now a per-library table with license and purpose)
  updated to match.

## [0.0.1] - 2026-07-10

### Added
- Initial release: `monitor.py` (CLI, built on `rich`) and `monitor_gui.py`
  (Tkinter GUI), sharing one capture/parsing engine.
- Protocol classification for GOOSE (`0x88B8`), Sampled Values (`0x88BA`),
  R-GOOSE (UDP multicast, IEC 61850-8-2), and PTP/IEEE 1588 (`0x88F7`), each
  with an optional detailed breakdown (VLAN, CoS, AppID, SVID/GOID,
  noASDU/stNum, confRev, Sim) toggled via `--goose`/`--sv`/`--rgoose`/`--ptp`
  or the matching GUI checkbox; everything else aggregated into "Other".
  MMS, GSSE, NTP, LLDP, RSTP, ARP, IPv4, and IPv6 recognized internally but
  not yet broken out individually.
- HSR (IEC 62439-3 §5, in-frame tag `0x892F`) and PRP (§4, RCT trailer
  `0x88FB`) redundancy detection, shown regardless of protocol flags.
- 802.1Q VLAN and QinQ tag parsing (VLAN id + CoS/PCP).
- Live capture via raw socket (root/`CAP_NET_RAW`) or `dumpcap` (no root
  needed with the `wireshark` group), and offline analysis of `.pcap`/
  `.pcapng` files via `--pcap`.
- CSV export and interface listing (`--list`) in both CLI and GUI.
- Windows support via PyInstaller-compiled `network-monitor.exe` /
  `network-monitor-gui.exe`, alongside running from source on Linux.
- CLI and GUI screenshots added to the README.

[Unreleased]: https://github.com/floko808/network-load-monitor/compare/v0.0.5...HEAD
[0.0.5]: https://github.com/floko808/network-load-monitor/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/floko808/network-load-monitor/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/floko808/network-load-monitor/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/floko808/network-load-monitor/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/floko808/network-load-monitor/releases/tag/v0.0.1
