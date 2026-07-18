# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) once it
reaches 1.0.0 — until then, `0.0.x` bumps may include new features, not just
fixes.

## [Unreleased]

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

[Unreleased]: https://github.com/floko808/network-load-monitor/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/floko808/network-load-monitor/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/floko808/network-load-monitor/releases/tag/v0.0.1
