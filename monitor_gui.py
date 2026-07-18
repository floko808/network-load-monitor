#!/usr/bin/env python3
"""
IEC 61850 Network Load Monitor — GUI
Tkinter frontend (stdlib only) sharing the capture and parsing engine
from monitor.py.

Usage:
  python3 monitor_gui.py
  sudo python3 monitor_gui.py   # if not in the 'wireshark' group
"""

import csv
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import traceback
from collections import defaultdict
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Dict, Optional

try:
    from monitor import (
        LICENSE_NAME, PROTO_ORDER, SOFTWARE_NAME, __version__,
        _fmt_bits, _iter_pcap, _list_interfaces, load_pcap_stats, parse_frame,
    )
except ImportError:
    raise SystemExit("monitor.py not found — place monitor_gui.py in the same directory.")

try:
    from scapy.all import AsyncSniffer
except ImportError:
    raise SystemExit("scapy not found — pip install scapy")


# ── helpers ───────────────────────────────────────────────────────────────────

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
    # AF_PACKET is Linux-only; Windows has no such attribute at all (raises
    # AttributeError, not PermissionError) so it must be caught here too.
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.close()
        return True
    except (PermissionError, AttributeError, OSError):
        return False


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


# ── table layout ──────────────────────────────────────────────────────────────

_COLS = (
    "Protocol", "VLAN", "CoS", "Redundancy", "AppID",
    "SVID/GOID", "noASDU/stNum", "confRev", "Sim", "bits/s", "%",
)

# Columns that expand to fill extra window width; all others stay content-wide.
_COLS_STRETCH = frozenset({"Protocol", "SVID/GOID"})

_COL_A = {
    "Protocol": "w",  "VLAN": "center", "CoS": "center",
    "Redundancy": "w", "AppID": "center", "SVID/GOID": "w",
    "noASDU/stNum": "center", "confRev": "center",
    "Sim": "center", "bits/s": "e", "%": "e",
}


# ── capture engine ────────────────────────────────────────────────────────────

class _CaptureEngine:
    _BATCH_PKTS = 200
    _BATCH_SEC  = 0.10

    def __init__(self, iface: str, on_batch) -> None:
        self._iface        = iface
        self._on_batch      = on_batch
        self._proc          = None
        self._sniffer       = None
        self._thread        = None
        self._dumpcap_path  = None
        self.running        = False
        self.backend        = "?"

    def start(self) -> None:
        dumpcap = _find_dumpcap()
        if _has_raw_socket():
            self.backend = "raw socket"
            self._start_raw()
        elif dumpcap:
            self.backend       = "dumpcap"
            self._dumpcap_path = dumpcap
            self._start_dumpcap()
        elif sys.platform.startswith("win"):
            raise RuntimeError(
                "No capture backend available.\n"
                "Install Wireshark (provides dumpcap) and run as Administrator, or "
                "uncheck 'Restrict Npcap driver's access to Administrators only' "
                "in the Npcap installer to capture without elevation."
            )
        else:
            raise RuntimeError(
                "No capture backend available.\n"
                "Run with sudo, or install Wireshark and join the 'wireshark' group."
            )

    def _start_raw(self) -> None:
        def _on_pkt(pkt) -> None:
            data   = bytes(pkt)
            result = parse_frame(data)
            self._on_batch([(result[0], result[1:], len(data))])

        self._sniffer = AsyncSniffer(iface=self._iface, prn=_on_pkt, store=False)
        self._sniffer.start()
        self.running = True

    def _start_dumpcap(self) -> None:
        self._proc = subprocess.Popen(
            [self._dumpcap_path, "-i", self._iface, "-w", "-", "-F", "pcap", "-q"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.running = True

        def _reader() -> None:
            batch      = []
            last_flush = time.monotonic()
            try:
                for data in _iter_pcap(self._proc.stdout):  # type: ignore[arg-type]
                    if not self.running:
                        break
                    result = parse_frame(data)
                    batch.append((result[0], result[1:], len(data)))
                    now = time.monotonic()
                    if len(batch) >= self._BATCH_PKTS or now - last_flush >= self._BATCH_SEC:
                        self._on_batch(batch)
                        batch      = []
                        last_flush = now
            except Exception:
                pass
            finally:
                if batch:
                    self._on_batch(batch)
                self.running = False

        self._thread = threading.Thread(target=_reader, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass


# ── pcap load progress dialog ───────────────────────────────────────────────

class _PcapLoadDialog:
    """Small modal window shown while an offline pcap/pcapng file is being
    parsed, mirroring the CLI's --pcap progress bar."""

    def __init__(self, root: tk.Tk, filename: str) -> None:
        self._win = tk.Toplevel(root)
        self._win.title("Loading capture")
        self._win.resizable(False, False)
        self._win.transient(root)
        self._win.protocol("WM_DELETE_WINDOW", lambda: None)  # no close while loading

        pad = ttk.Frame(self._win, padding=16)
        pad.pack(fill="both", expand=True)

        ttk.Label(pad, text=f"Loading {filename} …").pack(anchor="w")

        self._bar = ttk.Progressbar(
            pad, orient="horizontal", length=360, mode="determinate", maximum=100,
        )
        self._bar.pack(fill="x", pady=(10, 4))

        self._detail_var = tk.StringVar(value="0.0%   0 packets  (0.0 B)")
        ttk.Label(pad, textvariable=self._detail_var).pack(anchor="w")

        self._win.update_idletasks()
        x = root.winfo_rootx() + (root.winfo_width() - self._win.winfo_reqwidth()) // 2
        y = root.winfo_rooty() + (root.winfo_height() - self._win.winfo_reqheight()) // 2
        self._win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self._win.grab_set()

    def update(self, pkts: int, total_bytes: int, percent: float) -> None:
        self._bar["value"] = percent
        self._detail_var.set(
            f"{percent:.1f}%   {pkts:,} packets  ({_fmt_bytes(float(total_bytes))})"
        )

    def close(self) -> None:
        self._win.grab_release()
        self._win.destroy()


# ── application ───────────────────────────────────────────────────────────────

class MonitorApp:
    _REFRESH_MS = 1000

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(f"{SOFTWARE_NAME} v{__version__}")
        root.geometry("1280x540")

        self._lock         = threading.Lock()
        self._cur: dict    = defaultdict(lambda: defaultdict(int))
        self._win_start    = time.monotonic()
        self._total_pkts   = 0
        self._total_bytes  = 0
        self._start_time: Optional[float] = None
        self._engine: Optional[_CaptureEngine] = None
        self._after_id: Optional[str] = None
        self._dur_timer: Optional[threading.Timer] = None
        self._link_bytes_s = 100 * 1_000_000 / 8
        self._font: Optional[tkfont.Font] = None
        self._last_snap: dict = {}
        self._last_win_dur    = 1.0

        self._build_ui()
        self._populate_interfaces()

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        # Row height must be set explicitly; the default ignores the actual font
        # size and causes text to overflow or overlap adjacent rows.
        _f    = tkfont.nametofont("TkDefaultFont")
        row_h = _f.metrics("linespace") + 8   # font height + vertical padding
        style.configure("Treeview",         rowheight=row_h, font=_f)
        style.configure("Treeview.Heading", font=_f, padding=(6, 4))

        # ── menu bar ──────────────────────────────────────────────────────
        menubar = tk.Menu(self.root)
        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

        # ── toolbar ───────────────────────────────────────────────────────
        bar = ttk.Frame(self.root, padding=(8, 5))
        bar.pack(fill="x", side="top")

        ttk.Label(bar, text="Interface:").pack(side="left")
        self._iface_var = tk.StringVar()
        self._iface_map: Dict[str, str] = {}
        self._iface_cb  = ttk.Combobox(bar, textvariable=self._iface_var,
                                        width=14, state="readonly")
        self._iface_cb.pack(side="left", padx=(3, 14))

        ttk.Label(bar, text="Link speed:").pack(side="left")
        self._speed_var = tk.StringVar(value="100")
        ttk.Entry(bar, textvariable=self._speed_var, width=6).pack(side="left", padx=(3, 2))
        ttk.Label(bar, text="Mb/s").pack(side="left", padx=(0, 14))

        ttk.Label(bar, text="Duration:").pack(side="left")
        self._dur_var = tk.StringVar(value="10")
        ttk.Entry(bar, textvariable=self._dur_var, width=5).pack(side="left", padx=(3, 2))
        ttk.Label(bar, text="s  (0 = ∞)").pack(side="left", padx=(0, 14))

        self._btn_start = ttk.Button(bar, text="▶  Start", command=self._on_start)
        self._btn_start.pack(side="left", padx=3)
        self._btn_stop  = ttk.Button(bar, text="■  Stop", command=self._on_stop,
                                     state="disabled")
        self._btn_stop.pack(side="left", padx=3)

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Button(bar, text="⬇  Export CSV", command=self._export_csv).pack(side="left", padx=3)

        # ── second row: per-protocol detail toggles + offline file load ────
        bar2 = ttk.Frame(self.root, padding=(8, 0, 8, 5))
        bar2.pack(fill="x", side="top")

        ttk.Label(bar2, text="Detail:").pack(side="left")
        self._proto_vars: Dict[str, tk.BooleanVar] = {}
        for name in PROTO_ORDER:
            var = tk.BooleanVar(value=False)
            self._proto_vars[name] = var
            ttk.Checkbutton(
                bar2, text=name, variable=var, command=self._on_proto_toggle,
            ).pack(side="left", padx=(6, 0))

        ttk.Separator(bar2, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Button(bar2, text="Open pcap/pcapng...", command=self._open_pcap).pack(side="left", padx=3)

        # ── table ─────────────────────────────────────────────────────────
        frm = ttk.Frame(self.root)
        frm.pack(fill="both", expand=True, padx=6, pady=(2, 0))

        self._tree = ttk.Treeview(frm, columns=_COLS, show="headings",
                                  selectmode="none")
        self._font    = tkfont.nametofont("TkDefaultFont")
        self._bold_font = tkfont.Font(font=self._font, weight="bold")
        for col in _COLS:
            init_w = self._font.measure(col) + 20
            self._tree.heading(col, text=col)
            self._tree.column(col, width=init_w, minwidth=30,
                              anchor=_COL_A[col], stretch=(col in _COLS_STRETCH))

        vsb = ttk.Scrollbar(frm, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(frm, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right",  fill="y")
        self._tree.pack(fill="both", expand=True)

        # Only two visual variants: subtotal rows (muted) and the TOTAL row (bold).
        # All data rows are plain black — no colour coding.
        self._tree.tag_configure("subtot", foreground="#888888")
        self._tree.tag_configure("total",  font=self._bold_font)

        # ── status bar ────────────────────────────────────────────────────
        self._status = tk.StringVar(value="Ready — select an interface and click Start.")
        sb = ttk.Frame(self.root, relief="sunken", padding=(6, 2))
        sb.pack(fill="x", side="bottom")
        ttk.Label(sb, textvariable=self._status, anchor="w").pack(fill="x")

    def _populate_interfaces(self) -> None:
        labels, self._iface_map = _list_interfaces()
        self._iface_cb["values"] = labels
        if labels:
            self._iface_var.set(labels[0])

        # Widen the box to fit the longest label (Windows descriptions can be
        # long) instead of the fixed width sized for short Linux names like eth0.
        font  = tkfont.nametofont("TkDefaultFont")
        chars = max((font.measure(s) for s in labels), default=0) // max(font.measure("0"), 1) + 2
        self._iface_cb.config(width=min(max(chars, 14), 70))

    # ── capture control ───────────────────────────────────────────────────

    def _on_start(self) -> None:
        label = self._iface_var.get().strip()
        if not label:
            messagebox.showerror("Error", "Select a network interface first.")
            return
        iface = self._iface_map.get(label, label)
        try:
            speed = int(self._speed_var.get())
            if speed <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Link speed must be a positive integer.")
            return
        try:
            duration = float(self._dur_var.get())
            if duration < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Duration must be ≥ 0 (0 = run forever).")
            return

        self._link_bytes_s = speed * 1_000_000 / 8
        self._total_pkts   = 0
        self._total_bytes  = 0
        self._start_time   = time.monotonic()
        self._cur          = defaultdict(lambda: defaultdict(int))
        self._win_start    = time.monotonic()

        def on_batch(batch) -> None:
            with self._lock:
                for proto, key, size in batch:
                    self._cur[proto][key] += size
                    self._total_pkts += 1
                    self._total_bytes += size

        self._engine = _CaptureEngine(iface, on_batch)
        try:
            self._engine.start()
        except RuntimeError as exc:
            messagebox.showerror("Capture error", str(exc))
            return

        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._iface_cb.config(state="disabled")
        dur_label = "∞" if duration == 0 else f"{duration:.0f} s"
        self._status.set(f"Starting capture on {iface}  —  duration: {dur_label}")
        self._after_id = self.root.after(self._REFRESH_MS, self._refresh)

        if duration > 0:
            self._dur_timer = threading.Timer(
                duration, lambda: self.root.after(0, self._on_stop)
            )
            self._dur_timer.daemon = True
            self._dur_timer.start()

    def _on_stop(self) -> None:
        if self._dur_timer:
            self._dur_timer.cancel()
            self._dur_timer = None
        if self._engine:
            self._engine.stop()
            self._engine = None
        if self._after_id:
            self.root.after_cancel(self._after_id)
            self._after_id = None
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._iface_cb.config(state="readonly")
        self._status.set("Stopped.")

    # ── offline pcap/pcapng file loading ────────────────────────────────────

    def _open_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title="Open pcap/pcapng capture",
            filetypes=[("Capture files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            speed = int(self._speed_var.get())
            if speed <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Link speed must be a positive integer.")
            return

        self._on_stop()   # a static file load replaces any live capture in progress
        self._link_bytes_s = speed * 1_000_000 / 8
        self._status.set(f"Loading {path} …")
        self._btn_start.config(state="disabled")

        base = os.path.basename(path)
        dialog = _PcapLoadDialog(self.root, base)

        def on_progress(pkts: int, total_bytes: int, percent: float) -> None:
            self.root.after(0, lambda: dialog.update(pkts, total_bytes, percent))
            self.root.after(0, lambda: self._status.set(
                f"Loading {base}…  {percent:.1f}%  {pkts:,} packets  "
                f"({_fmt_bytes(float(total_bytes))})"
            ))

        def worker() -> None:
            try:
                stats, duration, pkts, total_bytes = load_pcap_stats(path, on_progress)
                error = None
            except Exception as exc:
                stats = duration = pkts = total_bytes = None
                error = exc
            self.root.after(
                0,
                lambda: self._on_pcap_loaded(path, stats, duration, pkts, total_bytes, error, dialog),
            )

        threading.Thread(target=worker, daemon=True).start()

    def _on_pcap_loaded(self, path, stats, duration, pkts, total_bytes, error, dialog) -> None:
        dialog.close()
        self._btn_start.config(state="normal")
        if error is not None:
            self._status.set("Ready.")
            messagebox.showerror("Open pcap error", f"Failed to read {path}:\n{error}")
            return
        self._total_pkts  = pkts
        self._total_bytes = total_bytes
        self._redraw(stats, duration)
        self._status.set(
            f"Loaded {os.path.basename(path)}   "
            f"packets: {pkts:,}   "
            f"total: {_fmt_bytes(float(total_bytes))}   "
            f"duration: {duration:.3f} s"
        )

    # ── display refresh ───────────────────────────────────────────────────

    def _refresh(self) -> None:
        now = time.monotonic()
        with self._lock:
            snap            = {p: dict(keys) for p, keys in self._cur.items()}
            win_dur         = max(now - self._win_start, 0.001)
            self._cur       = defaultdict(lambda: defaultdict(int))
            self._win_start = now
            t_pkts          = self._total_pkts
            t_bytes         = self._total_bytes

        self._redraw(snap, win_dur)

        if self._start_time is not None:
            up   = int(now - self._start_time)
            h, r = divmod(up, 3600); m, s = divmod(r, 60)
            bk   = self._engine.backend if self._engine else "-"
            self._status.set(
                f"Capturing on {self._iface_var.get()}   "
                f"backend: {bk}   "
                f"packets: {t_pkts:,}   "
                f"total: {_fmt_bytes(float(t_bytes))}   "
                f"uptime: {h:02d}:{m:02d}:{s:02d}"
            )

        if self._engine and self._engine.running:
            self._after_id = self.root.after(self._REFRESH_MS, self._refresh)

    def _enabled_protos(self) -> frozenset:
        return frozenset(name for name, var in self._proto_vars.items() if var.get())

    def _on_proto_toggle(self) -> None:
        """Detail checkboxes only change how already-captured data is displayed,
        so re-render immediately from the last snapshot instead of waiting for
        the next capture tick (or doing nothing if nothing has run yet)."""
        self._redraw(self._last_snap, self._last_win_dur)

    def _redraw(self, snap: dict, win_dur: float) -> None:
        self._last_snap    = snap
        self._last_win_dur = win_dur

        for item in self._tree.get_children():
            self._tree.delete(item)

        enabled     = self._enabled_protos()
        grand_total = 0.0

        for proto in PROTO_ORDER:
            if proto not in enabled or proto not in snap:
                continue
            sub = [
                (vlan, cos, redund, appid, svid, noasdu, confrev, sim, cnt / win_dur)
                for (vlan, cos, redund, appid, svid, noasdu, confrev, sim), cnt
                in sorted(snap[proto].items())
            ]
            proto_total  = sum(r for *_, r in sub)
            grand_total += proto_total

            for vlan, cos, redund, appid, svid, noasdu, confrev, sim, rate in sub:
                pct  = rate / self._link_bytes_s * 100.0
                vals = (proto, vlan, cos, redund, appid, svid, noasdu, confrev,
                        sim, _fmt_bits(rate * 8), f"{pct:.3f}%")
                self._tree.insert("", "end", values=vals)

            if len(sub) > 1:
                sp   = proto_total / self._link_bytes_s * 100.0
                vals = (f"  ∑ {proto}", "", "", "", "", "", "", "", "",
                        _fmt_bits(proto_total * 8), f"{sp:.3f}%")
                self._tree.insert("", "end", values=vals, tags=("subtot",))

        # All protocols that aren't individually enabled aggregated into "Other"
        other_rate = sum(
            cnt / win_dur
            for p, keys in snap.items()
            if p not in enabled
            for cnt in keys.values()
        )
        grand_total += other_rate
        if other_rate > 0:
            op   = other_rate / self._link_bytes_s * 100.0
            vals = ("Other", "-", "-", "-", "-", "-", "-", "-", "-",
                    _fmt_bits(other_rate * 8), f"{op:.3f}%")
            self._tree.insert("", "end", values=vals)

        # Grand total row
        tp   = grand_total / self._link_bytes_s * 100.0
        vals = ("TOTAL", "", "", "", "", "", "", "", "",
                _fmt_bits(grand_total * 8), f"{tp:.3f}%")
        self._tree.insert("", "end", values=vals, tags=("total",))

        self._autofit_columns()

    def _autofit_columns(self) -> None:
        """Resize each column to exactly fit its widest content (header or cell)."""
        pad = 20   # pixels of horizontal padding per cell
        for col in _COLS:
            w = self._font.measure(col) + pad
            for iid in self._tree.get_children():
                cell = self._tree.set(iid, col)
                if cell:
                    w = max(w, self._font.measure(cell) + pad)
            self._tree.column(col, width=w)

    # ── CSV export ────────────────────────────────────────────────────────

    def _export_csv(self) -> None:
        rows = [
            dict(zip(_COLS, self._tree.item(iid, "values")))
            for iid in self._tree.get_children()
        ]
        if not rows:
            messagebox.showinfo("Export CSV", "No data to export — run a capture first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"network_monitor_{datetime.now():%Y%m%d_%H%M%S}.csv",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(_COLS))
                w.writeheader()
                w.writerows(rows)
            messagebox.showinfo(
                "Export CSV",
                f"Saved {len(rows)} rows to:\n{path}",
            )
        except OSError as exc:
            messagebox.showerror("Export error", str(exc))

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About",
            f"{SOFTWARE_NAME}\n"
            f"Version: {__version__}\n"
            f"License: {LICENSE_NAME}",
        )

    def on_close(self) -> None:
        self._on_stop()
        self.root.destroy()


# ── entry point ───────────────────────────────────────────────────────────────

def _show_callback_exception(exc_type, exc_value, exc_tb) -> None:
    # The --noconsole Windows build has nowhere to print unhandled exceptions
    # from Tkinter callbacks (Tk's default handler writes to stderr), so a bug
    # here would otherwise look like the UI silently doing nothing on click.
    messagebox.showerror(
        "Unexpected error",
        "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
    )


def main() -> None:
    root = tk.Tk()
    root.report_callback_exception = _show_callback_exception
    app  = MonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
