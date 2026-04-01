"""
display.py — Real-Time Terminal Dashboard
Renders a live terminal-based dashboard using ANSI escape sequences.
Refresh rate is configurable (default 1s). No third-party TUI library needed.
"""

import os
import sys
import time
import threading
from typing import Optional
from capture import get_stats as capture_stats

# ── ANSI color codes ──────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BG_DARK= "\033[40m"

def _clear():
    os.system("clear" if os.name == "posix" else "cls")

def _hr(width=70, char="─", color=DIM):
    return f"{color}{char * width}{RESET}"

def _bar(value: int, max_val: int, width: int = 20, color: str = CYAN) -> str:
    if max_val == 0:
        return " " * width
    filled = int(round(value / max_val * width))
    filled = max(0, min(filled, width))
    return f"{color}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"

def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

def _severity_color(severity: str) -> str:
    return {"LOW": BLUE, "MEDIUM": YELLOW, "HIGH": RED, "CRITICAL": f"{RED}{BOLD}"}.get(severity, WHITE)


class Dashboard:
    """
    Live terminal dashboard. Call .start() to begin rendering.
    Access .latest_summary and .latest_alerts from the outside.
    """

    def __init__(self, analyzer, flow_tracker, refresh_rate: float = 1.0):
        self.analyzer      = analyzer
        self.flow_tracker  = flow_tracker
        self.refresh_rate  = refresh_rate
        self._running      = False
        self._show_flows   = True
        self._show_alerts  = True

    def start(self):
        self._running = True
        t = threading.Thread(target=self._render_loop, name="Dashboard", daemon=True)
        t.start()

    def stop(self):
        self._running = False

    def _render_loop(self):
        while self._running:
            try:
                self._render()
            except Exception:
                pass
            time.sleep(self.refresh_rate)

    def _render(self):
        summary = self.analyzer.get_summary()
        alerts  = self.analyzer.get_alerts(limit=5)
        cap     = capture_stats()
        flows   = self.flow_tracker.get_active_flows()

        _clear()
        lines = []

        # ── Header ────────────────────────────────────────────────────────
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{BOLD}{CYAN}{'━'*70}{RESET}")
        lines.append(f"  {BOLD}{CYAN}⬡  DPI Network Monitor{RESET}  {DIM}{ts}{RESET}  "
                     f"{GREEN}● LIVE{RESET}")
        lines.append(f"{BOLD}{CYAN}{'━'*70}{RESET}")

        # ── Capture stats ─────────────────────────────────────────────────
        elapsed = summary.get("elapsed_sec", 0)
        lines.append(f"\n{BOLD}  CAPTURE{RESET}")
        lines.append(f"  Packets captured : {GREEN}{cap.get('captured', 0):,}{RESET}   "
                     f"Dropped: {RED}{cap.get('dropped', 0):,}{RESET}   "
                     f"PPS: {CYAN}{cap.get('pps', 0):.1f}{RESET}")
        lines.append(f"  Total bytes      : {CYAN}{_fmt_bytes(summary.get('total_bytes', 0))}{RESET}   "
                     f"Uptime: {elapsed:.0f}s   "
                     f"Alerts: {RED}{summary.get('alert_count', 0)}{RESET}")

        # ── Throughput sparkline (last 30s) ───────────────────────────────
        bps_hist = summary.get("bps_history", [])[-30:]
        pps_hist = summary.get("pps_history", [])[-30:]
        if bps_hist:
            max_bps = max(bps_hist) or 1
            spark_bps = "".join(
                "▁▂▃▄▅▆▇█"[min(7, int(v / max_bps * 7))] for v in bps_hist
            )
            lines.append(f"\n{BOLD}  THROUGHPUT  {DIM}(last 30s){RESET}")
            lines.append(f"  BPS  {CYAN}{spark_bps}{RESET}  {_fmt_bytes(bps_hist[-1])}/s")
            if pps_hist:
                max_pps = max(pps_hist) or 1
                spark_pps = "".join(
                    "▁▂▃▄▅▆▇█"[min(7, int(v / max_pps * 7))] for v in pps_hist
                )
                lines.append(f"  PPS  {GREEN}{spark_pps}{RESET}  {pps_hist[-1]} pkt/s")

        # ── Protocol distribution ─────────────────────────────────────────
        proto = summary.get("proto_dist", {})
        if proto:
            total_pkts = max(sum(proto.values()), 1)
            lines.append(f"\n{BOLD}  PROTOCOLS{RESET}")
            for p, count in sorted(proto.items(), key=lambda x: x[1], reverse=True):
                pct = count / total_pkts * 100
                bar = _bar(count, total_pkts, width=18)
                lines.append(f"  {p:<10} {bar}  {count:>6,}  {pct:5.1f}%")

        # ── L7 Application layer ──────────────────────────────────────────
        l7 = summary.get("l7_dist", {})
        if l7:
            total_l7 = max(sum(l7.values()), 1)
            lines.append(f"\n{BOLD}  APPLICATIONS  {DIM}(L7){RESET}")
            for proto_name, count in sorted(l7.items(), key=lambda x: x[1], reverse=True)[:6]:
                bar = _bar(count, total_l7, width=14)
                lines.append(f"  {proto_name:<12} {bar}  {count:>5,}")

        # ── Top Talkers ───────────────────────────────────────────────────
        top_src = summary.get("top_src_ips", [])[:5]
        if top_src:
            max_b = top_src[0][1] if top_src else 1
            lines.append(f"\n{BOLD}  TOP SOURCES{RESET}")
            for ip, b in top_src:
                bar = _bar(b, max_b, width=14)
                flag = f"{RED}[PRIV]{RESET}" if ip.startswith(("10.", "192.168.", "172.")) else f"{DIM}[EXT]{RESET}"
                lines.append(f"  {ip:<18} {bar}  {_fmt_bytes(b):>10}  {flag}")

        # ── Active flows ──────────────────────────────────────────────────
        if flows and self._show_flows:
            lines.append(f"\n{BOLD}  ACTIVE FLOWS{RESET}  {DIM}(top 8){RESET}")
            lines.append(f"  {DIM}{'SRC':>18}  {'DST':>18}  {'PROTO':<8}  {'PKTS':>6}  {'BYTES':>10}  {'L7':<10}{RESET}")
            lines.append(f"  {DIM}{'─'*66}{RESET}")
            for flow in sorted(flows, key=lambda f: f.total_bytes, reverse=True)[:8]:
                src = f"{flow.src_ip}:{flow.src_port}"
                dst = f"{flow.dst_ip}:{flow.dst_port}"
                lines.append(
                    f"  {src:>18}  {dst:>18}  "
                    f"{CYAN}{flow.protocol:<8}{RESET}  "
                    f"{flow.total_packets:>6,}  "
                    f"{_fmt_bytes(flow.total_bytes):>10}  "
                    f"{YELLOW}{flow.l7_proto:<10}{RESET}"
                )

        # ── Recent alerts ─────────────────────────────────────────────────
        if alerts and self._show_alerts:
            lines.append(f"\n{BOLD}  RECENT ALERTS{RESET}")
            for a in alerts[-4:]:
                ts_a = time.strftime("%H:%M:%S", time.localtime(a["timestamp"]))
                sev  = a["severity"]
                col  = _severity_color(sev)
                lines.append(
                    f"  {DIM}{ts_a}{RESET}  "
                    f"{col}[{sev:8}]{RESET}  "
                    f"{BOLD}{a['type']:<20}{RESET}  "
                    f"{a['src_ip']:<16}  {DIM}{a['detail'][:35]}{RESET}"
                )

        # ── Footer ────────────────────────────────────────────────────────
        lines.append(f"\n{DIM}{'─'*70}")
        lines.append(f"  Press Ctrl+C to stop  │  q=quit  │  Refresh: {self.refresh_rate}s{RESET}")

        print("\n".join(lines), flush=True)
