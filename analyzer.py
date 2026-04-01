"""
analyzer.py — Real-Time Traffic Analyzer & Anomaly Detector
Maintains live counters, generates per-session summaries, and runs
lightweight heuristic threat detection on incoming PMOs and flows.
"""

import time
import threading
from collections import defaultdict, deque
from typing import List, Dict, Optional
from parser import PacketMetadata
from flow_tracker import FlowRecord

# ── Anomaly thresholds (tune to your environment) ────────────────────────────
PORTSCAN_THRESHOLD       = 20    # distinct dst_ports from same src_ip in WINDOW_SEC
PORTSCAN_WINDOW_SEC      = 10
SYN_FLOOD_THRESHOLD      = 200   # SYN packets/sec from same src_ip
HIGH_ENTROPY_THRESHOLD   = 7.2   # bits — flags possible C2/encrypted tunnel
LARGE_FLOW_BYTES         = 50_000_000  # 50 MB — large data exfil candidate
ICMP_FLOOD_THRESHOLD     = 100   # ICMP packets/sec from same src_ip
TTL_ANOMALY_DEVIATION    = 8     # TTL deviation from expected baseline

# Expected initial TTL baselines
TTL_BASELINES = [32, 64, 128, 255]

# Bogon / RFC1918 private ranges (simplified check)
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "169.254.")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _expected_ttl_baseline(observed_ttl: int) -> int:
    return min(TTL_BASELINES, key=lambda b: abs(b - observed_ttl))


class TrafficAnalyzer:
    """
    Thread-safe real-time traffic statistics and anomaly detector.
    Feed packets via .ingest(pmo) and completed flows via .ingest_flow(flow).
    Query state at any time for dashboards and exports.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # ── Global counters ───────────────────────────────────────────────
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_time: float = time.time()

        # ── Protocol distribution ─────────────────────────────────────────
        self.proto_count: Dict[str, int] = defaultdict(int)   # TCP/UDP/ICMP/ARP
        self.l7_count: Dict[str, int]    = defaultdict(int)   # HTTP/DNS/TLS/etc.
        self.service_count: Dict[str, int] = defaultdict(int)

        # ── Top talkers ───────────────────────────────────────────────────
        self.src_ip_bytes: Dict[str, int]    = defaultdict(int)
        self.dst_ip_bytes: Dict[str, int]    = defaultdict(int)
        self.src_ip_packets: Dict[str, int]  = defaultdict(int)
        self.dst_ip_packets: Dict[str, int]  = defaultdict(int)

        # ── Sliding window for rate-based detection ────────────────────────
        # deque of (timestamp, src_ip, event_type) tuples
        self._event_window: deque = deque()

        # ── Per-IP port tracking (port scan detection) ────────────────────
        self._ip_ports: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))

        # ── Per-IP SYN rate tracking ──────────────────────────────────────
        self._syn_events: deque = deque()

        # ── Completed flows log ───────────────────────────────────────────
        self.completed_flows: List[dict] = []

        # ── Alerts ────────────────────────────────────────────────────────
        self.alerts: List[dict] = []

        # ── Per-second throughput history (last 60 seconds) ───────────────
        self._bps_window: deque  = deque(maxlen=60)
        self._pps_window: deque  = deque(maxlen=60)
        self._last_tick: float   = time.time()
        self._tick_bytes: int    = 0
        self._tick_pkts: int     = 0
        self._start_tick_loop()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def ingest(self, pmo: PacketMetadata):
        """Process one parsed packet. Call from the parser worker thread."""
        if pmo is None:
            return
        with self._lock:
            self.total_packets += 1
            self.total_bytes += pmo.wire_length
            self._tick_bytes += pmo.wire_length
            self._tick_pkts += 1

            # Protocol counts
            self.proto_count[pmo.l4_proto] += 1
            if pmo.l7_proto:
                self.l7_count[pmo.l7_proto] += 1
            if pmo.service:
                self.service_count[pmo.service] += 1

            # Top talkers
            if pmo.src_ip:
                self.src_ip_bytes[pmo.src_ip] += pmo.wire_length
                self.src_ip_packets[pmo.src_ip] += 1
            if pmo.dst_ip:
                self.dst_ip_bytes[pmo.dst_ip] += pmo.wire_length
                self.dst_ip_packets[pmo.dst_ip] += 1

            # Anomaly checks
            self._check_anomalies(pmo)

    def ingest_flow(self, flow: FlowRecord):
        """Process a completed flow record."""
        with self._lock:
            d = flow.to_dict()
            self.completed_flows.append(d)
            # Keep last 10,000 flows in memory
            if len(self.completed_flows) > 10_000:
                self.completed_flows = self.completed_flows[-10_000:]
            self._check_flow_anomalies(flow)

    def get_summary(self) -> dict:
        """Return a snapshot of current statistics."""
        with self._lock:
            elapsed = max(time.time() - self.start_time, 1)
            top_src = sorted(self.src_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            top_dst = sorted(self.dst_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            top_services = sorted(self.service_count.items(), key=lambda x: x[1], reverse=True)[:10]

            return {
                "elapsed_sec":    round(elapsed, 1),
                "total_packets":  self.total_packets,
                "total_bytes":    self.total_bytes,
                "avg_pps":        round(self.total_packets / elapsed, 2),
                "avg_bps":        round(self.total_bytes / elapsed, 2),
                "proto_dist":     dict(self.proto_count),
                "l7_dist":        dict(self.l7_count),
                "top_src_ips":    top_src,
                "top_dst_ips":    top_dst,
                "top_services":   top_services,
                "alert_count":    len(self.alerts),
                "flow_count":     len(self.completed_flows),
                "bps_history":    list(self._bps_window),
                "pps_history":    list(self._pps_window),
            }

    def get_alerts(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return self.alerts[-limit:]

    # ─────────────────────────────────────────────────────────────────────────
    # Internal anomaly detection
    # ─────────────────────────────────────────────────────────────────────────

    def _alert(self, alert_type: str, severity: str, src_ip: str, detail: str):
        alert = {
            "timestamp": time.time(),
            "type": alert_type,
            "severity": severity,   # LOW / MEDIUM / HIGH / CRITICAL
            "src_ip": src_ip,
            "detail": detail,
        }
        self.alerts.append(alert)
        print(f"\n  [!] ALERT [{severity}] {alert_type} — {src_ip}: {detail}")

    def _check_anomalies(self, pmo: PacketMetadata):
        """Packet-level heuristic checks (called under _lock)."""
        now = pmo.timestamp or time.time()
        src = pmo.src_ip

        # 1. Port scan detection — many unique dst_ports from same src in window
        if pmo.l4_proto in ("TCP", "UDP") and pmo.dst_port:
            self._ip_ports[src].append((now, pmo.dst_port))
            recent = [(t, p) for t, p in self._ip_ports[src] if now - t < PORTSCAN_WINDOW_SEC]
            unique_ports = len(set(p for _, p in recent))
            if unique_ports > PORTSCAN_THRESHOLD:
                self._alert("PORT_SCAN", "HIGH", src,
                            f"{unique_ports} unique ports in {PORTSCAN_WINDOW_SEC}s")
                self._ip_ports[src].clear()

        # 2. SYN flood detection
        if "SYN" in pmo.tcp_flags and "ACK" not in pmo.tcp_flags:
            self._syn_events.append((now, src))
            # Purge old events
            while self._syn_events and now - self._syn_events[0][0] > 1.0:
                self._syn_events.popleft()
            syn_from_src = sum(1 for _, s in self._syn_events if s == src)
            if syn_from_src > SYN_FLOOD_THRESHOLD:
                self._alert("SYN_FLOOD", "CRITICAL", src,
                            f"{syn_from_src} SYN/sec (threshold={SYN_FLOOD_THRESHOLD})")
                self._syn_events = deque((t, s) for t, s in self._syn_events if s != src)

        # 3. High-entropy payload (possible C2 / encrypted tunnel)
        if pmo.payload_entropy > HIGH_ENTROPY_THRESHOLD and pmo.payload_length > 200 and pmo.dst_port not in (443, 8443) and pmo.src_port not in (443, 8443):
                    self._alert("HIGH_ENTROPY", "MEDIUM", src,
                        f"Entropy={pmo.payload_entropy:.2f} on {pmo.l4_proto}/{pmo.dst_port}")

        # 4. TTL anomaly
        if pmo.ttl > 0 and pmo.l4_proto in ("TCP", "UDP"):
            baseline = _expected_ttl_baseline(pmo.ttl)
            if abs(baseline - pmo.ttl) > TTL_ANOMALY_DEVIATION:
                self._alert("TTL_ANOMALY", "LOW", src,
                            f"TTL={pmo.ttl} baseline={baseline}")

        # 5. External src_ip in packet claiming to be internal (basic spoof check)
        if (not _is_private(src) and pmo.dst_ip and _is_private(pmo.dst_ip)
                and "SYN" in pmo.tcp_flags):
            pass  # Log only — false positive rate is high without full context

    def _check_flow_anomalies(self, flow: FlowRecord):
        """Flow-level anomaly checks (called under _lock)."""
        # Large data transfer (exfil candidate)
        if flow.total_bytes > LARGE_FLOW_BYTES:
            self._alert("LARGE_FLOW", "MEDIUM", flow.src_ip,
                        f"{flow.total_bytes/1e6:.1f} MB transferred to {flow.dst_ip}:{flow.dst_port}")

        # High mean entropy over entire flow (tunnel / C2)
        if flow.mean_entropy > HIGH_ENTROPY_THRESHOLD and flow.total_bytes > 10_000:
            self._alert("ENCRYPTED_TUNNEL", "MEDIUM", flow.src_ip,
                        f"mean_entropy={flow.mean_entropy:.2f} l7={flow.l7_proto}")

        # RST storm
        if flow.tcp_flags_seen.count("RST") > 10:
            self._alert("RST_STORM", "LOW", flow.src_ip,
                        f"{flow.tcp_flags_seen.count('RST')} RSTs in single flow")

    # ─────────────────────────────────────────────────────────────────────────
    # Throughput tick loop
    # ─────────────────────────────────────────────────────────────────────────

    def _start_tick_loop(self):
        def _tick():
            while True:
                time.sleep(1.0)
                with self._lock:
                    self._bps_window.append(self._tick_bytes)
                    self._pps_window.append(self._tick_pkts)
                    self._tick_bytes = 0
                    self._tick_pkts  = 0
        t = threading.Thread(target=_tick, name="ThroughputTick", daemon=True)
        t.start()
