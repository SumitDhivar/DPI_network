"""
flow_tracker.py — Bidirectional Flow Aggregator
Maintains a 5-tuple keyed flow table. Accumulates per-flow statistics
and flushes completed flows on timeout or TCP FIN/RST.
"""

import time
import threading
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from parser import PacketMetadata

# Timeout configuration (seconds)
ACTIVE_TIMEOUT = 120   # Max flow lifetime
IDLE_TIMEOUT   = 30    # Flush if no packets for this long
CLEANUP_INTERVAL = 5   # How often the reaper thread runs


@dataclass
class FlowRecord:
    """Bidirectional flow with accumulated statistics."""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    service: str
    l7_proto: str

    # Timing
    start_time: float = 0.0
    last_time: float = 0.0

    # Packet counts
    fwd_pkt_count: int = 0
    bwd_pkt_count: int = 0

    # Byte counts
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Packet lengths (for statistics)
    pkt_lengths: List[int] = field(default_factory=list)

    # Inter-arrival times
    iat_list: List[float] = field(default_factory=list)
    _last_pkt_time: float = field(default=0.0, repr=False)

    # TCP flags seen in flow
    tcp_flags_seen: List[str] = field(default_factory=list)

    # Payload entropy samples
    entropy_samples: List[float] = field(default_factory=list)

    # DNS queries seen in flow
    dns_queries: List[str] = field(default_factory=list)

    # HTTP metadata
    http_methods: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)

    # TLS presence
    tls_detected: bool = False

    def update(self, pmo: PacketMetadata, direction: str):
        now = pmo.timestamp
        self.last_time = now

        if self._last_pkt_time > 0:
            iat = now - self._last_pkt_time
            self.iat_list.append(round(iat, 6))
        self._last_pkt_time = now

        pkt_len = pmo.wire_length
        self.pkt_lengths.append(pkt_len)

        if direction == "fwd":
            self.fwd_pkt_count += 1
            self.fwd_bytes += pkt_len
        else:
            self.bwd_pkt_count += 1
            self.bwd_bytes += pkt_len

        if pmo.tcp_flags:
            self.tcp_flags_seen.extend(pmo.tcp_flags)

        if pmo.payload_entropy > 0:
            self.entropy_samples.append(pmo.payload_entropy)

        if pmo.dns_query:
            if pmo.dns_query not in self.dns_queries:
                self.dns_queries.append(pmo.dns_query)

        if pmo.http_method:
            self.http_methods.append(pmo.http_method)
        if pmo.http_host and pmo.http_host not in self.http_hosts:
            self.http_hosts.append(pmo.http_host)

        if pmo.tls_detected:
            self.tls_detected = True

        if pmo.l7_proto and pmo.l7_proto != "UNKNOWN":
            self.l7_proto = pmo.l7_proto

    @property
    def duration(self) -> float:
        return round(max(0.0, self.last_time - self.start_time), 6)

    @property
    def total_packets(self) -> int:
        return self.fwd_pkt_count + self.bwd_pkt_count

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def flow_pkt_rate(self) -> float:
        return round(self.total_packets / max(self.duration, 1e-9), 4)

    @property
    def flow_byte_rate(self) -> float:
        return round(self.total_bytes / max(self.duration, 1e-9), 4)

    @property
    def pkt_len_mean(self) -> float:
        return round(statistics.mean(self.pkt_lengths), 2) if self.pkt_lengths else 0.0

    @property
    def pkt_len_std(self) -> float:
        return round(statistics.stdev(self.pkt_lengths), 2) if len(self.pkt_lengths) > 1 else 0.0

    @property
    def iat_mean(self) -> float:
        return round(statistics.mean(self.iat_list), 6) if self.iat_list else 0.0

    @property
    def iat_max(self) -> float:
        return round(max(self.iat_list), 6) if self.iat_list else 0.0

    @property
    def mean_entropy(self) -> float:
        return round(statistics.mean(self.entropy_samples), 4) if self.entropy_samples else 0.0

    @property
    def unique_tcp_flags(self) -> List[str]:
        return list(set(self.tcp_flags_seen))

    def is_expired(self, now: float) -> bool:
        if (now - self.last_time) > IDLE_TIMEOUT:
            return True
        if (now - self.start_time) > ACTIVE_TIMEOUT:
            return True
        if "FIN" in self.tcp_flags_seen and "ACK" in self.tcp_flags_seen:
            return True
        if "RST" in self.tcp_flags_seen:
            return True
        return False

    def to_dict(self) -> dict:
        return {
            "flow_key":       self.flow_key,
            "src_ip":         self.src_ip,
            "dst_ip":         self.dst_ip,
            "src_port":       self.src_port,
            "dst_port":       self.dst_port,
            "protocol":       self.protocol,
            "service":        self.service,
            "l7_proto":       self.l7_proto,
            "tls_detected":   self.tls_detected,
            "duration":       self.duration,
            "fwd_pkt_count":  self.fwd_pkt_count,
            "bwd_pkt_count":  self.bwd_pkt_count,
            "total_packets":  self.total_packets,
            "fwd_bytes":      self.fwd_bytes,
            "bwd_bytes":      self.bwd_bytes,
            "total_bytes":    self.total_bytes,
            "flow_pkt_rate":  self.flow_pkt_rate,
            "flow_byte_rate": self.flow_byte_rate,
            "pkt_len_mean":   self.pkt_len_mean,
            "pkt_len_std":    self.pkt_len_std,
            "iat_mean":       self.iat_mean,
            "iat_max":        self.iat_max,
            "mean_entropy":   self.mean_entropy,
            "tcp_flags":      self.unique_tcp_flags,
            "dns_queries":    self.dns_queries,
            "http_methods":   self.http_methods,
            "http_hosts":     self.http_hosts,
            "start_time":     round(self.start_time, 3),
            "end_time":       round(self.last_time, 3),
        }


def _canonical_key(pmo: PacketMetadata) -> str:
    """Sort the 5-tuple so A→B and B→A map to the same flow key."""
    pair = sorted(
        [(pmo.src_ip, pmo.src_port), (pmo.dst_ip, pmo.dst_port)]
    )
    return f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{pmo.l4_proto}"


def _direction(pmo: PacketMetadata) -> str:
    """Determine if packet is forward (fwd) or backward (bwd) within its flow."""
    pair = sorted([(pmo.src_ip, pmo.src_port), (pmo.dst_ip, pmo.dst_port)])
    if (pmo.src_ip, pmo.src_port) == pair[0]:
        return "fwd"
    return "bwd"


class FlowTracker:
    """Thread-safe flow table with background expiry reaper."""

    def __init__(self, on_expire=None):
        """
        Args:
            on_expire: Callable(FlowRecord) called when a flow expires.
                       Useful for emitting flows to Kafka, CSV, etc.
        """
        self._table: Dict[str, FlowRecord] = {}
        self._lock = threading.Lock()
        self._on_expire = on_expire
        self._completed: List[FlowRecord] = []
        self._start_reaper()

    def process(self, pmo: PacketMetadata):
        """Ingest a parsed packet into the flow table."""
        if not pmo or not pmo.src_ip:
            return
        key = _canonical_key(pmo)
        direction = _direction(pmo)
        now = pmo.timestamp

        with self._lock:
            if key not in self._table:
                self._table[key] = FlowRecord(
                    flow_key=key,
                    src_ip=pmo.src_ip,
                    dst_ip=pmo.dst_ip,
                    src_port=pmo.src_port,
                    dst_port=pmo.dst_port,
                    protocol=pmo.l4_proto,
                    service=pmo.service,
                    l7_proto=pmo.l7_proto,
                    start_time=now,
                    last_time=now,
                    _last_pkt_time=now,
                )
            self._table[key].update(pmo, direction)

    def get_active_flows(self) -> List[FlowRecord]:
        with self._lock:
            return list(self._table.values())

    def get_completed_flows(self) -> List[FlowRecord]:
        with self._lock:
            completed = self._completed.copy()
            self._completed.clear()
            return completed

    def _reap(self):
        """Remove expired flows from the table and fire the callback."""
        now = time.time()
        expired_keys = []
        with self._lock:
            for key, flow in self._table.items():
                if flow.is_expired(now):
                    expired_keys.append(key)
            for key in expired_keys:
                flow = self._table.pop(key)
                self._completed.append(flow)
                if self._on_expire:
                    self._on_expire(flow)

    def _start_reaper(self):
        def _loop():
            while True:
                time.sleep(CLEANUP_INTERVAL)
                self._reap()
        t = threading.Thread(target=_loop, name="FlowReaper", daemon=True)
        t.start()
