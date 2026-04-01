"""
exporter.py — Flow & Packet Data Exporter
Exports completed flows and alerts to CSV and JSON formats.
Supports both real-time streaming writes and batch dump modes.
"""

import csv
import json
import os
import time
import threading
from typing import List
from flow_tracker import FlowRecord


# ── CSV column schema ─────────────────────────────────────────────────────────
FLOW_CSV_COLUMNS = [
    "flow_key", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "service", "l7_proto", "tls_detected",
    "duration", "fwd_pkt_count", "bwd_pkt_count", "total_packets",
    "fwd_bytes", "bwd_bytes", "total_bytes",
    "flow_pkt_rate", "flow_byte_rate",
    "pkt_len_mean", "pkt_len_std",
    "iat_mean", "iat_max",
    "mean_entropy",
    "tcp_flags",
    "dns_queries", "http_methods", "http_hosts",
    "start_time", "end_time",
]


class FlowExporter:
    """
    Thread-safe flow exporter. Writes completed flows to CSV and JSON files
    in real-time as they expire from the flow table.
    """

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.csv_path   = os.path.join(output_dir, f"flows_{timestamp}.csv")
        self.json_path  = os.path.join(output_dir, f"flows_{timestamp}.jsonl")
        self.alert_path = os.path.join(output_dir, f"alerts_{timestamp}.jsonl")

        self._lock = threading.Lock()
        self._flow_count = 0

        # Initialize CSV with header
        with open(self.csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FLOW_CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()

        print(f"[Exporter] CSV  → {self.csv_path}")
        print(f"[Exporter] JSON → {self.json_path}")
        print(f"[Exporter] Alerts → {self.alert_path}")

    def write_flow(self, flow: FlowRecord):
        """
        Write a single completed flow. Called by FlowTracker's on_expire callback.
        Thread-safe — multiple worker threads can call this simultaneously.
        """
        d = flow.to_dict()
        # Serialize list fields for CSV compatibility
        csv_row = d.copy()
        csv_row["tcp_flags"]   = "|".join(d.get("tcp_flags", []))
        csv_row["dns_queries"] = "|".join(d.get("dns_queries", []))
        csv_row["http_methods"]= "|".join(d.get("http_methods", []))
        csv_row["http_hosts"]  = "|".join(d.get("http_hosts", []))

        with self._lock:
            # Append to CSV
            with open(self.csv_path, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=FLOW_CSV_COLUMNS, extrasaction="ignore")
                writer.writerow(csv_row)

            # Append to JSONL (one JSON object per line)
            with open(self.json_path, "a") as f:
                f.write(json.dumps(d) + "\n")

            self._flow_count += 1

    def write_alert(self, alert: dict):
        """Append a single alert to the alert JSONL file."""
        with self._lock:
            with open(self.alert_path, "a") as f:
                f.write(json.dumps(alert) + "\n")

    def dump_summary(self, summary: dict):
        """Write a session summary JSON file."""
        summary_path = os.path.join(self.output_dir, "session_summary.json")
        with self._lock:
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2, default=str)
        print(f"[Exporter] Summary written → {summary_path}")

    @property
    def flow_count(self) -> int:
        return self._flow_count

    def get_paths(self) -> dict:
        return {
            "csv":   self.csv_path,
            "jsonl": self.json_path,
            "alerts": self.alert_path,
        }
