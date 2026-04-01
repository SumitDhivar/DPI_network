#!/usr/bin/env python3
"""
main.py — DPI Packet Capture & Analysis Engine
Entry point. Wires together capture → parse → analyze → display → export.

Usage:
    sudo python3 main.py                         # Auto-detect interface
    sudo python3 main.py -i eth0                 # Specific interface
    sudo python3 main.py -i eth0 -f "tcp port 80"# With BPF filter
    sudo python3 main.py -i eth0 --no-display    # Headless mode (CSV only)
    sudo python3 main.py --list-ifaces           # List available interfaces

Requirements:
    sudo apt install python3-pip libpcap-dev
    pip3 install scapy
"""

import argparse
import signal
import sys
import time
import threading
import logging

# ── Logging setup (file only — dashboard owns stdout) ─────────────────────────
logging.basicConfig(
    filename="dpi.log",
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def parse_args():
    ap = argparse.ArgumentParser(
        description="DPI Packet Capture & Analysis Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("-i", "--iface",       default=None, help="Network interface (default: auto)")
    ap.add_argument("-f", "--filter",      default="",   help="BPF capture filter (e.g. 'tcp port 443')")
    ap.add_argument("-c", "--count",       default=0, type=int, help="Max packets (0=unlimited)")
    ap.add_argument("-o", "--output",      default="./output", help="Output directory for CSV/JSON")
    ap.add_argument("-r", "--refresh",     default=1.0, type=float, help="Dashboard refresh rate (seconds)")
    ap.add_argument("--no-display",        action="store_true", help="Disable live dashboard (headless mode)")
    ap.add_argument("--list-ifaces",       action="store_true", help="List available network interfaces")
    return ap.parse_args()


def list_interfaces():
    """Print available network interfaces."""
    from scapy.all import get_if_list, get_if_addr
    print("\nAvailable interfaces:")
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
            print(f"  {iface:<20}  {addr}")
        except Exception:
            print(f"  {iface:<20}  (no address)")
    print()


def processing_worker(parser_module, analyzer, flow_tracker):
    """
    Worker thread: drains the ring buffer, parses each packet,
    feeds the analyzer and flow tracker.
    """
    import capture
    buf = capture.RING_BUFFER

    while True:
        try:
            pkt = buf.get(timeout=0.5)
            pmo = parser_module.parse(pkt)
            if pmo:
                analyzer.ingest(pmo)
                flow_tracker.process(pmo)
        except Exception:
            pass  # Empty queue timeout — just keep looping


def main():
    args = parse_args()

    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)

    print("\n" + "═" * 60)
    print("  DPI Packet Capture & Analysis Engine")
    print("  Python / Scapy Stack")
    print("═" * 60)
    print(f"  Interface : {args.iface or 'auto-detect'}")
    print(f"  Filter    : '{args.filter}' (empty = all traffic)")
    print(f"  Output    : {args.output}")
    print(f"  Headless  : {args.no_display}")
    print("═" * 60 + "\n")

    # ── Import modules ────────────────────────────────────────────────────
    import capture
    import parser as pkt_parser
    import analyzer as analyzer_module
    import flow_tracker as ft_module
    import exporter as exp_module
    import display as disp_module

    # ── Initialize components ─────────────────────────────────────────────
    exporter = exp_module.FlowExporter(output_dir=args.output)

    def on_flow_expire(flow):
        exporter.write_flow(flow)
        analyzer.ingest_flow(flow)

    flow_tracker = ft_module.FlowTracker(on_expire=on_flow_expire)
    analyzer     = analyzer_module.TrafficAnalyzer()

    # ── Graceful shutdown ─────────────────────────────────────────────────
    stop_event = threading.Event()

    def shutdown(sig=None, frame=None):
        print("\n\n  Shutting down... writing final output.")
        stop_event.set()

        # Force-flush active flows
        with flow_tracker._lock:
            for flow in list(flow_tracker._table.values()):
                exporter.write_flow(flow)
            flow_tracker._table.clear()

        # Write session summary
        summary = analyzer.get_summary()
        summary["alerts"] = analyzer.get_alerts()
        exporter.dump_summary(summary)

        paths = exporter.get_paths()
        print(f"\n  Exported {exporter.flow_count} flows:")
        for k, v in paths.items():
            print(f"    {k.upper():8} → {v}")
        print(f"\n  Total packets : {summary['total_packets']:,}")
        print(f"  Total bytes   : {summary['total_bytes']:,}")
        print(f"  Alerts        : {summary['alert_count']}")
        print(f"\n  Goodbye.\n")
        time.sleep(0.3) 
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start capture thread ──────────────────────────────────────────────
    capture.start_capture(
        iface=args.iface,
        bpf_filter=args.filter,
        count=args.count,
        stop_event=stop_event,
    )

    # ── Start N parser/analysis worker threads ────────────────────────────
    N_WORKERS = 4
    for i in range(N_WORKERS):
        t = threading.Thread(
            target=processing_worker,
            args=(pkt_parser, analyzer, flow_tracker),
            name=f"Worker-{i}",
            daemon=True,
        )
        t.start()
    logger.info(f"{N_WORKERS} worker threads started.")

    # ── Start dashboard ───────────────────────────────────────────────────
    if not args.no_display:
        dashboard = disp_module.Dashboard(
            analyzer=analyzer,
            flow_tracker=flow_tracker,
            refresh_rate=args.refresh,
        )
        dashboard.start()
    else:
        print("[Headless mode] Capturing... press Ctrl+C to stop and export.")

    # ── Main thread: stay alive ───────────────────────────────────────────
    while not stop_event.is_set():
        time.sleep(0.5)

    shutdown()


if __name__ == "__main__":
    main()
