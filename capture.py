"""
capture.py — Packet Capture Engine
Handles raw packet capture using Scapy with a dedicated producer thread
feeding a thread-safe ring buffer for downstream consumers.
"""

import threading
import queue
import time
import logging
from scapy.all import sniff, conf

logger = logging.getLogger(__name__)

# Global ring buffer: capture thread → parser thread
RING_BUFFER = queue.Queue(maxsize=10000)
_capture_stats = {"captured": 0, "dropped": 0, "start_time": None}


def get_stats() -> dict:
    """Return current capture statistics."""
    stats = _capture_stats.copy()
    if stats["start_time"]:
        elapsed = time.time() - stats["start_time"]
        total = stats["captured"] + stats["dropped"]
        stats["elapsed_seconds"] = round(elapsed, 2)
        stats["pps"] = round(stats["captured"] / max(elapsed, 1), 2)
        stats["drop_rate"] = round(stats["dropped"] / max(total, 1) * 100, 2)
    return stats


def _packet_callback(pkt):
    """
    Called by Scapy for every captured packet (runs in capture thread).
    Enqueues packet into ring buffer — non-blocking to avoid slowing Scapy.
    """
    _capture_stats["captured"] += 1
    try:
        RING_BUFFER.put_nowait(pkt)
    except queue.Full:
        _capture_stats["dropped"] += 1
        logger.debug("Ring buffer full — packet dropped.")


def start_capture(
    iface: str = None,
    bpf_filter: str = "",
    count: int = 0,
    stop_event: threading.Event = None,
) -> threading.Thread:
    """
    Start packet capture in a background daemon thread.

    Args:
        iface:      Network interface (e.g. 'eth0', 'enp0s3'). None = auto-detect.
        bpf_filter: BPF filter string (e.g. 'tcp port 80', 'udp', 'icmp').
        count:      Max packets to capture (0 = unlimited).
        stop_event: threading.Event — set it to gracefully stop capture.

    Returns:
        The capture daemon thread (already started).
    """
    _capture_stats["start_time"] = time.time()
    _capture_stats["captured"] = 0
    _capture_stats["dropped"] = 0

    # Auto-detect interface if none given
    if iface is None:
        iface = conf.iface
        logger.info(f"Auto-selected interface: {iface}")

    def _run():
        logger.info(f"Capture started on '{iface}' | filter='{bpf_filter}' | count={count or 'unlimited'}")
        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=_packet_callback,
                count=count,
                store=False,
                stop_filter=lambda _: stop_event.is_set() if stop_event else False,
            )
        except PermissionError:
            logger.error("Permission denied. Run with: sudo python main.py")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            logger.info("Capture thread exiting.")

    t = threading.Thread(target=_run, name="CaptureThread", daemon=True)
    t.start()
    return t
