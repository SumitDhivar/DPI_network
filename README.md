# DPI Network Packet Capture & Analysis Engine

> A real-time Deep Packet Inspection (DPI) system built entirely in Python using Scapy.  
> Captures live network traffic, parses all protocol layers, aggregates bidirectional flows,  
> detects network anomalies, renders a live terminal dashboard, and exports structured data.

---

## Table of Contents

- [What This Project Does](#what-this-project-does)
- [Project Structure](#project-structure)
- [How It Works — Architecture](#how-it-works--architecture)
- [Data Flow Pipeline](#data-flow-pipeline)
- [File-by-File Breakdown](#file-by-file-breakdown)
- [Requirements & Installation](#requirements--installation)
- [Running the Project](#running-the-project)
- [Command-Line Options](#command-line-options)
- [Live Dashboard Explained](#live-dashboard-explained)
- [Output Files](#output-files)
- [Real Capture Output Example](#real-capture-output-example)
- [Flow Features Reference](#flow-features-reference)
- [Anomaly Detection Rules](#anomaly-detection-rules)
- [Protocol Detection Reference](#protocol-detection-reference)
- [Known Issues & Fixes](#known-issues--fixes)
- [Concepts Glossary](#concepts-glossary)

---

## What This Project Does

This system sits on your network interface and inspects every packet in real time. It:

- **Captures** raw packets from the wire using Scapy's `sniff()`
- **Parses** each packet across all network layers (L2 Ethernet → L7 Application)
- **Groups** packets into bidirectional conversations called *flows* using a 5-tuple key
- **Extracts** 25+ statistical features per flow (bytes, rates, entropy, flags, timing)
- **Detects** network anomalies: port scans, SYN floods, high-entropy payloads, large transfers
- **Displays** a live ANSI terminal dashboard refreshing every second
- **Exports** completed flows to CSV, JSONL, and a session summary JSON

No external dependencies beyond **Scapy**. No databases. No cloud services. Everything runs locally on your machine.

---

## Project Structure

```
DPI/
├── main.py            ← Entry point. Wires all modules, handles startup and shutdown.
├── capture.py         ← Packet capture engine. Scapy sniff() + ring buffer.
├── parser.py          ← Multi-layer packet dissector. Outputs PacketMetadata objects.
├── flow_tracker.py    ← Bidirectional flow table. 5-tuple keyed hash map with timeouts.
├── analyzer.py        ← Live traffic statistics and anomaly detection engine.
├── display.py         ← Real-time ANSI terminal dashboard. Redraws every 1 second.
├── exporter.py        ← Writes flows and alerts to CSV, JSONL, and JSON files.
├── requirements.txt   ← Single dependency: scapy>=2.5.0
├── dpi.log            ← Auto-created. Thread-level log of capture events.
└── output/            ← Auto-created on first run. All exported data lands here.
    ├── flows_YYYYMMDD_HHMMSS.csv
    ├── flows_YYYYMMDD_HHMMSS.jsonl
    ├── alerts_YYYYMMDD_HHMMSS.jsonl
    └── session_summary.json
```

---

## How It Works — Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      YOUR NETWORK CARD (NIC)                    │
│              enp0s3 / eth0 — raw frames arrive here             │
└──────────────────────────────┬──────────────────────────────────┘
                               │  Scapy sniff() — BPF filter applied
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   capture.py  (CaptureThread)                   │
│         Ring buffer: Queue(maxsize=10000) — lock-free           │
└──────────────────────────────┬──────────────────────────────────┘
                               │  4 Worker threads drain the queue
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    parser.py  (Worker-0..3)                     │
│   L2 Ethernet → L3 IPv4/IPv6 → L4 TCP/UDP/ICMP → L7 DPI        │
│   Output: PacketMetadata dataclass (30+ fields per packet)      │
└───────────────┬───────────────────────────┬─────────────────────┘
                │                           │
                ▼                           ▼
┌──────────────────────┐      ┌─────────────────────────────────┐
│   flow_tracker.py    │      │         analyzer.py             │
│  5-tuple hash map    │      │  Protocol counters, top talkers  │
│  Bidirectional flows │      │  Throughput history (60s window) │
│  Timeout reaper      │      │  6 anomaly detectors             │
└──────────┬───────────┘      └──────────────┬──────────────────┘
           │ on_expire()                      │
           ▼                                 ▼
┌──────────────────────┐      ┌─────────────────────────────────┐
│    exporter.py       │      │         display.py              │
│  flows_*.csv         │      │  Live ANSI terminal dashboard   │
│  flows_*.jsonl       │      │  Refresh rate: 1 second         │
│  alerts_*.jsonl      │      │  Sparklines, flow table, alerts  │
│  session_summary.json│      └─────────────────────────────────┘
└──────────────────────┘
```

### Thread Map

| Thread Name      | Count | Job                                              |
|------------------|-------|--------------------------------------------------|
| `CaptureThread`  | 1     | Runs `sniff()`, enqueues packets to ring buffer  |
| `Worker-N`       | 4     | Parses packets, updates flow table + analyzer    |
| `Dashboard`      | 1     | Redraws terminal every 1 second                  |
| `FlowReaper`     | 1     | Expires timed-out flows every 5 seconds          |
| `ThroughputTick` | 1     | Records bytes/pps per second into history        |

---

## Data Flow Pipeline

Every packet goes through these exact stages in order:

```
Stage 1 — CAPTURE
  NIC receives raw Ethernet frame
  Scapy copies it to your process (raw socket, requires sudo)
  BPF filter drops non-matching frames at kernel level
  Callback enqueues packet into ring buffer (non-blocking)

Stage 2 — PARSE
  Worker thread dequeues one packet
  parser.py strips layers top-down:
    Ethernet header → src/dst MAC, EtherType
    IP header       → src/dst IP, TTL, protocol
    TCP/UDP header  → src/dst port, flags, window
    Payload         → Shannon entropy, HTTP method, DNS query, TLS detection
  Returns PacketMetadata object

Stage 3 — FLOW AGGREGATION
  Canonical 5-tuple key computed (sorted so A→B == B→A)
  Looked up in flow_tracker's dict
  If new: FlowRecord created with start_time
  If existing: bytes/packets accumulated, IAT computed, flags merged
  If expired (FIN/RST/timeout): flow flushed and emitted

Stage 4 — ANALYSIS
  Every PacketMetadata fed to analyzer.ingest()
  Protocol counters incremented
  Top-talker bytes map updated
  Anomaly checks run (port scan window, SYN rate, entropy check, TTL)

Stage 5 — OUTPUT
  display.py reads analyzer.get_summary() every 1s → redraws screen
  exporter.py.write_flow() called on each expired flow → appends to CSV + JSONL
  On Ctrl+C: active flows force-flushed, session_summary.json written
```

---

## File-by-File Breakdown

### `main.py` — Entry Point

The orchestrator. Does not do any processing itself.

```python
# What it does:
# 1. Parses CLI arguments (interface, filter, output dir, etc.)
# 2. Creates: exporter, flow_tracker, analyzer, dashboard
# 3. Starts: capture thread, 4 worker threads, dashboard thread
# 4. Registers SIGINT/SIGTERM handler for clean shutdown
# 5. Waits until stop_event is set, then flushes and exits
```

**Key shutdown logic:**
```python
def shutdown(sig=None, frame=None):
    stop_event.set()
    # Force-flush all active flows still in the table
    for flow in list(flow_tracker._table.values()):
        exporter.write_flow(flow)
    # Write session summary
    exporter.dump_summary(analyzer.get_summary())
    sys.exit(0)
```

---

### `capture.py` — Packet Capture Engine

Interfaces with the OS network stack via Scapy's `sniff()`.

```python
# Key objects:
RING_BUFFER = queue.Queue(maxsize=10000)   # bounded queue (back-pressure)
_capture_stats = {"captured": 0, "dropped": 0}

# Callback (called by Scapy for every packet):
def _packet_callback(pkt):
    _capture_stats["captured"] += 1
    try:
        RING_BUFFER.put_nowait(pkt)   # non-blocking
    except queue.Full:
        _capture_stats["dropped"] += 1   # ring full — drop
```

**Why `put_nowait()`?** Scapy's callback runs in the capture thread. If it blocked waiting for space, packet capture would stall and the OS would drop frames at the kernel level. Non-blocking drops at the Python level are preferable.

**Why `store=False`?** Without this, Scapy accumulates every captured packet in a list in RAM. For a long capture this would exhaust memory. `store=False` tells Scapy to discard packets after the callback returns.

---

### `parser.py` — Multi-Layer Packet Dissector

Converts a raw Scapy packet object into a structured `PacketMetadata` dataclass.

```python
@dataclass
class PacketMetadata:
    timestamp: float       # exact capture time
    wire_length: int       # total bytes on wire
    src_ip: str            # source IP address
    dst_ip: str            # destination IP address
    src_port: int          # source port (TCP/UDP)
    dst_port: int          # destination port
    l4_proto: str          # TCP | UDP | ICMP | ARP | OTHER
    tcp_flags: List[str]   # e.g. ["SYN", "ACK"]
    l7_proto: str          # HTTP | DNS | HTTPS | SSH | UNKNOWN
    dns_query: str         # e.g. "chatgpt.com"
    http_method: str       # e.g. "GET"
    http_host: str         # e.g. "example.com"
    tls_detected: bool     # True if TLS ClientHello signature found
    payload_entropy: float # Shannon entropy of payload bytes (0–8)
    # ... + 15 more fields
```

**Layer parsing order:**
```
parse(pkt)
  ├── L2: pkt.haslayer(Ether)  → MAC addresses, EtherType
  ├── ARP: pkt.haslayer(ARP)   → return early (no IP layer)
  ├── L3: pkt.haslayer(IP)     → src/dst IP, TTL, flags
  │     or pkt.haslayer(IPv6)  → IPv6 src/dst, hop limit
  ├── L4: pkt.haslayer(TCP)    → ports, flags, seq/ack, window
  │     or pkt.haslayer(UDP)   → ports only
  │     or pkt.haslayer(ICMP)  → type/code
  └── L7: detect_l7() heuristic → port lookup + payload signatures
```

**TLS detection (no SNI decryption needed):**
```python
tls = (len(payload) > 5
       and payload[0] in (0x16, 0x17)      # ContentType: Handshake or AppData
       and payload[1:3] in (b'\x03\x01',   # TLS 1.0
                            b'\x03\x03',   # TLS 1.2
                            b'\x03\x04'))  # TLS 1.3
```

**HTTP detection (no scapy.layers.http needed):**
```python
HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", ...)
if raw_payload[:4] in HTTP_METHODS:
    # Parse method and Host header from raw bytes
```

**Shannon entropy formula:**
```python
def shannon_entropy(data: bytes) -> float:
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())
# Range: 0.0 (all same byte) to 8.0 (perfectly random)
# Plain text ≈ 4.0   |   Encrypted/compressed ≈ 7.5–8.0
```

---

### `flow_tracker.py` — Bidirectional Flow Aggregator

Maintains a hash map of active conversations.

**The canonical key (bidirectional):**
```python
def _canonical_key(pmo):
    # Sort both endpoints so A→B and B→A produce identical key
    pair = sorted([(pmo.src_ip, pmo.src_port), (pmo.dst_ip, pmo.dst_port)])
    return f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{pmo.l4_proto}"

# Example:
# 10.0.2.15:50777 → 104.18.32.47:443   key = "10.0.2.15:50777-104.18.32.47:443-UDP"
# 104.18.32.47:443 → 10.0.2.15:50777   key = "10.0.2.15:50777-104.18.32.47:443-UDP"  ← same!
```

**Flow expiry conditions:**
```python
def is_expired(self, now: float) -> bool:
    if (now - self.last_time) > 30:    return True   # idle 30s
    if (now - self.start_time) > 120:  return True   # active 120s max
    if "FIN" in flags and "ACK" in flags: return True # TCP closed gracefully
    if "RST" in flags:                 return True   # TCP reset
    return False
```

**Computed flow properties:**
```python
@property
def flow_pkt_rate(self):
    return round(self.total_packets / max(self.duration, 1e-9), 4)

@property
def pkt_len_mean(self):
    return round(statistics.mean(self.pkt_lengths), 2)

@property
def mean_entropy(self):
    return round(statistics.mean(self.entropy_samples), 4)
```

---

### `analyzer.py` — Statistics & Anomaly Detection

Maintains all real-time counters and runs threat detection.

**Counters maintained:**
```python
self.proto_count      # {"TCP": 135, "UDP": 334}
self.l7_count         # {"HTTPS": 439, "DNS": 30}
self.src_ip_bytes     # {"10.0.2.15": 111344, ...}
self.src_ip_packets   # packet counts per source IP
self._bps_window      # deque(maxlen=60) — bytes/sec history
self._pps_window      # deque(maxlen=60) — packets/sec history
```

**Anomaly detector logic:**
```python
# Port scan: >20 unique dst_ports from same IP in 10s window
unique_ports = len(set(port for ts, port in recent if now - ts < 10))
if unique_ports > 20: alert("PORT_SCAN", "HIGH", src_ip)

# SYN flood: >200 SYN/sec from same IP
syn_from_src = sum(1 for _, s in self._syn_events if s == src)
if syn_from_src > 200: alert("SYN_FLOOD", "CRITICAL", src_ip)

# High entropy: payload > 7.2 bits AND payload > 200 bytes AND not port 443
if entropy > 7.2 and payload_len > 200 and dst_port not in (443, 8443):
    alert("HIGH_ENTROPY", "MEDIUM", src_ip)
```

---

### `display.py` — Terminal Dashboard

Renders the live UI using ANSI escape codes. No curses, no third-party TUI library.

```python
# Sparkline characters (maps value → bar height):
"▁▂▃▄▅▆▇█"[min(7, int(v / max_val * 7))]

# Progress bar for protocol distribution:
"█" * filled + "░" * (width - filled)

# Screen clear:
os.system("clear")   # redraws from scratch each second
```

**Dashboard sections:**
1. Header — hostname, timestamp, live indicator
2. Capture stats — packets captured, dropped, PPS, total bytes, uptime, alert count
3. Throughput sparklines — BPS and PPS last 30 seconds
4. Protocol distribution — bar chart per L4 protocol
5. Applications (L7) — bar chart per application protocol
6. Top sources — top 5 IPs by bytes with bars
7. Active flows table — top 8 flows by bytes (live, updates every second)
8. Recent alerts — last 4 alerts with severity, type, IP, detail

---

### `exporter.py` — Data Export

Writes completed flows to disk in real time as they expire from the flow table.

```python
# Called by FlowTracker.on_expire for each completed flow:
def write_flow(self, flow: FlowRecord):
    # CSV: list fields serialized with | separator
    csv_row["tcp_flags"] = "|".join(flow.tcp_flags)
    csv_row["dns_queries"] = "|".join(flow.dns_queries)
    # Write to CSV (append mode)
    writer.writerow(csv_row)
    # Write to JSONL (lists preserved as JSON arrays)
    f.write(json.dumps(flow.to_dict()) + "\n")
```

---

## Requirements & Installation

### System requirements

- Ubuntu 20.04 / 22.04 / 24.04 (or any Linux)
- Python 3.8+
- `libpcap` development library
- A network interface with traffic (physical or VirtualBox NAT)

### Step-by-step installation

```bash
# 1. Update system packages
sudo apt update && sudo apt upgrade -y

# 2. Install libpcap (required for raw packet capture)
sudo apt install -y python3-pip libpcap-dev python3-venv git

# 3. Create project directory
mkdir ~/DPI && cd ~/DPI

# 4. Copy all 7 .py files + requirements.txt into this folder

# 5. Create virtual environment
python3 -m venv venv

# 6. Activate virtual environment
source venv/bin/activate

# 7. Install Scapy
pip install scapy

# 8. Verify Scapy works
python3 -c "from scapy.all import sniff, IP, TCP; print('Scapy OK')"

# 9. Find your network interface name
ip link show
# or
sudo ./venv/bin/python3 main.py --list-ifaces
```

### VirtualBox-specific setup

In VirtualBox → Settings → Network → Adapter 1:
- Set to **NAT** or **Bridged Adapter**
- The interface inside Ubuntu will be `enp0s3` (NAT) or `eth0`
- To generate traffic: open Firefox and browse any website while the capture runs

---

## Running the Project

> **Important:** Always use the full venv path with sudo.  
> `sudo python3` uses the system Python (no Scapy).  
> `sudo ./venv/bin/python3` uses the venv Python (has Scapy).

```bash
cd ~/DPI

# Basic — capture all traffic, auto-detect interface
sudo ./venv/bin/python3 main.py

# Specific interface
sudo ./venv/bin/python3 main.py -i enp0s3

# With BPF filter — only TCP traffic
sudo ./venv/bin/python3 main.py -i enp0s3 -f "tcp"

# Only HTTPS traffic (port 443)
sudo ./venv/bin/python3 main.py -i enp0s3 -f "port 443"

# Only DNS queries
sudo ./venv/bin/python3 main.py -i enp0s3 -f "udp port 53"

# Only traffic to/from a specific IP
sudo ./venv/bin/python3 main.py -i enp0s3 -f "host 8.8.8.8"

# Headless mode — no dashboard, just write CSV files
sudo ./venv/bin/python3 main.py -i enp0s3 --no-display

# Custom output directory
sudo ./venv/bin/python3 main.py -i enp0s3 -o ./my_captures

# Stop the program
Ctrl + C     ← always use this — flushes data before exit
```

---

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i / --iface` | auto | Network interface (e.g. `enp0s3`, `eth0`) |
| `-f / --filter` | `""` (all) | BPF filter string |
| `-c / --count` | `0` (unlimited) | Stop after N packets |
| `-o / --output` | `./output` | Directory for CSV/JSON output files |
| `-r / --refresh` | `1.0` | Dashboard refresh rate in seconds |
| `--no-display` | off | Headless mode — no terminal dashboard |
| `--list-ifaces` | — | Print available interfaces and exit |

### BPF Filter Quick Reference

```bash
"tcp"                    # TCP only
"udp"                    # UDP only
"icmp"                   # ICMP (ping) only
"port 80"                # any traffic on port 80
"port 80 or port 443"    # HTTP or HTTPS
"host 8.8.8.8"           # traffic to/from Google DNS
"tcp and port 22"        # SSH only
"not port 443"           # everything except HTTPS
"src 10.0.2.15"          # outgoing traffic only
"dst 192.168.1.1"        # traffic to your router only
```

---

## Live Dashboard Explained

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⬡  DPI Network Monitor  2026-04-01 15:15:49  ● LIVE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  CAPTURE
  Packets captured : 469    Dropped: 0    PPS: 27.1
  Total bytes      : 306 KB   Uptime: 17s   Alerts: 217

  THROUGHPUT  (last 30s)
  BPS  ▁▁▁▃▁▁▁▁▂▂█▃▁▃▂▄  20.6 KB/s
  PPS  ▁▂▁▄▂▁▁▁▃▄█▃▂▅▃▄  27 pkt/s

  PROTOCOLS
  UDP        ██████████████░░░░     334   80.3%
  TCP        ████░░░░░░░░░░░░░░      78   19.7%

  APPLICATIONS  (L7)
  HTTPS        █████████████░    439
  DNS          █░░░░░░░░░░░░░     30

  TOP SOURCES
  10.0.2.15          ██████████████     111 KB  [PRIV]
  104.18.32.47       ████████████░░      90 KB  [EXT]
  192.178.211.84     ███░░░░░░░░░░░      69 KB  [EXT]

  ACTIVE FLOWS  (top 8 by bytes)
                 SRC                 DST  PROTO    PKTS      BYTES  L7
  ─────────────────────────────────────────────────────────────────────
     10.0.2.15:50777    104.18.32.47:443  UDP       141    124.7 KB  HTTPS
     10.0.2.15:60654  192.178.211.84:443  TCP        77     61.3 KB  HTTPS
     10.0.2.15:56106  172.217.174.238:443 UDP        54     34.8 KB  HTTPS

  RECENT ALERTS
  15:15:49  [MEDIUM  ]  HIGH_ENTROPY   192.178.211.84   Entropy=7.86 TCP/60654
  15:15:49  [MEDIUM  ]  HIGH_ENTROPY   10.0.2.15        Entropy=7.87 UDP/443
```

### Dashboard Field Reference

| Field | Meaning |
|-------|---------|
| `Packets captured` | Total raw packets received since start |
| `Dropped` | Packets lost because ring buffer was full |
| `PPS` | Packets per second (current rate) |
| `BPS sparkline` | Bytes/sec history, last 30 seconds |
| `[PRIV]` | Source IP is a private/internal address |
| `[EXT]` | Source IP is an external (internet) address |
| `SRC / DST` | `IP:port` for each side of the conversation |
| `L7` | Detected application protocol |

---

## Output Files

All files are created in `./output/` (or custom path via `-o`).

### `flows_YYYYMMDD_HHMMSS.csv`

One row per completed flow. Appended in real time as flows expire.

```
flow_key,src_ip,dst_ip,src_port,dst_port,protocol,service,l7_proto,
tls_detected,duration,fwd_pkt_count,bwd_pkt_count,total_packets,
fwd_bytes,bwd_bytes,total_bytes,flow_pkt_rate,flow_byte_rate,
pkt_len_mean,pkt_len_std,iat_mean,iat_max,mean_entropy,
tcp_flags,dns_queries,http_methods,http_hosts,start_time,end_time
```

### `flows_YYYYMMDD_HHMMSS.jsonl`

Same data in JSONL format (one JSON object per line). List fields preserved as arrays.

```json
{
  "flow_key": "10.0.2.15:50777-104.18.32.47:443-UDP",
  "src_ip": "10.0.2.15",
  "dst_ip": "104.18.32.47",
  "src_port": 50777,
  "dst_port": 443,
  "protocol": "UDP",
  "service": "HTTPS",
  "l7_proto": "HTTPS",
  "tls_detected": false,
  "duration": 6.002611,
  "fwd_pkt_count": 46,
  "bwd_pkt_count": 95,
  "total_packets": 141,
  "fwd_bytes": 33820,
  "bwd_bytes": 90035,
  "total_bytes": 123855,
  "flow_pkt_rate": 23.4898,
  "flow_byte_rate": 20633.521,
  "pkt_len_mean": 878.4,
  "pkt_len_std": 516.58,
  "iat_mean": 0.042572,
  "iat_max": 3.121202,
  "mean_entropy": 6.9401,
  "tcp_flags": [],
  "dns_queries": [],
  "http_methods": [],
  "http_hosts": [],
  "start_time": 1775036743.009,
  "end_time": 1775036749.011
}
```

### `alerts_YYYYMMDD_HHMMSS.jsonl`

One JSON object per alert, appended as they fire.

```json
{
  "timestamp": 1775036749.263927,
  "type": "HIGH_ENTROPY",
  "severity": "MEDIUM",
  "src_ip": "10.0.2.15",
  "detail": "Entropy=7.44 on UDP/443"
}
```

### `session_summary.json`

Written once on clean shutdown (Ctrl+C). Contains the full session snapshot.

```json
{
  "elapsed_sec": 16.9,
  "total_packets": 469,
  "total_bytes": 313302,
  "avg_pps": 27.79,
  "avg_bps": 18562.33,
  "proto_dist": {"UDP": 334, "TCP": 135},
  "l7_dist": {"HTTPS": 439, "DNS": 30},
  "top_src_ips": [["10.0.2.15", 111344], ["104.18.32.47", 90035]],
  "alert_count": 217,
  "flow_count": 29
}
```

### Analyzing output with Python + Pandas

```python
import pandas as pd
import json

# Load all flows
df = pd.read_csv("output/flows_20260401_151533.csv")

# Protocol breakdown
print(df["l7_proto"].value_counts())

# Top destinations by bytes
print(df.groupby("dst_ip")["total_bytes"].sum().sort_values(ascending=False).head(10))

# High-entropy flows (potential tunnels)
suspicious = df[df["mean_entropy"] > 7.2]
print(suspicious[["src_ip", "dst_ip", "l7_proto", "total_bytes", "mean_entropy"]])

# All DNS queries captured
dns_flows = df[df["l7_proto"] == "DNS"]
queries = dns_flows["dns_queries"].str.split("|").explode().dropna().unique()
print(sorted(queries))

# Load alerts
with open("output/alerts_20260401_151533.jsonl") as f:
    alerts = [json.loads(line) for line in f]
print(f"Total alerts: {len(alerts)}")
```

---

## Real Capture Output Example

This is actual output from a 17-second capture session on an Ubuntu VirtualBox VM.

### Session statistics

| Metric | Value |
|--------|-------|
| Duration | 17 seconds |
| Packets captured | 469 |
| Packets dropped | 0 (0%) |
| Total bytes | 313,302 bytes (~306 KB) |
| Flows exported | 29 |
| Alerts fired | 217 |
| Average throughput | 27.79 pkt/s / 18.5 KB/s |

### Protocol distribution

| Protocol | Packets | % |
|----------|---------|---|
| UDP | 334 | 71.2% |
| TCP | 135 | 28.8% |

| Application | Packets | % |
|-------------|---------|---|
| HTTPS | 439 | 93.6% |
| DNS | 30 | 6.4% |

### Top external IPs contacted

| IP Address | Owner | Bytes Received | Traffic Type |
|------------|-------|---------------|--------------|
| `104.18.32.47` | Cloudflare CDN | 90,035 B | QUIC/HTTP3 |
| `192.178.211.84` | Google | 69,802 B | TLS/HTTPS |
| `142.251.221.234` | Google | 16,528 B | QUIC |
| `172.217.174.238` | Google | 13,962 B | QUIC |
| `172.64.155.209` | Cloudflare | 7,129 B | QUIC |

### DNS queries captured

The system extracted every domain lookup from raw UDP packets:

```
chatgpt.com
ab.chatgpt.com
accounts.google.com
play.google.com
chat.google.com
browser-intake-us5-datadoghq.com
prod-dynamite-prod-01-us-signaler-pa.clients6.google.com
```

### Largest single flow

```
flow_key    : 10.0.2.15:50777-104.18.32.47:443-UDP
protocol    : UDP / HTTPS (QUIC)
duration    : 6.00 seconds
packets     : 141 (46 sent, 95 received)
bytes       : 123,855 (34 KB sent, 90 KB received)
pkt_rate    : 23.49 pkt/s
byte_rate   : 20,634 bytes/s
entropy     : 6.94 bits (encrypted — expected for QUIC)
```

### Sample alert

```json
{
  "timestamp": 1775036749.26,
  "type": "HIGH_ENTROPY",
  "severity": "MEDIUM",
  "src_ip": "192.178.211.84",
  "detail": "Entropy=7.86 on TCP/60654"
}
```

> **Note:** All 217 alerts in this session were false positives from normal TLS/QUIC traffic.  
> Apply Fix 1 below to suppress them.

---

## Flow Features Reference

Every row in the CSV represents one completed bidirectional conversation.

| Feature | Type | Description |
|---------|------|-------------|
| `flow_key` | string | Canonical 5-tuple key |
| `src_ip` | string | Source IP address |
| `dst_ip` | string | Destination IP address |
| `src_port` | int | Source port number |
| `dst_port` | int | Destination port number |
| `protocol` | string | L4 protocol: TCP / UDP / ICMP / ARP |
| `service` | string | Service name from port map (e.g. HTTPS, DNS, SSH) |
| `l7_proto` | string | Detected application protocol |
| `tls_detected` | bool | True if TLS ClientHello signature found in payload |
| `duration` | float | Seconds between first and last packet |
| `fwd_pkt_count` | int | Packets in forward direction (initiator → responder) |
| `bwd_pkt_count` | int | Packets in backward direction (responder → initiator) |
| `total_packets` | int | Total packets in both directions |
| `fwd_bytes` | int | Bytes sent in forward direction |
| `bwd_bytes` | int | Bytes sent in backward direction |
| `total_bytes` | int | Total bytes in both directions |
| `flow_pkt_rate` | float | Packets per second over flow lifetime |
| `flow_byte_rate` | float | Bytes per second over flow lifetime |
| `pkt_len_mean` | float | Mean packet size in bytes |
| `pkt_len_std` | float | Standard deviation of packet sizes |
| `iat_mean` | float | Mean inter-arrival time between packets (seconds) |
| `iat_max` | float | Maximum inter-arrival time (seconds) |
| `mean_entropy` | float | Mean Shannon entropy of payload bytes (0–8 bits) |
| `tcp_flags` | string | Pipe-separated set of TCP flags seen (e.g. `SYN\|ACK\|FIN`) |
| `dns_queries` | string | Pipe-separated DNS domain names resolved in this flow |
| `http_methods` | string | Pipe-separated HTTP methods observed (e.g. `GET\|POST`) |
| `http_hosts` | string | Pipe-separated HTTP Host header values |
| `start_time` | float | Unix timestamp of first packet |
| `end_time` | float | Unix timestamp of last packet |

---

## Anomaly Detection Rules

Six rules run in real time inside `analyzer.py`.

| Alert Type | Severity | Condition | Threshold |
|------------|----------|-----------|-----------|
| `SYN_FLOOD` | CRITICAL | SYN packets per second from same IP | > 200 / sec |
| `PORT_SCAN` | HIGH | Unique dst ports from same IP in time window | > 20 in 10 sec |
| `HIGH_ENTROPY` | MEDIUM | Payload entropy on non-443 port | > 7.2 bits, payload > 200 B |
| `LARGE_FLOW` | MEDIUM | Single flow total bytes | > 50 MB |
| `ENCRYPTED_TUNNEL` | MEDIUM | Mean flow entropy over entire conversation | > 7.2 bits, flow > 10 KB |
| `TTL_ANOMALY` | LOW | TTL deviation from OS baseline (64/128/255) | > ±8 hops |
| `RST_STORM` | LOW | RST flags in a single flow | > 10 RSTs |

### Tuning thresholds

Edit these constants at the top of `analyzer.py`:

```python
PORTSCAN_THRESHOLD      = 20     # unique ports
PORTSCAN_WINDOW_SEC     = 10     # seconds
SYN_FLOOD_THRESHOLD     = 200    # SYN/sec
HIGH_ENTROPY_THRESHOLD  = 7.2    # bits
LARGE_FLOW_BYTES        = 50_000_000   # 50 MB
ICMP_FLOOD_THRESHOLD    = 100    # ICMP/sec
TTL_ANOMALY_DEVIATION   = 8      # hops
```

---

## Protocol Detection Reference

### Port-based detection (WELL_KNOWN_PORTS)

| Port | Protocol | Transport |
|------|----------|-----------|
| 22 | SSH | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | UDP/TCP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP/UDP |
| 3306 | MySQL | TCP |
| 3389 | RDP | TCP |
| 5432 | PostgreSQL | TCP |
| 6379 | Redis | TCP |
| 8080 | HTTP-ALT | TCP |

### Payload signature detection

| Signature | Detected Protocol |
|-----------|------------------|
| `payload[0] == 0x16` + TLS version bytes | TLS (Handshake) |
| `payload[0] == 0x17` + TLS version bytes | TLS (AppData) |
| First 4 bytes in HTTP_METHODS tuple | HTTP |
| `payload[:3] == b"SSH"` | SSH |
| DNS layer present | DNS |

### Why UDP/443 shows as HTTPS

Modern browsers use **QUIC** (HTTP/3) — a Google-invented protocol that runs over **UDP port 443**. It encrypts everything including headers. The system detects it as HTTPS via the port number. `tls_detected` will be `False` for QUIC flows because QUIC does not use a traditional TLS handshake.

---

## Known Issues & Fixes

### Fix 1 — Too many HIGH_ENTROPY alerts on port 443

**Cause:** TLS 1.3 and QUIC encrypt data so thoroughly that payload entropy is always 7.5–8.0 bits. This is expected and not a threat.

**Fix:** In `analyzer.py`, update the entropy check in `_check_anomalies()`:

```python
# Before:
if pmo.payload_entropy > HIGH_ENTROPY_THRESHOLD and pmo.payload_length > 200:

# After:
if (pmo.payload_entropy > HIGH_ENTROPY_THRESHOLD
        and pmo.payload_length > 200
        and pmo.dst_port not in (443, 8443)
        and pmo.src_port not in (443, 8443)):
```

---

### Fix 2 — Negative flow duration in DNS flows

**Cause:** DNS response packets sometimes get timestamped slightly before the request due to kernel out-of-order processing.

**Fix:** In `flow_tracker.py`, update the `duration` property:

```python
# Before:
return round(self.last_time - self.start_time, 6)

# After:
return round(max(0.0, self.last_time - self.start_time), 6)
```

---

### Fix 3 — `Fatal Python error: _enter_buffered_busy` on shutdown

**Cause:** Multiple daemon threads print to stdout at the exact moment `sys.exit()` closes the stdout buffer.

**Fix:** In `main.py`, add a short sleep in the `shutdown()` function before `sys.exit(0)`:

```python
def shutdown(sig=None, frame=None):
    stop_event.set()
    # ... flush flows, write summary ...
    time.sleep(0.3)   # let daemon threads finish printing
    sys.exit(0)
```

---

### Fix 4 — `ModuleNotFoundError: No module named 'scapy'` with sudo

**Cause:** `sudo python3` uses the system Python interpreter, not the virtualenv Python. The system Python has no Scapy installed.

**Fix:** Always use the full venv Python path with sudo:

```bash
# Wrong:
sudo python3 main.py

# Correct:
sudo ./venv/bin/python3 main.py
```

---

### Fix 5 — `ImportError: cannot import name 'HTTPRequest' from 'scapy.all'`

**Cause:** `HTTPRequest` is in `scapy.layers.http`, a contrib module not available in all Scapy versions.

**Fix:** Already applied in `parser.py`. HTTP is detected via payload byte inspection instead — works on all Scapy versions.

---

## Concepts Glossary

| Term | Meaning |
|------|---------|
| **Packet** | A small chunk of data (typically ≤1500 bytes) sent over a network |
| **Flow** | A bidirectional conversation between two endpoints, identified by 5-tuple |
| **5-tuple** | {src_ip, dst_ip, src_port, dst_port, protocol} — uniquely identifies a flow |
| **DPI** | Deep Packet Inspection — reading packet contents beyond just the header |
| **BPF** | Berkeley Packet Filter — kernel-level packet filtering language |
| **Ring buffer** | Fixed-size circular queue; when full, new items drop the oldest (or are discarded) |
| **Entropy** | Measure of randomness in data; high entropy (>7) suggests encryption |
| **TTL** | Time To Live — max hops a packet can traverse; different per OS |
| **QUIC** | Google's protocol replacing TCP+TLS; runs over UDP port 443; used by Chrome |
| **TLS** | Transport Layer Security — encryption protocol for HTTPS |
| **SYN** | TCP flag meaning "I want to start a connection" |
| **RST** | TCP flag meaning "abort this connection immediately" |
| **FIN** | TCP flag meaning "I'm done sending, closing gracefully" |
| **ACK** | TCP flag meaning "I received your data" |
| **IAT** | Inter-Arrival Time — time between consecutive packets in a flow |
| **NIC** | Network Interface Card — the hardware that receives packets from the wire |
| **Daemon thread** | Background thread that auto-terminates when the main program exits |
| **Raw socket** | OS-level socket with access to all packet layers (requires root) |
| **Shannon entropy** | Formula: -Σ p(x)·log₂(p(x)) over all byte values; range 0–8 bits |
| **SPAN/TAP** | Hardware methods to mirror network traffic to a monitoring device |

---

## Log File

`dpi.log` is written automatically in the project directory.

```
2026-04-01 15:15:33,346 [CaptureThread] INFO: Capture started on 'enp0s3' | filter='' | count=unlimited
2026-04-01 15:15:33,359 [MainThread] INFO: 4 worker threads started.
2026-04-01 15:15:50,195 [CaptureThread] INFO: Capture thread exiting.
```

Log level is `INFO`. To enable debug logging, change in `main.py`:

```python
logging.basicConfig(level=logging.DEBUG, ...)
```

---

## Tech Stack Summary

| Component | Technology | Why |
|-----------|-----------|-----|
| Packet capture | `scapy.sniff()` | Only library needed; handles raw sockets |
| Concurrency | `threading` (stdlib) | Simple; no async complexity needed |
| Flow storage | `dict` (hash map) | O(1) lookup and update |
| Statistics | `statistics` (stdlib) | mean, stdev without numpy |
| Terminal UI | ANSI escape codes | No curses dependency |
| Data export | `csv`, `json` (stdlib) | Universal formats |
| Queue | `queue.Queue` (stdlib) | Thread-safe ring buffer |
| CLI | `argparse` (stdlib) | Standard Python CLI |

**Total external dependencies: 1** (`scapy`)

---

*Built with Python 3.12 · Scapy 2.5+ · Ubuntu 24.04 · VirtualBox*
