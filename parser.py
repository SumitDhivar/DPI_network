"""
parser.py — Multi-Layer Packet Parser
Fix: HTTPRequest / HTTPResponse removed — HTTP detected via payload bytes.
Works on all Scapy versions including 2.4.x / 2.5.x.
"""

import time
import math
from dataclasses import dataclass, field
from typing import List, Optional

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw

TCP_FLAGS = {
    0x001: "FIN", 0x002: "SYN", 0x004: "RST",
    0x008: "PSH", 0x010: "ACK", 0x020: "URG",
    0x040: "ECE", 0x080: "CWR", 0x100: "NS",
}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 179: "BGP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "SYSLOG", 587: "SMTP-TLS",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB",
}

HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE",
                b"PATC", b"OPTI", b"CONN", b"TRAC", b"HTTP")


@dataclass
class PacketMetadata:
    timestamp: float = 0.0
    wire_length: int = 0
    eth_src: str = ""
    eth_dst: str = ""
    eth_type: int = 0
    vlan_id: Optional[int] = None
    ip_version: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    ttl: int = 0
    ip_proto: int = 0
    ip_length: int = 0
    ip_flags: str = ""
    src_port: int = 0
    dst_port: int = 0
    l4_proto: str = ""
    tcp_flags: List[str] = field(default_factory=list)
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    payload_length: int = 0
    service: str = ""
    l7_proto: str = ""
    dns_query: str = ""
    http_method: str = ""
    http_host: str = ""
    tls_detected: bool = False
    payload_entropy: float = 0.0
    is_arp: bool = False
    is_broadcast: bool = False


def parse_tcp_flags(flags_int: int) -> List[str]:
    return [name for bit, name in TCP_FLAGS.items() if flags_int & bit]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in freq.values()), 4)


def _parse_http_payload(payload: bytes) -> tuple:
    """Extract HTTP method + Host header from raw TCP payload bytes."""
    if len(payload) < 4 or payload[:4] not in HTTP_METHODS:
        return "", ""
    try:
        header_end = payload.find(b"\r\n\r\n")
        header_bytes = payload[:header_end] if header_end != -1 else payload[:512]
        lines = header_bytes.split(b"\r\n")
        method = lines[0].split(b" ")[0].decode(errors="replace") if lines else ""
        host = ""
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                host = line[5:].strip().decode(errors="replace")
                break
        return method, host
    except Exception:
        return "", ""


def detect_l7(src_port: int, dst_port: int, payload: bytes) -> tuple:
    """Returns (protocol_name, tls_detected)."""
    tls = (len(payload) > 5
           and payload[0] in (0x16, 0x17)
           and payload[1:3] in (b'\x03\x01', b'\x03\x03', b'\x03\x04'))

    for port in (dst_port, src_port):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port], tls

    if len(payload) >= 4:
        if payload[:4] in HTTP_METHODS or payload[:4] == b"HTTP":
            return "HTTP", False
        if payload[:3] == b"SSH":
            return "SSH", False

    return "UNKNOWN", tls


def parse(pkt) -> Optional[PacketMetadata]:
    """Parse a raw Scapy packet into PacketMetadata. Returns None for non-IP frames."""
    pmo = PacketMetadata()
    pmo.timestamp   = float(pkt.time) if hasattr(pkt, "time") else time.time()
    pmo.wire_length = len(pkt)

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        pmo.eth_src      = eth.src
        pmo.eth_dst      = eth.dst
        pmo.eth_type     = eth.type
        pmo.is_broadcast = eth.dst.lower() == "ff:ff:ff:ff:ff:ff"

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        pmo.is_arp   = True
        pmo.l7_proto = "ARP"
        pmo.src_ip   = arp.psrc
        pmo.dst_ip   = arp.pdst
        pmo.l4_proto = "ARP"
        return pmo

    if pkt.haslayer(IP):
        ip = pkt[IP]
        pmo.ip_version = 4
        pmo.src_ip     = ip.src
        pmo.dst_ip     = ip.dst
        pmo.ttl        = ip.ttl
        pmo.ip_proto   = ip.proto
        pmo.ip_length  = ip.len
        flags = []
        if ip.flags.DF: flags.append("DF")
        if ip.flags.MF: flags.append("MF")
        pmo.ip_flags = "|".join(flags)
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        pmo.ip_version = 6
        pmo.src_ip     = ip6.src
        pmo.dst_ip     = ip6.dst
        pmo.ttl        = ip6.hlim
        pmo.ip_proto   = ip6.nh
    else:
        return None

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        pmo.l4_proto   = "TCP"
        pmo.src_port   = tcp.sport
        pmo.dst_port   = tcp.dport
        pmo.tcp_flags  = parse_tcp_flags(int(tcp.flags))
        pmo.tcp_seq    = tcp.seq
        pmo.tcp_ack    = tcp.ack
        pmo.tcp_window = tcp.window
        raw = bytes(tcp.payload)
        pmo.payload_length  = len(raw)
        pmo.payload_entropy = shannon_entropy(raw)
        pmo.l7_proto, pmo.tls_detected = detect_l7(tcp.sport, tcp.dport, raw)
        pmo.service = WELL_KNOWN_PORTS.get(tcp.dport) or WELL_KNOWN_PORTS.get(tcp.sport, "")
        if raw and raw[:4] in HTTP_METHODS:
            method, host = _parse_http_payload(raw)
            if method:
                pmo.l7_proto    = "HTTP"
                pmo.http_method = method
                pmo.http_host   = host

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        pmo.l4_proto = "UDP"
        pmo.src_port = udp.sport
        pmo.dst_port = udp.dport
        raw = bytes(udp.payload)
        pmo.payload_length  = len(raw)
        pmo.payload_entropy = shannon_entropy(raw)
        pmo.l7_proto, pmo.tls_detected = detect_l7(udp.sport, udp.dport, raw)
        pmo.service = WELL_KNOWN_PORTS.get(udp.dport) or WELL_KNOWN_PORTS.get(udp.sport, "")
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                pmo.l7_proto  = "DNS"
                pmo.dns_query = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            except Exception:
                pass

    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        pmo.l4_proto = "ICMP"
        pmo.l7_proto = f"ICMP-{icmp.type}/{icmp.code}"
        pmo.service  = "ICMP"
    else:
        pmo.l4_proto = "OTHER"

    return pmo