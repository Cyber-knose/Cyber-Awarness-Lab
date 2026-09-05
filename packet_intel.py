#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 PACKET INTEL v1.0  —  Senior Red Team Packet Intelligence & Threat Intel Tool
================================================================================
 Author  : Priyanshu Jangra  (Cyber Awareness Lab)
 Purpose : EDUCATIONAL ONLY. Authorized network analysis & threat intel.
           Capture live traffic on ONE interface, generate MULTIPLE traffic
           types to ONE target site, and run a real-time Threat Intelligence
           engine with a live Flask dashboard.

 LEGAL / ETHICS
 ------------------------------------------------------------------------------
 - Use ONLY on networks/systems you own OR have explicit written permission.
 - This tool does NOT inject, spoof, or attack. It OBSERVES + GENERATES benign
   awareness traffic (HTTP/HTTPS/DNS/TCP/ICMP/UDP) against an authorized target.
 - Unauthorized monitoring or traffic generation may violate law. You accept
   full responsibility. Educational demonstration only.

 Dependencies:
   pip install scapy requests flask colorama

 Usage examples:
   python packet_intel.py --target example.com --interface "Wi-Fi"
   python packet_intel.py --target 192.168.1.1 --duration 60 --traffic
   python packet_intel.py --target example.com --headless --traffic --count 500
   python packet_intel.py --help
================================================================================
"""

import argparse
import csv
import json
import os
import socket
import struct
import threading
import time
import webbrowser
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from ipaddress import ip_address

import colorama
from colorama import Fore, Style


def utcnow():
    """Timezone-aware UTC now (replaces deprecated datetime.utcnow())."""
    return datetime.now(timezone.utc)

# ---------------------------------------------------------------- dependencies
try:
    import requests
    REQUESTS_OK = True
except Exception:
    REQUESTS_OK = False

try:
    from flask import Flask, jsonify, render_template_string, request, send_file
    FLASK_OK = True
except Exception:
    FLASK_OK = False

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Ether,
        Raw, conf, get_if_list, sniff,
    )
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

colorama.init(autoreset=True)

# ==============================================================================
# CONFIG
# ==============================================================================

APP_TITLE = "PACKET INTEL // Red Team Traffic & Threat Intelligence"
VERSION = "1.0.0"
BANNER = r"""
  ____    _    ____ ____ _____ _____ _____ _   _ _____ _   _
 |  _ \  / \  / ___|  _ \_   _| ____|_   _| | | | ____| \ | |
 | |_) |/ _ \| |   | |_) || | |  _|   | | | |_| |  _| |  \| |
 |  __// ___ \ |___|  _ < | | | |___  | | |  _  | |___| |\  |
 |_|  /_/   \_\____|_| \_\|_| |_____| |_| |_| |_|_____|_| \_|
          Red Team Packet Intelligence & Threat Intel  v{0}
""".format(VERSION)

# Default thresholds
DEFAULT_TARGET = "example.com"
DEFAULT_INTERFACE = None          # None -> auto detect
MAX_PACKETS = 2000                # ring buffer cap
ALERT_QUEUE_MAX = 300
HISTORY_WINDOW = 60               # seconds for rolling counters
PORTSCAN_PORTS_THRESHOLD = 10     # distinct ports from one src -> alert
BRUTE_FORCE_THRESHOLD = 15        # rapid conn attempts to same dst port
SUSPICIOUS_PORTS = {
    21, 22, 23, 53, 445, 1433, 3306, 3389, 4444, 5555, 6667,
    8080, 8443, 9000, 10000, 12345, 1337, 31337, 44445,
}
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".zip", ".mov", ".country"}

# Payload signature database (educational detection rules)
PAYLOAD_SIGNATURES = {
    "SQL Injection": [
        b"' OR '1'='1", b"UNION SELECT", b"SELECT * FROM", b"1=1--", b"'; DROP TABLE",
        b"' OR 1=1 --", b"OR '1'='1' --", b"admin'--", b"' OR 'x'='x",
    ],
    "XSS Attempt": [
        b"<script>", b"<img src=x onerror=", b"javascript:", b"onload=",
        b"alert(1)", b"<svg/onload=", b"<iframe src=", b"<body onload=",
    ],
    "Path Traversal": [
        b"../", b"..\\..\\", b"%2e%2e%2f", b"..%2f", b"....//", b"/etc/passwd",
    ],
    "Command Injection": [
        b"; ls", b"; cat /etc/passwd", b"$(whoami)", b"`whoami`", b"&& nc ",
        b"| powershell", b"; rm -rf", b"&& cmd.exe",
    ],
    "Shellcode/Strings": [
        b"\\x90\\x90\\x90", b"\\x31\\xc0", b"\\xcc\\xcc\\xcc", b"MZ\x90\x00",
    ],
    "Ransomware/Strings": [
        b"WANNACRY", b"encrypt_all", b"bitcoin", b"pay_ransom", b"DECRYPT",
    ],
}

GEO_PREFIX_RULES = [
    ("Cloud/DC", ["13.107.", "20.", "40.", "52.", "104.", "168.63.", "146.112."]),
    ("Telecom/ISP", ["49.", "103.", "106.", "110.", "116.", "122.", "150.", "182.", "202."]),
    ("Private/Lab", ["10.", "127.", "172.16.", "192.168."]),
]

# ==============================================================================
# SHARED STATE (thread-safe)
# ==============================================================================

class SharedState:
    """Central state shared between capture, traffic generator, intel, web."""
    def __init__(self):
        self.lock = threading.Lock()
        self.started_at = utcnow()
        self.packets = deque(maxlen=MAX_PACKETS)
        self.alerts = deque(maxlen=ALERT_QUEUE_MAX)
        self.protocol_counts = Counter()
        self.port_counts = Counter()
        self.ip_counts = Counter()
        self.dst_counts = Counter()
        self.dns_queries = deque(maxlen=200)
        self.conn_attempts = defaultdict(list)   # src_ip -> [timestamps]
        self.dst_port_attempts = defaultdict(list)  # (src,dport) -> [timestamps]
        self.src_ports_seen = defaultdict(set)   # src_ip -> {dst_ports}
        self.payload_hits = Counter()
        self.packet_rate = deque(maxlen=HISTORY_WINDOW)
        self.traffic_sent = Counter()
        self.capture_active = False
        self.traffic_active = False
        self.target = DEFAULT_TARGET
        self.target_ip = None
        self.interface = DEFAULT_INTERFACE
        self.packet_count = 0

    def snapshot_stats(self):
        with self.lock:
            now = time.time()
            recent = [t for t in self.packet_rate if now - t <= HISTORY_WINDOW]
            total = sum(self.protocol_counts.values())
            threat_score = self.compute_threat_score_locked()
            return {
                "uptime_sec": int((utcnow() - self.started_at).total_seconds()),
                "total_packets": total,
                "packet_count": self.packet_count,
                "packets_per_sec": round(len(recent) / max(HISTORY_WINDOW, 1), 2),
                "protocols": dict(self.protocol_counts.most_common(10)),
                "top_ports": dict(self.port_counts.most_common(12)),
                "top_ips": dict(self.ip_counts.most_common(12)),
                "top_dst": dict(self.dst_counts.most_common(10)),
                "alerts_count": len(self.alerts),
                "capture_active": self.capture_active,
                "traffic_active": self.traffic_active,
                "target": self.target,
                "target_ip": self.target_ip,
                "interface": self.interface,
                "threat_score": threat_score,
                "payload_hits": dict(self.payload_hits.most_common(10)),
                "traffic_sent": dict(self.traffic_sent.most_common(20)),
                "dns_recent": list(self.dns_queries)[-10:],
            }

    def compute_threat_score_locked(self):
        score = 0
        if len(self.alerts) > 0:
            score += min(50, len(self.alerts) * 5)
        total = sum(self.protocol_counts.values())
        if total > 500:
            score += 10
        if len(self.src_ports_seen) > 0:
            for s in self.src_ports_seen.values():
                if len(s) >= PORTSCAN_PORTS_THRESHOLD:
                    score += 15
        if self.payload_hits:
            score += min(20, sum(self.payload_hits.values()) * 2)
        return min(100, score)

    def add_packet(self, pkt_info, alerts):
        with self.lock:
            self.packets.append(pkt_info)
            self.packet_count += 1
            self.packet_rate.append(time.time())
            proto = pkt_info.get("protocol", "OTHER")
            self.protocol_counts[proto] += 1
            sport = pkt_info.get("sport")
            dport = pkt_info.get("dport")
            if dport:
                self.port_counts[dport] += 1
            src = pkt_info.get("src")
            dst = pkt_info.get("dst")
            if src:
                self.ip_counts[src] += 1
            if dst:
                self.dst_counts[dst] += 1
            for a in alerts:
                self.alerts.append(a)

STATE = SharedState()

# ==============================================================================
# THREAT INTELLIGENCE ENGINE
# ==============================================================================

class ThreatIntelEngine:
    """Real-time detection rules over the packet stream."""

    def __init__(self, state: SharedState):
        self.state = state

    def evaluate(self, info: dict) -> list:
        alerts = []
        src = info.get("src")
        dst = info.get("dst")
        sport = info.get("sport")
        dport = info.get("dport")
        flags = info.get("flags", "")
        proto = info.get("protocol")
        now = time.time()

        # --- Port scan detection: one source -> many distinct dst ports
        if src and dport:
            with self.state.lock:
                self.state.src_ports_seen[src].add(dport)
                n = len(self.state.src_ports_seen[src])
            if n == PORTSCAN_PORTS_THRESHOLD:
                alerts.append(self._alert("HIGH", "Port Scan",
                    f"{src} probed {n} distinct ports (possible port scan / recon)"))
            elif n > PORTSCAN_PORTS_THRESHOLD and n % 10 == 0:
                alerts.append(self._alert("HIGH", "Port Scan",
                    f"{src} continues scanning — {n} distinct ports seen"))

        # --- Brute force detection: repeated connections to same dst port
        if src and dport:
            key = (src, dport)
            with self.state.lock:
                self.state.dst_port_attempts[key].append(now)
                self.state.dst_port_attempts[key] = [
                    t for t in self.state.dst_port_attempts[key] if now - t <= 10
                ]
                cnt = len(self.state.dst_port_attempts[key])
            if cnt == BRUTE_FORCE_THRESHOLD:
                alerts.append(self._alert("MEDIUM", "Brute Force",
                    f"{src} -> port {dport}: {cnt} rapid connections in 10s (possible brute force)"))

        # --- Suspicious ports
        if dport and dport in SUSPICIOUS_PORTS:
            alerts.append(self._alert("MEDIUM", "Suspicious Port",
                f"Traffic to known suspicious/service port {dport} from {src or '?'}"))
        if sport and sport in SUSPICIOUS_PORTS:
            alerts.append(self._alert("MEDIUM", "Suspicious Port",
                f"Traffic from known suspicious/service port {sport} to {dst or '?'}"))

        # --- SYN flood pattern (too many SYN in window)
        if "S" in flags and "A" not in flags:
            with self.state.lock:
                self.state.conn_attempts[src or "?"].append(now)
                self.state.conn_attempts[src or "?"] = [
                    t for t in self.state.conn_attempts[src or "?"] if now - t <= 10
                ]
                syns = len(self.state.conn_attempts[src or "?"])
            if syns == 30:
                alerts.append(self._alert("HIGH", "SYN Flood Pattern",
                    f"{src} sent {syns} SYN packets in 10s (possible SYN flood / DoS)"))

        # --- DNS anomalies
        if proto == "DNS" and info.get("qname"):
            qname = info["qname"].lower()
            with self.state.lock:
                self.state.dns_queries.append(qname)
            tld = None
            for s in SUSPICIOUS_TLDS:
                if qname.endswith(s):
                    tld = s
                    break
            if tld:
                alerts.append(self._alert("MEDIUM", "DNS Anomaly",
                    f"DNS query to suspicious TLD '{tld}': {qname}"))
            if qname.count(".") >= 5:
                alerts.append(self._alert("MEDIUM", "DNS Anomaly",
                    f"Excessive subdomain depth in DNS query: {qname}"))

        # --- Payload signature scan
        payload = info.get("payload")
        if payload:
            pl = payload if isinstance(payload, bytes) else str(payload).encode("utf-8", "ignore")
            for name, sigs in PAYLOAD_SIGNATURES.items():
                for sig in sigs:
                    if sig in pl:
                        self.state.payload_hits[name] += 1
                        alerts.append(self._alert("CRITICAL", "Payload Signature",
                            f"'{name}' signature detected from {src or '?'} to {dst or '?'} "
                            f"port {dport or '?'}"))
                        break

        # --- ICMP flood
        if proto == "ICMP":
            with self.state.lock:
                self.state.conn_attempts["icmp:" + (src or "?")].append(now)
                self.state.conn_attempts["icmp:" + (src or "?")] = [
                    t for t in self.state.conn_attempts["icmp:" + (src or "?")] if now - t <= 10
                ]
                if len(self.state.conn_attempts["icmp:" + (src or "?")]) == 20:
                    alerts.append(self._alert("MEDIUM", "ICMP Flood",
                        f"High ICMP volume from {src} (possible ping flood)"))

        # --- Geo/network flag
        if src:
            tag = self._geo_tag(src)
            if tag and tag != "Private/Lab":
                info["geo_tag"] = tag

        return alerts

    def _alert(self, severity, title, message):
        return {
            "time": utcnow().strftime("%H:%M:%S"),
            "severity": severity,
            "title": title,
            "message": message,
        }

    def _geo_tag(self, ip_str):
        for tag, prefixes in GEO_PREFIX_RULES:
            for p in prefixes:
                if ip_str.startswith(p):
                    return tag
        return None


# ==============================================================================
# PACKET CAPTURE
# ==============================================================================

class PacketCapture:
    """Scapy-based sniffer. Gracefully degrades if raw sockets unavailable."""

    def __init__(self, state: SharedState, intel: ThreatIntelEngine):
        self.state = state
        self.intel = intel
        self.thread = None
        self.stop_flag = threading.Event()

    def _extract(self, pkt) -> dict or None:
        info = {
            "time": utcnow().strftime("%H:%M:%S.%f")[:-3],
            "protocol": "OTHER",
            "src": None, "dst": None, "sport": None, "dport": None,
            "flags": "", "qname": None, "payload": None, "len": 0,
        }
        try:
            if Ether in pkt:
                info["src_mac"] = pkt[Ether].src
                info["dst_mac"] = pkt[Ether].dst
            if IP in pkt:
                info["src"] = pkt[IP].src
                info["dst"] = pkt[IP].dst
                info["len"] = int(getattr(pkt[IP], "len", 0))
                info["ttl"] = int(getattr(pkt[IP], "ttl", 0))
            if TCP in pkt:
                info["protocol"] = "TCP"
                info["sport"] = int(pkt[TCP].sport)
                info["dport"] = int(pkt[TCP].dport)
                info["flags"] = str(pkt[TCP].flags)
            elif UDP in pkt:
                info["protocol"] = "UDP"
                info["sport"] = int(pkt[UDP].sport)
                info["dport"] = int(pkt[UDP].dport)
            elif ICMP in pkt:
                info["protocol"] = "ICMP"
                info["type"] = int(getattr(pkt[ICMP], "type", 0))
            elif ARP in pkt:
                info["protocol"] = "ARP"
                info["src"] = pkt[ARP].psrc
                info["dst"] = pkt[ARP].pdst
                return info
            elif DNS in pkt and DNSQR in pkt:
                info["protocol"] = "DNS"
                info["qname"] = str(pkt[DNSQR].qname)
                return info

            if DNS in pkt and DNSQR in pkt:
                info["protocol"] = "DNS"
                info["qname"] = str(pkt[DNSQR].qname)

            if Raw in pkt:
                info["payload"] = bytes(pkt[Raw].load)

            # TLS/HTTP detection on top ports
            if TCP in pkt and info.get("dport") in (443, 8443):
                info["protocol"] = "TLS"
            elif TCP in pkt and info.get("dport") in (80, 8080, 8000):
                info["protocol"] = "HTTP"
        except Exception:
            pass
        return info

    def _handler(self, pkt):
        info = self._extract(pkt)
        if not info:
            return
        alerts = self.intel.evaluate(info)
        self.state.add_packet(info, alerts)

    def start(self):
        self.stop_flag.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        if not SCAPY_OK:
            print(Fore.RED + "[!] Scapy unavailable — capture disabled. "
                  "Install with: pip install scapy")
            return
        try:
            iface = self.state.interface
            print(Fore.CYAN + f"[*] Starting packet capture on interface: {iface or 'AUTO'}")
            self.state.capture_active = True
            sniff(prn=self._handler, store=0, iface=iface, stop_filter=lambda _: self.stop_flag.is_set())
        except PermissionError:
            print(Fore.RED + "[!] Permission denied. Run as Administrator for raw packet capture.")
            print(Fore.YELLOW + "[i] Packet capture requires admin/root privileges on most OS.")
        except Exception as e:
            print(Fore.RED + f"[!] Capture error: {e}")
            print(Fore.YELLOW + "[i] Trying without interface filter (may need admin)...")
            try:
                sniff(prn=self._handler, store=0, stop_filter=lambda _: self.stop_flag.is_set())
            except Exception as e2:
                print(Fore.RED + f"[!] Capture failed entirely: {e2}")
        finally:
            self.state.capture_active = False

    def stop(self):
        self.stop_flag.set()


# ==============================================================================
# TRAFFIC GENERATOR — MULTIPLE TRAFFIC TYPES TO ONE TARGET SITE
# ==============================================================================

class TrafficGenerator:
    """Generates multiple benign traffic types to the configured target site."""

    def __init__(self, state: SharedState):
        self.state = state
        self.stop_flag = threading.Event()
        self.thread = None

    def resolve_target(self, target):
        try:
            ip_address(target)
            return target
        except ValueError:
            pass
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    def start(self, target, duration=30, rate=10):
        self.stop_flag.clear()
        self.state.target = target
        self.state.target_ip = self.resolve_target(target)
        self.thread = threading.Thread(target=self._run, kwargs={
            "target": target, "duration": duration, "rate": rate,
        }, daemon=True)
        self.thread.start()

    def _run(self, target, duration, rate):
        self.state.traffic_active = True
        print(Fore.GREEN + f"[+] Traffic generator started -> {target} "
              f"(duration {duration}s, rate ~{rate}/s)")
        start = time.time()
        i = 0
        while not self.stop_flag.is_set() and time.time() - start < duration:
            kind = i % 5
            try:
                if kind == 0:
                    self._http_get(target)
                elif kind == 1:
                    self._http_post(target)
                elif kind == 2:
                    self._dns_query(target)
                elif kind == 3:
                    self._tcp_connect(target)
                else:
                    self._icmp_ping(target)
                self.state.traffic_sent[kind_label(kind)] += 1
            except Exception as e:
                pass
            i += 1
            time.sleep(max(0.05, 1.0 / max(rate, 1)))
        self.state.traffic_active = False
        print(Fore.GREEN + "[+] Traffic generator finished.")

    # --- HTTP/HTTPS GET
    def _http_get(self, target):
        url = target if target.startswith("http") else f"http://{target}"
        if REQUESTS_OK:
            try:
                requests.get(url, timeout=2,
                             headers={"User-Agent": "PacketIntel-Edu/1.0"},
                             allow_redirects=False)
            except Exception:
                pass
        else:
            self._raw_tcp(target, 80)

    # --- HTTP/HTTPS POST (form-like)
    def _http_post(self, target):
        url = target if target.startswith("http") else f"http://{target}"
        if REQUESTS_OK:
            try:
                requests.post(url, data={"module": "awareness", "ts": str(int(time.time()))},
                              timeout=2, headers={"User-Agent": "PacketIntel-Edu/1.0"})
            except Exception:
                pass
        else:
            self._raw_tcp(target, 80)

    # --- DNS query
    def _dns_query(self, target):
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        try:
            socket.gethostbyname(host)
        except Exception:
            pass

    # --- TCP connect probe
    def _tcp_connect(self, target):
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        for port in (80, 443):
            try:
                s = socket.create_connection((host, port), timeout=1.5)
                s.close()
            except Exception:
                pass

    # --- ICMP ping
    def _icmp_ping(self, target):
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return
        # Educational ICMP echo via raw socket (best-effort, admin required)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            pid = os.getpid() & 0xFFFF
            pkt = struct.pack("!BBHHH", 8, 0, 0, pid, 1) + b"packet-intel"
            chk = icmp_checksum(pkt)
            pkt = struct.pack("!BBHHH", 8, 0, chk, pid, 1) + b"packet-intel"
            sock.sendto(pkt, (ip, 1))
            sock.close()
        except PermissionError:
            pass  # requires admin; silently skip
        except Exception:
            pass

    # --- raw TCP banner probe fallback
    def _raw_tcp(self, target, port):
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        try:
            s = socket.create_connection((host, port), timeout=1.5)
            s.sendall(b"GET / HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % host.encode())
            s.close()
        except Exception:
            pass

    def stop(self):
        self.stop_flag.set()


def kind_label(k):
    return ["HTTP-GET", "HTTP-POST", "DNS", "TCP-PROBE", "ICMP-PING"][k]


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


# ==============================================================================
# REPORT GENERATOR
# ==============================================================================

def _threat_level(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def build_report_dict():
    stats = STATE.snapshot_stats()
    alerts = list(STATE.alerts)[::-1]
    return {
        "generated_at": utcnow().isoformat() + "Z",
        "tool": APP_TITLE,
        "version": VERSION,
        "threat_level": _threat_level(stats["threat_score"]),
        "threat_score": stats["threat_score"],
        "target": stats["target"],
        "target_ip": stats["target_ip"],
        "interface": stats["interface"],
        "uptime_sec": stats["uptime_sec"],
        "total_packets": stats["total_packets"],
        "packets_per_sec": stats["packets_per_sec"],
        "protocols": stats["protocols"],
        "top_ports": stats["top_ports"],
        "top_source_ips": stats["top_ips"],
        "top_destinations": stats["top_dst"],
        "payload_signatures": stats["payload_hits"],
        "traffic_generated": stats["traffic_sent"],
        "alerts": alerts,
        "recent_packets": [dict(p) for p in list(STATE.packets)[-25:]],
    }


def export_report(fmt="json"):
    os.makedirs("reports", exist_ok=True)
    ts = utcnow().strftime("%Y%m%d_%H%M%S")
    data = build_report_dict()
    if fmt == "json":
        path = os.path.join("reports", f"threat_report_{ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path
    if fmt == "csv":
        path = os.path.join("reports", f"threat_report_{ts}.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["time", "severity", "title", "message"])
            for a in data["alerts"]:
                w.writerow([a["time"], a["severity"], a["title"], a["message"]])
        return path
    if fmt == "html":
        return _export_html(ts, data)
    return None


def _export_html(ts, data):
    path = os.path.join("reports", f"threat_report_{ts}.html")
    rows = "".join(
        f"<tr><td>{a['time']}</td><td><span class='sev sev-{a['severity'].lower()}'>{a['severity']}</span></td>"
        f"<td>{a['title']}</td><td>{a['message']}</td></tr>"
        for a in data["alerts"][:100]
    )
    proto_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data["protocols"].items()
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Threat Intel Report</title><style>
body{{background:#07111D;color:#D8E2EB;font-family:Consolas,monospace;padding:30px;}}
h1{{color:#7CB9E8;letter-spacing:.1em;}} .box{{background:#0C1B2A;border:1px solid #2A3F55;
padding:14px;border-radius:6px;margin:10px 0;}}
table{{width:100%;border-collapse:collapse;}} td,th{{border:1px solid #2A3F55;padding:8px;font-size:13px;}}
.sev{{font-weight:bold;}} .sev-high{{color:#FF5C5C;}} .sev-medium{{color:#FFB454;}}
.sev-critical{{color:#FF2D2D;}} .sev-low{{color:#7CB9E8;}}
.meta{{color:#8A9BA8;font-size:13px;}}
</style></head><body>
<h1>🛡 THREAT INTELLIGENCE REPORT</h1>
<div class="meta">Generated: {data['generated_at']} | Target: {data['target']} ({data['target_ip']}) |
Interface: {data['interface']} | Uptime: {data['uptime_sec']}s</div>
<div class="box">Threat Score: <b>{data['threat_score']}</b> / 100 — Level: <b>{data['threat_level']}</b>
| Packets: {data['total_packets']} | PPS: {data['packets_per_sec']}</div>
<h2>Protocols</h2><div class="box"><table>{proto_rows}</table></div>
<h2>Alerts ({len(data['alerts'])})</h2><div class="box"><table>
<tr><th>Time</th><th>Severity</th><th>Title</th><th>Message</th></tr>{rows}</table></div>
<div class="meta" style="margin-top:20px">© Cyber Awareness Lab — Educational purpose only</div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ==============================================================================
# FLASK WEB DASHBOARD
# ==============================================================================

PAGE_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',monospace,sans-serif;}
body{background:#07111D;color:#D8E2EB;min-height:100vh;overflow-x:hidden;}
.wrap{max-width:1400px;margin:0 auto;padding:20px;}
header{background:#0C1B2A;border:1px solid #1E3350;padding:14px 22px;border-radius:8px;
display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:16px;}
.logo{font-weight:600;letter-spacing:.12em;color:#7CB9E8;font-size:15px;}
.logo span{color:#4A6B8A;font-weight:300;}
.meta{font-size:11px;color:#8A9BA8;letter-spacing:.06em;}
.status{font-size:11px;padding:4px 10px;border-radius:3px;border:1px solid #2A3F55;}
.status.on{color:#6FE7A4;border-color:#1E5540;background:rgba(31,170,110,.08);}
.status.off{color:#FF8A8A;border-color:#5C2A2A;background:rgba(255,60,60,.06);}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-bottom:16px;}
.card{background:#0C1B2A;border:1px solid #1E3350;border-radius:8px;padding:16px;}
.card h3{font-size:11px;color:#4A6B8A;letter-spacing:.14em;margin-bottom:10px;text-transform:uppercase;}
.big{font-size:30px;font-weight:500;color:#E4EBF0;}
.unit{font-size:12px;color:#4A6B8A;}
.bar-row{display:flex;align-items:center;gap:8px;font-size:12px;margin:4px 0;color:#A0B4C6;}
.bar{height:6px;background:#1E3350;border-radius:3px;flex:1;overflow:hidden;}
.bar > div{height:100%;background:#7CB9E8;border-radius:3px;}
.threat{font-size:20px;font-weight:600;}
.threat.critical{color:#FF2D2D;} .threat.high{color:#FF5C5C;} .threat.medium{color:#FFB454;} .threat.low{color:#6FE7A4;}
.sec-title{font-size:13px;color:#7CB9E8;letter-spacing:.1em;margin:18px 0 8px;}
table{width:100%;border-collapse:collapse;background:#0C1B2A;border:1px solid #1E3350;border-radius:8px;overflow:hidden;}
th{background:#13263C;color:#4A6B8A;font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:8px;text-align:left;}
td{padding:7px 8px;font-size:12px;border-top:1px solid #14283E;color:#A0B4C6;}
.sev{padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600;}
.sev-CRITICAL{background:#5C1A1A;color:#FF7A7A;} .sev-HIGH{background:#5C3A1A;color:#FFB454;}
.sev-MEDIUM{background:#3A4A5C;color:#FFD28A;} .sev-LOW{background:#1A3A5C;color:#7CB9E8;}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;}
button{background:#0C1B2A;border:1px solid #2A3F55;color:#A0B4C6;padding:9px 18px;border-radius:6px;
font-size:12px;cursor:pointer;letter-spacing:.06em;transition:.2s;}
button:hover{background:#13263C;border-color:#7CB9E8;color:#E4EBF0;}
button.active{background:#1A4A6A;border-color:#7CB9E8;color:#fff;}
input{background:#0C1B2A;border:1px solid #2A3F55;color:#D8E2EB;padding:9px 12px;border-radius:6px;
font-size:12px;min-width:220px;}
.mono{font-family:Consolas,monospace;font-size:11px;color:#8A9BA8;}
.muted{color:#4A6B8A;font-size:11px;}
#toast{position:fixed;bottom:20px;right:20px;background:#13263C;border:1px solid #7CB9E8;
color:#D8E2EB;padding:12px 18px;border-radius:6px;font-size:12px;opacity:0;transition:.3s;z-index:99;}
#toast.show{opacity:1;}
@media(max-width:700px){.grid{grid-template-columns:1fr;}}
</style></head><body>
<div class="wrap">
<header>
  <div class="logo">🛡 PACKET INTEL <span>// Red Team Traffic &amp; Threat Intelligence</span></div>
  <div class="meta">TARGET: <b id="metaTarget">--</b> &nbsp; IP: <b id="metaIp">--</b> &nbsp; IFACE: <b id="metaIface">--</b></div>
  <div><span class="status off" id="capStatus">CAPTURE OFF</span> &nbsp;
  <span class="status off" id="genStatus">TRAFFIC OFF</span></div>
</header>

<div class="actions">
  <input id="targetInput" placeholder="Target site (e.g. example.com or 192.168.1.10)">
  <button onclick="startTraffic()" id="btnTraffic">▶ Generate Traffic</button>
  <button onclick="stopTraffic()">■ Stop Traffic</button>
  <button onclick="startCapture()">👁 Start Capture</button>
  <button onclick="stopCapture()">✖ Stop Capture</button>
  <button onclick="exportJson()">⬇ JSON</button>
  <button onclick="exportCsv()">⬇ CSV</button>
  <button onclick="exportHtml()">⬇ HTML</button>
</div>

<div class="grid">
  <div class="card"><h3>Threat Score</h3><div class="threat" id="threatScore">0</div>
    <div class="muted" id="threatLevel">LOW</div></div>
  <div class="card"><h3>Total Packets</h3><div class="big" id="totalPackets">0</div>
    <div class="muted">Uptime <span id="uptime">0</span>s</div></div>
  <div class="card"><h3>Packets / Sec</h3><div class="big" id="pps">0.0</div></div>
  <div class="card"><h3>Alerts</h3><div class="big" id="alertsCount">0</div>
    <div class="muted">live events</div></div>
</div>

<div class="grid">
  <div class="card"><h3>Protocols</h3><div id="protoBars" class="mono"></div></div>
  <div class="card"><h3>Top Ports</h3><div id="portList" class="mono"></div></div>
  <div class="card"><h3>Top Source IPs</h3><div id="ipList" class="mono"></div></div>
  <div class="card"><h3>Traffic Generated</h3><div id="trafficList" class="mono"></div></div>
</div>

<div class="sec-title">▲ LIVE ALERTS (auto-refresh)</div>
<div class="card" style="padding:8px;max-height:260px;overflow:auto;">
<table><tr><th>Time</th><th>Severity</th><th>Title</th><th>Message</th></tr>
<tbody id="alertRows"><tr><td colspan="4" class="muted">No alerts yet — generating or capturing traffic will populate this feed.</td></tr></tbody></table>
</div>

<div class="sec-title">▲ RECENT PACKETS</div>
<div class="card" style="padding:8px;max-height:320px;overflow:auto;">
<table><tr><th>Time</th><th>Proto</th><th>Src</th><th>Sport</th><th>→</th><th>Dst</th><th>Dport</th><th>Flags</th><th>Len</th></tr>
<tbody id="packetRows"><tr><td colspan="9" class="muted">No packets yet.</td></tr></tbody></table>
</div>
<div class="muted" style="margin:20px 0;text-align:center">
© Cyber Awareness Lab · Educational &amp; authorized use only · Created by Priyanshu Jangra</div>
</div>
<div id="toast"></div>

<script>
let autoTimer = setInterval(refresh, 2000);
async function refresh(){
  try{
    const r = await fetch('/api/stats'); const s = await r.json();
    document.getElementById('threatScore').textContent = s.threat_score;
    const lvl = document.getElementById('threatLevel');
    lvl.textContent = s.threat_score>=75?'CRITICAL':s.threat_score>=50?'HIGH':s.threat_score>=25?'MEDIUM':'LOW';
    lvl.className = 'muted ' + (lvl.textContent.toLowerCase());
    document.getElementById('totalPackets').textContent = s.total_packets;
    document.getElementById('pps').textContent = s.packets_per_sec.toFixed(1);
    document.getElementById('alertsCount').textContent = s.alerts_count;
    document.getElementById('uptime').textContent = s.uptime_sec;
    document.getElementById('metaTarget').textContent = s.target;
    document.getElementById('metaIp').textContent = s.target_ip || '—';
    document.getElementById('metaIface').textContent = s.interface || 'AUTO';
    const cap = document.getElementById('capStatus');
    cap.textContent = s.capture_active?'CAPTURE ON':'CAPTURE OFF';
    cap.className = 'status ' + (s.capture_active?'on':'off');
    const gen = document.getElementById('genStatus');
    gen.textContent = s.traffic_active?'TRAFFIC ON':'TRAFFIC OFF';
    gen.className = 'status ' + (s.traffic_active?'on':'off');
    document.getElementById('btnTraffic').className = s.traffic_active?'active':'';
    // bars
    const maxP = Math.max(1,...Object.values(s.protocols));
    document.getElementById('protoBars').innerHTML =
      Object.entries(s.protocols).slice(0,6).map(([k,v])=>
        `<div class="bar-row"><span style="min-width:44px">${k}</span><span>${v}</span>
         <div class="bar"><div style="width:${(v/maxP*100).toFixed(0)}%"></div></div></div>`).join('') || '—';
    const maxPort = Math.max(1,...Object.values(s.top_ports));
    document.getElementById('portList').innerHTML =
      Object.entries(s.top_ports).slice(0,6).map(([k,v])=>
        `<div class="bar-row"><span style="min-width:52px">${k}</span><span>${v}</span>
         <div class="bar"><div style="width:${(v/maxPort*100).toFixed(0)}%"></div></div></div>`).join('') || '—';
    const maxIp = Math.max(1,...Object.values(s.top_ips));
    document.getElementById('ipList').innerHTML =
      Object.entries(s.top_ips).slice(0,6).map(([k,v])=>
        `<div class="bar-row"><span style="min-width:110px">${k}</span><span>${v}</span>
         <div class="bar"><div style="width:${(v/maxIp*100).toFixed(0)}%"></div></div></div>`).join('') || '—';
    const tList = document.getElementById('trafficList');
    tList.innerHTML = Object.entries(s.traffic_sent).length?
      Object.entries(s.traffic_sent).map(([k,v])=>`<div class="bar-row"><span>${k}</span><span>${v}</span></div>`).join('') : '—';

    // alerts
    const ar = await fetch('/api/alerts'); const alerts = await ar.json();
    document.getElementById('alertRows').innerHTML = alerts.length? alerts.slice(0,40).map(a=>
      `<tr><td class="mono">${a.time}</td><td><span class="sev sev-${a.severity}">${a.severity}</span></td>
       <td>${a.title}</td><td>${a.message}</td></tr>`).join('') :
      '<tr><td colspan="4" class="muted">No alerts yet.</td></tr>';

    // packets
    const pr = await fetch('/api/packets'); const pkts = await pr.json();
    document.getElementById('packetRows').innerHTML = pkts.length? pkts.slice(0,40).map(p=>
      `<tr><td class="mono">${p.time}</td><td>${p.protocol}</td>
       <td>${p.src||'—'}</td><td>${p.sport||''}</td><td>→</td>
       <td>${p.dst||'—'}</td><td>${p.dport||''}</td>
       <td class="mono">${p.flags||''}</td><td>${p.len||''}</td></tr>`).join('') :
      '<tr><td colspan="9" class="muted">No packets yet.</td></tr>';
  }catch(e){}
}

function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);}

async function startTraffic(){
  const t = document.getElementById('targetInput').value.trim() || 'example.com';
  const r = await fetch('/traffic',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:t,duration:30})});
  const j = await r.json(); toast(j.message);
}
async function stopTraffic(){const r=await fetch('/traffic/stop',{method:'POST'});const j=await r.json();toast(j.message);}
async function startCapture(){const r=await fetch('/capture/start',{method:'POST'});const j=await r.json();toast(j.message);}
async function stopCapture(){const r=await fetch('/capture/stop',{method:'POST'});const j=await r.json();toast(j.message);}
function exportJson(){window.location.href='/report?fmt=json';}
function exportCsv(){window.location.href='/report?fmt=csv';}
function exportHtml(){window.location.href='/report?fmt=html';}
</script>
</body></html>"""


def create_app(state: SharedState, intel: ThreatIntelEngine, capture: PacketCapture,
               gen: TrafficGenerator):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(PAGE_HTML, title=APP_TITLE)

    @app.route("/api/stats")
    def api_stats():
        return jsonify(state.snapshot_stats())

    @app.route("/api/packets")
    def api_packets():
        with state.lock:
            items = [dict(p) for p in list(state.packets)[-60:][::-1]]
        return jsonify(items)

    @app.route("/api/alerts")
    def api_alerts():
        with state.lock:
            items = list(state.alerts)[::-1]
        return jsonify(items)

    @app.route("/traffic", methods=["POST"])
    def traffic():
        data = request.get_json(silent=True) or {}
        target = data.get("target") or state.target
        duration = int(data.get("duration", 30))
        gen.start(target, duration=duration, rate=10)
        return jsonify({"message": f"Traffic generator started → {target} ({duration}s)"})

    @app.route("/traffic/stop", methods=["POST"])
    def traffic_stop():
        gen.stop()
        return jsonify({"message": "Traffic generator stop signal sent"})

    @app.route("/capture/start", methods=["POST"])
    def capture_start():
        if not capture.thread or not capture.thread.is_alive():
            capture.start()
        return jsonify({"message": "Packet capture started"})

    @app.route("/capture/stop", methods=["POST"])
    def capture_stop():
        capture.stop()
        return jsonify({"message": "Packet capture stop signal sent"})

    @app.route("/report")
    def report():
        fmt = request.args.get("fmt", "json")
        path = export_report(fmt)
        if path:
            return send_file(path, as_attachment=True)
        return jsonify({"error": "unknown format"}), 400

    return app


# ==============================================================================
# CLI
# ==============================================================================

def list_interfaces():
    print(Fore.CYAN + "\n[Available interfaces]")
    if SCAPY_OK:
        for i in get_if_list():
            print("  -", i)
    else:
        print("  (scapy unavailable)")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Senior Red Team Packet Intelligence & Threat Intel Tool (Educational)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --target example.com\n"
            "  %(prog)s --target 192.168.1.10 --interface 'Wi-Fi' --traffic\n"
            "  %(prog)s --target example.com --duration 60 --headless --traffic\n"
            "  %(prog)s --list-interfaces\n"
        ),
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target site/IP (authorized only)")
    parser.add_argument("--interface", default=None, help="Network interface to sniff on")
    parser.add_argument("--duration", type=int, default=30, help="Traffic generation duration (s)")
    parser.add_argument("--rate", type=int, default=10, help="Traffic rate per second")
    parser.add_argument("--traffic", action="store_true", help="Auto-start traffic generator")
    parser.add_argument("--capture", action="store_true", help="Auto-start packet capture")
    parser.add_argument("--headless", action="store_true", help="No web dashboard; CLI only")
    parser.add_argument("--port", type=int, default=8080, help="Web dashboard port")
    parser.add_argument("--list-interfaces", action="store_true", help="List interfaces and exit")
    parser.add_argument("--version", action="version", version=f"{APP_TITLE} v{VERSION}")
    args = parser.parse_args()

    print(Fore.CYAN + BANNER)
    print(Fore.YELLOW + "=" * 72)
    print(Fore.YELLOW + "  EDUCATIONAL / AUTHORIZED USE ONLY")
    print(Fore.YELLOW + "  Use only on networks/systems you own or have written permission to test.")
    print(Fore.YELLOW + "=" * 72 + Style.RESET_ALL)

    if args.list_interfaces:
        list_interfaces()
        return

    STATE.target = args.target
    STATE.interface = args.interface
    if STATE.interface:
        STATE.target_ip = None

    intel = ThreatIntelEngine(STATE)
    capture = PacketCapture(STATE, intel)
    gen = TrafficGenerator(STATE)

    print(Fore.CYAN + f"[*] Target          : {args.target}")
    print(Fore.CYAN + f"[*] Interface       : {args.interface or 'AUTO'}")

    # Resolve target
    ip = gen.resolve_target(args.target)
    STATE.target_ip = ip
    print(Fore.CYAN + f"[*] Resolved IP     : {ip or 'unresolved (offline)'}")

    if args.capture:
        capture.start()

    if args.traffic:
        gen.start(args.target, duration=args.duration, rate=args.rate)

    if args.headless:
        print(Fore.GREEN + "[+] Headless mode. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
                s = STATE.snapshot_stats()
                line = (f"\r[packets={s['total_packets']} pps={s['packets_per_sec']:.1f} "
                        f"alerts={s['alerts_count']} threat={s['threat_score']}]")
                print(Fore.CYAN + line + Style.RESET_ALL, end="", flush=True)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Stopped by user.")
        finally:
            capture.stop(); gen.stop()
            if STATE.alerts:
                path = export_report("html")
                print(Fore.GREEN + f"[+] Report saved: {path}")
        return

    if not FLASK_OK:
        print(Fore.RED + "[!] Flask not installed — cannot start web dashboard.")
        print(Fore.YELLOW + "[i] pip install flask  |  or use --headless mode.")
        return

    app = create_app(STATE, intel, capture, gen)
    url = f"http://127.0.0.1:{args.port}"
    print(Fore.GREEN + f"[+] Web dashboard: {url}")
    print(Fore.CYAN + "[i] Press Ctrl+C to stop. Capture must be started from dashboard "
                      "(admin privileges required for raw sockets).")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Stopped by user.")
    finally:
        capture.stop(); gen.stop()
        if STATE.alerts:
            path = export_report("html")
            print(Fore.GREEN + f"[+] Report saved: {path}")


if __name__ == "__main__":
    main()

