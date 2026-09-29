from scapy.all import sniff, IP, TCP, UDP, ARP
from threading import Lock
from collections import defaultdict
from datetime import datetime
import time
import math
from database import insert_packet
import config

# =============================
# Shared Data
# =============================
packets_data = []
ip_count = defaultdict(int)
syn_tracker = defaultdict(list)
port_tracker = defaultdict(lambda: defaultdict(list))
arp_table = {}
suspicious_ips = defaultdict(int)
traffic_history = []

packet_rate = 0
rate_timestamp = time.time()

# Statistical baseline
rate_samples = []
baseline_mean = 0
baseline_std = 0

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "suspicious": 0,
    "pps": 0
}

lock = Lock()

# =============================
# Statistical Model
# =============================
def update_baseline(current_rate):
    global baseline_mean, baseline_std

    rate_samples.append(current_rate)

    if len(rate_samples) > 100:
        rate_samples.pop(0)

    if len(rate_samples) >= 10:
        baseline_mean = sum(rate_samples) / len(rate_samples)
        variance = sum((x - baseline_mean) ** 2 for x in rate_samples) / len(rate_samples)
        baseline_std = math.sqrt(variance)

def compute_z_score(current_rate):
    if baseline_std == 0:
        return 0
    return (current_rate - baseline_mean) / baseline_std

# =============================
# Risk Model
# =============================
def calculate_risk_score(rule_flags, z_score):
    score = 0

    if rule_flags["syn"]:
        score += 25
    if rule_flags["port"]:
        score += 25
    if rule_flags["freq"]:
        score += 20

    if z_score > 3:
        score += 30
    elif z_score > 2:
        score += 15

    return score

def classify_severity(score):
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    elif score > 0:
        return "Low"
    return "Normal"

# =============================
# Cleanup
# =============================
def cleanup_trackers():
    current_time = time.time()

    for ip in list(syn_tracker.keys()):
        syn_tracker[ip] = [
            t for t in syn_tracker[ip]
            if current_time - t < config.SYN_WINDOW
        ]

    for ip in list(port_tracker.keys()):
        for port in list(port_tracker[ip].keys()):
            port_tracker[ip][port] = [
                t for t in port_tracker[ip][port]
                if current_time - t < config.PORT_SCAN_WINDOW
            ]

# =============================
# Packet Processing
# =============================
def process_packet(packet):
    global packet_rate, rate_timestamp

    timestamp = datetime.now().strftime("%H:%M:%S")

    current_time = time.time()
    packet_rate += 1

    if current_time - rate_timestamp >= 1:
        with lock:
            stats["pps"] = packet_rate
            traffic_history.append(packet_rate)
            if len(traffic_history) > 60:
                traffic_history.pop(0)

        update_baseline(packet_rate)
        packet_rate = 0
        rate_timestamp = current_time

    status = "Normal"
    reason = "Normal traffic"

    rule_flags = {"syn": False, "port": False, "freq": False}

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    protocol = "OTHER"
    dport = None

    with lock:
        stats["total"] += 1

    if TCP in packet:
        protocol = "TCP"
        dport = packet[TCP].dport

        with lock:
            stats["tcp"] += 1

        if packet[TCP].flags & 0x02:
            syn_tracker[src].append(current_time)
            if len(syn_tracker[src]) > config.SYN_THRESHOLD:
                rule_flags["syn"] = True

        port_tracker[src][dport].append(current_time)
        if len(port_tracker[src]) > config.PORT_SCAN_THRESHOLD:
            rule_flags["port"] = True

    elif UDP in packet:
        protocol = "UDP"
        with lock:
            stats["udp"] += 1

    ip_count[dst] += 1

    is_external = not dst.startswith(config.LOCAL_PREFIXES)
    high_frequency = ip_count[dst] > config.FREQUENCY_THRESHOLD
    unsafe_port = dport not in config.SAFE_PORTS if dport else False

    if is_external and high_frequency and unsafe_port:
        rule_flags["freq"] = True

    z_score = compute_z_score(stats["pps"])
    risk_score = calculate_risk_score(rule_flags, z_score)
    severity = classify_severity(risk_score)

    if severity != "Normal":
        status = severity
        reason = f"Risk Score: {risk_score} | Z-score: {round(z_score,2)}"
        with lock:
            stats["suspicious"] += 1
            suspicious_ips[src] += 1

    data = {
        "time": timestamp,
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "size": len(packet),
        "status": status,
        "reason": reason
    }

    with lock:
        packets_data.append(data)
        if len(packets_data) > config.MAX_PACKET_STORE:
            packets_data.pop(0)

    insert_packet(data)
    cleanup_trackers()

# =============================
# Start Sniffing
# =============================
def start_sniffing(interface=None):
    sniff(
        iface=interface,
        filter="ip",
        prn=process_packet,
        store=False
    )