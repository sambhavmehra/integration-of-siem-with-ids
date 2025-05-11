from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import random
import datetime
import pandas as pd
from joblib import load
import json

LOG_FILE = "ids_logs.json"
MODEL_PATH = "nids_model_balanced.joblib"

# Load the trained model
model = load(MODEL_PATH)

# Predefined feature names (used during training)
FEATURES = [
    "source_port", "destination_port", "bytes_sent", "bytes_received", "frequency",
    "protocol_ICMP", "protocol_TCP", "protocol_UDP"
]

# Store frequency of (src_ip + dst_port)
freq_map = {}


def extract_features(packet):
    protocol = "OTHER"
    src_port = dst_port = 0
    pkt_len = len(packet)

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"
        src_port = dst_port = 0

    key = f"{packet[IP].src}:{dst_port}"
    freq_map[key] = freq_map.get(key, 0) + 1

    return {
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "bytes_sent": pkt_len,
        "bytes_received": random.randint(100, 12000),
        "frequency": freq_map[key],
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "http_flag": detect_http(packet)
    }


def detect_http(packet):
    if TCP in packet and Raw in packet:
        payload = packet[Raw].load
        if b"HTTP" in payload or b"Host:" in payload:
            if b"https" not in payload.lower():
                return True  # HTTP, not HTTPS
    return False


def predict_and_log(packet_data):
    # Encode protocol manually
    protocol = packet_data["protocol"]
    packet_data["protocol_ICMP"] = 1 if protocol == "ICMP" else 0
    packet_data["protocol_TCP"] = 1 if protocol == "TCP" else 0
    packet_data["protocol_UDP"] = 1 if protocol == "UDP" else 0

    # Extract features for model
    input_data = [[
        packet_data["source_port"],
        packet_data["destination_port"],
        packet_data["bytes_sent"],
        packet_data["bytes_received"],
        packet_data["frequency"],
        packet_data["protocol_ICMP"],
        packet_data["protocol_TCP"],
        packet_data["protocol_UDP"]
    ]]

    df = pd.DataFrame(input_data, columns=FEATURES)
    prediction = model.predict(df)[0]

    is_http = packet_data.get("http_flag", False)
    if is_http:
        detection = "⚠  Unsecured HTTP traffic detected"
        status = detection
    else:
        detection = "Secure" if prediction == 0 else "Malicious IP detected (ML model)"
        status = "✅ Secure" if prediction == 0 else "⚠  Alert: Malicious"

    log = {
        "timestamp": packet_data["timestamp"],
        "source_ip": packet_data["source_ip"],
        "destination_ip": packet_data["destination_ip"],
        "protocol": packet_data["protocol"],
        "detection": detection
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")

    print(f"[{packet_data['timestamp']}] {status} traffic from {packet_data['source_ip']} to {packet_data['destination_ip']}")


def process_packet(packet):
    if IP in packet:
        features = extract_features(packet)
        predict_and_log(features)


if __name__ == "__main__":
    print("🔍 IDS started. Sniffing real network traffic... Press Ctrl+C to stop.")
    sniff(filter="ip", prn=process_packet, store=0)