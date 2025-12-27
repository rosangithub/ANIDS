# realtime_detector.py
import threading
import time
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from joblib import load
import os

# -------- CONFIG --------
INTERFACE = "Wi-Fi"  # change to "eth0" or "wlan0" on Linux
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "StackingEnsemble.joblib")
LOG_FILE = os.path.join(os.path.dirname(__file__), "realtime.csv")  # CSV log used by Flask

# feature order must match model training
feature_order = [
    'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Bwd Packets/s',
    'Total Length of Fwd Packets', 'Subflow Fwd Bytes', 'Flow Packets/s',
    'Packet Length Std', 'Flow IAT Mean', 'Avg Fwd Segment Size', 'Flow IAT Max',
    'Init_Win_bytes_backward', 'Avg Bwd Segment Size', 'Bwd Packet Length Mean',
    'Flow Duration', 'Bwd Packet Length Std', 'Bwd Packet Length Max',
    'Subflow Bwd Bytes', 'Total Length of Bwd Packets', 'Destination Port',
    'Packet Length Variance'
]

class_mapping_reverse = {
    0: 'BENIGN', 1: 'Bot', 2: 'DDoS', 3: 'DoS GoldenEye', 4: 'DoS Hulk',
    5: 'DoS Slowhttptest', 6: 'DoS slowloris', 7: 'FTP-Patator', 8: 'Heartbleed',
    9: 'Infiltration', 10: 'PortScan', 11: 'SSH-Patator',
    12: 'Web Attack - Brute Force', 13: 'Web Attack - Sql Injection',
    14: 'Web Attack - XSS'
}

# -------- GLOBALS --------
# load model once
loaded_model = load(MODEL_PATH)
flows = {}
lock = threading.Lock()
latest_predictions = []  # in-memory latest records (dicts)
_capture_thread = None

# -------- CSV logging helpers --------
def init_csv():
    """Ensure CSV exists with headers."""
    if not os.path.exists(LOG_FILE):
        df = pd.DataFrame(columns=["timestamp", "label", "destination_port", "avg_fwd_packet_len", "flow_duration"])
        df.to_csv(LOG_FILE, index=False)

def append_csv(record: dict):
    """Append one record (dict) to CSV in append mode."""
    file_exists = os.path.exists(LOG_FILE)
    df = pd.DataFrame([record])
    df.to_csv(LOG_FILE, mode='a', header=not file_exists, index=False)

# -------- Feature extraction & processing --------
def extract_features(packet):
    if IP not in packet:
        return None

    src = packet[IP].src
    dst = packet[IP].dst
    proto = packet[IP].proto
    key = (src, dst, proto)

    with lock:
        if key not in flows:
            flows[key] = {
                "start_time": time.time(),
                "packet_lengths": [],
                "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
            }

        flows[key]["packet_lengths"].append(len(packet))
        pkt_lens = flows[key]["packet_lengths"]
        dur = max(time.time() - flows[key]["start_time"], 0.0001)  # avoid zero division
        mean_len = sum(pkt_lens) / len(pkt_lens)

        features = {
            'Fwd Packet Length Max': max(pkt_lens),
            'Fwd Packet Length Mean': mean_len,
            'Bwd Packets/s': 0.0,
            'Total Length of Fwd Packets': sum(pkt_lens),
            'Subflow Fwd Bytes': sum(pkt_lens),
            'Flow Packets/s': len(pkt_lens)/dur,
            'Packet Length Std': float(pd.Series(pkt_lens).std()) if len(pkt_lens) > 1 else 0.0,
            'Flow IAT Mean': dur,
            'Avg Fwd Segment Size': mean_len,
            'Flow IAT Max': dur,
            'Init_Win_bytes_backward': 0,
            'Avg Bwd Segment Size': 0.0,
            'Bwd Packet Length Mean': 0.0,
            'Flow Duration': dur,
            'Bwd Packet Length Std': 0.0,
            'Bwd Packet Length Max': 0,
            'Subflow Bwd Bytes': 0,
            'Total Length of Bwd Packets': 0,
            'Destination Port': flows[key]['dst_port'],
            'Packet Length Variance': float(pd.Series(pkt_lens).var()) if len(pkt_lens) > 1 else 0.0
        }
        return features

def process_packet(packet):
    features = extract_features(packet)
    if features is None:
        return

    # prepare df in model feature order
    df = pd.DataFrame([features], columns=feature_order)
    pred = loaded_model.predict(df)[0]
    label = class_mapping_reverse.get(pred, "Unknown")

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    record = {
        "timestamp": timestamp,
        "label": label,
        "destination_port": int(features['Destination Port']) if features['Destination Port'] is not None else 0,
        "avg_fwd_packet_len": round(features['Fwd Packet Length Mean'], 2),
        "flow_duration": round(features['Flow Duration'], 3)
    }

    # keep last N in memory for quick UI (optional)
    with lock:
        latest_predictions.append(record)
        if len(latest_predictions) > 100:
            latest_predictions.pop(0)

    # persist to CSV
    append_csv(record)

# -------- Sniffing thread --------
def live_capture():
    init_csv()
    print(f"[realtime_detector] Starting sniff on {INTERFACE}")
    sniff(iface=INTERFACE, prn=process_packet, store=False)

def start_capture_thread():
    global _capture_thread
    if _capture_thread and _capture_thread.is_alive():
        return False  # already running

    _capture_thread = threading.Thread(target=live_capture, daemon=True)
    _capture_thread.start()
    return True
