# flow_engine.py
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List, Any

import numpy as np

# Scapy layers
from scapy.layers.inet import IP, TCP, UDP


FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, proto)


@dataclass
class FlowStats:
    # Flow identity
    flow_key: FlowKey
    start_time: float
    last_time: float

    # Direction definition: "forward" = direction of first packet
    fwd_src_ip: str
    fwd_src_port: int

    # Packet/byte counters
    total_packets: int = 0
    total_bytes: int = 0

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Packet length lists
    all_lens: List[int] = field(default_factory=list)
    fwd_lens: List[int] = field(default_factory=list)
    bwd_lens: List[int] = field(default_factory=list)

    # Packet timestamps
    all_times: List[float] = field(default_factory=list)

    # TCP window (for Init_Win_bytes_backward)
    init_win_bytes_backward: int = 0
    _got_bwd_window: bool = False

    # Destination port
    dst_port: int = 0


def _proto_of(pkt) -> Optional[str]:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return None


def _ports_of(pkt) -> Tuple[int, int]:
    if pkt.haslayer(TCP):
        return int(pkt[TCP].sport), int(pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return int(pkt[UDP].sport), int(pkt[UDP].dport)
    return 0, 0


def _pkt_len(pkt) -> int:
    """
    Approximate packet length as IP total length if available, else len(pkt).
    CICFlowMeter uses more exact logic; this is a strong practical approximation.
    """
    if pkt.haslayer(IP) and hasattr(pkt[IP], "len") and pkt[IP].len is not None:
        return int(pkt[IP].len)
    return int(len(pkt))


class FlowEngine:
    """
    Maintains active flows, updates stats per packet, and expires flows to generate features.
    """

    def __init__(self, flow_timeout_sec: float = 5.0, inactive_timeout_sec: float = 3.0):
        self.flow_timeout_sec = flow_timeout_sec
        self.inactive_timeout_sec = inactive_timeout_sec

        self._lock = threading.Lock()
        self.flows: Dict[FlowKey, FlowStats] = {}

    def process_packet(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return

        proto = _proto_of(pkt)
        if proto is None:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport, dport = _ports_of(pkt)
        if sport == 0 and dport == 0:
            return

        now = float(getattr(pkt, "time", time.time()))
        key: FlowKey = (src_ip, dst_ip, sport, dport, proto)

        plen = _pkt_len(pkt)

        with self._lock:
            fs = self.flows.get(key)
            if fs is None:
                fs = FlowStats(
                    flow_key=key,
                    start_time=now,
                    last_time=now,
                    fwd_src_ip=src_ip,
                    fwd_src_port=sport,
                    dst_port=dport
                )
                self.flows[key] = fs

            # Update flow times
            fs.last_time = now

            # Determine direction
            is_fwd = (src_ip == fs.fwd_src_ip and sport == fs.fwd_src_port)

            # Update counters
            fs.total_packets += 1
            fs.total_bytes += plen

            fs.all_lens.append(plen)
            fs.all_times.append(now)

            if is_fwd:
                fs.fwd_packets += 1
                fs.fwd_bytes += plen
                fs.fwd_lens.append(plen)
            else:
                fs.bwd_packets += 1
                fs.bwd_bytes += plen
                fs.bwd_lens.append(plen)

                # Init_Win_bytes_backward: first backward TCP window
                if (not fs._got_bwd_window) and pkt.haslayer(TCP):
                    fs.init_win_bytes_backward = int(pkt[TCP].window)
                    fs._got_bwd_window = True

    def expire_flows(self) -> List[FlowStats]:
        """
        Return a list of expired flows and remove them from active storage.
        Expiration conditions:
        - total lifetime exceeded flow_timeout_sec
        - inactive time exceeded inactive_timeout_sec
        """
        now = time.time()
        expired: List[FlowStats] = []

        with self._lock:
            keys_to_delete = []
            for k, fs in self.flows.items():
                lifetime = fs.last_time - fs.start_time
                inactive = now - fs.last_time
                if lifetime >= self.flow_timeout_sec or inactive >= self.inactive_timeout_sec:
                    expired.append(fs)
                    keys_to_delete.append(k)

            for k in keys_to_delete:
                del self.flows[k]

        return expired

    @staticmethod
    def extract_top20_features(fs: FlowStats) -> Dict[str, float]:
        """
        Build the exact top-20 feature dict (names must match training).
        """
        times = fs.all_times
        lens = fs.all_lens

        if len(times) < 2:
            duration = 0.0
            iats = np.array([0.0], dtype=float)
        else:
            duration = float(max(times) - min(times))
            sorted_times = np.array(sorted(times), dtype=float)
            iats = np.diff(sorted_times)
            if iats.size == 0:
                iats = np.array([0.0], dtype=float)

        # Safe duration for rates
        dur_safe = duration if duration > 1e-6 else 1e-6

        # Packet length stats
        lens_arr = np.array(lens, dtype=float) if lens else np.array([0.0], dtype=float)
        fwd_arr = np.array(fs.fwd_lens, dtype=float) if fs.fwd_lens else np.array([0.0], dtype=float)
        bwd_arr = np.array(fs.bwd_lens, dtype=float) if fs.bwd_lens else np.array([0.0], dtype=float)

        features = {
            # Top 20 (match training names)
            "Fwd Packet Length Max": float(np.max(fwd_arr)),
            "Fwd Packet Length Mean": float(np.mean(fwd_arr)),
            "Bwd Packets/s": float(fs.bwd_packets / dur_safe),

            "Total Length of Fwd Packets": float(fs.fwd_bytes),
            "Subflow Fwd Bytes": float(fs.fwd_bytes),  # approximation: treat whole flow as one subflow
            "Flow Packets/s": float(fs.total_packets / dur_safe),

            "Packet Length Std": float(np.std(lens_arr)),
            "Flow IAT Mean": float(np.mean(iats)),
            "Avg Fwd Segment Size": float(np.mean(fwd_arr)),
            "Flow IAT Max": float(np.max(iats)),

            "Init_Win_bytes_backward": float(fs.init_win_bytes_backward),
            "Avg Bwd Segment Size": float(np.mean(bwd_arr)),
            "Bwd Packet Length Mean": float(np.mean(bwd_arr)),

            "Flow Duration": float(duration),
            "Bwd Packet Length Std": float(np.std(bwd_arr)),
            "Bwd Packet Length Max": float(np.max(bwd_arr)),

            "Subflow Bwd Bytes": float(fs.bwd_bytes),  # approximation: treat whole flow as one subflow
            "Total Length of Bwd Packets": float(fs.bwd_bytes),
            "Destination Port": float(fs.dst_port),

            "Packet Length Variance": float(np.var(lens_arr)),
        }
        return features
