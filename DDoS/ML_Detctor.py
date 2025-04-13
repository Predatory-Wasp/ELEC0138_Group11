#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import pandas as pd
from collections import deque, defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# scikit-learn related packages
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from joblib import dump, load
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt

MODEL_PATH = "saved_models/model.joblib"
CSV_PATH = "C:/Users/ASUS/Desktop/all_in_one.csv"  # Assuming the CSV contains columns: [protocol, packet_len, info, label], etc.

# -----------------------------------------------------------
# (A) Training phase: Parse 'info' field from CSV
# -----------------------------------------------------------
def parse_info_field(info_str, protocol_str):
    """
    For offline CSV (exported from Wireshark, may include [SYN], [ACK], GET, POST etc.),
    parse TCP Flags (tcp_flag_val) and HTTP Method (http_method_val).

    Return: (tcp_flag_val, http_method_val)
    - tcp_flag_val: matched by checking strings like [SYN], [ACK], etc.
        SYN=0x02, ACK=0x10, FIN=0x01, PSH=0x08
    - http_method_val: GET=1, POST=2, others=0
    """
    if not isinstance(info_str, str):
        return (0, 0)

    protocol_str = (protocol_str or "").upper()
    info_str = info_str.upper()

    tcp_flag_val = 0
    http_method_val = 0

    if protocol_str == "TCP":
        if "[SYN]" in info_str:
            tcp_flag_val += 0x02
        if "[ACK]" in info_str:
            tcp_flag_val += 0x10
        if "[PSH]" in info_str:
            tcp_flag_val += 0x08
        if "[FIN]" in info_str:
            tcp_flag_val += 0x01

    if "GET" in info_str:
        http_method_val = 1
    elif "POST" in info_str:
        http_method_val = 2

    return (tcp_flag_val, http_method_val)

# -----------------------------------------------------------
def train_or_load_model():
    if os.path.exists(MODEL_PATH):
        print(f"[ML] Trained model found, loading directly: {MODEL_PATH}")
        pipeline = load(MODEL_PATH)
        return pipeline
    else:
        print("[ML] No trained model found, starting training...")

        df = pd.read_csv(CSV_PATH)
        df = df.dropna(subset=["label"])

        protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
        df["proto_val"] = df["protocol"].map(protocol_map).fillna(0)

        parsed = df.apply(
            lambda row: parse_info_field(row["info"], row["protocol"]),
            axis=1
        )
        df["tcp_flag_val"], df["http_method_val"] = zip(*parsed)

        X = df[["proto_val", "packet_len", "tcp_flag_val", "http_method_val"]]
        X = X.apply(pd.to_numeric, errors="coerce")
        y = df["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )

        pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="mean")),
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(n_estimators=100, random_state=42))
        ])

        pipeline.fit(X_train, y_train)
        print("[ML] Model training complete.")

        y_pred = pipeline.predict(X_test)

        all_labels = pipeline.classes_.tolist()
        excluded = {"Normal", "label"}
        filtered_labels = [lab for lab in all_labels if lab not in excluded]

        print("\n[Classification Report]:")
        print(classification_report(y_test, y_pred, labels=filtered_labels))
        print(f"\n[Model Accuracy]: {accuracy_score(y_test, y_pred):.4f}")

        cm = confusion_matrix(y_test, y_pred, labels=filtered_labels)
        disp = ConfusionMatrixDisplay(cm, display_labels=filtered_labels)
        fig, ax = plt.subplots(figsize=(6, 5))
        disp.plot(ax=ax, cmap=plt.cm.Blues)
        plt.title("Confusion Matrix")
        plt.show()

        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        dump(pipeline, MODEL_PATH)
        print(f"[ML] Model saved: {MODEL_PATH}")

        return pipeline

# -----------------------------------------------------------
# (B) Real-time detection phase: Extract flags / HTTP from Scapy packet
# -----------------------------------------------------------
def extract_features(pkt):
    """
    Extract (proto_val, packet_len, tcp_flag_val, http_method_val)
    from Scapy packet for ML prediction.
    """
    proto_val = 0
    pkt_len = len(pkt)
    tcp_flag_val = 0
    http_method_val = 0

    if IP in pkt:
        if TCP in pkt:
            proto_val = 1
            tcp_segment = pkt[TCP]
            if tcp_segment.flags & 0x02:
                tcp_flag_val += 0x02
            if tcp_segment.flags & 0x10:
                tcp_flag_val += 0x10
            if tcp_segment.flags & 0x01:
                tcp_flag_val += 0x01
            if tcp_segment.flags & 0x08:
                tcp_flag_val += 0x08

            if Raw in pkt:
                raw_data = pkt[Raw].load
                if b"GET" in raw_data[:10]:
                    http_method_val = 1
                elif b"POST" in raw_data[:10]:
                    http_method_val = 2

        elif UDP in pkt:
            proto_val = 2
        elif ICMP in pkt:
            proto_val = 3
        else:
            proto_val = 0

    return [proto_val, pkt_len, tcp_flag_val, http_method_val]

def ml_predict_packet(pkt, pipeline):
    """
    Predict label for a packet using trained ML pipeline.
    """
    feats = extract_features(pkt)
    feat_df = pd.DataFrame([feats], columns=["proto_val", "packet_len", "tcp_flag_val", "http_method_val"])
    predicted_label = pipeline.predict(feat_df)[0]
    return predicted_label

# -----------------------------------------------------------
# (C) SnifferGuard: Sliding time window + threshold + ML prediction
# -----------------------------------------------------------
class SnifferGuard:
    """
    Real-time packet monitor using ML (proto_val, packet_len, tcp_flag_val, http_method_val) to detect attacks.
    """

    def __init__(
        self,
        pipeline,
        threshold_packets=300,
        interval_seconds=20,
        log_file="logs/detection_attack_type.log"
    ):
        self.pipeline = pipeline
        self.threshold_packets = threshold_packets
        self.interval_seconds = interval_seconds

        self.packet_buffer = deque()
        self.ip_attack_map = defaultdict(lambda: defaultdict(int))
        self.alerted_set = set()

        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self.log_f = open(log_file, "a", encoding="utf-8")

    def _remove_old_packets(self):
        now = time.time()
        self.ip_attack_map.clear()

        while self.packet_buffer and (now - self.packet_buffer[0][1]) > self.interval_seconds:
            self.packet_buffer.popleft()

        for ip_addr, _, attack_label in self.packet_buffer:
            self.ip_attack_map[ip_addr][attack_label] += 1

    def handle_packet(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            now_t = time.time()

            attack_label = ml_predict_packet(pkt, self.pipeline)

            self.packet_buffer.append((src_ip, now_t, attack_label))
            self._remove_old_packets()

            count_now = self.ip_attack_map[src_ip][attack_label]
            if count_now > self.threshold_packets:
                if (src_ip, attack_label) not in self.alerted_set:
                    self.alerted_set.add((src_ip, attack_label))
                    msg = (
                        f"[ALERT] IP={src_ip}, Attack/Type={attack_label}, "
                        f"Count in {self.interval_seconds}s = {count_now}(> {self.threshold_packets})"
                    )
                    print(msg)
                    self.log_f.write(msg + "\n")

    def close_log(self):
        self.log_f.close()

# -----------------------------------------------------------
# (D) Main
# -----------------------------------------------------------
def main():
    pipeline = train_or_load_model()

    guard = SnifferGuard(
        pipeline=pipeline,
        threshold_packets=300,
        interval_seconds=20,
        log_file="logs/detection_attack_type.log"
    )

    iface = "\\Device\\NPF_Loopback"  # Example interface for Windows loopback (or 'eth0' on Linux)
    print(f"[START] Listening on interface {iface}. (Ctrl+C to stop)")

    try:
        sniff(
            filter="ip",
            iface=iface,
            prn=guard.handle_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[STOP] Detection stopped.")
    finally:
        guard.close_log()


if __name__ == "__main__":
    main()
