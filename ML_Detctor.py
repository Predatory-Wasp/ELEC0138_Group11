import sys
import time
from scapy.all import sniff, IP
from collections import deque, Counter
import os

import numpy as np
import pandas as pd

# 機器學習相關套件
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix,
    ConfusionMatrixDisplay,
    classification_report,
    accuracy_score,
)
from joblib import dump, load
import matplotlib.pyplot as plt

# -------------------------------------------------------------------
# 機器學習偵測器 - 封裝模型訓練與測試邏輯
# -------------------------------------------------------------------
class MLAnalyzer:
    """
    使用多種機器學習方法的攻擊偵測器。
    可選用 RF / SVM / LR / KNN 作為分類器。
    """

    def __init__(self, method="RF"):
        """
        初始化偵測器並指定分類方法。
        :param method: 機器學習方法，可為 'RF'、'SVM'、'LR'、'KNN'。
        """
        self.method = method
        if method == "RF":
            self.classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                class_weight="balanced"
            )
        elif method == "SVM":
            self.classifier = SVC(kernel="rbf")
        elif method == "LR":
            self.classifier = LogisticRegression(solver="liblinear")
        elif method == "KNN":
            self.classifier = KNeighborsClassifier(n_neighbors=3)
        else:
            raise ValueError("Unsupported method type.")

    def train_model(self, X, y, preprocessor=None, save_dir="saved_models"):
        """
        訓練模型並進行評估，最後儲存訓練完成的模型與混淆矩陣圖。
        :param X: 特徵資料（DataFrame 或 Numpy array）
        :param y: 目標（label）資料
        :param preprocessor: 前處理流程（如有需要，可自行定義）
        :param save_dir: 存放模型等輸出的資料夾路徑
        """
        if preprocessor is None:
            # 若未傳入前處理器，則預設使用簡單的數值前處理流程
            preprocessor = Pipeline([
                ("imputer", SimpleImputer(strategy="mean")),
                ("scaler", StandardScaler()),
            ])

        pipeline = Pipeline([
            ("preprocessor", preprocessor),
            ("model", self.classifier),
        ])

        # 將資料切分為訓練集與測試集
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        print("[訓練階段] 開始訓練模型...")
        pipeline.fit(X_train, y_train)
        print("[訓練階段] 模型完成訓練。")

        # 建立儲存模型的資料夾
        os.makedirs(save_dir, exist_ok=True)
        model_filename = os.path.join(save_dir, f"model_{self.method}.joblib")
        dump(pipeline, model_filename)
        print(f"[訓練階段] 模型已儲存於: {model_filename}")

        print("[測試階段] 進行測試預測...")
        y_pred = pipeline.predict(X_test)

        # 展示評估結果
        print("[測試階段] 預測結果分析：")
        print(classification_report(y_test, y_pred))
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")

        # 繪製並儲存混淆矩陣
        cm = confusion_matrix(y_test, y_pred, labels=pipeline.classes_)
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=pipeline.classes_)
        fig, ax = plt.subplots(figsize=(6, 4))
        disp.plot(ax=ax)
        plt.title(f"Confusion Matrix - {self.method}")
        fig_path = os.path.join(save_dir, f"cm_{self.method}.png")
        plt.savefig(fig_path)
        plt.close()
        print(f"[測試階段] 混淆矩陣已儲存：{fig_path}")

    def predict_attacks(self, data, model_path):
        """
        載入事先訓練好的模型，預測新資料的攻擊類型，並進行可疑度判斷。
        :param data: 新的封包特徵資料（DataFrame 或 Numpy array）
        :param model_path: 已訓練模型的檔案路徑
        """
        if not os.path.exists(model_path):
            print(f"找不到模型檔案：{model_path}")
            return

        if data.empty:
            print("輸入資料為空，無法進行攻擊預測。")
            return

        print("[偵測階段] 載入模型並進行攻擊預測...")
        pipeline = load(model_path)
        predictions = pipeline.predict(data)

        # 統計各類攻擊的數量
        attack_counts = Counter(predictions)
        print("[偵測階段] 預測結果彙整：")
        for attack_type, num in attack_counts.items():
            print(f"  - 攻擊類型 '{attack_type}' 數量: {num}")

        # 自定義門檻：如果某類攻擊數量超過門檻，就顯示警示
        threshold_map = {
            "UDP Flood": 10,
            "ICMP Flood": 10,
            "TCP Flood": 10,
            "HTTP Flood": 10,  # 如需擴充，可再加入新的攻擊類型
        }
        for atk, threshold in threshold_map.items():
            if atk in attack_counts and attack_counts[atk] > threshold:
                print(f"警告：偵測到潛在 {atk}，共 {attack_counts[atk]} 筆封包超過預設門檻！")

# -------------------------------------------------------------------
# 即時封包監控 - 結合基於閾值的簡易偵測機制
# -------------------------------------------------------------------
class RealTimeMonitor:
    """
    即時封包監控，用於檢測連續封包是否超過門檻，
    以偵測可能的DoS攻擊並允許用戶選擇是否封鎖IP。
    """

    def __init__(self,
                 max_packets=5000,
                 time_window=30,
                 log_file="logs/alert_log.txt"):
        """
        初始化即時監控器。
        :param max_packets: 在指定時間視窗內若同一IP的封包數超過此值，就判定為可疑。
        :param time_window: 監控時間視窗（秒），過期的封包統計將被清除。
        :param log_file: 記錄封鎖或警告資訊的檔案位置。
        """
        self.max_packets = max_packets
        self.time_window = time_window
        self._packet_times = deque()  # 全域時間戳管理 (ip, timestamp)
        self._ip_count_map = {}
        self._blocked_list = set()
        self._alerted_list = set()
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self.log_file = open(log_file, 'a')

    def _clean_old_packets(self):
        """
        移除超過設定時間視窗的封包。
        """
        current_time = time.time()
        # 1) 移除舊時間戳
        while self._packet_times and self._packet_times[0][1] < current_time - self.time_window:
            self._packet_times.popleft()
        # 2) 重新累計目前視窗內的封包
        self._ip_count_map.clear()
        for ip, tstamp in self._packet_times:
            self._ip_count_map[ip] = self._ip_count_map.get(ip, 0) + 1

    def check_packet(self, pkt):
        """
        核心函式：處理每個監測到的封包，如果超過閾值就警告或封鎖。
        """
        if IP in pkt:
            src_ip = pkt[IP].src
            current_time = time.time()

            # 新封包加入佇列
            self._packet_times.append((src_ip, current_time))
            # 清除舊封包資料以保持時間視窗內的統計
            self._clean_old_packets()

            current_count = self._ip_count_map.get(src_ip, 0)

            if current_count > self.max_packets and src_ip not in self._alerted_list:
                print(f"[警告] 偵測到疑似大流量攻擊來源：{src_ip}")
                user_choice = ""
                while user_choice.lower() not in ("y", "n"):
                    user_choice = input("是否要封鎖此IP？(Y/N)：").strip()
                    if user_choice.lower() == "y":
                        self._blocked_list.add(src_ip)
                        self._alerted_list.add(src_ip)
                        self.log_file.write(f"已封鎖IP：{src_ip}\n")
                        print(f"[動作] 已將 {src_ip} 加入封鎖名單。")
                    elif user_choice.lower() == "n":
                        self._alerted_list.add(src_ip)
                        print("[通知] 您選擇不封鎖該IP，但仍標記為已提醒。")
                    else:
                        print("輸入錯誤，請重新輸入 Y 或 N。")

    def close_log(self):
        """
        關閉日誌檔案。
        """
        self.log_file.close()

# -------------------------------------------------------------------
# 主程式範例: 不做假資料訓練，只做封包監測 + (選擇性) 已訓練模型預測
# -------------------------------------------------------------------
def main():
    print("[*] 即時封包監控初始化...")
    monitor = RealTimeMonitor(max_packets=3000, time_window=20, log_file="../logs/attack_alerts.txt")

    # 若需要機器學習預測功能，可在這裡載入你的模型
    # ml_detector = MLAnalyzer(method="RF")
    # model_path = "models_output/model_RF.joblib"
    # 之後可用 ml_detector.predict_attacks(封包特徵, model_path) 進行推論

    iface = "\\Device\\NPF_Loopback"  # Windows loopback 範例，請視情況修改
    print("[*] 開始監聽中: 按 Ctrl+C 結束監控...")
    try:
        sniff(filter="ip", prn=monitor.check_packet, iface=iface)
    except KeyboardInterrupt:
        print("\n[結束監聽] 偵測停止。")
    finally:
        monitor.close_log()

if __name__ == "__main__":
    main()
