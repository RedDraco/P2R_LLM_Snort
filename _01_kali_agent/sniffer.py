from scapy.all import sniff, IP, TCP, Raw
from packet_processor import build_json_bytes
from sender import send_data
import os
import sys

from dotenv import load_dotenv

# ── 경로 설정 ─────────────────────────────────────
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ── .env 로드 ─────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(ROOT_DIR, "..", ".env"))

INTERFACE  = os.getenv("INTERFACE")
BPF_FILTER = os.getenv("BPF_FILTER", "tcp port 80")
DEBUG      = os.getenv("DEBUG", "").lower() in ("1", "true", "yes")


HTTP_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]


def is_http_packet(payload):
    return any(payload.startswith(method) for method in HTTP_METHODS)


def packet_callback(packet):
    try:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        if not packet.haslayer(Raw):
            return

        raw_payload = packet[Raw].load

        if not is_http_packet(raw_payload):
            return

        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        decoded_payload = raw_payload.decode(errors="ignore")

        packet_data = {
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload":  decoded_payload,
        }

        if DEBUG:
            print("\n[HTTP REQUEST DETECTED]")
            print(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            print(decoded_payload[:300])

        json_bytes = build_json_bytes(packet_data)

        if json_bytes is None:
            if DEBUG:
                print("[INFO] HTTP parsing failed or not a target for sending")
            return

        if DEBUG:
            print("\n[JSON READY]")
            print(json_bytes.decode(errors="ignore"))

        send_data(json_bytes)

    except Exception as e:
        print(f"[ERROR] {e}")


def start_sniffer():
    print(f"[*] Sniffer started on interface: {INTERFACE}")
    sniff(
        iface=INTERFACE,
        filter=BPF_FILTER,
        prn=packet_callback,
        store=False,
    )


if __name__ == "__main__":
    start_sniffer()
