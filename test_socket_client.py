"""
test_socket_client.py  (프로젝트 루트에서 실행)

[역할]
실제 Kali 없이 Windows 서버를 테스트하기 위한 모의 패킷 전송기.
다양한 공격 유형의 HTTP 페이로드를 소켓으로 전송한다.

[실행]
    # Windows 서버(run_windows.py)를 먼저 실행한 후
    python test_socket_client.py

[옵션]
    python test_socket_client.py --host 127.0.0.1 --port 9999 --delay 2
"""

import argparse
import json
import socket
import time
from datetime import datetime

# ──────────────────────────────────────────────────
# 테스트 패킷 데이터셋
# ──────────────────────────────────────────────────

TEST_PACKETS = [
    # 1. SQL Injection (community.rules 매칭 예상)
    {
        "src_ip":    "192.168.100.10",
        "dst_ip":    "192.168.100.1",
        "method":    "GET",
        "uri":       "/login?id=1' OR '1'='1'--&pw=anything",
        "payload":   "id=1%27+OR+%271%27%3D%271%27--&pw=anything",
        "timestamp": "",
    },
    # 2. XSS (LLM 분석 예상)
    {
        "src_ip":    "192.168.100.11",
        "dst_ip":    "192.168.100.1",
        "method":    "POST",
        "uri":       "/comment",
        "payload":   "content=<script>document.cookie='stolen='+document.cookie</script>",
        "timestamp": "",
    },
    # 3. Path Traversal (community.rules 매칭 예상)
    {
        "src_ip":    "192.168.100.12",
        "dst_ip":    "192.168.100.1",
        "method":    "GET",
        "uri":       "/download?file=../../../../etc/passwd",
        "payload":   "file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "timestamp": "",
    },
    # 4. Command Injection (LLM 분석 예상)
    {
        "src_ip":    "192.168.100.13",
        "dst_ip":    "192.168.100.1",
        "method":    "POST",
        "uri":       "/ping",
        "payload":   "host=127.0.0.1;cat /etc/shadow",
        "timestamp": "",
    },
    # 5. 정상 트래픽 (공격 아님)
    {
        "src_ip":    "192.168.100.20",
        "dst_ip":    "192.168.100.1",
        "method":    "GET",
        "uri":       "/index.html",
        "payload":   "q=hello+world",
        "timestamp": "",
    },
    # 6. Union-based SQL Injection
    {
        "src_ip":    "192.168.100.14",
        "dst_ip":    "192.168.100.1",
        "method":    "GET",
        "uri":       "/search?q=1 UNION SELECT username,password FROM users--",
        "payload":   "q=1+UNION+SELECT+username%2Cpassword+FROM+users--",
        "timestamp": "",
    },
    # 7. HTTP Header Injection
    {
        "src_ip":    "192.168.100.15",
        "dst_ip":    "192.168.100.1",
        "method":    "POST",
        "uri":       "/redirect",
        "payload":   "url=http://evil.com%0d%0aSet-Cookie:+admin=true",
        "timestamp": "",
    },
]


# ──────────────────────────────────────────────────
# 소켓 전송 유틸
# ──────────────────────────────────────────────────

def send_packet(sock: socket.socket, data: dict):
    """
    4바이트 헤더 + JSON 본문 프로토콜로 패킷을 전송한다.
    socket_server.py의 수신 프로토콜과 쌍을 이룬다.
    """
    data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    header = len(raw).to_bytes(4, byteorder="big")
    sock.sendall(header + raw)


def run(host: str, port: int, delay: float):
    print(f"\n{'='*55}")
    print(f"  테스트 클라이언트 → {host}:{port}")
    print(f"  패킷 수: {len(TEST_PACKETS)}개 | 전송 간격: {delay}초")
    print(f"{'='*55}\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            print(f"[✓] 서버 연결 성공: {host}:{port}\n")

            for i, packet in enumerate(TEST_PACKETS, 1):
                label = f"[{i}/{len(TEST_PACKETS)}]"
                method = packet["method"]
                uri    = packet["uri"][:55]
                print(f"{label} 전송 중... {method} {uri}")
                send_packet(s, dict(packet))  # 원본 수정 방지를 위해 복사
                time.sleep(delay)

            print(f"\n[✓] 전체 {len(TEST_PACKETS)}개 전송 완료")
            print("    대시보드에서 결과를 확인하세요: http://localhost:7860\n")

    except ConnectionRefusedError:
        print(f"\n[✗] 연결 실패 — {host}:{port} 서버가 실행 중인지 확인하세요.")
        print("    → run_windows.py를 먼저 실행하세요.\n")
    except Exception as e:
        print(f"\n[✗] 오류 발생: {e}\n")


# ──────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="모의 패킷 전송 테스트 클라이언트")
    parser.add_argument("--host",  default="127.0.0.1", help="서버 IP (기본: 127.0.0.1)")
    parser.add_argument("--port",  default=9999, type=int, help="서버 포트 (기본: 9999)")
    parser.add_argument("--delay", default=2.0, type=float, help="패킷 간 전송 간격(초) (기본: 2)")
    args = parser.parse_args()

    run(args.host, args.port, args.delay)
