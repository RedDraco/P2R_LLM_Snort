import socket
import os
import sys
import time

from dotenv import load_dotenv

# ── 경로 설정 ─────────────────────────────────────
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ── .env 로드 ─────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(ROOT_DIR, ".env"))

SERVER_IP   = os.getenv("SERVER_IP")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9999"))

# ── 연결 재시도 설정 ──────────────────────────────
_RECONNECT_DELAY = 3.0

# ── 전역 소켓 (연결 유지) ─────────────────────────
# 패킷마다 새 연결을 열면 오버헤드가 크므로 1개 연결을 유지한다.
_sock: socket.socket | None = None


def _connect() -> socket.socket:
    """서버에 연결하고 소켓을 반환한다. 실패 시 재시도."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            print(f"[SENDER] 서버 연결 성공: {SERVER_IP}:{SERVER_PORT}")
            return s
        except (ConnectionRefusedError, OSError) as e:
            print(f"[SENDER] 연결 실패: {e} — {_RECONNECT_DELAY}초 후 재시도...")
            time.sleep(_RECONNECT_DELAY)


def send_data(data: bytes):
    """
    Windows 소켓 서버로 데이터를 전송한다.

    [프로토콜 - socket_server.py와 동일]
      [4바이트 big-endian 길이 헤더] + [UTF-8 JSON 본문]

      Windows 서버(socket_server.py)가 4바이트 헤더 방식을 사용
    """
    global _sock

    # newline 구분자 제거 — 순수 JSON bytes만 추출
    # packet_processor.py의 build_json_bytes()가 \n을 붙이므로 제거
    clean_data = data.rstrip(b"\n")

    # 4바이트 big-endian 길이 헤더 생성
    header = len(clean_data).to_bytes(4, byteorder="big")
    packet = header + clean_data

    # 최대 2회 시도 (1회 실패 시 재연결 후 재전송)
    for attempt in range(2):
        try:
            if _sock is None:
                _sock = _connect()
            _sock.sendall(packet)
            return
        except (BrokenPipeError, OSError) as e:
            print(f"[SENDER] 전송 실패 (시도 {attempt + 1}): {e} — 재연결...")
            try:
                _sock.close()
            except Exception:
                pass
            _sock = None

    print("[SENDER ERROR] 재연결 후에도 전송 실패")
