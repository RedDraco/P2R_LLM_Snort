"""
02_window_backend/socket_server.py

[역할]
- Kali(01_kali_agent)로부터 JSON 패킷 데이터를 소켓으로 수신
- 수신 즉시 03_ai_analyzer로 분석 요청을 전달
- 분석 결과를 공유 큐(shared_queue)에 적재하여 04_gradio_visual에서 참조
"""

import socket
import threading
import json
import logging
from queue import Queue

logger = logging.getLogger(__name__)


class SocketServer:
    """
    Kali 에이전트로부터 패킷 데이터를 수신하는 TCP 소켓 서버.

    수신된 JSON 데이터를 analyzer_callback을 통해 분석 모듈로 전달하고,
    결과를 result_queue에 넣어 Gradio 대시보드에서 실시간으로 읽을 수 있도록 한다.
    """

    def __init__(
        self,
        host: str,
        port: int,
        analyzer_callback,
        result_queue: Queue,
    ):
        """
        Args:
            host: 바인딩할 IP (보통 '0.0.0.0')
            port: 수신 포트
            analyzer_callback: 분석 함수 (03_ai_analyzer.analyzer.analyze)
            result_queue: Gradio와 공유하는 결과 큐
        """
        self.host = host
        self.port = port
        self.analyzer_callback = analyzer_callback
        self.result_queue = result_queue
        self._server_socket = None
        self._running = False

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def start(self):
        """서버를 별도 스레드로 기동한다."""
        self._running = True
        thread = threading.Thread(target=self._serve, daemon=True)
        thread.start()
        logger.info(f"[SocketServer] 서버 시작: {self.host}:{self.port}")

    def stop(self):
        """서버를 정지한다."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        logger.info("[SocketServer] 서버 종료")

    # ──────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────

    def _serve(self):
        """메인 accept 루프."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 포트 재사용 허용 (빠른 재시작 지원)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)

        while self._running:
            try:
                conn, addr = self._server_socket.accept()
                logger.info(f"[SocketServer] 연결: {addr}")
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                client_thread.start()
            except OSError:
                # stop() 호출 시 소켓이 닫혀 accept()가 예외를 던짐 → 정상 종료
                break

    def _handle_client(self, conn: socket.socket, addr):
        """
        단일 클라이언트(Kali)와의 통신을 처리한다.

        프로토콜:
          - 4바이트 big-endian unsigned int로 메시지 길이를 먼저 수신
          - 이후 해당 길이만큼 UTF-8 JSON 바이트를 수신
        """
        buffer = b""
        with conn:
            while True:
                try:
                    # 1) 헤더(4바이트) 수신
                    header = self._recv_exact(conn, 4)
                    if not header:
                        break
                    msg_len = int.from_bytes(header, byteorder="big")

                    # 2) 본문 수신
                    raw = self._recv_exact(conn, msg_len)
                    if not raw:
                        break

                    # 3) JSON 파싱
                    data = json.loads(raw.decode("utf-8"))
                    payload = data.get("payload", "")
                    logger.debug(f"[SocketServer] 수신: {payload[:80]}...")

                    # 4) 분석 요청 (비동기 처리로 수신 루프 블로킹 방지)
                    threading.Thread(
                        target=self._analyze_and_enqueue,
                        args=(data,),
                        daemon=True,
                    ).start()

                except (ConnectionResetError, json.JSONDecodeError) as e:
                    logger.warning(f"[SocketServer] 클라이언트 오류 ({addr}): {e}")
                    break

        logger.info(f"[SocketServer] 연결 종료: {addr}")

    def _analyze_and_enqueue(self, data: dict):
        """분석 후 결과를 큐에 적재한다."""
        try:
            result = self.analyzer_callback(data)
            self.result_queue.put(result)
        except Exception as e:
            logger.error(f"[SocketServer] 분석 중 오류: {e}")

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
        """
        정확히 n바이트를 수신한다.
        연결이 끊기면 None을 반환한다.
        """
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf
