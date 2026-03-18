"""
02_window_backend/controller.py

[역할]
- 수신된 원시 JSON 데이터에서 HTTP 페이로드를 전처리(정제)
- 분석 결과 큐를 Gradio 대시보드와 공유
- 서버 시작 / 종료 라이프사이클 관리
"""

import logging
import urllib.parse
from queue import Queue

from .socket_server import SocketServer

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────
# 전처리 유틸리티
# ──────────────────────────────────────────────────

def preprocess_payload(raw_payload: str) -> str:
    """
    L7 HTTP 페이로드 문자열을 정제한다.

    처리 순서:
      1. URL 디코딩 (%XX → 실제 문자)
      2. 개행·탭 등 불필요한 공백 제거
      3. NULL 바이트 제거
    """
    # 1) URL 디코딩 (이중 인코딩 대응을 위해 2회 적용)
    decoded = urllib.parse.unquote(urllib.parse.unquote(raw_payload))
    # 2) NULL 바이트 제거
    decoded = decoded.replace("\x00", "")
    # 3) 과도한 공백 정리
    decoded = " ".join(decoded.split())
    return decoded.strip()


# ──────────────────────────────────────────────────
# 메인 컨트롤러
# ──────────────────────────────────────────────────

class BackendController:
    """
    02_window_backend의 최상위 진입점.

    - SocketServer를 생성·기동
    - 분석 콜백(analyzer_callback)을 주입받아 전처리 후 분석 모듈에 전달
    - result_queue를 외부(Gradio)에 노출
    """

    def __init__(self, host: str, port: int, analyzer_callback):
        """
        Args:
            host: 소켓 서버 바인딩 IP
            port: 소켓 서버 포트
            analyzer_callback: 03_ai_analyzer.analyzer.Analyzer.analyze
        """
        self.result_queue: Queue = Queue()

        # 전처리를 거친 뒤 분석 콜백을 호출하는 래퍼
        def _wrapped_callback(raw_data: dict) -> dict:
            return self._process_and_analyze(raw_data, analyzer_callback)

        self._server = SocketServer(
            host=host,
            port=port,
            analyzer_callback=_wrapped_callback,
            result_queue=self.result_queue,
        )

    def start(self):
        """백엔드(소켓 서버)를 기동한다."""
        self._server.start()
        logger.info("[BackendController] 백엔드 기동 완료")

    def stop(self):
        """백엔드를 정지한다."""
        self._server.stop()
        logger.info("[BackendController] 백엔드 종료")

    # ──────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────

    def _process_and_analyze(self, raw_data: dict, analyzer_callback) -> dict:
        """
        수신 데이터를 전처리한 뒤 분석 콜백에 전달한다.

        raw_data 예시:
        {
            "src_ip": "192.168.x.x",
            "dst_ip": "192.168.x.x",
            "method": "GET",
            "uri": "/search?q=1' OR 1=1--",
            "payload": "q=1%27+OR+1%3D1--",
            "timestamp": "2025-01-01T00:00:00"
        }
        """
        raw_payload = raw_data.get("payload", "")
        uri = raw_data.get("uri", "")

        # URI와 페이로드를 합쳐 분석 대상 문자열 구성
        combined_raw = f"{uri} {raw_payload}".strip()
        clean_payload = preprocess_payload(combined_raw)

        logger.debug(f"[Controller] 전처리 완료: {clean_payload[:100]}")

        # 전처리된 페이로드를 포함해 분석 요청
        enriched_data = {**raw_data, "clean_payload": clean_payload}
        return analyzer_callback(enriched_data)
