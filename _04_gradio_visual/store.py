"""
04_gradio_visual/store.py

[역할]
- BackendController의 result_queue를 소비하여 내부 리스트에 누적
- Gradio 각 탭이 참조할 수 있도록 정제된 데이터를 제공
- 백그라운드 스레드로 지속 실행
"""

import threading
import logging
from queue import Queue, Empty
from datetime import datetime

logger = logging.getLogger(__name__)

# 최대 보관 건수 (메모리 보호)
MAX_RECORDS = 500


class ResultStore:
    """
    result_queue를 소비하여 분석 결과를 메모리에 누적하는 스토어.

    Gradio 대시보드의 세 탭이 모두 이 스토어를 참조한다.
    """

    def __init__(self, result_queue: Queue):
        self._queue = result_queue
        self._lock = threading.Lock()

        # 전체 결과 (최신순)
        self._records: list[dict] = []

        # 통계 카운터
        self._stats = {
            "total": 0,
            "attack": 0,
            "local": 0,
            "llm": 0,
            "rate_limited": 0,
        }

        self._running = False

    # ──────────────────────────────────────────────
    # 라이프사이클
    # ──────────────────────────────────────────────

    def start(self):
        """백그라운드 소비 스레드를 시작한다."""
        self._running = True
        t = threading.Thread(target=self._consume_loop, daemon=True)
        t.start()
        logger.info("[ResultStore] 소비 스레드 시작")

    def stop(self):
        self._running = False

    # ──────────────────────────────────────────────
    # 데이터 접근 (Gradio 콜백에서 호출)
    # ──────────────────────────────────────────────

    def get_packet_log_rows(self) -> list[list]:
        """
        패킷 로그 탭용 행 리스트 반환.
        컬럼: [시간, 출발IP, 목적IP, 메서드, URI, 위험도, 탐지방법]
        """
        with self._lock:
            rows = []
            for r in self._records:
                severity = r.get("severity", "N/A")
                rows.append([
                    r.get("timestamp", ""),
                    r.get("src_ip", ""),
                    r.get("dst_ip", ""),
                    r.get("method", ""),
                    r.get("uri", "")[:60],
                    _severity_badge(severity),
                    _source_badge(r.get("source", "")),
                ])
            return rows

    def get_ai_report_rows(self) -> list[list]:
        """
        AI 분석 리포트 탭용 행 리스트 반환.
        컬럼: [시간, 공격명, 기법, 위험도, 판단근거, 출처]
        공격으로 판정된 항목만 포함.
        """
        with self._lock:
            rows = []
            for r in self._records:
                if not r.get("is_attack"):
                    continue
                rows.append([
                    r.get("timestamp", ""),
                    r.get("attack_name", ""),
                    r.get("technique", "")[:80],
                    _severity_badge(r.get("severity", "N/A")),
                    r.get("reason", "")[:100],
                    _source_badge(r.get("source", "")),
                ])
            return rows

    def get_snort_rules_rows(self) -> list[list]:
        """
        Snort 룰 탭용 행 리스트 반환.
        컬럼: [시간, 공격명, Snort 룰]
        - LLM이 생성한 룰(source == "llm")만 포함
        - 중복 룰 제거
        """
        with self._lock:
            rows = []
            seen_rules = set()
            for r in self._records:
                # LLM이 생성한 룰만 표시
                if r.get("source") != "llm":
                    continue
                rule = r.get("snort_rule", "").strip()
                if not rule or rule in seen_rules:
                    continue
                seen_rules.add(rule)
                rows.append([
                    r.get("timestamp", ""),
                    r.get("attack_name", ""),
                    rule,
                ])
            return rows

    def get_stats(self) -> dict:
        """통계 dict 반환."""
        with self._lock:
            return dict(self._stats)

    def get_latest_record(self) -> dict | None:
        """가장 최근 수신 결과를 반환한다."""
        with self._lock:
            return self._records[0] if self._records else None

    # ──────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────

    def _consume_loop(self):
        """큐에서 결과를 꺼내 누적한다."""
        while self._running:
            try:
                result = self._queue.get(timeout=0.5)
                self._ingest(result)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"[ResultStore] 소비 중 오류: {e}")

    def _ingest(self, result: dict):
        """결과를 스토어에 저장하고 통계를 업데이트한다."""
        with self._lock:
            self._records.insert(0, result)  # 최신순 유지
            if len(self._records) > MAX_RECORDS:
                self._records.pop()

            self._stats["total"] += 1
            if result.get("is_attack"):
                self._stats["attack"] += 1
            src = result.get("source", "")
            if src in self._stats:
                self._stats[src] += 1

        logger.debug(f"[ResultStore] 결과 적재 — source={result.get('source')}")


# ──────────────────────────────────────────────────
# 배지 포매터
# ──────────────────────────────────────────────────

def _severity_badge(severity: str) -> str:
    mapping = {"HIGH": "🔴 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🟢 LOW"}
    return mapping.get(severity.upper(), severity)


def _source_badge(source: str) -> str:
    mapping = {
        "local":        "📋 로컬 룰",
        "llm":          "🧠 LLM",
        "rate_limited": "⏳ 쿨타임",
        "error":        "❌ 오류",
    }
    return mapping.get(source, source)
