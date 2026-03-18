"""
03_ai_analyzer/signature_checker.py

[역할]
- 파싱된 Snort community.rules를 메모리에 보유
- HTTP 페이로드 문자열에 대해 룰 매칭 수행
- 매칭 시 해당 룰 정보를 반환 → LLM 호출 생략
- 미매칭 시 None 반환 → LLM 호출로 분기
"""

import logging

logger = logging.getLogger(__name__)


class SnortRuleMatcher:
    """
    Snort community.rules 기반 1차 시그니처 검사기.

    모든 content 조건이 페이로드에 포함된 경우에만 매칭으로 판정한다.
    (Snort의 AND 조건과 동일한 방식)
    """

    def __init__(self, rules: list[dict]):
        """
        Args:
            rules: rule_parser.parse_community_rules()의 반환값
        """
        self._rules = rules
        logger.info(f"[SnortRuleMatcher] {len(self._rules)}개 룰 준비 완료")

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def match(self, payload: str) -> dict | None:
        """
        페이로드가 알려진 Snort 룰에 매칭되는지 검사한다.

        Args:
            payload: 전처리된 HTTP 페이로드 문자열 (소문자 변환은 내부에서 처리)

        Returns:
            매칭된 룰 dict 또는 None
            매칭된 룰 dict 예시:
            {
                "sid":      "1000001",
                "msg":      "SQL Injection attempt",
                "contents": ["union select", "1=1"],
                "raw":      "alert tcp ... (msg:...; sid:...;)"
            }
        """
        payload_lower = payload.lower()

        for rule in self._rules:
            if self._is_match(rule["contents"], payload_lower):
                logger.info(
                    f"[SnortRuleMatcher] 매칭 — SID: {rule['sid']} | {rule['msg']}"
                )
                return rule

        return None

    def rule_count(self) -> int:
        """로드된 룰 수를 반환한다."""
        return len(self._rules)

    # ──────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────

    @staticmethod
    def _is_match(contents: list[str], payload_lower: str) -> bool:
        """
        모든 content 조건이 페이로드에 포함되는지 확인한다.

        빈 content 리스트는 매칭하지 않는다.
        """
        if not contents:
            return False
        return all(keyword in payload_lower for keyword in contents)
