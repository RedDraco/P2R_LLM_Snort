"""
03_ai_analyzer/analyzer.py

[역할]
- 1차: Snort community.rules 기반 로컬 시그니처 매칭
- 2차: 미탐지 패킷에 한해 OpenAI API 호출
- 최종 결과를 통일된 dict 형태로 반환
"""

import json
import logging
import re
from datetime import datetime

from .rule_parser import parse_community_rules
from .signature_checker import SnortRuleMatcher
from .openai_client import OpenAIClient
from .prompt_templates import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)


class Analyzer:
    """
    HTTP 패킷 페이로드를 분석하는 통합 분석기.

    흐름:
        패킷 수신
          ↓
        로컬 Snort 룰 매칭?
          ├── YES → 기존 룰 결과 반환 (LLM 미호출)
          └── NO  → OpenAI API 호출 → JSON 파싱 → 결과 반환
    """

    def __init__(self, community_rules_path: str, openai_model: str = "gpt-4o-mini"):
        """
        Args:
            community_rules_path: community.rules 파일 경로
            openai_model: 사용할 OpenAI 모델명
        """
        # 서버 시작 시 1회만 룰 로드 (매 요청마다 파일 읽기 방지)
        rules = parse_community_rules(community_rules_path)
        self._matcher = SnortRuleMatcher(rules)
        self._llm = OpenAIClient(model=openai_model)

        logger.info(
            f"[Analyzer] 초기화 완료 — "
            f"룰 {self._matcher.rule_count()}개 로드 | 모델: {openai_model}"
        )

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def analyze(self, data: dict) -> dict:
        """
        패킷 데이터를 분석하고 결과를 반환한다.

        Args:
            data: BackendController에서 전달된 패킷 + clean_payload 포함 dict

        Returns:
            통일된 분석 결과 dict:
            {
                "timestamp":   str,
                "src_ip":      str,
                "dst_ip":      str,
                "method":      str,
                "uri":         str,
                "payload":     str,
                "source":      "local" | "llm" | "rate_limited" | "error",
                "is_attack":   bool,
                "attack_name": str,
                "technique":   str,
                "severity":    "HIGH" | "MEDIUM" | "LOW" | "N/A",
                "snort_rule":  str,
                "reason":      str,
            }
        """
        uri = data.get("uri", "")
        clean_payload = data.get("clean_payload", "")

        # 1차: 로컬 시그니처 매칭
        matched_rule = self._matcher.match(clean_payload)
        if matched_rule:
            return self._build_local_result(data, matched_rule)

        # 2차: 정적 리소스 화이트리스트
        safe_extensions = (
            ".jpg", ".jpeg", ".png", ".gif", ".css",
            ".js", ".woff", ".ico", ".svg"
        )

        is_static_ext = any(uri.lower().endswith(ext) for ext in safe_extensions)
        has_no_params = "?" not in uri and "=" not in clean_payload

        if is_static_ext and has_no_params:
            return self._build_error_result(
                data, "skip", "Safe Static Resource (No Params)"
            )

        # 3차: 위험 징후 스코어링
        if not self._is_suspicious(uri, clean_payload):
            return self._build_error_result(
                data, "skip", "Normal traffic (Low risk score)"
            )

        # 4차: LLM 분석
        return self._llm_analyze(data)

    def _is_suspicious(self, uri: str, payload: str) -> bool:
        """
        패킷이 AI 분석을 받을 만큼 의심스러운 요소가 있는지 검사한다.
        시연을 위해 임계치를 대폭 낮춤 (특수문자 1개라도 있으면 AI 분석)
        """
        danger_patterns = [
            "select", "union", "insert", "drop", "--", "case when", "or", "and", "'" ,
            "<script", "alert(", "onerror", "eval(",
            "../", "/etc/", "boot.ini", ".exe",
            "<?php", "${", "getruntime"
        ]

        target = (uri + payload).lower()

        # 1. 위험 키워드 포함 시 무조건 AI 분석
        if any(p in target for p in danger_patterns):
            return True

        # 2. 특수문자 임계치 완화 (특수문자가 1개라도 있으면 AI 분석으로 토스)
        special_chars = set("!@#$%^&*()[]{};:'\",.<>?/\\|")
        special_count = sum(1 for char in target if char in special_chars)
        
        if special_count > 0:  # 25% 비율 대신 '존재 여부'로 변경
            return True

        return False

   
    # ──────────────────────────────────────────────
    # Internal — 로컬 결과 생성
    # ──────────────────────────────────────────────

    @staticmethod
    def _build_local_result(data: dict, rule: dict) -> dict:
        """로컬 룰 매칭 결과를 통일된 형태로 변환한다."""
        logger.info(f"[Analyzer] 로컬 탐지 — {rule['msg']} (SID: {rule['sid']})")
        return {
            "timestamp":   data.get("timestamp", _now()),
            "src_ip":      data.get("src_ip", "N/A"),
            "dst_ip":      data.get("dst_ip", "N/A"),
            "method":      data.get("method", "N/A"),
            "uri":         data.get("uri", "N/A"),
            "payload":     data.get("clean_payload", ""),
            "source":      "local",
            "is_attack":   True,
            "attack_name": rule["msg"],
            "technique":   f"Snort SID {rule['sid']} 패턴에 매칭된 알려진 공격",
            "severity":    "HIGH",
            "snort_rule":  rule["raw"],
            "reason":      (
                f"community.rules SID {rule['sid']}에 정의된 시그니처와 일치합니다. "
                f"매칭 키워드: {', '.join(rule['contents'][:3])}"
            ),
        }

    # ──────────────────────────────────────────────
    # Internal — LLM 분석
    # ──────────────────────────────────────────────

    def _llm_analyze(self, data: dict) -> dict:
        """OpenAI API를 호출하여 분석 결과를 반환한다."""
        user_prompt = build_user_prompt(data)
        raw_response = self._llm.call(SYSTEM_PROMPT, user_prompt)

        # Rate Limit 쿨타임 중
        if raw_response is None:
            logger.warning("[Analyzer] Rate Limit — LLM 호출 스킵")
            return self._build_error_result(
                data,
                source="rate_limited",
                reason="Rate Limit 쿨타임 중. 잠시 후 재시도됩니다.",
            )

        # JSON 파싱
        parsed = _parse_llm_json(raw_response)
        if parsed is None:
            logger.error(f"[Analyzer] LLM 응답 파싱 실패: {raw_response[:200]}")
            return self._build_error_result(
                data,
                source="error",
                reason="LLM 응답 파싱 실패. 원본 로그를 확인하세요.",
            )

        logger.info(
            f"[Analyzer] LLM 탐지 — "
            f"is_attack={parsed.get('is_attack')} | {parsed.get('attack_name')}"
        )

        return {
            "timestamp":   data.get("timestamp", _now()),
            "src_ip":      data.get("src_ip", "N/A"),
            "dst_ip":      data.get("dst_ip", "N/A"),
            "method":      data.get("method", "N/A"),
            "uri":         data.get("uri", "N/A"),
            "payload":     data.get("clean_payload", ""),
            "source":      "llm",
            "is_attack":   bool(parsed.get("is_attack", False)),
            "attack_name": parsed.get("attack_name", "N/A"),
            "technique":   parsed.get("technique", "N/A"),
            "severity":    parsed.get("severity", "N/A"),
            "snort_rule":  parsed.get("snort_rule", ""),
            "reason":      parsed.get("reason", "N/A"),
        }

    @staticmethod
    def _build_error_result(data: dict, source: str, reason: str) -> dict:
        """오류/스킵 상황의 결과 dict를 생성한다."""
        return {
            "timestamp":   data.get("timestamp", _now()),
            "src_ip":      data.get("src_ip", "N/A"),
            "dst_ip":      data.get("dst_ip", "N/A"),
            "method":      data.get("method", "N/A"),
            "uri":         data.get("uri", "N/A"),
            "payload":     data.get("clean_payload", ""),
            "source":      source,
            "is_attack":   False,
            "attack_name": "N/A",
            "technique":   "N/A",
            "severity":    "N/A",
            "snort_rule":  "",
            "reason":      reason,
        }


# ──────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse_llm_json(raw: str) -> dict | None:
    """
    LLM 응답 문자열에서 JSON을 추출·파싱한다.

    LLM이 ```json ... ``` 마크다운 펜스를 붙이는 경우도 처리한다.
    """
    # 마크다운 코드 블록 제거
    cleaned = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # 중괄호 범위만 추출 시도
        match = re.search(r'\{.*\}', cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return None
