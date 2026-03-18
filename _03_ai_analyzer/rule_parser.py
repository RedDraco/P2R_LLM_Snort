"""
03_ai_analyzer/rule_parser.py

[역할]
- Snort community.rules 파일을 파싱하여 메모리에 로드
- content 기반 텍스트 매칭이 가능한 룰만 추출
- hex 인코딩된 content 룰은 HTTP 텍스트 매칭에 부적합하므로 제외
"""

import re
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def parse_community_rules(filepath: str) -> list[dict]:
    """
    community.rules 파일을 파싱해 룰 목록을 반환한다.

    Args:
        filepath: community.rules 파일 경로

    Returns:
        파싱된 룰 딕셔너리 리스트.
        각 항목:
        {
            "sid":      str,         # 룰 고유 ID
            "msg":      str,         # 공격 설명 메시지
            "contents": list[str],   # 매칭 키워드 목록 (소문자 정규화)
            "raw":      str,         # 원본 룰 문자열 전체
        }

    Note:
        - 주석(#)으로 시작하는 줄은 스킵
        - content 필드가 없는 룰은 매칭 불가 → 제외
        - hex 형식 content(|XX XX|)만 있는 룰은 텍스트 매칭 불가 → 제외
    """
    path = Path(filepath)
    if not path.exists():
        logger.error(f"[RuleParser] 파일 없음: {filepath}")
        return []

    rules: list[dict] = []
    skipped_no_content = 0
    skipped_hex_only = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()

            # 주석 및 빈 줄 스킵
            if not line or line.startswith("#"):
                continue

            rule = _parse_single_rule(line)
            if rule is None:
                skipped_no_content += 1
                continue
            if not rule["contents"]:
                skipped_hex_only += 1
                continue

            rules.append(rule)

    logger.info(
        f"[RuleParser] 로드 완료 — 유효: {len(rules)}개 | "
        f"content 없음: {skipped_no_content}개 | "
        f"hex 전용: {skipped_hex_only}개"
    )
    return rules


# ──────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────

# content:"<value>" 또는 content: "<value>" 패턴
_RE_CONTENT = re.compile(r'content\s*:\s*"([^"]*)"', re.IGNORECASE)
# |XX XX| 형태의 hex 시퀀스 탐지
_RE_HEX = re.compile(r'^\|[0-9A-Fa-f\s]+\|$')
_RE_SID = re.compile(r'sid\s*:\s*(\d+)', re.IGNORECASE)
_RE_MSG = re.compile(r'msg\s*:\s*"([^"]+)"', re.IGNORECASE)


def _parse_single_rule(line: str) -> dict | None:
    """
    한 줄짜리 Snort 룰을 파싱한다.

    Returns:
        파싱 결과 dict 또는 None (content 필드 자체가 없는 경우)
    """
    # content 추출
    raw_contents = _RE_CONTENT.findall(line)
    if not raw_contents:
        return None

    # hex-only content 필터링 → 순수 텍스트 content만 유지
    text_contents = [
        c.lower()
        for c in raw_contents
        if not _RE_HEX.match(c.strip())
    ]

    sid_match = _RE_SID.search(line)
    msg_match = _RE_MSG.search(line)

    return {
        "sid": sid_match.group(1) if sid_match else "unknown",
        "msg": msg_match.group(1) if msg_match else "Unknown Attack",
        "contents": text_contents,
        "raw": line,
    }
