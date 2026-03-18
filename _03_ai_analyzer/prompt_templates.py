"""
03_ai_analyzer/prompt_templates.py

[역할]
- OpenAI API에 전달할 시스템 프롬프트 및 사용자 프롬프트 템플릿 정의
- 일관된 JSON 응답 구조를 강제하여 파싱 안정성 확보
"""

# ──────────────────────────────────────────────────
# 시스템 프롬프트
# ──────────────────────────────────────────────────

SYSTEM_PROMPT = """당신은 네트워크 보안 전문가입니다.
HTTP 패킷 페이로드를 분석하여 공격 여부를 판단하고, Snort v2.9.x 룰을 생성합니다.

반드시 아래 JSON 형식으로만 응답하세요. 다른 텍스트는 절대 포함하지 마세요.

{
  "is_attack": true 또는 false,
  "attack_name": "공격 유형명 (예: SQL Injection, XSS, Command Injection 등)",
  "technique": "구체적인 공격 기법 설명 (1~2문장)",
  "severity": "HIGH 또는 MEDIUM 또는 LOW",
  "snort_rule": "완성된 Snort v2.9.x 룰 문자열",
  "reason": "판단 근거 (2~3문장)"
}

Snort 룰 작성 규칙:
- 형식: alert tcp any any -> any any (msg:"..."; content:"..."; nocase; sid:9000001; rev:1;)
- sid는 9000001부터 시작
- content는 페이로드에서 탐지된 핵심 패턴을 사용
- is_attack이 false인 경우 snort_rule은 빈 문자열("")로 설정
"""


# ──────────────────────────────────────────────────
# 사용자 프롬프트 생성기
# ──────────────────────────────────────────────────

def build_user_prompt(data: dict) -> str:
    """
    분석 요청용 사용자 프롬프트를 생성한다.

    Args:
        data: BackendController에서 전달된 패킷 정보 dict
              필드: src_ip, dst_ip, method, uri, clean_payload, timestamp

    Returns:
        포맷된 프롬프트 문자열
    """
    return f"""다음 HTTP 패킷을 분석하세요.

[패킷 정보]
- 출발지 IP : {data.get('src_ip', 'N/A')}
- 목적지 IP : {data.get('dst_ip', 'N/A')}
- HTTP 메서드: {data.get('method', 'N/A')}
- URI       : {data.get('uri', 'N/A')}
- 타임스탬프 : {data.get('timestamp', 'N/A')}

[분석 대상 페이로드]
{data.get('clean_payload', '')}

위 페이로드가 악성 공격인지 분석하고, JSON 형식으로 응답하세요."""
