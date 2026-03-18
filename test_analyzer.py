"""
test_analyzer.py  (프로젝트 루트에서 실행)

[역할]
- Analyzer 클래스 전체 흐름을 직접 테스트 (소켓 불필요)
- 로컬 매칭 → LLM 분기 양쪽을 모두 검증
- OpenAI API 키 필요

[실행]
    python test_analyzer.py
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)
load_dotenv(os.path.join(ROOT_DIR, ".env"))

RULES_PATH = os.getenv("COMMUNITY_RULES_PATH", os.path.join(ROOT_DIR, "community.rules"))
MODEL      = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

from _03_ai_analyzer.analyzer import Analyzer

# ── 테스트 패킷 ───────────────────────────────────
PACKETS = [
    {
        "label": "SQL Injection (로컬 매칭 예상)",
        "data": {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "method": "GET",
            "uri":    "/user?id=1' OR '1'='1'--",
            "payload": "id=1%27+OR+%271%27%3D%271%27--",
            "clean_payload": "id=1' OR '1'='1'--",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    },
    {
        "label": "XSS (LLM 분석 예상)",
        "data": {
            "src_ip": "10.0.0.3", "dst_ip": "10.0.0.2",
            "method": "POST",
            "uri":    "/post",
            "payload": "body=<img src=x onerror=alert(document.domain)>",
            "clean_payload": "body=<img src=x onerror=alert(document.domain)>",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    },
    {
        "label": "정상 트래픽 (is_attack=False 예상)",
        "data": {
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.2",
            "method": "GET",
            "uri":    "/about",
            "payload": "lang=ko",
            "clean_payload": "lang=ko",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    },
]


def run():
    print(f"\n{'='*60}")
    print("  Analyzer 통합 단위 테스트")
    print(f"{'='*60}\n")

    if not os.path.isfile(RULES_PATH):
        print(f"[✗] community.rules 없음: {RULES_PATH}")
        sys.exit(1)

    analyzer = Analyzer(community_rules_path=RULES_PATH, openai_model=MODEL)

    for i, tc in enumerate(PACKETS, 1):
        print(f"[테스트 {i}] {tc['label']}")
        print(f"  페이로드: {tc['data']['clean_payload'][:70]}")

        result = analyzer.analyze(tc["data"])

        print(f"  출처     : {result['source']}")
        print(f"  공격여부 : {result['is_attack']}")
        print(f"  공격명   : {result['attack_name']}")
        print(f"  위험도   : {result['severity']}")
        if result["snort_rule"]:
            print(f"  Snort 룰 : {result['snort_rule'][:80]}...")
        print(f"  근거     : {result['reason'][:80]}")
        print()

    print("✅ 테스트 완료\n")


if __name__ == "__main__":
    run()
