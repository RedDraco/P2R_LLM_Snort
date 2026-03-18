"""
test_local_rules.py  (프로젝트 루트에서 실행)

[역할]
- API 키 / 서버 구동 없이 로컬 룰 파싱·매칭 로직을 빠르게 검증
- community.rules 파일이 올바르게 로드되는지 확인
- 각 공격 패턴이 정상적으로 매칭되는지 확인

[실행]
    python test_local_rules.py
    python test_local_rules.py --rules ./community.rules
"""

import argparse
import os
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)

from _03_ai_analyzer.rule_parser import parse_community_rules
from _03_ai_analyzer.signature_checker import SnortRuleMatcher

# ── 테스트 케이스 ──────────────────────────────────
# (payload, 예상_매칭_여부, 설명)
TEST_CASES = [
    ("1' OR '1'='1'-- ",                  True,  "SQL Injection (OR 1=1)"),
    ("1 UNION SELECT username FROM users", True,  "SQL Injection (UNION SELECT)"),
    ("<script>alert(1)</script>",          True,  "XSS (script 태그)"),
    ("../../../../etc/passwd",             True,  "Path Traversal"),
    ("cmd.exe /c whoami",                  True,  "Windows CMD Injection"),
    ("hello world this is normal traffic", False, "정상 트래픽"),
    ("GET /index.html HTTP/1.1",           False, "정상 HTTP 요청"),
]


def run(rules_path: str):
    print(f"\n{'='*60}")
    print("  로컬 Snort 룰 매칭 단위 테스트")
    print(f"  룰 파일: {rules_path}")
    print(f"{'='*60}\n")

    # 룰 로드
    if not os.path.isfile(rules_path):
        print(f"[✗] community.rules 파일 없음: {rules_path}")
        print("    → Snort 공식 사이트에서 다운로드 후 프로젝트 루트에 배치하세요.")
        print("    → https://www.snort.org/downloads#rules\n")
        sys.exit(1)

    rules = parse_community_rules(rules_path)
    matcher = SnortRuleMatcher(rules)

    print(f"[✓] 룰 로드 완료: {matcher.rule_count()}개\n")
    print(f"{'번호':<4} {'결과':<6} {'예상':<6} {'설명':<35} 매칭 룰")
    print("-" * 90)

    passed = 0
    failed = 0

    for i, (payload, expected, desc) in enumerate(TEST_CASES, 1):
        matched = matcher.match(payload)
        is_match = matched is not None
        ok = is_match == expected

        result_icon = "✓" if ok else "✗"
        match_icon  = "탐지" if is_match else "정상"
        exp_icon    = "탐지" if expected  else "정상"
        rule_info   = f"SID {matched['sid']}: {matched['msg'][:40]}" if matched else "—"

        print(f"[{result_icon}] {i:<3} {match_icon:<6} {exp_icon:<6} {desc:<35} {rule_info}")

        if ok:
            passed += 1
        else:
            failed += 1

    print("-" * 90)
    print(f"\n결과: {passed}개 통과 / {failed}개 실패 (전체 {len(TEST_CASES)}개)\n")

    if failed == 0:
        print("✅ 모든 테스트 통과! 서버를 실행해도 됩니다.")
    else:
        print("⚠️  일부 테스트 실패. community.rules 파일을 확인하거나")
        print("   테스트 케이스 패턴을 조정해보세요.")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="로컬 룰 매칭 단위 테스트")
    parser.add_argument(
        "--rules",
        default=os.path.join(ROOT_DIR, "community.rules"),
        help="community.rules 경로 (기본: 프로젝트 루트)",
    )
    args = parser.parse_args()
    run(args.rules)
