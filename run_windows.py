"""
run_windows.py

[역할]
- 02_window_backend / 03_ai_analyzer / 04_gradio_visual 통합 기동
- .env에서 모든 설정값 로드
- Ctrl+C로 안전하게 전체 종료

[실행]
    python run_windows.py

[사전 조건]
    1. 프로젝트 루트에 .env 파일이 존재해야 합니다.
       (.env.example을 복사하여 API 키 입력)
    2. 프로젝트 루트에 community.rules 파일이 존재해야 합니다.
    3. pip install -r requirements.txt 완료
"""

import logging
import os
import sys

from dotenv import load_dotenv

# ── 경로 설정 ─────────────────────────────────────
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ── .env 로드 (import 전에 먼저 실행) ─────────────
load_dotenv(dotenv_path=os.path.join(ROOT_DIR, ".env"))

# ── 로깅 설정 ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(ROOT_DIR, "windows_server.log"),
            encoding="utf-8",
        ),
    ],
)
logger = logging.getLogger("run_windows")

# ── 설정값 ────────────────────────────────────────
SOCKET_HOST          = os.getenv("SOCKET_HOST", "0.0.0.0")
SOCKET_PORT          = int(os.getenv("SOCKET_PORT", "9999"))
OPENAI_MODEL         = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
COMMUNITY_RULES_PATH = os.getenv(
    "COMMUNITY_RULES",
    os.path.join(ROOT_DIR, "community.rules"),
)
GRADIO_PORT = int(os.getenv("GRADIO_PORT", "7860"))


def _check_prerequisites():
    """실행 전 필수 파일·환경변수를 검사한다."""
    errors = []

    if not os.path.isfile(COMMUNITY_RULES_PATH):
        errors.append(
            f"  ✗ community.rules 파일 없음: {COMMUNITY_RULES_PATH}\n"
            "    → https://www.snort.org/downloads#rules 에서 다운로드 후\n"
            "      프로젝트 루트(run_windows.py 와 같은 폴더)에 배치하세요."
        )

    if not os.getenv("OPENAI_API_KEY"):
        errors.append(
            "  ✗ OPENAI_API_KEY 미설정\n"
            "    → 프로젝트 루트의 .env 파일에 키를 입력하세요.\n"
            "    → cp .env.example .env  →  OPENAI_API_KEY=sk-..."
        )

    if errors:
        logger.error("사전 조건 미충족:\n" + "\n".join(errors))
        sys.exit(1)


def main():
    _check_prerequisites()

    logger.info("=" * 60)
    logger.info("  🛡️  LLM 기반 HTTP 패킷 분석 서버 기동")
    logger.info(f"  소켓 수신  : {SOCKET_HOST}:{SOCKET_PORT}")
    logger.info(f"  OpenAI 모델: {OPENAI_MODEL}")
    logger.info(f"  Snort 룰   : {COMMUNITY_RULES_PATH}")
    logger.info(f"  대시보드   : http://localhost:{GRADIO_PORT}")
    logger.info("=" * 60)

    # ── 03: 분석기 초기화 ─────────────────────────
    from _03_ai_analyzer.analyzer import Analyzer

    analyzer = Analyzer(
        community_rules_path=COMMUNITY_RULES_PATH,
        openai_model=OPENAI_MODEL,
    )

    # ── 02: 백엔드(소켓 서버) 초기화 및 기동 ─────
    from _02_window_backend.controller import BackendController

    backend = BackendController(
        host=SOCKET_HOST,
        port=SOCKET_PORT,
        analyzer_callback=analyzer.analyze,
    )
    backend.start()

    # ── 04: Gradio 대시보드 기동 (블로킹) ────────
    from _04_gradio_visual.dashboard import launch_dashboard

    try:
        launch_dashboard(
            result_queue=backend.result_queue,
            server_port=GRADIO_PORT,
        )
    except KeyboardInterrupt:
        logger.info("종료 신호 수신 — 서버 정지 중...")
    finally:
        backend.stop()
        logger.info("정상 종료 완료.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # 더블클릭 실행 시 오류가 발생해도 창이 바로 닫히지 않도록
        import traceback
        print("\n" + "=" * 60)
        print("  [오류] 서버 실행 중 문제가 발생했습니다.")
        print("=" * 60)
        traceback.print_exc()
        print("\n자주 발생하는 원인:")
        print("  1. .env 파일에 OPENAI_API_KEY가 없거나 잘못됨")
        print("  2. community.rules 파일이 이 폴더에 없음")
        print("  3. pip install -r requirements.txt 미실행")
        print("  4. 폴더명이 _02_, _03_, _04_ 형식인지 확인")
        print("\n위 내용을 확인한 후 다시 실행하세요.")
        print("=" * 60)
    finally:
        input("\n[Enter 키를 누르면 창이 닫힙니다]")

# ── 더블클릭 실행 보호 ────────────────────────────
# 위의 main() 호출을 아래로 교체
