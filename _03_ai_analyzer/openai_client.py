"""
03_ai_analyzer/openai_client.py

[역할]
- .env 파일에서 API 키를 안전하게 로드 (소스코드에 키 하드코딩 금지)
- OpenAI Chat Completions API 호출
- Rate Limit(쿨타임) 안전장치: 지정된 간격 내 중복 호출 차단
- 재시도(Retry) 로직: 일시적 API 오류 자동 복구
"""

import logging
import time
import threading
from functools import wraps

from openai import OpenAI, APIError, RateLimitError
from dotenv import load_dotenv
import os

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────
# 환경 변수 로드 (.env)
# ──────────────────────────────────────────────────

def _load_api_key() -> str:
    """
    .env 파일에서 OPENAI_API_KEY를 로드한다.

    .env 파일 위치: project-root/.env
    포맷 예시:
        OPENAI_API_KEY=sk-...

    보안 원칙:
        - .env는 절대 git에 커밋하지 않는다 (.gitignore에 등록 필수)
        - 소스코드에 키를 직접 입력하지 않는다
    """
    # 프로젝트 루트의 .env 탐색 (현재 파일 기준 2단계 상위)
    env_path = os.path.join(
        os.path.dirname(__file__), "..", ".env"
    )
    load_dotenv(dotenv_path=env_path)

    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise EnvironmentError(
            "[OpenAIClient] OPENAI_API_KEY가 설정되지 않았습니다.\n"
            "프로젝트 루트에 .env 파일을 생성하고 아래 형식으로 키를 입력하세요:\n"
            "  OPENAI_API_KEY=sk-..."
        )
    return api_key


# ──────────────────────────────────────────────────
# Rate Limit 데코레이터
# ──────────────────────────────────────────────────

def rate_limited(min_interval_sec: float):
    """
    동일 함수의 연속 호출 간격을 min_interval_sec 이상으로 강제한다.

    대량 패킷 유입 시 API 과부하 및 비용 폭탄을 방지하기 위한 안전장치.
    쿨타임이 지나지 않은 호출은 None을 반환한다.
    """
    lock = threading.Lock()
    last_called = [0.0]  # mutable container for closure

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                elapsed = time.time() - last_called[0]
                if elapsed < min_interval_sec:
                    remaining = min_interval_sec - elapsed
                    logger.warning(
                        f"[RateLimit] 쿨타임 중 — {remaining:.1f}초 후 재호출 가능"
                    )
                    return None  # 호출 스킵
                last_called[0] = time.time()
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ──────────────────────────────────────────────────
# OpenAI 클라이언트
# ──────────────────────────────────────────────────

class OpenAIClient:
    """
    OpenAI Chat Completions API 래퍼.

    - API 키를 .env에서 로드
    - Rate Limit 쿨타임 적용 (기본 10초)
    - 일시적 오류 시 최대 3회 재시도
    """

    # LLM 호출 간 최소 간격(초) — 필요에 따라 조정
    RATE_LIMIT_INTERVAL = 10.0
    # 재시도 횟수
    MAX_RETRIES = 3
    # 재시도 대기 시간(초)
    RETRY_DELAY = 2.0

    def __init__(self, model: str = "gpt-4o-mini"):
        """
        Args:
            model: 사용할 OpenAI 모델 (기본: gpt-4o-mini, 비용 효율적)
        """
        self.model = model
        self._client = OpenAI(api_key=_load_api_key())
        logger.info(f"[OpenAIClient] 초기화 완료 — 모델: {self.model}")

    def call(self, system_prompt: str, user_prompt: str) -> str | None:
        """
        Rate Limit이 적용된 API 호출 진입점.

        Returns:
            응답 텍스트 또는 None (쿨타임 중이거나 오류 시)
        """
        return self._rate_limited_call(system_prompt, user_prompt)

    # rate_limited 데코레이터를 인스턴스 메서드에 적용하기 위해
    # 클래스 외부에서 _raw_call을 래핑
    def _rate_limited_call(self, system_prompt: str, user_prompt: str) -> str | None:
        return self.__class__._apply_rate_limit(
            self, system_prompt, user_prompt
        )

    @staticmethod
    def _apply_rate_limit(instance, system_prompt: str, user_prompt: str) -> str | None:
        # 클래스 레벨 쿨타임 상태 (모든 인스턴스 공유)
        if not hasattr(OpenAIClient, "_last_call_time"):
            OpenAIClient._last_call_time = 0.0
            OpenAIClient._lock = threading.Lock()

        with OpenAIClient._lock:
            elapsed = time.time() - OpenAIClient._last_call_time
            if elapsed < OpenAIClient.RATE_LIMIT_INTERVAL:
                remaining = OpenAIClient.RATE_LIMIT_INTERVAL - elapsed
                logger.warning(
                    f"[RateLimit] 쿨타임 중 — {remaining:.1f}초 후 재호출 가능"
                )
                return None
            OpenAIClient._last_call_time = time.time()

        return instance._raw_call(system_prompt, user_prompt)

    def _raw_call(self, system_prompt: str, user_prompt: str) -> str | None:
        """
        실제 API 호출 (재시도 포함).
        """
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.2,  # 분석 결과의 일관성을 위해 낮게 설정
                    max_tokens=800,
                )
                result = response.choices[0].message.content.strip()
                logger.info(f"[OpenAIClient] 응답 수신 완료 (시도 {attempt}회)")
                return result

            except RateLimitError:
                logger.warning(
                    f"[OpenAIClient] OpenAI RateLimitError — "
                    f"{self.RETRY_DELAY * attempt}초 후 재시도 ({attempt}/{self.MAX_RETRIES})"
                )
                time.sleep(self.RETRY_DELAY * attempt)

            except APIError as e:
                logger.error(f"[OpenAIClient] APIError: {e} (시도 {attempt}/{self.MAX_RETRIES})")
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.RETRY_DELAY)
                else:
                    return None

            except Exception as e:
                logger.error(f"[OpenAIClient] 예상치 못한 오류: {e}")
                return None

        return None
