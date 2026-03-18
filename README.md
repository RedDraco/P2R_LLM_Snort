# 🛡️ LLM 기반 HTTP 패킷 분석 & Snort 룰 생성기

## 📁 프로젝트 구조

```
project-root/
│
├── .env                    ← ⚠️ 직접 생성 필요 (git 제외)
├── .env.example            ← 키 형식 참고용
├── .gitignore
├── requirements.txt
├── community.rules         ← ⚠️ 직접 다운로드 필요 (git 제외)
│
├── run_windows.py          ← Windows 통합 실행 진입점
│
├── _02_window_backend/     ← 소켓 수신 + 전처리
│   ├── __init__.py
│   ├── socket_server.py
│   └── controller.py
│
├── _03_ai_analyzer/        ← 시그니처 매칭 + LLM 분석
│   ├── __init__.py
│   ├── rule_parser.py
│   ├── signature_checker.py
│   ├── openai_client.py
│   ├── prompt_templates.py
│   └── analyzer.py
│
├── _04_gradio_visual/      ← Gradio 대시보드
│   ├── __init__.py
│   ├── store.py
│   └── dashboard.py
│
├── test_local_rules.py     ← 단위 테스트 1 (API 키 불필요)
├── test_analyzer.py        ← 단위 테스트 2 (API 키 필요)
└── test_socket_client.py   ← 통합 테스트 (서버 실행 후)
```

> ⚠️ **폴더명 주의**
> Python은 숫자로 시작하는 패키지명(`02_...`)을 import할 수 없습니다.
> 폴더명을 `_02_window_backend`, `_03_ai_analyzer`, `_04_gradio_visual`로
> 앞에 언더스코어를 붙여서 사용하세요.

---

## ⚙️ 초기 설정

### 1단계: community.rules 다운로드 및 배치

```
https://www.snort.org/downloads#rules
→ "Snort Community Ruleset" 클릭 → 다운로드
→ 압축 해제 후 community.rules 파일을
  프로젝트 루트(run_windows.py와 같은 폴더)에 복사
```

### 2단계: .env 파일 생성

```bash
cp .env.example .env
```

`.env` 파일을 열어 API 키 입력:
```
OPENAI_API_KEY=sk-실제키입력
```

### 3단계: 패키지 설치

```bash
pip install -r requirements.txt
```

---

## 🚀 실행 방법

### Windows 서버 실행
```bash
python run_windows.py
```
→ 소켓 서버(9999포트) + Gradio 대시보드(7860포트) 동시 기동
→ 브라우저에서 http://localhost:7860 접속

### Kali 에이전트 실행 (별도 머신)
```bash
python run_kali.py
```

---

## 🧪 테스트 방법 (단계별)

### Step 1 — 룰 파싱만 테스트 (API 키·서버 불필요)
```bash
python test_local_rules.py
```

### Step 2 — 분석기 전체 흐름 테스트 (API 키 필요, 서버 불필요)
```bash
python test_analyzer.py
```

### Step 3 — 실제 소켓 통합 테스트
```bash
# 터미널 1
python run_windows.py

# 터미널 2
python test_socket_client.py
```

---

## 🔒 보안 주의사항

- `.env` 파일을 절대 git에 커밋하지 마세요
- `community.rules`도 용량이 크고 라이선스 문제가 있으므로 git 제외
- API 키 유출 시 즉시 https://platform.openai.com/api-keys 에서 폐기
