# P2R_LLM_Snort

본 프로젝트는 모듈화된 설계를 바탕으로 5명의 팀원이 각 파트를 독립적으로 개발하고 통합하는 구조를 가집니다.

```bash
project-root/
│
├── ⚙️ 설정 및 공통 파일
│   ├── .gitignore          # 가상환경(.venv), 캐시, API Key(.env) 등 제외
│   ├── requirements.txt    # 프로젝트 실행을 위한 라이브러리 목록 (Scapy, Gradio, OpenAI 등)
│   └── main.py             # 각 모듈을 통합하여 실행하는 전체 시스템 엔트리 포인트
│
├── 📦 01_collector/        # [Packet Ingest] 실시간 패킷 수집 및 전처리
│   ├── sniffer.py          # Scapy를 이용한 실시간 네트워크 스니핑 로직
│   └── preprocessor.py     # RAW 패킷에서 HTTP/TCP 페이로드 및 헤더 추출
│
├── 🧠 02_analyzer/         # [AI Analysis] GPT API 연동 및 위협 분석
│   ├── gpt_client.py       # LLM API 호출 및 응답 처리 모듈
│   └── prompts.py          # 악성 패킷 판별을 위한 퓨샷(Few-shot) 프롬프트 설계
│
├── 🛡️ 03_generator/        # [Rule Generation] Snort 룰 변환 및 검증
│   ├── rule_factory.py     # 분석 결과를 바탕으로 Snort 구문 자동 생성
│   └── validator.py        # 생성된 룰의 문법 및 중복 검사 로직
│
├── 📊 04_dashboard/        # [Visualization] Gradio 기반 통합 모니터링
│   ├── app_ui.py           # 실시간 패킷 현황 및 분석 결과 출력 레이아웃
│   └── charts.py           # 공격 유형 통계 및 위협 수준 시각화 컴포넌트
│
└── 🧪 05_tester/           # [Environment] 공격 시뮬레이션 및 검증
    ├── payloads/           # Kali Linux용 공격 시나리오(SQLi, XSS 등) 스크립트
    └── test_report.md      # Meta 환경에서의 탐지 성능 테스트 결과 기록
