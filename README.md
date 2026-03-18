# P2R_LLM_Snort

project-root/
│
├── .gitignore          # .venv, __pycache__, .env 등 제외
├── requirements.txt    # 공통 라이브러리 목록
├── main.py             # 전체 모듈을 통합하여 실행하는 메인 스크립트
│
├── 01_collector/       # 패킷 수집 및 전처리 (Scapy)
├── 02_analyzer/        # GPT API 연동 및 프롬프트 설계
├── 03_generator/       # Snort 룰 변환 및 검증 로직
├── 04_dashboard/       # Gradio UI 및 실시간 시각화
└── 05_tester/          # Kali/Meta 환경 구축 및 공격 시나리오/테스트