# P2R_LLM_Snort

```bash
project-root/
│
├── ⚙️ 설정 및 공통 파일
│   ├── .gitignore          # 가상환경(.venv), 캐시, API Key(.env) 등 제외
│   ├── requirements.txt    # 프로젝트 실행을 위한 라이브러리 목록 (Scapy, Gradio, OpenAI 등)
│   └── main.py             # 각 모듈을 통합하여 실행하는 전체 시스템 엔트리 포인트
│
├── 📦 01_collector/        # [Packet Ingest] 실시간 패킷 수집 및 전처리
│
├── 🧠 02_analyzer/         # [AI Analysis] GPT API 연동 및 위협 분석
│
├── 🛡️ 03_generator/        # [Rule Generation] Snort 룰 변환 및 검증
│
├── 📊 04_dashboard/        # [Visualization] Gradio 기반 통합 모니터링
│
└── 🧪 05_tester/           # [Environment] 공격 시뮬레이션 및 검증
