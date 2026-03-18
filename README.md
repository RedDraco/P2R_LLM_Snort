# P2R_LLM_Snort

## 🏗️ 시스템 아키텍처 및 폴더 구조

본 프로젝트는 Kali Linux(에이전트)에서 수집된 실시간 패킷을 Windows(분석 서버)로 전송하여 AI가 분석하고 시각화하는 구조입니다.

```bash
project-root/
│
├── ⚙️ 공통 설정
│   ├── .gitignore          # .venv, .env, __pycache__ 제외
│   ├── requirements.txt    # (Windows) scapy, gradio, openai / (Kali) scapy
│   └── config.py           # 소켓 IP/Port 및 API 설정 값 관리
│
├── 🐍 01_kali_agent/       # [Kali Linux] 패킷 수집 및 송신 전용
│
├── 📡 02_socket_server/    # [Windows] 데이터 수신 및 대기열 관리
│
├── 🧠 03_ai_analyzer/      # [Windows] GPT 기반 위협 해석 엔진
│
├── 🛡️ 04_rule_generator/   # [Windows] Snort 룰 자동 생성 및 저장
│
└── 📊 05_gradio_visual/    # [Windows] 실시간 리포트 및 시각화 UI
