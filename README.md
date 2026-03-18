# P2R_LLM_Snort

## 🏗️ 시스템 아키텍처 및 폴더 구조

본 프로젝트는 Kali Linux(에이전트)에서 수집된 실시간 패킷을 Windows(분석 서버)로 전송하여 AI가 분석하고 시각화하는 구조입니다.

```bash
project-root/
│
├── ⚙️ 공통 설정
│   ├── .gitignore
│   └── requirements.txt
│
├── 🐍 01_kali_agent/        # [Kali] 패킷 스니핑 및 소켓 전송 (Sender)
├── 💻 02_window_backend/    # [Windows] 소켓 수신 및 Snort 룰 생성 로직
├── 🧠 03_ai_analyzer/       # [Windows] GPT API 분석 및 위협 판단
└── 📊 04_gradio_visual/     # [Windows] Gradio 통합 대시보드 및 리포트
