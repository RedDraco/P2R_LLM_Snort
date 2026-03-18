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
│   ├── sniffer.py          # Scapy를 이용한 실시간 패킷 스니핑
│   └── sender.py           # 추출된 페이로드를 Windows로 전송하는 Socket 클라이언트
│
├── 📡 02_socket_server/    # [Windows] 데이터 수신 및 대기열 관리
│   ├── receiver.py         # Kali로부터 패킷 데이터를 받는 Socket 서버
│   └── queue_manager.py    # 수신된 데이터를 분석 모듈로 전달하는 버퍼(Queue)
│
├── 🧠 03_ai_analyzer/      # [Windows] GPT 기반 위협 해석 엔진
│   ├── gpt_engine.py       # 수신된 페이로드 분석 및 악성 여부 판별
│   └── prompt_template.py  # 공격 유형별(SQLi, XSS 등) 분석 프롬프트
│
├── 🛡️ 04_rule_generator/   # [Windows] Snort 룰 자동 생성 및 저장
│   ├── rule_factory.py     # GPT 분석 결과 기반 Snort 구문 생성
│   └── snort_export.py     # 생성된 룰을 .rules 파일로 로컬 저장
│
└── 📊 05_gradio_visual/    # [Windows] 실시간 리포트 및 시각화 UI
    ├── app_main.py         # 패킷 수집 현황 + 분석 결과 + Snort 룰 통합 화면
    └── components.py       # 실시간 데이터 업데이트용 Gradio 컴포넌트
