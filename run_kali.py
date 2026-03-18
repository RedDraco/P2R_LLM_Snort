import os
import sys

# ── 경로 설정 ─────────────────────────────────────
# run_kali.py가 프로젝트 루트에 있으므로
# _01_kali_agent 폴더를 sys.path에 추가해야
# sniffer.py 안의 from packet_processor import ...가 동작함
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.join(ROOT_DIR, "_01_kali_agent")

for path in [ROOT_DIR, AGENT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)


def main():
    print("[*] Agent 시작됨...")

    # _01_kali_agent 폴더 안의 sniffer.py를 직접 import
    from _01_kali_agent.sniffer import start_sniffer
    start_sniffer()


if __name__ == "__main__":
    main()
