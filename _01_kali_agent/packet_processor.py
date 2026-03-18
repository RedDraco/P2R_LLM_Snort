import json
import time
from datetime import datetime


HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")


def is_http_payload(payload: str) -> bool:
    """
    payload 문자열이 HTTP 요청 후보인지 판별한다.
    """
    if not payload or not isinstance(payload, str):
        return False

    return payload.startswith(HTTP_METHODS)


def parse_http_payload(payload: str) -> dict | None:
    """
    HTTP payload 문자열에서 method, uri, version, headers, body를 파싱한다.
    파싱에 실패하면 None을 반환한다.
    """
    if not is_http_payload(payload):
        return None

    lines = payload.split("\r\n")
    if not lines or not lines[0]:
        return None

    # Request-Line 파싱
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) < 3:
        return None

    method  = parts[0].strip()
    uri     = parts[1].strip()
    version = parts[2].strip()

    headers = {}
    body = ""
    header_end_idx = None

    # Header 파싱
    for i, line in enumerate(lines[1:], start=1):
        if line == "":
            header_end_idx = i
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    # Body 파싱
    if header_end_idx is not None and header_end_idx + 1 < len(lines):
        body = "\r\n".join(lines[header_end_idx + 1:])

    return {
        "method":  method,
        "uri":     uri,
        "version": version,
        "host":    headers.get("Host", ""),
        "headers": headers,
        "body":    body,
    }


def build_processed_data(packet_data: dict) -> dict | None:
    """
    sniffer.py에서 전달받은 packet_data(dict)를 기반으로
    HTTP 요청 정보를 파싱하고 서버 전송용 dict로 가공한다.

    [수정 사항 — Windows 서버(controller.py) 호환]
    controller.py의 _process_and_analyze()는 아래 필드를 사용한다:
      - "payload"  : URI + 바디를 합친 분석 대상 문자열
      - "uri"      : HTTP 요청 경로
      - "src_ip"   : 출발지 IP
      - "dst_ip"   : 목적지 IP
      - "method"   : HTTP 메서드
      - "timestamp": 문자열 형식 (YYYY-MM-DD HH:MM:SS)
      
    """
    if not isinstance(packet_data, dict):
        return None

    payload = packet_data.get("payload", "")
    http_info = parse_http_payload(payload)
    if http_info is None:
        return None

    # payload 필드: URI 쿼리스트링 + 바디를 합쳐 분석 대상 문자열로 구성
    # controller.py의 preprocess_payload()가 이 값을 URL 디코딩·정제함
    uri  = http_info["uri"]
    body = http_info["body"]
    analysis_payload = f"{uri} {body}".strip() if body else uri

    return {
        # ── 서버가 반드시 필요로 하는 필드 ──────────
        "src_ip":    packet_data.get("src_ip", ""),
        "dst_ip":    packet_data.get("dst_ip", ""),
        "method":    http_info["method"],
        "uri":       uri,
        "payload":   analysis_payload,          # controller.py 전처리 대상
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        # ── 추가 정보 (대시보드 표시용) ─────────────
        "src_port":    packet_data.get("src_port", 0),
        "dst_port":    packet_data.get("dst_port", 0),
        "host":        http_info["host"],
        "version":     http_info["version"],
        "headers":     http_info["headers"],
        "body":        body,
        "raw_payload": payload,
    }


def build_json_message(packet_data: dict) -> str | None:
    """
    가공된 HTTP 요청 정보를 JSON 문자열로 변환한다.
    """
    processed_data = build_processed_data(packet_data)
    if processed_data is None:
        return None

    return json.dumps(processed_data, ensure_ascii=False)


def build_json_bytes(packet_data: dict) -> bytes | None:
    """
    sender.py 전송용 bytes(JSON + newline) 형태로 변환한다.

    ※ sender.py에서 \n을 제거하고 4바이트 헤더를 붙이므로
      이 함수의 \n은 하위 호환성을 위해 유지한다.
    """
    json_message = build_json_message(packet_data)
    if json_message is None:
        return None

    return (json_message + "\n").encode("utf-8")
