"""
04_gradio_visual/dashboard.py

[역할]
- Gradio 기반 3분할 실시간 대시보드
  탭 1: 패킷 로그      — 수신된 모든 패킷 표시
  탭 2: AI 분석 리포트 — 공격으로 판정된 패킷 상세 분석
  탭 3: Snort 룰       — 생성/매칭된 Snort 룰 목록 (중복 제거)
- 3초마다 자동 갱신
- 상단 요약 통계 카드 (총 패킷 / 공격 수 / 로컬 탐지 / LLM 탐지)
"""

import logging
from queue import Queue

import gradio as gr

from .store import ResultStore

logger = logging.getLogger(__name__)

# 자동 갱신 주기(초)
REFRESH_INTERVAL = 3

# ── 컬럼 정의 ─────────────────────────────────────
PACKET_LOG_COLS   = ["시간", "출발 IP", "목적 IP", "메서드", "URI", "위험도", "탐지방법"]
AI_REPORT_COLS    = ["시간", "공격명", "공격 기법", "위험도", "판단 근거", "출처"]
SNORT_RULE_COLS   = ["시간", "공격명", "Snort 룰"]


def launch_dashboard(result_queue: Queue, server_port: int = 7860):
    """
    Gradio 대시보드를 기동한다.

    Args:
        result_queue: BackendController.result_queue (분석 결과 공유 큐)
        server_port:  Gradio 웹 서버 포트 (기본 7860)
    """
    store = ResultStore(result_queue)
    store.start()

    # ── UI 콜백 ───────────────────────────────────

    def refresh_packet_log():
        return store.get_packet_log_rows()

    def refresh_ai_report():
        return store.get_ai_report_rows()

    def refresh_snort_rules():
        return store.get_snort_rules_rows()

    def refresh_stats():
        s = store.get_stats()
        attack_rate = (
            f"{s['attack'] / s['total'] * 100:.1f}%" if s["total"] > 0 else "0%"
        )
        return (
            f"📦 총 패킷: **{s['total']}**",
            f"🚨 공격 탐지: **{s['attack']}** ({attack_rate})",
            f"📋 로컬 룰 매칭: **{s['local']}**",
            f"🧠 LLM 분석: **{s['llm']}**",
        )

    def get_latest_detail():
        """최신 결과의 상세 정보를 마크다운으로 반환한다."""
        rec = store.get_latest_record()
        if rec is None:
            return "_아직 수신된 패킷이 없습니다._"

        attack_emoji = "🚨" if rec.get("is_attack") else "✅"
        severity = rec.get("severity", "N/A")
        sev_color = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

        snort = rec.get("snort_rule", "")
        snort_block = f"```\n{snort}\n```" if snort else "_생성된 룰 없음_"

        return f"""### {attack_emoji} 최신 분석 결과

| 항목 | 내용 |
|------|------|
| 시간 | `{rec.get('timestamp', 'N/A')}` |
| 출발 IP | `{rec.get('src_ip', 'N/A')}` |
| 목적 IP | `{rec.get('dst_ip', 'N/A')}` |
| 메서드 | `{rec.get('method', 'N/A')}` |
| URI | `{rec.get('uri', 'N/A')}` |
| 공격 여부 | {'**공격 탐지됨**' if rec.get('is_attack') else '정상'} |
| 공격명 | {rec.get('attack_name', 'N/A')} |
| 위험도 | {sev_color} {severity} |
| 분석 출처 | {rec.get('source', 'N/A')} |

**📝 판단 근거**
> {rec.get('reason', 'N/A')}

**🛡️ Snort 룰**
{snort_block}
"""

    # ── UI 레이아웃 ───────────────────────────────

    with gr.Blocks(
        title="LLM 기반 HTTP 패킷 분석 대시보드",
        theme=gr.themes.Soft(),
        css=_CUSTOM_CSS,
    ) as demo:

        gr.Markdown("# 🛡️ LLM 기반 HTTP 패킷 분석 & Snort 룰 생성 대시보드")
        gr.Markdown("실시간으로 HTTP 패킷을 분석하고 위협을 탐지합니다.")

        # ── 통계 카드 행 ──────────────────────────
        with gr.Row(elem_classes="stats-row"):
            stat_total    = gr.Markdown("📦 총 패킷: **0**")
            stat_attack   = gr.Markdown("🚨 공격 탐지: **0** (0%)")
            stat_local    = gr.Markdown("📋 로컬 룰 매칭: **0**")
            stat_llm      = gr.Markdown("🧠 LLM 분석: **0**")

        gr.Markdown("---")

        # ── 최신 결과 상세 ────────────────────────
        with gr.Row():
            latest_detail = gr.Markdown(
                value="_아직 수신된 패킷이 없습니다._",
                elem_classes="detail-box",
            )

        gr.Markdown("---")

        # ── 3분할 탭 ─────────────────────────────
        with gr.Tabs():

            # 탭 1: 패킷 로그
            with gr.Tab("📦 패킷 로그"):
                gr.Markdown("수신된 모든 HTTP 패킷 목록입니다. (최신순, 최대 500건)")
                packet_table = gr.Dataframe(
                    headers=PACKET_LOG_COLS,
                    datatype=["str"] * len(PACKET_LOG_COLS),
                    interactive=False,
                    wrap=True,
                    elem_classes="data-table",
                )

            # 탭 2: AI 분석 리포트
            with gr.Tab("🧠 AI 분석 리포트"):
                gr.Markdown("공격으로 판정된 패킷의 상세 분석 결과입니다.")
                ai_table = gr.Dataframe(
                    headers=AI_REPORT_COLS,
                    datatype=["str"] * len(AI_REPORT_COLS),
                    interactive=False,
                    wrap=True,
                    elem_classes="data-table",
                )

            # 탭 3: Snort 룰
            with gr.Tab("🛡️ Snort 룰"):
                gr.Markdown(
                    "🧠 LLM이 새롭게 생성한 Snort 룰 목록입니다. (중복 제거, 로컬 매칭 룰 제외)"
                )
                with gr.Row():
                    snort_table = gr.Dataframe(
                        headers=SNORT_RULE_COLS,
                        datatype=["str"] * len(SNORT_RULE_COLS),
                        interactive=False,
                        wrap=True,
                        elem_classes="data-table",
                    )
                with gr.Row():
                    copy_btn = gr.Button("📋 전체 룰 복사용 텍스트 생성", variant="secondary")
                    copy_output = gr.Textbox(
                        label="복사용 Snort 룰 전문",
                        lines=8,
                        interactive=False,
                        placeholder="버튼을 클릭하면 모든 룰이 여기에 표시됩니다.",
                    )

                def generate_copy_text():
                    rows = store.get_snort_rules_rows()
                    if not rows:
                        return "# 생성된 룰이 없습니다."
                    lines = ["# Auto-generated Snort Rules", "# Generated by LLM HTTP Packet Analyzer", ""]
                    for row in rows:
                        lines.append(f"# [{row[0]}] {row[1]}")
                        lines.append(row[2])
                        lines.append("")
                    return "\n".join(lines)

                copy_btn.click(fn=generate_copy_text, outputs=copy_output)

        # ── 자동 갱신 타이머 ──────────────────────
        timer = gr.Timer(value=REFRESH_INTERVAL)

        timer.tick(
            fn=refresh_stats,
            outputs=[stat_total, stat_attack, stat_local, stat_llm],
        )
        timer.tick(fn=get_latest_detail, outputs=latest_detail)
        timer.tick(fn=refresh_packet_log, outputs=packet_table)
        timer.tick(fn=refresh_ai_report,  outputs=ai_table)
        timer.tick(fn=refresh_snort_rules, outputs=snort_table)

    logger.info(f"[Dashboard] Gradio 대시보드 기동 — http://localhost:{server_port}")
    demo.launch(
        server_name="0.0.0.0",
        server_port=server_port,
        share=False,
        inbrowser=True,   # 자동으로 브라우저 열기
    )


# ── 커스텀 CSS ────────────────────────────────────
# CSS 변수를 사용해 라이트/다크모드 모두 대응

_CUSTOM_CSS = """
/* ── 통계 카드 행 ── */
.stats-row {
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 8px;
    border: 1px solid var(--border-color-primary, #e0e0e0);
    background: var(--background-fill-secondary, #f8f9fa);
}
.stats-row .prose p {
    font-size: 1.05rem;
    text-align: center;
    color: var(--body-text-color, inherit) !important;
}

/* ── 최신 결과 상세 박스 ── */
.detail-box {
    border-left: 4px solid var(--color-accent, #4f6ef7);
    padding: 16px;
    border-radius: 6px;
    background: var(--background-fill-secondary, #f0f4ff);
}
.detail-box p,
.detail-box td,
.detail-box th,
.detail-box code,
.detail-box blockquote {
    color: var(--body-text-color, inherit) !important;
}

/* ── 데이터 테이블 ── */
.data-table table {
    font-size: 0.88rem;
}
.data-table table th,
.data-table table td {
    color: var(--body-text-color, inherit) !important;
    background: var(--background-fill-primary, inherit);
}

/* ── 마크다운 전역 텍스트 색상 보장 ── */
.prose *,
.md * {
    color: var(--body-text-color, inherit);
}

/* ── 코드 블록 다크모드 대응 ── */
.prose pre,
.prose code {
    background: var(--background-fill-secondary, #1e1e1e) !important;
    color: var(--body-text-color, inherit) !important;
    border: 1px solid var(--border-color-primary, #444) !important;
}

/* ── 인용문(판단 근거) 다크모드 대응 ── */
.prose blockquote {
    border-left: 3px solid var(--color-accent, #4f6ef7);
    background: var(--background-fill-secondary, #f0f0f0) !important;
    color: var(--body-text-color, inherit) !important;
    padding: 8px 12px;
    border-radius: 4px;
}
"""
