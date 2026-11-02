"""
GIGANG - Unified Security Operations & Governance Dashboard
Zero Trust 기반 다기종 로그 상관분석 & 섀도우 AI 거버넌스 통합 웹 대시보드
"""

import os
import sys
from pathlib import Path

# 프로젝트 루트 디렉토리를 sys.path 최우선에 등록하여 로컬 및 클라우드 실행 보장
_root_dir = Path(__file__).resolve().parent.parent.parent
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

import streamlit as st
import streamlit.components.v1 as components
from gigang.storage import get_context

try:
    from dotenv import load_dotenv
    load_dotenv(_root_dir / ".env")
except Exception:
    pass

# 1. 페이지 기본 설정
st.set_page_config(
    page_title="GIGANG | 차세대 사이버 OS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# 2. 차세대 사이버 OS 풀스크린 단독 마운트
def render_cyber_os_terminal():
    """터미널 화면을 양방향 컴포넌트로 띄운다. 데이터는 terminal_bridge 가 실제 백엔드에서 만든다."""
    from gigang.collectors import team_collector as _tc
    from gigang.ui import terminal_bridge as bridge

    terminal_path = _root_dir / "gigang_terminal.html"
    if not terminal_path.exists():
        st.error("gigang_terminal.html 파일을 찾을 수 없습니다.")
        return

    # 컴포넌트는 폴더 단위라서 index.html 사본을 runtime/ 아래에 만든다 (원본이 바뀌면 자동 갱신).
    comp_dir = _root_dir / "runtime" / "terminal_component"
    comp_dir.mkdir(parents=True, exist_ok=True)
    src = terminal_path.read_text(encoding="utf-8")
    dst = comp_dir / "index.html"
    if not dst.exists() or dst.read_text(encoding="utf-8") != src:
        dst.write_text(src, encoding="utf-8")
    terminal = components.declare_component("gigang_terminal", path=str(comp_dir))

    st.markdown('''
    <style>
        [data-testid="stSidebar"], [data-testid="collapsedControl"],
        header[data-testid="stHeader"], footer { display: none !important; }
        .block-container { padding: 0 !important; margin: 0 !important; max-width: 100% !important; }
        iframe {
            position: fixed !important; top: 0 !important; left: 0 !important;
            width: 100vw !important; height: 100vh !important; height: 100dvh !important;
            border: none !important; z-index: 999999 !important;
        }
    </style>
    ''', unsafe_allow_html=True)

    ctx = get_context()
    ui = st.session_state.setdefault("term_ui", {"collect": True, "gemini": bool(os.getenv("GEMINI_API_KEY"))})
    if "term_snap" not in st.session_state:
        _tc.set_railway_collection_enabled(ui["collect"])
        bridge.refresh(ctx, force=True)
        st.session_state["term_snap"] = bridge.build_snapshot(ctx, ui)

    value = terminal(snapshot=st.session_state["term_snap"], key="gigang_terminal", default=None)
    if isinstance(value, dict) and value.get("nonce") != st.session_state.get("term_nonce"):
        st.session_state["term_nonce"] = value.get("nonce")
        ok, msg = bridge.handle_action(ctx, ui, str(value.get("action", "")), value.get("payload") or {})
        if msg:
            ui["last_result"] = {"nonce": value.get("nonce"), "ok": ok, "message": msg}
        st.session_state["term_snap"] = bridge.build_snapshot(ctx, ui)
        st.rerun()


render_cyber_os_terminal()
