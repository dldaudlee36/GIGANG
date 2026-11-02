"""
GIGANG - Unified Security Operations & Governance Dashboard
Zero Trust 기반 다기종 로그 상관분석 & 섀도우 AI 거버넌스 통합 웹 대시보드
"""

import sys
from pathlib import Path

# 프로젝트 루트 디렉토리를 sys.path 최우선에 등록하여 로컬 및 클라우드 실행 보장
_root_dir = Path(__file__).resolve().parent.parent.parent
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

import streamlit as st
import pandas as pd
import base64
import streamlit.components.v1 as components
from datetime import datetime, timedelta
from gigang.storage import get_context
from gigang.schemas import Severity, SanctionStatus, IncidentStatus, Incident
from gigang.schemas.event import SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata

# GIGANG Chrome enforcement policy. The local Agent exposes this file to the
# browser extension; no pasted/file content is stored here, only hostnames.
_BROWSER_POLICY_FILE = _root_dir / "runtime" / "blocked_domains.json"

try:
    from dotenv import load_dotenv
    load_dotenv(_root_dir / ".env")
except Exception:
    pass

def _config_value(name: str, default: str = "") -> str:
    import os
    value = os.getenv(name, "")
    if value:
        return value
    try:
        value = str(st.secrets.get(name, ""))
        if value:
            return value
    except Exception:
        pass
    return default

_RAILWAY_EVENTS_URL = _config_value("RAILWAY_URL", "https://bountiful-nature-production-22ec.up.railway.app/events")
_RAILWAY_BASE_URL = _RAILWAY_EVENTS_URL.rsplit("/", 1)[0] if _RAILWAY_EVENTS_URL.rstrip("/").endswith("/events") else _RAILWAY_EVENTS_URL.rstrip("/")
_RAILWAY_POLICY_URL = _config_value("RAILWAY_POLICY_URL", _RAILWAY_BASE_URL + "/policy")
_RAILWAY_API_KEY = _config_value("RAILWAY_API_KEY", "")

def _normalize_policy_domain(domain: str) -> str:
    value = (domain or "").strip().lower()
    value = value.removeprefix("https://").removeprefix("http://")
    value = value.split("/", 1)[0].split(":", 1)[0].strip(".")
    return value

def _load_browser_blocklist() -> set:
    try:
        import json
        payload = json.loads(_BROWSER_POLICY_FILE.read_text(encoding="utf-8"))
        items = payload.get("blocked_domains", []) if isinstance(payload, dict) else []
        return {_normalize_policy_domain(item) for item in items if isinstance(item, str) and _normalize_policy_domain(item)}
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return set()

def _set_browser_block_policy(domain: str, blocked: bool) -> None:
    normalized = _normalize_policy_domain(domain)
    if not normalized:
        return
    domains = _load_browser_blocklist()
    if blocked:
        domains.add(normalized)
    else:
        domains.discard(normalized)
    _BROWSER_POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    import json
    payload = {
        "blocked_domains": sorted(domains),
        "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    temp = _BROWSER_POLICY_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(_BROWSER_POLICY_FILE)

def _set_central_browser_policy(domain: str, blocked: bool) -> tuple:
    import requests
    normalized = _normalize_policy_domain(domain)
    if not normalized:
        return False, "도메인 형식이 올바르지 않습니다."
    if not _RAILWAY_API_KEY:
        return False, "RAILWAY_API_KEY가 설정되어 있지 않습니다."
    try:
        response = requests.post(
            _RAILWAY_POLICY_URL,
            json={"domain": normalized, "blocked": bool(blocked)},
            headers={"X-API-Key": _RAILWAY_API_KEY},
            timeout=6,
        )
        if response.status_code == 404:
            return False, "Railway에 중앙 정책 API(/policy)가 아직 배포되지 않았습니다."
        if response.status_code == 401:
            return False, "Railway 정책 API 인증에 실패했습니다. RAILWAY_API_KEY를 확인하세요."
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("domain") != normalized:
            return False, "Railway 정책 응답 형식이 올바르지 않습니다."
        _set_browser_block_policy(normalized, blocked)
        return True, "중앙 정책 저장 완료"
    except requests.RequestException as error:
        return False, f"Railway 정책 서버 연결 실패 ({type(error).__name__})"
    except (ValueError, TypeError):
        return False, "Railway 정책 응답을 읽지 못했습니다."


# 데이터프레임 내 검색 강조 색상을 선명한 골드 옐로우(rgba(250,204,21,0.65))로 보장
def _ensure_vivid_search_highlight():
    try:
        import os
        import streamlit
        st_dir = os.path.dirname(streamlit.__file__)
        js_dir = os.path.join(st_dir, "static", "static", "js")
        if os.path.isdir(js_dir):
            for fn in os.listdir(js_dir):
                if fn.startswith("DataFrame.") and fn.endswith(".js"):
                    fp = os.path.join(js_dir, fn)
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        c = f.read()
                    old_str = "bgSearchResult:ye(e.colors.primary,.9)"
                    new_str = 'bgSearchResult:"rgba(250,204,21,0.65)"'
                    if old_str in c:
                        c = c.replace(old_str, new_str)
                        with open(fp, "w", encoding="utf-8") as f:
                            f.write(c)
    except Exception:
        pass

_ensure_vivid_search_highlight()

# 1. 페이지 기본 설정
st.set_page_config(
    page_title="GIGANG | 차세대 사이버 OS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# 2. 차세대 사이버 OS 풀스크린 단독 마운트 (왼쪽 토글창/사이드바 완전 배제, 테마1·폰트5 고정)
def render_cyber_os_terminal():
    """터미널 화면을 양방향 컴포넌트로 띄운다. 데이터는 terminal_bridge 가 실제 백엔드에서 만든다."""
    import os
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

# 🚀 모든 기능은 차세대 사이버 OS로 대체: 메인에서 즉시 렌더링 후 완료
render_cyber_os_terminal()
