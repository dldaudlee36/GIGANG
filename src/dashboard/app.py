"""
Streamlit Web Dashboard Module (Member 4)
Interactive Security Event & Network Correlation Dashboard with AI SecOps Copilot.
"""
import os
import json
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from pathlib import Path

# Add project root to sys.path
import sys
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(ROOT_DIR))

from src.engine.ai_agent import AISecOpsAgent

st.set_page_config(
    page_title="AI Security Correlation & SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State
if "incidents" not in st.session_state:
    mock_file = ROOT_DIR / "data" / "mock_incidents.json"
    if mock_file.exists():
        with open(mock_file, "r", encoding="utf-8") as f:
            st.session_state.incidents = json.load(f)
    else:
        st.session_state.incidents = []

if "remediation_history" not in st.session_state:
    st.session_state.remediation_history = {}

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = [
        {"role": "assistant", "content": "안녕하세요! AI 보안 관제 코파일럿입니다. 현재 분석 중인 침해사고에 대해 궁금한 점이나 보고서 작성 요청이 있으시면 말씀해주세요."}
    ]

ai_agent = AISecOpsAgent()

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("보안관제 센터")
    st.markdown("---")
    
    st.subheader("📋 침해사고 목록")
    incident_options = {f"[{inc['severity']}] {inc['incident_id']} - {inc['title'][:18]}...": inc['incident_id'] for inc in st.session_state.incidents}
    
    if incident_options:
        selected_label = st.selectbox("분석할 사건 선택", list(incident_options.keys()))
        selected_id = incident_options[selected_label]
        current_inc = next((inc for inc in st.session_state.incidents if inc['incident_id'] == selected_id), None)
    else:
        current_inc = None

    st.markdown("---")
    st.subheader("⚙️ 모드 설정")
    auto_refresh = st.checkbox("실시간 수집 모니터링 (Auto Refresh)", value=False)
    st.caption("AI Model: Gemini 2.5 Flash / Local Fallback")

# ----------------- MAIN VIEW -----------------
st.title("🛡️ 보안 이벤트·네트워크 상관분석 대시보드")
st.caption("Auto Log Collection → Normalization → Correlation Scoring → AI Incident Response")

if not current_inc:
    st.warning("분석 가능한 침해사고 데이터가 없습니다.")
    st.stop()

# Top KPI Metric Cards
col1, col2, col3, col4 = st.columns(4)
col1.metric("총 탐지 사건 수", f"{len(st.session_state.incidents)} 건", "+1 new")
col2.metric("선택 사건 위험도", current_inc["severity"], delta_color="inverse")
col3.metric("상관분석 신뢰 점수", f"{current_inc['correlation_score']} / 12.0", "높은 연관성")
col4.metric("사건 처리 상태", current_inc["status"])

st.markdown("---")

# Main Content Tabs
tab_overview, tab_timeline, tab_network, tab_ai_copilot = st.tabs([
    "🔍 사건 개요 & AI 브리핑", 
    "⏱️ 공격 타임라인 & 근거", 
    "🌐 네트워크 이동 경로 (Hop)", 
    "🤖 AI 보안 Copilot (Q&A)"
])

# ----------------- TAB 1: OVERVIEW & AI BRIEFING -----------------
with tab_overview:
    c1, c2 = st.columns([3, 2])
    
    with c1:
        st.subheader(f"📌 {current_inc['title']}")
        st.markdown(f"**사건 ID:** `{current_inc['incident_id']}` | **발생 시각:** `{current_inc['created_at']}`")
        st.markdown(f"**공격자 출발지 IP:** `{current_inc['primary_src_ip']}` | **피해 대상 계정:** `{current_inc['target_user']}`")
        
        st.markdown("#### 🤖 AI 침해사고 브리핑 (GenAI Automated Summary)")
        ai_data = current_inc.get("ai_analysis", {})
        st.info(ai_data.get("summary", "AI 분석 요약 데이터가 생성되지 않았습니다."))
        
        st.markdown("#### 🏷️ MITRE ATT&CK 공격 기법 맵핑")
        tactics = ai_data.get("mitre_tactics", [])
        cols = st.columns(len(tactics) if tactics else 1)
        for i, tactic in enumerate(tactics):
            cols[i % len(cols)].button(f"🎯 {tactic}", key=f"tactic_{i}", disabled=True)

    with c2:
        st.subheader("⚡ AI 초동 조치 플레이북 (SOAR)")
        st.markdown("사고 분석에 기반하여 자동 생성된 방어 조치 스크립트입니다.")
        
        playbook = ai_data.get("recommended_playbook", [])
        for idx, item in enumerate(playbook):
            action_key = f"{current_inc['incident_id']}_action_{idx}"
            is_done = st.session_state.remediation_history.get(action_key, False)
            
            with st.container(border=True):
                st.markdown(f"**{idx+1}. {item['action']}** (`{item['target']}`)")
                st.code(item['command'], language="bash")
                
                btn_label = "✅ 조치 완료됨" if is_done else "🚀 1-Click 자동 실행"
                if st.button(btn_label, key=f"btn_{action_key}", disabled=is_done):
                    st.session_state.remediation_history[action_key] = True
                    st.success(f"명령어 실행 완료: `{item['command']}`")
                    st.rerun()

# ----------------- TAB 2: TIMELINE & EXPLAINABILITY -----------------
with tab_timeline:
    st.subheader("📊 상관분석 판단 근거 (왜 하나의 사건으로 묶었는가?)")
    
    reasons = current_inc.get("reasons", [])
    r_cols = st.columns(len(reasons) if reasons else 1)
    for idx, r in enumerate(reasons):
        with r_cols[idx]:
            st.metric(label=f"✓ {r['criteria']}", value=f"+{r['score']}점")
            st.caption(r["description"])

    st.markdown("---")
    st.subheader("⏱️ 다단계 공격 타임라인 (Kill-Chain)")
    
    timeline_data = current_inc.get("attack_timeline", [])
    df_timeline = pd.DataFrame(timeline_data)
    if not df_timeline.empty:
        for item in timeline_data:
            with st.expander(f"Step {item['step']}: [{item['source'].upper()}] {item['stage']} ({item['timestamp']})", expanded=True):
                st.markdown(f"**내용:** {item['description']}")
                st.caption(f"연계 원본 로그 ID: `{item['raw_log_id']}`")

# ----------------- TAB 3: NETWORK PATH -----------------
with tab_network:
    st.subheader("🌐 침해 시스템 간 횡적이동(Lateral Movement) 시각화")
    net_hops = current_inc.get("network_path", [])
    
    # Simple Visual representation
    hop_cols = st.columns(len(net_hops) * 2 - 1 if net_hops else 1)
    col_idx = 0
    for i, hop in enumerate(net_hops):
        with hop_cols[col_idx]:
            st.button(f"🖥️ {hop['from_node']}", key=f"from_{i}", disabled=True)
        col_idx += 1
        
        if col_idx < len(hop_cols):
            with hop_cols[col_idx]:
                st.markdown(f"<div style='text-align: center; color: red;'><b>➔ :{hop['port']} ({hop['protocol']})</b><br><small>{hop['status']}</small></div>", unsafe_allow_html=True)
            col_idx += 1

    st.markdown("---")
    st.table(pd.DataFrame(net_hops))

# ----------------- TAB 4: AI COPILOT -----------------
with tab_ai_copilot:
    st.subheader("💬 AI 보안 분석관 (SOC Copilot)")
    st.caption("현재 선택된 침해사고 맥락을 기반으로 질문에 실시간 답변합니다.")

    # Display chat messages
    for msg in st.session_state.chat_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat Input
    if user_prompt := st.chat_input("질문을 입력하세요 (예: 'DB에서 유출된 정보가 뭐야?', '팀장 보고용 요약문 써줘')"):
        st.session_state.chat_messages.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.markdown(user_prompt)

        with st.chat_message("assistant"):
            with st.spinner("AI 분석관이 사건 데이터를 검토 중입니다..."):
                response_text = ai_agent.answer_copilot_query(current_inc, user_prompt)
                st.markdown(response_text)
        
        st.session_state.chat_messages.append({"role": "assistant", "content": response_text})
