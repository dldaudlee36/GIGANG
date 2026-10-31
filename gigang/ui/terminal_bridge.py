"""
터미널 화면(gigang_terminal.html)과 백엔드를 잇는 다리.

화면은 목업 데이터를 갖지 않는다. 이 파일이 수집기(Railway·로컬 로그) → 상관분석 엔진 →
거버넌스 엔진을 거친 실제 결과를 JSON 한 덩어리(snapshot)로 만들어 화면에 넘기고,
화면에서 눌린 버튼(동기화, 도메인 차단, 일시 허용 등)은 handle_action() 이 실제로 수행한다.

데이터가 없는 항목은 빈 리스트·None 으로 넘긴다. 가짜 값으로 채우지 않는다.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from gigang.collectors import team_collector as tc
from gigang.engine import governance

KST = timezone(timedelta(hours=9))
_ROOT = Path(__file__).resolve().parents[2]
_RUNTIME = _ROOT / "runtime"
_BLOCK_FILE = _RUNTIME / "blocked_domains.json"
_ASSIGN_FILE = _RUNTIME / "case_assignees.json"

_SEVERITY_LABEL = {"HIGH": "HIGH", "MEDIUM": "WATCH", "LOW": "NORMAL"}
_STATUS_LABEL = {"ACTIVE": "진행 중", "CONTAINED": "차단 완료", "RESOLVED": "종결"}
_ACTION_LABEL = {
    "SELECT": "기밀 DB 조회", "DB_DOWNLOAD": "기밀 DB 파일 다운로드",
    "CLIPBOARD_COPY": "기밀 DB 텍스트 복사", "SCREEN_CAPTURE": "기밀 DB 화면 캡처",
    "DB_IMAGE_CAPTURE": "기밀 DB 이미지 캡처", "WEB_ACCESS": "외부 사이트 접속",
    "FILE_UPLOAD_ATTEMPT": "파일 첨부 시도", "PASTE_ATTEMPT": "텍스트 붙여넣기",
    "CLIPBOARD_CHANGED": "클립보드 변경", "QUERY": "도메인 질의",
}


# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------
def _base_url() -> str:
    url = tc.RAILWAY_URL.rstrip("/")
    return url.rsplit("/events", 1)[0] if url.endswith("/events") else url


def _api_key() -> str:
    return tc.get_railway_api_key()


def _norm_domain(domain: str) -> str:
    value = (domain or "").strip().lower()
    value = value.removeprefix("https://").removeprefix("http://")
    return value.split("/", 1)[0].split(":", 1)[0].strip(".")


def _kst(dt: Optional[datetime], utc: bool = True) -> str:
    """서버가 주는 시각은 UTC(naive). 화면에는 KST 로 보여 준다."""
    if not dt:
        return "-"
    if dt.tzinfo is None and utc:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S")


def _event_dt(item: Dict[str, Any]) -> datetime:
    return tc._parse_event_time(item.get("event_time"))


# ---------------------------------------------------------------------------
# 중앙 차단 정책 (Railway /policy)
# ---------------------------------------------------------------------------
def _local_blocklist() -> set:
    try:
        payload = json.loads(_BLOCK_FILE.read_text(encoding="utf-8"))
        return {_norm_domain(d) for d in payload.get("blocked_domains", []) if isinstance(d, str)}
    except (OSError, ValueError, AttributeError):
        return set()


def _save_local_blocklist(domains: set) -> None:
    _RUNTIME.mkdir(parents=True, exist_ok=True)
    tmp = _BLOCK_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({
        "blocked_domains": sorted(domains),
        "updated_at": datetime.now(KST).isoformat(timespec="seconds"),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_BLOCK_FILE)


def fetch_blocklist() -> Tuple[set, bool]:
    """중앙 서버의 차단 목록. 읽기는 공개 API. 실패하면 로컬 사본과 False 를 돌려준다."""
    try:
        r = requests.get(_base_url() + "/policy", timeout=4)
        r.raise_for_status()
        data = r.json()
        domains = {_norm_domain(d) for d in data.get("blocked_domains", [])}
        _save_local_blocklist(domains)
        return domains, True
    except (requests.RequestException, ValueError, AttributeError):
        return _local_blocklist(), False


def set_domain_block(domain: str, blocked: bool) -> Tuple[bool, str]:
    d = _norm_domain(domain)
    if not d:
        return False, "도메인 형식이 올바르지 않습니다."
    key = _api_key()
    if not key:
        return False, "RAILWAY_API_KEY가 설정되어 있지 않아 차단 정책을 저장할 수 없습니다."
    try:
        r = requests.post(_base_url() + "/policy", json={"domain": d, "blocked": bool(blocked)},
                          headers={"X-API-Key": key}, timeout=6)
        if r.status_code == 401:
            return False, "Railway 인증에 실패했습니다. RAILWAY_API_KEY를 확인하세요."
        if r.status_code == 404:
            return False, "Railway에 /policy API가 배포되어 있지 않습니다."
        r.raise_for_status()
        if r.json().get("domain") != d:
            return False, "Railway 정책 응답 형식이 올바르지 않습니다."
    except (requests.RequestException, ValueError):
        return False, "Railway 정책 서버에 연결하지 못했습니다."
    local = _local_blocklist()
    (local.add if blocked else local.discard)(d)
    _save_local_blocklist(local)
    return True, f"{d} {'차단' if blocked else '차단 해제'} 완료"


# ---------------------------------------------------------------------------
# 일시 허용 (Railway /site-access)
# ---------------------------------------------------------------------------
def fetch_site_access() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    key = _api_key()
    if not key:
        return [], "RAILWAY_API_KEY 미설정"
    try:
        r = requests.get(_base_url() + "/site-access", headers={"X-API-Key": key}, timeout=4)
        if r.status_code == 401:
            return [], "인증 실패 (RAILWAY_API_KEY 확인)"
        r.raise_for_status()
        groups = r.json()["groups"]
    except (requests.RequestException, ValueError, KeyError):
        return [], "일시 허용 정책 조회 실패"
    out = []
    now = datetime.now(timezone.utc)
    for g in groups:
        try:
            exp = datetime.fromisoformat(g["expires_at"]) if g.get("expires_at") else None
            if exp and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except ValueError:
            exp = None
        remain = max(0, int(-(-((exp - now).total_seconds()) // 60))) if exp else 0
        try:
            last = datetime.fromisoformat(g["last_time"]) if g.get("last_time") else None
        except ValueError:
            last = None
        out.append({
            "id": f"{g.get('device_id', '')}|{g.get('domain', '')}",
            "pcName": g.get("pc_name") or "-",
            "ip": g.get("local_ip") or "-",
            "user": g.get("user_name") or "-",
            "domain": g.get("domain") or "-",
            "attempts": g.get("attempts", 0),
            "status": "ALLOWED" if remain else "BLOCKED",
            "remainMin": remain,
            "lastActionTime": _kst(last) if last else "-",
            "lastAction": g.get("last_action") or "",
            "lastDetail": g.get("last_action") or "",
            "deviceId": g.get("device_id") or "",
        })
    return out, None


def change_site_access(device_id: str, domain: str, pc_name: str, minutes: int) -> Tuple[bool, str]:
    key = _api_key()
    if not key:
        return False, "RAILWAY_API_KEY가 설정되어 있지 않습니다."
    if minutes not in (0, 15, 30, 60):
        return False, "허용 시간은 15, 30, 60분만 가능합니다."
    try:
        r = requests.post(_base_url() + "/site-access", headers={"X-API-Key": key}, timeout=5,
                          json={"device_id": device_id, "domain": domain, "pc_name": pc_name, "minutes": minutes})
        r.raise_for_status()
    except requests.RequestException:
        return False, "정책 변경에 실패했습니다. 현재 권한은 바뀌지 않았을 수 있습니다."
    return True, f"{pc_name} · {domain} " + (f"{minutes}분 허용 적용" if minutes else "다시 차단")


# ---------------------------------------------------------------------------
# 사건 담당자 지정 (로컬 저장)
# ---------------------------------------------------------------------------
def _load_assignees() -> Dict[str, str]:
    try:
        return json.loads(_ASSIGN_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def assign_case(case_id: str, assignee: str) -> Tuple[bool, str]:
    assignee = (assignee or "").strip()[:40]
    if not case_id or not assignee:
        return False, "담당자 이름이 비어 있습니다."
    data = _load_assignees()
    data[case_id] = assignee
    _RUNTIME.mkdir(parents=True, exist_ok=True)
    _ASSIGN_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return True, f"{case_id} 담당자를 {assignee}(으)로 지정했습니다."


# ---------------------------------------------------------------------------
# 수집·분석
# ---------------------------------------------------------------------------
def _gemini_key() -> str:
    """환경변수 → Streamlit Secrets 순으로 Gemini 키를 찾는다 (값은 화면에 노출하지 않는다)."""
    v = os.getenv("GEMINI_API_KEY", "")
    if v:
        return v
    try:
        import streamlit as st
        return str(st.secrets.get("GEMINI_API_KEY", ""))
    except Exception:
        return ""


def refresh(ctx, force: bool = False) -> Dict[str, Any]:
    """Railway 로그를 받아 엔진에 투입한다. 실패해도 예외를 밖으로 던지지 않는다."""
    result = {"fetched": 0, "ingested": 0}
    events = tc.fetch_railway_events(force=force)
    result["fetched"] = len(events)
    try:
        from gigang.engine.live_sync import sync_live_events
        result["ingested"] = sync_live_events(ctx) if (force or tc.is_railway_collection_enabled()) else 0
    except Exception as exc:  # 엔진 오류가 화면 전체를 막지 않게 한다
        result["error"] = type(exc).__name__
    try:
        ctx.governance_engine.sync_railway_events(events)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# 스냅샷 (화면에 넘기는 데이터)
# ---------------------------------------------------------------------------
def _hop(step_no: int, ev: Any) -> Dict[str, str]:
    action = ev.action.value if hasattr(ev.action, "value") else str(ev.action)
    label = _ACTION_LABEL.get(action, action)
    target = ev.target.domain or ev.target.hostname or ev.target.dst_ip or "-"
    detail = label
    pl = ev.payload
    if pl.file_name:
        detail += f" · {pl.file_name}"
    if pl.table_name:
        detail += f" · {pl.table_name}"
    extra = pl.extra or {}
    if extra.get("text_length"):
        detail += f" · {extra['text_length']}자"
    return {
        "step": f"Step {step_no} · {label}",
        "nodeLabel": (ev.log_source.value if hasattr(ev.log_source, "value") else str(ev.log_source)).upper(),
        "nodeSub": str(target),
        "time": _kst(ev.timestamp).split(" ")[-1],
        "actor": f"{ev.actor.user_id or '-'} ({ev.actor.src_ip})",
        "detail": detail,
    }


def _build_hops(inc, events_by_id: Dict[str, Any]) -> List[Dict[str, str]]:
    evs = [events_by_id[i] for i in inc.event_ids if i in events_by_id]
    evs.sort(key=lambda e: e.timestamp)
    if evs and len(evs) < 3:
        # 같은 사용자의 직전 30분 이벤트(기밀 DB 조회 → AI 접속)를 앞 단계로 보강한다.
        user = _pc_ip(inc.actor)[1]
        last = evs[-1].timestamp
        have = {e.event_id for e in evs}
        related = [e for e in events_by_id.values()
                   if e.event_id not in have and e.actor.user_id == user
                   and timedelta(0) <= last - e.timestamp <= timedelta(minutes=30)]
        evs = sorted(related + evs, key=lambda e: e.timestamp)
    if len(evs) >= 3:
        picks = [evs[0], evs[len(evs) // 2], evs[-1]]
    else:
        picks = evs
    hops = _fill_hops(inc, picks, evs)
    return hops


def _endpoint_hop(inc, evs: List[Any]) -> Dict[str, str]:
    """HOP 1(발원 단말). 이벤트가 1건뿐이어도 엔진이 가진 사용자·PC 정보로 채운다."""
    ip, user = _pc_ip(inc.actor)
    if evs:  # 이벤트가 있으면 이벤트의 실제 사용자·IP가 가장 정확하다
        user, ip = evs[0].actor.user_id or user, evs[0].actor.src_ip or ip
    elif not user:  # "User" 처럼 괄호 없는 actor 문자열은 사용자명으로 본다
        ip, user = "", ip
    t = _kst(evs[0].timestamp).split(" ")[-1] if evs else _kst(inc.created_at).split(" ")[-1]
    return {"step": "Step 1 · 발원 단말", "nodeLabel": "ENDPOINT", "nodeSub": user or ip or "-",
            "time": t, "actor": f"{user or '-'} ({ip})" if ip else (user or "-"),
            "detail": f"발원 단말: {user or '-'} ({ip})" if ip else f"발원 단말: {user or '-'}"}


def _target_hop(inc, evs: List[Any]) -> Dict[str, str]:
    """HOP 3(표적). 마지막 이벤트의 대상 도메인과 엔진 점수를 쓴다."""
    last = evs[-1] if evs else None
    domain = (last.target.domain or last.target.hostname or last.target.dst_ip) if last else ""
    t = _kst(last.timestamp).split(" ")[-1] if last else _kst(inc.created_at).split(" ")[-1]
    note = inc.evidences[-1] if inc.evidences else (inc.summary or "근거 없음")
    return {"step": "Step 3 · 표적", "nodeLabel": "TARGET", "nodeSub": str(domain or inc.target_asset or "-"),
            "time": t, "actor": inc.actor, "detail": note}


def _fill_hops(inc, picks: List[Any], evs: List[Any]) -> List[Dict[str, str]]:
    """항상 3칸을 실제 데이터로 채운다. 이벤트가 모자라면 단말/표적을 엔진 정보로 보강한다.
    없는 사실은 만들지 않는다(시각은 실제 이벤트 시각 또는 인시던트 생성 시각)."""
    if len(picks) >= 3:
        return [_hop(i + 1, e) for i, e in enumerate(picks[:3])]
    if len(picks) == 2:
        return [_hop(1, picks[0]), _hop(2, picks[1]), _target_hop(inc, evs)]
    if len(picks) == 1:
        mid = _hop(2, picks[0])
        return [_endpoint_hop(inc, evs), mid, _target_hop(inc, evs)]
    ep = _endpoint_hop(inc, evs)
    mid = {"step": "Step 2 · 근거", "nodeLabel": "SENSOR", "nodeSub": "-", "time": ep["time"],
           "actor": inc.actor, "detail": inc.evidences[0] if inc.evidences else "이벤트 기록 없음"}
    return [ep, mid, _target_hop(inc, evs)]


def _incident_payload(inc, events_by_id) -> Dict[str, Any]:
    sev = _SEVERITY_LABEL.get(inc.severity.value, inc.severity.value)
    return {
        "id": inc.incident_id,
        "title": inc.title,
        "shortTitle": inc.title if len(inc.title) <= 40 else inc.title[:38] + "…",
        "severity": sev,
        "score": inc.score,
        "time": _kst(inc.created_at) + " KST",
        "createdAt": _kst(inc.created_at),
        "source": inc.actor,
        "target": inc.target_asset,
        "category": inc.category.value,
        "summary": inc.summary,
        "status": _STATUS_LABEL.get(inc.status.value, inc.status.value),
        "eventCount": len(inc.event_ids),
        "reasons": list(inc.evidences),
        "actions": list(inc.soar_actions),
        "hops": _build_hops(inc, events_by_id),
    }


def _pc_ip(inc_source: str) -> Tuple[str, str]:
    """'192.168.1.5 (kim)' 같은 actor 문자열에서 IP·사용자를 분리한다."""
    ip, user = inc_source, ""
    if "(" in inc_source and inc_source.endswith(")"):
        ip, user = inc_source.rsplit("(", 1)
        user = user[:-1]
    return ip.strip(), user.strip()


def build_snapshot(ctx, ui: Dict[str, Any]) -> Dict[str, Any]:
    """화면이 그릴 모든 데이터. ui 는 세션에 저장된 설정(수집 ON/OFF, Gemini 사용 여부 등)."""
    now_utc = datetime.now(timezone.utc)
    raw = list(tc.fetch_railway_events())
    status = tc.get_railway_fetch_status()
    events_by_id = {e.event_id: e for e in getattr(ctx, "team_events", [])}
    assignees = _load_assignees()
    blocked, policy_ok = fetch_blocklist()

    engine = ctx.correlation_engine
    incidents_raw = engine.get_all_incidents()
    incidents = [_incident_payload(i, events_by_id) for i in incidents_raw]

    # 인시던트별 이벤트 → 로그 점수 연결
    score_by_event: Dict[str, int] = {}
    for inc in incidents_raw:
        for eid in inc.event_ids:
            score_by_event[eid] = max(score_by_event.get(eid, 0), inc.score)

    # 로그 파이프라인
    logs = []
    for it in sorted(raw, key=_event_dt, reverse=True):
        ev_id = f"EVT-RLY-{it.get('id', 0)}"
        size = it.get("file_size_formatted")
        logs.append({
            "id": ev_id,
            "time": _kst(_event_dt(it)),
            "user": it.get("user_name") or "-",
            "pcName": it.get("pc_name") or "-",
            "ip": it.get("local_ip") or "-",
            "type": it.get("event_type") or "WEB_ACCESS",
            "site": it.get("target") or "-",
            "fileName": it.get("file_name") or "",
            "fileSize": size if size and size != "-" else "",
            "pasteChars": it.get("text_length"),
            "source": it.get("source") or "-",
            "score": score_by_event.get(ev_id),
        })

    pcs: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for l in logs:
        k = (l["pcName"], l["ip"])
        s = pcs.setdefault(k, {"pcName": l["pcName"], "ip": l["ip"], "count": 0,
                               "lastTime": l["time"], "user": l["user"]})
        s["count"] += 1
    pc_summary = sorted(pcs.values(), key=lambda s: s["lastTime"], reverse=True)

    # 케이스 (인시던트 1건 = 케이스 1건)
    cases = []
    for inc, p in zip(incidents_raw, incidents):
        ip, user = _pc_ip(inc.actor)
        cases.append({
            "id": inc.incident_id,
            "title": inc.title,
            "description": inc.summary,
            "isML": False,
            "severity": p["severity"],
            "status": ("신규" if inc.incident_id not in assignees else "진행 중")
            if inc.status.value == "ACTIVE" else p["status"],
            "asset": {"isFlow": False, "name": user or ip, "ip": ip},
            "assignee": assignees.get(inc.incident_id, "미배정"),
            "createdAt": p["createdAt"],
            "updatedAt": p["createdAt"],
            "score": inc.score,
        })

    active = []
    for inc, p in zip(incidents_raw, incidents):
        if inc.status.value == "RESOLVED":
            continue
        ip, user = _pc_ip(inc.actor)
        active.append({
            "id": inc.incident_id, "title": inc.title,
            "severity": "심각" if p["severity"] == "HIGH" else "선제 관찰",
            "status": p["status"], "riskScore": inc.score,
            "hostIp": inc.actor, "assetCount": 1, "eventCount": len(inc.event_ids),
            "correlationFlow": " → ".join(
                [h.from_node for h in inc.network_hops[:1]] + [h.to_node for h in inc.network_hops]
            ) or f"{inc.actor} → {inc.target_asset}",
            "aiSummary": inc.summary,
            "assignee": assignees.get(inc.incident_id, "미배정"),
            "time": p["time"],
        })

    # 감시 대상 (WATCH 상태이고 TTL 이 남은 사용자)
    watch = []
    for r in engine.get_watch_users():
        if r.get("state") != "WATCH":
            continue
        try:
            exp = datetime.strptime(str(r["expires_at"])[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        watch.append({"user": r["user"], "state": r["state"], "score": r.get("score", 0),
                      "ttlSeconds": max(0, int((exp - now_utc).total_seconds())),
                      "reasons": r.get("reasons", [])})

    # 감사 이력
    audit = []
    for h in engine.store.get_risk_history(25):
        audit.append({
            "utc": f"{h.get('at', '')} UTC", "target": h.get("user", "-"),
            "prev": h.get("from_state") or "-",
            "next": h.get("to_state") or "-",
            "reason": h.get("reason") or "",
        })

    # 거버넌스
    stats = ctx.governance_engine.get_railway_domain_stats()
    inc_score_by_domain: Dict[str, int] = {}
    for inc in incidents_raw:
        for dom in stats:
            if dom in (inc.target_asset or "") or dom in inc.title:
                inc_score_by_domain[dom] = max(inc_score_by_domain.get(dom, 0), inc.score)
    devices_by_domain: Dict[str, set] = {}
    exfil_by_domain: Dict[str, int] = {}
    for it in raw:
        dom = _norm_domain(it.get("target") or "")
        devices_by_domain.setdefault(dom, set()).add(it.get("pc_name") or it.get("local_ip") or "")
        if it.get("event_type") in ("FILE_UPLOAD_ATTEMPT", "PASTE_ATTEMPT"):
            exfil_by_domain[dom] = exfil_by_domain.get(dom, 0) + 1
    gov = []
    for a in ctx.governance_engine.get_all_assets():
        st = stats.get(a.domain, {})
        gov.append({
            "domain": a.domain, "service": a.service_name, "category": a.category,
            "riskLevel": {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(a.risk_level.value, a.risk_level.value),
            "riskScore": inc_score_by_domain.get(a.domain),
            "govStatus": "차단" if a.domain in blocked else {
                "APPROVED": "승인", "CONDITIONAL": "조건부 승인", "UNAPPROVED": "미승인", "BLOCKED": "차단"
            }.get(a.sanction_status.value, a.sanction_status.value),
            "liveHits": a.access_count, "liveDevices": len(devices_by_domain.get(a.domain, ())),
            "users": a.user_count, "freqLabel": a.usage_frequency,
            "totalCumulative": st.get("count", a.access_count),
            "exfilAttempts": exfil_by_domain.get(a.domain, 0),
            "aiOpinion": a.ai_diagnosis, "blocked": a.domain in blocked,
        })

    # 최근 7일 일자별 이벤트 수 (KST 기준)
    today = datetime.now(KST).date()
    per_day = {today - timedelta(days=i): 0 for i in range(6, -1, -1)}
    for it in raw:
        d = _event_dt(it).replace(tzinfo=timezone.utc).astimezone(KST).date()
        if d in per_day:
            per_day[d] += 1
    names = "월화수목금토일"
    weekly = [{"day": names[d.weekday()], "date": d.isoformat(), "count": c} for d, c in per_day.items()]

    sites, site_err = fetch_site_access()
    gem_key = bool(_gemini_key())
    return {
        "serverNow": datetime.now(KST).isoformat(timespec="seconds"),
        "meta": {
            "railwayLive": bool(ui.get("collect", True)),
            "fetchOk": status.get("ok"),
            "fetchError": status.get("error"),
            "lastSuccess": _kst(datetime.fromisoformat(status["last_success"].rstrip("Z")))
            if status.get("last_success") else None,
            "hasApiKey": bool(_api_key()),
            "apiBase": _base_url(),
            "policyOk": policy_ok,
            "siteAccessError": site_err,
            "geminiConfigured": gem_key,
            "geminiEnabled": bool(ui.get("gemini", gem_key)) and gem_key,
            "totalEvents": len(raw),
        },
        "activeIncidentsData": active,
        "casesData": cases,
        "incidents": incidents,
        "watchUsers": watch,
        "auditHistory": audit,
        "govAssets": gov,
        "siteAccessGroups": sites,
        "pcSummary": pc_summary,
        "pipelineLogs": logs,
        "weeklyActivity": weekly,
        "diag": ui.get("diag"),
        "lastResult": ui.get("last_result"),
    }


# ---------------------------------------------------------------------------
# 버튼 동작
# ---------------------------------------------------------------------------
def handle_action(ctx, ui: Dict[str, Any], action: str, p: Dict[str, Any]) -> Tuple[bool, str]:
    """화면에서 온 요청 한 건을 실제로 수행한다. (성공 여부, 사용자에게 보여줄 메시지)"""
    if action == "poll":
        refresh(ctx, force=False)
        return True, ""
    if action == "sync":
        res = refresh(ctx, force=True)
        st = tc.get_railway_fetch_status()
        if st.get("ok") is False:
            hint = "API 키 확인 필요" if not _api_key() else "서버 응답 오류"
            return False, f"Railway 동기화 실패 ({st.get('error') or '연결 오류'} · {hint})"
        return True, f"동기화 완료 · 수신 {res['fetched']}건 · 신규 분석 {res['ingested']}건"
    if action == "toggle_collect":
        on = bool(p.get("on"))
        ui["collect"] = on
        tc.set_railway_collection_enabled(on)
        if on:
            refresh(ctx, force=True)
        return True, "실시간 수집 " + ("ON" if on else "OFF")
    if action == "block_domain":
        ok, msg = set_domain_block(str(p.get("domain", "")), bool(p.get("blocked")))
        if ok:
            refresh(ctx, force=False)
        return ok, msg
    if action == "site_access":
        return change_site_access(str(p.get("deviceId", "")), str(p.get("domain", "")),
                                  str(p.get("pcName", "")), int(p.get("minutes", 0)))
    if action == "assign":
        return assign_case(str(p.get("id", "")), str(p.get("assignee", "")))
    if action == "toggle_gemini":
        if not _gemini_key():
            ui["gemini"] = False
            return False, "GEMINI_API_KEY가 서버에 설정되어 있지 않습니다. .env 또는 Streamlit Secrets에 등록하세요."
        ui["gemini"] = bool(p.get("on"))
        return True, "Gemini 판별 " + ("ON" if ui["gemini"] else "OFF (규칙 엔진)")
    if action == "diagnose":
        d = _norm_domain(str(p.get("domain", "")))
        if not d or "." not in d:
            return False, "도메인 형식이 올바르지 않습니다."
        use_gemini = bool(ui.get("gemini", bool(_gemini_key()))) and bool(_gemini_key())
        key = _gemini_key() if use_gemini else None
        asset = ctx.governance_engine.analyze_and_register_domain(
            d, api_key=key, live_context=ctx.governance_engine.get_railway_domain_stats().get(d))
        ui["diag"] = {
            "domain": asset.domain, "service": asset.service_name, "category": asset.category,
            "riskLevel": asset.risk_level.value, "opinion": asset.ai_diagnosis,
            "engine": governance.LAST_ENGINE["name"] if use_gemini else "Rule Engine",
            "hits": asset.access_count,
        }
        note = " — Gemini 호출 실패, 규칙 기반으로 대체됨" if use_gemini and ui["diag"]["engine"] != "Gemini" else ""
        return True, f"{asset.domain} 진단 완료 ({ui['diag']['engine']}){note}"
    return False, f"알 수 없는 동작: {action}"
