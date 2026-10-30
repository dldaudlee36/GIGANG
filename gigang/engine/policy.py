"""
GIGANG - 기밀 DB 반출 판정 (부서별 정책)

=====================================================================
[이 파일이 하는 일]
=====================================================================
기밀 DB에서 복사(CLIPBOARD_COPY)·화면 캡처(SCREEN_CAPTURE)·다운로드(DB_DOWNLOAD)한 이벤트 하나를 받아
"기록만 / WATCH" 와 규칙 번호를 정한다. (GIGANG_수정계획.md 1·3·4장, 9장 다운로드 규칙)

  judge()  ←  판정 함수 하나에 모았다
    1) 시간창 확인   AI 접속 전 N분 ~ AI 접속 후 M분(AI가 켜져 있는 상태) 안인가?  아니면 None
    2) 캡처인가?     → SS-1 WATCH (부서 무관)
       검사 못 하는 다운로드인가? → DL-2 WATCH (부서 무관, 1회도)
    3) 부서 찾기     → 없으면 COM-2: 기존 규칙대로 (기밀 DB + AI 접속 → WATCH)
    4) 정책 적용     → 부서 표의 ○× 와 건수로 CS-1 ~ DEV-1
                       검사한 다운로드(DL-1)는 같은 표에 규칙 번호만 DL- 를 붙인다 (DL-CS-2, DL-COM-2 ...)
    5) 결과          → Judgment(등급, 규칙 번호, 사유)

  judge_upload()  ←  DL-3: 기밀 DB에서 받은 파일(이름·크기 일치)을 AI에 올리면 HIGH (부서·상태·시간창 무관)

상태를 바꾸지는 않는다. 상태 저장·알림은 correlation.py 가 이 결과를 받아서 한다.
그래서 이 함수만 따로 불러 오탐·미탐을 셀 수 있다.

[정책 값]
지금은 같은 폴더의 department_policy.json 에서 읽는다.
Railway DB 정책 테이블이 생기면 load_policy() 만 바꾸면 된다. (rows 가 테이블 행과 같은 모양)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

POLICY_PATH = Path(__file__).resolve().parent / "department_policy.json"

DATA_LABELS = {
    "phone": "전화번호",
    "email": "이메일",
    "rrn": "주민번호",
    "account": "계좌번호",
    "card": "카드번호",
}


@dataclass
class Judgment:
    level: str                                   # "WATCH" 또는 "RECORD"(기록만), DL-3 은 "HIGH"
    rules: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    score: int = 0                               # 상관분석 점수 (score_judgment)
    kind: str = ""                               # 점수 기본값 종류 (정책 score.base 의 키)


# 상관분석 배점. department_policy.json 의 "score" 가 없을 때만 쓴다.
DEFAULT_SCORE = {
    "base": {"not_allowed": 60, "over_usual": 55, "no_department": 55, "capture": 60,
             "uninspectable": 62, "zero": 50, "usual": 25,
             # 이벤트 규칙(FSM)이 쓰는 기본점. 값은 기존 하드코딩 그대로다 (배점 변경 없음).
             "fsm_watch": 68, "image_watch": 70, "self_heal": 20,
             "fsm_high_upload": 95, "fsm_high_transfer": 92,
             "dormant_upload": 96, "dormant_transfer": 94,
             "paste_transfer": 93, "image_match": 93, "dl3": 95, "com3": 93},
    "data": {"rrn": 12, "card": 12, "account": 9, "phone": 4, "email": 4},
    "count": [[30, 14], [10, 10], [3, 5]],
    "near_minutes": 5, "near": 6,
    "download": 5,
    "min": {"WATCH": 60},
    "max": {"NORMAL": 59, "RECORD": 59, "WATCH": 89, "HIGH": 99},
}


def load_policy(path: Path = POLICY_PATH) -> Dict[str, Any]:
    """정책 파일을 읽는다. 파일이 없거나 깨져 있으면 부서 없음(전원 COM-2)으로 동작한다."""
    try:
        with open(path, encoding="utf-8") as f:
            policy = json.load(f)
    except (OSError, ValueError):
        policy = {}
    policy.setdefault("window_before_minutes", 15)
    policy.setdefault("ai_state_minutes", 60)
    policy.setdefault("rrn_low_min", 3)
    policy.setdefault("zero_hits", "RECORD")
    policy.setdefault("usual_count_minutes", 60)      # 평소 건수: 이 시간 안의 기밀 DB 복사·다운로드 건수를 누적해서 비교
    policy.setdefault("paste_match_minutes", 60)      # COM-3: 기밀 DB 복사 후 몇 분 안의 AI 붙여넣기를 볼지
    policy.setdefault("paste_match_tolerance", 0.15)  # COM-3: 복사·붙여넣기 글자 수 차이 허용 비율 (줄바꿈 CRLF·LF 차이 등)
    policy.setdefault("departments", {})
    policy.setdefault("users", {})
    policy.setdefault("rows", [])
    custom = policy.get("score") or {}
    policy["score"] = {**DEFAULT_SCORE, **custom}
    for key in ("base", "data", "min", "max"):      # 일부만 적어도 나머지는 기본값을 쓴다
        policy["score"][key] = {**DEFAULT_SCORE[key], **(custom.get(key) or {})}
    return policy


def merge_remote(local: Dict[str, Any], remote: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Railway 정책 표(GET /policies)를 로컬 정책 위에 덮는다.
    표에서 오는 것은 users / departments / rows 뿐이고, 시간창 등 설정값은 로컬 파일 값을 쓴다.
    형식이 이상한 값은 버리고 로컬 값을 그대로 둔다 (판정이 멈추지 않게).
    """
    merged = dict(local)
    if not isinstance(remote, dict):
        return merged
    users = remote.get("users")
    if isinstance(users, dict):
        merged["users"] = {str(u): str(d) for u, d in users.items()}
    departments = remote.get("departments")
    if isinstance(departments, dict) and departments:
        merged["departments"] = {str(c): str(n) for c, n in departments.items()}
    rows = remote.get("rows")
    if isinstance(rows, list) and rows and all(
        isinstance(r, list) and len(r) == 6 and r[1] in DATA_LABELS and isinstance(r[2], bool)
        and isinstance(r[3], int) and r[3] >= 1 and r[5] for r in rows
    ):
        merged["rows"] = rows
    return merged


def nearest_ai_access(event_time: datetime, ai_accesses: List[Tuple[datetime, str]],
                      policy: Dict[str, Any]) -> Optional[Tuple[datetime, str]]:
    """
    시간창 안의 AI 접속을 하나 찾는다. 없으면 None.

    AI 접속 a 에 대해 [a - 전 N분, a + 상태 M분] 안이면 짝이 된다.
      · DB 복사 → AI 켜기   : 복사가 a 보다 N분 이내 앞
      · AI 켜두고 → DB 복사 : 복사가 a 이후 M분 이내 (DNS 캐시 때문에 접속 로그가 한 번만 찍혀도 이어서 본다)
    """
    before = timedelta(minutes=policy["window_before_minutes"])
    after = timedelta(minutes=policy["ai_state_minutes"])
    matches = [(t, d) for t, d in ai_accesses if t - before <= event_time <= t + after]
    return min(matches, key=lambda m: abs(m[0] - event_time)) if matches else None


def effective_counts(pattern_hits: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, int]:
    """
    Agent 가 보낸 규칙별 건수를 판정용 건수로 바꾼다.
    주민번호 '낮음'(마스킹·느슨한 형식)은 rrn_low_min 건 이상 쌓일 때만 센다. (계획서 2장: 낮음은 건수가 쌓여야 인정)
    """
    def num(key):
        try:
            return max(int(pattern_hits.get(key, 0) or 0), 0)
        except (ValueError, TypeError):
            return 0

    counts = {key: num(key) for key in ("phone", "email", "account", "card")}
    if any(k in pattern_hits for k in ("rrn_high", "rrn_mid", "rrn_low")):
        low = num("rrn_low")
        counts["rrn"] = num("rrn_high") + num("rrn_mid") + (low if low >= policy["rrn_low_min"] else 0)
    else:
        counts["rrn"] = num("rrn")      # 신뢰도 구분이 없는 옛 형식
    return counts


def _apply_department(dept: str, counts: Dict[str, int], policy: Dict[str, Any],
                      prior: Optional[Dict[str, int]] = None) -> Judgment:
    """
    부서 표(rows)를 적용한다. WATCH 규칙이 하나라도 걸리면 WATCH.
    prior : 앞선 usual_count_minutes 분 동안의 기밀 DB 복사·다운로드 건수 (이번 것 제외).
            기준 건수는 '이번 + 앞선' 누적으로 비교한다 → 소량을 나눠서 여러 번 복사해도 평소 건수 초과로 잡힌다.
            이번 복사에 없는 종류는 판정에 넣지 않는다 (이번 복사가 그 데이터를 반출한 게 아니므로).
    """
    prior = prior or {}
    window = policy["usual_count_minutes"]

    def total(t):
        return counts.get(t, 0) + prior.get(t, 0)

    def show(t):
        n, p = counts.get(t, 0), prior.get(t, 0)
        return f"{DATA_LABELS[t]} {n + p}건" + (f"(이번 {n} + 앞선 {window}분 {p})" if p else "")

    name = policy["departments"].get(dept, dept)
    rows = [r for r in policy["rows"] if r[0] == dept]
    watch, record = [], []

    # 비허용(×) 데이터: 같은 WATCH 규칙 번호끼리 건수를 합쳐 기준 건수와 비교
    groups: Dict[str, Dict[str, Any]] = {}
    for _, data, allowed, threshold, _, watch_rule in rows:
        if not allowed:
            group = groups.setdefault(watch_rule, {"types": [], "threshold": threshold})
            group["types"].append(data)
    for rule, group in groups.items():
        if not any(counts.get(t, 0) for t in group["types"]):
            continue
        # 같은 규칙 번호끼리 합치는 묶음(FIN-4 = 전화+이메일)은 앞선 복사의 다른 종류도 함께 센다
        hit = [t for t in group["types"] if total(t)]
        group_total = sum(total(t) for t in hit)
        what = ", ".join(show(t) for t in hit)
        if group_total and group_total >= group["threshold"]:
            limit = "1건 이상" if group["threshold"] <= 1 else f"{group['threshold']}건 이상"
            watch.append((rule, f"[{rule}] {name} · {what} ({name}의 평소 업무 데이터 아님, {limit})"))
        elif group_total:
            # 낮은 신뢰도 데이터가 '여러 건' 기준에 못 미침 (FIN-4 등)
            record.append((f"{rule}(미만)", f"[{rule}(미만)] {name} · {what} (기준 {group['threshold']}건 미만)"))

    # 허용(○) 데이터: 데이터마다 평소 건수와 비교
    for _, data, allowed, threshold, record_rule, watch_rule in rows:
        if not allowed or not counts.get(data, 0):
            continue
        if total(data) > threshold:
            watch.append((watch_rule, f"[{watch_rule}] {name} · {show(data)} (평소 {window}분 {threshold}건 초과)"))
        else:
            record.append((record_rule, f"[{record_rule}] {name} · {show(data)} (평소 {window}분 {threshold}건 이하)"))

    if watch:
        kind = "not_allowed" if any(r in groups for r, _ in watch) else "over_usual"
        return Judgment("WATCH", _unique(r for r, _ in watch), [text for _, text in watch], kind=kind)
    if record:
        return Judgment("RECORD", _unique(r for r, _ in record), [text for _, text in record], kind="usual")
    # 5개 패턴이 하나도 없는 복사. 처리 방식은 아직 정하지 않았다 (정책의 zero_hits 값).
    level = "WATCH" if policy["zero_hits"] == "WATCH" else "RECORD"
    return Judgment(level, ["ZERO"], [f"[ZERO] {name} · 민감정보 패턴 0건 (처리 방식 미정 → {'WATCH' if level == 'WATCH' else '기록만'})"],
                    kind="zero")


def _unique(items) -> List[str]:
    seen: List[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def judge(kind: str, event_time: datetime, user: str, extra: Dict[str, Any], source: str,
          ai_accesses: List[Tuple[datetime, str]], policy: Dict[str, Any],
          prior_counts: Optional[Dict[str, int]] = None) -> Optional[Judgment]:
    """
    기밀 DB 복사·캡처·다운로드 이벤트 하나를 판정한다. 시간창 밖이면 None (아직 판정할 수 없음).

    kind        : "CLIPBOARD_COPY", "SCREEN_CAPTURE" 또는 "DB_DOWNLOAD"
    extra       : Agent 가 보낸 값 (pattern_hits, text_length / shortcut, image_width, image_height
                  / file_name, file_size, file_kind, inspectable, reason)
    source      : 걸린 기밀 DB 주소 (Agent 설정값)
    ai_accesses : 이 사용자의 AI 접속 [(시각, 도메인), ...]
    prior_counts: 앞선 usual_count_minutes 분의 기밀 DB 복사·다운로드 건수 합 (누적 비교용, 엔진이 넘김)
    """
    ai = nearest_ai_access(event_time, ai_accesses, policy)
    if ai is None:
        return None
    ai_time, ai_domain = ai
    minutes = (event_time - ai_time).total_seconds() / 60
    order = f"AI 접속 {minutes:.0f}분 뒤" if minutes >= 0 else f"AI 접속 {-minutes:.0f}분 전"

    counts = effective_counts(extra.get("pattern_hits") or {}, policy)
    prior = prior_counts or {}
    # 점수의 건수도 누적으로 (이번 복사에 있는 종류만)
    scored = {t: n + prior.get(t, 0) for t, n in counts.items() if n}
    download = kind == "DB_DOWNLOAD"

    if kind == "SCREEN_CAPTURE":
        size = f", {extra.get('image_width')}×{extra.get('image_height')}" if extra.get("image_width") else ""
        result = Judgment("WATCH", ["SS-1"], [f"[SS-1] 기밀 DB 화면 캡처 ({extra.get('shortcut') or '단축키'}{size}) · 부서 무관",
                                              f"기밀 DB({source}) 화면 캡처, {order}({ai_domain})",
                                              "캡처 이미지는 수집하지 않음 (단축키와 이미지 크기만 기록)"], kind="capture")
        return score_judgment(result, {}, minutes, False, policy)

    if download:
        what = f"'{extra.get('file_name') or '이름 없음'}' ({_size(extra.get('file_size'))})"
        if extra.get("inspectable") is not True:
            why = extra.get("reason") or "내용 검사 불가"
            result = Judgment("WATCH", ["DL-2"], [
                f"[DL-2] 내용을 검사할 수 없는 파일 다운로드 ({extra.get('file_kind') or '형식 모름'}, {why}) · 부서 무관",
                f"기밀 DB({source}) 다운로드 {what}, {order}({ai_domain})",
                "파일은 수집하지 않음 (이름·크기·형식만 기록)",
            ], kind="uninspectable")
            return score_judgment(result, {}, minutes, True, policy)
        context = [f"기밀 DB({source}) 다운로드 {what}, 글자 {int(extra.get('text_length') or 0):,}자, {order}({ai_domain})",
                   "파일 내용은 수집하지 않음 (PC 안에서 규칙 검사 후 건수만 기록)"]
        result = _apply_policy(user, extra, policy, context, prior)
        # DL-1: 부서 표는 그대로, 규칙 번호에만 DL- 를 붙여 복사와 구분한다
        result.rules = ["DL-" + rule for rule in result.rules]
        result.reasons = ["[DL-" + r[1:] if r.startswith("[") else r for r in result.reasons]
        return score_judgment(result, scored, minutes, True, policy)

    context = [f"기밀 DB({source}) 복사 {int(extra.get('text_length') or 0):,}자, {order}({ai_domain})",
               "복사한 내용은 수집하지 않음 (PC 안에서 규칙 검사 후 건수만 기록)"]
    return score_judgment(_apply_policy(user, extra, policy, context, prior), scored, minutes, False, policy)


def compute_score(kind: str, level: str, s: Dict[str, Any], counts: Optional[Dict[str, int]] = None,
                  minutes: Optional[float] = None, download: bool = False) -> Tuple[int, List[Tuple[str, int]], int]:
    """
    GIGANG 의 유일한 점수 계산식. 정책 판정(policy.py)과 상태 전이(correlation.py)가 모두 이 함수를 쓴다.

      기본점(kind) + 가장 민감한 데이터 1종 + 건수 + AI 접속과 가까움 + 파일 다운로드
      → 등급별 하한·상한으로 자른다 (등급은 이벤트 규칙이 정하고, 점수는 같은 등급 안의 중요도만 나눈다).
      건수는 종류를 합치지 않고 가장 많은 종류의 건수로 센다 (고객 5명 = 전화 5 + 이메일 5 를 10건으로 부풀리지 않게).

    돌려주는 값: (최종 점수, [(항목, 점수), ...], 자르기 전 합계)
    """
    parts = [(f"기본({kind})", s["base"].get(kind, s["base"]["no_department"]))]
    hit = [t for t, n in (counts or {}).items() if n]
    if hit:
        top = max(hit, key=lambda t: s["data"].get(t, 0))
        parts.append((DATA_LABELS[top], s["data"].get(top, 0)))
        most = max(counts.values())
        bonus = next((pts for least, pts in s["count"] if most >= least), 0)
        if bonus:
            parts.append((f"{most}건", bonus))
    if minutes is not None and abs(minutes) <= s["near_minutes"]:
        parts.append((f"AI 접속 {s['near_minutes']}분 이내", s["near"]))
    if download:
        parts.append(("파일 다운로드", s["download"]))
    raw = sum(p for _, p in parts if p)
    final = max(min(raw, s["max"].get(level, 99)), s.get("min", {}).get(level, 0))
    return final, parts, raw


def explain_score(parts: List[Tuple[str, int]], raw: int, final: int) -> str:
    """점수 근거 한 줄. 화면에 보이는 항목별 점수는 반드시 이 함수로 만든다 (문구에 점수를 직접 적지 않는다)."""
    cut = f" → 상한 {final}" if final < raw else f" → 하한 {final}" if final > raw else ""
    return "상관분석 점수: " + " + ".join(f"{n} {p}" for n, p in parts if p) + f" = {raw}점{cut}"


def score_judgment(result: Judgment, counts: Dict[str, int], minutes: Optional[float],
                   download: bool, policy: Dict[str, Any]) -> Judgment:
    """판정 결과에 상관분석 점수를 매기고 근거 줄을 덧붙인다. 계산은 compute_score() 하나."""
    result.score, parts, raw = compute_score(result.kind, result.level, policy["score"], counts, minutes, download)
    result.reasons.append(explain_score(parts, raw, result.score))
    return result


def _apply_policy(user: str, extra: Dict[str, Any], policy: Dict[str, Any], context: List[str],
                  prior: Optional[Dict[str, int]] = None) -> Judgment:
    """부서를 찾아 부서 표를 적용한다. 부서 정보가 없으면 COM-2."""
    counts = effective_counts(extra.get("pattern_hits") or {}, policy)
    dept = policy["users"].get(user)
    if not dept or not any(r[0] == dept for r in policy["rows"]):
        return Judgment("WATCH", ["COM-2"],
                        ["[COM-2] 부서 정보 없음 → 기존 규칙대로 판정 (기밀 DB 반출 + AI 접속 → WATCH)"] + context,
                        kind="no_department")
    result = _apply_department(dept, counts, policy, prior)
    result.reasons += context
    return result


def _size(value: Any) -> str:
    try:
        size = int(value)
    except (ValueError, TypeError):
        return "크기 모름"
    return f"{size / 1024:,.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):,.1f} MB"


def judge_upload(file_name: Optional[str], file_size: Optional[int], target: str, tagged_source: Optional[str],
                 downloads: List[Dict[str, Any]], score_cfg: Dict[str, Any] = DEFAULT_SCORE) -> Optional[Judgment]:
    """
    DL-3: AI에 올린 파일이 기밀 DB에서 받은 파일이면 HIGH. 아니면 None.

    tagged_source : Agent 가 업로드 이벤트에 붙인 기밀 DB 주소 (Agent 가 이름·크기로 이미 맞춰 본 경우)
    downloads     : 엔진이 기억하는 이 사용자의 기밀 DB 다운로드 [{"name", "size", "source", "time"}, ...]
    파일 내용이 아니라 이름·크기로 맞춘다. 이름을 바꾸거나 내용을 고치면 맞지 않는다 (알려진 한계).
    """
    if not file_name:
        return None
    matched = next((d for d in reversed(downloads) if d["name"] == file_name and d["size"] == file_size), None)
    source = tagged_source or (matched and matched["source"])
    if not source:
        return None
    when = f", {matched['time']:%m-%d %H:%M} 다운로드" if matched else ""
    score, parts, raw = compute_score("dl3", "HIGH", score_cfg)
    return Judgment("HIGH", ["DL-3"], [
        f"[DL-3] 기밀 DB({source})에서 받은 파일을 생성형 AI({target})에 업로드 · 부서·상태 무관",
        f"업로드 파일: '{file_name}' ({_size(file_size)}) — 다운로드 파일과 이름·크기 일치{when}",
        "킬체인 확정: 기밀 DB 다운로드 → 생성형 AI 업로드 · " + explain_score(parts, raw, score),
    ], score=score, kind="dl3")


def judge_paste_after_copy(copies: List[Dict[str, Any]], paste_time: datetime, paste_length: int, target: str,
                           policy: Dict[str, Any]) -> Optional[Judgment]:
    """
    COM-3: '기록만' 으로 끝난 기밀 DB 복사(평소 업무)라도, 그 내용을 생성형 AI 에 붙여넣으면 HIGH.
    허용은 '복사' 까지만이고 AI 입력은 부서와 상관없이 HIGH 라는 원칙 (계획서 3장).

    같은 내용인지는 원문 없이 글자 수로 맞춘다: paste_match_minutes 분 안의 기밀 DB 복사 중
    글자 수 차이가 paste_match_tolerance 이내인 것. 자기가 쓴 글을 붙여넣는 정상 사용은 길이가 달라 걸리지 않는다.
    copies : [{"time", "length", "source", "rules"}, ...]  (엔진이 기억하는 이 사용자의 기밀 DB 복사)
    """
    if paste_length <= 0:
        return None
    since = paste_time - timedelta(minutes=policy["paste_match_minutes"])
    tol = policy["paste_match_tolerance"]
    match = next((c for c in reversed(copies)
                  if since <= c["time"] <= paste_time + timedelta(minutes=1) and c["length"] > 0
                  and abs(c["length"] - paste_length) <= max(10, c["length"] * tol)), None)
    if match is None:
        return None
    gap = max((paste_time - match["time"]).total_seconds() / 60, 0)
    score, parts, raw = compute_score("com3", "HIGH", policy["score"])
    rules = f" ({', '.join(match['rules'])})" if match.get("rules") else ""
    return Judgment("HIGH", ["COM-3"], [
        f"[COM-3] 기밀 DB({match['source']}) 복사{rules} {gap:.0f}분 뒤 생성형 AI({target})에 붙여넣기 · 부서·상태 무관",
        f"복사 {match['length']:,}자 ↔ 붙여넣기 {paste_length:,}자 (글자 수 일치로 같은 내용 판단, 원문은 보지 않음)",
        "킬체인 확정: 기밀 DB 복사 → 생성형 AI 입력 · " + explain_score(parts, raw, score),
    ], score=score, kind="com3")
