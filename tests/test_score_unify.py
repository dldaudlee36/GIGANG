"""점수 계산식 일원화 검증: 배점은 그대로, 계산은 policy.compute_score() 하나, CRITICAL 제거."""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datetime import datetime, timedelta
from gigang.engine import policy as P
from gigang.engine.correlation import CorrelationEngine
from gigang.schemas.event import SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
from gigang.schemas.incident import Severity, RiskState

fails = []
def check(name, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok: fails.append(name)

S = P.load_policy()["score"]
# 1) 기존 하드코딩 값이 계산식 결과로 그대로 나온다 (배점 변경 없음)
expected = {"fsm_watch": ("WATCH", 68), "image_watch": ("WATCH", 70), "self_heal": ("NORMAL", 20),
            "fsm_high_upload": ("HIGH", 95), "fsm_high_transfer": ("HIGH", 92),
            "dormant_upload": ("HIGH", 96), "dormant_transfer": ("HIGH", 94),
            "paste_transfer": ("HIGH", 93), "image_match": ("HIGH", 93), "dl3": ("HIGH", 95), "com3": ("HIGH", 93)}
for kind, (level, want) in expected.items():
    got = P.compute_score(kind, level, S)[0]
    check(f"{kind} = {want}", got == want, got)
check("기본값(JSON 없음)도 동일", all(P.compute_score(k, l, P.DEFAULT_SCORE)[0] == v for k, (l, v) in expected.items()))

# 2) 등급 상한/하한은 점수가 아니라 등급이 정한다
check("WATCH 상한 89", P.compute_score("not_allowed", "WATCH", S, {"rrn": 99}, 0, True)[0] <= 89)

# 3) 엔진: WATCH → 파일 업로드 → HIGH, 상태 점수 = 인시던트 점수 = 95
e = CorrelationEngine(enable_mock_incidents=False); e.store.clear_all()
u, t0 = "score_unify_user", datetime.utcnow() - timedelta(minutes=10)
def ev(i, mins, action, dom, src=LogSource.WINDOWS_AGENT, **kw):
    return SecurityEvent(event_id=f"EVT-SU-{i}", timestamp=t0 + timedelta(minutes=mins), log_source=src,
                         actor=Actor(user_id=u, src_ip="192.168.10.9"), target=Target(domain=dom), action=action,
                         payload=PayloadMetadata(**kw))
e.ingest_events([ev(1, 0, EventAction.CLIPBOARD_COPY, "db.local", extra={"pattern_hits": {"card": 1}, "text_length": 50}),
                 ev(2, 1, EventAction.WEB_ACCESS, "chatgpt.com")])
cur = e.store.get_active_risk(u)
check("WATCH 진입", cur and cur["state"] == "WATCH", cur)
e.ingest_events([ev(3, 3, EventAction.FILE_UPLOAD_ATTEMPT, "chatgpt.com", src=LogSource.WEB, file_name="a.xlsx", file_size=2048)])
cur = e.store.get_active_risk(u)
check("HIGH 확정 점수 95", cur and cur["state"] == "HIGH" and cur["score"] == 95, cur)
inc = [i for i in e.incidents.values() if u in i.actor]
check("인시던트 점수 = 상태 점수", inc and inc[-1].score == 95, [i.score for i in inc])
check("증거에 계산식 근거 포함", inc and any("상관분석 점수:" in x for x in inc[-1].evidences))
check("가짜 (+N점) 문구 없음", inc and not any(re.search(r"\(\+\d점\)", x) for x in inc[-1].evidences))

# 4) correlation.py 에 점수 숫자 하드코딩이 없다
src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gigang/engine/correlation.py"), encoding="utf-8").read()
code = "\n".join(l for l in src.split("\n") if not l.strip().startswith("#"))
check("score 하드코딩 없음", not re.search(r"score\s*=\s*\d+|, (?:'|\")(?:WATCH|HIGH)(?:'|\"), \d{2},", code))

# 5) CRITICAL 제거
check("Severity/RiskState 에 CRITICAL 없음", not hasattr(Severity, "CRITICAL") and not hasattr(RiskState, "CRITICAL"))
print("\n전체 PASS" if not fails else f"\n실패 {len(fails)}건: {fails}")
sys.exit(1 if fails else 0)
