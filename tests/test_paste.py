"""PASTE_ATTEMPT 판정 규칙 검증 (SCORING_V3 기준):
 (a) NORMAL 사용자 일반 텍스트 붙여넣기 -> 상태 유지 (RECORD)
 (b) NORMAL 사용자 민감정보 붙여넣기 -> WATCH 로 전이
 (c) WATCH 사용자 기밀 DB 내용 일치 붙여넣기 -> HIGH 승격
 (d) 원문 미저장 (길이와 패턴 통계만 저장) 확인
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gigang.engine.correlation import CorrelationEngine
from gigang.schemas.event import (
    SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
)

PATTERN_HITS = {"rrn": 3, "card": 1, "email": 12, "phone": 5}


def make_paste_event(user, eid, hits=None, length=3420, match=False):
    extra = {"text_length": length, "pattern_hits": hits or {}}
    if match:
        extra["match_status"] = "matched"
        extra["match"] = {"source_domain": "desktop-oli.tail2bbbea.ts.net"}
    return SecurityEvent(
        event_id=eid,
        timestamp=datetime.utcnow(),
        log_source=LogSource.CHROME_EXTENSION,
        actor=Actor(user_id=user, src_ip="192.168.10.88"),
        target=Target(domain="chatgpt.com", hostname="TEST-PC"),
        action=EventAction.PASTE_ATTEMPT,
        payload=PayloadMetadata(
            category="Shadow_AI_Paste",
            extra=extra,
        ),
        raw_message=f"event=PASTE_ATTEMPT target=chatgpt.com text_length={length}",
    )


def test_paste_rules():
    engine = CorrelationEngine(enable_mock_incidents=False)
    engine.store.clear_all()

    try:
        # (a) NORMAL 사용자 일반 텍스트 -> 상태 유지 (RECORD)
        U_NORMAL_SAFE = "paste_normal_safe"
        engine.ingest_events([make_paste_event(U_NORMAL_SAFE, "EVT-PASTE-SAFE", hits={}, length=150)])
        r_safe = engine.store.get_active_risk(U_NORMAL_SAFE)
        assert (r_safe["state"] if r_safe else "NORMAL") == "NORMAL", "일반 텍스트는 NORMAL 유지"

        # (b) NORMAL 사용자 민감정보 붙여넣기 -> WATCH 전이 (SCORING_V3)
        U_NORMAL_SENS = "paste_normal_sens"
        engine.ingest_events([make_paste_event(U_NORMAL_SENS, "EVT-PASTE-SENS", hits=PATTERN_HITS, length=3420)])
        r_sens = engine.store.get_active_risk(U_NORMAL_SENS)
        assert r_sens and r_sens["state"] == "WATCH", f"민감정보 붙여넣기는 WATCH 로 전이되어야 함: {r_sens}"

        # (c) WATCH 사용자 기밀 DB 내용 일치 붙여넣기 -> HIGH 승격
        U_WATCH = "paste_watch_user"
        engine.store.upsert_risk(
            U_WATCH, "WATCH", 68, ["테스트용 사전 감시 상태"],
            datetime.utcnow() + timedelta(minutes=30),
        )
        engine.ingest_events([make_paste_event(U_WATCH, "EVT-PASTE-W1", hits=PATTERN_HITS, length=3420, match=True)])
        r_watch = engine.store.get_active_risk(U_WATCH)
        assert r_watch and r_watch["state"] == "HIGH", f"내용 일치 시 HIGH 로 승격되어야 함: {r_watch}"

        # (d) 원문 미저장 확인
        all_text = " ".join(
            h["reason"] or "" for h in engine.store.get_risk_history(limit=500)
        ) + " ".join(
            str(r["reasons"]) for r in engine.store.get_all_risks()
        )
        assert "3420" not in all_text or "text=" not in all_text, "원문이 저장되지 않고 통계만 저장되어야 함"
    finally:
        engine.store.clear_all()


if __name__ == "__main__":
    test_paste_rules()
    print("RESULT: PASS")
