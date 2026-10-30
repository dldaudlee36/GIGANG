"""프롬프트 3 검증: 같은 이벤트 리스트를 두 번 ingest 해도 두 번째엔 상태 전이가 없어야 한다."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from gigang.engine.correlation import CorrelationEngine
from gigang.schemas.event import (
    SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
)

engine = CorrelationEngine(enable_mock_incidents=False)
engine.store.clear_all()

USER = "test_dedup_user"
base = datetime.utcnow() - timedelta(minutes=5)

# [수정됨 10-06] 예전엔 'DB 감사 로그 SELECT → AI 접속' 으로 WATCH 를 만들었는데, 그 경로는 기록만으로 바뀌었다.
#   WATCH 는 기밀 DB 복사 규칙으로 만든다 (부서 정보 없는 사용자 → COM-2 WATCH).
events = [
    SecurityEvent(
        event_id="EVT-DUP-1", timestamp=base,
        log_source=LogSource.WINDOWS_AGENT,
        actor=Actor(user_id=USER, src_ip="192.168.10.77"),
        target=Target(domain="db.local"),
        action=EventAction.CLIPBOARD_COPY,
        payload=PayloadMetadata(extra={"pattern_hits": {"card": 1}, "text_length": 120}),
    ),
    SecurityEvent(
        event_id="EVT-DUP-2", timestamp=base + timedelta(seconds=60),
        log_source=LogSource.WINDOWS_AGENT,
        actor=Actor(user_id=USER, src_ip="192.168.10.77"),
        target=Target(domain="chatgpt.com"),
        action=EventAction.WEB_ACCESS,
        payload=PayloadMetadata(),
    ),
]

def hist_count():
    return len(engine.store.get_risk_history(limit=500))

print("== 1회차 ingest ==")
engine.ingest_events(events)
s1 = engine.store.get_active_risk(USER)
h1 = hist_count()
print(f"   상태: {s1['state'] if s1 else 'NORMAL'} | risk_history 건수: {h1} | 버퍼: {len(engine.event_buffer)}")

print("== 2회차 ingest (동일 리스트 재투입) ==")
engine.ingest_events(events)
s2 = engine.store.get_active_risk(USER)
h2 = hist_count()
print(f"   상태: {s2['state'] if s2 else 'NORMAL'} | risk_history 건수: {h2} | 버퍼: {len(engine.event_buffer)}")

ok = True
if not (s1 and s1["state"] == "WATCH"):
    print("FAIL: 1회차에 WATCH 로 전이되지 않음"); ok = False
if h2 != h1:
    print(f"FAIL: 2회차에 상태 이력이 늘어남 ({h1} -> {h2})"); ok = False
if len(engine.event_buffer) != 2:
    print(f"FAIL: 버퍼에 중복 이벤트가 쌓임 ({len(engine.event_buffer)}건)"); ok = False

engine.store.clear_all()
print("\nRESULT:", "PASS - 2회차에 상태 전이 없음" if ok else "FAIL")
sys.exit(0 if ok else 1)
