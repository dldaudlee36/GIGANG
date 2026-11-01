"""프롬프트 3 검증: 같은 이벤트 리스트를 두 번 ingest 해도 두 번째엔 상태 전이가 없어야 한다."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from gigang.engine.correlation import CorrelationEngine
from gigang.schemas.event import (
    SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
)


def test_dedup_no_state_transition_on_reingest():
    engine = CorrelationEngine(enable_mock_incidents=False)
    engine.store.clear_all()

    USER = "test_dedup_user"
    base = datetime.utcnow() - timedelta(minutes=5)

    events = [
        SecurityEvent(
            event_id="EVT-DUP-1", timestamp=base,
            log_source=LogSource.CHROME_EXTENSION,
            actor=Actor(user_id=USER, src_ip="192.168.10.77"),
            target=Target(domain="desktop-oli.tail2bbbea.ts.net"),
            action=EventAction.COPY_ATTEMPT,
            payload=PayloadMetadata(extra={"source_path": "/db", "detection_scope": "customer_table", "pattern_hits": {"card": 1}, "text_length": 120, "inspected": True}),
        ),
        SecurityEvent(
            event_id="EVT-DUP-2", timestamp=base + timedelta(seconds=60),
            log_source=LogSource.CHROME_EXTENSION,
            actor=Actor(user_id=USER, src_ip="192.168.10.77"),
            target=Target(domain="chatgpt.com"),
            action=EventAction.WEB_ACCESS,
            payload=PayloadMetadata(),
        ),
    ]

    engine.ingest_events(events)
    s1 = engine.store.get_active_risk(USER)
    h1 = len(engine.store.get_risk_history(limit=500))

    engine.ingest_events(events)
    s2 = engine.store.get_active_risk(USER)
    h2 = len(engine.store.get_risk_history(limit=500))

    assert s1 and s1["state"] == "WATCH", f"1회차에 WATCH 로 전이되지 않음: {s1}"
    assert h2 == h1, f"2회차에 상태 이력이 늘어남 ({h1} -> {h2})"
    assert len(engine.event_buffer) == 2, f"버퍼에 중복 이벤트가 쌓임 ({len(engine.event_buffer)}건)"

    engine.store.clear_all()


if __name__ == "__main__":
    test_dedup_no_state_transition_on_reingest()
    print("RESULT: PASS - 2회차에 상태 전이 없음")
