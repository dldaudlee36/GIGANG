"""terminal_bridge / memory_store: 가짜(목업) 이벤트를 주입하지 않는지 확인한다."""
from gigang.storage.memory_store import get_context
from gigang.ui import terminal_bridge as tb


def test_context_starts_without_mock_events():
    assert get_context().team_events == []


def test_unknown_action_is_rejected():
    ok, msg = tb.handle_action(get_context(), {}, "no_such_action", {})
    assert ok is False and msg


def test_snapshot_without_backend_reports_no_data(monkeypatch):
    monkeypatch.delenv("RAILWAY_API_KEY", raising=False)
    snap = tb.build_snapshot(get_context(), {})
    assert snap["meta"]["hasApiKey"] is False
    assert snap["pipelineLogs"] == [] and snap["govAssets"] == []
