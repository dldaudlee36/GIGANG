"""terminal_bridge / memory_store: 가짜(목업) 이벤트를 주입하지 않는지 확인한다."""
from gigang.collectors import team_collector
from gigang.storage.memory_store import AppContext, get_context
from gigang.ui import terminal_bridge as tb


def test_context_starts_without_mock_events():
    team_collector.set_railway_collection_enabled(False)
    team_collector._cached_railway_events = []
    AppContext._instance = None
    assert get_context().team_events == []


def test_unknown_action_is_rejected():
    ok, msg = tb.handle_action(get_context(), {}, "no_such_action", {})
    assert ok is False and msg


def test_snapshot_without_backend_reports_no_data(monkeypatch):
    monkeypatch.delenv("RAILWAY_API_KEY", raising=False)
    team_collector.set_railway_collection_enabled(False)
    team_collector._cached_railway_events = []
    AppContext._instance = None
    snap = tb.build_snapshot(get_context(), {})
    assert snap["meta"]["hasApiKey"] is False
    assert snap["pipelineLogs"] == [] and snap["govAssets"] == []


def test_hops_always_three_filled():
    from datetime import datetime, timezone
    from types import SimpleNamespace as N
    from gigang.ui import terminal_bridge as tb
    inc = N(actor="User", created_at=datetime.now(timezone.utc), evidences=["근거"], summary="s",
            target_asset="t", event_ids=[])
    hops = tb._build_hops(inc, {})
    assert len(hops) == 3
    assert all(h["nodeLabel"] != "-" and h["time"] != "-" and h["detail"] for h in hops)


def test_set_domain_policy_mutual_exclusion(tmp_path, monkeypatch):
    test_file = tmp_path / "blocked_domains.json"
    monkeypatch.setattr(tb, "_BLOCK_FILE", test_file)
    monkeypatch.setattr(tb, "_api_key", lambda: "test_key")

    class MockResp:
        status_code = 200
        def json(self): return {"domain": "claude.ai", "blocked": False}
        def raise_for_status(self): pass

    monkeypatch.setattr(tb.requests, "post", lambda *a, **kw: MockResp())

    # 1. leak block
    ok, msg = tb.set_domain_policy("claude.ai", "leak")
    assert ok is True
    full, leak = tb._local_policies()
    assert "claude.ai" in leak and "claude.ai" not in full

    # 2. full block switches mutually
    ok, msg = tb.set_domain_policy("claude.ai", "full")
    assert ok is True
    full, leak = tb._local_policies()
    assert "claude.ai" in full and "claude.ai" not in leak

    # 3. allow clears both
    ok, msg = tb.set_domain_policy("claude.ai", "allow")
    assert ok is True
    full, leak = tb._local_policies()
    assert "claude.ai" not in full and "claude.ai" not in leak
