"""slack_notify: HIGH 만 1회 전송, 원문 미포함, URL 검증."""
import sqlite3
import time
from datetime import datetime
from types import SimpleNamespace

from gigang.engine import slack_notify as sn

URL = "https://hooks.slack.com/services/T0/B0/xxx"


def _inc(sev="HIGH", iid="INC-T-1"):
    return SimpleNamespace(severity=SimpleNamespace(value=sev), score=95, actor="1.1.1.1 (kim)",
                           target_asset="chatgpt.com", incident_id=iid,
                           created_at=datetime(2026, 1, 1), title="SECRET-TITLE")


def test_sends_once_and_hides_title(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setenv("SLACK_WEBHOOK_URL", URL)
    monkeypatch.setattr(sn.requests, "post", lambda url, json, **k: sent.append(json) or SimpleNamespace(status_code=200, text="ok"))
    db = tmp_path / "t.db"
    assert sn.notify_high(_inc(), db) is True
    assert sn.notify_high(_inc(), db) is False
    time.sleep(0.5)
    assert len(sent) == 1 and "SECRET-TITLE" not in sent[0]["text"]
    assert sqlite3.connect(db).execute("select status from slack_notifications").fetchone()[0] == "sent"


def test_ignores_non_high_and_bad_url(tmp_path, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", URL)
    assert sn.notify_high(_inc("WATCH"), tmp_path / "a.db") is False
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://evil.example.com/services/x")
    assert sn.notify_high(_inc(), tmp_path / "b.db") is False
