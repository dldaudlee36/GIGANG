"""Background Slack-only monitoring; no UI, mock data, or policy changes."""
import logging
import os
import threading

_lock = threading.Lock()
_worker = None
log = logging.getLogger(__name__)


def start_slack_monitor():
    global _worker
    if not os.environ.get("SLACK_WEBHOOK_URL", "").strip():
        return
    with _lock:
        if _worker is not None and _worker.is_alive():
            return
        _worker = threading.Thread(target=_monitor, name="gigang-slack-monitor", daemon=True)
        _worker.start()


def _monitor():
    from gigang.engine.correlation import CorrelationEngine
    from gigang.engine.slack_notify import notification_context
    from gigang.collectors.team_collector import (
        fetch_railway_events, get_team_security_events, get_railway_fetch_status)
    engine = CorrelationEngine(enable_mock_incidents=False)
    baseline = True
    wait = threading.Event()
    log.warning("Slack monitoring started; homepage unchanged")
    while True:
        try:
            fetch_railway_events(timeout=5, force=True)
            if get_railway_fetch_status().get("ok"):
                # First successful batch establishes history without sending old alerts.
                notification_context.suppress = baseline
                events = get_team_security_events()
                engine.refresh_policy()
                engine.ingest_events(sorted(events, key=lambda event: event.timestamp))
                baseline = False
                notification_context.suppress = False
        except Exception:
            log.warning("Slack monitoring collection failed; retrying next cycle")
        wait.wait(5)
