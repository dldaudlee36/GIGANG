"""HIGH 사건 알림. 원문 자료는 보내지 않고, 사건 ID로 중복 전송을 막는다."""
from contextlib import closing
import logging
import os
import sqlite3
import threading
from urllib.parse import urlsplit

import requests

log = logging.getLogger(__name__)
notification_context = threading.local()


def build_payload(incident):
    # 제목/근거/파일명에는 원문이 들어갈 수 있어 전송하지 않는다.
    def safe(value):
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")[:200]
    text = (
        "🚨 GIGANG 보안 알림\n"
        f"등급: {safe(incident.severity.value)} · {incident.score}점\n"
        f"직원: {safe(incident.actor)}\n"
        f"대상: {safe(incident.target_asset)}\n"
        f"사건 ID: {safe(incident.incident_id)}\n"
        f"발생 시각: {safe(incident.created_at.isoformat())}\n"
        "회사 자료 관련 고위험 사건이 탐지됐습니다. 대시보드에서 상세 내용을 확인하세요.\n"
        "※ 입력·첨부 시도 또는 차단된 사건일 수 있으며, 실제 유출 완료를 뜻하지 않습니다."
    )
    return {"text": text, "unfurl_links": False, "unfurl_media": False}


def notify_high(incident, db_path):
    """환경변수가 없으면 끄기. 네트워크는 별도 스레드에서 실행한다."""
    if getattr(notification_context, "suppress", False):
        return False
    if incident.severity.value != "HIGH":
        return False
    url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    parsed = urlsplit(url)
    if not (parsed.scheme == "https" and parsed.netloc == "hooks.slack.com"
            and parsed.path.startswith("/services/")):
        return False
    try:
        with closing(sqlite3.connect(str(db_path), timeout=5)) as conn, conn:
            conn.execute("CREATE TABLE IF NOT EXISTS slack_notifications ("
                         "incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                         "updated_at TEXT DEFAULT CURRENT_TIMESTAMP)")
            claimed = conn.execute(
                "INSERT OR IGNORE INTO slack_notifications (incident_id,status) VALUES (?, 'pending')",
                (incident.incident_id,)).rowcount
        if not claimed:
            return False
        thread = threading.Thread(target=_deliver,
            args=(url, build_payload(incident), str(db_path), incident.incident_id), daemon=True)
        thread.start()
        return True
    except Exception:
        # 예외 문자열에 Webhook URL이 들어갈 수 있어 출력하지 않는다.
        log.warning("Slack notification could not be queued; incident remains saved")
        return False


def _deliver(url, payload, db_path, incident_id):
    status = "failed"
    try:
        response = requests.post(url, json=payload, timeout=(3, 7), allow_redirects=False)
        if response.status_code == 200 and response.text.strip() == "ok":
            status = "sent"
        else:
            log.warning("Slack notification rejected (HTTP %s)", response.status_code)
    except Exception:
        log.warning("Slack notification failed; incident remains saved")
    try:
        with closing(sqlite3.connect(db_path, timeout=5)) as conn, conn:
            conn.execute("UPDATE slack_notifications SET status=?, updated_at=CURRENT_TIMESTAMP "
                         "WHERE incident_id=?", (status, incident_id))
    except Exception:
        log.warning("Slack notification status could not be saved")
    # 불확실한 전송 결과를 재시도해 중복 알림을 만들지 않는다.
    # 종료 중 pending/failed가 된 건은 자동 재전송하지 않는다.
