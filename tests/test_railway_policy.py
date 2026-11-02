"""
Railway 중앙 브라우저 정책 서버(source/railway_server/app.py) 단위 테스트.
로컬 환경에 psycopg2, flask_cors가 없는 상태에서도 MagicMock을 통해 API 핸들러 및 스냅샷 분리 로직을 검증한다.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

# 1. psycopg2 및 flask_cors mock 주입 (서버 전용 패키지 로컬 환경 대응)
mock_psycopg2 = MagicMock()
mock_extras = MagicMock()
mock_psycopg2.extras = mock_extras
sys.modules["psycopg2"] = mock_psycopg2
sys.modules["psycopg2.extras"] = mock_extras

mock_cors = MagicMock()
mock_cors.CORS = MagicMock(return_value=None)
sys.modules["flask_cors"] = mock_cors

# 2. railway_server 모듈 import 경로 추가
server_dir = Path(__file__).resolve().parent.parent / "source" / "railway_server"
if str(server_dir) not in sys.path:
    sys.path.insert(0, str(server_dir))

import pytest
from app import app, _ensure_policy_table, _policy_snapshot, API_KEY


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_ensure_policy_table_executes_ddl_and_migration():
    cur = MagicMock()
    _ensure_policy_table(cur)
    # CREATE TABLE 과 ALTER TABLE ADD COLUMN 호출 확인
    assert cur.execute.call_count == 2
    calls = [c[0][0] for c in cur.execute.call_args_list]
    assert any("CREATE TABLE IF NOT EXISTS browser_block_policy" in c for c in calls)
    assert any("ALTER TABLE browser_block_policy" in c and "policy_type" in c for c in calls)


def test_policy_snapshot_partitions_full_and_leak(monkeypatch):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    # Mock DB 결과: full, leak, 그리고 policy_type이 None인 구형 레코드 혼합
    mock_cur.fetchall.return_value = [
        {"domain": "chatgpt.com", "policy_type": "full", "updated_at": now},
        {"domain": "claude.ai", "policy_type": "leak", "updated_at": now},
        {"domain": "legacy.com", "policy_type": None, "updated_at": now},
        {"domain": "deepseek.com", "policy_type": "leak", "updated_at": now},
    ]

    monkeypatch.setattr("app.get_db_connection", lambda: mock_conn)

    snap = _policy_snapshot()
    assert sorted(snap["blocked_domains"]) == ["chatgpt.com", "legacy.com"]
    assert sorted(snap["leak_blocked_domains"]) == ["claude.ai", "deepseek.com"]
    assert snap["updated_at"] is not None


def test_get_policy_endpoint(client, monkeypatch):
    monkeypatch.setattr("app._policy_snapshot", lambda: {
        "blocked_domains": ["chatgpt.com"],
        "leak_blocked_domains": ["notion.so"],
        "updated_at": "2026-11-02T02:00:00Z"
    })

    res = client.get("/policy")
    assert res.status_code == 200
    data = res.get_json()
    assert data["blocked_domains"] == ["chatgpt.com"]
    assert data["leak_blocked_domains"] == ["notion.so"]


def test_update_policy_leak_block(client, monkeypatch):
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    monkeypatch.setattr("app.get_db_connection", lambda: mock_conn)
    monkeypatch.setattr("app._policy_snapshot", lambda: {
        "blocked_domains": [],
        "leak_blocked_domains": ["notion.so"],
        "updated_at": "2026-11-02T02:00:00Z"
    })

    # policy_type='leak'
    res = client.post("/policy",
                      json={"domain": "notion.so", "policy_type": "leak"},
                      headers={"X-API-Key": API_KEY})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "leak_blocked"
    assert data["policy_type"] == "leak"
    assert data["domain"] == "notion.so"

    # INSERT/UPDATE 쿼리 인자에 'leak' 전달 확인
    exec_args = [c[0] for c in mock_cur.execute.call_args_list]
    upsert_call = [args for args in exec_args if len(args) > 1 and "INSERT INTO browser_block_policy" in args[0]]
    assert len(upsert_call) == 1
    assert upsert_call[0][1] == ("notion.so", "leak")


def test_update_policy_full_block(client, monkeypatch):
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    monkeypatch.setattr("app.get_db_connection", lambda: mock_conn)
    monkeypatch.setattr("app._policy_snapshot", lambda: {
        "blocked_domains": ["chatgpt.com"],
        "leak_blocked_domains": [],
        "updated_at": "2026-11-02T02:00:00Z"
    })

    res = client.post("/policy",
                      json={"domain": "chatgpt.com", "policy_type": "full"},
                      headers={"X-API-Key": API_KEY})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "blocked"
    assert data["policy_type"] == "full"

    exec_args = [c[0] for c in mock_cur.execute.call_args_list]
    upsert_call = [args for args in exec_args if len(args) > 1 and "INSERT INTO browser_block_policy" in args[0]]
    assert len(upsert_call) == 1
    assert upsert_call[0][1] == ("chatgpt.com", "full")


def test_update_policy_allow_deletes(client, monkeypatch):
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    monkeypatch.setattr("app.get_db_connection", lambda: mock_conn)
    monkeypatch.setattr("app._policy_snapshot", lambda: {
        "blocked_domains": [],
        "leak_blocked_domains": [],
        "updated_at": "2026-11-02T02:00:00Z"
    })

    res = client.post("/policy",
                      json={"domain": "chatgpt.com", "policy_type": "allow"},
                      headers={"X-API-Key": API_KEY})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "allowed"

    exec_args = [c[0] for c in mock_cur.execute.call_args_list]
    delete_call = [args for args in exec_args if len(args) > 1 and "DELETE FROM browser_block_policy" in args[0]]
    assert len(delete_call) == 1
    assert delete_call[0][1] == ("chatgpt.com",)


def test_update_policy_backward_compatible_boolean(client, monkeypatch):
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    monkeypatch.setattr("app.get_db_connection", lambda: mock_conn)
    monkeypatch.setattr("app._policy_snapshot", lambda: {
        "blocked_domains": ["old-agent.com"],
        "leak_blocked_domains": [],
        "updated_at": "2026-11-02T02:00:00Z"
    })

    # 구형 클라이언트: blocked=True 만 전송
    res = client.post("/policy",
                      json={"domain": "old-agent.com", "blocked": True},
                      headers={"X-API-Key": API_KEY})
    assert res.status_code == 200
    data = res.get_json()
    assert data["policy_type"] == "full"

    exec_args = [c[0] for c in mock_cur.execute.call_args_list]
    upsert_call = [args for args in exec_args if len(args) > 1 and "INSERT INTO browser_block_policy" in args[0]]
    assert len(upsert_call) == 1
    assert upsert_call[0][1] == ("old-agent.com", "full")


def test_update_policy_unauthorized_and_invalid_args(client):
    # 1. API 키 누락/오류
    res = client.post("/policy", json={"domain": "test.com", "policy_type": "leak"})
    assert res.status_code == 401

    # 2. 도메인 누락
    res = client.post("/policy", json={"policy_type": "leak"}, headers={"X-API-Key": API_KEY})
    assert res.status_code == 400

    # 3. 잘못된 정책 유형
    res = client.post("/policy", json={"domain": "test.com", "policy_type": "invalid"}, headers={"X-API-Key": API_KEY})
    assert res.status_code == 400
