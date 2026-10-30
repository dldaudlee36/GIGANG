"""이미지 붙여넣기 · 끌어다 놓기 감지 테스트 (Agent 중계 → 대시보드 변환 → 판정)

실행:  python test_image_paste.py
 - 확장(content.js)은 실제 크롬에서만 사용자 입력(isTrusted)으로 동작하므로 여기서는
   확장이 보내는 값을 Agent가 받아 넘기고, 대시보드가 판정하는 부분을 시험한다.
"""
import os
import sys
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'guard', 'agent'))
sys.path.insert(0, ROOT)

import agent
from gigang.collectors import team_collector
from gigang.engine.correlation import CorrelationEngine

fail = 0


def check(name, ok, detail=''):
    global fail
    if not ok:
        fail += 1
    print(f"{'OK  ' if ok else 'FAIL'} {name}" + ('' if ok else f'   {detail}'))


def relay(path, data):
    try:
        return agent.extension_event(path, data)
    except ValueError:
        return None


STAMP = '2026-10-05T10:00:00Z'

print('=== Agent 중계 (확장 → Agent) ===')
e = relay('/paste-event', {'target': 'chatgpt.com', 'text_length': 0, 'image_count': 1, 'image_bytes': 48213, 'timestamp': STAMP})
check('이미지만 붙여넣기', e and (e['text_length'], e['image_count'], e['image_bytes']) == (0, 1, 48213), e)
e = relay('/paste-event', {'target': 'chatgpt.com', 'text_length': 120, 'image_count': 2, 'image_bytes': 9000})
check('텍스트 + 이미지', e and (e['text_length'], e['image_count']) == (120, 2), e)
e = relay('/paste-event', {'target': 'chatgpt.com', 'text_length': 3420})
check('기존 텍스트 붙여넣기 그대로', e and e['text_length'] == 3420 and 'image_count' not in e, e)
check('글자도 이미지도 없음 → 거부', relay('/paste-event', {'target': 'chatgpt.com', 'text_length': 0}) is None)
check('이미지 장수 0 → 거부', relay('/paste-event', {'target': 'x.com', 'text_length': 0, 'image_count': 0, 'image_bytes': 0}) is None)
check('이미지 크기 빠짐 → 거부', relay('/paste-event', {'target': 'x.com', 'text_length': 0, 'image_count': 1}) is None)
check('음수 글자 수 → 거부', relay('/paste-event', {'target': 'x.com', 'text_length': -1, 'image_count': 1, 'image_bytes': 1}) is None)
e = relay('/upload-event', {'target': 'claude.ai', 'file_name': 'capture.png', 'file_size': 51200, 'method': 'drop'})
check('끌어다 놓기 첨부', e and (e['event_type'], e['method']) == ('FILE_UPLOAD_ATTEMPT', 'drop'), e)
e = relay('/upload-event', {'target': 'claude.ai', 'file_name': 'a.pdf', 'file_size': 10})
check('기존 파일 선택 첨부 그대로', e and 'method' not in e, e)
check('모르는 method → 거부', relay('/upload-event', {'target': 'claude.ai', 'file_name': 'a', 'file_size': 1, 'method': 'x'}) is None)

print('\n=== 대시보드 변환 (Railway → 엔진 이벤트) ===')
import json
rows = [
    {'id': 11, 'event_time': '2026-10-05T10:00:00', 'user_name': 'kim', 'event_type': 'PASTE_ATTEMPT',
     'source': 'chrome-extension', 'target': 'chatgpt.com',
     'raw_data': json.dumps({'text_length': 0, 'image_count': 1, 'image_bytes': 48213})},
    {'id': 12, 'event_time': '2026-10-05T10:01:00', 'user_name': 'kim', 'event_type': 'FILE_UPLOAD_ATTEMPT',
     'source': 'chrome-extension', 'target': 'claude.ai',
     'raw_data': json.dumps({'file_name': 'capture.png', 'file_size': 51200, 'method': 'drop'})},
]


class FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return [dict(r) for r in rows]


team_collector.requests.get = lambda *a, **k: FakeResponse()   # 실제 Railway 조회 대신 위 rows 를 돌려준다
team_collector.set_railway_collection_enabled(True)
team_collector.fetch_remote_db_logs = lambda *a, **k: []
team_collector.fetch_activity_log_events = lambda: []
events = {e.event_id: e for e in team_collector.get_team_security_events()}
paste, drop = events.get('EVT-RLY-11'), events.get('EVT-RLY-12')
check('이미지 붙여넣기 → PASTE_ATTEMPT', paste and paste.action.value == 'PASTE_ATTEMPT', paste)
check('이미지 장수·크기 전달', paste and (paste.payload.extra['image_count'], paste.payload.extra['image_bytes']) == (1, 48213),
      paste and paste.payload.extra)
check('끌어다 놓기 → FILE_UPLOAD_ATTEMPT', drop and drop.action.value == 'FILE_UPLOAD_ATTEMPT', drop)
check('method=drop 전달', drop and drop.payload.extra.get('method') == 'drop', drop and drop.payload.extra)

print('\n=== 판정 (COM-1: WATCH 상태에서 이미지 붙여넣기 → HIGH) ===')
engine = CorrelationEngine(enable_mock_incidents=False)
engine.store.clear_all()
paste.timestamp = datetime.utcnow()
paste.actor.user_id = 'img_normal'
engine.ingest_events([paste])
check('NORMAL 사용자 → 기록만', (engine.store.get_active_risk('img_normal') or {}).get('state', 'NORMAL') == 'NORMAL')

engine.store.upsert_risk('img_watch', 'WATCH', 68, ['테스트용 사전 감시 상태'], datetime.utcnow() + timedelta(minutes=30))
paste.event_id, paste.actor.user_id = 'EVT-RLY-11-W', 'img_watch'
engine.ingest_events([paste])
risk = engine.store.get_active_risk('img_watch') or {}
check('WATCH 사용자 → HIGH', risk.get('state') == 'HIGH', risk.get('state'))
reasons = ' / '.join(risk.get('reasons', []))
check('근거에 "이미지 붙여넣기" 표기', '이미지 붙여넣기' in reasons and '1장' in reasons, reasons)
check('근거에 "0자" 같은 혼란 표기 없음', '0자' not in reasons, reasons)
engine.store.clear_all()

print('\n전체 PASS' if fail == 0 else f'\n실패 {fail}건')
sys.exit(1 if fail else 0)
