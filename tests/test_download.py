"""기밀 DB 다운로드 감지(DB_DOWNLOAD) 테스트: DL-1 · DL-2 · DL-3

실행:  python test_download.py
 - Railway로 실제 전송하지 않는다. (send_to_railway 를 가짜로 바꿔 보낸 내용만 모은다)
 - 테스트 파일은 임시 폴더에 만들고 끝나면 지운다.
 - 로컬 gigang.db 의 위험 상태·이력을 지운다 (test_policy.py 와 같음).
"""
import copy
import json
import os
import shutil
import sys
import tempfile
import threading
import types
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'guard', 'agent'))
sys.path.insert(0, ROOT)

try:
    import requests  # noqa: F401
except ImportError:
    sys.modules['requests'] = types.SimpleNamespace(RequestException=Exception, post=None)

import agent
import files

DB = 'http://10.0.0.30:8080/vault'
agent.CONFIDENTIAL_URLS = [DB]
fail = 0


def check(name, ok, detail=''):
    global fail
    if not ok:
        fail += 1
    print(f"{'OK  ' if ok else 'FAIL'} {name}" + ('' if ok else f'   {detail}'))


def rrn(front, gender_and_serial):
    """검증번호까지 맞는 주민번호를 만든다 (테스트용)."""
    digits = front + gender_and_serial
    total = sum(int(d) * w for d, w in zip(digits, (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)))
    return f'{front}-{gender_and_serial}{(11 - total % 11) % 10}'


RRNS = [rrn('900101', '123456'), rrn('851231', '234567'), rrn('720615', '112233')]
CSV = '이름,주민번호,연락처\n' + '\n'.join(f'고객{i},{r},010-1234-56{i:02d}' for i, r in enumerate(RRNS))

tmp = tempfile.mkdtemp(prefix='gigang_dl_')


def make(name, data):
    path = os.path.join(tmp, name)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def make_xlsx(name, shared, rows):
    """엑셀이 저장하는 모양 그대로: 글자는 sharedStrings, 셀은 그 번호 (t="s")."""
    ns = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    sst = f'<sst xmlns="{ns}">' + ''.join(f'<si><t>{s}</t></si>' for s in shared) + '</sst>'
    body = ''.join('<row>' + ''.join(f'<c t="s"><v>{i}</v></c>' for i in row) + '</row>' for row in rows)
    path = os.path.join(tmp, name)
    with zipfile.ZipFile(path, 'w') as book:
        book.writestr('xl/sharedStrings.xml', sst)
        book.writestr('xl/worksheets/sheet1.xml', f'<worksheet xmlns="{ns}"><sheetData>{body}</sheetData></worksheet>')
    return path


try:
    print('=== Agent 파일 검사 (files.inspect_file) ===')
    r = files.inspect_file(make('customers.csv', CSV.encode('utf-8-sig')))
    check('CSV(UTF-8) → 검사, 주민번호 3·전화 3', r['inspectable'] and r['pattern_hits']['rrn'] == 3
          and r['pattern_hits']['phone'] == 3, r)
    r = files.inspect_file(make('엑셀저장.csv', CSV.encode('cp949')))
    check('CSV(CP949, 한국어 엑셀) → 검사, 주민번호 3', r['inspectable'] and r['pattern_hits']['rrn'] == 3, r)
    r = files.inspect_file(make('memo.txt', '담당자 kim.minsu@gmail.com 010-9876-5432'.encode()))
    check('TXT → 검사, 이메일 1·전화 1', r['inspectable'] and (r['pattern_hits']['email'], r['pattern_hits']['phone']) == (1, 1), r)
    shared = ['이름', '주민번호'] + [f'고객{i}' for i in range(3)] + RRNS
    xlsx = make_xlsx('고객명단.xlsx', shared, [[0, 1]] + [[2 + i, 5 + i] for i in range(3)])
    r = files.inspect_file(xlsx)
    check('XLSX → 검사, 주민번호 3', r['inspectable'] and r['file_kind'] == 'xlsx' and r['pattern_hits']['rrn'] == 3, r)
    check('결과에 파일 내용 없음', set(r) == {'file_kind', 'inspectable', 'text_length', 'pattern_hits'}, sorted(r))

    for name, data, reason in [
        ('report.pdf', b'%PDF-1.7 ...', '내용 검사 미지원 형식'),
        ('screen.png', b'\x89PNG\r\n', '내용 검사 미지원 형식'),
        ('dump.zip', b'PK\x03\x04', '내용 검사 미지원 형식'),
        ('locked.xlsx', b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 64, '암호 파일이거나 열 수 없는 형식'),
        ('binary.txt', b'abc\x00\x01\x02', '글자 파일이 아님'),
        ('noext', b'hello', '내용 검사 미지원 형식'),
    ]:
        r = files.inspect_file(make(name, data))
        check(f'{name:<12} → 검사 불가 ({reason})', not r['inspectable'] and r['reason'] == reason, r)
    saved = files.MAX_TEXT_BYTES
    files.MAX_TEXT_BYTES = 10
    r = files.inspect_file(os.path.join(tmp, 'customers.csv'))
    files.MAX_TEXT_BYTES = saved
    check('너무 큰 CSV → 검사 불가 (일부만 보고 0건이라 하지 않음)', not r['inspectable'] and '커서' in r['reason'], r)

    print('\n=== 확장 → Agent (/download-event) ===')
    sent = []
    agent.send_to_railway = lambda e: sent.append(e) or True
    server = ThreadingHTTPServer(('127.0.0.1', 0), agent.ExtensionEventHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    def post(path, body):
        request = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=json.dumps(body).encode(),
                                         headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, None

    csv_path = os.path.join(tmp, 'customers.csv')
    csv_size = os.path.getsize(csv_path)
    stamp = '2026-10-05T10:00:00.000Z'
    status, body = post('/download-event', {'url': f'{DB}/export', 'final_url': f'{DB}/export', 'referrer': f'{DB}/customers',
                                             'file_path': csv_path, 'timestamp': stamp})
    check('기밀 DB에서 받은 CSV → 1건 전송', status == 200 and body['status'] == 'saved' and len(sent) == 1, (status, body, len(sent)))
    if sent:
        e = sent[0]
        check('이벤트 내용', (e['event_type'], e['target'], e['file_name'], e['file_size'], e['inspectable'], e['pattern_hits']['rrn'])
              == ('DB_DOWNLOAD', DB, 'customers.csv', csv_size, True, 3), e)
        check('주소·저장 위치·파일 내용 미포함', not ({'url', 'final_url', 'referrer', 'file_path'} & set(e))
              and csv_path not in json.dumps(e, ensure_ascii=False), sorted(e))

    pdf = os.path.join(tmp, 'report.pdf')
    status, body = post('/download-event', {'url': 'https://storage.example.com/f/1', 'referrer': f'{DB}/reports', 'file_path': pdf})
    check('출발 페이지만 기밀 DB인 PDF → 검사 불가로 전송', status == 200 and len(sent) == 2 and sent[-1]['inspectable'] is False
          and sent[-1]['reason'] == '내용 검사 미지원 형식', sent[-1:])

    status, body = post('/download-event', {'url': 'https://www.naver.com/a.csv', 'referrer': 'https://www.naver.com/', 'file_path': csv_path})
    check('다른 사이트에서 받은 파일 → 보내지 않음', status == 200 and body['status'] == 'ignored' and len(sent) == 2, (body, len(sent)))
    status, _ = post('/download-event', {'url': f'{DB}/x', 'file_path': os.path.join(tmp, 'missing.csv')})
    check('파일 없음 → 400', status == 400 and len(sent) == 2)
    status, _ = post('/download-event', {'url': f'{DB}/x'})
    check('저장 위치 없음 → 400', status == 400)

    status, body = post('/upload-event', {'target': 'chatgpt.com', 'file_name': 'customers.csv', 'file_size': csv_size, 'timestamp': stamp})
    check('받은 파일을 AI에 올림 → 업로드에 기밀 DB 표시', status == 200 and sent[-1]['confidential_source'] == DB, sent[-1])
    post('/upload-event', {'target': 'chatgpt.com', 'file_name': 'customers.csv', 'file_size': csv_size + 1, 'timestamp': stamp})
    check('크기가 다르면 표시 안 함', 'confidential_source' not in sent[-1], sent[-1])
    server.shutdown()

    print('\n=== 대시보드 변환 (team_collector) ===')
    from gigang.collectors import team_collector
    raw_dl = {'event_type': 'DB_DOWNLOAD', 'file_name': 'report.pdf', 'file_size': 2048, 'file_kind': 'pdf',
              'inspectable': False, 'reason': '내용 검사 미지원 형식'}
    raw_up = {'event_type': 'FILE_UPLOAD_ATTEMPT', 'file_name': 'report.pdf', 'file_size': 2048, 'confidential_source': DB}
    rows = [
        {'id': 1, 'event_time': '2026-10-05T10:00:00', 'user_name': 'kim', 'event_type': 'DB_DOWNLOAD',
         'source': 'windows-agent', 'target': DB, 'raw_data': json.dumps(raw_dl, ensure_ascii=False)},
        {'id': 2, 'event_time': '2026-10-05T10:05:00', 'user_name': 'kim', 'event_type': 'FILE_UPLOAD_ATTEMPT',
         'source': 'chrome-extension', 'target': 'chatgpt.com', 'raw_data': json.dumps(raw_up)},
    ]
    team_collector.RAILWAY_URL = 'http://127.0.0.1:1/events'   # 실제 Railway 에 묻지 않게
    team_collector.set_railway_collection_enabled(True)
    team_collector.requests = types.SimpleNamespace(get=lambda *a, **k: types.SimpleNamespace(
        raise_for_status=lambda: None, json=lambda: copy.deepcopy(rows)), RequestException=Exception)
    team_collector.fetch_remote_db_logs = lambda: []
    team_collector.fetch_activity_log_events = lambda: []
    converted = {e.action.value: e for e in team_collector.get_team_security_events()}
    dl = converted.get('DB_DOWNLOAD')
    check('DB_DOWNLOAD → 다운로드 이벤트 (WEB_ACCESS 아님)', dl is not None and 'WEB_ACCESS' not in converted, list(converted))
    check('파일 이름·크기·검사 불가 전달', dl is not None and (dl.payload.file_name, dl.payload.file_size, dl.payload.extra['inspectable'],
          dl.payload.extra['reason']) == ('report.pdf', 2048, False, '내용 검사 미지원 형식'), dl and dl.payload)
    up = converted.get('FILE_UPLOAD_ATTEMPT')
    check('업로드의 기밀 DB 표시 전달', up is not None and up.payload.extra.get('confidential_source') == DB, up and up.payload.extra)
    team_collector.set_railway_collection_enabled(False)

    print('\n=== 규칙별 판정 (policy.judge) ===')
    from gigang.engine import policy as P
    POLICY = P.load_policy()
    POLICY['users'] = {'cs_kim': 'CS', 'hr_lee': 'HR'}
    T0 = datetime(2026, 10, 5, 10, 0)
    AI = [(T0, 'chatgpt.com')]

    def judge(user, extra, minutes=5):
        return P.judge('DB_DOWNLOAD', T0 + timedelta(minutes=minutes), user, extra, DB, AI, POLICY)

    def expect(name, result, level, rules):
        got = (result.level, result.rules) if result else None
        check(f'{name:<36} → {level} {",".join(rules)}', got == (level, rules), got)

    def csv_dl(hits):
        return {'file_name': 'a.csv', 'file_size': 900, 'file_kind': 'csv', 'inspectable': True, 'text_length': 300, 'pattern_hits': hits}

    expect('DL-1 고객지원 전화 3건 (평소 이하)', judge('cs_kim', csv_dl({'phone': 3})), 'RECORD', ['DL-CS-1'])
    expect('DL-1 고객지원 전화 11건 (평소 초과)', judge('cs_kim', csv_dl({'phone': 11})), 'WATCH', ['DL-CS-2'])
    expect('DL-1 고객지원 주민번호 1건', judge('cs_kim', csv_dl({'rrn_high': 1})), 'WATCH', ['DL-CS-3'])
    expect('DL-1 인사 주민번호 5건 (정상 업무)', judge('hr_lee', csv_dl({'rrn_high': 5})), 'RECORD', ['DL-HR-1'])
    expect('DL-1 부서 정보 없음', judge('unknown', csv_dl({})), 'WATCH', ['DL-COM-2'])
    expect('DL-1 패턴 0건', judge('cs_kim', csv_dl({})), 'RECORD', ['DL-ZERO'])
    pdf = {'file_name': 'r.pdf', 'file_size': 4096, 'file_kind': 'pdf', 'inspectable': False, 'reason': '내용 검사 미지원 형식'}
    expect('DL-2 PDF, 인사 (부서 무관)', judge('hr_lee', pdf), 'WATCH', ['DL-2'])
    expect('DL-2 inspectable 값이 없음 → 검사 불가로', judge('cs_kim', {'file_name': 'x'}), 'WATCH', ['DL-2'])
    r = judge('cs_kim', csv_dl({'phone': 11}))
    check('사유에 규칙 번호 DL-CS-2 와 파일 이름', r and r.reasons[0].startswith('[DL-CS-2]') and "'a.csv'" in ' '.join(r.reasons), r and r.reasons)
    check('DL-2 도 시간창 밖이면 판정 안 함 (AI 접속 16분 전)', judge('hr_lee', pdf, minutes=-16) is None)
    up = P.judge_upload('a.csv', 900, 'chatgpt.com', None, [{'name': 'a.csv', 'size': 900, 'source': DB, 'time': T0}])
    expect('DL-3 이름·크기 일치', up, 'HIGH', ['DL-3'])
    check('DL-3 크기 다름 → 아님', P.judge_upload('a.csv', 901, 'chatgpt.com', None,
                                                 [{'name': 'a.csv', 'size': 900, 'source': DB, 'time': T0}]) is None)
    expect('DL-3 Agent 표시만 있음', P.judge_upload('b.pdf', 1, 'claude.ai', DB, []), 'HIGH', ['DL-3'])

    print('\n=== 엔진 연결 (correlation.py) ===')
    from gigang.engine.correlation import CorrelationEngine
    from gigang.schemas.event import SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
    engine = CorrelationEngine(enable_mock_incidents=False)
    engine.policy = copy.deepcopy(POLICY)
    engine.store.clear_all()
    seq = iter(range(1, 1000))

    def event(user, minutes, action, source=LogSource.WINDOWS_AGENT, domain=DB, extra=None, name=None, size=None):
        return SecurityEvent(event_id=f'EVT-DL-{next(seq)}', timestamp=T0 + timedelta(minutes=minutes), log_source=source,
                             actor=Actor(user_id=user, src_ip='10.0.0.5'), target=Target(domain=domain, hostname='PC'),
                             action=action, payload=PayloadMetadata(extra=extra or {}, file_name=name, file_size=size))

    def download(user, minutes, extra):
        return event(user, minutes, EventAction.DB_DOWNLOAD, extra=extra, name=extra.get('file_name'), size=extra.get('file_size'))

    def upload(user, minutes, name, size, domain='chatgpt.com', extra=None):
        return event(user, minutes, EventAction.FILE_UPLOAD_ATTEMPT, LogSource.CHROME_EXTENSION, domain, extra, name, size)

    def ai(user, minutes, domain='chatgpt.com'):
        return event(user, minutes, EventAction.WEB_ACCESS, domain=domain)

    def state(user):
        r = engine.store.get_active_risk(user)
        return r['state'] if r else 'NORMAL'

    def reasons(user):
        r = engine.store.get_active_risk(user)
        return ' '.join(r['reasons']) if r else ''

    engine.ingest_events([download('cs_kim', 0, csv_dl({'card': 1}))])
    before = state('cs_kim')
    engine.ingest_events([ai('cs_kim', 10)])
    check('DL-1 다운로드 → 10분 뒤 AI: WATCH (DL-CS-3)', (before, state('cs_kim')) == ('NORMAL', 'WATCH') and 'DL-CS-3' in reasons('cs_kim'),
          (before, state('cs_kim'), reasons('cs_kim')))

    engine.ingest_events([ai('hr_lee', 0), download('hr_lee', 3, dict(pdf))])
    check('DL-2 인사 PDF 1회 → WATCH', state('hr_lee') == 'WATCH' and 'DL-2' in reasons('hr_lee'), (state('hr_lee'), reasons('hr_lee')))

    engine.ingest_events([download('u_far', 0, csv_dl({'phone': 1}) | {'file_name': '명단.csv', 'file_size': 1234})])
    check('AI 접속 없이 다운로드만 → NORMAL', state('u_far') == 'NORMAL', state('u_far'))
    n_inc = len(engine.incidents)
    engine.ingest_events([upload('u_far', 180, '명단.csv', 1234)])
    check('DL-3 3시간 뒤 같은 파일을 ChatGPT에 업로드 → NORMAL 에서 바로 HIGH', state('u_far') == 'HIGH' and 'DL-3' in reasons('u_far'),
          (state('u_far'), reasons('u_far')))
    check('DL-3 인시던트 생성', len(engine.incidents) == n_inc + 1
          and any('DL-3' in i.title for i in engine.incidents.values()), [i.title for i in engine.incidents.values()][-1:])

    engine.ingest_events([download('u_mail', 0, csv_dl({}) | {'file_name': 'm.csv', 'file_size': 50}),
                          upload('u_mail', 5, 'm.csv', 50, domain='mail.google.com')])
    check('같은 파일을 AI 아닌 곳(메일)에 업로드 → DL-3 아님', 'DL-3' not in reasons('u_mail'), (state('u_mail'), reasons('u_mail')))

    engine.ingest_events([download('u_other', 0, csv_dl({}) | {'file_name': 'x.csv', 'file_size': 10}),
                          upload('u_other', 5, 'y.csv', 10)])
    check('다른 파일 업로드 → DL-3 아님, 기밀 DB 연관 없으니 기록만 (10-06: 업로드 단독 WATCH 삭제)',
          state('u_other') == 'NORMAL' and 'DL-3' not in reasons('u_other'), (state('u_other'), reasons('u_other')))
    engine.ingest_events([upload('u_other', 7, 'y2.csv', 10)])
    check('기밀 DB 연관 없는 업로드 두 번 → HIGH 아님', state('u_other') == 'NORMAL', state('u_other'))

    engine.ingest_events([upload('u_tag', 0, 'z.pdf', 99, domain='claude.ai', extra={'confidential_source': DB})])
    check('DL-3 엔진이 다운로드를 못 봤어도 Agent 표시로 HIGH', state('u_tag') == 'HIGH', state('u_tag'))
    engine.store.clear_all()

    print('\n=== 거버넌스 ===')
    from gigang.engine.governance import ShadowAIGovernanceEngine
    gov = ShadowAIGovernanceEngine()
    gov.process_dns_event(download('kim', 0, dict(pdf)))
    check('기밀 DB 다운로드는 외부 서비스 자산으로 등록 안 됨', DB not in gov.assets, list(gov.assets)[:5])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print('\n전체 PASS' if fail == 0 else f'\n실패 {fail}건')
sys.exit(1 if fail else 0)
