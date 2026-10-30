"""기밀 DB 반출 판정(gigang/engine/policy.py) 규칙별 테스트 + 엔진 연결 테스트

실행:  python test_policy.py
 - 규칙 번호(COM·CS·HR·FIN·DEV·SS)마다 걸려야 하는 경우와 걸리면 안 되는 경우 (계획서 6장)
 - 평소 건수 등은 department_policy.json 의 임시값(평소 10건, FIN-4 3건, 시간창 전 15분·후 60분)을 쓴다.
 - 로컬 gigang.db 의 위험 상태·이력을 지운다 (test_paste.py 와 같음).
"""
import copy
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gigang.engine import policy as P
from gigang.engine.correlation import CorrelationEngine
from gigang.schemas.event import SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata

POLICY = P.load_policy()
POLICY['users'] = {'cs_kim': 'CS', 'hr_lee': 'HR', 'fin_park': 'FIN', 'dev_choi': 'DEV'}
T0 = datetime(2026, 10, 5, 10, 0)
AI = [(T0, 'chatgpt.com')]
fail = 0


def check(name, ok, detail=''):
    global fail
    if not ok:
        fail += 1
    print(f"{'OK  ' if ok else 'FAIL'} {name}" + ('' if ok else f'   {detail}'))


def judge(user, hits=None, kind='CLIPBOARD_COPY', minutes=5, extra=None):
    data = extra or {'pattern_hits': hits or {}, 'text_length': 300}
    return P.judge(kind, T0 + timedelta(minutes=minutes), user, data, 'db.local', AI, POLICY)


def expect(name, result, level, rules):
    got = (result.level, result.rules) if result else None
    check(f'{name:<34} → {level} {",".join(rules)}', got == (level, rules), got)


print('=== 규칙별 판정 (policy.judge) ===')
expect('COM-2 부서 정보 없는 사용자', judge('unknown', {}), 'WATCH', ['COM-2'])
expect('CS-1 고객지원 전화 3건', judge('cs_kim', {'phone': 3}), 'RECORD', ['CS-1'])
expect('CS-2 고객지원 전화 11건', judge('cs_kim', {'phone': 11}), 'WATCH', ['CS-2'])
expect('CS-3 고객지원 주민번호 1건', judge('cs_kim', {'rrn_high': 1}), 'WATCH', ['CS-3'])
expect('CS-3 고객지원 계좌 1건', judge('cs_kim', {'account': 1}), 'WATCH', ['CS-3'])
expect('HR-1 인사 주민번호 5건', judge('hr_lee', {'rrn_high': 3, 'rrn_mid': 2}), 'RECORD', ['HR-1'])
expect('HR-2 인사 주민번호 11건', judge('hr_lee', {'rrn_high': 11}), 'WATCH', ['HR-2'])
expect('HR-3 인사 카드 1건', judge('hr_lee', {'card': 1}), 'WATCH', ['HR-3'])
expect('FIN-1 재무 카드 2건', judge('fin_park', {'card': 2}), 'RECORD', ['FIN-1'])
expect('FIN-2 재무 계좌 11건', judge('fin_park', {'account': 11}), 'WATCH', ['FIN-2'])
expect('FIN-3 재무 주민번호(중간) 1건', judge('fin_park', {'rrn_mid': 1}), 'WATCH', ['FIN-3'])
expect('FIN-4 재무 전화2+이메일1 (합 3건)', judge('fin_park', {'phone': 2, 'email': 1}), 'WATCH', ['FIN-4'])
expect('FIN-4 미만 재무 전화 2건', judge('fin_park', {'phone': 2}), 'RECORD', ['FIN-4(미만)'])
expect('DEV-1 개발 이메일 1건', judge('dev_choi', {'email': 1}), 'WATCH', ['DEV-1'])
expect('섞임: 고객지원 전화3 + 카드1', judge('cs_kim', {'phone': 3, 'card': 1}), 'WATCH', ['CS-3'])
expect('주민번호 낮음 2건은 안 셈', judge('cs_kim', {'rrn_low': 2}), 'RECORD', ['ZERO'])
expect('주민번호 낮음 3건부터 셈', judge('cs_kim', {'rrn_low': 3}), 'WATCH', ['CS-3'])
expect('옛 형식 {rrn: 2}', judge('cs_kim', {'rrn': 2}), 'WATCH', ['CS-3'])
expect('ZERO 패턴 0건 (임시: 기록만)', judge('cs_kim', {}), 'RECORD', ['ZERO'])
expect('SS-1 인사 화면 캡처 (부서 무관)', judge('hr_lee', kind='SCREEN_CAPTURE',
       extra={'shortcut': 'Win+Shift+S', 'image_width': 800, 'image_height': 600}), 'WATCH', ['SS-1'])

print('\n=== 시간창 (AI 접속 전 15분 ~ 후 60분) ===')
check('AI 접속 10분 전 복사 → 판정', judge('dev_choi', {'email': 1}, minutes=-10) is not None)
check('AI 접속 16분 전 복사 → 아직 판정 안 함', judge('dev_choi', {'email': 1}, minutes=-16) is None)
check('AI 접속 55분 뒤 복사 → 판정', judge('dev_choi', {'email': 1}, minutes=55) is not None)
check('AI 접속 61분 뒤 복사 → 판정 안 함', judge('dev_choi', {'email': 1}, minutes=61) is None)
r = judge('unknown', {}, minutes=-10)
check('사유에 순서·규칙 번호 표기', r and '[COM-2]' in r.reasons[0] and 'AI 접속 10분 전' in ' '.join(r.reasons), r and r.reasons)
check('사유에 원문 없음 안내', r and any('수집하지 않음' in x for x in r.reasons), r and r.reasons)

print('\n=== 엔진 연결 (correlation.py) ===')
engine = CorrelationEngine(enable_mock_incidents=False)
engine.policy = copy.deepcopy(POLICY)
engine.store.clear_all()
seq = iter(range(1, 1000))


def event(user, minutes, action, source=LogSource.WINDOWS_AGENT, domain='db.local', extra=None):
    return SecurityEvent(event_id=f'EVT-POL-{next(seq)}', timestamp=T0 + timedelta(minutes=minutes), log_source=source,
                         actor=Actor(user_id=user, src_ip='10.0.0.5'), target=Target(domain=domain, hostname='PC'),
                         action=action, payload=PayloadMetadata(extra=extra or {}))


def ai(user, minutes, domain='chatgpt.com'):
    return event(user, minutes, EventAction.WEB_ACCESS, domain=domain)


def copy_ev(user, minutes, hits):
    return event(user, minutes, EventAction.CLIPBOARD_COPY, extra={'pattern_hits': hits, 'text_length': 200})


def state(user):
    r = engine.store.get_active_risk(user)
    return r['state'] if r else 'NORMAL'


def history(user):
    return [h for h in engine.store.get_risk_history(limit=500) if h['user'] == user]


engine.ingest_events([ai('dev_choi', 0), copy_ev('dev_choi', 5, {'email': 1})])
check('AI 켜두고 → 복사: WATCH', state('dev_choi') == 'WATCH', state('dev_choi'))
check('근거에 규칙 번호 DEV-1', 'DEV-1' in ' '.join(engine.store.get_active_risk('dev_choi')['reasons']))

engine.ingest_events([copy_ev('u_order', 0, {'card': 1})])
before = state('u_order')
engine.ingest_events([ai('u_order', 10)])
check('복사 → 10분 뒤 AI 켜기: 복사 땐 NORMAL, AI 접속 때 WATCH', (before, state('u_order')) == ('NORMAL', 'WATCH'),
      (before, state('u_order')))

engine.ingest_events([copy_ev('u_far', 0, {'card': 1}), ai('u_far', 20)])
check('복사 → 20분 뒤 AI: WATCH 아님', state('u_far') == 'NORMAL', state('u_far'))

engine.ingest_events([ai('hr_lee', 0), copy_ev('hr_lee', 3, {'rrn_high': 5})])
check('인사 주민번호 5건: 상태 그대로 (기록만)', state('hr_lee') == 'NORMAL', state('hr_lee'))
check('기록에 HR-1', any('HR-1' in (h['reason'] or '') for h in history('hr_lee')), history('hr_lee'))

engine.ingest_events([ai('cs_kim', 0), copy_ev('cs_kim', 2, {'card': 1})])
engine.ingest_events([event('cs_kim', 4, EventAction.PASTE_ATTEMPT, LogSource.CHROME_EXTENSION, 'chatgpt.com',
                            {'text_length': 0, 'image_count': 1, 'image_bytes': 2048})])
check('COM-1 흐름: CS-3 WATCH → 이미지 붙여넣기 → HIGH', state('cs_kim') == 'HIGH', state('cs_kim'))
engine.ingest_events([ai('cs_kim', 6), copy_ev('cs_kim', 7, {'card': 1})])
check('HIGH 인 사용자는 WATCH 로 내려가지 않음', state('cs_kim') == 'HIGH', state('cs_kim'))

engine.ingest_events([ai('u_more', 0), copy_ev('u_more', 2, {'card': 1}),
                      event('u_more', 3, EventAction.SCREEN_CAPTURE, extra={'shortcut': 'Win+Shift+S'})])
check('WATCH 중 캡처: 상태 그대로 + 이력에 SS-1 추가 근거',
      state('u_more') == 'WATCH' and any('[추가 근거]' in (h['reason'] or '') and 'SS-1' in h['reason']
                                         for h in history('u_more')), history('u_more'))

engine.policy['users'].update({'hr_com3': 'HR', 'hr_own': 'HR', 'hr_late': 'HR',
                               'cs_rep': 'CS', 'cs_gap': 'CS', 'fin_rep': 'FIN'})

# 소량 반복 복사: 평소 건수는 60분 누적으로 비교
engine.ingest_events([ai('cs_rep', 0), copy_ev('cs_rep', 1, {'phone': 4}), copy_ev('cs_rep', 3, {'phone': 4})])
check('누적: 전화 4건씩 2번(8건) → 기록만', state('cs_rep') == 'NORMAL', state('cs_rep'))
engine.ingest_events([copy_ev('cs_rep', 5, {'phone': 4})])
check('누적: 3번째(12건) → CS-2 WATCH', state('cs_rep') == 'WATCH', state('cs_rep'))
check('누적 근거 "이번 4 + 앞선 60분 8"', any('이번 4 + 앞선 60분 8' in (h['reason'] or '') for h in history('cs_rep')),
      history('cs_rep'))
engine.ingest_events([ai('cs_gap', 0), copy_ev('cs_gap', 1, {'phone': 8}), ai('cs_gap', 70), copy_ev('cs_gap', 75, {'phone': 8})])
check('누적: 74분 떨어진 두 복사(8+8)는 합치지 않음 → 기록만', state('cs_gap') == 'NORMAL', state('cs_gap'))
engine.ingest_events([ai('fin_rep', 0), copy_ev('fin_rep', 1, {'phone': 1}), copy_ev('fin_rep', 2, {'email': 1})])
check('FIN-4 누적: 전화1 + 이메일1 = 2건 → 기록만', state('fin_rep') == 'NORMAL', state('fin_rep'))
engine.ingest_events([copy_ev('fin_rep', 3, {'phone': 1})])
check('FIN-4 누적: 3건째 → WATCH', state('fin_rep') == 'WATCH', state('fin_rep'))

def paste_txt(user, minutes, length):
    return event(user, minutes, EventAction.PASTE_ATTEMPT, LogSource.CHROME_EXTENSION, 'chatgpt.com', {'text_length': length})

engine.ingest_events([ai('hr_com3', 0), copy_ev('hr_com3', 2, {'rrn_high': 5}), paste_txt('hr_com3', 4, 205)])
check('COM-3 HR-1 기록만 → 같은 길이 AI 붙여넣기 → HIGH', state('hr_com3') == 'HIGH', state('hr_com3'))
check('COM-3 근거에 HR-1 복사였다는 내용', any('COM-3' in (h['reason'] or '') and 'HR-1' in h['reason']
                                           for h in history('hr_com3')), history('hr_com3'))
engine.ingest_events([ai('hr_own', 0), copy_ev('hr_own', 2, {'rrn_high': 5}), paste_txt('hr_own', 4, 40)])
check('COM-3 아님: 길이가 다른 글(자기가 쓴 글) 붙여넣기 → 기록만', state('hr_own') == 'NORMAL', state('hr_own'))
engine.ingest_events([ai('hr_late', 0), copy_ev('hr_late', 2, {'rrn_high': 5}), paste_txt('hr_late', 70, 200)])
check('COM-3 아님: 복사 68분 뒤 붙여넣기 (60분 초과)', state('hr_late') == 'NORMAL', state('hr_late'))

engine.ingest_events([ai('u_ext', 0), copy_ev('u_ext', 2, {'card': 1}),
                      event('u_ext', 3, EventAction.HTTP_GET, LogSource.CHROME_EXTENSION, 'db.local')])
check('WATCH 중 확장의 일반 로그(파일 첨부 아님)는 HIGH 아님', state('u_ext') == 'WATCH', state('u_ext'))

engine.ingest_events([ai('u_mail', 0, 'mail.google.com'), copy_ev('u_mail', 2, {'card': 1})])
check('mail.google.com 은 AI 접속 아님', state('u_mail') == 'NORMAL', state('u_mail'))
engine.ingest_events([ai('u_db', 0, 'desktop-oli.tail2bbbea.ts.net'), copy_ev('u_db', 2, {'card': 1})])
check('기밀 DB 주소(tail2bbbea) 접속은 AI 접속 아님', state('u_db') == 'NORMAL', state('u_db'))

engine.ingest_events([event('u_cap', 0, EventAction.SCREEN_CAPTURE, extra={'shortcut': 'PrtSc'}), ai('u_cap', 5, 'claude.ai')])
check('캡처 → 5분 뒤 claude.ai: SS-1 WATCH', state('u_cap') == 'WATCH', state('u_cap'))
engine.store.clear_all()

print('\n=== Railway 정책 표 덮기 (GET /policies) ===')
local = P.load_policy()
remote = {'users': {'kim': 'CS'}, 'departments': {'CS': '고객지원'},
          'rows': [['CS', 'phone', True, 20, 'CS-1', 'CS-2']]}
merged = P.merge_remote(local, remote)
check('표의 사용자·행으로 바뀜', merged['users'] == {'kim': 'CS'} and merged['rows'] == remote['rows'], merged['rows'])
check('시간창 등 설정은 로컬 값 유지', merged['window_before_minutes'] == local['window_before_minutes'])
check('Railway 응답 없음 → 로컬 그대로', P.merge_remote(local, None)['rows'] == local['rows'])
bad = P.merge_remote(local, {'rows': [['CS', 'address', True, 1, 'X', 'Y']]})
check('모르는 데이터 종류가 섞인 표 → 로컬 그대로', bad['rows'] == local['rows'])
check('빈 표 → 로컬 그대로', P.merge_remote(local, {'rows': []})['rows'] == local['rows'])

import gigang.collectors.team_collector as tc
tc.fetch_railway_policy = lambda *a, **k: remote
fresh = CorrelationEngine(enable_mock_incidents=False)
fresh.refresh_policy()
check('엔진이 Railway 표로 판정 (kim=CS)', fresh.policy['users'].get('kim') == 'CS', fresh.policy['users'])
tc.fetch_railway_policy = lambda *a, **k: None
fresh._policy_checked_at = None
fresh.refresh_policy()
check('Railway 실패 → 로컬 파일로 계속', fresh.policy['rows'] == local['rows'])

print('\n=== AI·파일공유 도메인 판단 ===')
from gigang.engine.correlation import is_generative_ai, is_ai_or_file_sharing
for d in ('chatgpt.com', 'chat.openai.com', 'claude.ai', 'gemini.google.com', 'perplexity.ai', 'ai.google.dev'):
    check(f'AI: {d}', is_generative_ai(d))
for d in ('mail.google.com', 'desktop-oli.tail2bbbea.ts.net', 'www.naver.com', 'dropbox.com', 'xbox.com'):
    check(f'AI 아님: {d}', not is_generative_ai(d))
check('파일공유: www.dropbox.com', is_ai_or_file_sharing('www.dropbox.com'))
check('파일공유 아님: xbox.com', not is_ai_or_file_sharing('xbox.com'))

print('\n=== 거버넌스 (섀도우 AI 자산 목록) ===')
from gigang.engine.governance import ShadowAIGovernanceEngine
gov = ShadowAIGovernanceEngine()
gov.process_dns_event(copy_ev('kim', 0, {'card': 1}))
check('기밀 DB 복사는 외부 서비스 자산으로 등록 안 됨', 'db.local' not in gov.assets, list(gov.assets)[:5])

print('\n=== 상관분석 점수 (policy.score_judgment) ===')
s85 = judge('cs_kim', {'rrn_high': 3}, minutes=2)
check('CS-3 주민 3건 AI 2분 뒤 = 60+12+5+6 = 83', s85.score == 83, s85.score)
check('건수는 종류 합이 아니라 가장 많은 종류 (전화5+이메일5 → 5건)',
      '5건 5' in judge('cs_kim', {'phone': 5, 'email': 5}, minutes=30).reasons[-1])
check('WATCH 하한 60', judge('cs_kim', {'phone': 11}, minutes=30).score >= 60)
check('점수 근거 줄이 붙음', s85.reasons[-1].startswith('상관분석 점수:'), s85.reasons[-1])
check('평소 이하(기록만)는 59 이하', judge('cs_kim', {'phone': 3}, minutes=30).score <= 59)
check('WATCH 는 상한 89', judge('cs_kim', kind='DB_DOWNLOAD', minutes=2,
                                extra={'inspectable': True, 'pattern_hits': {'rrn_high': 50}}).score == 89)
check('같은 부서 규칙이면 주민번호가 전화보다 높음',
      judge('dev_choi', {'rrn_high': 1}).score > judge('dev_choi', {'phone': 1}).score)
check('DL-3 = 95', P.judge_upload('a.csv', 1, 'chatgpt.com', 'db', [], POLICY['score']).score == 95)

print('\n전체 PASS' if fail == 0 else f'\n실패 {fail}건')
sys.exit(1 if fail else 0)
