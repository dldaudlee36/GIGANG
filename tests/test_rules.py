"""Agent 규칙 검사(guard/agent/rules.py) 오탐·미탐 테스트

실행:  python test_rules.py
 - 걸리면 안 되는 경우(헷갈리는 데이터)가 걸리면 오탐
 - 걸려야 하는 경우가 안 걸리면 미탐
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'guard', 'agent'))

from rules import scan_text

KEYS = ('phone', 'email', 'rrn', 'rrn_high', 'rrn_mid', 'rrn_low', 'account', 'card')
fail = 0
total = 0


def run(name, text, **want):
    """want 에 적지 않은 항목은 0 이어야 한다."""
    global fail, total
    total += 1
    got = scan_text(text)
    expected = {k: want.get(k, 0) for k in KEYS}
    ok = got == expected
    if not ok:
        fail += 1
    shown = ' '.join(f'{k}={got[k]}' for k in KEYS if got[k])
    print(f"{'OK  ' if ok else 'FAIL'} {name:<28} {shown or '-'}")
    if not ok:
        diff = {k: (got[k], expected[k]) for k in KEYS if got[k] != expected[k]}
        print(f"     (실제, 기대): {diff}")


print('=== 걸리면 안 되는 경우 (오탐) ===')
run('일반 한글 기획문서', '이번 분기 전환율이 3.4% 상승했고 목표 KPI는 12만 세션입니다. 검색 42%, SNS 31%.')
run('파이썬 코드', 'def calc(events, weights=None):\n    weights = {"db": 2, "dns": 2, "upload": 4}\n    return min(sum(weights.values()), 100)')
run('에러 로그(타임스탬프)', '[2026-09-09T10:12:33.412Z] ERROR request_id=1757404800000 latency=1284ms\n'
    'upstream=10.0.0.30:3306 request_id=1757404812345 status=502 bytes=284719')
run('SQL / 주문번호 / 송장번호', "INSERT INTO orders VALUES (1002938477, '2026090912345678', 48900.00, NOW());\n"
    '운송장번호 1234567890123 주문번호 2026 0909 1234 5678')
run('대표번호 / 운영시간', '고객센터 1588-1234 / 1666-9876 운영시간 09:00-18:00 연중무휴')
run('우편번호 / 내선번호', '우편번호 06236, 담당 내선 4512, 회의실 302호')
run('UUID / 해시', 'id=550e8400-e29b-41d4-a716-446655440000\nsha=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
run('사업자번호', '사업자등록번호 123-45-67890 / 214-86-12345')
run('회사 공용 메일', '문의는 help@gigang.co.kr 또는 noreply@gigang.co.kr, support+kr@gigang.co.kr')
run('이미지 파일 이름', 'logo@2x.png, icon@3x.webp')
run('테스트 카드번호', '4111 1111 1111 1111 / 4242-4242-4242-4242 / 5555555555554444')
run('16자리 일련번호', 'S/N 1234-5678-9012-3456, 시리얼 1111222233334444')
run('송장번호 (계좌 단어 없음)', '송장번호 123456789012 / 관리번호 98765432101')
run('주민번호 마스킹 1건', '본인 확인 900101-1****** 완료')
run('표 복사 1줄 (6자리 탭 7자리)', '홍길동\t900101\t1234568')
run('없는 날짜 13자리', '주문 9013451234567, 9902301234567')

print('\n=== 걸려야 하는 경우 (미탐) ===')
# 3. 주민번호
run('주민번호 하이픈 2건', '홍길동 900101-1234568 / 김철수 851231-2345673', rrn=2, rrn_high=2)
run('2020.10 이후 발급(검증번호 X)', '홍길동 900101-1234567', rrn=1, rrn_mid=1)
run('하이픈 없는 13자리', '고객식별 9001011234568 등록완료', rrn=1, rrn_high=1)
run('하이픈 없음 + 검증번호 X', '고객식별 9001011234567', rrn=1, rrn_low=1)
run('구분자 변형 (공백·점·대시)', '900101 1234568 / 851231.2345673 / 020315–3123455 / 880315－2345670',
    rrn=4, rrn_high=4)
run('한글에 바로 붙음', '주민번호9001011234568이고', rrn=1, rrn_high=1)
run('외국인등록번호', '외국인 900101-5234569', rrn=1, rrn_high=1)
run('표 복사 2줄 (탭)', '홍길동\t900101\t1234568\n김철수\t851231\t2345673', rrn=2, rrn_high=2)
run('뒷자리 마스킹 2건', '900101-1****** / 851231-2******', rrn=2, rrn_low=2)
run('같은 번호 반복은 1건', '900101-1234568 ... 9001011234568', rrn=1, rrn_high=1)
# 5. 카드번호
run('카드번호 (Visa·MC·Amex)', '4532-1234-5678-9014 / 5366 4812 3456 7898 / 374212345678907', card=3)
run('국내 전용 카드', 'BC 9410-1234-5678-9010', card=1)
# 1. 전화번호
run('휴대폰 2건', '연락처 010-1234-5678 / 01098765432', phone=2)
run('지역번호·인터넷전화', '02-123-4567, (031)123-4567, 070-1234-5678', phone=3)
run('같은 번호 반복은 1건', '010-1234-5678 / 010-1234-5678', phone=1)
# 2. 이메일
run('개인 이메일 (대소문자 중복)', 'hong@corp.co.kr, kim@corp.co.kr, Hong@corp.co.kr', email=2)
# 4. 계좌번호
run('계좌번호 은행 형식', '123-456-789012 / 1002-123-456789 / 3333-01-1234567', account=3)
run('계좌 단어 + 하이픈 없음', '국민은행 계좌 123456789012', account=1)

print('\n=== 섞인 경우 ===')
run('고객명단 유출 시나리오',
    '홍길동 900101-1234568 010-1234-5678 hong@corp.co.kr 4532-1234-5678-9014 국민 123456-01-234567\n'
    '김영희 880315-2345670 010-9876-5432 kim@corp.co.kr',
    rrn=2, rrn_high=2, phone=2, email=2, card=1, account=1)
run('빈 값 / 문자열 아님', None)

print(f'\n전체 PASS ({total}/{total})' if fail == 0 else f'\n실패 {fail}건 / {total}건')
sys.exit(1 if fail else 0)
