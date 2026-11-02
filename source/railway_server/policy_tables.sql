-- GIGANG 부서별 탐지 기준 테이블 2개 (GIGANG_수정계획.md 3·5장)
--
-- ⚠ 아직 Railway DB에 실행하지 않았다. 팀 확인 + 백업 후 Railway PostgreSQL 콘솔에서 한 번 실행한다.
--   기존 events 테이블은 건드리지 않는다. 두 번 실행해도 안전하다 (IF NOT EXISTS / ON CONFLICT).
--
-- 값을 바꿀 때는 코드 수정·재배포 없이 이 표만 고치면 된다.
-- 대시보드는 GET /policies 로 읽어 가고, 못 읽으면 gigang/engine/department_policy.json 을 쓴다.

-- 1) 사용자 → 부서. 여기에 없는 사용자는 COM-2(기존 규칙대로 판정).
--    user_name 은 Agent 가 보내는 Windows 사용자 이름 (events.user_name 과 같은 값).
CREATE TABLE IF NOT EXISTS user_department (
    user_name  TEXT PRIMARY KEY,
    dept_code  TEXT NOT NULL            -- CS / HR / FIN / DEV
);

-- 2) 부서별 정책. 한 행 = 부서 × 데이터 종류.
--    allowed = true  (○, 평소 업무 데이터): threshold = 평소 건수. 이하면 record_rule(기록만), 초과면 watch_rule(WATCH)
--    allowed = false (×, 이상 신호)        : threshold = 이 건수 이상이면 watch_rule(WATCH). 같은 watch_rule 끼리 건수를 합친다.
CREATE TABLE IF NOT EXISTS department_policy (
    dept_code    TEXT    NOT NULL,
    dept_name    TEXT    NOT NULL,
    data_type    TEXT    NOT NULL CHECK (data_type IN ('phone', 'email', 'rrn', 'account', 'card')),
    allowed      BOOLEAN NOT NULL,
    threshold    INTEGER NOT NULL CHECK (threshold >= 1),
    record_rule  TEXT,
    watch_rule   TEXT    NOT NULL,
    PRIMARY KEY (dept_code, data_type)
);

-- 초기값: 계획서 3장 표. 평소 건수 10, FIN-4 '여러 건' 3 은 임시값 (계획서 7장 '아직 정할 값').
INSERT INTO department_policy (dept_code, dept_name, data_type, allowed, threshold, record_rule, watch_rule) VALUES
    ('CS',  '고객지원',  'phone',   TRUE,  10, 'CS-1',  'CS-2'),
    ('CS',  '고객지원',  'email',   TRUE,  10, 'CS-1',  'CS-2'),
    ('CS',  '고객지원',  'rrn',     FALSE, 1,  NULL,    'CS-3'),
    ('CS',  '고객지원',  'account', FALSE, 1,  NULL,    'CS-3'),
    ('CS',  '고객지원',  'card',    FALSE, 1,  NULL,    'CS-3'),
    ('HR',  '인사',      'phone',   TRUE,  10, 'HR-1',  'HR-2'),
    ('HR',  '인사',      'email',   TRUE,  10, 'HR-1',  'HR-2'),
    ('HR',  '인사',      'rrn',     TRUE,  10, 'HR-1',  'HR-2'),
    ('HR',  '인사',      'account', TRUE,  10, 'HR-1',  'HR-2'),
    ('HR',  '인사',      'card',    FALSE, 1,  NULL,    'HR-3'),
    ('FIN', '재무·정산', 'account', TRUE,  10, 'FIN-1', 'FIN-2'),
    ('FIN', '재무·정산', 'card',    TRUE,  10, 'FIN-1', 'FIN-2'),
    ('FIN', '재무·정산', 'rrn',     FALSE, 1,  NULL,    'FIN-3'),
    ('FIN', '재무·정산', 'phone',   FALSE, 3,  NULL,    'FIN-4'),
    ('FIN', '재무·정산', 'email',   FALSE, 3,  NULL,    'FIN-4'),
    ('DEV', '개발',      'phone',   FALSE, 1,  NULL,    'DEV-1'),
    ('DEV', '개발',      'email',   FALSE, 1,  NULL,    'DEV-1'),
    ('DEV', '개발',      'rrn',     FALSE, 1,  NULL,    'DEV-1'),
    ('DEV', '개발',      'account', FALSE, 1,  NULL,    'DEV-1'),
    ('DEV', '개발',      'card',    FALSE, 1,  NULL,    'DEV-1')
ON CONFLICT (dept_code, data_type) DO NOTHING;

-- 사용자 부서 등록 예시 (팀원 Windows 사용자 이름으로 바꿔서 실행)
-- INSERT INTO user_department (user_name, dept_code) VALUES ('kim', 'CS') ON CONFLICT (user_name) DO UPDATE SET dept_code = EXCLUDED.dept_code;

-- 3) 중앙 브라우저 차단 정책 (전면 차단 · 유출 차단)
CREATE TABLE IF NOT EXISTS browser_block_policy (
    domain       TEXT PRIMARY KEY,
    policy_type  VARCHAR(32) NOT NULL DEFAULT 'full',  -- 'full': 전면 차단, 'leak': 유출 차단
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 기존 테이블이 존재할 경우 컬럼 추가 마이그레이션
ALTER TABLE browser_block_policy ADD COLUMN IF NOT EXISTS policy_type VARCHAR(32) NOT NULL DEFAULT 'full';

