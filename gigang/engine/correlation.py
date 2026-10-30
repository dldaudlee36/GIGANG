"""GIGANG 상관분석 엔진.
사전 감시는 부서 정책을 사용하고, 외부 입력/첨부/전송은 policy.score_outbound로 평가한다.
HIGH는 강한 자료 연결과 점수 기준을 모두 만족해야 한다. 시도/차단은 전송 완료가 아니다.
과거 WATCH 이력만으로 승격하지 않으며, 같은 등급의 점수·근거도 저장한다.
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import json

from gigang.schemas.event import SecurityEvent, LogSource, EventAction
from gigang.schemas.incident import (
    Incident, Severity, IncidentCategory, IncidentStatus, NetworkHop, RiskState
)
from gigang.engine.respond import on_risk_state_changed
from gigang.engine import policy as dept_policy
from gigang.storage.sqlite_store import SQLiteStore
from gigang.engine.slack_notify import notify_high

# 상태별 만료 주기 (TTL)
# 이 시간이 지나면 해당 상태는 조회에서 제외되어 자동으로 NORMAL로 취급된다.
# WATCH를 30분으로 잡은 이유: 단순 질문만 하고 나간 사람을 계속 감시하면
# 관제사에게 쓸모없는 알람만 쌓이기 때문(Alert Fatigue).
TTL = {
    "NORMAL": timedelta(minutes=0),
    "WATCH": timedelta(minutes=30),       # 30분 경과 시 오탐 자동 해제 (NORMAL 복귀)
    "HIGH": timedelta(hours=24),          # 24시간 유지

}

# 기밀 테이블 목록 — 이 테이블을 조회하면 WATCH 승격 조건 A가 성립한다.
# ※ 지금은 코드에 고정되어 있다. 실제 운영에서는 설정 파일이나 DB로 빼는 것이 좋다.
SENSITIVE_TABLES = {"customer_info", "customer_vault", "corp_strategic_plan", "salary_2026", "secret_key"}

# 미승인 외부 AI/파일공유 도메인 목록 — 여기 접속하면 WATCH 승격 조건 B가 성립한다.
# ※ 아래 update_user_risk() 에서는 이 목록에 없어도 도메인 이름에 'ai', 'gpt' 등이
#   들어 있으면 같은 취급을 한다(신규 AI 사이트가 계속 생기기 때문).
KNOWN_AI_DOMAINS = {"chatgpt.com", "api.openai.com", "claude.ai", "wetransfer.com", "dropbox.com"}

# [수정됨] AI·파일공유 판단 기준.
# 예전에는 도메인에 'ai', 'box', 'drive' 글자가 들어 있기만 하면 AI/클라우드로 봤다.
# 그러면 mail.google.com, 기밀 DB 주소(tail2bbbea.ts.net), xbox.com 같은 일반 도메인까지 걸려
# '기밀 DB + AI 접속' 조건이 엉뚱하게 성립했다. 이제 이름 단위로 본다.
GENERATIVE_AI_KEYWORDS = ("chatgpt", "openai", "claude", "gemini", "copilot", "perplexity", "gpt")
FILE_SHARING_DOMAINS = ("wetransfer.com", "dropbox.com", "box.com", "drive.google.com", "onedrive.live.com", "1drv.ms", "mega.nz")


def _same_or_sub(domain: str, base: str) -> bool:
    return domain == base or domain.endswith("." + base)


def is_generative_ai(domain: str) -> bool:
    """생성형 AI 도메인인가. 목록(하위 도메인 포함) / AI 서비스 이름 / .ai 도메인 / 'ai' 이름 칸(ai.google.dev).
    KNOWN_AI_DOMAINS 의 파일공유(dropbox 등)는 여기서 뺀다."""
    domain = (domain or "").lower().strip(".")
    labels = domain.split(".")
    known_ai = [d for d in KNOWN_AI_DOMAINS if not any(_same_or_sub(d, s) for s in FILE_SHARING_DOMAINS)]
    return (any(_same_or_sub(domain, known) for known in known_ai)
            or any(k in domain for k in GENERATIVE_AI_KEYWORDS)
            or (len(labels) > 1 and "ai" in labels))


def is_ai_or_file_sharing(domain: str) -> bool:
    """미승인 AI 또는 파일공유 서비스인가. (파일 업로드·외부 전송 판정용)"""
    domain = (domain or "").lower().strip(".")
    return is_generative_ai(domain) or any(_same_or_sub(domain, s) for s in FILE_SHARING_DOMAINS)

# DB 로그인 계정 <-> 사원/단말 마스터 계정(Windows Agent User) 매핑 테이블
# DB 감사 로그의 원본 user_name(sales_user, report_user)을 보존하면서
# 윈도우 단말(User)과 동일 인물로 묶어 다단계 상관분석을 수행하기 위한 식별자 매핑
DB_USER_IDENTITY_MAPPING: Dict[str, str] = {
    "sales_user": "User",
    "report_user": "User",
    "test_user": "User",
    "kim_marketing": "User",
}



class CorrelationEngine:
    """
    2단계 위험 상태 기계 기반 이기종 보안 이벤트 상관분석 코어 엔진

    '상관분석(Correlation)'이란 로그 하나만 보지 않고
    여러 로그를 시간 축으로 엮어서 의미를 찾아내는 것을 말한다.

    예) "DB를 조회했다"  → 그 자체로는 정상 업무
        "ChatGPT에 접속했다" → 그 자체로도 정상 업무
        "DB 조회하고 5분 뒤 ChatGPT 접속" → 이건 유출 준비 정황
    """

    def __init__(self, time_window_minutes: int = 15, enable_mock_incidents: bool = False):
        """
        time_window_minutes: 두 행위를 '연관 있다'고 볼 시간 범위 (기본 15분)
                             DB 조회 후 15분 안에 AI 접속해야 WATCH로 올린다.
        enable_mock_incidents: 시연용 예시 인시던트를 미리 넣을지 여부 (기본 False: 실서버 수집 기반)
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.event_buffer: List[SecurityEvent] = []      # 지금까지 들어온 이벤트 보관함
        self.incidents: Dict[str, Incident] = {}         # 인시던트 ID → 인시던트 객체
        self.store = SQLiteStore()                       # 영속 저장소 (재시작해도 안 날아감)

        # 사용자별 최근 민감 행위 메모리 캐시 (DB 조회 기록 등)
        self.user_sensitive_db_touch: Dict[str, datetime] = {}
        self.user_visited_unapproved_ai: Dict[str, Dict[str, Any]] = {}

        # [추가됨] 기밀 DB 반출 판정용 (policy.py)
        #   AI 접속 기록과, 아직 짝이 될 AI 접속이 없어 판정을 미룬 복사·캡처
        self.policy = dept_policy.load_policy()
        self.user_ai_accesses: Dict[str, List[tuple]] = {}
        self.pending_db_exports: Dict[str, List[SecurityEvent]] = {}
        #   기밀 DB에서 받은 파일 (DL-3: 이 파일을 AI에 올리면 HIGH)
        self.user_db_downloads: Dict[str, List[Dict[str, Any]]] = {}
        #   기밀 DB 복사 (COM-3: 기록만 이어도 같은 글 AI 붙여넣기 시 HIGH)
        self.user_db_copies: Dict[str, List[Dict[str, Any]]] = {}
        #   기밀 DB 복사·다운로드 건수 (평소 건수 usual_count_minutes 창 누적용)
        self.user_db_counts: Dict[str, List[Dict[str, Any]]] = {}
        #   DB 감사 로그 조회 후 AI 접속 상황을 이미 남긴 조회 시각 (같은 조회로 중복 기록 안 되게)
        self._db_touch_noted: Dict[str, datetime] = {}

        # 이미 판정을 끝낸 event_id 모음
        self._processed_event_ids: set = set()

        # 인시던트 ID 발급용 접두사별 일련번호
        self._incident_seq: Dict[str, int] = {}

        if enable_mock_incidents:
            self._init_mock_incidents()

        # SQLite에서 기존 저장된 인시던트 로드
        persisted = self.store.get_all_incidents()
        for inc in persisted:
            self.incidents[inc.incident_id] = inc

        # 껐다 켠 뒤에도 번호가 겹치지 않도록, 이미 있는 인시던트의 최대 번호에서 이어 센다.
        self._seed_incident_seq()

    def _seed_incident_seq(self) -> None:
        """
        이미 존재하는 인시던트 ID에서 접두사별 최대 일련번호를 읽어 카운터를 맞춘다.
        """
        for inc_id in self.incidents.keys():
            prefix, _, suffix = inc_id.rpartition("-")
            if not prefix or not suffix.isdigit():
                continue
            num = int(suffix)
            if num > self._incident_seq.get(prefix, 0):
                self._incident_seq[prefix] = num

    def _next_incident_id(self, prefix: str) -> str:
        """
        접두사별로 겹치지 않는 인시던트 ID를 발급한다.
        """
        seq = self._incident_seq.get(prefix, 0)
        while True:
            seq += 1
            inc_id = f"{prefix}-{seq:03d}"
            if inc_id in self.incidents:
                continue
            try:
                if self.store.get_incident(inc_id) is not None:
                    continue
            except Exception:
                pass
            self._incident_seq[prefix] = seq
            return inc_id

    def _init_mock_incidents(self):
        """
        초기 목 인시던트 생성 방지:
        서버를 통해 수집된 실제 침해 로그 및 상관분석 시뮬레이터에 의해서만
        인시던트가 생성되도록 가짜 초기 데이터를 생성하지 않습니다.
        """
        pass

    def generate_incidents_from_railway(self, r_logs: List[Dict[str, Any]]) -> List[Incident]:
        """
        Railway 중앙 서버에서 수집된 실제 로그를 분석하여 보안 이벤트로 변환 및 상관분석을 수행합니다.
        """
        from gigang.collectors.team_collector import get_team_security_events
        self.refresh_policy()
        events = get_team_security_events()
        if events:
            self.ingest_events(sorted(events, key=lambda e: e.timestamp))
        return list(self.incidents.values())

    def ingest_events(self, events: List[SecurityEvent]):
        """
        이벤트 버퍼에 이벤트 추가 및 상태 기계 상관분석 수행

        여러 이벤트를 한꺼번에 엔진에 밀어 넣는 입구다.
        들어온 이벤트를 하나씩 update_user_risk()에 넘겨 판정시킨다.

        [수정됨] 예전에는 더미 로그만 이 입구로 들어왔으나,
          이제 storage/memory_store.py 에서 Railway 실제 수집 로그도 여기로 넘긴다.

        [수정됨] 같은 event_id 가 두 번 들어오면 두 번째는 건너뛴다.
          Railway 서버의 GET /events 는 매번 최신 100건을 그대로 돌려주고
          대시보드는 5초마다 폴링하므로, 막지 않으면 같은 이벤트가 계속 재투입되어
          상태가 무한히 재전이하고 risk_history 가 분당 수천 건씩 쌓인다.
        """
        # 처음 보는 이벤트만 추려낸다.
        new_events: List[SecurityEvent] = []
        for ev in events:
            if ev.event_id in self._processed_event_ids:
                continue                                  # 이미 처리한 이벤트 → 무시
            self._processed_event_ids.add(ev.event_id)
            new_events.append(ev)

        if not new_events:
            return                                        # 전부 중복이면 할 일이 없다

        self.event_buffer.extend(new_events)
        # 이벤트 timestamp 기준 정렬 (도착 역순 보정)
        # 네트워크 사정으로 나중에 발생한 로그가 먼저 도착할 수 있으므로
        # 실제 발생 시각 순으로 다시 줄을 세운다. 시간 순서가 틀리면 상관분석이 어긋난다.
        self.event_buffer.sort(key=lambda e: e.timestamp)

        # [수정됨] 예전에는 정렬되지 않은 원본 events 를 그대로 순회했다.
        #   버퍼만 정렬하고 판정은 도착 순서대로 하면
        #   "DB 조회 → AI 접속" 순서가 뒤집혀 WATCH 승격을 놓친다.
        #   그래서 판정도 timestamp 오름차순으로 돌린다.
        for ev in sorted(new_events, key=lambda e: e.timestamp):
            self.update_user_risk(ev)

    def update_user_risk(self, event: SecurityEvent) -> None:
        """입력 이벤트를 사전 감시 또는 공통 반출 평가기로 전달한다."""
        # 사용자를 무엇으로 식별할지 정한다. 계정명이 있으면 계정명, 없으면 IP를 쓴다.
        # DB 계정(sales_user, report_user 등)은 매핑 사전을 통해 윈도우 단말 마스터 계정(User)으로 정규화한다.
        raw_user = event.actor.user_id or event.actor.src_ip
        user = DB_USER_IDENTITY_MAPPING.get(raw_user, raw_user)
        if 'INC-EVT-' + event.event_id in getattr(self, 'incidents', {}):
            return  # 저장된 동일 이벤트를 재수신/재시작으로 다시 가산하지 않는다.
        now_utc = datetime.utcnow()

        # 1. 만료 시각(expires_at > now) 기준 현재 유효 상태 조회
        #    TTL이 지난 상태는 조회되지 않으므로, 결과가 없으면 NORMAL로 본다.
        #    ★ 여기서 '30분 지나면 자동으로 NORMAL로 돌아간다'는 자가 치유가 구현된다.
        current_risk = self.store.get_active_risk(user)
        old_state = current_risk["state"] if current_risk else "NORMAL"

        # 2. 행위 특징 분석 (DB, DNS/Web, Firewall)
        # 2.1 DB 조회 행위 포착  ─── WATCH 승격 조건 A
        #     기밀 테이블을 조회했다면, 그 '시각'만 메모리에 적어두고 여기서 끝낸다.
        #     조회 자체는 정상 업무일 수 있으므로 아직 상태를 올리지 않는다.
        #     나중에 AI 접속 이벤트가 들어왔을 때 이 기록과 짝을 맞춘다(2.3 참고).
        if getattr(event, "log_source", None) == LogSource.DB and event.action == EventAction.SELECT:
            tbl = event.payload.table_name or ""
            query = event.payload.query_string or ""
            # 테이블명이 기밀 목록에 있거나, 쿼리문에 민감 키워드가 섞여 있으면 기밀 조회로 본다
            if tbl in SENSITIVE_TABLES or any(k in query.lower() for k in ["customer", "secret", "vault", "plan"]):
                self.user_sensitive_db_touch[user] = event.timestamp
                return

        # 회사 사이트 캡처와 외부 입력은 각각 공통 평가기로 전달한다.
        if event.action == EventAction.DB_IMAGE_CAPTURE:
            if (event.target.domain == 'desktop-oli.tail2bbbea.ts.net'
                    and (event.payload.extra or {}).get('detection_scope') == 'db_image_content'):
                self._evaluate_portal(user, old_state, event)
            return

        image_guard = (event.payload.extra or {}).get('image_guard')
        if isinstance(image_guard, dict) and image_guard.get('outcome') in ('held_error', 'no_match'):
            return

        if event.action in (EventAction.PASTE_ATTEMPT, EventAction.FILE_UPLOAD_ATTEMPT) or (
                event.action in (EventAction.ALLOW, EventAction.HTTP_POST)
                and (event.payload.bytes_sent or 0) > 50000
                and event.log_source in (LogSource.FIREWALL, LogSource.WEB)):
            self._evaluate_outbound(user, old_state, event)
            return

        if event.action in (EventAction.COPY_ATTEMPT, EventAction.DOWNLOAD_STARTED):
            extra = event.payload.extra or {}
            expected_path = '/db' if event.action == EventAction.COPY_ATTEMPT else '/db/download'
            if (getattr(event, "log_source", None) != LogSource.CHROME_EXTENSION or
                event.target.domain != 'desktop-oli.tail2bbbea.ts.net' or
                extra.get('source_path') != expected_path):
                return
            if event.action == EventAction.COPY_ATTEMPT and extra.get('detection_scope') != 'customer_table':
                return
            self._evaluate_portal(user, old_state, event)
            return

        if event.action == EventAction.DOWNLOAD_COMPLETED:
            extra = event.payload.extra or {}
            if (event.target.domain == 'desktop-oli.tail2bbbea.ts.net'
                    and extra.get('source_path') == '/db/download' and event.payload.file_name):
                downloads = self.user_db_downloads.setdefault(user, [])
                downloads.append({"name": event.payload.file_name, "size": event.payload.file_size,
                                  "source": event.target.domain, "time": event.timestamp})
                del downloads[:-200]
            return  # 시작 시 이미 건수를 계산했으므로 완료 이벤트를 중복 합산하지 않는다.

        # 회사 사이트 전용 모드에서는 확장 로그와 중복되는 일반 에이전트 이벤트를 재채점하지 않는다.
        if self.policy.get('portal_only', True) and event.action in (
                EventAction.CLIPBOARD_COPY, EventAction.SCREEN_CAPTURE, EventAction.DB_DOWNLOAD):
            return

        # 2.1-c 기밀 DB 복사·화면 캡처·다운로드 (Agent)  [추가됨]
        #   AI 접속 시간창 안이면 부서 정책으로 판정, 아니면 AI 접속이 들어올 때까지 미뤄 둔다.
        #   다운로드는 시간창과 상관없이 파일 이름·크기를 기억해 둔다 (DL-3).
        if event.action in (EventAction.CLIPBOARD_COPY, EventAction.SCREEN_CAPTURE, EventAction.DB_DOWNLOAD):
            if event.action == EventAction.DB_DOWNLOAD and event.payload.file_name:
                downloads = self.user_db_downloads.setdefault(user, [])
                downloads.append({"name": event.payload.file_name, "size": event.payload.file_size,
                                  "source": event.target.domain or "unknown", "time": event.timestamp})
                del downloads[:-200]
            if event.action == EventAction.CLIPBOARD_COPY:
                try:
                    length = int((event.payload.extra or {}).get("text_length") or 0)
                except (ValueError, TypeError):
                    length = 0
                copies = self.user_db_copies.setdefault(user, [])
                copies.append({"id": event.event_id, "time": event.timestamp, "length": length,
                               "source": event.target.domain or "unknown", "rules": []})
                del copies[:-200]
            if event.action in (EventAction.CLIPBOARD_COPY, EventAction.DB_DOWNLOAD):
                counted = self.user_db_counts.setdefault(user, [])
                counted.append({"id": event.event_id, "time": event.timestamp,
                                "counts": dept_policy.effective_counts(
                                    (event.payload.extra or {}).get("pattern_hits") or {}, self.policy)})
                del counted[:-500]
            self._handle_db_export(user, event)
            return

        # 2.2 파일 업로드 시도 또는 외부 데이터 전송 발생 포착 (Chrome Extension / Firewall ALLOW / Web POST)
        target_domain = event.target.domain or ""

        # 2.2-a 생성형 AI 접속 기록 + 미뤄 둔 기밀 DB 복사·캡처 판정  [추가됨]
        #   "DB 복사 → AI 켜기" 순서는 복사 시점엔 짝이 없으므로 여기서 다시 본다.
        #   WATCH 가 됐으면 아래 기존 판정은 건너뛴다 (같은 이벤트로 두 번 전이하지 않게).
        if event.log_source in (LogSource.DNS, LogSource.WEB, LogSource.WINDOWS_AGENT) \
                and event.action not in (EventAction.FILE_UPLOAD_ATTEMPT,) and is_generative_ai(target_domain):
            self.user_ai_accesses.setdefault(user, []).append((event.timestamp, target_domain))
            if self._judge_pending_exports(user, event.timestamp):
                return

        # 이 도메인이 미승인 AI 또는 파일공유 서비스인가?
        # 등록된 목록에 있거나, 도메인 이름에 ai/gpt/claude 같은 단어가 들어 있으면 그렇다고 본다.
        # 새 AI 사이트가 매일 생기므로 목록만으로는 부족해서 이름 검사도 함께 한다.
        is_ai_or_cloud = is_ai_or_file_sharing(target_domain)

        file_name = event.payload.file_name or ""
        file_size = event.payload.file_size or event.payload.bytes_sent or 0
        bytes_out = event.payload.bytes_sent or file_size or 0

        # '파일을 첨부하려 했는가' 판정
        # 2.3 미승인 AI / 외부 SaaS 단순 접근 및 질의 포착 (전송 이전 선제 감시)
        # ★ GIGANG의 핵심 차별점이 구현된 부분이다.
        #   데이터가 나가기 '전에' 감시를 시작하는 곳.
        if (event.log_source in [LogSource.DNS, LogSource.WEB, LogSource.WINDOWS_AGENT]) and is_ai_or_cloud:
            # 이 사용자가 어느 AI 사이트에 언제 접속했는지 기록해둔다
            self.user_visited_unapproved_ai[user] = {
                "domain": target_domain,
                "time": event.timestamp
            }

            # 민감 DB 조회가 선행되었는지 확인 (self.time_window 이내)
            # 여기가 '조건 A + 조건 B를 모두 만족했는가'를 검사하는 지점이다.
            # 단순히 AI 사이트에 접속한 것만으로는 WATCH로 올리지 않는다.
            # 반드시 그 직전에 기밀 DB 조회가 있었어야 한다.
            #
            # [수정됨] 예전에는 여기에 timedelta(minutes=15) 가 박혀 있었다.
            #   __init__ 에서 만든 self.time_window 는 아무 데서도 쓰이지 않아서,
            #   CorrelationEngine(time_window_minutes=30) 처럼 인자를 바꿔도 효과가 없었다.
            #   이제 self.time_window 하나로 통일했다.
            db_touch_time = self.user_sensitive_db_touch.get(user)
            if db_touch_time and (event.timestamp - db_touch_time) <= self.time_window:
                # [정리 10-06] 전엔 여기서 WATCH(68)로 올렸다. 그러나
                #   ① 부서별로 본 'DB 조회 + AI 접속' 은 WATCH 일 수도 있고(HR-1 은 일상) WATCH 일 수도 있고
                #      자기가 쓴 글 붙여넣어도 HIGH 가 아니다 (부서 기준 무력화).
                #   ② AI 탭이 백그라운드에 켜져 있으면 로그가 또 와서 HIGH 가 도로 WATCH 로 내려간다 (등급 강등 버그).
                #   ③ DB 복사는 Agent 가 보낸 복사·캡처·다운로드 건(policy.py)이 부서별로 판정한다.
                #   여기서는 조회 1건이라는 정황만 이력에 남긴다.
                if self._db_touch_noted.get(user) != db_touch_time:
                    self._db_touch_noted[user] = db_touch_time
                    window_min = int(self.time_window.total_seconds() // 60)
                    self.store.append_history(user, old_state, old_state,
                                              f"[기록] 사내 기밀 DB SELECT 조회 후 {window_min}분 안에 AI({target_domain}) 접속 "
                                              "(DB 감사 로그) · 상태 판정은 기밀 DB 복사·캡처·다운로드 규칙으로")
                return

    # ------------------------------------------------------------------
    # 기밀 DB 복사·화면 캡처 판정  [추가됨]  (규칙은 policy.py 에 있다)
    # ------------------------------------------------------------------

    def refresh_policy(self) -> None:
        """
        Railway 정책 표를 5분마다 다시 읽는다. 못 읽으면 로컬 department_policy.json 그대로.
        표 값만 고치면 재배포 없이 반영된다. (계획서 5장 구현 원칙)
        """
        now = datetime.utcnow()
        if getattr(self, "_policy_checked_at", None) and now - self._policy_checked_at < timedelta(minutes=5):
            return
        self._policy_checked_at = now
        from gigang.collectors.team_collector import fetch_railway_policy
        self.policy = dept_policy.merge_remote(dept_policy.load_policy(), fetch_railway_policy())

    def _handle_db_export(self, user: str, event: SecurityEvent) -> None:
        """복사·캡처 하나를 판정한다. 짝이 될 AI 접속이 아직 없으면 미뤄 둔다."""
        if self._apply_db_export(user, event, self.user_ai_accesses.get(user, [])) is None:
            self.pending_db_exports.setdefault(user, []).append(event)

    def _judge_pending_exports(self, user: str, ai_time: datetime) -> bool:
        """
        AI 접속이 들어왔을 때, 그 전에 미뤄 둔 복사·캡처를 다시 판정한다.
        이 AI 접속보다 '전 N분'보다 오래된 것은 앞으로도 짝이 생기지 않으므로 버린다.
        WATCH 전이가 하나라도 있었으면 True.
        """
        pending = self.pending_db_exports.get(user)
        if not pending:
            return False
        oldest = ai_time - timedelta(minutes=self.policy["window_before_minutes"])
        watched, left = False, []
        for ev in pending:
            if ev.timestamp < oldest:
                continue
            level = self._apply_db_export(user, ev, self.user_ai_accesses.get(user, []))
            if level is None:
                left.append(ev)
            elif level == "WATCH":
                watched = True
        self.pending_db_exports[user] = left
        return watched

    def _record_assessment(self, user, event, result, stage):
        """사건에는 개별 점수를 저장하고, 사용자 요약에는 유효한 높은 점수를 유지한다."""
        severity = {"HIGH": Severity.HIGH, "WATCH": Severity.MEDIUM, "RECORD": Severity.LOW}[result.level]
        extra = event.payload.extra or {}
        link = extra.get('match') if isinstance(extra.get('match'), dict) else {}
        evidence = list(result.reasons)
        if link.get('source_trace_id'):
            evidence.append('연결된 회사 자료 추적 ID: ' + str(link['source_trace_id']))
        title = ('외부 입력·첨부 평가' if stage == 'outbound' else '회사 자료 취득 평가')
        inc = Incident(
            incident_id='INC-EVT-' + event.event_id,
            title=f'{title} · {event.action.value} · {user}',
            category=IncidentCategory.INSIDER_DATA_THEFT,
            severity=severity, score=result.score,
            status=IncidentStatus.RESOLVED if result.level == "RECORD" else IncidentStatus.ACTIVE,
            summary=f'{event.action.value} 사건 평가: {result.level} {result.score}점. '
                    + ('입력·첨부 시도는 전송 완료를 의미하지 않습니다.' if stage == 'outbound'
                       else '회사 사이트에서 자료를 가져온 단계이며 외부 전송을 의미하지 않습니다.'),
            actor=user, target_asset=event.target.domain or 'unknown', created_at=event.timestamp,
            event_ids=[event.event_id], evidences=evidence, network_hops=[], soar_actions=[])
        self.incidents[inc.incident_id] = inc
        self.store.save_incident(inc)
        if getattr(self.store, "db_path", None):
            notify_high(inc, self.store.db_path)
        return inc

    def _apply_db_export(self, user: str, event: SecurityEvent, ai_accesses: List[tuple]) -> Optional[str]:
        """policy.judge() 결과를 상태에 반영하고 등급("WATCH"/"RECORD")을 돌려준다. 시간창 밖이면 None."""
        since = event.timestamp - timedelta(minutes=self.policy["usual_count_minutes"])
        prior: Dict[str, int] = {}
        for item in self.user_db_counts.get(user, []):
            if item["id"] != event.event_id and since <= item["time"] <= event.timestamp:
                for key, n in item["counts"].items():
                    prior[key] = prior.get(key, 0) + n
        result = dept_policy.judge(
            event.action.value, event.timestamp, user, event.payload.extra or {},
            event.target.domain or "unknown", ai_accesses, self.policy, prior,
        )
        if result is None:
            return None
        for copy in self.user_db_copies.get(user, []):
            if copy["id"] == event.event_id:
                copy["rules"] = result.rules        # COM-3 근거에 "어떤 규칙으로 기록됐던 복사인지" 남기려고
        current_risk = self.store.get_active_risk(user)
        old_state = current_risk["state"] if current_risk else "NORMAL"
        # 이미 HIGH 이상이면 WATCH 로 내리지 않고 기록만 남긴다
        if result.level == "WATCH" and old_state not in ("HIGH", "CRITICAL"):
            self._apply_state_transition(user, old_state, "WATCH", result.score, result.reasons, event)
            if old_state == "WATCH":
                # 동일 등급의 추가 근거도 감사 이력에 남긴다.
                # 캡처·다운로드 같은 추가 반출 근거는 감사에 필요하므로 이력에는 남긴다.
                self.store.append_history(user, old_state, old_state, "[추가 근거] " + " / ".join(result.reasons))
        else:
            self.store.append_history(user, old_state, old_state, "[기록] " + " / ".join(result.reasons))
        return result.level

    # ------------------------------------------------------------------
    # 붙여넣기(PASTE_ATTEMPT) 판정  [추가됨]
    # ------------------------------------------------------------------

    # 패턴 키를 사람이 읽을 수 있는 이름으로 바꾸는 표.
    # 관리자가 근거를 볼 때 "rrn 3" 보다 "주민등록번호 형태 3건"이 이해가 빠르다.
    PASTE_PATTERN_LABELS = {
        "rrn": "주민등록번호 형태",
        "card": "카드번호 형태",
        "email": "이메일",
        "phone": "전화번호",
    }

    @staticmethod
    def _format_pattern_hits(pattern_hits: Dict[str, Any]) -> str:
        """
        패턴 검출 개수를 사람이 읽을 문장으로 만든다.

        예) {"rrn": 3, "card": 1, "email": 0} → "주민등록번호 형태 3건, 카드번호 형태 1건"
        0건인 항목은 빼고, 전부 0이면 "없음"을 돌려준다.

        ※ 여기서 다루는 것은 개수뿐이다. 붙여넣은 문자열은 애초에 이 함수까지 오지 않는다.
        """
        parts = []
        for key, label in CorrelationEngine.PASTE_PATTERN_LABELS.items():
            try:
                count = int(pattern_hits.get(key, 0) or 0)
            except (ValueError, TypeError):
                count = 0            # 값이 깨져 있으면 0으로 취급하고 넘어간다
            if count > 0:
                parts.append(f"{label} {count}건")
        return ", ".join(parts) if parts else "없음"

    def _evaluate_portal(self, user, old_state, event):
        extra = event.payload.extra or {}
        since = event.timestamp - timedelta(minutes=self.policy['usual_count_minutes'])
        counted = self.user_db_counts.setdefault(user, [])
        prior = {}
        for item in counted:
            if item['id'] != event.event_id and since <= item['time'] <= event.timestamp:
                for key, n in item['counts'].items(): prior[key] = prior.get(key, 0) + n
        result = dept_policy.judge_portal(event.action.value, user, extra, self.policy, prior)
        if event.action != EventAction.DB_IMAGE_CAPTURE:
            counted.append({'id':event.event_id, 'time':event.timestamp,
                            'counts':dept_policy.effective_counts(extra.get('pattern_hits') or {}, self.policy)})
            del counted[:-500]
        if event.action == EventAction.COPY_ATTEMPT:
            copies = self.user_db_copies.setdefault(user, [])
            copies.append({'id':event.event_id, 'time':event.timestamp,
                           'length':extra.get('text_length') or 0, 'source':event.target.domain,
                           'rules':result.rules})
            del copies[:-200]
        self._record_assessment(user, event, result, 'source')
        if result.level == 'WATCH' and old_state not in ('HIGH', 'CRITICAL'):
            self._apply_state_transition(user, old_state, 'WATCH', result.score, result.reasons, event)
        else:
            self.store.append_history(user, old_state, old_state,
                                      f'[회사 자료 {result.score}점] ' + ' / '.join(result.reasons))

    def _handle_paste_attempt(self, user, old_state, event):
        self._evaluate_outbound(user, old_state, event)

    def _evaluate_outbound(self, user, old_state, event):
        extra = event.payload.extra or {}
        target = (event.target.domain or "").lower().rstrip(".")
        link = extra.get("match") or {}
        if not isinstance(link, dict):
            link = {}
        source = link.get("source_domain")
        relation, minutes = "none", None
        if (extra.get("match_status") == "matched"
                and source == "desktop-oli.tail2bbbea.ts.net" and target and target != source):
            relation = "content"
        elif event.action == EventAction.FILE_UPLOAD_ATTEMPT:
            match = next((d for d in reversed(self.user_db_downloads.get(user, []))
                          if event.payload.file_name and event.payload.file_size is not None
                          and d["name"] == event.payload.file_name and d["size"] == event.payload.file_size), None)
            if match or extra.get("confidential_source"):
                relation = "metadata"
        elif event.action == EventAction.PASTE_ATTEMPT:
            try:
                length = int(extra.get("text_length") or 0)
            except (ValueError, TypeError):
                length = 0
            for copy in reversed(self.user_db_copies.get(user, [])):
                gap = (event.timestamp - copy["time"]).total_seconds() / 60
                if (0 <= gap <= self.policy["paste_match_minutes"] and length > 0 and copy["length"] > 0
                        and abs(copy["length"] - length) <= max(10, copy["length"] * self.policy["paste_match_tolerance"])):
                    relation, minutes = "length", gap
                    break
        approved = any(_same_or_sub(target, str(domain).lower().rstrip("."))
                       for domain in self.policy.get("approved_outbound_domains", []) if domain)
        external = bool(target) and not approved and (is_ai_or_file_sharing(target) or relation == "content")
        counts = dept_policy.effective_counts(extra.get("pattern_hits") or {}, self.policy)
        result = dept_policy.score_outbound(
            counts=counts, relation=relation, external=external, watched=old_state == "WATCH",
            policy=self.policy, minutes=minutes, download=(relation == "metadata" or
                (relation == "content" and link.get("source_kind") == "DOWNLOAD_COMPLETED")))
        guard = extra.get("image_guard") or {}
        blocked = isinstance(guard, dict) and guard.get("outcome") == "blocked_match"
        observed = event.action in (EventAction.ALLOW, EventAction.HTTP_POST)
        outcome = "전송 전 차단" if blocked else "전송 관측(민감자료 전송 완료 미확인)" if observed else "입력·첨부 시도(전송 완료 미확인)"
        result.reasons += [f"대상: {target or '미확인'}", f"전송 상태: {outcome}"]
        if extra.get('inspectable') is not True:
            result.reasons.append('민감정보 검사: 결과 미수신 또는 검사 불가 · 안전 판정 아님 · '
                                  + str(extra.get('reason') or 'INSPECTION_MISSING'))
        incident = self._record_assessment(user, event, result, 'outbound')
        # 낮은 위험의 새 사건이 기존 HIGH/CRITICAL 또는 WATCH를 지우지 않는다.
        rank = {"NORMAL": 0, "WATCH": 1, "HIGH": 2, "CRITICAL": 3}
        if result.level == "RECORD" or rank.get(result.level, 0) < rank.get(old_state, 0):
            self.store.append_history(user, old_state, old_state, " / ".join(result.reasons))
            return
        self._apply_state_transition(user, old_state, result.level, result.score, result.reasons, event, incident=incident)

    def _apply_state_transition(self, user: str, old_state: str, new_state: str,
                                score: int, reasons: List[str], event: SecurityEvent, incident=None):
        """
        판정 결과를 실제로 반영하는 함수. 위 update_user_risk()의 모든 분기가 결국 여기로 모인다.

        하는 일 3가지:
          1) user_risk 테이블에 현재 상태 저장 (만료 시각 포함)
          2) risk_history 테이블에 전이 기록 남기기 (감사 이력, 지우지 않음)
          3) 알림 훅 호출 (respond.py)
        """
        now_utc = datetime.utcnow()
        # 새 상태에 맞는 TTL을 지금 시각에 더해 만료 시각을 계산한다.
        # TTL 표에 없는 상태가 들어오면 안전하게 1시간을 준다.
        expires_at = now_utc + TTL.get(new_state, timedelta(hours=1))

        # 같은 등급도 점수·근거를 저장하고 알림만 억제
        # 이미 WATCH인 사람에게 또 WATCH 조건이 걸렸다고 알림을 다시 보내면
        # 관제사에게 중복 알림을 보내지 않되 갱신 이력은 보존한다.
        if new_state == old_state:
            current = self.store.get_active_risk(user)
            if current and score < current.get('score', 0):
                self.store.append_history(user, old_state, new_state,
                    f"[새 사건 {score}점 · 기존 유효 점수 유지] " + " / ".join(reasons))
                return
            self.store.upsert_risk(user, new_state, score, reasons, expires_at)
            self.store.append_history(user, old_state, new_state, "[근거 갱신] " + " / ".join(reasons))
            return

        # 상태 갱신 및 이력 적재
        self.store.upsert_risk(user, new_state, score, reasons, expires_at)     # 현재 상태 덮어쓰기
        self.store.append_history(user, old_state, new_state, " / ".join(reasons))  # 이력은 계속 쌓기

        # SOAR 알림 훅 호출
        # 여기서 2단계 알림이 갈린다. WATCH면 1차 주의 알림, HIGH면 2차 긴급 알림.
        # (실제 발송 로직은 engine/respond.py 에 있다)
        on_risk_state_changed(user, old_state, new_state, reasons, incident)


    def create_watch_incident(self, user: str, sc: Dict[str, Any]) -> Incident:
        """
        1단계 선제 감시(WATCH) 인시던트 생성 및 등록

        WATCH도 화면에 한 건으로 보여주기 위해 인시던트 객체를 만든다.
        severity는 MEDIUM(노랑)이고 점수는 68점 — 아직 유출이 아니므로 HIGH가 아니다.

        ※ 대시보드의 시뮬레이션 버튼에서 호출된다.
          sc(scenario) 인자로 시연용 시나리오 정보를 받는다.
        """
        inc_id = self._next_incident_id("INC-WATCH")   # [수정됨] 개수 기반 번호 → 겹치지 않는 일련번호
        now = datetime.utcnow()
        inc = Incident(
            incident_id=inc_id,
            title=f"사용자 '{user}' 미승인 AI 접속 및 기밀 반출 위험 선제 감시 (WATCH)",
            category=IncidentCategory.SHADOW_AI_EXFILTRATION,
            severity=Severity.MEDIUM,
            score=68,
            status=IncidentStatus.ACTIVE,
            summary=f"사내 기밀 DB({sc.get('table', 'vault')}) 조회 후 15분 내 미승인 서비스({sc.get('service', 'AI')}) 접속 포착 — 데이터 외부 반출 전 선제 감시(WATCH) 승격",
            actor=f"{sc.get('ip', '192.168.10.x')} ({user})",
            target_asset=f"Core DB -> {sc.get('service', 'external-ai')}",
            created_at=now,
            event_ids=[f"EVT-WATCH-{int(now.timestamp())}"],
            evidences=[
                f"사내 기밀 DB({sc.get('table', 'vault')}) SELECT 조회 선행 (+2점)",
                f"15분 내 미승인 외부 서비스({sc.get('service', 'AI')}) 접속 (+2점)",
                "위험 상태 기계: 1단계 사전 감시(WATCH) 승격 완료 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node=f"User PC ({sc.get('ip', '192.168.10.x')})", to_node="Internal DB", port=3306, hop_type="db_access"),
                NetworkHop(from_node=f"User PC ({sc.get('ip', '192.168.10.x')})", to_node=f"Cloud ({sc.get('service', 'external-ai')})", port=443, hop_type="suspicious")
            ],
            soar_actions=[
                f"단말({sc.get('ip', '192.168.10.x')}) 아웃바운드 트래픽 정밀 감시(DPI)",
                f"사용자({user}) 세션 선제 감시 플래그 점등",
                "사내 보안팀 1차 선제 감시 알림 전파"
            ]
        )
        self.incidents[inc_id] = inc
        self.store.save_incident(inc)
        return inc

    def create_heal_incident(self, user: str) -> Incident:
        """
        3단계 오탐 자가 치유(NORMAL) 인시던트 생성 및 등록

        WATCH였던 사람이 30분간 아무 전송도 하지 않아 정상으로 되돌아갔을 때,
        "이런 일이 있었고 문제없이 종료됐다"는 기록을 한 건 남긴다.
        status가 RESOLVED이고 점수는 20점이다.

        ※ 이 함수도 시뮬레이션 버튼에서 호출된다.
          실제 TTL 만료를 감지해 자동으로 불러주는 주기 작업은 아직 없다.
        """
        inc_id = self._next_incident_id("INC-NORM")   # [수정됨] 개수 기반 번호 → 겹치지 않는 일련번호
        now = datetime.utcnow()
        inc = Incident(
            incident_id=inc_id,
            title=f"사용자 '{user}' 30분 무전송 만료(TTL)로 인한 정상(NORMAL) 자가 치유",
            category=IncidentCategory.INSIDER_DATA_THEFT,
            severity=Severity.LOW,
            score=20,
            status=IncidentStatus.RESOLVED,
            summary=f"사전 감시(WATCH) 대상자였으나 30분간 추가 외부 데이터 전송이 발생하지 않아 정상(NORMAL) 상태로 안전하게 자가 치유(Self-healing) 완료",
            actor=f"Internal ({user})",
            target_asset=f"Audited Asset ({user})",
            created_at=now,
            event_ids=[f"EVT-TTL-{int(now.timestamp())}"],
            evidences=[
                "사전 감시 등록 후 30분간 외부 대용량 전송 무발생 (+0점)",
                "Self-Healing TTL 정책에 따른 안전한 NORMAL 자동 복귀 (+0점)"
            ],
            network_hops=[
                NetworkHop(from_node=f"User PC ({user})", to_node="Internal Gateway", port=443, hop_type="normal")
            ],
            soar_actions=[
                "선제 감시(WATCH) 플래그 정상 해제",
                "SQLite 상태 전이 감사 로그 영구 기록 완료"
            ]
        )
        self.incidents[inc_id] = inc
        self.store.save_incident(inc)
        return inc

    # ========================================================================
    # 대시보드에서 데이터를 꺼내갈 때 쓰는 조회 함수들
    # ========================================================================

    def get_all_incidents(self) -> List[Incident]:
        """모든 인시던트를 최신순으로 돌려준다. 대시보드 목록 화면에 쓰인다."""
        return sorted(list(self.incidents.values()), key=lambda x: x.created_at, reverse=True)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """인시던트 한 건을 ID로 찾아 돌려준다. 목록에서 클릭했을 때 상세 화면용."""
        return self.incidents.get(incident_id)

    def get_watch_users(self) -> List[Dict[str, Any]]:
        """
        현재 WATCH 상태에 있는 감시 대상자 목록 반환

        TTL이 지난 사람은 SQLite 조회 단계에서 이미 걸러지므로
        여기서 나오는 것은 '지금 유효하게 감시 중인' 사람들뿐이다.
        """
        return self.store.get_all_active_risks()

