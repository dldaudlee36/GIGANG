"""위험 상태 변경을 로컬 로그에 기록합니다. 외부 메신저로 전송하지 않습니다."""

import logging
from typing import List

# 'gigang.soar' 이름표를 단 로거.
# 나중에 이 이름으로 필터링하면 SOAR 관련 로그만 따로 볼 수 있다.
logger = logging.getLogger("gigang.soar")


def on_risk_state_changed(user: str, old_state: str, new_state: str, reasons: List[str], incident=None) -> None:
    """
    사용자 위험 상태 전이 시 자동 호출되는 범용 훅
    - NORMAL -> WATCH: 1차 사전 알림 (감시 대상 등록)
    - WATCH -> HIGH: 2차 긴급 알림 (Incident 확정)
    - WATCH -> NORMAL: 30분 만료 오탐 자동 해제 감사 로깅

    correlation.py 의 _apply_state_transition() 마지막 줄에서 호출된다.

    인자 설명:
      user      : 대상 사용자 (계정명 또는 IP)
      old_state : 바뀌기 전 상태
      new_state : 바뀐 후 상태
      reasons   : 왜 바뀌었는지 근거 목록
      incident  : HIGH일 때만 전달되는 인시던트 객체 (WATCH일 땐 None)
    """
    # 근거 목록을 한 줄 문자열로 합친다. 근거가 없으면 '단순 경과'로 표시.
    reason_str = " | ".join(reasons) if reasons else "단순 경과"

    # ── 1차 알림: 감시 대상 등록 ──────────────────────────────
    # 아직 데이터는 나가지 않았다. 관리자에게 "지켜보라"고 알리는 단계.
    if new_state == "WATCH":
        msg = f"⚠️ [1차 사전 감시] 사용자 '{user}' 감시 대상(WATCH) 승격 (사유: {reason_str})"
        logger.info(msg)

    # ── 2차 알림: 침해사고 확정 ───────────────────────────────
    # 실제로 데이터가 나갔다. 즉시 조치가 필요한 단계.
    elif new_state == "HIGH":
        # incident 객체가 넘어오지 않은 경우에도 알림은 나가야 하므로 기본값을 준비한다
        inc_title = incident.title if incident else "민감정보 외부 반출 의심"
        inc_id = incident.incident_id if incident else "INC-AUTO"
        msg = f"🚨 [2차 긴급 경보] [{inc_id}] '{user}' HIGH Incident 확정! (제목: {inc_title}, 근거: {reason_str})"
        logger.info(msg)

        # [SOAR 확장 포인트: 필요 시 주석 해제하여 활성화]
        # ↓ 이 두 줄은 의도적으로 꺼둔 것이다. 파일 상단 설명 참고.
        #   자동 차단을 켜면 오탐 시 정상 직원의 업무가 시스템에 의해 끊긴다.
        #   현재 설계에서는 관리자가 대시보드에서 직접 실행한다.
        # if incident and hasattr(incident, 'actor'):
        #     block_outbound_ip(incident.actor)
        # revoke_user_session(user)

    # ── 자가 치유 기록 ────────────────────────────────────────
    # 30분간 아무 일도 없어서 정상으로 돌아온 경우. 긴급하지 않으므로 로컬 로그로 남긴다.
    elif old_state == "WATCH" and new_state == "NORMAL":
        msg = f"ℹ️ [오탐 자동 해제] 사용자 '{user}' 30분 TTL 만료로 정상(NORMAL) 자동 복귀 완료."
        logger.info(msg)


# ============================================================================
# 실제 차단 조치 함수들
# 지금은 로그만 남기는 껍데기다. 실제 장비 연동 시 이 안을 채우면 된다.
# 대시보드의 대응 버튼이나 위 훅에서 호출하도록 연결한다.
# ============================================================================

def block_outbound_ip(target_ip: str) -> bool:
    """
    방화벽 아웃바운드 차단 룰 적용 훅

    실제 구현 시: 방화벽 API를 호출해 해당 IP의 외부 통신을 막는다.
    현재는 경고 로그만 남긴다.
    """
    logger.warning(f"방화벽 차단 정책 적용: {target_ip}")
    return True


def revoke_user_session(user_id: str) -> bool:
    """
    사용자 SSO 활성 세션 강제 종료 훅

    실제 구현 시: Active Directory 등에 요청해 로그인 세션을 만료시킨다.
    현재는 경고 로그만 남긴다.
    """
    logger.warning(f"사용자 세션 강제 종료: {user_id}")
    return True
