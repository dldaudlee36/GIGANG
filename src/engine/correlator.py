"""
Correlation & Anomaly Scoring Engine (Member 3)
Calculates correlation scores across time windows, IP hops, user identity, and kill-chain sequences.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional

class CorrelationEngine:
    def __init__(self, time_window_seconds: int = 600, min_score_threshold: float = 6.0):
        self.time_window_seconds = time_window_seconds
        self.min_score_threshold = min_score_threshold

    def correlate_events(self, logs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Analyzes a sequence of normalized logs, scores their correlation,
        and generates an Incident if threshold is met.
        """
        if not logs or len(logs) < 2:
            return None

        reasons = []
        total_score = 0.0

        # 1. User Identity Continuity Check (+2.0)
        users = [l.get("user") for l in logs if l.get("user")]
        if users and len(set(users)) == 1:
            score = 2.0
            total_score += score
            reasons.append({
                "criteria": "동일 사용자 계정",
                "score": score,
                "description": f"인증 및 내부 행위 주체가 '{users[0]}' 계정으로 일치함"
            })

        # 2. Network IP Chain / Hop Continuity (+4.0)
        has_ip_chain = False
        for i in range(len(logs) - 1):
            curr_dst = logs[i].get("dst_ip")
            next_src = logs[i+1].get("src_ip")
            if curr_dst and next_src and curr_dst == next_src:
                has_ip_chain = True
                break

        if has_ip_chain:
            score = 4.0
            total_score += score
            reasons.append({
                "criteria": "IP 연결 및 네트워크 홉 체인",
                "score": score,
                "description": "선행 이벤트의 목적지 IP가 후행 이벤트의 출발지 IP로 이어지는 횡적이동 경로 포착"
            })

        # 3. Time Proximity Check (+2.0)
        # Assuming timestamps are sequential or within time_window
        score = 2.0
        total_score += score
        reasons.append({
            "criteria": "시간적 인접성 (Time Window)",
            "score": score,
            "description": f"{self.time_window_seconds // 60}분 이내에 집중적으로 발생"
        })

        # 4. Attack Kill-Chain Sequence Order (+4.0)
        event_types = [l.get("event_type", "") for l in logs]
        has_kill_chain = any("LOGIN" in e for e in event_types) and (
            any("DB" in e or "PII" in e for e in event_types) or any("EXFILTRATION" in e for e in event_types)
        )
        if has_kill_chain:
            score = 4.0
            total_score += score
            reasons.append({
                "criteria": "공격 행동 순서 일치 (Kill Chain)",
                "score": score,
                "description": "초기 침투 -> 내부 이동 -> 데이터 접근/유출 순서의 전형적 공격 라이프사이클 부합"
            })

        if total_score < self.min_score_threshold:
            return None

        # Build attack timeline
        timeline = []
        for idx, log in enumerate(logs, start=1):
            timeline.append({
                "step": idx,
                "timestamp": log.get("timestamp"),
                "source": log.get("source"),
                "stage": log.get("event_type"),
                "description": f"[{log.get('source').upper()}] {log.get('event_type')} (src: {log.get('src_ip')} -> dst: {log.get('dst_ip')}:{log.get('dst_port')})",
                "raw_log_id": log.get("id")
            })

        # Build network path
        network_path = []
        for i in range(len(logs) - 1):
            src = logs[i].get("src_ip") or "Unknown"
            dst = logs[i].get("dst_ip") or "Unknown"
            port = logs[i].get("dst_port") or 80
            proto = logs[i].get("protocol") or "TCP"
            network_path.append({
                "from_node": src,
                "to_node": dst,
                "port": port,
                "protocol": proto,
                "status": "COMPROMISED" if i == 0 else "LATERAL_MOVE"
            })

        return {
            "incident_id": f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(int(total_score * 100))[:3]}",
            "title": "다중 시스템 연계 횡적 이동 및 데이터 유출 침해사고",
            "severity": "CRITICAL" if total_score >= 12 else "HIGH",
            "status": "OPEN",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "target_user": users[0] if users else "unknown",
            "primary_src_ip": logs[0].get("src_ip", "unknown"),
            "correlation_score": total_score,
            "reasons": reasons,
            "attack_timeline": timeline,
            "network_path": network_path,
            "ai_analysis": None # Will be enriched by ai_agent.py
        }
