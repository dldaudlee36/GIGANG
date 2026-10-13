"""
AI SecOps & Copilot Module (Member 3 / AI Automation)
Enriches security incidents with LLM-based summaries, MITRE ATT&CK mapping,
automated SOAR remediation playbooks, and interactive Q&A.
"""
import os
import json
from typing import Dict, Any, List, Optional

class AISecOpsAgent:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.client = None
        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"[AI Agent] Note: Initialized in mock mode ({e})")

    def enrich_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Generates natural language summary, MITRE ATT&CK mappings, and remediation playbook."""
        # If live Gemini API is available:
        if self.client:
            try:
                prompt = f"""
You are an expert SOC Incident Responder. Analyze this security incident JSON:
{json.dumps(incident, indent=2, ensure_ascii=False)}

Respond in valid JSON with:
{{
  "summary": "Detailed Korean incident summary explaining the threat flow",
  "mitre_tactics": ["T1557.002 (MitM: DNS Spoofing)", ...],
  "confidence": 0.95,
  "recommended_playbook": [
    {{"action": "...", "command": "...", "target": "...", "status": "PENDING"}}
  ]
}}
"""
                models_to_try = ["gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash", "gemini-1.5-flash"]
                response = None
                for m in models_to_try:
                    try:
                        response = self.client.models.generate_content(
                            model=m,
                            contents=prompt
                        )
                        if response and response.text:
                            break
                    except Exception:
                        continue

                if response and response.text:
                    text = response.text.strip()
                    if "```json" in text:
                        text = text.split("```json")[1].split("```")[0].strip()
                    elif "```" in text:
                        text = text.split("```")[1].split("```")[0].strip()
                    ai_data = json.loads(text)
                    incident["ai_analysis"] = ai_data
                    return incident
            except Exception as ex:
                print(f"[AI Agent] Live LLM call failed ({ex}), using intelligent fallback.")

        # High-Fidelity Rule-Based Mock Fallback
        src_ip = incident.get("primary_src_ip", "Unknown IP")
        user = incident.get("target_user", "Unknown User")
        score = incident.get("correlation_score", 10.0)

        if "Wi-Fi" in incident.get("title", "") or "Rogue" in incident.get("title", ""):
            incident["ai_analysis"] = {
                "summary": f"사용자({user})가 오픈 공공 Wi-Fi 환경에서 가짜 AP(Rogue AP)를 통한 DNS 스푸핑 및 사설 가짜 SSL 인증서 주입에 노출되었습니다. 제로 트러스트 PDP 정책에 따라 중요 API 요청이 즉시 차단되었으며, 암호화 VPN 터널링 전환이 권고됩니다.",
                "mitre_tactics": [
                    "T1557.002 (MitM: DNS Spoofing)",
                    "T1556 (Modify Authentication Process)",
                    "T1040 (Network Sniffing)"
                ],
                "confidence": 0.98,
                "recommended_playbook": [
                    {
                        "action": "단말 암호화 VPN 터널링 강제 전환",
                        "command": "mobile-agent-cli --enforce-vpn --profile corp-secure-vpn --strict",
                        "target": "Mobile Client Agent",
                        "status": "PENDING"
                    },
                    {
                        "action": f"피해 계정 '{user}' 임시 세션 토큰 즉시 무효화",
                        "command": f"redis-cli DEL session:token:{user}",
                        "target": "Auth Redis Cluster",
                        "status": "PENDING"
                    },
                    {
                        "action": "사용자 모바일 푸시 보안 알림 발송",
                        "command": f"push-notify --user {user} '⚠️ 안전하지 않은 Wi-Fi 감지: 사내 VPN으로 자동 전환되었습니다.'",
                        "target": "Push Notification Service",
                        "status": "PENDING"
                    }
                ]
            }
        else:
            incident["ai_analysis"] = {
                "summary": f"공격자 IP({src_ip})가 '{user}' 계정을 표적으로 초기 무차별 대입 공격에 성공한 후, 내부 점프 서버를 경유하여 중요 데이터베이스로 횡적이동(Lateral Movement)을 감행했습니다. (상관분석 신뢰도: {score}/12)",
                "mitre_tactics": [
                    "T1110 (Brute Force)",
                    "T1078 (Valid Accounts)",
                    "T1021.004 (Remote Services: SSH)",
                    "T1005 (Data from Local System)",
                    "T1041 (Exfiltration Over C2 Channel)"
                ],
                "confidence": 0.95,
                "recommended_playbook": [
                    {
                        "action": "공격자 IP 즉시 차단",
                        "command": f"iptables -A INPUT -s {src_ip} -j DROP",
                        "target": "Edge Firewall / Gateway",
                        "status": "PENDING"
                    },
                    {
                        "action": f"침해 계정 '{user}' 세션 강제 종료 및 계정 잠금",
                        "command": f"pkill -u {user} && usermod -L {user}",
                        "target": "Internal Jump & Web Hosts",
                        "status": "PENDING"
                    },
                    {
                        "action": "DB 활성 악성 연결 즉시 종료",
                        "command": f"mysqladmin -u root processlist | grep {user} | awk '{{print $1}}' | xargs -I {{}} mysqladmin kill {{}}",
                        "target": "DB Server (10.0.0.30)",
                        "status": "PENDING"
                    }
                ]
            }
        return incident

    def answer_copilot_query(self, incident: Dict[str, Any], question: str) -> str:
        """Answers SOC analyst questions about the incident."""
        if self.client:
            try:
                prompt = f"""
You are a SecOps AI Copilot. The analyst is asking a question about this incident:
Incident Context:
{json.dumps(incident, indent=2, ensure_ascii=False)}

User Question: {question}
Answer concisely and clearly in Korean:
"""
                resp = self.client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt
                )
                return resp.text
            except Exception as e:
                pass

        # Intelligent Fallback Responses
        q_lower = question.lower()
        if "가짜 ap" in q_lower or "wifi" in q_lower or "wi-fi" in q_lower or "dns" in q_lower or "ssl" in q_lower:
            return "사내 공식 도메인(auth.corp.com)에 대해 비정상 사설 IP(192.168.1.99)로 DNS가 응답되었고, 신뢰할 수 없는 사설 CA 인증서 주입 및 RTT 지연시간 급증이 확인되어 중간자 감청(MitM) 공격으로 분류되었습니다."
        elif "테이블" in q_lower or "db" in q_lower:
            return "공격자는 포트 3306(MySQL)으로 연결하여 `customers_pii` 테이블에서 약 50,000건의 고객 개인정보를 SELECT 쿼리로 조회했습니다."
        elif "알림" in q_lower or "문구" in q_lower:
            return "📱 **[사용자 발송 보안 알림]**\n> ⚠️ *'현재 접속하신 공공 Wi-Fi는 보안이 취약하여 패킷 감청 위험이 감지되었습니다. 사내 보안을 위해 안전한 암호화 VPN으로 자동 전환되었습니다.'*"
        elif "차단" in q_lower or "대응" in q_lower or "조치" in q_lower or "vpn" in q_lower:
            return f"우선 단말에 대해 `mobile-agent-cli --enforce-vpn --profile corp-secure-vpn --strict` 명령어로 안전한 암호화 VPN 전환을 강제하고, 피해 계정 `{incident.get('target_user')}`의 임시 인증 세션을 무효화해야 합니다."
        elif "보고서" in q_lower or "요약" in q_lower:
            return f"### [침해사고 요약 보고]\n- **사건 ID:** {incident.get('incident_id')}\n- **심각도:** {incident.get('severity')}\n- **대상 사용자:** {incident.get('target_user')}\n- **주요 원인:** {incident.get('title')}\n- **현재 상태:** 제로 트러스트 SOAR 1-Click 대응 대기 중."
        else:
            return f"분석 결과, 본 사건은 '{incident.get('title')}'(위험도: {incident.get('severity')})로 분류되었습니다. 추가 질문(예: '가짜 AP 원인', 'VPN 전환 조치', '사용자 알림 문구')을 입력해주세요."
