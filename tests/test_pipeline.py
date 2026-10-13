"""
End-to-End Pipeline Unit Tests
"""
import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from src.normalizer.parsers import LogNormalizer
from src.engine.correlator import CorrelationEngine
from src.engine.ai_agent import AISecOpsAgent

def test_normalization_and_correlation():
    normalizer = LogNormalizer()
    correlator = CorrelationEngine()
    ai_agent = AISecOpsAgent()

    # Raw sample logs
    auth_line = "2026-08-31T10:02:10Z sshd[14250]: Accepted password for admin from 203.0.113.10 port 49170 ssh2"
    fw_line = "2026-08-31T10:04:22Z iptables-FORWARD: ALLOW IN=eth0 OUT=eth1 SRC=10.0.0.10 DST=10.0.0.20 PROTO=TCP SPT=54210 DPT=22"
    db_line = "2026-08-31T10:08:15Z mysqld[1200]: [Query] admin@10.0.0.20: SELECT * FROM customers_pii LIMIT 50000; rows_sent=50000"

    norm_auth = normalizer.normalize("auth", auth_line)
    norm_fw = normalizer.normalize("firewall", fw_line)
    norm_db = normalizer.normalize("db", db_line)

    assert norm_auth["user"] == "admin"
    assert norm_auth["action"] == "login_success"
    assert norm_fw["dst_port"] == 22
    assert norm_db["event_type"] == "MASSIVE_PII_EXTRACTION"

    # Correlate
    logs = [norm_auth, norm_fw, norm_db]
    incident = correlator.correlate_events(logs)

    assert incident is not None
    assert incident["correlation_score"] >= 6.0
    assert len(incident["reasons"]) >= 2

    # Enrich with AI
    enriched = ai_agent.enrich_incident(incident)
    assert "ai_analysis" in enriched
    assert len(enriched["ai_analysis"]["mitre_tactics"]) > 0

    print("[OK] All pipeline unit tests passed successfully!")

if __name__ == "__main__":
    test_normalization_and_correlation()
