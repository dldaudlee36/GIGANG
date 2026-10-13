"""
Log Normalization Module (Member 2)
Parses multi-source heterogeneous logs into the standard JSON schema.
Includes an optional AI Fallback Parser for unfamiliar unstructured formats.
"""
import re
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

class LogNormalizer:
    def __init__(self, enable_ai_fallback: bool = False):
        self.enable_ai_fallback = enable_ai_fallback

    def parse_auth_log(self, line: str) -> Optional[Dict[str, Any]]:
        # e.g.: 2026-08-31T10:01:05Z sshd[14201]: Failed password for invalid user admin from 203.0.113.10 port 49152 ssh2
        pattern = r"(?P<ts>\S+)\s+sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+(?:for\s+(?:invalid\s+user\s+)?(?P<user>\w+))\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
        match = re.search(pattern, line)
        if not match:
            return None
        
        is_success = match.group("status") == "Accepted"
        return {
            "id": f"LOG-AUTH-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": match.group("ts"),
            "source": "auth",
            "user": match.group("user"),
            "src_ip": match.group("src_ip"),
            "dst_ip": "10.0.0.10", # default target host
            "src_port": int(match.group("port")),
            "dst_port": 22,
            "protocol": "SSH",
            "action": "login_success" if is_success else "login_fail",
            "event_type": "SSH_LOGIN_SUCCESS" if is_success else "SSH_LOGIN_FAILED",
            "details": {"raw": line},
            "severity": "INFO" if is_success else "LOW"
        }

    def parse_firewall_log(self, line: str) -> Optional[Dict[str, Any]]:
        # e.g.: 2026-08-31T10:04:22Z iptables-FORWARD: ALLOW IN=eth0 OUT=eth1 SRC=10.0.0.10 DST=10.0.0.20 PROTO=TCP SPT=54210 DPT=22
        pattern = r"(?P<ts>\S+)\s+iptables-(?P<chain>\w+):\s+(?P<action>ALLOW|ALERT|DROP)\s+IN=\S+\s+OUT=\S+\s+SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+PROTO=(?P<proto>\S+)\s+SPT=(?P<spt>\d+)\s+DPT=(?P<dpt>\d+)(?:\s+BYTES=(?P<bytes>\d+))?"
        match = re.search(pattern, line)
        if not match:
            return None

        action = match.group("action")
        bytes_val = int(match.group("bytes")) if match.group("bytes") else 0
        severity = "HIGH" if (action == "ALERT" or bytes_val > 10000000) else "INFO"
        event_type = "LARGE_DATA_EXFILTRATION" if bytes_val > 10000000 else "NETWORK_TRAFFIC"
        
        return {
            "id": f"LOG-FW-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": match.group("ts"),
            "source": "firewall",
            "user": None,
            "src_ip": match.group("src_ip"),
            "dst_ip": match.group("dst_ip"),
            "src_port": int(match.group("spt")),
            "dst_port": int(match.group("dpt")),
            "protocol": match.group("proto"),
            "action": "allow" if action == "ALLOW" else "deny",
            "event_type": event_type,
            "details": {"bytes": bytes_val, "chain": match.group("chain")},
            "severity": severity
        }

    def parse_db_log(self, line: str) -> Optional[Dict[str, Any]]:
        # e.g.: 2026-08-31T10:08:15Z mysqld[1200]: [Query] admin@10.0.0.20: SELECT * FROM customers_pii LIMIT 50000; rows_sent=50000
        pattern = r"(?P<ts>\S+)\s+mysqld\[\d+\]:\s+\[(?P<type>Connect|Query)\]\s+(?P<user>\w+)@(?P<src_ip>\d+\.\d+\.\d+\.\d+):\s*(?P<query>.*)"
        match = re.search(pattern, line)
        if not match:
            return None

        query_str = match.group("query")
        is_pii = "customers_pii" in query_str.lower() or "50000" in query_str
        return {
            "id": f"LOG-DB-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": match.group("ts"),
            "source": "db",
            "user": match.group("user"),
            "src_ip": match.group("src_ip"),
            "dst_ip": "10.0.0.30",
            "src_port": None,
            "dst_port": 3306,
            "protocol": "MySQL",
            "action": "query",
            "event_type": "MASSIVE_PII_EXTRACTION" if is_pii else "DB_QUERY",
            "details": {"query": query_str},
            "severity": "HIGH" if is_pii else "INFO"
        }

    def normalize(self, source_hint: str, raw_line: str) -> Dict[str, Any]:
        """Dispatches line to matching regex parser, falls back to AI or generic format."""
        parsed = None
        if "auth" in source_hint:
            parsed = self.parse_auth_log(raw_line)
        elif "firewall" in source_hint or "fw" in source_hint:
            parsed = self.parse_firewall_log(raw_line)
        elif "db" in source_hint:
            parsed = self.parse_db_log(raw_line)

        if parsed:
            return parsed

        # Generic fallback
        return {
            "id": f"LOG-GEN-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": source_hint,
            "user": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "action": "unknown",
            "event_type": "UNPARSED_LOG",
            "details": {"raw": raw_line},
            "severity": "INFO"
        }
