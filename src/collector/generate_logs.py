"""
Log Data Generator for Anomaly Detection & Correlation Analysis.
Generates realistic normal baseline logs (90%) and injects anomaly attack scenarios (10%):
1. Zero Trust: Rogue AP / MitM packet interception (DNS spoofing, fake SSL, high RTT)
2. Multi-Stage Kill Chain: SSH Brute Force -> Lateral Movement -> DB PII Extraction -> Exfiltration
3. Web Vulnerability: SQL Injection / Web Scanning attacks
"""

import os
import random
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
RAW_LOGS_DIR = ROOT_DIR / "data" / "raw_logs"
JSON_OUTPUT_FILE = ROOT_DIR / "data" / "generated_logs.json"

USERS = ["alice", "bob", "charlie", "david", "minji.kim", "jihun.park", "admin", "guest"]
INTERNAL_IPS = ["10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.40", "10.0.0.50"]
EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(10, 50)] + [f"198.51.100.{i}" for i in range(10, 50)]
SSIDS = ["Starbucks_Guest_Free", "Airport_Free_WiFi", "Subway_Public_WiFi", "Twosome_Guest", "Office_Secure_5G"]

NORMAL_QUERIES = [
    "SELECT id, name FROM products WHERE category = 'electronics' LIMIT 20;",
    "SELECT * FROM notices ORDER BY created_at DESC LIMIT 5;",
    "UPDATE users SET last_login = NOW() WHERE user_id = 42;",
    "SELECT count(*) FROM orders WHERE status = 'pending';",
    "SELECT price FROM item_prices WHERE item_code = 'A102';"
]

class LogGenerator:
    def __init__(self, start_time: datetime = None):
        self.current_time = start_time or (datetime.utcnow() - timedelta(hours=2))
        self.generated_logs = []
        self.raw_logs_map = {
            "auth": [],
            "firewall": [],
            "server": [],
            "db": [],
            "wifi_mitm": []
        }

    def _next_timestamp(self, seconds_step: int = 5) -> str:
        self.current_time += timedelta(seconds=random.randint(1, seconds_step))
        return self.current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # ==========================
    # NORMAL LOG GENERATORS
    # ==========================
    def generate_normal_auth(self) -> Dict[str, Any]:
        ts = self._next_timestamp(15)
        user = random.choice(USERS[:-1]) # rarely admin
        src_ip = random.choice(EXTERNAL_IPS[:10])
        is_success = random.random() > 0.1
        port = random.randint(40000, 65000)

        # Raw log
        status = "Accepted" if is_success else "Failed"
        raw_line = f"{ts} sshd[{random.randint(10000, 25000)}]: {status} password for {user} from {src_ip} port {port} ssh2"
        self.raw_logs_map["auth"].append(raw_line)

        return {
            "id": f"LOG-AUTH-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts,
            "source": "auth",
            "user": user,
            "src_ip": src_ip,
            "dst_ip": "10.0.0.10",
            "src_port": port,
            "dst_port": 22,
            "protocol": "SSH",
            "action": "login_success" if is_success else "login_fail",
            "event_type": "USER_LOGIN_NORMAL",
            "details": {"raw": raw_line},
            "severity": "INFO" if is_success else "LOW",
            "is_anomaly": False,
            "anomaly_type": None
        }

    def generate_normal_firewall(self) -> Dict[str, Any]:
        ts = self._next_timestamp(10)
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(INTERNAL_IPS)
        proto = "TCP"
        spt = random.randint(30000, 60000)
        dpt = random.choice([80, 443, 8080, 3306])
        bytes_val = random.randint(500, 50000)

        raw_line = f"{ts} iptables-FORWARD: ALLOW IN=eth0 OUT=eth1 SRC={src} DST={dst} PROTO={proto} SPT={spt} DPT={dpt} BYTES={bytes_val}"
        self.raw_logs_map["firewall"].append(raw_line)

        return {
            "id": f"LOG-FW-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts,
            "source": "firewall",
            "user": None,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": spt,
            "dst_port": dpt,
            "protocol": proto,
            "action": "allow",
            "event_type": "ROUTINE_NETWORK_TRAFFIC",
            "details": {"bytes": bytes_val},
            "severity": "INFO",
            "is_anomaly": False,
            "anomaly_type": None
        }

    def generate_normal_db(self) -> Dict[str, Any]:
        ts = self._next_timestamp(20)
        user = random.choice(["app_user", "api_service", "worker"])
        src_ip = random.choice(["10.0.0.10", "10.0.0.20"])
        query = random.choice(NORMAL_QUERIES)

        raw_line = f"{ts} mysqld[1200]: [Query] {user}@{src_ip}: {query} rows_sent={random.randint(1, 20)}"
        self.raw_logs_map["db"].append(raw_line)

        return {
            "id": f"LOG-DB-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts,
            "source": "db",
            "user": user,
            "src_ip": src_ip,
            "dst_ip": "10.0.0.30",
            "src_port": None,
            "dst_port": 3306,
            "protocol": "MySQL",
            "action": "query",
            "event_type": "NORMAL_DB_QUERY",
            "details": {"query": query},
            "severity": "INFO",
            "is_anomaly": False,
            "anomaly_type": None
        }

    def generate_normal_wifi(self) -> Dict[str, Any]:
        ts = self._next_timestamp(30)
        user = random.choice(["minji.kim", "jihun.park", "david"])
        client_ip = f"172.20.10.{random.randint(10, 99)}"
        ssid = random.choice(SSIDS)
        rtt_ms = random.randint(12, 28)

        raw_line = f"{ts} endpoint-monitor[{user}]: AP='{ssid}' IP={client_ip} RTT={rtt_ms}ms DNS_RESOLV=auth.corp.com:10.0.0.5 SSL_CA='DigiCert Valid' STATUS=HEALTHY"
        self.raw_logs_map["wifi_mitm"].append(raw_line)

        return {
            "id": f"LOG-WIFI-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts,
            "source": "endpoint",
            "user": user,
            "src_ip": client_ip,
            "dst_ip": "10.0.0.5",
            "src_port": None,
            "dst_port": 443,
            "protocol": "HTTPS",
            "action": "allow",
            "event_type": "ZERO_TRUST_HEALTHY_CONNECTION",
            "details": {"ssid": ssid, "rtt_ms": rtt_ms, "ssl_valid": True},
            "severity": "INFO",
            "is_anomaly": False,
            "anomaly_type": None
        }

    # ==========================
    # ANOMALY SCENARIO INJECTORS
    # ==========================
    def inject_rogue_ap_mitm_campaign(self) -> List[Dict[str, Any]]:
        """Injects Zero Trust Rogue AP / MitM attack scenario"""
        campaign_logs = []
        user = "minji.kim@company.com"
        client_ip = "172.20.10.4"
        fake_gw = "192.168.1.99"
        ssid = "Starbucks_Guest_Free"

        # 1. Connected to Untrusted AP
        ts1 = self._next_timestamp(5)
        raw1 = f"{ts1} endpoint-monitor[{user}]: AP_ASSOCIATION SSID='{ssid}' CLIENT_IP={client_ip} GW={fake_gw} SECURITY=OPEN"
        self.raw_logs_map["wifi_mitm"].append(raw1)
        campaign_logs.append({
            "id": f"LOG-WIFI-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts1,
            "source": "endpoint",
            "user": user,
            "src_ip": client_ip,
            "dst_ip": fake_gw,
            "src_port": None,
            "dst_port": 80,
            "protocol": "Wi-Fi",
            "action": "warn",
            "event_type": "UNTRUSTED_OPEN_AP_CONNECTION",
            "details": {"ssid": ssid, "gateway": fake_gw},
            "severity": "LOW",
            "is_anomaly": True,
            "anomaly_type": "ROGUE_AP_MITM"
        })

        # 2. DNS Spoofing detected
        ts2 = self._next_timestamp(10)
        raw2 = f"{ts2} dns-guard[{user}]: DNS_SPOOF_ALERT query='auth.corp.com' legit_ip='10.0.0.5' returned_ip='{fake_gw}' status=POISONED"
        self.raw_logs_map["wifi_mitm"].append(raw2)
        campaign_logs.append({
            "id": f"LOG-DNS-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts2,
            "source": "endpoint",
            "user": user,
            "src_ip": client_ip,
            "dst_ip": fake_gw,
            "src_port": None,
            "dst_port": 53,
            "protocol": "DNS",
            "action": "deny",
            "event_type": "DNS_CACHE_POISONING_SPOOF",
            "details": {"query": "auth.corp.com", "fake_ip": fake_gw},
            "severity": "HIGH",
            "is_anomaly": True,
            "anomaly_type": "ROGUE_AP_MITM"
        })

        # 3. SSL Stripping / Fake Certificate
        ts3 = self._next_timestamp(10)
        raw3 = f"{ts3} tls-verifier[{user}]: SSL_INTERCEPT_DETECTED host='auth.corp.com' issuer='Untrusted Root MitM CA' rtt=185ms status=CERT_FORGERY"
        self.raw_logs_map["wifi_mitm"].append(raw3)
        campaign_logs.append({
            "id": f"LOG-SSL-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts3,
            "source": "endpoint",
            "user": user,
            "src_ip": client_ip,
            "dst_ip": fake_gw,
            "src_port": None,
            "dst_port": 443,
            "protocol": "TLS",
            "action": "deny",
            "event_type": "MITM_SSL_CERTIFICATE_INTERCEPTION",
            "details": {"rtt_ms": 185, "issuer": "Untrusted Root MitM CA"},
            "severity": "CRITICAL",
            "is_anomaly": True,
            "anomaly_type": "ROGUE_AP_MITM"
        })

        # 4. Zero Trust PDP Policy Block
        ts4 = self._next_timestamp(5)
        raw4 = f"{ts4} api-gateway[pdp]: PDP_DECISION user='{user}' client_ip='{client_ip}' risk_score=95 ACTION=ENFORCE_VPN_BLOCK_API"
        self.raw_logs_map["server"].append(raw4)
        campaign_logs.append({
            "id": f"LOG-GW-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts4,
            "source": "server",
            "user": user,
            "src_ip": client_ip,
            "dst_ip": "10.0.0.5",
            "src_port": None,
            "dst_port": 443,
            "protocol": "HTTPS",
            "action": "deny",
            "event_type": "ZERO_TRUST_PDP_BLOCK_AND_VPN_ENFORCE",
            "details": {"risk_score": 95},
            "severity": "CRITICAL",
            "is_anomaly": True,
            "anomaly_type": "ROGUE_AP_MITM"
        })

        return campaign_logs

    def inject_lateral_movement_db_exfil_campaign(self) -> List[Dict[str, Any]]:
        """Injects Multi-stage Brute Force -> Lateral Move -> Massive DB PII Exfil"""
        campaign_logs = []
        attacker_ip = "203.0.113.10"
        target_user = "admin"

        # 1. Multiple SSH Failures (Brute Force)
        for _ in range(6):
            ts = self._next_timestamp(3)
            port = random.randint(48000, 52000)
            raw = f"{ts} sshd[{random.randint(14000, 15000)}]: Failed password for invalid user {target_user} from {attacker_ip} port {port} ssh2"
            self.raw_logs_map["auth"].append(raw)
            campaign_logs.append({
                "id": f"LOG-AUTH-{uuid.uuid4().hex[:6].upper()}",
                "timestamp": ts,
                "source": "auth",
                "user": target_user,
                "src_ip": attacker_ip,
                "dst_ip": "10.0.0.10",
                "src_port": port,
                "dst_port": 22,
                "protocol": "SSH",
                "action": "login_fail",
                "event_type": "SSH_BRUTE_FORCE_ATTEMPT",
                "details": {"raw": raw},
                "severity": "MEDIUM",
                "is_anomaly": True,
                "anomaly_type": "KILL_CHAIN_EXFILTRATION"
            })

        # 2. SSH Success
        ts_succ = self._next_timestamp(15)
        port_succ = 49170
        raw_succ = f"{ts_succ} sshd[14250]: Accepted password for {target_user} from {attacker_ip} port {port_succ} ssh2"
        self.raw_logs_map["auth"].append(raw_succ)
        campaign_logs.append({
            "id": f"LOG-AUTH-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts_succ,
            "source": "auth",
            "user": target_user,
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.10",
            "src_port": port_succ,
            "dst_port": 22,
            "protocol": "SSH",
            "action": "login_success",
            "event_type": "SSH_LOGIN_SUCCESS_COMPROMISED",
            "details": {"raw": raw_succ},
            "severity": "HIGH",
            "is_anomaly": True,
            "anomaly_type": "KILL_CHAIN_EXFILTRATION"
        })

        # 3. Lateral Movement to Internal Jump Server
        ts_lat = self._next_timestamp(30)
        raw_lat = f"{ts_lat} iptables-FORWARD: ALLOW IN=eth0 OUT=eth1 SRC=10.0.0.10 DST=10.0.0.20 PROTO=TCP SPT=54210 DPT=22 BYTES=24500"
        self.raw_logs_map["firewall"].append(raw_lat)
        campaign_logs.append({
            "id": f"LOG-FW-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts_lat,
            "source": "firewall",
            "user": target_user,
            "src_ip": "10.0.0.10",
            "dst_ip": "10.0.0.20",
            "src_port": 54210,
            "dst_port": 22,
            "protocol": "TCP",
            "action": "allow",
            "event_type": "LATERAL_MOVEMENT_INTERNAL_SSH",
            "details": {"bytes": 24500},
            "severity": "HIGH",
            "is_anomaly": True,
            "anomaly_type": "KILL_CHAIN_EXFILTRATION"
        })

        # 4. DB PII Massive SELECT
        ts_db = self._next_timestamp(45)
        raw_db = f"{ts_db} mysqld[1200]: [Query] {target_user}@10.0.0.20: SELECT * FROM customers_pii LIMIT 50000; rows_sent=50000"
        self.raw_logs_map["db"].append(raw_db)
        campaign_logs.append({
            "id": f"LOG-DB-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts_db,
            "source": "db",
            "user": target_user,
            "src_ip": "10.0.0.20",
            "dst_ip": "10.0.0.30",
            "src_port": 43100,
            "dst_port": 3306,
            "protocol": "MySQL",
            "action": "query",
            "event_type": "MASSIVE_PII_DATA_EXTRACTION",
            "details": {"query": "SELECT * FROM customers_pii LIMIT 50000", "rows_sent": 50000},
            "severity": "CRITICAL",
            "is_anomaly": True,
            "anomaly_type": "KILL_CHAIN_EXFILTRATION"
        })

        # 5. Data Exfiltration via External Port
        ts_exfil = self._next_timestamp(30)
        exfil_ip = "198.51.100.77"
        raw_exfil = f"{ts_exfil} iptables-OUTPUT: ALERT IN=eth1 OUT=wan0 SRC=10.0.0.20 DST={exfil_ip} PROTO=TCP SPT=59120 DPT=8080 BYTES=131072000"
        self.raw_logs_map["firewall"].append(raw_exfil)
        campaign_logs.append({
            "id": f"LOG-FW-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts_exfil,
            "source": "firewall",
            "user": target_user,
            "src_ip": "10.0.0.20",
            "dst_ip": exfil_ip,
            "src_port": 59120,
            "dst_port": 8080,
            "protocol": "TCP",
            "action": "deny",
            "event_type": "MASSIVE_EXTERNAL_DATA_EXFILTRATION",
            "details": {"bytes": 131072000, "dst": f"{exfil_ip}:8080"},
            "severity": "CRITICAL",
            "is_anomaly": True,
            "anomaly_type": "KILL_CHAIN_EXFILTRATION"
        })

        return campaign_logs

    def inject_sqli_attack(self) -> List[Dict[str, Any]]:
        """Injects SQL injection attack against web frontend"""
        attacker_ip = "198.51.100.44"
        ts = self._next_timestamp(20)
        uri = "/api/products?id=1' UNION SELECT username, password FROM users --"
        raw = f"{ts} nginx-access: {attacker_ip} - [403] 'GET {uri} HTTP/1.1' agent='sqlmap/1.5'"
        self.raw_logs_map["server"].append(raw)
        return [{
            "id": f"LOG-SRV-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": ts,
            "source": "server",
            "user": "anonymous",
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.10",
            "src_port": random.randint(40000, 60000),
            "dst_port": 80,
            "protocol": "HTTP",
            "action": "deny",
            "event_type": "SQL_INJECTION_SCAN_ATTEMPT",
            "details": {"uri": uri, "status": 403},
            "severity": "HIGH",
            "is_anomaly": True,
            "anomaly_type": "SQL_INJECTION"
        }]

    # ==========================
    # MAIN BATCH GENERATOR
    # ==========================
    def generate_dataset(self, total_count: int = 500, anomaly_ratio: float = 0.1):
        """Generates mixed logs with normal traffic and anomaly bursts."""
        print(f"[*] Generating {total_count} logs with ~{int(anomaly_ratio*100)}% anomaly injection...")

        all_logs = []
        normal_count = int(total_count * (1 - anomaly_ratio))

        # Generate normal logs
        for _ in range(normal_count):
            choice = random.random()
            if choice < 0.35:
                all_logs.append(self.generate_normal_firewall())
            elif choice < 0.60:
                all_logs.append(self.generate_normal_auth())
            elif choice < 0.80:
                all_logs.append(self.generate_normal_db())
            else:
                all_logs.append(self.generate_normal_wifi())

        # Inject Attack Scenarios
        all_logs.extend(self.inject_rogue_ap_mitm_campaign())
        all_logs.extend(self.inject_lateral_movement_db_exfil_campaign())
        all_logs.extend(self.inject_sqli_attack())
        # Inject an extra rogue AP and brute force campaign for volume
        all_logs.extend(self.inject_rogue_ap_mitm_campaign())
        all_logs.extend(self.inject_sqli_attack())

        # Sort logs chronologically by timestamp
        all_logs.sort(key=lambda x: x["timestamp"])

        # Write to JSON
        RAW_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with open(JSON_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(all_logs, f, ensure_ascii=False, indent=2)

        # Write to raw text log files
        for src, lines in self.raw_logs_map.items():
            filepath = RAW_LOGS_DIR / f"sample_{src}.log"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

        anomaly_count = sum(1 for log in all_logs if log["is_anomaly"])
        print(f"[+] Generation complete!")
        print(f"    - Total logs generated: {len(all_logs)}")
        print(f"    - Normal baseline logs: {len(all_logs) - anomaly_count}")
        print(f"    - Injected anomaly logs: {anomaly_count}")
        print(f"    - Normalized JSON saved to: {JSON_OUTPUT_FILE}")
        print(f"    - Raw text logs saved to: {RAW_LOGS_DIR}")
        return all_logs

if __name__ == "__main__":
    gen = LogGenerator()
    gen.generate_dataset(total_count=500, anomaly_ratio=0.1)
