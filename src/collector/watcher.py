"""
Log Collection Module (Member 1)
Watches raw log files or generates simulated live stream logs for real-time ingestion.
"""
import os
import time
import json
from pathlib import Path
from typing import Callable, Optional

class LogWatcher:
    def __init__(self, watch_dir: str, callback: Optional[Callable[[str, str], None]] = None):
        self.watch_dir = Path(watch_dir)
        self.callback = callback
        self._file_positions = {}

    def scan_new_lines(self):
        """Scans all .log files in watch_dir and yields new lines."""
        if not self.watch_dir.exists():
            return []
        
        events = []
        for log_file in self.watch_dir.glob("*.log"):
            filepath = str(log_file)
            last_pos = self._file_positions.get(filepath, 0)
            
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                self._file_positions[filepath] = f.tell()
                
                for line in new_lines:
                    line_str = line.strip()
                    if line_str:
                        events.append((log_file.name, line_str))
                        if self.callback:
                            self.callback(log_file.name, line_str)
        return events

def emit_mock_attack_logs(target_dir: str, delay_sec: float = 0.5):
    """Utility function to simulate live attack stream by appending lines to sample logs."""
    target_path = Path(target_dir)
    target_path.mkdir(parents=True, exist_ok=True)
    
    print(f"[Collector] Simulating attack sequence into {target_dir}...")
    auth_file = target_path / "sample_auth.log"
    fw_file = target_path / "sample_firewall.log"
    db_file = target_path / "sample_db.log"
    
    # 1. SSH brute force
    with open(auth_file, "a", encoding="utf-8") as f:
        f.write("2026-08-31T10:01:05Z sshd[14201]: Failed password for invalid user admin from 203.0.113.10 port 49152 ssh2\n")
        f.flush()
    time.sleep(delay_sec)
    
    # 2. SSH success
    with open(auth_file, "a", encoding="utf-8") as f:
        f.write("2026-08-31T10:02:10Z sshd[14250]: Accepted password for admin from 203.0.113.10 port 49170 ssh2\n")
        f.flush()
    time.sleep(delay_sec)
    
    # 3. FW Lateral move
    with open(fw_file, "a", encoding="utf-8") as f:
        f.write("2026-08-31T10:04:22Z iptables-FORWARD: ALLOW IN=eth0 OUT=eth1 SRC=10.0.0.10 DST=10.0.0.20 PROTO=TCP SPT=54210 DPT=22\n")
        f.flush()
    time.sleep(delay_sec)
    
    # 4. DB access
    with open(db_file, "a", encoding="utf-8") as f:
        f.write("2026-08-31T10:07:30Z mysqld[1200]: [Note] Connect admin@10.0.0.20 on prod_db using TCP/IP\n")
        f.write("2026-08-31T10:08:15Z mysqld[1200]: [Query] admin@10.0.0.20: SELECT * FROM customers_pii LIMIT 50000; rows_sent=50000\n")
        f.flush()
    print("[Collector] Mock attack simulation completed.")

if __name__ == "__main__":
    watcher = LogWatcher("data/raw_logs")
    print("Initial scan found new lines:", len(watcher.scan_new_lines()))
