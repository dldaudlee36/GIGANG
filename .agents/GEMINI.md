# Project Guidelines: Security Event & Network Correlation Analysis

## 📌 Project Overview
This project is an automated Security Operations and Correlation Analysis system.
It ingests multi-source logs (Authentication, Firewall/Network, Application Server, Database), normalizes them into a unified JSON format, correlates anomalous activities across time, user, IP path, and sequence into security Incidents, visualizes the attack paths on a Streamlit dashboard, and leverages AI for automated incident briefing, MITRE ATT&CK mapping, and 1-Click remediation playbooks.

## 👥 Module Ownership & Architecture
- `src/collector/` - [Member 1] Ingests and monitors raw logs from files/APIs.
- `src/normalizer/` - [Member 2] Parses raw logs into the standard JSON schema (`data/common_schema.json`), with an AI fallback parser.
- `src/engine/` - [Member 3] Anomaly detection, relationship scoring, correlation engine, and AI briefing/playbook generator.
- `src/dashboard/` - [Member 4] Streamlit interactive UI, attack timeline, network topology, and AI SOC Copilot.

## 📜 Coding Conventions
- Python 3.10+
- Type hints on all public functions.
- Every module must have standalone unit tests in `tests/` and be executable independently with mock fallback data.
- AI modules must gracefully fall back to local rule-based/mock responses when `GEMINI_API_KEY` is not present.
