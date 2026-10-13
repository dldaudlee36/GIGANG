# 🛡️ 보안 이벤트·네트워크 상관분석 & AI SecOps 대시보드

> **이 기종 보안 로그(인증·서버·DB·방화벽)를 실시간 자동 수집·정규화하고, 시간·계정·IP 홉 경로를 기준으로 상관분석(Correlation)하여 단일 침해사고(Incident)로 재구성한 뒤, GenAI 기반 공격 브리핑 및 1-Click 자동 대응(SOAR)을 제공하는 지능형 보안관제 시스템**

---

## 📂 프로젝트 구조 및 팀원별 분장

```text
goofy-hawking/
├── docs/                      # 원본 기획서 및 아키텍처/화면 다이어그램 (v0.4)
├── data/
│   ├── common_schema.json     # [핵심 규격] 로그 및 Incident 공통 JSON 스키마
│   ├── mock_incidents.json    # 대시보드 및 엔진 테스트용 풍부한 Mock 침해사고 데이터
│   └── raw_logs/              # 원본 샘플 로그 (auth, firewall, server, db)
├── src/
│   ├── collector/             # [팀원 1] watcher.py - 로그 파일 감시 및 모의 공격 스트림 생성기
│   ├── normalizer/            # [팀원 2] parsers.py - 정규식 파서 및 AI Fallback 정규화 모듈
│   ├── engine/                # [팀원 3] correlator.py (상관분석 엔진) & ai_agent.py (AI 분석/플레이북/Copilot)
│   └── dashboard/             # [팀원 4] app.py - Streamlit 대시보드 (KPI, 타임라인, 네트워크 맵, AI Copilot)
├── tests/
│   └── test_pipeline.py       # E2E 파이프라인 통합 테스트
├── requirements.txt           # 프로젝트 의존성 목록
└── README.md
```

---

## 🤖 구현된 AI 자동화 핵심 기능

1. **AI 침해사고 자동 브리핑**: 묶인 다단계 로그를 분석하여 공격 시나리오를 자연어 요약문으로 자동 생성.
2. **MITRE ATT&CK 자동 맵핑**: Initial Access(T1110/T1078), Lateral Movement(T1021), Exfiltration(T1041) 기법 자동 태깅.
3. **AI 초동 대응 플레이북 (SOAR) & 1-Click 실행**: 방화벽 차단(`iptables`), 계정 격리(`usermod/pkill`), DB 세션 킬 명령을 자동 생성하고 대시보드에서 1-Click 실행.
4. **대화형 AI 보안 분석관 (SOC Copilot)**: 사건 데이터 맥락을 바탕으로 보안 분석관의 질문(피해 규모, 특정 쿼리, 보고서 작성 등)에 실시간 응답.

---

## 🚀 빠른 시작 가이드

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. Streamlit 대시보드 실행
```bash
streamlit run src/dashboard/app.py
```
브라우저에서 `http://localhost:8501` 접속 후 대시보드 확인.

### 3. 파이프라인 단위 테스트 실행
```bash
python tests/test_pipeline.py
```

### 4. (선택) Google Gemini API Key 설정
Gemini API 키가 없어도 **자체 탑재된 고도화 Mock 엔진**으로 모든 기능(요약, 플레이북, Copilot)이 정상 작동합니다. 실시간 라이브 LLM을 연동하려면 환경변수를 설정하세요:
```bash
export GEMINI_API_KEY="your_api_key_here"   # Linux / macOS
$env:GEMINI_API_KEY="your_api_key_here"     # Windows PowerShell
```

---

## 👥 4명 역할별 첫날 독립 개발 가이드

* **① 인프라 & 로그 수집**: `src/collector/watcher.py`를 실행하여 `data/raw_logs/` 디렉터리에 실시간 로그 스트림을 주입하는 테스트 수행.
* **② 로그 파싱 & 정규화**: `src/normalizer/parsers.py`에서 새로운 로그 포맷(Nginx, Apache, Windows Event 등) 정규식 추가.
* **③ 상관분석 & AI 엔진**: `src/engine/correlator.py`의 시간 윈도우/가중치 점수 튜닝 및 `src/engine/ai_agent.py`의 프롬프트 고도화.
* **④ 웹 대시보드 UI**: `src/dashboard/app.py`를 실행하며 그래프 레이아웃 및 알림 UI 커스터마이징.
