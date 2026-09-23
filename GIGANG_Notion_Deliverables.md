# 🛡️ D조 GIGANG (기강) — 최종 산출물 (Notion 업로드용 종합 패키지)

> **💡 Notion 사용 팁**:  
> 본 문서의 각 섹션 내용을 노션의 **'산출물'** 페이지 해당 블록에 그대로 복사(`Ctrl + C`)하여 붙여넣기(`Ctrl + V`)하시면 서식(제목, 콜아웃, 표, 코드 블록, 토글)이 완벽하게 적용됩니다.

---

# 1. 필수 제출물

### 📄 프로젝트 계획서
* **제출 형태**: 파일 업로드 (`GIGANG_Notion_Proposal.md` 또는 PDF 변환본)
* **요약 내용**:
  * **프로젝트명**: GIGANG (Zero Trust 기반 이기종 로그 상관분석 & 섀도우 AI 거버넌스 플랫폼)
  * **기획 배경**: 기존 SIEM의 사후 대응 한계 및 무조건적 망분리로 인한 업무 마비 극복
  * **핵심 혁신**: DB 조회와 외부 AI 사이트 접속을 엮는 **2단계 위험 상태 기계(Risk State Machine: NORMAL ➔ WATCH ➔ HIGH)** 도입
  * **추진 일정**: 6주 WBS (기획 ➔ 스키마 ➔ 에이전트/엔진 ➔ 실시간 DB 연동 ➔ AI SOAR ➔ 최종 데모)

---

### 🎥 시연 영상
* **제출 형태**: 시연 영상 파일 업로드 또는 유튜브/구글 드라이브 링크 임베드
* **시연 영상 핵심 시나리오 (3분 킬체인 라이브 데모)**:
  * **00:00 ~ 00:40 [정상 관제]**: 단말 에이전트 구동 및 평온한 정상 상태 (`NORMAL`, 위험도 15점)
  * **00:41 ~ 01:20 [선제 감시 발동]**: 마케팅 김대리가 사내 DB에서 고객 2.4만 건 조회 직후 `chatgpt.com` 접속 ➔ GIGANG가 사전 유출 위험 포착하여 **`WATCH` (위험도 68점) 선제 승격**
  * **01:21 ~ 02:10 [유출 확정 및 경보]**: 클립보드에 복사된 대량 고객 데이터를 프롬프트에 붙여넣어 외부 전송 ➔ 즉시 **`HIGH` (위험도 95점) 인시던트 확정**
  * **02:11 ~ 03:00 [AI 자동 대응]**: Google Gemini Flash (Google Cloud API)가 침해 사고 5줄 요약 브리핑 및 MITRE ATT&CK 매핑 ➔ 관제사 **1-Click 방화벽 차단 & 단말 격리 플레이북** 실행

---

### 📊 발표 자료
* **제출 형태**: 발표 슬라이드 PPT/PDF 파일 업로드
* **발표 자료 12장 슬라이드 구성안 (Pitch Deck Structure)**:
  1. **표지**: GIGANG — 무너진 사내 보안 기강을 바로잡는 실시간 상관분석 & Shadow AI 거버넌스
  2. **문제 정의 (Problem)**: 사후 약방문식 기존 SIEM vs 업무를 마비시키는 DLP/망분리의 딜레마
  3. **핵심 솔루션 (Solution)**: DB 감사 로그와 웹/DNS 로그를 교차 검증하는 2단계 위험 상태 기계
  4. **시스템 아키텍처 (Architecture)**: 수집(Agent/Tailscale/Railway) ➔ 정규화(Unified JSON) ➔ 엔진(상관분석) ➔ 대시보드(Streamlit+Gemini)
  5. **핵심 기술 ① 실시간 이기종 수집**: MySQL 2.4만 건 감사 API 및 Windows/Chrome 감사 에이전트
  6. **핵심 기술 ② 2단계 상관분석 모델**: NORMAL ➔ WATCH (선제 감시 68점) ➔ HIGH (유출 확정 95점) ➔ Self-Healing (자동 치유)
  7. **핵심 기술 ③ AI 기반 SOAR 연동**: Google Gemini Flash 브리핑, MITRE ATT&CK 매핑, 1-Click Zero Trust 격리
  8. **라이브 시연 (Live Demo)**: 공격자 PC 화면 vs 보안관제 대시보드 동시 시연
  9. **오탐 방지 및 안정성 검증**: 중복 수집 방지(Dedup), 타임스탬프 필터링, 네트워크 장애 페일오버
  10. **비즈니스 기대효과**: 침해 사고 초기 감지 골든타임 85% 단축, 관제 피로도 70% 감소
  11. **팀 소개 및 R&R**: 4인 4색 풀스택 보안 엔지니어링 협업 과정
  12. **Q&A 및 최종 결언**

---

# 2. 추가 산출물

### 🌐 웹/앱 서비스
* **배포 URL**: 
  * 관제 대시보드: `https://gigang-aleph.streamlit.app/`
  * 사내 DB 감사 연동 뷰어: `https://desktop-oli.tail2bbbea.ts.net/viewer`
  * GitHub 공식 저장소: `https://github.com/dldaudlee36/GIGANG_SIM_TEST`
* **주요 기능**:
  * **다기종 로그 실시간 수집 및 Unified JSON 표준 정규화**: 사내 DB, Windows 단말 이벤트, Chrome 웹 트래픽을 단일 공통 스키마로 통합 변환
  * **2단계 위험 상태 머신 기반 엔드투엔드 상관분석**: 기밀 DB 조회 + 비인가 AI 접속 시 `WATCH` 선제 감시, 데이터 전송 발생 시 `HIGH` 즉시 인시던트 승격
  * **자가 치유(Self-Healing) 오탐 자동 해제**: 30분 동안 추가 반출 시도가 없을 경우 관제 피로도 경감을 위해 `NORMAL`로 안전 복귀
  * **Google Gemini AI 관제 코파일럿**: 복합 침해사고의 원인·영향도 5줄 브리핑 및 MITRE ATT&CK 기법 자동 분류
  * **1-Click Zero Trust SOAR 플레이북**: 이상 징후 단말 네트워크 격리, 침해 계정 세션 즉시 만료 및 방화벽 차단 스크립트 실행

---

### 📑 기술 문서
* **공식 GitHub 저장소**: `https://github.com/dldaudlee36/GIGANG_SIM_TEST`
* **설치/실행 가이드**: `https://github.com/dldaudlee36/GIGANG_SIM_TEST#quick-start`
  * Python 3.10+ 가상환경 세팅 및 `pip install -r requirements.txt`
  * 환경변수 파일 `.env` 구성 (`GEMINI_API_KEY`, `DB_LOG_API_URL`)
  * `streamlit run app.py`를 통한 올인원 관제 대시보드 구동
* **기술 스택**:
  * **Frontend / UI**: Streamlit, Plotly Express, Custom CSS3 Glassmorphism Bento 테마
  * **Backend / Engine**: Python 3.10+, SQLite3, 2단계 위험 상태 기계(Risk State Machine)
  * **Agent & Collector**: Windows 에이전트(`GIGANGAgent.exe`), Chrome Extension(Manifest v3), Railway 중앙 수집 서버
  * **AI & LLM**: Google Gemini Flash (Google Cloud API), MITRE ATT&CK v14 Knowledge Base
  * **Database & Infra**: MySQL 8.0 (`customer_vault` 24,500 rows), Tailscale P2P, Railway Cloud

---

### 🎨 디자인 문서
* **UI/UX 디자인**: 
  * **설계 컨셉**: SOC 보안 관제 최적화 16:9 와이드 다크 글래스모피즘 (`#0E1117`), Bento Grid 레이아웃 (4대 KPI ➔ 파이프라인 모니터링 ➔ 킬체인 타임라인 ➔ Gemini AI 거버넌스 패널)
* **브랜딩 가이드**:
  * **심볼마크 컨셉**: **GIGANG (G)** + **방패 (Zero Trust 방어)** + **네트워크 상관 노드 (Data Correlation)**의 융합
  * **컬러 팔레트**:
    * 🔴 **Cyber Crimson** (`#FF3B30`): CRITICAL / HIGH 침해 사고 및 차단 경보
    * 🟡 **Alert Amber** (`#FF9500`): WATCH 사전 선제 감시 상태
    * 🟢 **Safe Emerald** (`#34C759`): NORMAL 정상 동작 및 복구 완료
    * 🟣 **Deep Purple** (`#6C5CE7`): Gemini AI 코파일럿 및 스마트 분석
    * ⚫ **Dark SOC Gray** (`#0E1117` / `#161B22`): 관제 집중도 극대화를 위한 다크 배경
  * **타이포그래피**: 국문/영문 본문 `Pretendard`, 시스템 로그/IP/쿼리 `JetBrains Mono`

---

# 3. 기타 자료

### 👥 팀 소개서
* **팀명**: D조 — GIGANG (사내 보안의 기강을 세우다)
* **팀원 구성 및 R&R**:
  * **팀원 4 (팀장 / Dashboard & PM)**: 대시보드 UI/UX 구현, 시스템 통합, 일정 관리 및 라이브 데모 총괄
  * **팀원 1 (Collector)**: Windows 단말 감사 에이전트 및 Chrome Extension v3.1 수집 파이프라인 개발
  * **팀원 2 (Normalizer)**: Unified JSON 데이터 정규화 스키마 설계 및 이기종 파서 구현
  * **팀원 3 (Engine & AI)**: 2단계 상태 머신 상관분석 엔진 구현 및 Gemini Flash SOAR 플레이북 연동

---

### 📅 개발 일지
* **문서 링크**: `GIGANG_Meeting_Minutes_Notion.md` (프로젝트 내 1차~6차 전체 회의록 및 주차별 WBS 기록)
* **마일스톤 진행 요약**:
  * 1주차: 프로젝트 기획 및 위협 모델링 확정 (아이디어 융합)
  * 2주차: 통합 시스템 아키텍처 및 Unified JSON 스키마 설계
  * 3주차: 단말 에이전트 및 2단계 상관분석 엔진 1차 개발
  * 4주차: 사내 MySQL 2.4만 건 연동 및 Tailscale Funnel 고정 터널 구축
  * 5주차: 통합 킬체인 시나리오 검증 및 Gemini SOAR 자동화 고도화
  * 6주차: 라이브 데모 리허설, 화면 분할 시연 준비 및 최종 산출물 패키징

---

### 📚 참고 자료 모음
* **SKT ALEPH 5개 과목 연계 체계도**: 리눅스/서버, 네트워크, 데이터베이스, 정보보안, 파이썬 프로그래밍 전 과목 융합 적용
* **MITRE ATT&CK for Enterprise**:
  * T1078 (Valid Accounts) — 유효 계정 악용
  * T1059 (Command and Scripting Interpreter) — 내부 감사 쿼리 실행
  * T1567 (Exfiltration Over Web Service) — 미승인 외부 AI 서비스를 통한 데이터 반출
* **보안 표준 및 규제**:
  * OWASP Top 10 for LLM (LLM06: 민감 정보 유출 방지 거버넌스)
  * 개인정보보호법 및 금융보안원 침해사고 대응 가이드라인
