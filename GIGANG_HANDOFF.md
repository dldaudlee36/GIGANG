# 🛡️ GIGANG (기강) — 프로젝트 핸드오프 마스터 가이드 (Master Handoff Guide)

> **💡 다른 컴퓨터의 Antigravity / AI 세션에서 작업을 이어가는 방법**
> 1. 다른 컴퓨터에서 저장소 코드를 pull 받거나 `CAPSTONE` 폴더를 엽니다.
> 2. Antigravity 채팅창에 **"GIGANG_HANDOFF.md 읽고 작업을 이어서 진행해줘"** 라고 입력합니다.
> 3. 또는 아래 **[Antigravity 마스터 프롬프트 본문]** 블록 전체를 복사하여 새 대화창에 붙여넣으면, AI가 프로젝트 아키텍처, 4대 브랜치 구조, 오늘 완료된 프로토타입 및 세부 기능 보강 내역, 그리고 다음 착수 과제(Streamlit 이식)를 100% 이해하고 즉각 작업을 이어받습니다.

---

```markdown
# 🛡️ 프로젝트 핸드오프: GIGANG (Zero Trust 엔드포인트-DB-웹 상관분석 보안 관제 플랫폼)

안녕하세요! 저는 GIGANG 프로젝트를 개발 및 총괄하고 있는 조원웅입니다.
다른 컴퓨터 환경에서 진행하던 GIGANG의 UI/UX 고도화 및 캡스톤 프로젝트 개발 작업을 이어받아 지원해 주세요.
아래의 프로젝트 배경, 시스템 아키텍처, Git 브랜치 상태, 최근 세션에서 완료된 5대 핵심 작업, 그리고 바로 이어서 착수해야 할 작업 가이드를 숙지해 주시기 바랍니다.

---

## 1. 프로젝트 정체성 & 시스템 아키텍처

* **프로젝트명**: GIGANG (기강, Zero Trust SecOps Platform v3.3)
* **소속**: SKT ALEPH 캡스톤 4조
* **GitHub 원격 저장소**: `https://github.com/dldaudlee36/GIGANG.git`
* **핵심 가치 및 해결 과제**:
  - 사내 기밀 DB에서 대량/민감 데이터를 쿼리한 직후, 외부 미승인 생성형 AI(ChatGPT, Claude, v0 등)나 SaaS로 데이터를 유출(복사·붙여넣기, 파일 첨부)하려는 이상 행위를 실시간 탐지·차단.
  - 이기종 로그(단말 에이전트 + 크롬 확장 프로그램 + 사내 DB 감사 로그)를 정규화(`common_schema.json`)하고, 위험 상태 기계(FSM)와 3-Hop 인과관계 상관분석 엔진, Gemini LLM 거버넌스 평가를 결합하여 오탐 없는 능동 방어 수행.
  - **알람 피로도 해소(Self-Healing)**: 단말기가 WATCH(선제 감시) 상태로 승격되었더라도 30분 동안 추가 유출 행위가 없으면 자동으로 NORMAL 상태로 복귀.

### 4대 핵심 구성요소
1. **GIGANG 단말 에이전트** (`guard/agent/agent.py`): Windows 로컬 서비스, 클립보드 및 프로세스 모니터링
2. **Chrome 확장 프로그램** (`guard/extension/`): `Upload Detector`, 웹 사이트 접속(WEB_ACCESS), 텍스트 붙여넣기(PASTE), 파일 업로드 실시간 탐지 및 브라우저 레벨 차단
3. **상관분석 및 거버넌스 엔진** (`gigang/engine/`):
   - `correlation.py`: 3-Hop 인과관계 상관분석 및 위험 점수(Risk Score) 산출
   - `governance.py`: Gemini 기반 미등록 외부 도메인 위험도 진단 및 브라우저 차단 정책 동기화
4. **통합 관제 대시보드** (`gigang/ui/app.py`): Streamlit 기반 웹 콘솔

---

## 2. GitHub 저장소 및 브랜치 분할 현황

현재 로컬 작업 디렉토리 `D:\Jacob\CAPSTONE\Nexusguard_Git`과 원격 저장소(`https://github.com/dldaudlee36/GIGANG.git`)는 완전히 정돈되어 동기화되어 있습니다.
과거 타 컴퓨터에서 발생했던 파일 꼬임 및 오염 커밋을 완전히 리셋하고, 4대 도메인 기능 브랜치로 분할 배포를 마쳤습니다.

* **`main`**: 프로덕션 배포 브랜치 (최신 상태 동기화 완료)
* **`feat/collector`**: 단말 Windows 에이전트 및 Chrome 브라우저 확장 프로그램 전용 브랜치
* **`feat/engine`**: FSM 상태 기계, 3-Hop 인과관계 상관분석 및 Gemini AI 거버넌스 엔진 브랜치
* **`feat/normalizer`**: 이기종 텔레메트리 로그 표준 스키마(`common_schema.json`) 정규화 브랜치
* **`feat/ui`**: Streamlit 관제 콘솔 및 신규 UI/UX 프로토타입 이식 전용 브랜치

---

## 3. 오늘 세션에서 완료된 5대 핵심 작업 내역

### ① 깃허브 오염 리셋 및 4대 도메인 브랜치 정상화
- 타 컴퓨터에서 무단 업로드되었던 파일들을 로컬의 신뢰할 수 있는 소스로 완전히 덮어쓰기 복구.
- `main`, `feat/collector`, `feat/engine`, `feat/normalizer`, `feat/ui` 브랜치에 각각 도메인별 필수 파일만 깔끔하게 커밋 및 원격 `push --force` 완료.

### ② 기능별 4대 탭 멀티페이지 프로토타입 구축 (`gigang_multipage_candidates.html`)
- 한 화면에 모든 위젯이 빽빽하게 모여있던 구조를 실제 사용자가 직관적으로 탐색할 수 있도록 4대 독립 뷰로 분할:
  1. `종합 관제 (page-overview)`
  2. `킬체인 분석 (page-killchain)`
  3. `AI·IT 거버넌스 (page-governance)`
  4. `중앙 서버 파이프라인 (page-pipeline)`
- **사이드바 접힘/펼침(Collapse/Expand)** 기능 구현 (접힘 시 0px로 축소되고 메인 관제 영역이 가로 100% 전폭으로 부드럽게 확장).
- 사이드바 내 **`⚙️ 파이프라인 상태 모니터링 [● LIVE]`** 실시간 덱 복원.

### ③ 현대적 디자인 스킬 통합 (Apple Pro, Emil Craft, Impeccable)
- 서브픽셀 보더, 다크 글래스모피즘, 고대비 컬러 스케일 적용.
- 상단 4종 테마 스위처 탑재 (`Apple Pro`, `Emil Craft`, `Calm Salk`, `Cyber Matrix`).
- Edge 헤드리스 자동화 스크립트(`capture_multipage.py`, `capture_collapsed.py`)를 구축하여 1680x1050 해상도 스크린샷 자동 생성 체계 완비.

### ④ 원본 Streamlit 코드(`gigang/ui/app.py`, 3,694줄) 대비 100% 세부 기능 전수 보강
- 원본 코드를 전수 분석하여 누락되었던 마이크로 기능을 1:1로 복원:
  - 4대 Bento KPI 카드 및 원형 SVG 카운트다운 링
  - 주간 보안 이벤트 추이(7일 캡슐 바 차트)
  - 인시던트 드롭다운 셀렉터 및 위험도별 아이콘 표기
  - 3-Hop 원형 토폴로지 맵 및 좌우 2열 포렌식(공격 순서 Step 1~3 + 상관분석 근거 체크리스트)
  - 사내 단말 PC·IP별 수집 요약 테이블(`DESKTOP-0F0CMDB`, `DESKTOP-OLI` 등)
  - 다차원 필터링 셀렉트박스(로컬 IP별, 이벤트 종류별) 및 정규화 감사 로그 테이블

### ⑤ 관제 실무(SOC) & 디자인 평가표 기반 군더더기 다이어트 및 레이아웃 최적화
- **B2C 잡음 제거**: `Good Morning...` 인사말 및 대형 시계를 1줄 초슬림 **SOC 상태 바**(`● LIVE OPERATIONAL / 동기화: 14:28:30 KST`)로 교체하여 상단 80px 확보.
- **지표 위계 정상화**: 4번째 KPI 카드를 개인 타이머 대신 **`🛡️ 전사 정책 방어율 (98.2%)`** 거시 지표로 통일하고, 개인 18:42 카운트다운은 WATCH 배너 안으로 이동.
- **트리아지(Triage) 최우선 배치**: 실시간 대응이 핵심인 **`🎯 우선 대응 인시던트 선택`을 KPI 바로 아래 상단으로 전진 배치**하고, 사후 보고용 주간 차트는 하단으로 이동.
- **시각 피로(크리스마스 트리 효과) 차단**: 킬체인 맵 외부 SaaS 노드의 무한 붉은 펄스 점멸을 정적 고대비 적색 테두리 & `[유출 차단]` 뱃지로 정돈.
- **보안 및 오조작 방지 모달 분리**:
  - 사이드바 내비게이션을 어지럽히던 API Key 입력창을 하단 **`⚙️ 엔진 연동 환경설정` 모달 다이얼로그**로 격리.
  - 거버넌스 테이블의 차단 토글에 **2차 안전 확인 모달 다이얼로그(`confirmModal`)** 연동.
  - 파이프라인 조회 화면에서 실수로 수집을 꺼버릴 위험이 있던 상단 On/Off 스위치를 안전 상태 뱃지로 변경.

---

## 4. 파일 시스템 및 프로토타입 산출물 위치

```text
D:\Jacob\CAPSTONE\
├── GIGANG_HANDOFF.md                  # 본 인수인계 마스터 문서
├── ADMIN_START.bat                    # 관리자 대시보드(Streamlit:8501) 실행 배치
├── ADMIN_STOP.bat                     # 포트 8501 점유 프로세스 종료 배치
├── USER_START.bat                     # 사용자 단말 에이전트(8765) 실행 배치
├── USER_STOP.bat                      # 포트 8765 점유 프로세스 종료 배치
│
├── prototypes/                        # [중요] 최신 HTML/CSS/JS 프로토타입 산출물
│   ├── gigang_multipage_candidates.html # ★ 관제 최적화가 100% 반영된 마스터 인터랙티브 프로토타입
│   ├── page_1_overview.html / .png     # 종합 관제 뷰 (트리아지 최우선 + 슬림 SOC 상태바)
│   ├── page_1_overview_collapsed.html / .png # 종합 관제 사이드바 0px 접힘 뷰
│   ├── page_2_killchain.html / .png    # 킬체인 분석 뷰 (피로 없는 3-Hop 원형 맵 + 2열 포렌식)
│   ├── page_3_governance.html / .png   # 거버넌스 뷰 (1줄 압축 배너 + 안전 확인 모달 토글)
│   ├── page_4_pipeline.html / .png     # 파이프라인 뷰 (안전 상태바 + PC·IP별 수집 현황 + 필터)
│   ├── capture_multipage.py           # Edge headless 4개 페이지 일괄 캡처 스크립트
│   └── capture_collapsed.py           # 사이드바 접힘 캡처 스크립트
│
├── Nexusguard_Git/                    # GIGANG Git 로컬 저장소 (동기화 완료)
│   ├── gigang/
│   │   ├── ui/
│   │   │   ├── app.py                 # Streamlit 관제 메인 앱 (3,694줄 - 차기 수정 타깃)
│   │   │   └── site_access.py
│   │   ├── engine/                    # 상관분석 및 거버넌스 엔진
│   │   ├── collectors/                # Railway 수집기 및 팀 로그 연동 모듈
│   │   ├── normalizers/               # 로그 스키마 정규화 모듈
│   │   └── schemas/
│   └── docs/                          # 프로젝트 문서 및 매뉴얼
│
└── gigang_sim_test/                   # 로컬 시뮬레이션 및 비공개 학습 문서 보관소
    ├── GIGANG_학습지.md               # [비공개] 팀 학습 및 개념 정리 문서 (GitHub 푸시 절대 금지)
    └── GIGANG_향후_개선방안.md        # [비공개] 아이디어 및 향후 로드맵 (GitHub 푸시 절대 금지)
```

---

## 5. [절대 준수] 보안 및 비공개 파일 관리 규칙

* **절대 원격 GitHub에 푸시 금지**:
  - `GIGANG_학습지.md`
  - `GIGANG_향후_개선방안.md`
  - 위 파일들은 로컬 전용 문서로, 저장소의 `.git/info/exclude`에 등록되어 있어야 하며 원격 저장소에 절대 노출되어서는 안 됩니다.
* **환경변수 및 인증정보**:
  - `GEMINI_API_KEY`, `RAILWAY_API_KEY` 등은 `.env` 파일로 관리되며 Git 추적에서 제외되어 있습니다.

---

## 6. 바로 이어서 진행할 작업 (Next Action Steps)

새 세션을 시작하면 다음 단계부터 작업을 진행해 주세요:

1. **프로토타입 확인**:
   - `D:\Jacob\CAPSTONE\prototypes\gigang_multipage_candidates.html`의 완성된 HTML/CSS/JS 구조를 확인합니다.
2. **Streamlit 프로덕션 코드 이식 (`gigang/ui/app.py`)**:
   - 현재 브랜치를 `feat/ui`로 전환합니다 (`git checkout feat/ui`).
   - `gigang_multipage_candidates.html`에서 확정된 디자인 및 레이아웃을 `gigang/ui/app.py`에 이식합니다:
     - **사이드바**: 사이드바 접힘 애니메이션 지원 및 `🔑 Gemini AI 설정`을 하단 모달/팝오버로 분리
     - **Page 1 (종합 관제)**: 상단 웰컴 배너를 1줄 SOC 상태 바로 교체, 4번째 KPI를 `전사 정책 방어율(98.2%)`로 변경, 우선 대응 인시던트를 상단으로 전진 배치
     - **Page 2 (킬체인)**: 무한 펄스 제거 및 정적 고대비 원형 3-Hop 맵 유지, 상단 서머리 일체형 통합
     - **Page 3 (거버넌스)**: 1줄 상태 바 압축 및 차단 토글 실행 시 2차 안전 확인 다이얼로그 추가
     - **Page 4 (파이프라인)**: 상단 수집 제어 스위치 제거(안전 뱃지화) 및 PC·IP별 수집 현황 테이블 가독성 강화
3. **로컬 실행 및 검증**:
   - `streamlit run gigang/ui/app.py` 또는 `ADMIN_START.bat`을 실행하여 브라우저(`http://localhost:8501`)에서 실제 스트림릿 렌더링을 확인합니다.
4. **Git 커밋 및 `main` 병합**:
   - `feat/ui` 브랜치에 커밋 후 원격 푸시, 이후 `main` 브랜치에 PR/Merge를 진행합니다.
```
