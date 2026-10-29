# 📊 GIGANG — SecOps Dashboard, Terminal & Prototypes (통합 관제 콘솔 모듈)

> **팀원 4 담당 도메인**: Streamlit 기반 통합 보안관제(SecOps) 콘솔, Neo-Tactical Cyber OS Terminal 및 반응형 멀티페이지 프로토타입

이 브랜치는 **GIGANG (기강)** 보안 관제 플랫폼의 3계층(Tier 3) 프론트엔드 관제 UI 전용 브랜치입니다.  
보안 관제 요원(SOC)이 사내 실시간 위협 현황, 3-Hop 공격 킬체인 토폴로지, Shadow AI 거버넌스 및 중앙 텔레메트리 파이프라인을 직관적으로 관제하고 1-Click 격리 대응을 수행할 수 있도록 지원합니다.

---

## 📁 디렉터리 구성

```text
GIGANG (feat/ui)/
├── app.py                             # Streamlit Cloud 호환 루트 엔트리포인트
├── gigang/
│   └── ui/                            # Streamlit 대시보드 프로덕션 컴포넌트
│       ├── app.py                     # 통합 관제 콘솔 메인 애플리케이션 (Bento KPI, 3-Hop 시각화)
│       └── site_access.py             # 관리자 화면 내 사이트 접속 제어 UI 렌더러
│
├── prototypes/                        # 신규 UI/UX 다각화 시안 및 독립 프로토타입
│   ├── gigang_multipage_candidates.html # ★ 4대 핵심 탭 반응형 멀티페이지 마스터 프로토타입
│   ├── gigang_data_terminal.html      # Neo-Tactical 다크 테크니컬 터미널 뷰
│   ├── gigang_5themes_prototype.html  # 5대 테마 인터랙티브 스위처 (Apple, Emil, Matrix 등)
│   └── gigang_multipage_candidates_orig.html # 이전 원본 후보 시안
│
├── GIGANG_Data_Terminal_Beta.html     # 의존성 없는 독립 브라우저 구동형 Cyber OS 관제 터미널
├── screenshots/                       # 고해상도 대시보드 실화면 증적 캡처 (7종)
│
├── run-dashboard.bat                  # Streamlit 관제 대시보드 원클릭 실행 배치
├── run_beta_terminal.bat              # Cyber OS 관제 터미널 원클릭 실행 배치
├── ADMIN_START.bat                    # 관리자 대시보드 백그라운드 구동 배치 (포트 8501)
├── ADMIN_STOP.bat                     # 관리자 대시보드 프로세스 종료 배치
├── tools/                             # 런타임 제어 툴킷 (launch, stop, lifecycle)
├── requirements.txt                   # 대시보드 실행 필수 파이썬 라이브러리 (Streamlit 등)
└── VERSION.txt                        # UI 서브시스템 버전 명세서
```

---

## ⚡ 빠른 실행 및 검증 (Quick Start)

### 1. Streamlit 관제 대시보드 실행
```cmd
run-dashboard.bat
```
- 브라우저에서 자동으로 `http://localhost:8501`이 열리며 통합 관제 콘솔이 구동됩니다.
- 또는 백그라운드 서비스 형태로 실행 시 `ADMIN_START.bat`을 실행합니다.

### 2. Standalone Cyber OS Terminal 실행
```cmd
run_beta_terminal.bat
```
- 파이썬/서버 의존성 없이 즉시 브라우저에서 `GIGANG_Data_Terminal_Beta.html` 터미널이 로드됩니다.

### 3. 멀티페이지 프로토타입 프리뷰
- `prototypes/gigang_multipage_candidates.html` 파일을 브라우저로 열면 4대 탭(종합 관제, 킬체인, 거버넌스, 파이프라인)의 반응형 레이아웃 및 사이드바 0px 접힘 기능을 직접 체험할 수 있습니다.
