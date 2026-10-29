# 🗄️ GIGANG — Data Normalizer, Storage & Cloud Ingestion (정규화 및 스토리지 모듈)

> **팀원 2 담당 도메인**: 이기종 텔레메트리 표준 스키마 정규화, SQLite/Memory 영구 스토리지, 모의 로그 생성기 및 Railway 중앙 인제스천 서버

이 브랜치는 **GIGANG (기강)** 보안 관제 플랫폼의 2계층 데이터 파이프라인 전용 브랜치입니다.  
Chrome 확장 프로그램, Windows 에이전트, DB 감사 로그 등 다양한 포맷의 이기종 로그를 표준 JSON 스키마(`common_schema.json`)로 정규화하고 중앙 DB에 적재합니다.

---

## 📁 디렉터리 구성

```text
GIGANG (feat/normalizer)/
├── gigang/
│   ├── schemas/                       # 공통 보안 이벤트 및 인시던트 데이터 모델
│   │   ├── event.py                   # SecurityEvent, LogSource, EventAction, Actor, Target 모델
│   │   └── incident.py                # Incident, RiskLevel, KillchainHop, ForensicStep 모델
│   │
│   ├── storage/                       # 텔레메트리 및 캐시 영구 저장소
│   │   ├── sqlite_store.py            # SQLite 기반 이벤트, 인시던트 및 Shadow AI 캐시 스토어
│   │   └── memory_store.py            # 고속 실시간 상관분석용 인메모리 링 버퍼
│   │
│   └── generators/                    # 모의 시뮬레이션 및 데이터 테스트
│       └── dummy_logs.py              # 4대 이기종(Firewall, DNS, Auth, DB) 모의 이벤트 생성기
│
├── source/railway_server/             # Railway 클라우드 배포용 중앙 인제스천 서버
│   ├── Dockerfile                     # 클라우드 컨테이너 빌드 명세
│   ├── app.py                         # FastAPI 기반 실시간 이벤트 수집 및 정책 배포 API
│   ├── policy_tables.sql              # 부서별 보안 정책 및 접근 제어 DDL
│   ├── site_access.py                 # 전사 도메인 차단 정책 관리
│   └── requirements.txt               # 서버 구동용 라이브러리 목록
│
├── data/                              # 샘플 감사 로그 및 로컬 런타임 데이터
│   ├── activity.log                   # 실시간 텔레메트리 스트림 샘플
│   └── mysql_audit_log.csv            # 사내 고객 기밀 DB(MySQL) 조회 감사 로그
│
├── test_rules.py                      # 5개 데이터 수집 정규화 규칙 단위 테스트
├── test_download.py                   # 대용량 기밀 DB 다운로드 로그 검증
├── requirements.txt                   # 스토리지 및 서버 필수 라이브러리 목록
└── VERSION.txt                        # 정규화 파이프라인 버전 명세서
```

---

## ⚡ 빠른 실행 및 검증 (Quick Start)

### 1. 로그 정규화 규칙 단위 테스트
```bash
python test_rules.py
```

### 2. 기밀 DB 다운로드 스트림 파싱 테스트
```bash
python test_download.py
```

### 3. Railway 중앙 인제스천 서버 로컬 구동 (선택)
```bash
cd source/railway_server
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```
