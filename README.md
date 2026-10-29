# 🧠 GIGANG — Context-Aware Correlation Engine & Governance (상관분석 & 거버넌스 엔진)

> **팀원 3 담당 도메인**: 3-Hop 인과관계 상관분석 FSM, 부서별 보안 정책 매트릭스, Gemini AI 거버넌스 및 OCR Guard

이 브랜치는 **GIGANG (기강)** 보안 관제 플랫폼의 2계층(Tier 2) 핵심 두뇌 모듈 전용 브랜치입니다.  
이기종 텔레메트리 이벤트를 수집받아 시간창(Time-Window) 상관관계를 분석하고, 3단계 동적 위험 상태 기계(NORMAL ➔ WATCH ➔ HIGH ➔ Self-Healing)를 연산합니다.

---

## 📁 디렉터리 구성

```text
GIGANG (feat/engine)/
├── gigang/
│   └── engine/                        # 동적 상관분석 및 위협 대응 엔진
│       ├── correlation.py             # 3-Hop 인과관계 상관분석 FSM & Self-Healing (자가 치유)
│       ├── policy.py                  # 부서별 탐지 정책 및 민감 패턴 가중치 판정 (CS, HR, FIN, DEV)
│       ├── department_policy.json     # 부서별 기본 보안 정책 임시값 (Offline Fallback)
│       ├── governance.py              # Shadow AI 비인가 도메인 진단 & Gemini LLM Copilot 연동
│       ├── respond.py                 # 위협 인시던트 티켓 발행 & SOAR 긴급 차단 연동
│       └── live_sync.py               # Railway 클라우드 정책 실시간 동기화
│
├── tests_image_guard/                 # 광학 문자 인식(OCR) 시각 유출 차단 테스트 스위트
│   ├── ocr_fixture.jpg / .png         # 사내 기밀 DB 화면 캡처 모의 샘플 이미지
│   ├── ocr_fixture_result.json        # OCR 추출 기준값 검증 명세
│   ├── test_image_ocr.py              # 로컬 Tesseract OCR 추출 성능 검증
│   ├── test_image_match.cjs           # 클립보드 이미지 해시 일치 판정 테스트
│   ├── test_image_interception.cjs    # 브라우저 드래그앤드롭 차단 연동 테스트
│   ├── test_image_risk.py             # 이미지 내 민감정보 위험도 가산 로직 검증
│   └── test_image_api.py              # 로컬 에이전트 간 OCR API 프로토콜 검증
│
├── test_policy.py                     # 28개 부서 정책 및 60분 누적 누적 시간창 전수 테스트
├── test_paste.py                      # 클립보드 붙여넣기 및 FSM 상태 전이 검증
├── test_dedup.py                      # 이벤트 중복 유입 시 디바운싱 방어 검증
├── test_image_paste.py                # 이미지 붙여넣기 FSM 전이 검증
├── test_pattern_falsepositive.js      # 주민번호/카드번호 정규식 오탐·미탐 정밀 검증
├── run_demo.py                        # E2E 파이프라인 무결성 모의 검증 시뮬레이터
├── compare_engines.py                 # FSM 상관분석 엔진 벤치마크
├── runtime/blocked_domains.json       # 실시간 격리 도메인 동기화 런타임 저장소
├── requirements.txt                   # 엔진 전용 필수 파이썬 의존성 패키지
└── VERSION.txt                        # 엔진 시스템 버전 명세서
```

---

## ⚡ 빠른 실행 및 검증 (Quick Start)

### 1. 부서별 탐지 정책 전수 검증
```bash
python test_policy.py
```
- CS, HR, 재무, 개발 부서의 28개 세부 시나리오 및 60분 시간창 누적 위험도가 정상 통과하는지 검증합니다.

### 2. 이벤트 디바운싱 및 상태 머신 검증
```bash
python test_dedup.py
python test_paste.py
```

### 3. OCR 시각 유출 차단 검증
```bash
python -m unittest discover tests_image_guard
```
