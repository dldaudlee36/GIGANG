# 🛡️ GIGANG — Endpoint Agent & Browser Extension (수집기 모듈)

> **팀원 1 담당 도메인**: Windows 단말 에이전트, Chrome 브라우저 확장 프로그램 및 텔레메트리 수집기

이 브랜치는 **GIGANG (기강)** 보안 관제 플랫폼의 1계층(Tier 1) 수집 센서 전용 브랜치입니다.  
사용자 PC 단말에서 발생하는 클립보드 복사, 화면 캡처, 외부 SaaS 웹 접속 및 파일 첨부/붙여넣기 행위를 실시간으로 감지하고 메타데이터를 추출합니다.

---

## 📁 디렉터리 구성

```text
GIGANG (feat/collector)/
├── guard/
│   ├── agent/                         # Windows 단말 상주 감시 에이전트
│   │   ├── agent.py                   # 로컬 HTTP 서비스 (포트 8765) & DNS 폴링
│   │   ├── clipboard_watch.py         # 실시간 클립보드 텍스트/이미지 변경 감지
│   │   ├── image_ocr.py               # Tesseract OCR 기반 기밀 DB 화면 매칭
│   │   ├── rules.py                   # 민감 정보 패턴 정규식 스캐너 (PC 로컬 내 처리)
│   │   ├── files.py                   # 첨부 파일 메타데이터 검사기
│   │   ├── link_metadata.py           # 외부 AI 도메인 링크 메타데이터 파서
│   │   ├── site_access.py             # hosts 파일 기반 비인가 사이트 능동 격리
│   │   └── lifecycle.py               # 에이전트 구동 및 상태 관리
│   │
│   └── browser_extension/             # Chrome 브라우저 확장 프로그램 (Manifest V3)
│       ├── manifest.json              # MV3 매니페스트 설정
│       ├── background.js              # 서비스 워커 (웹 이벤트 디바운싱 & 단말 에이전트 전달)
│       ├── content.js                 # 웹 폼 붙여넣기(PASTE) 및 드래그앤드롭(D&D) 후킹
│       ├── popup.html & popup.js      # 단말 센서 연동 상태 확인 팝업 UI
│       ├── blocked.html & blocked.js  # 관리자 차단 시 표시되는 경고 및 차단 화면
│       ├── matching.js & blocking.js  # 실시간 패턴 매칭 및 폼 입력 차단
│       └── image_match.js             # 이미지 붙여넣기 감지 모듈
│
├── gigang/
│   └── collectors/                    # 중앙 클라우드 수집기 연동
│       └── team_collector.py          # Railway/FastAPI 수집 서버 이벤트 풀링
│
├── tools/                             # 단말 실행/종료 프로세스 제어 툴킷
│   ├── launch.py                      # UAC 관리자 권한 에이전트 실행 오케스트레이터
│   ├── stop.py                        # 에이전트 안전 종료 및 hosts 복원
│   └── lifecycle.py                   # 단말 서비스 수명주기 상태 머신
│
├── USER_START.bat                     # 사용자 단말 에이전트 원클릭 실행 배치
├── USER_STOP.bat                      # 사용자 단말 에이전트 원클릭 종료 배치
├── 실행방법.txt                        # 에이전트 및 확장 프로그램 설치/구동 가이드
├── test_clipboard.py                  # 클립보드 감시 및 민감 패턴 탐지 검증
├── test_screenshot.py                 # PrintScreen 화면 캡처 감지 검증
├── requirements.txt                   # 에이전트 전용 필수 파이썬 라이브러리
└── VERSION.txt                        # 단말 센서 버전 명세서
```

---

## ⚡ 빠른 실행 및 검증 (Quick Start)

### 1. 단말 에이전트 실행
```cmd
USER_START.bat
```
- Windows 관리자 권한(UAC) 요청을 승인하면 백그라운드에서 `127.0.0.1:8765` 로컬 서비스가 구동됩니다.
- 종료 시 `USER_STOP.bat`을 실행하면 잔여 프로세스 정리 및 네트워크 hosts 차단이 안전하게 해제됩니다.

### 2. Chrome 브라우저 확장 프로그램 로드
1. Chrome 주소창에 `chrome://extensions/` 입력
2. 우측 상단 **[개발자 모드]** 활성화
3. **[압축해제된 확장 프로그램을 로드합니다]** 클릭 후 `guard/browser_extension` 폴더 선택

### 3. 센서 동작 검증 테스트
```bash
python test_clipboard.py
python test_screenshot.py
```
- 민감 정보(주민번호, 카드번호, 전화번호) 복사 시 본문 원본 전송 없이 **패턴 건수(Count)**만 에이전트에 기록되는지 확인합니다.
