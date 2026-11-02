# GIGANG 프로젝트 인수인계 및 작업 연속 가이드 (Handoff Prompt)

> **💡 다른 컴퓨터의 Antigravity 또는 새로운 대화 세션에서 사용하는 방법**
> 1. 새 컴퓨터 또는 새 창에서 `git clone https://github.com/dldaudlee36/GIGANG.git` 을 수행하거나 최신 `main` 브랜치를 `git pull` 합니다.
> 2. Antigravity 채팅창에 아래 **[Antigravity 프롬프트 본문]** 코드 블록 전체를 복사하여 입력합니다.

---

## 📋 [Antigravity 프롬프트 본문]

```markdown
GitHub 원격 저장소 https://github.com/dldaudlee36/GIGANG (main 브랜치, commit ade9ce9 기준)의 최신 구조와 인수인계 맥락을 확인하고 작업을 이어받아줘.
현재 로컬 작업 폴더에서 git fetch 및 pull 상태를 확인하고, 아래의 정리된 아키텍처, 오늘 완료된 작업 내역, 그리고 엄격한 운영 제약사항을 숙지해줘.

### 1. [프로젝트 기본 정보 및 핵심 아키텍처]
- 프로젝트명: GIGANG (Zero Trust Multi-Source SecOps Platform)
- 원격 저장소: https://github.com/dldaudlee36/GIGANG.git (현재 브랜치: main)
- 라이브 배포 URL: https://gigang-aleph.streamlit.app/ (배포 최신화 안내 시 매번 'Reboot 필요' 명시 필수)
- 핵심 시나리오:
  - 1-Hop: 내부 기밀 DB 비정상 대량 조회/덤프 포착 (Internal DB Audit Log)
  - 2-Hop: 단말 화면 캡처, OCR 텍스트 추출, 클립보드 복사 이벤트 인터셉트 (Endpoint Monitor)
  - 3-Hop: 외부 비인가 SaaS/생성형 AI(ChatGPT, Claude 등)로 붙여넣기 및 파일 업로드 시도 (Network Hook)
  - 3-Hop 시퀀스 완성 즉시 FSM 위험도 90점 이상 승격 및 2단계 능동 격리 집행.
- 핵심 설계 원칙:
  1. Zero Payload: 기밀 텍스트 및 스크린샷 원문 미저장, SHA-256 해시·길이·메타데이터만 보관하여 개인정보/기밀 침해 원천 방지.
  2. 3-Hop 인과 상관분석: 단순 시간 인접이 아닌 데이터 크기 비율 및 10분 유효 타임윈도우 검증.
  3. FSM 3단계 상태머신 & 자가 치유(Self-Healing): NORMAL(0~20) ➔ WATCH(68, 30분 TTL) ➔ HIGH(90+). WATCH 진입 후 30분간 추가 위협 없을 시 관리자 개입 없이 자동 NORMAL 복귀.
  4. 점진적 2단계 차단: 1단계 로컬 OS hosts 싱크홀링(10ms 이내 0.0.0.0 바인딩) + 2단계 중앙 방화벽 및 크롬 확장 포털 차단.
  5. 중앙 서버 단절 대비 로컬 데몬(Port 8765) 자동 폴백(Central Fallback) 및 지연율 0ms Optimistic UI.

### 2. [오늘 완료된 작업 및 변경 내역 총정리 (2026-11-02)]
1. 거버넌스 2단계 차단 스위치 개편 (PR #28, #30, #31, #32):
   - 사이트 접속 자체는 허용하되 유출(복사/붙여넣기/업로드)만 선택 차단하는 기능 요구 반영.
   - UI에서 "전면 차단"과 "유출 차단"이 배타적으로 동작하도록 상호 배제 토글 구현.
2. 일시 허용 TTL 정상화 (PR #27):
   - 15분간 일시 허용 기능의 UI 표시 잔여 시간 오류 수정 및 15분 TTL 로직 동기화.
3. 슬랙 알림 기능 전면 삭제 (PR #29):
   - 사내 슬랙 발송 기능을 프로젝트 스코프에서 완전 영구 삭제 처리.
4. README 전면 최신화 및 다이어그램 문법 수정 (PR #36, #37, #38):
   - README 본문의 부자연스러운 문장 전면 정제.
   - 노후 스크린샷 22종 영구 삭제 및 1080p 고해상도 최신 콘솔 실측 화면 6종(01_overview ~ 06_pipeline.png) 캡처 및 교체.
   - GitHub Mermaid 파싱 오류(포트 괄호 및 특수문자로 인한 Parse error: got 'PS') 라벨 큰따옴표 감싸기 및 구문 정정 완료.
5. 최종 발표 슬라이드 덱 제작 (PR #39, #40, #41, #42):
   - oneurui-jim.vercel.app/slides의 완성도 높은 디자인 시스템(Paperlogy 헤드라인, SUIT 본문, 16:9 플로팅 덱 컨테이너, .point-card, .legs-diagram, 원본 확대 라이트박스 팝업, 하단 발표자 대본 패널) 완벽 이식.
   - 4종 컬러웨이 실시간 스위처(코발트 네이비 기본, 토스 블루, 인디고 슬레이트, 포레스트 그린) 탑재.
   - 산출물: docs/GIGANG_Final_Presentation_Deck.html (단독 실행형 웹 덱, 실측 1080p 스크린샷 6종 Base64 무손실 임베드)
   - 산출물: docs/GIGANG_Final_Presentation_Deck.pptx (16:9 와이드스크린 13.333" x 7.5", 동일 구조 및 색상 매핑)
   - 산출물: docs/GIGANG_Design_Concept_Picker.html (4대 아키타입 인터랙티브 시안 셀렉터)
6. 단위 테스트 신뢰성:
   - python -m pytest tests/ 기준 84개 테스트 전수 통과 (84 passed, 0 failed).

### 3. [절대 준수해야 하는 운영 및 행동 지침]
- [기밀 DB IP 보존]: 3번 기밀 DB 내부 주소(desktop-oli.tail2bbbea.ts.net)는 사용자가 의도한 설정이므로 절대 수정하거나 변경을 제안하지 말 것.
- [답변 톤앤매너]: 모든 답변은 한국어로 작성하며, 직설적이고 날카로운 톤을 유지한다. 완곡한 표현, 아부, 빈말, 사과 표현(죄송합니다 등)은 일절 배제한다.
- [금지 요소]: 이모티콘, 느낌표(!), 이탤릭체(*텍스트*)는 일절 사용하지 않는다.
- [파일 링크]: 파일 및 심볼 언급 시 file:// 스키마 기반 클릭 가능한 마크다운 링크를 사용한다 (Windows forward slash 사용).
- [배포 안내]: 배포 관련 안내 시 매번 'Reboot 필요'를 명시한다.
- [미해결 과제 보고]: 작업 완료 시, 반드시 남아있는 미해결 과제가 있는지 확인하고 보고해야 한다. 없으면 없다고 명확히 보고한다.

### 4. [주요 실행 및 검증 명령어]
- 단위 테스트 실행: python -m pytest tests/ -q (84개 통과 확인)
- Streamlit 관제 콘솔 로컬 실행: streamlit run gigang/ui/app.py
- 엔드포인트 수집 에이전트 구동: python -m gigang.collectors.client_agent (포트 8765)
- 발표 웹 슬라이드 확인: docs/GIGANG_Final_Presentation_Deck.html 브라우저 실행 (P/N: 대본, F: 전체화면)

확인이 완료되면 현재 상태를 간략히 확인 보고하고, 추가로 진행할 작업에 대해 문의해줘.
```
