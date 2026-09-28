# 🌐 GIGANG Chrome Web Sentry (v3.1.0)
### Zero Trust 기반 엔드포인트 웹 텔레메트리 센서 (Manifest V3)

웹 브라우저 상에서 비인가 생성형 AI 사이트로의 데이터 반출 시도(파일 첨부, 텍스트 붙여넣기)를 실시간 감지하여 중앙 인제스천 서버(Railway)로 메타데이터를 전송하는 확장 프로그램입니다.

---

## 📌 주요 기능
1. **파일 첨부 시도 실시간 감지 (`FILE_UPLOAD_ATTEMPT`)**:
   - `<input type="file">` 및 파일 선택 이벤트를 가로채어 대상 도메인, 파일명, 파일 크기(Bytes) 메타데이터를 추출합니다.
2. **클립보드 붙여넣기 실시간 감지 (`PASTE_ATTEMPT`)**:
   - 웹 폼에 텍스트 붙여넣기 시 텍스트 길이(글자 수)를 산출하여 메타데이터를 전송합니다. (단, 비밀번호 입력 필드는 감지 제외)
3. **본문 미수집 원칙 (Zero Payload Ingestion)**:
   - 붙여넣은 텍스트 본문이나 첨부 파일의 원본 내용은 메모리 상에서 절대 읽거나 전송하지 않으며, 오직 비식별 메타데이터만 전송합니다.
4. **Manifest V3 백그라운드 서비스 워커**:
   - `background.js` 서비스 워커가 이벤트 디바운싱 및 Railway 클라우드 서버와의 보안 통신을 담당합니다.

---

## 📁 파일 구성
| 파일 | 설명 |
| :--- | :--- |
| `manifest.json` | Chrome Manifest V3 확장 설정 |
| `content.js` | 웹 페이지 내 붙여넣기 및 파일 선택 이벤트 리스너 |
| `background.js` | 백그라운드 서비스 워커 및 중앙 수집 서버 HTTPS 전송 |
| `popup.html` / `popup.js` | 센서 상태 확인 팝업 UI |

---

## 🚀 설치 방법
1. Chrome 브라우저 주소창에 `chrome://extensions` 입력
2. 우측 상단 **'개발자 모드(Developer mode)'** 활성화
3. **'압축해제된 확장 프로그램을 로드(Load unpacked)'** 버튼 클릭
4. 이 `browser_extension` 폴더를 선택하여 로드
5. 테스트할 웹 사이트 새로고침 후 콘솔(`F12`)에서 `[GIGANG] 붙여넣기 감지 준비 완료 · 확장 3.1.0` 확인
