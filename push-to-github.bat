@echo off
chcp 65001 > nul
echo ========================================================
echo   끄투 LITE - GitHub 저장소 푸시 도우미
echo ========================================================
echo.
echo 1. https://github.com/new 에 접속하여 새 저장소를 만드세요 (예: kkutu-lite)
echo 2. 생성된 저장소의 주소를 복사하여 아래에 붙여넣고 Enter를 누르세요.
echo    (예: https://github.com/내계정/kkutu-lite.git)
echo.
set /p REPO_URL="GitHub 저장소 주소: "
if "%REPO_URL%"=="" goto end

set GIT_CONFIG_GLOBAL=%~dp0.gitconfig_temp
set GIT_CONFIG_SYSTEM=%~dp0.gitconfig_temp
type nul > "%GIT_CONFIG_GLOBAL%"

git remote remove origin 2>nul
git remote add origin %REPO_URL%
git branch -M main
echo.
echo GitHub으로 업로드를 시작합니다 (첫 로그인 시 브라우저 인증 창이 뜰 수 있습니다)...
git push -u origin main

del "%GIT_CONFIG_GLOBAL%" 2>nul
echo.
echo ========================================================
echo   업로드 완료! 이제 https://vercel.com/new 에 접속하여
echo   방금 올린 저장소를 선택하고 [Deploy]를 누르면 배포 완료!
echo ========================================================
pause
:end
