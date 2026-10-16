@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ====================================================================
echo   🌐 [끄투 LITE] 친구들에게 파일 전달 없이 '링크(URL)'로 초대하기
echo ====================================================================
echo.
echo 1. 로컬 끝말잇기 서버(포트 8080)를 실행합니다...
start "KKuTu-Lite-Server" /min kkutu-server.exe 8080 --no-browser
timeout /t 1 /nobreak >nul

echo 2. Windows 내장 OpenSSH를 이용해 외부 접속용 임시 링크를 생성합니다...
echo    잠시 후 화면 하단에 나타나는 [ https://xxxx.lhr.life ] 주소를 복사해서
echo    친구들에게 카톡/디스코드로 보내주시면 파일 없이 바로 접속됩니다!
echo ====================================================================
echo.
ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -R 80:localhost:8080 nokey@localhost.run
pause
