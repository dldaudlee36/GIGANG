@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Starting KKuTu-Lite Server...
kkutu-server.exe 8080
pause
