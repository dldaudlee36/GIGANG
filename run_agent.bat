@echo off
chcp 65001 > nul
title GIGANG Zero Trust Windows Agent

echo ===================================================
echo   GIGANG Zero Trust Endpoint Security Agent Launcher
echo ===================================================
echo.

:: 1. 관리자 권한 확인 (hosts 파일 조작 필수)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [안내] 관리자 권한이 필요합니다. 관리자 권한 승격 창을 호출합니다...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb runAs"
    exit /b
)

:: 2. 프로젝트 루트로 이동
cd /d "%~dp0"

:: 3. Python 실행 파일 탐색 (.venv 우선, 없으면 시스템 python)
set "PY_CMD="
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set "PY_CMD=python"
    )
)

if "%PY_CMD%"=="" (
    echo [오류] Python을 찾을 수 없습니다. Python 3.10 이상이 설치되어 있는지 확인하십시오.
    pause
    exit /b 1
)

echo [1/3] 관리자 권한 확인 완료.
echo [2/3] Python 인터프리터: %PY_CMD%
echo [3/3] GIGANG Agent 기동 중 (포트: 8765, hosts 관리 시작)...
echo.
echo ===================================================
echo   에이전트가 정상 실행 중입니다. 이 창을 닫지 마십시오.
echo   종료하려면 Ctrl+C 를 누르십시오.
echo ===================================================
echo.

"%PY_CMD%" -m guard.agent.agent

if %errorlevel% neq 0 (
    echo.
    echo [오류] 에이전트 프로세스가 비정상 종료되었습니다 (코드: %errorlevel%).
    pause
)
