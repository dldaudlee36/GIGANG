@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo [1/5] Testing Department Policy Engine...
echo ========================================
python tests\test_policy.py
if errorlevel 1 goto error

echo ========================================
echo [2/5] Testing Confidential DB Downloads...
echo ========================================
python tests\test_download.py
if errorlevel 1 goto error

echo ========================================
echo [3/5] Testing Sensitive Data Rules...
echo ========================================
python tests\test_rules.py
if errorlevel 1 goto error

echo ========================================
echo [4/5] Testing Image Guard OCR and API...
echo ========================================
python tests\image_guard\test_image_risk.py
if errorlevel 1 goto error
python tests\image_guard\test_image_api.py
if errorlevel 1 goto error

echo ========================================
echo [5/5] Testing Paste and Dedup Flow...
echo ========================================
python tests\test_paste.py
if errorlevel 1 goto error
python tests\test_dedup.py
if errorlevel 1 goto error
python tests\test_score_unify.py
if errorlevel 1 goto error

echo.
echo ========================================
echo ALL TESTS PASSED SUCCESSFULLY!
echo ========================================
goto end

:error
echo.
echo [ERROR] Test failure encountered.
pause
exit /b 1

:end
pause
endlocal
