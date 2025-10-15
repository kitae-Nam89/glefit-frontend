@echo off
setlocal ENABLEDELAYEDEXPANSION
chcp 65001 > nul
set PYTHONUTF8=1
cd /d "%~dp0"

REM ===== 기간 설정 (예: 2023~2025) =====
set START_DATE=2023-01-01
set END_DATE=2025-12-31

REM ===== 첫 적재는 전수 권장 =====
set ADS_NO_FILTER=1
set ADS_MIN_KEYWORDS=1
set LOG_KR=1

REM ===== 무한 방지 =====
set KFTC_MAX_PAGES=5000
set KFTC_STALE_LIMIT=20
set MFDS_BOARD_MAX_PAGES=5000
set MFDS_BOARD_STALE_LIMIT=8
set KCSC_MAX_PAGES=5000
set KCSC_STALE_LIMIT=8
set FSC_MAX_PAGES=2000
set FSC_STALE_LIMIT=5

if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

echo [시작] DB 초기화
python init_db.py || goto :err

echo [현황] (기관별/총계)
python -c "import sqlite3; c=sqlite3.connect('cases.db'); print(c.execute('SELECT regulator, COUNT(*) FROM cases GROUP BY regulator').fetchall()); print('TOTAL=', c.execute('SELECT COUNT(*) FROM cases').fetchone()[0]); c.close()"

echo [1/6] 공정위
python -u pull_kftc.py || goto :err

echo [2/6] 식약처(게시판)
python -u pull_mfds_board.py || goto :err

echo [3/6] 방심위
python -u pull_kcsc.py || goto :err

echo [4/6] 금융위
python -u pull_fsc_sanctions.py || goto :err

echo [5/6] 금투협
python -u pull_kofia_sanctions.py || goto :err

echo [6/6] 생보협
python -u pull_klia_ad_violations.py || goto :err

echo.
echo [완료] 최종 집계
python -c "import sqlite3; c=sqlite3.connect('cases.db'); print(c.execute('SELECT regulator, COUNT(*) FROM cases GROUP BY regulator').fetchall()); print('TOTAL=', c.execute('SELECT COUNT(*) FROM cases').fetchone()[0]); c.close()"
echo.
echo (창을 닫으려면 아무 키나 누르세요)
pause
goto :eof

:err
echo [ERROR] 종료 코드 %ERRORLEVEL%
pause
exit /b %ERRORLEVEL%
