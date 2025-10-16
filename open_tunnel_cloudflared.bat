@echo off
chcp 65001 >nul
set PORT=5000

REM 1) 5000 포트에서 백엔드가 떠있는지 간단 확인
netstat -ano | findstr /r ":%PORT% .*LISTENING" >nul
if errorlevel 1 (
  echo [ERROR] 백엔드가 http://localhost:%PORT% 에서 실행중이 아닙니다.
  echo        먼저 기존 서버 실행 bat로 서버를 켜고 다시 시도하세요.
  pause
  exit /b 1
)

REM 2) cloudflared 존재 확인 (PATH)
where cloudflared >nul 2>nul
if errorlevel 1 (
  echo [ERROR] cloudflared 가 없습니다.
  echo        설치: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation
  echo        설치 후, 다시 실행하세요.
  pause
  exit /b 1
)

echo [TUNNEL] http://localhost:%PORT% 를 외부로 공개합니다...
echo       이 창에 뜨는 https://xxxxx.trycloudflare.com 가 외부 접속 URL 입니다.
cloudflared tunnel --url http://localhost:%PORT%
