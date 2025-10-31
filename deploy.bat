@echo off
echo ===== Frontend Push (Vercel) =====
cd C:\Users\USER\Desktop\glefit
git add -A
git commit -m "update(frontend): latest sync"
git push origin main

echo ===== Server Push (Render) =====
cd C:\Users\USER\Desktop\glefit\glefit-server
git add -A
git commit -m "update(server): latest sync"
git push origin main

pause
