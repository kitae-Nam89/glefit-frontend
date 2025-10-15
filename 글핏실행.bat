@echo off
cd /d C:\Users\USER\Desktop\glefit\glefit-server
call venv\Scripts\activate
start cmd /k "python server.py"
cd /d C:\Users\USER\Desktop\glefit
start cmd /k "npm start"