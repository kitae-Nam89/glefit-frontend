@echo off
cd /d %~dp0
echo 🔁 가상환경 활성화 중...
call venv\Scripts\activate
chcp 65001 >nul

echo.
echo 📂 원고 수집 및 corpus.json 생성 중...
python make_corpus.py

echo.
echo 📌 인덱스 구축 중 (plagiarism_index.faiss)...
python prepare_db.py

echo.
echo ✅ 모든 작업 완료. 결과 확인 후 서버 실행 가능.
pause
