@echo off
cd /d %~dp0

echo [1/3] 수집 중...
python ingest_cases.py --agency all --since 2022 --max 500

echo [2/3] 노이즈 정리...
python -c "import sqlite3; c=sqlite3.connect('sanctions_cases.db'); \
c.execute(\"DELETE FROM cases WHERE source_url LIKE 'http://impfood.mfds.go.kr%' OR source_url LIKE 'http://radsafe.mfds.go.kr%'\"); \
c.commit(); print('cleanup ok'); c.close()"

echo [3/3] 상위 10건 확인(기관/법령/날짜/요약/출처)...
python -c "import sqlite3; c=sqlite3.connect('sanctions_cases.db'); \
print(*c.execute(\"SELECT (SELECT name FROM agencies WHERE id=c.agency_id), \
TRIM((SELECT title FROM laws WHERE id=c.law_id)||' '||IFNULL((SELECT article FROM laws WHERE id=c.law_id),'')), \
IFNULL(c.decided_at,''), substr(IFNULL(c.summary,''),1,60)||'…', IFNULL(c.source_url,'') \
FROM cases c ORDER BY c.id DESC LIMIT 10\").fetchall(), sep='\\n'); c.close()"

echo 완료. 창을 닫으셔도 됩니다.
pause
