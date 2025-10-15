# check_db.py
import sqlite3
conn = sqlite3.connect("sanctions_cases.db")
q = """
SELECT a.name AS agency,
       TRIM(l.title||' '||IFNULL(l.article,'')) AS law,
       IFNULL(cases.decided_at,'') AS decided_at,
       substr(IFNULL(cases.summary,''),1,60)||'…' AS summary_preview,
       IFNULL(cases.source_url,'') AS source_url
FROM cases
LEFT JOIN agencies a ON a.id=cases.agency_id
LEFT JOIN laws l     ON l.id=cases.law_id
ORDER BY cases.id DESC
LIMIT 10
"""
for row in conn.execute(q):
    print(row)
conn.close()
