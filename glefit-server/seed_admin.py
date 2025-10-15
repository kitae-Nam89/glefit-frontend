# seed_admin.py
import sqlite3, datetime
from passlib.hash import pbkdf2_sha256 as bcrypt

DB = "rewrite.db"
username = "admin"
password = "01045343815nam"   # 원하는 비번으로 변경

hash_ = bcrypt.hash(password)
paid_until = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()

con = sqlite3.connect(DB); cur = con.cursor()
cur.execute("""
INSERT OR REPLACE INTO users (id, username, password_hash, is_active, paid_until, role, notes)
VALUES ((SELECT id FROM users WHERE username=?), ?, ?, 1, ?, 'admin', 'seed admin')
""", (username, username, hash_, paid_until))
con.commit(); con.close()

print("✅ admin 계정 생성/업데이트 완료")
