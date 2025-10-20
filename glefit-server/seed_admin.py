#!/usr/bin/env python3
import argparse
import datetime as dt
import os
import sqlite3
from pathlib import Path
from passlib.hash import pbkdf2_sha256 as bcrypt  # 서버와 동일

# ==== DB 경로: server.py와 반드시 일치 ====
DB_PATH = os.getenv("GLEFIT_DB_PATH") or "rewrite.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active     INTEGER NOT NULL DEFAULT 1,
  paid_until    TEXT,
  role          TEXT NOT NULL DEFAULT 'user',
  notes         TEXT
);
-- username 고유 제약 보강
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
"""

UPSERT_SQL = """
INSERT INTO users (username, password_hash, is_active, paid_until, role, notes)
VALUES (?, ?, 1, ?, 'admin', 'seed admin')
ON CONFLICT(username) DO UPDATE SET
  password_hash = excluded.password_hash,
  is_active     = 1,
  paid_until    = excluded.paid_until,
  role          = 'admin',
  notes         = 'seed admin';
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--days", type=int, default=365)
    args = parser.parse_args()

    # timezone-aware UTC
    paid_until_dt = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=args.days)
    paid_until_iso = paid_until_dt.isoformat()

    pw_hash = bcrypt.hash(args.password)

    # DB 파일 디렉토리 보장
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        # 1) 스키마 보장
        cur.executescript(SCHEMA_SQL)

        # 2) admin 계정 UPSERT
        cur.execute(UPSERT_SQL, (args.username, pw_hash, paid_until_iso))
        conn.commit()

        # 3) 확인 출력
        cur.execute("SELECT id, username, is_active, paid_until, role FROM users WHERE username = ?", (args.username,))
        row = cur.fetchone()
        print("[OK] Seeded/Updated admin:", row)

    finally:
        conn.close()

if __name__ == "__main__":
    main()
