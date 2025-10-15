# -*- coding: utf-8 -*-
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY,
  regulator TEXT,           -- '공정위' 등 한글표기
  category  TEXT,
  title     TEXT,
  entity    TEXT,
  sanction_type TEXT,
  law_refs  TEXT,
  decision_date TEXT,       -- ISO YYYY-MM-DD
  source_url TEXT UNIQUE,
  attachment_urls TEXT,
  summary   TEXT,
  raw_text  TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

con = sqlite3.connect("cases.db")
con.executescript(SCHEMA)
con.commit()
con.close()
print("DB ready: cases.db / table `cases`")
