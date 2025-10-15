# -*- coding: utf-8 -*-
import os, time, sqlite3, requests, re
from bs4 import BeautifulSoup

# === 공통 유틸 ===
import os, re
from datetime import date
from dateutil import parser
LOG_KR = os.getenv("LOG_KR", "1") == "1"
START_DATE = os.getenv("START_DATE"); END_DATE = os.getenv("END_DATE")
def _to_iso(dstr):
    if not dstr: return None
    s=dstr.strip().replace("년","-").replace("월","-").replace("일","")
    s=re.sub(r"[./]","-",s); s=re.sub(r"\s+","",s)
    try: return parser.parse(s,yearfirst=True,fuzzy=True).date().isoformat()
    except: return None
from datetime import date as _d; _START=_d.min if not START_DATE else parser.parse(START_DATE).date(); _END=_d.max if not END_DATE else parser.parse(END_DATE).date()
def in_range(dstr):
    iso=_to_iso(dstr)
    if not iso: return True, None
    d=parser.parse(iso).date()
    return (_START<=d<=_END), iso
# ===============

BASE = "https://www.klia.or.kr"
LIST = BASE + "/member/insurProduct/advio/list.do"  # 광고심의 규정 위반내역
SLEEP = float(os.getenv("KLIA_SLEEP","0.5"))
TAG = "[생보협]" if LOG_KR else "[KLIA]"
HDRS = {"User-Agent":"glefit/1.0 (klia ads)"}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY,
  regulator TEXT, category TEXT, title TEXT, entity TEXT, sanction_type TEXT,
  law_refs TEXT, decision_date TEXT, source_url TEXT UNIQUE,
  attachment_urls TEXT, summary TEXT, raw_text TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""
def ensure_schema(conn): conn.executescript(SCHEMA_SQL)

def get_list():
    r = requests.get(LIST, headers=HDRS, timeout=30)
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

def parse_rows(doc):
    rows=[]
    for tr in doc.select("table tr"):
        tds = tr.select("td")
        if len(tds) >= 5:
            company = tds[0].get_text(" ", strip=True)
            adname  = tds[1].get_text(" ", strip=True)
            viol    = tds[2].get_text(" ", strip=True)
            date    = tds[3].get_text(" ", strip=True)
            action  = tds[4].get_text(" ", strip=True)
            rows.append((company, adname, viol, date, action))
    return rows

def main():
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL"); ensure_schema(conn)
    doc = get_list()
    rows = parse_rows(doc)
    print(f"{TAG} rows={len(rows)}")
    for company, adname, viol, d, action in rows:
        ok, iso = in_range(d)
        if not ok: continue
        title = f"[광고심의 위반] {company} - {adname}"
        summary = viol[:300]
        raw = "\n".join([f"회사={company}", f"광고명={adname}", f"위반내용={viol}", f"의결일자={d}", f"제재조치={action}"])
        conn.execute("""
          INSERT OR IGNORE INTO cases
          (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, attachment_urls, summary, raw_text)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, ("생보협","광고심의 위반", title, company, action, "광고심의 규정", iso, LIST, "", summary, raw))
    conn.commit(); conn.close(); print(f"{TAG} done.")

if __name__=="__main__":
    main()
