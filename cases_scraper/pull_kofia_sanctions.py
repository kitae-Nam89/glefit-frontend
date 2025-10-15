# -*- coding: utf-8 -*-
import os, time, sqlite3, requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

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

BASE = "https://www.kofia.or.kr"
LIST = BASE + "/brd/m_54/list.do"
SLEEP = float(os.getenv("KOFIA_SLEEP","0.5"))
MAX_PAGES = int(os.getenv("KOFIA_MAX_PAGES","500"))
STALE_LIMIT = int(os.getenv("KOFIA_STALE_LIMIT","5"))
TAG = "[금투협]" if LOG_KR else "[KOFIA]"
HDRS = {"User-Agent":"glefit/1.0 (kofia sanctions)"}

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

def get_list(page):
    r = requests.get(LIST, params={"page": page}, headers=HDRS, timeout=30)
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

def parse_list(doc):
    items=[]
    for tr in doc.select("table tr"):
        a = tr.select_one("a[href]")
        if not a: continue
        url = urljoin(BASE, a["href"])
        title = a.get_text(strip=True)
        date = ""
        tds = tr.select("td")
        if tds:
            date = tds[-2].get_text(strip=True) if len(tds)>=2 else ""
        items.append((url,title,date))
    return items

def parse_detail(url):
    r = requests.get(url, headers=HDRS, timeout=30); r.raise_for_status()
    s = BeautifulSoup(r.text, "lxml")
    title = (s.select_one("h3,.title") or s.title)
    title = title.get_text(strip=True) if title else ""
    text  = s.get_text("\n", strip=True)
    atts=[]
    for a in s.select("a[href]"):
        href=a["href"]
        if any(href.lower().endswith(ext) for ext in (".pdf",".hwp",".hwpx",".doc",".docx")):
            atts.append(urljoin(BASE, href))
    return title, text, atts

def main():
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL"); ensure_schema(conn)
    page, stale = 1, 0
    while True:
        if page>MAX_PAGES: print(f"{TAG} MAX_PAGES stop"); break
        doc = get_list(page)
        items = parse_list(doc)
        print(f"{TAG} page={page} → rows={len(items)}")
        if not items:
            stale += 1
            if stale>=STALE_LIMIT: break
        else:
            stale = 0
        for u,tit,dt in items:
            try:
                T, txt, atts = parse_detail(u)
                t = T or tit
                ok, iso = in_range(dt)
                if not ok: continue
                conn.execute("""
                  INSERT OR IGNORE INTO cases
                  (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, attachment_urls, summary, raw_text)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, ("금투협","제재공표", t, "", "", "", iso, u, ",".join(atts), txt[:300], txt))
            except Exception as e:
                print(f"  ! detail fail {u}: {e}")
        conn.commit()
        page += 1
        time.sleep(SLEEP)
    conn.close(); print(f"{TAG} done.")

if __name__=="__main__":
    main()
