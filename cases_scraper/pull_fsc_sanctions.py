# -*- coding: utf-8 -*-
import os, time, sqlite3, requests, re
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

BASE = "https://www.fsc.go.kr"
LIST = BASE + "/no020101"  # 의결정보(제재 등)
SLEEP = float(os.getenv("FSC_SLEEP","0.5"))
MAX_PAGES = int(os.getenv("FSC_MAX_PAGES","2000"))
STALE_LIMIT = int(os.getenv("FSC_STALE_LIMIT","5"))
TAG = "[금융위]" if LOG_KR else "[FSC]"
HDRS = {"User-Agent":"glefit/1.0 (fsc sanctions)"}

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
    for q in ({}, {"cp":page}, {"pageIndex":page}, {"page":page}):
        r = requests.get(LIST, params=q, headers=HDRS, timeout=30)
        if r.ok and len(r.text)>1000:
            return BeautifulSoup(r.text, "lxml")
    r = requests.get(LIST, headers=HDRS, timeout=30)
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

def parse_list(doc):
    items=[]
    for row in doc.select("ul.boardList li, table.board tr, .bbs_list tbody tr, .list tbody tr"):
        a = row.select_one("a[href]")
        if not a: continue
        url  = urljoin(BASE, a["href"])
        title= a.get_text(" ", strip=True)
        date = ""
        for sel in ("td.date",".date",".writeDate",".regDate"):
            d = row.select_one(sel)
            if d: date = d.get_text(strip=True); break
        items.append((url,title,date))
    # 백업
    html=str(doc)
    for m in re.finditer(r'href="(?P<h>/user\.do\?[^"]+)"', html):
        u = urljoin(BASE, m.group("h"))
        if u not in [x[0] for x in items]:
            items.append((u,"",""))
    return items

def parse_detail(url):
    r = requests.get(url, headers=HDRS, timeout=30); r.raise_for_status()
    s = BeautifulSoup(r.text, "lxml")
    title = (s.select_one("h3,h2,.title") or s.title)
    title = title.get_text(strip=True) if title else ""
    text  = s.get_text("\n", strip=True)
    atts=[]
    for a in s.select("a[href]"):
        href=a["href"]
        if any(href.lower().endswith(ext) for ext in (".pdf",".hwp",".hwpx",".zip",".doc",".docx")):
            atts.append(urljoin(BASE, href))
    date = ""
    for k in (".date",".writeDate",".regDate","td.date"):
        d = s.select_one(k)
        if d: date=d.get_text(strip=True); break
    return title, text, atts, date

def main():
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL"); ensure_schema(conn)
    page, stale, prev = 1, 0, None
    while True:
        if page > MAX_PAGES: print(f"{TAG} MAX_PAGES stop"); break
        doc = get_list(page)
        items = parse_list(doc)
        print(f"{TAG} page={page} → rows={len(items)}", flush=True)

        if not items or (prev is not None and set(items)==prev): stale += 1
        else: stale = 0
        prev = set(items)
        if stale >= STALE_LIMIT: print(f"{TAG} stale {STALE_LIMIT} stop"); break
        if not items: break

        for u,tit,dt in items:
            try:
                T, txt, atts, d2 = parse_detail(u)
                t = T or tit
                d = d2 or dt
                ok, iso = in_range(d)
                if not ok: continue
                conn.execute("""
                  INSERT OR IGNORE INTO cases
                  (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, attachment_urls, summary, raw_text)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, ("금융위","의결/제재정보", t, "", "", "", iso, u, ",".join(atts), txt[:300], txt))
            except Exception as e:
                print(f"  ! detail fail {u}: {e}")
        conn.commit()
        page += 1
        time.sleep(SLEEP)
    conn.close(); print(f"{TAG} done.", flush=True)

if __name__=="__main__":
    main()
