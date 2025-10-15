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

BASE  = "https://kocsc.or.kr"
LIST  = BASE + "/cop/bbs/selectBoardList.do?bbsId=info_Opinion_main"
SLEEP = float(os.getenv("KCSC_SLEEP","0.5"))
MAX_PAGES = int(os.getenv("KCSC_MAX_PAGES","5000"))
STALE_LIMIT = int(os.getenv("KCSC_STALE_LIMIT","8"))

TAG = "[방심위]" if LOG_KR else "[KCSC]"
HDRS = {"User-Agent":"glefit/1.0 (kcsc scraper)"}

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
    for pkey in ("pageIndex","pageIndex2","pageNo","cp"):
        r = requests.get(LIST, params={pkey: page}, headers=HDRS, timeout=30)
        if r.ok and len(r.text)>1000:
            return BeautifulSoup(r.text, "lxml")
    r = requests.get(LIST, headers=HDRS, timeout=30)
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

def parse_list(doc):
    links = []
    for a in doc.select("a[href*='selectBoardView']"):
        links.append(urljoin(BASE, a.get("href","")))
    html = str(doc)
    for m in re.finditer(r"/cop/bbs/selectBoardView\.do\?[^\"'>]+", html):
        links.append(urljoin(BASE, m.group(0)))
    return list(dict.fromkeys(links))

def parse_detail(url):
    r = requests.get(url, headers=HDRS, timeout=30); r.raise_for_status()
    s = BeautifulSoup(r.text, "lxml")
    title = (s.select_one(".title,h3,h2") or s.select_one("th.title") or s.title)
    title = title.get_text(strip=True) if title else ""
    text  = s.get_text("\n", strip=True)
    meta  = {}
    for tr in s.select("table tr"):
        th, td = tr.select_one("th"), tr.select_one("td")
        if th and td: meta[th.get_text(strip=True)] = td.get_text(" ", strip=True)
    atts = []
    for a in s.select("a[href]"):
        href = a["href"]
        if any(href.lower().endswith(ext) for ext in (".pdf",".hwp",".hwpx",".doc",".docx",".xls",".xlsx")):
            atts.append(urljoin(BASE, href))
    dec = meta.get("작성일","") or meta.get("의결일","") or ""
    return title, meta, text, atts, dec

def main():
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL")
    ensure_schema(conn)
    page, stale, prev = 1, 0, None
    while True:
        if page > MAX_PAGES: print(f"{TAG} MAX_PAGES stop"); break
        doc = get_list(page)
        links = parse_list(doc)
        print(f"{TAG} page={page} → links={len(links)}", flush=True)

        if not links or (prev is not None and set(links)==prev): stale += 1
        else: stale = 0
        prev = set(links)
        if stale >= STALE_LIMIT: print(f"{TAG} stale {STALE_LIMIT} stop"); break
        if not links: break

        for u in links:
            try:
                t,m,txt,atts,dec = parse_detail(u)
                ok, iso = in_range(dec)
                if not ok: continue
                conn.execute("""
                  INSERT OR IGNORE INTO cases
                  (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, attachment_urls, summary, raw_text)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, ("방심위","방송심의의결현황", t,
                      m.get("사업자","") or m.get("매체",""),
                      m.get("의결결과","") or m.get("조치",""),
                      m.get("관련법규","") or m.get("관련법령",""),
                      iso, u, ",".join(atts), txt[:300], txt))
            except Exception as e:
                print(f"  ! detail fail {u}: {e}")
        conn.commit()
        page += 1
        time.sleep(SLEEP)
    conn.close()
    print(f"{TAG} done.", flush=True)

if __name__ == "__main__":
    main()
