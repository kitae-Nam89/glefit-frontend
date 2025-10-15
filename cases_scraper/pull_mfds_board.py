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

LIST = "https://www.foodsafetykorea.go.kr/portal/fooddanger/administMeasureList.do"
BASE = "https://www.foodsafetykorea.go.kr"

MAX_PAGES   = int(os.getenv("MFDS_BOARD_MAX_PAGES",   "5000"))
STALE_LIMIT = int(os.getenv("MFDS_BOARD_STALE_LIMIT", "8"))
SLEEP_SEC   = float(os.getenv("MFDS_BOARD_SLEEP",     "0.4"))

ADS_NO_FILTER    = os.getenv("ADS_NO_FILTER","0") == "1"
ADS_MIN_KEYWORDS = int(os.getenv("ADS_MIN_KEYWORDS","1"))

AD_LAW_TOKENS = [
    "식품 등의 표시·광고에 관한 법률", "식품표시광고법",
    "건강기능식품에 관한 법률", "의료법", "화장품법", "의료기기법", "표시·광고","표시광고"
]
AD_KEYWORDS = ["광고","표시","과대","허위","거짓","기만","오인","효능","효과","치료","100%","완치","비교"]

TAG = "[식약처]" if LOG_KR else "[MFDS]"

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

def list_page(page=1):
    for key in ("pageIndex","page","cp","pageNo"):
        r = requests.get(LIST, params={key: page}, timeout=30, headers={"User-Agent":"glefit/1.0"})
        if r.ok and len(r.text) > 1000:
            return BeautifulSoup(r.text, "lxml")
    r = requests.get(LIST, timeout=30, headers={"User-Agent":"glefit/1.0"})
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

def parse_list(soup):
    out=set()
    for a in soup.select("a[href*='administMeasureView']"):
        href = a.get("href","")
        out.add(BASE + href if href.startswith("/") else href)
    for a in soup.select("a[onclick]"):
        oc = a.get("onclick") or ""
        m = re.search(r"administMeasureView.*?\(\s*'?(?P<id>\d+)'?\s*\)", oc)
        if m: out.add(f"{BASE}/portal/fooddanger/administMeasureView.do?id={m.group('id')}")
    return list(dict.fromkeys(out))

def parse_detail(url):
    r = requests.get(url, timeout=30, headers={"User-Agent":"glefit/1.0"})
    r.raise_for_status()
    s = BeautifulSoup(r.text, "lxml")
    title = (s.select_one(".title, h3, h2") or s.select_one("title"))
    title = title.get_text(strip=True) if title else ""
    text  = s.get_text("\n", strip=True)
    meta  = {}
    for tr in s.select("table tr"):
        th, td = tr.select_one("th"), tr.select_one("td")
        if th and td: meta[th.get_text(strip=True)] = td.get_text(" ", strip=True)
    atts = []
    for a in s.select("a[href]"):
        href = a["href"]
        if any(href.lower().endswith(ext) for ext in (".pdf",".hwp",".hwpx",".doc",".docx")):
            atts.append(href if href.startswith("http") else BASE + href)
    return title, meta, text, atts

def is_ad_related(meta, text):
    if ADS_NO_FILTER: return True
    t = ((meta.get("위반법령","") + " " + text) if meta else text).replace("ㆍ","·")
    if any(tok in t for tok in AD_LAW_TOKENS): return True
    kw_cnt  = sum(1 for k in AD_KEYWORDS if k in t)
    base    = ("광고" in t) or ("표시" in t) or ("표시광고" in t)
    return base and kw_cnt >= ADS_MIN_KEYWORDS

def upsert(conn, url, title, meta, text, atts):
    date_raw = meta.get("처분일","") or meta.get("처분일자","")
    ok, iso = in_range(date_raw)
    if not ok: return 0
    if not is_ad_related(meta, text): return 0
    cur = conn.execute("""
      INSERT OR IGNORE INTO cases
      (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, attachment_urls, summary, raw_text)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, ("식약처","식품/표시광고",
          title,
          meta.get("업소명","") or meta.get("업체명","") or "",
          meta.get("처분유형","") or meta.get("조치내용","") or "",
          meta.get("위반법령","") or "",
          iso, url, ",".join(atts), text[:300], text))
    return cur.rowcount

def main():
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL")
    ensure_schema(conn)
    page, stale = 1, 0
    while True:
        soup = list_page(page)
        links = parse_list(soup)
        print(f"{TAG} page={page} → links={len(links)}", flush=True)
        if not links: break
        ins = 0
        for url in links:
            try:
                t,m,txt,atts = parse_detail(url)
                ins += upsert(conn, url, t, m, txt, atts)
            except Exception as e:
                print(f"  ! detail fail {url}: {e}", flush=True)
        conn.commit()
        if ins == 0:
            stale += 1
            if stale >= STALE_LIMIT: print(f"{TAG} no inserts for {STALE_LIMIT} pages, stop.", flush=True); break
        else:
            stale = 0
        page += 1
        time.sleep(SLEEP_SEC)
    conn.close()
    print(f"{TAG} done.", flush=True)

if __name__ == "__main__":
    main()
