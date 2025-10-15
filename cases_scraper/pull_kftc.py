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

BASE = "https://case.ftc.go.kr"
LISTS = [
    ("공정위/의결서", f"{BASE}/ocp/co/ltfr.do"),
    ("공정위/법위반사실", f"{BASE}/ocp/co/violtLawList.do"),
]

MAX_PAGES   = int(os.getenv("KFTC_MAX_PAGES",   "5000"))
STALE_LIMIT = int(os.getenv("KFTC_STALE_LIMIT", "20"))
SLEEP_SEC   = float(os.getenv("KFTC_SLEEP",     "0.4"))

ADS_NO_FILTER      = os.getenv("ADS_NO_FILTER","0") == "1"
ADS_MIN_KEYWORDS   = int(os.getenv("ADS_MIN_KEYWORDS","1"))

AD_LAW_TOKENS = [
    "표시·광고", "표시ㆍ광고", "표시광고", "표시광고법",
    "표시·광고의 공정화에 관한 법률", "식품 등의 표시·광고에 관한 법률",
    "건강기능식품", "의료법", "의약품", "의료기기법", "화장품법",
]
AD_KEYWORDS = ["광고","표시","과대","허위","거짓","기만","오인","과장",
               "비교광고","최고","1위","100%","완치","효능","효과","치료","임상"]

TAG = "[공정위]" if LOG_KR else "[KFTC]"
HDRS = {"User-Agent": "glefit/1.0 (kftc scraper)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko,en;q=0.9", "Referer": BASE + "/", "Connection": "close"}

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

def fetch(url, params=None):
    for q in ([params or {}],
              {"pageIndex": (params or {}).get("pageIndex")},
              {"page":      (params or {}).get("pageIndex")},
              {"cp":        (params or {}).get("pageIndex")},
              {"pageNo":    (params or {}).get("pageIndex")}):
        try:
            r = requests.get(url, params=q, timeout=30, headers=HDRS)
            if r.ok and len(r.text) > 1000:
                return r.text
        except Exception:
            pass
    r = requests.get(url, timeout=30, headers=HDRS); r.raise_for_status(); return r.text

def parse_list(html):
    s = BeautifulSoup(html, "lxml")
    links = set()
    for a in s.select("a[href*='ltfrView.do'], a[href*='violtLawView.do']"):
        links.add(urljoin(BASE, a.get("href","")))
    for a in s.select("a[onclick]"):
        oc = a.get("onclick") or ""
        m  = re.search(r"ltfrView.*?\(\s*'?(?P<id>\d+)'?\s*\)", oc)
        if m: links.add(f"{BASE}/ocp/co/ltfrView.do?nttId={m.group('id')}")
        m2 = re.search(r"violtLawView.*?\(\s*'?(?P<id2>\d+)'?\s*\)", oc)
        if m2: links.add(f"{BASE}/ocp/co/violtLawView.do?nttId={m2.group('id2')}")
    for m in re.finditer(r'href="(?P<h>/ocp/co/[^"]*(?:ltfrView|violtLawView)\.do[^"]*)"', html, re.I):
        links.add(urljoin(BASE, m.group("h")))
    return sorted(links)

def parse_detail(url):
    html = fetch(url)
    s = BeautifulSoup(html, "lxml")
    h = s.select_one("h3,.title,h2")
    title = h.get_text(strip=True) if h else ""
    body = s.select_one(".board_view,.view,.tbl_view,.cont") or s
    text = body.get_text("\n", strip=True)
    meta = {}
    for tr in s.select("table tr"):
        th, td = tr.select_one("th"), tr.select_one("td")
        if th and td: meta[th.get_text(strip=True)] = td.get_text(" ", strip=True)
    atts = []
    for a in s.select("a[href]"):
        href = a["href"].lower()
        if href.endswith((".pdf",".hwp",".hwpx",".doc",".docx",".zip")):
            atts.append(urljoin(BASE, a["href"]))
    return title, meta, text, atts

def is_ad_related(meta, text):
    if ADS_NO_FILTER: return True
    t = (" ".join(f"{k}:{v}" for k,v in (meta or {}).items()) + " " + (text or "")).replace("ㆍ","·")
    if any(tok in t for tok in AD_LAW_TOKENS): return True
    kw_cnt  = sum(1 for k in AD_KEYWORDS if k in t)
    base    = ("광고" in t) or ("표시" in t) or ("표시광고" in t)
    return base and kw_cnt >= ADS_MIN_KEYWORDS

def main():
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL")
    ensure_schema(conn)
    for cat, list_url in LISTS:
        page, stale, prev_links = 1, 0, None
        while True:
            if page > MAX_PAGES: print(f"{TAG} {cat} reached MAX_PAGES={MAX_PAGES}, stop.", flush=True); break
            html  = fetch(list_url, params={"pageIndex": page})
            links = parse_list(html)
            print(f"{TAG} {cat} page={page} → links={len(links)}", flush=True)

            if not links or (prev_links is not None and set(links) == prev_links): stale += 1
            else: stale = 0
            prev_links = set(links)
            if stale >= STALE_LIMIT: print(f"{TAG} {cat} no new links for {STALE_LIMIT} pages, stop.", flush=True); break
            if not links: break

            ins = 0
            for url in links:
                try:
                    t, m, txt, atts = parse_detail(url)
                    date_raw = m.get("의결일","") or m.get("공표일","") or m.get("등록일","")
                    ok, iso = in_range(date_raw)
                    if not ok: continue
                    if not is_ad_related(m, txt): continue
                    cur = conn.execute("""
                      INSERT OR IGNORE INTO cases
                      (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, attachment_urls, summary, raw_text)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """, ("공정위", cat,
                          t,
                          m.get("피심인","") or m.get("사업자명","") or m.get("피조사업체","") or "",
                          m.get("조치내용","") or m.get("제재유형","") or m.get("주요내용","") or "",
                          m.get("관련법령","") or m.get("법조항","") or "",
                          iso, url, ",".join(atts), txt[:300], txt))
                    ins += cur.rowcount
                except Exception as e:
                    print(f"  ! detail fail {url}: {e}", flush=True)
            conn.commit()

            if ins == 0:
                stale += 1
                if stale >= STALE_LIMIT: print(f"{TAG} {cat} no inserts for {STALE_LIMIT} pages, stop.", flush=True); break
            else: stale = 0

            page += 1
            time.sleep(SLEEP_SEC)
    conn.close()
    print(f"{TAG} done.", flush=True)

if __name__ == "__main__":
    main()
