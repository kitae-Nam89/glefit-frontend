
import time, sqlite3, requests
from bs4 import BeautifulSoup
BASE = "https://www.kofiu.go.kr"
LIST = f"{BASE}/kor/notification/sanctions.do"

def list_page(page=1):
    r = requests.get(LIST, params={"pageIndex": page}, timeout=30, headers={"User-Agent":"glefit/1.0"})
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

def parse_list(s):
    out = []
    for a in s.select("table a"):
        href = a.get("href","")
        if href and href.startswith("/kor/notification/sanctions.do?") and "mode=view" in href:
            out.append(BASE + href)
    return out

def parse_detail(url):
    r = requests.get(url, timeout=30, headers={"User-Agent":"glefit/1.0"})
    r.raise_for_status()
    s = BeautifulSoup(r.text, "lxml")
    h = s.select_one(".title,h3,h2") or s.select_one("th")
    title = h.get_text(strip=True) if h else ""
    meta = {}
    for tr in s.select("table tr"):
        th, td = tr.select_one("th"), tr.select_one("td")
        if th and td:
            meta[th.get_text(strip=True)] = td.get_text(" ", strip=True)
    text = s.get_text("\n", strip=True)
    return title, meta, text

def upsert(conn, url, title, meta, text):
    conn.execute(
        """
        INSERT OR IGNORE INTO cases
        (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, summary, raw_text)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            "FIU",
            "자금세탁/특금법",
            title,
            meta.get("대상기관","") or meta.get("피제재기관","") or "",
            meta.get("조치내용","") or meta.get("제재유형","") or "",
            meta.get("관련법령","") or "",
            meta.get("공표일","") or meta.get("등록일","") or "",
            url,
            text[:300],
            text,
        ),
    )

def main():
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL")
    page = 1
    while True:
        s = list_page(page)
        links = list(parse_list(s))
        if not links:
            break
        for url in links:
            t, m, txt = parse_detail(url)
            upsert(conn, url, t, m, txt)
            conn.commit()
            time.sleep(0.3)
        page += 1
        time.sleep(0.5)
    conn.close()

if __name__ == "__main__":
    main()
