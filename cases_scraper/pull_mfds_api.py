# -*- coding: utf-8 -*-
import os, time, sqlite3, requests

API_URL = "https://www.foodsafetykorea.go.kr/api/I0470/json/%(KEY)s/%(start)d/%(end)d"
API_KEY = os.environ.get("DATA_GO_KR_KEY")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY,
  regulator TEXT, category TEXT, title TEXT, entity TEXT, sanction_type TEXT,
  law_refs TEXT, decision_date TEXT, source_url TEXT UNIQUE,
  attachment_urls TEXT, summary TEXT, raw_text TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""
AD_LAW_TOKENS = [
    "식품 등의 표시·광고에 관한 법률", "식품표시광고법",
    "건강기능식품에 관한 법률", "표시·광고", "표시광고"
]
AD_KEYWORDS = ["광고","표시","과대","허위","거짓","기만","오인","효능","효과","치료","100%","완치","비교"]

def ensure_schema(conn): conn.executescript(SCHEMA_SQL)

def is_ad_row(row):
    t = " ".join([
        str(row.get("LOW_NM","")),   # 위반법령
        str(row.get("PRCS_CN","")), # 처분사유/내용
        str(row.get("VLTN_CN","")), # 위반내용
    ]).replace("ㆍ","·")
    law_hit = any(tok in t for tok in AD_LAW_TOKENS)
    kw_hit  = sum(1 for k in AD_KEYWORDS if k in t) >= 2
    base    = ("광고" in t) or ("표시" in t) or ("표시광고" in t)
    return law_hit or (base and kw_hit)

def upsert(conn, row):
    if not is_ad_row(row):
        return 0
    cur = conn.execute("""
      INSERT OR IGNORE INTO cases
      (regulator, category, title, entity, sanction_type, law_refs, decision_date, source_url, summary, raw_text)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    """, ("MFDS","식품/표시광고",
          (row.get("PRCS_CN","") or row.get("VLTN_CN","")).strip(),
          row.get("BSSH_NM",""),
          row.get("PRCS_KND_NM",""),
          row.get("LOW_NM",""),
          row.get("PRCS_DE",""),
          f"mfds-api:I0470:{row.get('PRCS_DE','')}:{row.get('BSSH_NM','')}",
          (row.get("VLTN_CN","") or "")[:300],
          str(row)))
    return cur.rowcount

def main():
    if not API_KEY:
        print("DATA_GO_KR_KEY not set; skip API.")
        return
    conn = sqlite3.connect("cases.db"); conn.execute("PRAGMA journal_mode=WAL")
    ensure_schema(conn)
    start, step, total = 1, 1000, 0
    while True:
        url = API_URL % {"KEY": API_KEY, "start": start, "end": start + step - 1}
        r = requests.get(url, timeout=30, headers={"User-Agent":"glefit/1.0"})
        r.raise_for_status()
        data = r.json()
        rows = (data.get("I0470", {}) or {}).get("row", []) or []
        if not rows: break
        ins = 0
        for row in rows:
            ins += upsert(conn, row)
        conn.commit()
        total += ins
        print(f"[MFDS API] fetched {len(rows)} rows, inserted≈{ins} (total≈{total})")
        start += step
        time.sleep(0.3)
    conn.close()
    print("[MFDS API] done.")

if __name__ == "__main__":
    main()
