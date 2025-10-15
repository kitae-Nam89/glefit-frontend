# ingest_cases.py
# 사용:  python ingest_cases.py --agency all --since 2019 --max 5000
#        python ingest_cases.py --agency mfds
#        python ingest_cases.py --dry-run  (DB 반영 없이 파싱만 확인)
import os, re, sys, time, json, argparse, sqlite3, datetime, html
from dataclasses import dataclass
from typing import List, Dict, Optional, Iterable, Tuple
import requests
from bs4 import BeautifulSoup

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "sanctions_cases.db")
UA       = {"User-Agent": "glefit-bot/1.0 (+for compliance report; contact: admin)"}

# ---------- 공통 DB 유틸 ----------
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def get_lookup_id(conn, table, code):
    cur = conn.execute(f"SELECT id FROM {table} WHERE code=?", (code,))
    r = cur.fetchone()
    return r[0] if r else None

def upsert_case(conn, agency_id:int, data:dict) -> int:
    # 고유키는 (agency_id, case_code, title, decided_at) 조합으로 보수적 중복 방지
    cur = conn.execute("""
        SELECT id FROM cases
        WHERE agency_id=? AND IFNULL(case_code,'')=IFNULL(?, '') AND IFNULL(decided_at,'')=IFNULL(?, '')
              AND title=?
    """, (agency_id, data.get("case_code"), data.get("decided_at"), data["title"]))
    row = cur.fetchone()
    if row:
        case_id = row[0]
        conn.execute("""
          UPDATE cases SET summary=?, law_id=?, decision=?, penalty=?, source_url=?, updated_at=datetime('now')
          WHERE id=?
        """,(data.get("summary"), data.get("law_id"), data.get("decision"), data.get("penalty"), data.get("source_url"), case_id))
        return case_id
    cur = conn.execute("""
      INSERT INTO cases(agency_id, case_code, year, title, summary, law_id, decision, penalty, decided_at, source_url)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        agency_id, data.get("case_code"), data.get("year"), data["title"], data.get("summary"),
        data.get("law_id"), data.get("decision"), data.get("penalty"), data.get("decided_at"), data.get("source_url")
    ))
    return cur.lastrowid

def add_tags(conn, case_id:int, tags:Iterable[str]):
    for t in set([x.strip() for x in tags if x and x.strip()]):
        conn.execute("INSERT INTO case_tags(case_id, tag) VALUES (?,?)", (case_id, t))

def link_rules(conn, case_id:int, rule_ids:Iterable[str]):
    for r in set([x.strip() for x in rule_ids if x and x.strip()]):
        conn.execute("INSERT OR IGNORE INTO case_rules(case_id, rule_id) VALUES (?,?)", (case_id, r))

# ---------- 간단 규칙 매핑(제목/요약 키워드→YAML 규칙 id 힌트) ----------
KEYWORD_TO_RULES = {
    # 식품/건기식
    "혈압": ["FOOD-DISEASE-CLAIM-02","HFS-DISEASE-CLAIM-A"],
    "혈당": ["FOOD-DISEASE-CLAIM-02","HFS-DISEASE-CLAIM-A"],
    "콜레스테롤": ["FOOD-DISEASE-CLAIM-02","HFS-DISEASE-CLAIM-A"],
    "면역": ["FOOD-DISEASE-CLAIM-02","HFS-ABSOLUTE-A"],
    # 의료
    "완치": ["MED-OVERCLAIM-01","MED-OVERCLAIM-CONTEXT-A"],
    "전후": ["MED-BEFORE-AFTER-03","MED-BEFORE-AFTER-04"],
    "부작용 없음": ["MED-RISK-OMISSION-05","MULTI-LINGUAL-ZERO"],
    "리프팅": ["MED-COSMETIC-EFFECT-01","MED-COSMETIC-EFFECT-03"],
    # 공정위
    "국내 1위": ["FTC-ABSOLUTE-CLAIM-01"],
    "최고": ["FTC-ABSOLUTE-CLAIM-01"],
    "유일": ["FTC-ABSOLUTE-CLAIM-01"],
    # 금감원
    "원금 보장": ["FSS-PRINCIPAL-GUAR-01","FSS-NO-RISK-04"],
    "무위험": ["FSS-PRINCIPAL-GUAR-01","FSS-NO-RISK-04"],
    # 방심위
    "선정": ["KCSC-OBSCENE-01"],
    "도박": ["KCSC-ILLEGAL-03"],
}

def guess_rules(title:str, summary:str)->List[str]:
    text = f"{title} {summary or ''}"
    hits=[]
    for k, rules in KEYWORD_TO_RULES.items():
        if k in text:
            hits.extend(rules)
    return list(dict.fromkeys(hits))

# ---------- 스크레이퍼 베이스 ----------
@dataclass
class CaseItem:
    title: str
    summary: Optional[str]
    decided_at: Optional[str]
    source_url: Optional[str]
    case_code: Optional[str]
    decision: Optional[str]
    law_title: Optional[str]
    law_article: Optional[str]
    penalty: Optional[str]

class BaseScraper:
    code: str
    law_default_code: Optional[str] = None  # laws.code 매핑
    start_urls: List[str] = []
    def __init__(self, since:int, max_items:int, delay:float):
        self.since = since
        self.max_items = max_items
        self.delay = delay
        self.items: List[CaseItem] = []

    def fetch(self, url)->BeautifulSoup:
        r = requests.get(url, headers=UA, timeout=20)
        r.raise_for_status()
        return BeautifulSoup(r.text, "html.parser")

    def parse_list(self)->Iterable[CaseItem]:
        raise NotImplementedError

    def run(self)->List[CaseItem]:
        for item in self.parse_list():
            if len(self.items) >= self.max_items:
                break
            # 연도 필터
            y = None
            if item.decided_at and re.match(r"\d{4}-\d{2}-\d{2}", item.decided_at):
                y = int(item.decided_at[:4])
            elif item.decided_at and re.match(r"\d{4}", item.decided_at):
                y = int(item.decided_at[:4])
            if y and y < self.since:
                continue
            self.items.append(item)
            time.sleep(self.delay)
        return self.items

# ---------- 기관별 매우 보수적 파서 (페이지 구조는 바뀔 수 있어 필요시 수정) ----------
class MFDScraper(BaseScraper):
    code = "MFDS"
    law_default_code = "FOOD_AD_ACT"
    # 행정처분/보도자료 목록(예시): 실제 서비스에서 기관 사이트 구조에 맞게 갱신 필요
    start_urls = [
        # 아래 URL들은 기관 구조 변경 시 수정 필요. 키워드 검색 URL을 권장.
        "https://www.mfds.go.kr/brd/m_76/list.do",     # 보도자료
        "https://www.mfds.go.kr/brd/m_99/list.do",     # 공고/공시
    ]
    def parse_list(self):
        for url in self.start_urls:
            soup = self.fetch(url)
            for a in soup.select("a"):  # 사이트마다 적절한 셀렉터로 교체 필요
                title = a.get_text(strip=True)
                href  = a.get("href")
                if not title or not href: 
                    continue
                if not re.search("(광고|행정처분|제재|표시|위반|건강기능|식품)", title):
                    continue
                link = href if href.startswith("http") else requests.compat.urljoin(url, href)
                # 상세 페이지에서 날짜/요약 뽑기(보수적)
                decided_at=None; summary=None
                try:
                    ds = self.fetch(link)
                    date_el = ds.select_one("span, .date, .reg_date")
                    if date_el: decided_at = re.sub(r"[^0-9\-]", "", date_el.get_text(" ", strip=True))[:10] or None
                    body = ds.select_one("#contents, .bdView, .board-view, article, .content")
                    if body: summary = body.get_text(" ", strip=True)[:350]
                except Exception:
                    pass
                yield CaseItem(
                    title=title, summary=summary, decided_at=decided_at,
                    source_url=link, case_code=None, decision=None,
                    law_title="식품표시광고법", law_article="제8조", penalty=None
                )

class FTCScraper(BaseScraper):
    code = "FTC"
    law_default_code = "FTC_AD_ACT"
    start_urls = ["https://www.ftc.go.kr/site/ftc/ex/bbs/List.do?cbIdx=1088"] # 보도자료(예시)
    def parse_list(self):
        for url in self.start_urls:
            soup = self.fetch(url)
            for a in soup.select("a"):
                title = a.get_text(strip=True)
                href  = a.get("href")
                if not title or not href:
                    continue
                if not re.search("(표시광고|광고법|부당|과장|1위|유일|과징금|시정)", title):
                    continue
                link = href if href.startswith("http") else requests.compat.urljoin(url, href)
                decided_at=None; summary=None
                try:
                    ds = self.fetch(link)
                    date_el = ds.find(text=re.compile(r"\d{4}-\d{2}-\d{2}"))
                    if date_el: decided_at = re.search(r"\d{4}-\d{2}-\d{2}", date_el).group(0)
                    body = ds.select_one("article, .board_view, .content")
                    if body: summary = body.get_text(" ", strip=True)[:350]
                except Exception:
                    pass
                yield CaseItem(title=title, summary=summary, decided_at=decided_at,
                               source_url=link, case_code=None, decision="시정명령", 
                               law_title="표시·광고의 공정화에 관한 법률", law_article=None, penalty=None)

class FSSScraper(BaseScraper):
    code = "FSS"
    law_default_code = "FIN_CONS_PROT_ACT"
    start_urls = ["https://www.fss.or.kr/fss/bbs/B0000133/list.do"]  # 보도자료(예시)
    def parse_list(self):
        for url in self.start_urls:
            soup = self.fetch(url)
            for a in soup.select("a"):
                title=a.get_text(strip=True); href=a.get("href")
                if not title or not href: 
                    continue
                if not re.search("(광고|원금|수익|무위험|과징금|위반|제재)", title):
                    continue
                link = href if href.startswith("http") else requests.compat.urljoin(url, href)
                decided_at=None; summary=None
                try:
                    ds = self.fetch(link)
                    date_el = ds.find(text=re.compile(r"\d{4}-\d{2}-\d{2}"))
                    if date_el: decided_at = re.search(r"\d{4}-\d{2}-\d{2}", date_el).group(0)
                    body = ds.select_one("article, .board_view, .content")
                    if body: summary = body.get_text(" ", strip=True)[:350]
                except Exception:
                    pass
                yield CaseItem(title=title, summary=summary, decided_at=decided_at,
                               source_url=link, case_code=None, decision=None,
                               law_title="금융소비자보호법", law_article="제19조", penalty=None)

class KCSCScraper(BaseScraper):
    code = "KCSC"
    law_default_code = "BROADCAST_REVIEW_RULE"
    start_urls = ["https://www.kocsc.or.kr/youth/decide/decideList.do"]  # 심의결정 현황(예시)
    def parse_list(self):
        for url in self.start_urls:
            soup = self.fetch(url)
            for a in soup.select("a"):
                title=a.get_text(strip=True); href=a.get("href")
                if not title or not href: 
                    continue
                if not re.search("(광고|의료|선정|도박|제재|법정제재)", title):
                    continue
                link = href if href.startswith("http") else requests.compat.urljoin(url, href)
                decided_at=None; summary=None; decision=None
                try:
                    ds = self.fetch(link)
                    date_el = ds.find(text=re.compile(r"\d{4}-\d{2}-\d{2}"))
                    if date_el: decided_at = re.search(r"\d{4}-\d{2}-\d{2}", date_el).group(0)
                    body = ds.select_one("article, .board_view, .content")
                    if body: summary = body.get_text(" ", strip=True)[:350]
                    if re.search("(법정제재|주의|경고)", summary or ""):
                        decision = re.search("(법정제재|주의|경고)", summary).group(1)
                except Exception:
                    pass
                yield CaseItem(title=title, summary=summary, decided_at=decided_at,
                               source_url=link, case_code=None, decision=decision,
                               law_title="방송심의에 관한 규정", law_article=None, penalty=None)

class MEDADVScraper(BaseScraper):
    code = "MEDADV"
    law_default_code = "MEDICAL_ACT"
    start_urls = ["https://medi-ad.or.kr"]  # 의료광고심의위(예시: 게시판 URL로 교체)
    def parse_list(self):
        # 실제 사이트 구조에 맞춰 게시판 URL/셀렉터 갱신 필요
        for url in self.start_urls:
            soup = self.fetch(url)
            for a in soup.select("a"):
                title=a.get_text(strip=True); href=a.get("href")
                if not title or not href: 
                    continue
                if not re.search("(의료광고|심의|반려|불수리|광고제한|위반|전후|완치)", title):
                    continue
                link = href if href.startswith("http") else requests.compat.urljoin(url, href)
                decided_at=None; summary=None
                try:
                    ds = self.fetch(link)
                    body = ds.select_one("article, .board_view, .content")
                    if body: summary = body.get_text(" ", strip=True)[:350]
                except Exception:
                    pass
                yield CaseItem(title=title, summary=summary, decided_at=decided_at,
                               source_url=link, case_code=None, decision="심의 반려",
                               law_title="의료법", law_article="제56조", penalty=None)

SCRAPERS = {
    "mfds":   MFDScraper,
    "ftc":    FTCScraper,
    "fss":    FSSScraper,
    "kcsc":   KCSCScraper,
    "medadv": MEDADVScraper,
}

def pick_law_id(conn, law_title:str, article:Optional[str])->Optional[int]:
    # title/기사에 맞춰 laws 테이블에서 찾아 매핑
    title_key = None
    if "의료법" in law_title: title_key="MEDICAL_ACT"
    elif "식품표시광고법" in law_title: title_key="FOOD_AD_ACT"
    elif "금융소비자보호법" in law_title: title_key="FIN_CONS_PROT_ACT"
    elif "표시·광고의 공정화" in law_title: title_key="FTC_AD_ACT"
    elif "방송심의" in law_title: title_key="BROADCAST_REVIEW_RULE"
    if not title_key:
        return None
    cur = conn.execute("SELECT id FROM laws WHERE code=?", (title_key,))
    r = cur.fetchone()
    return r[0] if r else None

def run(agency:str, since:int, max_items:int, delay:float, dry_run:bool):
    conn = db_conn()
    # lookup
    agency_ids = {k: get_lookup_id(conn, "agencies", v.code.upper()) for k,v in SCRAPERS.items()}
    law_cache = {}

    targets = [agency] if agency!="all" else list(SCRAPERS.keys())
    total_new=0
    for key in targets:
        Scr = SCRAPERS[key]
        print(f"[{key}] crawling…")
        items = Scr(since=since, max_items=max_items, delay=delay).run()
        print(f" → {len(items)} items parsed.")

        for it in items:
            a_id = agency_ids[key]
            y = None
            if it.decided_at and re.match(r"\d{4}", it.decided_at):
                y = int(it.decided_at[:4])
            data = {
                "case_code": it.case_code,
                "year": y,
                "title": it.title,
                "summary": it.summary,
                "decision": it.decision,
                "penalty": it.penalty,
                "decided_at": it.decided_at,
                "source_url": it.source_url,
                "law_id": pick_law_id(conn, it.law_title or "", it.law_article),
            }

            # 규칙 연결 힌트
            rules = guess_rules(it.title, it.summary or "")

            if dry_run:
                print("  DRY-RUN:", data["title"][:70], "| rules:", ",".join(rules))
                continue

            case_id = upsert_case(conn, a_id, data)
            add_tags(conn, case_id, rules + [k for k in KEYWORD_TO_RULES.keys() if k in (it.title + (it.summary or ""))])
            link_rules(conn, case_id, rules)
            total_new += 1
        if not dry_run:
            conn.commit()
        time.sleep(delay)
    conn.close()
    print(f"Done. inserted/updated ~{total_new} rows.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--agency", choices=["all","mfds","ftc","fss","kcsc","medadv"], default="all")
    ap.add_argument("--since", type=int, default=2019, help="해당 연도 이후만 수집")
    ap.add_argument("--max", type=int, default=2000, help="기관별 최대 수집 개수")
    ap.add_argument("--delay", type=float, default=0.7, help="요청 간 지연(초)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    run(args.agency, args.since, args.max, args.dry_run)
