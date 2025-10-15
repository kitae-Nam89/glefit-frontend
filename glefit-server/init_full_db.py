# init_full_db.py
# 목적: sanctions_cases.db 를 ingest_cases.py 가 기대하는 정규 스키마로 초기화 + 기본 시드 입력
# - 기존 DB가 있으면 .bak로 백업
# - agencies / laws / cases / case_rules / case_tags 테이블 생성
# - 기본 기관/법령 시드 입력

import sqlite3, os, shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "sanctions_cases.db")
BAK_PATH = os.path.join(BASE_DIR, "sanctions_cases.db.bak")

def backup_db():
    if os.path.exists(DB_PATH):
        # 기존 DB 백업
        shutil.copy2(DB_PATH, BAK_PATH)
        print(f"🗂  기존 DB 백업 완료 → {BAK_PATH}")

def init_schema():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
    PRAGMA foreign_keys = ON;

    DROP TABLE IF EXISTS case_tags;
    DROP TABLE IF EXISTS case_rules;
    DROP TABLE IF EXISTS cases;
    DROP TABLE IF EXISTS laws;
    DROP TABLE IF EXISTS agencies;

    CREATE TABLE agencies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,      -- MFDS, FTC, FSS, KCSC, MEDADV
      name TEXT NOT NULL,             -- 기관명
      homepage TEXT
    );

    CREATE TABLE laws (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT,                      -- MEDICAL_ACT 등
      title TEXT NOT NULL,            -- 법령/고시명
      article TEXT,                   -- 조(예: 제56조)
      clause TEXT,                    -- 항/호
      note TEXT
    );

    CREATE TABLE cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agency_id INTEGER NOT NULL,
      case_code TEXT,                 -- 사건번호 등 (우린 비워둘 예정)
      year INTEGER,
      title TEXT NOT NULL,            -- (마스킹 후 저장)
      summary TEXT,                   -- (마스킹 후 저장)
      law_id INTEGER,                 -- 대표 법령 매핑
      decision TEXT,                  -- 경고/시정명령/과징금...
      penalty TEXT,                   -- 금액/세부 (우린 비워둘 예정)
      decided_at TEXT,                -- YYYY-MM-DD
      source_url TEXT,                -- 출처 링크
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (agency_id) REFERENCES agencies(id),
      FOREIGN KEY (law_id) REFERENCES laws(id)
    );

    CREATE TABLE case_rules (
      case_id INTEGER NOT NULL,       -- cases.id
      rule_id TEXT NOT NULL,          -- YAML 규칙 id
      PRIMARY KEY (case_id, rule_id)
    );

    CREATE TABLE case_tags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL,       -- cases.id
      tag TEXT NOT NULL
    );
    """)
    conn.commit()

    # 기본 기관/법령 시드
    agencies = [
        ("MFDS","식품의약품안전처","https://www.mfds.go.kr/"),
        ("FTC","공정거래위원회","https://www.ftc.go.kr/"),
        ("FSS","금융감독원","https://www.fss.or.kr/"),
        ("KCSC","방송통신심의위원회","https://www.kocsc.or.kr/"),
        ("MEDADV","의료광고심의위원회(복지부 위탁)","https://medi-ad.or.kr/")
    ]
    laws = [
        ("FOOD_AD_ACT","식품표시광고법","제8조",None,"거짓·과장 표시·광고 금지"),
        ("MEDICAL_ACT","의료법","제56조",None,"의료광고 금지행위"),
        ("FIN_CONS_PROT_ACT","금융소비자보호법","제19조",None,"광고 규제"),
        ("BROADCAST_REVIEW_RULE","방송심의에 관한 규정",None,None,"광고 관련 조항"),
        ("FTC_AD_ACT","표시·광고의 공정화에 관한 법률",None,None,"부당한 표시·광고 금지")
    ]
    cur.executemany("INSERT INTO agencies(code,name,homepage) VALUES (?,?,?)", agencies)
    cur.executemany("INSERT INTO laws(code,title,article,clause,note) VALUES (?,?,?,?,?)", laws)
    conn.commit()
    conn.close()
    print("✅ 스키마 생성 + 기본 시드 입력 완료")

def main():
    backup_db()
    init_schema()
    print("🎉 sanctions_cases.db 초기화가 완료되었습니다.")

if __name__ == "__main__":
    main()
