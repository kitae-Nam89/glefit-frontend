# -*- coding: utf-8 -*-
import os, re, json, time, sqlite3, unicodedata
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS

# [ADD] Auth imports
from datetime import datetime, timedelta
from functools import wraps
import jwt
from passlib.hash import pbkdf2_sha256 as bcrypt


from openai import OpenAI
import yaml
from collections import defaultdict
# --- [LOCAL SPELLCHECK] begin ---
import os, re
from symspellpy import SymSpell, Verbosity
import uuid

_HANGUL_RE = re.compile(r"[가-힣]+")
DATA_DIR = "data"
KO_WORDS_PATH = os.path.join(DATA_DIR, "ko_words.txt")   # "단어<TAB>빈도"
WHITE_PATH    = os.path.join(DATA_DIR, "whitelist.txt")  # 줄당 1개 단어

_sym = None
_whitelist = set()

def _init_symspell():
    import os
    os.makedirs(DATA_DIR, exist_ok=True)
    global _sym, _whitelist
    _sym = SymSpell(max_dictionary_edit_distance=2, prefix_length=7)

    if os.path.exists(KO_WORDS_PATH):
        _sym.load_dictionary(KO_WORDS_PATH, term_index=0, count_index=1,
                             separator="\t", encoding="utf-8")

    custom_path = os.path.join(DATA_DIR, "custom_words.txt")
    if os.path.exists(custom_path):
        _sym.load_dictionary(custom_path, term_index=0, count_index=1,
                             separator="\t", encoding="utf-8")

    _whitelist = set()
    if os.path.exists(WHITE_PATH):
        for enc in ("utf-8","utf-8-sig","cp949","euc-kr"):
            try:
                with open(WHITE_PATH,"r",encoding=enc) as f:
                    _whitelist = {ln.strip() for ln in f if ln.strip()}
                break
            except UnicodeDecodeError:
                continue

    print(f"🔤 SymSpell ready: words={len(_sym.words)}, whitelist={len(_whitelist)}")

def _token_spans_ko(text: str):
    """한글 연속구간을 토큰으로 뽑아 (start, end, token)"""
    for m in _HANGUL_RE.finditer(text or ""):
        yield m.start(), m.end(), m.group()
# --- [LOCAL SPELLCHECK] end ---


# ================== 기본 설정 ==================
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY가 설정되지 않았습니다 (.env 확인)")

client = OpenAI(api_key=OPENAI_API_KEY, timeout=30)

MODEL = "gpt-4o"
DB_PATH = "rewrite.db"
MAX_CHARS_PER_CHUNK = 4000

# [ADD] JWT config
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_TO_RANDOM_SECRET")
JWT_ALG = "HS256"
# [ADD] ensure users table
def ensure_users_table():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_active INTEGER DEFAULT 0,
        paid_until TEXT,
        role TEXT DEFAULT 'user',
        notes TEXT
    )
    """)
    conn.commit()
    conn.close()

ensure_users_table()

def migrate_users_table():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 로그인/세션 관리 및 편의 필드 추가 (이미 있으면 넘어감)
    try: cur.execute("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0")
    except Exception: pass
    try: cur.execute("ALTER TABLE users ADD COLUMN last_jti TEXT")
    except Exception: pass
    try: cur.execute("ALTER TABLE users ADD COLUMN allow_concurrent INTEGER DEFAULT 0")
    except Exception: pass
    try: cur.execute("ALTER TABLE users ADD COLUMN site_url TEXT")
    except Exception: pass
    try: cur.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
    except Exception: pass

    # ★ 신규: 게시글 작성 정지 플래그
    try: cur.execute("ALTER TABLE users ADD COLUMN posting_blocked INTEGER DEFAULT 0")
    except Exception: pass
    # (선택) 인덱스
    try: cur.execute("CREATE INDEX IF NOT EXISTS idx_users_posting_blocked ON users(posting_blocked)")
    except Exception: pass

    conn.commit()
    conn.close()


# === (BOOT SEED) 서버 기동 시 관리자 계정 보장 ===
def _boot_seed_admin():
    try:
        import sqlite3, os
        from datetime import datetime, timedelta
        # passlib 해시를 전역에서: from passlib.hash import pbkdf2_sha256 as bcrypt

        admin_user = (os.getenv("ADMIN_USER") or "").strip()
        admin_pass = (os.getenv("ADMIN_PASS") or "").strip()
        admin_days = int(os.getenv("ADMIN_DAYS") or 0)
        if not admin_user or not admin_pass or admin_days <= 0:
            return

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # 최소 스키마 보장 (테이블/인덱스만)
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            paid_until TEXT,
            role TEXT DEFAULT 'user',
            notes TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
        """)

        paid_until = (datetime.utcnow() + timedelta(days=admin_days)).isoformat()
        cur.execute("""
        INSERT INTO users (username, password_hash, is_active, paid_until, role, notes)
        VALUES (?, ?, 1, ?, 'admin', 'seed admin')
        ON CONFLICT(username) DO UPDATE SET
          password_hash = excluded.password_hash,
          is_active     = 1,
          paid_until    = excluded.paid_until,
          role          = 'admin',
          notes         = 'seed admin'
        """, (admin_user, bcrypt.hash(admin_pass), paid_until))

        conn.commit()
        conn.close()
        print(f"[boot-seed] admin ready: {admin_user} (until {paid_until})")

    except Exception as e:
        print("[boot-seed] skip/error:", e)

# [ADD] 운영/통계/캐시용 테이블
def migrate_ops_tables():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS usage_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,           -- verify|policy|dedup_intra|dedup_inter|spell_local|login
        files_count INTEGER,
        created_at TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS error_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        path TEXT,
        status INTEGER,
        message TEXT,
        created_at TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agreements (
        username TEXT PRIMARY KEY,
        agreed_at TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS visit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,            -- 로그인 전/후 모두 기록(없으면 빈문자)
        path TEXT,                -- 프론트가 보내는 현재 경로/스크린 명
        ip TEXT,
        user_agent TEXT,
        created_at TEXT
    )""")

    # --- [ADD] board posts & limits ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS board_posts (
        id TEXT PRIMARY KEY,
        username TEXT,
        text TEXT,
        pinned INTEGER DEFAULT 0,
        ts INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS board_limits (
        username TEXT PRIMARY KEY,
        daily_limit INTEGER DEFAULT 2
    )
    """)


    conn.commit()
    conn.close()

# === INSERT near line ~217 (after migrate_ops_tables, before "마이그레이션 실행") ===
def migrate_board_tables():
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS board_posts (
        id TEXT PRIMARY KEY,
        username TEXT,
        text TEXT,
        pinned INTEGER DEFAULT 0,
        ts INTEGER
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS board_limits (
        username TEXT PRIMARY KEY,
        daily_limit INTEGER DEFAULT 2
    )""")

    # --- NEW: hidden 컬럼(소프트 삭제/숨김) 보강 ---
    cur.execute("PRAGMA table_info(board_posts)")
    cols = [r[1] for r in cur.fetchall()]
    if "hidden" not in cols:
        cur.execute("ALTER TABLE board_posts ADD COLUMN hidden INTEGER DEFAULT 0")

    conn.commit(); conn.close()



def log_visit(username, path):
    try:
        ip  = request.headers.get("CF-Connecting-IP") or request.remote_addr or ""
        ua  = request.headers.get("User-Agent") or ""
        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute(
            "INSERT INTO visit_logs (username, path, ip, user_agent, created_at) VALUES (?,?,?,?,?)",
            (username or "", path or "", ip[:120], ua[:300], datetime.utcnow().isoformat())
        )
        conn.commit(); conn.close()
    except Exception:
        pass

# 마이그레이션 실행
migrate_users_table()
migrate_ops_tables()
migrate_board_tables()
_boot_seed_admin()

# [ADD] user helpers & guards
def _get_user(username: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, is_active, paid_until, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0], "username": row[1], "password_hash": row[2],
        "is_active": bool(row[3]),
        "paid_until": row[4],
        "role": row[5] or "user",
    }

# === [ADD] Non-admin text size limit ===============================
MAX_TEXT_BYTES_NON_ADMIN = 100 * 1024  # 100KB

def _utf8_len(s: str) -> int:
    if not s:
        return 0
    return len(s.encode("utf-8", "ignore"))

def _is_admin_current() -> bool:
    try:
        uname = _username_from_req()
        u = _get_user(uname) if uname else None
        return (u or {}).get("role") == "admin"
    except Exception:
        return False

def enforce_size_limit_or_400(texts_or_iterable):
    """
    - 관리자면 무제한 통과
    - 비관리자(일반/체험판)는 '항목당' 100KB 초과 시 400 반환
    - texts_or_iterable: str | list[str] | list[{'text':str}, ...]
    """
    if _is_admin_current():
        return  # admin unlimited

    # normalize
    if isinstance(texts_or_iterable, str):
        payloads = [texts_or_iterable]
    else:
        payloads = []
        for item in (texts_or_iterable or []):
            if isinstance(item, str):
                payloads.append(item)
            elif isinstance(item, dict) and "text" in item:
                payloads.append(item.get("text") or "")
            else:
                payloads.append(str(item or ""))

    for idx, s in enumerate(payloads):
        if _utf8_len(s) > MAX_TEXT_BYTES_NON_ADMIN:
            return jsonify({
                "ok": False,
                "error": "TEXT_TOO_LARGE",
                "message": f"일반/체험판은 항목당 100KB(102400 bytes)까지만 허용됩니다. (#{idx+1})",
                "limit_bytes": MAX_TEXT_BYTES_NON_ADMIN
            }), 400
    return
# ===================================================================

def _remaining_days(paid_until: str) -> int:
    if not paid_until:
        return 0
    try:
        delta = datetime.fromisoformat(paid_until) - datetime.utcnow()
        return max(0, delta.days)
    except Exception:
        return 0

# [ADD] 사용량/에러 로깅 헬퍼
def log_usage(username, action, files_count=0):
    try:
        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute("INSERT INTO usage_logs (username, action, files_count, created_at) VALUES (?,?,?,?)",
                    (username or "", action or "", int(files_count or 0), datetime.utcnow().isoformat()))
        conn.commit(); conn.close()
    except Exception:
        pass

def log_error(username, path, status, message):
    try:
        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute("INSERT INTO error_logs (username, path, status, message, created_at) VALUES (?,?,?,?,?)",
                    (username or "", path or "", int(status or 0), str(message)[:500], datetime.utcnow().isoformat()))
        conn.commit(); conn.close()
    except Exception:
        pass

def _username_from_req():
    try:
        auth = request.headers.get("Authorization","")
        tok = auth.split(" ",1)[1]
        data = jwt.decode(tok, JWT_SECRET, algorithms=[JWT_ALG])
        return data.get("sub") or ""
    except Exception:
        return ""

def _is_paid_and_active(u: dict) -> bool:
    if not u or not u.get("is_active"):
        return False
    try:
        pu = u.get("paid_until")
        if not pu:
            return False
        return datetime.utcnow() <= datetime.fromisoformat(pu)
    except Exception:
        return False

def _origin_allowed(user_site_url: str) -> bool:
    if not user_site_url:
        return True  # 주소 제한 안 건 계정
    origin = (request.headers.get("Origin") or "").lower()
    referer = (request.headers.get("Referer") or "").lower()
    target = user_site_url.lower()
    return (target in origin) or (target in referer)

def require_user(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return "", 200

        auth = request.headers.get("Authorization","").strip()
        if not auth.startswith("Bearer "):
            return jsonify({"error":"Unauthorized"}), 401
        token = auth.split(" ",1)[1]

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception:
            return jsonify({"error":"Invalid token"}), 401

        username = data.get("sub","")
        tok_ver  = int(data.get("ver", 0) or 0)
        tok_jti  = data.get("jti","") or ""

                # DB에서 최신 상태(활성/기간/사이트/버전/JTI/동시접속) 확인
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute(
            "SELECT is_active, paid_until, site_url, token_version, last_jti, allow_concurrent "
            "FROM users WHERE username=?",
            (username,)
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"error":"Unauthorized"}), 401

        is_active, paid_until, site_url, db_ver, db_jti, allow_concurrent = (
            row[0], row[1], (row[2] or ""), int(row[3] or 0), (row[4] or ""), bool(row[5])
        )

        # 결제/기간/활성 체크
        try:
            if not is_active or not paid_until or datetime.utcnow() > datetime.fromisoformat(paid_until):
                return jsonify({"error":"Payment required or expired"}), 402
        except Exception:
            return jsonify({"error":"Payment required or expired"}), 402

        # 단일 로그인 강제: 동시접속 허용이 아닐 때만 버전/JTI 검증
        if not allow_concurrent:
            if tok_ver != db_ver or (db_jti and tok_jti != db_jti):
                return jsonify({"error":"Session invalidated. Please log in again.", "code":"SESSION"}), 401

        # 도메인 제한(옵션)
        if site_url:
            origin  = (request.headers.get("Origin") or "").lower()
            referer = (request.headers.get("Referer") or "").lower()
            if site_url.lower() not in origin and site_url.lower() not in referer:
                return jsonify({"error":"Origin not allowed"}), 403

        return fn(*args, **kwargs)
    return wrapper

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization","").strip()
        if not auth.startswith("Bearer "):
            return jsonify({"error":"Unauthorized"}), 401
        token = auth.split(" ",1)[1]

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception:
            return jsonify({"error":"Invalid token"}), 401

        username = data.get("sub","")
        tok_ver  = int(data.get("ver", 0) or 0)
        tok_jti  = data.get("jti","") or ""

        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute(
            "SELECT role, is_active, paid_until, token_version, last_jti, allow_concurrent "
            "FROM users WHERE username=?",
            (username,)
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"error":"Unauthorized"}), 401

        role, is_active, paid_until, db_ver, db_jti, allow_concurrent = (
            (row[0] or "user"), row[1], row[2], int(row[3] or 0), (row[4] or ""), bool(row[5])
        )

        # 결제/기간/활성 체크
        try:
            if not is_active or not paid_until or datetime.utcnow() > datetime.fromisoformat(paid_until):
                return jsonify({"error":"Payment required or expired"}), 402
        except Exception:
            return jsonify({"error":"Payment required or expired"}), 402

        # 단일 로그인 강제 — 허용 계정은 예외
        if not allow_concurrent:
            if tok_ver != db_ver or (db_jti and tok_jti != db_jti):
                return jsonify({"error":"Session invalidated. Please log in again.", "code":"SESSION"}), 401

        if role != "admin":
            return jsonify({"error":"Admin only"}), 403

        return fn(*args, **kwargs)
    return wrapper


RULE_PATH = os.getenv("RULE_PATH", "kr-medhealth.yaml")
RULES = {}   # {"rules":[{...}], ...}
RULES_INDEX = {}  # {rule_id: rule_obj}

# === INSERT @ line 467 (right after require_admin ends) ===
def verify_board_auth(payload):
    """
    payload: {"username": "...", "password": "..."}
    - users 테이블의 자격 확인
    - 반환: (ok, username, is_admin)
    """
    try:
        u = (payload.get("username") or "").strip()
        p = payload.get("password") or ""
        user = _get_user(u)
        if not user or not bcrypt.verify(p, user["password_hash"]):
            return False, "", False
        # 결제/활성 유효
        if not _is_paid_and_active(user):
            return False, "", False
        is_admin = (user.get("role") == "admin")
        return True, user["username"], is_admin
    except Exception:
        return False, "", False

# ================== 유틸 ==================

# === username 규칙: 소문자 영문/숫자/._- 3~32자 ===
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")

def normalize_username(u: str) -> str:
    # 공백 제거 + 소문자 통일
    return (u or "").strip().lower()

def validate_username(u: str):
    if not USERNAME_RE.match(u or ""):
        raise ValueError("username must be 3-32 chars: a-z, 0-9, dot, underscore, hyphen only")

def search_db(sentence):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT alternative FROM sentences WHERE original = ?", (sentence,))
        rows = cur.fetchall()
        conn.close()
        return [r[0] for r in rows] if rows else []
    except Exception as e:
        print("DB 검색 오류:", e)
        return []

def find_all(text, substring, start_from=0):
    out = []
    i = start_from
    L = len(substring)
    if not substring:
        return out
    while True:
        i = text.find(substring, i)
        if i == -1:
            break
        out.append(i)
        i += L
    return out

def chunk_text_with_offsets(text, max_chars=MAX_CHARS_PER_CHUNK):
    chunks = []
    n = len(text)
    i = 0
    while i < n:
        end = min(i + max_chars, n)
        if end < n:
            cut = text.rfind("\n", i, end)
            if cut == -1 or cut <= i + int(max_chars * 0.3):
                cut = end
        else:
            cut = end
        chunks.append((i, text[i:cut]))
        i = cut
    return chunks

_json_array_pattern = re.compile(r"\[\s*{.*?}\s*\]", re.DOTALL)
def extract_json_array(s):
    if not s:
        return []
    s = re.sub(r"^```json\s*|\s*```$", "", s.strip(), flags=re.IGNORECASE | re.DOTALL)
    m = _json_array_pattern.search(s)
    if not m:
        try:
            j = json.loads(s)
            return j if isinstance(j, list) else []
        except:
            return []
    try:
        return json.loads(m.group(0))
    except Exception as e:
        print("JSON 파싱 실패:", e)
        return []

def basic_kr_sentence_split(text):
    parts = re.split(r"([\.?!]+|\n+)", text)
    out, buf = [], ""
    for p in parts:
        if p is None:
            continue
        buf += p
        if p.endswith((".", "?", "!", "\n")) or p.strip() == "":
            s = buf.strip()
            if s:
                out.append(s)
            buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out

def add_context(text, start, length, window=8):
    before = text[max(0, start - window): start]
    after  = text[start + length: start + length + window]
    return before, after

def gpt_call(model, messages):
    return client.chat.completions.create(model=model, messages=messages)

# --- 공백/문자 정규화 & 공백무시 키워드용 ---
def kr_norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    s = s.replace("%", "퍼센트")
    s = re.sub(r"\s+", " ", s)
    return s

def spacing_agnostic_regex(kw: str) -> str:
    parts = list(kw)
    return r"\s*".join(map(re.escape, parts))

# ================== 심의 규칙 로딩/스캔 ==================
def load_rules(path=RULE_PATH):
    global RULES, RULES_INDEX
    try:
        with open(path, "r", encoding="utf-8") as f:
            RULES = yaml.safe_load(f) or {}
        if not isinstance(RULES, dict):
            RULES = {}
        print(f"✅ 심의 규칙 로드 완료: {path}")
        pack = RULES.get("pack")
        ver = RULES.get("version")
        topics = RULES.get("topics")
        if pack or ver or topics:
            print(f"  - pack={pack}, version={ver}, topics={topics}")
        RULES_INDEX = {}
        for r in (RULES.get("rules") or []):
            rid = (r or {}).get("id")
            if rid:
                RULES_INDEX[str(rid)] = r
        print(f"  - rules indexed: {len(RULES_INDEX)}")
    except Exception as e:
        print("[WARN] 심의 규칙 로드 실패:", e)
        RULES, RULES_INDEX = {}, {}


load_rules()

# === (ADD) 사유/법령 매핑 유틸 (YAML meta 사용) ====================
def _load_reason_index_from_rules():
    meta = (RULES or {}).get("meta") or {}
    cats = meta.get("reason_categories") or {}
    mapping = []
    for ent in meta.get("rule_category_by_prefix") or []:
        try:
            rx = re.compile(ent.get("pattern", ""), re.IGNORECASE)
            mapping.append((rx, ent.get("category")))
        except re.error:
            pass
    return cats, mapping

REASON_CATS, REASON_MAP = _load_reason_index_from_rules()

def _reason_for_rule_id(rule_id: str):
    rid = rule_id or ""
    for rx, cat in (REASON_MAP or []):
        if rx.search(rid):
            info = (REASON_CATS or {}).get(cat) or {}
            reason = info.get("reason")
            legal  = info.get("legal")
            url    = info.get("legal_url")
            if not reason:
                return None, None
            small = None
            if legal and url:
                small = f"<small style='color:#777'>(근거: {legal} · <a href=\"{url}\" target=\"_blank\">법령</a>)</small>"
            elif legal:
                small = f"<small style='color:#777'>(근거: {legal})</small>"
            return f"사유: {reason}", small
    return None, None

_rule_id_rx = re.compile(r"\(rule:([^)]+)\)")
def attach_reasons(items):
    """
    결과 항목에 사용자 친화적 사유/출처를 부착하고,
    내부 rule ID 노출을 제거한다.
    우선순위:
      1) RULES_INDEX[rule_id]의 rationale / legal_ref
      2) meta(reason_categories/rule_category_by_prefix) 폴백
    """
    for it in items:
        rid = it.get("rule_id")
        if not rid:
            m = _rule_id_rx.search(it.get("reason","") or "")
            rid = m.group(1) if m else None

        reason_line = None
        legal_small = None

        # 1) 규칙 본문에서 직접 취득
        rule = RULES_INDEX.get(str(rid)) if rid else None
        if rule:
            rationale = rule.get("rationale") or rule.get("description") or ""
            legal     = rule.get("legal_ref")  or ""   # YAML에 선택적으로 추가
            if rationale:
                reason_line = rationale
            if legal:
                legal_small = f"<small style='color:#777'>(출처: {legal})</small>"

        # 2) 폴백: meta 카테고리 매핑 사용
        if not reason_line:
            rline, small = _reason_for_rule_id(rid or "")
            if rline:
                # rline 예: "사유: …" 형태 → 통일 위해 접두어 제거
                reason_line = rline.replace("사유:", "").strip()
            if small:
                legal_small = small

        if reason_line:
            it["reason_line"] = reason_line
        if legal_small:
            it["legal_small"] = legal_small

        # 화면 노출용 reason 문자열에서 (rule:XXX) 제거
        if it.get("reason"):
            it["reason"] = re.sub(_rule_id_rx, "", it["reason"]).strip()
    return items# =====================================================================

def _iter_rule_patterns(rule):
    patterns = ((rule or {}).get("patterns") or {}).get("any") or []
    for p in patterns:
        if not isinstance(p, dict):
            continue
        if p.get("type") in ("keyword", "regex", "phrase"):
            yield p

def _compile_regex_from_pattern(pat: dict):
    ptype = pat.get("type")
    flags = 0
    if str(pat.get("flags","")).lower().find("i") >= 0 or pat.get("casefold", True):
        flags |= re.IGNORECASE

    if ptype == "keyword":
        val = kr_norm(pat.get("value",""))
        if not val:
            return None, None
        if pat.get("spacing_agnostic", True):
            rx = spacing_agnostic_regex(val)
        else:
            rx = re.escape(val)
        return re.compile(rx, flags), f"kw:{val}"

    if ptype == "regex":
        val = pat.get("value","")
        if not val:
            return None, None
        return re.compile(val, flags), "rx"

    if ptype == "phrase":
        terms = [kr_norm(t) for t in (pat.get("terms") or []) if t]
        if len(terms) < 2:
            return None, None
        max_gap = int(pat.get("max_gap", 6))
        terms_rx = [spacing_agnostic_regex(t) for t in terms]
        rx = terms_rx[0]
        for nxt in terms_rx[1:]:
            rx += rf".{{0,{max_gap}}}" + nxt
        return re.compile(rx, flags), f"ph:{'|'.join(terms)}"
    return None, None

def _rule_excepts(rule):
    ex = ((rule or {}).get("except") or {}).get("any") or []
    out = []
    for r in ex:
        try:
            out.append(re.compile(r, re.IGNORECASE))
        except re.error:
            pass
    return out

def _scan_with_rule(text, rule):
    hits = []
    exceptors = _rule_excepts(rule)
    window = int((rule or {}).get("except_window", 14))
    for p in _iter_rule_patterns(rule):
        rx, _ = _compile_regex_from_pattern(p)
        if not rx:
            continue
        for m in rx.finditer(text):
            s, e = m.start(), m.end()
            seg = text[s:e]
            if exceptors:
                ctx = text[max(0, s - window): min(len(text), e + window)]
                if any(ex.search(ctx) for ex in exceptors):
                    continue
            hits.append((s, e, seg))
    return hits

def rule_scan(text):
    rules = (RULES or {}).get("rules") or []
    items = []
    gid = 0
    for rule in rules:
        rid   = rule.get("id", "")
        topic = rule.get("topic", "")
        sev   = (rule.get("severity") or "warn").lower()
        rationale = rule.get("rationale") or rule.get("description") or ""
        actions   = rule.get("actions") or []
        rule_type = "심의위반" if sev == "block" else "주의표현"

        for (s, e, seg) in _scan_with_rule(text, rule):
            before, after = add_context(text, s, e - s)
            sugg = []
            if any(str(a).startswith("suggest:") for a in actions):
                human = "표현 완화/근거 제시/주의문 병기 검토"
                if "MED" in " ".join(actions):
                    human = "의료 표현 완화 또는 객관 근거 제시"
                elif "HFS" in " ".join(actions):
                    human = "건기식/의약품 오인 방지 문구로 수정"
                elif "GEN_NEED_EVIDENCE" in " ".join(actions):
                    human = "비교·우월 표현은 출처/근거 병기"
                sugg = [human]
            else:
                sugg = ["문구 완화 또는 삭제 검토"]

            items.append({
                "id": f"r_{gid}",
                "type": rule_type,
                "original": seg,
                "suggestions": sugg[:3],
                "reason": f"[{topic}] {rationale or '규칙 매칭'}",
                "rule_id": rid,
                "severity": "high" if sev == "block" else "medium",
                "startIndex": s,
                "endIndex": e,
                "before": before,
                "after": after
            })
            gid += 1

    used = set()
    dedup = []
    for it in sorted(items, key=lambda x: (x["startIndex"], -(x["endIndex"]-x["startIndex"]))):
        k = (it["startIndex"], it["endIndex"], it["type"])
        if k in used:
            continue
        used.add(k)
        dedup.append(it)
    return dedup

# ============== (NEW) 도돌이표/유사문장 탐지 유틸 ==============
_punc_rx = re.compile(r"[^\w\u3131-\u318E\uAC00-\uD7A3]+", re.UNICODE)
_ws_rx = re.compile(r"\s+")

def _norm_for_dup(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    s = s.lower()
    s = _punc_rx.sub(" ", s)
    s = _ws_rx.sub(" ", s).strip()
    return s

def _char_ngrams(s: str, n=3):
    s = _norm_for_dup(s)
    return {s[i:i+n] for i in range(max(0, len(s)-n+1))} if s else set()

def _jaccard(a: set, b: set) -> float:
    if not a and not b: return 1.0
    if not a or not b:  return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0

def _sentence_spans(text):
    """문장 단위로 (start, end, raw_sentence) 반환"""
    sentences = basic_kr_sentence_split(text)
    spans = []
    cursor = 0
    for s in sentences:
        idx = text.find(s, cursor)
        if idx == -1:
            idx = text.find(s)
        if idx != -1:
            spans.append((idx, idx+len(s), s))
            cursor = idx + len(s)
    return spans

def _dedup_intra(text, min_len=6, sim_threshold=0.85):
    spans = _sentence_spans(text)
    # 1) exact 도돌이표(정규화 후 동일)
    buckets = defaultdict(list)  # norm -> [(i, start, end, raw)]
    for i, (s, e, raw) in enumerate(spans):
        n = _norm_for_dup(raw)
        if len(n) >= min_len:
            buckets[n].append((i, s, e, raw))

    exact_groups = []
    for n, occ in buckets.items():
        if len(occ) >= 2:
            exact_groups.append({
                "norm": n,
                "occurrences": [
                    {"index": i, "start": s, "end": e, "original": raw} for (i,s,e,raw) in occ
                ]
            })

    # 2) similar(자카드: 문자 3-gram)
    sims = []
    ngrams = []
    for i, (s, e, raw) in enumerate(spans):
        n = _norm_for_dup(raw)
        if len(n) >= min_len:
            ngrams.append((i, s, e, raw, _char_ngrams(raw, 3)))
    for a in range(len(ngrams)):
        i, s1, e1, r1, g1 = ngrams[a]
        for b in range(a+1, len(ngrams)):
            j, s2, e2, r2, g2 = ngrams[b]
            score = _jaccard(g1, g2)
            if score >= sim_threshold and r1 != r2:
                sims.append({
                    "i": i, "j": j, "score": round(score, 3),
                    "a": {"start": s1, "end": e1, "original": r1},
                    "b": {"start": s2, "end": e2, "original": r2}
                })

    return exact_groups, sims

def _dedup_inter(files, min_len=6, sim_threshold=0.85):
    """
    files: [{"name": str, "text": str}, ...]
    교차 파일 간 동일/유사 문장 탐지
    """
    # 수집
    recs = []  # (file_idx, name, sent_idx, start, end, raw, norm, ngrams)
    for fi, f in enumerate(files):
        name = f.get("name") or f"file_{fi+1}"
        text = f.get("text") or ""
        spans = _sentence_spans(text)
        for si, (s, e, raw) in enumerate(spans):
            n = _norm_for_dup(raw)
            if len(n) >= min_len:
                recs.append((fi, name, si, s, e, raw, n, _char_ngrams(raw, 3)))

    # exact
    exact_map = defaultdict(list)  # norm -> [occ...]
    for fi, name, si, s, e, raw, n, grams in recs:
        exact_map[n].append({"file": name, "fileIndex": fi, "sentIndex": si,
                             "start": s, "end": e, "original": raw})

    exact = []
    for n, occ in exact_map.items():
        # 서로 다른 파일에서 2개 이상일 때만 의미
        uniq_files = {o["fileIndex"] for o in occ}
        if len(uniq_files) >= 2:
            exact.append({"norm": n, "occurrences": occ})

    # similar
    sims = []
    for a in range(len(recs)):
        fi1, n1, si1, s1, e1, r1, norm1, g1 = recs[a]
        for b in range(a+1, len(recs)):
            fi2, n2, si2, s2, e2, r2, norm2, g2 = recs[b]
            if fi1 == fi2:  # 같은 파일은 intra에서 다룸
                continue
            score = _jaccard(g1, g2)
            if score >= sim_threshold and r1 != r2:
                sims.append({
                    "score": round(score, 3),
                    "a": {"fileIndex": fi1, "file": n1, "sentIndex": si1, "start": s1, "end": e1, "original": r1},
                    "b": {"fileIndex": fi2, "file": n2, "sentIndex": si2, "start": s2, "end": e2, "original": r2},
                })
    return exact, sims

# ==================== Flask ====================
from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)

# HEAD는 라우팅 매칭을 통과해야 하므로 캐치올 라우트가 필요
@app.route("/", defaults={"path": ""}, methods=["HEAD"])
@app.route("/<path:path>", methods=["HEAD"])
def __head_ok(path):
    return ("", 200, {"Content-Type": "text/plain; charset=utf-8"})

@app.route("/healthz", methods=["GET", "HEAD"])
def __healthz():
    if request.method == "HEAD":
        return ("", 200, {"Content-Type": "text/plain; charset=utf-8"})
    return jsonify({"ok": True})


# 1) HEAD 헬스체크/프록시 안전 가드 (모든 경로 공통)
@app.before_request
def _head_guard():
    if request.method == "HEAD":
        return ("", 200, {"Content-Type": "text/plain; charset=utf-8"})

# 2) CORS (프리뷰/터널/로컬 허용)
ALLOWED_ORIGINS = [
    "https://glefit-frontend.vercel.app",
    re.compile(r"https://.*\.vercel\.app"),
    re.compile(r"https://.*\.trycloudflare\.com"),
    "http://localhost:3000",
]
CORS(
    app,
    resources={r"/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True,
    allow_headers=["*"],
    expose_headers=["*"],
)

# 3) 루트 & 헬스 — 단일 정의만 유지
@app.route("/", methods=["GET", "HEAD"])
def root():
    # HEAD는 위 before_request에서 이미 200 처리됨 → 여기서는 GET만 도달
    return jsonify({"ok": True, "service": "glefit-server"}), 200

@app.route("/health", methods=["GET", "HEAD"])
def health():
    if request.method == "HEAD":
        return ("", 200, {"Content-Type": "text/plain; charset=utf-8"})
    return jsonify({"ok": True, "routes": [
        "/","/health",
        "/auth/login","/auth/ping","/auth/me",
        "/admin/issue_user","/admin/set_active","/admin/reset_password",
        "/admin/list_users","/admin/delete_user",
        "/verify","/policy_verify","/dedup_intra","/dedup_inter","/spell/local"
    ]})

@app.route("/auth/login", methods=["POST"])
def auth_login():
    payload = request.get_json(force=True, silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    u = _get_user(username)
    if not u or not bcrypt.verify(password, u["password_hash"]):
        return jsonify({"error":"Bad credentials"}), 401
    if not _is_paid_and_active(u):
        return jsonify({"error":"Payment required", "code":"PAYMENT"}), 402

        # (단일 로그인용 버전/토큰ID 업데이트) — 동시접속 허용 계정은 예외
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT token_version, allow_concurrent FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    cur_ver = int((row[0] if row else 0) or 0)
    allow_concurrent = bool(row[1]) if row and row[1] is not None else False

    if allow_concurrent:
        new_ver = cur_ver
        new_jti = ""
    else:
        new_ver = cur_ver + 1
        new_jti = str(uuid.uuid4())
        cur.execute(
            "UPDATE users SET token_version=?, last_jti=? WHERE username=?",
            (new_ver, new_jti, username)
        )
        conn.commit()
    conn.close()

    token = jwt.encode({
        "sub": u["username"],
        "role": u["role"],
        "ver": new_ver,     # 토큰 버전
        "jti": new_jti,     # 토큰 고유ID
        "exp": datetime.utcnow() + timedelta(hours=12)
    }, JWT_SECRET, algorithm=JWT_ALG)

    log_usage(username, "login", 0)

    return jsonify({"access_token": token, "token_type": "bearer"})

@app.route("/auth/ping", methods=["GET", "OPTIONS"])
@require_user
def auth_ping():
    if request.method == "OPTIONS":
        return "", 200
    return jsonify({"ok": True})

@app.route("/auth/agree_refund", methods=["POST"])
@require_user
def auth_agree_refund():
    username = _username_from_req()
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO agreements (username, agreed_at) VALUES (?,?)",
                (username, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.post("/track/visit")
def track_visit():
    try:
        body = request.get_json(force=True, silent=True) or {}
        path = (body.get("path") or "/").strip()
        # 토큰이 있으면 유저명 추출, 없으면 공백 처리
        username = _username_from_req()
        log_visit(username, path)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 200

@app.route("/auth/me", methods=["GET", "OPTIONS"])
@require_user
def auth_me():
    if request.method == "OPTIONS":
        return "", 200
    auth = request.headers.get("Authorization","")
    token = auth.split(" ",1)[1]
    data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    u = _get_user(data.get("sub",""))
    return jsonify({
        "username": u["username"],
        "role": u["role"],
        "is_active": u["is_active"],
        "paid_until": u["paid_until"],
        "remaining_days": _remaining_days(u["paid_until"]),
    })

@app.route("/admin/create_user", methods=["POST"])
@require_admin
def admin_create_user():
    body = request.get_json(force=True, silent=True) or {}
    username = normalize_username(body.get("username") or "")
    password = body.get("password") or ""
    days = int(body.get("days") or 0)

    try:
        validate_username(username)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not password:
        return jsonify({"error":"username/password required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        paid_until = datetime.utcnow() + timedelta(days=days) if days>0 else datetime.utcnow()
        cur.execute(
            "INSERT INTO users (username, password_hash, is_active, paid_until, role) VALUES (?,?,?,?,?)",
            (username, bcrypt.hash(password), 1 if days>0 else 0, paid_until.isoformat(), "user")
        )
        conn.commit()
        return jsonify({"ok":True})
    except sqlite3.IntegrityError:
        return jsonify({"error":"username exists"}), 409
    finally:
        conn.close()

@app.route("/admin/approve", methods=["POST"])
@require_admin
def admin_approve():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    extend_days = int(body.get("extend_days") or 0)
    note = (body.get("note") or "").strip()

    u = _get_user(username)
    if not u:
        return jsonify({"error":"user not found"}), 404

    base = datetime.utcnow()
    try:
        if u.get("paid_until"):
            base = max(base, datetime.fromisoformat(u["paid_until"]))
    except Exception:
        pass

    new_until = base + timedelta(days=max(1, extend_days))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_active=?, paid_until=?, notes=? WHERE username=?",
        (1, new_until.isoformat(), note, username)
    )
    conn.commit()
    conn.close()
    return jsonify({"ok":True, "paid_until": new_until.isoformat()})

@app.route("/admin/issue_user", methods=["POST"])
@require_admin
def admin_issue_user():
    """
    관리자 전용: 신규 발급 또는 기존 연장/정보 업데이트를 한 번에 처리
    body: { username, password?, days=32, site_url?, role? }
    신규: password 필수, 기존: 생략 가능
    """
    body = request.get_json(force=True, silent=True) or {}
    username = normalize_username(body.get("username") or "")
    password = (body.get("password") or "").strip()
    days     = int(body.get("days") or 32)   # 기본 32일
    site_url = (body.get("site_url") or "").strip()
    role     = (body.get("role") or "user").strip()
    note     = (body.get("note") or "").strip()

    try:
        validate_username(username)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not username:
        return jsonify({"error":"username required"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT username, paid_until FROM users WHERE username=?", (username,))
    row = cur.fetchone()

    base = datetime.utcnow()
    if row and row[1]:
        try:
            prev = datetime.fromisoformat(row[1])
            if prev > base:
                base = prev
        except Exception:
            pass
    new_until = base + timedelta(days=max(1, days))

    if row is None:
        if not password:
            return jsonify({"error":"password required for new user"}), 400
        cur.execute(
            "INSERT INTO users (username, password_hash, is_active, paid_until, role, notes, site_url, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (username, bcrypt.hash(password), 1, new_until.isoformat(), role, note, (site_url or None), datetime.utcnow().isoformat())
        )
    else:
        # 기존 사용자: 연장 + 선택 필드 갱신
        if password:
            cur.execute("UPDATE users SET password_hash=? WHERE username=?", (bcrypt.hash(password), username))
        cur.execute(
            "UPDATE users SET is_active=?, paid_until=?, role=?, notes=?, site_url=? WHERE username=?",
            (1, new_until.isoformat(), role, note, (site_url or None), username)
        )

    conn.commit(); conn.close()
    return jsonify({"ok": True, "username": username, "paid_until": new_until.isoformat(), "remaining_days": _remaining_days(new_until.isoformat())})

@app.route("/admin/set_active", methods=["POST"])
@require_admin
def admin_set_active():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    is_active = 1 if body.get("is_active") else 0
    if not username:
        return jsonify({"error":"username required"}), 400
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("UPDATE users SET is_active=? WHERE username=?", (is_active, username))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/admin/set_allow_concurrent", methods=["POST"])
@require_admin
def admin_set_allow_concurrent():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    allow = 1 if body.get("allow") else 0
    if not username:
        return jsonify({"error": "username required"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    if allow:
        # 허용: 그대로 플래그만 켜기
        cur.execute(
            "UPDATE users SET allow_concurrent=? WHERE username=?",
            (allow, username)
        )
    else:
        # 해제: 기존 세션 무효화를 위해 버전++ 및 새로운 jti 세팅
        import uuid
        new_jti = str(uuid.uuid4())
        cur.execute(
            "UPDATE users SET allow_concurrent=?, token_version=token_version+1, last_jti=? WHERE username=?",
            (allow, new_jti, username)
        )
    conn.commit(); conn.close()
    return jsonify({"ok": True, "username": username, "allow_concurrent": bool(allow)})

@app.route("/admin/reset_password", methods=["POST"])
@require_admin
def admin_reset_password():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    new_pw = (body.get("new_password") or "").strip()
    if not username or not new_pw:
        return jsonify({"error":"username/new_password required"}), 400
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE username=?", (bcrypt.hash(new_pw), username))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

# --- 관리자: 사용자 삭제(자기 자신/최상위 admin 보호, 존재여부 체크) ---
@app.route("/admin/delete_user", methods=["POST"])
@require_admin
def admin_delete_user():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()

    if not username:
        return jsonify({"error": "username required"}), 400
    # 최상위 관리자 보호 (필요 없다면 주석 처리)
    if username == "admin":
        return jsonify({"error": "cannot delete admin"}), 400

    # 본인 계정 삭제 방지
    try:
        auth = request.headers.get("Authorization", "")
        token = auth.split(" ", 1)[1]
        sub = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG]).get("sub")
        if sub == username:
            return jsonify({"error": "본인 계정은 삭제할 수 없습니다"}), 400
    except Exception:
        # 토큰 파싱 실패 시 자기삭제 방지는 건너뛰되, admin 보호는 위에서 이미 적용됨
        pass

    # 실제 삭제
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()

    if deleted == 0:
        return jsonify({"error": "존재하지 않는 사용자"}), 404

    return jsonify({"ok": True, "deleted": username})

@app.route("/admin/list_users", methods=["GET"])
@require_admin
def admin_list_users():
    q = (request.args.get("q") or "").strip()
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    if q:
        like = f"%{q}%"
        cur.execute(
            """
            SELECT username,is_active,paid_until,role,notes,site_url,created_at,allow_concurrent
            FROM users
            WHERE username LIKE ? OR IFNULL(notes,'') LIKE ? OR IFNULL(site_url,'') LIKE ?
            ORDER BY
              CASE WHEN paid_until IS NULL THEN 1 ELSE 0 END,   -- 만료일 없는 계정은 뒤로
              datetime(paid_until) ASC,                         -- 만료 임박순
              username ASC
            """,
            (like, like, like)
        )
    else:
        cur.execute(
            """
            SELECT username,is_active,paid_until,role,notes,site_url,created_at,allow_concurrent
            FROM users
            ORDER BY
              CASE WHEN paid_until IS NULL THEN 1 ELSE 0 END,
              datetime(paid_until) ASC,
              username ASC
            """
        )
    rows = cur.fetchall()
    conn.close()

    out = []
    for u,a,pu,r,nt,site,created,ac in rows:
        out.append({
            "username": u,
            "is_active": bool(a),
            "paid_until": pu,
            "remaining_days": _remaining_days(pu),
            "role": r,
            "note": nt,
            "site_url": site,
            "created_at": created,
            "allow_concurrent": bool(ac),
        })
    return jsonify({"users": out})

# === [ADD] 부분일치 사용자 검색 (게시글이 없어도 검색) ===
@app.get("/admin/board_user_search")
@require_admin
def admin_board_user_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"ok": True, "items": []})

    # LIKE 안전 이스케이프
    esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like = f"%{esc}%"

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("""
        WITH users_union AS (
          SELECT DISTINCT username FROM users
          UNION
          SELECT DISTINCT username FROM board_posts
        )
        SELECT uu.username,
               COALESCE((SELECT daily_limit
                         FROM board_limits bl
                         WHERE bl.username = uu.username), 2) AS daily_limit
        FROM users_union uu
        WHERE uu.username LIKE ? ESCAPE '\\'
        ORDER BY uu.username
        LIMIT 50
    """, (like,))
    rows = cur.fetchall()
    conn.close()

    items = [{"username": r[0], "blocked": (int(r[1] or 2) <= 0), "daily_limit": int(r[1] or 2)} for r in rows]
    return jsonify({"ok": True, "items": items})

# ===== 관리자: 한 줄 홍보 게시판 =====
@app.get("/admin/board_list")
@require_admin
def admin_board_list():
    args = request.args
    username = (args.get("username") or "").strip()
    keyword  = (args.get("q") or "").strip()
    pinned_only = args.get("pinned_only") in ("1","true","True")
    include_hidden = args.get("include_hidden") in ("1","true","True")

    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    where = []
    params = []

    if username:
        where.append("p.username = ?")
        params.append(username)
    if keyword:
        where.append("p.text LIKE ?")
        params.append(f"%{keyword}%")
    if not include_hidden:
        where.append("p.hidden = 0")
    if pinned_only:
        where.append("p.pinned = 1")

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
    SELECT p.id, p.username, p.text, p.pinned, p.ts, p.hidden,
           COALESCE(u.posting_blocked,0) AS user_blocked
      FROM board_posts p
      LEFT JOIN users u ON u.username = p.username
      {where_sql}
      ORDER BY p.pinned DESC, p.ts DESC
    """
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()

    def to_iso(ts):
        try:
            return datetime.utcfromtimestamp(int(ts)).isoformat()+"Z"
        except Exception:
            return None

    posts = []
    for r in rows:
        posts.append({
            "id": r["id"],
            "username": r["username"],
            "content": r["text"],
            "pinned": bool(r["pinned"]),
            "created_at": to_iso(r["ts"]),
            "user_blocked": bool(r["user_blocked"]),
            "hidden": int(r["hidden"] or 0),
        })
    return jsonify({"posts": posts})

@app.post("/admin/board_update")
@require_admin
def admin_board_update():
    body = request.get_json(force=True, silent=True) or {}
    pid = (body.get("id") or "").strip()
    content = (body.get("content") or "").strip()
    if not pid: return jsonify({"error":"id required"}), 400
    if not content: return jsonify({"error":"content required"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("UPDATE board_posts SET text=? WHERE id=?", (content, pid))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.post("/admin/board_delete")
@require_admin
def admin_board_delete():
    body = request.get_json(force=True, silent=True) or {}
    pid = (body.get("id") or "").strip()
    if not pid: return jsonify({"error":"id required"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    # 소프트 삭제: hidden=1
    cur.execute("UPDATE board_posts SET hidden=1 WHERE id=?", (pid,))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.post("/admin/board_pin")
@require_admin
def admin_board_pin():
    body = request.get_json(force=True, silent=True) or {}
    pid = (body.get("id") or "").strip()
    pinned = 1 if body.get("pinned") in (True, "1", "true", "True") else 0
    if not pid: return jsonify({"error":"id required"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("UPDATE board_posts SET pinned=? WHERE id=?", (pinned, pid))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.post("/admin/board_block_user")
@require_admin
def admin_board_block_user():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    blocked = 1 if body.get("blocked") in (True, "1", "true", "True") else 0
    if not username: return jsonify({"error":"username required"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("UPDATE users SET posting_blocked=? WHERE username=?", (blocked, username))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/board/create", methods=["POST"])
@require_user
def create_board_post():
    # 현재 파일에는 g.user를 세팅하지 않으므로 토큰에서 추출
    username = _username_from_req()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()

    # 작성정지 여부 확인
    r = cur.execute(
        "SELECT IFNULL(posting_blocked,0) FROM users WHERE username=?",
        (username,)
    ).fetchone()
    if r and int(r[0]) == 1:
        conn.close()
        return jsonify({"error": "작성정지 사용자입니다"}), 403

    payload = request.get_json(force=True, silent=True) or {}
    content = (payload.get("content") or "").strip()   # ← .trim() → .strip()
    if not content:
        conn.close()
        return jsonify({"error": "내용이 비어 있습니다"}), 400

    # board_posts 스키마: (id, username, text, pinned, hidden, ts)
    cur.execute(
        "INSERT INTO board_posts (id, username, text, pinned, hidden, ts) "
        "VALUES (?, ?, ?, 0, 0, strftime('%s','now'))",
        (str(uuid.uuid4()), username, content)
    )
    conn.commit(); conn.close()
    return jsonify({"ok": True})



# 로컬 맞춤법 초기화
_init_symspell()

@app.route("/verify", methods=["POST", "OPTIONS"])
@require_user
def verify():
    if request.method == "OPTIONS":
        return "", 200  # preflight OK

    try:
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"error": "No text provided", "results": []}), 400

        # [ADD] non-admin size guard (항목당 100KB)
        limit_resp = enforce_size_limit_or_400(text)
        if limit_resp:
            return limit_resp

        all_items = []

        # 여기에 GPT 맞춤법/문맥 검사 호출 로직 삽입
        # (chunk_text_with_offsets + gpt_call 활용)

        # === GPT 기반 맞춤법/문맥오류 검사 ===
        chunks = chunk_text_with_offsets(text)  # (base_offset, chunk_text)
        for base, chunk in chunks:
            prompt = f"""
너는 한국어 문장 교정 전문가다.
아래 글에서 **맞춤법/띄어쓰기/어법 오류(=type: "맞춤법")**,
**부자연스럽거나 끊긴 문장(=type: "문맥오류")**만 찾아라.
심의/광고법/의료 규정(효과·재발률·보장 등)은 **완전히 무시**한다.

반드시 JSON 배열만 출력하며, 각 항목은 아래 스키마를 따른다:
{{
  "type": "맞춤법" | "문맥오류",
  "original": "원문에서 그대로 복사(공백/기호도 동일)",
  "reason": "간단 설명",
  "severity": "low" | "medium" | "high",
  "suggestions": ["대안1","대안2"],   // 없으면 빈 배열
  "start": 정수,   // 이 청크 내 시작 오프셋
  "end": 정수      // 이 청크 내 끝 오프셋(포함X)
}}

검사할 글:
\"\"\"{chunk}\"\"\"
""".strip()

            resp = gpt_call(MODEL, [{"role": "user", "content": prompt}])
            raw = (resp.choices[0].message.content or "").strip()
            items = extract_json_array(raw)

            used_local = set()
            for it in (items or []):
                origin = (it.get("original") or "").strip()
                if not origin:
                    continue

                # 1) GPT가 준 start/end 오프셋을 최우선 신뢰
                s_rel = it.get("start")
                e_rel = it.get("end")
                locs = []
                if isinstance(s_rel, int) and isinstance(e_rel, int) and 0 <= s_rel < e_rel <= len(chunk):
                    locs = [s_rel]
                else:
                    # 2) 실패 시 fallback: 부분 문자열 탐색
                    locs = find_all(chunk, origin)

                for local_idx in locs:
                    gidx = base + local_idx
                    if gidx in used_local:
                        continue
                    used_local.add(gidx)

                    before, after = add_context(text, gidx, len(origin))
                    all_items.append({
                        "id": f"v_{len(all_items)}",
                        "type": it.get("type") or "맞춤법",
                        "original": origin,
                        "suggestions": (it.get("suggestions") or [])[:3],
                        "reason": it.get("reason") or "",
                        "severity": it.get("severity") or "low",
                        "startIndex": gidx,
                        "endIndex": gidx + len(origin),
                        "before": before,
                        "after": after
                    })
                    break  # 동일 항목 중복 방지


        # 문장 단위 휴리스틱 추가 (루프 밖에서 한 번만)
        all_items.extend(find_fragments_by_sentence(text))
        all_items.extend(find_context_issues(text))

        # 출처 태그
        for it in all_items:
            it["source"] = "verify"

        return jsonify({"results": all_items, "aiSummary": None})
    except Exception as e:
        import traceback
        print("❌ /verify 오류:", e)
        traceback.print_exc()
        return jsonify({"error": str(e), "results": []}), 500

@app.post("/spell/local")
def spell_local():
    """
    로컬 철자(맞춤법)만 검사. 문맥/어법/심의 판단 없음.
    body: { "text": str, "min_len": 3, "max_sug": 3 }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get("text") or "")

        # [ADD] non-admin size guard (항목당 100KB)
        limit_resp = enforce_size_limit_or_400(text)
        if limit_resp:
            return limit_resp

        if not text.strip() or _sym is None:
            return jsonify({"results": []})

        min_len = int(data.get("min_len") or 3)   # 짧은 토큰 제외(오탑↓)
        max_sug = int(data.get("max_sug") or 3)   # 제안 상위 N개

        results = []
        for s, e, tok in _token_spans_ko(text):
            if len(tok) < min_len:
                continue
            # 화이트리스트/사전에 있으면 통과
            if tok in _whitelist or _sym.words.get(tok, 0) > 0:
                continue

            suggs = _sym.lookup(tok, Verbosity.TOP, max_edit_distance=2, include_unknown=False)
            if not suggs:
                continue

            suggs = _sym.lookup(tok, Verbosity.TOP, max_edit_distance=2, include_unknown=False)
            if not suggs:
                continue

            cand = [su.term for su in suggs[:max_sug]]
            results.append({
                "type": "맞춤법",
                "original": tok,
                "reason": "사전에 없는 단어로 추정",
                "severity": "low",
                "suggestions": cand,
                "startIndex": s,
                "endIndex": e,
                "before": text[max(0, s-24):s],
                "after":  text[e:min(len(text), e+24)],
                "source": "local-spell"
            })

        results.sort(key=lambda x: (x["startIndex"], x["endIndex"]))
        return jsonify({"results": results})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"results": [], "error": str(e)}), 500


# ===== 문장 단위 문맥오류 유틸 =====

SENT_SPLIT_RE = re.compile(r'(?<=[\.!?])\s+')
END_TOKEN_RE = re.compile(r'(다|요|니다|합니다|했다|였다|됩니다|돼요|\.|!|\?)\s*$')

LEADING_CONNECTIVES = (
    "하지만", "그러나", "반면에", "그런데", "다만",
    "또한", "그리고", "게다가", "특히", "또", "한편"
)

def split_sentences_with_pos(text: str):
    spans = []
    parts = SENT_SPLIT_RE.split(text)
    cur = 0
    for p in parts:
        if not p.strip():
            cur += len(p)
            continue
        start = text.find(p, cur)
        if start == -1:
            start = text.find(p)
        end = start + len(p)
        spans.append((p, start, end))
        cur = end
    return spans

def find_fragments_by_sentence(text: str):
    items = []
    spans = split_sentences_with_pos(text)
    for s, start, end in spans:
        sent = s.strip()
        if len(sent) < 15:
            continue
        if sent.startswith(("“", "\"", "‘", "'")) and sent.endswith(("”", "\"", "’", "'")):
            continue
        if not END_TOKEN_RE.search(sent):
            items.append({
                "id": f"frag_{start}",
                "type": "문맥오류",
                "original": sent,
                "reason": "불완전 문장(종결어미/마침표 누락) 가능",
                "severity": "medium",
                "suggestions": ["문장을 마무리하는 종결어미/마침표 추가 검토"],
                "startIndex": start,
                "endIndex": end,
                "before": "", "after": ""
            })
    return items

def find_context_issues(text: str):
    items = []
    spans = split_sentences_with_pos(text)
    for i, (s, start, end) in enumerate(spans):
        sent = s.strip()
        if len(sent) < 10:
            continue
        for conn in LEADING_CONNECTIVES:
            if sent.startswith(conn):
                if i == 0:
                    items.append({
                        "id": f"ctx_first_{start}",
                        "type": "문맥오류",
                        "original": sent[:min(40, len(sent))],
                        "reason": f"첫 문장에서 '{conn}' 사용",
                        "severity": "low",
                        "suggestions": ["첫 문장은 전환 없이 주제를 제시하는 것이 자연스러움"],
                        "startIndex": start, "endIndex": end,
                        "before": "", "after": ""
                    })
                else:
                    prev = spans[i-1][0].strip()
                    if len(prev) < 10 or not END_TOKEN_RE.search(prev):
                        items.append({
                            "id": f"ctx_link_{start}",
                            "type": "문맥오류",
                            "original": sent[:min(40, len(sent))],
                            "reason": f"앞 문장이 약한 상태에서 '{conn}' 시작",
                            "severity": "low",
                            "suggestions": ["앞 문장을 보강하거나 연결어를 생략/변경"],
                            "startIndex": start, "endIndex": end,
                            "before": "", "after": ""
                        })
                break
    return items


# ============== (NEW) 도돌이표/유사 라우트 ==============
@app.route("/dedup_intra", methods=["POST"])
@require_user
def dedup_intra():
    """
    본문 한 건 내 도돌이표(정확히 같은 문장) + 유사 문장(3-gram 자카드) 탐지
    body: { "text": str, "min_len": 6, "sim_threshold": 0.85 }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get("text") or "")
        if not text.strip():
            return jsonify({"error": "No text provided"}), 400

        # [ADD] non-admin size guard (항목당 100KB)
        limit_resp = enforce_size_limit_or_400(text)
        if limit_resp:
            return limit_resp

        min_len = int(data.get("min_len", 6))
        sim_th  = float(data.get("sim_threshold", 0.85))
        exact, sims = _dedup_intra(text, min_len=min_len, sim_threshold=sim_th)
        return jsonify({"exact_groups": exact, "similar_pairs": sims})
    except Exception as e:
        import traceback
        print("✘ /dedup_intra 오류:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/dedup_inter", methods=["POST"])
@require_user
def dedup_inter():
    """
    여러 파일 간 도돌이표/유사 문장 탐지
    body: { "files": [{"name": str, "text": str}, ...], "min_len": 6, "sim_threshold": 0.85 }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        files = data.get("files") or []
        if not files:
            return jsonify({"error": "No files provided"}), 400

        # [ADD] non-admin size guard (각 항목 text 100KB)
        limit_resp = enforce_size_limit_or_400(files)
        if limit_resp:
            return limit_resp

        min_len = int(data.get("min_len", 6))
        sim_th  = float(data.get("sim_threshold", 0.85))

        exact, sims = _dedup_inter(files, min_len=min_len, sim_threshold=sim_th)

        # (선택) 사용량 로깅: 헬퍼가 있으면 유지, 없으면 무시
        try:
            log_usage(_username_from_req(), "dedup_inter", len(files))
        except Exception:
            pass

        return jsonify({"exact_groups": exact, "similar_pairs": sims})

    except Exception as e:
        import traceback
        print("✘ /dedup_inter 오류:", e)
        traceback.print_exc()
        # (선택) 에러 로깅
        try:
            log_error(_username_from_req(), "/dedup_inter", 500, str(e))
        except Exception:
            pass
        return jsonify({"error": str(e)}), 500


@app.route("/policy_verify", methods=["POST", "OPTIONS"])
@require_user
def policy_verify():
    if request.method == "OPTIONS":
        return "", 200

    try:
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"error": "No text provided"}), 400

        # [ADD] non-admin size guard (항목당 100KB)
        limit_resp = enforce_size_limit_or_400(text)
        if limit_resp:
            return limit_resp

        # 심의 규칙 검사
        items = rule_scan(text)
        items = attach_reasons(items)

        # 출처 태그
        for it in items:
            it["source"] = "policy"

        # (선택) 사용량 로깅
        try:
            log_usage(_username_from_req(), "policy", 1)
        except Exception:
            pass

        return jsonify({"results": items})

    except Exception as e:
        import traceback
        print("✘ /policy_verify 오류:", e)
        traceback.print_exc()
        # (선택) 에러 로깅
        try:
            log_error(_username_from_req(), "/policy_verify", 500, str(e))
        except Exception:
            pass
        return jsonify({"error": str(e), "results": []}), 500


@app.after_request
def _after(resp):
    try:
        if resp.status_code >= 400:
            log_error(_username_from_req(), request.path, resp.status_code, getattr(resp, "data", b"")[:120])
    except Exception:
        pass
    return resp

from werkzeug.exceptions import HTTPException

@app.errorhandler(HTTPException)
def _http_error(e):
    # 404/401/405 같은 정상 HTTP 오류는 원래 상태코드로 그대로 반환
    return e

@app.errorhandler(Exception)
def _on_error(e):
    # 404/401/405 같은 HTTP 예외는 원래 상태코드 그대로 반환해야 함
    if isinstance(e, HTTPException):
        return e  # ★ 반드시 return e !!!
    # 그 외 진짜 에러만 500 처리
    return jsonify({"error": "internal"}), 500



# === 4) 관리자: 기간 조정 API ===
# 위치: (① /admin/approve 아래) 또는 (② if __name__ == "__main__": 바로 위)

@app.route("/admin/adjust_days", methods=["POST"])
@require_admin
def admin_adjust_days():
    """
    body: { "username": "trial@glefit", "days": -1 }  # 음수/양수 모두 허용
    """
    body = request.get_json(force=True, silent=True) or {}
    username   = (body.get("username") or "").strip()
    delta_days = int(body.get("days") or 0)
    if not username or delta_days == 0:
        return jsonify({"error": "username/days required"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT paid_until FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close(); return jsonify({"error":"user not found"}), 404

    now = datetime.utcnow()
    try:
        base = datetime.fromisoformat(row[0]) if row[0] else now
    except Exception:
        base = now

    new_until = base + timedelta(days=delta_days)
    cur.execute(
        "UPDATE users SET paid_until=?, is_active=? WHERE username=?",
        (new_until.isoformat(), 1 if new_until > now else 0, username)
    )
    conn.commit(); conn.close()
    return jsonify({"ok": True, "paid_until": new_until.isoformat()})

@app.get("/admin/usage_summary")
@require_admin
def admin_usage_summary():
    """
    반환:
    {
      "usage":[ {username, verify, policy, dedup_inter, dedup_intra, files}, ... ],
      "errors":[ {username, errors, last}, ... ],
      "agreements":[ {username, agreed_at}, ... ]
    }
    """
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()

    # usage_logs 집계
    cur.execute("""
      SELECT username,
             SUM(CASE WHEN action='verify' THEN 1 ELSE 0 END) AS verify,
             SUM(CASE WHEN action='policy' THEN 1 ELSE 0 END) AS policy,
             SUM(CASE WHEN action='dedup_inter' THEN 1 ELSE 0 END) AS dedup_inter,
             SUM(CASE WHEN action='dedup_intra' THEN 1 ELSE 0 END) AS dedup_intra,
             SUM(files_count) AS files
      FROM usage_logs
      GROUP BY username
      ORDER BY username
    """)
    usage = []
    for row in cur.fetchall():
        usage.append({
            "username": row[0] or "",
            "verify": row[1] or 0,
            "policy": row[2] or 0,
            "dedup_inter": row[3] or 0,
            "dedup_intra": row[4] or 0,
            "files": row[5] or 0
        })

    # error_logs 집계(유저별 개수 + 마지막 시각)
    cur.execute("""
      SELECT username, COUNT(*),
             MAX(created_at)
      FROM error_logs
      GROUP BY username
    """)
    errors = []
    for row in cur.fetchall():
        errors.append({
            "username": row[0] or "",
            "errors": row[1] or 0,
            "last": row[2] or ""
        })

    # 동의 목록
    cur.execute("SELECT username, agreed_at FROM agreements ORDER BY agreed_at DESC")
    agreements = [{"username": r[0], "agreed_at": r[1]} for r in cur.fetchall()]

    conn.close()
    return jsonify({"usage": usage, "errors": errors, "agreements": agreements})

@app.get("/admin/traffic_summary")
@require_admin
def admin_traffic_summary():
    """
    쿼리:
      granularity=day|week|month (기본: day)
      start=YYYY-MM-DD ISO(UTC)  예: 2025-10-01
      end=YYYY-MM-DD   (포함)
    반환:
      { "series":[ { "bucket":"2025-10-21", "visits":n, "logins":m, "active_users":k }, ... ],
        "totals": { "visits":X, "logins":Y, "unique_users":Z } }
    """
    gran = (request.args.get("granularity") or "day").lower()
    start = (request.args.get("start") or "").strip()
    end   = (request.args.get("end") or "").strip()

    # 기본 기간: 최근 30일
    today = datetime.utcnow().date()
    if not start:
        start_date = today - timedelta(days=29)
    else:
        start_date = datetime.fromisoformat(start).date()
    if not end:
        end_date = today
    else:
        end_date = datetime.fromisoformat(end).date()

    # SQLite strftime 패턴
    if gran == "month":
        fmt = "%Y-%m"
    elif gran == "week":
        # ISO week-year-weeknum
        fmt = "%Y-W%W"
    else:
        fmt = "%Y-%m-%d"

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()

    # visits: visit_logs 기준
    cur.execute(f"""
      SELECT strftime('{fmt}', created_at), COUNT(*)
      FROM visit_logs
      WHERE date(created_at) BETWEEN date(?) AND date(?)
      GROUP BY 1
      ORDER BY 1
    """, (start_date.isoformat(), end_date.isoformat()))
    visit_rows = dict(cur.fetchall() or [])

    # logins: usage_logs(action='login')
    cur.execute(f"""
      SELECT strftime('{fmt}', created_at), COUNT(*)
      FROM usage_logs
      WHERE action='login'
        AND date(created_at) BETWEEN date(?) AND date(?)
      GROUP BY 1
      ORDER BY 1
    """, (start_date.isoformat(), end_date.isoformat()))
    login_rows = dict(cur.fetchall() or [])

    # active users(해당 기간 내 로그인했던 유니크)
    cur.execute("""
      SELECT username
      FROM usage_logs
      WHERE action='login'
        AND date(created_at) BETWEEN date(?) AND date(?)
    """, (start_date.isoformat(), end_date.isoformat()))
    uniq = set([r[0] for r in (cur.fetchall() or []) if r and r[0]])

    # 버킷 생성
    series = []
    cur_d = start_date
    while cur_d <= end_date:
        if fmt == "%Y-%m":
            bucket = cur_d.strftime("%Y-%m")
            # 월 말까지 점프
            next_d = (cur_d.replace(day=1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            cur_d = (cur_d.replace(day=1) + timedelta(days=32)).replace(day=1)
        elif fmt == "%Y-W%W":
            bucket = cur_d.strftime("%Y-W%W")
            next_d = cur_d + timedelta(days=6)
            cur_d = cur_d + timedelta(days=7)
        else:
            bucket = cur_d.strftime("%Y-%m-%d")
            next_d = cur_d
            cur_d = cur_d + timedelta(days=1)

        series.append({
            "bucket": bucket,
            "visits": int(visit_rows.get(bucket, 0) or 0),
            "logins": int(login_rows.get(bucket, 0) or 0),
            "active_users": len(uniq) if fmt != "%Y-%m-%d" else None  # 일별 active_users는 보통 별도 산출
        })

    totals = {
        "visits": sum(v["visits"] for v in series),
        "logins": sum(v["logins"] for v in series),
        "unique_users": len(uniq),
    }
    conn.close()
    return jsonify({"series": series, "totals": totals})


@app.route("/admin/set_days_from_now", methods=["POST"])
@require_admin
def admin_set_days_from_now():
    """
    body: { "username": "trial@glefit", "days": 7 }  # 0 허용(즉시 만료)
    """
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    days     = int(body.get("days") or 0)
    if not username:
        return jsonify({"error":"username required"}), 400

    now = datetime.utcnow()
    new_until = now + timedelta(days=max(0, days))

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute(
        "UPDATE users SET paid_until=?, is_active=? WHERE username=?",
        (new_until.isoformat(), 1 if days > 0 else 0, username)
    )
    conn.commit(); conn.close()
    return jsonify({"ok": True, "paid_until": new_until.isoformat()})

# === [ADD] BOARD API (list/add/edit/delete/pin/admin_delete_all) ===
from flask import Flask

def _default_daily_limit(username):
    # board_limits 테이블에서 per-user limit을 읽고, 없으면 2 리턴
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT daily_limit FROM board_limits WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return int(row[0]) if row and row[0] is not None else 2

def _count_today_posts(username):
    day_start = int(datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000)
    day_end   = int(datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999000).timestamp() * 1000)
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM board_posts
        WHERE username=? AND ts BETWEEN ? AND ? AND (hidden IS NULL OR hidden=0)
    """, (username, day_start, day_end))
    n = cur.fetchone()[0]
    conn.close()
    return int(n or 0)

# === INSERT BLOCK between line 1935 and 1936 ===
from uuid import uuid4

DEFAULT_DAILY = 2

def _board_daily_limit(username):
    try:
        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute("SELECT daily_limit FROM board_limits WHERE username=?", (username,))
        row = cur.fetchone(); conn.close()
        if row and row[0] is not None:
            return int(row[0]) or DEFAULT_DAILY
    except Exception:
        pass
    return DEFAULT_DAILY

def _count_posts_today(username):
    try:
        start = int(datetime.utcnow().replace(hour=0,minute=0,second=0,microsecond=0).timestamp()*1000)
        end   = int(datetime.utcnow().replace(hour=23,minute=59,second=59,microsecond=999999).timestamp()*1000)
        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute("SELECT COUNT(1) FROM board_posts WHERE username=? AND ts BETWEEN ? AND ?",
                    (username, start, end))
        c = cur.fetchone()[0]; conn.close()
        return int(c or 0)
    except Exception:
        return 0

@app.get("/board/posts")
def board_posts_list():
    """읽기 전용: 최근 100건, pinned 우선"""
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("""
        SELECT id, username, text, pinned, ts
        FROM board_posts
        ORDER BY pinned DESC, ts DESC
        LIMIT 100
    """)
    rows = cur.fetchall(); conn.close()
    posts = [{"id":r[0], "user":r[1], "text":r[2], "pinned":bool(r[3]), "ts":int(r[4])} for r in rows]
    return jsonify({"posts": posts})

@app.post("/board/posts")
def board_posts_add():
    """작성: username/password 인증 + 일일 제한"""
    payload = request.get_json(force=True, silent=True) or {}
    ok, uname, is_admin = verify_board_auth(payload)
    if not ok:
        return jsonify({"error":"auth"}), 401

    text = (payload.get("text") or "").strip()
    if not text or len(text) > 60:
        return jsonify({"error":"length"}), 400

    # 일일 제한(관리자는 무제한)
    if not is_admin:
        used = _count_posts_today(uname)
        if used >= _board_daily_limit(uname):
            return jsonify({"error":"limit"}), 429

    pid = "p_" + uuid4().hex[:10]
    now = int(time.time()*1000)
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("INSERT INTO board_posts (id, username, text, pinned, ts) VALUES (?,?,?,?,?)",
                (pid, uname, text, 0, now))
    conn.commit(); conn.close()
    return jsonify({"ok":True, "id":pid, "ts":now})

@app.put("/board/posts/<pid>")
def board_posts_edit(pid):
    payload = request.get_json(force=True, silent=True) or {}
    ok, uname, is_admin = verify_board_auth(payload)
    if not ok:
        return jsonify({"error":"auth"}), 401
    text = (payload.get("text") or "").strip()
    if not text or len(text) > 60:
        return jsonify({"error":"length"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT username FROM board_posts WHERE id=?", (pid,))
    row = cur.fetchone()
    if not row:
        conn.close(); return jsonify({"error":"not_found"}), 404
    if (row[0] != uname) and (not is_admin):
        conn.close(); return jsonify({"error":"forbidden"}), 403

    cur.execute("UPDATE board_posts SET text=? WHERE id=?", (text, pid))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.delete("/board/posts/<pid>")
def board_posts_delete(pid):
    payload = request.get_json(force=True, silent=True) or {}
    ok, uname, is_admin = verify_board_auth(payload)
    if not ok:
        return jsonify({"error":"auth"}), 401

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT username FROM board_posts WHERE id=?", (pid,))
    row = cur.fetchone()
    if not row:
        conn.close(); return jsonify({"error":"not_found"}), 404
    if (row[0] != uname) and (not is_admin):
        conn.close(); return jsonify({"error":"forbidden"}), 403

    cur.execute("DELETE FROM board_posts WHERE id=?", (pid,))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.post("/board/pin/<pid>")
def board_posts_pin(pid):
    payload = request.get_json(force=True, silent=True) or {}
    ok, uname, is_admin = verify_board_auth(payload)
    if not ok or not is_admin:
        return jsonify({"error":"admin_only"}), 403

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT pinned FROM board_posts WHERE id=?", (pid,))
    row = cur.fetchone()
    if not row:
        conn.close(); return jsonify({"error":"not_found"}), 404
    new_pin = 0 if row[0] else 1
    cur.execute("UPDATE board_posts SET pinned=? WHERE id=?", (new_pin, pid))
    conn.commit(); conn.close()
    return jsonify({"ok":True, "pinned": bool(new_pin)})

# === [ADD] 게시판 미니로그인 관리자 여부 확인 ===
@app.post("/board/auth_check")
def board_auth_check():
    payload = request.get_json(force=True, silent=True) or {}
    ok, uname, is_admin = verify_board_auth(payload)
    if not ok:
        return jsonify({"ok": False}), 401
    return jsonify({"ok": True, "username": uname, "is_admin": bool(is_admin)})

@app.post("/admin/board/limit")
def board_limit_set():
    """관리자: 특정 ID 일일 작성 제한 변경"""
    payload = request.get_json(force=True, silent=True) or {}
    ok, uname, is_admin = verify_board_auth(payload)
    if not ok or not is_admin:
        return jsonify({"error":"admin_only"}), 403
    target = (payload.get("target") or "").strip().lower()
    n = int(payload.get("limit") or DEFAULT_DAILY)
    if not target:
        return jsonify({"error":"target"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("""
        INSERT INTO board_limits (username, daily_limit)
        VALUES (?,?)
        ON CONFLICT(username) DO UPDATE SET daily_limit=excluded.daily_limit
    """, (target, n))
    conn.commit(); conn.close()
    return jsonify({"ok":True, "username": target, "limit": n})

# === Board APIs ===
@app.route("/board/list", methods=["GET"])
def board_list():
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("""
        SELECT id, username, text, pinned, ts
        FROM board_posts
        WHERE (hidden IS NULL OR hidden=0)
        ORDER BY pinned DESC, ts DESC
        LIMIT 200
    """)
    rows = cur.fetchall(); conn.close()
    items = [{"id": r[0], "user": r[1], "text": r[2], "pinned": bool(r[3]), "ts": int(r[4] or 0)} for r in rows]
    return jsonify({"ok": True, "items": items})

@app.route("/board/add", methods=["POST"])
@require_user
def board_add():
    data = (request.get_json(silent=True) or {})
    text = (data.get("text") or "").strip()
    if not text: return jsonify({"ok": False, "error":"EMPTY"}), 400
    if len(text) > 60: return jsonify({"ok": False, "error":"TOO_LONG"}), 400

    uname = _username_from_req()
    user = _get_user(uname)
    is_admin = (user or {}).get("role") == "admin"

    # 작성 정지 사용자면 즉시 차단
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    r = cur.execute("SELECT IFNULL(posting_blocked,0) FROM users WHERE username=?", (uname,)).fetchone()
    if r and int(r[0]) == 1:
        conn.close()
        return jsonify({"ok": False, "error": "BLOCKED"}), 403
    conn.close()

    # === 일일 제한: KST 자정 기준 (삭제글 포함 카운트) ===
    now_utc = datetime.utcnow()
    now_kst = now_utc + timedelta(hours=9)
    kst_midnight = datetime(now_kst.year, now_kst.month, now_kst.day, 0, 0, 0)
    boundary_utc = kst_midnight - timedelta(hours=9)
    boundary_ms = int(boundary_utc.timestamp() * 1000)

    # 관리자면 무제한 통과
    if not is_admin:
        # per-user 한도: board_limits.daily_limit 사용, 없으면 기본 2회
        try:
            daily_limit = _default_daily_limit(uname)  # 함수 정의: server.py에 이미 있음
        except Exception:
            daily_limit = 2

        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM board_posts WHERE username=? AND ts>=?",
            (uname, boundary_ms)
        )
        used = int(cur.fetchone()[0] or 0)
        conn.close()

        if used >= int(daily_limit):
            return jsonify({
                "ok": False,
                "error": "LIMIT",
                "used": used,
                "limit": int(daily_limit),
                "reset_at_kst": int(kst_midnight.timestamp() * 1000)
            }), 400
    # (관리자는 위 제한을 건너뜀)


    # === 저장 ===
    pid = f"p_{int(time.time()*1000)}_{uuid.uuid4().hex[:5]}"
    ts  = int(time.time()*1000)

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute(
        "INSERT INTO board_posts (id, username, text, pinned, ts, hidden) VALUES (?,?,?,?,?,0)",
        (pid, uname, text, 0, ts)
    )
    conn.commit(); conn.close()

    return jsonify({
        "ok": True,
        "item": {"id": pid, "user": uname, "text": text, "pinned": False, "ts": ts}
    })


@app.route("/board/edit", methods=["POST"])
@require_user
def board_edit():
    data = (request.get_json(silent=True) or {})
    pid  = data.get("id") or ""
    text = (data.get("text") or "").strip()
    if not pid or not text: return jsonify({"ok": False, "error":"BAD_REQ"}), 400
    if len(text) > 60: return jsonify({"ok": False, "error":"TOO_LONG"}), 400

    uname = _username_from_req()
    user = _get_user(uname)
    is_admin = (user or {}).get("role") == "admin"

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT username FROM board_posts WHERE id=? AND (hidden IS NULL OR hidden=0)", (pid,))
    row = cur.fetchone()
    if not row: 
        conn.close(); return jsonify({"ok": False, "error": "NOT_FOUND"}), 404

    if (not is_admin) and (row[0] != uname):
        conn.close(); return jsonify({"ok": False, "error": "FORBIDDEN"}), 403

    cur.execute("UPDATE board_posts SET text=? WHERE id=?", (text, pid))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/board/delete", methods=["POST"])
@require_user
def board_delete():
    data = (request.get_json(silent=True) or {})
    pid  = data.get("id") or ""
    if not pid: return jsonify({"ok": False, "error":"BAD_REQ"}), 400

    uname = _username_from_req()
    user = _get_user(uname)
    is_admin = (user or {}).get("role") == "admin"

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT username FROM board_posts WHERE id=? AND (hidden IS NULL OR hidden=0)", (pid,))
    row = cur.fetchone()
    if not row: 
        conn.close(); return jsonify({"ok": False, "error": "NOT_FOUND"}), 404

    if (not is_admin) and (row[0] != uname):
        conn.close(); return jsonify({"ok": False, "error": "FORBIDDEN"}), 403

    cur.execute("UPDATE board_posts SET hidden=1 WHERE id=?", (pid,))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/board/toggle_pin", methods=["POST"])
@require_admin
def board_toggle_pin():
    data = (request.get_json(silent=True) or {})
    pid  = data.get("id") or ""
    if not pid: return jsonify({"ok": False, "error":"BAD_REQ"}), 400

    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("SELECT pinned FROM board_posts WHERE id=? AND (hidden IS NULL OR hidden=0)", (pid,))
    row = cur.fetchone()
    if not row:
        conn.close(); return jsonify({"ok": False, "error":"NOT_FOUND"}), 404

    new_pin = 0 if (row[0] or 0) else 1
    cur.execute("UPDATE board_posts SET pinned=? WHERE id=?", (new_pin, pid))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "pinned": bool(new_pin)})

@app.route("/board/admin/delete_all", methods=["POST"])
@require_admin
def board_admin_delete_all():
    conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
    cur.execute("UPDATE board_posts SET hidden=1 WHERE (hidden IS NULL OR hidden=0)")
    conn.commit(); conn.close()
    return jsonify({"ok": True, "all_deleted": True})

# === END INSERT BLOCK ===

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
