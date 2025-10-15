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
    # 고객 접속 주소 보관(선택)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN site_url TEXT")
    except Exception:
        pass
    # 생성 시각(관리 편의)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
    except Exception:
        pass

    # ★★★ 동시접속 제어용 컬럼 추가 ★★★
    try:
        cur.execute("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN last_jti TEXT")
    except Exception:
        pass

    conn.commit()
    conn.close()

migrate_users_table()

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

def _remaining_days(paid_until: str) -> int:
    if not paid_until:
        return 0
    try:
        delta = datetime.fromisoformat(paid_until) - datetime.utcnow()
        return max(0, delta.days)
    except Exception:
        return 0

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

        # DB에서 최신 상태(활성/기간/사이트/버전/JTI) 확인
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("SELECT is_active, paid_until, site_url, token_version, last_jti FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"error":"Unauthorized"}), 401

        is_active, paid_until, site_url, db_ver, db_jti = row[0], row[1], (row[2] or ""), int(row[3] or 0), (row[4] or "")

        # 결제/기간/활성 체크
        try:
            if not is_active or not paid_until or datetime.utcnow() > datetime.fromisoformat(paid_until):
                return jsonify({"error":"Payment required or expired"}), 402
        except Exception:
            return jsonify({"error":"Payment required or expired"}), 402

        # ★ 단일 로그인 강제: 토큰의 ver/jti가 DB의 최신값과 일치해야 통과
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
        cur.execute("SELECT role, is_active, paid_until, token_version, last_jti FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"error":"Unauthorized"}), 401

        role, is_active, paid_until, db_ver, db_jti = (row[0] or "user"), row[1], row[2], int(row[3] or 0), (row[4] or "")

        # 결제/기간/활성 체크
        try:
            if not is_active or not paid_until or datetime.utcnow() > datetime.fromisoformat(paid_until):
                return jsonify({"error":"Payment required or expired"}), 402
        except Exception:
            return jsonify({"error":"Payment required or expired"}), 402

        # 단일 로그인 강제
        if tok_ver != db_ver or (db_jti and tok_jti != db_jti):
            return jsonify({"error":"Session invalidated. Please log in again.", "code":"SESSION"}), 401

        if role != "admin":
            return jsonify({"error":"Admin only"}), 403

        return fn(*args, **kwargs)
    return wrapper


RULE_PATH = os.getenv("RULE_PATH", "kr-medhealth.yaml")
RULES = {}   # {"rules":[{...}], ...}
RULES_INDEX = {}  # {rule_id: rule_obj}

# ================== 유틸 ==================
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

# ================== Flask ==================
app = Flask(__name__)
CORS(app,
     resources={r"/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Content-Type"],
     supports_credentials=False)

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

    # (단일 로그인용 버전/토큰ID 업데이트)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT token_version FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    cur_ver = int((row[0] if row else 0) or 0)

    new_ver = cur_ver + 1
    new_jti = str(uuid.uuid4())
    cur.execute("UPDATE users SET token_version=?, last_jti=? WHERE username=?", (new_ver, new_jti, username))
    conn.commit()
    conn.close()

    token = jwt.encode({
        "sub": u["username"],
        "role": u["role"],
        "ver": new_ver,     # 토큰 버전
        "jti": new_jti,     # 토큰 고유ID
        "exp": datetime.utcnow() + timedelta(hours=12)
    }, JWT_SECRET, algorithm=JWT_ALG)

    return jsonify({"access_token": token, "token_type": "bearer"})

@app.route("/auth/ping", methods=["GET", "OPTIONS"])
@require_user
def auth_ping():
    if request.method == "OPTIONS":
        return "", 200
    return jsonify({"ok": True})

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
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    days = int(body.get("days") or 0)

    if not username or not password:
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
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()
    days     = int(body.get("days") or 32)   # 기본 32일
    site_url = (body.get("site_url") or "").strip()
    role     = (body.get("role") or "user").strip()
    note     = (body.get("note") or "").strip()

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
        cur.execute("SELECT username,is_active,paid_until,role,notes,site_url,created_at FROM users WHERE username LIKE ? ORDER BY username", (f"%{q}%",))
    else:
        cur.execute("SELECT username,is_active,paid_until,role,notes,site_url,created_at FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    out = []
    for u,a,pu,r,nt,site,created in rows:
        out.append({
            "username": u,
            "is_active": bool(a),
            "paid_until": pu,
            "remaining_days": _remaining_days(pu),
            "role": r,
            "note": nt,
            "site_url": site,
            "created_at": created
        })
    return jsonify({"users": out})

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
        if not text.strip() or _sym is None:
            return jsonify({"results": []})

        min_len = int(data.get("min_len") or 3)   # 짧은 토큰 제외(오탐↓)
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
        min_len = int(data.get("min_len", 6))
        sim_th  = float(data.get("sim_threshold", 0.85))
        exact, sims = _dedup_intra(text, min_len=min_len, sim_threshold=sim_th)
        return jsonify({"exact_groups": exact, "similar_pairs": sims})
    except Exception as e:
        import traceback
        print("❌ /dedup_intra 오류:", e)
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
        min_len = int(data.get("min_len", 6))
        sim_th  = float(data.get("sim_threshold", 0.85))
        exact, sims = _dedup_inter(files, min_len=min_len, sim_threshold=sim_th)
        return jsonify({"exact_groups": exact, "similar_pairs": sims})
    except Exception as e:
        import traceback
        print("❌ /dedup_inter 오류:", e)
        traceback.print_exc()
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
            return jsonify({"error": "No text provided", "results": []}), 400

        # 심의 규칙 검사
        items = rule_scan(text)
        items = attach_reasons(items)

        # 출처 태그
        for it in items:
            it["source"] = "policy"

        return jsonify({"results": items})
    except Exception as e:
        import traceback
        print("❌ /policy_verify 오류:", e)
        traceback.print_exc()
        return jsonify({"error": str(e), "results": []}), 500

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "routes": [
            "/auth/login","/auth/ping","/auth/me",
            "/admin/issue_user","/admin/set_active","/admin/reset_password","/admin/list_users","/admin/delete_user",
            "/verify","/policy_verify","/dedup_intra","/dedup_inter","/spell/local","/health"
        ]
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
