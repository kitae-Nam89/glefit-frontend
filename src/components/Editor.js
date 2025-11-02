import React, { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import mammoth from "mammoth";
import { Document, Packer, Paragraph } from "docx";

/**
 * Editor.js – 다중 업로드 + 중복문장/유사문장(단일/교차) + 하이라이트/정확 커서이동 + 저장
 * 좌(원문/업로드) / 중(하이라이트) / 우(추천항목 + 중복탐지)
 */
// === API / AUTH 기본 ===

// 0) 쿼리파라미터 오버라이드: ?api_base=http://127.0.0.1:5000
let queryApiBase = "";
try {
  if (typeof window !== "undefined") {
    const u = new URL(window.location.href);
    queryApiBase = (u.searchParams.get("api_base") || "").trim();
  }
} catch (_) {}

// 1) 환경변수 안전 추출 (process가 없을 수도 있으니 가드)
const ENV = (typeof process !== "undefined" && process.env) ? process.env : {};
const envApiBase =
  (ENV.NEXT_PUBLIC_API_BASE && String(ENV.NEXT_PUBLIC_API_BASE).trim()) ||
  (ENV.REACT_APP_API_BASE && String(ENV.REACT_APP_API_BASE).trim()) ||
  "";

// 2) 최종 API_BASE 결정
const API_BASE =
  queryApiBase ||
  (typeof window !== "undefined" && window.__API_BASE__ && String(window.__API_BASE__).trim()) ||
  envApiBase ||
  ((typeof window !== "undefined") &&
   (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
     ? "http://127.0.0.1:5000"
     : "https://glefit.onrender.com");

// 3) axios baseURL 적용 (⚠️ axios import는 파일 상단 import 구역에 있어야 함)
axios.defaults.baseURL = API_BASE;

// 4) 토큰/헤더 유틸 상수
const AUTH_KEY_LOCAL   = "glefit_token";          // 자동로그인: localStorage
const AUTH_KEY_SESS    = "glefit_token_session";  // 일반로그인: sessionStorage
const REMEMBER_ID_KEY  = "glefit_saved_id";       // 로그인 아이디 저장
const AUTO_LOGIN_KEY   = "glefit_auto_login";     // "1"=자동, "0"=일반

// 5) 공통: Authorization 헤더 적용/해제
function applyAuthHeader(token) {
  if (token) {
    axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  } else {
    delete axios.defaults.headers.common["Authorization"];
  }
}

// 현재 저장된 토큰 읽기
function getToken() {
  return (
    (typeof sessionStorage !== "undefined" && sessionStorage.getItem(AUTH_KEY_SESS)) ||
    (typeof localStorage  !== "undefined" && localStorage.getItem(AUTH_KEY_LOCAL)) ||
    ""
  );
}

// 처음 로드 시 1회 헤더 반영
applyAuthHeader(getToken());

// 6) 로그인/토큰/아이디 저장 헬퍼 ===== (추가됨) =====
function setToken(token, opts = { auto: false }) {
  try {
    const auto = !!opts.auto;
    if (auto) {
      // 자동 로그인: localStorage에 저장
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(AUTH_KEY_LOCAL, token || "");
        localStorage.setItem(AUTO_LOGIN_KEY, "1");
      }
      if (typeof sessionStorage !== "undefined") {
        sessionStorage.removeItem(AUTH_KEY_SESS);
      }
    } else {
      // 일반 로그인: sessionStorage에 저장
      if (typeof sessionStorage !== "undefined") {
        sessionStorage.setItem(AUTH_KEY_SESS, token || "");
      }
      if (typeof localStorage !== "undefined") {
        localStorage.removeItem(AUTH_KEY_LOCAL);
        localStorage.setItem(AUTO_LOGIN_KEY, "0");
      }
    }
  } finally {
    applyAuthHeader(token);
  }
}

function clearToken() {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(AUTH_KEY_LOCAL);
      localStorage.removeItem(AUTO_LOGIN_KEY);
    }
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.removeItem(AUTH_KEY_SESS);
    }
  } finally {
    applyAuthHeader("");
  }
}

function setSavedId(id = "", remember = false) {
  if (typeof localStorage === "undefined") return;
  if (remember && id) {
    localStorage.setItem(REMEMBER_ID_KEY, String(id));
  } else {
    localStorage.removeItem(REMEMBER_ID_KEY);
  }
}

function getSavedId() {
  try {
    return (typeof localStorage !== "undefined" && localStorage.getItem(REMEMBER_ID_KEY)) || "";
  } catch {
    return "";
  }
}

function getAutoLogin() {
  try {
    if (typeof localStorage === "undefined") return false;
    return localStorage.getItem(AUTO_LOGIN_KEY) === "1";
  } catch {
    return false;
  }
}
// ===== 헬퍼 끝 =====

// 7) 부팅 시 토큰 장착 보강
const bootToken = getToken();
if (bootToken) {
  axios.defaults.headers.common["Authorization"] = `Bearer ${bootToken}`;
} else {
  delete axios.defaults.headers.common["Authorization"];
}

// 8) 응답 인터셉터(만료/미결제 처리)
axios.interceptors.response.use(
  (res) => res,
  (err) => {
    const s = err?.response?.status;

    if (s === 401) {
      // 1) 토큰만 깨끗이 지우고
      clearToken(); // 이미 파일에 있는 함수

      // 2) 강한 새로고침 대신 "부드러운 교체"
      //    - 히스토리에 남기지 않도록 replace 사용
      //    - 번쩍임 줄이려고 requestAnimationFrame으로 다음 프레임에 실행
      if (typeof window !== "undefined") {
        requestAnimationFrame(() => {
          window.location.replace(window.location.pathname);
        });
      }
      // 3) alert()는 제거 (번쩍임 원인)
      return Promise.reject(err);
    }

    if (s === 402) {
      // 필요한 경우에만 안내 (402는 결제/만료)
      // alert("결제 대기 또는 이용기간 만료입니다. 관리자에게 문의하세요.");
      // → 팝업 대신 페이지 상단 배너/토스트가 있다면 그걸로 안내하는 편이 부드러움
    }

    return Promise.reject(err);
  }
);

// ========= 유틸 =========
const escapeRegExp = (s = "") => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const escapeHTML = (str = "") =>
  String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const getKeywordsFromFilename = (file) => {
  if (!file) return "";
  return file.name.replace(/\.[^/.]+$/, "");
};

function mapTokenType(resultType) {
  switch (resultType) {
    case "AI표현":
      return "ai";
    case "심의위반":
      return "policy-block";
    case "주의표현":
      return "policy-warn";
    default:
      return "error";
  }
}

function canonKR(s = "") {
  let t = String(s)
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, " ") // 구두점 제거
    .replace(/\s+/g, " ")
    .trim();
  t = t
    .replace(/\b(은|는|이|가|을|를|과|와|도|에|에서|으로|로|뿐|까지|부터)\b/g, "")
    .replace(/\b(합니다|했습니다|됩니다|될\s*수\s*있습니다|수\s*있습니다)\b/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return t;
}

function ngramSet(s, n = 3) {
  const t = canonKR(s);
  const out = new Set();
  if (t.length <= n) {
    out.add(t);
    return out;
  }
  for (let i = 0; i <= t.length - n; i++) out.add(t.slice(i, i + n));
  return out;
}

function jaccardByNgram(a, b, n = 3) {
  const A = ngramSet(a, n),
    B = ngramSet(b, n);
  let inter = 0;
  for (const x of A) if (B.has(x)) inter++;
  const uni = A.size + B.size - inter;
  return uni ? inter / uni : 0;
}

// === 위치까지 고려한 중복 병합 (짧은 토큰·한 글자 차이 보정) ===
function iou(a, b) {
  const inter = Math.max(
    0,
    Math.min(a.endIndex, b.endIndex) - Math.max(a.startIndex, b.startIndex)
  );
  const union =
    (a.endIndex - a.startIndex) + (b.endIndex - b.startIndex) - inter;
  return union === 0 ? 0 : inter / union;
}

function normText(s = "") {
  // 공백/구두점 제거해서 비교
  return String(s)
    .replace(/\s+/g, " ")
    .replace(/[^\p{L}\p{N}\s]/gu, "")
    .trim();
}

function mergeResultsPositionAware(results, overlapThreshold = 0.8) {
  const merged = [];
  (results || []).forEach((r) => {
    const item = {
      ...r,
      startIndex: Number(r?.startIndex) || 0,
      endIndex: Number(r?.endIndex) || 0,
      original: r?.original || "",
      type: r?.type || r?.rule_id || "구분",
      reasons: r?.reasons || [],
    };

    let bucket = null;

    for (const m of merged) {
      const sameType = (m.type || "") === (item.type || "");

      // 텍스트 유사성(완전 동일 or 포함관계 or 거의 동일)
      const a = normText(m.original);
      const b = normText(item.original);
      const sameText = a === b;
      const contains = a && b && (a.includes(b) || b.includes(a));
      const lenDiffOK = Math.abs(a.length - b.length) <= 2; // 1~2글자 차이 허용(짧은 토큰 보정)
      const textClose = sameText || (contains && lenDiffOK);

      // 위치 유사성(IoU/시작 위치 근접)
      const sameSpot =
        m.startIndex === item.startIndex && m.endIndex === item.endIndex;
      const iouVal = iou(m, item);
      const lenA = m.endIndex - m.startIndex;
      const lenB = item.endIndex - item.startIndex;
      const minLen = Math.max(1, Math.min(lenA, lenB));
      const allowShift = Math.max(1, Math.ceil(minLen * 0.35)); // 길이가 짧을수록 더 관대
      const nearStart = Math.abs(m.startIndex - item.startIndex) <= allowShift;

      // 병합 조건
      // - 타입 같고
      // - (텍스트가 거의 같으면서 위치가 가깝거나 IoU 충족) 또는 (아주 높은 IoU + 포함관계)
      if (
        sameType &&
        ((textClose && (sameSpot || nearStart || iouVal >= overlapThreshold)) ||
          (contains && iouVal >= 0.95))
      ) {
        bucket = m;
        break;
      }
    }

    if (!bucket) {
      merged.push({
        ...item,
        reasons: [
          item.reason_line || item.reason || item.guidance || null,
        ].filter(Boolean),
        legal_small_list: item.legal_small ? [item.legal_small] : [],
      });
    } else {
      const addReason = item.reason_line || item.reason || item.guidance;
      if (addReason && !bucket.reasons.includes(addReason))
        bucket.reasons.push(addReason);

      if (item.legal_small) {
        bucket.legal_small_list = bucket.legal_small_list || [];
        if (!bucket.legal_small_list.includes(item.legal_small))
          bucket.legal_small_list.push(item.legal_small);
      }

      const rank = {
        low: 1,
        medium: 2,
        high: 3,
        critical: 4,
        Low: 1,
        Medium: 2,
        High: 3,
        Critical: 4,
      };
      const cur = rank[(bucket.severity || "").toLowerCase()] || 0;
      const nxt = rank[(item.severity || "").toLowerCase()] || 0;
      if (nxt > cur) bucket.severity = item.severity;
    }
  });
  return merged;
}
// ========= 상태 =========
export default function Editor() {
  // [ADD] login hooks
  // [LOGIN UI 상태]
const [token, setTokenState] = useState(() => getToken());
const [loginU, setLoginU] = useState(getSavedId() || "");
const [loginP, setLoginP] = useState("");
const [rememberId, setRememberId] = useState(!!getSavedId());
const [autoLogin, setAutoLogin] = useState(getAutoLogin());
const [loginErr, setLoginErr] = useState("");

// ⬇⬇ 추가: 게스트(체험) 모드 스위치
const [guestMode, setGuestMode] = useState(false);


  // [상단 표시용 내 정보]
  const [me, setMe] = useState(undefined);
  // 권한 계산 (서버가 role 또는 is_admin을 줄 수 있으니 모두 허용)
  const userRole = String(me?.role ?? "").toLowerCase();
  const isAdmin = !!(
    me?.is_admin === true ||
    userRole === "admin" ||
    userRole === "owner" ||
    userRole === "manager"
  );

// === [ADD] 게시판 전용 로그인 상태 (메인 토큰과 분리) ===
const [boardLoggedIn, setBoardLoggedIn] = useState(() => {
  try { return localStorage.getItem("glefit_board_ok") === "1"; } catch { return false; }
});
const [boardLogging, setBoardLogging] = useState(false);

// 게시판 전용 토큰 (미니 로그인용)
const [boardToken, setBoardToken] = useState(() => {
  try { return localStorage.getItem("glefit_board_token") || ""; } catch { return ""; }
});

// === [1회용 마이그레이션: sessionStorage → localStorage] ===
useEffect(() => {
  try {
    const ok  = sessionStorage.getItem("glefit_board_ok");
    const tk  = sessionStorage.getItem("glefit_board_token");
    const ia  = sessionStorage.getItem("glefit_board_is_admin");

    if (ok || tk || ia) {
      if (ok) localStorage.setItem("glefit_board_ok", ok);
      if (tk) localStorage.setItem("glefit_board_token", tk);
      if (ia) localStorage.setItem("glefit_board_is_admin", ia);

      sessionStorage.removeItem("glefit_board_ok");
      sessionStorage.removeItem("glefit_board_token");
      sessionStorage.removeItem("glefit_board_is_admin");
    }
  } catch {}
}, []);

// 공통 인증 헤더: 메인 토큰 > 게시판 토큰
function authHeaders() {
  const t = (token || boardToken || "").trim();
  return t ? { Authorization: `Bearer ${t}` } : {};
}


// 미니로그인 입력은 기존 loginU/loginP 상태를 재사용해도 OK (동일 계정)
// 게시판 전용 로그인: 메인 토큰/헤더는 건드리지 않음
async function doBoardLogin(e) {
  e?.preventDefault();
  if (boardLogging) return;
  try {
    setBoardLogging(true);

    // 1) 로그인해서 토큰 받기
    const { data } = await axios.post(`${API_BASE}/auth/login`, {
      username: loginU,
      password: loginP,
    });
    const t = data?.access_token || data?.token;
    if (!t) throw new Error("토큰 없음");

    // 2) 게시판 전용 토큰 저장(+표시 플래그)
    setBoardToken(t);
    try {
      localStorage.setItem("glefit_board_ok", "1");
      localStorage.setItem("glefit_board_token", t);
    } catch {}

    // 3) (선택) 관리자 여부 캐시
    try {
      const me = await axios.get(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${t}` }
      });
      const role =
        me?.data?.role ||
        me?.data?.user?.role ||
        me?.data?.payload?.role || "";
      const isAdmin =
        String(role || "").toLowerCase() === "admin" ||
        me?.data?.is_admin || me?.data?.isAdmin;
      try { localStorage.setItem("glefit_board_is_admin", isAdmin ? "1" : "0"); } catch {}
    } catch {}

    setBoardLoggedIn(true);
  } catch (err) {
    alert("게시판 로그인 실패: 아이디/비번을 확인하세요.");
  } finally {
    setBoardLogging(false);
  }
}

function doBoardLogout() {
  setBoardLoggedIn(false);
  try {
    localStorage.removeItem("glefit_board_token");
    localStorage.removeItem("glefit_board_ok");
    localStorage.removeItem("glefit_board_is_admin");
  } catch {}
  setBoardToken("");
  setLoginU("");
  setLoginP("");
}

// === [ADD] 한 줄 홍보게시판: 로컬 저장 + 서버 연동 준비형 ===
const BOARD_KEY = "glefit_board_v1";

const [boardPosts, setBoardPosts] = useState(() => {
  try { return JSON.parse(localStorage.getItem(BOARD_KEY) || "[]"); } catch { return []; }
});

// [ADD] 서버 목록 로더
async function loadBoardList() {
  try {
    const { data } = await axios.get(`${API_BASE}/board/list`);
    const items = Array.isArray(data?.items) ? data.items : [];
    // pinned DESC, ts DESC 정렬은 서버에서도 하지만, 안전하게 프론트도 동일 정렬
    const sorted = [...items].sort((a,b)=>
      (b.pinned?1:0)-(a.pinned?1:0) ||
      ((a.pin_rank ?? 9e9) - (b.pin_rank ?? 9e9)) ||
      (b.ts - a.ts)
    );

    setBoardPosts(sorted);
  } catch (e) {
    // 서버 실패 시, 기존 로컬 값 유지
  }
}

useEffect(() => {
  loadBoardList();
  // 로그인/권한이 바뀌면 목록 새로고침
}, [token, boardLoggedIn, isAdmin]);

useEffect(() => {
  try {
    if (boardPosts.length > 200) {
      const trimmed = [...boardPosts].sort((a,b)=>a.ts-b.ts).slice(-200);
      localStorage.setItem(BOARD_KEY, JSON.stringify(trimmed));
      setBoardPosts(trimmed);
    } else {
      localStorage.setItem(BOARD_KEY, JSON.stringify(boardPosts));
    }
  } catch {}
}, [boardPosts]);

const [boardInput, setBoardInput] = useState("");
const [boardErr, setBoardErr] = useState("");

// ▶ 게시판 작성자 판정: 토큰 로그인 사용자 우선,
//    미니게시판에 별도 로그인한 경우에만 loginU 허용
const myId = React.useMemo(() => {
  const tokenUser = (me?.username || "").trim();
  if (tokenUser) return tokenUser;
  return boardLoggedIn ? (loginU || "").trim() : "";
}, [me, loginU, boardLoggedIn]);

const todayKey = new Date().toISOString().slice(0,10);
function countTodayByUser(uid) {
  const dayStart = new Date(todayKey+"T00:00:00").getTime();
  const dayEnd   = new Date(todayKey+"T23:59:59").getTime();
  return (boardPosts || []).filter(p => p.user===uid && p.ts>=dayStart && p.ts<=dayEnd).length;
}

// 기본: 1 ID/일 2회, 관리자 무제한 (관리자 UI로 가변 확장 예정)
const DEFAULT_DAILY_LIMIT = 2;
const dailyLimitFor = (uid) => (isAdmin ? 9999 : DEFAULT_DAILY_LIMIT);

async function addPost() {
  setBoardErr("");
  const text = (boardInput || "").trim();
  if (!boardLoggedIn && !token) { setBoardErr("로그인 후 작성 가능합니다."); return; }
  if (!text) { setBoardErr("내용을 입력하세요."); return; }
  if (text.length > 60) { setBoardErr("한 줄(60자) 제한을 초과했습니다."); return; }

  try {
    const res = await axios.post(`${API_BASE}/board/add`, { text }, { headers: authHeaders() });
    if (res?.data?.ok) {
      const item = res.data.item;
      setBoardPosts(prev => {
        const next = [item, ...prev].sort((a,b)=> (b.pinned?1:0)-(a.pinned?1:0) || b.ts - a.ts);
        return next.slice(0, 200);
      });
      setBoardInput("");
      setBoardErr("");
    } else {
      const e = res?.data?.error || "ERR";
      if (e === "LIMIT") setBoardErr("일일 작성 한도를 초과했습니다.");
      else if (e === "BLOCKED") setBoardErr("작성 정지된 사용자입니다.");
      else if (e === "TOO_LONG") setBoardErr("한 줄(60자) 제한입니다.");
      else setBoardErr("작성 실패");
    }
  } catch (err) {
    const s = err?.response?.status;
    if (s === 400 && err?.response?.data?.error === "LIMIT") {
      setBoardErr("일일 작성 한도를 초과했습니다.");
    } else if (s === 403 && err?.response?.data?.error === "BLOCKED") {
      setBoardErr("작성 정지된 사용자입니다.");
    } else {
      setBoardErr("작성 실패");
    }
  }
}

async function deletePost(id) {
  try {
    const { data } = await axios.post(`${API_BASE}/board/delete`, { id }, { headers: authHeaders() });
    if (data?.ok) {
      setBoardPosts(prev => prev.filter(p => p.id !== id));
    } else {
      alert("삭제 실패");
    }
  } catch {
    alert("삭제 실패(권한 또는 네트워크)");
  }
}

async function editPost(id, nextText) {
  const t = (nextText || "").trim();
  if (!t || t.length > 60) return alert("한 줄(60자) 제한");

  try {
    const { data } = await axios.post(`${API_BASE}/board/edit`, { id, text: t }, { headers: authHeaders() });
    if (data?.ok) {
      setBoardPosts(prev => prev.map(p => p.id === id ? { ...p, text: t } : p));
    } else {
      alert("수정 실패");
    }
  } catch {
    alert("수정 실패(권한 또는 네트워크)");
  }
}

async function togglePin(id) {
  if (!isAdmin) return alert("관리자만 상단 고정 가능");
  try {
    const { data } = await axios.post(`${API_BASE}/board/toggle_pin`, { id }, { headers: authHeaders() });
    if (data?.ok) {
      setBoardPosts(prev => {
        const next = prev.map(p => p.id === id ? { ...p, pinned: !!data.pinned } : p);
        return next.sort((a,b)=> (b.pinned?1:0)-(a.pinned?1:0) || b.ts - a.ts);
      });
    } else {
      alert("상단고정 실패");
    }
  } catch {
    alert("상단고정 실패(권한 또는 네트워크)");
  }
}


  // ▶ 상단 공지 (로컬 저장)
  const [notice, setNotice] = React.useState(
    localStorage.getItem("glefit_notice") || ""
  );
  React.useEffect(() => {
    const v = localStorage.getItem("glefit_notice");
    if (v !== null) setNotice(v);
  }, []);
  React.useEffect(() => {
    localStorage.setItem("glefit_notice", notice || "");
  }, [notice]);

  // 잠금 스타일
  const lockedBtnStyle = {
    opacity: 0.55,
    cursor: "not-allowed",
    filter: "grayscale(0.6)",
  };

const [showNoticeModal, setShowNoticeModal] = useState(false);

// === 업로드 제한 상수/유틸 ===
const MAX_FILES_USER = 50;
const MAX_FILES_GUEST = 3;

// [ADD] 100KB 제한(일반/체험판), 관리자는 무제한
const MAX_TEXT_BYTES_NON_ADMIN = 100 * 1024;

// 로그인/역할 상태를 이미 갖고 있다면 그대로 사용 (isAdmin, guestMode, token 등)
// 예: const isGuest = guestMode || !token; const canUploadUnlimited = !!isAdmin;

// [ADD] 초과 파일 필터
const getFileSizeBytes = (f) => (f && typeof f.size === "number" ? f.size : 0);

function filterOversizeFiles(list = [], canUploadUnlimited) {
  if (canUploadUnlimited) return list; // 관리자 예외
  const kept = [];
  const dropped = [];
  for (const f of list) {
    const name = f?.name || "";
    const lower = name.toLowerCase();
    // 기존 포맷 필터는 유지
    if (!(lower.endsWith(".txt") || lower.endsWith(".docx"))) continue;
    const sz = getFileSizeBytes(f);
    if (sz > MAX_TEXT_BYTES_NON_ADMIN) dropped.push({ name, size: sz });
    else kept.push(f);
  }
  if (dropped.length) {
    alert(
      "일반/체험판은 항목당 100KB까지만 업로드할 수 있습니다.\n제외된 파일:\n" +
      dropped.map((x) => `- ${x.name} (${x.size} bytes)`).join("\n")
    );
  }
  return kept;
}

const isGuest = guestMode || !token; // 게스트 모드이거나 토큰 없으면 게스트
const canUploadUnlimited = !!isAdmin; // 관리자는 무제한

function clampUploadList(list = []) {
  if (canUploadUnlimited) return list;
  const limit = isGuest ? MAX_FILES_GUEST : MAX_FILES_USER;
  if (list.length > limit) {
    alert(`업로드 제한: ${isGuest ? "체험 계정" : "일반 계정"}은 최대 ${limit}건까지 가능합니다.`);
    return list.slice(0, limit);
  }
  return list;
}

  // /auth/me 호출
  async function fetchMe() {
    try {
      const { data } = await axios.get(`${API_BASE}/auth/me`);
      // { username, role, is_active, paid_until, remaining_days }
      setMe(data);
    } catch {
      setMe(null);
    }
  }
  useEffect(() => {
    if (token) fetchMe();
  }, [token]);

  async function doLogin(e) {
    e?.preventDefault();
    setLoginErr("");
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, {
        username: loginU,
        password: loginP,
      });
      const t = res.data?.access_token;
      if (!t) throw new Error("토큰 없음");
      // 저장 옵션 반영
      setToken(t, { auto: autoLogin });
      if (rememberId) setSavedId(loginU, true);
      else setSavedId("", false);
      axios.defaults.headers.common["Authorization"] = `Bearer ${t}`;
      setTokenState(t);
      setLoginP("");
    } catch (err) {
      if (err?.response?.status === 402) setLoginErr("결제 대기/기간 만료");
      else setLoginErr("로그인 실패");
    }
  }

  function doLogout() {
   try {
     // 1) 모든 토큰/자동로그인 흔적 제거
     clearToken();
     if (axios?.defaults?.headers?.common) {
       delete axios.defaults.headers.common["Authorization"];
     }
     // 2) 상태를 즉시 게스트로
     setTokenState("");
     setMe(null);
     setGuestMode(true);
   } finally {
     // 3) 현재 경로로 하드 리로드(부팅 토큰 로직 재평가)
     window.location.replace(window.location.pathname);
   }
 }

// === [ADD] TXT 인코딩 자동 판별 디코더 ===
async function decodeTxtBest(arrayBuffer) {
  // 브라우저 TextDecoder로 시도할 후보 (우선순위)
  const candidates = [
    { label: "utf-8", bomAware: true },
    { label: "utf-16le" },
    { label: "utf-16be" },
    { label: "euc-kr" }, // 대부분의 CP949 문서를 커버
  ];

  const bytes = new Uint8Array(arrayBuffer);

  // 간단한 품질 스코어러:  (U+FFFD) 비율↓, 한글(가-힣) 비율↑ 가 좋은 해석
  const scoreText = (s) => {
    if (!s) return -1;
    const total = s.length || 1;
    const bad = (s.match(/\uFFFD/g) || []).length;          // 치환문자
    const hangul = (s.match(/[가-힣]/g) || []).length;       // 한글자수
    const asciiCtrl = (s.match(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g) || []).length;
    // 가중치: 깨짐패널티, 제어문자 패널티, 한글 가점
    return (hangul * 3) - (bad * 10) - (asciiCtrl * 2);
  };

  let best = { enc: "utf-8", text: new TextDecoder("utf-8", { fatal: false }).decode(bytes), score: -1 };

  for (const c of candidates) {
    try {
      // BOM 자동 무시는 utf-8-sig와 동일 효과
      const dec = new TextDecoder(c.label, { fatal: false });
      const text = dec.decode(bytes);
      const sc = scoreText(text);
      if (sc > best.score) best = { enc: c.label, text, score: sc };
    } catch (_) {
      // 해당 인코딩 미지원/실패 시 패스
    }
  }
  return best.text || "";
}


  const [text, setText] = useState("");
  const [highlightedHTML, setHighlightedHTML] = useState("");

  // [ADD] 검사화면 줄바꿈 토글: 기본=자동 줄바꿈 켜짐
  const [wrapLongLines, setWrapLongLines] = useState(true);
  const [results, setResults] = useState([]); // 현재 표시 중인 파일의 개별 결과
  const [resultsVerify, setResultsVerify] = useState([]); // /verify 전용
  const [resultsPolicy, setResultsPolicy] = useState([]); // /policy_verify 전용
  const [aiSummary, setAiSummary] = useState(null);
  const [files, setFiles] = useState([]);
  const [fileIndex, setFileIndex] = useState(0);

  // 🔴 파일별 캐시 구조 확장
  // fileResults[fileName] = { text, verify:[], policy:[], highlightedHTML, aiSummary }
  const [fileResults, setFileResults] = useState({});
  const [isChecking, setIsChecking] = useState(false);
  const [currentBatchIndex, setCurrentBatchIndex] = useState(0);

  // 키워드(파일명 자동 채움, 로컬저장)
  const [keywordInput, setKeywordInput] = useState(
    () => localStorage.getItem("glfit_keywords") || ""
  );

  // 단어찾기(키워드와 분리, 로컬저장)
  const [termInput, setTermInput] = useState(
    () => localStorage.getItem("glfit_terms") || ""
  );

  // 결과 패널 필터
  const [filterPolicyOnly, setFilterPolicyOnly] = useState(false);

  // ====== (NEW) 중복/유사 탐지 상태 ======
  // 단일 문서 내
  const [intraExactGroups, setIntraExactGroups] = useState([]); // [{norm, occurrences:[{index,start,end,original}...]}]
  const [intraSimilarPairs, setIntraSimilarPairs] = useState([]); // [{i,j,score,a:{start,end,original},b:{...}}]

  // 교차(여러 문서 간)
  const [interExactGroups, setInterExactGroups] = useState([]); // [{norm, occurrences:[{file,fileIndex,sentIndex,start,end,original}...]}]
  const [, setInterSimilarPairs] = useState([]);
  const [interSimilarGroups, setInterSimilarGroups] = useState([]);

  // 교차 탐지 옵션
  const [interMinLen, setInterMinLen] = useState(6);
  const [interSimTh, setInterSimTh] = useState(0.70);
  const [intraMinLen, setIntraMinLen] = useState(6);
  const [intraSimTh, setIntraSimTh] = useState(0.70);

  const textareaRef = useRef(null);

// === [ADD] 워커 풀(Worker Pool) 뼈대: 큐 + 분배 ===
const WORKER_URL = "/workers/readerWorker.js";
// 코어 수 기반 기본값: 동시에 과하게 돌지 않도록 2~4개 범위
const POOL_SIZE = Math.max(2, Math.min(4, (navigator.hardwareConcurrency || 4) - 1));

const __workers = [];
const __busy = [];
let __jobSeq = 1;
const __callbacks = new Map();
const __queue = [];

function initWorkers() {
  if (__workers.length) return;
  for (let i = 0; i < POOL_SIZE; i++) {
    const w = new Worker(WORKER_URL);
    w.onmessage = (ev) => {
      const { id, ok, data, error } = ev.data || {};
      const cb = __callbacks.get(id);
      if (cb) {
        __callbacks.delete(id);
        try { cb(ok, data, error); } catch (_) {}
      }
      __busy[i] = false;
      flushQueue();
    };
    __workers.push(w);
    __busy.push(false);
  }
}

function postJob(kind, payload) {
  return new Promise((resolve) => {
    const id = __jobSeq++;
    __queue.push({ id, kind, payload, resolve });
    flushQueue();
  });
}

function flushQueue() {
  for (let i = 0; i < __workers.length; i++) {
    if (__busy[i]) continue;
    const job = __queue.shift();
    if (!job) return;
    __busy[i] = true;
    __callbacks.set(job.id, (ok, data, error) => job.resolve({ ok, data, error }));
    __workers[i].postMessage({ id: job.id, kind: job.kind, payload: job.payload });
  }
}

  // ========= 로컬 스토리지 =========
  useEffect(() => {
    localStorage.setItem("glfit_keywords", keywordInput || "");
  }, [keywordInput]);
  useEffect(() => {
    localStorage.setItem("glfit_terms", termInput || "");
  }, [termInput]);
// ========= 파생 데이터(통계) =========
const parsedKeywords = (keywordInput || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const parsedTerms = (termInput || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const keywordStats = useMemo(
  () =>
    parsedKeywords.map((kw) => ({
      word: kw,
      count: (text.match(new RegExp(escapeRegExp(kw), "g")) || []).length,
    })),
  [parsedKeywords, text]
);

const termStats = useMemo(
  () =>
    parsedTerms.map((t) => ({
      word: t,
      count: (text.match(new RegExp(escapeRegExp(t), "g")) || []).length,
    })),
  [parsedTerms, text]
);

// ========= 파일 추출/적재 =========
//⬇️ 이 함수 전체를 교체
const extractFileText = async (file) => {
  const lower = (file.name || "").toLowerCase();

  // 1) TXT: ArrayBuffer로 읽은 뒤 최적 인코딩으로 디코딩
  if (lower.endsWith(".txt")) {
    const buf = await file.arrayBuffer();
    return await decodeTxtBest(buf);
  }

  // 2) DOCX: 기존대로 mammoth 사용 (한글 호환 우수)
  if (lower.endsWith(".docx")) {
    const arrayBuffer = await file.arrayBuffer();
    const { value } = await mammoth.extractRawText({ arrayBuffer });
    return value || "";
  }

  // 3) 기타 포맷은 빈 문자열
  return "";
};

const collectFilesFromDataTransfer = async (dataTransfer) => {
  const out = [];
  const items = dataTransfer.items || [];

  const traverseEntry = (entry) =>
    new Promise((resolve) => {
      if (entry.isFile) {
        entry.file((file) => {
          const lower = file.name.toLowerCase();
          if (lower.endsWith(".txt") || lower.endsWith(".docx")) out.push(file);
          resolve();
        });
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        const readEntries = () => {
          reader.readEntries((entries) => {
            if (!entries.length) return resolve();
            let i = 0;
            const next = () => {
              if (i >= entries.length) return readEntries();
              traverseEntry(entries[i++]).then(next);
            };
            next();
          });
        };
        readEntries();
      } else {
        resolve();
      }
    });

  const tasks = [];
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    const entry = it.webkitGetAsEntry && it.webkitGetAsEntry();
    if (entry) tasks.push(traverseEntry(entry));
    else {
      const f = it.getAsFile && it.getAsFile();
      if (f) {
        const lower = f.name.toLowerCase();
        if (lower.endsWith(".txt") || lower.endsWith(".docx")) out.push(f);
      }
    }
  }
  await Promise.all(tasks);
  return out;
};

//⬇️ 이 함수 전체를 교체
const loadFileContent = async (file, idx = null) => {
  if (!file) return;
  const textContent = await extractFileText(file);
  setText(textContent);
  // (선택) 파일명 → 키워드 자동 세팅 비활성
  setKeywordInput(getKeywordsFromFilename(file));

  const cached = fileResults[file.name];
  if (cached) {
    // 🔴 분리 결과 복원
    setResultsVerify(Array.isArray(cached.verify) ? cached.verify : []);
    setResultsPolicy(Array.isArray(cached.policy) ? cached.policy : []);
    const merged = [
      ...(Array.isArray(cached.verify) ? cached.verify : []),
      ...(Array.isArray(cached.policy) ? cached.policy : []),
    ];
    setResults(merged);
    setHighlightedHTML(cached.highlightedHTML || "");
    setAiSummary(cached.aiSummary || null);
  } else {
    setResultsVerify([]);
    setResultsPolicy([]);
    setResults([]);
    setHighlightedHTML("");
    setAiSummary(null);
  }

  // 중복탐지 패널 초기화
  setInterExactGroups([]); // ⬅️ 교차(여러 문서 간) 결과까지 초기화
  setInterSimilarPairs([]);
  setInterSimilarGroups([]);
  setIntraExactGroups([]);
  setIntraSimilarPairs([]);
};

const replaceAllFiles = async (arr) => {
  // 1) 포맷 필터
  let onlySupported = (arr || []).filter((f) => {
    const lower = (f.name || "").toLowerCase();
    return lower.endsWith(".txt") || lower.endsWith(".docx");
  });

  // 2) 100KB 초과 파일 제거 (관리자 무제한)
  onlySupported = filterOversizeFiles(onlySupported, !!isAdmin);

  // 3) 정렬
  onlySupported.sort((a, b) => a.name.localeCompare(b.name));

  // 4) 업로드 목록 상태에 반영
  setFiles(onlySupported);
  setFileIndex(0);

  // 5) 보기 패널 초기화
  setIntraExactGroups([]);
  setIntraSimilarPairs([]);
  setInterExactGroups([]);
  setInterSimilarPairs([]);
  setInterSimilarGroups([]);

  // 6) 첫 파일 로드 or 화면 정리
  if (onlySupported.length) {
    await loadFileContent(onlySupported[0], 0);
    setKeywordInput(getKeywordsFromFilename(onlySupported[0]));
  } else {
    setText("");
    setResultsVerify([]);
    setResultsPolicy([]);
    setResults([]);
    setHighlightedHTML("");
    setAiSummary(null);
  }
};

const handleFileInputChange = async (e) => {
  const list = Array.from(e.target.files || []);
  const limited = clampUploadList(list);
  await replaceAllFiles(limited);
};

const handleDrop = async (e) => {
  e.preventDefault();
  e.stopPropagation();
  const collected = await collectFilesFromDataTransfer(e.dataTransfer);
  let all = collected;
  if ((!all || !all.length) && e.dataTransfer.files?.length) {
    all = Array.from(e.dataTransfer.files);
  }
  const limited = clampUploadList(all || []);
  await replaceAllFiles(limited);
};

const handleDragOver = (e) => e.preventDefault();

const handleNextFile = async () => {
  const next = fileIndex + 1;
  if (next < files.length) {
    setFileIndex(next);
    await loadFileContent(files[next], next);
    setKeywordInput(getKeywordsFromFilename(files[next]));
  } else {
    alert("더 이상 파일이 없습니다.");
  }
};

const handlePrevFile = async () => {
  const prev = fileIndex - 1;
  if (prev >= 0) {
    setFileIndex(prev);
    await loadFileContent(files[prev], prev);
    setKeywordInput(getKeywordsFromFilename(files[prev]));
  } else {
    alert("이전 파일이 없습니다.");
  }
};

// (REPLACE) generateHighlightedHTML — 원문 유지 + dataset 첨부 + 유연 검증
const generateHighlightedHTML = (raw, matches, keywords, terms) => {
  const text = String(raw || "");
  const N = text.length;

  const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));
  const norm = (s = "") => String(s).replace(/\s+/g, " ").trim();
  const esc = (s = "") =>
    String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  const escAttr = (s = "") => esc(String(s)).replace(/"/g, "&quot;");

  const resolve = (full, r) => {
    const orig = String(r?.original || "");
    const bef = String(r?.before || "");
    const aft = String(r?.after || "");
    const s0 = Number.isFinite(r?.startIndex) ? r.startIndex : -1;
    const e0 = Number.isFinite(r?.endIndex) ? r.endIndex : -1;

    if (s0 >= 0 && e0 > s0 && e0 <= full.length) return { s: s0, e: e0 };

    if (bef && orig && aft) {
      const i = full.indexOf(bef + orig + aft);
      if (i >= 0) return { s: i + bef.length, e: i + bef.length + orig.length };
    }
    if (bef && orig) {
      const i = full.indexOf(bef + orig);
      if (i >= 0) return { s: i + bef.length, e: i + bef.length + orig.length };
    }
    if (orig && aft) {
      const i = full.indexOf(orig + aft);
      if (i >= 0) return { s: i, e: i + orig.length };
    }
    if (orig) {
      let best = -1,
        pos = full.indexOf(orig);
      while (pos !== -1) {
        if (best === -1 || (s0 >= 0 && Math.abs(pos - s0) < Math.abs(best - s0)))
          best = pos;
        pos = full.indexOf(orig, pos + 1);
      }
      if (best !== -1) return { s: best, e: best + orig.length };
    }
    if (s0 >= 0) {
      const s = clamp(s0, 0, full.length);
      const e = clamp(Math.max(s0, e0), s, full.length);
      if (e > s) return { s, e };
    }
    return null;
  };

  const spans = [];

  // 1) 검수 결과: 원문 구간만 하이라이트 + 클릭용 dataset
  (matches || []).forEach((r) => {
    const pos = resolve(text, r);
    if (!pos) return;

    let { s, e } = pos;
    s = clamp(s, 0, N);
    e = clamp(e, s, N);
    if (e - s <= 0 || e - s > 400) return;

    const slice = text.slice(s, e);
    const want = r?.original ? String(r.original) : slice;

    // 공백/문장부호 차이 정도만 허용
    const clean = (x) => norm(x.replace(/[^\p{L}\p{N}\s]/gu, ""));
    if (clean(slice) !== clean(want)) return;

    const title = [
      r?.type ? `[${r.type}]` : "",
      r?.reason_line || "",
      r?.legal_small ? String(r.legal_small).replace(/<[^>]+>/g, "") : "",
      ...(Array.isArray(r?.suggestions) ? r.suggestions.slice(0, 3) : []),
    ]
      .filter(Boolean)
      .join(" / ");

    spans.push({
      start: s,
      end: e,
      content: slice,
      type: mapTokenType(r?.type),
      title,
      data: {
        bef: r?.before || "",
        aft: r?.after || "",
        orig: r?.original || slice,
      },
    });
  });

  // 2) 키워드/단어찾기 — 중앙 화면에서는 렌더하지 않음
  // (keywords || []).forEach((kw) => {
  //   if (!kw) return;
  //   const re = new RegExp(escapeRegExp(kw), "g"); let m;
  //   while ((m = re.exec(text)) !== null) {
  //     spans.push({
  //       start: m.index,
  //       end: m.index + kw.length,
  //       content: text.slice(m.index, m.index + kw.length),
  //       type: "keyword",
  //       title: "키워드",
  //       data: { bef: "", aft: "", orig: text.slice(m.index, m.index + kw.length) },
  //     });
  //   }
  // });

  // (terms || []).forEach((t) => {
  //   if (!t) return;
  //   const re = new RegExp(escapeRegExp(t), "g"); let m;
  //   while ((m = re.exec(text)) !== null) {
  //     spans.push({
  //       start: m.index,
  //       end: m.index + t.length,
  //       content: text.slice(m.index, m.index + t.length),
  //       type: "term",
  //       title: "단어찾기",
  //       data: { bef: "", aft: "", orig: text.slice(m.index, m.index + t.length) },
  //     });
  //   }
  // });

  // 3) 겹침 제거
  spans.sort((a, b) => a.start - b.start || a.end - b.end);
  const nonOverlap = [];
  let lastEnd = -1;
  for (const s of spans) if (s.start >= lastEnd) {
    nonOverlap.push(s);
    lastEnd = s.end;
  }

  // 4) 원문 재조립 (dataset 포함)
  let html = "",
    cur = 0;
  for (const s of nonOverlap) {
    html += esc(text.slice(cur, s.start));
    const body = esc(s.content);
    const common =
      `title="${escAttr(s.title || "")}" ` +
      `data-start="${s.start}" data-end="${s.end}" ` +
      `data-bef="${escAttr(s.data?.bef || "")}" ` +
      `data-aft="${escAttr(s.data?.aft || "")}" ` +
      `data-orig="${escAttr(s.data?.orig || s.content)}"`;

    if (s.type === "error")
      html += `<span class="error-token"${common}>${body}</span>`;
    else if (s.type === "ai")
      html += `<span class="ai-token"${common}>${body}</span>`;
    else if (s.type === "policy-block")
      html += `<span class="policy-block"${common}>${body}</span>`;
    else if (s.type === "policy-warn")
      html += `<span class="policy-warn"${common}>${body}</span>`;
    else if (s.type === "keyword")
      html += `<span class="keyword-token"${common}>${body}</span>`;
    else html += `<span class="term-token"${common}>${body}</span>`;

    cur = s.end;
  }
  html += esc(text.slice(cur));
  return html;
};

// ⬇️ 이 함수 전체를 교체
const handleCheck = async () => {
  try {
    setIsChecking(true);
    // === 캐시 재사용: 텍스트/파일명 동일하면 서버 호출 스킵 ===
    const cur = files[fileIndex];
    const fname = cur?.name || "";
    const cached = fname && fileResults?.[fname];
    if (cached && (cached.text || "") === (text || "")) {
      // 캐시된 화면 상태 복원
      setResultsVerify(cached.verify || []);
      setResultsPolicy(cached.policy || []);
      setResults(mergeResultsPositionAware([...(cached.verify||[]), ...(cached.policy||[])]));
      setHighlightedHTML(cached.highlightedHTML || "");
      setAiSummary(cached.aiSummary || null);
      return; // 서버 호출 생략
    }

    const res = await axios.post(`${API_BASE}/verify`, { text });
    const payload = res.data || {};
    const data = Array.isArray(payload.results) ? payload.results : [];

    // 🔴 현재 파일의 policy 결과는 유지하면서 verify만 갱신
    setResultsVerify(data);
    const mergedRaw = [...data, ...resultsPolicy];

    const filtered = mergedRaw.filter(
      (r) =>
        Number.isFinite(r?.startIndex) &&
        Number.isFinite(r?.endIndex) &&
        r.endIndex > r.startIndex &&
        (r.original || "").length > 0
    );

    const merged = mergeResultsPositionAware(filtered);
    setResults(merged);

    const highlighted = generateHighlightedHTML(
      text,
      merged,
      parsedKeywords,
      parsedTerms
    );
    setHighlightedHTML(highlighted);
    setAiSummary(payload.aiSummary || null);

    // 🔴 파일별 캐시에 분리 저장
    if (fname) {
      setFileResults((prev) => ({
        ...prev,
        [fname]: {
          text,
          verify: data,
          policy: prev[fname]?.policy || [],
          highlightedHTML: highlighted,
          aiSummary: payload.aiSummary || null,
        },
      }));
    }
  } catch (e) {
  try { navigator.sendBeacon?.(`${API_BASE}/log/client_error`, JSON.stringify({ where:"handleCheck", msg: String(e?.message||e), time: Date.now() })); } catch {}
  alert("검사 실패: " + (e?.message || "Unknown error"));
} finally {
    setIsChecking(false);
  }
};
// ⬇️ 이 함수 전체를 교체
const handlePolicyCheck = async () => {
  try {
    setIsChecking(true);
    // === 캐시 재사용: 텍스트/파일명 동일하면 서버 호출 스킵 ===
    const cur = files[fileIndex];
    const fname = cur?.name || "";
    const cached = fname && fileResults?.[fname];
    if (cached && (cached.text || "") === (text || "")) {
      setResultsVerify(cached.verify || []);
      setResultsPolicy(cached.policy || []);
      setResults(mergeResultsPositionAware([...(cached.verify||[]), ...(cached.policy||[])]));
      setHighlightedHTML(cached.highlightedHTML || "");
      setAiSummary(cached.aiSummary || null);
      return; // 서버 호출 생략
    }

    const res = await axios.post(`${API_BASE}/policy_verify`, { text });
    const payload = res.data || {};
    const data = Array.isArray(payload.results) ? payload.results : [];

    // 🔴 verify 유지 + policy 갱신
    setResultsPolicy(data);
    const mergedRaw = [...resultsVerify, ...data];

    const filtered = mergedRaw.filter(
      (r) =>
        Number.isFinite(r?.startIndex) &&
        Number.isFinite(r?.endIndex) &&
        r.endIndex > r.startIndex &&
        (r.original || "").length > 0
    );

    const merged = mergeResultsPositionAware(filtered);
    setResults(merged);
    setAiSummary(null);

    const highlighted = generateHighlightedHTML(
      text,
      merged,
      parsedKeywords,
      parsedTerms
    );
    setHighlightedHTML(highlighted);

    // 🔴 파일별 캐시에 분리 저장
    if (fname) {
      setFileResults((prev) => ({
        ...prev,
        [fname]: {
          text,
          verify: prev[fname]?.verify || [],
          policy: data,
          highlightedHTML: highlighted,
          aiSummary: null,
        },
      }));
    }
  } catch (e) {
    alert("심의 검사 실패: " + (e?.message || "Unknown error"));
  } finally {
    setIsChecking(false);
  }
};

// ⬇️ 이 함수 전체를 교체
const handleBatchCheck = async () => {
  if (!files.length) return alert("업로드된 파일이 없습니다.");
  setIsChecking(true);
  setCurrentBatchIndex(0);

  for (let i = 0; i < files.length; i++) {
    setCurrentBatchIndex(i);
    const f = files[i];
    const textContent = await extractFileText(f);
    try {
      // 1) 검사
      const r1 = await axios.post(`${API_BASE}/verify`, { text: textContent });
      const dataVerify = Array.isArray(r1.data?.results) ? r1.data.results : [];
      const aiSum = r1.data?.aiSummary || null;

      // 2) 심의
      const r2 = await axios.post(`${API_BASE}/policy_verify`, { text: textContent });
      const dataPolicy = Array.isArray(r2.data?.results) ? r2.data.results : [];

      // 3) 중앙 표시용 합본
      const mergedRaw = [...dataVerify, ...dataPolicy];
      const filtered = mergedRaw.filter(
        (r) =>
          Number.isFinite(r?.startIndex) &&
          Number.isFinite(r?.endIndex) &&
          r.endIndex > r.startIndex &&
          (r.original || "").length > 0
      );
      const merged = mergeResultsPositionAware(filtered);
      const highlighted = generateHighlightedHTML(
        textContent,
        merged,
        parsedKeywords,
        parsedTerms
      );

      // 4) 🔴 파일별 캐시에 분리 저장
      setFileResults((prev) => ({
        ...prev,
        [f.name]: {
          text: textContent,
          verify: dataVerify,
          policy: dataPolicy,
          highlightedHTML: highlighted,
          aiSummary: aiSum,
        },
      }));

      // 5) 현재 화면에 떠 있는 파일이면 즉시 반영
      if (i === fileIndex) {
        setText(textContent);
        setResultsVerify(dataVerify);
        setResultsPolicy(dataPolicy);
        setResults(merged);
        setHighlightedHTML(highlighted);
        setAiSummary(aiSum);
      }
      } catch (e) {
       console.error(`파일 ${f.name} 검사 실패:`, e?.message || e);
  }
  }

  setIsChecking(false);
  alert("전체 검사 완료");
};

// 텍스트/결과/키워드/단어찾기 변경 시 하이라이트 즉시 반영
useEffect(() => {
  const html = generateHighlightedHTML(
    text,
    results,
    parsedKeywords,
    parsedTerms
  );
  setHighlightedHTML(html);
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [text, results, keywordInput, termInput]);

useEffect(() => {
  if (document.getElementById("glefit-client-style")) return;
   const css = `
   .error-token { ... }
   ...
      box-shadow: inset 0 -0.72em #fff1c2;
      border-bottom:2px dashed #d33;
    }
    .ai-token {
      box-shadow: inset 0 -0.72em #ffe1e1;
      border-bottom:2px dashed #b22;
    }
    .policy-block {
      box-shadow: inset 0 -0.72em #ffd2d2;
      border-bottom:2px solid #d10000;
    }
    .policy-warn {
      box-shadow: inset 0 -0.72em #fff3cd;
      border-bottom:2px solid #cc9a00;
    }
  `;
  const el = document.createElement("style");
  el.id = "glefit-client-style";
  el.type = "text/css";
  el.appendChild(document.createTextNode(css));
  document.head.appendChild(el);
}, []);
// ========= 커서 이동(정확 탐색 + 중앙 정렬) =========
function resolveSelection(full, start, end, original, before, after) {
  const orig = original || "";
  const bef = before || "";
  const aft = after || "";

  if (bef && aft) {
    const idx = full.indexOf(bef + orig + aft);
    if (idx >= 0) {
      const s = idx + bef.length;
      return { s, e: s + orig.length };
    }
  }

  if (bef) {
    const idx = full.indexOf(bef + orig);
    if (idx >= 0) {
      const s = idx + bef.length;
      return { s, e: s + orig.length };
    }
  }

  if (aft) {
    const idx = full.indexOf(orig + aft);
    if (idx >= 0) {
      return { s: idx, e: idx + orig.length };
    }
  }

  if (orig) {
    let nearest = -1;
    let pos = full.indexOf(orig, 0);
    while (pos !== -1) {
      if (nearest === -1 || Math.abs(pos - start) < Math.abs(nearest - start)) {
        nearest = pos;
      }
      pos = full.indexOf(orig, pos + 1);
    }
    if (nearest !== -1) {
      return { s: nearest, e: nearest + orig.length };
    }
  }

  return {
    s: Math.max(0, Math.min(start, full.length)),
    e: Math.max(0, Math.min(end, full.length)),
  };
}

function moveCursorAccurate(start, end, before, after, original = "") {
  const textarea = textareaRef.current;
  if (!textarea) return;

  const full = textarea.value || "";
  const { s, e } = resolveSelection(full, start, end, original, before, after);

  textarea.focus();
  textarea.setSelectionRange(s, e);

  setTimeout(() => {
    const lineHeight = 24;
    const linesAbove = full.slice(0, s).split("\n").length - 1;
    const idealTop = Math.max(
      0,
      linesAbove * lineHeight - textarea.clientHeight / 2
    );
    textarea.scrollTop = idealTop;
  }, 0);
}

// ========= 저장 =========
const saveAsTxt = () => {
  const baseName = parsedKeywords[0] || "수정된_원고";
  const BOM = "\uFEFF"; // UTF-8 BOM for Notepad compatibility
  const blob = new Blob([BOM + (text || "")], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${baseName}.txt`;
  link.click();
};

const saveAsDocx = () => {
  const baseName = parsedKeywords[0] || "수정된_원고";
  const doc = new Document({
    sections: [{ properties: {}, children: [new Paragraph(text)] }],
  });
  Packer.toBlob(doc).then((blob) => {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${baseName}.docx`;
    link.click();
  });
};

// === REPLACE: saveAsPDFSimple (no redeclare, no duplicate detailSec) ===
const saveAsPDFSimple = async () => {
  try {
    const baseName =
      (window.keywordInput || keywordInput || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)[0] || "검사_리포트";
    const docTitle = baseName;
    const checkedAt = new Date().toLocaleDateString("ko-KR");

    // 화면 상태에서 결과 분리/합산 (중복 선언 X)
    const resAll = Array.isArray(results) ? results : [];
    const resAllMerged = mergeResultsPositionAware(resAll);
    const onlyVerify = Array.isArray(resultsVerify) ? resultsVerify : [];
    const onlyPolicy = Array.isArray(resultsPolicy) ? resultsPolicy : [];

    // ⬇️ 추가 (PDF 표도 화면과 동일하게 중복 병합)
    const onlyVerifyMerged = mergeResultsPositionAware(onlyVerify);
    const onlyPolicyMerged = mergeResultsPositionAware(onlyPolicy);

    const hlHTML = String(highlightedHTML || "");

    if (!window.html2pdf) {
      alert("html2pdf 라이브러리가 필요합니다. window.html2pdf가 없습니다.");
      return;
    }

    // utils
    const esc = (s = "") =>
      String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    const sevClass = (sev) => {
      const s = String(sev || "").toLowerCase();
      if (s === "critical") return "sev-critical";
      if (s === "high") return "sev-high";
      if (s === "medium") return "sev-medium";
      return "sev-low";
    };
    const sevLabel = (sev) => {
      const s = String(sev || "").toLowerCase();
      if (s === "critical") return "Critical";
      if (s === "high") return "High";
      if (s === "medium") return "Medium";
      return "Low";
    };

    // charts (canvas 2D)
    const drawBarChart = (canvas, labels, values) => {
      const ctx = canvas.getContext("2d");
      const W = canvas.width,
        H = canvas.height;
      ctx.clearRect(0, 0, W, H);
      const padL = 40,
        padB = 28,
        padT = 10,
        padR = 10;
      const innerW = W - padL - padR,
        innerH = H - padT - padB;
      const maxV = Math.max(1, Math.max(...values));
      const barW = (innerW / Math.max(1, values.length)) * 0.6;

      ctx.strokeStyle = "#c9d2ea";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, H - padB);
      ctx.lineTo(W - padR, H - padB);
      ctx.moveTo(padL, H - padB);
      ctx.lineTo(padL, padT);
      ctx.stroke();

      for (let i = 0; i < values.length; i++) {
        const x = padL + (i + 0.2) * (innerW / Math.max(1, values.length));
        const h = (values[i] / maxV) * innerH;
        const y = H - padB - h;
        ctx.fillStyle = "#6b8cff";
        ctx.fillRect(x, y, barW, h);
        ctx.fillStyle = "#233159";
        ctx.font = "10px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(String(labels[i]), x + barW / 2, H - padB + 14);
      }
    };

    const drawPieChart = (canvas, values) => {
      const ctx = canvas.getContext("2d");
      const W = canvas.width,
        H = canvas.height;
      ctx.clearRect(0, 0, W, H);
      const cx = W / 2,
        cy = H / 2,
        r = Math.min(W, H) / 2 - 10;
      const total = Math.max(1, values.reduce((a, b) => a + b, 0));
      const cols = ["#b20000", "#a04b00", "#c0a200", "#6b8cff"]; // critical, high, medium, low

      let start = -Math.PI / 2;
      for (let i = 0; i < values.length; i++) {
        const angle = (values[i] / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.fillStyle = cols[i] || "#ced4e2";
        ctx.arc(cx, cy, r, start, start + angle);
        ctx.closePath();
        ctx.fill();
        start += angle;
      }
    };

    // styles (once)
   if (!document.getElementById("glefit-pro-style")) {
    const css = `
        /* 본문 폭 축소: 210mm -> 190mm, 좌우 패딩도 약간 늘림 */
        #glefit-report-pro {
          width:190mm;
          min-height:297mm;
          box-sizing:border-box;
          padding:16mm 20mm;
          background:#fff;
          color:#0b0f1a;
          margin:0 auto;
          display:block;
          font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",Arial;
        }
        /* 종이 여백은 html2pdf margin:0 그대로 두고, 본문 폭으로 여백을 확보 */
        @page {
          size:A4;
          margin:0;
        }
        .rp-header h1 {
          margin:0 0 4mm;
          font-size:20pt;
          font-weight:700;
        }
        .rp-meta {
          display:flex;
          gap:10mm;
          margin:0 0 6mm;
          color:#3b4358;
          font-size:10pt;
        }
        .rp-cards {
          display:grid;
          grid-template-columns:repeat(5,1fr);
          gap:6mm;
          margin:6mm 0;
        }
        .rp-card {
          background:#f4f7ff;
          border:1px solid #e2e8ff;
          border-radius:10px;
          padding:6mm;
          text-align:center;
        }
        .rp-card .label {
          font-size:10pt;
          color:#4a5a86;
        }
        .rp-card .value {
          font-size:16pt;
          font-weight:700;
          margin-top:1mm;
        }
        .sev-badge {
          display:inline-block;
          padding:2px 8px;
          border-radius:999px;
          font-size:9pt;
          font-weight:600;
        }
        .sev-critical {
          background:#ffe5e5;
          color:#b20000;
          border:1px solid #ffb3b3;
        }
        .sev-high {
          background:#fff1e0;
          color:#a04b00;
          border:1px solid #ffd4a8;
        }
        .sev-medium {
          background:#fff9d6;
          color:#6a5c00;
          border:1px solid #ffe996;
        }
        .sev-low {
          background:#eef1f6;
          color:#3b4358;
          border:1px solid #d7dbe5;
        }
        .rp-section {
          margin:10mm 0 6mm;
          break-inside:avoid;
          page-break-inside:avoid;
        }
        .rp-section h2 {
          font-size:14pt;
          margin:0 0 4mm;
          border-left:4px solid #6b8cff;
          padding-left:6px;
        }
        table.rp-table {
          width:100%;
          border-collapse:collapse;
          font-size:10pt;
        }
        table.rp-table thead th {
          background:#eaf0ff;
          color:#233159;
          padding:8px;
          text-align:left;
          border-bottom:1px solid #cfd9f8;
        }
        table.rp-table tbody td {
          padding:7px 8px;
          border-bottom:1px solid #edf0f5;
          vertical-align:top;
        }
        table.rp-table, .rp-chart, .rp-fulltext {
          break-inside:avoid;
          page-break-inside:avoid;
        }
        .rp-charts {
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:8mm;
        }
        .rp-chart {
          background:#fafbff;
          border:1px solid #ebeffa;
          border-radius:10px;
          padding:6mm;
        }
        .rp-chart h3 {
          margin:0 0 3mm;
          font-size:11pt;
          color:#233159;
        }
        .rp-fulltext {
          background:#fff;
          border:1px solid #e5e8ef;
          border-radius:10px;
          padding:6mm;
        }
        .rp-fulltext .legend {
          font-size:9pt;
          color:#4a5a86;
          margin-bottom:4mm;
        }
        .rp-fulltext .legend .swatch {
          display:inline-block;
          width:10px;
          height:10px;
          border-radius:2px;
          margin:0 4px -1px 8px;
        }
        .rp-fulltext-content {
          white-space:pre-wrap;
          word-break:break-word;
          line-height:1.8;
          isolation:isolate;
        }
        .error-token, .ai-token, .policy-block, .policy-warn, .keyword-token, .term-token{
          position:relative;
          z-index:1;
          color:#111 !important;
          -webkit-text-fill-color:#111;
          -webkit-text-stroke:0.2px rgba(0,0,0,0.6);
          text-shadow:0 0 0 #111;
          mix-blend-mode:normal !important;
          background:none !important;
          box-decoration-break:clone;
          -webkit-box-decoration-break:clone;
        }
        .error-token {
          box-shadow: inset 0 -0.72em #fff1c2;
          border-bottom:2px dashed #d33;
        }
        .ai-token {
          box-shadow: inset 0 -0.72em #ffe1e1;
          border-bottom:2px dashed #b22;
        }
        .policy-block {
          box-shadow: inset 0 -0.72em #ffd2d2;
          border-bottom:2px solid #d10000;
        }
        .policy-warn {
          box-shadow: inset 0 -0.72em #fff3cd;
          border-bottom:2px solid #cc9a00;
        }
        .keyword-token {
          box-shadow: inset 0 -0.72em #d0f0ff;
          border-bottom:2px solid #3399cc;
        }
        .term-token {
          box-shadow: inset 0 -0.72em #dfffe0;
          border-bottom:2px solid #2c9955;
        }
      `;
      const styleEl = document.createElement("style");
      styleEl.id = "glefit-pro-style";
      styleEl.type = "text/css";
      styleEl.appendChild(document.createTextNode(css));
      document.head.appendChild(styleEl);
    }
// 집계(합쳐진 결과 기준)
const sevCount = { critical: 0, high: 0, medium: 0, low: 0 };
const typeCount = {};

resAllMerged.forEach((r) => {
  const s = String(r.severity || "").toLowerCase();
  if (sevCount[s] != null) sevCount[s]++;
  const t = r.type || r.rule_id || "기타";
  typeCount[t] = (typeCount[t] || 0) + 1;
});

const typeLabels = Object.keys(typeCount).slice(0, 8);
const typeValues = typeLabels.map((k) => typeCount[k]);

// root
const root = document.createElement("div");
root.id = "glefit-report-pro";
root.innerHTML =
  `<div class="rp-header">
    <h1>글핏 리스크 보고서</h1>
    <div class="rp-meta">
      <div><b>대상</b> : ${esc(docTitle)}</div>
      <div><b>검사일</b> : ${esc(checkedAt)}</div>
      <div><b>판정</b> : ${sevCount.critical > 0 ? "위험 가능성이 높음" : sevCount.high > 0 ? "주의 요망" : "양호 범위"}</div>
    </div>
  </div>
  <div class="rp-cards">
    <div class="rp-card"><div class="label">총 항목</div><div class="value">${resAllMerged.length}</div></div>
    <div class="rp-card"><div class="label">Critical</div><div class="value">${sevCount.critical}</div></div>
    <div class="rp-card"><div class="label">High</div><div class="value">${sevCount.high}</div></div>
    <div class="rp-card"><div class="label">Medium</div><div class="value">${sevCount.medium}</div></div>
    <div class="rp-card"><div class="label">Low</div><div class="value">${sevCount.low}</div></div>
  </div>`;

// 시각화 섹션
const chartsSec = document.createElement("div");
chartsSec.className = "rp-section";
chartsSec.innerHTML = `<h2>시각화 요약</h2>`;

const chartsGrid = document.createElement("div");
chartsGrid.className = "rp-charts";

const barBox = document.createElement("div");
barBox.className = "rp-chart";
barBox.innerHTML = `<h3>유형별 검출 건수</h3>`;
const barCanvas = document.createElement("canvas");
barBox.appendChild(barCanvas);

const pieBox = document.createElement("div");
pieBox.className = "rp-chart";
pieBox.innerHTML = `<h3>위험도 분포</h3>`;
const pieCanvas = document.createElement("canvas");
pieBox.appendChild(pieCanvas);

chartsGrid.appendChild(barBox);
chartsGrid.appendChild(pieBox);
chartsSec.appendChild(chartsGrid);
root.appendChild(chartsSec);

// === 핵심 지표 미니라인 ===
const charNoSpace = String(text || "").replace(/\s/g, "").length;
const kwList = ((window.keywordInput || keywordInput || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean));
let kwHits = 0;
kwList.forEach(kw => {
  if (!kw) return;
  const re = new RegExp(kw.replace(/[-.*+?^${}()|[\]\\]/g, "\\$&"), "g");
  const m = String(text || "").match(re);
  kwHits += m ? m.length : 0;
});
const exactCnt = Array.isArray(intraExactGroups) ? intraExactGroups.length : 0;
const similarCnt = Array.isArray(intraSimilarPairs) ? intraSimilarPairs.length : 0;
const dedupCount = exactCnt + similarCnt;

const miniLine = document.createElement("div");
miniLine.style.fontSize = "10pt";
miniLine.style.color = "#555";
miniLine.style.margin = "2mm 0";
miniLine.textContent = `공백제외 글자수: ${charNoSpace} / 키워드 횟수: ${kwHits} / 중복문장 문장: ${dedupCount}개`;
root.appendChild(miniLine);

// === 세부 결과 (분리: 언어 품질 / 심의) ===
const detailSec = document.createElement("div");
detailSec.className = "rp-section";
detailSec.innerHTML = `<h2>세부 결과</h2>`;

const buildTable = (arr, title) => {
  const sec = document.createElement("div");
  sec.style.marginTop = "6mm";
  sec.innerHTML = `<h3 style="margin:0 0 3mm;">${title}</h3>`;

  const tbl = document.createElement("table");
  tbl.className = "rp-table";
  tbl.innerHTML =
    `<thead>
      <tr>
        <th style="width:60px;">구분</th>
        <th>문장 발췌</th>
        <th style="width:70px;">위험도</th>
        <th style="width:220px;">권장/사유·출처</th>
      </tr>
    </thead>
    <tbody></tbody>`;

  const tbody = tbl.querySelector("tbody");
  arr.forEach((r) => {
    const sev = String(r.severity || "").toLowerCase();
    const sevBadge = `<span class="sev-badge ${sevClass(sev)}">${sevLabel(sev)}</span>`;
    const safeCore =
      (r.suggestions && r.suggestions.length ? r.suggestions.join(" / ") : r.guidance) ||
      "조건부/우회 표현으로 수정 권장";
    const smallReason = r.reason_line
      ? `<div style="font-size:11px;color:#666;margin-top:4px;">${esc(r.reason_line)}</div>`
      : "";
    const smallLaw = r.legal_small
      ? `<div style="font-size:11px;color:#555;margin-top:2px;" class="legal-small">${r.legal_small}</div>`
      : "";
    const reasonText = r.reason
      ? `<div style="font-size:11px;color:#666;margin-top:4px;">사유: ${esc(r.reason)}</div>`
      : "";

    const row = document.createElement("tr");
    row.innerHTML =
      `<td>${esc(r.type || r.rule_id || "구분")}</td>
       <td>${esc(r.original || r.sentence || "")}</td>
       <td>${sevBadge}</td>
       <td>${esc(safeCore)}${smallReason}${smallLaw}${reasonText}</td>`;
    tbody.appendChild(row);
  });

  sec.appendChild(tbl);
  return sec;
};

detailSec.appendChild(buildTable(onlyVerifyMerged, "언어 품질(맞춤법·문맥)"));
detailSec.appendChild(buildTable(onlyPolicyMerged, "심의(광고·의료 규정)"));
root.appendChild(detailSec);

// === 중복문장·유사 문장 (있을 때만) ===
const hasDup = (intraExactGroups?.length || 0) + (intraSimilarPairs?.length || 0);
if (hasDup > 0) {
  const dupSec = document.createElement("div");
  dupSec.className = "rp-section";
  dupSec.innerHTML = `<h2>🔁 중복문장·유사 문장</h2>`;

  const wrap = document.createElement("div");
  wrap.className = "rp-fulltext";
  wrap.style.padding = "6mm";

  const escLocal = (s) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;");
  let html = "";

  if (Array.isArray(intraExactGroups) && intraExactGroups.length) {
    html += `<h3 style="margin:8px 0 4px;">정확 중복 문장</h3>`;
    html += intraExactGroups
      .map((g, i) => {
        const count = (g.occurrences || []).length;
        const sample = (g.occurrences && g.occurrences[0]?.original) || "";
        return `<div style="margin:6px 0; padding:6px 8px; border:1px solid #e5e8ef; border-radius:8px; background:#fff;">
          <b>[E${i + 1}]</b> ${escLocal(sample)} <span style="color:#6b7280">— ${count}회</span>
        </div>`;
      })
      .join("");
  }

  if (Array.isArray(intraSimilarPairs) && intraSimilarPairs.length) {
    html += `<h3 style="margin:10px 0 4px;">유사 문장</h3>`;
    html += intraSimilarPairs
      .map((p, i) => {
        const score =
          typeof p.sim === "number"
            ? p.sim
            : typeof p.score === "number"
            ? p.score
            : null;
        const a = p.a?.original || p.a?.text || p.a || "";
        const b = p.b?.original || p.b?.text || p.b || "";
        return `<div style="margin:6px 0; padding:6px 8px; border:1px solid #e5e8ef; border-radius:8px; background:#fff;">
          <div><b>[S${i + 1}] 유사도${score != null ? `: ${score.toFixed(3)}` : ""}</b></div>
          <div style="margin-top:3px;">A: ${escLocal(a)}</div>
          <div>B: ${escLocal(b)}</div>
        </div>`;
      })
      .join("");
  }

  wrap.innerHTML = html;
  dupSec.appendChild(wrap);
  root.appendChild(dupSec);
}

// === 원문 전체(하이라이트) ===
const fullSec = document.createElement("div");
fullSec.className = "rp-section";
fullSec.innerHTML = `<h2>원문 전체(문제 구간 표시)</h2>`;

const fullWrap = document.createElement("div");
fullWrap.className = "rp-fulltext";

const legend = document.createElement("div");
legend.className = "legend";
legend.innerHTML =
  `표시 기준:
   <span class="swatch" style="background:#ffe5e5"></span>Critical
   <span class="swatch" style="background:#fff1e0"></span>High
   <span class="swatch" style="background:#fff9d6"></span>Medium
   <span class="swatch" style="background:#eef1f6"></span>Low`;
fullWrap.appendChild(legend);

const fullHTML = document.createElement("div");
fullHTML.className = "rp-fulltext-content";
fullHTML.innerHTML = /<span|<mark|class=/.test(hlHTML)
  ? hlHTML
  : (hlHTML || '<div style="color:#556">(원문 미제공)</div>');

fullWrap.appendChild(fullHTML);
fullSec.appendChild(fullWrap);
root.appendChild(fullSec);
// === 주의사항 ===
const foot = document.createElement("div");
foot.className = "rp-footnotes";
foot.innerHTML = `
  <h2>주의사항</h2>
  <ol>
    <li>본 보고서는 사전에 정의된 규칙을 기반으로 한 <b>자동 검수 참고자료</b>입니다. 실제 심의 결과는 문맥·상황에 따라 달라질 수 있으므로 최종 판단은 관계 기관 및 담당자 검토가 필요합니다.</li>
    <li>확정적·단언적 표현(예: 완치, 보장, 100%)은 <b>완화된 표현</b>(예: 도움이 될 수 있음, 개인차가 있을 수 있음)으로 수정하는 것이 권장됩니다.</li>
    <li>식품/건강기능식품은 질병의 예방·치료 효능을 <b>광고할 수 없습니다</b>. 기능성 고시문구 범위 내에서만 활용해야 합니다.</li>
    <li>우월성·비교 표현(최고, 유일, 1위 등)은 <b>객관적 근거</b>(기간·표본·지표·출처)를 제시하지 않을 경우 제재 대상이 될 수 있습니다.</li>
    <li><b>보고서 전달 후에는 환불이 불가합니다.</b><br/> (검출 항목이 없더라도 이는 "리스크 최소"로 판단된 결과이므로 환불 사유가 되지 않습니다.)</li>
    <li>본 자료는 법령·가이드라인의 일부를 반영한 것이며, <b>최신 규정 확인 및 전문가 검토 병행</b>을 권장드립니다.</li>
    <li>맞춤법·문맥 등 언어 품질 검사는 <b>사유와 검출 결과가 해석에 따라 약간씩 차이</b>가 있을 수 있습니다. 자동 검출 참고자료로만 활용하시기 바랍니다.</li>
    <li>여러 사유(규칙)가 <b>동일 구간에 겹칠 경우</b> 자동화의 특성상 <b>중복 사유로 계산</b>되거나, 반대로 유사 항목이 <b>하나로 통합</b>될 수 있습니다. 최종 수정은 문맥을 고려하여 개별 사유를 검토해 주세요.</li>
  </ol>
  <div class="rp-refs">
    <h3>관련 법령 주요 조항 및 사례</h3>
    <ul>
      <li><b>의료법 제56조</b>: 의료인은 거짓·과장된 광고, 비교광고, 치료효과 보장 광고를 할 수 없음<br/><i>사례</i>: "100% 완치 보장" 문구 사용으로 병원에 과태료 및 광고 중지 명령</li>
      <li><b>식품표시광고법 제8조</b>: 질병 치료·예방·경감 등 의약적 효능을 표방하는 표시·광고 금지<br/><i>사례</i>: 일반 음료를 "혈압 치료 효과"로 광고해 과징금 부과</li>
      <li><b>건강기능식품법 제18조</b>: 허위·과장된 기능성 광고, 의약품 오인 광고 금지<br/><i>사례</i>: 건강기능식품을 "부작용 전혀 없음"으로 홍보하다 행정처분</li>
      <li><b>의료기기법 제25조·제52조</b>: 허위·과대광고 금지, 위반 시 판매정지·형사처벌 가능<br/><i>사례</i>: 의료기기를 "통증 1회 완전 제거"로 광고해 판매정지 처분</li>
      <li><b>표시·광고의 공정화법</b>: 소비자를 속이거나 부당하게 비교하는 광고 행위 금지<br/><i>사례</i>: "국내 유일 최고" 표현 사용으로 시정명령 및 과징금 부과</li>
    </ul>
    <p style="font-size:12px; color:#777;">※ 본 요약과 사례는 이해를 돕기 위한 것이며, 실제 법령 전문 및 최신 제재 사례는 관계 부처(보건복지부·식약처·공정위 등) 공고문을 반드시 확인해야 합니다.</p>
  </div>
  `;
root.appendChild(foot);
// === (NEW) 단어찾기 결과: 줄 번호 포함 표 ===
// 위치: saveAsPDFSimple() 내부, root 섹션들 append 한 뒤, html2pdf 저장 호출 직전
(function addTermFindingsSection(rootEl) {
  // 1) CRLF → LF 정규화: 빈 줄도 줄번호로 계산
  const srcText = (text || "").replace(/\r\n/g, "\n");

  // 2) 사용자 입력 단어 목록 (쉼표 구분)
  const termList = ((window.termInput ?? termInput ?? "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean));
  if (!termList.length) return;

  // 3) 메모장과 동일한 1-based 줄번호 인덱스
  const lineIdxs = buildLineIndex(srcText);

  // 4) 전체 발생 위치 수집
  const hits = [];
  termList.forEach((t) => {
    const re = new RegExp(escapeRegExp(t), "g");
    let m;
    while ((m = re.exec(srcText)) !== null) {
      const start = m.index;
      const end = start + t.length;
      const line = lineNoFromIndex(lineIdxs, start);
      const ctxStart = Math.max(0, start - 30);
      const ctxEnd = Math.min(srcText.length, end + 30);
      const before = srcText.slice(ctxStart, start);
      const middle = srcText.slice(start, end);
      const after = srcText.slice(end, ctxEnd);
      hits.push({
        term: t,
        line,
        excerptHTML: `${escapeHTML(before)}<mark>${escapeHTML(middle)}</mark>${escapeHTML(after)}`
      });
    }
  });

  // 5) 섹션 DOM
  const termSec = document.createElement("div");
  termSec.className = "rp-section";
  termSec.innerHTML =
    `<h2 style="margin:16px 0 8px;">단어찾기 결과</h2>
     <div style="font-size:13px;color:#666;margin-bottom:8px;">
       사용자 지정 단어(${termList.length}개) 발생 위치를 줄 번호 기준으로 표시합니다.
     </div>`;

  const tbl = document.createElement("table");
  tbl.className = "rp-table";
  tbl.style.width = "100%";
  tbl.style.borderCollapse = "collapse";
  tbl.innerHTML =
    `<thead>
       <tr>
         <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:6px 8px;white-space:nowrap;width:140px;">단어</th>
         <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:6px 8px;white-space:nowrap;width:80px;">줄번호</th>
         <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:6px 8px;">문맥 발췌</th>
       </tr>
     </thead>
     <tbody></tbody>`;

  const tbody = tbl.querySelector("tbody");

  if (!hits.length) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="3" style="padding:8px;color:#666;">결과 없음</td>`;
    tbody.appendChild(row);
  } else {
    hits.sort((a, b) => (a.term.localeCompare(b.term)) || (a.line - b.line));
    hits.forEach(h => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td style="border-bottom:1px solid #f1f5f9;padding:6px 8px;white-space:nowrap;">${escapeHTML(h.term)}</td>
         <td style="border-bottom:1px solid #f1f5f9;padding:6px 8px;">${h.line}</td>
         <td style="border-bottom:1px solid #f1f5f9;padding:6px 8px;">${h.excerptHTML}</td>`;
      tbody.appendChild(tr);
    });
  }

  termSec.appendChild(tbl);

  // 6) 보고서 루트에 "주의사항" 바로 위에 끼워넣기
 const footEl = rootEl.querySelector('.rp-footnotes');
 if (footEl && footEl.parentNode === rootEl) {
   rootEl.insertBefore(termSec, footEl);
 } else {
   // reference 노드가 없거나 직계가 아니면 안전하게 뒤에 붙이기
   rootEl.appendChild(termSec);
 }
})(root);
// 오프스크린 렌더 + 차트 그리기
const holder = document.createElement("div");
holder.style.position = "fixed";
holder.style.left = "-9999px";
holder.style.top = "0";
holder.appendChild(root);
document.body.appendChild(holder);

const colEls = chartsGrid.children;
const safeColWidth = (() => {
  const w0 = colEls[0].getBoundingClientRect().width || 320;
  return Math.max(260, Math.min(320, Math.floor(w0 - 24)));
})();

const safeHeight = 220;
[barCanvas, pieCanvas].forEach((cv) => {
  cv.style.width = "100%";
  cv.style.height = `${safeHeight}px`;
  cv.width = safeColWidth;
  cv.height = safeHeight;
});

drawBarChart(barCanvas, typeLabels, typeValues);
drawPieChart(pieCanvas, [sevCount.critical, sevCount.high, sevCount.medium, sevCount.low]);

const opt = {
  margin: 0,
  filename: `${baseName}_보고서.pdf`,
  image: { type: "jpeg", quality: 0.98 },
  html2canvas: { scale: 2, useCORS: true, letterRendering: true, backgroundColor: "#ffffff" },
  jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
};

await window.html2pdf().set(opt).from(root).save();
document.body.removeChild(holder);
} catch (e) {
  console.error(e);
  alert("PDF 생성 실패: " + (e?.message || "Unknown error"));
} finally {
  const ghost = document.getElementById("glefit-report-pro")?.parentElement;
  if (ghost && ghost.style && ghost.style.left === "-9999px") {
    try {
      document.body.removeChild(ghost);
    } catch {}
  }
}
};

// === 그룹 보고서 + 문서별 통합 보고서를 연속 저장 ===
const handleDedupPDFBoth = async () => {
  try {
    const hasGroup =
      (Array.isArray(interExactGroups) && interExactGroups.length > 0) ||
      (Array.isArray(interSimilarGroups) && interSimilarGroups.length > 0);

    if (hasGroup && typeof saveInterDedupReportPDF === "function") {
      await Promise.resolve(saveInterDedupReportPDF()); // ① 그룹별
      await new Promise(r => setTimeout(r, 600)); // html2pdf 연속 저장 안정화
    }
    await savePerDocDedupReportPDF(); // ② 문서별 통합
  } catch (e) {
    console.error(e);
    alert("중복문장 PDF 동시 저장 중 오류: " + (e?.message || "Unknown error"));
  }
};

// ========= (NEW) 단일 문서 내 중복문장/유사 =========
 const handleIntraDedup = async () => {
   // 🔒 게스트 잠금: 한 문서 중복탐지 제한
   if (isGuest) {
     alert("체험(게스트)에서는 한 문서 중복탐지가 잠깁니다. 로그인 후 이용해주세요.");
     return;
   }
   try {
    if (!text.trim()) return alert("텍스트가 비어 있습니다.");

    const res = await axios.post(`${API_BASE}/dedup_intra`, {
      text,
      min_len: Number(intraMinLen) || 6,
      sim_threshold: Number(intraSimTh) || 0.85,
    });
    const payload = res.data || {};

    // 현재 에디터 텍스트 기준 줄인덱스 생성
    const idxs = buildLineIndex(text || "");

    const exactWithLines = (payload.exact_groups || []).map(g => ({
      ...g,
      occurrences: (g.occurrences || []).map(o => ({
        ...o,
        line: lineNoFromIndex(idxs, Number(o.start) || 0),
      })),
    }));

    const simWithLines = (payload.similar_pairs || []).map(p => ({
      ...p,
      a: { ...(p.a || {}), line: lineNoFromIndex(idxs, Number(p?.a?.start) || 0) },
      b: { ...(p.b || {}), line: lineNoFromIndex(idxs, Number(p?.b?.start) || 0) },
    }));

    setIntraExactGroups(exactWithLines);
    setIntraSimilarPairs(simWithLines);

    if (!payload.exact_groups?.length && !payload.similar_pairs?.length) {
      alert("이 문서 내 중복문장·유사 문장이 발견되지 않았습니다.");
    }
  } catch (e) {
    console.error(e);
    alert("내부 중복 탐지 실패: " + (e?.message || "Unknown error"));
  }
};

// 파일 텍스트 모두 확보 (캐시 없으면 읽기)
const getAllFilesText = async () => {
  const out = [];
  for (const f of files) {
    const cached = fileResults[f.name]?.text;
    if (typeof cached === "string") {
      out.push({ name: f.name, text: cached });
    } else {
      const t = await extractFileText(f);
      out.push({ name: f.name, text: t });
    }
  }
  return out;
};

// === 줄번호 유틸 ===
const buildLineIndex = (text = "") => {
  const idxs = [];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") idxs.push(i);
  return idxs;
};

const lineNoFromIndex = (lineIdxs, idx) => {
  let lo = 0, hi = lineIdxs.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (lineIdxs[mid] < idx) lo = mid + 1;
    else hi = mid;
  }
  return lo + 1; // 1-based (메모장과 동일)
};

const getFileTextMapWithLines = async () => {
  // getAllFilesText()는 위에서 정의됨 (컴포넌트 상태 files/fileResults 사용)
  const arr = await getAllFilesText(); // [{name, text}]
  const map = {};
  for (const { name, text } of arr) {
    map[name] = { text, lineIdxs: buildLineIndex(text || "") };
  }
  return map;
};
// === NEW: 문서별 "통합" 중복문장 보고서 (모든 원고를 한 파일로) ===
const savePerDocDedupReportPDF = async () => {
  try {
    if (!window.html2pdf) {
      alert("html2pdf가 필요합니다.");
      return;
    }

    // 1) 파일별 매칭(정확/유사)을 문서 기준으로 재구성
    const perDoc = new Map(); // file -> [{ line, text, kind, partnerFile, partnerLine, score }...]

    const push = (file, entry) => {
      if (!file) return;
      const arr = perDoc.get(file) || [];
      arr.push(entry);
      perDoc.set(file, arr);
    };

    const normText = (x) => (x?.original ?? x?.text ?? x?.sentence ?? "");
    const truncate = (s, n = 140) => (s && s.length > n ? s.slice(0, n) + "…" : s);

    // 정확 중복 그룹 → 모든 조합을 문서별로 양방향 기록
    (interExactGroups || []).forEach(g => {
      const occ = g?.occurrences || [];
      for (let i = 0; i < occ.length; i++) {
        for (let j = i + 1; j < occ.length; j++) {
          const a = occ[i], b = occ[j];
          const ta = a?.original ?? a?.text ?? "";
          const tb = b?.original ?? b?.text ?? ta;

          push(a?.file, {
            line: a?.line,
            text: ta,
            kind: "정확",
            partnerFile: b?.file,
            partnerLine: b?.line,
            partnerText: normText(b), // ★ 추가
            score: null
          });

          push(b?.file, {
            line: b?.line,
            text: tb,
            kind: "정확",
            partnerFile: a?.file,
            partnerLine: a?.line,
            partnerText: normText(a), // ★ 추가
            score: null
          });
        }
      }
    });

    // 유사 그룹 → pair 형식/cluster 형식을 모두 안전 처리해 양방향 기록
    (interSimilarGroups || []).forEach(grp => {
      const items = grp?.pairs || grp?.items || grp?.representatives || grp?.occurrences || [];
      const asPair = items.length && (items[0]?.a || items[0]?.b);

      if (asPair) {
        items.forEach(p => {
          const a = p?.a || {}, b = p?.b || {};
          const score = p?.score ?? p?.sim ?? p?.similarity ?? null;

          push(a?.file, {
            line: a?.line,
            text: normText(a),
            kind: "유사",
            partnerFile: b?.file,
            partnerLine: b?.line,
            partnerText: normText(b), // ★ 추가
            score
          });

          push(b?.file, {
            line: b?.line,
            text: normText(b),
            kind: "유사",
            partnerFile: a?.file,
            partnerLine: a?.line,
            partnerText: normText(a), // ★ 추가
            score
          });
        });
      } else {
        for (let i = 0; i < items.length; i++) {
          for (let j = i + 1; j < items.length; j++) {
            const a = items[i] || {}, b = items[j] || {};
            const score = grp?.avg ?? grp?.score ?? grp?.similarity ?? null;

            push(a?.file, {
              line: a?.line,
              text: normText(a),
              kind: "유사",
              partnerFile: b?.file,
              partnerLine: b?.line,
              partnerText: normText(b), // ★ 추가
              score
            });

            push(b?.file, {
              line: b?.line,
              text: normText(b),
              kind: "유사",
              partnerFile: a?.file,
              partnerLine: a?.line,
              partnerText: normText(a), // ★ 추가
              score
            });
          }
        }
      }
    });

    // 2) PDF 루트 DOM + 커버
    const now = new Date();
    const ymd = now.toLocaleDateString("ko-KR"); // 날짜만 (시간 X)
    const exactCnt = (interExactGroups || []).length; // 정확 그룹 수
    const simCnt = (interSimilarGroups || []).length; // 유사 그룹 수

    const root = document.createElement("div");
    root.style.cssText = "width:190mm;min-height:297mm;box-sizing:border-box;background:#fff;font-family:'Noto Sans KR',Segoe UI,Roboto,Arial;color:#111";

    // 표지 섹션
    const totalFiles = files?.length ?? 0;
    const matchedFiles = perDoc.size; // 문서별은 perDoc.size = 중복 발견 문서 수
    const cover = buildCoverSection({
      title: "다 문서 중복문장·유사 보고서 (원고별)",
      dateStr: ymd,
      targetSummary: `중복 발견 문서: ${matchedFiles}개 / 전체: ${totalFiles}개`,
      stats: { fileCount: totalFiles, exactCount: exactCnt, similarCount: simCnt },
    });

    // 3) 문서별 섹션(파일명 오름차순)
    const fileNames = Array.from(perDoc.keys()).sort((a, b) => String(a).localeCompare(String(b), 'ko'));

    if (!fileNames.length) {
      const none = document.createElement("div");
      none.style.cssText = "color:#64748b";
      none.textContent = "중복문장·유사 결과가 없습니다.";
      root.appendChild(none);
    } else {
      fileNames.forEach((fname, idx) => {
        const sec = document.createElement("div");
        sec.style.cssText = "margin:10mm 0 0";

        const h2 = document.createElement("h2");
        h2.textContent = `${idx + 1}. ${fname}`;
        h2.style.cssText = "margin:0 0 4mm;border-bottom:1px solid #e5e7eb;padding-bottom:3mm";
        sec.appendChild(h2);

        const entries = perDoc.get(fname) || [];

        // 같은 줄을 묶음
        const byLine = new Map();
        entries.forEach(e => {
          const k = e?.line ?? "-";
          const arr = byLine.get(k) || [];
          arr.push(e);
          byLine.set(k, arr);
        });

        const lines = Array.from(byLine.keys()).sort((a, b) => (Number(a || 0) - Number(b || 0)));

        lines.forEach(ln => {
          const box = document.createElement("div");
          box.style.cssText = "border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px;margin:6px 0;background:#fff;font-size:11pt;line-height:1.7";

          const first = (byLine.get(ln) || [])[0] || {};
          const esc = (s = "") => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
          box.innerHTML = `<div style="color:#0f172a"><b>${ln}줄</b> — ${esc(first?.text || "")}</div>`;

          (byLine.get(ln) || []).forEach(m => {
            const scoreStr = (typeof m?.score === "number")
              ? `(유사도 ${m.score.toFixed(3)})`
              : (m?.score ? `(유사도 ${String(m.score)})` : "");
            const kind = m?.kind === "정확" ? "정확" : "유사";
            const meta = `${m?.partnerFile || ""}${m?.partnerLine ? ` · ${m.partnerLine}줄` : ""}`;
            const row = document.createElement("div");
            row.style.cssText = "margin-top:4px;color:#475569";
            const partnerTextHtml = m?.partnerText ? ` — <span style="color:#0f172a">${esc(truncate(m.partnerText))}</span>` : "";
            row.innerHTML = `↔ <b>${kind}</b> · ${esc(meta)}${scoreStr}${partnerTextHtml}`;
            box.appendChild(row);
          });

          sec.appendChild(box);
        });

        if (!lines.length) {
          const none2 = document.createElement("div");
          none2.style.cssText = "color:#64748b";
          none2.textContent = "이 문서에 대한 중복문장·유사 결과가 없습니다.";
          sec.appendChild(none2);
        }

        root.appendChild(sec);
      });
    }
// 4) 저장 — 대량 안정화: 섹션 단위로 순차 렌더링
const holder = document.createElement("div");
holder.style.position = "fixed";
holder.style.left = "-9999px";
document.body.appendChild(holder);

const pageOpts = {
  margin: 0,
  filename: "중복문장_원고별.pdf",
  image: { type: "jpeg", quality: 0.98 },
  html2canvas: { scale: 1.6, useCORS: true, backgroundColor: "#ffffff" },
  jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
};

// 4-1) 렌더할 페이지 DOM 조각 만들기 (0페이지 = 커버, 이후 섹션)
const pages = [];
(() => {
  // 0페이지 = 커버
  const p0 = document.createElement("div");
  p0.style.cssText = "width:190mm;min-height:297mm;box-sizing:border-box;background:#fff";
  p0.appendChild(cover.cloneNode(true)); // 커버만 단독 페이지로
  pages.push(p0);

  // 1번 인덱스부터는 root에 쌓인 문서 섹션들
  for (let i = 1; i < root.children.length; i++) {
    const page = document.createElement("div");
    page.style.cssText =
      "width:190mm;min-height:297mm;box-sizing:border-box;padding:16mm 20mm;background:#fff";
    page.appendChild(root.children[i].cloneNode(true));
    pages.push(page);
  }
})();

// 4-2) 순차 렌더링 (캔버스 한계 회피)
let worker = null;
for (let i = 0; i < pages.length; i++) {
  holder.appendChild(pages[i]);
  if (i === 0) {
    worker = window.html2pdf().set(pageOpts).from(pages[i]).toPdf();
  } else {
    worker = worker
      .get("pdf")
      .then((pdf) => {
        pdf.addPage();
      })
      .from(pages[i])
      .toContainer()
      .toCanvas()
      .toPdf();
  }
}

// 4-3) 저장 & 정리
await worker.save();
document.body.removeChild(holder);
;
} catch (e) {
  console.error(e);
  alert("문서별 통합 PDF 생성 실패: " + (e?.message || "Unknown error"));
}
};

// ========= (NEW) 여러 문서 간 중복문장/유사 =========
const handleInterDedup = async () => {
  const localCompute = async (arr, lineIdxMap) => {
    const MIN = Number(interMinLen) || 6;
    const TH  = Number(interSimTh) || 0.88;

    // 1) 문장 분할 (간단: 마침표/개행 기준) + 길이 필터
    const split = (name, txt) => {
      const s = String(txt || "");
      const parts = s.split(/(?<=[\.!?。！？])\s+|\n+/g);
      let off = 0;
      const out = [];
      for (const seg of parts) {
        const t = seg || "";
        const i = s.indexOf(seg, off);
        if (i < 0) continue;
        const j = i + seg.length;
        off = j;
        const core = t.replace(/\s+/g, "");
        if (core.length >= MIN) {
          out.push({
            file: name,
            original: t,
            text: t,
            start: i,
            end: j,
            line: lineNoFromIndex(lineIdxMap[name] || [], i),
          });
        }
      }
      return out;
    };

    // 2) 전 문서 문장 수집
    const all = [];
    for (const { name, text } of arr) all.push(...split(name, text));

    // 3) 정확 중복: 정규화 키로 그룹
    const canonMap = new Map();
    for (const s of all) {
      const key = canonKR(s.original || s.text || "");
      if (!key) continue;
      const v = canonMap.get(key) || [];
      v.push({ file: s.file, line: s.line, start: s.start, original: s.original });
      canonMap.set(key, v);
    }
    const exact_groups = Array.from(canonMap.values())
      .filter((occ) => {
        // 서로 다른 파일에서 최소 2회 이상
        const files = new Set(occ.map(o => o.file));
        return files.size >= 2;
      })
      .map((occ, idx) => ({ id: idx + 1, occurrences: occ }));

    // 4) 유사 페어: 서로 다른 파일끼리만, Jaccard n-gram(3)
    const pairs = [];
    for (let i = 0; i < all.length; i++) {
      for (let j = i + 1; j < all.length; j++) {
        const A = all[i], B = all[j];
        if (A.file === B.file) continue;
        const a = A.original || A.text || "";
        const b = B.original || B.text || "";
        // 정확중복은 유사에서 제외
        if (canonKR(a) === canonKR(b)) continue;
        const score = jaccardByNgram(a, b, 3);
        if (score >= TH) {
          pairs.push({
            a: { file: A.file, line: A.line, start: A.start, original: A.original },
            b: { file: B.file, line: B.line, start: B.start, original: B.original },
            score: Number(score.toFixed(3)),
          });
        }
      }
    }

    // 5) 상태 반영 (UI 동일 구조)
    setInterExactGroups(exact_groups);
    setInterSimilarPairs(pairs);

    // 유사 페어 클러스터링(완전동일 제외)
    const simPairsNoExact = (pairs || []).filter((p) => {
      const s = Number(p?.score ?? 0);
      const a = p?.a?.original ?? p?.a?.text ?? "";
      const b = p?.b?.original ?? p?.b?.text ?? "";
      if (s >= 0.9995) return false;
      if (canonKR(a) === canonKR(b)) return false;
      return true;
    });

    const mergeTh = Number(interSimTh) || 0.70;
    const repMergeTh = Math.max((Number(interSimTh) || 0.70) - 0.05, 0.65);
    const groups = clusterSimilarPairs(simPairsNoExact, mergeTh, repMergeTh);
    setInterSimilarGroups(groups);

    if (!exact_groups.length && !simPairsNoExact.length) {
      alert("교차 중복문장·유사 문장이 발견되지 않았습니다.");
    } else {
      alert("여러 문서 간 탐지를 완료했습니다.");
    }
  };

  try {
    if (!files.length) return alert("업로드된 파일이 없습니다.");

    // API로 보낼 원문들 확보
    const arr = await getAllFilesText();

    // 파일별 줄인덱스 캐시 준비
    const lineIdxMap = {};
    for (const { name, text } of arr) {
      lineIdxMap[name] = buildLineIndex(text || "");
    }

    // 🔓 모든 사용자 사용 가능: 게스트면 로컬 계산
    if (isGuest) {
      await localCompute(arr, lineIdxMap);
      return;
    }

    // 회원/관리자: 서버 API 우선
    const res = await axios.post(`${API_BASE}/dedup_inter`, {
      files: arr,
      min_len: Number(interMinLen) || 6,
      sim_threshold: Number(interSimTh) || 0.88,
    });
    const payload = res.data || {};

    // 서버 응답에 줄번호 주입
    const withLinesExact = (payload.exact_groups || []).map((g) => ({
      ...g,
      occurrences: (g.occurrences || []).map((o) => ({
        ...o,
        line: lineNoFromIndex(lineIdxMap[o.file] || [], Number(o.start) || 0),
      })),
    }));

    const withLinesSim = (payload.similar_pairs || []).map((p) => ({
      ...p,
      a: {
        ...p.a,
        line: lineNoFromIndex(lineIdxMap[p.a.file] || [], Number(p.a.start) || 0),
      },
      b: {
        ...p.b,
        line: lineNoFromIndex(lineIdxMap[p.b.file] || [], Number(p.b.start) || 0),
      },
    }));

    setInterExactGroups(withLinesExact);
    setInterSimilarPairs(withLinesSim);

    const simPairsNoExact = (withLinesSim || []).filter((p) => {
      const s = Number(p?.score ?? 0);
      const a = p?.a?.original ?? p?.a?.text ?? "";
      const b = p?.b?.original ?? p?.b?.text ?? "";
      if (s >= 0.9995) return false;
      if (canonKR(a) === canonKR(b)) return false;
      return true;
    });

    const mergeTh = Number(interSimTh) || 0.70;
    const repMergeTh = Math.max((Number(interSimTh) || 0.70) - 0.05, 0.65);
    const groups = clusterSimilarPairs(simPairsNoExact, mergeTh, repMergeTh);
    setInterSimilarGroups(groups);

    if (!withLinesExact.length && !simPairsNoExact.length) {
      alert("교차 중복문장·유사 문장이 발견되지 않았습니다.");
    }
  } catch (e) {
    // 서버 실패(401 등) → 로컬 계산 폴백
    console.error(e);
    try {
      const arr = await getAllFilesText();
      const lineIdxMap = {};
      for (const { name, text } of arr) lineIdxMap[name] = buildLineIndex(text || "");
      await localCompute(arr, lineIdxMap);
    } catch (ee) {
      console.error(ee);
      alert("교차 중복 탐지 실패: " + (ee?.message || "Unknown error"));
    }
  }
};

// === [교체] 유사 페어를 "그룹(클러스터)"로 묶기: Union-Find + 대표문장 2차 병합 ===
const clusterSimilarPairs = (pairs = [], mergeTh = 0.82, repMergeTh = 0.85) => {
  const parent = new Map();
  const keyOf = (x) => `${x.file}::${x.start}::${x.end}`; // 파일+문장시작오프셋으로 고유키

  const find = (k) => {
    if (!parent.has(k)) parent.set(k, k);
    const p = parent.get(k);
    if (p !== k) parent.set(k, find(p));
    return parent.get(k);
  };

  const union = (a, b) => {
    const ra = find(a), rb = find(b);
    if (ra !== rb) parent.set(rb, ra);
  };

  // 1) 1차: 페어 기반 연결
  for (const p of pairs) {
    const ka = keyOf(p.a), kb = keyOf(p.b);
    if (!parent.has(ka)) parent.set(ka, ka);
    if (!parent.has(kb)) parent.set(kb, kb);
    if (typeof p.score === "number" ? p.score >= mergeTh : true) union(ka, kb);
  }

  // 루트별 버킷
  const bucket = new Map();
  const pushOcc = (node, score) => {
    const k = keyOf(node), r = find(k);
    if (!bucket.has(r)) bucket.set(r, { occ: [], keys: new Set(), pairScores: [] });
    const g = bucket.get(r);
    if (!g.keys.has(k)) {
      g.keys.add(k);
      g.occ.push({
        file: node.file,
        line: node.line ?? node.row ?? 0,
        start: node.start,
        original: node.original ?? node.text ?? "",
      });
    }
    if (score != null) g.pairScores.push(score);
  };

  for (const p of pairs) {
    pushOcc(p.a, p.score);
    pushOcc(p.b, p.score);
  }

  // 그룹 요약(대표문장 뽑기)
  const groups = Array.from(bucket.values()).map((g) => {
    g.occ.sort((x, y) => x.file.localeCompare(y.file) || (x.line - y.line));
    const cnt = {};
    for (const o of g.occ) {
      const t = (o.original || "").trim();
      cnt[t] = (cnt[t] || 0) + 1;
    }
    const arr = Object.entries(cnt).map(([t, c]) => [t, c * Math.log2(Math.max(2, t.length))]);
    arr.sort((a, b) => b[1] - a[1]);
    const rep = (arr[0]?.[0] || g.occ[0]?.original || "").trim();
    const avg = g.pairScores.length ? g.pairScores.reduce((a, b) => a + b, 0) / g.pairScores.length : 0;
    const max = g.pairScores.length ? Math.max(...g.pairScores) : 0;
    return {
      representative: rep,
      occurrences: g.occ,
      size: g.occ.length,
      avgScore: Number(avg.toFixed(3)),
      maxScore: Number(max.toFixed(3)),
      _canon: canonKR(rep),
    };
  });

  // 2) 2차: 대표문장 유사도로 A/B 병합
  const used = new Array(groups.length).fill(false);
  const out = [];

  for (let i = 0; i < groups.length; i++) {
    if (used[i]) continue;
    let base = groups[i];

    for (let j = i + 1; j < groups.length; j++) {
      if (used[j]) continue;
      const g = groups[j];
      const sim = jaccardByNgram(base._canon, g._canon, 3);
      if (sim >= repMergeTh) {
        base.occurrences = base.occurrences.concat(g.occurrences);
        base.size += g.size;
        base.avgScore = Number(((base.avgScore + g.avgScore) / 2).toFixed(3));
        base.maxScore = Math.max(base.maxScore, g.maxScore);
        if (g.representative.length > base.representative.length) {
          base.representative = g.representative;
          base._canon = g._canon;
        }
        used[j] = true;
      }
    }

    base.occurrences.sort((x, y) => x.file.localeCompare(y.file) || (x.line - y.line));
    out.push({
      id: out.length + 1,
      representative: base.representative,
      occurrences: base.occurrences,
      size: base.size,
      avgScore: base.avgScore,
      maxScore: base.maxScore,
    });
  }

  // 큰 그룹 우선
  out.sort((a, b) => b.size - a.size || b.maxScore - a.maxScore);
  return out;
};

// === 공통 표지/주의 빌더 ===
const buildCoverSection = ({ title, dateStr, targetSummary, stats }) => {
  const sec = document.createElement("div");
  sec.style.cssText =
    "width:190mm;min-height:297mm;box-sizing:border-box;padding:16mm 20mm;background:#fff";
  sec.innerHTML =
    `<h1 style="margin:0 0 6mm;font-size:22px;">${title}</h1>
<div style="color:#334155;font-size:12.5px;margin:0 0 10mm;">
  <div>생성일: <b>${dateStr}</b></div>
  <div>대상 문서 수: <b>${stats.fileCount ?? "-"}</b>개 · 정확: <b>${stats.exactCount ?? 0}</b> · 유사: <b>${stats.similarCount ?? 0}</b></div>
  ${targetSummary ? `<div style="margin-top:3px;">${targetSummary}</div>` : ""}
</div>
<div style="background:#fff8e1;border:1px solid #f6d365;border-left-width:4px;border-radius:10px;padding:12px 14px;">
  <div style="font-weight:700;margin-bottom:6px;">중복문장 유사성·정확도 주의사항</div>
  <ul style="margin:0 0 0 18px;padding:0;line-height:1.7;font-size:12.5px;color:#444;">
    <li>줄 번호는 업로드한 <b>최신 원고의 줄바꿈</b> 기준(메모장 표기와 동일)입니다. PDF 생성 후 원고가 바뀌면 번호가 달라질 수 있습니다.</li>
    <li><b>흔히 쓰이는 인사/상투구</b>(예: “안녕하세요”, “감사합니다”) 같은 관용적 표현도 기술적으로 유사로 표기될 수 있습니다. 이 경우 <b>실제 유사로 보기 어려우며 담당자 확인이 필수</b>입니다.</li>
    <li>가이드/법정 고지 등 <b>필수 멘트</b>는 일관 사용이 필요하므로 일반적으로 <b>유사 판정의 근거로 삼지 않습니다</b>.</li>
    <li>지역명·조사·어미 같은 <b>작은 표현 차이</b>는 같은 뜻이면 한 묶음으로 보일 수 있고, 반대로 <b>핵심 의미</b>가 다르면 같은 단어가 있어도 별도 묶음으로 구분됩니다.</li>
    <li><b>아주 짧은 문장/문장구</b>는 오탐을 줄이기 위해 제외되거나 간략 처리됩니다.</li>
    <li>본 결과는 <b>자동 분석 보조자료</b>이며, 최종 판단은 <b>담당자 검토</b>가 필요합니다.</li>
  </ul>
</div>`;
  return sec;
};
// === (NEW) 여러 문서 중복문장 보고서(PDF) ===
const saveInterDedupReportPDF = async () => {
  try {
    if (!interExactGroups.length && !interSimilarGroups.length) {
      alert("먼저 '탐지'를 눌러 결과를 만든 뒤 보고서를 생성하세요.");
      return;
    }
    if (!window.html2pdf) {
      alert("html2pdf 라이브러리가 필요합니다. window.html2pdf가 없습니다.");
      return;
    }

    const fileMap = await getFileTextMapWithLines();
    const now = new Date();
    const ymd = now.toLocaleDateString("ko-KR"); // 날짜만 (시간 X)
    const exactCnt = interExactGroups?.length ?? 0;
    const simCnt = interSimilarGroups?.length ?? 0;

    // 표지 섹션
    const totalFiles = files?.length ?? 0; // ⬅ 재선언 삭제(그대로 사용)
    const matchedFiles = new Set(
      [
        ...(interExactGroups || []).flatMap((g) =>
          (g.occurrences || []).map((o) => o.file)
        ),
        ...(interSimilarGroups || []).flatMap((g) =>
          (g.occurrences || []).map((o) => o.file)
        ),
      ]
    ).size;

    const cover = buildCoverSection({
      title: "다 문서 중복문장·유사 보고서 (그룹별)",
      dateStr: ymd, // 시간 없이 yyyymmdd만
      targetSummary: `중복 발견 문서: ${matchedFiles}개 / 전체: ${totalFiles}개`,
      stats: { fileCount: totalFiles, exactCount: exactCnt, similarCount: simCnt },
    });

    // 루트 DOM (기존 개별 style 할당 → 통합 cssText로 교체)
    const root = document.createElement("div");
    root.id = "glefit-inter-report";

    // === 중앙 정렬 래퍼 추가 ===
    const wrap = document.createElement("div");
    wrap.id = "glefit-inter-wrap";
    wrap.style.cssText = [
      "width:100%",
      "margin:0",
      "padding:0",
      "display:flex",
      "justify-content:center",
      "align-items:flex-start",
      "box-sizing:border-box",
    ].join(";");

    // root를 래퍼에 넣기
    // (이 줄은 root.appendChild(cover) 보다 먼저 실행되어도 되고, 직후여도 됩니다)
    wrap.appendChild(root);

    // ⬅️ 제일 위에 표지 붙이기
    root.appendChild(cover);

    // (한 번만) 도돌이 리포트 공용 스타일 주입
    if (!document.getElementById("glefit-dedup-style")) {
      const css =
        /* 중앙 정렬용 래퍼 */
        `#glefit-inter-wrap, #glefit-perdoc-wrap {
  width:100%;
  margin:0;
  padding:0;
  display:flex;
  justify-content:center;
  align-items:flex-start;
  box-sizing:border-box;
}
/* 본문 컨테이너 폭 고정 (표지 포함 전 구간) */
#glefit-inter-report, #glefit-perdoc-report {
  width:190mm;
  max-width:190mm;
  margin:0 auto;
  padding:0 4mm; /* 좌우 살짝 여백 */
  box-sizing:border-box;
}
/* 섹션 기본 간격 */
#glefit-inter-report .section, #glefit-perdoc-report .section {
  margin: 6mm 0;
}`;
      const styleEl = document.createElement("style");
      styleEl.id = "glefit-dedup-style";
      styleEl.type = "text/css";
      styleEl.appendChild(document.createTextNode(css));
      document.head.appendChild(styleEl);
    }

    // 1) 파일 간 완전 동일
    const secExact = document.createElement("div");
    secExact.innerHTML = `<h2 style="font-size:16px;margin:16px 0 8px;">1) 파일 간 완전 동일(중복문장)</h2>`;

    if (!interExactGroups.length) {
      const none = document.createElement("div");
      none.textContent = "결과 없음";
      none.style.fontSize = "13px";
      none.style.color = "#666";
      secExact.appendChild(none);
    } else {
      interExactGroups.forEach((g, gi) => {
        const box = document.createElement("div");
        box.style.border = "1px solid #e5e7eb";
        box.style.borderRadius = "8px";
        box.style.padding = "8px 10px";
        box.style.margin = "8px 0";

        const title = document.createElement("div");
        title.style.fontWeight = "700";
        title.style.marginBottom = "6px";
        title.textContent = `그룹 ${gi + 1}`;
        box.appendChild(title);

        (g.occurrences || []).forEach((o, oi) => {
          const fm = fileMap[o.file] || { text: "", lineIdxs: [] };
          const ln = lineNoFromIndex(fm.lineIdxs, Number(o.start) || 0);

          const row = document.createElement("div");
          row.style.fontSize = "13px";
          row.style.borderTop = oi === 0 ? "none" : "1px dashed #eee";
          row.style.padding = "6px 0";
          row.textContent = `${o.file} / ${ln}번째 줄 / ${o.original}`;
          box.appendChild(row);
        });

        secExact.appendChild(box);
      });
    }

    root.appendChild(secExact);
// 2) 파일 간 유사 그룹(클러스터)
const secSim = document.createElement("div");
secSim.innerHTML   = `<h2 style="font-size:16px;margin:16px 0 8px;">2) 파일 간 유사 그룹(클러스터)</h2>`;

const simGroups = Array.isArray(interSimilarGroups) ? interSimilarGroups : [];
if (!simGroups.length) {
  const none = document.createElement("div");
  none.textContent = "결과 없음";
  none.style.fontSize = "13px";
  none.style.color = "#666";
  secSim.appendChild(none);
} else {
  simGroups.forEach((g, gi) => {
    const box = document.createElement("div");
    box.style.border = "1px solid #e5e7eb";
    box.style.borderRadius = "8px";
    box.style.padding = "8px 10px";
    box.style.margin = "8px 0";

    const head = document.createElement("div");
    head.style.fontSize = "12px";
    head.style.color = "#444";
    head.style.marginBottom = "6px";
    head.textContent = `유사 그룹 ${gi + 1} · 문장 수 ${g.size} · 평균유사도 ${g.avgScore} (최대 ${g.maxScore})`;
    box.appendChild(head);

    if (g.representative) {
      const rep = document.createElement("div");
      rep.style.fontSize = "12px";
      rep.style.fontStyle = "italic";
      rep.style.color = "#555";
      rep.style.marginBottom = "6px";
      rep.textContent = `대표: ${g.representative}`;
      box.appendChild(rep);
    }

    (g.occurrences || []).forEach((o, oi) => {
      const row = document.createElement("div");
      row.style.fontSize = "13px";
      row.style.borderTop = oi === 0 ? "none" : "1px dashed #eee";
      row.style.padding = "6px 0";
      row.textContent = `${o.file} / ${o.line}번째 줄 / ${o.original}`;
      box.appendChild(row);
    });

    secSim.appendChild(box);
  });
}
root.appendChild(secSim);

await new Promise(r => setTimeout(r, 0)); // 커밋 프레임 분리 (안전 대기)
// 오프스크린 렌더 & PDF 저장
const holder = document.createElement("div");
holder.style.position = "fixed";
holder.style.left = "-9999px";
holder.style.top = "0";
holder.appendChild(wrap);
document.body.appendChild(holder);

const opt = {
  margin: 0,
  filename: `중복문장_교차보고서_${ymd}.pdf`,
  image: { type: "jpeg", quality: 0.98 },
  html2canvas: { scale: 2, useCORS: true, letterRendering: true, backgroundColor: "#ffffff" },
  jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
};
await window.html2pdf().set(opt).from(wrap).save();
document.body.removeChild(holder);
} catch (e) {
  console.error(e);
  alert("PDF 생성 실패: " + (e?.message || "Unknown error"));
}
};

// 특정 파일·오프셋으로 이동(교차 결과 클릭 시)
const jumpToFileOffset = async (targetFileName, start, end, original = "", before = "", after = "") => {
  const idx = files.findIndex((f) => f.name === targetFileName);
  if (idx === -1) return alert("파일을 찾을 수 없습니다: " + targetFileName);

  if (idx !== fileIndex) {
    // 파일 전환 후 이동
    setFileIndex(idx);
    const t = fileResults[targetFileName]?.text ?? (await extractFileText(files[idx]));
    setText(t);

    // 캐시 없으면 기본 세팅
    if (!fileResults[targetFileName]) {
      setResults([]);
      setHighlightedHTML("");
      setAiSummary(null);
    }

    setTimeout(() => {
      moveCursorAccurate(start, end, before, after, original);
    }, 50);
  } else {
    moveCursorAccurate(start, end, before, after, original);
  }
};

// === [REPLACE or ADD] Login gate rendering (grid로 완전 분리, 겹침 방지) ===
if (!token && !guestMode) {
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        // ▶ 너비/여백 재조정: 오른쪽 치우침 방지
        gridTemplateColumns: "minmax(620px,1fr) 420px",
        gap: 24,
        background: "#fff",
        padding: "32px 24px",
        alignItems: "start",
        maxWidth: 1200,
        margin: "0 auto",
      }}
    >
      {/* 좌: 한 줄 홍보게시판 (고정 높이 + 스크롤) */}
      <div
        style={{
          background: "#fff",
          border: "1px solid #e5e7eb",
          borderRadius: 12,
          display: "flex",
          flexDirection: "column",
          maxHeight: "80vh",
          overflow: "hidden",
        }}
      >
        {/* 상단 공지 + 미니 로그인 (sticky) */}
        <div
          style={{
            borderBottom: "1px solid #f0f2f5",
            padding: "10px 12px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            position: "sticky",
            top: 0,
            background: "#fff",
            zIndex: 1,
          }}
        >
          <div style={{ display: "flex", gap: 10, alignItems: "center", minWidth: 0 }}>
            <b>📢 공지</b>
            <div style={{ color: "#6b7280", fontSize: 13, maxWidth: 480, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {notice || "동시 접속자가 많아 검사 시간이 지연될 수 있습니다"}
            </div>
          </div>

          {/* ▶ 미니 로그인바: doBoardLogin 사용 (메인 doLogin 아님) */}
          <form onSubmit={doBoardLogin} style={{ display: "flex", gap: 6, alignItems: "center" }}>
            {/* boardLoggedIn이면 '접속중' 배지 + 해제 버튼 */}
            {boardLoggedIn ? (
              <>
                <span style={{ fontSize: 12, padding: "4px 8px", borderRadius: 999, background: "#ecfdf5", color: "#065f46", border: "1px solid #a7f3d0" }}>
                  접속중
                </span>
                <button type="button" onClick={doBoardLogout} style={{ fontSize: 12, padding: "6px 10px", borderRadius: 6, border: "1px solid #e5e7eb", background: "#fff" }}>
                  해제
                </button>
              </>
            ) : (
              <>
                <input
                  value={loginU}
                  onChange={(e) => setLoginU(e.target.value)}
                  placeholder="ID"
                  style={{ width: 90, fontSize: 12, padding: "6px 8px", border: "1px solid #d1d5db", borderRadius: 6 }}
                />
                <input
                  type="password"
                  value={loginP}
                  onChange={(e) => setLoginP(e.target.value)}
                  placeholder="PW"
                  style={{ width: 90, fontSize: 12, padding: "6px 8px", border: "1px solid #d1d5db", borderRadius: 6 }}
                />
                <button type="submit" disabled={boardLogging} style={{ fontSize: 12, padding: "6px 10px", borderRadius: 6, border: "1px solid #d1d5db", background: "#f9fafb" }}>
                  {boardLogging ? "확인중..." : "로그인"}
                </button>
              </>
            )}
          </form>
        </div>

{isAdmin && (
  <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", margin: "4px 12px 8px" }}>
    <span style={{ fontSize: 12, opacity: 0.7 }}>관리자 메뉴</span>
    <button
      type="button"
      onClick={async () => {
        if (!window.confirm("정말 전체 삭제(숨김 처리) 하시겠습니까?")) return;
        try {
          const { data } = await axios.post(`${API_BASE}/board/admin/delete_all`, {}, { headers: authHeaders() });
          if (data?.ok) {
            setBoardPosts([]);
          } else {
            alert("전체 삭제 실패");
          }
        } catch {
          alert("전체 삭제 실패(권한 또는 네트워크)");
        }
      }}

      style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid #e5e7eb", background: "#fff" }}
    >
      전체 삭제
    </button>
  </div>
)}

        {/* 글 목록 */}
        <div style={{ flex: 1, overflowY: "auto", padding: 12 }}>
          {(boardPosts || []).length === 0 && (
            <div style={{ color: "#9ca3af", fontSize: 14 }}>첫 홍보 글을 남겨 보세요. (로그인 필요)</div>
          )}

          {(boardPosts || []).map((p) => (
            <div
              key={p.id}
              style={{
                display: "grid",
                gridTemplateColumns: "1fr auto",
                gap: 8,
                alignItems: "center",
                borderBottom: "1px solid #f3f4f6",
                padding: "6px 4px",
                fontSize: 14,
              }}
              title={new Date(p.ts).toLocaleString()}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "center", minWidth: 0 }}>
                {p.pinned && <span style={{ fontSize: 12, color: "#b91c1c" }}>📌</span>}
                <span style={{ color: "#374151", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  [{p.user}] {p.text}
                </span>
              </div>

              <div style={{ display: "flex", gap: 6 }}>
                {(isAdmin || (boardLoggedIn && p.user === (myId || ""))) && (
                  <>
                    <button
                      type="button"
                      onClick={() => {
                        const t = prompt("수정할 내용을 입력하세요(60자 이내)", p.text);
                        if (t == null) return;
                        editPost(p.id, t);
                      }}
                      style={{ fontSize: 12, padding: "2px 6px", border: "1px solid #e5e7eb", borderRadius: 6, background: "#fff" }}
                    >
                      수정
                    </button>
                    <button
                      type="button"
                      onClick={() => deletePost(p.id)}
                      style={{ fontSize: 12, padding: "2px 6px", border: "1px solid #e5e7eb", borderRadius: 6, background: "#fff" }}
                    >
                      삭제
                    </button>
                  </>
                )}
                {isAdmin && (
                  <button
                    type="button"
                    onClick={() => togglePin(p.id)}
                    style={{ fontSize: 12, padding: "2px 6px", border: "1px solid #e5e7eb", borderRadius: 6, background: "#fff" }}
                  >
                    {p.pinned ? "고정 해제" : "상단 고정"}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* 글쓰기: ▶ boardLoggedIn 기준 (메인 토큰 아님) */}
        <form
          onSubmit={(e) => { e.preventDefault(); addPost(); }}
          style={{
            borderTop: "1px solid #f0f2f5",
            padding: 12,
            display: "grid",
            gridTemplateColumns: "1fr auto",
            gap: 8,
          }}
        >
          <input
            value={boardInput}
            onChange={(e)=> setBoardInput(e.target.value)}
            disabled={!boardLoggedIn}
            maxLength={60}
            placeholder={boardLoggedIn ? "한 줄 메시지 (60자 제한 / 1 ID 하루 2회)" : "로그인 후 작성 가능 (읽기만 가능)"}
            style={{ padding: "10px 12px", border: "1px solid #d1d5db", borderRadius: 8 }}
          />
          <button
            type="submit"
            disabled={!boardLoggedIn}
            style={{
              padding: "10px 16px",
              borderRadius: 8,
              border: "1px solid #d1d5db",
              background: boardLoggedIn ? "#111827" : "#f3f4f6",
              color: boardLoggedIn ? "#fff" : "#9ca3af",
              cursor: boardLoggedIn ? "pointer" : "not-allowed",
            }}
          >
            등록
          </button>
          {!!boardErr && <div style={{ gridColumn: "1 / -1", color: "#b91c1c", fontSize: 12 }}>{boardErr}</div>}
        </form>
      </div>

      {/* 우: 메인 로그인 카드 (진짜 글핏 진입) */}
      <form
        onSubmit={doLogin}
        style={{
          width: "100%",
          background: "#fff",
          padding: 24,
          border: "1px solid #e5e8ef",
          borderRadius: 12,
          boxShadow: "0 6px 20px rgba(0,0,0,0.06)",
          height: "fit-content",
          position: "sticky",
          top: 24,
        }}
      >
        <h2 style={{ marginTop: 0, marginBottom: 8 }}>하루 1,100원 다 문서 중복체크 글핏</h2>
        <div style={{ color: "#6b7280", fontSize: 13, marginBottom: 12 }}>
          **본 로그인은 글핏 서비스 본편으로 진입합니다.**
        </div>

        <div style={{ marginBottom: 12 }}>
          <input
            value={loginU}
            onChange={(e) => setLoginU(e.target.value)}
            placeholder="아이디"
            style={{ width: "100%", padding: "10px", border: "1px solid #d6dbe6", borderRadius: 8 }}
          />
        </div>

        <div style={{ marginBottom: 12 }}>
          <input
            type="password"
            value={loginP}
            onChange={(e) => setLoginP(e.target.value)}
            placeholder="비밀번호"
            style={{ width: "100%", padding: "10px", border: "1px solid #d6dbe6", borderRadius: 8 }}
          />
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 8 }}>
          <label>
            <input
              type="checkbox"
              checked={rememberId}
              onChange={(e) => setRememberId(e.target.checked)}
              style={{ marginRight: 6 }}
            />
            아이디 저장
          </label>
          <label>
            <input
              type="checkbox"
              checked={autoLogin}
              onChange={(e) => setAutoLogin(e.target.checked)}
              style={{ marginRight: 6 }}
            />
            자동 로그인
          </label>
        </div>

        {loginErr && <div style={{ color: "#b91c1c", fontSize: 12, marginBottom: 8 }}>{loginErr}</div>}
        <button
          type="submit"
          style={{
            width: "100%",
            padding: "10px 12px",
            borderRadius: 8,
            border: "1px solid #111827",
            background: "#111827",
            color: "#fff",
            fontWeight: 600,
          }}
        >
          로그인
        </button>

        {/* ───── 추가: 구분선 + 데모 체험 버튼/안내 ───── */}
        <div style={{ margin: "10px 0", textAlign: "center", color: "#9ca3af", fontSize: 12 }}>또는</div>

        <button
          type="button"
          onClick={() => setGuestMode(true)}
          style={{ width: "100%", padding: "10px", borderRadius: 8, border: "1px solid #d1d5db", background: "#f9fafb" }}
          title="체험판: 업로드 3건, 단어찾기/다문서 중복만 가능, 보고서 저장 불가"
        >
          데모 체험(제한 모드)
        </button>

{/* ====== 상단 고정 안내(강조) ====== */}
<div
  style={{
    border: "1px solid #e5e7eb",
    borderRadius: 12,
    padding: 12,
    background: "#fff",
    marginBottom: 12,
  }}
>
  <p style={{ margin: 0, fontSize: 15, fontWeight: 700, color: "#111827" }}>
    💳 계정당 <span style={{ color: "#dc2626" }}>33,000원/월</span>
    <span style={{ fontWeight: 500, color: "#6b7280" }}>
      {" "} (계정 공유·대여 시 이용 제한)
    </span>
  </p>

  <p style={{ marginTop: 8, fontSize: 14, fontWeight: 600, color: "#1d4ed8" }}>
    📞 글핏 이용 문의: txt365 (카카오톡)<br />
    <span style={{ fontSize: 12, color: "#6b7280", fontWeight: 400 }}>
      ※ 문의는 내부 사정에 따라 최대 1~2일이 소요될 수 있으며,<br />
      &nbsp;&nbsp;&nbsp;공휴일·주말은 응답이 불가합니다.
    </span>
  </p>

  <p style={{ marginTop: 8, fontSize: 14, color: "#111827", fontWeight: 600 }}>
    🏦 입금: 농협 352-1639-3012-83 (늘솜제작소 / 남기태)
  </p>

  <p style={{ marginTop: 10, fontSize: 14, fontWeight: 700, color: "#0f766e" }}>
    ⚡ 빠른 ID 발급 방법
  </p>

  <div
    style={{
      marginTop: 6,
      padding: 8,
      background: "#f9fafb",
      border: "1px dashed #e5e7eb",
      borderRadius: 8,
      lineHeight: 1.6,
    }}
  >
    <div style={{ fontSize: 13, color: "#6b7280" }}>결제 후</div>
    <div style={{ fontSize: 13, color: "#6b7280" }}>
      입금자명: <span style={{ color: "#9ca3af" }}>입금자 오류 시 발급이 지연될 수 있습니다.</span>
    </div>
    <div style={{ fontSize: 13, color: "#6b7280" }}>회사명 또는 담당자명:</div>
    <div style={{ fontSize: 13, color: "#6b7280" }}>
      간략 요청 사항: 원하는 ID와 비밀번호 등 <span style={{ color: "#9ca3af" }}>중복 시 랜덤</span>
    </div>
    <div style={{ fontSize: 13, color: "#6b7280" }}>
      세금계산서: <span style={{ color: "#9ca3af" }}>사업자등록증과 메일주소 필수 전달</span>
    </div>
  </div>
</div>

{/* ====== 기존 멘트(아래 유지) ====== */}
<p style={{ marginTop: 8, fontSize: 12, color: "#6b7280" }}>
  ※ 체험판은 로그인 없이 사용 가능: 업로드 3건 / 단어찾기·다문서 중복
</p>
<p style={{ marginTop: 4, fontSize: 12, color: "#6b7280" }}>
  ※ 서비스 운영 일정 및 요금 정책은 예고 없이 변경될 수 있습니다. 
</p>
<p style={{ marginTop: 4, fontSize: 12, color: "#6b7280" }}>
  ※ ID·비밀번호는 타인과 공유하지 말고 개인 보관을 권장드립니다. 
</p>
<p style={{ marginTop: 4, fontSize: 12, color: "#6b7280" }}>
  ※ 1계정 1접속만 가능하며, 계정 공유·대여 시 이용이 제한됩니다.
</p>
<p style={{ marginTop: 4, fontSize: 12, color: "#6b7280" }}>
  ※ 환불은 불가하며, 서비스 사용 내역(횟수·파일 수)이 기록됩니다.
</p>
<p style={{ marginTop: 4, fontSize: 12, color: "#dc2626", fontWeight: 700 }}>
  ⚠ 모든 검수 결과는 참고용입니다. 최종 게시 전 담당자 확인이 필수입니다.
</p>
      </form>
    </div>
  );
}

// === 로그인 게이트: 토큰 없으면 좌(미리보기) + 우(공지) 노출 ===
if (!token && !guestMode) {
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        gridTemplateColumns: "1fr 420px",
        gap: 24,
        background: "#eef2f7",
        padding: 24,
      }}
    >
      {/* 좌: 글핏 UI 미리보기 (읽기 전용 캡처 스타일) */}
      <div
        style={{
          position: "relative",
          borderRadius: 16,
          overflow: "hidden",
          border: "1px solid #e5e7eb",
          background: "#fff",
        }}
      >
        <div
          style={{
            padding: 16,
            borderBottom: "1px solid #f0f2f5",
            fontWeight: 700,
          }}
        >
          Glefit 미리보기
        </div>
        <div style={{ padding: 16, opacity: 0.9 }}>
          {/* 실제 편집 UI의 요약 프리뷰(정적) — 텍스트/버튼은 클릭 불가 */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: 12,
            }}
          >
            <div
              style={{
                border: "1px solid #e5e7eb",
                borderRadius: 8,
                padding: 12,
              }}
            >
              <div style={{ fontWeight: 600, marginBottom: 6 }}>
                키워드·단어찾기
              </div>
              <div style={{ fontSize: 12, color: "#555" }}>
                파일명에서 키워드 자동 추출 · 등장 횟수 집계
              </div>
            </div>
            <div
              style={{
                border: "1px solid #e5e7eb",
                borderRadius: 8,
                padding: 12,
              }}
            >
              <div style={{ fontWeight: 600, marginBottom: 6 }}>
                중복문장(단일/다문서)
              </div>
              <div style={{ fontSize: 12, color: "#555" }}>
                타이트~느슨 감도 조절 · 교차 그룹 보기
              </div>
            </div>
            <div
              style={{
                border: "1px solid #e5e7eb",
                borderRadius: 8,
                padding: 12,
              }}
            >
              <div style={{ fontWeight: 600, marginBottom: 6 }}>
                심의 리스크
              </div>
              <div style={{ fontSize: 12, color: "#555" }}>
                식약처/보건복지부/공정위 가이드 기반 규칙
              </div>
            </div>
          </div>
          <div style={{ marginTop: 12, fontSize: 12, color: "#666" }}>
            ※ 데모 체험: 업로드 3건, 단어찾기/다문서 중복 검사만 사용
            가능. 보고서 저장/맞춤법·문맥/전체검사 제한.
          </div>
        </div>
      </div>

      {/* 우: 로그인/공지/규정 */}
      <div
        style={{
          borderRadius: 16,
          border: "1px solid #e5e7eb",
          background: "#fff",
          padding: 16,
        }}
      >
        <div style={{ marginBottom: 16 }}>
          <form onSubmit={doLogin}>
            {/* === 아이디/비밀번호/체크박스/에러/로그인버튼 — 기존 코드 그대로 삽입 === */}
          </form>
        </div>

        <div style={{ borderTop: "1px solid #f3f4f6", paddingTop: 12 }}>
          <div style={{ fontWeight: 700, marginBottom: 6 }}>
            공지 & 서비스 소개
          </div>
          <ul
            style={{
              margin: 0,
              paddingLeft: 16,
              fontSize: 13,
              lineHeight: 1.6,
            }}
          >
            <li>월정액 ID 단위 사용 (관리자 승인 후 이용)</li>
            <li>
              주요 기능: 글자수/키워드 횟수, 금칙어, 중복문장(단일/다문서), 심의
              리스크, TXT/DOCX/PDF 보고서
            </li>
          </ul>

          <div style={{ marginTop: 10, fontWeight: 700, marginBottom: 6 }}>
            환불 규정 요약
          </div>
          <div style={{ fontSize: 12, color: "#555" }}>
            검사 사용량(횟수/파일수) 기록을 근거로 환불 불가 원칙을 적용합니다.
            결제 전 데모 체험으로 충분히 테스트하세요.
          </div>

          <button
            type="button"
            onClick={() => setShowNoticeModal(true)}
            style={{
              marginTop: 12,
              width: "100%",
              padding: "10px 12px",
              borderRadius: 8,
              border: "1px solid #d1d5db",
              background: "#f9fafb",
            }}
          >
            서비스 규정 전문 보기
          </button>
        </div>
      </div>

      {/* [ADD] 로그인 화면 하단 고정 안내 — 그리드 안(두 칼럼 전체) */}
      <div style={{ gridColumn: "1 / -1", marginTop: 12 }}>
        <div
          style={{
            border: "1px solid #e5e7eb",
            borderRadius: 8,
            background: "#fffdf7",
            padding: "10px 12px",
            fontSize: 13,
            lineHeight: 1.6,
            color: "#444",
          }}
        >
          <b className="mr-2">⚠️ 안내</b>
          체험판은 업로드 3건 제한 · 보고서 저장 불가입니다. 유료 결제 후 환불은
          불가하며, 모든 검수 결과는 참고용으로 최종 책임은 사용자에게 있습니다.
          계정 공유/대여 시 이용이 제한될 수 있습니다.
        </div>
      </div>

      {/* 모달 */}
      {showNoticeModal && (
        <div
          onClick={() => setShowNoticeModal(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.5)",
            display: "grid",
            placeItems: "center",
            zIndex: 9999,
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: 720,
              maxWidth: "90vw",
              maxHeight: "80vh",
              overflow: "auto",
              borderRadius: 12,
              background: "#fff",
              padding: 20,
            }}
          >
            <h3 style={{ marginTop: 0 }}>서비스 이용 규정 (전문)</h3>
            <p style={{ color: "#444", fontSize: 14, lineHeight: 1.7 }}>
              {/* 규정 전문 HTML/문구 또는 별도 페이지 iframe 삽입 가능 */}
              관리자 공지에서 수정/연결 가능하도록 차후 확장 예정.
            </p>
            <div style={{ textAlign: "right" }}>
              <button
                onClick={() => setShowNoticeModal(false)}
                style={{
                  padding: "8px 12px",
                  borderRadius: 6,
                  border: "1px solid #d1d5db",
                  background: "#f9fafb",
                }}
              >
                닫기
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ========= 렌더 =========
return (
  <>
    {/* ==== 상단 로그인/계정 바 ==== */}
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "8px 10px",
        margin: "10px auto",
        maxWidth: 1400,
        background: "#0f172a",
        color: "#fff",
        borderRadius: 8,
        position: "relative",
      }}
    >
{/* 가운데 공지(항상 중앙 고정) */}
{(notice || (isAdmin && notice === "")) && (
  <div
    style={{
      position: "absolute",
      left: "50%",
      transform: "translateX(-50%)",
      top: 8,
      maxWidth: 700,
      textAlign: "center",
      padding: "4px 10px",
      borderRadius: 6,
      background: "rgba(255,255,255,0.12)",
      backdropFilter: "blur(2px)",
      fontSize: 13,
      lineHeight: 1.4,
      pointerEvents: "none", // 가운데 공지가 좌/우 클릭을 막지 않도록
    }}
    title={isAdmin ? "관리자는 공지 옆 [수정]으로 변경 가능" : undefined}
  >
    <span style={{ pointerEvents: "auto" }}>
      {notice || (isAdmin ? "공지(비어 있음)" : "")}
      {/* 관리자만 보이는 수정 링크 */}
      {isAdmin && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            const v = window.prompt("상단 공지 내용을 입력하세요:", notice || "");
            if (v != null) setNotice(v.trim());
          }}
          style={{
            marginLeft: 8,
            padding: "2px 6px",
            borderRadius: 4,
            border: "1px solid #cfe2ff",
            background: "#1f2a44",
            color: "#fff",
            cursor: "pointer",
            pointerEvents: "auto", // 버튼은 클릭 가능
          }}
        >
          수정
        </button>
      )}
    </span>
  </div>
)}
      <div style={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 8 }}>
        {me ? (
          <>
            {me.username}
            <span
              style={{
                fontSize: 12,
                padding: "2px 6px",
                borderRadius: 999,
                background: isAdmin ? "#dcfce7" : "#e5e7eb",
                color: isAdmin ? "#14532d" : "#374151",
                border: isAdmin ? "1px solid #86efac" : "1px solid #d1d5db"
              }}
            >
              {isAdmin ? "관리자" : "일반"}
            </span>
            {" · 만료 "}
{me?.paid_until?.slice(0, 10)}
{typeof me?.remaining_days === "number" && (
  <>
    <span>{` (${me.remaining_days}일 남음)`}</span>
    <div style={{ marginTop: 6, width: 160, height: 6, background: "rgba(255,255,255,0.18)", borderRadius: 6, overflow: "hidden" }}>
      <div
        style={{
          height: "100%",
          width: `${Math.max(0, Math.min(100, (me.remaining_days_ratio ?? (me.remaining_days/30))*100))}%`,
          background: "#22c55e"
        }}
        title="남은일수 비율(대략치)"
      />
    </div>
  </>
)}

          </>
        ) : (
          "계정 정보 불러오는 중…"
        )}
      </div>

      <button
        onClick={doLogout}
        style={{
          background: "#ef4444",
          color: "#fff",
          border: 0,
          borderRadius: 6,
          padding: "6px 10px",
          cursor: "pointer",
        }}
        type="button"
      >
        로그아웃
      </button>
    </div>

    {/* ==== 기존 그리드 레이아웃 ==== */}
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "420px 1fr 380px", // 좌/중/우 고정
        columnGap: 16,
        height: 720,
        maxWidth: 1400,
        margin: "0 auto",
        boxSizing: "border-box",
      }}
    >
      {/* 좌측: 원문 입력 + 업로드 */}
      <div style={{ flex: 1.25, padding: 16, background: "#fff", border: "1px solid #ddd", borderRadius: 8 }}>
        <h3>✍ 원문 입력(최대50건 내)</h3>

        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          style={{
            border: "2px dashed #aaa",
            padding: 16,
            marginBottom: 12,
            textAlign: "center",
            borderRadius: 8,
            background: "#f9f9f9",
          }}
        >
          <p style={{ margin: 0 }}>
  📂 <b>여러 폴더/파일</b>을 드래그하면 하위의 txt/docx만 자동 추출합니다.
</p>

{/* [ADD] 100KB 고정 안내문 */}
<p style={{ marginTop: 6, fontSize: 12, color: "#666" }}>
  일반/체험판은 <b>항목당 100KB</b>까지만 업로드할 수 있습니다. (초과 파일은 업로드 목록에서 제외)
</p>

<div style={{ marginTop: 8 }}>
  <label style={{ marginRight: 8 }}>파일 선택:</label>
  <input type="file" accept=".txt,.docx" multiple onChange={handleFileInputChange} />
</div>

<div style={{ marginTop: 6 }}>
  <label style={{ marginRight: 8 }}>폴더 선택:</label>
  <input type="file" webkitdirectory="true" directory="true" multiple onChange={handleFileInputChange} />
</div>

<p style={{ marginTop: 8, fontSize: 12, color: "#666" }}>
  새로 드래그/선택하면 <b>기존 업로드 목록은 초기화</b>됩니다.
</p>
        </div>

        <div
          style={{
            fontSize: 14,
            fontWeight: "bold",
            marginBottom: 8,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {files.length ? (
            <span>
              📄 <b title={files[fileIndex]?.name}>{files[fileIndex]?.name}</b> ({fileIndex + 1}/{files.length})
            </span>
          ) : (
            <span>📄 파일이 아직 업로드되지 않았습니다.</span>
          )}
        </div>

        <textarea
  ref={textareaRef}
  value={text}
  onChange={(e) => setText(e.target.value)}
  style={{
    width: "100%",
    maxWidth: "100%",        // ✅ 부모 안에서 100% 한정
    boxSizing: "border-box", // ✅ 패딩/보더 포함해서 100%
    display: "block",        // ✅ 인라인 요소 여백 이슈 방지
    height: 340,
    fontSize: 16,
    padding: 12,
    resize: "none",
    border: "1px solid #333",
    overflowY: "auto",
    borderRadius: 6,
    lineHeight: 1.6,
  }}
  placeholder="여기에 글을 입력하거나 상단 파일/폴더를 드래그하세요…"
/>

        {me && !isAdmin && (
          <div
            style={{
              marginTop: 8,
              marginBottom: -4,
              padding: "8px 10px",
              border: "1px dashed #e5e7eb",
              borderRadius: 8,
              background: "#f9fafb",
              color: "#374151",
              fontSize: 13,
            }}
          >
            잠긴(🔒) 항목은 <b>관리자 전용</b> 기능입니다. 심의·중복문장 기능은 사용 가능합니다.
          </div>
        )}

        <div style={{ marginTop: 16, display: "flex", flexWrap: "wrap", gap: 10 }}>
  {/* ✅ 맞춤법·문맥 — 관리자만 (일반/게스트 잠금) */}
  <button
  onClick={isAdmin ? handleCheck : undefined}
  disabled={!isAdmin}                                // ← 여기
  title={isAdmin ? "맞춤법·문맥 검사 실행" : "관리자 전용 기능입니다"}
  style={!isAdmin ? lockedBtnStyle : undefined}      // ← 여기
>
  {!isAdmin ? "🔒 개별 검사(관리자전용)" : "맞춤법·문맥"}
</button>

  {/* ✅ 심의 — 게스트만 잠금 (관리자/일반 가능) */}
  <button
    onClick={!isGuest ? handlePolicyCheck : undefined}
    disabled={isGuest}
    title={isGuest ? "체험(게스트)에서는 사용이 제한됩니다." : "심의(광고/의료 규정) 검사 실행"}
    style={isGuest ? lockedBtnStyle : undefined}
  >
    {isGuest ? "🔒 심의(게스트 제한)" : "심의"}
  </button>

  {/* ✅ 전체검사 — 관리자만 (일반/게스트 잠금) */}
  <button
  onClick={isAdmin ? handleBatchCheck : undefined}
  disabled={!isAdmin}                                // ← 여기
  title={isAdmin ? "업로드된 모든 파일을 순차 검사" : "관리자 전용 기능입니다"}
  style={!isAdmin ? lockedBtnStyle : undefined}      // ← 여기
>
  {!isAdmin ? "🔒 전체 검사(관리자전용)" : "전체검사"}
</button>


          {/* ✅ 저장류 — 로그인 사용자만 허용 (게스트 잠금) */}
<button
  onClick={!isGuest ? saveAsTxt : undefined}
  disabled={isGuest}
  title={isGuest ? "체험 모드에서는 저장이 제한됩니다." : "TXT 저장"}
  style={isGuest ? lockedBtnStyle : undefined}
>
  <span className="notranslate" translate="no" lang="en">TXT</span>
</button>

<button
  onClick={!isGuest ? saveAsDocx : undefined}
  disabled={isGuest}
  title={isGuest ? "체험 모드에서는 저장이 제한됩니다." : "DOCX 저장"}
  style={isGuest ? lockedBtnStyle : undefined}
>
  <span className="notranslate" translate="no" lang="en">DOCX</span>
</button>

<button
  onClick={!isGuest ? saveAsPDFSimple : undefined}
  disabled={isGuest}
  title={isGuest ? "체험 모드에서는 PDF 보고서 저장이 제한됩니다." : "PDF 리포트 저장"}
  style={isGuest ? lockedBtnStyle : undefined}
>
  PDF 보고서(통합)
</button>

          <button onClick={handlePrevFile} disabled={fileIndex <= 0}>
            이전
          </button>
          <button onClick={handleNextFile} disabled={fileIndex >= files.length - 1}>
            다음
          </button>
        </div>

        {isChecking && (
          <p style={{ color: "red", fontWeight: "bold", marginTop: 10 }}>
            ⏳ 전체 {files.length}건 중 {currentBatchIndex + 1}번째 파일 검사 중…
          </p>
        )}

        {aiSummary && (
          <div
            style={{
              marginTop: 10,
              padding: 8,
              borderRadius: 6,
              background: "#f0f7ff",
              border: "1px solid #cde2ff",
            }}
          >
            <b>AI 가능성 요약</b> — 평균: <b>{aiSummary.avgProb}</b>, 고위험 문장: <b>{aiSummary.highRiskCount}</b> / 총{" "}
            <b>{aiSummary.totalSentences}</b>
          </div>
        )}

        {/* 키워드 & 단어찾기 (같은 줄) */}
        <div style={{ marginTop: 20 }}>
          <h4>🔎 키워드 / 🧭 단어찾기</h4>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, alignItems: "stretch" }}>
            {/* 키워드 입력 */}
            <div>
              <div style={{ fontSize: 13, marginBottom: 4 }}>키워드 입력 (파일 교체 자동 세팅)</div>
              <textarea
                value={keywordInput}
                onChange={(e) => setKeywordInput(e.target.value)}
                style={{ width: "100%", height: 56, padding: 8 }}
                placeholder="파일명 그대로 사용하거나, 쉼표로 다중 입력"
              />
              <ul style={{ marginTop: 6, fontSize: 13, lineHeight: 1.5 }}>
                {keywordStats.map((k) => (
                  <li key={k.word}>
                    {k.word}: <strong>{k.count}</strong>회
                  </li>
                ))}
              </ul>
            </div>

            {/* 단어찾기 입력 */}
            <div>
              <div style={{ fontSize: 13, marginBottom: 4 }}>단어찾기 (키워드와 분리)</div>
              <textarea
                value={termInput}
                onChange={(e) => setTermInput(e.target.value)}
                style={{ width: "100%", height: 56, padding: 8 }}
                placeholder="쉼표(,)로 구분 — 예: 과장, 허위, 과대광고"
              />
              <ul style={{ marginTop: 6, fontSize: 13, lineHeight: 1.5 }}>
                {termStats.map((t) => (
                  <li key={t.word}>
                    {t.word}: <strong>{t.count}</strong>회
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div style={{ fontSize: 14, marginTop: 8 }}>
            공백 제외 글자수: <strong>{text.replace(/\s/g, "").length}</strong>자
          </div>
        </div>
      </div>

      {/* 중앙: 하이라이트 + 단어찾기(아래) */}
      <div style={{ flex: 1.1, padding: 16, background: "#fafafa", border: "1px solid #ddd", borderRadius: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
  <h3 style={{ margin: 0 }}> 📄 검사(간헐적 양식 깨짐 현상 검사 후 복원됩니다.)</h3>
  <label style={{ fontSize: 12, fontWeight: 500, display: "inline-flex", alignItems: "center", gap: 6 }}>
    <input
      type="checkbox"
      checked={wrapLongLines}
      onChange={(e) => setWrapLongLines(e.target.checked)}
    />
    긴 줄 자동 줄바꿈
  </label>
</div>

        <div
          id="highlight-view"
          style={{
            height: 520,
            border: "1px solid #eee",
            padding: 12,
            overflowY: "auto",
            background: "#fff",
            fontSize: 16,
            whiteSpace: wrapLongLines ? "pre-wrap" : "pre",
            wordBreak: wrapLongLines ? "break-word" : "normal",
            overflowWrap: wrapLongLines ? "anywhere" : "normal",
            lineHeight: 1.6,
            borderRadius: 6,
          }}
          onClick={(e) => {
            const token = e.target.closest(
              ".error-token, .ai-token, .policy-block, .policy-warn, .keyword-token, .term-token"
            );
            if (!token || !textareaRef.current) return;

            const s = parseInt(token.getAttribute("data-start"), 10) || 0;
            const ePos = parseInt(token.getAttribute("data-end"), 10) || s;
            const bef = token.getAttribute("data-bef") || "";
            const aft = token.getAttribute("data-aft") || "";
            const orig = token.getAttribute("data-orig") || token.textContent || "";

            // results.find(...) 없이 토큰의 dataset 기준으로 정확 위치 이동
            moveCursorAccurate(s, ePos, bef, aft, orig);
          }}
          dangerouslySetInnerHTML={{ __html: highlightedHTML }}
        />
      </div>

      {/* 우측 컬럼: 추천항목(위) + 중복문장 탐지(아래, 바깥 박스) */}
      <div style={{ width: 380, display: "flex", flexDirection: "column", gap: 12 }}>
{/* ───────── 박스 #1: 추천 항목 ───────── */}
<div style={{ padding: 16, background: "#f8f9fa", border: "1px solid #ddd", borderRadius: 8 }}>
  <h3>✅ 추천 항목</h3>

  <label style={{ display: "block", margin: "6px 0 10px" }}>
    <input
      type="checkbox"
      checked={filterPolicyOnly}
      onChange={(e) => setFilterPolicyOnly(e.target.checked)}
    />{" "}
    심의 결과만 보기
  </label>

  <div style={{ maxHeight: 420, overflowY: "auto", marginBottom: 12 }}>
    {results.length === 0 && <p>검사 결과가 여기에 표시됩니다.</p>}

    {mergeResultsPositionAware([...resultsVerify, ...resultsPolicy])
      .filter(
        (item) =>
          !filterPolicyOnly ||
          item.type === "심의위반" ||
          item.type === "주의표현"
      )
      .map((item, idx) => {
        const s = Number(item.startIndex) || 0;
        const e =
          Number(item.endIndex ?? (s + (item.original?.length || 0))) || s;

        // ✅ 안정적 key (동일 문장 재정렬/토글 시 React가 잘못 재사용하지 않도록)
        const stableKey = `${item.type || "t"}-${s}-${e}-${
          (item.original || "").slice(0, 20)
        }`;

        return (
          <div
            key={stableKey}
            onClick={() =>
              moveCursorAccurate(
                s,
                e,
                item.before || "",
                item.after || "",
                item.original || ""
              )
            }
            // ✅ style 오브젝트를 실제 값으로 명시
            style={{
              background: "#fff",
              border: "1px solid #e5e7eb",
              borderRadius: 8,
              padding: 12,
              marginBottom: 8,
              cursor: "pointer",
            }}
          >
            <div style={{ fontWeight: "bold" }}>
              {idx + 1}. [{item.type}] {item.original}
            </div>

            {!!(item.suggestions || []).length && (
              <ul style={{ margin: "6px 0 0 18px" }}>
                {(item.suggestions || [])
                  .slice(0, 3)
                  .map((sug, i) => <li key={i}>{sug}</li>)}
              </ul>
            )}

            {item.reason_line && (
              <div style={{ marginTop: 6, fontSize: 12, color: "#444" }}>
                {item.reason_line}
              </div>
            )}

            {item.legal_small && (
              <div
                style={{ marginTop: 2, fontSize: 11, color: "#777" }}
                dangerouslySetInnerHTML={{ __html: item.legal_small }}
              />
            )}

            {item.reason && (
              <div style={{ marginTop: 6, fontSize: 12, color: "#666" }}>
                사유: {item.reason} (심각도: {item.severity || "low"})
              </div>
            )}
          </div>
        );
      })}
  </div>
</div>

{/* ───────── 박스 #2: 중복문장/유사 탐지 (추천항목 ‘밖에’ 있는 별도 박스) ───────── */}
<div style={{ padding: 16, background: "#eef6ff", border: "1px solid #cfe2ff", borderRadius: 8 }}>
  <h3 style={{ marginTop: 0 }}>🔁 중복문장·유사 탐지</h3>

  {/* 한 문서 내 */}
  <div style={{ marginTop: 10 }}>
    <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
      <span style={{ fontWeight: "bold" }}>한 문서 내</span>

      <label title={`최소 글자 수 가이드
권장 범위: 4~12자 / 실무 평균값: 6~8자

4~5자: 짧은 관용구·조사 중심 문장이 많이 끼어들어 오탐↑
6~8자: 짧은 감탄/접속 문장 걸러지고 균형적
10~12자: 짧은 문장·항목이 많이 제외되어 정밀(재현율↓)`}>
        최소 글자 수 <span style={{ color: "#6b7280", marginLeft: 4 }}>(기준치)</span>
        <input
          type="number"
          min={1}
          value={intraMinLen}
          onChange={(e) => setIntraMinLen(Number(e.target.value))}
          disabled={isGuest}
          style={{ width: 60, marginLeft: 4, ...(isGuest ? lockedBtnStyle : {}) }}
          title={isGuest ? "체험(게스트)에서는 설정 변경이 잠깁니다." : ""}
        />
      </label>

      <label title={`유사도 기준 가이드
권장 범위 : 0.65 ~ 0.80

실무 평균값:
- 단일 문서 내: 0.70 전후
- 여러 문서 간: 0.75 전후(조금 더 엄격)

0.65~0.69: 느슨(재현↑/정밀↓)
0.70~0.74: 보통
0.75~0.80: 타이트(정밀↑/재현↓)`}>
        유사도 기준 <span style={{ color: "#6b7280", marginLeft: 4 }}>(기준값)</span>
        <input
          type="number"
          step="0.01"
          value={intraSimTh}
          onChange={(e) => setIntraSimTh(Number(e.target.value))}
          disabled={isGuest}
          style={{ width: 70, marginLeft: 4, ...(isGuest ? lockedBtnStyle : {}) }}
          title={isGuest ? "체험(게스트)에서는 설정 변경이 잠깁니다." : ""}
        />
      </label>

      {/* ✅ 게스트만 잠금, 일반/관리자 실행 가능 */}
      <button
        onClick={!isGuest ? handleIntraDedup : undefined}
        disabled={isGuest || !text?.trim()}
        style={isGuest ? lockedBtnStyle : undefined}
        title={isGuest ? "체험(게스트)에서는 한 문서 중복탐지가 잠깁니다." : "탐지"}
      >
        {isGuest ? "🔒 탐지(게스트 제한)" : "탐지"}
      </button>
    </div>

    {/* 결과 영역 이하 그대로 */}
    <div
      style={{
        maxHeight: 150,
        overflowY: "auto",
        marginTop: 6,
        background: "#fff",
        border: "1px solid #ddd",
        borderRadius: 6,
        padding: 8,
      }}
    >
      {!intraExactGroups.length && !intraSimilarPairs.length && (
        <div style={{ color: "#666" }}>결과 없음</div>
      )}

      {!!intraExactGroups.length && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ fontWeight: "bold" }}>• 중복문장(완전 동일)</div>
          {intraExactGroups.map((g, i) => (
            <div key={i} style={{ margin: "6px 0" }}>
              {g.occurrences.map((o, j) => (
                <div
                  key={j}
                  style={{ cursor: "pointer", padding: "4px 6px", borderBottom: "1px dashed #eee" }}
                  title="클릭 시 위치로 이동"
                  onClick={() =>
                    moveCursorAccurate(
                      Number(o.start) || 0,
                      Number(o.end) || 0,
                      "",
                      "",
                      o.original || ""
                    )
                  }
                >
                  [{o.index + 1}] {o.original}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {!!intraSimilarPairs.length && (
        <div>
          <div style={{ fontWeight: "bold" }}>• 유사 문장</div>
          {intraSimilarPairs.map((p, i) => (
            <div key={i} style={{ margin: "6px 0", borderBottom: "1px dashed #eee" }}>
              <div style={{ fontSize: 12, color: "#444" }}>유사도: {p.score}</div>
              <div style={{ display: "flex", gap: 6 }}>
                <div
                  style={{ flex: 1, cursor: "pointer", background: "#fdfdfd", padding: 4, borderRadius: 4 }}
                  title="A 위치로 이동"
                  onClick={() =>
                    moveCursorAccurate(
                      Number(p.a.start) || 0,
                      Number(p.a.end) || 0,
                      "",
                      "",
                      p.a.original || ""
                    )
                  }
                >
                  A[{p.i + 1}] {p.a.original}
                </div>

                <div
                  style={{ flex: 1, cursor: "pointer", background: "#fdfdfd", padding: 4, borderRadius: 4 }}
                  title="B 위치로 이동"
                  onClick={() =>
                    moveCursorAccurate(
                      Number(p.b.start) || 0,
                      Number(p.b.end) || 0,
                      "",
                      "",
                      p.b.original || ""
                    )
                  }
                >
                  B[{p.j + 1}] {p.b.original}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  </div>
</div>

{/* ───────── 박스 #3: 여러 문서 간 중복문장/유사 탐지 ───────── */}
<div style={{ marginTop: 16, padding: 16, background: "#eef6ff", border: "1px solid #cfe2ff", borderRadius: 8 }}>
  <h3 style={{ marginTop: 0 }}>🔁 여러 문서 간 중복문장·유사 탐지</h3>

  {/* 옵션 */}
  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap", marginTop: 6 }}>
    <label
      title={`최소 글자 수 가이드
권장 범위: 4~12자 / 실무 평균값: 6~8자

4~5자: 짧은 관용구·조사 중심 문장이 많이 끼어들어 오탐↑
6~8자: 짧은 감탄/접속 문장 걸러지고 균형적
10~12자: 짧은 문장·항목이 많이 제외되어 정밀(재현율↓)`}
    >
      최소 글자 수 <span style={{ color: "#6b7280", marginLeft: 4 }}>(기준치)</span>
      <input
        type="number"
        min={1}
        value={interMinLen}
        onChange={(e) => setInterMinLen(Number(e.target.value))}
        style={{ width: 60, marginLeft: 4 }}
      />
    </label>

    <label
      title={`유사도 기준 가이드
권장 범위 : 0.65 ~ 0.80

실무 평균값:
- 단일 문서 내: 0.70 전후
- 여러 문서 간: 0.75 전후(조금 더 엄격하게 잡는 편)

0.65~0.69: 느슨(재현↑/정밀↓)
0.70~0.74: 보통
0.75~0.80: 타이트(정밀↑/재현↓)`}
    >
      유사도 기준 <span style={{ color: "#6b7280", marginLeft: 4 }}>(기준값)</span>
      <input
        type="number"
        step="0.01"
        value={interSimTh}
        onChange={(e) => setInterSimTh(Number(e.target.value))}
        style={{ width: 70, marginLeft: 4 }}
      />
    </label>

    <button onClick={handleInterDedup} disabled={!files.length}>탐지</button>
  </div>

  {/* 저장 버튼들 */}
  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 6 }}>
    <button
      onClick={saveInterDedupReportPDF}
      disabled={isChecking || !(interExactGroups?.length || interSimilarGroups?.length)}
      title="여러 문서 간 그룹(정확/유사) 보고서"
    >
      그룹 보고서(PDF)
    </button>

    <button
      onClick={savePerDocDedupReportPDF}
      disabled={isChecking || !(interExactGroups?.length || interSimilarGroups?.length)}
      title="업로드한 모든 원고를 문서별 섹션으로 한 파일에"
    >
      문서별 통합(PDF)
    </button>

    <button
      onClick={handleDedupPDFBoth}
      disabled={isChecking || !(interExactGroups?.length || interSimilarGroups?.length)}
      title="그룹 보고서 + 문서별 통합 보고서를 순서대로 저장"
    >
      둘 다 저장
    </button>
  </div>

  {/* 결과 영역 */}
  <div
    style={{
      maxHeight: 200,
      overflowY: "auto",
      marginTop: 6,
      background: "#fff",
      border: "1px solid #ddd",
      borderRadius: 6,
      padding: 8,
    }}
  >
    {!interExactGroups.length && !interSimilarGroups.length && (
      <div style={{ color: "#666" }}>결과 없음</div>
    )}

    {/* ==== 파일 간 유사 그룹(클러스터) ==== */}
    {!interSimilarGroups.length ? (
      <div style={{ fontSize: 13, color: "#666" }}>결과 없음</div>
    ) : (
      interSimilarGroups.map((g, gi) => (
        <div
          key={gi}
          style={{
            border: "1px solid #e5e7eb",
            borderRadius: 8,
            padding: "8px 10px",
            margin: "8px 0",
          }}
        >
          <div style={{ fontSize: 12, color: "#444", marginBottom: 6 }}>
            유사 그룹 {gi + 1} · 문장 수 {g.size} · 평균유사도 {g.avgScore} (최대 {g.maxScore})
          </div>

          {g.representative && (
            <div style={{ fontSize: 12, fontStyle: "italic", color: "#555", marginBottom: 6 }}>
              대표: {g.representative}
            </div>
          )}

          {(g.items || g.pairs || []).map((p, pi) => {
            const a = p?.a || {}, b = p?.b || {};
            return (
              <div key={pi} style={{ fontSize: 12, margin: "4px 0" }}>
                <div>• {a.file} #{a.line} — {a.text}</div>
                <div>  ↔ {b.file} #{b.line} — {b.text} (유사도 {p?.score ?? p?.sim ?? p?.similarity})</div>
              </div>
            );
          })}
        </div>
      ))
    )}
  </div>
</div>
</div>
</div>

{/* 강조 스타일 */}
<style>{`
  /* 컨테이너를 독립 합성 컨텍스트로 */
  #highlight-view { isolation: isolate; }

  /* 공통 보호: 글자색/윤곽선 고정 + 블렌딩 차단 + 줄바꿈 유지 */
  .error-token,
  .ai-token,
  .policy-block,
  .policy-warn,
  .keyword-token,
  .term-token {
    position: relative;
    z-index: 1;
    color: #111 !important;
    -webkit-text-fill-color: #111;
    -webkit-text-stroke: 0.2px rgba(0,0,0,0.6); /* 윤곽선 보강 */
    text-shadow: 0 0 0 #111;
    mix-blend-mode: normal !important;
    background: none !important; /* 배경색 직접 칠하지 않음 */
    box-decoration-break: clone; /* 여러 줄에서도 동일 적용 */
    -webkit-box-decoration-break: clone;
  }

  /* 형광펜 방식(배경 대체): inset box-shadow 로 아래쪽을 채움 */
  .error-token { box-shadow: inset 0 -0.72em #fff1c2; border-bottom: 2px dashed #d33; }
  .ai-token { box-shadow: inset 0 -0.72em #ffe1e1; border-bottom: 2px dashed #b22; }
  .policy-block { box-shadow: inset 0 -0.72em #ffd2d2; border-bottom: 2px solid #d10000; }
  .policy-warn { box-shadow: inset 0 -0.72em #fff3cd; border-bottom: 2px solid #cc9a00; }
  .keyword-token { box-shadow: inset 0 -0.72em #d0f0ff; border-bottom: 2px solid #3399cc; }
  .term-token { box-shadow: inset 0 -0.72em #dfffe0; border-bottom: 2px solid #2c9955; }
  `}</style>
 </>
);
}
