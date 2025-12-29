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

// 🔍 실제 사용 중인 API_BASE 확인용 디버그 로그
console.log("🔥 API_BASE =", API_BASE);

// 3) axios baseURL 적용⚠️ axios import는 파일 상단 import 구역에 있어야 함)
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

// === 공백 무시 정규식 (전역 유틸) ===
// 예: "정확 판단" ↔ "정확한   판단을" 매칭
const buildLooseRegex = (phrase = "") => {
  const escaped  = String(phrase).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const loosened = escaped.replace(/\s+/g, "\\s*");
  return new RegExp(loosened, "gu"); // u 플래그 유지
};

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
export default function Editor(props) {
  // readOnlyPreview 모드 여부 (배경 프리뷰일 때는 방문수 안 찍음)
  const { readOnlyPreview } = props || {};

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

  // === [ADD] 방문 로그 기록: 게스트/일반/관리자 공통 ===
  useEffect(() => {
    // SSR 방지 + 배경 프리뷰 모드는 제외
    if (typeof window === "undefined") return;
    if (readOnlyPreview) return;

    try {
      const path =
        (window.location && window.location.pathname) || "/";
      const qs =
        (window.location && window.location.search) || "";
      // Editor.js 상단에서 axios.defaults.baseURL = API_BASE; 가 이미 설정되어 있으므로
      // 여기서는 절대경로가 아니라 상대경로만 보내면 됨.
      axios
        .post("/track/visit", { path: path + qs })
        .catch(() => {
          // 방문 로그 실패는 조용히 무시 (사용자에게 영향 X)
        });
    } catch {
      // 어떤 예외도 사용자에게는 영향 없도록 무시
    }
  }, [readOnlyPreview]);

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

  // === 필수가이드 입력 및 결과 ===
  const [requiredText, setRequiredText] = useState("");   // 사용자가 적는 '필수가이드' 다중 줄 입력
  const [requiredResults, setRequiredResults] = useState([]); // 항목별 검사 결과 (있음/없음)


  // 🔴 파일별 캐시 구조 확장
  // fileResults[fileName] = {
  //   text,
  //   verify: [],
  //   policy: [],
  //   highlightedHTML,
  //   aiSummary,
  //   required,          // 필수가이드 결과
  //   intraExactGroups,  // 한 문서 중복 검사(완전 일치)
  //   intraSimilarPairs, // 한 문서 중복 검사(유사 문장)
  //   aiLocal,           // 로컬 AI 탐지(v1) 결과 (예비필터)
  // }
  const [fileResults, setFileResults] = useState({});
  const [isChecking, setIsChecking] = useState(false);
  const [currentBatchIndex, setCurrentBatchIndex] = useState(0);

  // 로컬 AI 탐지(v1) 상태
  const [aiLocalLoading, setAiLocalLoading] = useState(false);
  const [aiLocalResult, setAiLocalResult] = useState(null);
  const [aiLocalError, setAiLocalError] = useState("");

  // 문서 스타일/서술형 프로파일 (정보성/후기 등)
  const [styleProfile, setStyleProfile] = useState(null);
  const [styleLoading, setStyleLoading] = useState(false);
  const [styleError, setStyleError] = useState("");

  // 키워드(파일명 자동 채움, **세션 내 파일별 유지**)
  const [keywordInput, setKeywordInput] = useState("");
  const [keywordByFile, setKeywordByFile] = useState({});

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
// 🔹 문서별 중복 비율 요약 (화면엔 상위 10건만 표시, 전체는 보고서에서)
const [interDocSummary, setInterDocSummary] = useState([]);

// 교차 탐지 옵션
const [interMinLen, setInterMinLen] = useState(5);
const [interSimTh, setInterSimTh] = useState(0.50);
const [intraMinLen, setIntraMinLen] = useState(5);
const [intraSimTh, setIntraSimTh] = useState(0.50);

// 여러 문서 간 중복 탐지 진행 상태
const [isInterChecking, setIsInterChecking] = useState(false);

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
  // 키워드는 새로고침/재접속 때 항상 비우기 위해 localStorage에 저장하지 않음
  useEffect(() => {
    localStorage.setItem("glfit_terms", termInput || "");
  }, [termInput]);

  // (선택) 예전 버전에서 남아 있을 수 있는 glfit_keywords 키는 한 번 지워줌
  useEffect(() => {
    try {
      localStorage.removeItem("glfit_keywords");
    } catch {}
  }, []);

// ========= 파생 데이터(통계) =========
const parsedKeywords = (keywordInput || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const parsedTerms = (termInput || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// generateHighlightedHTML 내부에 이미 존재하는 buildLooseRegex(공백 무시)를 재사용하세요.
const keywordStats = useMemo(() =>
  parsedKeywords.map((kw) => {
    const re = buildLooseRegex(kw);
    let c = 0, m;
    while ((m = re.exec(text)) !== null) { c++; if (re.lastIndex === m.index) re.lastIndex++; }
    return { word: kw, count: c };
  }), [parsedKeywords, text]);

const termStats = useMemo(() =>
  parsedTerms.map((t) => {
    const re = buildLooseRegex(t);
    let c = 0, m;
    while ((m = re.exec(text)) !== null) { c++; if (re.lastIndex === m.index) re.lastIndex++; }
    return { word: t, count: c };
  }), [parsedTerms, text]);


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
  setText(normalizeForIndexing(textContent)); // ⬅️ 통일
  // 🔹 키워드는 여기서 직접 건드리지 않음
  //    (파일 전환 함수에서 keywordByFile 기반으로 세팅)

  const cached = fileResults[file.name];
  if (cached) {
      setResultsVerify(Array.isArray(cached.verify) ? cached.verify : []);
      setResultsPolicy(Array.isArray(cached.policy) ? cached.policy : []);
      const merged = [
        ...(Array.isArray(cached.verify) ? cached.verify : []),
        ...(Array.isArray(cached.policy) ? cached.policy : []),
        ...(Array.isArray(cached.required) ? cached.required : [])   // ⭐ 필수가이드 복원
      ];
      setResults(merged);

      // ⭐ 필수가이드 전용 결과 복원
      setRequiredResults(Array.isArray(cached.required) ? cached.required : []);

      // ⭐ 한 문서 중복 검사 결과 복원
      setIntraExactGroups(cached.intraExactGroups || []);
      setIntraSimilarPairs(cached.intraSimilarPairs || []);

      // ⭐ 다문서 중복 검사 결과 복원
      setInterExactGroups(cached.interExactGroups || []);
      setInterSimilarPairs(cached.interSimilarPairs || []);
      setInterSimilarGroups(cached.interSimilarGroups || []);

      setHighlightedHTML(cached.highlightedHTML || "");
      setAiSummary(cached.aiSummary || null);
  } else {
    setResultsVerify([]);
    setResultsPolicy([]);
    setResults([]);
    setHighlightedHTML("");
    setAiSummary(null);
  }

  // 📌 파일이 바뀔 때: 파일별로 저장된 로컬 AI 탐지 결과를 복원 (없으면 초기화)
  if (cached && cached.aiLocal) {
    setAiLocalResult(cached.aiLocal);
    setAiLocalError("");
  } else {
    setAiLocalResult(null);
    setAiLocalError("");
  }

  // 📌 파일이 바뀔 때: 문서 스타일/서술형 프로파일 복원
  if (cached && cached.styleProfile) {
    setStyleProfile(cached.styleProfile);
    setStyleError("");
  } else {
    setStyleProfile(null);
    setStyleError("");
  }

// ❌ 기존: 파일 이동시 중복결과/필수가이드 모두 초기화됨 → 문제 발생
// ⬇⬇ 완전 교체

// 캐시에 저장된 결과가 있을 경우 복원하고
// 없으면 그 파일은 검사한 적 없는 파일이므로 빈 값 유지.
if (cached) {
    setRequiredResults(cached.required || []);
    setIntraExactGroups(cached.intraExactGroups || []);
    setIntraSimilarPairs(cached.intraSimilarPairs || []);

    // 교차(다문서) 중복은 전역 패널에서만 쓰므로 복원하지 않음
    // (원하는 경우 복원 코드 여기에 추가 가능)
} else {
    setRequiredResults([]);
    setIntraExactGroups([]);
    setIntraSimilarPairs([]);
}
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

  // 🔹 다문서 유사도 요약/진행 상태도 함께 초기화
  setInterDocSummary([]);
  setIsInterChecking(false);

  // 🔹 파일별 키워드 기본값 초기화 (파일명 기반)
  const initialKeywordMap = {};
  onlySupported.forEach((f) => {
    initialKeywordMap[f.name] = getKeywordsFromFilename(f);
  });
  setKeywordByFile(initialKeywordMap);

  // 6) 첫 파일 로드 or 화면 정리
  if (onlySupported.length) {
    const first = onlySupported[0];
    await loadFileContent(first, 0);
    setKeywordInput(initialKeywordMap[first.name] || "");
  } else {
    setText("");
    setResultsVerify([]);
    setResultsPolicy([]);
    setResults([]);
    setHighlightedHTML("");
    setAiSummary(null);
    setKeywordInput("");
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
    const f = files[next];
    setFileIndex(next);
    await loadFileContent(f, next);

    if (f) {
      const name = f.name;
      // 이미 저장된 값이 있으면 그 값, 없으면 파일명에서 추출
      const existing =
        (keywordByFile && keywordByFile[name]) || getKeywordsFromFilename(f);

      // map에 없던 경우 기본값 채워넣기
      if (!keywordByFile || keywordByFile[name] === undefined) {
        setKeywordByFile((prev) => ({
          ...(prev || {}),
          [name]: existing,
        }));
      }

      setKeywordInput(existing);
    } else {
      setKeywordInput("");
    }
  } else {
    alert("더 이상 파일이 없습니다.");
  }
};

const handlePrevFile = async () => {
  const prev = fileIndex - 1;
  if (prev >= 0) {
    const f = files[prev];
    setFileIndex(prev);
    await loadFileContent(f, prev);

    if (f) {
      const name = f.name;
      const existing =
        (keywordByFile && keywordByFile[name]) || getKeywordsFromFilename(f);

      if (!keywordByFile || keywordByFile[name] === undefined) {
        setKeywordByFile((prev) => ({
          ...(prev || {}),
          [name]: existing,
        }));
      }

      setKeywordInput(existing);
    } else {
      setKeywordInput("");
    }
  } else {
    alert("이전 파일이 없습니다.");
  }
};

// === 인덱스 계산 통일용: CRLF/NBSP/Tab 정규화 ===
function normalizeForIndexing(str) {
  return String(str || "")
    .replace(/\r\n/g, "\n")   // CRLF → LF
    .replace(/\u00A0/g, " ")  // NBSP → space
    .replace(/\t/g, " ");     // tab → space
}

// (REPLACE) generateHighlightedHTML — 원문 유지 + dataset 첨부 + 유연
const generateHighlightedHTML = (raw, matches, keywords, terms) => {
  // 0) 인덱스 기준 통일
  const text = normalizeForIndexing(raw || "");
  const N = text.length;

  const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));
  const norm = (s = "") => String(s).replace(/\s+/g, " ").trim();

  const esc = (str = "") =>
    String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  const escAttr = (s = "") => esc(String(s)).replace(/"/g, "&quot;");

  // 줄바꿈 보존 (pre-wrap + <br/> 둘 다 사용해도 안전)
  const renderSeg = (s = "") => esc(String(s)).replace(/\r\n/g, "\n").replace(/\n/g, "<br/>");

  // ===== 1) 서버 검사 결과 span =====
  const spans = [];

  (matches || []).forEach((r) => {
    const s0 = Number(r?.startIndex);
    const e0 = Number(r?.endIndex);

    if (!Number.isFinite(s0) || !Number.isFinite(e0)) return;
    if (e0 <= s0) return;

    const start = clamp(s0, 0, N);
    const end = clamp(e0, 0, N);
    if (end <= start) return;

    const reasons = Array.isArray(r?.reasons) ? r.reasons : [];
    const legalList = Array.isArray(r?.legal_small_list)
      ? r.legal_small_list
      : r?.legal_small
      ? [r.legal_small]
      : [];
    const suggestions = Array.isArray(r?.suggestions)
      ? r.suggestions.slice(0, 3)
      : [];

    const titleParts = [];
    if (reasons.length) titleParts.push(reasons.join(" / "));
    if (legalList.length) titleParts.push("관련 규정: " + legalList.join(", "));
    if (suggestions.length)
      titleParts.push("추천: " + suggestions.map(norm).join(" / "));
    const tip = titleParts.join("\n");

    const type = (r?.type || "").toLowerCase();
    let cls = "";
    if (type === "ai") cls = "ai-token";
    else if (type === "policy-block") cls = "policy-block";
    else if (type === "policy-warn") cls = "policy-warn";
    else cls = "error-token";

    spans.push({
      kind: "result",
      priority: 1,          // 결과 span 최우선
      start,
      end,
      cls,
      attrs: {
        "data-type": type || "error",
        "data-severity": (r?.severity || "").toLowerCase() || "low",
        "data-start": start,
        "data-end": end,
        "data-bef": r?.before ?? "",
        "data-orig": r?.original ?? "",
        "data-aft": r?.after ?? "",
        "data-core":
          Array.isArray(r?.core_terms || r?.coreTerms)
            ? (r.core_terms || r.coreTerms).join("|")
            : "",
        title: tip,
      },
    });
  });

  const overlaps = (a, b) => !(a.end <= b.start || b.end <= a.start);
  const hasOverlap = (list, s, e) =>
    list.some((sp) => !(sp.end <= s || e <= sp.start));

  // ===== 2) 키워드 / 단어찾기 span (글자색 + 굵기만 강조) =====
  // - 서버 검사 결과(span)가 있는 구간은 덮어쓰지 않음
  // - 클릭하면 data-start / data-end 로 커서 이동 가능

  // 2-1) 키워드
  if (Array.isArray(keywords)) {
    keywords.forEach((raw) => {
      const kw = (raw || "").trim();
      if (!kw) return;

      let re;
      try {
        re = buildLooseRegex(kw);
      } catch {
        return;
      }

      let m;
      while ((m = re.exec(text)) !== null) {
        const s0 = m.index;
        const e0 = re.lastIndex;
        if (!Number.isFinite(s0) || !Number.isFinite(e0) || e0 <= s0) continue;

        const start = clamp(s0, 0, N);
        const end = clamp(e0, 0, N);
        if (end <= start) continue;
        if (hasOverlap(spans, start, end)) continue; // 기존 결과(span) 우선

        spans.push({
          kind: "keyword",
          priority: 5,
          start,
          end,
          cls: "keyword-token",
          attrs: {
            "data-type": "keyword",
            "data-start": start,
            "data-end": end,
            "data-orig": text.slice(start, end),
          },
        });
      }
    });
  }

  // 2-2) 단어찾기(핵심용어)
  if (Array.isArray(terms)) {
    terms.forEach((raw) => {
      const t = (raw || "").trim();
      if (!t) return;

      let re;
      try {
        re = buildLooseRegex(t);
      } catch {
        return;
      }

      let m;
      while ((m = re.exec(text)) !== null) {
        const s0 = m.index;
        const e0 = re.lastIndex;
        if (!Number.isFinite(s0) || !Number.isFinite(e0) || e0 <= s0) continue;

        const start = clamp(s0, 0, N);
        const end = clamp(e0, 0, N);
        if (end <= start) continue;
        if (hasOverlap(spans, start, end)) continue;

        spans.push({
          kind: "term",
          priority: 4,
          start,
          end,
          cls: "term-token",
          attrs: {
            "data-type": "term",
            "data-start": start,
            "data-end": end,
            "data-orig": text.slice(start, end),
          },
        });
      }
    });
  }

  // ===== 3) 시작 위치 + 우선순위 순으로 정렬 =====
  spans.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return a.priority - b.priority;
  });

  // ===== 4) HTML 생성 — 원문 순서 그대로 =====
  let html = "";
  let cur = 0;

  spans.forEach((sp) => {
    if (sp.start > cur) {
      html += renderSeg(text.slice(cur, sp.start));
    }
    const seg = renderSeg(text.slice(sp.start, sp.end));

    const attrStr = Object.entries(sp.attrs)
      .filter(([, v]) => v !== undefined && v !== null && v !== "")
      .map(([k, v]) => ` ${k}="${escAttr(v)}"`)
      .join("");

    html += `<span class="${sp.cls}"${attrStr}>${seg}</span>`;
    cur = sp.end;
  });

  if (cur < N) {
    html += renderSeg(text.slice(cur));
  }

  return html;
};


// === 필수가이드 검사 ===
// 이제 "유사도 점수"는 쓰지 않고,
// 서버에서 내려주는 paragraph_candidates(핵심단어 2개 이상 + 윈도우)만 사용해서
// "가능성 있음" 구간만 표시한다.
async function runRequiredCheck() {
  // 1) 필수가이드 목록 정리
  const guideList = (requiredText || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  if (!guideList.length) {
    alert("필수가이드를 한 줄 이상 입력해주세요.");
    return;
  }
  if (!text || !text.trim()) {
    alert("검사할 원고가 비어 있습니다.");
    return;
  }

  try {
    // 원문 줄번호 계산용(보고서, 라벨에 공통 사용)
    const srcText = (text || "").replace(/\r\n/g, "\n");

    const buildLineIndex = (s) => {
      const idxs = [0];
      for (let i = 0; i < s.length; i++) if (s[i] === "\n") idxs.push(i + 1);
      return idxs;
    };
    const lineNoFromIndex = (idxs, pos) => {
      let lo = 0, hi = idxs.length - 1, ans = 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (idxs[mid] <= pos) {
          ans = mid + 1;
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      return ans;
    };
    const L = buildLineIndex(srcText);

    // 2) 서버 호출: /guide_verify_local
    //  - threshold는 서버 내부용(있어도 되고, 안 써도 됨)
    //  - window_size: 80자 근처
    //  - min_core_hits: 핵심단어 2개 이상인 구간만 후보로
    const { data } = await axios.post(`${API_BASE}/guide_verify_local`, {
      text,
      required_guides: guideList,
      threshold: 0.85,
      window_size: 80,
      min_core_hits: 2,
    });

    const payload = data || {};
    const candidatesRaw = Array.isArray(payload.paragraph_candidates)
      ? payload.paragraph_candidates
      : [];

    // 3) 템플릿별로 가장 좋은 후보 하나씩만 뽑기
    //    - core_hits(핵심단어 개수) 우선
    //    - 동률이면 best_score(있다면) 큰 쪽
    const byTemplateKey = new Map();
    for (const c of candidatesRaw) {
      if (!c) continue;
      const tpl = (c.template || "").trim();
      const key =
        tpl ||
        `#${typeof c.template_index === "number" ? c.template_index : c.template_index || ""}`;

      const prev = byTemplateKey.get(key);
      if (!prev) {
        byTemplateKey.set(key, c);
      } else {
        const prevHits = Number(prev.core_hits || 0);
        const curHits = Number(c.core_hits || 0);
        if (curHits > prevHits) {
          byTemplateKey.set(key, c);
        } else if (curHits === prevHits) {
          const prevScore = Number(prev.best_score || 0);
          const curScore = Number(c.best_score || 0);
          if (curScore > prevScore) byTemplateKey.set(key, c);
        }
      }
    }

    // 4) 필수가이드 한 줄씩 돌면서:
    //    - 후보가 있으면 "필수가이드(가능성)" + 위치/줄번호 + 핵심단어 리스트
    //    - 없으면 "필수가이드(없음)" 으로만 기록
    const out = [];

    for (let i = 0; i < guideList.length; i++) {
      const tpl = guideList[i];
      const key1 = tpl.trim();

      // 우선 텍스트 키로 찾고, 없으면 template_index로 보조 검색
      let cand = byTemplateKey.get(key1);
      if (!cand) {
        cand = candidatesRaw.find(
          (c) => Number(c.template_index || 0) === i + 1
        );
      }

      if (cand) {
        const start = Number(cand.start ?? cand.startIndex ?? 0) || 0;
        const end =
          Number(cand.end ?? cand.endIndex ?? start + (tpl.length || 1)) || 0;
        const line = lineNoFromIndex(L, start);

        const coreTerms = Array.isArray(cand.core_terms)
          ? cand.core_terms
          : [];
        const coreHits =
          Number(cand.core_hits) || coreTerms.length || 0;

        const termsLabel = coreTerms.length
          ? coreTerms.join(", ")
          : "핵심 단어";

        out.push({
          type: "필수가이드(가능성)",
          original: tpl,
          startIndex: start,
          endIndex: end,
          line,
          found: true,
          reason_line: `해당 문단에 필수가이드와 관련된 ${termsLabel} 등이 함께 포함되어 있습니다. (단어 ${coreHits}개 이상 조합)`,
          severity: "medium",
        });
      } else {
        // 후보 구간이 전혀 없으면 "없음"으로만 남김
        out.push({
          type: "필수가이드(없음)",
          original: tpl,
          startIndex: 0,
          endIndex: 0,
          line: null,
          found: false,
          reason_line:
            "원고에서 해당 필수가이드의 핵심 단어가 2개 이상 동시에 포함된 구간을 찾지 못했습니다.",
          severity: "high",
        });
      }
    }

    // 5) 상태/하이라이트 갱신
    setRequiredResults(out);

    const merged = [
      ...(Array.isArray(resultsVerify) ? resultsVerify : []),
      ...(Array.isArray(resultsPolicy) ? resultsPolicy : []),
      ...out,
    ];
    setResults(merged); // useEffect에서 하이라이트 자동 재생성

    // 6) 현재 파일 캐시에 저장 (파일 모드일 때만)
    if (files && fileIndex >= 0 && files[fileIndex]) {
      const curFile = files[fileIndex];
      setFileResults((prev) => ({
        ...prev,
        [curFile.name]: {
          ...(prev[curFile.name] || {}),
          required: out,
        },
      }));
    }

    alert(
      "필수가이드 검사 결과가 갱신되었습니다.\n- '가능성 있음' 구간만 표시되며,\n- PDF 보고서의 필수가이드 섹션에도 동일하게 반영됩니다."
    );
  } catch (err) {
    console.error(err);
    alert("필수가이드 검사 중 오류가 발생했습니다.");
  }
}

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

  // 🔴 파일별 캐시에 분리 저장 (필수가이드 + 중복문장까지 저장)
  if (fname) {
    setFileResults((prev) => ({
      ...prev,
      [fname]: {
        text,
        verify: data,
        policy: prev[fname]?.policy || [],
        required: requiredResults,              // ⭐ 필수가이드
        intraExactGroups,                       // ⭐ 한 문서 내 중복
        intraSimilarPairs,
        interExactGroups: prev[fname]?.interExactGroups || [],
        interSimilarPairs: prev[fname]?.interSimilarPairs || [],
        interSimilarGroups: prev[fname]?.interSimilarGroups || [],
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

// ✅ 로컬 AI 탐지(v1) – 실제 핸들러
const handleAiLocalDetect = async () => {
  if (!text || !text.trim()) {
    alert("검사할 원고가 비어 있습니다.");
    return;
  }

  try {
    setAiLocalLoading(true);
    setAiLocalError("");
    setAiLocalResult(null);

    // 서버의 /ai_local_detect 엔드포인트 호출
    const res = await axios.post(`${API_BASE}/ai_local_detect_v2`, { text });
    const data = res.data || {};

    // 통일: { ok:bool, score:number, label:str, message:str } 형태 가정
    if (data.ok === false && data.error) {
      setAiLocalError(data.error);
    } else {
      setAiLocalResult(data);

      // 📌 현재 파일 기준으로 로컬 AI 탐지 결과를 파일별 캐시에 저장
      if (files && fileIndex >= 0 && files[fileIndex]) {
        const curFile = files[fileIndex];
        setFileResults((prev) => ({
          ...prev,
          [curFile.name]: {
            ...(prev[curFile.name] || {}),
            aiLocal: data,
          },
        }));
      }
    }
  } catch (e) {
    console.error("ai_local_detect 실패:", e);
    const msg = e?.response?.data?.error || e?.message || "알 수 없는 오류";
    setAiLocalError(msg);
    alert("AI 탐지(v1) 실패: " + msg);
  } finally {
    setAiLocalLoading(false);
  }
};

// ✅ 문서 스타일/서술형 프로파일 (/doc_style_profile)
const handleDocStyleProfile = async () => {
  if (!text || !text.trim()) {
    alert("검사할 원고가 비어 있습니다.");
    return;
  }

  try {
    setStyleLoading(true);
    setStyleError("");
    setStyleProfile(null);

    const res = await axios.post(
      `${API_BASE}/doc_style_profile`,
      { text },
      { headers: authHeaders() }   // 🔐 로그인 토큰 포함
    );
    const data = res.data || {};

    if (data.ok === false && data.error) {
      setStyleError(data.error);
      alert("문서 스타일 분석 오류: " + data.error);
      return;
    }

    // 전체 응답을 그대로 보관 (doc_type / issues 등)
    setStyleProfile(data);

    // 📌 현재 파일에 스타일 프로파일도 캐시
    if (files && fileIndex >= 0 && files[fileIndex]) {
      const curFile = files[fileIndex];
      setFileResults((prev) => ({
        ...prev,
        [curFile.name]: {
          ...(prev[curFile.name] || {}),
          styleProfile: data,
        },
      }));
    }
  } catch (e) {
    console.error("doc_style_profile 실패:", e);
    const msg =
      e?.response?.data?.error ||
      e?.message ||
      "알 수 없는 오류";
    setStyleError(msg);
    alert("문서 스타일 분석 실패: " + msg);
  } finally {
    setStyleLoading(false);
  }
};

// =======================
// 🔥 배치 실행(여러 파일 반복 실행)
// =======================

// 업로드된 파일 전체 AI 검사 실행
const handleAiBatchDetect = async () => {
  if (!files || !files.length) {
    alert("업로드된 파일이 없습니다.");
    return;
  }

  setAiLocalLoading(true);

  try {
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const textContent = await extractFileText(f);

      try {
        const res = await axios.post(`${API_BASE}/ai_local_detect_v2`, { text: textContent });
        const data = res.data || {};

        if (data.ok === false && data.error) {
          // 파일별 오류는 콘솔에만 찍고 계속 진행
          console.error(`AI 탐지 실패 (${f.name}):`, data.error);
        } else {
          // 🔹 파일별 캐시에 저장
          setFileResults((prev) => ({
            ...prev,
            [f.name]: {
              ...(prev[f.name] || {}),
              aiLocal: data,
            },
          }));

          // 🔹 현재 화면에서 보고 있는 파일이면 상태도 갱신
          if (i === fileIndex) {
            setText(normalizeForIndexing(textContent));
            setAiLocalResult(data);
          }
        }
      } catch (e) {
        console.error(`AI 탐지 요청 실패 (${f.name}):`, e?.message || e);
      }
    }

    alert("AI 탐지(참고) 전체 검사가 완료되었습니다.");
  } finally {
    setAiLocalLoading(false);
  }
};


// 업로드된 파일 전체 문체/서술형 분석 실행
const handleBatchStyleProfile = async () => {
  if (!files || !files.length) {
    alert("업로드된 파일이 없습니다.");
    return;
  }

  setStyleLoading(true);

  try {
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const textContent = await extractFileText(f);

      try {
        const res = await axios.post(
          `${API_BASE}/doc_style_profile`,
          { text: textContent },
          { headers: authHeaders() }
        );
        const data = res.data || {};

        if (data.ok === false && data.error) {
          console.error(`문서 스타일 분석 실패 (${f.name}):`, data.error);
        } else {
          // 🔹 파일별 캐시에 저장
          setFileResults((prev) => ({
            ...prev,
            [f.name]: {
              ...(prev[f.name] || {}),
              styleProfile: data,
            },
          }));

          // 🔹 현재 보고 있는 파일이면 즉시 반영
          if (i === fileIndex) {
            setText(normalizeForIndexing(textContent));
            setStyleProfile(data);
          }
        }
      } catch (e) {
        console.error(`문서 스타일 분석 요청 실패 (${f.name}):`, e?.message || e);
      }
    }

    alert("문체/서술형 분석 전체 검사가 완료되었습니다.");
  } finally {
    setStyleLoading(false);
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

// === [ADD] 필수가이드 검사 (배치용, textContent 기준, /guide_verify_local 사용) ===
let reqList = [];
let mergedPlusRequired = merged;
let highlighted2 = highlighted;

try {
  const guideList = (requiredText || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  if (guideList.length) {
    const src = (textContent || "").replace(/\r\n/g, "\n");

    const buildLineIndex = (s) => {
      const idxs = [0];
      for (let i = 0; i < s.length; i++) if (s[i] === "\n") idxs.push(i + 1);
      return idxs;
    };
    const lineNoFromIndex = (idxs, pos) => {
      let lo = 0, hi = idxs.length - 1, ans = 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (idxs[mid] <= pos) { ans = mid + 1; lo = mid + 1; }
        else hi = mid - 1;
      }
      return ans;
    };
    const L = buildLineIndex(src);

    const gRes = await axios.post(`${API_BASE}/guide_verify_local`, {
      text: textContent,
      templates: guideList,
      threshold: 0.85,
      window_lo: 0.7,
      window_hi: 1.4,
    });

    const gItems = Array.isArray(gRes.data?.results) ? gRes.data.results : [];

    reqList = gItems.map((r) => {
      const tpl = r?.template || "";
      const matches = Array.isArray(r?.matches) ? r.matches : [];
      const best = matches[0];

      if (r?.present && best && Number.isFinite(best.start) && Number.isFinite(best.end) && best.end > best.start) {
        const start = best.start;
        const end = best.end;
        return {
          type: "필수가이드(가능성 높음)",
          original: tpl,
          startIndex: start,
          endIndex: end,
          line: lineNoFromIndex(L, start),
          found: true,
          reason_line: r.message || `유사도 ${(best.score * 100).toFixed(1)}%`,
          severity: "low",
          score: best.score,
          sem_score: best.sem_score,
        };
      }
      return {
        type: "필수가이드(가능성 낮음)",
        original: tpl,
        startIndex: 0,
        endIndex: 0,
        line: null,
        found: false,
        reason_line: r?.message || "원고에 없음",
        severity: "high",
      };
    });

    const reqForHighlight = reqList.filter(
      (r) => r.found && Number.isFinite(r.startIndex) && r.endIndex > r.startIndex
    );

    mergedPlusRequired = mergeResultsPositionAware([...merged, ...reqList]);
    highlighted2 = generateHighlightedHTML(
      textContent,
      [...merged, ...reqForHighlight],
      parsedKeywords,
      parsedTerms
    );
  } else {
    // 필수가이드 미입력 시 기존 값 유지
    mergedPlusRequired = merged;
    highlighted2 = highlighted;
  }
} catch (e) {
  console.error("배치 필수가이드 검사 실패:", e?.message || e);
  // 실패해도 verify/policy 결과는 그대로 사용
  mergedPlusRequired = merged;
  highlighted2 = highlighted;
}

      // 4) 🔴 파일별 캐시에 분리 저장
      setFileResults((prev) => ({
        ...prev,
        [f.name]: {
          text: textContent,
          verify: dataVerify,
          policy: dataPolicy,
          highlightedHTML: highlighted2,
          aiSummary: aiSum,
          required: reqList,
        },
      }));

      // 5) 현재 화면에 떠 있는 파일이면 즉시 반영
      if (i === fileIndex) {
        setText(normalizeForIndexing(textContent)); // ⬅️ 통일
        setResultsVerify(dataVerify);
        setResultsPolicy(dataPolicy);
        setResults(mergedPlusRequired);
        setHighlightedHTML(highlighted2);
        setAiSummary(aiSum);
        setRequiredResults(reqList);
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

// === [REPLACE] 로그인/게스트 UI에서 약관/개인정보 링크 숨김 (로그인 화면만 예외) ===
useEffect(() => {
  // 👉 token도 없고 guestMode도 아니면 "순수 로그인 화면" 이라서 그대로 노출
  //    (글핏 첫 로그인 페이지, 로그인 게이트 화면)
  if (!token && !guestMode) return;

  const HIDE_STYLE_ID = "glefit-hide-legal-on-ui";
  let styleEl = document.getElementById(HIDE_STYLE_ID);
  if (!styleEl) {
    styleEl = document.createElement("style");
    styleEl.id = HIDE_STYLE_ID;
    document.head.appendChild(styleEl);
  }
  // href에 terms / privacy가 '포함'된 모든 앵커 숨김 + 필수가이드 구역 내 앵커도 보정
  styleEl.textContent = `
    a[href*="terms"] , a[href*="privacy"] { display: none !important; }
    .required-guide a { display: none !important; }
  `;

  const hideAll = () => {
    document
      .querySelectorAll(
        'a[href*="terms"], a[href*="privacy"], .required-guide a'
      )
      .forEach((a) => {
        a.style.display = "none";
      });
  };
  hideAll();
  const mo = new MutationObserver(hideAll);
  mo.observe(document.body, { childList: true, subtree: true });

  return () => mo.disconnect();
}, [token, guestMode]);


// ========= 커서 이동(정확 탐색 + 중앙 정렬) =========
// ⬇ 핵심단어 기반 확장 + 줄 경계 확장 추가
function resolveSelection(full, start, end, original, before, after, opts = {}) {
  const orig = original || "";
  const bef = before || "";
  const aft = after || "";
  const coreTerms = Array.isArray(opts.coreTerms) ? opts.coreTerms : [];

  const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));

  // 줄 경계(문단)로 확장
  const expandToLine = (s, e) => {
    const L = full.length;
    let ls = s, le = e;
    while (ls > 0 && full[ls - 1] !== "\n") ls--;
    while (le < L && full[le] !== "\n") le++;
    return { s: clamp(ls, 0, L), e: clamp(le, 0, L) };
  };

  // 1) coreTerms가 있으면: 각 핵심단어를 공백무시 정규식으로 찾아 범위를 합집합
  if (coreTerms.length) {
    let minS = Number.POSITIVE_INFINITY;
    let maxE = -1;

    // 탐색 창(있으면 start/end 주변, 없으면 전체)
    const W = 160; // 핵심단어 조합 기준 윈도우
    const winS = clamp((Number.isFinite(start) ? start : 0) - W, 0, full.length);
    const winE = clamp((Number.isFinite(end) ? end : full.length) + W, 0, full.length);
    const scope = full.slice(winS, Math.max(winS, winE));

    coreTerms.forEach((t) => {
      const term = (t || "").trim();
      if (!term) return;
      const re = buildLooseRegex(term);  // ← 이미 파일에 있음
      let m;
      while ((m = re.exec(scope)) !== null) {
        const s0 = winS + m.index;
        const e0 = s0 + (m[0] || "").length;  // 원문 구간 그대로
        if (e0 > s0) {
          if (s0 < minS) minS = s0;
          if (e0 > maxE) maxE = e0;
        }
        if (re.lastIndex === m.index) re.lastIndex++;
      }
    });

    if (Number.isFinite(minS) && maxE > minS) {
      // 문단 경계까지 살짝 확장
      return expandToLine(minS, maxE);
    }
  }

  // 2) 문맥(bef/aft) 우선
  if (bef && aft) {
    const idx = full.indexOf(bef + orig + aft);
    if (idx >= 0) {
      const s = idx + bef.length;
      return expandToLine(s, s + orig.length);
    }
  }
  if (bef) {
    const idx = full.indexOf(bef + orig);
    if (idx >= 0) {
      const s = idx + bef.length;
      return expandToLine(s, s + orig.length);
    }
  }
  if (aft) {
    const idx = full.indexOf(orig + aft);
    if (idx >= 0) {
      return expandToLine(idx, idx + orig.length);
    }
  }

  // 3) original 근접치 탐색
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
      return expandToLine(nearest, nearest + orig.length);
    }
  }

  // 4) 최후 보정(기존과 동일)
  const s = clamp(Number.isFinite(start) ? start : 0, 0, full.length);
  const e = clamp(Number.isFinite(end) ? end : s, s, full.length);
  return expandToLine(s, e);
}

function getCaretClientRect(textarea, index) {
  const ta = textarea;
  const cs = window.getComputedStyle(ta);

  const mirror = document.createElement("div");
  mirror.style.position = "absolute";
  mirror.style.visibility = "hidden";
  mirror.style.whiteSpace = "pre-wrap";
  mirror.style.wordWrap = "break-word";
  [
    "boxSizing","width","paddingTop","paddingRight","paddingBottom","paddingLeft",
    "borderTopWidth","borderRightWidth","borderBottomWidth","borderLeftWidth",
    "fontFamily","fontSize","fontWeight","fontStyle","letterSpacing","lineHeight",
    "textIndent","textTransform","textAlign","direction","tabSize","wordSpacing"
  ].forEach(k => mirror.style[k] = cs[k]);

  const value = ta.value || "";
  const before = document.createTextNode(value.slice(0, index));
  const caretSpan = document.createElement("span");
  const after = document.createTextNode(value.slice(index));
  mirror.appendChild(before);
  mirror.appendChild(caretSpan);
  mirror.appendChild(after);

  document.body.appendChild(mirror);
  const r = caretSpan.getBoundingClientRect();
  const base = mirror.getBoundingClientRect();
  document.body.removeChild(mirror);

  return { top: r.top - base.top, height: r.height };
}

function lfToCrlfIndex(posLF, raw) {
  // raw = textarea.value (CRLF 포함 문자열)
  // posLF = LF 기준 인덱스
  let visible = 0;
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] !== "\r") {
      if (visible === posLF) return i;
      visible++;
    }
  }
  return raw.length;
}

// 핵심단어를 함께 전달해 단어조합 기준으로 범위를 확장
function moveCursorAccurate(start, end) {
  const textarea = textareaRef.current;
  if (!textarea) return;

  const full = textarea.value || "";
  const N = full.length;

  // 1) 서버에서 준 인덱스를 그대로 클램프만 해서 사용
  let s = Number.isFinite(start) ? start : 0;
  let e = Number.isFinite(end) ? end : s;

  if (s < 0) s = 0;
  if (s > N) s = N;
  if (e < s) e = s;
  if (e > N) e = N;

  // 2) 커서/드래그 설정
  textarea.focus();
  textarea.setSelectionRange(s, e);

  // 3) 선택 지점을 화면 위쪽 근처로 스크롤
  requestAnimationFrame(() => {
    try {
      const caret = getCaretClientRect(textarea, s);
      const topInScroll = caret.top + textarea.scrollTop;
      const offset = 80; // 화면 위에서 약간 아래로
      textarea.scrollTo({
        top: Math.max(0, topInScroll - offset),
        behavior: "smooth",
      });
    } catch {
      // mirror 계산 실패할 때 대략적인 위치
      const approx = Math.max(0, Math.floor(s / 60) * 22 - 60);
      textarea.scrollTo({ top: approx, behavior: "smooth" });
    }
  });
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
        /* ───────── 글핏 리포트 · 하이라이트 공통 테마 ───────── */
        table.rp-table {
          width:100%;
          border-collapse:collapse;
          font-size:10pt;
        }
        table.rp-table thead th {
          background:#f3e8ff;
          color:#4c1d95;
          padding:8px;
          text-align:left;
          border-bottom:1px solid #e9d5ff;
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

        .rp-section {
          margin:0 0 4mm;
          border-left:4px solid #7c3aed;
          padding-left:6px;
        }

        .rp-charts {
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:8mm;
        }
        .rp-chart {
          background:#faf5ff;
          border:1px solid #e9d5ff;
          border-radius:12px;
          padding:6mm;
        }
        .rp-chart h3 {
          margin:0 0 3mm;
          font-size:11pt;
          color:#4c1d95;
        }

        .rp-fulltext {
          background:#ffffff;
          border:1px solid #e5e8ef;
          border-radius:12px;
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

        /* 하이라이트 토큰 – 글핏 퍼플 테마 (오류/심의만 공통 처리) */
        .error-token,
        .ai-token,
        .policy-block,
        .policy-warn {
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

        /* 맞춤법/문맥 오류 – 옅은 노랑 + 빨간 점선 */
        .error-token {
          box-shadow: inset 0 -0.72em #fef3c7;
          border-bottom:2px dashed #e11d48;
        }

        /* AI 의심 – 연보라 밑줄 */
        .ai-token {
          box-shadow: inset 0 -0.72em #ede9fe;
          border-bottom:2px dashed #7c3aed;
        }

        /* 심의 금지 표현 – 강한 빨간 밑줄 */
        .policy-block {
          box-shadow: inset 0 -0.72em #fee2e2;
          border-bottom:2px solid #b91c1c;
        }

        /* 심의 주의 표현 – 주황색 */
        .policy-warn {
          box-shadow: inset 0 -0.72em #fef3c7;
          border-bottom:2px solid #d97706;
        }

        /* 키워드/단어찾기 – 텍스트만 강조 (색 + 굵기) */
        .keyword-token {
          box-shadow: none;
          border-bottom: none;
          font-weight: 700;
          color: #1d4ed8 !important;
        }

        /* 필수용어/핵심용어 – 텍스트만 강조 (색 + 굵기) */
        .term-token {
          box-shadow: none;
          border-bottom: none;
          font-weight: 700;
          color: #15803d !important;
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

// === [ADD] 필수가이드 결과 섹션 — 줄번호/색상표기 ===
(function addRequiredGuideSection(rootEl) {
  const list = Array.isArray(requiredResults) ? requiredResults : [];
  if (!list.length) return;

  const srcText = (text || "").replace(/\r\n/g, "\n");
  const buildLineIndex = (s) => { const idxs=[0]; for (let i=0;i<s.length;i++) if (s[i]==="\n") idxs.push(i+1); return idxs; };
  const lineNoFromIndex = (idxs, pos) => { let lo=0,hi=idxs.length-1,ans=1; while(lo<=hi){const mid=(lo+hi)>>1; if (idxs[mid] <= pos){ans=mid+1; lo=mid+1;} else hi=mid-1;} return ans; };
  const L = buildLineIndex(srcText);
  const esc = (s="") => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const mkCtx = (start, end) => {
    if (!(start>=0 && end>start)) return "-";
    const ctxStart = Math.max(0, start - 30);
    const ctxEnd   = Math.min(srcText.length, end + 30);
    const before = esc(srcText.slice(ctxStart, start));
    const middle = esc(srcText.slice(start, end));
    const after  = esc(srcText.slice(end, ctxEnd));
    return `${before}<mark>${middle}</mark>${after}`;
  };

  const sec = document.createElement("div");
  sec.className = "rp-section";
  sec.innerHTML = `
    <h2 style="margin:16px 0 8px;">필수가이드 점검 결과</h2>
    <div style="font-size:13px;color:#666;margin-bottom:8px;">
      작성자가 입력한 필수가이드 문구의 포함 여부를 표시합니다.
      <span style="color:#16a34a;font-weight:600">● 있음</span> /
      <span style="color:#dc2626;font-weight:600">● 없음</span>
    </div>
    <table class="rp-table">
      <thead>
        <tr>
          <th style="width:10%">상태</th>
          <th>문구</th>
          <th style="width:12%">줄번호</th>
          <th style="width:28%">문맥</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  `;
  const tbody = sec.querySelector("tbody");

  (list || []).forEach(r => {
    const found = !!r?.found;
    const s = Number(r?.startIndex)||0, e = Number(r?.endIndex)||0;
    const ln = found ? (r?.line ?? lineNoFromIndex(L, s)) : "-";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="font-weight:700; color:${found ? '#16a34a' : '#dc2626'}">${found ? "있음" : "없음"}</td>
      <td>${esc(r?.original || "")}</td>
      <td>${ln}</td>
      <td>${found ? mkCtx(s,e) : "-"}</td>
    `;
    tbody.appendChild(tr);
  });

  rootEl.appendChild(sec);
})(root);

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
      a: {
        ...p.a,
        line: lineNoFromIndex(idxs, Number(p.a?.start) || 0),
      },
      b: {
        ...p.b,
        line: lineNoFromIndex(idxs, Number(p.b?.start) || 0),
      },
    }));

    setIntraExactGroups(exactWithLines);
    setIntraSimilarPairs(simWithLines);

    // 🔹 현재 파일 캐시에 저장 (파일 모드일 때만)
    if (files && fileIndex >= 0 && files[fileIndex]) {
      const curFile = files[fileIndex];
      setFileResults((prev) => ({
        ...prev,
        [curFile.name]: {
          ...(prev[curFile.name] || {}),
          intraExactGroups: exactWithLines,
          intraSimilarPairs: simWithLines,
        },
      }));
    }

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
// === (교체 후) 현재 화면 기준 문서만 위한 중복문장 상세 보고서 ===
const savePerDocDedupReportPDF = async () => {
  try {
    if (typeof window === "undefined" || !window.html2pdf) {
      alert("PDF 생성 라이브러리(html2pdf)가 준비되지 않았습니다.");
      return;
    }

    if (!files?.length) {
      alert("검사 대상 파일이 없습니다.");
      return;
    }

    const baseFile = files[fileIndex];
    if (!baseFile) {
      alert("현재 선택된 파일이 없습니다.");
      return;
    }

    const baseName = baseFile.name || "기준 문서";
    const totalFiles = files.length;

    // ───────────────────────────────────
    // 1) 이 기준 문서와 관련된 문서별 유사도 요약 추출
    //    - interDocSummary 중 file === baseName 인 것만
    //    - 5% 이상만 상세 표에 노출
    //    - 1% 이상 5% 미만은 "5% 미만 묶음" 개수로만 표시
    // ───────────────────────────────────
    const THRESH = 5; // 5% 이상만 상세 노출

    const allRowsForBase = Array.isArray(interDocSummary)
      ? interDocSummary.filter((r) => r?.file === baseName)
      : [];

    const highRows = allRowsForBase
      .filter((r) => {
        const v =
          typeof r?.ratio === "number"
            ? r.ratio
            : Number(r?.ratio || 0);
        return v >= THRESH;
      })
      .sort((a, b) => {
        const va =
          typeof a?.ratio === "number"
            ? a.ratio
            : Number(a?.ratio || 0);
        const vb =
          typeof b?.ratio === "number"
            ? b.ratio
            : Number(b?.ratio || 0);
        return vb - va;
      });

    const lowCount = allRowsForBase.filter((r) => {
      const v =
        typeof r?.ratio === "number"
          ? r.ratio
          : Number(r?.ratio || 0);
      return v > 0 && v < THRESH;
    }).length;

    // 5% 이상 문서만 "실제 상세 하이라이트 대상"으로 사용
    const allowedPartners = new Set(
      highRows.map((r) => r.otherFile).filter(Boolean)
    );

    // ───────────────────────────────────
    // 2) 기준 문서 원문 확보 (fileResults 캐시 우선, 없으면 text 상태)
    // ───────────────────────────────────
    const cachedText =
      fileResults?.[baseName]?.text ??
      fileResults?.[baseName]?.rawText ??
      text ??
      "";
    const baseText = String(cachedText).replace(/\r\n/g, "\n");
    const lines = baseText.split("\n");

    // ───────────────────────────────────
    // 3) 라인 단위 하이라이트 정보 구성
    //
    //    - interExactGroups / interSimilarGroups 에서
    //      file === baseName 인 occurrence 들만 모음
    //    - 그 occurrence 가 연결된 partnerFile 이
    //      allowedPartners(5% 이상) 에 포함될 때만 강조
    //    - start/end 는 쓰지 않고 line 기준으로만 강조
    // ───────────────────────────────────
    const highlightLines = new Map(); // lineNo(1-base) -> { kind, partners:Set }

    const markLine = (lineNo, kind, partnerFile) => {
      const ln = Number(lineNo || 0);
      if (!ln || ln < 1 || ln > lines.length) return;
      if (!partnerFile || !allowedPartners.has(partnerFile)) return;

      let entry = highlightLines.get(ln);
      if (!entry) {
        entry = { kind, partners: new Set() };
        highlightLines.set(ln, entry);
      }
      // 정확 매칭이 한 번이라도 있으면 kind를 "정확"으로 승격
      if (entry.kind !== "정확" && kind === "정확") {
        entry.kind = "정확";
      }
      entry.partners.add(partnerFile);
    };

    const pushFromGroup = (group, kind) => {
      if (!group) return;
      const occs = group.occurrences || [];
      if (!Array.isArray(occs) || !occs.length) return;

      // 기준 문서에 해당하는 occurrence만
      const mine = occs.filter((o) => o?.file === baseName);
      if (!mine.length) return;

      mine.forEach((a) => {
        const lineNo =
          Number(a?.line ?? a?.lineNo ?? a?.lineIndex ?? 0) || 0;

        // 같은 그룹 내에서의 상대 문서들
        const partners = occs
          .map((o) => o?.file)
          .filter(
            (f) =>
              f && f !== baseName && allowedPartners.has(f)
          );

        if (!partners.length) return;

        partners.forEach((p) => markLine(lineNo, kind, p));
      });
    };

    (interExactGroups || []).forEach((g) =>
      pushFromGroup(g, "정확")
    );
    (interSimilarGroups || []).forEach((g) =>
      pushFromGroup(g, "유사")
    );

    // ───────────────────────────────────
    // 4) PDF DOM 구성
    // ───────────────────────────────────
    const esc = (s = "") =>
      String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

    const now = new Date();
    const ymd = now.toLocaleDateString("ko-KR");

    const holder = document.createElement("div");
    holder.id = "glefit-perdoc-report-holder";
    holder.style.position = "fixed";
    holder.style.left = "-9999px";
    holder.style.top = "0";
    holder.style.width = "210mm";
    holder.style.zIndex = "-1";
    holder.style.backgroundColor = "#f3f4f6";
    document.body.appendChild(holder);

    const root = document.createElement("div");
    root.id = "glefit-perdoc-report-root";
    root.style.width = "190mm";
    root.style.minHeight = "297mm";
    root.style.boxSizing = "border-box";
    root.style.margin = "0 auto";
    root.style.padding = "12mm 10mm 14mm 10mm";
    root.style.backgroundColor = "#ffffff";
    root.style.fontFamily =
      '"Noto Sans KR","Segoe UI",Roboto,"Apple SD Gothic Neo",sans-serif';
    root.style.fontSize = "10pt";
    root.style.color = "#111827";

    // 4-1) 타이틀 / 메타 정보
    const hTitle = document.createElement("h1");
    hTitle.textContent = "문서별 중복문장 상세 보고서";
    hTitle.style.fontSize = "16pt";
    hTitle.style.margin = "0 0 6mm";
    hTitle.style.borderBottom = "1px solid #e5e7eb";
    hTitle.style.paddingBottom = "3mm";
    root.appendChild(hTitle);

    const meta = document.createElement("div");
    meta.style.fontSize = "9pt";
    meta.style.color = "#4b5563";
    meta.style.marginBottom = "6mm";
    meta.innerHTML = `
      <div><strong>기준 문서</strong> : ${esc(baseName)}</div>
      <div>문서 위치 : ${fileIndex + 1} / ${totalFiles}</div>
      <div>검사 일시 : ${esc(ymd)}</div>
      <div>전체 검사 문서 수 : ${totalFiles}건</div>
    `;
    root.appendChild(meta);

    // 4-2) 유사도 해석/주의 안내 (요약 보고서와 톤 맞춤)
    const note = document.createElement("div");
    note.style.fontSize = "9pt";
    note.style.lineHeight = "1.5";
    note.style.margin = "0 0 6mm 0";
    note.style.color = "#374151";

    note.innerHTML = `
      <div style="font-weight:600; color:#111827; margin-bottom:1mm;">
        ※ 유사도 결과 해석 안내
      </div>

      <div>
        본 유사도 값은
        <strong style="color:#111827;">내부 중복·재활용 위험도 참고 지표</strong>입니다.
      </div>

      <div style="margin-top:2mm;">
        <span style="color:#6b7280;">구간 해석 :</span><br>
        <span style="color:#2563eb; font-weight:600;">0~10%</span> 자연스러운 유사 /
        <span style="color:#ca8a04; font-weight:600;">11~20%</span> 주의·부분 수정 /
        <span style="color:#ea580c; font-weight:600;">21~30%</span> 재작성·집중 점검 /
        <span style="color:#dc2626; font-weight:700;">31% 이상 재활용 의심</span>
      </div>

      <div style="margin-top:2mm;">
        <span style="color:#6b7280;">표기 규칙 :</span><br>
        <strong style="color:#111827;">‘그 외 유사율 5% 미만 문서’</strong> 건수는
        <strong style="color:#111827;">유사율 1.0% 이상 ~ 4.9%</strong> 구간만 집계되며,<br>
        <span style="color:#dc2626; font-weight:700;">
          유사율 1% 미만(0% 포함)은 자동 분석 한계로 인해 별도로 표시되지 않습니다.
        </span>
      </div>
    `;

    root.appendChild(note);

    // 11~20% 구간 해석 보충
    const note2 = document.createElement("div");
    note2.style.fontSize = "9pt";
    note2.style.lineHeight = "1.5";
    note2.style.margin = "0 0 6mm 0";
    note2.style.color = "#374151";

    note2.innerHTML = `
      <div style="font-weight:600; color:#111827;">
        ※ 11~20% 구간 해석 안내(20% 이하 실무 기준)
      </div>

      <div>
        11~20% 구간은
        <strong style="color:#111827;">동일 키워드·업종 특성으로 인해 자연스럽게 발생하는 유사 패턴</strong>이
        일부 포함될 수 있습니다.
      </div>

      <div style="margin-top:2mm;">
        이 구간은 <strong style="color:#111827;">중복 의심 구간이 아니라, 추가 검토가 필요한 관리 구간</strong>으로 해석합니다.<br>
        동일 키워드 반복 위주의 유사도는 실사용에 큰 문제가 없으며,<br>
        <span style="color:#111827; font-weight:600;">
          문장 구조가 동일한 구간만 선택적으로 수정할 것을 권장합니다.
        </span>
      </div>
    `;
    root.appendChild(note2);

    // 4-3) 기준 문서와 5% 이상으로 겹치는 문서 목록 표
    const secSummary = document.createElement("div");
    secSummary.style.margin = "0 0 8mm";

    const h2 = document.createElement("h2");
    h2.textContent = "기준 문서와 유사한 문서 목록 (5% 이상만)";
    h2.style.fontSize = "12pt";
    h2.style.margin = "0 0 3mm";
    secSummary.appendChild(h2);

    const desc = document.createElement("div");
    desc.style.fontSize = "9pt";
    desc.style.color = "#6b7280";
    desc.style.marginBottom = "2mm";
    desc.textContent =
      "이 문서와 교차 중복·유사가 5% 이상인 문서만 정리한 표입니다.";
    secSummary.appendChild(desc);

    const table = document.createElement("table");
    table.style.width = "100%";
    table.style.borderCollapse = "collapse";
    table.style.fontSize = "9pt";

    const thead = document.createElement("thead");
    const trHead = document.createElement("tr");
    ["상대 문서", "유사율(%)"].forEach((label, idx) => {
      const th = document.createElement("th");
      th.textContent = label;
      th.style.textAlign = idx === 0 ? "left" : "right";
      th.style.padding = "3px 2px";
      th.style.borderBottom = "1px solid #d1d5db";
      th.style.fontWeight = "600";
      th.style.backgroundColor = "#f9fafb";
      trHead.appendChild(th);
    });
    thead.appendChild(trHead);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");

    if (highRows.length) {
      highRows.forEach((r) => {
        const tr = document.createElement("tr");

        const tdName = document.createElement("td");
        tdName.textContent = r.otherFile || "";
        tdName.style.padding = "3px 2px";
        tdName.style.borderBottom = "1px solid #f3f4f6";
        tdName.style.textAlign = "left";

        const tdRatio = document.createElement("td");
        const v =
          typeof r.ratio === "number"
            ? r.ratio
            : Number(r.ratio || 0);
        tdRatio.textContent = v ? v.toFixed(1) : "-";
        tdRatio.style.padding = "3px 2px";
        tdRatio.style.borderBottom = "1px solid #f3f4f6";
        tdRatio.style.textAlign = "right";

        tr.appendChild(tdName);
        tr.appendChild(tdRatio);
        tbody.appendChild(tr);
      });
    } else {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 2;
      td.textContent =
        "5% 이상 중복/유사 문서가 없습니다.";
      td.style.padding = "4px 2px";
      td.style.textAlign = "left";
      tbody.appendChild(td);
    }

    if (lowCount > 0) {
      const tr = document.createElement("tr");
      const tdName = document.createElement("td");
      tdName.textContent = "그 외 유사율 5% 미만 문서";
      tdName.style.padding = "3px 2px";
      tdName.style.borderBottom = "1px solid #f3f4f6";
      tdName.style.textAlign = "left";

      const tdRatio = document.createElement("td");
      tdRatio.textContent = `${lowCount}건`;
      tdRatio.style.padding = "3px 2px";
      tdRatio.style.borderBottom = "1px solid #f3f4f6";
      tdRatio.style.textAlign = "right";

      tr.appendChild(tdName);
      tr.appendChild(tdRatio);
      tbody.appendChild(tr);
    }

    table.appendChild(tbody);
    secSummary.appendChild(table);
    root.appendChild(secSummary);

    // 4-4) 원고 전문 + 중복 라인 강조
    const secText = document.createElement("div");
    secText.style.margin = "0 0 8mm";

    const h2Text = document.createElement("h2");
    h2Text.textContent = "기준 문서 전체 텍스트 (중복 구간 강조)";
    h2Text.style.fontSize = "12pt";
    h2Text.style.margin = "0 0 3mm";
    secText.appendChild(h2Text);

    const legend = document.createElement("div");
    legend.style.fontSize = "9pt";
    legend.style.color = "#6b7280";
    legend.style.marginBottom = "2mm";
    legend.innerHTML = `
      <span style="font-weight:600; color:#b91c1c;">굵은 붉은색 줄</span> :
      다른 문서와 중복·유사(5% 이상 구간에 포함된 문서 기준)로 검출된 줄입니다.
    `;
    secText.appendChild(legend);

    const pre = document.createElement("pre");
    pre.style.fontFamily =
      '"SFMono-Regular","Menlo","Consolas","Liberation Mono",monospace';
    pre.style.fontSize = "8.5pt";
    pre.style.backgroundColor = "#f9fafb";
    pre.style.border = "1px solid #e5e7eb";
    pre.style.borderRadius = "4px";
    pre.style.padding = "6px 8px";
    pre.style.whiteSpace = "pre-wrap";
    pre.style.wordBreak = "break-word";
    pre.style.margin = "0";

    lines.forEach((lineText, idx) => {
      const lineNo = idx + 1;
      const info = highlightLines.get(lineNo);

      const lineWrapper = document.createElement("div");
      lineWrapper.style.display = "flex";

      const num = document.createElement("span");
      num.textContent = String(lineNo).padStart(3, " ");
      num.style.width = "28px";
      num.style.marginRight = "6px";
      num.style.color = "#9ca3af";

      const textSpan = document.createElement("span");
      const safe = esc(lineText || "");

      if (info) {
        textSpan.innerHTML = `<span style="
          font-weight:700;
          color:#b91c1c;
          background:#fee2e2;
          box-decoration-break:clone;
          -webkit-box-decoration-break:clone;
        ">${safe || " "}</span>`;
      } else {
        textSpan.innerHTML = safe || " ";
      }

      lineWrapper.appendChild(num);
      lineWrapper.appendChild(textSpan);
      pre.appendChild(lineWrapper);
    });

    secText.appendChild(pre);
    root.appendChild(secText);

    holder.appendChild(root);

    // ───────────────────────────────────
    // 5) PDF 생성
    // ───────────────────────────────────
    const safeName = String(baseName || "기준문서").replace(
      /[\\/:*?"<>|]/g,
      "_"
    );

    const opt = {
      margin: [0, 0, 0, 0],
      filename: `${safeName}_중복문장_상세보고서.pdf`,
      image: { type: "jpeg", quality: 0.98 },
      html2canvas: { scale: 1 },
      jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
    };

    await window.html2pdf().set(opt).from(root).save();
    document.body.removeChild(holder);
  } catch (e) {
    console.error("savePerDocDedupReportPDF error:", e);
    alert("문서별 중복문장 상세 보고서 생성 중 오류가 발생했습니다.");
  }
};

// ========= (NEW) 여러 문서 간 중복문장/유사 =========
const handleInterDedup = async () => {
  // 이미 검사 중이면 중복 클릭 무시
  if (isInterChecking) return;

  // 새 교차 탐지 시작 시, 이전 요약은 비워두고 다시 계산
  setInterDocSummary([]);

const localCompute = async (arr, lineIdxMap) => {
  const MIN = Number(interMinLen) || 6;
  // 🔹 interSimTh가 비어있을 때도 너무 빡세지 않게 기본값 0.70 적용
  const TH  = Number(interSimTh) || 0.70;

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

  // 🔹 2-1) 문서별 통계 준비 (total / dup sentence set)
  const docMap = new Map();
  for (const s of all) {
    const f = s.file || "";
    if (!f) continue;
    let info = docMap.get(f);
    if (!info) {
      info = { file: f, total: 0, dupKeys: new Set() };
      docMap.set(f, info);
    }
    info.total += 1;
  }

  const makeKey = (obj) => `${obj.file || ""}::${obj.line || 0}::${obj.start || 0}`;

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
      const files = new Set(occ.map((o) => o.file));
      return files.size >= 2;
    })
    .map((occ, idx) => ({ id: idx + 1, occurrences: occ }));

  // 🔹 3-1) 정확 중복에 포함된 문장 → dupKeys에 반영
  for (const g of exact_groups) {
    for (const o of g.occurrences || []) {
      const f = o.file || "";
      const info = docMap.get(f);
      if (!info) continue;
      info.dupKeys.add(makeKey(o));
    }
  }

  // 4) 유사 페어: 서로 다른 파일끼리만, Jaccard n-gram(3)
  const pairs = [];
  for (let i = 0; i < all.length; i++) {
    for (let j = i + 1; j < all.length; j++) {
      const A = all[i],
        B = all[j];
      if (A.file === B.file) continue;
      const a = A.original || A.text || "";
      const b = B.original || B.text || "";
      // 정확중복은 유사에서 제외
      if (canonKR(a) === canonKR(b)) continue;
      const score = jaccardByNgram(a, b, 3);
      if (score >= TH) {
        const pa = { file: A.file, line: A.line, start: A.start, original: A.original };
        const pb = { file: B.file, line: B.line, start: B.start, original: B.original };
        pairs.push({
          a: pa,
          b: pb,
          score: Number(score.toFixed(3)),
        });

        // 🔹 유사 페어에 포함된 문장도 dupKeys에 반영
        const ia = docMap.get(pa.file || "");
        if (ia) ia.dupKeys.add(makeKey(pa));
        const ib = docMap.get(pb.file || "");
        if (ib) ib.dupKeys.add(makeKey(pb));
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

  // 🔹 5-1) 문서쌍별 유사도 집계 (겹치는 글자수 기준, A↔B 대칭)
  const pairStats = new Map(); // key = "fileA||fileB" (사전순)

  // 한 문장(세그먼트) 길이 계산: 공백 제거 + start/end 있으면 그 구간 길이 우선
  const segLen = (node) => {
    if (!node) return 0;
    const raw = (node.original ?? node.text ?? "")
      .toString()
      .replace(/\s+/g, "");
    const s = Number(node.start ?? node.startIndex ?? 0);
    const e = Number(node.end ?? node.endIndex ?? 0);
    const byPos = e > s ? e - s : 0;
    const len = byPos || raw.length;
    return len > 0 ? len : 0;
  };

  // 문장 위치 기준 고유키 (makeKey랑 이름 겹치지 않게 별도 사용)
  const makeInterKey = (obj) =>
    `${obj.file || ""}::${obj.line || 0}::${obj.start || 0}`;

  const getPairStat = (fa, fb) => {
    const A = String(fa || "");
    const B = String(fb || "");
    if (!A || !B || A === B) return null;
    const [f1, f2] = A <= B ? [A, B] : [B, A];
    const key = `${f1}||${f2}`;
    let rec = pairStats.get(key);
    if (!rec) {
      rec = {
        fileA: f1,
        fileB: f2,
        keysA: new Set(),
        keysB: new Set(),
        sharedLenA: 0,
        sharedLenB: 0,
      };
      pairStats.set(key, rec);
    }
    return rec;
  };

  const addPairHit = (nodeA, nodeB) => {
    const rec = getPairStat(nodeA?.file, nodeB?.file);
    if (!rec) return;

    const kA = makeInterKey(nodeA || {});
    const kB = makeInterKey(nodeB || {});
    const lenA = segLen(nodeA);
    const lenB = segLen(nodeB);

    const pushA = (k, len) => {
      if (!rec.keysA.has(k)) {
        rec.keysA.add(k);
        rec.sharedLenA += len || 0;
      }
    };
    const pushB = (k, len) => {
      if (!rec.keysB.has(k)) {
        rec.keysB.add(k);
        rec.sharedLenB += len || 0;
      }
    };

    if ((nodeA?.file || "") === rec.fileA && (nodeB?.file || "") === rec.fileB) {
      pushA(kA, lenA);
      pushB(kB, lenB);
    } else if (
      (nodeA?.file || "") === rec.fileB &&
      (nodeB?.file || "") === rec.fileA
    ) {
      // A/B가 뒤집혀서 들어온 경우
      pushA(kB, lenB);
      pushB(kA, lenA);
    }
  };

  // 5-1-1) 정확 중복 그룹에서 문서쌍 추출
  (exact_groups || []).forEach((g) => {
    const occ = g?.occurrences || [];
    for (let i = 0; i < occ.length; i++) {
      for (let j = i + 1; j < occ.length; j++) {
        const a = occ[i];
        const b = occ[j];
        if (!a || !b) continue;
        if ((a.file || "") === (b.file || "")) continue;
        addPairHit(a, b);
      }
    }
  });

  // 5-1-2) 유사 페어에서 문서쌍 추출
  (simPairsNoExact || []).forEach((p) => {
    const a = p?.a;
    const b = p?.b;
    if (!a || !b) return;
    if ((a.file || "") === (b.file || "")) return;
    addPairHit(a, b);
  });

  // 🔹 5-2) 문서별 "상대 문서 유사율" 리스트로 변환 (문서 전체 char n-gram 기준)
  //   - 문장 탐지 결과(exact/similar)는 하이라이트용으로만 사용하고,
  //     요약 유사율은 각 문서 전체 텍스트의 겹치는 구간 비율로 다시 계산한다.
  const makeNormForDup = (s) =>
    (s || "")
      .toString()
      .replace(/\s+/g, "")
      .replace(/[^\p{L}\p{N}]/gu, "");

  const makeShingles = (s, n = 6, step = 2) => {
    const t = makeNormForDup(s);
    if (!t || t.length < n) return new Set();
    const out = new Set();
    for (let i = 0; i <= t.length - n; i += step) {
      out.add(t.slice(i, i + n));
    }
    return out;
  };

  // 원문 텍스트만 뽑기
  const docTexts = (arr || []).map(({ name, text }) => ({
    name,
    text: text || "",
  }));

  // 각 문서별 shingle 집합 캐시
  const shingleMap = new Map();
  docTexts.forEach(({ name, text }) => {
    if (!name) return;
    shingleMap.set(name, makeShingles(text, 6, 2));
  });

  // 🔹 문서쌍 요약 리스트
  const docPairSummary = [];

  for (let i = 0; i < docTexts.length; i++) {
    const aName = docTexts[i].name;
    if (!aName) continue;
    const aSet = shingleMap.get(aName) || new Set();
    const lenA = aSet.size || 1;

    for (let j = i + 1; j < docTexts.length; j++) {
      const bName = docTexts[j].name;
      if (!bName) continue;
      const bSet = shingleMap.get(bName) || new Set();
      const lenB = bSet.size || 1;

      // 교집합 크기 계산
      let inter = 0;
      if (aSet.size <= bSet.size) {
        for (const v of aSet) {
          if (bSet.has(v)) inter++;
        }
      } else {
        for (const v of bSet) {
          if (aSet.has(v)) inter++;
        }
      }
      if (!inter) continue;

      const ratioA = (inter * 100) / lenA;
      const ratioB = (inter * 100) / lenB;
      const ratio = Number(Math.max(ratioA, ratioB).toFixed(1));

      // A 화면에서 볼 때: A ↔ B
      docPairSummary.push({
        file: aName,
        otherFile: bName,
        ratio,
        sharedCount: inter,
        countA: lenA,
        countB: lenB,
      });

      // B 화면에서 볼 때: B ↔ A
      docPairSummary.push({
        file: bName,
        otherFile: aName,
        ratio,
        sharedCount: inter,
        countA: lenB,
        countB: lenA,
      });
    }
  }

  // 전역 상태에 저장 → UI 상단 "현재 문서 기준 유사 문서 상위 10개"에서 사용
  setInterDocSummary(docPairSummary);

  if (!exact_groups.length && !simPairsNoExact.length) {
    alert("교차 중복문장·유사 문장이 발견되지 않았습니다.");
  } else {
    alert("여러 문서 간 탐지를 완료했습니다.");
  }
};

  try {
    if (!files.length) {
      alert("업로드된 파일이 없습니다.");
      return;
    }

    // 여기서부터 실제 검사 시작 → 버튼을 '검사중…' 상태로
    setIsInterChecking(true);

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
      sim_threshold: Number(interSimTh) || 0.70,
      mode: "full", // 🔹 에디터 UI에서는 항상 상세 모드 사용
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

    // 🔹 5-1) 문서쌍별 유사도 집계 (겹치는 글자수 기준, A↔B 대칭)
    const pairStats = new Map(); // key = "fileA||fileB" (사전순)

    const segLen = (node) => {
      if (!node) return 0;
      const raw = (node.original ?? node.text ?? "")
        .toString()
        .replace(/\s+/g, "");
      const s = Number(node.start ?? node.startIndex ?? 0);
      const e = Number(node.end ?? node.endIndex ?? 0);
      const byPos = e > s ? e - s : 0;
      const len = byPos || raw.length;
      return len > 0 ? len : 0;
    };

    const makeInterKey = (obj) =>
      `${obj.file || ""}::${obj.line || 0}::${obj.start || 0}`;

    const getPairStat = (fa, fb) => {
      const A = String(fa || "");
      const B = String(fb || "");
      if (!A || !B || A === B) return null;
      const [f1, f2] = A <= B ? [A, B] : [B, A];
      const key = `${f1}||${f2}`;
      let rec = pairStats.get(key);
      if (!rec) {
        rec = {
          fileA: f1,
          fileB: f2,
          keysA: new Set(),
          keysB: new Set(),
          sharedLenA: 0,
          sharedLenB: 0,
        };
        pairStats.set(key, rec);
      }
      return rec;
    };

    const addPairHit = (nodeA, nodeB) => {
      const rec = getPairStat(nodeA?.file, nodeB?.file);
      if (!rec) return;

      const kA = makeInterKey(nodeA || {});
      const kB = makeInterKey(nodeB || {});
      const lenA = segLen(nodeA);
      const lenB = segLen(nodeB);

      const pushA = (k, len) => {
        if (!rec.keysA.has(k)) {
          rec.keysA.add(k);
          rec.sharedLenA += len || 0;
        }
      };
      const pushB = (k, len) => {
        if (!rec.keysB.has(k)) {
          rec.keysB.add(k);
          rec.sharedLenB += len || 0;
        }
      };

      if (
        (nodeA?.file || "") === rec.fileA &&
        (nodeB?.file || "") === rec.fileB
      ) {
        pushA(kA, lenA);
        pushB(kB, lenB);
      } else if (
        (nodeA?.file || "") === rec.fileB &&
        (nodeB?.file || "") === rec.fileA
      ) {
        pushA(kB, lenB);
        pushB(kA, lenA);
      }
    };

    // 5-1-1) 정확 중복 그룹에서 문서쌍 추출
    (withLinesExact || []).forEach((g) => {
      const occ = g?.occurrences || [];
      for (let i = 0; i < occ.length; i++) {
        for (let j = i + 1; j < occ.length; j++) {
          const a = occ[i];
          const b = occ[j];
          if (!a || !b) continue;
          if ((a.file || "") === (b.file || "")) continue;
          addPairHit(a, b);
        }
      }
    });

    // 5-1-2) 유사 페어에서 문서쌍 추출
    (simPairsNoExact || []).forEach((p) => {
      const a = p?.a;
      const b = p?.b;
      if (!a || !b) return;
      if ((a.file || "") === (b.file || "")) return;
      addPairHit(a, b);
    });

    // 🔹 5-2) 문서별 "상대 문서 유사율" 리스트로 변환 (겹치는 글자수 / 전체 글자수)
    const docPairSummary = [];

    const docLenMap = {};
    (arr || []).forEach(({ name, text }) => {
      if (!name) return;
      docLenMap[name] = String(text || "").replace(/\s+/g, "").length;
    });
    const getDocLen = (file) => docLenMap[file] || 0;

    for (const rec of pairStats.values()) {
      const cntA = rec.keysA.size || 0;
      const cntB = rec.keysB.size || 0;
      const sharedKeys = Math.min(cntA, cntB);
      if (!sharedKeys) continue;

      const totalA = getDocLen(rec.fileA);
      const totalB = getDocLen(rec.fileB);
      const dupA = rec.sharedLenA || 0;
      const dupB = rec.sharedLenB || 0;

      const ratioA = totalA > 0 ? (dupA * 100) / totalA : 0;
      const ratioB = totalB > 0 ? (dupB * 100) / totalB : 0;

      let ratio;
      if (ratioA > 0 || ratioB > 0) {
        ratio = Math.max(ratioA, ratioB);
      } else {
        const base = Math.max(cntA, cntB) || 1;
        ratio = (sharedKeys * 100) / base;
      }

      const ratioRounded = Number(ratio.toFixed(1));

      // A 화면에서 볼 때: A ↔ B
      docPairSummary.push({
        file: rec.fileA,
        otherFile: rec.fileB,
        ratio: ratioRounded,
        sharedCount: sharedKeys,
        countA: cntA,
        countB: cntB,
      });

      // B 화면에서 볼 때: B ↔ A
      docPairSummary.push({
        file: rec.fileB,
        otherFile: rec.fileA,
        ratio: ratioRounded,
        sharedCount: sharedKeys,
        countA: cntB,
        countB: cntA,
      });
    }

    setInterDocSummary(docPairSummary);

    if (!withLinesExact.length && !simPairsNoExact.length) {
      alert("교차 중복문장·유사 문장이 발견되지 않았습니다.");
    } else {
      alert("여러 문서 간 중복·유사 탐지가 완료되었습니다.");
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
  } finally {
    // 어떤 경우든 검사 상태 해제
    setIsInterChecking(false);
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

    // ✅ 1) interDocSummary가 있으면, "요약 보고서" 전용 경량 PDF로 우선 생성
    const summaryArr = Array.isArray(interDocSummary) ? interDocSummary : [];
    if (summaryArr.length > 0) {
      // 1-1) 파일별로 요약 묶기
      const byFile = new Map();
      summaryArr.forEach((row) => {
        const key = row.file || "";
        if (!key) return;
        const arr = byFile.get(key) || [];
        arr.push(row);
        byFile.set(key, arr);
      });

      // 1-2) 파일 리스트 (업로드 순서 기준) – 실제 summary에 존재하는 것만 사용
      const rawFileNames = Array.isArray(files)
        ? files.map((f) => f?.name).filter(Boolean)
        : Array.from(new Set(summaryArr.map((r) => r.file).filter(Boolean)));

      const fileNames = rawFileNames.filter((name) => byFile.has(name));
      if (!fileNames.length) {
        alert("요약 데이터는 있으나 파일명이 없습니다.");
        return;
      }

      // 1-3) PDF 한 개당 최대 섹션 수
      const MAX_PER_PDF = 50;
      const totalFiles = fileNames.length;
      const totalParts = Math.max(1, Math.ceil(totalFiles / MAX_PER_PDF));

      // 1-4) 섹션 번호 전역 카운터 (1. 2. 3. …)
      let globalIndex = 1;

      const esc = (s = "") =>
        String(s)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;");

      // 1-5) 50개씩 잘라 여러 개 PDF 생성
      for (let part = 0; part < totalParts; part++) {
        const startIdx = part * MAX_PER_PDF;
        const endIdx = Math.min(startIdx + MAX_PER_PDF, totalFiles);
        const chunkNames = fileNames.slice(startIdx, endIdx);

        // 숨김용 루트 DOM
        const holder = document.createElement("div");
        holder.style.position = "fixed";
        holder.style.left = "-9999px";
        holder.style.top = "0";
        holder.style.width = "0";
        holder.style.height = "0";
        document.body.appendChild(holder);

        const root = document.createElement("div");
        root.style.width = "190mm";
        root.style.maxWidth = "190mm";
        root.style.margin = "0 auto";
        root.style.fontFamily =
          "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif";
        root.style.fontSize = "11pt";
        root.style.lineHeight = "1.6";
        root.style.color = "#111827";

        // 표지
        const title = document.createElement("h1");
        title.textContent = "여러 문서 간 중복문장·유사 탐지 — 요약 보고서";
        title.style.fontSize = "18pt";
        title.style.margin = "0 0 8mm";
        root.appendChild(title);

        // 총 검사 원고 수 표시 (전체 기준)
        const totalInfo = document.createElement("div");
        totalInfo.style.fontSize = "9pt";
        totalInfo.style.margin = "2mm 0 3mm 0";
        totalInfo.style.color = "#374151";
        totalInfo.textContent = `총 검사 원고 수 : ${totalFiles}건`;
        root.appendChild(totalInfo);

        const sub = document.createElement("div");
        const today = new Date().toLocaleDateString("ko-KR");
        sub.textContent = `검사일: ${today} · 총 문서 수: ${totalFiles} · PDF 묶음: ${
          part + 1
        } / ${totalParts} (이 파일에는 ${startIdx + 1}~${endIdx}번 원고 포함)`;
        sub.style.margin = "0 0 6mm";
        sub.style.color = "#4b5563";
        sub.style.fontSize = "10pt";
        root.appendChild(sub);

        // ───────── 주의사항 블록 ─────────
        const note = document.createElement("div");
        note.style.fontSize = "9pt";
        note.style.lineHeight = "1.5";
        note.style.margin = "0 0 8mm 0";
        note.style.color = "#374151";

        note.innerHTML = `
          <div style="font-weight:600; color:#111827;">※ 유사도 결과 해석 안내</div>

          <div>
            본 유사도 값은
            <strong style="color:#111827;">내부 중복·재활용 위험도 참고 지표</strong>입니다.
          </div>

          <div style="margin-top:2mm;">
            <span style="color:#6b7280;">구간 해석 :</span><br>
            <span style="color:#2563eb; font-weight:600;">0~10%</span> 자연스러운 유사 /
            <span style="color:#ca8a04; font-weight:600;">11~20%</span> 주의·부분 수정(관리 구간) /
            <span style="color:#ea580c; font-weight:600;">21~30%</span> 재작성·집중 점검 /
            <span style="color:#dc2626; font-weight:700;">31% 이상 재활용 의심</span>
          </div>

          <div style="margin-top:2mm;">
            <span style="color:#6b7280;">표기 규칙 :</span><br>
            <strong style="color:#111827;">‘그 외 유사율 5% 미만 문서’</strong> 건수는
            <strong style="color:#111827;">유사율 1.0% 이상 ~ 4.9%</strong> 구간만 집계되며,<br>
            <span style="color:#dc2626; font-weight:700;">
              유사율 1% 미만(0% 포함) 문서는 별도로 표시되지 않습니다.
            </span>
          </div>
        `;
        root.appendChild(note);

        // 11~20% 관리 구간 안내
        const note2 = document.createElement("div");
        note2.style.fontSize = "9pt";
        note2.style.lineHeight = "1.5";
        note2.style.margin = "0 0 10mm 0";
        note2.style.color = "#374151";

        note2.innerHTML = `
          <div style="font-weight:600; color:#111827;">※ 11~20% 구간 해석 안내(20%이하 실무 기준)</div>

          <div>
            11~20% 구간은
            <strong style="color:#111827;">동일 키워드·업종 특성으로 인해 자연스럽게 발생하는 유사 패턴</strong>이
            일부 포함될 수 있습니다.
          </div>

          <div style="margin-top:2mm;">
            이 구간은 <strong style="color:#111827;">중복 의심 구간이 아니라, 추가 검토가 필요한 관리 구간</strong>으로 해석합니다.<br>
            동일 키워드 반복 위주의 유사도는 실사용에 큰 문제가 없으며,<br>
            <span style="color:#111827; font-weight:600;">
              문장 구조가 동일한 구간만 선택적으로 수정할 것을 권장합니다.
            </span>
          </div>
        `;
        root.appendChild(note2);

        // 1-6) 파일별 섹션 (현재 묶음에 해당하는 이름만)
        chunkNames.forEach((fname) => {
          // 1) 해당 기준 문서에 대한 전체 유사도 행 정렬 (자르지 않음)
          const allRows = (byFile.get(fname) || [])
            .slice()
            .sort(
              (a, b) =>
                (b.ratio || 0) - (a.ratio || 0) ||
                String(a.otherFile || "").localeCompare(
                  String(b.otherFile || "")
                )
            );

          if (!allRows.length) return;

          const sec = document.createElement("div");
          sec.style.margin = "0 0 8mm";
          sec.className = "summary-section";

          const h2 = document.createElement("h2");
          const myIndex = globalIndex++;
          h2.textContent = `${myIndex}. ${fname}`;
          h2.style.fontSize = "13pt";
          h2.style.margin = "0 0 3mm";
          sec.appendChild(h2);

          const table = document.createElement("table");
          table.style.width = "100%";
          table.style.borderCollapse = "collapse";
          table.style.marginBottom = "2mm";
          table.style.fontSize = "9pt";

          const thead = document.createElement("thead");
          const trHead = document.createElement("tr");

          const th1 = document.createElement("th");
          th1.textContent = "유사 문서";
          th1.style.textAlign = "left";
          th1.style.padding = "3px 2px";
          th1.style.borderBottom = "1px solid #d1d5db";

          const th2 = document.createElement("th");
          th2.textContent = "유사율(%)";
          th2.style.textAlign = "right";
          th2.style.padding = "3px 2px";
          th2.style.borderBottom = "1px solid #d1d5db";

          trHead.appendChild(th1);
          trHead.appendChild(th2);
          thead.appendChild(trHead);
          table.appendChild(thead);

          const tbody = document.createElement("tbody");

          // 2) 5% 이상/미만 분리
          const highRows = [];
          let lowCount = 0;

          allRows.forEach((r) => {
            const num =
              typeof r.ratio === "number" ? Number(r.ratio) : null;

            if (num !== null && num < 5) {
              // 5% 미만은 개수만 집계 (전체 기준)
              lowCount += 1;
            } else {
              highRows.push(r);
            }
          });

          // 3) 5% 이상 문서만 "상위 10개"까지 개별 표기
          const visibleRows = highRows.slice(0, 10);

          // 5% 이상 개별 행
          visibleRows.forEach((r) => {
            const tr = document.createElement("tr");

            const tdName = document.createElement("td");
            tdName.innerHTML = esc(r.otherFile || "");
            tdName.style.padding = "3px 2px";
            tdName.style.borderBottom = "1px solid #f3f4f6";
            tdName.style.textAlign = "left";

            const tdRatio = document.createElement("td");
            tdRatio.textContent =
              typeof r.ratio === "number" ? r.ratio.toFixed(1) : "-";
            tdRatio.style.padding = "3px 2px";
            tdRatio.style.borderBottom = "1px solid #f3f4f6";
            tdRatio.style.textAlign = "right";

            tr.appendChild(tdName);
            tr.appendChild(tdRatio);
            tbody.appendChild(tr);
          });

          // 4) 5% 미만 묶음 행 (전체 기준)
          if (lowCount > 0) {
            const tr = document.createElement("tr");

            const tdName = document.createElement("td");
            tdName.textContent = "그 외 유사율 5% 미만 문서";
            tdName.style.padding = "3px 2px";
            tdName.style.borderBottom = "1px solid #f3f4f6";
            tdName.style.textAlign = "left";

            const tdRatio = document.createElement("td");
            tdRatio.textContent = `${lowCount}건`;
            tdRatio.style.padding = "3px 2px";
            tdRatio.style.borderBottom = "1px solid #f3f4f6";
            tdRatio.style.textAlign = "right";

            tr.appendChild(tdName);
            tr.appendChild(tdRatio);
            tbody.appendChild(tr);
          }

          table.appendChild(tbody);
          sec.appendChild(table);

          root.appendChild(sec);
        });

        // A4(210mm) 안에서 페이지 폭을 190mm로 고정해서 잘리지 않게 처리
        root.style.boxSizing = "border-box";
        root.style.padding = "10mm 10mm 12mm 10mm";
        root.style.backgroundColor = "#ffffff";

        holder.appendChild(root);

        const filename =
          totalParts === 1
            ? "여러문서_유사도_요약보고서.pdf"
            : `여러문서_유사도_요약보고서_${part + 1}of${totalParts}.pdf`;

        const opt = {
          margin: [0, 0, 0, 0],
          filename,
          image: { type: "jpeg", quality: 0.98 },
          html2canvas: { scale: 1 },
          jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
        };

        await window.html2pdf().set(opt).from(root).save();
        document.body.removeChild(holder);
      }

      return; // ✅ 요약 보고서 여러 개 생성 후, 아래의 구버전 그룹 보고서는 타지 않음
    }

    // ✅ 2) interDocSummary가 없을 때만 — 기존 "그룹 보고서" 로직 실행
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
    setText((t || "").replace(/\r\n/g, "\n"));

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
        <h2 style={{ marginTop: 0, marginBottom: 8 }}>대량 내부 문서 중복 체크 글핏</h2>
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
    💳 계정당 <span style={{ color: "#dc2626" }}>문의/월</span>
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
    🏦 늘솜제작소
  </p>

  <p style={{ marginTop: 10, fontSize: 14, fontWeight: 700, color: "#0f766e" }}>
    ⚡ 공지사항
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
    <div style={{ fontSize: 13, color: "#6b7280" }}>개별 ID발급 종료</div>
    <div style={{ fontSize: 13, color: "#6b7280" }}>
      카카오톡 문의: <span style={{ color: "#9ca3af" }}>txt365</span>
    </div>
    <div style={{ fontSize: 13, color: "#6b7280" }}>요청 수량에 따라 스케줄이 변동됩니다.</div>
    <div style={{ fontSize: 13, color: "#6b7280" }}>
      문의 시간: <span style={{ color: "#9ca3af" }}>주말/공휴일 검사 불가</span>
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
  <div
    style={{
      minHeight: "100vh",
      padding: "24px 0 40px",
      background:
        "linear-gradient(180deg, #0f172a 0%, #1e293b 40%, #020617 100%)",
      backgroundImage:
        "url('/glefit-winter.png'), " +
        "radial-gradient(circle at 0 0, rgba(148,163,184,0.16) 0, transparent 55%)," +
        "radial-gradient(circle at 100% 0, rgba(56,189,248,0.16) 0, transparent 55%)",
      backgroundSize: "cover",
      backgroundPosition: "center top",
      backgroundRepeat: "no-repeat",
    }}
  >
    {/* 눈 내리는 효과 오버레이 */}
    <div className="glefit-snow-overlay" aria-hidden="true">
      {Array.from({ length: 80 }).map((_, idx) => (
        <span
          key={idx}
          className="glefit-snowflake"
          style={{
            left: `${Math.random() * 100}%`,
            fontSize: `${8 + Math.random() * 8}px`,
            animationDelay: `${Math.random() * 10}s`,
            animationDuration: `${10 + Math.random() * 10}s`,
            opacity: 0.35 + Math.random() * 0.4,
          }}
        >
          ✶
        </span>
      ))}
    </div>

    <div style={{ maxWidth: 1400, margin: "0 auto" }}>

{/* ==== 상단 로그인/계정 바 ==== */}
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "12px 18px",
        margin: "14px auto 10px",
        maxWidth: 1400,
        background: "linear-gradient(90deg, #4c1d95, #7c3aed)",
        color: "#f9fafb",
        borderRadius: 12,
        boxShadow: "0 10px 25px rgba(15,23,42,0.22)",
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
          top: 6,                // ⬅ 살짝 위로 올리기 (10 → 6)
          maxWidth: 720,
          textAlign: "center",
          padding: "8px 14px",   // ⬅ 좌우 여백 아주 조금 축소 (18 → 14)
          borderRadius: 999,
          background: "#ffffff",
          border: "1px solid rgba(148,163,184,0.7)",
          boxShadow: "0 8px 24px rgba(15,23,42,0.35)",
          fontSize: 14,
          fontWeight: 500,
          color: "#0f172a",
          lineHeight: 1.5,
          pointerEvents: "none",
          zIndex: 3,
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
                padding: "2px 8px",
                borderRadius: 6,
                border: "1px solid #cbd5f5",
                background: "#111827",
                color: "#fff",
                cursor: "pointer",
                fontSize: 12,
                pointerEvents: "auto", // 버튼은 클릭 가능
              }}
            >
              수정
            </button>
          )}
        </span>
      </div>
    )}
      <div style={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 12 }}>
        {/* 좌: 글핏 겨울 로고/타이틀 */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 999,
              border: "2px solid rgba(248,250,252,0.9)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 16,
              fontWeight: 800,
            }}
          >
            G
          </div>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
            <span style={{ fontSize: 14, fontWeight: 700 }}>글핏 작업실</span>
            <span style={{ fontSize: 12, opacity: 0.9 }}>
              모든 글의 검수 도구
            </span>
          </div>
        </div>

        {/* 구분선 */}
        <div
          style={{
            width: 1,
            height: 20,
            margin: "0 8px",
            background: "rgba(248,250,252,0.35)",
          }}
        />

        {/* 우: 계정/만료 정보 */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
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
                  border: isAdmin ? "1px solid #86efac" : "1px solid #d1d5db",
                }}
              >
                {isAdmin ? "관리자" : "일반"}
              </span>
              <span>
                {" · 만료 "}
                {me?.paid_until?.slice(0, 10)}
              </span>

              {typeof me?.remaining_days === "number" && (
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 12 }}>
                    ({me.remaining_days}일 남음)
                  </span>
                  <div
                    style={{
                      marginTop: 2,
                      width: 160,
                      height: 6,
                      background: "rgba(15,23,42,0.25)",
                      borderRadius: 6,
                      overflow: "hidden",
                    }}
                  >
                    <div
                      style={{
                        height: "100%",
                        width: `${Math.max(
                          0,
                          Math.min(
                            100,
                            (me.remaining_days_ratio ??
                              me.remaining_days / 30) * 100
                          )
                        )}%`,
                        background: "#22c55e",
                      }}
                      title="남은일수 비율(대략치)"
                    />
                  </div>
                </div>
              )}
            </>
          ) : (
            "계정 정보 불러오는 중…"
          )}
        </div>
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
        gridTemplateColumns:
          // 좌 / 중 / 우 최소폭을 줄여서 작은 화면에서도 안 밀리게
          "minmax(320px, 1.2fr) minmax(320px, 1.3fr) minmax(320px, 1.0fr)",
        columnGap: 16,
        alignItems: "flex-start",
        maxWidth: 1400,
        margin: "0 auto 24px",
        padding: "0 4px 8px",
        boxSizing: "border-box",
      }}
    >
      {/* 좌측: 원문 입력 + 업로드 */}
      <div
        style={{
          flex: 1.25,
          padding: 16,
          background: "#ffffff",
          border: "1px solid #e5e7eb",
          borderRadius: 12,
          boxShadow: "0 10px 30px rgba(15,23,42,0.08)",
          display: "flex",
          flexDirection: "column",
          minHeight: 0,
        }}
      >
        <h3>✍ 원문 입력(최대50건 내)</h3>

        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          style={{
            border: "2px dashed #cbd5f5",
            padding: 16,
            marginBottom: 12,
            textAlign: "center",
            borderRadius: 10,
            background: "#f9fafb",
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
  {!isAdmin ? "🔒 개별(관리자)" : "맞춤법·문맥"}
</button>

          {/* ✅ 심의 — 게스트만 잠금 (관리자/일반 가능) */}
          <button
            onClick={!isGuest ? handlePolicyCheck : undefined}
            disabled={isGuest}
            title={isGuest ? "체험(게스트)에서는 사용이 제한됩니다." : "심의 규정 기반 표현 검토"}
            style={isGuest ? lockedBtnStyle : undefined}
          >
            심의(표현/위험어)
          </button>

          {/* ✅ 로컬 AI 탐지(v1) – 서버 비용 없이 휴리스틱 기반 */}
          <button
            onClick={!isGuest ? handleAiBatchDetect : undefined}
            disabled={isGuest || aiLocalLoading}
            title={
              isGuest
                ? "체험(게스트)에서는 사용이 제한됩니다."
                : "정확한 결과가 아니며 AI패턴 검사로 참고용입니다./점수가 낮을 수록 ai에 가까운 결과"
            }
            style={isGuest ? lockedBtnStyle : undefined}
          >
            {aiLocalLoading ? "AI 탐지 중…" : "AI 탐지(참고)"}
          </button>

          {/* ✅ 문체/서술형 분석 – 정보성/후기 프로파일 */}
          <button
            onClick={!isGuest ? handleBatchStyleProfile : undefined}
            disabled={isGuest || styleLoading}
            title={
              isGuest
                ? "체험(게스트)에서는 사용이 제한됩니다."
                : "정보성/후기 여부와 문장 패턴을 규칙 기반으로 분석합니다."
            }
            style={isGuest ? lockedBtnStyle : undefined}
          >
            {styleLoading ? "문체 분석 중…" : "문체/서술형 분석"}
          </button>

          {/* ✅ 전체 검사(배치) — 관리자 전용 */}
          <button
            onClick={isAdmin ? handleBatchCheck : undefined}
            disabled={!isAdmin}
            title={
              isAdmin
                ? "현재 업로드된 전체 파일을 한 번에 검사합니다."
                : "관리자 전용 기능입니다"
            }
            style={!isAdmin ? lockedBtnStyle : undefined}
          >
            {!isAdmin ? "🔒 전체 검사" : "전체 검사"}
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

{aiLocalResult && (
          <div
            style={{
              marginTop: 8,
              padding: 8,
              borderRadius: 6,
              background: "#fefce8",
              border: "1px solid #facc15",
              fontSize: 13,
              lineHeight: 1.5,
            }}
          >
            <b>AI 탐지(v1 · 로컬)</b>
            {typeof aiLocalResult.score === "number" && (
              <>
                {" — 점수: "}
                <b>{aiLocalResult.score}</b>
                {(() => {
                  const s = aiLocalResult.score;
                  let label = "";
                  let msg = "";

                  if (s <= 7) {
                    label = "AI 의심(예비필터)";
                    msg =
                      "이 글은 로컬 기준에서 AI 작성 가능성이 높습니다. 중요한 글이라면 외부 탐지를 한 번 더 권장합니다.";
                  } else if (s <= 14) {
                    label = "경계 구간(혼합/의심)";
                    msg =
                      "일부 AI 패턴이 보이지만 단정하기 어렵습니다. 중요도에 따라 외부 탐지를 선택적으로 사용해도 좋습니다.";
                  } else {
                    label = "사람 글에 가까움";
                    msg =
                      "로컬 기준에서는 사람 글 패턴이 더 강하게 보입니다. 단, 이 결과만으로 확정 판정은 불가능합니다.";
                  }

                  return (
                    <>
                      {" ("}
                      {label}
                      {")"}
                      <div style={{ marginTop: 4 }}>{msg}</div>
                    </>
                  );
                })()}
              </>
            )}
          </div>
        )}

        {aiLocalError && (
          <div
            style={{
              marginTop: 6,
              padding: 6,
              borderRadius: 4,
              background: "#fef2f2",
              border: "1px solid #fecaca",
              color: "#b91c1c",
              fontSize: 12,
            }}
          >
            AI 탐지 오류: {aiLocalError}
          </div>
        )}

        {/* ✍️ 문서 스타일/서술형 프로파일 표시 */}
        {styleProfile && (
          <div
            style={{
              marginTop: 16,
              padding: 10,
              borderRadius: 8,
              background: "#eff6ff",
              border: "1px solid #bfdbfe",
              fontSize: 13,
              lineHeight: 1.5,
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: 4 }}>
              ✍️ 문서 스타일 분석
              {styleProfile.doc_type && (
                <span style={{ marginLeft: 6 }}>
                  {styleProfile.doc_type === "info"
                    ? "(정보성)"
                    : styleProfile.doc_type === "review"
                    ? "(후기/리뷰)"
                    : `(${styleProfile.doc_type})`}
                </span>
              )}
            </div>

            {Array.isArray(styleProfile.issues) &&
            styleProfile.issues.length > 0 ? (
              <ul style={{ paddingLeft: 18, margin: 0 }}>
                {styleProfile.issues.map((it, idx) => (
                  <li key={idx} style={{ marginBottom: 4 }}>
                    <strong>[{it.label || it.code || `규칙 ${idx + 1}`}]</strong>{" "}
                    {it.reason || it.message}
                  </li>
                ))}
              </ul>
            ) : (
              <div>특별히 크게 문제되는 패턴은 발견되지 않았습니다.</div>
            )}
          </div>
        )}

        {styleError && (
          <div
            style={{
              marginTop: 6,
              padding: 6,
              borderRadius: 4,
              background: "#fef2f2",
              border: "1px solid #fecaca",
              color: "#b91c1c",
              fontSize: 12,
            }}
          >
            문서 스타일 분석 오류: {styleError}
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
                onChange={(e) => {
                  const value = e.target.value;
                  setKeywordInput(value);

                  // 🔹 현재 선택된 파일 이름 기준으로 map에 저장
                 const curFile = files[fileIndex];
                 if (curFile) {
                    setKeywordByFile((prev) => ({
                      ...(prev || {}),
                      [curFile.name]: value,
                    }));
                  }
                }}
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
              <div style={{ fontSize: 13, marginBottom: 4 }}>단어찾기 ( , 쉼표 구분)</div>
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
      <div
        style={{
          flex: 1.1,
          padding: 16,
          background: "#f9fafb",
          border: "1px solid #e5e7eb",
          borderRadius: 12,
          boxShadow: "0 10px 30px rgba(15,23,42,0.06)",
          display: "flex",
          flexDirection: "column",
          minHeight: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {/* 제목 + 작은 안내 문구(아래) */}
          <div style={{ display: "flex", flexDirection: "column" }}>
            <h3 style={{ margin: 0 }}>📄 중앙 검사 화면</h3>
            <span
              style={{
                marginTop: 2,
                fontSize: 11,
                color: "#64748b",
                fontWeight: 400,
              }}
            >
              (간헐적 양식 깨짐 현상 검사 후 복원됩니다.)
            </span>
          </div>

          {/* 오른쪽 끝: 자동 줄바꿈 토글 */}
          <label
            style={{
              marginLeft: "auto",       // ▶ 오른쪽으로 밀기
              fontSize: 12,
              fontWeight: 500,
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              whiteSpace: "nowrap",     // 한 줄 유지
            }}
          >
            <input
              type="checkbox"
              checked={wrapLongLines}
              onChange={(e) => setWrapLongLines(e.target.checked)}
            />
            자동 줄바꿈
          </label>
        </div>

        <div
          id="highlight-view"
          style={{
            height: 520,
            border: "1px solid #eee",
            padding: 12,
            overflowY: "auto",
            overflowX: "auto",              // ✅ 가로 스크롤 추가
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
{/* === 필수가이드 입력(중앙 검사결과 아래) === */}
<div style={{ marginTop: 20 }}>
  <h4>📘 필수가이드 입력(핵심 단어 조합을 권장합니다)</h4>

  {/* 안내문 + 예시 (링크 없음, 1세트만) */}
  <div style={{ fontSize: 13, marginBottom: 8, color:"#475569", lineHeight: 1.6 }}>
    📢 한 줄에 한 항목씩 입력. 특정구간 내 단어 2개 이상 포함 기준으로 검사.<br/>
    <div style={{ color:"#64748b", marginTop: 6 }}>
      <div>📢 필수항목 포함 여부를 보장하지 않습니다. 반드시 확인이 필요합니다.</div>
      <div>📢 의미는 동일하지만 완전히 다른 단어와 문장일 경우 확인되지 않을 수 있습니다.</div>
      <div>예시) 추천(핵심단어조합): 부작용 발생 전문가 상담</div>
      <div>예시) 효과에는 개인차가 있습니다</div>
    </div>
  </div>

  {/* 입력창 */}
  <textarea
    value={requiredText}
    onChange={(e) => setRequiredText(e.target.value)}
    style={{
      width: "100%",
      height: 80,
      padding: 8,
      borderRadius: 6,
      border: "1px solid #d1d5db",
      boxSizing: "border-box",   // 👉 이 줄 추가
    }}
    placeholder={
      "예)\n효과에는 개인차가 있습니다\n부작용 발생 시 전문가와 상담하세요\n광고심의 인증번호: ..."
    }
  />

  {/* 버튼/카운트 */}
  <div style={{ marginTop: 8, display:"flex", gap:8, alignItems:"center" }}>
    <button onClick={runRequiredCheck} title="필수가이드만 다시 검사">
      필수가이드 검사
    </button>
    <span style={{ fontSize:12, color:"#64748b" }}>
      현재 항목 수: <b>{(requiredText || "").split("\n").map(s=>s.trim()).filter(Boolean).length}</b>
    </span>
  </div>
</div>
      </div>

      {/* 우측 컬럼: 추천항목(위) + 중복문장 탐지(아래, 바깥 박스) */}
      <div
        style={{
          // ⬇ 고정 폭(380px) 때문에 오른쪽으로 밀리던 현상 → 유연한 폭으로 변경
          width: "100%",
          maxWidth: 340,
          display: "flex",
          flexDirection: "column",
          gap: 12,
          alignSelf: "stretch",
        }}
      >

{/* ───────── 박스 #1: 추천 항목 ───────── */}
<div
  style={{
    padding: 16,
    background: "#f9fafb",
    border: "1px solid #e5e7eb",
    borderRadius: 12,
    boxShadow: "0 10px 24px rgba(15,23,42,0.06)",
  }}
>
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

    {(() => {
      // 1) 기본 검사/심의 결과
      const base = mergeResultsPositionAware([...resultsVerify, ...resultsPolicy]);

      // 2) 필수가이드 결과(있음/없음 모두 패널에 노출)
      const reqItems = (requiredResults || []).map(r => ({
        ...r,
        // 패널 표기용 타입명
        type: r.found ? "필수가이드(있음)" : "필수가이드(없음)",
        // 클릭 이동 대비 인덱스 보정
        startIndex: Number(r.startIndex) || 0,
        endIndex: Number(r.endIndex) || Number(r.startIndex) || 0,
        original: r.original || ""
      }));

      // 3) “심의 결과만 보기” 체크 시 필수가이드는 숨김
      const rows = [...reqItems, ...base].filter(item =>
        !filterPolicyOnly ||
        item.type === "심의위반" || item.type === "주의표현"
      );

      return rows.map((item, idx) => {
        const s = Number(item.startIndex) || 0;
        const e = Number(item.endIndex ?? (s + (item.original?.length || 0))) || s;

        // 안정적 key
        const stableKey = `${item.type || "t"}-${s}-${e}-${(item.original || "").slice(0, 20)}`;

        return (
          <div
            key={stableKey}
onClick={() => {
  const base = normalizeForIndexing(textareaRef.current?.value || "");
  const pos = resolveSelection(
    base,
    s, e,
    item.original || "",
    item.before || "",
    item.after || ""
  );
  moveCursorAccurate(
    pos.s, pos.e,
    item.before || "",
    item.after || "",
    item.original || ""
  );
}}
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
                {(item.suggestions || []).slice(0, 3).map((sug, i) => (
                  <li key={i}>{sug}</li>
                ))}
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
      });
    })()}
  </div>
</div>

{/* ───────── 박스 #2: 중복문장/유사 탐지 (추천항목 ‘밖에’ 있는 별도 박스) ───────── */}
<div
  style={{
    padding: 16,
    background: "#f5f3ff",
    border: "1px solid #e5defe",
    borderRadius: 12,
    boxShadow: "0 10px 24px rgba(15,23,42,0.06)",
  }}
>
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

    <button
      onClick={!isInterChecking ? handleInterDedup : undefined}
      disabled={!files.length || isInterChecking}
    >
      {isInterChecking ? "검사중…" : "탐지"}
    </button>
  </div>

  {/* 저장 버튼들 */}
  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 6 }}>
    {/* 요약 보고서: 파일 간 유사율 표만 간단히 정리 */}
    <button
      onClick={saveInterDedupReportPDF}
      disabled={isChecking || !(interExactGroups?.length || interSimilarGroups?.length)}
      title="여러 문서 간 유사율을 파일별로 정리한 요약 보고서"
    >
      요약 보고서(PDF)
    </button>

    {/* 상세 보고서: 각 파일별 중복·유사 문장과 내용을 전부 포함 */}
    <button
      onClick={savePerDocDedupReportPDF}
      disabled={isChecking || !(interExactGroups?.length || interSimilarGroups?.length)}
      title="각 원고별 중복·유사 문장과 내용을 상세히 정리한 보고서"
    >
      상세 보고서(PDF)
    </button>

    {/* 둘 다 저장: 요약 + 상세를 순서대로 저장 */}
    <button
      onClick={handleDedupPDFBoth}
      disabled={isChecking || !(interExactGroups?.length || interSimilarGroups?.length)}
      title="요약 보고서 + 상세 보고서를 순서대로 저장"
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
  {!interExactGroups.length && !interSimilarGroups.length && !interDocSummary.length && (
    <div style={{ color: "#666" }}>결과 없음</div>
  )}

{/* ==== 현재 파일 기준 문서쌍 유사도 요약 (상위 10건) ==== */}
{!!interDocSummary?.length &&
  files &&
  files.length > 0 &&
  fileIndex >= 0 &&
  fileIndex < files.length &&
  (() => {
    // 다음/이전 이동 후에도 항상 안전한 인덱스를 사용
    const safeIndex = Math.min(
      Math.max(fileIndex, 0),
      files.length - 1
    );
    const curName = files[safeIndex]?.name || "";

    if (!curName) return null;

    // 현재 문서가 file 이든 otherFile 이든 모두 잡아서,
    // 항상 "file = 현재문서, otherFile = 상대문서" 형태로 정규화
    const rows = (interDocSummary || [])
      .filter(
        (row) => row.file === curName || row.otherFile === curName
      )
      .map((row) =>
        row.file === curName
          ? row
          : {
              ...row,
              file: curName,
              otherFile: row.file,
            }
      )
      .sort(
        (a, b) =>
          (b.ratio || 0) - (a.ratio || 0) ||
          (b.sharedCount || 0) - (a.sharedCount || 0) ||
          String(a.otherFile || "").localeCompare(
            String(b.otherFile || "")
          )
      );

    // 같은 상대 문서가 여러 번 들어오면(대칭 등) 한 번만 남김
    const dedup = [];
    const seen = new Set();
    for (const r of rows) {
      const key = r.otherFile || "";
      if (!key || seen.has(key)) continue;
      seen.add(key);
      dedup.push(r);
    }

    const top10 = dedup.slice(0, 10);
    if (!top10.length) return null;

    return (
      <div style={{ fontSize: 12, marginBottom: 8, color: "#111" }}>
        <div style={{ marginBottom: 4 }}>
          현재 문서 기준 유사 문서 상위 10개
        </div>
        <div
          style={{ fontSize: 11, color: "#4b5563", marginBottom: 2 }}
        >
          기준 문서: <strong>{curName}</strong>
        </div>
        {top10.map((d, idx) => {
          let rangeText = "-";

          if (typeof d.ratio === "number") {
            // 중앙값 기준 ±1~2% 정도 구간으로 표기
            const center = d.ratio;
            const base = Math.round(center);
            const min = Math.max(0, base - 2);
            const max = Math.min(100, base + 2);
            rangeText = `${min}~${max}%`;
          }

          return (
            <div key={d.otherFile || idx} style={{ margin: "2px 0" }}>
              • {idx + 1}. {d.otherFile} — 유사율 {rangeText}
            </div>
          );
        })}
    <div
      style={{
        fontSize: 11,
        color: "#6b7280",
        marginTop: 4,
      }}
    >
      상세 유사 문장 목록과 문장 묶음은 오른쪽 그룹 보고서(PDF)에서
      확인하실 수 있습니다.
      <br />
      ※ 유사율은 내부 중복·재활용 위험도를 가늠하는 참고값입니다.{" "}
      0~10%: 자연스러운 유사 수준 /{" "}
      11~20%: 주의·수정 권장 /{" "}
      21~30%: 재작성·집중 점검 권장 /{" "}
      31% 이상: 재활용 원고 의심(사용 자제 권장).
    </div>
      </div>
    );
  })()}

  {/* ==== 파일 간 유사 그룹(클러스터) ==== */}
  <div style={{ fontSize: 12, color: "#6b7280", marginTop: 4 }}>
    상세 유사 문장 그룹과 문장 목록은{" "}
    <b>그룹 보고서(PDF)</b>에서만 확인하도록 변경했습니다.
    <br />
    화면에서는 각 파일별 상위 10개 유사 문서의 유사율만 제공합니다.
  </div>
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
  .policy-warn {
    position: relative;
    z-index: 1;
    color: #111 !important;
    -webkit-text-fill-color: #111;
    -webkit-text-stroke: 0.2px rgba(0,0,0,0.6);
    text-shadow: 0 0 0 #111;
    mix-blend-mode: normal !important;
    background: none !important;
    box-decoration-break: clone;
    -webkit-box-decoration-break: clone;
  }

  /* 글핏 테마 형광펜 (inset box-shadow) */
  .error-token {
    box-shadow: inset 0 -0.72em #fef3c7;
    border-bottom: 2px dashed #e11d48;
  }
  .ai-token {
    box-shadow: inset 0 -0.72em #ede9fe;
    border-bottom: 2px dashed #7c3aed;
  }
  .policy-block {
    box-shadow: inset 0 -0.72em #fee2e2;
    border-bottom: 2px solid #b91c1c;
  }
  .policy-warn {
    box-shadow: inset 0 -0.72em #fff7ed;
    border-bottom: 2px solid #d97706;
  }
  .keyword-token {
    box-shadow: none;
    border-bottom: none;
    font-weight: 700;
    color: #1d4ed8 !important;
  }
  .term-token {
    box-shadow: none;
    border-bottom: none;
    font-weight: 700;
    color: #15803d !important;
  }
`}</style>

      {/* 눈 내리는 효과 스타일 */}
      <style>{`
        .glefit-snow-overlay {
          position: fixed;
          inset: 0;
          pointer-events: none;
          overflow: hidden;
          z-index: 4; /* 상단바/카드 위에 살짝 */
        }
        .glefit-snowflake {
          position: absolute;
          top: -10%;
          color: rgba(255,255,255,0.95);
          text-shadow: 0 0 6px rgba(15,23,42,0.45);
          animation-name: glefit-snow-fall;
          animation-timing-function: linear;
          animation-iteration-count: infinite;
        }
        @keyframes glefit-snow-fall {
          0% {
            transform: translate3d(0, -10%, 0);
          }
          100% {
            transform: translate3d(0, 110vh, 0);
          }
        }
      `}</style>

      </div>
    </div>
  );
}
