// src/auth.js
import axios from "axios";

export const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000";

// 저장 키
const K = {
  tokenLocal: "glefit_token",          // 자동로그인 시
  tokenSession: "glefit_token_session",// 일반 로그인(세션)
  rememberId: "glefit_saved_id",
  autoLogin: "glefit_auto_login"       // "1"|"0"
};

// 현재 토큰 가져오기: 세션 > 로컬
export function getToken() {
  return sessionStorage.getItem(K.tokenSession) || localStorage.getItem(K.tokenLocal) || "";
}

export function setToken(token, { auto } = { auto: false }) {
  clearToken();
  if (auto) {
    localStorage.setItem(K.tokenLocal, token);
    localStorage.setItem(K.autoLogin, "1");
  } else {
    sessionStorage.setItem(K.tokenSession, token);
    localStorage.setItem(K.autoLogin, "0");
  }
}

export function clearToken() {
  localStorage.removeItem(K.tokenLocal);
  sessionStorage.removeItem(K.tokenSession);
}

export function getSavedId() {
  return localStorage.getItem(K.rememberId) || "";
}
export function setSavedId(id, on) {
  if (on && id) localStorage.setItem(K.rememberId, id);
  else localStorage.removeItem(K.rememberId);
}
export function getAutoLogin() {
  return localStorage.getItem(K.autoLogin) === "1";
}
export function setAutoLogin(on) {
  localStorage.setItem(K.autoLogin, on ? "1" : "0");
}

// Axios 인스턴스
export const api = axios.create({
  baseURL: API_BASE,
});

// 요청 인터셉터: 매 요청마다 토큰 헤더 주입
api.interceptors.request.use((config) => {
  const t = getToken();
  if (t) config.headers.Authorization = `Bearer ${t}`;
  return config;
});

// 응답 인터셉터: 401/402 → 토큰 클리어(만료/비활성)
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const code = err?.response?.status;
    if (code === 401 || code === 402) {
      clearToken();
    }
    return Promise.reject(err);
  }
);

// 현재 사용자 정보
export async function fetchMe() {
  const { data } = await api.get("/auth/me");
  return data; // { username, role, is_active, paid_until, remaining_days }
}

// 로그인
export async function login({ username, password, auto, remember }) {
  const { data } = await api.post("/auth/login", { username, password });
  setToken(data?.access_token, { auto });
  setSavedId(username, remember);
  setAutoLogin(auto);
  return fetchMe();
}

// 로그아웃
export function logout() {
  clearToken();
}
