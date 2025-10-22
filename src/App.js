// src/App.js
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Editor from "./components/Editor";
import AdminPage from "./pages/AdminPageWithLogin"; // 파일이 src/pages/AdminPageWithLogin.jsx 에 있어야 합니다.

// ▷ 토큰 보유 여부 체크 (Editor.js와 동일 키 사용)
const AUTH_KEY_LOCAL = "glefit_token";           // 자동로그인
const AUTH_KEY_SESS  = "glefit_token_session";   // 일반로그인
function hasToken() {
  try {
    return Boolean(
      (typeof sessionStorage !== "undefined" && sessionStorage.getItem(AUTH_KEY_SESS)) ||
      (typeof localStorage !== "undefined" && localStorage.getItem(AUTH_KEY_LOCAL))
    );
  } catch {
    return false;
  }
}

// ▷ 로그인 배경+전경 레이아웃
function LoginWithBackdrop() {
  return (
    <div>
      {/* 배경: 글핏 UI (읽기 전용) */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 0,
          pointerEvents: "none",   // 배경 클릭/타이핑 차단
          opacity: 0.85,
          filter: "saturate(0.95)",
        }}
      >
        <Editor readOnlyPreview={true} previewWhenLoggedOut={true} />
      </div>

      {/* 전경: 로그인 카드 (기존 Editor가 로그인 UI 포함) */}
      <div style={{ position: "relative", zIndex: 1 }}>
        <Editor />

        {/* ← 로그인 카드 하단에 정책 링크 고정 노출 */}
        <div style={{
          textAlign: "center",
          marginTop: 12,
          padding: "8px 0",
          fontSize: 13,
          color: "#6b7280"  /* slate-500 */
        }}>
          <a href="/terms.html" target="_blank" rel="noopener noreferrer" style={{ textDecoration: "underline" }}>
            이용약관
          </a>
          {" · "}
          <a href="/privacy.html" target="_blank" rel="noopener noreferrer" style={{ textDecoration: "underline" }}>
            개인정보 처리방침
          </a>
        </div>
      </div>
    </div>
  );
}

// ▷ 전역 푸터 (약관/개인정보 링크)
function Footer() {
  return (
    <footer
      style={{
        marginTop: 24,
        padding: "12px 0",
        borderTop: "1px solid #eee",
        fontSize: 14,
        textAlign: "center",
      }}
    >
      <a href="/terms.html" target="_blank" rel="noopener noreferrer">
        이용약관
      </a>
      {" | "}
      <a href="/privacy.html" target="_blank" rel="noopener noreferrer">
        개인정보 처리방침
      </a>
    </footer>
  );
}

export default function App() {
  const loggedIn = hasToken();

  return (
    <>
      <BrowserRouter>
        <Routes>
          {/* 홈: 로그인 여부에 따라 분기 */}
          <Route path="/" element={loggedIn ? <Editor /> : <LoginWithBackdrop />} />
          {/* 관리자 페이지 (상단 공지 포함) */}
          <Route path="/admin" element={<AdminPage />} />
          {/* 알 수 없는 경로 -> 홈으로 */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
      <Footer />
    </>
  );
}
