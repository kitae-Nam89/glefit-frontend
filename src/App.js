// src/App.js
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Editor from "./components/Editor";
import AdminPage from "./pages/AdminPageWithLogin"; // 파일이 src/pages/AdminPageWithLogin.jsx 에 있어야 합니다.

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* 기본 편집기 */}
        <Route path="/" element={<Editor />} />
        {/* 관리자 페이지 (상단 공지 포함) */}
        <Route path="/admin" element={<AdminPage />} />
        {/* 알 수 없는 경로 -> 홈으로 */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
