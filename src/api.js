import { BrowserRouter, Routes, Route } from "react-router-dom";
import Editor from "./components/Editor";
import AdminPage from "./pages/AdminPageWithLogin"; // 기존 관리자 페이지
import HeaderBar from "./components/HeaderBar";

export default function App() {
  return (
    <BrowserRouter>
      <HeaderBar />
      <Routes>
        <Route path="/admin" element={<AdminPage />} />
        <Route path="*" element={<Editor />} />
      </Routes>
    </BrowserRouter>
  );
}
