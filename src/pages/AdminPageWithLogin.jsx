import React, { useEffect, useMemo, useState, useCallback } from "react";
import axios from "axios";

/**
 * AdminPageWithLogin.jsx
 * - 관리자 전용 단일 페이지
 * - 화면 내에 로그인 폼 내장 (토큰 없으면 로그인 카드 노출)
 * - 로그인 성공 시 localStorage('glefit_token')에 토큰 저장 후 관리자 기능 활성화
 * - 기능: 발급/연장(/admin/issue_user), 중단/해지(/admin/set_active), 비번 초기화(/admin/reset_password),
 *         목록/검색(/admin/list_users), 상단 로그아웃, 남은일수/메모/주소 표시, 도메인 제한(site_url) 등록
 *
 * 전제: server.py의 엔드포인트 배포 필요 (REACT_APP_API_BASE .env로 설정 가능)
 */

const API_BASE = process.env.REACT_APP_API_BASE || ""; // 예: "http://localhost:5000"

// axios 기본 헤더 설정
function setAuthHeader(token) {
  if (token) {
    axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  } else {
    delete axios.defaults.headers.common["Authorization"];
  }
}

function fmtDate(iso) {
  if (!iso) return "-";
  try {
    const d = new Date(iso);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
      d.getDate()
    ).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(
      d.getMinutes()
    ).padStart(2, "0")}`;
  } catch {
    return iso;
  }
}

export default function AdminPage() {
  // auth
  const [token, setToken] = useState("");
  const [me, setMe] = useState(null);
  const [authErr, setAuthErr] = useState("");
  const [pingOK, setPingOK] = useState(false);

  // ⬇️ 여기 한 줄 추가 (처음 기본 공지 문구는 바꿔도 됨)
  const [notice, setNotice] = useState(
  localStorage.getItem("glefit_notice") || "📢 공지를 입력하세요 (우측 ‘공지 수정’)"
  );

  // ⬇️ 저장/복원 (붙여넣기)
  useEffect(() => {
  const saved = localStorage.getItem("glefit_notice");
  if (saved && saved.trim() !== "") setNotice(saved);
  }, []);
  useEffect(() => {
  localStorage.setItem("glefit_notice", notice || "");
  }, [notice]);


  // login form
  const [loginId, setLoginId] = useState(localStorage.getItem("glefit_saved_admin_id") || "");
  const [loginPw, setLoginPw] = useState("");
  const [rememberId, setRememberId] = useState(!!localStorage.getItem("glefit_saved_admin_id"));
  const [loggingIn, setLoggingIn] = useState(false);

  // 발급/연장 폼
  const [fUser, setFUser] = useState({ username: "", password: "", days: 32, site_url: "", note: "" });

  // 목록/검색
  const [q, setQ] = useState("");
  const [rows, setRows] = useState([]);
  const [listLoading, setListLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  // 초기 토큰 장착
  useEffect(() => {
    const t = localStorage.getItem("glefit_token") || "";
    setToken(t);
    setAuthHeader(t);
    if (t) {
      verifyToken();
    }
  }, []);

  async function verifyToken() {
    try {
      await axios.get(`${API_BASE}/auth/ping`);
      setPingOK(true);
      const { data } = await axios.get(`${API_BASE}/auth/me`);
      setMe(data);
    } catch (e) {
      setPingOK(false);
      setMe(null);
    }
  }

  const isAdmin = useMemo(() => {
  const r = String(me?.role || "").trim().toLowerCase();
  // 서버가 role을 '관리자'/'owner'/'manager'처럼 줄 수도 있고 is_admin 플래그가 있을 수도 있으니 모두 허용
  return r === "admin" || r === "owner" || r === "manager" || r === "관리자" || me?.is_admin === true;
  }, [me]);


  // 로그인 실행
  async function doLogin(e) {
    e?.preventDefault();
    setLoggingIn(true);
    setAuthErr("");
    try {
      const { data } = await axios.post(`${API_BASE}/auth/login`, { username: loginId, password: loginPw });
      const t = data?.access_token;
      if (!t) throw new Error("토큰 없음");
      localStorage.setItem("glefit_token", t);
      if (rememberId) {
        localStorage.setItem("glefit_saved_admin_id", loginId);
      } else {
        localStorage.removeItem("glefit_saved_admin_id");
      }
      setAuthHeader(t);
      setToken(t);
      await verifyToken();
      setLoginPw("");
    } catch (e) {
      setAuthErr(e?.response?.data?.error || "로그인 실패");
    } finally {
      setLoggingIn(false);
    }
  }

  function doLogout() {
    localStorage.removeItem("glefit_token");
    setAuthHeader("");
    setToken("");
    setMe(null);
    setPingOK(false);
  }

  // 목록 로딩
  const refreshList = useCallback(async () => {
    setListLoading(true);
    try {
      const { data } = await axios.get(`${API_BASE}/admin/list_users`, { params: q ? { q } : undefined });
      setRows(data.users || []);
    } catch (e) {
      setAuthErr(e?.response?.data?.error || "목록 불러오기 실패");
    } finally {
      setListLoading(false);
    }
  }, [q]);

  useEffect(() => {
    if (token) refreshList();
  }, [token, refreshList]);

  // 발급/연장
  async function onIssue(e) {
    e?.preventDefault();
    setActionLoading(true);
    try {
      const payload = { ...fUser };
      if (!payload.password) delete payload.password; // 기존 유저 연장 시 비번 생략
      const { data } = await axios.post(`${API_BASE}/admin/issue_user`, payload);
      await refreshList();
      setFUser({ username: fUser.username, password: "", days: fUser.days || 32, site_url: fUser.site_url || "", note: "" });
      alert(`처리 완료: ${data.username} · 만료 ${data.paid_until}\n잔여 ${data.remaining_days}일`);
    } catch (e) {
      alert(e?.response?.data?.error || "발급/연장 실패");
    } finally {
      setActionLoading(false);
    }
  }

  // 활성 토글
  async function onToggleActive(u, next) {
    try {
      await axios.post(`${API_BASE}/admin/set_active`, { username: u.username, is_active: next });
      await refreshList();
    } catch (e) {
      alert(e?.response?.data?.error || "상태 변경 실패");
    }
  }

  // 비번 초기화
  async function onResetPassword(u) {
    const p = prompt(`새 비밀번호 입력 (사용자: ${u.username})`);
    if (!p) return;
    try {
      await axios.post(`${API_BASE}/admin/reset_password`, { username: u.username, new_password: p });
      alert("비밀번호 초기화 완료");
    } catch (e) {
      alert(e?.response?.data?.error || "비밀번호 초기화 실패");
    }
  }

  // 삭제
  async function onDeleteUser(u) {
    if (!window.confirm(`정말 삭제할까요? (${u.username})`)) return;
    try {
      await axios.post(`${API_BASE}/admin/delete_user`, { username: u.username });
      await refreshList();
    } catch (e) {
      alert(e?.response?.data?.error || "삭제 실패");
    }
  }

  // ========== UI 렌더링 ==========
  // 1) 토큰이 없거나, me가 admin이 아니면 로그인 카드
  if (!token || !pingOK || !isAdmin) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-lg p-6 space-y-6">
          <div className="space-y-1">
            <h1 className="text-2xl font-bold">관리자 로그인</h1>
            <p className="text-sm text-gray-600">관리자 계정으로 로그인해 아이디 발급/연장을 수행하세요.</p>
          </div>

          <form onSubmit={doLogin} className="space-y-4">
            <div>
              <label className="text-sm text-gray-600">아이디</label>
              <input className="w-full border rounded-lg px-3 py-2" value={loginId} onChange={e=>setLoginId(e.target.value)} required />
            </div>
            <div>
              <label className="text-sm text-gray-600">비밀번호</label>
              <input type="password" className="w-full border rounded-lg px-3 py-2" value={loginPw} onChange={e=>setLoginPw(e.target.value)} required />
            </div>
            <div className="flex items-center justify-between">
              <label className="inline-flex items-center gap-2 text-sm text-gray-700">
                <input type="checkbox" checked={rememberId} onChange={e=>setRememberId(e.target.checked)} />
                아이디 저장
              </label>
              {authErr && <span className="text-red-600 text-sm">{authErr}</span>}
            </div>
            <button type="submit" disabled={loggingIn} className="w-full py-2 rounded-xl bg-black text-white disabled:opacity-60">
              {loggingIn ? "로그인 중..." : "로그인"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // 2) 관리자 기능 화면
  return (
    <div className="max-w-6xl mx-auto p-6 space-y-8">
      {/* 상단 바 (3열: 좌 상태 · 중 공지 · 우 버튼) */}
<div className="grid grid-cols-[auto,1fr,auto] items-center gap-3 rounded-xl p-3"
     style={{ background:"#0b1324", color:"#fff" }}>
  {/* 좌: 상태 */}
  <div className="text-[13px] opacity-95">
    <span className="px-2 py-0.5 rounded-full" style={{background:"#2b334a"}}>일반</span>
    <span className="ml-2">· 만료 <b>{me?.paid_until ? me.paid_until.slice(0,10) : "-"}</b></span>
    <span className="ml-1">(<b>{me?.remaining_days ?? "-"}</b>일 남음)</span>
  </div>

  {/* 중: 공지(없으면 비움) */}
  <div
  title={notice?.trim() ? notice : "공지 없음"}
  className="text-center text-[13px] opacity-90 truncate"
>
  {notice?.trim() ? notice : "— 공지를 입력하세요 —"}
</div>

  {/* 우: 버튼들 */}
  <div className="justify-self-end flex items-center gap-2">
    {/* (선택) 관리자만 공지 수정 버튼 */}
    {isAdmin && (
      <button
        onClick={()=>{
          const v = prompt("상단 공지 문구를 입력하세요 (빈칸=숨김)", notice || "");
          if (v !== null) setNotice(v);
        }}
        className="px-3 py-2 rounded-lg border"
        style={{ background:"#16223a", borderColor:"#334", color:"#fff" }}
      >
        공지 수정
      </button>
    )}
    <button
      onClick={doLogout}
      className="px-3 py-2 rounded-lg"
      style={{ background:"#ff5a5a", color:"#fff" }}
    >
      로그아웃
    </button>
  </div>
</div>

      {/* 발급/연장 폼 */}
      <form onSubmit={onIssue} className="border rounded-2xl p-5 space-y-4 shadow-sm">
        <h2 className="text-lg font-semibold">아이디 발급 / 연장</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-sm text-gray-600">아이디 (username)</label>
            <input className="w-full border rounded-lg px-3 py-2" required value={fUser.username} onChange={(e)=>setFUser(v=>({...v, username:e.target.value}))} />
          </div>
          <div>
            <label className="text-sm text-gray-600">초기 비밀번호 (신규 시 필수)</label>
            <input className="w-full border rounded-lg px-3 py-2" placeholder="기존 연장 시 생략" value={fUser.password} onChange={(e)=>setFUser(v=>({...v, password:e.target.value}))} />
          </div>
          <div>
            <label className="text-sm text-gray-600">기간(days)</label>
            <div className="flex gap-2">
              <input type="number" min={1} className="w-32 border rounded-lg px-3 py-2" value={fUser.days} onChange={(e)=>setFUser(v=>({...v, days:Number(e.target.value||0)}))} />
              <div className="flex gap-2">
                {[32,60,90].map(d=> (
                  <button type="button" key={d} className="px-2 py-1 border rounded hover:bg-gray-100" onClick={()=>setFUser(v=>({...v, days:d}))}>{d}일</button>
                ))}
              </div>
            </div>
          </div>
          <div>
            <label className="text-sm text-gray-600">글핏 주소 제한 (site_url)</label>
            <input className="w-full border rounded-lg px-3 py-2" placeholder="예: https://partner.example.com" value={fUser.site_url} onChange={(e)=>setFUser(v=>({...v, site_url:e.target.value}))} />
          </div>
          <div className="md:col-span-2">
  <label className="text-sm text-gray-600">메모 (업체명/담당자 등)</label>
  <textarea
    className="w-full border rounded-lg px-3 py-2 whitespace-pre-wrap break-words resize-y"
    rows={6}
    placeholder="예) ○○병원 / 담당자 홍길동 010-1234-5678 / 특이사항…"
    value={fUser.note}
    onChange={(e)=>setFUser(v=>({...v, note:e.target.value}))}
    style={{ minHeight: 120, lineHeight: 1.5 }}
  />
  <div className="text-right text-xs text-gray-500">{fUser.note?.length || 0}자</div>
</div>
        </div>
        <div className="flex items-center gap-3">
          <button type="submit" disabled={actionLoading} className="px-4 py-2 rounded-xl bg-black text-white disabled:opacity-60">{actionLoading?"처리중...":"발급 / 연장 실행"}</button>
        </div>
      </form>

      {/* 검색/목록 */}
      <div className="border rounded-2xl p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4 gap-3">
          <h2 className="text-lg font-semibold">사용자 목록</h2>
          <div className="flex gap-2 items-center">
            <input className="border rounded-lg px-3 py-2" placeholder="아이디 검색" value={q} onChange={(e)=>setQ(e.target.value)} />
            <button className="px-3 py-2 border rounded-lg bg-white hover:bg-gray-100" onClick={refreshList}>검색</button>
          </div>
        </div>

        <div className="overflow-x-auto">
          {/* ▶ 표 너비 확대 */}
          <table className="min-w-[1200px] border">
            <thead>
              <tr className="bg-gray-50 text-sm">
                <th className="p-2 border w-48">아이디</th>
                <th className="p-2 border w-20">활성</th>
                <th className="p-2 border w-24">동시</th>
                <th className="p-2 border w-24">남은일수</th>
                <th className="p-2 border w-40">만료일</th>
                <th className="p-2 border w-[560px]">메모</th>
                <th className="p-2 border w-[420px]">글핏주소</th>
                <th className="p-2 border w-40">생성일</th>
                <th className="p-2 border w-64">작업</th>
              </tr>
            </thead>
            <tbody>
              {listLoading ? (
  <tr><td className="p-4 text-center" colSpan={9}>불러오는 중...</td></tr>
) : rows.length === 0 ? (
  <tr><td className="p-6 text-center text-gray-500" colSpan={9}>데이터 없음</td></tr>
) : (
                rows.map((u) => (
                  <tr key={u.username} className="text-sm hover:bg-gray-50">
  <td className="p-2 border font-mono">{u.username}</td>

  {/* 활성 */}
  <td className="p-2 border">
    <label className="inline-flex items-center gap-2 cursor-pointer">
      <input
        type="checkbox"
        checked={!!u.is_active}
        onChange={(e)=>onToggleActive(u, e.target.checked)}
      />
      <span>{u.is_active ? "ON" : "OFF"}</span>
    </label>
  </td>

  {/* 동시접속 허용 */}
  <td className="p-2 border">
    <label className="inline-flex items-center gap-2 cursor-pointer" title="동시접속 허용">
      <input
        type="checkbox"
        checked={!!u.allow_concurrent}
        onChange={async (e) => {
          try {
            setActionLoading(true);
            await axios.post(`${API_BASE}/admin/set_allow_concurrent`, {
              username: u.username,
              allow: e.target.checked
            });
            await refreshList();
          } finally {
            setActionLoading(false);
          }
        }}
      />
      <span>{u.allow_concurrent ? "허용" : "차단"}</span>
    </label>
  </td>

  {/* 남은일수 */}
  <td className="p-2 border text-center">
    <span className={u.remaining_days<=3 ? "text-red-600 font-semibold" : ""}>
      {u.remaining_days}
    </span>
  </td>

  {/* 만료일 */}
  <td className="p-2 border">{fmtDate(u.paid_until)}</td>

  {/* 메모 */}
  <td className="p-2 border whitespace-pre-wrap break-words max-w-[560px]">
    {u.note?.trim() ? u.note : "-"}
  </td>

  {/* 글핏주소 */}
  <td className="p-2 border max-w-[480px] truncate" title={u.site_url || "-"}>
    {u.site_url || "-"}
  </td>

  {/* 생성일 */}
  <td className="p-2 border">{fmtDate(u.created_at)}</td>

  {/* 작업 */}
  <td className="p-2 border">
    <div className="flex flex-wrap gap-2">
      <button
        className="px-2 py-1 border rounded"
        onClick={() => setFUser(v=>({...v, username:u.username}))}
      >
        연장 대상
      </button>
      <button
        className="px-2 py-1 border rounded"
        onClick={() => onResetPassword(u)}
      >
        비번초기화
      </button>
      <button
        className="px-2 py-1 border rounded"
        onClick={() => {
          const add = Number(prompt("얼마나 연장할까요? (일)", "32")||0);
          if (!add) return;
          setActionLoading(true);
          axios.post(`${API_BASE}/admin/issue_user`, { username: u.username, days: add, note: "+연장" })
            .then(()=>refreshList())
            .finally(()=>setActionLoading(false));
        }}
      >
        +연장
      </button>
      <button
        className="px-2 py-1 border rounded text-red-600"
        onClick={() => onDeleteUser(u)}
      >
        삭제
      </button>
    </div>
  </td>
</tr>

                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
