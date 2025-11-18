import React, { useEffect, useMemo, useState, useCallback, useRef } from "react";
import axios from "axios";

const API_BASE = process.env.REACT_APP_API_BASE || "";

/* ===== util ===== */
function setAuthHeader(token) {
  if (token) axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  else delete axios.defaults.headers.common["Authorization"];
}
function fmtDate(iso) {
  if (!iso) return "-";
  try {
    const d = new Date(iso);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")} ${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}`;
  } catch { return iso; }
}

/* ===== inline css (경량) ===== */
const CSS = `
.shell{max-width:1280px;margin:0 auto;padding:20px}
.topbar{display:grid;grid-template-columns:auto 1fr auto;gap:10px;background:#0b1324;color:#fff;border-radius:12px;padding:10px}
.badge{padding:.25rem .5rem;border-radius:9999px;background:#2b334a;color:#fff;font-size:12px}
.btn{border:1px solid #d1d5db;border-radius:10px;background:#fff;padding:.45rem .7rem;cursor:pointer}
.btn:disabled{opacity:.6;cursor:not-allowed}
.input,.select,.textarea{border:1px solid #d1d5db;border-radius:10px;padding:.5rem .7rem;width:100%}
.card{border:1px solid #e5e7eb;border-radius:16px;padding:16px;box-shadow:0 1px 2px rgba(16,24,40,.04);background:#fff}
.small{font-size:12px;color:#64748b}
.h2{font-size:18px;font-weight:600;margin:0 0 10px}
.table{border-collapse:collapse;width:100%}
.table th,.table td{border:1px solid #e5e7eb;padding:6px 8px;font-size:13px;line-height:1.2}
.btn-sm{border:1px solid #e5e7eb;border-radius:8px;background:#fff;padding:.25rem .45rem;font-size:12px;cursor:pointer}
.btn-sm:disabled{opacity:.6;cursor:not-allowed}
.table thead{background:#f9fafb}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
.grid{display:grid;grid-template-columns:260px minmax(0,1fr) 360px;gap:18px;margin-top:18px}
@media (max-width:1100px){.grid{grid-template-columns:1fr;}}
.sticky{position:sticky;top:14px}
.kpis{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
@media (max-width:800px){.kpis{grid-template-columns:1fr}}
.scrollx{overflow:auto;cursor:grab}
.scrollx:active{cursor:grabbing}
.minw-users{min-width:960px}     /* 사용자 목록 */
.minw-usage{min-width:840px}     /* 운영 통계 표 */
.minw-traffic{min-width:720px}   /* 트래픽 표 */
.right-col{display:grid;gap:18px;height:fit-content}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;justify-content:flex-end}
`;
const InlineStyle = () => <style>{CSS}</style>;

/* ===== drag-to-scroll 훅 ===== */
function useDragScroll() {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    let isDown = false, startX = 0, scrollLeft = 0;
    const onDown = (e) => { isDown = true; startX = (e.pageX || e.touches?.[0]?.pageX) - el.offsetLeft; scrollLeft = el.scrollLeft; };
    const onLeave = () => { isDown = false; };
    const onUp = () => { isDown = false; };
    const onMove = (e) => {
      if (!isDown) return;
      e.preventDefault();
      const x = (e.pageX || e.touches?.[0]?.pageX) - el.offsetLeft;
      el.scrollLeft = scrollLeft - (x - startX);
    };
    el.addEventListener("mousedown", onDown); el.addEventListener("mouseleave", onLeave);
    el.addEventListener("mouseup", onUp); el.addEventListener("mousemove", onMove);
    el.addEventListener("touchstart", onDown, {passive:true}); el.addEventListener("touchend", onUp);
    el.addEventListener("touchmove", onMove, {passive:false});
    return () => {
      el.removeEventListener("mousedown", onDown); el.removeEventListener("mouseleave", onLeave);
      el.removeEventListener("mouseup", onUp); el.removeEventListener("mousemove", onMove);
      el.removeEventListener("touchstart", onDown); el.removeEventListener("touchend", onUp);
      el.removeEventListener("touchmove", onMove);
    };
  }, []);
  return ref;
}

export default function AdminPage(){
  /* ---------- auth ---------- */
  const [token, setToken] = useState("");
  const [me, setMe] = useState(null);
  const [pingOK, setPingOK] = useState(false);
  const [authErr, setAuthErr] = useState("");

  /* 상단 공지 */
  const [notice, setNotice] = useState(localStorage.getItem("glefit_notice") || "📢 공지를 입력하세요 (우측 ‘공지 수정’)");

  useEffect(()=>{ const v = localStorage.getItem("glefit_notice"); if(v?.trim()) setNotice(v); },[]);
  useEffect(()=>{ localStorage.setItem("glefit_notice", notice || ""); },[notice]);

  /* 로그인 폼 */
  const [loginId, setLoginId] = useState(localStorage.getItem("glefit_saved_admin_id") || "");
  const [loginPw, setLoginPw] = useState("");
  const [rememberId, setRememberId] = useState(!!localStorage.getItem("glefit_saved_admin_id"));
  const [loggingIn, setLoggingIn] = useState(false);

  /* 발급/연장 폼 */
  const [fUser, setFUser] = useState({ username:"", password:"", days:32, site_url:"", note:"" });

  /* 목록/검색 */
  const [q, setQ] = useState("");
  const [rows, setRows] = useState([]);
  const [listLoading, setListLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  /* 운영 통계 */
  const [usageSummary, setUsageSummary] = useState({ usage:[], errors:[], agreements:[] });
  const [usageLoading, setUsageLoading] = useState(false);

  /* 트래픽 */
  const [gran, setGran] = useState("day");
  const [range, setRange] = useState({ start:"", end:"" });
  const [traffic, setTraffic] = useState({ series:[], totals:{ visits:0, logins:0, unique_users:0 }});
  const [trafficLoading, setTrafficLoading] = useState(false);

  /* 초기 토큰 */
  useEffect(()=>{ const t = localStorage.getItem("glefit_token") || ""; setToken(t); setAuthHeader(t); if (t) verifyToken(); },[]);
  async function verifyToken(){
    try{
      await axios.get(`${API_BASE}/auth/ping`);
      const { data } = await axios.get(`${API_BASE}/auth/me`);
      setMe(data); setPingOK(true);
    }catch{ setPingOK(false); setMe(null); }
  }
  const isAdmin = useMemo(()=> {
    const r = String(me?.role||"").toLowerCase().trim();
    return r==="admin"||r==="owner"||r==="manager"||r==="관리자"||me?.is_admin===true;
  },[me]);

  /* 로그인/로그아웃 */
  async function doLogin(e){
    e?.preventDefault(); setLoggingIn(true); setAuthErr("");
    try{
      const { data } = await axios.post(`${API_BASE}/auth/login`, { username:loginId, password:loginPw });
      const t = data?.access_token; if(!t) throw new Error("토큰 없음");
      localStorage.setItem("glefit_token", t);
      rememberId ? localStorage.setItem("glefit_saved_admin_id", loginId) : localStorage.removeItem("glefit_saved_admin_id");
      setAuthHeader(t); setToken(t); await verifyToken(); setLoginPw("");
    }catch(e){ setAuthErr(e?.response?.data?.error || "로그인 실패"); }
    finally{ setLoggingIn(false); }
  }
  function doLogout(){ localStorage.removeItem("glefit_token"); setAuthHeader(""); setToken(""); setMe(null); setPingOK(false); }

  /* 목록 */
  const refreshList = useCallback(async ()=>{
    setListLoading(true);
    try{
      const { data } = await axios.get(`${API_BASE}/admin/list_users`, { params: q ? { q } : undefined });
      setRows(data?.users || []);
    } finally { setListLoading(false); }
  },[q]);
  useEffect(()=>{ if(token) refreshList(); },[token, refreshList]);

  /* usage */
  const loadUsageSummary = useCallback(async ()=>{
    if(!token) return; setUsageLoading(true);
    try{
      const { data } = await axios.get(`${API_BASE}/admin/usage_summary`);
      setUsageSummary({ usage:data?.usage||[], errors:data?.errors||[], agreements:data?.agreements||[] });
    } finally { setUsageLoading(false); }
  },[token]);
  useEffect(()=>{ if(token) loadUsageSummary(); },[token, loadUsageSummary]);

  /* traffic */
  const loadTraffic = useCallback(async ()=>{
    if(!token) return; setTrafficLoading(true);
    try{
      const params = new URLSearchParams();
      if(gran) params.set("granularity", gran);
      if(range.start) params.set("start", range.start);
      if(range.end) params.set("end", range.end);
      const { data } = await axios.get(`${API_BASE}/admin/traffic_summary?`+params.toString());
      setTraffic({ series:data?.series||[], totals:data?.totals || { visits:0, logins:0, unique_users:0 }});
    } finally { setTrafficLoading(false); }
  },[token, gran, range]);
  useEffect(()=>{ if(token) loadTraffic(); },[token, loadTraffic]);

// === [ADD] 게시판 관리 상태 ===
const [boardLoading, setBoardLoading] = useState(false);
const [boardRows, setBoardRows] = useState([]);
const [boardQ, setBoardQ] = useState("");              // 내용 검색
const [boardUser, setBoardUser] = useState("");        // 작성자 필터
const [boardPinnedOnly, setBoardPinnedOnly] = useState(false);
const [boardIncludeHidden, setBoardIncludeHidden] = useState(false);

// === [ADD] 게시판 목록 로더 ===
const loadBoardList = useCallback(async ()=>{
  if(!token) return;
  setBoardLoading(true);
  try{
    const params = new URLSearchParams();
    if (boardQ) params.set("q", boardQ);
    if (boardUser) params.set("username", boardUser);
    if (boardPinnedOnly) params.set("pinned_only", "1");
    if (boardIncludeHidden) params.set("include_hidden", "1");
    const { data } = await axios.get(`${API_BASE}/admin/board_list?`+params.toString());
    setBoardRows(data?.posts || []);
  } finally { setBoardLoading(false); }
}, [token, boardQ, boardUser, boardPinnedOnly, boardIncludeHidden]);
useEffect(()=>{ if(token) loadBoardList(); }, [token, loadBoardList]);

// ▼ [ADD] 작성자 부분검색(게시글 없어도 users 테이블에서 검색)
const [userSearchQ, setUserSearchQ] = useState("");
const [userSearchRes, setUserSearchRes] = useState([]);
const searchTimer = useRef(null);

function searchUsersDebounced(q) {
  if (searchTimer.current) clearTimeout(searchTimer.current);
  searchTimer.current = setTimeout(async () => {
    if (!q) { setUserSearchRes([]); return; }
    try {
      const { data } = await axios.get(`${API_BASE}/admin/list_users`, {
        params: { q },                 // ← 한 글자도 부분일치
        headers: axios.defaults.headers.common, // 이미 setAuthHeader 적용됨
      });
      setUserSearchRes(Array.isArray(data?.users) ? data.users : []);
    } catch {
      setUserSearchRes([]);
    }
  }, 250);
}


// === [ADD] 핀 토글 ===
async function onTogglePin(p){
  try{
    await axios.post(`${API_BASE}/admin/board_pin`, { id: p.id, pinned: !p.pinned });
    await loadBoardList();
  }catch(e){ alert(e?.response?.data?.error || "핀 설정 실패"); }
}

// === [ADD] 게시글 삭제(숨김) ===
async function onDeletePost(p){
  if(!window.confirm("삭제(숨김) 처리할까요?")) return;
  try{
    await axios.post(`${API_BASE}/admin/board_delete`, { id: p.id });
    await loadBoardList();
  }catch(e){ alert(e?.response?.data?.error || "삭제 실패"); }
}

// === [ADD] 사용자 게시판 작성정지 토글 ===
async function onToggleUserBlock(username, nextBlocked){
  try{
    await axios.post(`${API_BASE}/admin/board_block_user`, { username, blocked: nextBlocked ? 1 : 0 });
    await loadBoardList();
    // 사용자 표에도 반영되게 목록 리프레시(선택)
    if (typeof refreshList === "function") await refreshList();
  }catch(e){ alert(e?.response?.data?.error || "작성정지 변경 실패"); }
}


  /* 활성/비번/삭제 */
  async function onIssue(e){
    e?.preventDefault(); setActionLoading(true);
    try{
      const payload = { ...fUser }; if(!payload.password) delete payload.password;
      const { data } = await axios.post(`${API_BASE}/admin/issue_user`, payload);
      await refreshList();
      setFUser({ username:fUser.username, password:"", days:fUser.days||32, site_url:fUser.site_url||"", note:"" });
      alert(`처리 완료: ${data.username} · 만료 ${data.paid_until}\n잔여 ${data.remaining_days}일`);
    } finally { setActionLoading(false); }
  }
  async function onToggleActive(u, next){
    try{ await axios.post(`${API_BASE}/admin/set_active`, { username:u.username, is_active: next }); await refreshList(); }
    catch(e){ alert(e?.response?.data?.error || "상태 변경 실패"); }
  }
  async function onResetPassword(u){
    const p = prompt(`새 비밀번호 입력 (사용자: ${u.username})`); if(!p) return;
    try{ await axios.post(`${API_BASE}/admin/reset_password`, { username:u.username, new_password:p }); alert("비밀번호 초기화 완료"); }
    catch(e){ alert(e?.response?.data?.error || "비밀번호 초기화 실패"); }
  }
  async function onDeleteUser(u){
    if(!window.confirm(`정말 삭제할까요? (${u.username})`)) return;
    try{ await axios.post(`${API_BASE}/admin/delete_user`, { username:u.username }); await refreshList(); }
    catch(e){ alert(e?.response?.data?.error || "삭제 실패"); }
  }

  /* 드래그 스크롤 refs */
  const usersScrollRef = useDragScroll();
  const usageScrollRef = useDragScroll();
  const trafficScrollRef = useDragScroll();

  /* ===== 로그인 화면 ===== */
  if (!token || !pingOK || !isAdmin) {
    return (
      <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",background:"#f8fafc",padding:16}}>
        <InlineStyle />
        <div className="card" style={{width:"100%",maxWidth:420}}>
          <h1 style={{fontSize:24,fontWeight:700,marginBottom:6}}>관리자 로그인</h1>
          <p className="small" style={{marginBottom:16}}>관리자 계정으로 로그인해 아이디 발급/연장을 수행하세요.</p>
          <form onSubmit={doLogin} style={{display:"grid",gap:12}}>
            <div><label className="small">아이디</label><input className="input" value={loginId} onChange={e=>setLoginId(e.target.value)} required/></div>
            <div><label className="small">비밀번호</label><input type="password" className="input" value={loginPw} onChange={e=>setLoginPw(e.target.value)} required/></div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <label className="small" style={{display:"inline-flex",gap:8,alignItems:"center"}}>
                <input type="checkbox" checked={rememberId} onChange={e=>setRememberId(e.target.checked)}/> 아이디 저장
              </label>
              {authErr && <span style={{color:"#dc2626",fontSize:12}}>{authErr}</span>}
            </div>
            <button type="submit" className="btn" disabled={loggingIn} style={{background:"#000",color:"#fff",borderColor:"#000"}}>{loggingIn?"로그인 중...":"로그인"}</button>
          </form>
        </div>
      </div>
    );
  }

  /* ===== 관리자 화면 ===== */
  return (
    <div className="shell">
      <InlineStyle />

      {/* topbar */}
      <div className="topbar">
        <div style={{fontSize:13,opacity:.95}}>
          <span className="badge">일반</span>
          <span style={{marginLeft:8}}>· 만료 <b>{me?.paid_until ? me.paid_until.slice(0,10) : "-"}</b></span>
          <span style={{marginLeft:4}}>(<b>{me?.remaining_days ?? "-"}</b>일 남음)</span>
        </div>
        <div title={notice?.trim()?notice:"공지 없음"} style={{textAlign:"center",fontSize:13,opacity:.9,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>
          {notice?.trim()?notice:"— 공지를 입력하세요 —"}
        </div>
        <div className="toolbar">
          <button className="btn" onClick={()=>{ const v = prompt("상단 공지 문구를 입력하세요 (빈칸=숨김)", notice || ""); if(v!==null) setNotice(v); }}>공지 수정</button>
          <button className="btn" onClick={doLogout} style={{background:"#ff5a5a",color:"#fff",borderColor:"#ff5a5a"}}>로그아웃</button>
        </div>
      </div>

      {/* grid: 좌(조작 고정) / 중(사용자 목록 크게) / 우(통계/트래픽) */}
      <div className="grid">
        {/* 좌: 발급/연장 */}
<div className="sticky" style={{display:"grid",gap:16}}>
  <form onSubmit={onIssue} className="card card-tight form-compact">
    <h2 className="h2">아이디 발급 / 연장</h2>

    {/* 아이디 */}
    <div className="row">
      <label>아이디 (사용자 이름)</label>
      <input
  className="input"
  required
  value={fUser.username}
  onChange={e=>setFUser(v=>({...v, username:e.target.value}))}
  onBlur={e=>setFUser(v=>({...v, username: (e.target.value||"").trim().toLowerCase()}))}
  translate="no"
  lang="en"
  spellCheck={false}
  autoCorrect="off"
  autoCapitalize="off"
  inputMode="latin"
  autoComplete="off"
  pattern="^[a-z0-9._-]{3,32}$"
  title="영문 소문자/숫자/.-_ 만 3~32자"
/>
    </div>

    {/* 초기 비밀번호 */}
    <div className="row">
      <label>초기 비밀번호 (신규 시 필수)</label>
      <input
        className="input"
        placeholder="기존 연장 시 생략"
        value={fUser.password}
        onChange={e=>setFUser(v=>({...v, password:e.target.value}))}
      />
    </div>

    {/* 기간 */}
    <div className="row">
      <label>기간(일)</label>
      <div className="actions">
        <input
          type="number"
          min={1}
          className="input"
          style={{width:100}}
          value={fUser.days}
          onChange={e=>setFUser(v=>({...v, days:Number(e.target.value||0)}))}
        />
        <div className="quick-days">
          {[32,60,90].map(d=>(
            <button type="button" key={d} onClick={()=>setFUser(v=>({...v, days:d}))}>{d}일</button>
          ))}
        </div>
      </div>
    </div>

    {/* 도메인 */}
    <div className="row">
      <label>접속 허용 도메인 (site_url)</label>
      <input
        className="input"
        placeholder="예: https://partner.example.com"
        value={fUser.site_url}
        onChange={e=>setFUser(v=>({...v, site_url:e.target.value}))}
      />
    </div>

    {/* 메모 */}
    <div className="row">
      <label>메모 (업체명/담당자 등)</label>
      <textarea
        className="textarea"
        rows={4}
        placeholder="예) ○○병원 / 담당자 010-1234-5678 / 특이사항…"
        value={fUser.note}
        onChange={e=>setFUser(v=>({...v, note:e.target.value}))}
      />
      <div className="text-xs" style={{textAlign:"right", color:"#6b7280"}}>
        {(fUser.note?.length||0)}자
      </div>
    </div>

    {/* 실행 버튼 */}
    <div className="actions">
      <button
        type="submit"
        disabled={actionLoading}
        className="btn"
        style={{background:"#000",color:"#fff",borderColor:"#000"}}
      >
        {actionLoading ? "처리중..." : "발급 / 연장 실행"}
      </button>
    </div>
  </form>
</div>

{/* 중: 사용자 목록 (중앙, 크게) */}
<div style={{ display: "flex", flexDirection: "column", gap: 18, minWidth: 0 }}>
  {/* ───────── 사용자 목록 카드 ───────── */}
  <div className="card" style={{ height: "fit-content" }}>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:10,marginBottom:10}}>
      <h2 className="h2">사용자 목록</h2>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        <input className="input" placeholder="아이디 검색" value={q} onChange={e=>setQ(e.target.value)} style={{width:220}}/>
        <button className="btn" onClick={refreshList}>검색</button>
      </div>
    </div>

    <div ref={usersScrollRef} className="scrollx">
      <table className="table minw-users">
        <thead>
          <tr>
            <th style={{width:160}}>아이디</th>
            <th style={{width:66}}>활성</th>
            <th style={{width:66}}>동시</th>
            <th style={{width:70}}>남은</th>
            <th style={{width:120}}>만료일</th>
            <th style={{width:260}}>메모</th>
            <th style={{width:220}}>제한 도메인</th>
            <th style={{width:120}}>생성일</th>
            <th style={{width:280}}>작업</th>
          </tr>
        </thead>
        <tbody>
          {listLoading ? (
            <tr><td colSpan={9} align="center" className="small">불러오는 중...</td></tr>
          ) : rows.length === 0 ? (
            <tr><td colSpan={9} align="center" className="small">데이터 없음</td></tr>
          ) : rows.map(u => (
            <tr key={u.username}>
              <td className="mono" style={{ whiteSpace: "nowrap" }} translate="no">
                <span className="notranslate" translate="no" lang="en">{u.username}</span>
              </td>
              <td align="center">
                <input type="checkbox" checked={!!u.is_active}
                       onChange={(e)=>onToggleActive(u, e.target.checked)} />
              </td>
              <td align="center">
                <input
                  type="checkbox"
                  checked={!!u.allow_concurrent}
                  onChange={async (e)=>{
                    try{
                      setActionLoading(true);
                      await axios.post(`${API_BASE}/admin/set_allow_concurrent`, { username:u.username, allow:e.target.checked });
                      await refreshList();
                    } finally { setActionLoading(false); }
                  }}
                />
              </td>
              <td align="center" style={{whiteSpace:"nowrap"}}>
                <span style={{color:u.remaining_days<=3?"#dc2626":"inherit",fontWeight:u.remaining_days<=3?600:400}}>
                  {u.remaining_days}
                </span>
              </td>
              <td className="mono" style={{whiteSpace:"nowrap"}}>{fmtDate(u.paid_until)}</td>
              <td title={u.note || ""} style={{whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis",maxWidth:260}}>
                {u.note?.trim() ? u.note : "-"}
              </td>
              <td className="mono" title={u.site_url || "-"}
                  style={{whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis",maxWidth:220}}>
                {u.site_url || "-"}
              </td>
              <td className="mono" style={{whiteSpace:"nowrap"}}>{fmtDate(u.created_at)}</td>
              <td>
                <div style={{display:"flex",gap:6,flexWrap:"nowrap",overflowX:"auto"}}>
                  <button className="btn-sm" onClick={()=>setFUser(v=>({...v, username:u.username}))}>연장대상</button>
                  <button className="btn-sm" onClick={()=>onResetPassword(u)}>비번초기화</button>
                  <button
                    className="btn-sm"
                    onClick={()=>{
                      const add = Number(prompt("얼마나 연장할까요? (일)", "32")||0);
                      if(!add) return;
                      setActionLoading(true);
                      axios.post(`${API_BASE}/admin/issue_user`, { username:u.username, days:add, note:"+연장" })
                        .then(()=>refreshList())
                        .finally(()=>setActionLoading(false));
                    }}
                  >+연장</button>
                  <button className="btn-sm" style={{color:"#dc2626",borderColor:"#fecaca"}} onClick={()=>onDeleteUser(u)}>삭제</button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>

  {/* ───────── 한 줄 게시판 관리 카드 ───────── */}
  <div className="card" style={{ marginBottom: 0 }}>
    <h2 className="h2">한 줄 게시판 관리</h2>

    {/* 툴바 */}
    <div className="toolbar" style={{ marginBottom: 10 }}>
      <input className="input" style={{width:160}} placeholder="작성자(ID)"
        value={boardUser} onChange={e=>setBoardUser(e.target.value)} />
      <input className="input" style={{width:220}} placeholder="내용 검색(포함)"
        value={boardQ} onChange={e=>setBoardQ(e.target.value)} />
      <label className="small" style={{display:"flex",alignItems:"center",gap:6}}>
        <input type="checkbox" checked={boardPinnedOnly} onChange={e=>setBoardPinnedOnly(e.target.checked)} />
        고정만
      </label>
      <label className="small" style={{display:"flex",alignItems:"center",gap:6}}>
        <input type="checkbox" checked={boardIncludeHidden} onChange={e=>setBoardIncludeHidden(e.target.checked)} />
        삭제(숨김) 포함
      </label>
      <button className="btn" onClick={loadBoardList} disabled={boardLoading}>
        {boardLoading ? "불러오는 중..." : "새로고침"}
      </button>
    </div>

    {/* 작성자(ID) 부분검색 — 카드 내부 */}
    <div style={{ display:"flex", flexDirection:"column", gap:8, margin:"6px 0 12px" }}>
      <input
        className="input"
        placeholder="작성자(ID) 검색 — 부분일치·1글자 가능"
        value={userSearchQ}
        onChange={(e)=>{ const v = e.target.value; setUserSearchQ(v); searchUsersDebounced(v); }}
        style={{ maxWidth: 360 }}
      />
      {userSearchQ && (
        <div style={{ border:"1px solid #e5e7eb", borderRadius:8, padding:8, maxHeight:240, overflowY:"auto" }}>
          {(userSearchRes || []).map(u => (
            <div key={u.username} style={{ display:"grid", gridTemplateColumns:"1fr auto", alignItems:"center", padding:"6px 4px", borderBottom:"1px solid #f3f4f6" }}>
              <div>
                <div className="mono" style={{ whiteSpace:"nowrap" }}>{u.username}</div>
                <div className="small" style={{ opacity:.8 }}>권한: {u.role || "-"}</div>
              </div>
              <div style={{ display:"flex", gap:6 }}>
                <button className="btn-sm" onClick={async ()=>{
                  await axios.post(`${API_BASE}/admin/board_block_user`, { username: u.username, blocked: true });
                  await loadBoardList(); await refreshList(); searchUsersDebounced(userSearchQ);
                }}>정지</button>
                <button className="btn-sm" onClick={async ()=>{
                  await axios.post(`${API_BASE}/admin/board_block_user`, { username: u.username, blocked: false });
                  await loadBoardList(); await refreshList(); searchUsersDebounced(userSearchQ);
                }}>해제</button>
              </div>
            </div>
          ))}
          {(!userSearchRes || userSearchRes.length===0) && (
            <div className="small" style={{ color:"#9ca3af" }}>검색 결과가 없습니다.</div>
          )}
        </div>
      )}
    </div>

    {/* 게시글 목록: 고정 높이 + 내부 스크롤 */}
    <div
      style={{
        maxHeight: 420,          // 10~20행 정도 보이게 조절 (320~480에서 취향대로)
        overflowY: "auto",
        overflowX: "auto",
        border: "1px solid #e5e7eb",
        borderRadius: 8
      }}
    >
      <div className="scrollx" style={{ overflowY: "visible" }}>
        <table className="table" style={{ width: "100%", tableLayout: "auto", minWidth: 900 }}>
          <thead>
            <tr>
              <th style={{width:70}}>고정</th>
              <th>내용</th>
              <th style={{width:220}}>작성자</th>
              <th style={{width:160}}>작성시각</th>
              <th style={{width:100}}>상태</th>
              <th style={{width:160}}>조작</th>
            </tr>
          </thead>
          <tbody>
            {boardRows.length ? boardRows.map(p=>(
              <tr key={p.id} style={p.hidden ? {opacity:.6} : undefined}>
                <td align="center">
                  <input type="checkbox" checked={!!p.pinned} onChange={()=>onTogglePin(p)} />
                </td>
                <td><div style={{whiteSpace:"pre-wrap"}}>{p.content || ""}</div></td>
                <td>
                  <div className="mono">{p.username}</div>
                  <div className="small" style={{marginTop:6, display:"flex", gap:6, alignItems:"center"}}>
                    <span>작성권한:</span>
                    {p.user_blocked ? (
                      <>
                        <span className="badge" style={{background:"#fee2e2",color:"#991b1b"}}>정지</span>
                        <button className="btn-sm" onClick={()=>onToggleUserBlock(p.username, false)}>해제</button>
                      </>
                    ) : (
                      <>
                        <span className="badge" style={{background:"#ecfdf5",color:"#065f46"}}>허용</span>
                        <button className="btn-sm" onClick={()=>onToggleUserBlock(p.username, true)}>정지</button>
                      </>
                    )}
                  </div>
                </td>
                <td>{p.created_at ? fmtDate(p.created_at) : "-"}</td>
                <td>{p.hidden ? "삭제됨" : "정상"}</td>
                <td>
                  <button className="btn-sm" style={{color:"#dc2626",borderColor:"#fecaca"}} onClick={()=>onDeletePost(p)}>삭제</button>
                </td>
              </tr>
            )) : (
              <tr><td colSpan={6} align="center" className="small">데이터 없음</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

        {/* 우: 운영 통계 + 트래픽 (보조) */}
        <div className="right-col">
          {/* 운영 통계 */}
          <div className="card">
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
              <h2 className="h2">운영 통계</h2>
              <button className="btn" onClick={loadUsageSummary} disabled={usageLoading}>
                {usageLoading ? "새로고침..." : "새로고침"}
              </button>
            </div>

            <div className="kpis" style={{marginBottom:10}}>
              <div className="card" style={{padding:12}}><div className="small">동의(환불규정) 기록</div><div style={{fontSize:18,fontWeight:600}}>{usageSummary.agreements?.length||0}</div></div>
              <div className="card" style={{padding:12}}><div className="small">에러 사용자 수</div><div style={{fontSize:18,fontWeight:600}}>{usageSummary.errors?.length||0}</div></div>
              <div className="card" style={{padding:12}}><div className="small">집계 사용자 수</div><div style={{fontSize:18,fontWeight:600}}>{usageSummary.usage?.length||0}</div></div>
            </div>

            <div ref={usageScrollRef} className="scrollx">
              <table className="table minw-usage">
                <thead><tr><th>아이디</th><th>verify</th><th>policy</th><th>dedup_inter</th><th>dedup_intra</th><th>files합</th></tr></thead>
                <tbody>
                  {usageSummary.usage?.length ? usageSummary.usage.map(u=>(
                    <tr key={u.username}>
                      <td className="mono">{u.username}</td>
                      <td align="center">{u.verify||0}</td>
                      <td align="center">{u.policy||0}</td>
                      <td align="center">{u.dedup_inter||0}</td>
                      <td align="center">{u.dedup_intra||0}</td>
                      <td align="center">{u.files||0}</td>
                    </tr>
                  )) : <tr><td colSpan={6} align="center" className="small">데이터 없음</td></tr>}
                </tbody>
              </table>
            </div>

            <div ref={usageScrollRef} className="scrollx" style={{marginTop:10}}>
              <table className="table minw-usage">
                <thead><tr><th>아이디</th><th>에러수</th><th>마지막</th></tr></thead>
                <tbody>
                  {usageSummary.errors?.length ? usageSummary.errors.map(e=>(
                    <tr key={e.username}>
                      <td className="mono">{e.username||"-"}</td>
                      <td align="center">{e.errors||0}</td>
                      <td>{e.last||"-"}</td>
                    </tr>
                  )) : <tr><td colSpan={3} align="center" className="small">에러 기록 없음</td></tr>}
                </tbody>
              </table>
            </div>
          </div>

          {/* 트래픽 */}
          <div className="card">
            <div style={{display:"flex",gap:10,flexWrap:"wrap",alignItems:"end",justifyContent:"space-between",marginBottom:10}}>
              <h2 className="h2">접속·로그인 트래픽</h2>
              <div className="toolbar">
                <label className="small">기간</label>
                <input
                   type="date"
                   className="input"
                   style={{ width: 150 }}
                   value={range.start}
                   onChange={e => setRange(v => ({ ...v, start: e.target.value }))}
                />
               <span className="small">~</span>
               <input
                   type="date"
                   className="input"
                   style={{ width: 150 }}
                   value={range.end}
                   onChange={e => setRange(v => ({ ...v, end: e.target.value }))}
                />

                <select className="select" style={{width:110}} value={gran} onChange={e=>setGran(e.target.value)}>
                  <option value="day">일별</option>
                  <option value="week">주별</option>
                  <option value="month">월별</option>
                </select>
                <button className="btn" onClick={loadTraffic} disabled={trafficLoading}>{trafficLoading?"불러오는 중...":"새로고침"}</button>
              </div>
            </div>

            <div className="kpis" style={{marginBottom:10}}>
              <div className="card" style={{padding:12}}><div className="small">총 방문수</div><div style={{fontSize:20,fontWeight:700}}>{traffic?.totals?.visits ?? 0}</div></div>
              <div className="card" style={{padding:12}}><div className="small">총 로그인수</div><div style={{fontSize:20,fontWeight:700}}>{traffic?.totals?.logins ?? 0}</div></div>
              <div className="card" style={{padding:12}}><div className="small">유니크 로그인(ID)</div><div style={{fontSize:20,fontWeight:700}}>{traffic?.totals?.unique_users ?? 0}</div></div>
            </div>

            <div ref={trafficScrollRef} className="scrollx">
              <table className="table minw-traffic">
                <thead><tr><th>버킷</th><th>방문수</th><th>로그인수</th><th>Active Users*</th></tr></thead>
                <tbody>
                  {Array.isArray(traffic?.series) && traffic.series.length > 0 ? traffic.series.map(r=>(
                    <tr key={r.bucket}>
                      <td className="mono">{r.bucket}</td>
                      <td align="right">{r.visits ?? 0}</td>
                      <td align="right">{r.logins ?? 0}</td>
                      <td align="right">{r.active_users ?? "-"}</td>
                    </tr>
                  )) : <tr><td colSpan={4} align="center" className="small">데이터가 없습니다</td></tr>}
                </tbody>
              </table>
              <div className="small" style={{marginTop:6}}>* 주/월 집계에서는 기간 내 유니크 로그인 수가 고정값으로 표시됩니다.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
