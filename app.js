// ============================================================
//  TbsgBounties — frontend logic
// ============================================================
const SUPABASE_URL  = "https://nbxfivjfbiixakbrwhwy.supabase.co";
const SUPABASE_ANON = "sb_publishable_g1b8KTlJeG1OirNYhPvB6w_K_OU4q0R";

const sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON);

let ME = null;        // profile row
let authMode = "signin";
let submitTaskId = null;

// ---------- helpers ----------
const $ = (id) => document.getElementById(id);
function toast(msg, kind = "") {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast " + kind;
  setTimeout(() => (t.className = "toast hidden"), 3200);
}
function clickToast(msg, onClick){
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast ok";
  t.style.cursor = "pointer";
  const handler = ()=>{ onClick(); t.className="toast hidden"; t.style.cursor=""; t.removeEventListener("click",handler); };
  t.addEventListener("click", handler);
  setTimeout(()=>{ t.className="toast hidden"; t.style.cursor=""; t.removeEventListener("click",handler); }, 6000);
}
function fmt(n) { return Number(n || 0).toFixed(8); }
function pill(status) {
  const map = { open:"pill-open", claimed:"pill-claimed", completed:"pill-approved",
    pending:"pill-pending", approved:"pill-approved", denied:"pill-denied",
    sent:"pill-approved", failed:"pill-denied",
    processing:"pill-pending", cancelled:"pill-denied" };
  return `<span class="pill ${map[status]||''}">${status}</span>`;
}
function closeModal(id){ $(id).classList.add("hidden"); }

// ---------- auth UI ----------
// Usernames are turned into a hidden internal email so Supabase auth works,
// but users only ever see username + password.
const EMAIL_DOMAIN = "tbsgbounties.local";
function usernameToEmail(username){
  // normalise: lowercase, strip anything not a-z0-9._-
  const clean = username.toLowerCase().replace(/[^a-z0-9._-]/g,"");
  return `${clean}@${EMAIL_DOMAIN}`;
}

function switchAuth(mode){
  authMode = mode;
  $("tabSignin").classList.toggle("active", mode==="signin");
  $("tabSignup").classList.toggle("active", mode==="signup");
  $("authBtn").textContent = mode==="signin" ? "Sign in" : "Create account";
  $("authHint").textContent = mode==="signup"
    ? "Pick any username. (The owner username unlocks the admin panel.)" : "";
}

async function doAuth(){
  const username = $("authUsername").value.trim();
  const password = $("authPassword").value;
  if(!username || !password){ return toast("Enter username and password","err"); }
  if(username.replace(/[^a-z0-9._-]/gi,"").length < 3){ return toast("Username must be at least 3 letters/numbers","err"); }
  const email = usernameToEmail(username);
  $("authBtn").disabled = true;

  try{
    if(authMode==="signup"){
      const { error } = await sb.auth.signUp({
        email, password,
        options:{ data:{ username } }
      });
      if(error) throw error;
      // some projects still require confirmation; try immediate sign-in
      const { error: siErr } = await sb.auth.signInWithPassword({ email, password });
      if(siErr) throw siErr;
      toast("Account created!","ok");
    } else {
      const { error } = await sb.auth.signInWithPassword({ email, password });
      if(error){
        if(String(error.message).toLowerCase().includes("invalid")) throw new Error("Wrong username or password");
        throw error;
      }
    }
    await loadSession();
  }catch(e){ toast(e.message || "Auth failed","err"); }
  $("authBtn").disabled = false;
}

async function signOut(){ await sb.auth.signOut(); location.reload(); }

// ---------- session ----------
async function loadSession(){
  const { data:{ session } } = await sb.auth.getSession();
  if(!session){ showAuth(); return; }

  // fetch my profile (retry a moment in case the signup trigger is still running)
  let profile = null;
  for(let i=0;i<5;i++){
    const { data } = await sb.from("profiles").select("*").eq("id", session.user.id).single();
    if(data){ profile = data; break; }
    await new Promise(r=>setTimeout(r,400));
  }
  if(!profile){ toast("Profile not ready, try refreshing","err"); showAuth(); return; }

  ME = profile;

  // Unapproved accounts get held at the gate. The server enforces this too
  // (RLS returns nothing for them) — this screen is just the friendly face.
  if(!ME.approved){ showPending(); return; }

  // The owner account needs its PIN before the app opens. This screen is a
  // convenience: the real enforcement is that verify_admin_pin() is the only
  // way to learn the PIN is right, and payout RPCs check is_owner() server-side.
  if(isOwnerAccount() && !pinCleared()){ showPin(); return; }

  enterApp();
}

// ---------- owner PIN gate ----------
function isOwnerAccount(){
  return !!ME && String(ME.username||"").toLowerCase() === "snowy";
}
// Cleared per browser session only — closing the tab re-locks it.
function pinCleared(){
  try{ return sessionStorage.getItem("pin_ok_"+ME.id) === "1"; }catch(e){ return false; }
}
function markPinCleared(){
  try{ sessionStorage.setItem("pin_ok_"+ME.id, "1"); }catch(e){}
}

function showPin(){
  $("authScreen").classList.add("hidden");
  $("pendingScreen").classList.add("hidden");
  $("app").classList.add("hidden");
  $("topbar").classList.add("hidden");
  $("pinScreen").classList.remove("hidden");
  $("pinInput").value = "";
  $("pinInput").focus();
}

async function submitPin(){
  const pin = $("pinInput").value.trim();
  if(!pin){ return toast("Enter your PIN","err"); }
  $("pinBtn").disabled = true;
  try{
    const { data, error } = await sb.rpc("verify_admin_pin", { p_pin: pin });
    if(error) throw error;
    if(data !== true){
      $("pinInput").value = "";
      toast("Incorrect PIN","err");
      return;
    }
    markPinCleared();
    $("pinScreen").classList.add("hidden");
    enterApp();
  }catch(e){
    toast(e?.message || "PIN check failed","err");
  }finally{
    $("pinBtn").disabled = false;
  }
}

function showAuth(){
  $("authScreen").classList.remove("hidden");
  $("app").classList.add("hidden");
  $("topbar").classList.add("hidden");
  $("pendingScreen").classList.add("hidden");
  $("pinScreen").classList.add("hidden");
}

function showPending(){
  $("authScreen").classList.add("hidden");
  $("app").classList.add("hidden");
  $("topbar").classList.add("hidden");
  $("pendingScreen").classList.remove("hidden");
  $("pendingUser").textContent = ME.username;

  // Poll for approval so the user gets in without refreshing.
  if(!window.__approvalPoll){
    window.__approvalPoll = setInterval(async ()=>{
      const { data } = await sb.from("profiles").select("*").eq("id", ME.id).single();
      if(data && data.approved){
        clearInterval(window.__approvalPoll); window.__approvalPoll = null;
        ME = data;
        toast("You've been approved. Welcome!","ok");
        enterApp();
      }
    }, 5000);
  }
}

function enterApp(){
  $("authScreen").classList.add("hidden");
  $("pendingScreen").classList.add("hidden");
  $("pinScreen").classList.add("hidden");
  $("app").classList.remove("hidden");
  $("topbar").classList.remove("hidden");
  $("balanceVal").textContent = fmt(ME.balance);
  if(ME.is_admin){
    $("adminBadge").classList.remove("hidden");
    $("adminTabBtn").classList.remove("hidden");
  }
  // stop the pending-approval poller if we came in via that screen
  if(window.__approvalPoll){ clearInterval(window.__approvalPoll); window.__approvalPoll = null; }

  showView("tasks");
  loadTasks();
  subscribeRealtime();
  loadSiteAvailable();
  paintFaucet();

  // guard against double-entry stacking duplicate timers
  if(!window.__appTimers){
    window.__appTimers = true;
    setInterval(loadSiteAvailable, 60000); // refresh every minute
    setInterval(paintFaucet, 1000);        // live countdown
  }
}

// ---------- faucet ----------
const FAUCET_AMOUNT = 0.0005;
const FAUCET_COOLDOWN_MS = 60 * 60 * 1000;

function faucetReadyAt(){
  if(!ME || !ME.last_faucet_at) return 0;
  return new Date(ME.last_faucet_at).getTime() + FAUCET_COOLDOWN_MS;
}

function paintFaucet(){
  const btn = $("faucetBtn"), note = $("faucetNote");
  if(!btn) return;
  const remaining = faucetReadyAt() - Date.now();
  if(remaining <= 0){
    btn.disabled = false;
    btn.textContent = `Claim ${FAUCET_AMOUNT.toFixed(4)} LTC`;
    note.textContent = "Free every hour.";
  } else {
    btn.disabled = true;
    const m = Math.floor(remaining/60000), s = Math.floor((remaining%60000)/1000);
    btn.textContent = `Next claim in ${m}:${String(s).padStart(2,"0")}`;
    note.textContent = "You've already claimed this hour.";
  }
}

async function claimFaucet(){
  const btn = $("faucetBtn");
  if(btn.disabled) return;              // mid-cooldown or already in flight
  btn.disabled = true;
  btn.textContent = "Claiming…";
  try{
    const { data, error } = await sb.rpc("claim_faucet");
    if(error) throw error;
    const row = Array.isArray(data) ? data[0] : data;
    toast(`Claimed ${fmt(row?.amount ?? FAUCET_AMOUNT)} LTC!`, "ok");
  }catch(e){
    // Surface the real reason instead of failing silently.
    toast(e?.message || "Faucet claim failed", "err");
  }finally{
    await refreshMe();
    paintFaucet();                      // always re-derives button state
  }
}

// Public on-chain balance of the payout wallet
async function loadSiteAvailable(){
  try{
    const r = await fetch(`${SUPABASE_URL}/functions/v1/wallet-balance`, {
      method:"POST",
      headers:{ "Content-Type":"application/json", "Authorization":`Bearer ${SUPABASE_ANON}` },
      body:"{}"
    });
    const d = await r.json();
    if(typeof d.balance === "number"){
      $("siteAvailVal").textContent = d.balance.toFixed(8);
    } else {
      $("siteAvailVal").textContent = "—";
    }
  }catch(e){ $("siteAvailVal").textContent = "—"; }
}

// ---------- views ----------
function showView(v){
  ["tasks","mine","admin"].forEach(x=>{
    $("view-"+x).classList.toggle("hidden", x!==v);
  });
  document.querySelectorAll("#mainTabs button").forEach(b=>{
    b.classList.toggle("active", b.dataset.view===v);
  });
  if(v==="tasks") loadTasks();
  if(v==="mine") loadMine();
  if(v==="admin") loadAdmin();
}

// ---------- tasks ----------
async function loadTasks(){
  const { data, error } = await sb.from("tasks").select("*").eq("status","open").order("created_at",{ascending:false});
  const box = $("taskList");
  if(error){ box.innerHTML = `<p class="empty">Error: ${error.message}</p>`; return; }
  if(!data.length){ box.innerHTML = `<div class="empty">No tasks available yet. Check back soon!</div>`; return; }
  box.innerHTML = data.map(t=>`
    <div class="card">
      <div class="row">
        <h3>${esc(t.title)}</h3>
        <span class="price">${fmt(t.price)} LTC</span>
      </div>
      <p class="muted" style="margin:8px 0 14px">${esc(t.description)}</p>
      <button class="btn-primary btn-sm" onclick="claimTask('${t.id}')">Claim this bounty</button>
    </div>`).join("");
}

async function claimTask(id){
  const { error } = await sb.from("tasks")
    .update({ status:"claimed", claimed_by: ME.id })
    .eq("id", id).eq("status","open");   // only if still open
  if(error){ return toast(error.message,"err"); }
  clickToast("Task claimed! Click here to check My Bounties →", ()=>showView("mine"));
  loadTasks();
}

// ---------- my bounties ----------
async function loadMine(){
  const { data:tasks } = await sb.from("tasks").select("*").eq("claimed_by", ME.id).order("created_at",{ascending:false});
  const { data:subs }  = await sb.from("submissions").select("*").eq("user_id", ME.id);
  const box = $("myList");
  if(!tasks || !tasks.length){ box.innerHTML = `<div class="empty">You haven't claimed any tasks yet.</div>`; return; }
  box.innerHTML = tasks.map(t=>{
    const sub = (subs||[]).find(s=>s.task_id===t.id);
    let action;
    if(sub){ action = `Submission: ${pill(sub.status)}`; }
    else if(t.status==="completed"){ action = pill("completed"); }
    else { action = `<button class="btn-primary btn-sm" onclick="openSubmit('${t.id}','${esc(t.title)}','${esc(t.description)}')">Upload proof & submit</button>`; }
    return `<div class="card">
      <div class="row"><h3>${esc(t.title)}</h3><span class="price">${fmt(t.price)} LTC</span></div>
      <p class="muted" style="margin:8px 0 14px">${esc(t.description)}</p>
      <div>${action}</div>
    </div>`;
  }).join("");
}

function openSubmit(taskId,title,desc){
  submitTaskId = taskId;
  $("smTitle").textContent = "Submit: " + title;
  $("smDesc").textContent = desc;
  $("smImage").value = "";
  $("submitModal").classList.remove("hidden");
}

async function submitProof(){
  const file = $("smImage").files[0];
  if(!file){ return toast("Choose an image first","err"); }
  $("smBtn").disabled = true;
  try{
    const path = `${ME.id}/${Date.now()}_${file.name}`;
    const { error:upErr } = await sb.storage.from("proofs").upload(path, file);
    if(upErr) throw upErr;
    const { data:pub } = sb.storage.from("proofs").getPublicUrl(path);
    const { error } = await sb.from("submissions").insert({
      task_id: submitTaskId, user_id: ME.id, image_url: pub.publicUrl, status:"pending"
    });
    if(error) throw error;
    toast("Submitted! Waiting on admin approval.","ok");
    closeModal("submitModal");
    loadMine();
  }catch(e){ toast(e.message,"err"); }
  $("smBtn").disabled = false;
}

// ---------- wallet / cashout ----------
async function refreshMe(){
  const { data, error } = await sb.from("profiles").select("*").eq("id", ME.id).single();
  if(error){ console.error("refreshMe failed:", error); return; }
  if(data){ ME = data; paintBalance(); paintFaucet(); }
}

// keep every balance readout in sync
function paintBalance(){
  $("balanceVal").textContent = fmt(ME.balance);
  if(!$("walletModal").classList.contains("hidden")){
    $("wmBalance").textContent = fmt(ME.balance) + " LTC";
  }
}

async function openWallet(){
  await refreshMe();
  $("wmBalance").textContent = fmt(ME.balance) + " LTC";
  renderWithdrawHistory();
  $("walletModal").classList.remove("hidden");
}

async function renderWithdrawHistory(){
  const { data:wds } = await sb.from("withdrawals").select("*").eq("user_id", ME.id).order("created_at",{ascending:false});
  if(!wds || !wds.length){
    $("wmHistory").innerHTML = `<p class="muted" style="font-size:13px">No withdrawals yet.</p>`;
    return;
  }
  const now = Date.now();
  $("wmHistory").innerHTML = wds.map(w=>{
    const created = new Date(w.created_at).getTime();
    const unlockAt = created + 5*60*1000;
    let cancelUi = "";
    if(w.status === "processing"){
      cancelUi = `<div class="muted" style="font-size:11px;margin-top:8px">Sending on-chain — cannot cancel</div>`;
    } else if(w.status === "pending"){
      if(now >= unlockAt){
        cancelUi = `<button class="btn-ghost btn-sm" style="margin-top:8px" onclick="cancelWithdraw('${w.id}')">Cancel & refund</button>`;
      } else {
        const mins = Math.ceil((unlockAt - now)/60000);
        cancelUi = `<div class="muted" style="font-size:11px;margin-top:8px">Can cancel in ~${mins} min</div>`;
      }
    }
    return `<div class="list-item">
      <div class="row"><span>${fmt(w.amount)} LTC</span>${pill(w.status)}</div>
      <div class="muted" style="font-size:12px;margin-top:6px;word-break:break-all">${esc(w.ltc_address)}</div>
      ${w.txid?`<div class="muted" style="font-size:11px;margin-top:4px">tx: ${esc(w.txid)}</div>`:""}
      ${cancelUi}
    </div>`;
  }).join("");
}

async function requestWithdraw(){
  const addr = $("wmAddress").value.trim();
  const amount = parseFloat($("wmAmount").value);
  if(!addr){ return toast("Enter your LTC address","err"); }
  if(!amount || amount<=0){ return toast("Enter a valid amount","err"); }
  if(amount > Number(ME.balance)){ return toast("Amount exceeds your balance","err"); }
  // RPC reserves the balance immediately + creates the request atomically
  const { error } = await sb.rpc("request_withdrawal", { p_amount: amount, p_address: addr });
  if(error){ return toast(error.message,"err"); }
  toast("Cashout requested! Balance reserved. Admin will review it.","ok");
  $("wmAmount").value=""; $("wmAddress").value="";
  await refreshMe();
  $("wmBalance").textContent = fmt(ME.balance) + " LTC";
  renderWithdrawHistory();
}

async function cancelWithdraw(id){
  const { error } = await sb.rpc("cancel_withdrawal", { p_id: id });
  if(error){ return toast(error.message,"err"); }
  toast("Withdrawal cancelled — funds refunded.","ok");
  await refreshMe();
  $("wmBalance").textContent = fmt(ME.balance) + " LTC";
  renderWithdrawHistory();
}

// ---------- admin ----------
async function postTask(){
  if(!ME.is_admin) return;
  const title = $("ntTitle").value.trim();
  const description = $("ntDesc").value.trim();
  const price = parseFloat($("ntPrice").value);
  if(!title||!description||!price){ return toast("Fill in all fields","err"); }
  const { error } = await sb.from("tasks").insert({ title, description, price, status:"open" });
  if(error){ return toast(error.message,"err"); }
  toast("Bounty posted!","ok");
  $("ntTitle").value=""; $("ntDesc").value=""; $("ntPrice").value="";
}

async function loadAdmin(){
  if(!ME.is_admin) return;
  loadUsers();
  // pending submissions with task + user info
  const { data:subs } = await sb.from("submissions").select("*, tasks(title,price), profiles(username)").eq("status","pending").order("created_at");
  $("adminSubs").innerHTML = (subs && subs.length) ? subs.map(s=>`
    <div class="list-item">
      <div class="row"><strong>${esc(s.tasks?.title||'?')}</strong><span class="price">${fmt(s.tasks?.price)} LTC</span></div>
      <div class="muted" style="font-size:12px;margin:4px 0 8px">by ${esc(s.profiles?.username||'?')}</div>
      ${s.image_url?`<a href="${esc(s.image_url)}" target="_blank">View proof image ↗</a>`:""}
      <div class="row" style="margin-top:12px">
        <button class="btn-green btn-sm" onclick="reviewSub('${s.id}','approve')">Approve & pay</button>
        <button class="btn-danger btn-sm" onclick="reviewSub('${s.id}','deny')">Deny</button>
      </div>
    </div>`).join("") : `<p class="muted" style="font-size:13px">No pending submissions.</p>`;

  // pending withdrawals
  const { data:wds } = await sb.from("withdrawals").select("*, profiles(username)").eq("status","pending").order("created_at");
  $("adminWds").innerHTML = (wds && wds.length) ? wds.map(w=>`
    <div class="list-item">
      <div class="row"><strong>${esc(w.profiles?.username||'?')}</strong><span class="price">${fmt(w.amount)} LTC</span></div>
      <div class="addr-box">${esc(w.ltc_address)}</div>
      <div class="row" style="margin-top:12px">
        <button class="btn-green btn-sm" onclick="reviewWd('${w.id}','approve')">Approve & send</button>
        <button class="btn-danger btn-sm" onclick="reviewWd('${w.id}','deny')">Deny</button>
      </div>
    </div>`).join("") : `<p class="muted" style="font-size:13px">No pending withdrawals.</p>`;

  loadWalletAddress();
}

// ---------- admin: users + approvals ----------
async function loadUsers(){
  const { data, error } = await sb.rpc("admin_list_users");
  if(error){
    $("adminPending").innerHTML = `<p class="muted" style="font-size:13px">Error: ${esc(error.message)}</p>`;
    $("adminUsers").innerHTML = "";
    return;
  }
  const users   = data || [];
  const pending = users.filter(u=>!u.approved);
  const badge   = $("pendingCount");

  badge.textContent = pending.length;
  badge.classList.toggle("hidden", pending.length === 0);

  $("adminPending").innerHTML = pending.length ? pending.map(u=>`
    <div class="list-item">
      <div class="row">
        <strong>${esc(u.username)}</strong>
        <span class="muted" style="font-size:12px">${new Date(u.created_at).toLocaleString()}</span>
      </div>
      <div class="row" style="margin-top:12px">
        <button class="btn-green btn-sm"  onclick="setApproval('${u.id}',true)">Approve</button>
        <button class="btn-danger btn-sm" onclick="setApproval('${u.id}',false)">Reject</button>
      </div>
    </div>`).join("") : `<p class="muted" style="font-size:13px">No sign-ups waiting.</p>`;

  $("adminUsers").innerHTML = users.length ? users.map(u=>`
    <div class="list-item">
      <div class="row">
        <span>
          <strong>${esc(u.username)}</strong>
          ${u.is_admin ? `<span class="pill pill-approved" style="margin-left:6px">admin</span>` : ""}
          ${u.approved ? "" : `<span class="pill pill-pending" style="margin-left:6px">pending</span>`}
        </span>
        <span class="price">${fmt(u.balance)} LTC</span>
      </div>
      <div class="muted" style="font-size:11px;margin-top:6px">
        joined ${new Date(u.created_at).toLocaleDateString()}
        ${u.last_faucet_at ? ` · last faucet ${new Date(u.last_faucet_at).toLocaleString()}` : ""}
      </div>
      ${u.is_admin ? "" : `<button class="btn-ghost btn-sm" style="margin-top:8px"
          onclick="setApproval('${u.id}',${!u.approved})">
          ${u.approved ? "Revoke access" : "Approve"}
        </button>`}
    </div>`).join("") : `<p class="muted" style="font-size:13px">No users yet.</p>`;
}

async function setApproval(userId, approved){
  const { error } = await sb.rpc("admin_set_approval", { p_user_id:userId, p_approved:approved });
  if(error){ return toast(error.message,"err"); }
  toast(approved ? "User approved" : "Access revoked","ok");
  loadUsers();
}

// Approving a submission credits the claimer's balance (done via edge function for safety)
async function reviewSub(id, action){
  const { data:{ session } } = await sb.auth.getSession();
  const res = await callFn("review-submission", { submission_id:id, action }, session);
  if(res.error){ return toast(res.error,"err"); }
  toast(action==="approve"?"Approved & funds credited":"Submission denied","ok");
  loadAdmin();
}

// Approving a withdrawal triggers the on-chain send
async function reviewWd(id, action){
  const { data:{ session } } = await sb.auth.getSession();
  toast("Processing…");
  const res = await callFn("review-withdrawal", { withdrawal_id:id, action }, session);
  if(res.error){ return toast(res.error,"err"); }
  toast(action==="approve"?("Sent! tx: "+(res.txid||"")):"Withdrawal denied","ok");
  loadAdmin();
}

async function loadWalletAddress(){
  try{
    const { data:{ session } } = await sb.auth.getSession();
    const res = await callFn("get-wallet-address", {}, session);
    if(res.address){ $("walletAddrBox").textContent = res.address; }
  }catch(e){ /* function not deployed yet */ }
}

// ---------- edge function helper ----------
async function callFn(name, body, session){
  try{
    const r = await fetch(`${SUPABASE_URL}/functions/v1/${name}`, {
      method:"POST",
      headers:{ "Content-Type":"application/json", "Authorization":`Bearer ${session.access_token}` },
      body: JSON.stringify(body)
    });
    return await r.json();
  }catch(e){ return { error: e.message }; }
}

// ---------- realtime (auto-update task board) ----------
function subscribeRealtime(){
  // enterApp() can run twice (e.g. pending → approved without a reload).
  // Channels must be torn down before re-registering handlers, otherwise
  // `.on()` throws "cannot add postgres_changes callbacks after subscribe()".
  sb.getChannels().forEach(ch=>{
    if(ch.topic === "realtime:rt-main" || ch.topic === "realtime:rt-admin"){
      sb.removeChannel(ch);
    }
  });

  sb.channel("rt-main")
    // task board / my bounties auto-update
    .on("postgres_changes",{ event:"*", schema:"public", table:"tasks" }, ()=>{
      const active = document.querySelector("#mainTabs button.active")?.dataset.view;
      if(active==="tasks") loadTasks();
      if(active==="mine") loadMine();
    })
    // my balance updates instantly from the pushed row
    .on("postgres_changes",{ event:"UPDATE", schema:"public", table:"profiles", filter:`id=eq.${ME.id}` }, (payload)=>{
      if(!payload.new) return;
      const wasApproved = ME.approved;
      ME = { ...ME, ...payload.new };
      paintBalance();
      paintFaucet();
      // access revoked mid-session → kick straight back to the gate
      if(wasApproved && !ME.approved){
        toast("Your access has been revoked.","err");
        showPending();
      }
    })
    // my submissions status changes → refresh My Bounties
    .on("postgres_changes",{ event:"*", schema:"public", table:"submissions", filter:`user_id=eq.${ME.id}` }, ()=>{
      const active = document.querySelector("#mainTabs button.active")?.dataset.view;
      if(active==="mine") loadMine();
    })
    // my withdrawals change → refresh wallet history if open
    .on("postgres_changes",{ event:"*", schema:"public", table:"withdrawals", filter:`user_id=eq.${ME.id}` }, ()=>{
      if(!$("walletModal").classList.contains("hidden")) renderWithdrawHistory();
    })
    .subscribe();

  // admin: live-refresh the admin panel when anything relevant changes
  if(ME.is_admin){
    sb.channel("rt-admin")
      .on("postgres_changes",{ event:"*", schema:"public", table:"submissions" }, ()=>{
        if(document.querySelector("#mainTabs button.active")?.dataset.view==="admin") loadAdmin();
      })
      .on("postgres_changes",{ event:"*", schema:"public", table:"withdrawals" }, ()=>{
        if(document.querySelector("#mainTabs button.active")?.dataset.view==="admin") loadAdmin();
      })
      // new sign-ups appear in the approval queue live
      .on("postgres_changes",{ event:"*", schema:"public", table:"profiles" }, ()=>{
        if(document.querySelector("#mainTabs button.active")?.dataset.view==="admin") loadUsers();
      })
      .subscribe();
  }
}

// ---------- util ----------
function esc(s){ return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ---------- boot ----------
switchAuth("signin");
loadSession();
sb.auth.onAuthStateChange((_e,_s)=>{ /* handled manually */ });
