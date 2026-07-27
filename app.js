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
function fmt(n) { return Number(n || 0).toFixed(8); }
function pill(status) {
  const map = { open:"pill-open", claimed:"pill-claimed", completed:"pill-approved",
    pending:"pill-pending", approved:"pill-approved", denied:"pill-denied",
    sent:"pill-approved", failed:"pill-denied" };
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
  enterApp();
}

function showAuth(){
  $("authScreen").classList.remove("hidden");
  $("app").classList.add("hidden");
  $("topbar").classList.add("hidden");
}

function enterApp(){
  $("authScreen").classList.add("hidden");
  $("app").classList.remove("hidden");
  $("topbar").classList.remove("hidden");
  $("balanceVal").textContent = fmt(ME.balance);
  if(ME.is_admin){
    $("adminBadge").classList.remove("hidden");
    $("adminTabBtn").classList.remove("hidden");
  }
  showView("tasks");
  loadTasks();
  subscribeRealtime();
  loadSiteAvailable();
  setInterval(loadSiteAvailable, 60000); // refresh every minute
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
  toast("Task claimed! Find it under My Bounties.","ok");
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
  const { data } = await sb.from("profiles").select("*").eq("id", ME.id).single();
  if(data){ ME = data; $("balanceVal").textContent = fmt(ME.balance); }
}

async function openWallet(){
  await refreshMe();
  $("wmBalance").textContent = fmt(ME.balance) + " LTC";
  const { data:wds } = await sb.from("withdrawals").select("*").eq("user_id", ME.id).order("created_at",{ascending:false});
  $("wmHistory").innerHTML = (wds && wds.length)
    ? wds.map(w=>`<div class="list-item"><div class="row"><span>${fmt(w.amount)} LTC</span>${pill(w.status)}</div>
        <div class="muted" style="font-size:12px;margin-top:6px;word-break:break-all">${esc(w.ltc_address)}</div>
        ${w.txid?`<div class="muted" style="font-size:11px;margin-top:4px">tx: ${esc(w.txid)}</div>`:""}</div>`).join("")
    : `<p class="muted" style="font-size:13px">No withdrawals yet.</p>`;
  $("walletModal").classList.remove("hidden");
}

async function requestWithdraw(){
  const addr = $("wmAddress").value.trim();
  const amount = parseFloat($("wmAmount").value);
  if(!addr){ return toast("Enter your LTC address","err"); }
  if(!amount || amount<=0){ return toast("Enter a valid amount","err"); }
  if(amount > Number(ME.balance)){ return toast("Amount exceeds your balance","err"); }
  const { error } = await sb.from("withdrawals").insert({
    user_id: ME.id, amount, ltc_address: addr, status:"pending"
  });
  if(error){ return toast(error.message,"err"); }
  toast("Cashout requested! Admin will review it.","ok");
  $("wmAmount").value=""; $("wmAddress").value="";
  openWallet();
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
  sb.channel("public-tasks")
    .on("postgres_changes",{ event:"*", schema:"public", table:"tasks" }, ()=>{
      const active = document.querySelector("#mainTabs button.active")?.dataset.view;
      if(active==="tasks") loadTasks();
      if(active==="mine") loadMine();
    })
    .on("postgres_changes",{ event:"*", schema:"public", table:"profiles", filter:`id=eq.${ME.id}` }, refreshMe)
    .subscribe();
}

// ---------- util ----------
function esc(s){ return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ---------- boot ----------
switchAuth("signin");
loadSession();
sb.auth.onAuthStateChange((_e,_s)=>{ /* handled manually */ });
