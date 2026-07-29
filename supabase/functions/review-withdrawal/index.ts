// review-withdrawal
// Admin approves/denies a cashout. On approve, builds + signs + broadcasts
// a real Litecoin transaction paying the user's address, then debits their
// on-site balance. The private key lives only in the LTC_PRIVATE_KEY_WIF
// secret and never leaves the server.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { sendLitecoin } from "../_shared/ltc.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { withdrawal_id, action } = await req.json();
    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // OWNER check — payouts move real Litecoin, so this is restricted to the
    // single owner account, not merely anyone holding is_admin. The RPCs
    // below re-check is_owner() independently; this is defence in depth.
    const jwt = req.headers.get("Authorization")?.replace("Bearer ", "") ?? "";
    const { data: userData } = await admin.auth.getUser(jwt);
    if (!userData?.user) return json({ error: "Not authenticated" }, 401);
    const { data: me } = await admin
      .from("profiles").select("username, is_admin, approved")
      .eq("id", userData.user.id).single();
    if (!me?.is_admin || !me?.approved || String(me?.username).toLowerCase() !== "snowy") {
      return json({ error: "Only the owner account may review payouts" }, 403);
    }

    // Call RPCs as the requesting user so auth.uid() resolves inside them.
    const asUser = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${jwt}` } } },
    );

    // NOTE: balance was already reserved (deducted) when the user requested.
    if (action === "deny") {
      const { error } = await asUser.rpc("admin_refund_withdrawal", {
        p_id: withdrawal_id,
        p_status: "denied",
      });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    const wif = Deno.env.get("LTC_PRIVATE_KEY_WIF");
    if (!wif) return json({ error: "Wallet not configured" }, 400);

    // Atomically flip pending -> processing. Only ONE caller can win this
    // race, so a double-click can never broadcast two on-chain sends.
    const { data: wd, error: lockErr } = await asUser.rpc("admin_lock_withdrawal", {
      p_id: withdrawal_id,
    });
    if (lockErr || !wd) return json({ error: lockErr?.message ?? "Already reviewed" }, 400);

    // send on-chain (balance already reserved, so we do NOT deduct again)
    let txid: string;
    try {
      txid = await sendLitecoin(wif, wd.ltc_address, Number(wd.amount));
    } catch (e) {
      // send failed → refund the reservation so the user isn't out of pocket
      await asUser.rpc("admin_refund_withdrawal", {
        p_id: withdrawal_id,
        p_status: "failed",
      });
      return json({ error: "Send failed (refunded): " + String(e?.message ?? e) }, 500);
    }

    const { error: doneErr } = await asUser.rpc("admin_complete_withdrawal", {
      p_id: withdrawal_id,
      p_txid: txid,
    });
    // The coin is already sent; a bookkeeping failure here must be loud.
    if (doneErr) {
      return json({
        ok: true,
        txid,
        warning: "SENT ON-CHAIN but failed to mark as sent — reconcile manually: " + doneErr.message,
      });
    }
    return json({ ok: true, txid });
  } catch (e) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status, headers: { ...cors, "Content-Type": "application/json" },
  });
}
