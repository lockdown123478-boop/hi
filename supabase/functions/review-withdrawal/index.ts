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

    // admin check
    const jwt = req.headers.get("Authorization")?.replace("Bearer ", "") ?? "";
    const { data: userData } = await admin.auth.getUser(jwt);
    if (!userData?.user) return json({ error: "Not authenticated" }, 401);
    const { data: me } = await admin.from("profiles").select("is_admin").eq("id", userData.user.id).single();
    if (!me?.is_admin) return json({ error: "Not an admin" }, 403);

    const { data: wd } = await admin.from("withdrawals").select("*").eq("id", withdrawal_id).single();
    if (!wd) return json({ error: "Withdrawal not found" }, 404);
    if (wd.status !== "pending") return json({ error: "Already reviewed" }, 400);

    // NOTE: balance was already reserved (deducted) when the user requested.
    if (action === "deny") {
      // refund the reserved amount
      const { data: u } = await admin.from("profiles").select("balance").eq("id", wd.user_id).single();
      await admin.from("profiles").update({ balance: Number(u.balance) + Number(wd.amount) }).eq("id", wd.user_id);
      await admin.from("withdrawals").update({ status: "denied" }).eq("id", withdrawal_id);
      return json({ ok: true });
    }

    const wif = Deno.env.get("LTC_PRIVATE_KEY_WIF");
    if (!wif) return json({ error: "Wallet not configured" }, 400);

    // send on-chain (balance already reserved, so we do NOT deduct again)
    let txid: string;
    try {
      txid = await sendLitecoin(wif, wd.ltc_address, Number(wd.amount));
    } catch (e) {
      // send failed → refund the reservation so the user isn't out of pocket
      const { data: u } = await admin.from("profiles").select("balance").eq("id", wd.user_id).single();
      await admin.from("profiles").update({ balance: Number(u.balance) + Number(wd.amount) }).eq("id", wd.user_id);
      await admin.from("withdrawals").update({ status: "failed" }).eq("id", withdrawal_id);
      return json({ error: "Send failed (refunded): " + String(e?.message ?? e) }, 500);
    }

    await admin.from("withdrawals").update({ status: "sent", txid }).eq("id", withdrawal_id);
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
