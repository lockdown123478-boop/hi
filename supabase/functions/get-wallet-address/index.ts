// get-wallet-address
// Returns the site's Litecoin deposit address (admin only).
// The address is derived from the WIF private key stored as a secret;
// the private key itself is NEVER returned to the client.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { wifToAddress } from "../_shared/ltc.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );
    const jwt = req.headers.get("Authorization")?.replace("Bearer ", "") ?? "";
    const { data: userData } = await admin.auth.getUser(jwt);
    if (!userData?.user) return json({ error: "Not authenticated" }, 401);
    const { data: me } = await admin.from("profiles").select("is_admin").eq("id", userData.user.id).single();
    if (!me?.is_admin) return json({ error: "Not an admin" }, 403);

    const wif = Deno.env.get("LTC_PRIVATE_KEY_WIF");
    if (!wif) return json({ error: "Wallet not configured" }, 400);

    const address = await wifToAddress(wif);
    return json({ address });
  } catch (e) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status, headers: { ...cors, "Content-Type": "application/json" },
  });
}
