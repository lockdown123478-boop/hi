// review-submission
// Admin approves/denies a proof submission. On approve, credits the
// claimer's on-site balance by the task's price. Runs server-side with
// the service_role key so it can safely mutate balances.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { submission_id, action } = await req.json();

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // verify caller is an admin
    const jwt = req.headers.get("Authorization")?.replace("Bearer ", "") ?? "";
    const { data: userData } = await admin.auth.getUser(jwt);
    if (!userData?.user) return json({ error: "Not authenticated" }, 401);
    const { data: me } = await admin.from("profiles").select("is_admin").eq("id", userData.user.id).single();
    if (!me?.is_admin) return json({ error: "Not an admin" }, 403);

    // All state changes happen inside a single SECURITY DEFINER transaction.
    // The RPC re-verifies admin, verifies the submitter actually claimed the
    // task, locks the rows, and credits atomically (no read-modify-write race).
    // We call it as the requesting user so auth.uid() is correct inside.
    const asUser = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${jwt}` } } },
    );

    if (action === "deny") {
      const { error } = await asUser.rpc("admin_deny_submission", {
        p_submission_id: submission_id,
      });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    const { data: credited, error } = await asUser.rpc("admin_approve_submission", {
      p_submission_id: submission_id,
    });
    if (error) return json({ error: error.message }, 400);

    return json({ ok: true, credited: Number(credited) });
  } catch (e) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}
