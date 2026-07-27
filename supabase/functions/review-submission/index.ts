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

    // load submission + its task
    const { data: sub } = await admin.from("submissions").select("*, tasks(price)").eq("id", submission_id).single();
    if (!sub) return json({ error: "Submission not found" }, 404);
    if (sub.status !== "pending") return json({ error: "Already reviewed" }, 400);

    if (action === "deny") {
      await admin.from("submissions").update({ status: "denied" }).eq("id", submission_id);
      return json({ ok: true });
    }

    // approve → credit balance + mark task completed
    const price = Number(sub.tasks.price);
    const { data: claimer } = await admin.from("profiles").select("balance").eq("id", sub.user_id).single();
    const newBalance = Number(claimer.balance) + price;

    await admin.from("profiles").update({ balance: newBalance }).eq("id", sub.user_id);
    await admin.from("submissions").update({ status: "approved" }).eq("id", submission_id);
    await admin.from("tasks").update({ status: "completed" }).eq("id", sub.task_id);

    return json({ ok: true, credited: price });
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
