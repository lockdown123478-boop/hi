// wallet-balance
// Public: returns the on-chain confirmed balance (in LTC) of the site's
// payout wallet, so users can see how much is available for withdrawals.
// Reveals only the balance — never the private key.
import { wifToAddress } from "../_shared/ltc.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
};

const EXPLORER = "https://litecoinspace.org/api";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const wif = Deno.env.get("LTC_PRIVATE_KEY_WIF");
    if (!wif) return json({ error: "Wallet not configured" }, 400);

    const address = await wifToAddress(wif);
    const r = await fetch(`${EXPLORER}/address/${address}`);
    if (!r.ok) return json({ error: "Explorer fetch failed" }, 502);
    const info = await r.json();

    // funded - spent = current balance, in litoshis → LTC
    const cs = info.chain_stats ?? {};
    const ms = info.mempool_stats ?? {};
    const confirmed = (cs.funded_txo_sum ?? 0) - (cs.spent_txo_sum ?? 0);
    const pending = (ms.funded_txo_sum ?? 0) - (ms.spent_txo_sum ?? 0);
    const balanceLtc = (confirmed) / 1e8;
    const pendingLtc = (pending) / 1e8;

    return json({ address, balance: balanceLtc, pending: pendingLtc });
  } catch (e) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status, headers: { ...cors, "Content-Type": "application/json" },
  });
}
