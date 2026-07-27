// _shared/ltc.ts
// Minimal Litecoin wallet utilities for Deno edge functions.
// Uses bitcoinjs-lib with Litecoin network params, ecpair for signing,
// and a public explorer (Blockstream-style Litecoin API) for UTXOs +
// broadcast. Amounts are in LTC (converted to litoshis internally).

import * as bitcoin from "https://esm.sh/bitcoinjs-lib@6.1.5";
import ECPairFactory from "https://esm.sh/ecpair@2.1.0";
import * as ecc from "https://esm.sh/@bitcoinerlab/secp256k1@1.1.1";

const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);

// Litecoin mainnet parameters
const litecoin: bitcoin.networks.Network = {
  messagePrefix: "\x19Litecoin Signed Message:\n",
  bech32: "ltc",
  bip32: { public: 0x019da462, private: 0x019d9cfe },
  pubKeyHash: 0x30, // L addresses
  scriptHash: 0x32, // M addresses
  wif: 0xb0,
};

// A public Litecoin REST explorer (Blockstream-compatible / Litecoinspace).
const EXPLORER = "https://litecoinspace.org/api";

/** Derive a native segwit (ltc1...) address from a WIF private key. */
export async function wifToAddress(wif: string): Promise<string> {
  const kp = ECPair.fromWIF(wif, litecoin);
  const { address } = bitcoin.payments.p2wpkh({
    pubkey: kp.publicKey,
    network: litecoin,
  });
  if (!address) throw new Error("Could not derive address");
  return address;
}

interface Utxo { txid: string; vout: number; value: number; }

async function getUtxos(address: string): Promise<Utxo[]> {
  const r = await fetch(`${EXPLORER}/address/${address}/utxo`);
  if (!r.ok) throw new Error("Explorer UTXO fetch failed");
  return await r.json();
}

async function getRawTx(txid: string): Promise<string> {
  const r = await fetch(`${EXPLORER}/tx/${txid}/hex`);
  if (!r.ok) throw new Error("Explorer raw-tx fetch failed");
  return await r.text();
}

async function broadcast(hex: string): Promise<string> {
  const r = await fetch(`${EXPLORER}/tx`, { method: "POST", body: hex });
  const txt = await r.text();
  if (!r.ok) throw new Error("Broadcast failed: " + txt);
  return txt.trim(); // returns txid
}

const LITOSHI = 1e8;
const FEE_RATE = 15; // litoshis per vbyte — conservative for fast confirm

/**
 * Send `amountLtc` from the WIF's address to `toAddress`.
 * Returns the broadcast txid. Uses P2WPKH inputs.
 */
export async function sendLitecoin(
  wif: string,
  toAddress: string,
  amountLtc: number,
): Promise<string> {
  const kp = ECPair.fromWIF(wif, litecoin);
  const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: kp.publicKey, network: litecoin });
  const fromAddress = p2wpkh.address!;
  const amount = Math.round(amountLtc * LITOSHI);

  const utxos = await getUtxos(fromAddress);
  if (!utxos.length) throw new Error("No funds in payout wallet");

  // rough fee estimate: assume ~110 vbytes per input + 2 outputs (~70)
  const psbt = new bitcoin.Psbt({ network: litecoin });
  let inputTotal = 0;
  const chosen: Utxo[] = [];
  for (const u of utxos.sort((a, b) => b.value - a.value)) {
    chosen.push(u);
    inputTotal += u.value;
    const estVbytes = chosen.length * 110 + 70;
    if (inputTotal >= amount + estVbytes * FEE_RATE) break;
  }

  const vbytes = chosen.length * 110 + 70;
  const fee = vbytes * FEE_RATE;
  if (inputTotal < amount + fee) throw new Error("Insufficient funds (incl. fee)");

  for (const u of chosen) {
    psbt.addInput({
      hash: u.txid,
      index: u.vout,
      witnessUtxo: { script: p2wpkh.output!, value: u.value },
    });
  }

  psbt.addOutput({ address: toAddress, value: amount });
  const change = inputTotal - amount - fee;
  if (change > 1000) psbt.addOutput({ address: fromAddress, value: change });

  psbt.signAllInputs(kp);
  psbt.finalizeAllInputs();
  const hex = psbt.extractTransaction().toHex();
  return await broadcast(hex);
}

/** Generate a brand-new random Litecoin wallet. Returns WIF + address. */
export function generateWallet(): { wif: string; address: string } {
  const kp = ECPair.makeRandom({ network: litecoin });
  const { address } = bitcoin.payments.p2wpkh({ pubkey: kp.publicKey, network: litecoin });
  return { wif: kp.toWIF(), address: address! };
}
