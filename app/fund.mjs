// One-shot dev script: send 1 testnet SUI from the old funded wallet to the new
// zkLogin address. Testnet-only throwaway wallet — never reuse this pattern with
// real funds. Run from mac-app/:  node fund.mjs
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";

const FUNDED_PHRASE = "electric indoor grid raw wage proof obvious cheese sniff baby rubber window";
const TO = "0x75b694d88ddb6a536db0ebcaedaffd35ad4f64b546935a4943d3acec6fed5e23";
const AMOUNT = 500_000_000n; // 0.5 SUI

const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl("testnet"), network: "testnet" });
const kp = Ed25519Keypair.deriveKeypair(FUNDED_PHRASE);
console.log("from:", kp.toSuiAddress());
const fromBal = await client.getBalance({ owner: kp.toSuiAddress() });
console.log("from balance:", Number(fromBal.totalBalance) / 1e9, "SUI");

const tx = new Transaction();
const [coin] = tx.splitCoins(tx.gas, [AMOUNT]);
tx.transferObjects([coin], TO);

const res = await client.signAndExecuteTransaction({ signer: kp, transaction: tx, options: { showEffects: true } });
await client.waitForTransaction({ digest: res.digest });
console.log("status:", JSON.stringify(res.effects?.status), "digest:", res.digest);
const bal = await client.getBalance({ owner: TO });
console.log("zkLogin address balance:", Number(bal.totalBalance) / 1e9, "SUI");
