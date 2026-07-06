// check-balances.mjs — print SUI (and any other coin) balances for one or more wallets.
//
// Usage:
//   node check-balances.mjs                    # checks the DEFAULT list below
//   node check-balances.mjs 0xabc... 0xdef...  # checks the addresses you pass
//   SUI_NETWORK=mainnet node check-balances.mjs 0xabc...   # mainnet (default: testnet)
//
// Needs @mysten/sui (already a dependency in this repo).

import { SuiGrpcClient } from '@mysten/sui/grpc';

const NETWORK = process.env.SUI_NETWORK || 'testnet';
const client = new SuiGrpcClient({ baseUrl: `https://fullnode.${NETWORK}.sui.io:443`, network: NETWORK });

// Edit this list, or pass addresses as command-line args instead.
const DEFAULT_WALLETS = [
  { name: 'deployer', address: '0x4506bc687360ba89fb1146f0e078432a691cdc374d5a77b1840fd810c3506e11' },
  { name: 'party-B',  address: '0x5010562848c713490e73e1b7be1435cb3bd2d6566a5b80beee67c68c1369d11c' },
];

const args = process.argv.slice(2);
const wallets = args.length
  ? args.map((address, i) => ({ name: `wallet-${i + 1}`, address }))
  : DEFAULT_WALLETS;

const fmt = (mist, decimals = 9) => (Number(mist) / 10 ** decimals).toLocaleString(undefined, { maximumFractionDigits: 6 });

console.log(`\nNetwork: ${NETWORK}\n`);

for (const w of wallets) {
  try {
    // SUI balance
    const res = await client.core.getBalance({ owner: w.address, coinType: '0x2::sui::SUI' });
    const sui = res.balance ?? res;
    console.log(`${w.name.padEnd(12)} ${w.address}`);
    console.log(`   SUI: ${fmt(sui.balance)}`);

    // Any other coin types held
    const lb = await client.core.listBalances({ owner: w.address });
    const all = lb.balances ?? lb;
    for (const c of all) {
      if (c.coinType.endsWith('::sui::SUI')) continue;
      const sym = c.coinType.split('::').pop();
      console.log(`   ${sym}: raw ${c.balance}  (type ${c.coinType})`);
    }
    console.log('');
  } catch (e) {
    console.log(`${w.name.padEnd(12)} ${w.address}\n   ERROR: ${e.message}\n`);
  }
}
