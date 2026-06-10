# Yale — Deployment record

## Testnet — first deploy
- **Network:** Sui Testnet
- **PackageID:** `0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff`
- **Module:** `access`
- **UpgradeCap:** `0x3b766882846ac4e94fa7e1f6913eda8344b664ed574d24d25fecf9e06e93c4b8` (owned by deployer — needed to upgrade the package)
- **Deployer address:** `0x4506bc687360ba89fb1146f0e078432a691cdc374d5a77b1840fd810c3506e11`
- **Publish tx digest:** `7h6ux18U3hoPpsxRW2VenJ8Nvq7TH8g8f1DwuxkTjnKi`
- **Gas spent:** ~0.0252 SUI (testnet, free)

### View it
- Explorer (object): https://suiscan.xyz/testnet/object/0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff
- or: https://testnet.suivision.xyz/package/0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff

### Call it (create a real AccessPolicy token)
`mint(mode, expiry_ms, max_opens, watermark_seed, clock, ctx)` — Clock is the system object `0x6`.
```bash
sui client call \
  --package 0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff \
  --module access --function mint \
  --args 0 0 0 "[1,2,3,4]" 0x6 \
  --gas-budget 100000000
```
(mode 0 = bearer, expiry 0 = never, max_opens 0 = unlimited, watermark seed = sample bytes.)
Creates a shared `AccessPolicy` + transfers an `OwnerCap` to you.

> Testnet wallet recovery phrase is a throwaway with no value. A mainnet wallet's phrase would never be stored or shared.
