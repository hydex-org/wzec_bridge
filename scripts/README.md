# wZEC Bridge Scripts

Helper scripts for deploying and interacting with the wzec_bridge program on Solana.

## Scripts

### `deploy-testnet.ts`

Deploys the wzec_bridge program to Solana testnet and initializes all configuration.

**Usage:**
```bash
yarn deploy:testnet
# or
ts-node scripts/deploy-testnet.ts
```

**What it does:**
1. Checks wallet balance (needs at least 0.5 SOL)
2. Derives all Program Derived Addresses (PDAs)
3. Creates wZEC mint
4. Initializes bridge configuration
5. Saves deployment info to `deployments/testnet.json`

**Requirements:**
- `.env` file with configuration (see DEPLOYMENT.md)
- Solana wallet configured for testnet
- At least 0.5 SOL in wallet

### `interact.ts`

Interactive script for testing and managing the deployed bridge.

**Usage:**
```bash
yarn interact <command> [args]
# or
ts-node scripts/interact.ts <command> [args]
```

**Commands:**

#### `info`
Shows current bridge configuration and status.

```bash
yarn interact info
```

#### `create-deposit`
Creates a new deposit intent for your wallet.

```bash
yarn interact create-deposit
```

Returns a deposit ID and PDA. You then need to call the bridge-custody API to get your Zcash deposit address.

#### `demo-mint <amount>`
Mints test wZEC tokens (admin only). Useful for testing withdrawals.

```bash
# Mint 1 wZEC
yarn interact demo-mint 1

# Mint 10 wZEC
yarn interact demo-mint 10
```

#### `balance [address]`
Checks wZEC token balance.

```bash
# Check your balance
yarn interact balance

# Check specific address
yarn interact balance AbC123...xyz
```

## Examples

### Full Deposit Test Flow

```bash
# 1. Deploy to testnet
yarn deploy:testnet

# 2. Check bridge info
yarn interact info

# 3. Create deposit intent
yarn interact create-deposit
# Note the deposit ID

# 4. Get Zcash address from bridge-custody
# POST http://localhost:3001/api/deposit-address
# { "solana_pubkey": "YOUR_WALLET_PUBKEY" }

# 5. Send testnet ZEC to that address

# 6. Wait for scanner to detect deposit

# 7. Check wZEC balance
yarn interact balance
```

### Test Withdrawal Flow

```bash
# 1. Mint test wZEC
yarn interact demo-mint 5

# 2. Check balance
yarn interact balance

# 3. Burn wZEC for withdrawal (requires Arcium + MPC integration)
# This is handled by the frontend or custom script
```

## Deployment Files

After deployment, the following file is created:

### `deployments/testnet.json`

Contains all important addresses and configuration:

```json
{
  "programId": "HefTNtytDcQgSQmBpPuwjGipbVcJTMRHnppU9poWRXhD",
  "bridgeConfig": "ABC...",
  "wzecMint": "XYZ...",
  "mintAuthority": "DEF...",
  "admin": "GHI...",
  "enclaveAuthority": "JKL...",
  "deployedAt": "2024-01-15T10:30:00.000Z",
  "transaction": "...",
  "network": "testnet"
}
```

Use these addresses to configure other components:
- Frontend: Program ID, Bridge Config, wZEC Mint
- MPC Nodes: Program ID, Bridge Config
- Scanner: Program ID for event listening

## Troubleshooting

### "insufficient funds" error
Request SOL from testnet faucet:
```bash
solana airdrop 2 --url testnet
```

### "Account already in use"
Bridge is already initialized. Use `yarn interact info` to view current config.

### "custom program error"
Check that you're using the correct network and PDAs are derived properly.

### Script won't run
Make sure dependencies are installed:
```bash
yarn install
```

### Can't find deployment file
Run `yarn deploy:testnet` first to create the deployment.

## Adding New Scripts

To add a new interaction script:

1. Create `scripts/my-script.ts`
2. Add to `package.json`:
   ```json
   "scripts": {
     "my-script": "ts-node scripts/my-script.ts"
   }
   ```
3. Run with: `yarn my-script`

## See Also

- [DEPLOYMENT.md](../DEPLOYMENT.md) - Full deployment guide
- [README.md](../README.md) - Project overview
- [Anchor Docs](https://www.anchor-lang.com/) - Anchor framework

