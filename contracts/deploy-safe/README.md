# OPRF Safe Deployment

Deploy OPRF contracts through a Safe multi-sig wallet.

## Setup

```bash
cd deploy-safe
npm install
cp .env.example .env
# Edit .env with your values
```

## Usage

### Step 1: Test locally on forked Sepolia

```bash
# Terminal 1: Start Anvil fork
anvil --fork-url https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY

# Terminal 2: Run deployment
npm run deploy:local
```

This will:
- Execute the full deployment through your Safe on the fork
- Show you the deterministic addresses for all contracts
- Verify everything works before going to production

### Step 2: Propose to Sepolia

```bash
npm run deploy:sepolia
```

This will:
- Build the same transactions
- Propose them to the Safe Transaction Service
- Give you a link to share with other signers

### Step 3: Sign and execute

1. Other Safe owners open the link
2. Review and sign the transaction
3. Once threshold is met, execute

## Deterministic Addresses

Using the same `DEPLOY_SALT`, you'll get identical contract addresses on any EVM network. This is useful for:
- Cross-chain deployments
- Documentation
- Frontend configuration before deployment

## File Structure

```
deploy-safe/
├── src/
│   └── deploy.ts      # Main deployment script
├── package.json
├── tsconfig.json
├── .env.example
└── README.md
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFE_ADDRESS` | Your Safe multi-sig address |
| `SIGNER_PRIVATE_KEY` | Private key of one Safe owner |
| `THRESHOLD` | OPRF threshold (2 or 3) |
| `NUM_PEERS` | OPRF peer count (3 or 5) |
| `DEPLOY_SALT` | CREATE2 salt for deterministic addresses |
| `*_RPC_URL` | RPC endpoints for each network |
