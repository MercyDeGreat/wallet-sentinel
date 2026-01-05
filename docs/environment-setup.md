# Environment Configuration

## Required Environment Variables

Create a `.env.local` file in the project root with the following variables:

```bash
# ============================================
# WALLET SENTINEL - ENVIRONMENT CONFIGURATION
# ============================================

# RPC Endpoints (optional - uses public defaults if not set)
# Using private RPC endpoints will provide better rate limits and reliability
ETHEREUM_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
BASE_RPC_URL=https://base-mainnet.g.alchemy.com/v2/YOUR_KEY
BNB_RPC_URL=https://bsc-dataseed.binance.org
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com

# Explorer API Keys (optional - enables higher rate limits)
ETHEREUM_EXPLORER_API_KEY=your-etherscan-api-key
BASE_EXPLORER_API_KEY=your-basescan-api-key
BNB_EXPLORER_API_KEY=your-bscscan-api-key

# Application Settings
NEXT_PUBLIC_APP_URL=http://localhost:3000
NODE_ENV=development
```

## Getting API Keys

### RPC Providers

| Provider | Free Tier | URL |
|----------|-----------|-----|
| Alchemy | 300M compute units/month | https://www.alchemy.com |
| Infura | 100K requests/day | https://infura.io |
| QuickNode | 10M API credits | https://www.quicknode.com |

### Block Explorer APIs

| Explorer | Free Tier | URL |
|----------|-----------|-----|
| Etherscan | 5 calls/sec | https://etherscan.io/apis |
| Basescan | 5 calls/sec | https://basescan.org/apis |
| BscScan | 5 calls/sec | https://bscscan.com/apis |

## Default Public Endpoints

If no environment variables are set, the application uses these public endpoints:

| Chain | RPC | Explorer API |
|-------|-----|--------------|
| Ethereum | https://eth.llamarpc.com | https://api.etherscan.io/api |
| Base | https://mainnet.base.org | https://api.basescan.org/api |
| BNB Chain | https://bsc-dataseed.binance.org | https://api.bscscan.com/api |
| Solana | https://api.mainnet-beta.solana.com | https://api.solscan.io |

**Note:** Public endpoints have rate limits. For production use, configure private RPC endpoints.







