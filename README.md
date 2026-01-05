# 🛡️ Wallet Sentinel

**Blockchain Security Analysis Platform**

A production-ready web application for comprehensive wallet security analysis. Detect threats, protect assets, and recover safely across Ethereum, Base, BNB Chain, and Solana.

![Wallet Sentinel](https://img.shields.io/badge/Security-Defensive%20Only-green)
![Chains](https://img.shields.io/badge/Chains-ETH%20%7C%20Base%20%7C%20BNB%20%7C%20SOL-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ⚠️ Important Disclaimer

**Wallet Sentinel is a DEFENSIVE security tool only.**

- ✅ Detection, containment, recovery, and education
- ❌ No hacking, retaliation, or exploit development
- ❌ No wallet custody or private key handling
- ❌ No automatic wallet connections
- ✅ All operations are read-only or require explicit user approval

---

## 🚀 Features

### 1. Wallet Compromise Detection Engine
- Scans transaction history for known drainer patterns
- Detects approval abuse (ERC-20, ERC-721, ERC-1155)
- Identifies infinite approvals and suspicious contract interactions
- Compares against malicious contract databases
- Assigns clear security status: ✅ SAFE | ⚠️ AT RISK | 🚨 COMPROMISED

### 2. Attack Type Identification
- Wallet Drainer
- Approval Hijack
- Private Key Leak (behavioral inference)
- Phishing Signature Abuse
- Malicious NFT Airdrop
- Compromised Solana Program Authority
- MEV Sandwich Drain

### 3. Live Risk Monitoring
- Active malicious approvals
- Drainer callbacks detection
- Pending suspicious transactions
- Time-sensitive action alerts

### 4. Recovery & Containment Toolkit
- Approval revocation dashboard
- Asset containment planning
- Transaction simulation (drainer interception detection)
- Solana-specific: program authority checks, token account closures

### 5. Security Hardening Education
- Attack explanations
- Prevention tips
- Chain-specific best practices
- Interactive security checklist

---

## 🔧 Tech Stack

| Component | Technology |
|-----------|------------|
| Frontend | Next.js 14, React 18, TypeScript |
| Styling | Tailwind CSS, Framer Motion |
| Backend | Next.js API Routes |
| Blockchain | ethers.js v6, @solana/web3.js |
| Icons | Lucide React |

---

## 📁 Project Structure

```
wallet-sentinel/
├── src/
│   ├── app/                      # Next.js App Router
│   │   ├── api/
│   │   │   ├── analyze/          # Wallet analysis endpoint
│   │   │   └── simulate/         # Transaction simulation
│   │   ├── globals.css           # Global styles
│   │   ├── layout.tsx            # Root layout
│   │   └── page.tsx              # Main page
│   ├── components/               # React components
│   │   ├── Header.tsx
│   │   ├── WalletInput.tsx
│   │   ├── LoadingState.tsx
│   │   ├── SecurityDashboard.tsx
│   │   ├── ThreatCard.tsx
│   │   ├── ApprovalsDashboard.tsx
│   │   ├── RecoveryPlan.tsx
│   │   └── EducationalPanel.tsx
│   ├── lib/
│   │   ├── analyzers/            # Chain-specific analyzers
│   │   │   ├── evm-analyzer.ts   # Ethereum, Base, BNB
│   │   │   └── solana-analyzer.ts
│   │   └── detection/            # Detection engine
│   │       ├── detection-engine.ts
│   │       └── malicious-database.ts
│   └── types/                    # TypeScript definitions
│       └── index.ts
├── package.json
├── tsconfig.json
├── tailwind.config.ts
├── next.config.js
└── README.md
```

---

## 🏃 Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
# Clone the repository
cd wallet-sentinel

# Install dependencies
npm install

# Set up environment variables (optional)
cp .env.example .env.local

# Start development server
npm run dev
```

### Environment Variables (Optional)

```env
# RPC Endpoints (uses public defaults if not set)
ETHEREUM_RPC_URL=https://your-ethereum-rpc.com
BASE_RPC_URL=https://your-base-rpc.com
BNB_RPC_URL=https://your-bnb-rpc.com
SOLANA_RPC_URL=https://your-solana-rpc.com

# Explorer API Keys (for enhanced rate limits)
ETHEREUM_EXPLORER_API_KEY=your-etherscan-key
BASE_EXPLORER_API_KEY=your-basescan-key
BNB_EXPLORER_API_KEY=your-bscscan-key
```

---

## 📡 API Reference

### POST `/api/analyze`

Analyze a wallet address for security threats.

**Request:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f...",
  "chain": "ethereum"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "address": "0x742d35cc6634c0532925a3b844bc9e7595f...",
    "chain": "ethereum",
    "timestamp": "2024-01-15T12:00:00.000Z",
    "securityStatus": "AT_RISK",
    "riskScore": 45,
    "summary": "2 potential security concerns detected...",
    "detectedThreats": [...],
    "approvals": [...],
    "suspiciousTransactions": [...],
    "recommendations": [...],
    "recoveryPlan": {...},
    "educationalContent": {...}
  },
  "timestamp": "2024-01-15T12:00:00.000Z"
}
```

### POST `/api/simulate`

Simulate a transaction to check for drainer interception.

**Request:**
```json
{
  "chain": "ethereum",
  "from": "0x...",
  "to": "0x...",
  "data": "0x...",
  "value": "0x0"
}
```

---

## 🔒 Security Architecture

### Read-Only Operations
- All blockchain queries use public RPC endpoints
- No private keys are ever requested or stored
- Transaction signing requires explicit user action via their own wallet

### Rate Limiting
- API endpoints are rate-limited (10 requests/minute per IP)
- Protects against abuse while allowing legitimate use

### Privacy-First
- No user data is stored
- Wallet addresses are not logged
- Analysis is performed client-side when possible

---

## 🎨 UI/UX Design Principles

- **Dark, professional security-focused theme**
- **Clear warnings with confidence indicators**
- **Non-technical language with optional advanced view**
- **Trust-building tone** (no fear-mongering)
- **Staggered animations** for polished feel
- **Responsive design** for all devices

---

## 🛠️ Extending the Platform

### Adding a New Chain

1. Create analyzer in `src/lib/analyzers/`
2. Add chain config to `malicious-database.ts`
3. Update `Chain` type in `src/types/index.ts`
4. Add chain option in `WalletInput.tsx`

### Adding Detection Patterns

1. Add pattern to `DRAINER_PATTERNS` in `malicious-database.ts`
2. Implement detection logic in `detection-engine.ts`
3. Map to `AttackType` enum

### Updating Malicious Database

The malicious contract database can be extended by:
- Adding entries to `KNOWN_MALICIOUS_CONTRACTS`
- Integrating with external APIs (ScamSniffer, Forta, ChainAbuse)

---

## 📝 Legal Notices

### No Warranty
This software is provided "as is" without warranty of any kind. Use at your own risk.

### Not Financial Advice
Wallet Sentinel provides security analysis for educational purposes only. It does not constitute financial, legal, or security advice.

### Liability
The developers are not responsible for any losses incurred through the use of this software.

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📜 License

MIT License - see LICENSE file for details.

---

## 🔗 Resources

- [Revoke.cash](https://revoke.cash) - Token approval checker
- [Etherscan](https://etherscan.io) - Ethereum explorer
- [ScamSniffer](https://scamsniffer.io) - Scam detection
- [ChainAbuse](https://www.chainabuse.com) - Report malicious addresses
- [Forta Network](https://forta.org) - Threat detection

---

**Built with 🛡️ for the Web3 community**







