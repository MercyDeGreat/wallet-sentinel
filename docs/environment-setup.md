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

---

## Threat Intelligence Environment Configuration

Securnex supports multiple off-chain threat intelligence providers through a unified abstraction layer. This system powers:

- **Off-Chain Threat Intelligence (OTTI)** — Aggregates phishing, impersonation, and scam campaign signals from external security providers.
- **Threat Context Graph (TCG)** — Maps relationships between addresses, domains, and campaigns for deeper threat analysis.

The architecture is provider-agnostic: no single vendor is required, and new providers can be added without modifying core logic.

---

### Core Variables

These variables control the overall behavior of the threat intelligence subsystem.

```bash
# ============================================
# THREAT INTELLIGENCE - CORE CONFIGURATION
# ============================================

# Master toggle for threat intelligence features
# When false, all OTTI and TCG functionality is disabled
THREAT_INTEL_ENABLED=true

# How often to refresh cached threat signals (in minutes)
# Lower values = fresher data, higher API usage
THREAT_INTEL_REFRESH_INTERVAL_MINUTES=360

# Minimum confidence score (0-100) required to surface a signal
# Signals below this threshold are stored but not displayed
THREAT_INTEL_CONFIDENCE_THRESHOLD=40

# Number of days before a signal's confidence begins to decay
# After this period, confidence decreases linearly until expiration
THREAT_INTEL_SIGNAL_DECAY_DAYS=90

# Maximum evidence items stored per wallet address
# Prevents unbounded storage growth from high-volume targets
THREAT_INTEL_MAX_EVIDENCE_PER_WALLET=50
```

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `THREAT_INTEL_ENABLED` | boolean | `false` | Master toggle for all threat intel features |
| `THREAT_INTEL_REFRESH_INTERVAL_MINUTES` | number | `360` | Cache refresh interval |
| `THREAT_INTEL_CONFIDENCE_THRESHOLD` | number | `40` | Minimum confidence to display signals |
| `THREAT_INTEL_SIGNAL_DECAY_DAYS` | number | `90` | Days before signal confidence decay begins |
| `THREAT_INTEL_MAX_EVIDENCE_PER_WALLET` | number | `50` | Max stored evidence items per address |

---

### Provider-Level Configuration (Modular)

Each threat intelligence provider follows a consistent naming convention. This allows new providers to be added without code changes—simply add the environment variables.

#### Generic Provider Template

```bash
# Provider template (replace <NAME> with provider identifier)
PROVIDER_<NAME>_ENABLED=true|false
PROVIDER_<NAME>_API_KEY=<secret>
PROVIDER_<NAME>_BASE_URL=https://api.provider.example/v1
PROVIDER_<NAME>_TIMEOUT_MS=5000
PROVIDER_<NAME>_CONFIDENCE_WEIGHT=1.0
```

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `PROVIDER_<NAME>_ENABLED` | boolean | Yes | Enable/disable this provider |
| `PROVIDER_<NAME>_API_KEY` | string | Yes | API key (never logged) |
| `PROVIDER_<NAME>_BASE_URL` | string | No | Override default endpoint |
| `PROVIDER_<NAME>_TIMEOUT_MS` | number | No | Request timeout (default: 5000) |
| `PROVIDER_<NAME>_CONFIDENCE_WEIGHT` | number | No | Weight multiplier for confidence scoring (default: 1.0) |

#### Adding New Providers

To add a new provider (e.g., TRM Labs, Chainalysis), simply define its environment variables following the pattern above. No code changes required.

Example for a hypothetical compliance provider:

```bash
PROVIDER_COMPLIANCE_INTEL_ENABLED=true
PROVIDER_COMPLIANCE_INTEL_API_KEY=your-api-key
PROVIDER_COMPLIANCE_INTEL_BASE_URL=https://api.compliance-provider.example/v2
PROVIDER_COMPLIANCE_INTEL_TIMEOUT_MS=8000
PROVIDER_COMPLIANCE_INTEL_CONFIDENCE_WEIGHT=0.8
```

---

### Example Provider Configuration

Below is an example configuration for a phishing intelligence provider. This does not imply exclusivity or endorsement of any specific vendor.

```bash
# ============================================
# EXAMPLE: PHISHING INTELLIGENCE PROVIDER
# ============================================

# Enable phishing intelligence signals
PROVIDER_PHISHING_INTEL_ENABLED=true

# API key (keep secret, never log)
PROVIDER_PHISHING_INTEL_API_KEY=pk_live_xxxxxxxxxxxxxxxx

# Optional: Override base URL for staging/testing
# PROVIDER_PHISHING_INTEL_BASE_URL=https://api.example.com/v1

# Request timeout in milliseconds
PROVIDER_PHISHING_INTEL_TIMEOUT_MS=5000

# Confidence weight (0.0-1.0)
# Higher weight = more influence on overall risk score
PROVIDER_PHISHING_INTEL_CONFIDENCE_WEIGHT=0.6
```

---

### Threat Context Graph (TCG) Configuration

The Threat Context Graph maps relationships between addresses, domains, and campaigns. These variables control graph behavior and performance.

```bash
# ============================================
# THREAT CONTEXT GRAPH (TCG) CONFIGURATION
# ============================================

# Enable Threat Context Graph features
TCG_ENABLED=true

# Maximum nodes in a single graph query
# Higher values = more complete graphs, higher memory usage
TCG_MAX_NODES=500

# Maximum edges in a single graph query
# Prevents runaway graph expansion from highly-connected entities
TCG_MAX_EDGES=2000

# Time window for campaign clustering (in days)
# Addresses active within this window may be grouped into campaigns
TCG_CAMPAIGN_CLUSTER_WINDOW_DAYS=30

# Minimum address reuse count to flag as potential campaign
# Lower values = more sensitive detection, more false positives
TCG_MIN_REUSE_THRESHOLD=3

# Graph cache TTL in minutes
# Cached graphs reduce computation for repeated queries
TCG_GRAPH_CACHE_TTL_MINUTES=60
```

| Variable | Type | Default | Effect |
|----------|------|---------|--------|
| `TCG_ENABLED` | boolean | `false` | Master toggle for graph features |
| `TCG_MAX_NODES` | number | `500` | Controls graph size / memory usage |
| `TCG_MAX_EDGES` | number | `2000` | Prevents graph explosion |
| `TCG_CAMPAIGN_CLUSTER_WINDOW_DAYS` | number | `30` | Timeline grouping for campaign detection |
| `TCG_MIN_REUSE_THRESHOLD` | number | `3` | Sensitivity for campaign classification |
| `TCG_GRAPH_CACHE_TTL_MINUTES` | number | `60` | Performance optimization |

---

### Cache Configuration

```bash
# ============================================
# THREAT INTEL CACHE CONFIGURATION
# ============================================

# Enable caching (strongly recommended for production)
THREAT_INTEL_CACHE_ENABLED=true

# Cache backend: 'memory' or 'redis'
# Use 'redis' for distributed deployments
THREAT_INTEL_CACHE_BACKEND=memory

# Cache TTL for threat signals (in seconds)
# Default: 6 hours (21600 seconds)
THREAT_INTEL_CACHE_TTL=21600

# Cache TTL for clean (no-threat) results (in seconds)
# Default: 24 hours (86400 seconds)
THREAT_INTEL_CLEAN_CACHE_TTL=86400

# Redis connection URL (required if backend=redis)
# REDIS_URL=redis://localhost:6379
```

---

### Security Requirements

The threat intelligence system enforces the following security practices:

| Requirement | Implementation |
|-------------|----------------|
| **API keys are never logged** | Keys are masked in all log output; only the last 4 characters may appear in debug traces |
| **Secrets via environment only** | No hardcoded credentials; all secrets must be injected via environment variables |
| **Response sanitization** | Provider responses are validated and sanitized before storage; untrusted fields are stripped |
| **Evidence URL handling** | URLs are stored as references only; they are not automatically fetched or rendered to prevent SSRF and XSS |
| **No secret exposure in errors** | Error messages never include API keys, tokens, or full request payloads |

```bash
# Optional: Enable verbose logging for debugging (development only)
# WARNING: Even in verbose mode, secrets are masked
THREAT_INTEL_VERBOSE=false
```

---

### UX Safety Guarantees

Securnex intentionally separates off-chain intelligence from on-chain security status.

| Guarantee | Description |
|-----------|-------------|
| **Off-chain signals do NOT mark wallets as compromised** | A wallet's compromise status is determined exclusively by on-chain evidence (e.g., drainer transactions, unauthorized transfers) |
| **Threat intel affects "Context" and "Exposure" only** | Off-chain signals inform contextual awareness, not security verdicts |
| **No alarmist labels** | Terms like "scam wallet", "malicious address", or "dangerous" are intentionally avoided in UI copy |
| **Source attribution required** | All displayed signals include the reporting provider for transparency |
| **Clear labeling** | Off-chain signals are marked: *"Reported by external security intelligence providers (off-chain signal)"* |

---

### Complete `.env` Example

Copy and customize this block for your environment:

```bash
# ============================================
# SECURNEX - THREAT INTELLIGENCE CONFIGURATION
# ============================================
# Production-ready template
# Replace placeholder values before deployment

# ------------------------------
# CORE SETTINGS
# ------------------------------
THREAT_INTEL_ENABLED=true
THREAT_INTEL_REFRESH_INTERVAL_MINUTES=360
THREAT_INTEL_CONFIDENCE_THRESHOLD=40
THREAT_INTEL_SIGNAL_DECAY_DAYS=90
THREAT_INTEL_MAX_EVIDENCE_PER_WALLET=50
THREAT_INTEL_VERBOSE=false

# ------------------------------
# CACHE SETTINGS
# ------------------------------
THREAT_INTEL_CACHE_ENABLED=true
THREAT_INTEL_CACHE_BACKEND=memory
THREAT_INTEL_CACHE_TTL=21600
THREAT_INTEL_CLEAN_CACHE_TTL=86400
# REDIS_URL=redis://localhost:6379

# ------------------------------
# THREAT CONTEXT GRAPH
# ------------------------------
TCG_ENABLED=true
TCG_MAX_NODES=500
TCG_MAX_EDGES=2000
TCG_CAMPAIGN_CLUSTER_WINDOW_DAYS=30
TCG_MIN_REUSE_THRESHOLD=3
TCG_GRAPH_CACHE_TTL_MINUTES=60

# ------------------------------
# PROVIDER: PHISHING INTELLIGENCE (EXAMPLE)
# ------------------------------
PROVIDER_PHISHING_INTEL_ENABLED=true
PROVIDER_PHISHING_INTEL_API_KEY=your-api-key-here
PROVIDER_PHISHING_INTEL_TIMEOUT_MS=5000
PROVIDER_PHISHING_INTEL_CONFIDENCE_WEIGHT=0.6

# ------------------------------
# PROVIDER: DRAINER DETECTION (EXAMPLE)
# ------------------------------
PROVIDER_DRAINER_INTEL_ENABLED=true
PROVIDER_DRAINER_INTEL_API_KEY=your-api-key-here
PROVIDER_DRAINER_INTEL_TIMEOUT_MS=5000
PROVIDER_DRAINER_INTEL_CONFIDENCE_WEIGHT=0.8

# ------------------------------
# PROVIDER: BRAND PROTECTION (EXAMPLE)
# ------------------------------
PROVIDER_BRAND_PROTECTION_ENABLED=true
PROVIDER_BRAND_PROTECTION_API_KEY=your-api-key-here
PROVIDER_BRAND_PROTECTION_TIMEOUT_MS=8000
PROVIDER_BRAND_PROTECTION_CONFIDENCE_WEIGHT=0.5

# ------------------------------
# PROVIDER: SIMULATION SERVICE (EXAMPLE)
# ------------------------------
PROVIDER_SIMULATION_ENABLED=true
PROVIDER_SIMULATION_API_KEY=your-api-key-here
PROVIDER_SIMULATION_TIMEOUT_MS=10000
PROVIDER_SIMULATION_CONFIDENCE_WEIGHT=0.9

# ------------------------------
# ADD NEW PROVIDERS BELOW
# Follow the PROVIDER_<NAME>_* pattern
# ------------------------------
# PROVIDER_TRM_ENABLED=false
# PROVIDER_TRM_API_KEY=
# PROVIDER_TRM_CONFIDENCE_WEIGHT=1.0
#
# PROVIDER_CHAINALYSIS_ENABLED=false
# PROVIDER_CHAINALYSIS_API_KEY=
# PROVIDER_CHAINALYSIS_CONFIDENCE_WEIGHT=1.0
```

---

**Note:** Public threat intelligence endpoints may have rate limits. For production deployments, ensure you have appropriate API tier subscriptions and configure rate limiting accordingly.



