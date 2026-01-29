# Securnex Usage Metrics - Setup Guide (Vercel + Neon)

## 🚨 Current State

**As of this audit, Securnex has NO historical usage data.** The application was not instrumented to persist scan events.

### What Has Been Added

This implementation adds comprehensive metrics tracking using **Neon** (serverless PostgreSQL):

| Component | File | Purpose |
|-----------|------|---------|
| Types | `src/lib/metrics/types.ts` | TypeScript definitions |
| Database | `src/lib/metrics/db.ts` | Neon connection |
| Hashing | `src/lib/metrics/hash-utils.ts` | Privacy-preserving user identification |
| Tracker | `src/lib/metrics/tracker.ts` | Records scan events |
| Queries | `src/lib/metrics/queries.ts` | Computes aggregated metrics |
| Schema | `schema.sql` | PostgreSQL database schema |
| API | `src/app/api/metrics/route.ts` | HTTP endpoint for metrics |

---

## 🔧 Setup Instructions

### Step 1: Create Neon Database (Free)

1. Go to [neon.tech](https://neon.tech) and sign up
2. Create a new project (e.g., "securnex-metrics")
3. Copy the connection string (looks like `postgresql://user:pass@host/db?sslmode=require`)

### Step 2: Add Environment Variable to Vercel

1. Go to your Vercel project dashboard
2. Navigate to **Settings** → **Environment Variables**
3. Add:
   - **Name**: `DATABASE_URL`
   - **Value**: Your Neon connection string
   - **Environments**: Production, Preview, Development

### Step 3: Apply Database Schema

1. In Neon dashboard, click **SQL Editor**
2. Paste the contents of `schema.sql`
3. Click **Run**

Or via command line:
```bash
psql "YOUR_CONNECTION_STRING" -f schema.sql
```

### Step 4: Redeploy

Push your changes to trigger a new Vercel deployment:
```bash
git add .
git commit -m "Add metrics tracking"
git push
```

---

## 📊 Available Metrics

| Metric | Description | Deduplication |
|--------|-------------|---------------|
| `total_scans` | All completed wallet analyses | None |
| `successful_scans` | Scans excluding re-scans | 24-hour cooldown window |
| `unique_wallets` | Distinct wallet addresses | Address normalization |
| `unique_users` | Distinct IP+UserAgent combos | Privacy-preserving hash |
| `scans_by_verdict` | Breakdown by SAFE/AT_RISK/COMPROMISED | Per-verdict count |
| `scans_by_chain` | Breakdown by chain | Per-chain count |
| `daily_scans` | Last 30 days daily counts | Re-scans excluded |
| `weekly_scans` | Last 12 weeks weekly counts | Re-scans excluded |
| `launch_date` | First scan timestamp | Auto-detected |

### Deduplication Logic

A **re-scan** is detected when the same combination of:
- Wallet address (normalized)
- IP hash
- User-Agent hash

occurs within a **24-hour cooldown window**.

---

## 🔍 API Endpoints

### GET /api/metrics?public=true

Public-safe metrics (for website, tweets, investor decks):

```bash
curl https://your-app.vercel.app/api/metrics?public=true
```

Response:
```json
{
  "success": true,
  "data": {
    "wallets_protected": 892,
    "total_scans": 1247,
    "threats_detected": 412,
    "chains_supported": 4,
    "launch_date": "2026-01-15T10:23:45.000Z",
    "last_updated": "2026-01-29T14:00:00.000Z"
  }
}
```

### GET /api/metrics

Full metrics (for admin/internal use):

```bash
curl https://your-app.vercel.app/api/metrics
```

### GET /api/metrics?anomalies=true

Include bot/abuse detection.

---

## 📝 Raw SQL Queries

Connect to Neon directly for debugging:

### Total Wallets Protected
```sql
SELECT COUNT(DISTINCT wallet_address) FROM scans WHERE is_rescan = false;
```

### Total Scans Performed
```sql
SELECT COUNT(*) FROM scans WHERE is_rescan = false;
```

### Unique Users
```sql
SELECT COUNT(DISTINCT ip_hash || '::' || user_agent_hash) FROM scans;
```

### Launch Date
```sql
SELECT MIN(timestamp) FROM scans;
```

### Daily Breakdown (Last 30 Days)
```sql
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as scans
FROM scans
WHERE timestamp >= NOW() - INTERVAL '30 days'
  AND is_rescan = false
GROUP BY DATE(timestamp)
ORDER BY date DESC;
```

### Scans by Chain
```sql
SELECT chain, COUNT(*) 
FROM scans 
WHERE is_rescan = false 
GROUP BY chain;
```

---

## 📈 Output Formats

### For Metrics Page
```
🛡️ 892 wallets protected
📊 1,247 security scans performed
⚠️ 412 threats detected
🔗 4 chains supported
```

### For Investor Deck
| Metric | Value |
|--------|-------|
| Wallets Protected | 892 |
| Total Scans | 1,247 |
| Threats Detected | 412 |
| Unique Users | 743 |
| Launch Date | Jan 15, 2026 |

### For Twitter/Milestone
```
🚀 Securnex Milestone!

✅ 892 wallets protected
✅ 1,247 security scans
✅ 412 threats detected

Protecting Web3, one wallet at a time 🛡️
```

---

## ⚠️ Important Notes

1. **Historical Data**: Cannot recover past metrics. Tracking starts from deployment.

2. **Privacy**: IPs and User-Agents are SHA-256 hashed. Original values never stored.

3. **Free Tier**: Neon free tier includes:
   - 0.5 GB storage
   - 3 GB data transfer / month
   - Plenty for thousands of scans

4. **Costs**: Neon is very affordable. See [neon.tech/pricing](https://neon.tech/pricing)

---

## 🔧 Files Created/Modified

```
wallet-sentinel/
├── src/lib/metrics/
│   ├── types.ts         # Type definitions
│   ├── db.ts            # Neon database connection
│   ├── hash-utils.ts    # Privacy-preserving hashing
│   ├── tracker.ts       # Records scan events
│   ├── queries.ts       # Computes metrics
│   └── index.ts         # Exports
├── src/app/api/
│   ├── analyze/route.ts # Updated with metrics tracking
│   └── metrics/route.ts # New metrics endpoint
├── schema.sql           # PostgreSQL schema
└── docs/METRICS-SETUP.md # This file
```

---

## 📞 Troubleshooting

### "Metrics database not configured"

The `DATABASE_URL` environment variable is not set. Add it in Vercel.

### "QUERY_ERROR"

1. Check that the schema has been applied
2. Verify connection string is correct
3. Check Neon dashboard for errors

### No metrics appearing

1. Metrics only track **new** scans after deployment
2. Visit `/api/analyze` to trigger a scan first
3. Then check `/api/metrics`
