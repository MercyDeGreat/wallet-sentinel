-- ============================================
-- SECURNEX METRICS DATABASE SCHEMA (PostgreSQL/Neon)
-- ============================================
-- Run this in your Neon database console or via psql
-- 
-- Connection: Get your DATABASE_URL from Neon dashboard

-- Main scans table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    wallet_address TEXT NOT NULL,
    chain TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('SAFE', 'AT_RISK', 'COMPROMISED')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    threats_count INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL,
    ip_hash TEXT NOT NULL,
    user_agent_hash TEXT NOT NULL,
    is_rescan BOOLEAN NOT NULL DEFAULT FALSE,
    source TEXT NOT NULL DEFAULT 'web' CHECK (source IN ('web', 'api'))
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_wallet ON scans(wallet_address);
CREATE INDEX IF NOT EXISTS idx_scans_chain ON scans(chain);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_scans_ip_hash ON scans(ip_hash);
CREATE INDEX IF NOT EXISTS idx_scans_rescan ON scans(is_rescan);

-- Composite index for deduplication checks
CREATE INDEX IF NOT EXISTS idx_scans_dedup ON scans(wallet_address, ip_hash, user_agent_hash, timestamp);

-- ============================================
-- QUICK REFERENCE: KEY METRICS QUERIES
-- ============================================

-- Total unique wallets protected:
-- SELECT COUNT(DISTINCT wallet_address) FROM scans WHERE is_rescan = false;

-- Total scans performed:
-- SELECT COUNT(*) FROM scans WHERE is_rescan = false;

-- Unique users:
-- SELECT COUNT(DISTINCT ip_hash || '::' || user_agent_hash) FROM scans;

-- Launch date:
-- SELECT MIN(timestamp) FROM scans;

-- Daily breakdown (last 30 days):
-- SELECT DATE(timestamp) as date, COUNT(*) as count 
-- FROM scans WHERE timestamp >= NOW() - INTERVAL '30 days' AND is_rescan = false
-- GROUP BY DATE(timestamp) ORDER BY date DESC;

-- Scans by chain:
-- SELECT chain, COUNT(*) FROM scans WHERE is_rescan = false GROUP BY chain;

-- Scans by verdict:
-- SELECT verdict, COUNT(*) FROM scans WHERE is_rescan = false GROUP BY verdict;
