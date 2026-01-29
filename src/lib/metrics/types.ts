// ============================================
// SECURNEX USAGE METRICS - TYPE DEFINITIONS
// ============================================

export type SecurityVerdict = 'SAFE' | 'AT_RISK' | 'COMPROMISED';

export interface ScanEvent {
  id: string;
  timestamp: string;           // ISO 8601
  wallet_address: string;      // Normalized (lowercase for EVM)
  chain: string;               // ethereum | base | bnb | solana
  verdict: SecurityVerdict;
  risk_score: number;
  threats_count: number;
  duration_ms: number;
  
  // Deduplication identifiers
  ip_hash: string;             // SHA-256 hash of IP (privacy-preserving)
  user_agent_hash: string;     // SHA-256 hash of User-Agent
  
  // Metadata
  is_rescan: boolean;          // Same wallet within cooldown window
  source: 'web' | 'api';       // Origin of request
}

export interface UsageMetrics {
  // Core counts
  total_scans: number;
  successful_scans: number;
  unique_wallets: number;
  unique_users: number;          // Based on ip_hash + user_agent_hash composite
  
  // By verdict
  scans_by_verdict: {
    safe: number;
    at_risk: number;
    compromised: number;
  };
  
  // By chain
  scans_by_chain: {
    ethereum: number;
    base: number;
    bnb: number;
    solana: number;
  };
  
  // Time-based
  daily_scans: { date: string; count: number }[];
  weekly_scans: { week_start: string; count: number }[];
  
  // Metadata
  launch_date: string;         // First production scan timestamp
  computed_at: string;
  cooldown_hours: number;      // Dedup window used (default: 24)
}

export interface MetricsQueryOptions {
  start_date?: string;         // ISO date
  end_date?: string;
  chain?: string;
  cooldown_hours?: number;     // For dedup calculation (default: 24)
  exclude_rescans?: boolean;   // Filter out re-scans
}

// Cloudflare D1 row types (SQLite)
export interface D1ScanRow {
  id: string;
  timestamp: string;
  wallet_address: string;
  chain: string;
  verdict: string;
  risk_score: number;
  threats_count: number;
  duration_ms: number;
  ip_hash: string;
  user_agent_hash: string;
  is_rescan: number;         // 0 or 1 (SQLite boolean)
  source: string;
}
