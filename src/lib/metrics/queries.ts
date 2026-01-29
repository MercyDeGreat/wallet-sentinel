// ============================================
// SECURNEX METRICS QUERIES (Vercel + Neon)
// ============================================
// PostgreSQL queries to compute usage metrics

import { UsageMetrics, MetricsQueryOptions } from './types';
import { getDb, NeonClient } from './db';

// Default cooldown for deduplication (24 hours)
const DEFAULT_COOLDOWN_HOURS = 24;

/**
 * Compute comprehensive usage metrics
 */
export async function computeUsageMetrics(
  options: MetricsQueryOptions = {}
): Promise<UsageMetrics | null> {
  const db = getDb();
  if (!db) return null;

  const excludeRescans = options.exclude_rescans ?? true;
  const rescanFilter = excludeRescans ? 'AND is_rescan = false' : '';
  
  try {
    // Execute queries
    const [
      totalResult,
      successfulResult,
      uniqueWalletsResult,
      uniqueUsersResult,
      verdictResult,
      chainResult,
      dailyResult,
      weeklyResult,
      launchResult
    ] = await Promise.all([
      // Total scans
      db`SELECT COUNT(*) as count FROM scans`,
      
      // Successful scans (excluding rescans if specified)
      db`SELECT COUNT(*) as count FROM scans WHERE 1=1 ${excludeRescans ? db`AND is_rescan = false` : db``}`,
      
      // Unique wallets
      db`SELECT COUNT(DISTINCT wallet_address) as count FROM scans`,
      
      // Unique users
      db`SELECT COUNT(DISTINCT ip_hash || '::' || user_agent_hash) as count FROM scans`,
      
      // By verdict
      db`
        SELECT 
          COUNT(*) FILTER (WHERE verdict = 'SAFE') as safe,
          COUNT(*) FILTER (WHERE verdict = 'AT_RISK') as at_risk,
          COUNT(*) FILTER (WHERE verdict = 'COMPROMISED') as compromised
        FROM scans WHERE 1=1 ${excludeRescans ? db`AND is_rescan = false` : db``}
      `,
      
      // By chain
      db`
        SELECT 
          COUNT(*) FILTER (WHERE chain = 'ethereum') as ethereum,
          COUNT(*) FILTER (WHERE chain = 'base') as base,
          COUNT(*) FILTER (WHERE chain = 'bnb') as bnb,
          COUNT(*) FILTER (WHERE chain = 'solana') as solana
        FROM scans WHERE 1=1 ${excludeRescans ? db`AND is_rescan = false` : db``}
      `,
      
      // Daily (last 30 days)
      db`
        SELECT 
          DATE(timestamp) as date,
          COUNT(*) as count
        FROM scans 
        WHERE timestamp >= NOW() - INTERVAL '30 days'
          ${excludeRescans ? db`AND is_rescan = false` : db``}
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
      `,
      
      // Weekly (last 12 weeks)
      db`
        SELECT 
          DATE_TRUNC('week', timestamp) as week_start,
          COUNT(*) as count
        FROM scans 
        WHERE timestamp >= NOW() - INTERVAL '84 days'
          ${excludeRescans ? db`AND is_rescan = false` : db``}
        GROUP BY week_start
        ORDER BY week_start DESC
      `,
      
      // Launch date
      db`SELECT MIN(timestamp) as launch_date FROM scans`
    ]);

    return {
      total_scans: Number(totalResult[0]?.count || 0),
      successful_scans: Number(successfulResult[0]?.count || 0),
      unique_wallets: Number(uniqueWalletsResult[0]?.count || 0),
      unique_users: Number(uniqueUsersResult[0]?.count || 0),
      
      scans_by_verdict: {
        safe: Number(verdictResult[0]?.safe || 0),
        at_risk: Number(verdictResult[0]?.at_risk || 0),
        compromised: Number(verdictResult[0]?.compromised || 0),
      },
      
      scans_by_chain: {
        ethereum: Number(chainResult[0]?.ethereum || 0),
        base: Number(chainResult[0]?.base || 0),
        bnb: Number(chainResult[0]?.bnb || 0),
        solana: Number(chainResult[0]?.solana || 0),
      },
      
      daily_scans: dailyResult.map(r => ({ 
        date: String(r.date), 
        count: Number(r.count) 
      })),
      weekly_scans: weeklyResult.map(r => ({ 
        week_start: String(r.week_start), 
        count: Number(r.count) 
      })),
      
      launch_date: launchResult[0]?.launch_date || 'N/A',
      computed_at: new Date().toISOString(),
      cooldown_hours: DEFAULT_COOLDOWN_HOURS,
    };
  } catch (error) {
    console.error('[METRICS] Query error:', error);
    return null;
  }
}

/**
 * Detect potential bot/abuse patterns
 */
export async function detectAnomalies(): Promise<{
  suspicious_ips: { ip_hash: string; scan_count: number; unique_wallets: number }[];
  high_frequency_wallets: { wallet_address: string; scan_count: number }[];
  anomaly_summary: string;
} | null> {
  const db = getDb();
  if (!db) return null;

  try {
    const [suspiciousIps, highFreqWallets] = await Promise.all([
      db`
        SELECT 
          ip_hash,
          COUNT(*) as scan_count,
          COUNT(DISTINCT wallet_address) as unique_wallets
        FROM scans 
        WHERE timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY ip_hash
        HAVING COUNT(*) > 50
        ORDER BY scan_count DESC
        LIMIT 20
      `,
      db`
        SELECT 
          wallet_address,
          COUNT(*) as scan_count
        FROM scans 
        WHERE timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY wallet_address
        HAVING COUNT(*) > 20
        ORDER BY scan_count DESC
        LIMIT 20
      `
    ]);

    const totalAnomalies = suspiciousIps.length + highFreqWallets.length;

    return {
      suspicious_ips: suspiciousIps.map(r => ({
        ip_hash: String(r.ip_hash),
        scan_count: Number(r.scan_count),
        unique_wallets: Number(r.unique_wallets)
      })),
      high_frequency_wallets: highFreqWallets.map(r => ({
        wallet_address: String(r.wallet_address),
        scan_count: Number(r.scan_count)
      })),
      anomaly_summary: totalAnomalies === 0 
        ? 'No anomalies detected' 
        : `Found ${totalAnomalies} potential anomalies requiring review`,
    };
  } catch (error) {
    console.error('[METRICS] Anomaly detection error:', error);
    return null;
  }
}

/**
 * Get metrics for public display
 */
export async function getPublicMetrics(): Promise<{
  wallets_protected: number;
  total_scans: number;
  threats_detected: number;
  chains_supported: number;
  launch_date: string;
  last_updated: string;
} | null> {
  const db = getDb();
  if (!db) return null;

  try {
    const [result] = await Promise.all([
      db`
        SELECT 
          COUNT(DISTINCT wallet_address) as unique_wallets,
          COUNT(*) FILTER (WHERE is_rescan = false) as total_scans,
          COALESCE(SUM(threats_count) FILTER (WHERE is_rescan = false), 0) as threats_detected,
          MIN(timestamp) as launch_date
        FROM scans
      `
    ]);

    return {
      wallets_protected: Number(result[0]?.unique_wallets || 0),
      total_scans: Number(result[0]?.total_scans || 0),
      threats_detected: Number(result[0]?.threats_detected || 0),
      chains_supported: 4,
      launch_date: result[0]?.launch_date || 'N/A',
      last_updated: new Date().toISOString(),
    };
  } catch (error) {
    console.error('[METRICS] Public metrics error:', error);
    return null;
  }
}
