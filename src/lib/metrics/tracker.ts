// ============================================
// SECURNEX METRICS TRACKER (Vercel + Neon)
// ============================================
// Records scan events to PostgreSQL

import { SecurityVerdict } from './types';
import { sha256Hash, normalizeWalletAddress, generateScanId } from './hash-utils';
import { getDb, NeonClient } from './db';

// Cooldown window for re-scan detection (in hours)
const RESCAN_COOLDOWN_HOURS = 24;

/**
 * MetricsTracker - Records wallet scan events
 */
export class MetricsTracker {
  private db: NeonClient | null;

  constructor() {
    this.db = getDb();
  }

  /**
   * Record a completed wallet scan
   */
  async recordScan(params: {
    walletAddress: string;
    chain: string;
    verdict: SecurityVerdict;
    riskScore: number;
    threatsCount: number;
    durationMs: number;
    ip: string;
    userAgent: string;
    source?: 'web' | 'api';
  }): Promise<{ success: boolean; scanId?: string; error?: string }> {
    if (!this.db) {
      return { success: false, error: 'Database not configured' };
    }

    try {
      const scanId = generateScanId();
      const timestamp = new Date().toISOString();
      const normalizedAddress = normalizeWalletAddress(params.walletAddress, params.chain);
      
      // Create privacy-preserving hashes
      const ipHash = await sha256Hash(params.ip);
      const userAgentHash = await sha256Hash(params.userAgent);
      
      // Check if this is a re-scan
      const isRescan = await this.checkRescan(normalizedAddress, ipHash, userAgentHash);

      // Insert the scan event
      await this.db`
        INSERT INTO scans (
          id, timestamp, wallet_address, chain, verdict, 
          risk_score, threats_count, duration_ms,
          ip_hash, user_agent_hash, is_rescan, source
        ) VALUES (
          ${scanId}, ${timestamp}, ${normalizedAddress}, ${params.chain}, ${params.verdict},
          ${params.riskScore}, ${params.threatsCount}, ${params.durationMs},
          ${ipHash}, ${userAgentHash}, ${isRescan}, ${params.source || 'web'}
        )
      `;

      console.log(`[METRICS] Recorded scan ${scanId}: ${params.chain}/${normalizedAddress.slice(0, 10)}... -> ${params.verdict}`);
      
      return { success: true, scanId };
    } catch (error) {
      console.error('[METRICS] Failed to record scan:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Check if this is a re-scan within the cooldown window
   */
  private async checkRescan(
    walletAddress: string, 
    ipHash: string, 
    userAgentHash: string
  ): Promise<boolean> {
    if (!this.db) return false;

    try {
      const cooldownTime = new Date(
        Date.now() - RESCAN_COOLDOWN_HOURS * 60 * 60 * 1000
      ).toISOString();

      const result = await this.db`
        SELECT COUNT(*) as count FROM scans 
        WHERE wallet_address = ${walletAddress}
          AND ip_hash = ${ipHash}
          AND user_agent_hash = ${userAgentHash}
          AND timestamp > ${cooldownTime}
      `;

      return (result[0]?.count || 0) > 0;
    } catch {
      return false;
    }
  }
}

/**
 * Get a metrics tracker instance
 */
export function getMetricsTracker(): MetricsTracker {
  return new MetricsTracker();
}
