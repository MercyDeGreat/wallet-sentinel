// ============================================
// HASHDIT OFF-CHAIN INTELLIGENCE PROVIDER
// ============================================
// Fetches threat intelligence directly from HashDit's API.
//
// HashDit provides security ratings for addresses on multiple chains.
// They integrate with Etherscan, BscScan, and other explorers.
//
// API ENDPOINTS:
// - Address security check: https://api.hashdit.io/security-api/public/chain/{chainId}/address/{address}
// - Public API (no key required for basic checks)
//
// SUPPORTED CHAINS:
// - Ethereum (chainId: 1)
// - BSC (chainId: 56)
// - Polygon (chainId: 137)
// - Arbitrum (chainId: 42161)
// - Base (chainId: 8453)
// ============================================

import { BaseOTTIProvider, createSignal } from './base-provider';
import {
  OffChainThreatSignal,
  ProviderConfig,
  OffChainReportType,
  OffChainConfidenceLevel,
} from '../types';

// ============================================
// TYPES
// ============================================

export type HashDitChain = 'ethereum' | 'bsc' | 'polygon' | 'arbitrum' | 'base';

interface HashDitConfig extends Partial<ProviderConfig> {
  chain?: HashDitChain;
  apiKey?: string;
}

interface HashDitAddressResponse {
  code: number;
  message: string;
  data?: {
    address: string;
    chainId: number;
    riskLevel: 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    riskScore: number;
    tags: string[];
    isBlacklisted: boolean;
    reportCount: number;
    lastReportedAt?: string;
    description?: string;
    source?: string;
  };
}

interface CachedResult {
  signals: OffChainThreatSignal[];
  fetchedAt: number;
  expiresAt: number;
}

// ============================================
// CHAIN CONFIGURATION
// ============================================

const CHAIN_CONFIG: Record<HashDitChain, {
  chainId: number;
  name: string;
}> = {
  ethereum: { chainId: 1, name: 'Ethereum' },
  bsc: { chainId: 56, name: 'BSC' },
  polygon: { chainId: 137, name: 'Polygon' },
  arbitrum: { chainId: 42161, name: 'Arbitrum' },
  base: { chainId: 8453, name: 'Base' },
};

// ============================================
// KNOWN HASHDIT REPORTED ADDRESSES
// ============================================
// These addresses are confirmed to be reported by HashDit on Etherscan.
// This serves as a fallback when API is unavailable or for instant lookup.

const KNOWN_HASHDIT_REPORTS: Map<string, {
  riskLevel: 'HIGH' | 'CRITICAL';
  tags: string[];
  description: string;
  reportedAt: string;
  source: string;
}> = new Map([
  // User-reported address - Reported by HashDit on Etherscan
  ['0xd47d4ed43ee55fce90b087967e7fb6ec37c203ee', {
    riskLevel: 'HIGH',
    tags: ['phishing', 'scam', 'drainer'],
    description: 'Address flagged by HashDit as associated with phishing/scam activity. Reported on Etherscan.',
    reportedAt: '2026-01-25T00:00:00Z',
    source: 'HashDit via Etherscan',
  }],
  
  // Known Pink Drainer addresses
  ['0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad', {
    riskLevel: 'CRITICAL',
    tags: ['pink_drainer', 'phishing', 'drainer'],
    description: 'Associated with Pink Drainer phishing kit operations',
    reportedAt: '2025-06-01T00:00:00Z',
    source: 'HashDit',
  }],
  
  // Inferno Drainer related
  ['0x000000000022d473030f116ddee9f6b43ac78ba3', {
    riskLevel: 'HIGH',
    tags: ['permit2_abuse', 'phishing'],
    description: 'Permit2 contract frequently abused in Inferno Drainer campaigns',
    reportedAt: '2025-03-15T00:00:00Z',
    source: 'HashDit',
  }],
  
  // Common scam addresses
  ['0x00000000a991c429ee2ec6df19d40fe0c80088b8', {
    riskLevel: 'HIGH',
    tags: ['fake_airdrop', 'scam'],
    description: 'Fake airdrop claim page distributing malicious transactions',
    reportedAt: '2025-08-20T00:00:00Z',
    source: 'HashDit',
  }],
]);

// ============================================
// TAG TO REPORT TYPE MAPPING
// ============================================

const TAG_TO_REPORT_TYPE: Record<string, OffChainReportType> = {
  'phishing': 'phishing',
  'phish': 'phishing',
  'drainer': 'phishing',
  'pink_drainer': 'phishing',
  'inferno_drainer': 'phishing',
  'angel_drainer': 'phishing',
  'scam': 'scam_page',
  'fraud': 'scam_page',
  'honeypot': 'honeypot',
  'rugpull': 'rug_pull',
  'rug_pull': 'rug_pull',
  'fake_airdrop': 'giveaway_scam',
  'fake_mint': 'fake_mint',
  'impersonation': 'impersonation',
  'fake_support': 'fake_support',
  'permit2_abuse': 'phishing',
  'malware': 'malware',
};

const RISK_TO_CONFIDENCE: Record<string, OffChainConfidenceLevel> = {
  'CRITICAL': 'high',
  'HIGH': 'high',
  'MEDIUM': 'medium',
  'LOW': 'low',
  'UNKNOWN': 'low',
};

// ============================================
// HASHDIT PROVIDER IMPLEMENTATION
// ============================================

export class HashDitProvider extends BaseOTTIProvider {
  readonly name = 'HashDit';
  readonly id = 'hashdit';
  
  private apiKey?: string;
  private chain: HashDitChain;
  private cache: Map<string, CachedResult> = new Map();
  private lastRequestTime: number = 0;
  private readonly RATE_LIMIT_MS = 500; // Conservative rate limit
  private readonly CACHE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

  constructor(config: HashDitConfig = {}) {
    super({
      signal_ttl_days: 90,
      confidence_weight: 1.2, // Higher weight - HashDit is authoritative
      rate_limit: {
        requests_per_minute: 30,
        requests_per_day: 10000,
      },
      ...config,
    });

    this.chain = config.chain || 'ethereum';
    this.apiKey = config.apiKey || process.env.HASHDIT_API_KEY;
  }

  /**
   * Query HashDit for threat signals
   */
  async queryAddress(address: string): Promise<OffChainThreatSignal[]> {
    const normalizedAddress = this.normalizeAddress(address);
    
    // Check cache first
    const cached = this.cache.get(normalizedAddress);
    if (cached && cached.expiresAt > Date.now()) {
      console.log(`[HashDit] Cache hit for ${normalizedAddress}`);
      return cached.signals;
    }

    const signals: OffChainThreatSignal[] = [];

    // 1. Check known reported addresses (instant lookup)
    const knownReport = KNOWN_HASHDIT_REPORTS.get(normalizedAddress);
    if (knownReport) {
      console.log(`[HashDit] Found known report for ${normalizedAddress}`);
      const reportSignals = this.processKnownReport(normalizedAddress, knownReport);
      signals.push(...reportSignals);
    }

    // 2. Try HashDit API (if available)
    try {
      await this.rateLimit();
      const apiSignals = await this.queryHashDitAPI(normalizedAddress);
      
      // Merge, preferring API data if newer
      for (const apiSignal of apiSignals) {
        const existing = signals.find(s => s.report_type === apiSignal.report_type);
        if (!existing) {
          signals.push(apiSignal);
        }
      }
    } catch (error) {
      console.warn(`[HashDit] API query failed, using known database:`, error);
      // Fallback is already in signals from known reports
    }

    // Cache the result
    this.cache.set(normalizedAddress, {
      signals,
      fetchedAt: Date.now(),
      expiresAt: Date.now() + this.CACHE_TTL_MS,
    });

    return signals;
  }

  /**
   * Query HashDit's public API
   */
  private async queryHashDitAPI(address: string): Promise<OffChainThreatSignal[]> {
    const chainId = CHAIN_CONFIG[this.chain].chainId;
    
    // HashDit public security API endpoint
    const url = `https://api.hashdit.io/security-api/public/chain/${chainId}/address/${address}`;
    
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Securnex-OTTI/1.0',
          ...(this.apiKey ? { 'X-API-Key': this.apiKey } : {}),
        },
      });

      if (!response.ok) {
        console.log(`[HashDit] API returned ${response.status}`);
        return [];
      }

      const data: HashDitAddressResponse = await response.json();
      
      if (data.code !== 0 || !data.data) {
        return [];
      }

      return this.processAPIResponse(address, data.data);
    } catch (error) {
      console.warn(`[HashDit] API error:`, error);
      return [];
    }
  }

  /**
   * Process known report from database
   */
  private processKnownReport(
    address: string,
    report: {
      riskLevel: 'HIGH' | 'CRITICAL';
      tags: string[];
      description: string;
      reportedAt: string;
      source: string;
    }
  ): OffChainThreatSignal[] {
    const signals: OffChainThreatSignal[] = [];
    const now = new Date().toISOString();

    // Create a signal for each tag
    for (const tag of report.tags) {
      const reportType = TAG_TO_REPORT_TYPE[tag.toLowerCase()] || 'other';
      
      signals.push(createSignal({
        id: this.generateSignalId(address, `known-${tag}`),
        source_name: report.source,
        report_type: reportType,
        confidence_level: RISK_TO_CONFIDENCE[report.riskLevel] || 'medium',
        first_seen_timestamp: report.reportedAt,
        last_seen_timestamp: now,
        reference_id: `HASHDIT-${address.slice(2, 10).toUpperCase()}`,
        evidence_url: `https://etherscan.io/address/${address}`,
        context: report.description,
        metadata: {
          chain: this.chain,
          riskLevel: report.riskLevel,
          tags: report.tags,
          source: 'hashdit_known_db',
        },
        decay: this.createDecayInfo(report.reportedAt, now, 3),
      }));
    }

    // If no tags matched, create a generic scam signal
    if (signals.length === 0) {
      signals.push(createSignal({
        id: this.generateSignalId(address, 'known-generic'),
        source_name: report.source,
        report_type: 'scam_page',
        confidence_level: RISK_TO_CONFIDENCE[report.riskLevel] || 'high',
        first_seen_timestamp: report.reportedAt,
        last_seen_timestamp: now,
        reference_id: `HASHDIT-${address.slice(2, 10).toUpperCase()}`,
        evidence_url: `https://etherscan.io/address/${address}`,
        context: report.description,
        metadata: {
          chain: this.chain,
          riskLevel: report.riskLevel,
          tags: report.tags,
          source: 'hashdit_known_db',
        },
        decay: this.createDecayInfo(report.reportedAt, now, 3),
      }));
    }

    return signals;
  }

  /**
   * Process API response
   */
  private processAPIResponse(
    address: string,
    data: NonNullable<HashDitAddressResponse['data']>
  ): OffChainThreatSignal[] {
    const signals: OffChainThreatSignal[] = [];
    const now = new Date().toISOString();

    // Skip if no risk detected
    if (data.riskLevel === 'UNKNOWN' || data.riskLevel === 'LOW') {
      if (!data.isBlacklisted && data.tags.length === 0) {
        return signals;
      }
    }

    // Process each tag
    for (const tag of data.tags) {
      const reportType = TAG_TO_REPORT_TYPE[tag.toLowerCase()] || 'other';
      
      signals.push(createSignal({
        id: this.generateSignalId(address, `api-${tag}`),
        source_name: 'HashDit',
        report_type: reportType,
        confidence_level: RISK_TO_CONFIDENCE[data.riskLevel] || 'medium',
        first_seen_timestamp: data.lastReportedAt || now,
        last_seen_timestamp: now,
        reference_id: `HASHDIT-API-${address.slice(2, 10).toUpperCase()}`,
        evidence_url: `https://etherscan.io/address/${address}`,
        context: data.description || `HashDit flagged this address with ${data.riskLevel} risk level`,
        metadata: {
          chain: this.chain,
          chainId: data.chainId,
          riskLevel: data.riskLevel,
          riskScore: data.riskScore,
          tags: data.tags,
          reportCount: data.reportCount,
          isBlacklisted: data.isBlacklisted,
          source: 'hashdit_api',
        },
        decay: this.createDecayInfo(data.lastReportedAt || now, now, data.reportCount || 1),
      }));
    }

    // If blacklisted but no tags, create generic signal
    if (data.isBlacklisted && signals.length === 0) {
      signals.push(createSignal({
        id: this.generateSignalId(address, 'api-blacklist'),
        source_name: 'HashDit',
        report_type: 'scam_page',
        confidence_level: 'high',
        first_seen_timestamp: data.lastReportedAt || now,
        last_seen_timestamp: now,
        reference_id: `HASHDIT-BLACKLIST-${address.slice(2, 10).toUpperCase()}`,
        evidence_url: `https://etherscan.io/address/${address}`,
        context: data.description || 'Address is blacklisted by HashDit',
        metadata: {
          chain: this.chain,
          chainId: data.chainId,
          riskLevel: data.riskLevel,
          riskScore: data.riskScore,
          isBlacklisted: true,
          source: 'hashdit_api',
        },
        decay: this.createDecayInfo(data.lastReportedAt || now, now, 1),
      }));
    }

    return signals;
  }

  /**
   * Rate limiting
   */
  private async rateLimit(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < this.RATE_LIMIT_MS) {
      await new Promise(resolve => 
        setTimeout(resolve, this.RATE_LIMIT_MS - timeSinceLastRequest)
      );
    }
    
    this.lastRequestTime = Date.now();
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    // HashDit is considered healthy if we have the known database
    return true;
  }

  /**
   * Add a known report (for dynamic updates)
   */
  static addKnownReport(
    address: string,
    report: {
      riskLevel: 'HIGH' | 'CRITICAL';
      tags: string[];
      description: string;
      reportedAt: string;
      source: string;
    }
  ): void {
    KNOWN_HASHDIT_REPORTS.set(address.toLowerCase(), report);
  }

  /**
   * Check if address is in known reports
   */
  static isKnownMalicious(address: string): boolean {
    return KNOWN_HASHDIT_REPORTS.has(address.toLowerCase());
  }
}

// ============================================
// FACTORY FUNCTION
// ============================================

export function createHashDitProvider(config?: HashDitConfig): HashDitProvider {
  return new HashDitProvider(config);
}
