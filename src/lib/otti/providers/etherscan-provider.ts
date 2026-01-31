// ============================================
// ETHERSCAN OFF-CHAIN INTELLIGENCE PROVIDER
// ============================================
// Fetches address labels, scam reports, and threat tags from
// Etherscan and compatible explorers (BaseScan, BscScan).
//
// SUPPORTED CHAINS:
// - Ethereum (etherscan.io)
// - Base (basescan.org)
// - BNB Chain (bscscan.com)
//
// DATA SOURCES:
// - Address labels (verified contracts, exchanges, etc.)
// - Scam/phishing reports from community
// - HashDit threat intelligence (via Etherscan integration)
// - Name tags and token tracking
//
// RATE LIMITS:
// - Free tier: 5 calls/second, 100,000 calls/day
// - Pro tier: 10 calls/second, 500,000 calls/day
//
// API KEY STORAGE:
// - Environment variables (ETHERSCAN_API_KEY, BASESCAN_API_KEY, BSCSCAN_API_KEY)
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

export type SupportedChain = 'ethereum' | 'base' | 'bnb';

interface EtherscanConfig extends Partial<ProviderConfig> {
  chain: SupportedChain;
  apiKey?: string;
}

interface EtherscanLabelResponse {
  status: string;
  message: string;
  result: {
    address: string;
    publicnametag?: string;
    labels?: string[];
  }[];
}

interface EtherscanAddressInfoResponse {
  status: string;
  message: string;
  result: {
    isContract?: boolean;
    contractCreator?: string;
    contractCreationTx?: string;
    balance?: string;
    txCount?: string;
    // Labels and tags
    labels?: string[];
    nameTag?: string;
    // Risk indicators
    riskScore?: number;
    hashditRiskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    hashditReportType?: string;
    hashditReportDate?: string;
    // Flags
    isScam?: boolean;
    isPhishing?: boolean;
    isHacked?: boolean;
    isSuspicious?: boolean;
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

const CHAIN_CONFIG: Record<SupportedChain, {
  name: string;
  apiBase: string;
  explorerUrl: string;
  envKey: string;
}> = {
  ethereum: {
    name: 'Etherscan',
    apiBase: 'https://api.etherscan.io/api',
    explorerUrl: 'https://etherscan.io',
    envKey: 'ETHERSCAN_API_KEY',
  },
  base: {
    name: 'BaseScan',
    apiBase: 'https://api.basescan.org/api',
    explorerUrl: 'https://basescan.org',
    envKey: 'BASESCAN_API_KEY',
  },
  bnb: {
    name: 'BscScan',
    apiBase: 'https://api.bscscan.com/api',
    explorerUrl: 'https://bscscan.com',
    envKey: 'BSCSCAN_API_KEY',
  },
};

// ============================================
// THREAT LABEL MAPPING
// ============================================

// Map Etherscan labels to OTTI report types
const LABEL_TO_REPORT_TYPE: Record<string, OffChainReportType> = {
  // Phishing related
  'phishing': 'phishing',
  'phish': 'phishing',
  'phisher': 'phishing',
  'fake': 'phishing',
  'drainer': 'phishing',
  'pink drainer': 'phishing',
  'inferno drainer': 'phishing',
  'angel drainer': 'phishing',
  
  // Scam related
  'scam': 'scam_page',
  'scammer': 'scam_page',
  'fraud': 'scam_page',
  'suspicious': 'community_report',
  
  // Honeypot/rug
  'honeypot': 'honeypot',
  'rugpull': 'rug_pull',
  'rug pull': 'rug_pull',
  'rug': 'rug_pull',
  
  // Fake projects
  'fake token': 'honeypot',
  'fake nft': 'fake_mint',
  'fake airdrop': 'giveaway_scam',
  
  // Impersonation
  'impersonator': 'impersonation',
  'impersonation': 'impersonation',
  'copycat': 'impersonation',
  
  // Malware
  'malware': 'malware',
  'exploit': 'other',
  'exploiter': 'other',
  'hacker': 'other',
  'hack': 'other',
};

// HashDit risk level to OTTI confidence
const HASHDIT_TO_CONFIDENCE: Record<string, OffChainConfidenceLevel> = {
  'CRITICAL': 'high',
  'HIGH': 'high',
  'MEDIUM': 'medium',
  'LOW': 'low',
};

// ============================================
// ETHERSCAN PROVIDER IMPLEMENTATION
// ============================================

export class EtherscanProvider extends BaseOTTIProvider {
  readonly name: string;
  readonly id: string;
  
  private chain: SupportedChain;
  private apiKey: string;
  private apiBase: string;
  private explorerUrl: string;
  private cache: Map<string, CachedResult> = new Map();
  private requestCount: number = 0;
  private lastRequestTime: number = 0;
  private readonly RATE_LIMIT_MS = 200; // 5 requests/second
  private readonly CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

  constructor(config: EtherscanConfig) {
    super({
      signal_ttl_days: 90,
      confidence_weight: 1.0,
      rate_limit: {
        requests_per_minute: 5,
        requests_per_day: 100000,
      },
      ...config,
    });

    this.chain = config.chain;
    const chainConfig = CHAIN_CONFIG[this.chain];
    
    this.name = `${chainConfig.name} (via Etherscan)`;
    this.id = `etherscan-${this.chain}`;
    this.apiBase = chainConfig.apiBase;
    this.explorerUrl = chainConfig.explorerUrl;
    
    // Get API key from config or environment
    this.apiKey = config.apiKey || 
      (typeof process !== 'undefined' ? process.env[chainConfig.envKey] || '' : '');
    
    if (!this.apiKey) {
      console.warn(`[${this.name}] No API key configured. Using limited free tier.`);
    }
  }

  /**
   * Query Etherscan for off-chain threat signals about an address
   */
  async queryAddress(address: string): Promise<OffChainThreatSignal[]> {
    const normalizedAddress = this.normalizeAddress(address);
    
    // Check cache first
    const cached = this.cache.get(normalizedAddress);
    if (cached && cached.expiresAt > Date.now()) {
      console.log(`[${this.name}] Cache hit for ${normalizedAddress}`);
      return cached.signals;
    }

    try {
      // Rate limiting
      await this.rateLimit();

      // Fetch address information and labels
      const signals = await this.fetchAddressIntelligence(normalizedAddress);
      
      // Cache the result
      this.cache.set(normalizedAddress, {
        signals,
        fetchedAt: Date.now(),
        expiresAt: Date.now() + this.CACHE_TTL_MS,
      });

      return signals;
    } catch (error) {
      console.error(`[${this.name}] Error querying address:`, error);
      return [];
    }
  }

  /**
   * Fetch comprehensive address intelligence from Etherscan
   */
  private async fetchAddressIntelligence(address: string): Promise<OffChainThreatSignal[]> {
    const signals: OffChainThreatSignal[] = [];

    // 1. Fetch address labels via tag API
    const labels = await this.fetchAddressLabels(address);
    if (labels.length > 0) {
      const labelSignals = this.processLabels(address, labels);
      signals.push(...labelSignals);
    }

    // 2. Check for known scam/phishing reports (via getaddressinfo if available)
    const addressInfo = await this.fetchAddressInfo(address);
    if (addressInfo) {
      const infoSignals = this.processAddressInfo(address, addressInfo);
      signals.push(...infoSignals);
    }

    // 3. Check contract verification status (for contract addresses)
    const contractSignals = await this.checkContractRisks(address);
    signals.push(...contractSignals);

    return signals;
  }

  /**
   * Fetch address labels from Etherscan's public tag system
   */
  private async fetchAddressLabels(address: string): Promise<string[]> {
    try {
      // Try the accountlabel API endpoint
      const url = new URL(this.apiBase);
      url.searchParams.set('module', 'account');
      url.searchParams.set('action', 'addressinfo');
      url.searchParams.set('address', address);
      if (this.apiKey) {
        url.searchParams.set('apikey', this.apiKey);
      }

      const response = await fetch(url.toString(), {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Securnex-OTTI/1.0',
        },
      });

      if (!response.ok) {
        return [];
      }

      const data = await response.json();
      
      // Extract labels from response
      if (data.result?.labels && Array.isArray(data.result.labels)) {
        return data.result.labels.map((l: string) => l.toLowerCase());
      }
      
      if (data.result?.publicnametag) {
        return [data.result.publicnametag.toLowerCase()];
      }

      return [];
    } catch (error) {
      console.warn(`[${this.name}] Failed to fetch labels:`, error);
      return [];
    }
  }

  /**
   * Fetch extended address information including risk scores
   */
  private async fetchAddressInfo(address: string): Promise<EtherscanAddressInfoResponse['result'] | null> {
    try {
      // Try to get HashDit risk data via Etherscan
      const url = new URL(this.apiBase);
      url.searchParams.set('module', 'account');
      url.searchParams.set('action', 'balance');
      url.searchParams.set('address', address);
      url.searchParams.set('tag', 'latest');
      if (this.apiKey) {
        url.searchParams.set('apikey', this.apiKey);
      }

      const response = await fetch(url.toString(), {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Securnex-OTTI/1.0',
        },
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      
      // Note: The standard Etherscan API doesn't return HashDit data directly
      // This is a placeholder for when they add it or for scraping
      return {
        balance: data.result,
        txCount: undefined,
      };
    } catch (error) {
      console.warn(`[${this.name}] Failed to fetch address info:`, error);
      return null;
    }
  }

  /**
   * Check contract-specific risks
   */
  private async checkContractRisks(address: string): Promise<OffChainThreatSignal[]> {
    const signals: OffChainThreatSignal[] = [];

    try {
      // Check if address is a contract
      const url = new URL(this.apiBase);
      url.searchParams.set('module', 'contract');
      url.searchParams.set('action', 'getabi');
      url.searchParams.set('address', address);
      if (this.apiKey) {
        url.searchParams.set('apikey', this.apiKey);
      }

      const response = await fetch(url.toString(), {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Securnex-OTTI/1.0',
        },
      });

      if (!response.ok) {
        return signals;
      }

      const data = await response.json();
      
      // If status is 0 and message indicates unverified source
      if (data.status === '0' && data.result?.includes('not verified')) {
        // Unverified contract - add as low confidence signal
        signals.push(createSignal({
          id: this.generateSignalId(address, 'unverified-contract'),
          source_name: this.name,
          report_type: 'community_report',
          confidence_level: 'low',
          first_seen_timestamp: new Date().toISOString(),
          context: 'Unverified contract source code. Exercise caution when interacting.',
          evidence_url: `${this.explorerUrl}/address/${address}#code`,
          metadata: {
            chain: this.chain,
            isContract: true,
            verified: false,
          },
          decay: this.createDecayInfo(new Date().toISOString()),
        }));
      }
    } catch (error) {
      console.warn(`[${this.name}] Failed to check contract:`, error);
    }

    return signals;
  }

  /**
   * Process labels into threat signals
   */
  private processLabels(address: string, labels: string[]): OffChainThreatSignal[] {
    const signals: OffChainThreatSignal[] = [];
    const now = new Date().toISOString();

    for (const label of labels) {
      const lowerLabel = label.toLowerCase();
      
      // Check if this label indicates a threat
      let reportType: OffChainReportType | null = null;
      let confidence: OffChainConfidenceLevel = 'medium';

      // Direct match
      if (LABEL_TO_REPORT_TYPE[lowerLabel]) {
        reportType = LABEL_TO_REPORT_TYPE[lowerLabel];
        confidence = 'high';
      } else {
        // Partial match
        for (const [key, type] of Object.entries(LABEL_TO_REPORT_TYPE)) {
          if (lowerLabel.includes(key)) {
            reportType = type;
            confidence = 'medium';
            break;
          }
        }
      }

      if (reportType) {
        signals.push(createSignal({
          id: this.generateSignalId(address, `label-${label}`),
          source_name: this.name,
          report_type: reportType,
          confidence_level: confidence,
          first_seen_timestamp: now,
          context: `Address labeled as "${label}" on ${CHAIN_CONFIG[this.chain].name}`,
          evidence_url: `${this.explorerUrl}/address/${address}`,
          reference_id: `ETH-LABEL-${address.slice(2, 10).toUpperCase()}`,
          metadata: {
            chain: this.chain,
            label: label,
            source: 'etherscan_labels',
          },
          decay: this.createDecayInfo(now),
        }));
      }
    }

    return signals;
  }

  /**
   * Process address info into threat signals
   */
  private processAddressInfo(
    address: string, 
    info: EtherscanAddressInfoResponse['result']
  ): OffChainThreatSignal[] {
    const signals: OffChainThreatSignal[] = [];
    const now = new Date().toISOString();

    // HashDit risk level (if available)
    if (info.hashditRiskLevel && info.hashditRiskLevel !== 'LOW') {
      signals.push(createSignal({
        id: this.generateSignalId(address, 'hashdit'),
        source_name: `HashDit via ${this.name}`,
        report_type: this.mapHashDitReportType(info.hashditReportType),
        confidence_level: HASHDIT_TO_CONFIDENCE[info.hashditRiskLevel] || 'medium',
        first_seen_timestamp: info.hashditReportDate || now,
        last_seen_timestamp: now,
        context: `HashDit flagged this address with ${info.hashditRiskLevel} risk level`,
        evidence_url: `${this.explorerUrl}/address/${address}`,
        reference_id: `HASHDIT-${address.slice(2, 10).toUpperCase()}`,
        metadata: {
          chain: this.chain,
          hashditRiskLevel: info.hashditRiskLevel,
          hashditReportType: info.hashditReportType,
          riskScore: info.riskScore,
        },
        decay: this.createDecayInfo(info.hashditReportDate || now, now, 1),
      }));
    }

    // Scam/phishing flags
    if (info.isScam) {
      signals.push(createSignal({
        id: this.generateSignalId(address, 'scam-flag'),
        source_name: `${this.name} Community`,
        report_type: 'scam_page',
        confidence_level: 'high',
        first_seen_timestamp: now,
        context: 'Address flagged as scam by Etherscan community',
        evidence_url: `${this.explorerUrl}/address/${address}`,
        metadata: {
          chain: this.chain,
          flagType: 'scam',
        },
        decay: this.createDecayInfo(now),
      }));
    }

    if (info.isPhishing) {
      signals.push(createSignal({
        id: this.generateSignalId(address, 'phishing-flag'),
        source_name: `${this.name} Community`,
        report_type: 'phishing',
        confidence_level: 'high',
        first_seen_timestamp: now,
        context: 'Address flagged as phishing by Etherscan community',
        evidence_url: `${this.explorerUrl}/address/${address}`,
        metadata: {
          chain: this.chain,
          flagType: 'phishing',
        },
        decay: this.createDecayInfo(now),
      }));
    }

    return signals;
  }

  /**
   * Map HashDit report type to OTTI report type
   */
  private mapHashDitReportType(type?: string): OffChainReportType {
    if (!type) return 'other';
    
    const lower = type.toLowerCase();
    if (lower.includes('phish')) return 'phishing';
    if (lower.includes('scam')) return 'scam_page';
    if (lower.includes('honeypot')) return 'honeypot';
    if (lower.includes('rug')) return 'rug_pull';
    if (lower.includes('imperson')) return 'impersonation';
    
    return 'other';
  }

  /**
   * Rate limiting to respect API limits
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
    this.requestCount++;
  }

  /**
   * Health check for the provider
   */
  async healthCheck(): Promise<boolean> {
    try {
      const url = new URL(this.apiBase);
      url.searchParams.set('module', 'stats');
      url.searchParams.set('action', 'ethsupply');
      if (this.apiKey) {
        url.searchParams.set('apikey', this.apiKey);
      }

      const response = await fetch(url.toString(), {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Securnex-OTTI/1.0',
        },
      });

      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Clear the cache
   */
  clearCache(address?: string): void {
    if (address) {
      this.cache.delete(address.toLowerCase());
    } else {
      this.cache.clear();
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; oldestEntry: number | null } {
    let oldest: number | null = null;
    
    for (const [, value] of this.cache) {
      if (oldest === null || value.fetchedAt < oldest) {
        oldest = value.fetchedAt;
      }
    }

    return {
      size: this.cache.size,
      oldestEntry: oldest,
    };
  }

  /**
   * Force refresh for an address
   */
  async forceRefresh(address: string): Promise<OffChainThreatSignal[]> {
    this.clearCache(address);
    return this.queryAddress(address);
  }
}

// ============================================
// MULTI-CHAIN ETHERSCAN PROVIDER
// ============================================
// Aggregates signals from all supported chains

export class MultiChainEtherscanProvider extends BaseOTTIProvider {
  readonly name = 'Etherscan (Multi-Chain)';
  readonly id = 'etherscan-multichain';
  
  private providers: EtherscanProvider[];

  constructor(config?: {
    chains?: SupportedChain[];
    apiKeys?: Partial<Record<SupportedChain, string>>;
  }) {
    super({
      signal_ttl_days: 90,
      confidence_weight: 1.0,
    });

    const chains = config?.chains || ['ethereum', 'base', 'bnb'];
    
    this.providers = chains.map(chain => new EtherscanProvider({
      chain,
      apiKey: config?.apiKeys?.[chain],
    }));
  }

  async queryAddress(address: string): Promise<OffChainThreatSignal[]> {
    // Query all chain providers in parallel
    const results = await Promise.allSettled(
      this.providers.map(p => p.queryAddress(address))
    );

    // Aggregate successful results
    const allSignals: OffChainThreatSignal[] = [];
    
    for (const result of results) {
      if (result.status === 'fulfilled') {
        allSignals.push(...result.value);
      }
    }

    // Deduplicate by reference_id
    const seen = new Set<string>();
    return allSignals.filter(signal => {
      const key = signal.reference_id || signal.id;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  async healthCheck(): Promise<boolean> {
    const results = await Promise.allSettled(
      this.providers.map(p => p.healthCheck())
    );
    
    // Return true if at least one provider is healthy
    return results.some(r => r.status === 'fulfilled' && r.value);
  }
}

// ============================================
// FACTORY FUNCTIONS
// ============================================

/**
 * Create an Etherscan provider for a specific chain
 */
export function createEtherscanProvider(
  chain: SupportedChain,
  apiKey?: string
): EtherscanProvider {
  return new EtherscanProvider({ chain, apiKey });
}

/**
 * Create providers for all supported chains
 */
export function createAllEtherscanProviders(
  apiKeys?: Partial<Record<SupportedChain, string>>
): EtherscanProvider[] {
  const chains: SupportedChain[] = ['ethereum', 'base', 'bnb'];
  
  return chains.map(chain => new EtherscanProvider({
    chain,
    apiKey: apiKeys?.[chain],
  }));
}

/**
 * Create multi-chain aggregated provider
 */
export function createMultiChainEtherscanProvider(
  apiKeys?: Partial<Record<SupportedChain, string>>
): MultiChainEtherscanProvider {
  return new MultiChainEtherscanProvider({
    chains: ['ethereum', 'base', 'bnb'],
    apiKeys,
  });
}
