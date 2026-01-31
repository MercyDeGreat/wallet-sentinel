// ============================================
// WALLET GUARD THREAT PROVIDER
// ============================================
// Production integration with Wallet Guard API.
// Wallet Guard provides real-time transaction simulation and threat detection.
//
// API Documentation: https://docs.walletguard.app/
//
// PROVIDER-SPECIFIC QUIRKS:
// - Strong focus on transaction simulation
// - Detects approval scams and drainers
// - Provides risk explanations with confidence scores
// - Browser extension data source (high volume)

import { BaseThreatProvider, createProviderConfig } from './base-provider';
import {
  ThreatFinding,
  ThreatIntelInput,
  ThreatCategory,
  ThreatSeverity,
  ThreatProviderConfig,
} from '../types';

// ============================================
// WALLET GUARD API TYPES
// ============================================

interface WalletGuardAddressResponse {
  address: string;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  isKnownThreat: boolean;
  threats?: WalletGuardThreat[];
  metadata?: {
    chain?: string;
    label?: string;
    contractType?: string;
    firstSeen?: string;
    lastSeen?: string;
    reportCount?: number;
    userReports?: number;
    verificationStatus?: 'verified' | 'unverified' | 'suspicious';
  };
}

interface WalletGuardThreat {
  type: WalletGuardThreatType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  title: string;
  description: string;
  recommendation?: string;
  evidence?: {
    transactionHashes?: string[];
    relatedAddresses?: string[];
    signatures?: string[];
  };
  detectedAt?: string;
}

type WalletGuardThreatType =
  | 'wallet_drainer'
  | 'approval_scam'
  | 'permit_abuse'
  | 'phishing_contract'
  | 'honeypot_token'
  | 'malicious_approval'
  | 'suspicious_activity'
  | 'known_scammer'
  | 'rug_pull_risk'
  | 'unverified_contract';

interface WalletGuardDomainResponse {
  domain: string;
  status: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  threats?: WalletGuardThreat[];
  metadata?: {
    category?: string;
    firstSeen?: string;
    userReports?: number;
    associatedAddresses?: string[];
  };
}

// ============================================
// WALLET GUARD PROVIDER IMPLEMENTATION
// ============================================

export class WalletGuardProvider extends BaseThreatProvider {
  readonly name = 'Wallet Guard';
  readonly id = 'walletguard';

  constructor(config: Partial<ThreatProviderConfig> = {}) {
    super(createProviderConfig('walletguard', 'Wallet Guard', {
      endpoint: 'https://api.walletguard.app/v1',
      apiKeyEnvVar: 'WALLETGUARD_API_KEY',
      timeoutMs: 5000,
      maxRetries: 2,
      retryDelayMs: 1000,
      confidenceWeight: 1.0, // High trust - real-time detection
      rateLimit: {
        requestsPerMinute: 60,
        requestsPerDay: 10000,
      },
      ...config,
    }));
  }

  /**
   * Execute query to Wallet Guard API.
   */
  protected async executeQuery(input: ThreatIntelInput): Promise<ThreatFinding[]> {
    const apiKey = this.getApiKey();
    if (!apiKey) {
      this.log('warn', 'No API key configured, skipping Wallet Guard check');
      return [];
    }

    try {
      if (input.type === 'domain' || input.type === 'url') {
        return await this.queryDomain(input, apiKey);
      } else {
        return await this.queryAddress(input, apiKey);
      }
    } catch (error) {
      this.log('error', `Wallet Guard query failed: ${this.sanitizeError(error as Error)}`);
      throw error;
    }
  }

  /**
   * Query wallet/contract address.
   */
  private async queryAddress(input: ThreatIntelInput, apiKey: string): Promise<ThreatFinding[]> {
    const normalizedAddress = this.normalizeAddress(input.value);

    const response = await this.makeRequest(
      `${this._config.endpoint}/address/${normalizedAddress}`,
      {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'X-Chain-ID': this.getChainId(input.chain),
        },
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        this.log('info', `Wallet Guard: ${normalizedAddress.slice(0, 10)}... not in database`);
        return [];
      }
      if (response.status === 429) {
        this.log('warn', 'Rate limited by Wallet Guard');
        return [];
      }
      throw new Error(`Wallet Guard API error: ${response.status}`);
    }

    const data: WalletGuardAddressResponse = await response.json();
    return this.processAddressResponse(data, input);
  }

  /**
   * Query domain/URL.
   */
  private async queryDomain(input: ThreatIntelInput, apiKey: string): Promise<ThreatFinding[]> {
    let domain = input.value;
    if (input.type === 'url') {
      try {
        const url = new URL(input.value);
        domain = url.hostname;
      } catch {
        domain = input.value;
      }
    }

    const response = await this.makeRequest(
      `${this._config.endpoint}/domain/${encodeURIComponent(domain)}`,
      {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
        },
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        return [];
      }
      if (response.status === 429) {
        this.log('warn', 'Rate limited by Wallet Guard');
        return [];
      }
      throw new Error(`Wallet Guard API error: ${response.status}`);
    }

    const data: WalletGuardDomainResponse = await response.json();
    return this.processDomainResponse(data, input);
  }

  /**
   * Process address response into ThreatFindings.
   */
  private processAddressResponse(
    data: WalletGuardAddressResponse,
    input: ThreatIntelInput
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Check if this is a known threat
    if (!data.isKnownThreat && data.riskLevel === 'safe') {
      this.log('info', `Wallet Guard: ${input.value.slice(0, 10)}... is safe`);
      return [];
    }

    // Process specific threats
    if (data.threats && data.threats.length > 0) {
      for (const threat of data.threats) {
        const finding = this.createThreatFinding(threat, input, data.metadata);
        findings.push(finding);
      }
    }

    // If no specific threats but risk level is high, create general finding
    if (findings.length === 0 && this.isHighRisk(data.riskLevel)) {
      const finding = this.createFinding({
        category: this.inferCategory(data),
        severity: this.mapRiskLevelToSeverity(data.riskLevel),
        confidence: this.calculateAddressConfidence(data),
        description: this.buildAddressDescription(data, input),
        firstReportedAt: data.metadata?.firstSeen,
        lastSeenAt: data.metadata?.lastSeen,
        referenceUrl: `https://walletguard.app/address/${input.value}`,
        metadata: {
          riskLevel: data.riskLevel,
          label: data.metadata?.label,
          contractType: data.metadata?.contractType,
          verificationStatus: data.metadata?.verificationStatus,
          reportCount: data.metadata?.reportCount,
        },
        tags: this.buildAddressTags(data),
        raw: data,
      });
      findings.push(finding);
    }

    this.log('info', `Wallet Guard: Found ${findings.length} threat(s) for ${input.value.slice(0, 10)}...`);
    return findings;
  }

  /**
   * Process domain response into ThreatFindings.
   */
  private processDomainResponse(
    data: WalletGuardDomainResponse,
    input: ThreatIntelInput
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    if (data.status === 'safe' || data.status === 'unknown') {
      this.log('info', `Wallet Guard: ${input.value} is ${data.status}`);
      return [];
    }

    // Process specific threats
    if (data.threats && data.threats.length > 0) {
      for (const threat of data.threats) {
        const finding = this.createThreatFinding(threat, input, data.metadata);
        findings.push(finding);
      }
    }

    // Create general finding if malicious but no specific threats
    if (findings.length === 0 && data.status === 'malicious') {
      const finding = this.createFinding({
        category: this.inferDomainCategory(data),
        severity: 'high',
        confidence: 75,
        description: `This domain has been flagged as malicious by Wallet Guard.`,
        firstReportedAt: data.metadata?.firstSeen,
        referenceUrl: 'https://walletguard.app',
        metadata: {
          status: data.status,
          category: data.metadata?.category,
          userReports: data.metadata?.userReports,
        },
        raw: data,
      });
      findings.push(finding);
    }

    this.log('info', `Wallet Guard: Found ${findings.length} threat(s) for ${input.value}`);
    return findings;
  }

  /**
   * Create ThreatFinding from Wallet Guard threat.
   */
  private createThreatFinding(
    threat: WalletGuardThreat,
    input: ThreatIntelInput,
    metadata?: Record<string, unknown>
  ): ThreatFinding {
    return this.createFinding({
      category: this.mapWalletGuardType(threat.type),
      severity: threat.severity,
      confidence: threat.confidence,
      description: `${threat.title}: ${threat.description}`,
      firstReportedAt: threat.detectedAt,
      referenceUrl: `https://walletguard.app/address/${input.value}`,
      metadata: {
        threatType: threat.type,
        recommendation: threat.recommendation,
        evidence: threat.evidence,
        ...metadata,
      },
      tags: this.buildThreatTags(threat),
      raw: threat,
    });
  }

  /**
   * Map Wallet Guard threat type to ThreatCategory.
   */
  private mapWalletGuardType(type: WalletGuardThreatType): ThreatCategory {
    const mapping: Record<WalletGuardThreatType, ThreatCategory> = {
      'wallet_drainer': 'drainer',
      'approval_scam': 'drainer',
      'permit_abuse': 'drainer',
      'phishing_contract': 'phishing',
      'honeypot_token': 'honeypot',
      'malicious_approval': 'drainer',
      'suspicious_activity': 'unknown',
      'known_scammer': 'scam',
      'rug_pull_risk': 'rug_pull',
      'unverified_contract': 'unknown',
    };

    return mapping[type] || 'unknown';
  }

  /**
   * Map risk level to severity.
   */
  private mapRiskLevelToSeverity(riskLevel: string): ThreatSeverity {
    const mapping: Record<string, ThreatSeverity> = {
      'low': 'low',
      'medium': 'medium',
      'high': 'high',
      'critical': 'critical',
    };
    return mapping[riskLevel] || 'medium';
  }

  /**
   * Check if risk level is high enough to report.
   */
  private isHighRisk(riskLevel: string): boolean {
    return ['medium', 'high', 'critical'].includes(riskLevel);
  }

  /**
   * Infer category from address data.
   */
  private inferCategory(data: WalletGuardAddressResponse): ThreatCategory {
    // Check label for hints
    const label = data.metadata?.label?.toLowerCase() || '';
    if (label.includes('drainer') || label.includes('drain')) return 'drainer';
    if (label.includes('phish')) return 'phishing';
    if (label.includes('scam')) return 'scam';
    if (label.includes('honeypot')) return 'honeypot';

    // Check verification status
    if (data.metadata?.verificationStatus === 'suspicious') {
      return 'scam';
    }

    return 'unknown';
  }

  /**
   * Infer category from domain data.
   */
  private inferDomainCategory(data: WalletGuardDomainResponse): ThreatCategory {
    const category = data.metadata?.category?.toLowerCase() || '';
    
    if (category.includes('phish')) return 'phishing';
    if (category.includes('drain')) return 'drainer';
    if (category.includes('scam')) return 'scam';
    
    return 'phishing'; // Default for malicious domains
  }

  /**
   * Calculate confidence for address.
   */
  private calculateAddressConfidence(data: WalletGuardAddressResponse): number {
    let confidence = 60;

    // Boost for multiple reports
    const reports = data.metadata?.reportCount || 0;
    if (reports >= 10) confidence += 20;
    else if (reports >= 5) confidence += 10;
    else if (reports >= 2) confidence += 5;

    // Boost for user reports
    const userReports = data.metadata?.userReports || 0;
    if (userReports >= 5) confidence += 10;
    else if (userReports >= 2) confidence += 5;

    // Boost for high risk level
    if (data.riskLevel === 'critical') confidence += 15;
    else if (data.riskLevel === 'high') confidence += 10;

    return Math.min(100, confidence);
  }

  /**
   * Build description for address.
   */
  private buildAddressDescription(
    data: WalletGuardAddressResponse,
    input: ThreatIntelInput
  ): string {
    const parts: string[] = [];

    parts.push(`Wallet Guard has flagged this ${input.type} as ${data.riskLevel} risk`);

    if (data.metadata?.label) {
      parts.push(`Label: ${data.metadata.label}`);
    }

    if (data.metadata?.reportCount) {
      parts.push(`${data.metadata.reportCount} reports`);
    }

    if (data.metadata?.verificationStatus === 'suspicious') {
      parts.push('Verification status: suspicious');
    }

    return parts.join('. ') + '.';
  }

  /**
   * Build tags for address.
   */
  private buildAddressTags(data: WalletGuardAddressResponse): string[] {
    const tags: string[] = [data.riskLevel];

    if (data.metadata?.label) {
      tags.push(data.metadata.label.toLowerCase().replace(/\s+/g, '_'));
    }

    if (data.metadata?.contractType) {
      tags.push(data.metadata.contractType.toLowerCase());
    }

    return tags;
  }

  /**
   * Build tags for threat.
   */
  private buildThreatTags(threat: WalletGuardThreat): string[] {
    const tags: string[] = [threat.type, threat.severity];
    return tags;
  }

  /**
   * Get chain ID for Wallet Guard API.
   */
  private getChainId(chain?: string): string {
    const chainMap: Record<string, string> = {
      'ethereum': '1',
      'base': '8453',
      'bnb': '56',
      'polygon': '137',
      'arbitrum': '42161',
      'optimism': '10',
      'avalanche': '43114',
    };

    return chainMap[chain || 'ethereum'] || '1';
  }

  /**
   * Override category mapping for Wallet Guard-specific types.
   */
  protected override mapCategory(externalCategory: string): ThreatCategory {
    const walletGuardMapping: Record<string, ThreatCategory> = {
      'drainer_contract': 'drainer',
      'approval_attack': 'drainer',
      'permit2_abuse': 'drainer',
      'setapprovalforall_abuse': 'drainer',
      'fake_claim': 'phishing',
      'malicious_mint': 'scam',
    };

    const normalized = externalCategory.toLowerCase().replace(/[_\s-]+/g, '_');
    return walletGuardMapping[normalized] || super.mapCategory(externalCategory);
  }
}

/**
 * Factory function to create Wallet Guard provider.
 */
export function createWalletGuardProvider(
  config?: Partial<ThreatProviderConfig>
): WalletGuardProvider {
  return new WalletGuardProvider(config);
}
