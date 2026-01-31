// ============================================
// SCAMSNIFFER THREAT PROVIDER
// ============================================
// Production integration with ScamSniffer API.
// ScamSniffer specializes in detecting wallet drainers and phishing sites.
//
// API Documentation: https://docs.scamsniffer.io/
//
// PROVIDER-SPECIFIC QUIRKS:
// - Strong focus on wallet drainer detection
// - Tracks drainer families (Inferno, Pink, Angel, etc.)
// - Provides domain blocklists
// - May return multiple threat types for single address

import { BaseThreatProvider, createProviderConfig } from './base-provider';
import {
  ThreatFinding,
  ThreatIntelInput,
  ThreatCategory,
  ThreatSeverity,
  ThreatProviderConfig,
} from '../types';

// ============================================
// SCAMSNIFFER API TYPES
// ============================================

interface ScamSnifferAddressResponse {
  isRisky: boolean;
  riskLevel?: 'low' | 'medium' | 'high' | 'critical';
  risks?: ScamSnifferRisk[];
  metadata?: {
    firstSeen?: string;
    lastSeen?: string;
    totalReports?: number;
    drainerFamily?: string;
    relatedAddresses?: string[];
    relatedDomains?: string[];
  };
}

interface ScamSnifferRisk {
  type: string;
  severity: string;
  description: string;
  evidence?: string[];
  reportedAt?: string;
  source?: string;
}

interface ScamSnifferDomainResponse {
  isBlocked: boolean;
  blockReason?: string;
  risks?: ScamSnifferRisk[];
  metadata?: {
    registeredAt?: string;
    reportedAt?: string;
    category?: string;
    drainerKit?: string;
  };
}

// Known drainer families tracked by ScamSniffer
const DRAINER_FAMILIES = [
  'Inferno',
  'Pink',
  'Angel',
  'Monkey',
  'Venom',
  'MS',
  'Pussy',
  'Atomic',
  'Wallet Connect',
  'Permit2',
] as const;

// ============================================
// SCAMSNIFFER PROVIDER IMPLEMENTATION
// ============================================

export class ScamSnifferProvider extends BaseThreatProvider {
  readonly name = 'ScamSniffer';
  readonly id = 'scamsniffer';

  constructor(config: Partial<ThreatProviderConfig> = {}) {
    super(createProviderConfig('scamsniffer', 'ScamSniffer', {
      endpoint: 'https://api.scamsniffer.io/v1',
      apiKeyEnvVar: 'SCAMSNIFFER_API_KEY',
      timeoutMs: 5000,
      maxRetries: 2,
      retryDelayMs: 1000,
      confidenceWeight: 1.1, // Slightly higher trust - specialists in drainer detection
      rateLimit: {
        requestsPerMinute: 100,
        requestsPerDay: 50000,
      },
      ...config,
    }));
  }

  /**
   * Execute query to ScamSniffer API.
   */
  protected async executeQuery(input: ThreatIntelInput): Promise<ThreatFinding[]> {
    const apiKey = this.getApiKey();
    if (!apiKey) {
      this.log('warn', 'No API key configured, skipping ScamSniffer check');
      return [];
    }

    try {
      if (input.type === 'domain' || input.type === 'url') {
        return await this.queryDomain(input, apiKey);
      } else {
        return await this.queryAddress(input, apiKey);
      }
    } catch (error) {
      this.log('error', `ScamSniffer query failed: ${this.sanitizeError(error as Error)}`);
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
          'X-Chain': input.chain || 'ethereum',
        },
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        // Not found = not risky
        this.log('info', `ScamSniffer: ${normalizedAddress.slice(0, 10)}... not in database`);
        return [];
      }
      if (response.status === 429) {
        this.log('warn', 'Rate limited by ScamSniffer');
        return [];
      }
      throw new Error(`ScamSniffer API error: ${response.status}`);
    }

    const data: ScamSnifferAddressResponse = await response.json();
    return this.processAddressResponse(data, input);
  }

  /**
   * Query domain/URL.
   */
  private async queryDomain(input: ThreatIntelInput, apiKey: string): Promise<ThreatFinding[]> {
    // Extract domain from URL if needed
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
        this.log('warn', 'Rate limited by ScamSniffer');
        return [];
      }
      throw new Error(`ScamSniffer API error: ${response.status}`);
    }

    const data: ScamSnifferDomainResponse = await response.json();
    return this.processDomainResponse(data, input);
  }

  /**
   * Process address response into ThreatFindings.
   */
  private processAddressResponse(
    data: ScamSnifferAddressResponse,
    input: ThreatIntelInput
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    if (!data.isRisky) {
      this.log('info', `ScamSniffer: ${input.value.slice(0, 10)}... is not risky`);
      return [];
    }

    // Process each risk
    if (data.risks && data.risks.length > 0) {
      for (const risk of data.risks) {
        const finding = this.createRiskFinding(risk, data, input);
        findings.push(finding);
      }
    } else {
      // Create a general finding if no specific risks
      const finding = this.createFinding({
        category: this.determineAddressCategory(data),
        severity: this.mapSeverity(data.riskLevel || 'medium'),
        confidence: this.calculateAddressConfidence(data),
        description: this.buildAddressDescription(data, input),
        firstReportedAt: data.metadata?.firstSeen,
        lastSeenAt: data.metadata?.lastSeen,
        referenceUrl: `https://scamsniffer.io/address/${input.value}`,
        metadata: {
          drainerFamily: data.metadata?.drainerFamily,
          totalReports: data.metadata?.totalReports,
          relatedAddresses: data.metadata?.relatedAddresses,
        },
        tags: data.metadata?.drainerFamily ? [data.metadata.drainerFamily] : undefined,
        raw: data,
      });
      findings.push(finding);
    }

    this.log('info', `ScamSniffer: Found ${findings.length} threat(s) for ${input.value.slice(0, 10)}...`);
    return findings;
  }

  /**
   * Process domain response into ThreatFindings.
   */
  private processDomainResponse(
    data: ScamSnifferDomainResponse,
    input: ThreatIntelInput
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    if (!data.isBlocked) {
      return [];
    }

    const category = this.determineDomainCategory(data);
    const severity = this.determineDomainSeverity(data);

    const finding = this.createFinding({
      category,
      severity,
      confidence: 85, // High confidence for blocklisted domains
      description: this.buildDomainDescription(data, input),
      firstReportedAt: data.metadata?.reportedAt,
      referenceUrl: `https://scamsniffer.io/domain/${encodeURIComponent(input.value)}`,
      metadata: {
        blockReason: data.blockReason,
        drainerKit: data.metadata?.drainerKit,
        domainCategory: data.metadata?.category,
      },
      tags: data.metadata?.drainerKit ? ['drainer', data.metadata.drainerKit] : ['scam'],
      raw: data,
    });

    findings.push(finding);
    return findings;
  }

  /**
   * Create a ThreatFinding from a ScamSniffer risk.
   */
  private createRiskFinding(
    risk: ScamSnifferRisk,
    data: ScamSnifferAddressResponse,
    input: ThreatIntelInput
  ): ThreatFinding {
    return this.createFinding({
      category: this.mapCategory(risk.type),
      severity: this.mapSeverity(risk.severity),
      confidence: this.calculateRiskConfidence(risk, data),
      description: risk.description,
      firstReportedAt: risk.reportedAt || data.metadata?.firstSeen,
      lastSeenAt: data.metadata?.lastSeen,
      referenceUrl: `https://scamsniffer.io/address/${input.value}`,
      metadata: {
        riskType: risk.type,
        evidence: risk.evidence,
        source: risk.source,
        drainerFamily: data.metadata?.drainerFamily,
      },
      tags: this.buildTags(risk, data),
      raw: risk,
    });
  }

  /**
   * Determine category for address.
   */
  private determineAddressCategory(data: ScamSnifferAddressResponse): ThreatCategory {
    // Check for drainer family
    if (data.metadata?.drainerFamily) {
      return 'drainer';
    }

    // Check risks for category hints
    if (data.risks && data.risks.length > 0) {
      for (const risk of data.risks) {
        if (risk.type.toLowerCase().includes('drain')) return 'drainer';
        if (risk.type.toLowerCase().includes('phish')) return 'phishing';
        if (risk.type.toLowerCase().includes('scam')) return 'scam';
      }
    }

    return 'unknown';
  }

  /**
   * Determine category for domain.
   */
  private determineDomainCategory(data: ScamSnifferDomainResponse): ThreatCategory {
    if (data.metadata?.drainerKit) {
      return 'drainer';
    }

    const category = data.metadata?.category?.toLowerCase();
    if (category) {
      if (category.includes('phish')) return 'phishing';
      if (category.includes('drain')) return 'drainer';
      if (category.includes('scam')) return 'scam';
    }

    const reason = data.blockReason?.toLowerCase();
    if (reason) {
      if (reason.includes('phish')) return 'phishing';
      if (reason.includes('drain')) return 'drainer';
      if (reason.includes('scam')) return 'scam';
    }

    return 'scam'; // Default for blocked domains
  }

  /**
   * Determine severity for domain.
   */
  private determineDomainSeverity(data: ScamSnifferDomainResponse): ThreatSeverity {
    // Drainer kits are critical
    if (data.metadata?.drainerKit) {
      return 'critical';
    }

    // Check for severity hints in risks
    if (data.risks && data.risks.length > 0) {
      const severities = data.risks.map(r => this.mapSeverity(r.severity));
      if (severities.includes('critical')) return 'critical';
      if (severities.includes('high')) return 'high';
    }

    return 'high'; // Default for blocked domains
  }

  /**
   * Calculate confidence for address.
   */
  private calculateAddressConfidence(data: ScamSnifferAddressResponse): number {
    let confidence = 70;

    // Boost for known drainer family
    if (data.metadata?.drainerFamily) {
      confidence += 20;
    }

    // Boost for multiple reports
    const reports = data.metadata?.totalReports || 0;
    if (reports >= 10) confidence += 10;
    else if (reports >= 5) confidence += 5;

    // Boost for related addresses (indicates pattern)
    if (data.metadata?.relatedAddresses?.length) {
      confidence += 5;
    }

    return Math.min(100, confidence);
  }

  /**
   * Calculate confidence for specific risk.
   */
  private calculateRiskConfidence(
    risk: ScamSnifferRisk,
    data: ScamSnifferAddressResponse
  ): number {
    let confidence = 65;

    // Boost for evidence
    if (risk.evidence && risk.evidence.length > 0) {
      confidence += risk.evidence.length * 5;
    }

    // Boost for drainer family association
    if (data.metadata?.drainerFamily) {
      confidence += 15;
    }

    return Math.min(100, confidence);
  }

  /**
   * Build description for address.
   */
  private buildAddressDescription(
    data: ScamSnifferAddressResponse,
    input: ThreatIntelInput
  ): string {
    const parts: string[] = [];

    parts.push(`ScamSniffer has flagged this ${input.type} as risky`);

    if (data.metadata?.drainerFamily) {
      parts.push(`Associated with ${data.metadata.drainerFamily} drainer family`);
    }

    if (data.riskLevel) {
      parts.push(`Risk level: ${data.riskLevel}`);
    }

    if (data.metadata?.totalReports) {
      parts.push(`${data.metadata.totalReports} reports`);
    }

    return parts.join('. ') + '.';
  }

  /**
   * Build description for domain.
   */
  private buildDomainDescription(
    data: ScamSnifferDomainResponse,
    input: ThreatIntelInput
  ): string {
    const parts: string[] = [];

    parts.push(`This domain is blocked by ScamSniffer`);

    if (data.blockReason) {
      parts.push(data.blockReason);
    }

    if (data.metadata?.drainerKit) {
      parts.push(`Uses ${data.metadata.drainerKit} drainer kit`);
    }

    return parts.join('. ') + '.';
  }

  /**
   * Build tags from risk and data.
   */
  private buildTags(risk: ScamSnifferRisk, data: ScamSnifferAddressResponse): string[] {
    const tags: string[] = [];

    if (data.metadata?.drainerFamily) {
      tags.push(data.metadata.drainerFamily.toLowerCase());
      tags.push('drainer');
    }

    if (risk.type) {
      tags.push(risk.type.toLowerCase().replace(/\s+/g, '_'));
    }

    return [...new Set(tags)]; // Deduplicate
  }

  /**
   * Check if an address is associated with a known drainer family.
   */
  public isDrainerFamilyAssociated(data: ScamSnifferAddressResponse): boolean {
    if (!data.metadata?.drainerFamily) return false;
    
    return DRAINER_FAMILIES.some(
      family => data.metadata?.drainerFamily?.toLowerCase().includes(family.toLowerCase())
    );
  }

  /**
   * Override category mapping for ScamSniffer-specific types.
   */
  protected override mapCategory(externalCategory: string): ThreatCategory {
    const scamSnifferMapping: Record<string, ThreatCategory> = {
      'wallet_drainer': 'drainer',
      'drainer_contract': 'drainer',
      'phishing_signature': 'phishing',
      'approval_scam': 'drainer',
      'fake_airdrop': 'scam',
      'honeypot_token': 'honeypot',
      'rug_pull': 'rug_pull',
    };

    const normalized = externalCategory.toLowerCase().replace(/[_\s-]+/g, '_');
    return scamSnifferMapping[normalized] || super.mapCategory(externalCategory);
  }
}

/**
 * Factory function to create ScamSniffer provider.
 */
export function createScamSnifferProvider(
  config?: Partial<ThreatProviderConfig>
): ScamSnifferProvider {
  return new ScamSnifferProvider(config);
}
