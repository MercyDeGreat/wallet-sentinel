// ============================================
// PHISHFORT THREAT PROVIDER
// ============================================
// Production integration with PhishFort API.
// PhishFort specializes in brand protection and impersonation detection.
//
// API Documentation: https://docs.phishfort.com/
//
// PROVIDER-SPECIFIC QUIRKS:
// - Strong focus on brand impersonation
// - Tracks fake support/helpdesk scams
// - Domain-centric but also tracks associated wallets
// - Includes takedown status information

import { BaseThreatProvider, createProviderConfig } from './base-provider';
import {
  ThreatFinding,
  ThreatIntelInput,
  ThreatCategory,
  ThreatSeverity,
  ThreatProviderConfig,
} from '../types';

// ============================================
// PHISHFORT API TYPES
// ============================================

interface PhishFortCheckResponse {
  status: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  threats?: PhishFortThreat[];
  brands?: PhishFortBrandMatch[];
  metadata?: {
    checkedAt: string;
    cacheHit?: boolean;
    totalThreats?: number;
  };
}

interface PhishFortThreat {
  id: string;
  type: PhishFortThreatType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  description: string;
  detectedAt: string;
  lastSeenAt?: string;
  evidence?: {
    screenshots?: string[];
    reportUrls?: string[];
    relatedAssets?: string[];
  };
  takedownStatus?: 'pending' | 'in_progress' | 'completed' | 'failed';
}

type PhishFortThreatType = 
  | 'impersonation'
  | 'fake_support'
  | 'phishing'
  | 'social_engineering'
  | 'brand_abuse'
  | 'credential_theft'
  | 'scam_website';

interface PhishFortBrandMatch {
  brand: string;
  matchType: 'exact' | 'similar' | 'typosquat' | 'keyword';
  confidence: number;
  legitimate: boolean;
}

interface PhishFortWalletResponse {
  isAssociated: boolean;
  associatedThreats?: PhishFortThreat[];
  domains?: string[];
  firstSeen?: string;
  lastSeen?: string;
}

// ============================================
// PHISHFORT PROVIDER IMPLEMENTATION
// ============================================

export class PhishFortProvider extends BaseThreatProvider {
  readonly name = 'PhishFort';
  readonly id = 'phishfort';

  constructor(config: Partial<ThreatProviderConfig> = {}) {
    super(createProviderConfig('phishfort', 'PhishFort', {
      endpoint: 'https://api.phishfort.com/v1',
      apiKeyEnvVar: 'PHISHFORT_API_KEY',
      timeoutMs: 5000,
      maxRetries: 2,
      retryDelayMs: 1000,
      confidenceWeight: 0.95, // Slightly lower - focused on brand protection
      rateLimit: {
        requestsPerMinute: 30,
        requestsPerDay: 5000,
      },
      ...config,
    }));
  }

  /**
   * Execute query to PhishFort API.
   */
  protected async executeQuery(input: ThreatIntelInput): Promise<ThreatFinding[]> {
    const apiKey = this.getApiKey();
    if (!apiKey) {
      this.log('warn', 'No API key configured, skipping PhishFort check');
      return [];
    }

    try {
      if (input.type === 'wallet' || input.type === 'contract') {
        return await this.checkWallet(input, apiKey);
      } else {
        return await this.checkDomain(input, apiKey);
      }
    } catch (error) {
      this.log('error', `PhishFort query failed: ${this.sanitizeError(error as Error)}`);
      throw error;
    }
  }

  /**
   * Check wallet/contract address.
   */
  private async checkWallet(input: ThreatIntelInput, apiKey: string): Promise<ThreatFinding[]> {
    const normalizedAddress = this.normalizeAddress(input.value);

    const response = await this.makeRequest(
      `${this._config.endpoint}/wallet/check`,
      {
        method: 'POST',
        headers: {
          'X-API-Key': apiKey,
        },
        body: JSON.stringify({
          address: normalizedAddress,
          chain: input.chain || 'ethereum',
        }),
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        this.log('info', `PhishFort: ${normalizedAddress.slice(0, 10)}... not found`);
        return [];
      }
      if (response.status === 429) {
        this.log('warn', 'Rate limited by PhishFort');
        return [];
      }
      throw new Error(`PhishFort API error: ${response.status}`);
    }

    const data: PhishFortWalletResponse = await response.json();
    return this.processWalletResponse(data, input);
  }

  /**
   * Check domain/URL.
   */
  private async checkDomain(input: ThreatIntelInput, apiKey: string): Promise<ThreatFinding[]> {
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
      `${this._config.endpoint}/domain/check`,
      {
        method: 'POST',
        headers: {
          'X-API-Key': apiKey,
        },
        body: JSON.stringify({
          domain,
          includeScreenshots: false,
        }),
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        return [];
      }
      if (response.status === 429) {
        this.log('warn', 'Rate limited by PhishFort');
        return [];
      }
      throw new Error(`PhishFort API error: ${response.status}`);
    }

    const data: PhishFortCheckResponse = await response.json();
    return this.processDomainResponse(data, input);
  }

  /**
   * Process wallet response into ThreatFindings.
   */
  private processWalletResponse(
    data: PhishFortWalletResponse,
    input: ThreatIntelInput
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    if (!data.isAssociated) {
      this.log('info', `PhishFort: ${input.value.slice(0, 10)}... not associated with threats`);
      return [];
    }

    // Process associated threats
    if (data.associatedThreats && data.associatedThreats.length > 0) {
      for (const threat of data.associatedThreats) {
        const finding = this.createThreatFinding(threat, input, {
          associatedDomains: data.domains,
          firstSeen: data.firstSeen,
          lastSeen: data.lastSeen,
        });
        findings.push(finding);
      }
    } else {
      // Create general finding for association
      const finding = this.createFinding({
        category: 'impersonation',
        severity: 'medium',
        confidence: 60,
        description: `This wallet is associated with ${data.domains?.length || 0} suspicious domain(s) tracked by PhishFort.`,
        firstReportedAt: data.firstSeen,
        lastSeenAt: data.lastSeen,
        referenceUrl: 'https://phishfort.com',
        metadata: {
          associatedDomains: data.domains,
        },
        tags: ['associated_wallet'],
        raw: data,
      });
      findings.push(finding);
    }

    this.log('info', `PhishFort: Found ${findings.length} threat(s) for ${input.value.slice(0, 10)}...`);
    return findings;
  }

  /**
   * Process domain response into ThreatFindings.
   */
  private processDomainResponse(
    data: PhishFortCheckResponse,
    input: ThreatIntelInput
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    if (data.status === 'safe' || data.status === 'unknown') {
      this.log('info', `PhishFort: ${input.value} is ${data.status}`);
      return [];
    }

    // Process each threat
    if (data.threats && data.threats.length > 0) {
      for (const threat of data.threats) {
        const finding = this.createThreatFinding(threat, input, {
          brands: data.brands,
        });
        findings.push(finding);
      }
    }

    // Add brand impersonation findings
    if (data.brands && data.brands.length > 0) {
      const illegitimateBrands = data.brands.filter(b => !b.legitimate);
      for (const brand of illegitimateBrands) {
        const finding = this.createBrandFinding(brand, input);
        findings.push(finding);
      }
    }

    // If no specific threats but status is malicious, create general finding
    if (findings.length === 0 && data.status === 'malicious') {
      const finding = this.createFinding({
        category: 'phishing',
        severity: 'high',
        confidence: 75,
        description: `This domain has been flagged as malicious by PhishFort.`,
        referenceUrl: 'https://phishfort.com',
        metadata: {
          status: data.status,
        },
        raw: data,
      });
      findings.push(finding);
    }

    this.log('info', `PhishFort: Found ${findings.length} threat(s) for ${input.value}`);
    return findings;
  }

  /**
   * Create ThreatFinding from PhishFort threat.
   */
  private createThreatFinding(
    threat: PhishFortThreat,
    input: ThreatIntelInput,
    additionalMetadata?: Record<string, unknown>
  ): ThreatFinding {
    return this.createFinding({
      category: this.mapPhishFortType(threat.type),
      severity: threat.severity,
      confidence: threat.confidence,
      description: threat.description,
      firstReportedAt: threat.detectedAt,
      lastSeenAt: threat.lastSeenAt,
      referenceUrl: 'https://phishfort.com',
      metadata: {
        threatId: threat.id,
        threatType: threat.type,
        takedownStatus: threat.takedownStatus,
        evidence: threat.evidence,
        ...additionalMetadata,
      },
      tags: this.buildThreatTags(threat),
      raw: threat,
    });
  }

  /**
   * Create ThreatFinding from brand match.
   */
  private createBrandFinding(
    brand: PhishFortBrandMatch,
    input: ThreatIntelInput
  ): ThreatFinding {
    return this.createFinding({
      category: 'impersonation',
      severity: this.determineBrandSeverity(brand),
      confidence: brand.confidence,
      description: `This domain appears to impersonate ${brand.brand} (${brand.matchType} match).`,
      referenceUrl: 'https://phishfort.com',
      metadata: {
        brand: brand.brand,
        matchType: brand.matchType,
      },
      tags: ['brand_impersonation', brand.brand.toLowerCase().replace(/\s+/g, '_')],
      raw: brand,
    });
  }

  /**
   * Map PhishFort threat type to ThreatCategory.
   */
  private mapPhishFortType(type: PhishFortThreatType): ThreatCategory {
    const mapping: Record<PhishFortThreatType, ThreatCategory> = {
      'impersonation': 'impersonation',
      'fake_support': 'impersonation',
      'phishing': 'phishing',
      'social_engineering': 'scam',
      'brand_abuse': 'impersonation',
      'credential_theft': 'phishing',
      'scam_website': 'scam',
    };

    return mapping[type] || 'unknown';
  }

  /**
   * Determine severity for brand match.
   */
  private determineBrandSeverity(brand: PhishFortBrandMatch): ThreatSeverity {
    // Exact and typosquat matches are more severe
    if (brand.matchType === 'exact' || brand.matchType === 'typosquat') {
      if (brand.confidence >= 90) return 'critical';
      if (brand.confidence >= 70) return 'high';
      return 'medium';
    }

    // Similar and keyword matches
    if (brand.confidence >= 90) return 'high';
    if (brand.confidence >= 70) return 'medium';
    return 'low';
  }

  /**
   * Build tags from threat.
   */
  private buildThreatTags(threat: PhishFortThreat): string[] {
    const tags: string[] = [threat.type];

    if (threat.takedownStatus) {
      tags.push(`takedown_${threat.takedownStatus}`);
    }

    return tags;
  }

  /**
   * Override category mapping for PhishFort-specific types.
   */
  protected override mapCategory(externalCategory: string): ThreatCategory {
    const phishFortMapping: Record<string, ThreatCategory> = {
      'fake_helpdesk': 'impersonation',
      'fake_customer_support': 'impersonation',
      'brand_impersonation': 'impersonation',
      'typosquatting': 'phishing',
      'credential_phishing': 'phishing',
      'social_media_scam': 'scam',
    };

    const normalized = externalCategory.toLowerCase().replace(/[_\s-]+/g, '_');
    return phishFortMapping[normalized] || super.mapCategory(externalCategory);
  }
}

/**
 * Factory function to create PhishFort provider.
 */
export function createPhishFortProvider(
  config?: Partial<ThreatProviderConfig>
): PhishFortProvider {
  return new PhishFortProvider(config);
}
