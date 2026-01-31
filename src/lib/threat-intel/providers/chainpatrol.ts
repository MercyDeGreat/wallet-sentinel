// ============================================
// CHAINPATROL THREAT PROVIDER
// ============================================
// Production integration with ChainPatrol API.
// ChainPatrol provides phishing intelligence and scam detection.
//
// API Documentation: https://docs.chainpatrol.io/
//
// PROVIDER-SPECIFIC QUIRKS:
// - Returns asset-level data (URLs, contracts, wallets)
// - Uses "status" field: "BLOCKED", "ALLOWED", "UNKNOWN"
// - Includes reason codes for detections
// - Rate limit: varies by plan (check headers)

import { BaseThreatProvider, createProviderConfig } from './base-provider';
import {
  ThreatFinding,
  ThreatIntelInput,
  ThreatCategory,
  ThreatSeverity,
  ThreatProviderConfig,
} from '../types';

// ============================================
// CHAINPATROL API TYPES
// ============================================

interface ChainPatrolAssetResponse {
  status: 'BLOCKED' | 'ALLOWED' | 'UNKNOWN';
  reason?: ChainPatrolReason;
  asset?: {
    type: 'URL' | 'CONTRACT' | 'WALLET';
    content: string;
    status: string;
    createdAt?: string;
    updatedAt?: string;
  };
  metadata?: {
    reportCount?: number;
    firstReportedAt?: string;
    lastReportedAt?: string;
    categories?: string[];
    tags?: string[];
    relatedAssets?: string[];
  };
}

interface ChainPatrolReason {
  code: string;
  description: string;
  severity?: string;
  category?: string;
}

interface ChainPatrolCheckResponse {
  status: 'BLOCKED' | 'ALLOWED' | 'UNKNOWN';
  type?: string;
  reason?: string;
  details?: ChainPatrolAssetResponse;
}

// ============================================
// CHAINPATROL PROVIDER IMPLEMENTATION
// ============================================

export class ChainPatrolProvider extends BaseThreatProvider {
  readonly name = 'ChainPatrol';
  readonly id = 'chainpatrol';

  constructor(config: Partial<ThreatProviderConfig> = {}) {
    super(createProviderConfig('chainpatrol', 'ChainPatrol', {
      endpoint: 'https://api.chainpatrol.io/v2',
      apiKeyEnvVar: 'CHAINPATROL_API_KEY',
      timeoutMs: 5000,
      maxRetries: 2,
      retryDelayMs: 1000,
      confidenceWeight: 1.0, // High trust - reputable provider
      rateLimit: {
        requestsPerMinute: 60,
        requestsPerDay: 10000,
      },
      ...config,
    }));
  }

  /**
   * Execute query to ChainPatrol API.
   */
  protected async executeQuery(input: ThreatIntelInput): Promise<ThreatFinding[]> {
    const apiKey = this.getApiKey();
    if (!apiKey) {
      this.log('warn', 'No API key configured, skipping ChainPatrol check');
      return [];
    }

    // Determine asset type for ChainPatrol
    const assetType = this.getAssetType(input);
    const normalizedValue = input.type === 'wallet' || input.type === 'contract'
      ? this.normalizeAddress(input.value)
      : input.value;

    try {
      // ChainPatrol uses POST for checks
      const response = await this.makeRequest(
        `${this._config.endpoint}/asset/check`,
        {
          method: 'POST',
          headers: {
            'X-API-Key': apiKey,
          },
          body: JSON.stringify({
            type: assetType,
            content: normalizedValue,
          }),
        }
      );

      if (!response.ok) {
        if (response.status === 429) {
          this.log('warn', 'Rate limited by ChainPatrol');
          return [];
        }
        throw new Error(`ChainPatrol API error: ${response.status}`);
      }

      const data: ChainPatrolCheckResponse = await response.json();
      return this.processResponse(data, input);
    } catch (error) {
      this.log('error', `ChainPatrol query failed: ${this.sanitizeError(error as Error)}`);
      throw error;
    }
  }

  /**
   * Process ChainPatrol response into ThreatFindings.
   */
  private processResponse(
    data: ChainPatrolCheckResponse,
    input: ThreatIntelInput
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Only create findings for BLOCKED status
    if (data.status !== 'BLOCKED') {
      this.log('info', `ChainPatrol: ${input.value.slice(0, 10)}... is ${data.status}`);
      return [];
    }

    // Parse the response to create findings
    const category = this.determineCategory(data);
    const severity = this.determineSeverity(data);
    const confidence = this.calculateConfidence(data);

    const finding = this.createFinding({
      category,
      severity,
      confidence,
      description: this.buildDescription(data, input),
      firstReportedAt: data.details?.metadata?.firstReportedAt,
      lastSeenAt: data.details?.metadata?.lastReportedAt,
      referenceUrl: `https://app.chainpatrol.io/search?q=${encodeURIComponent(input.value)}`,
      metadata: {
        chainpatrolStatus: data.status,
        reasonCode: data.details?.reason?.code,
        reportCount: data.details?.metadata?.reportCount,
        categories: data.details?.metadata?.categories,
        tags: data.details?.metadata?.tags,
      },
      tags: data.details?.metadata?.tags,
      raw: data,
    });

    findings.push(finding);

    this.log('info', `ChainPatrol: Found threat for ${input.value.slice(0, 10)}... (${category})`);
    return findings;
  }

  /**
   * Determine threat category from ChainPatrol response.
   */
  private determineCategory(data: ChainPatrolCheckResponse): ThreatCategory {
    const reason = data.details?.reason?.code || data.reason || '';
    const categories = data.details?.metadata?.categories || [];

    // Map ChainPatrol reason codes to our categories
    if (reason.includes('PHISH') || categories.includes('phishing')) {
      return 'phishing';
    }
    if (reason.includes('DRAIN') || categories.includes('drainer')) {
      return 'drainer';
    }
    if (reason.includes('SCAM') || categories.includes('scam')) {
      return 'scam';
    }
    if (reason.includes('MALWARE') || categories.includes('malware')) {
      return 'malware';
    }
    if (reason.includes('IMPERSON') || categories.includes('impersonation')) {
      return 'impersonation';
    }
    if (reason.includes('RUG') || categories.includes('rug_pull')) {
      return 'rug_pull';
    }
    if (reason.includes('HONEYPOT') || categories.includes('honeypot')) {
      return 'honeypot';
    }
    if (reason.includes('EXPLOIT') || categories.includes('exploit')) {
      return 'exploit';
    }

    return 'unknown';
  }

  /**
   * Determine threat severity from ChainPatrol response.
   */
  private determineSeverity(data: ChainPatrolCheckResponse): ThreatSeverity {
    const severity = data.details?.reason?.severity?.toLowerCase();
    
    if (severity) {
      return this.mapSeverity(severity);
    }

    // Default severity based on category
    const category = this.determineCategory(data);
    const severityMap: Record<ThreatCategory, ThreatSeverity> = {
      drainer: 'critical',
      exploit: 'critical',
      phishing: 'high',
      malware: 'high',
      scam: 'medium',
      impersonation: 'medium',
      honeypot: 'medium',
      rug_pull: 'medium',
      unknown: 'low',
    };

    return severityMap[category] || 'medium';
  }

  /**
   * Calculate confidence score.
   */
  private calculateConfidence(data: ChainPatrolCheckResponse): number {
    let confidence = 70; // Base confidence for ChainPatrol

    // Boost confidence based on report count
    const reportCount = data.details?.metadata?.reportCount || 0;
    if (reportCount >= 10) confidence += 20;
    else if (reportCount >= 5) confidence += 15;
    else if (reportCount >= 2) confidence += 10;

    // Boost for explicit categorization
    if (data.details?.metadata?.categories?.length) {
      confidence += 5;
    }

    return Math.min(100, confidence);
  }

  /**
   * Build human-readable description.
   */
  private buildDescription(data: ChainPatrolCheckResponse, input: ThreatIntelInput): string {
    const reason = data.details?.reason?.description || data.reason;
    const categories = data.details?.metadata?.categories || [];
    const reportCount = data.details?.metadata?.reportCount;

    let description = `ChainPatrol has flagged this ${input.type} as malicious`;

    if (reason) {
      description += `: ${reason}`;
    } else if (categories.length > 0) {
      description += ` (${categories.join(', ')})`;
    }

    if (reportCount && reportCount > 1) {
      description += `. Reported ${reportCount} times.`;
    }

    return description;
  }

  /**
   * Get ChainPatrol asset type from input type.
   */
  private getAssetType(input: ThreatIntelInput): string {
    switch (input.type) {
      case 'wallet':
      case 'contract':
        return 'ADDRESS';
      case 'domain':
      case 'url':
        return 'URL';
      default:
        return 'ADDRESS';
    }
  }

  /**
   * Override map category for ChainPatrol-specific mappings.
   */
  protected override mapCategory(externalCategory: string): ThreatCategory {
    const chainPatrolMapping: Record<string, ThreatCategory> = {
      'phishing_site': 'phishing',
      'wallet_drainer': 'drainer',
      'scam_project': 'scam',
      'fake_token': 'honeypot',
      'impersonation_attack': 'impersonation',
      'rug_pull_project': 'rug_pull',
    };

    const normalized = externalCategory.toLowerCase().replace(/[_\s-]+/g, '_');
    return chainPatrolMapping[normalized] || super.mapCategory(externalCategory);
  }
}

/**
 * Factory function to create ChainPatrol provider.
 */
export function createChainPatrolProvider(
  config?: Partial<ThreatProviderConfig>
): ChainPatrolProvider {
  return new ChainPatrolProvider(config);
}
