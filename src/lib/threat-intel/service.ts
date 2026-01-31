// ============================================
// THREAT INTELLIGENCE AGGREGATION SERVICE
// ============================================
// Core service that orchestrates threat intelligence gathering.
// Queries multiple providers, aggregates results, and computes risk scores.
//
// PRODUCTION REQUIREMENTS:
// - Parallel provider queries
// - Graceful failure handling (partial results)
// - Confidence scoring based on cross-source agreement
// - Caching to avoid rate limits
// - Clear off-chain signal labeling
//
// ARCHITECTURE:
// ThreatIntelService
//   ├── Provider Registry (ChainPatrol, ScamSniffer, PhishFort, WalletGuard)
//   ├── Cache (Memory or Redis)
//   └── Aggregator (Score calculation, deduplication)

import {
  ThreatProvider,
  ThreatProviderConfig,
  ThreatIntelInput,
  ThreatFinding,
  ThreatReport,
  CategorySummary,
  ThreatReportSummary,
  ProviderQueryResult,
  ThreatIntelServiceConfig,
  DEFAULT_THREAT_INTEL_CONFIG,
  OverallRiskLevel,
  ThreatCategory,
  OFF_CHAIN_LABELS,
  getRiskLevelFromScore,
  getSeverityWeight,
  getCategoryWeight,
  getSeverityLabel,
  getCategoryLabel,
} from './types';
import { ThreatIntelCache, createCache, generateCacheKey } from './cache';
import { createChainPatrolProvider } from './providers/chainpatrol';
import { createScamSnifferProvider } from './providers/scamsniffer';
import { createPhishFortProvider } from './providers/phishfort';
import { createWalletGuardProvider } from './providers/walletguard';

// ============================================
// THREAT INTEL SERVICE CLASS
// ============================================

export class ThreatIntelService {
  private providers: Map<string, ThreatProvider> = new Map();
  private config: ThreatIntelServiceConfig;
  private cache: ThreatIntelCache;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  constructor(config: Partial<ThreatIntelServiceConfig> = {}) {
    this.config = { ...DEFAULT_THREAT_INTEL_CONFIG, ...config };
    this.cache = createCache(this.config.cache);

    // Initialize with real or mock providers based on feature flag
    if (this.config.featureFlags.useRealThreatIntel) {
      this.initializeRealProviders();
    }

    // Start health checks if enabled
    if (this.config.featureFlags.enableHealthChecks) {
      this.startHealthChecks();
    }
  }

  /**
   * Initialize real production providers.
   */
  private initializeRealProviders(): void {
    // Only register providers that are enabled and have API keys
    const providers = [
      { id: 'chainpatrol', create: createChainPatrolProvider, envVar: 'CHAINPATROL_API_KEY' },
      { id: 'scamsniffer', create: createScamSnifferProvider, envVar: 'SCAMSNIFFER_API_KEY' },
      { id: 'phishfort', create: createPhishFortProvider, envVar: 'PHISHFORT_API_KEY' },
      { id: 'walletguard', create: createWalletGuardProvider, envVar: 'WALLETGUARD_API_KEY' },
    ];

    for (const { id, create, envVar } of providers) {
      if (this.config.enabledProviders.includes(id)) {
        const hasApiKey = !!process.env[envVar];
        if (hasApiKey) {
          const provider = create();
          this.registerProvider(provider);
          this.log('info', `Registered provider: ${provider.name}`);
        } else {
          this.log('warn', `Provider ${id} enabled but no API key found (${envVar})`);
        }
      }
    }
  }

  /**
   * Register a threat provider.
   */
  registerProvider(provider: ThreatProvider): void {
    if (this.providers.has(provider.id)) {
      this.log('warn', `Provider ${provider.id} already registered, replacing...`);
    }
    this.providers.set(provider.id, provider);
  }

  /**
   * Unregister a provider.
   */
  unregisterProvider(providerId: string): boolean {
    return this.providers.delete(providerId);
  }

  /**
   * Get all registered providers.
   */
  getProviders(): ThreatProvider[] {
    return Array.from(this.providers.values());
  }

  /**
   * Get enabled providers only.
   */
  getEnabledProviders(): ThreatProvider[] {
    return this.getProviders().filter(p => p.enabled);
  }

  /**
   * Main method: Query all providers and aggregate results.
   * 
   * @param input - The address/domain to check
   * @returns Aggregated threat report
   */
  async checkAddress(input: ThreatIntelInput): Promise<ThreatReport> {
    const cacheKey = generateCacheKey(input.value, input.type, input.chain);
    
    // Check cache first
    const cached = await this.cache.get(cacheKey);
    if (cached) {
      this.log('info', `Cache hit for ${input.value.slice(0, 10)}...`);
      return cached;
    }

    this.log('info', `Checking ${input.type}: ${input.value.slice(0, 10)}...`);
    const startTime = Date.now();

    // Query all enabled providers in parallel
    const enabledProviders = this.getEnabledProviders();
    const results = await this.queryAllProviders(input, enabledProviders);

    // Aggregate findings from all providers
    const aggregatedFindings = this.aggregateFindings(results);

    // Calculate risk score and level
    const { score, level } = this.calculateRiskScore(aggregatedFindings);

    // Generate category summaries
    const categorySummaries = this.generateCategorySummaries(aggregatedFindings);

    // Calculate cross-source agreement
    const crossSourceAgreement = this.calculateCrossSourceAgreement(
      results,
      categorySummaries
    );

    // Generate source attributions
    const sourceAttributions = this.generateSourceAttributions(aggregatedFindings);

    // Generate display summary
    const displaySummary = this.generateDisplaySummary(
      aggregatedFindings,
      score,
      level,
      enabledProviders.map(p => p.name)
    );

    // Build the report
    const report: ThreatReport = {
      input,
      overallRiskScore: score,
      riskLevel: level,
      threatDetected: aggregatedFindings.length > 0,
      findings: aggregatedFindings,
      categorySummaries,
      crossSourceAgreement,
      sourceAttributions,
      queriedProviders: enabledProviders.map(p => p.name),
      failedProviders: results
        .filter(r => !r.success)
        .map(r => r.providerName),
      assessedAt: new Date().toISOString(),
      cacheTTL: this.config.cache.enabled 
        ? (aggregatedFindings.length > 0 
            ? this.config.cache.threatTTLSeconds 
            : this.config.cache.cleanTTLSeconds)
        : undefined,
      displaySummary,
    };

    // Cache the result
    await this.cache.set(cacheKey, report);

    const duration = Date.now() - startTime;
    this.log('info', `Check completed in ${duration}ms. Findings: ${aggregatedFindings.length}, Score: ${score}`);

    return report;
  }

  /**
   * Query all providers in parallel with timeout.
   */
  private async queryAllProviders(
    input: ThreatIntelInput,
    providers: ThreatProvider[]
  ): Promise<ProviderQueryResult[]> {
    if (providers.length === 0) {
      this.log('warn', 'No providers registered');
      return [];
    }

    const queryPromises = providers.map(async (provider): Promise<ProviderQueryResult> => {
      const startTime = Date.now();
      
      try {
        // Race between provider query and global timeout
        const findings = await Promise.race([
          provider.checkAddress(input),
          new Promise<ThreatFinding[]>((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), this.config.queryTimeoutMs)
          ),
        ]);

        return {
          providerId: provider.id,
          providerName: provider.name,
          findings,
          queryTimeMs: Date.now() - startTime,
          queriedAt: new Date().toISOString(),
          success: true,
        };
      } catch (error) {
        this.log('error', `Provider ${provider.name} failed: ${(error as Error).message}`);
        
        return {
          providerId: provider.id,
          providerName: provider.name,
          findings: [],
          queryTimeMs: Date.now() - startTime,
          queriedAt: new Date().toISOString(),
          success: false,
          error: (error as Error).message,
        };
      }
    });

    const results = await Promise.all(queryPromises);

    // Check if we have minimum successful providers
    const successCount = results.filter(r => r.success).length;
    if (successCount < this.config.minSuccessfulProviders && !this.config.returnPartialResults) {
      throw new Error(`Insufficient providers responded: ${successCount}/${this.config.minSuccessfulProviders}`);
    }

    return results;
  }

  /**
   * Aggregate findings from multiple providers.
   * Deduplicates and merges similar findings.
   */
  private aggregateFindings(results: ProviderQueryResult[]): ThreatFinding[] {
    const allFindings: ThreatFinding[] = [];

    for (const result of results) {
      if (result.success && result.findings.length > 0) {
        allFindings.push(...result.findings);
      }
    }

    // Deduplicate by category + provider (keep highest confidence per provider per category)
    const deduplicated = this.deduplicateFindings(allFindings);

    // Sort by confidence (highest first)
    deduplicated.sort((a, b) => b.confidence - a.confidence);

    return deduplicated;
  }

  /**
   * Deduplicate findings - keep highest confidence per provider per category.
   */
  private deduplicateFindings(findings: ThreatFinding[]): ThreatFinding[] {
    const seen = new Map<string, ThreatFinding>();

    for (const finding of findings) {
      const key = `${finding.provider}:${finding.category}`;
      const existing = seen.get(key);

      if (!existing || finding.confidence > existing.confidence) {
        seen.set(key, finding);
      }
    }

    return Array.from(seen.values());
  }

  /**
   * Calculate overall risk score from findings.
   */
  private calculateRiskScore(findings: ThreatFinding[]): { score: number; level: OverallRiskLevel } {
    if (findings.length === 0) {
      return { score: 0, level: 'safe' };
    }

    let score = 0;
    const { aggregation } = this.config;

    // Calculate base score from findings
    for (const finding of findings) {
      const severityWeight = getSeverityWeight(finding.severity, aggregation);
      const categoryWeight = getCategoryWeight(finding.category, aggregation);
      const confidenceMultiplier = finding.confidence / 100;

      score += severityWeight * categoryWeight * confidenceMultiplier;
    }

    // Apply multi-provider boost
    const uniqueProviders = new Set(findings.map(f => f.provider)).size;
    if (uniqueProviders >= aggregation.minProvidersForHighConfidence) {
      score += aggregation.multiProviderConfidenceBoost * (uniqueProviders - 1);
    }

    // Cap at 100
    score = Math.min(100, Math.round(score));

    // Determine level
    const level = getRiskLevelFromScore(score, aggregation);

    return { score, level };
  }

  /**
   * Generate category summaries for the report.
   */
  private generateCategorySummaries(findings: ThreatFinding[]): CategorySummary[] {
    const categoryMap = new Map<ThreatCategory, ThreatFinding[]>();

    // Group by category
    for (const finding of findings) {
      const existing = categoryMap.get(finding.category) || [];
      existing.push(finding);
      categoryMap.set(finding.category, existing);
    }

    // Build summaries
    const summaries: CategorySummary[] = [];

    for (const [category, categoryFindings] of categoryMap) {
      const providers = [...new Set(categoryFindings.map(f => f.provider))];
      const maxSeverity = categoryFindings.reduce(
        (max, f) => this.compareSeverity(f.severity, max) > 0 ? f.severity : max,
        categoryFindings[0].severity
      );
      const maxConfidence = Math.max(...categoryFindings.map(f => f.confidence));

      summaries.push({
        category,
        count: categoryFindings.length,
        maxSeverity,
        maxConfidence,
        providers,
        findings: categoryFindings,
      });
    }

    // Sort by severity and count
    summaries.sort((a, b) => {
      const severityDiff = this.compareSeverity(b.maxSeverity, a.maxSeverity);
      if (severityDiff !== 0) return severityDiff;
      return b.count - a.count;
    });

    return summaries;
  }

  /**
   * Compare severity levels (-1, 0, 1).
   */
  private compareSeverity(a: string, b: string): number {
    const order = ['low', 'medium', 'high', 'critical'];
    return order.indexOf(a) - order.indexOf(b);
  }

  /**
   * Calculate cross-source agreement metrics.
   */
  private calculateCrossSourceAgreement(
    results: ProviderQueryResult[],
    categorySummaries: CategorySummary[]
  ): ThreatReport['crossSourceAgreement'] {
    const successfulResults = results.filter(r => r.success);
    const totalProviders = successfulResults.length;
    
    // Count providers that found threats
    const providersWithFindings = successfulResults.filter(
      r => r.findings.length > 0
    ).length;

    // Find categories with multi-provider agreement
    const agreedCategories = categorySummaries
      .filter(s => s.providers.length >= 2)
      .map(s => s.category);

    return {
      agreementCount: providersWithFindings,
      totalProviders,
      agreementPercentage: totalProviders > 0 
        ? Math.round((providersWithFindings / totalProviders) * 100) 
        : 0,
      agreedCategories,
    };
  }

  /**
   * Generate source attributions for transparency.
   */
  private generateSourceAttributions(findings: ThreatFinding[]): ThreatReport['sourceAttributions'] {
    return findings.map((finding, index) => ({
      provider: finding.provider,
      reportedAt: finding.firstReportedAt || new Date().toISOString(),
      confidence: finding.confidence,
      findingId: `finding-${index}`,
    }));
  }

  /**
   * Generate display summary for UI.
   * CRITICAL: Always includes off-chain labels.
   */
  private generateDisplaySummary(
    findings: ThreatFinding[],
    score: number,
    level: OverallRiskLevel,
    providerNames: string[]
  ): ThreatReportSummary {
    if (findings.length === 0) {
      return {
        headline: 'No off-chain threat reports found',
        explanation: `Checked ${providerNames.length} security intelligence provider(s). No reports found for this address.`,
        guidance: 'This does not guarantee the address is safe. Always verify through official channels.',
        warningLevel: 'none',
        showWarning: false,
        offChainLabel: OFF_CHAIN_LABELS.label,
        offChainDisclaimer: OFF_CHAIN_LABELS.disclaimer,
      };
    }

    const uniqueProviders = [...new Set(findings.map(f => f.provider))];
    const topCategories = [...new Set(findings.slice(0, 3).map(f => getCategoryLabel(f.category)))];

    // Build headline
    let headline: string;
    if (level === 'critical') {
      headline = `⛔ Critical: ${findings.length} security report(s) from ${uniqueProviders.length} provider(s)`;
    } else if (level === 'high_risk') {
      headline = `⚠️ High Risk: ${findings.length} security report(s) found`;
    } else if (level === 'suspicious') {
      headline = `⚠️ ${findings.length} off-chain threat report(s) found`;
    } else {
      headline = `ℹ️ ${findings.length} report(s) found from external providers`;
    }

    // Build explanation
    const explanation = 
      `This ${findings.length > 1 ? 'address has' : 'address has'} been reported by ` +
      `${uniqueProviders.join(', ')} for ${topCategories.join(', ').toLowerCase()} activity. ` +
      `These are off-chain reports and do not indicate on-chain malicious activity.`;

    // Build guidance
    let guidance: string;
    if (level === 'critical' || level === 'high_risk') {
      guidance = 'Exercise extreme caution. Verify the address through official channels before interacting.';
    } else if (level === 'suspicious') {
      guidance = 'Verify the legitimacy of this address through trusted sources before proceeding.';
    } else {
      guidance = 'Review the reports and exercise normal caution when interacting.';
    }

    // Map risk level to warning level
    const warningLevel = level === 'safe' ? 'none' : 
                         level === 'suspicious' ? 'medium' : 
                         level === 'high_risk' ? 'high' : 
                         level as 'none' | 'low' | 'high' | 'critical' | 'medium';

    return {
      headline,
      explanation,
      guidance,
      warningLevel,
      showWarning: findings.length > 0,
      offChainLabel: OFF_CHAIN_LABELS.label,
      offChainDisclaimer: OFF_CHAIN_LABELS.disclaimer,
    };
  }

  /**
   * Start periodic health checks for providers.
   */
  private startHealthChecks(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    this.healthCheckInterval = setInterval(async () => {
      for (const provider of this.getProviders()) {
        try {
          const health = await provider.healthCheck();
          if (!health.isHealthy) {
            this.log('warn', `Provider ${provider.name} unhealthy: ${health.errorMessage}`);
          }
        } catch (error) {
          this.log('error', `Health check failed for ${provider.name}`);
        }
      }
    }, this.config.featureFlags.healthCheckIntervalMs);
  }

  /**
   * Stop health checks.
   */
  stopHealthChecks(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }

  /**
   * Clear the cache.
   */
  async clearCache(): Promise<void> {
    await this.cache.clear();
    this.log('info', 'Cache cleared');
  }

  /**
   * Get cache statistics.
   */
  getCacheStats() {
    return this.cache.getStats();
  }

  /**
   * Get service statistics.
   */
  getStats(): {
    registeredProviders: number;
    enabledProviders: number;
    cacheStats: ReturnType<ThreatIntelCache['getStats']>;
    config: ThreatIntelServiceConfig;
  } {
    return {
      registeredProviders: this.providers.size,
      enabledProviders: this.getEnabledProviders().length,
      cacheStats: this.cache.getStats(),
      config: this.config,
    };
  }

  /**
   * Update service configuration.
   */
  updateConfig(config: Partial<ThreatIntelServiceConfig>): void {
    this.config = { ...this.config, ...config };
    
    // Reinitialize cache if cache config changed
    if (config.cache) {
      this.cache = createCache(this.config.cache);
    }
  }

  /**
   * Log message.
   */
  private log(level: 'info' | 'warn' | 'error', message: string): void {
    const prefix = '[ThreatIntelService]';
    
    switch (level) {
      case 'error':
        console.error(`${prefix} ${message}`);
        break;
      case 'warn':
        console.warn(`${prefix} ${message}`);
        break;
      case 'info':
        if (this.config.featureFlags.verboseLogging) {
          console.log(`${prefix} ${message}`);
        }
        break;
    }
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let serviceInstance: ThreatIntelService | null = null;

/**
 * Get the ThreatIntelService singleton.
 */
export function getThreatIntelService(
  config?: Partial<ThreatIntelServiceConfig>
): ThreatIntelService {
  if (!serviceInstance) {
    serviceInstance = new ThreatIntelService(config);
  }
  return serviceInstance;
}

/**
 * Reset the service (for testing).
 */
export function resetThreatIntelService(): void {
  if (serviceInstance) {
    serviceInstance.stopHealthChecks();
  }
  serviceInstance = null;
}

// ============================================
// CONVENIENCE FUNCTIONS
// ============================================

/**
 * Quick check for an address.
 * Uses the singleton service instance.
 */
export async function checkAddressThreat(
  address: string,
  chain?: string
): Promise<ThreatReport> {
  const service = getThreatIntelService();
  return service.checkAddress({
    value: address,
    type: 'wallet',
    chain: chain as any,
  });
}

/**
 * Quick check for a domain.
 * Uses the singleton service instance.
 */
export async function checkDomainThreat(domain: string): Promise<ThreatReport> {
  const service = getThreatIntelService();
  return service.checkAddress({
    value: domain,
    type: 'domain',
  });
}
