// ============================================
// OFF-CHAIN THREAT INTELLIGENCE SERVICE
// ============================================
// Core service for OTTI signal aggregation and scoring.
//
// DESIGN PRINCIPLES:
// 1. Modular - Providers can be added/removed without code changes
// 2. Non-blocking - Provider failures don't break the assessment
// 3. Honest - Clearly separates on-chain safety from off-chain risk
// 4. Decaying - Signals expire if not re-confirmed
// 5. Reversible - All signals can be disputed/overridden

import {
  OTTIAssessment,
  OTTISummary,
  OffChainThreatSignal,
  OffChainExposureScore,
  OffChainScoreFactor,
  OffChainIntelProvider,
  ProviderQueryResult,
  OTTIServiceConfig,
  DEFAULT_OTTI_CONFIG,
  OffChainConfidenceLevel,
} from './types';

/**
 * OTTI Service - Orchestrates off-chain threat intelligence gathering
 */
export class OTTIService {
  private providers: Map<string, OffChainIntelProvider> = new Map();
  private config: OTTIServiceConfig;
  private cache: Map<string, { assessment: OTTIAssessment; expires_at: number }> = new Map();

  constructor(config: Partial<OTTIServiceConfig> = {}) {
    this.config = { ...DEFAULT_OTTI_CONFIG, ...config };
  }

  /**
   * Register a new intel provider
   */
  registerProvider(provider: OffChainIntelProvider): void {
    if (this.providers.has(provider.id)) {
      console.warn(`[OTTI] Provider ${provider.id} already registered, replacing...`);
    }
    this.providers.set(provider.id, provider);
    console.log(`[OTTI] Registered provider: ${provider.name} (${provider.id})`);
  }

  /**
   * Unregister a provider
   */
  unregisterProvider(providerId: string): boolean {
    const removed = this.providers.delete(providerId);
    if (removed) {
      console.log(`[OTTI] Unregistered provider: ${providerId}`);
    }
    return removed;
  }

  /**
   * Get all registered providers
   */
  getProviders(): OffChainIntelProvider[] {
    return Array.from(this.providers.values());
  }

  /**
   * Get enabled providers
   */
  getEnabledProviders(): OffChainIntelProvider[] {
    return this.getProviders().filter(p => p.enabled);
  }

  /**
   * Assess a wallet address for off-chain threats
   * 
   * @param address - The wallet address to assess
   * @param onChainStatus - The on-chain security status (for separation display)
   * @returns OTTIAssessment with all signals and scores
   */
  async assessAddress(
    address: string,
    onChainStatus: 'safe' | 'at_risk' | 'compromised' = 'safe'
  ): Promise<OTTIAssessment> {
    const normalizedAddress = address.toLowerCase();
    
    // Check cache
    if (this.config.enable_cache) {
      const cached = this.cache.get(normalizedAddress);
      if (cached && cached.expires_at > Date.now()) {
        console.log(`[OTTI] Cache hit for ${normalizedAddress}`);
        return { ...cached.assessment, on_chain_status: onChainStatus };
      }
    }

    console.log(`[OTTI] Assessing address: ${normalizedAddress}`);
    const startTime = Date.now();

    // Query all enabled providers in parallel
    const enabledProviders = this.getEnabledProviders();
    const providerResults = await this.queryAllProviders(normalizedAddress, enabledProviders);

    // Aggregate signals from all providers
    const allSignals = this.aggregateSignals(providerResults);
    
    // Filter to only active (non-expired) signals
    const activeSignals = allSignals.filter(s => s.decay.is_active);
    
    // Calculate exposure score
    const exposureScore = this.calculateExposureScore(activeSignals);
    
    // Generate summary for UI
    const summary = this.generateSummary(activeSignals, exposureScore, onChainStatus);
    
    // Build assessment
    const assessment: OTTIAssessment = {
      wallet_address: normalizedAddress,
      on_chain_status: onChainStatus,
      off_chain_risk_detected: activeSignals.length > 0,
      signals: activeSignals,
      exposure_score: exposureScore,
      summary,
      assessed_at: new Date().toISOString(),
      assessment_version: '1.0.0',
      sources_queried: enabledProviders.map(p => p.name),
    };

    // Cache the result
    if (this.config.enable_cache) {
      this.cache.set(normalizedAddress, {
        assessment,
        expires_at: Date.now() + this.config.cache_ttl_minutes * 60 * 1000,
      });
    }

    const duration = Date.now() - startTime;
    console.log(`[OTTI] Assessment completed in ${duration}ms. Signals: ${activeSignals.length}, Score: ${exposureScore.score.toFixed(2)}`);

    return assessment;
  }

  /**
   * Query all providers in parallel with timeout
   */
  private async queryAllProviders(
    address: string,
    providers: OffChainIntelProvider[]
  ): Promise<ProviderQueryResult[]> {
    if (providers.length === 0) {
      return [];
    }

    const queryPromises = providers.map(async (provider): Promise<ProviderQueryResult> => {
      const startTime = Date.now();
      try {
        // Race between provider query and timeout
        const signals = await Promise.race([
          provider.queryAddress(address),
          new Promise<OffChainThreatSignal[]>((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), this.config.query_timeout_ms)
          ),
        ]);

        return {
          provider_id: provider.id,
          provider_name: provider.name,
          signals,
          query_timestamp: new Date().toISOString(),
          response_time_ms: Date.now() - startTime,
        };
      } catch (error) {
        console.warn(`[OTTI] Provider ${provider.name} query failed:`, error);
        return {
          provider_id: provider.id,
          provider_name: provider.name,
          signals: [],
          query_timestamp: new Date().toISOString(),
          response_time_ms: Date.now() - startTime,
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    });

    return Promise.all(queryPromises);
  }

  /**
   * Aggregate signals from multiple providers
   */
  private aggregateSignals(results: ProviderQueryResult[]): OffChainThreatSignal[] {
    const allSignals: OffChainThreatSignal[] = [];
    
    for (const result of results) {
      if (result.signals.length > 0) {
        allSignals.push(...result.signals);
      }
    }

    // Deduplicate by reference_id if present
    const seen = new Set<string>();
    const deduplicated: OffChainThreatSignal[] = [];
    
    for (const signal of allSignals) {
      const key = signal.reference_id || signal.id;
      if (!seen.has(key)) {
        seen.add(key);
        deduplicated.push(signal);
      }
    }

    return deduplicated;
  }

  /**
   * Calculate off-chain exposure score from signals
   * 
   * IMPORTANT: This score NEVER affects on-chain risk score.
   * It's a separate "reputation/exposure" metric.
   */
  private calculateExposureScore(signals: OffChainThreatSignal[]): OffChainExposureScore {
    if (signals.length === 0) {
      return {
        score: 0,
        level: 'none',
        factors: [],
        calculated_at: new Date().toISOString(),
      };
    }

    const factors: OffChainScoreFactor[] = [];
    let totalWeight = 0;

    // Factor: Number of distinct sources
    const distinctSources = new Set(signals.map(s => s.source_name)).size;
    if (distinctSources >= 3) {
      factors.push({
        factor: 'multiple_sources',
        weight: 0.3,
        description: `Reported by ${distinctSources} independent sources`,
      });
      totalWeight += 0.3;
    } else if (distinctSources >= 2) {
      factors.push({
        factor: 'corroborated',
        weight: 0.15,
        description: `Corroborated by ${distinctSources} sources`,
      });
      totalWeight += 0.15;
    }

    // Factor: High confidence signals
    const highConfidenceCount = signals.filter(s => s.confidence_level === 'high').length;
    if (highConfidenceCount > 0) {
      const weight = Math.min(0.35, highConfidenceCount * 0.12);
      factors.push({
        factor: 'high_confidence',
        weight,
        description: `${highConfidenceCount} high-confidence report(s)`,
      });
      totalWeight += weight;
    }

    // Factor: Medium confidence signals
    const mediumConfidenceCount = signals.filter(s => s.confidence_level === 'medium').length;
    if (mediumConfidenceCount > 0) {
      const weight = Math.min(0.2, mediumConfidenceCount * 0.07);
      factors.push({
        factor: 'medium_confidence',
        weight,
        description: `${mediumConfidenceCount} medium-confidence report(s)`,
      });
      totalWeight += weight;
    }

    // Factor: Recent activity
    const recentSignals = signals.filter(s => {
      const lastSeen = s.last_seen_timestamp || s.first_seen_timestamp;
      const daysSince = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60 * 24);
      return daysSince <= 30;
    });
    if (recentSignals.length > 0) {
      factors.push({
        factor: 'recent_activity',
        weight: 0.15,
        description: `${recentSignals.length} report(s) in last 30 days`,
      });
      totalWeight += 0.15;
    }

    // Factor: Signal types (phishing and impersonation are higher risk)
    const highRiskTypes = signals.filter(s => 
      ['phishing', 'impersonation', 'fake_mint', 'rug_pull'].includes(s.report_type)
    ).length;
    if (highRiskTypes > 0) {
      const weight = Math.min(0.25, highRiskTypes * 0.08);
      factors.push({
        factor: 'high_risk_type',
        weight,
        description: `${highRiskTypes} high-risk threat type(s)`,
      });
      totalWeight += weight;
    }

    // Cap total weight at 1.0
    const score = Math.min(1.0, totalWeight);

    // Determine level
    let level: OffChainExposureScore['level'] = 'none';
    if (score >= this.config.score_thresholds.critical) {
      level = 'critical';
    } else if (score >= this.config.score_thresholds.high) {
      level = 'high';
    } else if (score >= this.config.score_thresholds.moderate) {
      level = 'moderate';
    } else if (score > 0) {
      level = 'low';
    }

    return {
      score,
      level,
      factors,
      calculated_at: new Date().toISOString(),
    };
  }

  /**
   * Generate non-alarmist summary for UI display
   */
  private generateSummary(
    signals: OffChainThreatSignal[],
    exposureScore: OffChainExposureScore,
    onChainStatus: 'safe' | 'at_risk' | 'compromised'
  ): OTTISummary {
    const sourceCount = new Set(signals.map(s => s.source_name)).size;
    const highestConfidence = this.getHighestConfidence(signals);

    // No signals = no warning
    if (signals.length === 0) {
      return {
        show_warning: false,
        headline: '',
        explanation: '',
        guidance: '',
        status_line: onChainStatus === 'safe' 
          ? 'No off-chain threat reports detected'
          : 'No additional off-chain reports detected',
        source_count: 0,
        signal_count: 0,
        highest_confidence: null,
      };
    }

    // Build non-alarmist messaging
    const headline = '⚠️ Off-chain threat reports detected';
    
    const explanation = this.buildExplanation(signals);
    const guidance = this.buildGuidance(signals, onChainStatus);
    const statusLine = this.buildStatusLine(onChainStatus, signals.length);

    return {
      show_warning: signals.length >= this.config.min_signals_for_warning,
      headline,
      explanation,
      guidance,
      status_line: statusLine,
      source_count: sourceCount,
      signal_count: signals.length,
      highest_confidence: highestConfidence,
    };
  }

  /**
   * Build explanation text
   */
  private buildExplanation(signals: OffChainThreatSignal[]): string {
    const types = [...new Set(signals.map(s => s.report_type))];
    
    if (types.includes('phishing') || types.includes('impersonation')) {
      return 'This address has been reported in phishing or impersonation activity outside the blockchain. No malicious on-chain activity has been detected.';
    }
    
    if (types.includes('scam_page') || types.includes('fake_mint')) {
      return 'This address has been associated with scam websites or fake minting pages. No malicious on-chain activity has been detected.';
    }
    
    return 'This address has been reported in off-chain threat intelligence feeds. No malicious on-chain activity has been detected.';
  }

  /**
   * Build user guidance text
   */
  private buildGuidance(
    signals: OffChainThreatSignal[],
    onChainStatus: 'safe' | 'at_risk' | 'compromised'
  ): string {
    if (onChainStatus !== 'safe') {
      return 'Review both on-chain threats and off-chain reports before interacting with this address.';
    }

    const types = [...new Set(signals.map(s => s.report_type))];
    
    if (types.includes('phishing') || types.includes('impersonation') || types.includes('fake_support')) {
      return 'Exercise caution when interacting via links, DMs, or websites associated with this address. Verify authenticity through official channels.';
    }
    
    if (types.includes('scam_page') || types.includes('fake_mint') || types.includes('giveaway_scam')) {
      return 'Be cautious of any websites, minting pages, or promotions linked to this address. Verify through official project channels.';
    }

    return 'Exercise caution when interacting with this address. Verify legitimacy through trusted sources.';
  }

  /**
   * Build status line text
   */
  private buildStatusLine(
    onChainStatus: 'safe' | 'at_risk' | 'compromised',
    signalCount: number
  ): string {
    if (onChainStatus === 'safe') {
      return `Safe on-chain, but associated with ${signalCount} off-chain threat report${signalCount > 1 ? 's' : ''}`;
    }
    
    if (onChainStatus === 'at_risk') {
      return `At risk on-chain, with ${signalCount} additional off-chain report${signalCount > 1 ? 's' : ''}`;
    }
    
    return `Compromised on-chain, with ${signalCount} off-chain report${signalCount > 1 ? 's' : ''}`;
  }

  /**
   * Get highest confidence level from signals
   */
  private getHighestConfidence(signals: OffChainThreatSignal[]): OffChainConfidenceLevel | null {
    if (signals.length === 0) return null;
    
    if (signals.some(s => s.confidence_level === 'high')) return 'high';
    if (signals.some(s => s.confidence_level === 'medium')) return 'medium';
    return 'low';
  }

  /**
   * Mark a signal as disputed (internal override)
   */
  disputeSignal(
    assessment: OTTIAssessment,
    signalId: string,
    reason: string
  ): OTTIAssessment {
    const updatedSignals = assessment.signals.map(signal => {
      if (signal.id === signalId) {
        return {
          ...signal,
          disputed: true,
          disputed_reason: reason,
          disputed_at: new Date().toISOString(),
        };
      }
      return signal;
    });

    // Recalculate with non-disputed signals only
    const activeNonDisputed = updatedSignals.filter(s => !s.disputed && s.decay.is_active);
    const newExposureScore = this.calculateExposureScore(activeNonDisputed);
    const newSummary = this.generateSummary(activeNonDisputed, newExposureScore, assessment.on_chain_status);

    return {
      ...assessment,
      signals: updatedSignals,
      exposure_score: newExposureScore,
      summary: newSummary,
      off_chain_risk_detected: activeNonDisputed.length > 0,
    };
  }

  /**
   * Clear cache for an address
   */
  clearCache(address?: string): void {
    if (address) {
      this.cache.delete(address.toLowerCase());
    } else {
      this.cache.clear();
    }
  }

  /**
   * Get service statistics
   */
  getStats(): {
    registered_providers: number;
    enabled_providers: number;
    cache_size: number;
    config: OTTIServiceConfig;
  } {
    return {
      registered_providers: this.providers.size,
      enabled_providers: this.getEnabledProviders().length,
      cache_size: this.cache.size,
      config: this.config,
    };
  }
}

// Singleton instance
let ottiServiceInstance: OTTIService | null = null;

/**
 * Get the OTTI service singleton
 */
export function getOTTIService(config?: Partial<OTTIServiceConfig>): OTTIService {
  if (!ottiServiceInstance) {
    ottiServiceInstance = new OTTIService(config);
  }
  return ottiServiceInstance;
}

/**
 * Reset the OTTI service (for testing)
 */
export function resetOTTIService(): void {
  ottiServiceInstance = null;
}
