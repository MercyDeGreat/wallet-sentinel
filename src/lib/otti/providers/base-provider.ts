// ============================================
// BASE PROVIDER IMPLEMENTATION
// ============================================
// Abstract base class for OTTI intel providers.
// Extend this to create new provider integrations.

import {
  OffChainIntelProvider,
  OffChainThreatSignal,
  ProviderConfig,
  SignalDecayInfo,
  OffChainReportType,
  OffChainConfidenceLevel,
} from '../types';

/**
 * Abstract base class for OTTI intel providers
 */
export abstract class BaseOTTIProvider implements OffChainIntelProvider {
  abstract readonly name: string;
  abstract readonly id: string;
  
  protected _enabled: boolean = true;
  protected _config: ProviderConfig;

  constructor(config: Partial<ProviderConfig> = {}) {
    this._config = {
      signal_ttl_days: 90,
      confidence_weight: 1.0,
      ...config,
    };
  }

  get enabled(): boolean {
    return this._enabled;
  }

  setEnabled(enabled: boolean): void {
    this._enabled = enabled;
  }

  getConfig(): ProviderConfig {
    return this._config;
  }

  abstract queryAddress(address: string): Promise<OffChainThreatSignal[]>;
  
  abstract healthCheck(): Promise<boolean>;

  /**
   * Helper to create signal decay info
   */
  protected createDecayInfo(
    firstSeenTimestamp: string,
    lastConfirmedTimestamp?: string,
    confirmationCount: number = 1
  ): SignalDecayInfo {
    const ttlMs = this._config.signal_ttl_days * 24 * 60 * 60 * 1000;
    const lastConfirmed = lastConfirmedTimestamp || firstSeenTimestamp;
    const expiresAt = new Date(new Date(lastConfirmed).getTime() + ttlMs);
    const now = new Date();
    const daysUntilExpiry = Math.max(0, Math.ceil((expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)));
    
    return {
      expires_at: expiresAt.toISOString(),
      confirmation_count: confirmationCount,
      last_confirmed_at: lastConfirmed,
      is_active: expiresAt > now,
      days_until_expiry: daysUntilExpiry,
    };
  }

  /**
   * Helper to generate unique signal ID
   */
  protected generateSignalId(address: string, reportType: string): string {
    return `${this.id}-${address.toLowerCase().slice(0, 10)}-${reportType}-${Date.now()}`;
  }

  /**
   * Helper to normalize address
   */
  protected normalizeAddress(address: string): string {
    return address.toLowerCase().trim();
  }
}

/**
 * Helper function to create a signal
 */
export function createSignal(params: {
  id: string;
  source_name: string;
  report_type: OffChainReportType;
  confidence_level: OffChainConfidenceLevel;
  first_seen_timestamp: string;
  last_seen_timestamp?: string;
  reference_id?: string;
  evidence_url?: string;
  context?: string;
  metadata?: Record<string, unknown>;
  decay: SignalDecayInfo;
}): OffChainThreatSignal {
  return {
    ...params,
    disputed: false,
  };
}
