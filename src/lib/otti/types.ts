// ============================================
// OFF-CHAIN THREAT INTELLIGENCE SIGNALS (OTTI)
// ============================================
// Type definitions for off-chain threat intelligence.
//
// CORE PRINCIPLE:
// On-chain safety and off-chain risk MUST be separated.
// Never upgrade wallet status to "Compromised" based solely on off-chain signals.
//
// This module enables Securnex to flag wallet addresses associated with:
// - Phishing campaigns
// - Brand impersonation
// - Scam domains
// - Community security reports
// - Open threat intel sources
//
// WITHOUT affecting the on-chain security assessment.

/**
 * Types of off-chain threat reports
 */
export type OffChainReportType =
  | 'phishing'           // Phishing campaign association
  | 'impersonation'      // Brand/person impersonation
  | 'scam_page'          // Scam website/landing page
  | 'fake_mint'          // Fake NFT mint pages
  | 'honeypot'           // Honeypot token/contract promotion
  | 'rug_pull'           // Rug pull association
  | 'social_engineering' // Social engineering campaigns
  | 'malware'            // Malware distribution
  | 'fake_support'       // Fake support/help desk
  | 'giveaway_scam'      // Fake giveaway promotions
  | 'investment_scam'    // Ponzi/investment fraud
  | 'community_report'   // Community-reported suspicious activity
  | 'other';             // Other off-chain threats

/**
 * Confidence level of the off-chain signal
 */
export type OffChainConfidenceLevel = 'low' | 'medium' | 'high';

/**
 * A single off-chain threat signal from an intel provider
 */
export interface OffChainThreatSignal {
  // Unique identifier for this signal
  id: string;
  
  // Which intel source reported this
  source_name: string;
  
  // Type of off-chain report
  report_type: OffChainReportType;
  
  // Confidence in the report (low/medium/high)
  confidence_level: OffChainConfidenceLevel;
  
  // When the threat was first observed
  first_seen_timestamp: string; // ISO timestamp
  
  // When the threat was last confirmed (optional)
  last_seen_timestamp?: string; // ISO timestamp
  
  // Reference ID from the source (optional)
  reference_id?: string;
  
  // Link to evidence or report (optional)
  evidence_url?: string;
  
  // Human-readable context/description
  context?: string;
  
  // Additional metadata from the source
  metadata?: Record<string, unknown>;
  
  // Signal decay information
  decay: SignalDecayInfo;
  
  // Has this signal been disputed/overridden internally?
  disputed?: boolean;
  disputed_reason?: string;
  disputed_at?: string;
}

/**
 * Signal decay tracking - signals expire if not re-confirmed
 */
export interface SignalDecayInfo {
  // When the signal will expire if not refreshed
  expires_at: string; // ISO timestamp
  
  // How many times this signal has been confirmed
  confirmation_count: number;
  
  // Last time the signal was refreshed/confirmed
  last_confirmed_at: string; // ISO timestamp
  
  // Is the signal currently active (not expired)?
  is_active: boolean;
  
  // Days until expiration
  days_until_expiry: number;
}

/**
 * Off-chain exposure score (separate from on-chain risk score)
 */
export interface OffChainExposureScore {
  // Score from 0-1 (0 = no exposure, 1 = high exposure)
  score: number;
  
  // Human-readable level
  level: 'none' | 'low' | 'moderate' | 'high' | 'critical';
  
  // Factors that contributed to the score
  factors: OffChainScoreFactor[];
  
  // Timestamp of score calculation
  calculated_at: string;
}

/**
 * Factor contributing to off-chain exposure score
 */
export interface OffChainScoreFactor {
  factor: string;
  weight: number;
  description: string;
  signal_id?: string;
}

/**
 * Complete OTTI assessment for a wallet
 */
export interface OTTIAssessment {
  // The wallet address assessed
  wallet_address: string;
  
  // On-chain vs off-chain separation
  on_chain_status: 'safe' | 'at_risk' | 'compromised';
  off_chain_risk_detected: boolean;
  
  // All active off-chain signals
  signals: OffChainThreatSignal[];
  
  // Aggregated exposure score (NEVER affects on-chain score)
  exposure_score: OffChainExposureScore;
  
  // Summary for UI display
  summary: OTTISummary;
  
  // Metadata
  assessed_at: string;
  assessment_version: string;
  sources_queried: string[];
  
  // Internal override/dispute flag
  internal_override?: {
    is_overridden: boolean;
    override_reason?: string;
    overridden_by?: string;
    overridden_at?: string;
  };
}

/**
 * Summary for UI display - non-alarmist messaging
 */
export interface OTTISummary {
  // Should we show the off-chain warning banner?
  show_warning: boolean;
  
  // Banner headline (e.g., "Off-chain threat reports detected")
  headline: string;
  
  // Expandable explanation
  explanation: string;
  
  // User guidance
  guidance: string;
  
  // Display status line (e.g., "Safe on-chain, but associated with off-chain phishing reports")
  status_line: string;
  
  // Number of distinct sources reporting
  source_count: number;
  
  // Number of active signals
  signal_count: number;
  
  // Highest confidence level among signals
  highest_confidence: OffChainConfidenceLevel | null;
}

// ============================================
// INTEL PROVIDER ABSTRACTION
// ============================================
// Modular design for future intel sources

/**
 * Abstract interface for off-chain intelligence providers
 * Implement this to add new data sources
 */
export interface OffChainIntelProvider {
  // Provider name (e.g., 'ChainPatrol', 'PhishFort')
  readonly name: string;
  
  // Provider identifier (e.g., 'chainpatrol', 'phishfort')
  readonly id: string;
  
  // Whether this provider is currently enabled
  readonly enabled: boolean;
  
  // Query the provider for signals about an address
  queryAddress(address: string): Promise<OffChainThreatSignal[]>;
  
  // Check if the provider is healthy/available
  healthCheck(): Promise<boolean>;
  
  // Get provider-specific configuration
  getConfig(): ProviderConfig;
}

/**
 * Provider configuration
 */
export interface ProviderConfig {
  // API endpoint (if applicable)
  endpoint?: string;
  
  // Rate limits
  rate_limit?: {
    requests_per_minute: number;
    requests_per_day: number;
  };
  
  // How long signals from this provider are valid
  signal_ttl_days: number;
  
  // Confidence weight (how much to trust this source)
  confidence_weight: number;
  
  // Provider-specific options
  options?: Record<string, unknown>;
}

/**
 * Result from provider query
 */
export interface ProviderQueryResult {
  provider_id: string;
  provider_name: string;
  signals: OffChainThreatSignal[];
  query_timestamp: string;
  response_time_ms: number;
  error?: string;
}

// ============================================
// OTTI SERVICE CONFIGURATION
// ============================================

/**
 * OTTI service configuration
 */
export interface OTTIServiceConfig {
  // Enabled providers
  enabled_providers: string[];
  
  // Default signal TTL in days
  default_signal_ttl_days: number;
  
  // Minimum signals required to show warning
  min_signals_for_warning: number;
  
  // Score thresholds
  score_thresholds: {
    low: number;      // 0.0 - 0.2
    moderate: number; // 0.2 - 0.4
    high: number;     // 0.4 - 0.7
    critical: number; // 0.7 - 1.0
  };
  
  // Whether to cache results
  enable_cache: boolean;
  cache_ttl_minutes: number;
  
  // Parallel query timeout
  query_timeout_ms: number;
}

/**
 * Default OTTI service configuration
 */
export const DEFAULT_OTTI_CONFIG: OTTIServiceConfig = {
  enabled_providers: [],
  default_signal_ttl_days: 90,
  min_signals_for_warning: 1,
  score_thresholds: {
    low: 0.2,
    moderate: 0.4,
    high: 0.7,
    critical: 0.9,
  },
  enable_cache: true,
  cache_ttl_minutes: 60,
  query_timeout_ms: 5000,
};

// ============================================
// DISPLAY HELPERS
// ============================================

/**
 * Get human-readable label for report type
 */
export function getReportTypeLabel(type: OffChainReportType): string {
  const labels: Record<OffChainReportType, string> = {
    phishing: 'Phishing Campaign',
    impersonation: 'Brand Impersonation',
    scam_page: 'Scam Website',
    fake_mint: 'Fake NFT Mint',
    honeypot: 'Honeypot Token',
    rug_pull: 'Rug Pull Association',
    social_engineering: 'Social Engineering',
    malware: 'Malware Distribution',
    fake_support: 'Fake Support Scam',
    giveaway_scam: 'Fake Giveaway',
    investment_scam: 'Investment Fraud',
    community_report: 'Community Report',
    other: 'Other Threat',
  };
  return labels[type] || 'Unknown Threat';
}

/**
 * Get icon name for report type (for UI)
 */
export function getReportTypeIcon(type: OffChainReportType): string {
  const icons: Record<OffChainReportType, string> = {
    phishing: 'fish',
    impersonation: 'user-x',
    scam_page: 'globe',
    fake_mint: 'image-off',
    honeypot: 'flask-round',
    rug_pull: 'trending-down',
    social_engineering: 'message-circle-warning',
    malware: 'bug',
    fake_support: 'headphones-off',
    giveaway_scam: 'gift',
    investment_scam: 'piggy-bank',
    community_report: 'users',
    other: 'alert-circle',
  };
  return icons[type] || 'alert-circle';
}

/**
 * Get confidence level display properties
 */
export function getConfidenceLevelDisplay(level: OffChainConfidenceLevel): {
  label: string;
  color: string;
  bgColor: string;
} {
  const displays: Record<OffChainConfidenceLevel, { label: string; color: string; bgColor: string }> = {
    low: { label: 'Low', color: 'text-blue-400', bgColor: 'bg-blue-500/10' },
    medium: { label: 'Medium', color: 'text-amber-400', bgColor: 'bg-amber-500/10' },
    high: { label: 'High', color: 'text-orange-400', bgColor: 'bg-orange-500/10' },
  };
  return displays[level] || displays.low;
}

/**
 * Get exposure level display properties
 */
export function getExposureLevelDisplay(level: OffChainExposureScore['level']): {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
} {
  const displays: Record<OffChainExposureScore['level'], {
    label: string;
    color: string;
    bgColor: string;
    borderColor: string;
  }> = {
    none: { 
      label: 'None', 
      color: 'text-green-400', 
      bgColor: 'bg-green-500/10',
      borderColor: 'border-green-500/30'
    },
    low: { 
      label: 'Low', 
      color: 'text-blue-400', 
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/30'
    },
    moderate: { 
      label: 'Moderate', 
      color: 'text-amber-400', 
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/30'
    },
    high: { 
      label: 'High', 
      color: 'text-orange-400', 
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/30'
    },
    critical: { 
      label: 'Critical', 
      color: 'text-red-400', 
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/30'
    },
  };
  return displays[level] || displays.none;
}
