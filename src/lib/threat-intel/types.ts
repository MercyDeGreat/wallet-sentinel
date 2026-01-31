// ============================================
// THREAT INTELLIGENCE AGGREGATION - TYPE DEFINITIONS
// ============================================
// Production-ready types for the Threat Intelligence Aggregation Layer.
// These types are used across all provider adapters and the aggregation service.
//
// DESIGN PRINCIPLES:
// 1. Provider-agnostic - Works with any external threat intel API
// 2. Strongly typed - Full TypeScript support with strict nullability
// 3. Extensible - Easy to add new threat categories and providers
// 4. UX-focused - Clear labeling for off-chain vs on-chain signals

import { Chain } from '@/types';

// ============================================
// THREAT INPUT TYPES
// ============================================

/**
 * Input for threat intelligence queries.
 * Supports wallet addresses, contract addresses, and domains.
 */
export interface ThreatIntelInput {
  // The value to check (address, domain, etc.)
  value: string;
  
  // Type of input
  type: 'wallet' | 'contract' | 'domain' | 'url';
  
  // Optional chain context for address lookups
  chain?: Chain;
  
  // Request metadata
  requestId?: string;
  requestedAt?: string;
}

// ============================================
// THREAT FINDING SCHEMA (Unified)
// ============================================

/**
 * Threat category classification.
 * All providers must normalize their findings to these categories.
 */
export type ThreatCategory = 
  | 'phishing'     // Phishing campaigns, fake login pages
  | 'scam'         // Scam websites, fake projects
  | 'drainer'      // Wallet drainer contracts
  | 'malware'      // Malware distribution
  | 'exploit'      // Known exploit contracts
  | 'impersonation' // Brand/person impersonation
  | 'honeypot'     // Honeypot tokens/contracts
  | 'rug_pull'     // Rug pull projects
  | 'unknown';     // Unclassified threats

/**
 * Threat severity levels.
 * Normalized across all providers.
 */
export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * A single threat finding from a provider.
 * This is the normalized, unified schema for all provider responses.
 */
export interface ThreatFinding {
  // Which provider reported this finding
  provider: string;
  
  // Normalized threat category
  category: ThreatCategory;
  
  // Severity level
  severity: ThreatSeverity;
  
  // Confidence score (0-100)
  // Higher values indicate more certainty
  confidence: number;
  
  // Human-readable description
  description: string;
  
  // When this threat was first reported (ISO timestamp)
  firstReportedAt?: string;
  
  // When this threat was last seen active (ISO timestamp)
  lastSeenAt?: string;
  
  // Reference URL to evidence or report
  referenceUrl?: string;
  
  // Raw response from the provider (for debugging)
  raw?: unknown;
  
  // Provider-specific metadata
  metadata?: Record<string, unknown>;
  
  // Tags for additional classification
  tags?: string[];
}

// ============================================
// AGGREGATED THREAT REPORT
// ============================================

/**
 * Overall risk level after aggregation.
 */
export type OverallRiskLevel = 'safe' | 'suspicious' | 'high_risk' | 'critical';

/**
 * Source attribution for transparency.
 * Shows which providers reported each finding.
 */
export interface SourceAttribution {
  provider: string;
  reportedAt: string;
  confidence: number;
  findingId: string;
}

/**
 * Aggregated findings by category.
 */
export interface CategorySummary {
  category: ThreatCategory;
  count: number;
  maxSeverity: ThreatSeverity;
  maxConfidence: number;
  providers: string[];
  findings: ThreatFinding[];
}

/**
 * Complete aggregated threat report.
 * This is returned by ThreatIntelService after querying all providers.
 */
export interface ThreatReport {
  // Input that was analyzed
  input: ThreatIntelInput;
  
  // Overall risk assessment
  overallRiskScore: number; // 0-100
  riskLevel: OverallRiskLevel;
  
  // Was any threat detected?
  threatDetected: boolean;
  
  // All findings from all providers
  findings: ThreatFinding[];
  
  // Findings grouped by category
  categorySummaries: CategorySummary[];
  
  // Cross-source agreement metrics
  crossSourceAgreement: {
    // Number of providers that agree on threat detection
    agreementCount: number;
    // Total providers queried
    totalProviders: number;
    // Agreement percentage
    agreementPercentage: number;
    // Categories with multi-provider agreement
    agreedCategories: ThreatCategory[];
  };
  
  // Source attribution for transparency
  sourceAttributions: SourceAttribution[];
  
  // Providers that were queried
  queriedProviders: string[];
  
  // Providers that failed (for partial results)
  failedProviders: string[];
  
  // Assessment metadata
  assessedAt: string;
  cacheTTL?: number; // Seconds until cache expires
  
  // UI display helpers
  displaySummary: ThreatReportSummary;
}

/**
 * Summary for UI display.
 * Pre-computed for efficient rendering.
 */
export interface ThreatReportSummary {
  // Short headline (e.g., "2 security reports found")
  headline: string;
  
  // Longer explanation
  explanation: string;
  
  // User guidance
  guidance: string;
  
  // Warning level for UI styling
  warningLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  
  // Should show warning banner?
  showWarning: boolean;
  
  // ============================================
  // CRITICAL UX REQUIREMENT
  // ============================================
  // Off-chain signals must be clearly labeled
  offChainLabel: string;
  offChainDisclaimer: string;
}

// ============================================
// PROVIDER INTERFACE
// ============================================

/**
 * Provider health status.
 */
export interface ProviderHealth {
  isHealthy: boolean;
  lastCheckAt: string;
  latencyMs?: number;
  errorMessage?: string;
  consecutiveFailures: number;
}

/**
 * Provider rate limit status.
 */
export interface ProviderRateLimit {
  requestsRemaining: number;
  requestsLimit: number;
  resetAt: string;
  isLimited: boolean;
}

/**
 * Provider configuration.
 */
export interface ThreatProviderConfig {
  // Provider identifier
  id: string;
  
  // Display name
  name: string;
  
  // API endpoint
  endpoint: string;
  
  // API key environment variable name
  apiKeyEnvVar: string;
  
  // Timeout in milliseconds
  timeoutMs: number;
  
  // Max retries on failure
  maxRetries: number;
  
  // Retry delay in milliseconds
  retryDelayMs: number;
  
  // Rate limit configuration
  rateLimit?: {
    requestsPerMinute: number;
    requestsPerDay: number;
  };
  
  // Confidence weight (how much to trust this provider)
  // 1.0 = full trust, 0.5 = half trust
  confidenceWeight: number;
  
  // Whether this provider is enabled
  enabled: boolean;
  
  // Provider-specific options
  options?: Record<string, unknown>;
}

/**
 * Provider query result.
 */
export interface ProviderQueryResult {
  providerId: string;
  providerName: string;
  findings: ThreatFinding[];
  queryTimeMs: number;
  queriedAt: string;
  success: boolean;
  error?: string;
  rateLimit?: ProviderRateLimit;
}

/**
 * Interface that all threat intelligence providers must implement.
 */
export interface ThreatProvider {
  // Provider name
  readonly name: string;
  
  // Provider ID (lowercase, no spaces)
  readonly id: string;
  
  // Whether the provider is currently enabled
  readonly enabled: boolean;
  
  // Configuration
  readonly config: ThreatProviderConfig;
  
  // Query the provider for threat information
  checkAddress(input: ThreatIntelInput): Promise<ThreatFinding[]>;
  
  // Check if the provider is healthy
  healthCheck(): Promise<ProviderHealth>;
  
  // Get current rate limit status
  getRateLimitStatus(): ProviderRateLimit | null;
  
  // Update configuration
  updateConfig(config: Partial<ThreatProviderConfig>): void;
}

// ============================================
// SERVICE CONFIGURATION
// ============================================

/**
 * Cache configuration.
 */
export interface CacheConfig {
  // Enable caching
  enabled: boolean;
  
  // Default TTL in seconds
  defaultTTLSeconds: number;
  
  // TTL for clean results (no threats found)
  cleanTTLSeconds: number;
  
  // TTL for threat results
  threatTTLSeconds: number;
  
  // Cache backend type
  backend: 'memory' | 'redis';
  
  // Redis connection string (if using Redis)
  redisUrl?: string;
  
  // Maximum cache size (for memory cache)
  maxSize?: number;
}

/**
 * Aggregation configuration.
 */
export interface AggregationConfig {
  // Minimum providers required for high confidence
  minProvidersForHighConfidence: number;
  
  // Confidence boost when multiple providers agree
  multiProviderConfidenceBoost: number;
  
  // Score thresholds for risk levels
  scoreThresholds: {
    suspicious: number;   // Score >= this is suspicious
    highRisk: number;     // Score >= this is high risk
    critical: number;     // Score >= this is critical
  };
  
  // Severity weights for score calculation
  severityWeights: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  
  // Category weights (some categories are more serious)
  categoryWeights: Record<ThreatCategory, number>;
}

/**
 * ThreatIntelService configuration.
 */
export interface ThreatIntelServiceConfig {
  // Enabled providers
  enabledProviders: string[];
  
  // Query timeout for all providers (ms)
  queryTimeoutMs: number;
  
  // Whether to return partial results on provider failure
  returnPartialResults: boolean;
  
  // Minimum providers that must succeed
  minSuccessfulProviders: number;
  
  // Cache configuration
  cache: CacheConfig;
  
  // Aggregation configuration
  aggregation: AggregationConfig;
  
  // Feature flags
  featureFlags: {
    // Use real threat intel APIs vs mock
    useRealThreatIntel: boolean;
    
    // Enable verbose logging
    verboseLogging: boolean;
    
    // Enable provider health checks
    enableHealthChecks: boolean;
    
    // Interval for health checks (ms)
    healthCheckIntervalMs: number;
  };
}

/**
 * Default service configuration.
 */
export const DEFAULT_THREAT_INTEL_CONFIG: ThreatIntelServiceConfig = {
  enabledProviders: ['chainpatrol', 'scamsniffer', 'phishfort', 'walletguard'],
  queryTimeoutMs: 10000,
  returnPartialResults: true,
  minSuccessfulProviders: 1,
  cache: {
    enabled: true,
    defaultTTLSeconds: 21600, // 6 hours
    cleanTTLSeconds: 86400,   // 24 hours for clean results
    threatTTLSeconds: 21600,   // 6 hours for threat results
    backend: 'memory',
    maxSize: 10000,
  },
  aggregation: {
    minProvidersForHighConfidence: 2,
    multiProviderConfidenceBoost: 15,
    scoreThresholds: {
      suspicious: 20,
      highRisk: 50,
      critical: 80,
    },
    severityWeights: {
      low: 5,
      medium: 15,
      high: 30,
      critical: 50,
    },
    categoryWeights: {
      phishing: 1.2,
      scam: 1.0,
      drainer: 1.5,
      malware: 1.3,
      exploit: 1.4,
      impersonation: 0.9,
      honeypot: 1.1,
      rug_pull: 1.0,
      unknown: 0.5,
    },
  },
  featureFlags: {
    useRealThreatIntel: process.env.USE_REAL_THREAT_INTEL === 'true',
    verboseLogging: process.env.THREAT_INTEL_VERBOSE === 'true',
    enableHealthChecks: true,
    healthCheckIntervalMs: 60000, // 1 minute
  },
};

// ============================================
// DISPLAY CONSTANTS
// ============================================

/**
 * Standard off-chain signal labels.
 * CRITICAL UX REQUIREMENT: Always use these labels.
 */
export const OFF_CHAIN_LABELS = {
  // Main label
  label: 'Reported by external security intelligence providers (off-chain signal)',
  
  // Short label for badges
  shortLabel: 'Off-chain signal',
  
  // Disclaimer text
  disclaimer: 'This information is based on reports from external threat intelligence providers. ' +
              'It does not indicate on-chain malicious activity. ' +
              'Do NOT mark wallets as "compromised" solely based on off-chain reports.',
  
  // Provider attribution prefix
  attributionPrefix: 'Reported by:',
  
  // Confidence explanation
  confidenceExplanation: {
    low: 'Single source report with limited verification',
    medium: 'Corroborated by multiple sources or verified by provider',
    high: 'Strong evidence from multiple independent sources',
  },
} as const;

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Get severity weight for score calculation.
 */
export function getSeverityWeight(severity: ThreatSeverity, config: AggregationConfig): number {
  return config.severityWeights[severity] || 0;
}

/**
 * Get category weight for score calculation.
 */
export function getCategoryWeight(category: ThreatCategory, config: AggregationConfig): number {
  return config.categoryWeights[category] || 0.5;
}

/**
 * Determine risk level from score.
 */
export function getRiskLevelFromScore(score: number, config: AggregationConfig): OverallRiskLevel {
  if (score >= config.scoreThresholds.critical) return 'critical';
  if (score >= config.scoreThresholds.highRisk) return 'high_risk';
  if (score >= config.scoreThresholds.suspicious) return 'suspicious';
  return 'safe';
}

/**
 * Get human-readable severity label.
 */
export function getSeverityLabel(severity: ThreatSeverity): string {
  const labels: Record<ThreatSeverity, string> = {
    low: 'Low',
    medium: 'Medium',
    high: 'High',
    critical: 'Critical',
  };
  return labels[severity] || 'Unknown';
}

/**
 * Get human-readable category label.
 */
export function getCategoryLabel(category: ThreatCategory): string {
  const labels: Record<ThreatCategory, string> = {
    phishing: 'Phishing',
    scam: 'Scam',
    drainer: 'Wallet Drainer',
    malware: 'Malware',
    exploit: 'Exploit',
    impersonation: 'Impersonation',
    honeypot: 'Honeypot',
    rug_pull: 'Rug Pull',
    unknown: 'Unknown Threat',
  };
  return labels[category] || 'Unknown';
}

/**
 * Get UI color for severity.
 */
export function getSeverityColor(severity: ThreatSeverity): {
  text: string;
  bg: string;
  border: string;
} {
  const colors: Record<ThreatSeverity, { text: string; bg: string; border: string }> = {
    low: { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30' },
    medium: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
    high: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
    critical: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30' },
  };
  return colors[severity] || colors.low;
}

/**
 * Get UI color for risk level.
 */
export function getRiskLevelColor(level: OverallRiskLevel): {
  text: string;
  bg: string;
  border: string;
} {
  const colors: Record<OverallRiskLevel, { text: string; bg: string; border: string }> = {
    safe: { text: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/30' },
    suspicious: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
    high_risk: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
    critical: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30' },
  };
  return colors[level] || colors.safe;
}
