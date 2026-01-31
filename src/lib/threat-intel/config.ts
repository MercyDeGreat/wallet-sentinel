// ============================================
// THREAT INTELLIGENCE CONFIGURATION
// ============================================
// Environment-based configuration for threat intelligence.
// All settings can be overridden via environment variables.
//
// ENVIRONMENT VARIABLES:
// - USE_REAL_THREAT_INTEL: Enable production API calls (default: false)
// - THREAT_INTEL_VERBOSE: Enable verbose logging (default: false)
// - THREAT_INTEL_CACHE_BACKEND: Cache backend (memory | redis)
// - THREAT_INTEL_CACHE_TTL: Default cache TTL in seconds
// - REDIS_URL: Redis connection string for distributed cache
//
// PROVIDER API KEYS:
// - CHAINPATROL_API_KEY: ChainPatrol API key
// - SCAMSNIFFER_API_KEY: ScamSniffer API key
// - PHISHFORT_API_KEY: PhishFort API key
// - WALLETGUARD_API_KEY: Wallet Guard API key

import { ThreatIntelServiceConfig, DEFAULT_THREAT_INTEL_CONFIG } from './types';

// ============================================
// ENVIRONMENT HELPERS
// ============================================

/**
 * Get environment variable with fallback.
 */
function getEnv(key: string, fallback: string = ''): string {
  return process.env[key] || fallback;
}

/**
 * Get boolean environment variable.
 */
function getEnvBool(key: string, fallback: boolean = false): boolean {
  const value = process.env[key];
  if (value === undefined) return fallback;
  return value === 'true' || value === '1';
}

/**
 * Get numeric environment variable.
 */
function getEnvNumber(key: string, fallback: number): number {
  const value = process.env[key];
  if (value === undefined) return fallback;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? fallback : parsed;
}

// ============================================
// CONFIGURATION BUILDER
// ============================================

/**
 * Build configuration from environment variables.
 */
export function buildConfigFromEnv(): ThreatIntelServiceConfig {
  const useRealThreatIntel = getEnvBool('USE_REAL_THREAT_INTEL', false);
  const verboseLogging = getEnvBool('THREAT_INTEL_VERBOSE', false);
  const cacheBackend = getEnv('THREAT_INTEL_CACHE_BACKEND', 'memory') as 'memory' | 'redis';
  const cacheTTL = getEnvNumber('THREAT_INTEL_CACHE_TTL', 21600); // 6 hours default
  const redisUrl = getEnv('REDIS_URL');

  // Determine which providers are enabled based on API key presence
  const enabledProviders: string[] = [];
  if (process.env.CHAINPATROL_API_KEY) enabledProviders.push('chainpatrol');
  if (process.env.SCAMSNIFFER_API_KEY) enabledProviders.push('scamsniffer');
  if (process.env.PHISHFORT_API_KEY) enabledProviders.push('phishfort');
  if (process.env.WALLETGUARD_API_KEY) enabledProviders.push('walletguard');

  return {
    ...DEFAULT_THREAT_INTEL_CONFIG,
    enabledProviders,
    queryTimeoutMs: getEnvNumber('THREAT_INTEL_TIMEOUT_MS', 10000),
    returnPartialResults: getEnvBool('THREAT_INTEL_PARTIAL_RESULTS', true),
    minSuccessfulProviders: getEnvNumber('THREAT_INTEL_MIN_PROVIDERS', 1),
    cache: {
      enabled: getEnvBool('THREAT_INTEL_CACHE_ENABLED', true),
      defaultTTLSeconds: cacheTTL,
      cleanTTLSeconds: getEnvNumber('THREAT_INTEL_CLEAN_TTL', 86400), // 24 hours
      threatTTLSeconds: getEnvNumber('THREAT_INTEL_THREAT_TTL', 21600), // 6 hours
      backend: cacheBackend,
      redisUrl: cacheBackend === 'redis' ? redisUrl : undefined,
      maxSize: getEnvNumber('THREAT_INTEL_CACHE_SIZE', 10000),
    },
    aggregation: {
      ...DEFAULT_THREAT_INTEL_CONFIG.aggregation,
      minProvidersForHighConfidence: getEnvNumber('THREAT_INTEL_MIN_AGREEMENT', 2),
      multiProviderConfidenceBoost: getEnvNumber('THREAT_INTEL_AGREEMENT_BOOST', 15),
    },
    featureFlags: {
      useRealThreatIntel,
      verboseLogging,
      enableHealthChecks: getEnvBool('THREAT_INTEL_HEALTH_CHECKS', true),
      healthCheckIntervalMs: getEnvNumber('THREAT_INTEL_HEALTH_INTERVAL', 60000),
    },
  };
}

/**
 * Get the default configuration.
 */
export function getDefaultConfig(): ThreatIntelServiceConfig {
  return DEFAULT_THREAT_INTEL_CONFIG;
}

// ============================================
// FEATURE FLAGS
// ============================================

/**
 * Feature flag helpers for threat intelligence.
 */
export const FeatureFlags = {
  /**
   * Check if real threat intelligence is enabled.
   */
  isRealThreatIntelEnabled(): boolean {
    return getEnvBool('USE_REAL_THREAT_INTEL', false);
  },

  /**
   * Check if verbose logging is enabled.
   */
  isVerboseLoggingEnabled(): boolean {
    return getEnvBool('THREAT_INTEL_VERBOSE', false);
  },

  /**
   * Check if caching is enabled.
   */
  isCachingEnabled(): boolean {
    return getEnvBool('THREAT_INTEL_CACHE_ENABLED', true);
  },

  /**
   * Check if Redis cache is being used.
   */
  isRedisCacheEnabled(): boolean {
    return getEnv('THREAT_INTEL_CACHE_BACKEND', 'memory') === 'redis' && 
           !!getEnv('REDIS_URL');
  },

  /**
   * Check if a specific provider is configured (has API key).
   */
  isProviderConfigured(providerId: string): boolean {
    const envVars: Record<string, string> = {
      chainpatrol: 'CHAINPATROL_API_KEY',
      scamsniffer: 'SCAMSNIFFER_API_KEY',
      phishfort: 'PHISHFORT_API_KEY',
      walletguard: 'WALLETGUARD_API_KEY',
    };
    const envVar = envVars[providerId];
    return envVar ? !!process.env[envVar] : false;
  },

  /**
   * Get list of configured providers.
   */
  getConfiguredProviders(): string[] {
    const providers: string[] = [];
    if (this.isProviderConfigured('chainpatrol')) providers.push('chainpatrol');
    if (this.isProviderConfigured('scamsniffer')) providers.push('scamsniffer');
    if (this.isProviderConfigured('phishfort')) providers.push('phishfort');
    if (this.isProviderConfigured('walletguard')) providers.push('walletguard');
    return providers;
  },
};

// ============================================
// ENVIRONMENT DOCUMENTATION
// ============================================

/**
 * Generate documentation for environment variables.
 */
export function getEnvDocumentation(): Record<string, { description: string; default: string; required: boolean }> {
  return {
    USE_REAL_THREAT_INTEL: {
      description: 'Enable real threat intelligence API calls. When false, no external APIs are called.',
      default: 'false',
      required: false,
    },
    THREAT_INTEL_VERBOSE: {
      description: 'Enable verbose logging for debugging.',
      default: 'false',
      required: false,
    },
    THREAT_INTEL_CACHE_ENABLED: {
      description: 'Enable result caching to reduce API calls.',
      default: 'true',
      required: false,
    },
    THREAT_INTEL_CACHE_BACKEND: {
      description: 'Cache backend type: "memory" or "redis".',
      default: 'memory',
      required: false,
    },
    THREAT_INTEL_CACHE_TTL: {
      description: 'Default cache TTL in seconds.',
      default: '21600 (6 hours)',
      required: false,
    },
    THREAT_INTEL_TIMEOUT_MS: {
      description: 'Timeout for provider queries in milliseconds.',
      default: '10000',
      required: false,
    },
    REDIS_URL: {
      description: 'Redis connection string for distributed caching.',
      default: '',
      required: false,
    },
    CHAINPATROL_API_KEY: {
      description: 'API key for ChainPatrol threat intelligence.',
      default: '',
      required: false,
    },
    SCAMSNIFFER_API_KEY: {
      description: 'API key for ScamSniffer threat intelligence.',
      default: '',
      required: false,
    },
    PHISHFORT_API_KEY: {
      description: 'API key for PhishFort threat intelligence.',
      default: '',
      required: false,
    },
    WALLETGUARD_API_KEY: {
      description: 'API key for Wallet Guard threat intelligence.',
      default: '',
      required: false,
    },
  };
}

/**
 * Print environment configuration status.
 */
export function printConfigStatus(): void {
  console.log('\n=== Threat Intelligence Configuration ===');
  console.log(`Real threat intel enabled: ${FeatureFlags.isRealThreatIntelEnabled()}`);
  console.log(`Verbose logging: ${FeatureFlags.isVerboseLoggingEnabled()}`);
  console.log(`Caching enabled: ${FeatureFlags.isCachingEnabled()}`);
  console.log(`Cache backend: ${getEnv('THREAT_INTEL_CACHE_BACKEND', 'memory')}`);
  console.log(`Configured providers: ${FeatureFlags.getConfiguredProviders().join(', ') || 'none'}`);
  console.log('==========================================\n');
}
