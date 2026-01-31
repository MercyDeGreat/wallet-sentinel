// ============================================
// THREAT INTELLIGENCE AGGREGATION LAYER
// ============================================
// Main export file for the Threat Intelligence module.
//
// This module provides production-ready threat intelligence by:
// - Querying multiple external APIs in parallel (ChainPatrol, ScamSniffer, PhishFort, Wallet Guard)
// - Normalizing responses into a unified threat schema
// - Assigning confidence scores based on cross-source agreement
// - Caching results to avoid rate limits
// - Gracefully handling API failures
//
// CORE PRINCIPLE:
// Off-chain threat intelligence provides additional context but should
// NEVER be used to mark wallets as "compromised" without on-chain evidence.
//
// USAGE:
// ```typescript
// import { getThreatIntelService, checkAddressThreat } from '@/lib/threat-intel';
//
// // Quick check
// const report = await checkAddressThreat('0x...', 'ethereum');
//
// // Or use the service directly
// const service = getThreatIntelService();
// const report = await service.checkAddress({ value: '0x...', type: 'wallet' });
// ```

// ============================================
// TYPES
// ============================================
export type {
  // Input/Output types
  ThreatIntelInput,
  ThreatFinding,
  ThreatReport,
  ThreatReportSummary,
  
  // Classification types
  ThreatCategory,
  ThreatSeverity,
  OverallRiskLevel,
  
  // Aggregation types
  CategorySummary,
  SourceAttribution,
  
  // Provider types
  ThreatProvider,
  ThreatProviderConfig,
  ProviderHealth,
  ProviderRateLimit,
  ProviderQueryResult,
  
  // Configuration types
  ThreatIntelServiceConfig,
  CacheConfig,
  AggregationConfig,
} from './types';

// Export constants and helpers
export {
  DEFAULT_THREAT_INTEL_CONFIG,
  OFF_CHAIN_LABELS,
  getSeverityWeight,
  getCategoryWeight,
  getRiskLevelFromScore,
  getSeverityLabel,
  getCategoryLabel,
  getSeverityColor,
  getRiskLevelColor,
} from './types';

// ============================================
// SERVICE
// ============================================
export {
  ThreatIntelService,
  getThreatIntelService,
  resetThreatIntelService,
  checkAddressThreat,
  checkDomainThreat,
} from './service';

// ============================================
// CACHE
// ============================================
export {
  type ThreatIntelCache,
  type CacheEntry,
  type CacheStats,
  MemoryThreatCache,
  RedisThreatCache,
  createCache,
  generateCacheKey,
  parseCacheKey,
} from './cache';

// ============================================
// PROVIDERS
// ============================================
export {
  // Base provider
  BaseThreatProvider,
  createProviderConfig,
  
  // Production providers
  ChainPatrolProvider,
  ScamSnifferProvider,
  PhishFortProvider,
  WalletGuardProvider,
  
  // Factory functions
  createChainPatrolProvider,
  createScamSnifferProvider,
  createPhishFortProvider,
  createWalletGuardProvider,
  
  // Provider utilities
  createProvider,
  createAllProviders,
  getAvailableProviderTypes,
  getConfiguredProviders,
  type ProviderType,
} from './providers';

// ============================================
// CONFIGURATION
// ============================================
export {
  buildConfigFromEnv,
  getDefaultConfig,
  FeatureFlags,
  getEnvDocumentation,
  printConfigStatus,
} from './config';

// ============================================
// QUICK START GUIDE
// ============================================
/*
1. Set up environment variables:
   - CHAINPATROL_API_KEY=your_key
   - SCAMSNIFFER_API_KEY=your_key
   - PHISHFORT_API_KEY=your_key
   - WALLETGUARD_API_KEY=your_key
   - USE_REAL_THREAT_INTEL=true

2. Use the service:
   ```typescript
   import { checkAddressThreat, OFF_CHAIN_LABELS } from '@/lib/threat-intel';
   
   const report = await checkAddressThreat('0x123...', 'ethereum');
   
   if (report.threatDetected) {
     console.log(report.displaySummary.headline);
     console.log(OFF_CHAIN_LABELS.disclaimer); // Always show this!
   }
   ```

3. Display in UI:
   - Always show off-chain label: "Reported by external security intelligence providers (off-chain signal)"
   - Never mark wallet as "compromised" based solely on off-chain reports
   - Show provider attribution for transparency
*/
