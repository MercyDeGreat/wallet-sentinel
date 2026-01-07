// ============================================
// INCIDENT CORRELATION MODULE
// ============================================
// High-confidence detection of seed/signer compromise
// across multiple wallets with low false positive rate.
//
// This module provides:
// - Wallet correlation engine
// - Attack classification
// - Attacker infrastructure profiling
// - Exchange escalation reporting
//
// Design Philosophy:
// - Prioritize correctness over sensitivity
// - Minimize false positives at all costs
// - Never accuse legitimate protocols without proof
// - Prefer "Insufficient Evidence" over wrong attribution

// Main analyzer
export {
  analyzeIncident,
  quickSeedCompromiseCheck,
  formatIncidentAnalysisForAPI,
} from './incident-analyzer';

// Correlation engine
export { correlateWallets } from './correlation-engine';

// Attack classifier
export { classifyAttack } from './attack-classifier';

// Attacker profiler
export { buildAttackerProfile } from './attacker-profiler';

// Exchange report generator
export { generateExchangeReport } from './exchange-report-generator';

// Types
export type {
  // Attack classification
  AttackClassification,
  AttackClassificationResult,
  AttackClassificationReasoning,
  ConfidenceLevel,
  ClassificationEvidence,
  RejectedClassification,
  
  // Incident wallets
  IncidentWallet,
  DrainedAsset,
  TransferStep,
  WalletApproval,
  ContractInteraction,
  
  // Correlation
  CorrelationResult,
  CorrelationFactor,
  CorrelationFactorType,
  CorrelationConfig,
  TimeCorrelation,
  DestinationCorrelation,
  BehaviorCorrelation,
  
  // Attacker profiling
  AttackerProfile,
  AttackerWallet,
  AttackerWalletRole,
  AttackerStats,
  RoutingPattern,
  RoutingStep,
  ExitLiquidity,
  
  // Exchange escalation
  ExchangeEscalationReport,
  IncidentSummary,
  VictimInfo,
  AttackerInfo,
  TransactionEvidence,
  TimelineEvent,
  ExchangeSpecificData,
  ExchangeInfo,
  
  // Results
  IncidentAnalysisResult,
  UserRecommendation,
  IncidentDisplaySummary,
} from './types';

// Constants and utilities
export {
  DEFAULT_CORRELATION_CONFIG,
  KNOWN_EXCHANGES,
  generateIncidentId,
  generateCorrelationId,
  generateReportId,
  getConfidenceLevel,
} from './types';

// ============================================
// SOLANA-SPECIFIC INCIDENT CORRELATION
// ============================================
// Rule-based detection with explicit thresholds for:
// - Multi-wallet seed compromise
// - Sweeper bot detection
// - Attacker wallet clustering
// - Near Intents obfuscation
// - Exchange exit detection

// Solana incident analyzer
export {
  analyzeSolanaIncident,
  quickSolanaSeedCompromiseCheck,
  formatSolanaIncidentForAPI,
} from './solana-incident-analyzer';

// Solana rules engine
export {
  evaluateSeedCompromise,
  evaluateSweeperBot,
  evaluateAttackerCluster,
  evaluateNearIntentsObfuscation,
  evaluateExchangeExit,
  calculateConfidenceScore,
  buildAttackerWalletList,
} from './solana-rules-engine';

// Solana types
export type {
  // Wallet data
  SolanaIncidentWallet,
  SolanaTokenBalance,
  SolanaDrainTransaction,
  SolanaProgramInteraction,
  SolanaProgramCategory,
  SolanaAuthority,
  
  // Rule evaluations
  SeedCompromiseEvaluation,
  SweeperBotEvaluation,
  AttackerClusterEvaluation,
  NearIntentsEvaluation,
  ExchangeExitEvaluation,
  RuleResult,
  
  // Results
  SolanaIncidentAnalysisResult,
  SolanaAttackClassification,
  SolanaIncidentTimeline,
  SolanaTimelineEvent,
  SolanaAttackerWallet,
  NearIntentTransaction,
  SolanaRecommendation,
  SolanaMachineReadableOutput,
} from './solana-types';

// Solana constants
export {
  SOLANA_CORRELATION_CONFIG,
  SOLANA_KNOWN_PROGRAMS,
  SOLANA_NFT_PROGRAMS,
  SOLANA_DEX_PROGRAMS,
  SOLANA_BRIDGE_PROGRAMS,
  SOLANA_KNOWN_EXCHANGES,
  generateSolanaIncidentId,
  isKnownNFTProgram,
  isKnownDEXProgram,
  isKnownBridgeProgram,
  isKnownExchange,
  lamportsToSOL,
  calculateDrainPercentage,
} from './solana-types';
