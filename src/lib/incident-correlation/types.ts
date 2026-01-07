// ============================================
// INCIDENT CORRELATION & ATTACK CLASSIFICATION
// ============================================
// High-confidence detection of seed/signer compromise
// across multiple wallets with low false positive rate.
//
// Design Philosophy:
// - Prioritize correctness over sensitivity
// - Minimize false positives at all costs
// - Never accuse legitimate protocols without proof
// - Prefer "Insufficient Evidence" over wrong attribution

import { Chain } from '@/types';

// ============================================
// ATTACK CLASSIFICATION TYPES
// ============================================

/**
 * Attack classification categories.
 * Only classify as SEED_SIGNER_COMPROMISE when ALL criteria are met.
 */
export type AttackClassification =
  | 'SEED_SIGNER_COMPROMISE'     // Multi-wallet drain from compromised seed/signer
  | 'APPROVAL_BASED_DRAIN'       // Drain via malicious token approvals
  | 'CONTRACT_EXPLOIT'           // Drain via smart contract vulnerability
  | 'SINGLE_WALLET_INCIDENT'     // Isolated incident affecting one wallet
  | 'UNKNOWN_INSUFFICIENT_EVIDENCE'; // Cannot determine with confidence

/**
 * Confidence levels for attack classification.
 * Only "HIGH" confidence should trigger automated actions.
 */
export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT';

/**
 * Detailed attack classification result.
 */
export interface AttackClassificationResult {
  classification: AttackClassification;
  confidence: ConfidenceLevel;
  confidenceScore: number; // 0-100
  
  // Why this classification was chosen
  reasoning: AttackClassificationReasoning;
  
  // Why other classifications were rejected
  rejectedClassifications: RejectedClassification[];
  
  // Human-readable summary
  summary: string;
  
  // Evidence that supports this classification
  supportingEvidence: ClassificationEvidence[];
  
  // Evidence that contradicts this classification
  contradictingEvidence: ClassificationEvidence[];
}

export interface AttackClassificationReasoning {
  // For SEED_SIGNER_COMPROMISE
  multiWalletDrain: boolean;
  withinTimeWindow: boolean;
  noSharedMaliciousContract: boolean;
  noSharedApprovalTarget: boolean;
  fundsRoutedToSameDestination: boolean;
  includesNativeAssets: boolean;
  fullBalanceExtractions: boolean;
  
  // For APPROVAL_BASED_DRAIN
  maliciousApprovalFound: boolean;
  drainFollowedApproval: boolean;
  approvalTargetKnownMalicious: boolean;
  
  // For CONTRACT_EXPLOIT
  sharedContractInteraction: boolean;
  contractKnownVulnerable: boolean;
  exploitPatternMatched: boolean;
  
  // Summary of why NOT other classifications
  whyNotApprovalDrain?: string;
  whyNotContractExploit?: string;
  whyNotSeedCompromise?: string;
}

export interface RejectedClassification {
  classification: AttackClassification;
  reason: string;
  contradictingFactors: string[];
}

export interface ClassificationEvidence {
  type: 'SUPPORTING' | 'CONTRADICTING';
  category: string;
  description: string;
  weight: number; // 0-100, how much this affects classification
  txHash?: string;
  address?: string;
  timestamp?: string;
}

// ============================================
// WALLET CORRELATION TYPES
// ============================================

/**
 * Represents a wallet involved in an incident.
 */
export interface IncidentWallet {
  address: string;
  chain: Chain;
  
  // Drain details
  drainTimestamp: string; // ISO timestamp
  drainBlockNumber: number;
  drainTxHash: string;
  
  // What was drained
  drainedAssets: DrainedAsset[];
  totalDrainedValueUSD: number;
  
  // Transfer details
  destinationAddresses: string[];
  transferSequence: TransferStep[];
  
  // Gas analysis
  gasPrice: string;
  gasUsed: string;
  
  // Context
  wasFullBalance: boolean;
  hadPriorApprovals: boolean;
  relevantApprovals: WalletApproval[];
  priorContractInteractions: ContractInteraction[];
  
  // User session indicators (optional)
  sessionId?: string;
  environmentFingerprint?: string;
}

export interface DrainedAsset {
  type: 'NATIVE' | 'ERC20' | 'ERC721' | 'ERC1155';
  contractAddress?: string;
  symbol: string;
  amount: string;
  valueUSD: number;
  txHash: string;
}

export interface TransferStep {
  order: number;
  txHash: string;
  from: string;
  to: string;
  asset: string;
  amount: string;
  timestamp: string;
  blockNumber: number;
}

export interface WalletApproval {
  tokenAddress: string;
  tokenSymbol: string;
  spender: string;
  amount: string;
  isUnlimited: boolean;
  approvalTxHash: string;
  approvalTimestamp: string;
  wasRevoked: boolean;
  revokedTimestamp?: string;
}

export interface ContractInteraction {
  contractAddress: string;
  contractName?: string;
  method: string;
  txHash: string;
  timestamp: string;
  isLegitimateProtocol: boolean;
}

// ============================================
// CORRELATION ENGINE TYPES
// ============================================

/**
 * Configuration for the correlation engine.
 */
export interface CorrelationConfig {
  // Time window for grouping drains (default: 90 minutes)
  drainTimeWindowMinutes: number;
  
  // Minimum wallets to consider multi-wallet attack
  minWalletsForMultiWallet: number;
  
  // Confidence thresholds
  highConfidenceThreshold: number; // Default: 85
  mediumConfidenceThreshold: number; // Default: 60
  lowConfidenceThreshold: number; // Default: 40
  
  // Exchange escalation threshold
  exchangeEscalationThreshold: number; // Default: 80
  
  // Known legitimate protocols to exclude
  legitimateProtocols: string[];
  
  // Known exchange deposit addresses
  knownExchangeAddresses: string[];
}

export const DEFAULT_CORRELATION_CONFIG: CorrelationConfig = {
  drainTimeWindowMinutes: 90,
  minWalletsForMultiWallet: 2,
  highConfidenceThreshold: 85,
  mediumConfidenceThreshold: 60,
  lowConfidenceThreshold: 40,
  exchangeEscalationThreshold: 80,
  legitimateProtocols: [],
  knownExchangeAddresses: [],
};

/**
 * Result of wallet correlation analysis.
 */
export interface CorrelationResult {
  // Correlation ID for this incident
  correlationId: string;
  
  // All wallets in this correlated group
  wallets: IncidentWallet[];
  
  // Correlation factors detected
  correlationFactors: CorrelationFactor[];
  
  // Overall correlation strength
  correlationStrength: number; // 0-100
  
  // Time analysis
  timeAnalysis: TimeCorrelation;
  
  // Destination analysis
  destinationAnalysis: DestinationCorrelation;
  
  // Behavior analysis
  behaviorAnalysis: BehaviorCorrelation;
  
  // Is this likely a multi-wallet attack?
  isMultiWalletAttack: boolean;
  multiWalletConfidence: number;
}

export interface CorrelationFactor {
  type: CorrelationFactorType;
  strength: number; // 0-100
  description: string;
  affectedWallets: string[];
  evidence: string[];
}

export type CorrelationFactorType =
  | 'TIME_PROXIMITY'
  | 'DESTINATION_REUSE'
  | 'TRANSFER_SEQUENCING'
  | 'GAS_PATTERN_MATCH'
  | 'FULL_BALANCE_DRAIN'
  | 'NO_PRIOR_APPROVAL'
  | 'SAME_ATTACKER_INFRASTRUCTURE';

export interface TimeCorrelation {
  earliestDrain: string;
  latestDrain: string;
  totalWindowMinutes: number;
  withinConfiguredWindow: boolean;
  averageTimeBetweenDrains: number;
  drainSequenceOrder: string[]; // Wallet addresses in drain order
}

export interface DestinationCorrelation {
  uniqueDestinations: string[];
  sharedDestinations: string[];
  destinationReuseCount: number;
  primaryDestination?: string;
  destinationIsExchange: boolean;
  destinationIsKnownAttacker: boolean;
}

export interface BehaviorCorrelation {
  allFullBalanceDrains: boolean;
  allIncludeNativeAssets: boolean;
  similarGasPatterns: boolean;
  identicalTransferSequencing: boolean;
  noSharedApprovalTarget: boolean;
  noSharedContractExploit: boolean;
}

// ============================================
// ATTACKER INFRASTRUCTURE TYPES
// ============================================

/**
 * Represents an attacker's infrastructure profile.
 */
export interface AttackerProfile {
  // Primary identifier
  profileId: string;
  
  // Attacker wallets (aggregation, routing, etc.)
  wallets: AttackerWallet[];
  
  // Attack statistics
  stats: AttackerStats;
  
  // Routing patterns
  routingPatterns: RoutingPattern[];
  
  // Exit liquidity
  exitLiquidity: ExitLiquidity[];
  
  // Confidence this is actually an attacker
  confidence: number; // 0-100
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  
  // Only label as "scammer" if confidence ≥ 90
  labelAsScammer: boolean;
  
  // Metadata
  firstSeen: string;
  lastSeen: string;
  isActive: boolean;
}

export interface AttackerWallet {
  address: string;
  chain: Chain;
  role: AttackerWalletRole;
  
  // Statistics
  totalReceivedFromVictims: number; // USD
  totalTransactions: number;
  linkedVictimCount: number;
  
  // Timestamps
  firstSeen: string;
  lastSeen: string;
  
  // Trust indicators
  confidence: number;
}

export type AttackerWalletRole =
  | 'AGGREGATION'       // Collects funds from multiple victims
  | 'SWEEPER'           // Automated sweeping of victim wallets
  | 'ROUTER'            // Routes funds through obfuscation paths
  | 'BRIDGE_STAGING'    // Stages funds before bridging
  | 'EXCHANGE_DEPOSIT'  // Final deposit to exchange
  | 'UNKNOWN';

export interface AttackerStats {
  totalVictims: number;
  totalStolenUSD: number;
  chainsInvolved: Chain[];
  attackMethods: AttackClassification[];
  averageTimeBetweenAttacks: number; // minutes
  isOngoing: boolean;
}

export interface RoutingPattern {
  patternId: string;
  description: string;
  steps: RoutingStep[];
  frequency: number; // How many times this pattern was used
  confidence: number;
}

export interface RoutingStep {
  order: number;
  type: 'TRANSFER' | 'SWAP' | 'BRIDGE' | 'DEPOSIT';
  fromChain: Chain;
  toChain?: Chain;
  intermediaryAddress?: string;
  protocol?: string;
}

export interface ExitLiquidity {
  type: 'EXCHANGE' | 'BRIDGE' | 'DEX' | 'MIXER' | 'UNKNOWN';
  name: string;
  address?: string;
  chain: Chain;
  totalVolumeUSD: number;
  transactionCount: number;
  confidence: number;
}

// ============================================
// EXCHANGE ESCALATION REPORT TYPES
// ============================================

/**
 * Exchange escalation report for abuse portals.
 */
export interface ExchangeEscalationReport {
  // Report metadata
  reportId: string;
  generatedAt: string; // ISO timestamp
  reportVersion: string;
  
  // Incident overview
  incidentSummary: IncidentSummary;
  
  // Attack details
  attackClassification: AttackClassificationResult;
  
  // Victim information
  victims: VictimInfo[];
  
  // Attacker information
  attackerInfo: AttackerInfo;
  
  // Transaction evidence
  transactionEvidence: TransactionEvidence[];
  
  // Timeline
  incidentTimeline: TimelineEvent[];
  
  // Exchange-specific data
  exchangeData: ExchangeSpecificData;
  
  // Confidence and readiness
  confidenceScore: number;
  escalationReady: boolean;
  escalationReadinessReason: string;
  
  // Human-readable report
  humanReadableReport: string;
  
  // Machine-readable evidence (JSON-serializable)
  machineReadableEvidence: object;
}

export interface IncidentSummary {
  incidentId: string;
  title: string;
  description: string;
  totalLossUSD: number;
  victimCount: number;
  chainsAffected: Chain[];
  incidentStart: string; // ISO timestamp
  incidentEnd: string;
  status: 'ONGOING' | 'COMPLETED' | 'UNDER_INVESTIGATION';
}

export interface VictimInfo {
  walletAddress: string;
  chain: Chain;
  lossUSD: number;
  drainTimestamp: string;
  assetsLost: DrainedAsset[];
  txHashes: string[];
}

export interface AttackerInfo {
  primaryWallet: string;
  additionalWallets: string[];
  chainsUsed: Chain[];
  totalStolenUSD: number;
  routingPath: string[];
  exchangeDeposit?: {
    exchangeName: string;
    depositAddress: string;
    depositTxHash: string;
    depositTimestamp: string;
    depositAmountUSD: number;
  };
}

export interface TransactionEvidence {
  txHash: string;
  chain: Chain;
  type: 'DRAIN' | 'TRANSFER' | 'BRIDGE' | 'EXCHANGE_DEPOSIT';
  from: string;
  to: string;
  asset: string;
  amount: string;
  valueUSD: number;
  timestamp: string;
  blockNumber: number;
  description: string;
}

export interface TimelineEvent {
  timestamp: string;
  eventType: string;
  description: string;
  txHash?: string;
  walletAddress?: string;
  significance: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface ExchangeSpecificData {
  exchangeName: string;
  depositAddress: string;
  depositTxHashes: string[];
  totalDepositedUSD: number;
  firstDepositTimestamp: string;
  lastDepositTimestamp: string;
  
  // Compliance data
  complianceNotes: string[];
  urgencyLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  requestedAction: 'FREEZE_FUNDS' | 'FLAG_ACCOUNT' | 'INVESTIGATE' | 'MONITOR';
}

// ============================================
// INCIDENT ANALYSIS RESULT
// ============================================

/**
 * Complete incident analysis result.
 */
export interface IncidentAnalysisResult {
  // Unique incident ID
  incidentId: string;
  
  // Analysis timestamp
  analyzedAt: string;
  
  // Correlation result
  correlation: CorrelationResult;
  
  // Attack classification
  classification: AttackClassificationResult;
  
  // Attacker profile
  attackerProfile?: AttackerProfile;
  
  // Exchange escalation report (if applicable)
  exchangeReport?: ExchangeEscalationReport;
  
  // User recommendations
  recommendations: UserRecommendation[];
  
  // Analysis confidence
  overallConfidence: number;
  confidenceLevel: ConfidenceLevel;
  
  // Summary for display
  displaySummary: IncidentDisplaySummary;
}

export interface UserRecommendation {
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  action: string;
  reason: string;
  timeframe: 'IMMEDIATE' | 'URGENT' | 'SOON' | 'WHEN_POSSIBLE';
}

export interface IncidentDisplaySummary {
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  briefDescription: string;
  detailedExplanation: string;
  
  // Why this is NOT an approval or dApp exploit
  whyNotApprovalExploit?: string;
  whyNotDAppExploit?: string;
  
  // Attacker infrastructure summary
  attackerInfrastructureSummary?: string;
  
  // Exchange escalation readiness
  exchangeEscalationReady: boolean;
  exchangeEscalationReason?: string;
}

// ============================================
// KNOWN EXCHANGES DATABASE
// ============================================

export interface ExchangeInfo {
  name: string;
  type: 'CEX' | 'DEX' | 'BRIDGE';
  depositAddresses: Record<Chain, string[]>;
  abuseReportUrl?: string;
  abuseReportEmail?: string;
  complianceTeamEmail?: string;
  responseTimeSLA?: string;
}

export const KNOWN_EXCHANGES: ExchangeInfo[] = [
  {
    name: 'Binance',
    type: 'CEX',
    depositAddresses: {
      ethereum: [],
      base: [],
      bnb: [],
      solana: [],
    },
    abuseReportUrl: 'https://www.binance.com/en/support/law-enforcement',
    responseTimeSLA: '24-48 hours',
  },
  {
    name: 'Coinbase',
    type: 'CEX',
    depositAddresses: {
      ethereum: [],
      base: [],
      bnb: [],
      solana: [],
    },
    abuseReportUrl: 'https://help.coinbase.com/en/coinbase/privacy-and-security/other/how-do-i-report-an-unauthorized-transaction',
    responseTimeSLA: '24-72 hours',
  },
  {
    name: 'Kraken',
    type: 'CEX',
    depositAddresses: {
      ethereum: [],
      base: [],
      bnb: [],
      solana: [],
    },
    abuseReportUrl: 'https://support.kraken.com/hc/en-us/requests/new',
    responseTimeSLA: '24-48 hours',
  },
  {
    name: 'OKX',
    type: 'CEX',
    depositAddresses: {
      ethereum: [],
      base: [],
      bnb: [],
      solana: [],
    },
    responseTimeSLA: '24-48 hours',
  },
  {
    name: 'KuCoin',
    type: 'CEX',
    depositAddresses: {
      ethereum: [],
      base: [],
      bnb: [],
      solana: [],
    },
    responseTimeSLA: '48-72 hours',
  },
];

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Generate a unique incident ID.
 */
export function generateIncidentId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `INC-${timestamp}-${random}`.toUpperCase();
}

/**
 * Generate a unique correlation ID.
 */
export function generateCorrelationId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `COR-${timestamp}-${random}`.toUpperCase();
}

/**
 * Generate a unique report ID.
 */
export function generateReportId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `RPT-${timestamp}-${random}`.toUpperCase();
}

/**
 * Determine confidence level from score.
 */
export function getConfidenceLevel(score: number, config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG): ConfidenceLevel {
  if (score >= config.highConfidenceThreshold) return 'HIGH';
  if (score >= config.mediumConfidenceThreshold) return 'MEDIUM';
  if (score >= config.lowConfidenceThreshold) return 'LOW';
  return 'INSUFFICIENT';
}

