// ============================================
// SOLANA INCIDENT CORRELATION - TYPE DEFINITIONS
// ============================================
// Explicit, rule-based detection types for:
// - Seed/signer compromise
// - Sweeper bots
// - Attacker wallet clustering
// - Near Intents obfuscation
// - Exchange exit detection
//
// Design Philosophy:
// - Measurable thresholds, not heuristics
// - Explicit rules, not probability
// - Forensic-grade precision

// ============================================
// CONFIGURATION CONSTANTS
// ============================================

export const SOLANA_CORRELATION_CONFIG = {
  // Rule Set 1: Multi-Wallet Seed Compromise
  SEED_COMPROMISE: {
    MIN_WALLETS: 2,                        // Minimum distinct wallets
    TIME_WINDOW_STRONG_MINUTES: 30,        // Strong signal threshold
    TIME_WINDOW_MAX_MINUTES: 90,           // Hard threshold
    MIN_BALANCE_DRAIN_PERCENT: 80,         // Minimum % of balance drained
  },
  
  // Rule Set 2: Sweeper Bot Detection
  SWEEPER: {
    TRIGGER_DELAY_MAX_SECONDS: 10,         // Max seconds after receipt
    RENT_BUFFER_SOL: 0.002,                // Min SOL left (rent exempt)
    MIN_RULES_FOR_DETECTION: 2,            // Minimum rules to match
  },
  
  // Rule Set 3: Attacker Clustering
  ATTACKER_CLUSTER: {
    MIN_VICTIM_COUNT: 2,                   // Min victims for aggregation
    AGGREGATION_WINDOW_HOURS: 24,          // Time window for aggregation
    MIN_RULES_FOR_CLASSIFICATION: 2,       // Min rules to classify
  },
  
  // Rule Set 4: Near Intents Obfuscation
  NEAR_INTENTS: {
    POST_DRAIN_WINDOW_MINUTES: 60,         // Max minutes after drain
  },
  
  // Confidence Scoring
  CONFIDENCE: {
    MULTI_WALLET_DRAIN: 30,
    NATIVE_SOL_DRAINED: 20,
    DESTINATION_REUSE: 20,
    AUTOMATED_SWEEPER: 15,
    NEAR_INTENTS_POST_DRAIN: 10,
    EXCHANGE_EXIT: 5,
    HIGH_THRESHOLD: 85,
    MEDIUM_THRESHOLD: 70,
  },
} as const;

// ============================================
// SOLANA WALLET DATA
// ============================================

export interface SolanaIncidentWallet {
  // Identity
  address: string;
  
  // Pre-drain state
  preDrainBalance: {
    solLamports: bigint;
    splTokens: SolanaTokenBalance[];
    totalValueUSD: number;
  };
  
  // Post-drain state
  postDrainBalance: {
    solLamports: bigint;
    splTokens: SolanaTokenBalance[];
    totalValueUSD: number;
  };
  
  // Drain details
  drainTransactions: SolanaDrainTransaction[];
  drainTimestamp: string; // ISO timestamp
  drainSlot: number;
  
  // Transfer destinations
  destinations: string[];
  
  // Program interactions
  programInteractions: SolanaProgramInteraction[];
  
  // Token accounts
  tokenAccounts: string[];
  
  // Authority relationships
  authorities: SolanaAuthority[];
  
  // Computed metrics
  drainPercentage: number;
  wasNativeSOLDrained: boolean;
  wasSimpleTransfer: boolean;
  
  // Fee analysis
  feePayer: string;
}

export interface SolanaTokenBalance {
  mint: string;
  symbol: string;
  amount: string;
  decimals: number;
  valueUSD: number;
}

export interface SolanaDrainTransaction {
  signature: string;
  slot: number;
  blockTime: number;
  timestamp: string;
  
  // Transfer details
  type: 'SOL_TRANSFER' | 'SPL_TRANSFER' | 'PROGRAM_CALL';
  from: string;
  to: string;
  amount: string;
  mint?: string; // For SPL transfers
  
  // Program info
  programId: string;
  programName?: string;
  
  // Fee info
  feePayer: string;
  fee: number;
  
  // Instruction analysis
  instructionCount: number;
  isSimpleTransfer: boolean;
  hasMemo: boolean;
  
  // Timing
  secondsSinceLastInbound?: number;
}

export interface SolanaProgramInteraction {
  programId: string;
  programName?: string;
  signature: string;
  timestamp: string;
  isKnownLegitimate: boolean;
  category?: SolanaProgramCategory;
}

export type SolanaProgramCategory = 
  | 'NFT_MINT'
  | 'DEX_SWAP'
  | 'BRIDGE'
  | 'LENDING'
  | 'STAKING'
  | 'GAMING'
  | 'UNKNOWN';

export interface SolanaAuthority {
  type: 'OWNER' | 'DELEGATE' | 'CLOSE_AUTHORITY' | 'FREEZE_AUTHORITY';
  authority: string;
  tokenAccount?: string;
}

// ============================================
// RULE EVALUATION RESULTS
// ============================================

/**
 * Rule Set 1: Multi-Wallet Seed Compromise Evaluation
 */
export interface SeedCompromiseEvaluation {
  // Individual rule results
  rule1_1_walletCount: RuleResult;
  rule1_2_timeCorrelation: RuleResult;
  rule1_3_drainPattern: RuleResult;
  rule1_4_absenceOfLegitCause: RuleResult;
  rule1_5_destinationCorrelation: RuleResult;
  
  // Overall result
  allRulesPassed: boolean;
  classification: 'SEED_SIGNER_COMPROMISE' | 'INSUFFICIENT_EVIDENCE';
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT';
}

export interface RuleResult {
  ruleName: string;
  passed: boolean;
  score: number;
  evidence: string[];
  metrics?: Record<string, number | string | boolean>;
}

/**
 * Rule Set 2: Sweeper Bot Evaluation
 */
export interface SweeperBotEvaluation {
  rule2_1_automationSignature: RuleResult;
  rule2_2_balanceMaximization: RuleResult;
  rule2_3_noHumanVariability: RuleResult;
  
  rulesMatched: number;
  isSweeperBot: boolean;
}

/**
 * Rule Set 3: Attacker Wallet Clustering
 */
export interface AttackerClusterEvaluation {
  rule3_1_victimAggregation: RuleResult;
  rule3_2_noLegitimateRole: RuleResult;
  rule3_3_launderingBehavior: RuleResult;
  
  rulesMatched: number;
  isAttackerInfrastructure: boolean;
  clusterConfidence: number;
}

/**
 * Rule Set 4: Near Intents Obfuscation
 */
export interface NearIntentsEvaluation {
  rule4_1_sourceContext: RuleResult;
  rule4_2_intentPurpose: RuleResult;
  rule4_3_temporalProximity: RuleResult;
  
  allRulesPassed: boolean;
  isPostDrainObfuscation: boolean;
}

/**
 * Rule Set 5: Exchange Exit Detection
 */
export interface ExchangeExitEvaluation {
  isExchangeExit: boolean;
  exchangeName?: string;
  depositAddress?: string;
  routingPath: string[];
  hasPriorUserInteraction: boolean;
  isEscalationEligible: boolean;
}

// ============================================
// INCIDENT ANALYSIS RESULT
// ============================================

export interface SolanaIncidentAnalysisResult {
  // Incident ID
  incidentId: string;
  analyzedAt: string;
  
  // Attack Classification
  classification: SolanaAttackClassification;
  confidenceScore: number;
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT';
  
  // Affected Wallets
  affectedWallets: SolanaIncidentWallet[];
  
  // Drain Timeline (UTC)
  timeline: SolanaIncidentTimeline;
  
  // Attacker Infrastructure
  attackerWallets: SolanaAttackerWallet[];
  attackerCluster?: AttackerClusterEvaluation;
  
  // Near Intents Usage
  nearIntentsUsage: {
    detected: boolean;
    evaluation?: NearIntentsEvaluation;
    intents: NearIntentTransaction[];
  };
  
  // Exchange Exit
  exchangeExit: {
    detected: boolean;
    evaluation?: ExchangeExitEvaluation;
  };
  
  // Rule Evaluations
  seedCompromiseEval: SeedCompromiseEvaluation;
  sweeperBotEval: SweeperBotEvaluation;
  
  // User Recommendations
  recommendations: SolanaRecommendation[];
  
  // Mandatory User Message
  userMessage: string;
  
  // Machine-readable output
  machineReadable: SolanaMachineReadableOutput;
}

export type SolanaAttackClassification =
  | 'SEED_SIGNER_COMPROMISE_MULTI_WALLET'
  | 'SWEEPER_BOT_ATTACK'
  | 'APPROVAL_BASED_DRAIN'
  | 'SINGLE_WALLET_INCIDENT'
  | 'INSUFFICIENT_EVIDENCE';

export interface SolanaIncidentTimeline {
  firstDrainUTC: string;
  lastDrainUTC: string;
  totalDurationMinutes: number;
  events: SolanaTimelineEvent[];
}

export interface SolanaTimelineEvent {
  timestamp: string;
  slot: number;
  eventType: 'DRAIN' | 'AGGREGATION' | 'NEAR_INTENT' | 'EXCHANGE_DEPOSIT';
  description: string;
  signature: string;
  walletAddress: string;
  significance: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface SolanaAttackerWallet {
  address: string;
  role: 'AGGREGATION' | 'SWEEPER' | 'NEAR_ROUTER' | 'EXCHANGE_DEPOSIT' | 'UNKNOWN';
  victimCount: number;
  totalReceivedSOL: number;
  totalReceivedUSD: number;
  firstSeen: string;
  lastSeen: string;
  confidence: number;
  isLabeledScammer: boolean; // Only true if confidence >= 90
}

export interface NearIntentTransaction {
  intentId: string;
  sourceChain: 'solana';
  targetChain: string;
  sourceWallet: string;
  amount: string;
  timestamp: string;
  minutesAfterDrain: number;
  purpose: 'CROSS_CHAIN_TRANSFER' | 'ASSET_OBFUSCATION' | 'EXCHANGE_ROUTING' | 'USER_BRIDGE';
}

export interface SolanaRecommendation {
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  action: string;
  reason: string;
}

export interface SolanaMachineReadableOutput {
  version: string;
  incidentId: string;
  classification: SolanaAttackClassification;
  confidenceScore: number;
  wallets: Array<{
    address: string;
    drainPercentage: number;
    drainedSOL: string;
    drainedUSD: number;
    drainTimestamp: string;
    signatures: string[];
  }>;
  attackerWallets: Array<{
    address: string;
    role: string;
    victimCount: number;
    confidence: number;
  }>;
  nearIntentsUsed: boolean;
  exchangeExit: boolean;
  ruleResults: {
    seedCompromise: boolean;
    sweeperBot: boolean;
    attackerCluster: boolean;
    nearObfuscation: boolean;
    exchangeEscalation: boolean;
  };
}

// ============================================
// KNOWN SOLANA PROGRAMS (WHITELIST)
// ============================================

export const SOLANA_KNOWN_PROGRAMS = {
  // System
  SYSTEM_PROGRAM: '11111111111111111111111111111111',
  TOKEN_PROGRAM: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  TOKEN_2022: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  ASSOCIATED_TOKEN: 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
  
  // NFT
  METAPLEX: 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',
  CANDY_MACHINE_V2: 'cndy3Z4yapfJBmL3ShUp5exZKqR3z33thTzeNMm2gRZ',
  CANDY_MACHINE_V3: 'CndyV3LdqHUfDLmE5naZjVN8rBZz4tqhdefbAnjHG3JR',
  TENSOR: 'TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN',
  MAGIC_EDEN: 'M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K',
  
  // DEX
  JUPITER: 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',
  RAYDIUM_V4: '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8',
  ORCA: 'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc',
  
  // Bridge
  WORMHOLE: 'worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth',
  ALLBRIDGE: 'ALLEXaUr9fqQv6kRd2Hu7pqLyVb1Xmz2CZNFXkM31jaz',
  
  // Staking
  MARINADE: 'MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD',
  LIDO: 'CrX7kMhLC3cSsXJdT7JDgqrRVWGnUpX3gfEfxxU2NVLi',
} as const;

export const SOLANA_NFT_PROGRAMS = new Set([
  SOLANA_KNOWN_PROGRAMS.METAPLEX,
  SOLANA_KNOWN_PROGRAMS.CANDY_MACHINE_V2,
  SOLANA_KNOWN_PROGRAMS.CANDY_MACHINE_V3,
  SOLANA_KNOWN_PROGRAMS.TENSOR,
  SOLANA_KNOWN_PROGRAMS.MAGIC_EDEN,
]);

export const SOLANA_DEX_PROGRAMS = new Set([
  SOLANA_KNOWN_PROGRAMS.JUPITER,
  SOLANA_KNOWN_PROGRAMS.RAYDIUM_V4,
  SOLANA_KNOWN_PROGRAMS.ORCA,
]);

export const SOLANA_BRIDGE_PROGRAMS = new Set([
  SOLANA_KNOWN_PROGRAMS.WORMHOLE,
  SOLANA_KNOWN_PROGRAMS.ALLBRIDGE,
]);

// ============================================
// KNOWN SOLANA EXCHANGES
// ============================================

export const SOLANA_KNOWN_EXCHANGES: Record<string, string> = {
  // Binance hot wallets (examples - in production, use comprehensive list)
  '5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9': 'Binance',
  'AC5RDfQFmDS1deWZos921JfqscXdByf8BKHs5ACWjtW2': 'Binance',
  
  // Coinbase
  'GJRs4FwHtemZ5ZE9x3FNvJ8TMwitKTh21yxdRPqn7npE': 'Coinbase',
  
  // FTX (legacy)
  '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM': 'FTX',
  
  // Kraken
  'CuieVDEDtLo7FypA9SbLM9saXFdb1dsshEkyErMqkRQq': 'Kraken',
};

// ============================================
// UTILITY FUNCTIONS
// ============================================

export function generateSolanaIncidentId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `SOL-INC-${timestamp}-${random}`.toUpperCase();
}

export function isKnownNFTProgram(programId: string): boolean {
  return SOLANA_NFT_PROGRAMS.has(programId);
}

export function isKnownDEXProgram(programId: string): boolean {
  return SOLANA_DEX_PROGRAMS.has(programId);
}

export function isKnownBridgeProgram(programId: string): boolean {
  return SOLANA_BRIDGE_PROGRAMS.has(programId);
}

export function isKnownExchange(address: string): string | null {
  return SOLANA_KNOWN_EXCHANGES[address] || null;
}

export function lamportsToSOL(lamports: bigint): number {
  return Number(lamports) / 1_000_000_000;
}

export function calculateDrainPercentage(
  preDrain: bigint,
  postDrain: bigint
): number {
  if (preDrain === BigInt(0)) return 0;
  const drained = preDrain - postDrain;
  return Number((drained * BigInt(10000)) / preDrain) / 100;
}

