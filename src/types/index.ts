// ============================================
// SECURNEX - TYPE DEFINITIONS
// ============================================
// Security analysis types with behavioral risk scoring
// Prevents false positives through directional analysis
//
// CRITICAL FALSE POSITIVE PREVENTION:
// - Contracts are classified BEFORE threat labels are applied
// - Safe contracts (OpenSea, ENS, Pendle, etc.) are NEVER flagged
// - Confidence < 90% = no CRITICAL alerts
// - Normal user behavior is explicitly classified

// Supported blockchain networks
export type Chain = 'ethereum' | 'base' | 'bnb' | 'solana';

// Security status levels
// CRITICAL: Distinguish between HISTORICAL and ACTIVE compromise
// - Historical: Past exploit occurred but all malicious access revoked
// - Active: Ongoing threat with active approvals or drainer access
//
// HARD RULE (2024-01 Security Fix):
// ACTIVE_COMPROMISE_DRAINER MUST override ALL other statuses when ANY
// drainer behavior is detected within the last 90 days. This prevents
// false negatives where active drainers are incorrectly labeled as "Safe"
// or "Previously Compromised (Resolved)".
export type SecurityStatus = 
  | 'SAFE'                      // No risk indicators, no historical compromise
  | 'HIGH_ACTIVITY_WALLET'      // High-activity wallet, NOT malicious - just very active (DEX traders, protocols)
  | 'PROTOCOL_INTERACTION'      // Primarily interacts with known safe protocols (DEXes, bridges, etc.)
  | 'PREVIOUSLY_COMPROMISED'    // Historical exploit, NO active threat, ≥90 days clean
  | 'PREVIOUSLY_COMPROMISED_NO_ACTIVITY' // Historical compromise, ZERO drainer signals for ≥90 days
  | 'POTENTIALLY_COMPROMISED'   // At least one concrete risk signal exists
  | 'AT_RISK'                   // Active risk indicators present
  | 'ACTIVELY_COMPROMISED'      // Confirmed ACTIVE compromise (ongoing threat)
  | 'ACTIVE_COMPROMISE_DRAINER' // ** HARD OVERRIDE ** Active wallet drainer detected - HIGH CERTAINTY ONLY
  | 'COMPROMISED'               // Legacy: maps to ACTIVELY_COMPROMISED
  | 'INCOMPLETE_DATA';          // Analysis could not complete (RPC failure, partial history)

// ============================================
// COMPROMISE SUB-STATUS SYSTEM
// ============================================
// Provides granular distinction between resolved and monitored historical compromise
// These are INFORMATIONAL only - they do NOT increase risk score
//
// SECURITY FIX (2024-01): Added ACTIVE_DRAINER_DETECTED which OVERRIDES all other sub-statuses

export type CompromiseSubStatus = 
  | 'RESOLVED'                  // Historical compromise with all threats remediated (≥90 days)
  | 'NO_ACTIVE_RISK'           // Historical compromise, no active threats, but should be monitored
  | 'ACTIVE_THREAT'            // Currently compromised with active threat vectors
  | 'ACTIVE_DRAINER_DETECTED'  // ** HARD OVERRIDE ** Active drainer behavior detected (<90 days)
  | 'NONE';                    // No compromise history

// ============================================
// RECENCY-AWARE THREAT URGENCY LEVELS
// ============================================
// Detection confidence MUST scale with time since last activity.
// Any activity <90 days = ACTIVE, not historical.

export type DrainerActivityRecency = 
  | 'CRITICAL'   // <24h activity - IMMEDIATE threat
  | 'HIGH'       // <7d activity - HIGH priority threat
  | 'MEDIUM'     // <30d activity - MEDIUM priority, still ACTIVE
  | 'LOW'        // <90d activity - LOW but STILL ACTIVE (not historical)
  | 'HISTORICAL' // ≥90d since last activity - MAY be considered historical
  | 'NONE';      // No drainer activity detected

export interface DrainerActivityRecencyInfo {
  recency: DrainerActivityRecency;
  daysSinceLastActivity: number;
  lastActivityTimestamp?: string;
  lastActivityTxHash?: string;
  isActive: boolean;  // TRUE if <90 days, FALSE if ≥90 days
  confidenceMultiplier: number; // 1.0 for CRITICAL, decreasing to 0.3 for LOW
}

// ============================================
// DRAINER BEHAVIOR SIGNALS
// ============================================
// Any of these signals within 90 days = ACTIVE_COMPROMISE_DRAINER

export type DrainerBehaviorSignal =
  | 'IMMEDIATE_OUTBOUND_TRANSFER'    // Outbound transfer within seconds of inbound
  | 'GAS_FUNDED_EXECUTION'           // Gas-funded third-party transaction execution
  | 'APPROVAL_RAPID_DRAIN'           // Token approval followed by rapid balance drain
  | 'ERC20_SWEEP_PATTERN'            // ERC20 sweep to external address
  | 'ERC721_SWEEP_PATTERN'           // ERC721 (NFT) sweep pattern
  | 'ERC1155_SWEEP_PATTERN'          // ERC1155 sweep pattern
  | 'DRAIN_TO_AGGREGATION_HUB'       // Drain routing to known aggregation/laundering hub
  | 'MULTI_TOKEN_ZEROING'            // Multiple token balances zeroed rapidly
  | 'AUTOMATED_SWEEPER_BEHAVIOR';    // Automated sweeper bot pattern

export interface DrainerBehaviorDetection {
  signal: DrainerBehaviorSignal;
  detectedAt: string;       // ISO timestamp
  txHash: string;           // Transaction hash where detected
  confidence: number;       // 0-100
  details: string;          // Human-readable description
  relatedAddresses: string[]; // Related addresses involved
}

// ============================================
// STATUS PRIORITY (for sorting/display)
// ============================================
// Higher priority = more severe
// Previously compromised (Resolved/No Active Risk) does NOT increase risk score
// These are purely informational badges
//
// CRITICAL: ACTIVE_COMPROMISE_DRAINER has HIGHEST priority (110)
// It MUST override all other statuses when active drainer behavior is detected.
export const SECURITY_STATUS_PRIORITY: Record<SecurityStatus, number> = {
  'ACTIVE_COMPROMISE_DRAINER': 110, // ** HIGHEST ** Confirmed drainer with HIGH CERTAINTY - NEVER downgrade
  'ACTIVELY_COMPROMISED': 100,  // Most severe - immediate action required
  'COMPROMISED': 100,           // Legacy alias
  'AT_RISK': 80,                // Active risk indicators
  'POTENTIALLY_COMPROMISED': 60, // Concrete risk signal exists
  'PREVIOUSLY_COMPROMISED': 20, // Historical only - NO active risk (≥90 days clean)
  'PREVIOUSLY_COMPROMISED_NO_ACTIVITY': 15, // Historical, verified ≥90 days no activity
  'INCOMPLETE_DATA': 10,        // Analysis incomplete
  'HIGH_ACTIVITY_WALLET': 5,    // High activity, NOT malicious - informational only
  'PROTOCOL_INTERACTION': 3,    // Protocol interaction - informational only
  'SAFE': 0,                    // No issues
};

// ============================================
// BACKWARD COMPATIBILITY: LEGACY STATUS MIGRATION
// ============================================
// When re-analyzing a wallet previously marked as "COMPROMISED",
// the system automatically re-evaluates using the new sub-status system:
// - If no active threats → PREVIOUSLY_COMPROMISED (Resolved or No Active Risk)
// - If active threats remain → ACTIVELY_COMPROMISED
// This migration happens automatically on every fresh analysis.

/**
 * Migrate legacy COMPROMISED status to new status system.
 * Used for backward compatibility when displaying old results.
 * 
 * SECURITY FIX (2024-01): If drainerOverride indicates active drainer,
 * ALWAYS return ACTIVE_COMPROMISE_DRAINER regardless of other factors.
 */
export function migrateLegacyStatus(
  status: SecurityStatus,
  hasActiveThreats: boolean,
  drainerOverride?: DrainerOverrideResult
): SecurityStatus {
  // HARD OVERRIDE: Drainer detection supersedes all other logic
  if (drainerOverride?.shouldOverride) {
    return 'ACTIVE_COMPROMISE_DRAINER';
  }
  
  if (status === 'COMPROMISED') {
    return hasActiveThreats ? 'ACTIVELY_COMPROMISED' : 'PREVIOUSLY_COMPROMISED';
  }
  return status;
}

// ============================================
// DRAINER HARD OVERRIDE RESULT
// ============================================
// This is the OUTPUT of the DrainerActivityDetector.
// If `shouldOverride` is TRUE, the classification MUST be ACTIVE_COMPROMISE_DRAINER
// regardless of any other analysis results.
//
// SECURITY RULE: FALSE NEGATIVES ARE WORSE THAN FALSE POSITIVES HERE.

export interface DrainerOverrideResult {
  // If TRUE, status MUST be ACTIVE_COMPROMISE_DRAINER - no exceptions
  // CRITICAL: Only TRUE when ALL strict criteria are met (false positives are damaging)
  shouldOverride: boolean;
  
  // The signals that triggered the override
  detectedSignals: DrainerBehaviorDetection[];
  
  // Recency information
  recency: DrainerActivityRecencyInfo;
  
  // Overall confidence in drainer detection (0-100)
  confidence: number;
  
  // Can this wallet ever be marked SAFE? FALSE if any drainer signal detected <90d
  canEverBeSafe: boolean;
  
  // Can this wallet be marked PREVIOUSLY_COMPROMISED? Only if ≥90d no activity
  canBePreviouslyCompromised: boolean;
  
  // Human-readable explanation of why override was triggered
  overrideReason: string;
  
  // Explicit list of conditions that MUST ALL be true to downgrade
  downgradeBlockers: string[];
  
  // Context classification result (SAFE_PROTOCOL, SELF_OWNED, RELAY, etc.)
  // If classification is NOT 'UNKNOWN', the wallet is NOT a drainer
  contextClassification?: {
    classification: 'SAFE_PROTOCOL' | 'SELF_OWNED' | 'RELAY' | 'DEPLOYER' | 'HIGH_ACTIVITY' | 'UNKNOWN';
    confidence: number;
    reason: string;
    suggestedStatus?: 'SAFE' | 'HIGH_ACTIVITY_WALLET' | null;
  };
}

export interface CompromiseResolutionInfo {
  // Current sub-status
  subStatus: CompromiseSubStatus;
  
  // Data model fields (as per requirements)
  historical_compromise: boolean;
  active_threats: boolean;
  compromise_resolved_at?: string; // ISO timestamp when all threats were resolved
  
  // Resolution details
  resolution: {
    allApprovalsRevoked: boolean;
    noActiveMaliciousContracts: boolean;
    noRecentSweeperActivity: boolean; // No sweeper/drainer in last 30-60 days
    noOngoingAutomatedOutflows: boolean;
    daysSinceLastMaliciousActivity?: number;
    lastMaliciousActivityTimestamp?: string;
  };
  
  // Display information
  displayBadge: CompromiseDisplayBadge;
  
  // Tooltip text for UI
  tooltipText: string;
  
  // User-friendly explanation
  explanation: string;
}

export interface CompromiseDisplayBadge {
  // Badge text
  text: string;
  
  // Badge variant (for styling)
  variant: 'informational' | 'neutral' | 'warning' | 'danger';
  
  // Icon suggestion
  icon: 'shield-check' | 'info' | 'alert-triangle' | 'alert-circle';
  
  // Color scheme (NOT red for resolved/no-active-risk)
  colorScheme: 'gray' | 'blue' | 'yellow' | 'red';
}

// Historical compromise information
export interface HistoricalCompromiseInfo {
  // Was this wallet ever compromised?
  hasHistoricalCompromise: boolean;
  
  // Details of the historical incident(s)
  incidents: HistoricalIncident[];
  
  // Is the threat currently active?
  isCurrentlyActive: boolean;
  
  // Why is it no longer active?
  remediationStatus?: {
    allApprovalsRevoked: boolean;
    noActiveDrainerAccess: boolean;
    noOngoingDrains: boolean;
    lastMaliciousActivity?: string; // ISO timestamp
    daysSinceLastIncident?: number;
  };
}

export interface HistoricalIncident {
  // What happened
  type: 'AIRDROP_DRAIN' | 'APPROVAL_EXPLOIT' | 'PHISHING' | 'SWEEPER_ATTACK' | 'UNKNOWN';
  
  // When it happened
  timestamp: string;
  
  // Transaction hash of the exploit
  txHash: string;
  
  // What was lost
  assetsLost?: {
    token: string;
    symbol: string;
    amount: string;
    valueAtTime?: string;
  }[];
  
  // The malicious contract/address involved
  maliciousAddress: string;
  maliciousContractName?: string;
  
  // Chain where it occurred
  chain: Chain;
  
  // Is the related approval still active?
  approvalStillActive: boolean;
  
  // Human-readable explanation
  explanation: string;
}

// Analysis completeness - tracks whether we have full data to make a determination
export type AnalysisCompleteness = 
  | 'COMPLETE'                  // All data fetched successfully
  | 'PARTIAL_HISTORY'           // Transaction history may be incomplete
  | 'RPC_FAILURE'               // RPC calls failed
  | 'UNSUPPORTED_CHAIN'         // Chain not fully supported
  | 'RATE_LIMITED';             // API rate limits hit

// Analysis completeness info
export interface AnalysisCompletenessInfo {
  status: AnalysisCompleteness;
  dataAvailable: {
    transactions: boolean;
    tokenTransfers: boolean;
    approvals: boolean;
    balance: boolean;
  };
  warnings?: string[];
}

// Reason codes for compromise detection
export type CompromiseReasonCode =
  | 'UNLIMITED_APPROVAL_EOA'           // Unlimited approval to EOA (not contract)
  | 'UNLIMITED_APPROVAL_UNVERIFIED'    // Unlimited approval to unverified contract
  | 'APPROVAL_THEN_DRAIN'              // Approval followed by attacker transfer
  | 'POST_INCIDENT_REVOKE'             // Approval revoked after asset loss
  | 'DRAINER_CLUSTER_INTERACTION'      // Interaction with known drainer cluster
  | 'SHARED_ATTACKER_PATTERN'          // Same attacker targeted multiple victims
  | 'SUDDEN_OUTFLOW_POST_APPROVAL'     // Asset outflow shortly after approval
  | 'INACTIVE_PERIOD_DRAIN'            // Asset movement during user inactivity
  | 'MULTI_ASSET_RAPID_DRAIN'          // Multiple asset types drained quickly
  | 'ATTACKER_LINKED_ADDRESS'          // Transaction with attacker-linked address
  | 'UNEXPLAINED_ASSET_LOSS'           // Assets lost without clear user intent
  | 'INDIRECT_DRAINER_EXPOSURE'        // Indirect contact with confirmed drainer
  | 'SUSPICIOUS_APPROVAL_PATTERN'      // Abnormal approval behavior
  | 'TIMING_ANOMALY'                   // Suspicious timing patterns
  | 'UNKNOWN_RECIPIENT_DRAIN'          // Funds sent to unknown address after approval
  // NEW: Comprehensive Risk Flags
  | 'CONFIRMED_DRAINER_INTERACTION'    // Direct interaction with confirmed drainer (Pink, Angel, Inferno, MS, etc.)
  | 'ASSET_SWEEP_DETECTED'             // ERC20 + NFT drained rapidly within ≤3 blocks
  | 'MALICIOUS_CONTRACT_INTERACTION'   // Interaction with contract that executes unauthorized transfers
  | 'CROSS_CHAIN_COMPROMISE'           // Compromised on another chain (ETH/BNB/Base/Solana)
  // Sub-status detection
  | 'SWEEPER_PATTERN'                  // Automated sweeper bot detected
  | 'SWEEPER_BOT_DETECTED'             // Confirmed sweeper bot attack
  | 'AUTOMATED_OUTFLOW'                // Automated outflows without user initiation
  | 'AIRDROP_DRAIN'                    // Airdrop followed by drain
  | 'AIRDROP_FOLLOWED_BY_DRAIN'        // Airdrop followed by drain (explicit)
  | 'MALICIOUS_APPROVAL'               // Approval to known malicious address
  | 'UNLIMITED_APPROVAL_TO_UNKNOWN'    // Unlimited approval to unknown address
  | 'MULTIPLE_UNLIMITED_APPROVALS';    // Multiple unlimited approvals

// Risk flags that PERMANENTLY prevent SAFE status
export type PermanentRiskFlag =
  | 'CONFIRMED_DRAINER_INTERACTION'
  | 'ASSET_SWEEP_DETECTED'
  | 'MALICIOUS_CONTRACT_INTERACTION'
  | 'HISTORICAL_COMPROMISE';

// Reasoning output for risk classification (for debugging/transparency)
export interface RiskReasoningOutput {
  drainerContractsInteracted: string[];
  sweepTransactions: string[];
  maliciousContracts: string[];
  firstCompromiseBlock?: number;
  firstCompromiseTxHash?: string;
  firstCompromiseTimestamp?: string;
  affectedChains: Chain[];
  permanentFlags: PermanentRiskFlag[];
  whyNotSafe: string[];
}

// Compromise evidence structure
export interface CompromiseEvidence {
  code: CompromiseReasonCode;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  relatedTxHash?: string;
  relatedAddress?: string;
  timestamp?: string;
  confidence: number; // 0-100
  
  // Historical vs Active classification (populated by classifyThreatTiming)
  isHistorical?: boolean;       // True if this is a past incident with no active threat
  isActiveThreat?: boolean;     // True if threat is currently active
  wasRemediated?: boolean;      // True if the issue was fixed (approval revoked, etc.)
  remediationDetails?: string;  // How it was fixed
}

// ============================================
// CHAIN-AWARE SECURITY STATUS
// ============================================
// Ethereum: Deterministic compromise detection (on-chain artifacts)
// Solana: Absence-of-evidence, NOT proof of safety (off-chain attacks)
//
// CRITICAL: Solana wallets should NEVER be labeled as "Fully Safe" or "Clean"
// because Solana compromises (phishing, session hijacks) often leave NO on-chain traces.

export type SolanaSecurityStatus = 
  | 'NO_ONCHAIN_RISK_DETECTED'  // No detectable on-chain risk (NOT "safe")
  | 'AT_RISK'                    // On-chain risk indicators found
  | 'COMPROMISED';               // Strong on-chain evidence of compromise

// ============================================
// SOLANA THREE-STATE SECURITY MODEL
// ============================================
// Three explicit wallet states for Solana:
// - SAFE: No historical or active compromise signals
// - PREVIOUSLY_COMPROMISED: No active drain behavior detected, but past incidents exist
// - ACTIVELY_COMPROMISED: Ongoing automated or hostile fund movement
//
// DESIGN PHILOSOPHY: Prefer false negatives over false positives.
// This tool is for protection, not fear amplification.

export type SolanaWalletSecurityState =
  | 'SAFE'                    // No historical or active compromise signals
  | 'PREVIOUSLY_COMPROMISED'  // Past incidents exist but no active threat
  | 'ACTIVELY_COMPROMISED';   // Ongoing hostile fund movement

export interface SolanaSecurityAnalysis {
  // Primary security state
  state: SolanaWalletSecurityState;
  
  // Confidence in this assessment (0-100)
  confidence: number;
  
  // Whether risk is historical or active
  isHistorical: boolean;
  isActive: boolean;
  
  // Number of independent high-confidence signals
  signalCount: number;
  
  // Explanation string (never alarming unless ACTIVE compromise confirmed)
  explanation: string;
  
  // Risk score (0-100)
  riskScore: number;
  
  // Days since last suspicious activity
  daysSinceLastIncident?: number;
}

// Secondary tags that provide additional context without affecting risk score
export type SecondarySecurityTag = 
  | 'HISTORICAL_OFFCHAIN_COMPROMISE_POSSIBLE'  // For Solana - off-chain attacks may have occurred
  | 'UNKNOWN_CONTRACT_INTERACTIONS'             // Interacted with unverified contracts
  | 'HIGH_VALUE_TARGET'                         // Wallet holds significant value
  | 'INACTIVE_WALLET';                          // Wallet has been inactive for extended period

export interface SecondaryTagInfo {
  tag: SecondarySecurityTag;
  displayText: string;
  shortText: string;
  description: string;
  severity: 'INFO' | 'WARNING' | 'CAUTION';
  affectsRiskScore: false; // NEVER affects risk score
}

// Pre-defined secondary tags
export const SECONDARY_TAGS: Record<SecondarySecurityTag, SecondaryTagInfo> = {
  HISTORICAL_OFFCHAIN_COMPROMISE_POSSIBLE: {
    tag: 'HISTORICAL_OFFCHAIN_COMPROMISE_POSSIBLE',
    displayText: 'Historical Compromise Possible (Off-Chain)',
    shortText: 'Off-Chain Risk',
    description: 'This wallet may have been compromised through off-chain methods (phishing, session hijack) that leave no on-chain trace.',
    severity: 'CAUTION',
    affectsRiskScore: false,
  },
  UNKNOWN_CONTRACT_INTERACTIONS: {
    tag: 'UNKNOWN_CONTRACT_INTERACTIONS',
    displayText: 'Unknown Contract Interactions',
    shortText: 'Unverified Contracts',
    description: 'This wallet has interacted with contracts that could not be verified.',
    severity: 'INFO',
    affectsRiskScore: false,
  },
  HIGH_VALUE_TARGET: {
    tag: 'HIGH_VALUE_TARGET',
    displayText: 'High Value Target',
    shortText: 'High Value',
    description: 'This wallet holds significant assets and may be a target for attackers.',
    severity: 'WARNING',
    affectsRiskScore: false,
  },
  INACTIVE_WALLET: {
    tag: 'INACTIVE_WALLET',
    displayText: 'Inactive Wallet',
    shortText: 'Inactive',
    description: 'This wallet has been inactive for an extended period.',
    severity: 'INFO',
    affectsRiskScore: false,
  },
};

// Display labels for security status (chain-aware)
export interface ChainAwareSecurityLabel {
  status: SecurityStatus | SolanaSecurityStatus;
  displayLabel: string;
  shortLabel: string;
  description: string;
  disclaimer?: string;
  isDefinitiveSafe: boolean;  // FALSE for Solana - absence of evidence ≠ safe
  secondaryTags?: SecondaryTagInfo[];  // Additional context tags (do NOT affect risk score)
}

// Chain-specific analysis metadata
export interface ChainAnalysisMetadata {
  chain: Chain;
  analysisType: 'DETERMINISTIC' | 'HEURISTIC' | 'LIMITED';
  canDetectOffChainCompromise: boolean;
  disclaimer?: string;
  limitations: string[];
}

// Solana-specific disclaimer
export const SOLANA_SECURITY_DISCLAIMER = 
  'Solana compromises are often off-chain (phishing signatures, session hijacks) ' +
  'and may not leave detectable on-chain artifacts. ' +
  'This analysis only covers on-chain indicators.';

// Chain analysis boundaries
export const CHAIN_ANALYSIS_METADATA: Record<Chain, ChainAnalysisMetadata> = {
  ethereum: {
    chain: 'ethereum',
    analysisType: 'DETERMINISTIC',
    canDetectOffChainCompromise: false,
    limitations: [
      'Cannot detect phishing signatures before execution',
      'Cannot detect compromised private keys until used',
    ],
  },
  base: {
    chain: 'base',
    analysisType: 'DETERMINISTIC',
    canDetectOffChainCompromise: false,
    limitations: [
      'Cannot detect phishing signatures before execution',
      'Cannot detect compromised private keys until used',
    ],
  },
  bnb: {
    chain: 'bnb',
    analysisType: 'DETERMINISTIC',
    canDetectOffChainCompromise: false,
    limitations: [
      'Cannot detect phishing signatures before execution',
      'Cannot detect compromised private keys until used',
    ],
  },
  solana: {
    chain: 'solana',
    analysisType: 'LIMITED',
    canDetectOffChainCompromise: false,
    disclaimer: SOLANA_SECURITY_DISCLAIMER,
    limitations: [
      'Cannot detect off-chain phishing signatures',
      'Cannot detect session/cookie hijacks',
      'Cannot detect compromised browser extensions',
      'Many Solana drains leave no on-chain trace',
      'Absence of evidence is NOT proof of safety',
    ],
  },
};

// Attack type classifications
export type AttackType =
  | 'WALLET_DRAINER'
  | 'APPROVAL_HIJACK'
  | 'PRIVATE_KEY_LEAK'
  | 'PHISHING_SIGNATURE'
  | 'MALICIOUS_NFT_AIRDROP'
  | 'COMPROMISED_PROGRAM_AUTHORITY'
  | 'ROGUE_CONTRACT_INTERACTION'
  | 'MEV_SANDWICH_DRAIN'
  | 'UNKNOWN';

// Risk severity levels
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// ============================================
// NEW: USER BEHAVIOR CLASSIFICATION
// ============================================
// Classifies wallet behavior to prevent false positives.
// Normal users and power users should NEVER be flagged as drainers.

export type UserBehaviorType =
  | 'NORMAL_USER'           // Regular user activity
  | 'POWER_USER'            // High-frequency trader / power user
  | 'NEW_WALLET'            // New wallet with limited history
  | 'SWEEPER_BOT_SUSPECT'   // Shows sweeper behavior patterns
  | 'CONFIRMED_SWEEPER'     // Confirmed sweeper bot
  | 'DRAINER_SUSPECT'       // Shows drainer patterns
  | 'CONFIRMED_DRAINER'     // Confirmed drainer
  | 'COMPROMISED_VICTIM'    // Wallet was drained by someone else
  | 'UNKNOWN';

// ============================================
// NEW: CONTRACT CLASSIFICATION
// ============================================
// Contracts must be classified BEFORE applying threat labels.
// Safe contracts can NEVER be flagged as malicious.

export type ContractType =
  | 'MARKETPLACE'           // NFT marketplaces (OpenSea, Blur, etc.)
  | 'NFT_MINT'              // NFT mint contracts
  | 'DEFI_PROTOCOL'         // DeFi protocols (Uniswap, Aave, etc.)
  | 'INFRASTRUCTURE'        // Routers, relayers, bridges, multisigs
  | 'TOKEN_CONTRACT'        // ERC20/721/1155 tokens
  | 'USER_WALLET'           // EOA (Externally Owned Account)
  | 'UNKNOWN_CONTRACT'      // Unverified smart contract
  | 'VERIFIED_SERVICE'      // Other verified high-interaction contracts
  | 'CEX_HOT_WALLET'        // Centralized exchange hot wallet
  | 'BRIDGE'                // Cross-chain bridge
  | 'ENS'                   // Ethereum Name Service
  | 'STAKING';              // Staking protocol

// ============================================
// NEW: CONFIDENCE-BASED ALERT LEVELS
// ============================================
// CRITICAL: If confidence < 90%, do NOT show CRITICAL or DRAINER labels.

export interface ConfidenceMetrics {
  // Overall confidence in the analysis (0-100)
  confidence: number;
  
  // Should we show a critical alert?
  showCriticalAlert: boolean;
  
  // Reasons contributing to confidence
  confidenceFactors: string[];
  
  // Reasons that reduced confidence
  uncertaintyFactors: string[];
}

// ============================================
// WALLET ROLE CLASSIFICATION
// ============================================
// Critical for preventing false positives:
// - A wallet that RECEIVES from compromised wallets is NOT automatically malicious
// - Must analyze BEHAVIOR and DIRECTION of fund flow

export type WalletRole = 
  | 'VICTIM'              // Lost funds to drainer/attacker
  | 'ATTACKER'            // Initiated malicious transactions, received stolen funds
  | 'INFRASTRUCTURE'      // DEX, bridge, router - neutral intermediary
  | 'SERVICE_RECEIVER'    // Receives fees/payments from many sources (NOT malicious)
  | 'INDIRECT_EXPOSURE'   // Had contact with compromised wallet but no malicious behavior
  | 'SELF_MANAGED'        // Auto-forwarding wallet managed by owner (NOT compromised)
  | 'AUTO_FORWARDING'     // Wallet that consistently forwards funds to same address
  | 'POWER_USER'          // High-frequency trader/user with legitimate activity
  | 'UNKNOWN';            // Insufficient data to classify

// ============================================
// WEIGHTED RISK SCORING
// ============================================
// Replaces boolean isDrainer with nuanced scoring
// Indirect exposure should NOT trigger alerts

export interface RiskScoreBreakdown {
  // Base score from detected threats (0-100)
  threatScore: number;
  
  // Behavioral indicators (-20 to +40)
  behaviorScore: number;
  
  // Approval risk score (0-30)
  approvalScore: number;
  
  // Exposure penalty - minimal for indirect contact (0-10)
  exposureScore: number;
  
  // Final weighted score (0-100)
  totalScore: number;
  
  // Factors that contributed to the score
  factors: RiskFactor[];
}

export interface RiskFactor {
  id: string;
  type: RiskFactorType;
  weight: number;  // Positive = increases risk, Negative = decreases risk
  description: string;
  evidence?: string[];
}

export type RiskFactorType =
  | 'DIRECT_MALICIOUS_CALL'      // Wallet called a malicious function (HIGH weight)
  | 'RECEIVED_FROM_DRAINER'      // Received funds from drainer (MEDIUM weight - could be refund)
  | 'SENT_TO_DRAINER'            // Sent funds to drainer (HIGH weight)
  | 'APPROVAL_TO_MALICIOUS'      // Approved malicious spender (CRITICAL weight)
  | 'TRANSFERFROM_INITIATED'     // Used transferFrom to drain (CRITICAL weight)
  | 'INDIRECT_CONTACT'           // Interacted with wallet that was compromised (LOW weight)
  | 'HIGH_VOLUME_RECEIVER'       // Receives from many wallets (NEUTRAL - likely service)
  | 'INFRASTRUCTURE_USAGE'       // Used known DEX/bridge (NEGATIVE - reduces suspicion)
  | 'NORMAL_TRADING_PATTERN'     // Regular buy/sell pattern (NEGATIVE - reduces suspicion)
  | 'TIME_CLUSTERED_DRAIN'       // Multiple assets drained in short window (CRITICAL)
  | 'SWEEPER_PATTERN'            // Funds swept immediately after deposit (CRITICAL);

// ============================================
// TRANSACTION DIRECTION ANALYSIS
// ============================================
// Essential for distinguishing victim from attacker

export interface DirectionalAnalysis {
  // Did this wallet SEND assets to a malicious address?
  sentToMalicious: boolean;
  sentToMaliciousCount: number;
  sentToMaliciousValue: string;
  
  // Did this wallet RECEIVE assets from a malicious address?
  receivedFromMalicious: boolean;
  receivedFromMaliciousCount: number;
  receivedFromMaliciousValue: string;
  
  // Did this wallet CALL malicious contract functions?
  calledMaliciousFunction: boolean;
  maliciousFunctionsCalled: string[];
  
  // Did this wallet APPROVE a malicious spender?
  approvedMaliciousSpender: boolean;
  maliciousApprovals: string[];
  
  // Was this wallet DRAINED via transferFrom by another party?
  drainedViaTransferFrom: boolean;
  drainerAddresses: string[];
  
  // Conclusion
  walletRole: WalletRole;
  roleConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

// Token standards
export type TokenStandard = 'ERC20' | 'ERC721' | 'ERC1155' | 'SPL' | 'NATIVE';

// ============================================
// WALLET ANALYSIS TYPES
// ============================================

export interface WalletAnalysisRequest {
  address: string;
  chain: Chain;
  includeApprovals?: boolean;
  includeTransactions?: boolean;
  includeRiskMonitoring?: boolean;
}

export interface WalletAnalysisResult {
  address: string;
  chain: Chain;
  timestamp: string;
  
  // ============================================
  // CORE SECURITY ASSESSMENT
  // ============================================
  
  // Overall security status (SAFE, AT_RISK, COMPROMISED)
  securityStatus: SecurityStatus;
  
  // Weighted risk score (0-100)
  riskScore: number;
  
  // ============================================
  // CHAIN-AWARE STATUS (NEW)
  // ============================================
  // For Solana: Never show "SAFE" - use "NO_ONCHAIN_RISK_DETECTED" instead
  // This prevents misleading users about off-chain risks
  
  // Chain-aware security label for display
  chainAwareStatus?: ChainAwareSecurityLabel;
  
  // Chain analysis metadata and limitations
  analysisMetadata?: ChainAnalysisMetadata;
  
  // Solana-specific disclaimer (if applicable)
  chainDisclaimer?: string;
  
  // ============================================
  // CLASSIFICATION (Prevents False Positives)
  // ============================================
  // Critical: A wallet is NOT malicious just because it received from compromised wallets
  
  // Wallet's determined role based on BEHAVIORAL analysis
  classification: WalletClassification;
  
  // Risk level for display (separate from classification)
  riskLevel: RiskLevel;
  
  // Human-readable explanation of why this classification was made
  classificationReason: string;
  
  // ============================================
  // DETAILED ANALYSIS
  // ============================================
  summary: string;
  detectedThreats: DetectedThreat[];
  approvals: TokenApproval[];
  suspiciousTransactions: SuspiciousTransaction[];
  recommendations: SecurityRecommendation[];
  recoveryPlan?: RecoveryPlan;
  educationalContent?: EducationalContent;
  
  // Directional analysis breakdown (for transparency)
  directionalAnalysis?: DirectionalAnalysis;
  
  // ============================================
  // COMPROMISE SUB-STATUS (NEW)
  // ============================================
  // Provides granular information about historical vs active compromise
  // This is INFORMATIONAL - does NOT affect risk score
  
  // Sub-status resolution info for previously compromised wallets
  compromiseResolution?: CompromiseResolutionInfo;
  
  // Historical compromise data
  historicalCompromise?: HistoricalCompromiseInfo;
}

// ============================================
// WALLET CLASSIFICATION
// ============================================
// This is the final determination of wallet's role
// CRITICAL: Receiving funds ≠ malicious behavior

export interface WalletClassification {
  // The wallet's role
  role: WalletRole;
  
  // Confidence in this classification
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  
  // Evidence supporting this classification
  evidence: ClassificationEvidence[];
  
  // Was this wallet flagged as malicious? (Distinct from being a victim)
  isMalicious: boolean;
  
  // Is this an infrastructure/service contract?
  isInfrastructure: boolean;
  
  // Is this a service fee receiver?
  isServiceFeeReceiver: boolean;
}

export interface ClassificationEvidence {
  type: 'OUTBOUND_TO_DRAINER' | 'INBOUND_FROM_DRAINER' | 'INITIATED_DRAIN' | 
        'APPROVED_MALICIOUS' | 'INFRASTRUCTURE_USAGE' | 'HIGH_VOLUME_RECEIVER' |
        'NORMAL_ACTIVITY' | 'SWEEPER_PATTERN' | 'UNKNOWN';
  description: string;
  weight: 'HIGH' | 'MEDIUM' | 'LOW';
  addresses?: string[];
  transactions?: string[];
}

// Threat category - distinguishes historical exposure from active risk
export type ThreatCategory = 
  | 'ACTIVE_RISK'           // Current exploit vector exists (affects risk score)
  | 'HISTORICAL_EXPOSURE'   // Past interaction, no current risk (informational only)
  | 'RESOLVED';             // Was a threat, now remediated (e.g., approval revoked)

// Remediation status for threats that can be resolved
export interface ThreatRemediationStatus {
  isRemediated: boolean;
  remediatedAt?: string;           // ISO timestamp of remediation
  remediationTxHash?: string;      // Transaction that resolved the threat
  remediationMethod?: 'APPROVAL_REVOKED' | 'FUNDS_MOVED' | 'CONTRACT_PAUSED' | 'OTHER';
  currentOnChainState?: {
    allowance?: string;            // Current allowance (0 if revoked)
    hasAccess?: boolean;           // Does the attacker still have access?
  };
}

export interface DetectedThreat {
  id: string;
  type: AttackType;
  severity: RiskLevel;
  title: string;
  description: string;
  technicalDetails: string;
  detectedAt: string;
  relatedAddresses: string[];
  relatedTransactions: string[];
  ongoingRisk: boolean;
  recoverableAssets?: AssetInfo[];
  attackerInfo?: {
    address: string;
    type: 'SWEEPER_BOT' | 'DRAINER' | 'PHISHING' | 'UNKNOWN';
    sweepCount?: number;
    avgResponseTime?: number;
    totalStolen?: string;
    confidence?: number;       // Behavioral detection confidence (0-100)
    evidenceCount?: number;    // Number of behavioral indicators detected
    firstSeenAt?: string;      // When first detected
  };
  
  // ============================================
  // NEW: Historical vs Active Threat Classification
  // ============================================
  category?: ThreatCategory;              // Whether this is active or historical
  isHistorical?: boolean;                 // True if this is a past event, not current risk
  remediation?: ThreatRemediationStatus;  // Remediation status if applicable
  
  // For approval-based threats: current on-chain state
  currentAllowance?: string;              // Current allowance (fetched on-chain)
  approvalRevoked?: boolean;              // True if approval was revoked
  
  // Display override for historical threats
  displayLabel?: string;                  // Override label for UI (e.g., "Previously revoked – no active risk")
  excludeFromRiskScore?: boolean;         // True if this should NOT affect risk score
}

export interface TokenApproval {
  id: string;
  token: TokenInfo;
  spender: string;
  spenderLabel?: string;
  amount: string;
  isUnlimited: boolean;
  riskLevel: RiskLevel;
  riskReason?: string;
  grantedAt: string;
  lastUsed?: string;
  isMalicious: boolean;
}

export interface TokenInfo {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  standard: TokenStandard;
  logoUrl?: string;
  verified: boolean;
}

export interface AssetInfo {
  token: TokenInfo;
  balance: string;
  balanceUsd?: number;
  isRecoverable: boolean;
  recoveryMethod?: string;
}

export interface SuspiciousTransaction {
  hash: string;
  timestamp: string;
  type: string;
  from: string;
  to: string;
  value?: string;
  riskLevel: RiskLevel;
  flags: string[];
  description: string;
}

// ============================================
// RECOVERY & CONTAINMENT TYPES
// ============================================

export interface RecoveryPlan {
  urgencyLevel: RiskLevel;
  estimatedTimeMinutes: number;
  steps: RecoveryStep[];
  warnings: string[];
  safeWalletRequired: boolean;
}

export interface RecoveryStep {
  order: number;
  title: string;
  description: string;
  action: RecoveryAction;
  estimatedGasCost?: string;
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  completed?: boolean;
}

export interface RecoveryAction {
  type: 'REVOKE_APPROVAL' | 'TRANSFER_ASSETS' | 'CLOSE_ACCOUNT' | 'DELEGATE_REVOKE' | 'MANUAL';
  contractAddress?: string;
  tokenAddress?: string;
  callData?: string;
  simulationResult?: TransactionSimulation;
}

export interface TransactionSimulation {
  success: boolean;
  gasEstimate: string;
  warnings: string[];
  assetChanges: AssetChange[];
  drainerInterception: boolean;
  safeToExecute: boolean;
}

export interface AssetChange {
  token: string;
  from: string;
  to: string;
  amount: string;
  direction: 'IN' | 'OUT';
}

// ============================================
// SECURITY RECOMMENDATIONS
// ============================================

export interface SecurityRecommendation {
  id: string;
  priority: RiskLevel;
  category: 'IMMEDIATE' | 'SHORT_TERM' | 'LONG_TERM';
  title: string;
  description: string;
  actionable: boolean;
  actionType?: string;
}

export interface EducationalContent {
  attackExplanation: AttackExplanation;
  preventionTips: PreventionTip[];
  securityChecklist: ChecklistItem[];
}

export interface AttackExplanation {
  whatHappened: string;
  howItWorks: string;
  ongoingDamage: string;
  recoverableInfo: string;
}

export interface PreventionTip {
  title: string;
  description: string;
  importance: RiskLevel;
}

export interface ChecklistItem {
  id: string;
  category: string;
  item: string;
  completed: boolean;
  chainSpecific?: Chain[];
}

// ============================================
// MALICIOUS DATABASE TYPES
// ============================================

export interface MaliciousContract {
  address: string;
  chain: Chain;
  type: AttackType;
  name?: string;
  reportedAt: string;
  confirmationLevel: 'CONFIRMED' | 'SUSPECTED' | 'COMMUNITY_REPORTED';
  incidentUrl?: string;
  affectedUsers?: number;
}

export interface DrainerPattern {
  id: string;
  name: string;
  signatures: string[];
  contractBytecodePatterns?: string[];
  behaviorPatterns: BehaviorPattern[];
}

export interface BehaviorPattern {
  type: string;
  description: string;
  threshold?: number;
  timeWindowMinutes?: number;
}

// ============================================
// API RESPONSE TYPES
// ============================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
  timestamp: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: string;
}

// ============================================
// LIVE MONITORING TYPES
// ============================================

export interface MonitoringAlert {
  id: string;
  type: 'ACTIVE_DRAIN' | 'NEW_APPROVAL' | 'SUSPICIOUS_TX' | 'DRAINER_CALLBACK';
  severity: RiskLevel;
  message: string;
  timestamp: string;
  requiresAction: boolean;
  timeToAct?: string;
}

export interface LiveMonitoringSession {
  sessionId: string;
  walletAddress: string;
  chain: Chain;
  startedAt: string;
  alerts: MonitoringAlert[];
  isActive: boolean;
}


