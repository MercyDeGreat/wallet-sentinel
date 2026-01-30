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

// ============================================
// SECURITY STATUS LEVELS - REDESIGNED 2026-01
// ============================================
// 
// THREE DISTINCT WALLET STATES:
//
// 1. ACTIVELY_COMPROMISED (CRITICAL - RED)
//    Show ONLY if at least ONE of the following is true:
//    - Funds are being swept automatically within seconds/minutes of receiving
//    - Repeated drain patterns to the same destination in real-time
//    - Fresh approvals + immediate value extraction detected
//    - Private key/signer compromise strongly inferred via behavioral patterns
//    - Live monitoring shows attacker-triggered transactions without user interaction
//    REQUIREMENT: Confidence ≥ 80%
//
// 2. HISTORICALLY_COMPROMISED / PREVIOUS_ATTACK (WARNING - ORANGE)
//    Show if:
//    - Wallet interacted with a known drainer in the past
//    - Previous sweep events occurred but have stopped
//    - No active outflows in recent blocks
//    - No new malicious approvals or contract interactions
//    - No evidence of current attacker access
//    REQUIREMENT: Confidence 50-79%
//
// 3. RISK_EXPOSURE / USER_ERROR (INFO - YELLOW)
//    Show if:
//    - User voluntarily sent assets to a known drainer address
//    - Phishing contract interaction occurred but no approvals remain
//    - No automation or repeat patterns exist
//    - Wallet behavior matches manual user actions
//    REQUIREMENT: Confidence < 50%
//
// CRITICAL RULE: "ACTIVELY COMPROMISED" requires confidence ≥ 80%
// If confidence is borderline, DOWNGRADE severity.

export type SecurityStatus = 
  | 'SAFE'                      // No risk indicators, no historical compromise
  | 'HIGH_ACTIVITY_WALLET'      // High-activity wallet, NOT malicious - just very active (DEX traders, protocols)
  | 'PROTOCOL_INTERACTION'      // Primarily interacts with known safe protocols (DEXes, bridges, etc.)
  
  // ============================================
  // NEW: THREE-STATE CLASSIFICATION SYSTEM
  // ============================================
  | 'ACTIVELY_COMPROMISED'      // CRITICAL (RED): Active attacker control confirmed (confidence ≥ 80%)
  | 'ACTIVE_COMPROMISE_DRAINER' // ** HIGHEST ** Active wallet drainer with ongoing sweep behavior
  | 'HISTORICALLY_COMPROMISED'  // WARNING (ORANGE): Past compromise, no current attacker access (confidence 50-79%)
  | 'RISK_EXPOSURE'             // INFO (YELLOW): User error/exposure, no compromise (confidence < 50%)
  
  // Legacy statuses (mapped to new system internally)
  | 'PREVIOUSLY_COMPROMISED'    // → HISTORICALLY_COMPROMISED (for backward compatibility)
  | 'PREVIOUSLY_COMPROMISED_NO_ACTIVITY' // → HISTORICALLY_COMPROMISED with resolved flag
  | 'POTENTIALLY_COMPROMISED'   // → RISK_EXPOSURE or HISTORICALLY_COMPROMISED based on confidence
  | 'AT_RISK'                   // → RISK_EXPOSURE (no active compromise)
  | 'COMPROMISED'               // Legacy: maps to ACTIVELY_COMPROMISED
  | 'INCOMPLETE_DATA';          // Analysis could not complete (RPC failure, partial history)

// ============================================
// COMPROMISE SUB-STATUS SYSTEM - REDESIGNED 2026-01
// ============================================
// Provides granular distinction between compromise states
// These sub-statuses map to the three-state classification:
//
// ACTIVELY_COMPROMISED states:
//   - ACTIVE_SWEEP_IN_PROGRESS: Funds being swept in real-time
//   - ACTIVE_DRAINER_DETECTED: Active wallet drainer with live behavior
//   - LIVE_ATTACKER_ACCESS: Attacker has active control
//
// HISTORICALLY_COMPROMISED states:
//   - RESOLVED: All threats remediated, ≥30 days clean
//   - NO_ACTIVE_RISK: Past incident, no current threats, monitoring recommended
//   - PREVIOUS_ATTACK: Historical drainer interaction, attack has stopped
//
// RISK_EXPOSURE states:
//   - USER_SENT_TO_DRAINER: User voluntarily sent funds (not drained)
//   - PHISHING_INTERACTION: Phishing interaction but no approvals remain
//   - NONE: No compromise history

export type CompromiseSubStatus = 
  // ACTIVELY_COMPROMISED sub-states (CRITICAL - RED)
  | 'ACTIVE_SWEEP_IN_PROGRESS'  // Funds being swept within seconds/minutes of receiving
  | 'ACTIVE_DRAINER_DETECTED'   // Active wallet drainer behavior (<7 days)
  | 'LIVE_ATTACKER_ACCESS'      // Attacker has demonstrable active control
  | 'ACTIVE_THREAT'             // Currently compromised with active threat vectors
  
  // HISTORICALLY_COMPROMISED sub-states (WARNING - ORANGE)
  | 'RESOLVED'                  // Historical compromise, all remediated (≥30 days)
  | 'NO_ACTIVE_RISK'           // Historical compromise, no active threats, monitor
  | 'PREVIOUS_ATTACK'          // Past attack stopped, no ongoing activity
  
  // RISK_EXPOSURE sub-states (INFO - YELLOW)
  | 'USER_SENT_TO_DRAINER'     // User voluntarily sent to known drainer
  | 'PHISHING_INTERACTION'     // Phishing interaction, no active approvals
  | 'INDIRECT_EXPOSURE'        // Indirect contact with compromised wallet
  
  // No issues
  | 'NONE';                    // No compromise history

// ============================================
// CONFIDENCE-GATED CLASSIFICATION
// ============================================
// The three-state classification requires confidence thresholds:
// - ACTIVELY_COMPROMISED: ≥80% confidence (strong live evidence)
// - HISTORICALLY_COMPROMISED: 50-79% confidence (past indicators)
// - RISK_EXPOSURE: <50% confidence (weak/circumstantial)
//
// If confidence is borderline, ALWAYS downgrade severity.

export interface CompromiseClassification {
  // Final wallet state (one of the three states)
  state: 'ACTIVELY_COMPROMISED' | 'HISTORICALLY_COMPROMISED' | 'RISK_EXPOSURE' | 'SAFE';
  
  // Confidence in this classification (0-100)
  confidence: number;
  
  // Sub-status for granular UI display
  subStatus: CompromiseSubStatus;
  
  // Evidence that supports this classification
  activeIndicators: ActiveCompromiseIndicator[];
  historicalIndicators: HistoricalCompromiseIndicator[];
  
  // User-facing explanation (calm, non-panic language)
  explanation: StatusExplanation;
  
  // Whether this is a first scan (affects messaging)
  isFirstScan: boolean;
  
  // Timestamp of classification
  classifiedAt: string;
}

// Indicators for ACTIVE compromise (requires ≥80% confidence)
export interface ActiveCompromiseIndicator {
  type: 'LIVE_SWEEP' | 'REPEATED_DRAIN' | 'FRESH_APPROVAL_EXTRACTION' | 'KEY_COMPROMISE_BEHAVIOR' | 'ATTACKER_TRIGGERED_TX';
  description: string;
  evidence: {
    txHash?: string;
    timestamp?: string;
    amount?: string;
    destination?: string;
  };
  confidence: number;
  isRealTime: boolean; // Must be TRUE for active classification
}

// Indicators for HISTORICAL compromise (confidence 50-79%)
export interface HistoricalCompromiseIndicator {
  type: 'PAST_DRAINER_INTERACTION' | 'STOPPED_SWEEP' | 'NO_RECENT_OUTFLOWS' | 'REVOKED_APPROVALS' | 'DORMANT_ATTACKER';
  description: string;
  evidence: {
    txHash?: string;
    timestamp?: string;
    daysSinceIncident?: number;
  };
  confidence: number;
  hasEnded: boolean; // Must be TRUE for historical classification
}

// User-facing explanation with calm, explanatory wording
export interface StatusExplanation {
  // Short status label
  label: string;
  
  // One-line summary
  summary: string;
  
  // Detailed explanation (2-3 sentences)
  details: string;
  
  // Why this status was assigned
  reasoning: string;
  
  // Recommended action (if any)
  action?: string;
  
  // Severity indicator for UI styling
  severity: 'CRITICAL' | 'WARNING' | 'INFO' | 'SAFE';
  
  // Icon suggestion
  icon: 'alert-octagon' | 'alert-triangle' | 'info' | 'shield-check';
  
  // Color scheme
  color: 'red' | 'orange' | 'yellow' | 'green' | 'gray';
}

// ============================================
// RECENCY-AWARE THREAT URGENCY LEVELS
// ============================================
// Detection confidence MUST scale with time since last activity.
// Redesigned thresholds for the three-state system:
// - <7 days = potentially ACTIVE (needs live indicators to confirm)
// - 7-30 days = likely HISTORICAL (attack stopped)
// - >30 days = definitely HISTORICAL

export type DrainerActivityRecency = 
  | 'CRITICAL'   // <24h activity - potential IMMEDIATE threat
  | 'HIGH'       // <7d activity - HIGH priority, may be active
  | 'MEDIUM'     // 7-30d activity - likely HISTORICAL
  | 'LOW'        // 30-90d activity - definitely HISTORICAL
  | 'HISTORICAL' // ≥90d since last activity - old incident
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
// STATUS PRIORITY (for sorting/display) - REDESIGNED 2026-01
// ============================================
// Priority levels aligned with THREE-STATE classification:
//
// ACTIVELY_COMPROMISED (100-110): Immediate action required
// HISTORICALLY_COMPROMISED (20-40): Informational, no active threat
// RISK_EXPOSURE (10-15): User error, minimal concern
// SAFE (0-5): No issues
//
// CRITICAL: Historical signals NEVER trigger ACTIVELY_COMPROMISED
// Only live/real-time indicators with ≥80% confidence can do so.

export const SECURITY_STATUS_PRIORITY: Record<SecurityStatus, number> = {
  // ACTIVELY_COMPROMISED tier (100-110) - CRITICAL, requires live evidence
  'ACTIVE_COMPROMISE_DRAINER': 110, // ** HIGHEST ** Live sweeper with real-time activity
  'ACTIVELY_COMPROMISED': 100,      // Confirmed active attacker control
  'COMPROMISED': 100,               // Legacy alias → ACTIVELY_COMPROMISED
  
  // HISTORICALLY_COMPROMISED tier (20-40) - WARNING, past incident only
  'HISTORICALLY_COMPROMISED': 40,   // Past compromise, attack has stopped
  'PREVIOUSLY_COMPROMISED': 35,     // Legacy → HISTORICALLY_COMPROMISED  
  'PREVIOUSLY_COMPROMISED_NO_ACTIVITY': 30, // Historical, verified dormant
  
  // RISK_EXPOSURE tier (10-20) - INFO, user error/exposure
  'RISK_EXPOSURE': 20,              // User error, no compromise
  'AT_RISK': 18,                    // Legacy → RISK_EXPOSURE
  'POTENTIALLY_COMPROMISED': 15,    // Legacy → RISK_EXPOSURE or HISTORICAL
  
  // INFORMATIONAL tier (1-10) - No concern
  'INCOMPLETE_DATA': 10,            // Analysis incomplete
  'HIGH_ACTIVITY_WALLET': 5,        // High activity, NOT malicious
  'PROTOCOL_INTERACTION': 3,        // Protocol interaction only
  
  // SAFE tier (0) - All clear
  'SAFE': 0,                        // No issues detected
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
  
  // ============================================
  // SECURITY TIMELINE (NEW)
  // ============================================
  // Chronological narrative of security events
  // CRITICAL: Past compromise ≠ Active compromise
  
  // Full timeline of security events for this wallet
  timeline?: WalletTimeline;
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

// ============================================
// WALLET STATUS TIMELINE - ATTACK & RECOVERY NARRATIVE
// ============================================
// Chronological timeline that explains:
// - WHAT happened
// - WHEN it happened
// - WHAT changed
// - CURRENT wallet state
//
// CRITICAL: Past compromise ≠ Active compromise
// The timeline must persist even after status becomes SAFE

/**
 * Core timeline event types that track wallet security history
 */
export type TimelineEventType =
  | 'COMPROMISE_ENTRY'      // First interaction with malicious contract/approval
  | 'DRAIN_EVENT'           // Funds transferred to known drainer destination
  | 'APPROVAL_ABUSE'        // Malicious/high-risk approval granted
  | 'APPROVAL_REVOKED'      // User revoked a malicious approval
  | 'THREAT_CEASED'         // No attacker activity for X blocks/hours
  | 'REMEDIATION_ACTION'    // User took protective action
  | 'SAFE_STATE_CONFIRMED'  // Wallet confirmed safe (no active threats)
  | 'MONITORING_STARTED'    // Analysis began
  | 'STATUS_CHANGE'         // Security status changed
  | 'SUSPICIOUS_ACTIVITY'   // Suspicious but not confirmed malicious
  | 'RECOVERY_COMPLETE';    // Full recovery from compromise

/**
 * Severity level at the time of the event
 * Used for color-coding the timeline
 */
export type TimelineEventSeverity = 
  | 'CRITICAL'   // 🟥 Red - Active threat/compromise
  | 'HIGH'       // 🟧 Orange - Threat ceased/historical
  | 'MEDIUM'     // 🟨 Yellow - Recovery action/remediation
  | 'LOW'        // 🟦 Blue - Informational
  | 'SAFE';      // 🟩 Green - Safe state confirmed

/**
 * Technical reference for an event (transaction, contract, address)
 */
export interface TimelineEventReference {
  type: 'transaction' | 'contract' | 'address' | 'approval' | 'block';
  value: string;           // Hash, address, or block number
  label?: string;          // Human-readable label (e.g., "Fake Mint Contract")
  explorerUrl?: string;    // Direct link to block explorer
}

/**
 * A single event in the wallet security timeline
 */
export interface TimelineEvent {
  id: string;                          // Unique event ID
  timestamp: string;                   // ISO timestamp (block time)
  blockNumber?: number;                // Block number if available
  eventType: TimelineEventType;        // Type of event
  severityAtTime: TimelineEventSeverity; // Severity when event occurred
  
  // Human-readable content
  title: string;                       // Short title (e.g., "Wallet Compromised")
  description: string;                 // Human-readable description
  technicalDetails?: string;           // Optional technical explanation
  
  // References
  references: TimelineEventReference[]; // Related tx hashes, contracts, addresses
  
  // Context
  chain: Chain;                        // Which chain this occurred on
  relatedEventIds?: string[];          // IDs of related events (e.g., drain linked to approval)
  
  // UI hints
  isExpandable: boolean;               // Whether event has expandable details
  isPersistent: boolean;               // Should persist in timeline even after resolution
  affectsCurrentStatus: boolean;       // Does this event affect current wallet status?
}

/**
 * The complete wallet timeline with current status derivation
 */
export interface WalletTimeline {
  walletAddress: string;
  chain: Chain;
  
  // All events ordered by timestamp (oldest first)
  events: TimelineEvent[];
  
  // Current status derived from timeline
  currentStatus: {
    status: SecurityStatus;
    derivedFromEventId: string;        // ID of the event that determined current status
    lastUpdated: string;               // When status was last evaluated
    summary: string;                   // Human-readable current state
  };
  
  // Timeline metadata
  metadata: {
    firstEventTimestamp?: string;      // When timeline starts
    lastEventTimestamp: string;        // Most recent event
    totalEvents: number;
    hasActiveThreats: boolean;
    hasHistoricalCompromise: boolean;
    isFullyRecovered: boolean;
  };
  
  // Analysis info
  generatedAt: string;                 // When this timeline was generated
  analysisVersion: string;             // Version of analysis logic
}

/**
 * Timeline generation input - data needed to build timeline
 */
export interface TimelineGenerationInput {
  walletAddress: string;
  chain: Chain;
  
  // Historical data
  transactions: Array<{
    hash: string;
    timestamp: string;
    blockNumber: number;
    from: string;
    to: string;
    value?: string;
    method?: string;
    isMalicious?: boolean;
    maliciousType?: string;
  }>;
  
  // Approvals
  approvals: Array<{
    txHash: string;
    timestamp: string;
    token: string;
    spender: string;
    amount: string;
    isRevoked: boolean;
    revokedAt?: string;
    isMalicious: boolean;
  }>;
  
  // Detected threats
  threats: CompromiseEvidence[];
  
  // Drainer activity
  drainerActivity?: {
    firstDetected?: string;
    lastDetected?: string;
    drainerAddresses: string[];
    sweepEvents: Array<{
      timestamp: string;
      txHash: string;
      amount: string;
      destination: string;
    }>;
  };
  
  // Current analysis result
  currentAnalysis: {
    status: SecurityStatus;
    confidence: number;
    hasActiveThreats: boolean;
  };
}

/**
 * Pre-defined timeline event templates for consistent messaging
 */
export const TIMELINE_EVENT_TEMPLATES: Record<TimelineEventType, {
  titleTemplate: string;
  severityDefault: TimelineEventSeverity;
  isPersistent: boolean;
  affectsStatus: boolean;
}> = {
  COMPROMISE_ENTRY: {
    titleTemplate: 'Wallet Compromised',
    severityDefault: 'CRITICAL',
    isPersistent: true,
    affectsStatus: true,
  },
  DRAIN_EVENT: {
    titleTemplate: 'Funds Drained',
    severityDefault: 'CRITICAL',
    isPersistent: true,
    affectsStatus: true,
  },
  APPROVAL_ABUSE: {
    titleTemplate: 'Malicious Approval Granted',
    severityDefault: 'CRITICAL',
    isPersistent: true,
    affectsStatus: true,
  },
  APPROVAL_REVOKED: {
    titleTemplate: 'Approval Revoked',
    severityDefault: 'MEDIUM',
    isPersistent: true,
    affectsStatus: true,
  },
  THREAT_CEASED: {
    titleTemplate: 'Threat Activity Stopped',
    severityDefault: 'HIGH',
    isPersistent: true,
    affectsStatus: true,
  },
  REMEDIATION_ACTION: {
    titleTemplate: 'Recovery Action Taken',
    severityDefault: 'MEDIUM',
    isPersistent: true,
    affectsStatus: true,
  },
  SAFE_STATE_CONFIRMED: {
    titleTemplate: 'Wallet Safe',
    severityDefault: 'SAFE',
    isPersistent: false,
    affectsStatus: true,
  },
  MONITORING_STARTED: {
    titleTemplate: 'Analysis Started',
    severityDefault: 'LOW',
    isPersistent: false,
    affectsStatus: false,
  },
  STATUS_CHANGE: {
    titleTemplate: 'Status Updated',
    severityDefault: 'LOW',
    isPersistent: true,
    affectsStatus: true,
  },
  SUSPICIOUS_ACTIVITY: {
    titleTemplate: 'Suspicious Activity Detected',
    severityDefault: 'MEDIUM',
    isPersistent: true,
    affectsStatus: false,
  },
  RECOVERY_COMPLETE: {
    titleTemplate: 'Recovery Complete',
    severityDefault: 'SAFE',
    isPersistent: true,
    affectsStatus: true,
  },
};

/**
 * Color mapping for timeline event severities
 */
export const TIMELINE_SEVERITY_COLORS: Record<TimelineEventSeverity, {
  bg: string;
  border: string;
  text: string;
  icon: string;
  emoji: string;
}> = {
  CRITICAL: {
    bg: 'bg-red-500/10',
    border: 'border-red-500',
    text: 'text-red-400',
    icon: 'text-red-500',
    emoji: '🟥',
  },
  HIGH: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500',
    text: 'text-orange-400',
    icon: 'text-orange-500',
    emoji: '🟧',
  },
  MEDIUM: {
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500',
    text: 'text-yellow-400',
    icon: 'text-yellow-500',
    emoji: '🟨',
  },
  LOW: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500',
    text: 'text-blue-400',
    icon: 'text-blue-500',
    emoji: '🟦',
  },
  SAFE: {
    bg: 'bg-green-500/10',
    border: 'border-green-500',
    text: 'text-green-400',
    icon: 'text-green-500',
    emoji: '🟩',
  },
};

