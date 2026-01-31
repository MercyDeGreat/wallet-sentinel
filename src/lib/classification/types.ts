// ============================================
// ATTACK CLASSIFICATION ENGINE - TYPE DEFINITIONS
// ============================================
// 
// Securnex Attack Classification System
// This module provides DETERMINISTIC classification of attack types
// AFTER detection has occurred.
//
// CRITICAL: Classification ≠ Detection
// Detection: "Something suspicious happened"
// Classification: "This is specifically ADDRESS_POISONING, not SWEEPER_BOT"
//
// HARD RULES:
// - Never label address poisoning as sweeper bot
// - Never say "wallet compromised" without signer or approval proof
// - Always explain uncertainty
// ============================================

import type { Chain, CompromiseEvidence, TokenApproval } from '@/types';

// ============================================
// ATTACK TYPE ENUM
// ============================================

/**
 * The five mutually exclusive attack types + fallback
 */
export type AttackType =
  | 'SWEEPER_BOT'        // Automated immediate outbound after inbound
  | 'APPROVAL_DRAINER'   // ERC20/721/1155 approve + transferFrom abuse
  | 'SIGNER_COMPROMISE'  // Private key leak, direct signed transfers
  | 'ADDRESS_POISONING'  // Dust transfers from look-alike addresses
  | 'SUSPICIOUS_ACTIVITY'// Signals overlap, can't classify definitively
  | 'NO_COMPROMISE';     // No attack detected

// ============================================
// CLASSIFICATION RESULT
// ============================================

/**
 * The output of the Attack Classification Engine
 */
export interface AttackClassification {
  /** Primary attack type */
  type: AttackType;
  
  /** Confidence score (0-100) */
  confidence: number;
  
  /** Human-readable explanation for the user */
  explanation: string;
  
  /** List of indicators that led to this classification */
  indicators: string[];
  
  /** What was explicitly ruled out (equally important) */
  ruledOut: string[];
  
  /** Technical details for advanced users */
  technicalDetails?: AttackTechnicalDetails;
  
  /** UX-safe display information */
  display: AttackDisplayInfo;
  
  /** Timestamp of classification */
  classifiedAt: string;
  
  /** Chain where the attack occurred */
  chain: Chain;
}

/**
 * Technical details about the attack
 */
export interface AttackTechnicalDetails {
  /** Transaction hashes involved */
  transactionHashes: string[];
  
  /** Addresses involved in the attack */
  involvedAddresses: string[];
  
  /** Token addresses affected */
  affectedTokens: string[];
  
  /** Block range of the attack */
  blockRange?: { start: number; end: number };
  
  /** Time delta between key events (in seconds) */
  timeDelta?: number;
  
  /** Similarity score for address poisoning (0-100) */
  similarityScore?: number;
  
  /** Gas patterns detected */
  gasPatterns?: GasPatternInfo;
}

/**
 * Gas pattern analysis for sweeper detection
 */
export interface GasPatternInfo {
  avgGasPrice: string;
  gasConsistency: number; // How consistent gas usage is (0-100)
  priorityFeePattern: 'FIXED' | 'VARIABLE' | 'UNKNOWN';
  isAutomated: boolean;
}

/**
 * UX-safe display information
 */
export interface AttackDisplayInfo {
  /** Headline emoji */
  emoji: string;
  
  /** Short headline for the alert */
  headline: string;
  
  /** Badge text */
  badgeText: string;
  
  /** Badge color scheme */
  badgeColor: 'red' | 'orange' | 'yellow' | 'blue' | 'green' | 'gray';
  
  /** Severity level */
  severity: 'CRITICAL' | 'WARNING' | 'INFO' | 'SAFE';
  
  /** One-sentence summary */
  summary: string;
  
  /** What happened (bullet points) */
  whatHappened: string[];
  
  /** What did NOT happen (bullet points) - CRITICAL for accurate messaging */
  whatDidNotHappen: string[];
  
  /** Recommended actions (if any) */
  recommendedActions: string[];
  
  /** Confidence display text */
  confidenceText: string;
}

// ============================================
// INPUT DATA STRUCTURES
// ============================================

/**
 * Transaction data for classification
 */
export interface ClassificationTransaction {
  hash: string;
  from: string;
  to: string;
  value: string;
  timestamp: number;
  blockNumber: number;
  methodId?: string;
  gasUsed?: string;
  gasPrice?: string;
  input?: string;
  isInbound: boolean; // Relative to the wallet being analyzed
}

/**
 * Token transfer data for classification
 */
export interface ClassificationTokenTransfer {
  hash: string;
  from: string;
  to: string;
  value: string;
  timestamp: number;
  blockNumber?: number;
  tokenAddress: string;
  tokenSymbol: string;
  tokenType: 'ERC20' | 'ERC721' | 'ERC1155' | 'NATIVE';
  isInbound: boolean; // Relative to the wallet being analyzed
  isDust: boolean;    // Is this a dust transfer?
}

/**
 * Token approval data for classification
 */
export interface ClassificationApproval {
  hash: string;
  token: string;
  tokenSymbol: string;
  spender: string;
  owner: string;
  amount: string;
  isUnlimited: boolean;
  timestamp: number;
  blockNumber: number;
  wasRevoked: boolean;
  revokedTimestamp?: number;
  wasUsed: boolean;           // Was this approval actually used?
  usedByTransferFrom: boolean; // Was it used via transferFrom?
}

/**
 * Complete input for attack classification
 */
export interface AttackClassificationInput {
  /** Wallet address being analyzed */
  walletAddress: string;
  
  /** Chain */
  chain: Chain;
  
  /** All transactions (both inbound and outbound) */
  transactions: ClassificationTransaction[];
  
  /** All token transfers */
  tokenTransfers: ClassificationTokenTransfer[];
  
  /** All token approvals */
  approvals: ClassificationApproval[];
  
  /** Known malicious addresses that the wallet interacted with */
  maliciousAddresses: string[];
  
  /** Previous detection evidence (from existing system) */
  detectionEvidence?: CompromiseEvidence[];
  
  /** Frequently used recipient addresses by this wallet */
  frequentRecipients?: string[];
  
  /** Current timestamp for recency calculations */
  currentTimestamp?: number;
}

// ============================================
// CLASSIFIER CONFIGURATION
// ============================================

/**
 * Configurable thresholds for classification
 */
export interface ClassificationConfig {
  // Address Poisoning
  addressSimilarityThreshold: number;  // Prefix+suffix match (default: 4)
  minDustTransfersForPoisoning: number; // Repeated dusting (default: 2)
  dustValueThreshold: string;           // Max value to be considered dust
  
  // Sweeper Bot
  sweeperTimeDeltaSeconds: number;      // Max time between in/out (default: 60)
  minSweeperPatternCount: number;       // Repeated pattern count (default: 2)
  
  // Approval Drainer
  minApprovalValueForDrainer: string;   // Min approval value to flag
  
  // Signer Compromise
  behaviorDeviationThreshold: number;   // How different from normal (0-100)
  rapidDrainAssetCount: number;         // Assets drained quickly
}

/**
 * Default configuration values
 */
export const DEFAULT_CLASSIFICATION_CONFIG: ClassificationConfig = {
  // Address Poisoning: 4 matching chars (2 prefix + 2 suffix minimum)
  addressSimilarityThreshold: 4,
  minDustTransfersForPoisoning: 2,
  dustValueThreshold: '100000000000000', // 0.0001 ETH in wei
  
  // Sweeper Bot: 60 second window
  sweeperTimeDeltaSeconds: 60,
  minSweeperPatternCount: 2,
  
  // Approval Drainer
  minApprovalValueForDrainer: '1000000000000000000', // 1 token unit
  
  // Signer Compromise
  behaviorDeviationThreshold: 70,
  rapidDrainAssetCount: 3,
};

// ============================================
// INDIVIDUAL CLASSIFIER RESULTS
// ============================================

/**
 * Result from each individual attack classifier
 */
export interface ClassifierResult {
  /** Is this attack type detected? */
  detected: boolean;
  
  /** Confidence (0-100) */
  confidence: number;
  
  /** Positive indicators found */
  positiveIndicators: string[];
  
  /** Indicators explicitly ruled out */
  ruledOutIndicators: string[];
  
  /** Technical evidence */
  evidence: {
    transactionHashes: string[];
    addresses: string[];
    timestamps: number[];
  };
  
  /** Why this classification was made or not made */
  reasoning: string;
}

// ============================================
// CLASSIFICATION PRIORITY ORDER
// ============================================

/**
 * Priority order for classification when multiple attack types are possible.
 * Lower number = higher priority (checked first).
 * 
 * Rationale:
 * 1. SIGNER_COMPROMISE is most severe - if detected, it supersedes others
 * 2. APPROVAL_DRAINER is next - clear approval abuse pattern
 * 3. SWEEPER_BOT - automated behavior pattern
 * 4. ADDRESS_POISONING - social engineering, no actual compromise
 */
export const ATTACK_TYPE_PRIORITY: Record<AttackType, number> = {
  'SIGNER_COMPROMISE': 1,
  'APPROVAL_DRAINER': 2,
  'SWEEPER_BOT': 3,
  'ADDRESS_POISONING': 4,
  'SUSPICIOUS_ACTIVITY': 5,
  'NO_COMPROMISE': 6,
};

// ============================================
// EXPORTS
// ============================================

export type {
  AttackType,
  AttackClassification,
  AttackTechnicalDetails,
  GasPatternInfo,
  AttackDisplayInfo,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationApproval,
  AttackClassificationInput,
  ClassificationConfig,
  ClassifierResult,
};
