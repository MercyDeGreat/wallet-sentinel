// ============================================
// SECURITY EXPLANATION LAYER - TYPE DEFINITIONS
// ============================================
// 
// This module provides probabilistic, evidence-aware messaging
// that explains uncertainty honestly instead of binary labels.
//
// CORE PRINCIPLES:
// 1. NEVER claim attacker control unless direct evidence exists
// 2. Separate "suspicious activity" from "confirmed compromise"
// 3. Always explain WHY something was flagged
// 4. Always explain WHAT WAS NOT observed
// 5. Default to calm, non-alarmist language

import { SecurityStatus, RiskLevel, Chain } from '@/types';

// ============================================
// EVIDENCE CLASSIFICATION
// ============================================

/**
 * Types of positive signals (what triggered concern)
 */
export type PositiveSignalType =
  | 'KNOWN_DRAINER_INTERACTION'      // Interaction with known drainer contract
  | 'HIGH_RISK_APPROVAL'             // Unlimited/high-risk approval granted
  | 'FLAGGED_ADDRESS_TRANSFER'       // Transfer to/from flagged address
  | 'SUSPICIOUS_TIMING_PATTERN'      // Unusual timing patterns
  | 'RAPID_APPROVAL_SEQUENCE'        // Multiple approvals in short time
  | 'UNKNOWN_CONTRACT_INTERACTION'   // Interaction with unverified contract
  | 'HIGH_RISK_CLUSTER'              // Address in high-risk cluster
  | 'HISTORICAL_INCIDENT'            // Past security incident on record
  | 'PHISHING_CONTRACT_SIGNATURE'    // Known phishing contract patterns
  | 'SUSPICIOUS_TOKEN_MOVEMENT';     // Unusual token transfer patterns

/**
 * Types of negative signals (what was NOT detected)
 */
export type NegativeSignalType =
  | 'NO_SWEEPER_BOT_BEHAVIOR'        // No automated sweeper patterns
  | 'NO_RAPID_DRAINAGE'              // No repeated rapid fund drainage
  | 'NO_SIGNER_COMPROMISE'           // No private key compromise evidence
  | 'NO_AUTOMATED_OUTFLOWS'          // No automation patterns detected
  | 'NO_ACTIVE_MALICIOUS_APPROVALS'  // No current dangerous approvals
  | 'NO_KNOWN_ATTACKER_CONTROL'      // No evidence of attacker access
  | 'NO_RECENT_SUSPICIOUS_ACTIVITY'  // No recent concerning activity
  | 'NO_FUND_LOSS_DETECTED'          // No actual fund loss observed
  | 'NO_REPEAT_DRAIN_PATTERNS'       // No repeated drain behavior
  | 'APPROVALS_REVOKED';             // Dangerous approvals were revoked

/**
 * A signal that triggered a flag
 */
export interface PositiveSignal {
  type: PositiveSignalType;
  description: string;
  confidence: number;           // 0-100
  timestamp?: string;
  reference?: {
    type: 'transaction' | 'address' | 'contract' | 'approval';
    value: string;
    explorerUrl?: string;
  };
}

/**
 * A signal that was explicitly NOT detected
 */
export interface NegativeSignal {
  type: NegativeSignalType;
  description: string;
  importance: 'HIGH' | 'MEDIUM' | 'LOW';  // How important this absence is
}

// ============================================
// EXPLANATION CONFIDENCE LEVELS
// ============================================

/**
 * Confidence level for the overall explanation
 */
export type ExplanationConfidence =
  | 'CONFIRMED'           // High confidence, direct evidence
  | 'LIKELY'              // Strong indicators but not definitive
  | 'SUSPICIOUS'          // Concerning but inconclusive
  | 'UNCERTAIN'           // Limited evidence, unclear
  | 'UNLIKELY';           // Evidence suggests low risk

/**
 * Explanation severity determines the headline style
 */
export type ExplanationSeverity =
  | 'CRITICAL'            // 🔴 Active compromise confirmed
  | 'WARNING'             // 🟠 Suspicious activity detected
  | 'CAUTION'             // 🟡 Minor concerns noted
  | 'INFORMATIONAL'       // 🔵 For your awareness
  | 'SAFE';               // 🟢 No issues detected

// ============================================
// MAIN EXPLANATION STRUCTURE
// ============================================

/**
 * The complete security explanation for UI rendering
 */
export interface SecurityExplanation {
  // ============================================
  // PRIMARY MESSAGE (User-facing headline)
  // ============================================
  headline: {
    emoji: string;                    // 🔴 🟠 🟡 🔵 🟢
    text: string;                     // Main headline text
    severity: ExplanationSeverity;
  };
  
  // One-sentence reassurance or call to action
  summary: string;
  
  // ============================================
  // EVIDENCE BREAKDOWN
  // ============================================
  
  // What triggered the flag
  positiveSignals: PositiveSignal[];
  
  // What was NOT detected (equally important)
  negativeSignals: NegativeSignal[];
  
  // ============================================
  // CONFIDENCE & CLASSIFICATION
  // ============================================
  
  // Overall confidence in the assessment
  confidence: ExplanationConfidence;
  confidenceScore: number;            // 0-100
  
  // The underlying status (for reference)
  underlyingStatus: SecurityStatus;
  
  // ============================================
  // GUIDANCE
  // ============================================
  
  // Optional guidance for the user
  guidance?: string;
  
  // Recommended actions (if any)
  recommendedActions?: string[];
  
  // ============================================
  // METADATA
  // ============================================
  
  chain: Chain;
  generatedAt: string;
  
  // For toggle section title
  toggleTitle: string;               // "Why Securnex flagged this"
  negativeToggleTitle: string;       // "What Securnex did NOT detect"
}

// ============================================
// HEADLINE TEMPLATES
// ============================================

export const HEADLINE_TEMPLATES: Record<ExplanationSeverity, {
  emoji: string;
  prefix: string;
  defaultGuidance: string;
}> = {
  CRITICAL: {
    emoji: '🔴',
    prefix: 'Active wallet compromise confirmed',
    defaultGuidance: 'Immediate action recommended. Review the recovery plan.',
  },
  WARNING: {
    emoji: '🟠',
    prefix: 'Suspicious activity detected',
    defaultGuidance: 'Continue monitoring. Review flagged interactions.',
  },
  CAUTION: {
    emoji: '🟡',
    prefix: 'Minor concerns noted',
    defaultGuidance: 'No immediate action required. Monitor for changes.',
  },
  INFORMATIONAL: {
    emoji: '🔵',
    prefix: 'For your awareness',
    defaultGuidance: 'No action required at this time.',
  },
  SAFE: {
    emoji: '🟢',
    prefix: 'No security issues detected',
    defaultGuidance: 'Your wallet appears safe based on available data.',
  },
};

// ============================================
// SIGNAL DESCRIPTIONS (Human-readable)
// ============================================

export const POSITIVE_SIGNAL_DESCRIPTIONS: Record<PositiveSignalType, string> = {
  KNOWN_DRAINER_INTERACTION: 'Interaction with a known drainer contract',
  HIGH_RISK_APPROVAL: 'High-risk or unlimited token approval granted',
  FLAGGED_ADDRESS_TRANSFER: 'Transfer to/from a flagged address',
  SUSPICIOUS_TIMING_PATTERN: 'Unusual timing patterns in transactions',
  RAPID_APPROVAL_SEQUENCE: 'Multiple approvals granted in rapid succession',
  UNKNOWN_CONTRACT_INTERACTION: 'Interaction with an unverified contract',
  HIGH_RISK_CLUSTER: 'Address associated with high-risk cluster',
  HISTORICAL_INCIDENT: 'Previous security incident on record',
  PHISHING_CONTRACT_SIGNATURE: 'Contract matches known phishing patterns',
  SUSPICIOUS_TOKEN_MOVEMENT: 'Unusual token transfer patterns detected',
};

export const NEGATIVE_SIGNAL_DESCRIPTIONS: Record<NegativeSignalType, string> = {
  NO_SWEEPER_BOT_BEHAVIOR: 'No automated sweeper bot behavior detected',
  NO_RAPID_DRAINAGE: 'No repeated rapid fund drainage observed',
  NO_SIGNER_COMPROMISE: 'No private key or signer compromise evidence',
  NO_AUTOMATED_OUTFLOWS: 'No automated outflow patterns detected',
  NO_ACTIVE_MALICIOUS_APPROVALS: 'No current dangerous approvals remain',
  NO_KNOWN_ATTACKER_CONTROL: 'No evidence of attacker access to wallet',
  NO_RECENT_SUSPICIOUS_ACTIVITY: 'No recent suspicious activity observed',
  NO_FUND_LOSS_DETECTED: 'No actual fund loss detected',
  NO_REPEAT_DRAIN_PATTERNS: 'No repeated drain patterns observed',
  APPROVALS_REVOKED: 'Previously dangerous approvals have been revoked',
};

// ============================================
// INFERENCE RULES
// ============================================

/**
 * Rules for determining explanation severity based on evidence
 */
export interface InferenceRule {
  id: string;
  name: string;
  conditions: {
    requiredPositiveSignals?: PositiveSignalType[];
    requiredNegativeSignals?: NegativeSignalType[];
    minConfidence?: number;
    maxConfidence?: number;
  };
  result: {
    severity: ExplanationSeverity;
    confidence: ExplanationConfidence;
    headlineModifier?: string;
  };
}

export const INFERENCE_RULES: InferenceRule[] = [
  // CRITICAL: Only if direct compromise evidence
  {
    id: 'confirmed_compromise',
    name: 'Confirmed Active Compromise',
    conditions: {
      minConfidence: 85,
      // Must NOT have these negative signals (i.e., these bad things WERE detected)
    },
    result: {
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      headlineModifier: '— immediate action required',
    },
  },
  
  // WARNING: Suspicious but unconfirmed
  {
    id: 'suspicious_unconfirmed',
    name: 'Suspicious but Unconfirmed',
    conditions: {
      minConfidence: 40,
      maxConfidence: 84,
      requiredNegativeSignals: ['NO_SWEEPER_BOT_BEHAVIOR', 'NO_SIGNER_COMPROMISE'],
    },
    result: {
      severity: 'WARNING',
      confidence: 'SUSPICIOUS',
      headlineModifier: '— but no attacker access confirmed',
    },
  },
  
  // CAUTION: Minor concerns
  {
    id: 'minor_concerns',
    name: 'Minor Concerns',
    conditions: {
      minConfidence: 20,
      maxConfidence: 39,
    },
    result: {
      severity: 'CAUTION',
      confidence: 'UNCERTAIN',
      headlineModifier: '— monitoring recommended',
    },
  },
  
  // SAFE: Low/no risk
  {
    id: 'safe',
    name: 'Safe',
    conditions: {
      maxConfidence: 19,
    },
    result: {
      severity: 'SAFE',
      confidence: 'UNLIKELY',
    },
  },
];
