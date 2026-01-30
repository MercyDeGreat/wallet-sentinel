// ============================================
// SECURNEX VERDICT ENFORCER
// ============================================
// Ensures all detection outputs conform to the 4 allowed verdicts
//
// ALLOWED VERDICTS ONLY:
// 1. ACTIVE_WALLET_DRAINER_DETECTED  - Very rare, requires overwhelming evidence
// 2. PREVIOUSLY_COMPROMISED_RESOLVED - Historical compromise, no active threat
// 3. SUSPICIOUS_PATTERN_LOW_CONFIDENCE - Some signals but not enough
// 4. NO_ACTIVE_THREAT_DETECTED - Default, absence of evidence
//
// RULE: Never collapse uncertainty into "Active Drainer"

import { Chain } from '@/types';

// ============================================
// STRICT VERDICT TYPES
// ============================================

export type SecurnexVerdict =
  | 'ACTIVE_WALLET_DRAINER_DETECTED'    // Very rare - requires overwhelming evidence
  | 'PREVIOUSLY_COMPROMISED_RESOLVED'   // Historical compromise, no active threat
  | 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE' // Some signals but not enough for conviction
  | 'NO_ACTIVE_THREAT_DETECTED';        // Default - absence of evidence

// Map legacy status values to new verdicts
export type LegacySecurityStatus =
  | 'SAFE'
  | 'AT_RISK'
  | 'COMPROMISED'
  | 'HIGH_RISK'
  | 'MEDIUM_RISK'
  | 'LOW_RISK'
  | 'ACTIVELY_COMPROMISED'
  | 'PREVIOUSLY_COMPROMISED'
  | 'UNKNOWN';

// ============================================
// VERDICT REQUIREMENTS
// ============================================

export interface VerdictRequirements {
  verdict: SecurnexVerdict;
  minSignals: number;
  minConfidence: number;
  requiresActiveThreats: boolean;
  requiresRecentActivity: boolean;
  maxDaysSinceLastIncident?: number;
}

export const VERDICT_REQUIREMENTS: Record<SecurnexVerdict, VerdictRequirements> = {
  'ACTIVE_WALLET_DRAINER_DETECTED': {
    verdict: 'ACTIVE_WALLET_DRAINER_DETECTED',
    minSignals: 3,           // MANDATORY: ≥3 independent signals
    minConfidence: 90,       // Very high confidence required
    requiresActiveThreats: true,
    requiresRecentActivity: true,
    maxDaysSinceLastIncident: 90,
  },
  'PREVIOUSLY_COMPROMISED_RESOLVED': {
    verdict: 'PREVIOUSLY_COMPROMISED_RESOLVED',
    minSignals: 1,
    minConfidence: 50,
    requiresActiveThreats: false,
    requiresRecentActivity: false,
    maxDaysSinceLastIncident: undefined, // Any time ago
  },
  'SUSPICIOUS_PATTERN_LOW_CONFIDENCE': {
    verdict: 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE',
    minSignals: 1,
    minConfidence: 30,
    requiresActiveThreats: false,
    requiresRecentActivity: false,
  },
  'NO_ACTIVE_THREAT_DETECTED': {
    verdict: 'NO_ACTIVE_THREAT_DETECTED',
    minSignals: 0,
    minConfidence: 0,
    requiresActiveThreats: false,
    requiresRecentActivity: false,
  },
};

// ============================================
// VERDICT INPUT
// ============================================

export interface VerdictInput {
  // Detection signals
  signalCount: number;
  confidence: number;
  hasActiveThreats: boolean;
  daysSinceLastIncident?: number;
  
  // Historical context
  hadHistoricalCompromise: boolean;
  historicalCompromiseResolved: boolean;
  
  // Exclusion flags
  matchedAllowList: boolean;
  matchedAllowListCount: number;
  isProtectedInfrastructure: boolean;
  
  // Chain context
  chain: Chain;
}

// ============================================
// VERDICT OUTPUT
// ============================================

export interface VerdictOutput {
  verdict: SecurnexVerdict;
  isValid: boolean;
  validationErrors: string[];
  explanation: string;
  recommendation: string;
  displayBadge: string;
  urgency: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
}

// ============================================
// VERDICT DETERMINATION
// ============================================

/**
 * Determine the correct verdict based on detection input.
 * 
 * RULES:
 * 1. If matched allow-list → NO_ACTIVE_THREAT_DETECTED
 * 2. If protected infrastructure → NO_ACTIVE_THREAT_DETECTED
 * 3. If <3 signals → CANNOT be ACTIVE_WALLET_DRAINER_DETECTED
 * 4. If confidence <90 → CANNOT be ACTIVE_WALLET_DRAINER_DETECTED
 * 5. Historical compromise + resolved → PREVIOUSLY_COMPROMISED_RESOLVED
 * 6. Some signals but not enough → SUSPICIOUS_PATTERN_LOW_CONFIDENCE
 * 7. Default → NO_ACTIVE_THREAT_DETECTED
 */
export function determineVerdict(input: VerdictInput): VerdictOutput {
  const validationErrors: string[] = [];
  
  // ============================================
  // RULE 1 & 2: Allow-list and infrastructure protection
  // ============================================
  if (input.matchedAllowList || input.isProtectedInfrastructure) {
    return {
      verdict: 'NO_ACTIVE_THREAT_DETECTED',
      isValid: true,
      validationErrors: [],
      explanation: input.matchedAllowList 
        ? `Activity involves ${input.matchedAllowListCount} allow-listed protocol(s). No threat detected.`
        : 'Protected infrastructure contract. No threat detected.',
      recommendation: 'No action required.',
      displayBadge: 'Verified Safe',
      urgency: 'NONE',
    };
  }
  
  // ============================================
  // RULE 5: Historical compromise + resolved
  // ============================================
  if (input.hadHistoricalCompromise && input.historicalCompromiseResolved && !input.hasActiveThreats) {
    return {
      verdict: 'PREVIOUSLY_COMPROMISED_RESOLVED',
      isValid: true,
      validationErrors: [],
      explanation: `Historical compromise detected but resolved. Last incident: ${input.daysSinceLastIncident ?? 'unknown'} days ago. No active threats.`,
      recommendation: 'Monitor periodically. Consider rotating credentials if not already done.',
      displayBadge: 'Previously Compromised (Resolved)',
      urgency: 'LOW',
    };
  }
  
  // ============================================
  // RULE 3 & 4: Check ACTIVE_WALLET_DRAINER requirements
  // ============================================
  const drainerReqs = VERDICT_REQUIREMENTS['ACTIVE_WALLET_DRAINER_DETECTED'];
  
  const canBeActiveDrainer = 
    input.signalCount >= drainerReqs.minSignals &&
    input.confidence >= drainerReqs.minConfidence &&
    input.hasActiveThreats &&
    (input.daysSinceLastIncident === undefined || 
     input.daysSinceLastIncident <= (drainerReqs.maxDaysSinceLastIncident || 90));
  
  if (input.hasActiveThreats && !canBeActiveDrainer) {
    // Signals present but not enough for conviction
    if (input.signalCount < drainerReqs.minSignals) {
      validationErrors.push(`Insufficient signals: ${input.signalCount} < ${drainerReqs.minSignals} required`);
    }
    if (input.confidence < drainerReqs.minConfidence) {
      validationErrors.push(`Insufficient confidence: ${input.confidence}% < ${drainerReqs.minConfidence}% required`);
    }
    
    return {
      verdict: 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE',
      isValid: true,
      validationErrors,
      explanation: `Suspicious patterns detected but insufficient evidence for drainer classification. ` +
        `${input.signalCount} signal(s), ${input.confidence}% confidence. ` +
        `Required: ≥${drainerReqs.minSignals} signals, ≥${drainerReqs.minConfidence}% confidence.`,
      recommendation: 'Monitor wallet activity. Do not flag as malicious without additional evidence.',
      displayBadge: 'Suspicious - Low Confidence',
      urgency: 'MEDIUM',
    };
  }
  
  if (canBeActiveDrainer) {
    return {
      verdict: 'ACTIVE_WALLET_DRAINER_DETECTED',
      isValid: true,
      validationErrors: [],
      explanation: `CRITICAL: Active wallet drainer detected. ${input.signalCount} independent malicious signals with ${input.confidence}% confidence.`,
      recommendation: 'URGENT: Do NOT send any funds to this address. This is a confirmed drainer.',
      displayBadge: 'Active Drainer Detected',
      urgency: 'CRITICAL',
    };
  }
  
  // ============================================
  // RULE 6: Some signals but not active threat
  // ============================================
  if (input.signalCount > 0 && !input.hasActiveThreats) {
    return {
      verdict: 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE',
      isValid: true,
      validationErrors: [],
      explanation: `${input.signalCount} suspicious pattern(s) detected but no active threat confirmed.`,
      recommendation: 'Review activity history. Monitor for changes.',
      displayBadge: 'Review Recommended',
      urgency: 'LOW',
    };
  }
  
  // ============================================
  // RULE 7: Default - No active threat detected
  // ============================================
  return {
    verdict: 'NO_ACTIVE_THREAT_DETECTED',
    isValid: true,
    validationErrors: [],
    explanation: 'No drainer behavior patterns detected. Wallet appears safe.',
    recommendation: 'No action required.',
    displayBadge: 'No Issues Detected',
    urgency: 'NONE',
  };
}

// ============================================
// LEGACY STATUS CONVERSION
// ============================================

/**
 * Convert legacy security status to new verdict system.
 * 
 * IMPORTANT: This ensures backward compatibility while enforcing
 * the 4-verdict rule.
 */
export function convertLegacyStatus(
  legacyStatus: LegacySecurityStatus,
  context: {
    signalCount?: number;
    confidence?: number;
    hasActiveThreats?: boolean;
    daysSinceLastIncident?: number;
  }
): SecurnexVerdict {
  const signalCount = context.signalCount ?? 0;
  const confidence = context.confidence ?? 0;
  const hasActiveThreats = context.hasActiveThreats ?? false;
  
  switch (legacyStatus) {
    case 'SAFE':
    case 'LOW_RISK':
      return 'NO_ACTIVE_THREAT_DETECTED';
      
    case 'MEDIUM_RISK':
    case 'AT_RISK':
      // Check if we have enough signals for suspicious
      if (signalCount > 0) {
        return 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE';
      }
      return 'NO_ACTIVE_THREAT_DETECTED';
      
    case 'HIGH_RISK':
    case 'ACTIVELY_COMPROMISED':
    case 'COMPROMISED':
      // STRICT: Only ACTIVE_WALLET_DRAINER if criteria met
      if (signalCount >= 3 && confidence >= 90 && hasActiveThreats) {
        return 'ACTIVE_WALLET_DRAINER_DETECTED';
      }
      // Downgrade to suspicious if criteria not met
      if (signalCount > 0) {
        return 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE';
      }
      return 'NO_ACTIVE_THREAT_DETECTED';
      
    case 'PREVIOUSLY_COMPROMISED':
      if (!hasActiveThreats) {
        return 'PREVIOUSLY_COMPROMISED_RESOLVED';
      }
      // If still active, check drainer criteria
      if (signalCount >= 3 && confidence >= 90) {
        return 'ACTIVE_WALLET_DRAINER_DETECTED';
      }
      return 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE';
      
    case 'UNKNOWN':
    default:
      return 'NO_ACTIVE_THREAT_DETECTED';
  }
}

// ============================================
// VERDICT VALIDATION
// ============================================

/**
 * Validate that a verdict assignment is correct.
 * 
 * HARD FAIL CONDITIONS:
 * - ACTIVE_WALLET_DRAINER with <3 signals
 * - ACTIVE_WALLET_DRAINER with <90% confidence
 * - ACTIVE_WALLET_DRAINER without active threats
 * - Any verdict when allow-list match exists
 */
export function validateVerdict(
  verdict: SecurnexVerdict,
  input: VerdictInput
): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Check allow-list override
  if (input.matchedAllowList && verdict !== 'NO_ACTIVE_THREAT_DETECTED') {
    errors.push(`INVALID: Verdict ${verdict} assigned despite allow-list match. Must be NO_ACTIVE_THREAT_DETECTED.`);
  }
  
  // Check infrastructure protection
  if (input.isProtectedInfrastructure && verdict !== 'NO_ACTIVE_THREAT_DETECTED') {
    errors.push(`INVALID: Verdict ${verdict} assigned to protected infrastructure. Must be NO_ACTIVE_THREAT_DETECTED.`);
  }
  
  // Validate ACTIVE_WALLET_DRAINER requirements
  if (verdict === 'ACTIVE_WALLET_DRAINER_DETECTED') {
    const reqs = VERDICT_REQUIREMENTS['ACTIVE_WALLET_DRAINER_DETECTED'];
    
    if (input.signalCount < reqs.minSignals) {
      errors.push(`HARD FAIL: ACTIVE_WALLET_DRAINER with only ${input.signalCount} signals (need ≥${reqs.minSignals})`);
    }
    
    if (input.confidence < reqs.minConfidence) {
      errors.push(`HARD FAIL: ACTIVE_WALLET_DRAINER with only ${input.confidence}% confidence (need ≥${reqs.minConfidence}%)`);
    }
    
    if (!input.hasActiveThreats) {
      errors.push('HARD FAIL: ACTIVE_WALLET_DRAINER without active threats');
    }
    
    if (input.daysSinceLastIncident !== undefined && 
        reqs.maxDaysSinceLastIncident !== undefined &&
        input.daysSinceLastIncident > reqs.maxDaysSinceLastIncident) {
      errors.push(`HARD FAIL: ACTIVE_WALLET_DRAINER but last incident was ${input.daysSinceLastIncident} days ago (max ${reqs.maxDaysSinceLastIncident})`);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

// ============================================
// DISPLAY HELPERS
// ============================================

export function getVerdictColor(verdict: SecurnexVerdict): string {
  switch (verdict) {
    case 'ACTIVE_WALLET_DRAINER_DETECTED':
      return '#dc2626'; // Red
    case 'PREVIOUSLY_COMPROMISED_RESOLVED':
      return '#f59e0b'; // Amber
    case 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE':
      return '#eab308'; // Yellow
    case 'NO_ACTIVE_THREAT_DETECTED':
      return '#22c55e'; // Green
  }
}

export function getVerdictIcon(verdict: SecurnexVerdict): string {
  switch (verdict) {
    case 'ACTIVE_WALLET_DRAINER_DETECTED':
      return '🚨';
    case 'PREVIOUSLY_COMPROMISED_RESOLVED':
      return '⚠️';
    case 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE':
      return '🔍';
    case 'NO_ACTIVE_THREAT_DETECTED':
      return '✅';
  }
}

export function getVerdictDescription(verdict: SecurnexVerdict): string {
  switch (verdict) {
    case 'ACTIVE_WALLET_DRAINER_DETECTED':
      return 'This wallet is actively draining funds. Do NOT send any assets.';
    case 'PREVIOUSLY_COMPROMISED_RESOLVED':
      return 'This wallet had a past security incident but it appears resolved.';
    case 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE':
      return 'Some suspicious patterns detected but not enough evidence to confirm malicious activity.';
    case 'NO_ACTIVE_THREAT_DETECTED':
      return 'No security issues detected. Wallet appears safe for normal use.';
  }
}

// ============================================
// EXPORTS
// ============================================

export const ALLOWED_VERDICTS: SecurnexVerdict[] = [
  'ACTIVE_WALLET_DRAINER_DETECTED',
  'PREVIOUSLY_COMPROMISED_RESOLVED',
  'SUSPICIOUS_PATTERN_LOW_CONFIDENCE',
  'NO_ACTIVE_THREAT_DETECTED',
];

export function isValidVerdict(value: string): value is SecurnexVerdict {
  return ALLOWED_VERDICTS.includes(value as SecurnexVerdict);
}
