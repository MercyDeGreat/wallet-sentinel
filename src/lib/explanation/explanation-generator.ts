// ============================================
// SECURITY EXPLANATION GENERATOR
// ============================================
//
// Generates probabilistic, evidence-aware explanations
// that explain uncertainty honestly.
//
// CORE UX RULES:
// 1. NEVER claim attacker control unless direct evidence exists
// 2. Separate "suspicious activity" from "confirmed compromise"
// 3. Always explain WHY something was flagged
// 4. Always explain WHAT WAS NOT observed
// 5. Default to calm, non-alarmist language

import {
  SecurityExplanation,
  ExplanationSeverity,
  ExplanationConfidence,
  PositiveSignal,
  NegativeSignal,
  PositiveSignalType,
  NegativeSignalType,
  HEADLINE_TEMPLATES,
  POSITIVE_SIGNAL_DESCRIPTIONS,
  NEGATIVE_SIGNAL_DESCRIPTIONS,
} from './types';

import {
  SecurityStatus,
  Chain,
  CompromiseEvidence,
  CompromiseReasonCode,
  WalletAnalysisResult,
} from '@/types';

// ============================================
// INPUT INTERFACE
// ============================================

export interface ExplanationInput {
  walletAddress: string;
  chain: Chain;
  
  // From analysis
  securityStatus: SecurityStatus;
  riskScore: number;
  confidence: number;
  
  // Evidence
  evidence: CompromiseEvidence[];
  reasonCodes: CompromiseReasonCode[];
  
  // Behavioral flags
  hasSweeperBotBehavior: boolean;
  hasRapidDrainage: boolean;
  hasSignerCompromise: boolean;
  hasAutomatedOutflows: boolean;
  hasActiveMaliciousApprovals: boolean;
  hasFundLoss: boolean;
  hasRepeatDrainPatterns: boolean;
  
  // Historical context
  hasHistoricalCompromise: boolean;
  approvalsRevoked: boolean;
  daysSinceLastIncident?: number;
}

// ============================================
// MAIN GENERATOR FUNCTION
// ============================================

/**
 * Generate a security explanation from analysis results
 * 
 * This function creates probabilistic, evidence-aware messaging
 * that explains uncertainty honestly.
 */
export function generateSecurityExplanation(input: ExplanationInput): SecurityExplanation {
  const now = new Date().toISOString();
  
  // ============================================
  // STEP 1: COLLECT POSITIVE SIGNALS
  // ============================================
  const positiveSignals = collectPositiveSignals(input);
  
  // ============================================
  // STEP 2: COLLECT NEGATIVE SIGNALS
  // ============================================
  const negativeSignals = collectNegativeSignals(input);
  
  // ============================================
  // STEP 3: DETERMINE SEVERITY & CONFIDENCE
  // ============================================
  const { severity, confidence, confidenceScore } = determineSeverityAndConfidence(
    input,
    positiveSignals,
    negativeSignals
  );
  
  // ============================================
  // STEP 4: GENERATE HEADLINE
  // ============================================
  const headline = generateHeadline(severity, confidence, positiveSignals, negativeSignals);
  
  // ============================================
  // STEP 5: GENERATE SUMMARY
  // ============================================
  const summary = generateSummary(severity, confidence, positiveSignals, negativeSignals);
  
  // ============================================
  // STEP 6: GENERATE GUIDANCE
  // ============================================
  const { guidance, recommendedActions } = generateGuidance(severity, input);
  
  return {
    headline,
    summary,
    positiveSignals,
    negativeSignals,
    confidence,
    confidenceScore,
    underlyingStatus: input.securityStatus,
    guidance,
    recommendedActions,
    chain: input.chain,
    generatedAt: now,
    toggleTitle: 'Why Securnex flagged this',
    negativeToggleTitle: 'What Securnex did NOT detect',
  };
}

// ============================================
// POSITIVE SIGNAL COLLECTION
// ============================================

function collectPositiveSignals(input: ExplanationInput): PositiveSignal[] {
  const signals: PositiveSignal[] = [];
  
  // Map evidence to positive signals
  for (const ev of input.evidence) {
    const signal = mapEvidenceToPositiveSignal(ev);
    if (signal) {
      signals.push(signal);
    }
  }
  
  // Map reason codes to positive signals
  for (const code of input.reasonCodes) {
    const signal = mapReasonCodeToPositiveSignal(code, input);
    if (signal && !signals.some(s => s.type === signal.type)) {
      signals.push(signal);
    }
  }
  
  // Add behavioral signals
  if (input.hasSweeperBotBehavior) {
    signals.push({
      type: 'SUSPICIOUS_TOKEN_MOVEMENT',
      description: 'Automated sweeper bot behavior patterns detected',
      confidence: 90,
    });
  }
  
  if (input.hasRapidDrainage) {
    signals.push({
      type: 'SUSPICIOUS_TOKEN_MOVEMENT',
      description: 'Rapid fund drainage patterns observed',
      confidence: 85,
    });
  }
  
  if (input.hasHistoricalCompromise) {
    signals.push({
      type: 'HISTORICAL_INCIDENT',
      description: 'Previous security incident on record for this wallet',
      confidence: 70,
    });
  }
  
  // Sort by confidence (highest first)
  return signals.sort((a, b) => b.confidence - a.confidence);
}

function mapEvidenceToPositiveSignal(evidence: CompromiseEvidence): PositiveSignal | null {
  const codeToType: Partial<Record<CompromiseReasonCode, PositiveSignalType>> = {
    'CONFIRMED_DRAINER_INTERACTION': 'KNOWN_DRAINER_INTERACTION',
    'DRAINER_CLUSTER_INTERACTION': 'HIGH_RISK_CLUSTER',
    'UNLIMITED_APPROVAL_EOA': 'HIGH_RISK_APPROVAL',
    'UNLIMITED_APPROVAL_UNVERIFIED': 'HIGH_RISK_APPROVAL',
    'UNLIMITED_APPROVAL_TO_UNKNOWN': 'HIGH_RISK_APPROVAL',
    'MALICIOUS_APPROVAL': 'HIGH_RISK_APPROVAL',
    'APPROVAL_THEN_DRAIN': 'HIGH_RISK_APPROVAL',
    'ATTACKER_LINKED_ADDRESS': 'FLAGGED_ADDRESS_TRANSFER',
    'UNKNOWN_RECIPIENT_DRAIN': 'FLAGGED_ADDRESS_TRANSFER',
    'MALICIOUS_CONTRACT_INTERACTION': 'KNOWN_DRAINER_INTERACTION',
    'SUSPICIOUS_APPROVAL_PATTERN': 'RAPID_APPROVAL_SEQUENCE',
    'TIMING_ANOMALY': 'SUSPICIOUS_TIMING_PATTERN',
    'SWEEPER_PATTERN': 'SUSPICIOUS_TOKEN_MOVEMENT',
    'SWEEPER_BOT_DETECTED': 'SUSPICIOUS_TOKEN_MOVEMENT',
  };
  
  const type = codeToType[evidence.code];
  if (!type) return null;
  
  return {
    type,
    description: evidence.description || POSITIVE_SIGNAL_DESCRIPTIONS[type],
    confidence: evidence.confidence,
    timestamp: evidence.timestamp,
    reference: evidence.relatedTxHash ? {
      type: 'transaction',
      value: evidence.relatedTxHash,
    } : evidence.relatedAddress ? {
      type: 'address',
      value: evidence.relatedAddress,
    } : undefined,
  };
}

function mapReasonCodeToPositiveSignal(
  code: CompromiseReasonCode, 
  input: ExplanationInput
): PositiveSignal | null {
  const codeToSignal: Partial<Record<CompromiseReasonCode, { type: PositiveSignalType; confidence: number }>> = {
    'CONFIRMED_DRAINER_INTERACTION': { type: 'KNOWN_DRAINER_INTERACTION', confidence: 85 },
    'ASSET_SWEEP_DETECTED': { type: 'SUSPICIOUS_TOKEN_MOVEMENT', confidence: 80 },
    'INDIRECT_DRAINER_EXPOSURE': { type: 'HIGH_RISK_CLUSTER', confidence: 50 },
    'UNEXPLAINED_ASSET_LOSS': { type: 'SUSPICIOUS_TOKEN_MOVEMENT', confidence: 60 },
  };
  
  const mapping = codeToSignal[code];
  if (!mapping) return null;
  
  return {
    type: mapping.type,
    description: POSITIVE_SIGNAL_DESCRIPTIONS[mapping.type],
    confidence: mapping.confidence,
  };
}

// ============================================
// NEGATIVE SIGNAL COLLECTION
// ============================================

function collectNegativeSignals(input: ExplanationInput): NegativeSignal[] {
  const signals: NegativeSignal[] = [];
  
  // These are things we explicitly check for and did NOT find
  // This is crucial for honest, transparent communication
  
  if (!input.hasSweeperBotBehavior) {
    signals.push({
      type: 'NO_SWEEPER_BOT_BEHAVIOR',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['NO_SWEEPER_BOT_BEHAVIOR'],
      importance: 'HIGH',
    });
  }
  
  if (!input.hasRapidDrainage) {
    signals.push({
      type: 'NO_RAPID_DRAINAGE',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['NO_RAPID_DRAINAGE'],
      importance: 'HIGH',
    });
  }
  
  if (!input.hasSignerCompromise) {
    signals.push({
      type: 'NO_SIGNER_COMPROMISE',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['NO_SIGNER_COMPROMISE'],
      importance: 'HIGH',
    });
  }
  
  if (!input.hasAutomatedOutflows) {
    signals.push({
      type: 'NO_AUTOMATED_OUTFLOWS',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['NO_AUTOMATED_OUTFLOWS'],
      importance: 'MEDIUM',
    });
  }
  
  if (!input.hasActiveMaliciousApprovals) {
    signals.push({
      type: 'NO_ACTIVE_MALICIOUS_APPROVALS',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['NO_ACTIVE_MALICIOUS_APPROVALS'],
      importance: 'HIGH',
    });
  }
  
  if (!input.hasFundLoss) {
    signals.push({
      type: 'NO_FUND_LOSS_DETECTED',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['NO_FUND_LOSS_DETECTED'],
      importance: 'HIGH',
    });
  }
  
  if (!input.hasRepeatDrainPatterns) {
    signals.push({
      type: 'NO_REPEAT_DRAIN_PATTERNS',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['NO_REPEAT_DRAIN_PATTERNS'],
      importance: 'MEDIUM',
    });
  }
  
  if (input.approvalsRevoked) {
    signals.push({
      type: 'APPROVALS_REVOKED',
      description: NEGATIVE_SIGNAL_DESCRIPTIONS['APPROVALS_REVOKED'],
      importance: 'HIGH',
    });
  }
  
  // Check for no recent activity
  if (input.daysSinceLastIncident && input.daysSinceLastIncident > 30) {
    signals.push({
      type: 'NO_RECENT_SUSPICIOUS_ACTIVITY',
      description: `No suspicious activity observed in the last ${input.daysSinceLastIncident} days`,
      importance: 'MEDIUM',
    });
  }
  
  // Sort by importance
  const importanceOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  return signals.sort((a, b) => importanceOrder[a.importance] - importanceOrder[b.importance]);
}

// ============================================
// SEVERITY & CONFIDENCE DETERMINATION
// ============================================

function determineSeverityAndConfidence(
  input: ExplanationInput,
  positiveSignals: PositiveSignal[],
  negativeSignals: NegativeSignal[]
): { severity: ExplanationSeverity; confidence: ExplanationConfidence; confidenceScore: number } {
  
  // ============================================
  // CRITICAL: Only if DIRECT COMPROMISE EVIDENCE
  // ============================================
  // Requires: sweeper bot OR signer compromise OR rapid drain patterns
  // AND high confidence
  
  const hasDirectCompromiseEvidence = 
    input.hasSweeperBotBehavior || 
    input.hasSignerCompromise || 
    (input.hasRapidDrainage && input.hasRepeatDrainPatterns);
  
  if (hasDirectCompromiseEvidence && input.confidence >= 80) {
    return {
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      confidenceScore: input.confidence,
    };
  }
  
  // ============================================
  // WARNING: Suspicious but not confirmed
  // ============================================
  // Has positive signals but missing key compromise indicators
  
  const highImportanceNegatives = negativeSignals.filter(s => s.importance === 'HIGH').length;
  const hasManyNegatives = highImportanceNegatives >= 3;
  
  if (positiveSignals.length > 0 && input.confidence >= 40 && input.confidence < 80) {
    // If we have many negative signals, it's suspicious but unconfirmed
    if (hasManyNegatives) {
      return {
        severity: 'WARNING',
        confidence: 'SUSPICIOUS',
        confidenceScore: input.confidence,
      };
    }
    
    // Otherwise it might be more likely
    return {
      severity: 'WARNING',
      confidence: 'LIKELY',
      confidenceScore: input.confidence,
    };
  }
  
  // ============================================
  // CAUTION: Minor concerns
  // ============================================
  
  if (positiveSignals.length > 0 && input.confidence >= 20 && input.confidence < 40) {
    return {
      severity: 'CAUTION',
      confidence: 'UNCERTAIN',
      confidenceScore: input.confidence,
    };
  }
  
  // ============================================
  // INFORMATIONAL: Historical only
  // ============================================
  
  if (input.hasHistoricalCompromise && !hasDirectCompromiseEvidence && hasManyNegatives) {
    return {
      severity: 'INFORMATIONAL',
      confidence: 'UNLIKELY',
      confidenceScore: Math.min(input.confidence, 30),
    };
  }
  
  // ============================================
  // SAFE: No significant concerns
  // ============================================
  
  if (positiveSignals.length === 0 || input.confidence < 20) {
    return {
      severity: 'SAFE',
      confidence: 'UNLIKELY',
      confidenceScore: input.confidence,
    };
  }
  
  // Default to CAUTION for edge cases
  return {
    severity: 'CAUTION',
    confidence: 'UNCERTAIN',
    confidenceScore: input.confidence,
  };
}

// ============================================
// HEADLINE GENERATION
// ============================================

function generateHeadline(
  severity: ExplanationSeverity,
  confidence: ExplanationConfidence,
  positiveSignals: PositiveSignal[],
  negativeSignals: NegativeSignal[]
): SecurityExplanation['headline'] {
  const template = HEADLINE_TEMPLATES[severity];
  
  // For WARNING severity, add the important qualifier
  if (severity === 'WARNING') {
    const hasNoAttackerControl = negativeSignals.some(
      s => s.type === 'NO_SWEEPER_BOT_BEHAVIOR' || 
           s.type === 'NO_SIGNER_COMPROMISE' ||
           s.type === 'NO_KNOWN_ATTACKER_CONTROL'
    );
    
    if (hasNoAttackerControl) {
      return {
        emoji: template.emoji,
        text: `${template.prefix} — but no attacker access confirmed`,
        severity,
      };
    }
  }
  
  // For CRITICAL, be explicit about what was found
  if (severity === 'CRITICAL') {
    return {
      emoji: template.emoji,
      text: `${template.prefix} — immediate action required`,
      severity,
    };
  }
  
  // For CAUTION/INFORMATIONAL, provide context
  if (severity === 'CAUTION' || severity === 'INFORMATIONAL') {
    const topSignal = positiveSignals[0];
    if (topSignal) {
      return {
        emoji: template.emoji,
        text: `${template.prefix} — monitoring recommended`,
        severity,
      };
    }
  }
  
  // Default
  return {
    emoji: template.emoji,
    text: template.prefix,
    severity,
  };
}

// ============================================
// SUMMARY GENERATION
// ============================================

function generateSummary(
  severity: ExplanationSeverity,
  confidence: ExplanationConfidence,
  positiveSignals: PositiveSignal[],
  negativeSignals: NegativeSignal[]
): string {
  switch (severity) {
    case 'CRITICAL':
      return 'Direct evidence of wallet compromise detected. Review the recovery plan immediately.';
    
    case 'WARNING':
      const concernCount = positiveSignals.length;
      const safeIndicators = negativeSignals.filter(s => s.importance === 'HIGH').length;
      
      if (safeIndicators >= 3) {
        return `${concernCount} concerning indicator${concernCount !== 1 ? 's' : ''} detected, but ${safeIndicators} key compromise indicators are absent. Continue monitoring.`;
      }
      return `${concernCount} concerning indicator${concernCount !== 1 ? 's' : ''} detected. Review the details below.`;
    
    case 'CAUTION':
      return 'Minor concerns noted. No immediate action required unless new activity appears.';
    
    case 'INFORMATIONAL':
      return 'Historical activity flagged for awareness. No current threat indicators detected.';
    
    case 'SAFE':
      return 'No security issues detected based on available on-chain data.';
    
    default:
      return 'Review the details below for more information.';
  }
}

// ============================================
// GUIDANCE GENERATION
// ============================================

function generateGuidance(
  severity: ExplanationSeverity,
  input: ExplanationInput
): { guidance: string; recommendedActions?: string[] } {
  const template = HEADLINE_TEMPLATES[severity];
  
  switch (severity) {
    case 'CRITICAL':
      return {
        guidance: template.defaultGuidance,
        recommendedActions: [
          'Stop using this wallet immediately',
          'Transfer remaining assets to a new, secure wallet',
          'Revoke all token approvals',
          'Review the recovery plan',
        ],
      };
    
    case 'WARNING':
      return {
        guidance: 'Continue monitoring. Review flagged interactions and consider revoking suspicious approvals.',
        recommendedActions: [
          'Review flagged transactions and approvals',
          'Consider revoking any suspicious approvals',
          'Monitor for new suspicious activity',
        ],
      };
    
    case 'CAUTION':
      return {
        guidance: template.defaultGuidance,
        recommendedActions: [
          'Review the flagged items for context',
          'No immediate action required',
        ],
      };
    
    case 'INFORMATIONAL':
      return {
        guidance: 'This information is provided for awareness. Past incidents do not necessarily indicate current risk.',
      };
    
    case 'SAFE':
      return {
        guidance: template.defaultGuidance,
      };
    
    default:
      return {
        guidance: template.defaultGuidance,
      };
  }
}

// ============================================
// CONVENIENCE FUNCTION: FROM ANALYSIS RESULT
// ============================================

/**
 * Generate explanation directly from WalletAnalysisResult
 */
export function generateExplanationFromAnalysis(
  result: WalletAnalysisResult,
  additionalContext?: Partial<ExplanationInput>
): SecurityExplanation {
  // Extract behavioral flags from threats
  const threats = result.detectedThreats || [];
  const hasSweeperBotBehavior = threats.some(
    t => t.attackerInfo?.type === 'SWEEPER_BOT' || 
         t.type === 'WALLET_DRAINER'
  );
  const hasRapidDrainage = threats.some(
    t => t.type === 'APPROVAL_HIJACK' && t.ongoingRisk
  );
  
  // Check for active malicious approvals
  const approvals = result.approvals || [];
  const hasActiveMaliciousApprovals = approvals.some(
    a => a.isMalicious && a.riskLevel === 'CRITICAL'
  );
  
  // Build input
  const input: ExplanationInput = {
    walletAddress: result.address,
    chain: result.chain,
    securityStatus: result.securityStatus,
    riskScore: result.riskScore,
    confidence: result.compromiseResolution?.resolution ? 70 : result.riskScore,
    evidence: [], // Would be populated from actual analysis
    reasonCodes: [],
    hasSweeperBotBehavior,
    hasRapidDrainage,
    hasSignerCompromise: false, // Would be detected separately
    hasAutomatedOutflows: hasSweeperBotBehavior,
    hasActiveMaliciousApprovals,
    hasFundLoss: threats.some(t => t.ongoingRisk),
    hasRepeatDrainPatterns: false,
    hasHistoricalCompromise: result.historicalCompromise?.hasHistoricalCompromise || false,
    approvalsRevoked: result.compromiseResolution?.resolution?.allApprovalsRevoked || false,
    daysSinceLastIncident: result.historicalCompromise?.remediationStatus?.daysSinceLastIncident,
    ...additionalContext,
  };
  
  return generateSecurityExplanation(input);
}

export default generateSecurityExplanation;
