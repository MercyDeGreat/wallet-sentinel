// ============================================
// UNCERTAINTY-AWARE MESSAGING SYSTEM
// ============================================
//
// This module provides probabilistic, evidence-aware messaging
// that explains uncertainty HONESTLY instead of binary labels.
//
// CORE PRINCIPLES:
// 1. NEVER claim attacker control unless DIRECT evidence exists
// 2. Separate "suspicious activity" from "confirmed compromise"  
// 3. Always explain WHY something was flagged
// 4. Always explain WHAT WAS NOT observed
// 5. Default to calm, non-alarmist language
//
// TONE REQUIREMENTS:
// • Honest     • Calm        • Transparent
// • Educational • Non-alarmist
//
// AVOID:
// • Absolutes  • Fear language  • Blame  • Overconfidence

import { Chain, SecurityStatus, CompromiseEvidence, CompromiseReasonCode } from '@/types';

// ============================================
// EVIDENCE CLASSIFICATION
// ============================================

/**
 * Positive signals: What triggered concern
 */
export interface TriggerSignal {
  id: string;
  category: TriggerCategory;
  description: string;
  confidence: number; // 0-100
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp?: string;
  reference?: SignalReference;
  isDirectEvidence: boolean; // TRUE = definitive, FALSE = circumstantial
}

export type TriggerCategory =
  | 'DRAINER_INTERACTION'      // Interaction with known drainer
  | 'SWEEPER_BOT_ACTIVITY'     // Automated sweeper patterns
  | 'SIGNER_COMPROMISE'        // Private key compromise evidence
  | 'RAPID_DRAIN_PATTERN'      // Rapid fund drainage
  | 'HIGH_RISK_APPROVAL'       // Dangerous token approvals
  | 'FLAGGED_ADDRESS'          // Transfer to/from flagged address
  | 'SUSPICIOUS_TIMING'        // Unusual timing patterns
  | 'PHISHING_SIGNATURE'       // Known phishing contract
  | 'UNUSUAL_TOKEN_MOVEMENT'   // Suspicious token transfers
  | 'HISTORICAL_INCIDENT';     // Past security incident

/**
 * Negative signals: What was NOT detected (equally important!)
 */
export interface AbsenceSignal {
  id: string;
  category: AbsenceCategory;
  description: string;
  importance: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  reassuranceLevel: number; // 0-100, how reassuring is this absence?
}

export type AbsenceCategory =
  | 'NO_SWEEPER_BOT'           // No automated sweeper patterns
  | 'NO_RAPID_DRAINAGE'        // No repeated rapid fund drain
  | 'NO_SIGNER_COMPROMISE'     // No private key compromise evidence
  | 'NO_AUTOMATED_OUTFLOWS'    // No automation detected
  | 'NO_ACTIVE_APPROVALS'      // No dangerous approvals remain
  | 'NO_ATTACKER_CONTROL'      // No evidence of attacker access
  | 'NO_RECENT_ACTIVITY'       // No recent suspicious activity
  | 'NO_FUND_LOSS'             // No actual fund loss
  | 'NO_REPEAT_PATTERNS'       // No repeated drain patterns
  | 'APPROVALS_REVOKED';       // Dangerous approvals were revoked

export interface SignalReference {
  type: 'transaction' | 'address' | 'contract' | 'approval';
  value: string;
  label?: string;
  explorerUrl?: string;
}

// ============================================
// INFERENCE STATE MACHINE
// ============================================

/**
 * The three possible states for uncertainty-aware messaging:
 * 
 * CONFIRMED_COMPROMISE: Direct evidence of active attacker control
 *   Requires: sweeper bot OR signer compromise OR rapid drain patterns
 *   Confidence: ≥80%
 * 
 * SUSPICIOUS_UNCONFIRMED: Concerning but no direct compromise evidence
 *   Has trigger signals but key absence signals present
 *   Confidence: 40-79%
 * 
 * MONITORING_RECOMMENDED: Minor concerns or informational only
 *   Low confidence or single trigger with many absences
 *   Confidence: <40%
 */
export type InferenceState = 
  | 'CONFIRMED_COMPROMISE'     // 🔴 Direct evidence exists
  | 'SUSPICIOUS_UNCONFIRMED'   // ⚠️ Suspicious but not confirmed
  | 'MONITORING_RECOMMENDED'   // 🟡 Minor concerns, monitor
  | 'INFORMATIONAL_ONLY'       // 🔵 Historical/awareness
  | 'NO_ISSUES_DETECTED';      // 🟢 Clean

export interface InferenceResult {
  state: InferenceState;
  confidence: number;
  reasoning: string;
  
  // The critical question: Can we claim attacker control?
  canClaimAttackerControl: boolean;
  attackerControlEvidence?: string[];
  
  // What are we certain about vs uncertain about?
  certainties: string[];
  uncertainties: string[];
}

// ============================================
// HEADLINE TEMPLATES (User-facing)
// ============================================

export interface HeadlineConfig {
  emoji: string;
  primaryText: string;
  qualifier?: string; // e.g., "— but no attacker access confirmed"
  tone: 'urgent' | 'cautious' | 'calm' | 'informational' | 'reassuring';
}

export const HEADLINE_CONFIGS: Record<InferenceState, HeadlineConfig> = {
  CONFIRMED_COMPROMISE: {
    emoji: '🔴',
    primaryText: 'Active wallet compromise confirmed',
    qualifier: '— immediate action required',
    tone: 'urgent',
  },
  SUSPICIOUS_UNCONFIRMED: {
    emoji: '⚠️',
    primaryText: 'Suspicious activity detected',
    qualifier: '— but no attacker access confirmed',
    tone: 'cautious',
  },
  MONITORING_RECOMMENDED: {
    emoji: '🟡',
    primaryText: 'Minor concerns noted',
    qualifier: '— monitoring recommended',
    tone: 'calm',
  },
  INFORMATIONAL_ONLY: {
    emoji: '🔵',
    primaryText: 'For your awareness',
    qualifier: '— no current risk indicators',
    tone: 'informational',
  },
  NO_ISSUES_DETECTED: {
    emoji: '🟢',
    primaryText: 'No security issues detected',
    tone: 'reassuring',
  },
};

// ============================================
// SUMMARY TEMPLATES (One-sentence reassurance)
// ============================================

export const SUMMARY_TEMPLATES: Record<InferenceState, (triggerCount: number, absenceCount: number) => string> = {
  CONFIRMED_COMPROMISE: () => 
    'Direct evidence of wallet compromise detected. Review the recovery plan immediately.',
  
  SUSPICIOUS_UNCONFIRMED: (triggerCount, absenceCount) => 
    `${triggerCount} concerning indicator${triggerCount !== 1 ? 's' : ''} detected, but ${absenceCount} key compromise indicators are absent. Continue monitoring.`,
  
  MONITORING_RECOMMENDED: () => 
    'Minor concerns noted. No immediate action required unless new activity appears.',
  
  INFORMATIONAL_ONLY: () => 
    'Historical activity flagged for awareness. No current threat indicators detected.',
  
  NO_ISSUES_DETECTED: () => 
    'No security issues detected based on available on-chain data.',
};

// ============================================
// GUIDANCE TEMPLATES
// ============================================

export interface GuidanceConfig {
  mainGuidance: string;
  recommendedActions: string[];
  urgency: 'immediate' | 'soon' | 'when-convenient' | 'optional';
}

export const GUIDANCE_CONFIGS: Record<InferenceState, GuidanceConfig> = {
  CONFIRMED_COMPROMISE: {
    mainGuidance: 'Immediate action recommended. Review the recovery plan.',
    recommendedActions: [
      'Stop using this wallet immediately',
      'Transfer remaining assets to a new, secure wallet',
      'Revoke all token approvals',
      'Review the full recovery plan',
    ],
    urgency: 'immediate',
  },
  SUSPICIOUS_UNCONFIRMED: {
    mainGuidance: 'Continue monitoring. Review flagged interactions and consider revoking suspicious approvals.',
    recommendedActions: [
      'Review flagged transactions and approvals below',
      'Consider revoking any suspicious approvals',
      'Monitor for new suspicious activity',
    ],
    urgency: 'soon',
  },
  MONITORING_RECOMMENDED: {
    mainGuidance: 'No immediate action required. Monitor for changes.',
    recommendedActions: [
      'Review the flagged items for context',
      'Continue normal wallet usage with awareness',
    ],
    urgency: 'when-convenient',
  },
  INFORMATIONAL_ONLY: {
    mainGuidance: 'This information is provided for awareness. Past incidents do not necessarily indicate current risk.',
    recommendedActions: [
      'No action required at this time',
    ],
    urgency: 'optional',
  },
  NO_ISSUES_DETECTED: {
    mainGuidance: 'Your wallet appears safe based on available data.',
    recommendedActions: [],
    urgency: 'optional',
  },
};

// ============================================
// SIGNAL DESCRIPTION LIBRARY
// ============================================

export const TRIGGER_DESCRIPTIONS: Record<TriggerCategory, string> = {
  DRAINER_INTERACTION: 'Interaction with a known drainer contract detected',
  SWEEPER_BOT_ACTIVITY: 'Automated sweeper bot behavior patterns observed',
  SIGNER_COMPROMISE: 'Evidence suggesting private key or signer compromise',
  RAPID_DRAIN_PATTERN: 'Rapid fund drainage patterns detected',
  HIGH_RISK_APPROVAL: 'High-risk or unlimited token approval granted',
  FLAGGED_ADDRESS: 'Transfer to/from a flagged address detected',
  SUSPICIOUS_TIMING: 'Unusual timing patterns in transactions',
  PHISHING_SIGNATURE: 'Contract matches known phishing patterns',
  UNUSUAL_TOKEN_MOVEMENT: 'Unusual token transfer patterns detected',
  HISTORICAL_INCIDENT: 'Previous security incident on record',
};

export const ABSENCE_DESCRIPTIONS: Record<AbsenceCategory, string> = {
  NO_SWEEPER_BOT: 'No automated sweeper bot behavior detected',
  NO_RAPID_DRAINAGE: 'No repeated rapid fund drainage observed',
  NO_SIGNER_COMPROMISE: 'No private key or signer compromise evidence',
  NO_AUTOMATED_OUTFLOWS: 'No automated outflow patterns detected',
  NO_ACTIVE_APPROVALS: 'No current dangerous approvals remain active',
  NO_ATTACKER_CONTROL: 'No evidence of attacker access to wallet',
  NO_RECENT_ACTIVITY: 'No recent suspicious activity observed',
  NO_FUND_LOSS: 'No actual fund loss detected',
  NO_REPEAT_PATTERNS: 'No repeated drain patterns observed',
  APPROVALS_REVOKED: 'Previously dangerous approvals have been revoked',
};

// ============================================
// COMPLETE EXPLANATION OUTPUT
// ============================================

/**
 * The complete UI-ready explanation structure
 */
export interface UncertaintyAwareExplanation {
  // ===== PRIMARY MESSAGE =====
  headline: {
    emoji: string;
    text: string;
    tone: HeadlineConfig['tone'];
  };
  
  // One-sentence reassurance
  summary: string;
  
  // ===== EVIDENCE BREAKDOWN =====
  
  // Toggle section: "Why Securnex flagged this"
  triggerSignals: TriggerSignal[];
  triggerToggleTitle: string;
  
  // Toggle section: "What Securnex did NOT detect"
  absenceSignals: AbsenceSignal[];
  absenceToggleTitle: string;
  
  // ===== INFERENCE RESULT =====
  inference: InferenceResult;
  
  // ===== GUIDANCE =====
  guidance: GuidanceConfig;
  
  // ===== METADATA =====
  chain: Chain;
  underlyingStatus: SecurityStatus;
  generatedAt: string;
}

// ============================================
// INFERENCE RULE ENGINE
// ============================================

/**
 * Determines the inference state based on evidence
 * 
 * CRITICAL RULES:
 * - ONLY claim "CONFIRMED_COMPROMISE" if direct evidence exists
 * - Presence of absence signals ALWAYS reduces severity
 * - Single trigger + many absences = MONITORING_RECOMMENDED
 * - Historical triggers without active indicators = INFORMATIONAL_ONLY
 */
export function inferState(
  triggers: TriggerSignal[],
  absences: AbsenceSignal[],
  inputConfidence: number
): InferenceResult {
  
  // Count signals by type
  const directEvidenceCount = triggers.filter(t => t.isDirectEvidence).length;
  const criticalAbsences = absences.filter(a => a.importance === 'CRITICAL');
  const highAbsences = absences.filter(a => a.importance === 'HIGH');
  
  // ===== RULE 1: CONFIRMED_COMPROMISE =====
  // Requires: (sweeper bot OR signer compromise OR rapid drain patterns) AND confidence ≥ 80%
  const hasSweeperBot = triggers.some(t => t.category === 'SWEEPER_BOT_ACTIVITY' && t.isDirectEvidence);
  const hasSignerCompromise = triggers.some(t => t.category === 'SIGNER_COMPROMISE' && t.isDirectEvidence);
  const hasRapidDrain = triggers.some(t => t.category === 'RAPID_DRAIN_PATTERN' && t.isDirectEvidence);
  
  const hasDirectCompromiseEvidence = hasSweeperBot || hasSignerCompromise || hasRapidDrain;
  
  if (hasDirectCompromiseEvidence && inputConfidence >= 80) {
    return {
      state: 'CONFIRMED_COMPROMISE',
      confidence: inputConfidence,
      reasoning: 'Direct evidence of active wallet compromise detected with high confidence.',
      canClaimAttackerControl: true,
      attackerControlEvidence: [
        hasSweeperBot ? 'Automated sweeper bot behavior detected' : null,
        hasSignerCompromise ? 'Signer compromise evidence found' : null,
        hasRapidDrain ? 'Rapid drain patterns observed' : null,
      ].filter(Boolean) as string[],
      certainties: ['Active attacker control is confirmed', 'Funds are at immediate risk'],
      uncertainties: ['Full extent of compromise may not be known'],
    };
  }
  
  // ===== RULE 2: SUSPICIOUS_UNCONFIRMED =====
  // Has triggers but key absence signals present (no sweeper, no signer compromise)
  const hasNoSweeperAbsence = absences.some(a => a.category === 'NO_SWEEPER_BOT');
  const hasNoSignerAbsence = absences.some(a => a.category === 'NO_SIGNER_COMPROMISE');
  const hasNoAttackerAbsence = absences.some(a => a.category === 'NO_ATTACKER_CONTROL');
  
  const hasKeyAbsences = hasNoSweeperAbsence || hasNoSignerAbsence || hasNoAttackerAbsence;
  
  if (triggers.length > 0 && inputConfidence >= 40 && inputConfidence < 80 && hasKeyAbsences) {
    return {
      state: 'SUSPICIOUS_UNCONFIRMED',
      confidence: inputConfidence,
      reasoning: 'Suspicious activity detected, but key compromise indicators are absent.',
      canClaimAttackerControl: false,
      certainties: triggers.map(t => t.description),
      uncertainties: [
        'Whether an attacker has access to this wallet',
        'Whether the suspicious activity was user-initiated',
        'Whether there is an active threat',
      ],
    };
  }
  
  // ===== RULE 3: MONITORING_RECOMMENDED =====
  // Single trigger with many absences, or low confidence
  if (triggers.length > 0 && (inputConfidence < 40 || (triggers.length === 1 && criticalAbsences.length >= 2))) {
    return {
      state: 'MONITORING_RECOMMENDED',
      confidence: inputConfidence,
      reasoning: 'Minor concerns noted, but insufficient evidence for elevated alert.',
      canClaimAttackerControl: false,
      certainties: ['Some unusual activity was observed'],
      uncertainties: [
        'The significance of the detected activity',
        'Whether this represents a real threat',
      ],
    };
  }
  
  // ===== RULE 4: INFORMATIONAL_ONLY =====
  // Historical triggers only, no active indicators
  const hasOnlyHistorical = triggers.every(t => t.category === 'HISTORICAL_INCIDENT');
  
  if (hasOnlyHistorical && criticalAbsences.length >= 2) {
    return {
      state: 'INFORMATIONAL_ONLY',
      confidence: Math.min(inputConfidence, 30),
      reasoning: 'Historical activity flagged for awareness. No current threat indicators.',
      canClaimAttackerControl: false,
      certainties: ['Past security incidents were detected'],
      uncertainties: ['Current relevance of historical incidents'],
    };
  }
  
  // ===== RULE 5: NO_ISSUES_DETECTED =====
  if (triggers.length === 0 || inputConfidence < 20) {
    return {
      state: 'NO_ISSUES_DETECTED',
      confidence: inputConfidence,
      reasoning: 'No significant security concerns detected.',
      canClaimAttackerControl: false,
      certainties: ['No known threat indicators found'],
      uncertainties: ['Analysis is based on available on-chain data only'],
    };
  }
  
  // ===== DEFAULT: MONITORING_RECOMMENDED =====
  return {
    state: 'MONITORING_RECOMMENDED',
    confidence: inputConfidence,
    reasoning: 'Insufficient evidence to determine threat level. Monitoring recommended.',
    canClaimAttackerControl: false,
    certainties: [],
    uncertainties: ['The nature and severity of detected signals'],
  };
}

// ============================================
// MAIN GENERATOR FUNCTION
// ============================================

export interface GeneratorInput {
  walletAddress: string;
  chain: Chain;
  securityStatus: SecurityStatus;
  confidence: number;
  
  // Detection results
  evidence: CompromiseEvidence[];
  reasonCodes: CompromiseReasonCode[];
  
  // Behavioral flags (from analysis)
  hasSweeperBotBehavior: boolean;
  hasRapidDrainage: boolean;
  hasSignerCompromise: boolean;
  hasAutomatedOutflows: boolean;
  hasActiveMaliciousApprovals: boolean;
  hasFundLoss: boolean;
  hasRepeatDrainPatterns: boolean;
  hasHistoricalCompromise: boolean;
  approvalsRevoked: boolean;
  daysSinceLastIncident?: number;
}

/**
 * Generates uncertainty-aware explanation from analysis results
 */
export function generateUncertaintyAwareExplanation(
  input: GeneratorInput
): UncertaintyAwareExplanation {
  const now = new Date().toISOString();
  
  // Step 1: Collect trigger signals
  const triggers = collectTriggerSignals(input);
  
  // Step 2: Collect absence signals
  const absences = collectAbsenceSignals(input);
  
  // Step 3: Run inference
  const inference = inferState(triggers, absences, input.confidence);
  
  // Step 4: Generate headline
  const headlineConfig = HEADLINE_CONFIGS[inference.state];
  const headline = {
    emoji: headlineConfig.emoji,
    text: headlineConfig.qualifier 
      ? `${headlineConfig.primaryText} ${headlineConfig.qualifier}`
      : headlineConfig.primaryText,
    tone: headlineConfig.tone,
  };
  
  // Step 5: Generate summary
  const criticalAbsenceCount = absences.filter(a => a.importance === 'CRITICAL' || a.importance === 'HIGH').length;
  const summary = SUMMARY_TEMPLATES[inference.state](triggers.length, criticalAbsenceCount);
  
  // Step 6: Get guidance
  const guidance = GUIDANCE_CONFIGS[inference.state];
  
  return {
    headline,
    summary,
    triggerSignals: triggers,
    triggerToggleTitle: 'Why Securnex flagged this',
    absenceSignals: absences,
    absenceToggleTitle: 'What Securnex did NOT detect',
    inference,
    guidance,
    chain: input.chain,
    underlyingStatus: input.securityStatus,
    generatedAt: now,
  };
}

// ============================================
// SIGNAL COLLECTION FUNCTIONS
// ============================================

function collectTriggerSignals(input: GeneratorInput): TriggerSignal[] {
  const signals: TriggerSignal[] = [];
  let idCounter = 0;
  
  // Map behavioral flags to trigger signals
  if (input.hasSweeperBotBehavior) {
    signals.push({
      id: `trigger-${idCounter++}`,
      category: 'SWEEPER_BOT_ACTIVITY',
      description: TRIGGER_DESCRIPTIONS.SWEEPER_BOT_ACTIVITY,
      confidence: 90,
      severity: 'CRITICAL',
      isDirectEvidence: true,
    });
  }
  
  if (input.hasSignerCompromise) {
    signals.push({
      id: `trigger-${idCounter++}`,
      category: 'SIGNER_COMPROMISE',
      description: TRIGGER_DESCRIPTIONS.SIGNER_COMPROMISE,
      confidence: 85,
      severity: 'CRITICAL',
      isDirectEvidence: true,
    });
  }
  
  if (input.hasRapidDrainage && input.hasRepeatDrainPatterns) {
    signals.push({
      id: `trigger-${idCounter++}`,
      category: 'RAPID_DRAIN_PATTERN',
      description: TRIGGER_DESCRIPTIONS.RAPID_DRAIN_PATTERN,
      confidence: 85,
      severity: 'CRITICAL',
      isDirectEvidence: true,
    });
  }
  
  if (input.hasActiveMaliciousApprovals) {
    signals.push({
      id: `trigger-${idCounter++}`,
      category: 'HIGH_RISK_APPROVAL',
      description: TRIGGER_DESCRIPTIONS.HIGH_RISK_APPROVAL,
      confidence: 70,
      severity: 'HIGH',
      isDirectEvidence: false,
    });
  }
  
  if (input.hasHistoricalCompromise) {
    signals.push({
      id: `trigger-${idCounter++}`,
      category: 'HISTORICAL_INCIDENT',
      description: TRIGGER_DESCRIPTIONS.HISTORICAL_INCIDENT,
      confidence: 60,
      severity: 'MEDIUM',
      isDirectEvidence: false,
    });
  }
  
  // Map evidence to trigger signals
  for (const ev of input.evidence) {
    const mappedSignal = mapEvidenceToTrigger(ev, idCounter++);
    if (mappedSignal && !signals.some(s => s.category === mappedSignal.category)) {
      signals.push(mappedSignal);
    }
  }
  
  // Sort by severity and confidence
  return signals.sort((a, b) => {
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return b.confidence - a.confidence;
  });
}

function collectAbsenceSignals(input: GeneratorInput): AbsenceSignal[] {
  const signals: AbsenceSignal[] = [];
  let idCounter = 0;
  
  // These are things we explicitly checked for and did NOT find
  // This is CRUCIAL for honest, transparent communication
  
  if (!input.hasSweeperBotBehavior) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_SWEEPER_BOT',
      description: ABSENCE_DESCRIPTIONS.NO_SWEEPER_BOT,
      importance: 'CRITICAL',
      reassuranceLevel: 90,
    });
  }
  
  if (!input.hasSignerCompromise) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_SIGNER_COMPROMISE',
      description: ABSENCE_DESCRIPTIONS.NO_SIGNER_COMPROMISE,
      importance: 'CRITICAL',
      reassuranceLevel: 90,
    });
  }
  
  if (!input.hasRapidDrainage) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_RAPID_DRAINAGE',
      description: ABSENCE_DESCRIPTIONS.NO_RAPID_DRAINAGE,
      importance: 'CRITICAL',
      reassuranceLevel: 85,
    });
  }
  
  if (!input.hasAutomatedOutflows) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_AUTOMATED_OUTFLOWS',
      description: ABSENCE_DESCRIPTIONS.NO_AUTOMATED_OUTFLOWS,
      importance: 'HIGH',
      reassuranceLevel: 80,
    });
  }
  
  if (!input.hasActiveMaliciousApprovals) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_ACTIVE_APPROVALS',
      description: ABSENCE_DESCRIPTIONS.NO_ACTIVE_APPROVALS,
      importance: 'HIGH',
      reassuranceLevel: 85,
    });
  }
  
  if (!input.hasFundLoss) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_FUND_LOSS',
      description: ABSENCE_DESCRIPTIONS.NO_FUND_LOSS,
      importance: 'HIGH',
      reassuranceLevel: 90,
    });
  }
  
  if (!input.hasRepeatDrainPatterns) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_REPEAT_PATTERNS',
      description: ABSENCE_DESCRIPTIONS.NO_REPEAT_PATTERNS,
      importance: 'HIGH',
      reassuranceLevel: 80,
    });
  }
  
  if (input.approvalsRevoked) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'APPROVALS_REVOKED',
      description: ABSENCE_DESCRIPTIONS.APPROVALS_REVOKED,
      importance: 'HIGH',
      reassuranceLevel: 85,
    });
  }
  
  // Check for no recent activity
  if (input.daysSinceLastIncident && input.daysSinceLastIncident > 30) {
    signals.push({
      id: `absence-${idCounter++}`,
      category: 'NO_RECENT_ACTIVITY',
      description: `No suspicious activity observed in the last ${input.daysSinceLastIncident} days`,
      importance: 'MEDIUM',
      reassuranceLevel: 70,
    });
  }
  
  // Sort by importance and reassurance level
  const importanceOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  return signals.sort((a, b) => {
    const importanceDiff = importanceOrder[a.importance] - importanceOrder[b.importance];
    if (importanceDiff !== 0) return importanceDiff;
    return b.reassuranceLevel - a.reassuranceLevel;
  });
}

function mapEvidenceToTrigger(evidence: CompromiseEvidence, id: number): TriggerSignal | null {
  const codeToCategory: Partial<Record<CompromiseReasonCode, TriggerCategory>> = {
    'CONFIRMED_DRAINER_INTERACTION': 'DRAINER_INTERACTION',
    'DRAINER_CLUSTER_INTERACTION': 'DRAINER_INTERACTION',
    'SWEEPER_PATTERN': 'SWEEPER_BOT_ACTIVITY',
    'SWEEPER_BOT_DETECTED': 'SWEEPER_BOT_ACTIVITY',
    'UNLIMITED_APPROVAL_EOA': 'HIGH_RISK_APPROVAL',
    'UNLIMITED_APPROVAL_UNVERIFIED': 'HIGH_RISK_APPROVAL',
    'UNLIMITED_APPROVAL_TO_UNKNOWN': 'HIGH_RISK_APPROVAL',
    'MALICIOUS_APPROVAL': 'HIGH_RISK_APPROVAL',
    'APPROVAL_THEN_DRAIN': 'RAPID_DRAIN_PATTERN',
    'ATTACKER_LINKED_ADDRESS': 'FLAGGED_ADDRESS',
    'UNKNOWN_RECIPIENT_DRAIN': 'FLAGGED_ADDRESS',
    'SUSPICIOUS_APPROVAL_PATTERN': 'UNUSUAL_TOKEN_MOVEMENT',
    'TIMING_ANOMALY': 'SUSPICIOUS_TIMING',
  };
  
  const category = codeToCategory[evidence.code];
  if (!category) return null;
  
  return {
    id: `trigger-${id}`,
    category,
    description: evidence.description || TRIGGER_DESCRIPTIONS[category],
    confidence: evidence.confidence,
    severity: evidence.severity === 'CRITICAL' || evidence.severity === 'HIGH' ? evidence.severity : 'MEDIUM',
    isDirectEvidence: ['SWEEPER_PATTERN', 'SWEEPER_BOT_DETECTED', 'APPROVAL_THEN_DRAIN'].includes(evidence.code),
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

// ============================================
// CONVENIENCE FUNCTION: FROM ANALYSIS RESULT
// ============================================

import { WalletAnalysisResult } from '@/types';

/**
 * Generate uncertainty-aware explanation directly from WalletAnalysisResult
 */
export function generateFromAnalysisResult(
  result: WalletAnalysisResult
): UncertaintyAwareExplanation {
  // Extract behavioral flags from threats
  const threats = result.detectedThreats || [];
  
  const hasSweeperBotBehavior = threats.some(
    t => t.attackerInfo?.type === 'SWEEPER_BOT' || t.type === 'WALLET_DRAINER'
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
  const input: GeneratorInput = {
    walletAddress: result.address,
    chain: result.chain,
    securityStatus: result.securityStatus,
    confidence: result.compromiseResolution?.resolution ? 70 : result.riskScore,
    evidence: [],
    reasonCodes: [],
    hasSweeperBotBehavior,
    hasRapidDrainage,
    hasSignerCompromise: false,
    hasAutomatedOutflows: hasSweeperBotBehavior,
    hasActiveMaliciousApprovals,
    hasFundLoss: threats.some(t => t.ongoingRisk),
    hasRepeatDrainPatterns: false,
    hasHistoricalCompromise: result.historicalCompromise?.hasHistoricalCompromise || false,
    approvalsRevoked: result.compromiseResolution?.resolution?.allApprovalsRevoked || false,
    daysSinceLastIncident: result.historicalCompromise?.remediationStatus?.daysSinceLastIncident,
  };
  
  return generateUncertaintyAwareExplanation(input);
}

export default generateUncertaintyAwareExplanation;
