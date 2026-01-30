// ============================================
// THREE-STATE COMPROMISE CLASSIFICATION (2026-01 REDESIGN)
// ============================================
//
// This module implements the redesigned compromise classification logic
// that distinguishes between:
//
// 1. ACTIVELY_COMPROMISED (CRITICAL - RED)
//    - Confidence ≥ 80%
//    - ONLY for wallets under ACTIVE attacker control
//    - Requires LIVE indicators (real-time sweep, ongoing drain)
//
// 2. HISTORICALLY_COMPROMISED (WARNING - ORANGE)
//    - Confidence 50-79%
//    - Past drainer interaction, attack has STOPPED
//    - No evidence of CURRENT attacker access
//
// 3. RISK_EXPOSURE (INFO - YELLOW)
//    - Confidence < 50%
//    - User error, voluntary interaction with suspicious addresses
//    - No compromise, just exposure
//
// CRITICAL RULE: Historical signals NEVER trigger "ACTIVELY COMPROMISED"
// CRITICAL RULE: Confidence < 80% → DOWNGRADE to lower severity

import { 
  SecurityStatus, 
  CompromiseSubStatus,
  CompromiseClassification,
  StatusExplanation,
  ActiveCompromiseIndicator,
  HistoricalCompromiseIndicator,
  CompromiseEvidence,
} from '@/types';

// ============================================
// CONFIDENCE THRESHOLDS
// ============================================
const ACTIVE_COMPROMISE_THRESHOLD = 80;   // Must be ≥80% for ACTIVELY_COMPROMISED
const HISTORICAL_COMPROMISE_MIN = 50;     // 50-79% for HISTORICALLY_COMPROMISED
const RISK_EXPOSURE_MAX = 49;             // <50% for RISK_EXPOSURE

// Time thresholds for "live" classification
const CRITICAL_LIVE_HOURS = 48;   // CRITICAL indicators must be <48h old
const HIGH_LIVE_HOURS = 168;      // HIGH indicators must be <7 days old

// ============================================
// MAIN CLASSIFICATION FUNCTION
// ============================================

export interface ClassificationInput {
  activeThreats: CompromiseEvidence[];
  historicalThreats: CompromiseEvidence[];
  allEvidence: CompromiseEvidence[];
  daysSinceLastIncident?: number;
  isRemediated: boolean;
  hasActiveApprovals: boolean;
  hasOngoingDrains: boolean;
  isFirstScan: boolean;
}

export interface ClassificationResult {
  status: SecurityStatus;
  subStatus: CompromiseSubStatus;
  confidence: number;
  summary: string;
  explanation: StatusExplanation;
  reasoning: string;
}

/**
 * Classify wallet compromise status using the three-state system.
 * 
 * RULES:
 * 1. ACTIVELY_COMPROMISED requires ≥80% confidence AND live indicators
 * 2. Historical signals ALONE cannot trigger ACTIVELY_COMPROMISED
 * 3. If confidence is borderline, ALWAYS downgrade severity
 * 4. First scan should NEVER show ACTIVELY_COMPROMISED without live evidence
 */
export function classifyCompromiseState(input: ClassificationInput): ClassificationResult {
  const {
    activeThreats,
    historicalThreats,
    allEvidence,
    daysSinceLastIncident,
    isRemediated,
    hasActiveApprovals,
    hasOngoingDrains,
    isFirstScan,
  } = input;

  // ============================================
  // STEP 1: Identify LIVE active indicators
  // ============================================
  const liveIndicators = identifyLiveIndicators(activeThreats);
  const liveConfidence = calculateLiveConfidence(liveIndicators);

  // ============================================
  // STEP 2: Check for ACTIVELY_COMPROMISED (≥80% confidence)
  // ============================================
  if (liveIndicators.length > 0 && liveConfidence >= ACTIVE_COMPROMISE_THRESHOLD) {
    // Additional check: Don't show ACTIVELY_COMPROMISED on first scan
    // unless we have very strong live evidence
    if (isFirstScan && liveConfidence < 90) {
      // Downgrade to HISTORICALLY_COMPROMISED for first scan
      return createHistoricalResult(
        Math.min(79, liveConfidence),
        'PREVIOUS_ATTACK',
        daysSinceLastIncident,
        isRemediated,
        'First scan - monitoring for confirmation'
      );
    }

    return createActiveResult(liveIndicators, liveConfidence, hasOngoingDrains);
  }

  // ============================================
  // STEP 3: Check for HISTORICALLY_COMPROMISED (50-79%)
  // ============================================
  const significantHistorical = historicalThreats.filter(
    t => t.severity === 'CRITICAL' || t.severity === 'HIGH' || t.severity === 'MEDIUM'
  );

  if (significantHistorical.length > 0 || (daysSinceLastIncident !== undefined && daysSinceLastIncident < 365)) {
    const historicalConfidence = calculateHistoricalConfidence(
      significantHistorical,
      daysSinceLastIncident,
      isRemediated,
      hasActiveApprovals
    );

    if (historicalConfidence >= HISTORICAL_COMPROMISE_MIN) {
      const subStatus = determineHistoricalSubStatus(
        daysSinceLastIncident,
        isRemediated,
        hasActiveApprovals
      );
      
      return createHistoricalResult(
        historicalConfidence,
        subStatus,
        daysSinceLastIncident,
        isRemediated
      );
    }

    // Below 50% = RISK_EXPOSURE
    return createRiskExposureResult(
      historicalConfidence,
      significantHistorical,
      'Historical interaction detected but confidence too low for compromise classification'
    );
  }

  // ============================================
  // STEP 4: Check for RISK_EXPOSURE (<50%)
  // ============================================
  if (allEvidence.length > 0) {
    const avgConfidence = allEvidence.reduce((sum, e) => sum + e.confidence, 0) / allEvidence.length;
    
    if (avgConfidence < ACTIVE_COMPROMISE_THRESHOLD) {
      return createRiskExposureResult(
        avgConfidence,
        allEvidence,
        'Risk indicators present but insufficient evidence for compromise'
      );
    }
  }

  // ============================================
  // STEP 5: SAFE (no evidence)
  // ============================================
  return createSafeResult();
}

// ============================================
// HELPER: Identify live (real-time) indicators
// ============================================
function identifyLiveIndicators(threats: CompromiseEvidence[]): CompromiseEvidence[] {
  return threats.filter(threat => {
    // Must be CRITICAL or HIGH severity
    if (threat.severity !== 'CRITICAL' && threat.severity !== 'HIGH') {
      return false;
    }

    // Must have high individual confidence
    if (threat.confidence < 70) {
      return false;
    }

    // Must be recent to be "live"
    if (threat.timestamp) {
      const hoursSince = (Date.now() - new Date(threat.timestamp).getTime()) / (1000 * 60 * 60);
      
      if (threat.severity === 'CRITICAL' && hoursSince > CRITICAL_LIVE_HOURS) {
        return false;
      }
      if (threat.severity === 'HIGH' && hoursSince > HIGH_LIVE_HOURS) {
        return false;
      }
    }

    return true;
  });
}

// ============================================
// HELPER: Calculate confidence for live indicators
// ============================================
function calculateLiveConfidence(liveIndicators: CompromiseEvidence[]): number {
  if (liveIndicators.length === 0) return 0;
  
  const avgConfidence = liveIndicators.reduce((sum, i) => sum + i.confidence, 0) / liveIndicators.length;
  
  // Boost confidence if multiple critical indicators
  const criticalCount = liveIndicators.filter(i => i.severity === 'CRITICAL').length;
  const boost = Math.min(10, criticalCount * 3);
  
  return Math.min(100, Math.round(avgConfidence + boost));
}

// ============================================
// HELPER: Calculate confidence for historical threats
// ============================================
function calculateHistoricalConfidence(
  threats: CompromiseEvidence[],
  daysSinceLastIncident?: number,
  isRemediated?: boolean,
  hasActiveApprovals?: boolean
): number {
  if (threats.length === 0) {
    return daysSinceLastIncident !== undefined ? 40 : 0;
  }

  let confidence = threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length;

  // Decay confidence based on time since incident
  if (daysSinceLastIncident !== undefined) {
    if (daysSinceLastIncident > 90) {
      confidence *= 0.3;  // 70% decay after 90 days
    } else if (daysSinceLastIncident > 30) {
      confidence *= 0.5;  // 50% decay after 30 days
    } else if (daysSinceLastIncident > 7) {
      confidence *= 0.7;  // 30% decay after 7 days
    }
  }

  // Boost if not remediated (but cap at 79%)
  if (!isRemediated) {
    confidence = Math.min(79, confidence + 10);
  }
  if (hasActiveApprovals) {
    confidence = Math.min(79, confidence + 5);
  }

  // Cap at 79% for historical (below active threshold)
  return Math.round(Math.max(0, Math.min(79, confidence)));
}

// ============================================
// HELPER: Determine historical sub-status
// ============================================
function determineHistoricalSubStatus(
  daysSinceLastIncident?: number,
  isRemediated?: boolean,
  hasActiveApprovals?: boolean
): CompromiseSubStatus {
  if (isRemediated && (daysSinceLastIncident === undefined || daysSinceLastIncident > 30)) {
    return 'RESOLVED';
  }
  
  if (!hasActiveApprovals && (daysSinceLastIncident === undefined || daysSinceLastIncident > 7)) {
    return 'NO_ACTIVE_RISK';
  }
  
  return 'PREVIOUS_ATTACK';
}

// ============================================
// RESULT CREATORS
// ============================================

function createActiveResult(
  liveIndicators: CompromiseEvidence[],
  confidence: number,
  hasOngoingDrains: boolean
): ClassificationResult {
  const criticalCount = liveIndicators.filter(i => i.severity === 'CRITICAL').length;
  const reasons = liveIndicators.slice(0, 2).map(i => i.description.split('.')[0]).join('; ');

  const subStatus: CompromiseSubStatus = hasOngoingDrains 
    ? 'ACTIVE_SWEEP_IN_PROGRESS' 
    : 'LIVE_ATTACKER_ACCESS';

  const summary = `🚨 ACTIVELY COMPROMISED: ${criticalCount > 0 ? `${criticalCount} critical` : 'Active'} threat(s) confirmed. ` +
                  `${reasons}. Immediate action required.`;

  const explanation: StatusExplanation = {
    label: 'Actively Compromised',
    summary: 'This wallet is under active attacker control.',
    details: `Live indicators confirm ongoing attacker access. ${criticalCount} critical and ` +
             `${liveIndicators.length - criticalCount} high severity threats detected within the monitoring window.`,
    reasoning: `Confidence: ${confidence}%. Live threat indicators detected: ${liveIndicators.map(i => i.code).join(', ')}`,
    action: 'Stop using this wallet immediately. Transfer remaining assets to a new, secure wallet.',
    severity: 'CRITICAL',
    icon: 'alert-octagon',
    color: 'red',
  };

  return {
    status: 'ACTIVELY_COMPROMISED',
    subStatus,
    confidence,
    summary,
    explanation,
    reasoning: explanation.reasoning,
  };
}

function createHistoricalResult(
  confidence: number,
  subStatus: CompromiseSubStatus,
  daysSinceLastIncident?: number,
  isRemediated?: boolean,
  extraNote?: string
): ClassificationResult {
  const timePhrase = daysSinceLastIncident !== undefined 
    ? `Last incident: ${daysSinceLastIncident} day${daysSinceLastIncident !== 1 ? 's' : ''} ago.`
    : '';

  let summary: string;
  let details: string;
  let action: string | undefined;

  if (subStatus === 'RESOLVED' || (isRemediated && daysSinceLastIncident && daysSinceLastIncident > 30)) {
    summary = `⚠️ Previous compromise detected — no active attacker control observed. ${timePhrase}`;
    details = 'This wallet was compromised in the past, but all malicious access has been revoked. ' +
              'No ongoing attacker activity detected.';
    action = undefined;
  } else if (subStatus === 'NO_ACTIVE_RISK') {
    summary = `⚠️ Previous compromise detected — attack appears stopped. ${timePhrase}`;
    details = 'Historical compromise indicators found. The attack appears to have ended. ' +
              'Continue monitoring for unusual activity.';
    action = 'Review recent transactions and revoke any suspicious approvals.';
  } else {
    summary = `⚠️ Historical compromise indicators detected. ${timePhrase}`;
    details = `Previous security incident identified. ${extraNote || 'Monitoring recommended.'}`;
    action = 'Review approvals and transaction history.';
  }

  const explanation: StatusExplanation = {
    label: 'Previously Compromised',
    summary: 'Past attack detected, no current attacker access.',
    details,
    reasoning: `Confidence: ${confidence}%. ${timePhrase} Remediated: ${isRemediated ? 'Yes' : 'No'}`,
    action,
    severity: 'WARNING',
    icon: 'alert-triangle',
    color: 'orange',
  };

  return {
    status: 'HISTORICALLY_COMPROMISED',
    subStatus,
    confidence,
    summary,
    explanation,
    reasoning: explanation.reasoning,
  };
}

function createRiskExposureResult(
  confidence: number,
  evidence: CompromiseEvidence[],
  reason: string
): ClassificationResult {
  const threatTypes = [...new Set(evidence.map(e => e.code))].slice(0, 2);
  
  const summary = `ℹ️ Risk exposure noted. ${reason}. ` +
                  `This appears to be user activity, not an active attack.`;

  const explanation: StatusExplanation = {
    label: 'Risk Exposure',
    summary: 'Some risk indicators present, but no compromise detected.',
    details: `Interaction with flagged addresses detected (${threatTypes.join(', ')}), ` +
             `but wallet behavior matches normal user actions. This is NOT classified as a compromise.`,
    reasoning: `Confidence: ${confidence}%. Evidence types: ${threatTypes.join(', ')}`,
    action: undefined,
    severity: 'INFO',
    icon: 'info',
    color: 'yellow',
  };

  return {
    status: 'RISK_EXPOSURE',
    subStatus: evidence.some(e => e.code === 'DRAINER_CLUSTER_INTERACTION') 
      ? 'USER_SENT_TO_DRAINER' 
      : 'INDIRECT_EXPOSURE',
    confidence: Math.max(10, Math.round(confidence)),
    summary,
    explanation,
    reasoning: explanation.reasoning,
  };
}

function createSafeResult(): ClassificationResult {
  return {
    status: 'SAFE',
    subStatus: 'NONE',
    confidence: 95,
    summary: '✓ No risk indicators detected. Wallet appears safe.',
    explanation: {
      label: 'Safe',
      summary: 'No security issues detected.',
      details: 'Analysis complete. No compromise indicators, suspicious transactions, or risky approvals found.',
      reasoning: 'No evidence of malicious activity in transaction history or approvals.',
      action: undefined,
      severity: 'SAFE',
      icon: 'shield-check',
      color: 'green',
    },
    reasoning: 'No evidence of malicious activity.',
  };
}

// ============================================
// UTILITY: Map legacy status to new system
// ============================================
export function mapLegacyToThreeState(
  legacyStatus: SecurityStatus,
  confidence: number
): SecurityStatus {
  switch (legacyStatus) {
    case 'COMPROMISED':
    case 'ACTIVELY_COMPROMISED':
    case 'ACTIVE_COMPROMISE_DRAINER':
      // Only keep as ACTIVELY_COMPROMISED if confidence ≥ 80%
      return confidence >= ACTIVE_COMPROMISE_THRESHOLD 
        ? 'ACTIVELY_COMPROMISED' 
        : 'HISTORICALLY_COMPROMISED';
    
    case 'PREVIOUSLY_COMPROMISED':
    case 'PREVIOUSLY_COMPROMISED_NO_ACTIVITY':
      return 'HISTORICALLY_COMPROMISED';
    
    case 'AT_RISK':
    case 'POTENTIALLY_COMPROMISED':
      // Downgrade based on confidence
      if (confidence >= ACTIVE_COMPROMISE_THRESHOLD) return 'HISTORICALLY_COMPROMISED';
      if (confidence >= HISTORICAL_COMPROMISE_MIN) return 'HISTORICALLY_COMPROMISED';
      return 'RISK_EXPOSURE';
    
    case 'SAFE':
    case 'HIGH_ACTIVITY_WALLET':
    case 'PROTOCOL_INTERACTION':
      return 'SAFE';
    
    default:
      return legacyStatus;
  }
}

// ============================================
// UTILITY: Generate user-facing explanation
// ============================================
export function generateStatusExplanation(
  status: SecurityStatus,
  confidence: number,
  subStatus: CompromiseSubStatus,
  daysSinceIncident?: number
): StatusExplanation {
  switch (status) {
    case 'ACTIVELY_COMPROMISED':
    case 'ACTIVE_COMPROMISE_DRAINER':
      return {
        label: 'Actively Compromised',
        summary: 'Wallet under active attacker control',
        details: 'Live indicators confirm ongoing malicious activity. Immediate action required.',
        reasoning: `Confidence: ${confidence}%. Active threat indicators detected.`,
        action: 'Stop using this wallet. Transfer assets to a secure wallet immediately.',
        severity: 'CRITICAL',
        icon: 'alert-octagon',
        color: 'red',
      };
    
    case 'HISTORICALLY_COMPROMISED':
      const timeNote = daysSinceIncident 
        ? `Last incident: ${daysSinceIncident} days ago.`
        : '';
      return {
        label: 'Previously Compromised',
        summary: 'Past attack detected — no current threat',
        details: `Historical compromise indicators found. Attack has stopped. ${timeNote}`,
        reasoning: `Confidence: ${confidence}%. No live threat indicators.`,
        action: subStatus === 'RESOLVED' ? undefined : 'Review approvals and monitor activity.',
        severity: 'WARNING',
        icon: 'alert-triangle',
        color: 'orange',
      };
    
    case 'RISK_EXPOSURE':
      return {
        label: 'Risk Exposure',
        summary: 'Some risk indicators — no compromise',
        details: 'Interaction with flagged addresses detected, but this appears to be user activity.',
        reasoning: `Confidence: ${confidence}%. Insufficient evidence for compromise.`,
        action: undefined,
        severity: 'INFO',
        icon: 'info',
        color: 'yellow',
      };
    
    default:
      return {
        label: 'Safe',
        summary: 'No security issues detected',
        details: 'Wallet appears safe based on available data.',
        reasoning: 'No malicious activity detected.',
        action: undefined,
        severity: 'SAFE',
        icon: 'shield-check',
        color: 'green',
      };
  }
}

export default classifyCompromiseState;
