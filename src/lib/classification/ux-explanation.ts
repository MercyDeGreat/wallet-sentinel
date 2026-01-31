// ============================================
// UX EXPLANATION GENERATOR
// ============================================
//
// Generates human-readable explanations for attack classifications.
//
// CORE PRINCIPLES:
// 1. Truthful status messages - never overstate severity
// 2. Explain what HAPPENED and what DID NOT happen
// 3. Always explain uncertainty
// 4. Calm, non-alarmist language
// 5. Actionable guidance
// ============================================

import type {
  AttackType,
  AttackClassification,
  AttackDisplayInfo,
  ClassifierResult,
} from './types';

// ============================================
// DISPLAY CONFIGURATION BY ATTACK TYPE
// ============================================

interface AttackDisplayConfig {
  emoji: string;
  headline: string;
  badgeText: string;
  badgeColor: 'red' | 'orange' | 'yellow' | 'blue' | 'green' | 'gray';
  severity: 'CRITICAL' | 'WARNING' | 'INFO' | 'SAFE';
  summaryTemplate: string;
  whatHappened: string[];
  whatDidNotHappen: string[];
  recommendedActions: string[];
}

const ATTACK_DISPLAY_CONFIG: Record<AttackType, AttackDisplayConfig> = {
  ADDRESS_POISONING: {
    emoji: '⚠️',
    headline: 'Address Poisoning Detected',
    badgeText: 'Address Poisoning',
    badgeColor: 'yellow',
    severity: 'WARNING',
    summaryTemplate: 'No wallet compromise found. This is a social engineering attempt.',
    whatHappened: [
      'This wallet received repeated dust transfers from a look-alike address',
      'The address visually mimics a frequently used recipient',
      'Funds may have been sent manually to the spoofed address',
    ],
    whatDidNotHappen: [
      'No private key compromise',
      'No approval abuse',
      'No automated draining',
      'No sweeper bot activity',
    ],
    recommendedActions: [
      'Always verify the FULL address before sending funds',
      'Do not copy addresses from transaction history',
      'Use address book / saved contacts',
    ],
  },
  
  SWEEPER_BOT: {
    emoji: '🤖',
    headline: 'Sweeper Bot Detected',
    badgeText: 'Active Sweeper',
    badgeColor: 'red',
    severity: 'CRITICAL',
    summaryTemplate: 'Wallet is under automated sweeper bot control.',
    whatHappened: [
      'Funds are being swept automatically within seconds of receiving',
      'Automated system is monitoring and draining the wallet',
      'Multiple sweep events detected with consistent patterns',
    ],
    whatDidNotHappen: [
      'This is not address poisoning',
      'No approval abuse mechanism used',
    ],
    recommendedActions: [
      'DO NOT send any funds to this wallet',
      'Transfer any remaining assets immediately (may be swept)',
      'Create a new wallet with fresh seed phrase',
      'Investigate source of private key compromise',
    ],
  },
  
  APPROVAL_DRAINER: {
    emoji: '🔓',
    headline: 'Approval Drainer Detected',
    badgeText: 'Approval Abuse',
    badgeColor: 'orange',
    severity: 'CRITICAL',
    summaryTemplate: 'Token approvals have been exploited to drain funds.',
    whatHappened: [
      'Malicious contract was granted token approval',
      'Attacker used transferFrom to drain tokens',
      'Funds left without user-initiated transaction',
    ],
    whatDidNotHappen: [
      'No private key compromise',
      'Wallet signature NOT required for drain',
      'No sweeper bot pattern',
    ],
    recommendedActions: [
      'Revoke all active approvals immediately',
      'Review recent approval transactions',
      'Use a tool like revoke.cash to check approvals',
      'Only approve trusted contracts in the future',
    ],
  },
  
  SIGNER_COMPROMISE: {
    emoji: '🔴',
    headline: 'Private Key Compromise',
    badgeText: 'Key Compromised',
    badgeColor: 'red',
    severity: 'CRITICAL',
    summaryTemplate: 'Private key appears compromised. Wallet is under attacker control.',
    whatHappened: [
      'Direct transfers signed by wallet to malicious destination',
      'Behavior inconsistent with wallet history',
      'Rapid multi-asset drainage detected',
    ],
    whatDidNotHappen: [
      'Not approval-based drain',
      'Not address poisoning',
      'Not sweeper bot (but key may have been stolen by sweeper operator)',
    ],
    recommendedActions: [
      'DO NOT use this wallet ever again',
      'Create new wallet with fresh seed phrase',
      'Transfer any remaining assets to new wallet',
      'Investigate source of key compromise (phishing, malware)',
      'Check other wallets derived from same seed',
    ],
  },
  
  SUSPICIOUS_ACTIVITY: {
    emoji: '🟡',
    headline: 'Suspicious Activity Detected',
    badgeText: 'Under Review',
    badgeColor: 'yellow',
    severity: 'WARNING',
    summaryTemplate: 'Multiple concerning signals detected but classification uncertain.',
    whatHappened: [
      'Unusual transaction patterns detected',
      'Some indicators of potential compromise',
      'Classification overlaps between attack types',
    ],
    whatDidNotHappen: [
      'No single attack type definitively confirmed',
      'May be legitimate but unusual activity',
    ],
    recommendedActions: [
      'Review recent transactions manually',
      'Check for any unexpected approvals',
      'Monitor for further suspicious activity',
      'Consider using a fresh wallet for new transactions',
    ],
  },
  
  NO_COMPROMISE: {
    emoji: '✅',
    headline: 'No Compromise Detected',
    badgeText: 'Safe',
    badgeColor: 'green',
    severity: 'SAFE',
    summaryTemplate: 'No attack patterns detected. Wallet appears safe.',
    whatHappened: [],
    whatDidNotHappen: [
      'No sweeper bot behavior',
      'No approval abuse',
      'No private key compromise',
      'No address poisoning',
    ],
    recommendedActions: [
      'Continue to practice good security hygiene',
      'Regularly review token approvals',
      'Keep seed phrase secure and offline',
    ],
  },
};

// ============================================
// CONFIDENCE TEXT GENERATION
// ============================================

function generateConfidenceText(confidence: number): string {
  if (confidence >= 90) {
    return `Very High Confidence (${confidence}%)`;
  } else if (confidence >= 75) {
    return `High Confidence (${confidence}%)`;
  } else if (confidence >= 50) {
    return `Moderate Confidence (${confidence}%)`;
  } else if (confidence >= 25) {
    return `Low Confidence (${confidence}%)`;
  } else {
    return `Very Low Confidence (${confidence}%)`;
  }
}

// ============================================
// MAIN EXPLANATION GENERATOR
// ============================================

/**
 * Generate UX-safe display information for an attack classification
 */
export function generateAttackDisplayInfo(
  attackType: AttackType,
  confidence: number,
  positiveIndicators: string[],
  ruledOutIndicators: string[]
): AttackDisplayInfo {
  const config = ATTACK_DISPLAY_CONFIG[attackType];
  
  // Build whatHappened from config defaults + specific indicators
  const whatHappened = [
    ...config.whatHappened,
  ];
  
  // Add specific positive indicators (deduplicated)
  for (const indicator of positiveIndicators) {
    if (!whatHappened.some(w => w.toLowerCase().includes(indicator.toLowerCase().slice(0, 30)))) {
      whatHappened.push(`• ${indicator}`);
    }
  }
  
  // Build whatDidNotHappen from config defaults + ruled out indicators
  const whatDidNotHappen = [
    ...config.whatDidNotHappen,
  ];
  
  // Add specific ruled out indicators
  for (const indicator of ruledOutIndicators) {
    if (!whatDidNotHappen.some(w => w.toLowerCase().includes(indicator.toLowerCase().slice(0, 30)))) {
      whatDidNotHappen.push(indicator);
    }
  }
  
  return {
    emoji: config.emoji,
    headline: config.headline,
    badgeText: config.badgeText,
    badgeColor: config.badgeColor,
    severity: config.severity,
    summary: config.summaryTemplate,
    whatHappened: whatHappened.slice(0, 6), // Limit to 6 items
    whatDidNotHappen: whatDidNotHappen.slice(0, 5), // Limit to 5 items
    recommendedActions: config.recommendedActions,
    confidenceText: generateConfidenceText(confidence),
  };
}

/**
 * Generate detailed explanation text for an attack classification
 */
export function generateDetailedExplanation(
  attackType: AttackType,
  confidence: number,
  classifierResults: Map<AttackType, ClassifierResult>
): string {
  const config = ATTACK_DISPLAY_CONFIG[attackType];
  const result = classifierResults.get(attackType);
  
  let explanation = `${config.emoji} ${config.headline}\n\n`;
  explanation += `${config.summaryTemplate}\n\n`;
  
  // What happened section
  if (config.whatHappened.length > 0 || (result?.positiveIndicators.length ?? 0) > 0) {
    explanation += `**What happened:**\n`;
    for (const item of config.whatHappened) {
      explanation += `• ${item}\n`;
    }
    if (result?.positiveIndicators) {
      for (const indicator of result.positiveIndicators.slice(0, 3)) {
        explanation += `• ${indicator}\n`;
      }
    }
    explanation += '\n';
  }
  
  // What did NOT happen section
  if (config.whatDidNotHappen.length > 0) {
    explanation += `**What did NOT happen:**\n`;
    for (const item of config.whatDidNotHappen) {
      explanation += `• ${item}\n`;
    }
    explanation += '\n';
  }
  
  // Confidence
  explanation += `**Confidence:** ${generateConfidenceText(confidence)}\n`;
  
  return explanation;
}

/**
 * Generate the "Why Securnex Flagged This" toggle content
 */
export function generateWhyFlaggedContent(
  positiveSignals: string[],
  ruledOutSignals: string[]
): { positiveSignals: string[]; ruledOutSignals: string[] } {
  return {
    positiveSignals: positiveSignals.map(s => 
      // Clean up and format signals
      s.replace(/^\s*[-•]\s*/, '').trim()
    ),
    ruledOutSignals: ruledOutSignals.map(s =>
      s.replace(/^\s*[-•]\s*/, '').trim()
    ),
  };
}

// Note: Functions and constants are already exported inline above
