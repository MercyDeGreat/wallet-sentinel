// ============================================
// INCIDENT ANALYZER - MAIN ORCHESTRATOR
// ============================================
// Orchestrates the incident correlation, attack classification,
// attacker profiling, and exchange escalation report generation.
//
// This is the main entry point for analyzing potential
// multi-wallet attacks and seed/signer compromises.

import {
  IncidentAnalysisResult,
  IncidentWallet,
  CorrelationConfig,
  DEFAULT_CORRELATION_CONFIG,
  UserRecommendation,
  IncidentDisplaySummary,
  generateIncidentId,
  getConfidenceLevel,
} from './types';

import { correlateWallets } from './correlation-engine';
import { classifyAttack } from './attack-classifier';
import { buildAttackerProfile } from './attacker-profiler';
import { generateExchangeReport } from './exchange-report-generator';

// ============================================
// MAIN ANALYSIS FUNCTION
// ============================================

/**
 * Analyze a group of wallets to detect and classify attacks.
 * 
 * This is the main entry point for incident correlation.
 * It will:
 * 1. Correlate wallets to find patterns
 * 2. Classify the attack type
 * 3. Profile attacker infrastructure
 * 4. Generate exchange escalation report if applicable
 * 5. Provide user recommendations
 */
export async function analyzeIncident(
  wallets: IncidentWallet[],
  config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG
): Promise<IncidentAnalysisResult> {
  const incidentId = generateIncidentId();
  const analyzedAt = new Date().toISOString();
  
  console.log(`[IncidentAnalyzer] Analyzing incident ${incidentId} with ${wallets.length} wallet(s)`);
  
  // Step 1: Correlate wallets
  const correlation = correlateWallets(wallets, config);
  console.log(`[IncidentAnalyzer] Correlation complete. Strength: ${correlation.correlationStrength}, Multi-wallet: ${correlation.isMultiWalletAttack}`);
  
  // Step 2: Classify the attack
  const classification = classifyAttack(correlation, config);
  console.log(`[IncidentAnalyzer] Classification: ${classification.classification}, Confidence: ${classification.confidenceScore}`);
  
  // Step 3: Build attacker profile
  const attackerProfile = buildAttackerProfile(correlation);
  console.log(`[IncidentAnalyzer] Attacker profile built. ${attackerProfile.wallets.length} attacker wallet(s) identified`);
  
  // Step 4: Generate exchange report if applicable
  const exchangeReport = generateExchangeReport(correlation, classification, attackerProfile, config);
  if (exchangeReport) {
    console.log(`[IncidentAnalyzer] Exchange report generated for ${exchangeReport.exchangeData.exchangeName}`);
  }
  
  // Step 5: Generate user recommendations
  const recommendations = generateRecommendations(classification, attackerProfile, correlation);
  
  // Step 6: Build display summary
  const displaySummary = buildDisplaySummary(correlation, classification, attackerProfile, exchangeReport !== null);
  
  // Calculate overall confidence
  const overallConfidence = Math.round(
    (correlation.correlationStrength * 0.3) + 
    (classification.confidenceScore * 0.5) + 
    (attackerProfile.confidence * 0.2)
  );
  
  return {
    incidentId,
    analyzedAt,
    correlation,
    classification,
    attackerProfile,
    exchangeReport: exchangeReport || undefined,
    recommendations,
    overallConfidence,
    confidenceLevel: getConfidenceLevel(overallConfidence, config),
    displaySummary,
  };
}

// ============================================
// RECOMMENDATIONS GENERATOR
// ============================================

function generateRecommendations(
  classification: ReturnType<typeof classifyAttack>,
  attackerProfile: ReturnType<typeof buildAttackerProfile>,
  correlation: ReturnType<typeof correlateWallets>
): UserRecommendation[] {
  const recommendations: UserRecommendation[] = [];
  
  // Seed/Signer Compromise specific recommendations
  if (classification.classification === 'SEED_SIGNER_COMPROMISE') {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Environment compromised – abandon seed immediately',
      reason: 'Multiple wallets from the same seed were drained. The seed phrase or private keys have been compromised.',
      timeframe: 'IMMEDIATE',
    });
    
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Do not reuse browser or wallet instance',
      reason: 'The attack may have originated from malware or a compromised browser extension. Use a completely fresh environment.',
      timeframe: 'IMMEDIATE',
    });
    
    recommendations.push({
      priority: 'HIGH',
      action: 'Generate new seed phrase on secure device',
      reason: 'Create a new wallet using a hardware wallet or air-gapped device that has never been connected to the compromised environment.',
      timeframe: 'URGENT',
    });
    
    recommendations.push({
      priority: 'HIGH',
      action: 'Scan all devices for malware',
      reason: 'The seed may have been stolen via keylogger, screen capture, or clipboard hijacking. Perform a full security scan.',
      timeframe: 'URGENT',
    });
  }
  
  // Approval-based drain specific recommendations
  if (classification.classification === 'APPROVAL_BASED_DRAIN') {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Revoke all unlimited token approvals',
      reason: 'The attacker drained funds using token approvals. Revoke all approvals to prevent further losses.',
      timeframe: 'IMMEDIATE',
    });
    
    recommendations.push({
      priority: 'HIGH',
      action: 'Revoke approvals from clean device only',
      reason: 'Use a device that was not used to grant the malicious approval. The original device may be compromised.',
      timeframe: 'URGENT',
    });
    
    recommendations.push({
      priority: 'MEDIUM',
      action: 'Review recent dApp interactions',
      reason: 'The malicious approval may have come from a phishing site or compromised dApp. Review your recent interactions.',
      timeframe: 'SOON',
    });
  }
  
  // Contract exploit specific recommendations
  if (classification.classification === 'CONTRACT_EXPLOIT') {
    recommendations.push({
      priority: 'HIGH',
      action: 'Stop interacting with the affected protocol',
      reason: 'The smart contract may have a vulnerability. Avoid further interactions until the issue is resolved.',
      timeframe: 'IMMEDIATE',
    });
    
    recommendations.push({
      priority: 'MEDIUM',
      action: 'Report the exploit to the protocol team',
      reason: 'Contact the protocol\'s security team to report the vulnerability and help protect other users.',
      timeframe: 'SOON',
    });
  }
  
  // General recommendations
  if (attackerProfile.exitLiquidity.some(e => e.type === 'EXCHANGE')) {
    recommendations.push({
      priority: 'HIGH',
      action: 'Report to exchange abuse team',
      reason: 'Stolen funds were deposited to a centralized exchange. Submit a report to their compliance team for potential fund recovery.',
      timeframe: 'URGENT',
    });
  }
  
  // Always recommend monitoring
  recommendations.push({
    priority: 'MEDIUM',
    action: 'Monitor attacker addresses',
    reason: 'Track the attacker\'s addresses for any fund movement that could aid in recovery or future prevention.',
    timeframe: 'WHEN_POSSIBLE',
  });
  
  // Sort by priority
  const priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  recommendations.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);
  
  return recommendations;
}

// ============================================
// DISPLAY SUMMARY BUILDER
// ============================================

function buildDisplaySummary(
  correlation: ReturnType<typeof correlateWallets>,
  classification: ReturnType<typeof classifyAttack>,
  attackerProfile: ReturnType<typeof buildAttackerProfile>,
  exchangeReportReady: boolean
): IncidentDisplaySummary {
  // Determine severity
  let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  if (classification.classification === 'SEED_SIGNER_COMPROMISE' && classification.confidenceScore >= 85) {
    severity = 'CRITICAL';
  } else if (classification.confidenceScore >= 70) {
    severity = 'HIGH';
  } else if (classification.confidenceScore >= 50) {
    severity = 'MEDIUM';
  } else {
    severity = 'LOW';
  }
  
  // Build title
  let title: string;
  switch (classification.classification) {
    case 'SEED_SIGNER_COMPROMISE':
      title = `Seed/Signer Compromise Detected (${correlation.wallets.length} Wallets)`;
      break;
    case 'APPROVAL_BASED_DRAIN':
      title = 'Token Approval Exploit Detected';
      break;
    case 'CONTRACT_EXPLOIT':
      title = 'Smart Contract Exploit Detected';
      break;
    case 'SINGLE_WALLET_INCIDENT':
      title = 'Single Wallet Incident';
      break;
    default:
      title = 'Security Incident Under Investigation';
  }
  
  // Brief description
  const totalLoss = correlation.wallets.reduce((sum, w) => sum + w.totalDrainedValueUSD, 0);
  const briefDescription = `${correlation.wallets.length} wallet(s) affected. Total loss: $${totalLoss.toLocaleString()} USD. Confidence: ${classification.confidence} (${classification.confidenceScore}%).`;
  
  // Detailed explanation
  let detailedExplanation = classification.summary;
  
  // Why NOT approval or dApp exploit
  let whyNotApprovalExploit: string | undefined;
  let whyNotDAppExploit: string | undefined;
  
  if (classification.classification === 'SEED_SIGNER_COMPROMISE') {
    whyNotApprovalExploit = classification.reasoning.whyNotApprovalDrain || 
      'No shared malicious approval target was found that could explain all the drains. Native assets (ETH/BNB/SOL) were drained, which cannot be taken via token approvals.';
    
    whyNotDAppExploit = classification.reasoning.whyNotContractExploit ||
      'No shared contract interaction was found across all affected wallets. The drains occurred independently without a common exploit vector.';
  }
  
  // Attacker infrastructure summary
  let attackerInfrastructureSummary: string | undefined;
  if (attackerProfile.wallets.length > 0) {
    const aggregationCount = attackerProfile.wallets.filter(w => w.role === 'AGGREGATION').length;
    const routerCount = attackerProfile.wallets.filter(w => w.role === 'ROUTER').length;
    const exchangeCount = attackerProfile.wallets.filter(w => w.role === 'EXCHANGE_DEPOSIT').length;
    
    const parts: string[] = [];
    if (aggregationCount > 0) parts.push(`${aggregationCount} aggregation wallet(s)`);
    if (routerCount > 0) parts.push(`${routerCount} routing wallet(s)`);
    if (exchangeCount > 0) parts.push(`${exchangeCount} exchange deposit(s)`);
    
    attackerInfrastructureSummary = `Identified attacker infrastructure: ${parts.join(', ')}. ` +
      `Total stolen: $${attackerProfile.stats.totalStolenUSD.toLocaleString()} USD across ${attackerProfile.stats.chainsInvolved.length} chain(s).`;
  }
  
  // Exchange escalation readiness
  const exchangeEscalationReason = exchangeReportReady
    ? 'Exchange deposit detected and evidence collected. Report ready for submission to exchange abuse portal.'
    : 'No exchange deposit detected or insufficient evidence for escalation.';
  
  return {
    title,
    severity,
    briefDescription,
    detailedExplanation,
    whyNotApprovalExploit,
    whyNotDAppExploit,
    attackerInfrastructureSummary,
    exchangeEscalationReady: exchangeReportReady,
    exchangeEscalationReason,
  };
}

// ============================================
// CONVENIENCE FUNCTIONS
// ============================================

/**
 * Quick check if a set of wallets shows signs of seed compromise.
 * Use this for preliminary screening before full analysis.
 */
export function quickSeedCompromiseCheck(
  wallets: IncidentWallet[],
  config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG
): { isPossibleSeedCompromise: boolean; indicators: string[] } {
  const indicators: string[] = [];
  
  // Must have multiple wallets
  if (wallets.length < config.minWalletsForMultiWallet) {
    return { isPossibleSeedCompromise: false, indicators: [] };
  }
  
  // Check time proximity
  const timestamps = wallets.map(w => new Date(w.drainTimestamp).getTime()).sort((a, b) => a - b);
  const windowMinutes = (timestamps[timestamps.length - 1] - timestamps[0]) / (1000 * 60);
  
  if (windowMinutes <= config.drainTimeWindowMinutes) {
    indicators.push(`All drains within ${windowMinutes.toFixed(0)} minutes`);
  }
  
  // Check for shared destinations
  const allDestinations = new Set<string>();
  const destinationCounts = new Map<string, number>();
  
  for (const wallet of wallets) {
    for (const dest of wallet.destinationAddresses) {
      const key = dest.toLowerCase();
      allDestinations.add(key);
      destinationCounts.set(key, (destinationCounts.get(key) || 0) + 1);
    }
  }
  
  for (const [dest, count] of destinationCounts) {
    if (count > 1) {
      indicators.push(`Shared destination: ${dest.slice(0, 10)}... (${count} wallets)`);
    }
  }
  
  // Check for full balance drains
  const fullDrains = wallets.filter(w => w.wasFullBalance).length;
  if (fullDrains === wallets.length) {
    indicators.push('All wallets fully drained');
  }
  
  // Check for native asset drains
  const nativeDrains = wallets.filter(w => 
    w.drainedAssets.some(a => a.type === 'NATIVE')
  ).length;
  if (nativeDrains > 0) {
    indicators.push(`${nativeDrains} wallet(s) had native assets drained`);
  }
  
  const isPossibleSeedCompromise = 
    indicators.length >= 2 && 
    windowMinutes <= config.drainTimeWindowMinutes &&
    destinationCounts.size < wallets.length; // Some destination reuse
  
  return { isPossibleSeedCompromise, indicators };
}

/**
 * Format the analysis result for API response.
 */
export function formatIncidentAnalysisForAPI(result: IncidentAnalysisResult): object {
  return {
    incidentId: result.incidentId,
    analyzedAt: result.analyzedAt,
    
    summary: {
      title: result.displaySummary.title,
      severity: result.displaySummary.severity,
      briefDescription: result.displaySummary.briefDescription,
    },
    
    classification: {
      type: result.classification.classification,
      confidence: result.classification.confidence,
      confidenceScore: result.classification.confidenceScore,
      summary: result.classification.summary,
    },
    
    correlation: {
      walletCount: result.correlation.wallets.length,
      correlationStrength: result.correlation.correlationStrength,
      isMultiWalletAttack: result.correlation.isMultiWalletAttack,
      timeWindow: {
        start: result.correlation.timeAnalysis.earliestDrain,
        end: result.correlation.timeAnalysis.latestDrain,
        durationMinutes: result.correlation.timeAnalysis.totalWindowMinutes,
      },
    },
    
    attackerProfile: result.attackerProfile ? {
      walletCount: result.attackerProfile.wallets.length,
      totalStolenUSD: result.attackerProfile.stats.totalStolenUSD,
      chainsInvolved: result.attackerProfile.stats.chainsInvolved,
      confidence: result.attackerProfile.confidence,
      isScammer: result.attackerProfile.labelAsScammer,
    } : null,
    
    exchangeEscalation: {
      ready: result.displaySummary.exchangeEscalationReady,
      reason: result.displaySummary.exchangeEscalationReason,
      reportId: result.exchangeReport?.reportId || null,
    },
    
    recommendations: result.recommendations.map(r => ({
      priority: r.priority,
      action: r.action,
      reason: r.reason,
      timeframe: r.timeframe,
    })),
    
    overallConfidence: result.overallConfidence,
    confidenceLevel: result.confidenceLevel,
  };
}

export { analyzeIncident, quickSeedCompromiseCheck, formatIncidentAnalysisForAPI };

