// ============================================
// SOLANA INCIDENT ANALYZER
// ============================================
// Main orchestrator for Solana-focused incident correlation.
// Implements deterministic, rule-based detection for:
// - Seed/signer compromise
// - Sweeper bots
// - Attacker wallet clustering
// - Near Intents obfuscation
// - Exchange exit detection
//
// Forensic-grade precision with explicit thresholds.

import {
  SolanaIncidentWallet,
  SolanaIncidentAnalysisResult,
  SolanaAttackClassification,
  SolanaIncidentTimeline,
  SolanaTimelineEvent,
  SolanaRecommendation,
  SolanaMachineReadableOutput,
  NearIntentTransaction,
  generateSolanaIncidentId,
  SOLANA_CORRELATION_CONFIG,
  lamportsToSOL,
} from './solana-types';

import {
  evaluateSeedCompromise,
  evaluateSweeperBot,
  evaluateAttackerCluster,
  evaluateNearIntentsObfuscation,
  evaluateExchangeExit,
  calculateConfidenceScore,
  buildAttackerWalletList,
} from './solana-rules-engine';

// ============================================
// MAIN ANALYSIS FUNCTION
// ============================================

/**
 * Analyze a group of Solana wallets for incident correlation.
 * 
 * This function:
 * 1. Evaluates all 5 rule sets
 * 2. Calculates confidence scores
 * 3. Builds attacker profiles
 * 4. Generates timeline
 * 5. Produces recommendations
 */
export async function analyzeSolanaIncident(
  wallets: SolanaIncidentWallet[],
  nearIntents: NearIntentTransaction[] = [],
  userPriorExchangeInteractions: Set<string> = new Set()
): Promise<SolanaIncidentAnalysisResult> {
  const incidentId = generateSolanaIncidentId();
  const analyzedAt = new Date().toISOString();
  
  console.log(`[SolanaIncidentAnalyzer] Analyzing incident ${incidentId} with ${wallets.length} wallet(s)`);
  
  // ============================================
  // RULE SET 1: SEED COMPROMISE EVALUATION
  // ============================================
  const seedCompromiseEval = evaluateSeedCompromise(wallets);
  console.log(`[SolanaIncidentAnalyzer] Seed Compromise: ${seedCompromiseEval.allRulesPassed ? 'DETECTED' : 'NOT DETECTED'}`);
  
  // ============================================
  // RULE SET 2: SWEEPER BOT EVALUATION
  // ============================================
  const sweeperBotEval = evaluateSweeperBot(wallets);
  console.log(`[SolanaIncidentAnalyzer] Sweeper Bot: ${sweeperBotEval.isSweeperBot ? 'DETECTED' : 'NOT DETECTED'}`);
  
  // ============================================
  // RULE SET 3: ATTACKER CLUSTERING
  // ============================================
  const allDestinations = [...new Set(wallets.flatMap(w => w.destinations))];
  const clusterEvaluations = new Map<string, ReturnType<typeof evaluateAttackerCluster>>();
  
  for (const dest of allDestinations) {
    // Build incoming transfers for this destination
    const incomingTransfers = wallets
      .filter(w => w.destinations.includes(dest))
      .map(w => ({
        from: w.address,
        amount: w.preDrainBalance.solLamports - w.postDrainBalance.solLamports,
        timestamp: w.drainTimestamp,
        isDrainLike: w.drainPercentage >= 80,
      }));
    
    // Build outgoing transfers (would need additional data in production)
    const outgoingTransfers: Array<{ to: string; amount: bigint; timestamp: string }> = [];
    
    // Filter Near Intents for this destination
    const destNearIntents = nearIntents.filter(ni => ni.sourceWallet === dest);
    
    const clusterEval = evaluateAttackerCluster(
      dest,
      incomingTransfers,
      outgoingTransfers,
      destNearIntents
    );
    
    clusterEvaluations.set(dest, clusterEval);
  }
  
  // Build attacker wallets list
  const attackerWallets = buildAttackerWalletList(allDestinations, clusterEvaluations, nearIntents);
  console.log(`[SolanaIncidentAnalyzer] Attacker Wallets: ${attackerWallets.length} identified`);
  
  // ============================================
  // RULE SET 4: NEAR INTENTS OBFUSCATION
  // ============================================
  const drainedWallets = new Set(wallets.map(w => w.address));
  const attackerWalletAddresses = new Set(attackerWallets.map(a => a.address));
  const drainTimestamps = new Map(
    wallets.map(w => [w.address, new Date(w.drainTimestamp).getTime()])
  );
  
  const nearIntentsEval = evaluateNearIntentsObfuscation(
    nearIntents,
    drainedWallets,
    attackerWalletAddresses,
    drainTimestamps
  );
  console.log(`[SolanaIncidentAnalyzer] Near Intents Obfuscation: ${nearIntentsEval.isPostDrainObfuscation ? 'DETECTED' : 'NOT DETECTED'}`);
  
  // ============================================
  // RULE SET 5: EXCHANGE EXIT DETECTION
  // ============================================
  const aggregationWallets = attackerWallets
    .filter(a => a.role === 'AGGREGATION')
    .map(a => a.address);
  
  const exchangeExitEval = evaluateExchangeExit(
    allDestinations,
    nearIntents,
    aggregationWallets,
    userPriorExchangeInteractions
  );
  console.log(`[SolanaIncidentAnalyzer] Exchange Exit: ${exchangeExitEval.isExchangeExit ? 'DETECTED' : 'NOT DETECTED'}`);
  
  // ============================================
  // CALCULATE CONFIDENCE SCORE
  // ============================================
  const { score: confidenceScore, level: confidenceLevel } = calculateConfidenceScore(
    seedCompromiseEval,
    sweeperBotEval,
    nearIntentsEval,
    exchangeExitEval
  );
  console.log(`[SolanaIncidentAnalyzer] Confidence: ${confidenceScore} (${confidenceLevel})`);
  
  // ============================================
  // DETERMINE CLASSIFICATION
  // ============================================
  const classification = determineClassification(
    seedCompromiseEval,
    sweeperBotEval,
    wallets.length,
    confidenceLevel
  );
  
  // ============================================
  // BUILD TIMELINE
  // ============================================
  const timeline = buildTimeline(wallets, nearIntents, exchangeExitEval);
  
  // ============================================
  // GENERATE RECOMMENDATIONS
  // ============================================
  const recommendations = generateRecommendations(
    classification,
    seedCompromiseEval,
    sweeperBotEval,
    exchangeExitEval
  );
  
  // ============================================
  // BUILD USER MESSAGE
  // ============================================
  const userMessage = generateUserMessage(classification, confidenceLevel);
  
  // ============================================
  // BUILD MACHINE-READABLE OUTPUT
  // ============================================
  const machineReadable = buildMachineReadableOutput(
    incidentId,
    classification,
    confidenceScore,
    wallets,
    attackerWallets,
    nearIntentsEval,
    exchangeExitEval,
    seedCompromiseEval,
    sweeperBotEval
  );
  
  // Get first attacker cluster evaluation (if any)
  const firstAttackerCluster = attackerWallets.length > 0
    ? clusterEvaluations.get(attackerWallets[0].address)
    : undefined;
  
  return {
    incidentId,
    analyzedAt,
    classification,
    confidenceScore,
    confidenceLevel,
    affectedWallets: wallets,
    timeline,
    attackerWallets,
    attackerCluster: firstAttackerCluster,
    nearIntentsUsage: {
      detected: nearIntents.length > 0,
      evaluation: nearIntentsEval,
      intents: nearIntents,
    },
    exchangeExit: {
      detected: exchangeExitEval.isExchangeExit,
      evaluation: exchangeExitEval,
    },
    seedCompromiseEval,
    sweeperBotEval,
    recommendations,
    userMessage,
    machineReadable,
  };
}

// ============================================
// CLASSIFICATION DETERMINATION
// ============================================

function determineClassification(
  seedCompromise: ReturnType<typeof evaluateSeedCompromise>,
  sweeperBot: ReturnType<typeof evaluateSweeperBot>,
  walletCount: number,
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT'
): SolanaAttackClassification {
  // Priority 1: Seed/Signer Compromise (Multi-wallet)
  if (seedCompromise.allRulesPassed && walletCount >= 2) {
    return 'SEED_SIGNER_COMPROMISE_MULTI_WALLET';
  }
  
  // Priority 2: Sweeper Bot Attack
  if (sweeperBot.isSweeperBot) {
    return 'SWEEPER_BOT_ATTACK';
  }
  
  // Priority 3: Single Wallet Incident
  if (walletCount === 1) {
    return 'SINGLE_WALLET_INCIDENT';
  }
  
  // Default: Insufficient Evidence
  return 'INSUFFICIENT_EVIDENCE';
}

// ============================================
// TIMELINE BUILDER
// ============================================

function buildTimeline(
  wallets: SolanaIncidentWallet[],
  nearIntents: NearIntentTransaction[],
  exchangeExit: ReturnType<typeof evaluateExchangeExit>
): SolanaIncidentTimeline {
  const events: SolanaTimelineEvent[] = [];
  
  // Add drain events
  for (const wallet of wallets) {
    events.push({
      timestamp: wallet.drainTimestamp,
      slot: wallet.drainSlot,
      eventType: 'DRAIN',
      description: `Wallet ${wallet.address.slice(0, 8)}... drained (${wallet.drainPercentage.toFixed(1)}%)`,
      signature: wallet.drainTransactions[0]?.signature || '',
      walletAddress: wallet.address,
      significance: 'HIGH',
    });
  }
  
  // Add Near Intent events
  for (const intent of nearIntents) {
    events.push({
      timestamp: intent.timestamp,
      slot: 0, // Would need slot from intent
      eventType: 'NEAR_INTENT',
      description: `Near Intent: ${intent.purpose} to ${intent.targetChain}`,
      signature: intent.intentId,
      walletAddress: intent.sourceWallet,
      significance: 'MEDIUM',
    });
  }
  
  // Add exchange deposit event
  if (exchangeExit.isExchangeExit && exchangeExit.depositAddress) {
    events.push({
      timestamp: new Date().toISOString(), // Would need actual timestamp
      slot: 0,
      eventType: 'EXCHANGE_DEPOSIT',
      description: `Funds deposited to ${exchangeExit.exchangeName}`,
      signature: '',
      walletAddress: exchangeExit.depositAddress,
      significance: 'HIGH',
    });
  }
  
  // Sort by timestamp
  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  // Calculate timeline metadata
  const timestamps = events.map(e => new Date(e.timestamp).getTime());
  const firstDrainUTC = events.find(e => e.eventType === 'DRAIN')?.timestamp || new Date().toISOString();
  const lastDrainUTC = [...events].reverse().find(e => e.eventType === 'DRAIN')?.timestamp || firstDrainUTC;
  const totalDurationMinutes = timestamps.length >= 2
    ? (Math.max(...timestamps) - Math.min(...timestamps)) / (1000 * 60)
    : 0;
  
  return {
    firstDrainUTC,
    lastDrainUTC,
    totalDurationMinutes,
    events,
  };
}

// ============================================
// RECOMMENDATIONS GENERATOR
// ============================================

function generateRecommendations(
  classification: SolanaAttackClassification,
  seedCompromise: ReturnType<typeof evaluateSeedCompromise>,
  sweeperBot: ReturnType<typeof evaluateSweeperBot>,
  exchangeExit: ReturnType<typeof evaluateExchangeExit>
): SolanaRecommendation[] {
  const recommendations: SolanaRecommendation[] = [];
  
  // Seed/Signer Compromise recommendations
  if (classification === 'SEED_SIGNER_COMPROMISE_MULTI_WALLET') {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Stop using this wallet environment immediately',
      reason: 'Multiple wallets from the same seed were drained. The seed phrase or private keys have been compromised.',
    });
    
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Generate new seed phrase on secure device',
      reason: 'Create a new wallet using a hardware wallet or air-gapped device that has never been connected to the compromised environment.',
    });
    
    recommendations.push({
      priority: 'HIGH',
      action: 'Do not reuse browser or wallet instance',
      reason: 'The attack may have originated from malware or a compromised browser extension.',
    });
    
    recommendations.push({
      priority: 'HIGH',
      action: 'Scan all devices for malware',
      reason: 'The seed may have been stolen via keylogger, screen capture, or clipboard hijacking.',
    });
  }
  
  // Sweeper Bot recommendations
  if (sweeperBot.isSweeperBot) {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Abandon all wallets in this cluster',
      reason: 'Automated sweeper is actively monitoring these wallets. Any new funds will be immediately drained.',
    });
    
    recommendations.push({
      priority: 'HIGH',
      action: 'Do not attempt to recover remaining dust',
      reason: 'Sweeper bots leave minimal balance intentionally. Attempting to fund gas for recovery will trigger immediate drain.',
    });
  }
  
  // Exchange Exit recommendations
  if (exchangeExit.isEscalationEligible) {
    recommendations.push({
      priority: 'HIGH',
      action: `Report to ${exchangeExit.exchangeName || 'exchange'} abuse team`,
      reason: 'Stolen funds were deposited to a centralized exchange. Submit a report for potential fund recovery.',
    });
  }
  
  // General recommendations
  recommendations.push({
    priority: 'MEDIUM',
    action: 'Monitor attacker addresses',
    reason: 'Track the attacker\'s addresses for any fund movement that could aid in recovery.',
  });
  
  return recommendations;
}

// ============================================
// USER MESSAGE GENERATOR
// ============================================

function generateUserMessage(
  classification: SolanaAttackClassification,
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT'
): string {
  if (classification === 'SEED_SIGNER_COMPROMISE_MULTI_WALLET' && confidenceLevel === 'HIGH') {
    return 'This pattern indicates a signer or seed compromise. Stop using this wallet environment immediately.';
  }
  
  if (classification === 'SEED_SIGNER_COMPROMISE_MULTI_WALLET') {
    return 'This pattern is consistent with a potential seed compromise. Exercise extreme caution and consider abandoning this wallet environment.';
  }
  
  if (classification === 'SWEEPER_BOT_ATTACK') {
    return 'Automated sweeper behavior detected. These wallets are being actively monitored by attackers. Do not deposit any funds.';
  }
  
  if (classification === 'SINGLE_WALLET_INCIDENT') {
    return 'Single wallet incident detected. The cause may be approval-based drain, phishing, or isolated compromise.';
  }
  
  return 'Insufficient evidence to determine attack classification. Manual investigation is recommended.';
}

// ============================================
// MACHINE-READABLE OUTPUT BUILDER
// ============================================

function buildMachineReadableOutput(
  incidentId: string,
  classification: SolanaAttackClassification,
  confidenceScore: number,
  wallets: SolanaIncidentWallet[],
  attackerWallets: ReturnType<typeof buildAttackerWalletList>,
  nearIntentsEval: ReturnType<typeof evaluateNearIntentsObfuscation>,
  exchangeExitEval: ReturnType<typeof evaluateExchangeExit>,
  seedCompromiseEval: ReturnType<typeof evaluateSeedCompromise>,
  sweeperBotEval: ReturnType<typeof evaluateSweeperBot>
): SolanaMachineReadableOutput {
  return {
    version: '1.0.0',
    incidentId,
    classification,
    confidenceScore,
    wallets: wallets.map(w => ({
      address: w.address,
      drainPercentage: w.drainPercentage,
      drainedSOL: lamportsToSOL(w.preDrainBalance.solLamports - w.postDrainBalance.solLamports).toFixed(6),
      drainedUSD: w.preDrainBalance.totalValueUSD - w.postDrainBalance.totalValueUSD,
      drainTimestamp: w.drainTimestamp,
      signatures: w.drainTransactions.map(tx => tx.signature),
    })),
    attackerWallets: attackerWallets.map(a => ({
      address: a.address,
      role: a.role,
      victimCount: a.victimCount,
      confidence: a.confidence,
    })),
    nearIntentsUsed: nearIntentsEval.isPostDrainObfuscation,
    exchangeExit: exchangeExitEval.isExchangeExit,
    ruleResults: {
      seedCompromise: seedCompromiseEval.allRulesPassed,
      sweeperBot: sweeperBotEval.isSweeperBot,
      attackerCluster: attackerWallets.length > 0,
      nearObfuscation: nearIntentsEval.isPostDrainObfuscation,
      exchangeEscalation: exchangeExitEval.isEscalationEligible,
    },
  };
}

// ============================================
// QUICK SEED COMPROMISE CHECK
// ============================================

/**
 * Quick preliminary check for seed compromise indicators.
 * Use for screening before full analysis.
 */
export function quickSolanaSeedCompromiseCheck(
  wallets: SolanaIncidentWallet[]
): { isPossibleSeedCompromise: boolean; indicators: string[] } {
  const indicators: string[] = [];
  
  // Check wallet count
  if (wallets.length < SOLANA_CORRELATION_CONFIG.SEED_COMPROMISE.MIN_WALLETS) {
    return { isPossibleSeedCompromise: false, indicators: [] };
  }
  indicators.push(`${wallets.length} wallets affected`);
  
  // Check time proximity
  const timestamps = wallets
    .map(w => new Date(w.drainTimestamp).getTime())
    .sort((a, b) => a - b);
  
  const windowMinutes = (timestamps[timestamps.length - 1] - timestamps[0]) / (1000 * 60);
  if (windowMinutes <= SOLANA_CORRELATION_CONFIG.SEED_COMPROMISE.TIME_WINDOW_MAX_MINUTES) {
    indicators.push(`All drains within ${windowMinutes.toFixed(0)} minutes`);
  }
  
  // Check drain percentage
  const highDrainWallets = wallets.filter(
    w => w.drainPercentage >= SOLANA_CORRELATION_CONFIG.SEED_COMPROMISE.MIN_BALANCE_DRAIN_PERCENT
  );
  if (highDrainWallets.length === wallets.length) {
    indicators.push('All wallets experienced 80%+ balance drain');
  }
  
  // Check for native SOL drains
  const solDrainWallets = wallets.filter(w => w.wasNativeSOLDrained);
  if (solDrainWallets.length > 0) {
    indicators.push(`${solDrainWallets.length} wallet(s) had native SOL drained`);
  }
  
  // Check destination correlation
  const allDestinations = wallets.flatMap(w => w.destinations);
  const destCounts = new Map<string, number>();
  for (const dest of allDestinations) {
    destCounts.set(dest, (destCounts.get(dest) || 0) + 1);
  }
  const sharedDests = [...destCounts.entries()].filter(([_, c]) => c > 1);
  if (sharedDests.length > 0) {
    indicators.push(`Shared destination(s): ${sharedDests.length}`);
  }
  
  const isPossibleSeedCompromise = 
    indicators.length >= 3 &&
    windowMinutes <= SOLANA_CORRELATION_CONFIG.SEED_COMPROMISE.TIME_WINDOW_MAX_MINUTES &&
    highDrainWallets.length >= wallets.length * 0.8;
  
  return { isPossibleSeedCompromise, indicators };
}

// ============================================
// FORMAT FOR API
// ============================================

/**
 * Format the analysis result for API response.
 */
export function formatSolanaIncidentForAPI(result: SolanaIncidentAnalysisResult): object {
  return {
    incidentId: result.incidentId,
    analyzedAt: result.analyzedAt,
    
    // Attack Classification
    classification: result.classification,
    confidenceScore: result.confidenceScore,
    confidenceLevel: result.confidenceLevel,
    
    // Affected Wallets
    affectedWallets: result.affectedWallets.map(w => ({
      address: w.address,
      drainPercentage: w.drainPercentage,
      drainTimestamp: w.drainTimestamp,
      wasNativeSOLDrained: w.wasNativeSOLDrained,
    })),
    
    // Drain Timeline (UTC)
    timeline: {
      firstDrain: result.timeline.firstDrainUTC,
      lastDrain: result.timeline.lastDrainUTC,
      durationMinutes: result.timeline.totalDurationMinutes,
    },
    
    // Attacker Wallet(s)
    attackerWallets: result.attackerWallets.map(a => ({
      address: a.address,
      role: a.role,
      victimCount: a.victimCount,
      confidence: a.confidence,
      isLabeledScammer: a.isLabeledScammer,
    })),
    
    // Near Intent Usage
    nearIntentsUsed: result.nearIntentsUsage.detected,
    nearIntentDetails: result.nearIntentsUsage.detected ? {
      isObfuscation: result.nearIntentsUsage.evaluation?.isPostDrainObfuscation,
      intentCount: result.nearIntentsUsage.intents.length,
    } : null,
    
    // Exchange Exit
    exchangeExit: result.exchangeExit.detected,
    exchangeDetails: result.exchangeExit.detected ? {
      exchangeName: result.exchangeExit.evaluation?.exchangeName,
      depositAddress: result.exchangeExit.evaluation?.depositAddress,
      isEscalationEligible: result.exchangeExit.evaluation?.isEscalationEligible,
    } : null,
    
    // User Message (mandatory)
    userMessage: result.userMessage,
    
    // Recommendations
    recommendations: result.recommendations,
  };
}

