// ============================================
// SOLANA RULES ENGINE
// ============================================
// Explicit, rule-based detection for:
// - Rule Set 1: Multi-Wallet Seed Compromise
// - Rule Set 2: Sweeper Bot Detection
// - Rule Set 3: Attacker Wallet Clustering
// - Rule Set 4: Near Intents Obfuscation
// - Rule Set 5: Exchange Exit Detection
//
// Each rule has measurable thresholds.
// No heuristics - only deterministic logic.

import {
  SOLANA_CORRELATION_CONFIG,
  SolanaIncidentWallet,
  SolanaDrainTransaction,
  SeedCompromiseEvaluation,
  SweeperBotEvaluation,
  AttackerClusterEvaluation,
  NearIntentsEvaluation,
  ExchangeExitEvaluation,
  RuleResult,
  NearIntentTransaction,
  SolanaAttackerWallet,
  isKnownNFTProgram,
  isKnownDEXProgram,
  isKnownBridgeProgram,
  isKnownExchange,
  lamportsToSOL,
} from './solana-types';

const CONFIG = SOLANA_CORRELATION_CONFIG;

// ============================================
// RULE SET 1: MULTI-WALLET SEED COMPROMISE
// ============================================

/**
 * Evaluate all Rule Set 1 conditions for seed/signer compromise.
 * ALL rules must pass for classification.
 */
export function evaluateSeedCompromise(
  wallets: SolanaIncidentWallet[]
): SeedCompromiseEvaluation {
  // Evaluate each rule
  const rule1_1 = evaluateRule1_1_WalletCount(wallets);
  const rule1_2 = evaluateRule1_2_TimeCorrelation(wallets);
  const rule1_3 = evaluateRule1_3_DrainPattern(wallets);
  const rule1_4 = evaluateRule1_4_AbsenceOfLegitCause(wallets);
  const rule1_5 = evaluateRule1_5_DestinationCorrelation(wallets);
  
  // ALL rules must pass
  const allRulesPassed = 
    rule1_1.passed &&
    rule1_2.passed &&
    rule1_3.passed &&
    rule1_4.passed &&
    rule1_5.passed;
  
  // Determine confidence level
  const totalScore = rule1_1.score + rule1_2.score + rule1_3.score + rule1_4.score + rule1_5.score;
  let confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT';
  
  if (allRulesPassed && totalScore >= CONFIG.CONFIDENCE.HIGH_THRESHOLD) {
    confidenceLevel = 'HIGH';
  } else if (allRulesPassed && totalScore >= CONFIG.CONFIDENCE.MEDIUM_THRESHOLD) {
    confidenceLevel = 'MEDIUM';
  } else if (allRulesPassed) {
    confidenceLevel = 'LOW';
  } else {
    confidenceLevel = 'INSUFFICIENT';
  }
  
  return {
    rule1_1_walletCount: rule1_1,
    rule1_2_timeCorrelation: rule1_2,
    rule1_3_drainPattern: rule1_3,
    rule1_4_absenceOfLegitCause: rule1_4,
    rule1_5_destinationCorrelation: rule1_5,
    allRulesPassed,
    classification: allRulesPassed ? 'SEED_SIGNER_COMPROMISE' : 'INSUFFICIENT_EVIDENCE',
    confidenceLevel,
  };
}

/**
 * Rule 1.1: Wallet Count
 * - ≥ 2 distinct Solana wallets
 * - No shared token accounts between them
 * - No on-chain authority relationship
 */
function evaluateRule1_1_WalletCount(wallets: SolanaIncidentWallet[]): RuleResult {
  const evidence: string[] = [];
  let passed = true;
  
  // Check minimum wallet count
  if (wallets.length < CONFIG.SEED_COMPROMISE.MIN_WALLETS) {
    passed = false;
    evidence.push(`Only ${wallets.length} wallet(s) - minimum required: ${CONFIG.SEED_COMPROMISE.MIN_WALLETS}`);
  } else {
    evidence.push(`${wallets.length} distinct wallets detected`);
  }
  
  // Check for shared token accounts
  const allTokenAccounts = wallets.flatMap(w => w.tokenAccounts);
  const tokenAccountCounts = new Map<string, number>();
  for (const account of allTokenAccounts) {
    tokenAccountCounts.set(account, (tokenAccountCounts.get(account) || 0) + 1);
  }
  const sharedAccounts = [...tokenAccountCounts.entries()].filter(([_, count]) => count > 1);
  
  if (sharedAccounts.length > 0) {
    passed = false;
    evidence.push(`Shared token accounts detected: ${sharedAccounts.length}`);
  } else {
    evidence.push('No shared token accounts between wallets');
  }
  
  // Check for authority relationships
  const allAuthorities = wallets.flatMap(w => w.authorities.map(a => a.authority));
  const walletAddresses = new Set(wallets.map(w => w.address));
  const authorityOverlap = allAuthorities.filter(a => walletAddresses.has(a));
  
  if (authorityOverlap.length > 0) {
    passed = false;
    evidence.push(`On-chain authority relationship detected: ${authorityOverlap.length} overlaps`);
  } else {
    evidence.push('No on-chain authority relationships between wallets');
  }
  
  return {
    ruleName: 'Rule 1.1: Wallet Count',
    passed,
    score: passed ? 10 : 0,
    evidence,
    metrics: {
      walletCount: wallets.length,
      sharedTokenAccounts: sharedAccounts.length,
      authorityOverlaps: authorityOverlap.length,
    },
  };
}

/**
 * Rule 1.2: Time Correlation
 * - Drain events occur within ≤ 90 minutes
 * - 30 minutes = strong signal
 */
function evaluateRule1_2_TimeCorrelation(wallets: SolanaIncidentWallet[]): RuleResult {
  const evidence: string[] = [];
  
  // Get all drain timestamps
  const timestamps = wallets
    .map(w => new Date(w.drainTimestamp).getTime())
    .sort((a, b) => a - b);
  
  if (timestamps.length < 2) {
    return {
      ruleName: 'Rule 1.2: Time Correlation',
      passed: false,
      score: 0,
      evidence: ['Insufficient wallets for time correlation'],
    };
  }
  
  const earliestMs = timestamps[0];
  const latestMs = timestamps[timestamps.length - 1];
  const windowMinutes = (latestMs - earliestMs) / (1000 * 60);
  
  // Check against thresholds
  const withinMaxWindow = windowMinutes <= CONFIG.SEED_COMPROMISE.TIME_WINDOW_MAX_MINUTES;
  const withinStrongWindow = windowMinutes <= CONFIG.SEED_COMPROMISE.TIME_WINDOW_STRONG_MINUTES;
  
  if (withinStrongWindow) {
    evidence.push(`All drains within ${windowMinutes.toFixed(1)} minutes (STRONG signal - under ${CONFIG.SEED_COMPROMISE.TIME_WINDOW_STRONG_MINUTES} min threshold)`);
  } else if (withinMaxWindow) {
    evidence.push(`All drains within ${windowMinutes.toFixed(1)} minutes (within ${CONFIG.SEED_COMPROMISE.TIME_WINDOW_MAX_MINUTES} min threshold)`);
  } else {
    evidence.push(`Drains spread over ${windowMinutes.toFixed(1)} minutes (exceeds ${CONFIG.SEED_COMPROMISE.TIME_WINDOW_MAX_MINUTES} min threshold)`);
  }
  
  // Calculate score based on time proximity
  let score = 0;
  if (withinStrongWindow) {
    score = 20; // Strong signal
  } else if (withinMaxWindow) {
    score = 15; // Within threshold
  }
  
  return {
    ruleName: 'Rule 1.2: Time Correlation',
    passed: withinMaxWindow,
    score,
    evidence,
    metrics: {
      windowMinutes,
      withinStrongWindow,
      withinMaxWindow,
      earliestDrain: new Date(earliestMs).toISOString(),
      latestDrain: new Date(latestMs).toISOString(),
    },
  };
}

/**
 * Rule 1.3: Drain Pattern
 * For EACH wallet:
 * - ≥ 80% of total SOL + SPL balance removed
 * - Native SOL transferred
 * - Simple transfers (system_program::transfer or direct SPL)
 * - No complex program interaction
 */
function evaluateRule1_3_DrainPattern(wallets: SolanaIncidentWallet[]): RuleResult {
  const evidence: string[] = [];
  let allWalletsPass = true;
  let nativeSOLDrainedCount = 0;
  let simpleTransferCount = 0;
  
  for (const wallet of wallets) {
    const walletEvidence: string[] = [];
    let walletPasses = true;
    
    // Check drain percentage
    if (wallet.drainPercentage < CONFIG.SEED_COMPROMISE.MIN_BALANCE_DRAIN_PERCENT) {
      walletPasses = false;
      walletEvidence.push(`Drain: ${wallet.drainPercentage.toFixed(1)}% (below ${CONFIG.SEED_COMPROMISE.MIN_BALANCE_DRAIN_PERCENT}% threshold)`);
    } else {
      walletEvidence.push(`Drain: ${wallet.drainPercentage.toFixed(1)}%`);
    }
    
    // Check if native SOL was drained
    if (!wallet.wasNativeSOLDrained) {
      walletPasses = false;
      walletEvidence.push('No native SOL drained');
    } else {
      nativeSOLDrainedCount++;
      walletEvidence.push('Native SOL drained');
    }
    
    // Check for simple transfers
    if (!wallet.wasSimpleTransfer) {
      walletPasses = false;
      walletEvidence.push('Complex program interaction detected');
    } else {
      simpleTransferCount++;
      walletEvidence.push('Simple transfer pattern');
    }
    
    if (!walletPasses) {
      allWalletsPass = false;
    }
    
    evidence.push(`${wallet.address.slice(0, 8)}...: ${walletEvidence.join(', ')}`);
  }
  
  // Calculate score
  let score = 0;
  if (allWalletsPass) {
    score += CONFIG.CONFIDENCE.MULTI_WALLET_DRAIN;
    if (nativeSOLDrainedCount === wallets.length) {
      score += CONFIG.CONFIDENCE.NATIVE_SOL_DRAINED;
    }
  }
  
  return {
    ruleName: 'Rule 1.3: Drain Pattern',
    passed: allWalletsPass,
    score,
    evidence,
    metrics: {
      walletsEvaluated: wallets.length,
      walletsPassed: wallets.filter(w => 
        w.drainPercentage >= CONFIG.SEED_COMPROMISE.MIN_BALANCE_DRAIN_PERCENT &&
        w.wasNativeSOLDrained &&
        w.wasSimpleTransfer
      ).length,
      nativeSOLDrainedCount,
      simpleTransferCount,
    },
  };
}

/**
 * Rule 1.4: Absence of Legitimate Cause
 * - No interaction with known NFT/DEX/Bridge programs
 * - No shared malicious program invocation
 * - No shared approval-style authority change
 */
function evaluateRule1_4_AbsenceOfLegitCause(wallets: SolanaIncidentWallet[]): RuleResult {
  const evidence: string[] = [];
  let passed = true;
  
  // Check for NFT/DEX/Bridge program interactions
  const legitimateInteractions: string[] = [];
  
  for (const wallet of wallets) {
    for (const interaction of wallet.programInteractions) {
      if (isKnownNFTProgram(interaction.programId)) {
        legitimateInteractions.push(`NFT program: ${interaction.programId.slice(0, 8)}...`);
      }
      if (isKnownDEXProgram(interaction.programId)) {
        legitimateInteractions.push(`DEX program: ${interaction.programId.slice(0, 8)}...`);
      }
      if (isKnownBridgeProgram(interaction.programId)) {
        legitimateInteractions.push(`Bridge program: ${interaction.programId.slice(0, 8)}...`);
      }
    }
  }
  
  if (legitimateInteractions.length > 0) {
    passed = false;
    evidence.push(`Legitimate program interactions detected: ${[...new Set(legitimateInteractions)].join(', ')}`);
  } else {
    evidence.push('No interaction with known NFT/DEX/Bridge programs');
  }
  
  // Check for shared malicious program invocation
  const programCounts = new Map<string, number>();
  for (const wallet of wallets) {
    const programs = new Set(wallet.programInteractions.map(p => p.programId));
    for (const program of programs) {
      programCounts.set(program, (programCounts.get(program) || 0) + 1);
    }
  }
  
  const sharedPrograms = [...programCounts.entries()]
    .filter(([_, count]) => count > 1)
    .filter(([programId]) => 
      programId !== '11111111111111111111111111111111' && // System program
      programId !== 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' // Token program
    );
  
  if (sharedPrograms.length > 0) {
    // This could be a contract exploit, not seed compromise
    evidence.push(`Shared program invocations detected: ${sharedPrograms.map(([p]) => p.slice(0, 8) + '...').join(', ')}`);
    // Note: Don't fail the rule, but record it
  } else {
    evidence.push('No shared malicious program invocation');
  }
  
  // Check for authority changes
  const authorityChanges = wallets.filter(w => 
    w.authorities.some(a => a.type === 'DELEGATE' || a.type === 'CLOSE_AUTHORITY')
  );
  
  if (authorityChanges.length > 0) {
    evidence.push(`Authority changes detected in ${authorityChanges.length} wallet(s)`);
  } else {
    evidence.push('No approval-style authority changes');
  }
  
  return {
    ruleName: 'Rule 1.4: Absence of Legitimate Cause',
    passed,
    score: passed ? 15 : 0,
    evidence,
    metrics: {
      legitimateInteractionCount: legitimateInteractions.length,
      sharedProgramCount: sharedPrograms.length,
      authorityChangeCount: authorityChanges.length,
    },
  };
}

/**
 * Rule 1.5: Destination Correlation
 * At least ONE of:
 * - Same destination wallet
 * - Same destination cluster
 * - Same Near Intent routing path
 */
function evaluateRule1_5_DestinationCorrelation(
  wallets: SolanaIncidentWallet[],
  nearIntents?: NearIntentTransaction[]
): RuleResult {
  const evidence: string[] = [];
  
  // Collect all destinations
  const allDestinations = wallets.flatMap(w => w.destinations);
  const destinationCounts = new Map<string, number>();
  
  for (const dest of allDestinations) {
    destinationCounts.set(dest, (destinationCounts.get(dest) || 0) + 1);
  }
  
  // Check for shared destinations
  const sharedDestinations = [...destinationCounts.entries()].filter(([_, count]) => count > 1);
  
  let hasSharedDestination = sharedDestinations.length > 0;
  let hasNearIntentPath = false;
  
  if (hasSharedDestination) {
    evidence.push(`Shared destination(s): ${sharedDestinations.map(([d, c]) => `${d.slice(0, 8)}... (${c} wallets)`).join(', ')}`);
  }
  
  // Check for Near Intent routing
  if (nearIntents && nearIntents.length > 0) {
    const walletAddresses = new Set(wallets.map(w => w.address));
    const nearIntentsFromVictims = nearIntents.filter(ni => walletAddresses.has(ni.sourceWallet));
    
    if (nearIntentsFromVictims.length > 1) {
      hasNearIntentPath = true;
      evidence.push(`Near Intent routing detected from ${nearIntentsFromVictims.length} victim wallet(s)`);
    }
  }
  
  const passed = hasSharedDestination || hasNearIntentPath;
  
  if (!passed) {
    evidence.push('No destination correlation detected');
  }
  
  return {
    ruleName: 'Rule 1.5: Destination Correlation',
    passed,
    score: passed ? CONFIG.CONFIDENCE.DESTINATION_REUSE : 0,
    evidence,
    metrics: {
      uniqueDestinations: destinationCounts.size,
      sharedDestinationCount: sharedDestinations.length,
      hasNearIntentPath,
    },
  };
}

// ============================================
// RULE SET 2: SWEEPER BOT DETECTION
// ============================================

/**
 * Evaluate all Rule Set 2 conditions for sweeper bot behavior.
 * ≥ 2 rules must match for classification.
 */
export function evaluateSweeperBot(
  wallets: SolanaIncidentWallet[]
): SweeperBotEvaluation {
  const rule2_1 = evaluateRule2_1_AutomationSignature(wallets);
  const rule2_2 = evaluateRule2_2_BalanceMaximization(wallets);
  const rule2_3 = evaluateRule2_3_NoHumanVariability(wallets);
  
  const rulesMatched = [rule2_1, rule2_2, rule2_3].filter(r => r.passed).length;
  
  return {
    rule2_1_automationSignature: rule2_1,
    rule2_2_balanceMaximization: rule2_2,
    rule2_3_noHumanVariability: rule2_3,
    rulesMatched,
    isSweeperBot: rulesMatched >= CONFIG.SWEEPER.MIN_RULES_FOR_DETECTION,
  };
}

/**
 * Rule 2.1: Automation Signature
 * - Transactions triggered within seconds of balance receipt
 * - Consistent fee payer across wallets
 * - Identical instruction ordering across drains
 */
function evaluateRule2_1_AutomationSignature(wallets: SolanaIncidentWallet[]): RuleResult {
  const evidence: string[] = [];
  let automationSignals = 0;
  
  // Check trigger delay
  const rapidTriggers = wallets.filter(w =>
    w.drainTransactions.some(tx =>
      tx.secondsSinceLastInbound !== undefined &&
      tx.secondsSinceLastInbound <= CONFIG.SWEEPER.TRIGGER_DELAY_MAX_SECONDS
    )
  );
  
  if (rapidTriggers.length === wallets.length) {
    automationSignals++;
    evidence.push(`All drains triggered within ${CONFIG.SWEEPER.TRIGGER_DELAY_MAX_SECONDS}s of balance receipt`);
  } else if (rapidTriggers.length > 0) {
    evidence.push(`${rapidTriggers.length}/${wallets.length} wallets had rapid trigger (<${CONFIG.SWEEPER.TRIGGER_DELAY_MAX_SECONDS}s)`);
  }
  
  // Check fee payer consistency
  const feePayers = new Set(wallets.map(w => w.feePayer));
  if (feePayers.size === 1 && wallets.length > 1) {
    automationSignals++;
    evidence.push(`Consistent fee payer across all wallets: ${[...feePayers][0].slice(0, 8)}...`);
  }
  
  // Check instruction ordering
  const instructionPatterns = wallets.map(w => {
    const pattern = w.drainTransactions.map(tx => `${tx.programId}:${tx.instructionCount}`).join('|');
    return pattern;
  });
  
  const uniquePatterns = new Set(instructionPatterns);
  if (uniquePatterns.size === 1 && wallets.length > 1) {
    automationSignals++;
    evidence.push('Identical instruction ordering across all drains');
  }
  
  return {
    ruleName: 'Rule 2.1: Automation Signature',
    passed: automationSignals >= 2,
    score: automationSignals >= 2 ? CONFIG.CONFIDENCE.AUTOMATED_SWEEPER : 0,
    evidence,
    metrics: {
      rapidTriggerCount: rapidTriggers.length,
      uniqueFeePayers: feePayers.size,
      uniqueInstructionPatterns: uniquePatterns.size,
      automationSignals,
    },
  };
}

/**
 * Rule 2.2: Balance Maximization
 * - Leaves < 0.002 SOL (rent minimum buffer)
 * - Transfers dust-adjusted maximum possible balance
 */
function evaluateRule2_2_BalanceMaximization(wallets: SolanaIncidentWallet[]): RuleResult {
  const evidence: string[] = [];
  const rentBufferLamports = BigInt(Math.floor(CONFIG.SWEEPER.RENT_BUFFER_SOL * 1_000_000_000));
  
  // Check if all wallets left minimal balance
  const maximalDrains = wallets.filter(w =>
    w.postDrainBalance.solLamports <= rentBufferLamports
  );
  
  if (maximalDrains.length === wallets.length) {
    evidence.push(`All wallets drained to rent-exempt minimum (<${CONFIG.SWEEPER.RENT_BUFFER_SOL} SOL)`);
  } else {
    evidence.push(`${maximalDrains.length}/${wallets.length} wallets drained to minimum`);
  }
  
  // Check drain percentages
  const highDrainWallets = wallets.filter(w => w.drainPercentage >= 99);
  if (highDrainWallets.length === wallets.length) {
    evidence.push('All wallets experienced 99%+ balance extraction');
  }
  
  const passed = maximalDrains.length === wallets.length && highDrainWallets.length === wallets.length;
  
  return {
    ruleName: 'Rule 2.2: Balance Maximization',
    passed,
    score: passed ? 10 : 0,
    evidence,
    metrics: {
      maximalDrainCount: maximalDrains.length,
      highDrainCount: highDrainWallets.length,
      totalWallets: wallets.length,
    },
  };
}

/**
 * Rule 2.3: No Human Variability
 * - No memo usage
 * - No delayed execution
 * - No partial transfers
 */
function evaluateRule2_3_NoHumanVariability(wallets: SolanaIncidentWallet[]): RuleResult {
  const evidence: string[] = [];
  let signals = 0;
  
  // Check for memo usage
  const memoTransactions = wallets.filter(w =>
    w.drainTransactions.some(tx => tx.hasMemo)
  );
  
  if (memoTransactions.length === 0) {
    signals++;
    evidence.push('No memo usage detected');
  } else {
    evidence.push(`Memos detected in ${memoTransactions.length} wallet(s)`);
  }
  
  // Check for delayed execution (variance in timing)
  const timestamps = wallets.map(w => new Date(w.drainTimestamp).getTime()).sort((a, b) => a - b);
  if (timestamps.length >= 2) {
    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }
    
    // Low variance = automation
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    const coefficientOfVariation = avgInterval > 0 ? stdDev / avgInterval : 0;
    
    if (coefficientOfVariation < 0.3) { // Low variance
      signals++;
      evidence.push(`Consistent timing pattern (CV: ${coefficientOfVariation.toFixed(3)})`);
    }
  }
  
  // Check for partial transfers
  const partialTransfers = wallets.filter(w => w.drainPercentage < 95);
  if (partialTransfers.length === 0) {
    signals++;
    evidence.push('No partial transfers - all wallets fully drained');
  } else {
    evidence.push(`Partial transfers in ${partialTransfers.length} wallet(s)`);
  }
  
  return {
    ruleName: 'Rule 2.3: No Human Variability',
    passed: signals >= 2,
    score: signals >= 2 ? 5 : 0,
    evidence,
    metrics: {
      memoCount: memoTransactions.length,
      partialTransferCount: partialTransfers.length,
      signals,
    },
  };
}

// ============================================
// RULE SET 3: ATTACKER WALLET CLUSTERING
// ============================================

/**
 * Evaluate if a wallet is attacker infrastructure.
 * ≥ 2 rules must match for classification.
 */
export function evaluateAttackerCluster(
  destinationWallet: string,
  incomingTransfers: Array<{
    from: string;
    amount: bigint;
    timestamp: string;
    isDrainLike: boolean;
  }>,
  outgoingTransfers: Array<{
    to: string;
    amount: bigint;
    timestamp: string;
  }>,
  nearIntents: NearIntentTransaction[]
): AttackerClusterEvaluation {
  const rule3_1 = evaluateRule3_1_VictimAggregation(incomingTransfers);
  const rule3_2 = evaluateRule3_2_NoLegitimateRole(destinationWallet);
  const rule3_3 = evaluateRule3_3_LaunderingBehavior(outgoingTransfers, nearIntents);
  
  const rulesMatched = [rule3_1, rule3_2, rule3_3].filter(r => r.passed).length;
  
  // Calculate cluster confidence
  let clusterConfidence = 0;
  if (rule3_1.passed) clusterConfidence += 40;
  if (rule3_2.passed) clusterConfidence += 30;
  if (rule3_3.passed) clusterConfidence += 30;
  
  return {
    rule3_1_victimAggregation: rule3_1,
    rule3_2_noLegitimateRole: rule3_2,
    rule3_3_launderingBehavior: rule3_3,
    rulesMatched,
    isAttackerInfrastructure: rulesMatched >= CONFIG.ATTACKER_CLUSTER.MIN_RULES_FOR_CLASSIFICATION,
    clusterConfidence,
  };
}

/**
 * Rule 3.1: Victim Aggregation
 * - Receives funds from ≥ 2 unrelated wallets
 * - Within ≤ 24 hours
 * - With drain-like characteristics
 */
function evaluateRule3_1_VictimAggregation(
  incomingTransfers: Array<{
    from: string;
    amount: bigint;
    timestamp: string;
    isDrainLike: boolean;
  }>
): RuleResult {
  const evidence: string[] = [];
  
  // Filter drain-like transfers
  const drainLikeTransfers = incomingTransfers.filter(t => t.isDrainLike);
  const uniqueSources = new Set(drainLikeTransfers.map(t => t.from));
  
  if (uniqueSources.size < CONFIG.ATTACKER_CLUSTER.MIN_VICTIM_COUNT) {
    evidence.push(`Only ${uniqueSources.size} unique source(s) - minimum required: ${CONFIG.ATTACKER_CLUSTER.MIN_VICTIM_COUNT}`);
    return {
      ruleName: 'Rule 3.1: Victim Aggregation',
      passed: false,
      score: 0,
      evidence,
    };
  }
  
  // Check time window
  const timestamps = drainLikeTransfers.map(t => new Date(t.timestamp).getTime()).sort((a, b) => a - b);
  const windowHours = (timestamps[timestamps.length - 1] - timestamps[0]) / (1000 * 60 * 60);
  
  const withinWindow = windowHours <= CONFIG.ATTACKER_CLUSTER.AGGREGATION_WINDOW_HOURS;
  
  if (withinWindow) {
    evidence.push(`Received from ${uniqueSources.size} wallets within ${windowHours.toFixed(1)} hours`);
  } else {
    evidence.push(`Transfers spread over ${windowHours.toFixed(1)} hours (exceeds ${CONFIG.ATTACKER_CLUSTER.AGGREGATION_WINDOW_HOURS}h threshold)`);
  }
  
  return {
    ruleName: 'Rule 3.1: Victim Aggregation',
    passed: uniqueSources.size >= CONFIG.ATTACKER_CLUSTER.MIN_VICTIM_COUNT && withinWindow,
    score: withinWindow ? 40 : 0,
    evidence,
    metrics: {
      uniqueSources: uniqueSources.size,
      drainLikeCount: drainLikeTransfers.length,
      windowHours,
    },
  };
}

/**
 * Rule 3.2: No Legitimate Program Role
 * - Not a known exchange hot wallet
 * - Not a bridge vault
 * - Not a protocol treasury
 */
function evaluateRule3_2_NoLegitimateRole(wallet: string): RuleResult {
  const evidence: string[] = [];
  
  // Check if it's a known exchange
  const exchangeName = isKnownExchange(wallet);
  if (exchangeName) {
    evidence.push(`Known exchange hot wallet: ${exchangeName}`);
    return {
      ruleName: 'Rule 3.2: No Legitimate Role',
      passed: false,
      score: 0,
      evidence,
    };
  }
  
  // Check if it's a known bridge vault
  if (isKnownBridgeProgram(wallet)) {
    evidence.push('Known bridge vault');
    return {
      ruleName: 'Rule 3.2: No Legitimate Role',
      passed: false,
      score: 0,
      evidence,
    };
  }
  
  evidence.push('Not identified as known exchange, bridge, or protocol treasury');
  
  return {
    ruleName: 'Rule 3.2: No Legitimate Role',
    passed: true,
    score: 30,
    evidence,
  };
}

/**
 * Rule 3.3: Laundering Behavior
 * At least one:
 * - Forwards funds to Near Intent contracts
 * - Splits funds before bridging
 * - Consolidates then bridges
 */
function evaluateRule3_3_LaunderingBehavior(
  outgoingTransfers: Array<{
    to: string;
    amount: bigint;
    timestamp: string;
  }>,
  nearIntents: NearIntentTransaction[]
): RuleResult {
  const evidence: string[] = [];
  let signals = 0;
  
  // Check for Near Intent usage
  if (nearIntents.length > 0) {
    signals++;
    evidence.push(`${nearIntents.length} Near Intent transaction(s) detected`);
  }
  
  // Check for fund splitting
  const uniqueDestinations = new Set(outgoingTransfers.map(t => t.to));
  if (uniqueDestinations.size >= 3 && outgoingTransfers.length >= 3) {
    signals++;
    evidence.push(`Funds split to ${uniqueDestinations.size} different destinations`);
  }
  
  // Check for consolidation pattern (many in, few out)
  // This would need incoming transfers context, simplified here
  if (outgoingTransfers.length > 0 && outgoingTransfers.length <= 2) {
    evidence.push('Consolidation pattern detected (few outgoing transfers)');
  }
  
  return {
    ruleName: 'Rule 3.3: Laundering Behavior',
    passed: signals >= 1,
    score: signals >= 1 ? 30 : 0,
    evidence,
    metrics: {
      nearIntentCount: nearIntents.length,
      uniqueDestinations: uniqueDestinations.size,
      signals,
    },
  };
}

// ============================================
// RULE SET 4: NEAR INTENTS OBFUSCATION
// ============================================

/**
 * Evaluate Near Intents usage for malicious obfuscation.
 * ALL rules must apply for classification.
 */
export function evaluateNearIntentsObfuscation(
  nearIntents: NearIntentTransaction[],
  drainedWallets: Set<string>,
  attackerWallets: Set<string>,
  drainTimestamps: Map<string, number> // wallet -> timestamp in ms
): NearIntentsEvaluation {
  const rule4_1 = evaluateRule4_1_SourceContext(nearIntents, drainedWallets, attackerWallets);
  const rule4_2 = evaluateRule4_2_IntentPurpose(nearIntents);
  const rule4_3 = evaluateRule4_3_TemporalProximity(nearIntents, drainTimestamps);
  
  const allRulesPassed = rule4_1.passed && rule4_2.passed && rule4_3.passed;
  
  return {
    rule4_1_sourceContext: rule4_1,
    rule4_2_intentPurpose: rule4_2,
    rule4_3_temporalProximity: rule4_3,
    allRulesPassed,
    isPostDrainObfuscation: allRulesPassed,
  };
}

/**
 * Rule 4.1: Source Context
 * Funds originate from:
 * - Recently drained Solana wallet
 * - Wallet tagged as attacker infrastructure
 */
function evaluateRule4_1_SourceContext(
  nearIntents: NearIntentTransaction[],
  drainedWallets: Set<string>,
  attackerWallets: Set<string>
): RuleResult {
  const evidence: string[] = [];
  
  const fromDrainedWallet = nearIntents.filter(ni => drainedWallets.has(ni.sourceWallet));
  const fromAttackerWallet = nearIntents.filter(ni => attackerWallets.has(ni.sourceWallet));
  
  const relevantIntents = [...new Set([...fromDrainedWallet, ...fromAttackerWallet])];
  
  if (fromDrainedWallet.length > 0) {
    evidence.push(`${fromDrainedWallet.length} intent(s) from recently drained wallet(s)`);
  }
  
  if (fromAttackerWallet.length > 0) {
    evidence.push(`${fromAttackerWallet.length} intent(s) from attacker infrastructure`);
  }
  
  const passed = relevantIntents.length > 0;
  
  if (!passed) {
    evidence.push('No Near Intents from drained or attacker wallets');
  }
  
  return {
    ruleName: 'Rule 4.1: Source Context',
    passed,
    score: passed ? CONFIG.CONFIDENCE.NEAR_INTENTS_POST_DRAIN : 0,
    evidence,
    metrics: {
      fromDrainedCount: fromDrainedWallet.length,
      fromAttackerCount: fromAttackerWallet.length,
    },
  };
}

/**
 * Rule 4.2: Intent Purpose
 * Intent used for:
 * - Cross-chain transfer
 * - Asset obfuscation
 * - Exchange routing
 * NOT simple user-initiated bridging
 */
function evaluateRule4_2_IntentPurpose(nearIntents: NearIntentTransaction[]): RuleResult {
  const evidence: string[] = [];
  
  const obfuscationIntents = nearIntents.filter(ni =>
    ni.purpose === 'CROSS_CHAIN_TRANSFER' ||
    ni.purpose === 'ASSET_OBFUSCATION' ||
    ni.purpose === 'EXCHANGE_ROUTING'
  );
  
  const userBridgeIntents = nearIntents.filter(ni => ni.purpose === 'USER_BRIDGE');
  
  if (obfuscationIntents.length > 0) {
    evidence.push(`${obfuscationIntents.length} intent(s) for cross-chain/obfuscation/exchange routing`);
  }
  
  if (userBridgeIntents.length > 0) {
    evidence.push(`${userBridgeIntents.length} user-initiated bridge intent(s) (excluded)`);
  }
  
  const passed = obfuscationIntents.length > 0;
  
  return {
    ruleName: 'Rule 4.2: Intent Purpose',
    passed,
    score: passed ? 5 : 0,
    evidence,
    metrics: {
      obfuscationIntentCount: obfuscationIntents.length,
      userBridgeCount: userBridgeIntents.length,
    },
  };
}

/**
 * Rule 4.3: Temporal Proximity
 * Near Intent invoked ≤ 60 minutes post-drain
 */
function evaluateRule4_3_TemporalProximity(
  nearIntents: NearIntentTransaction[],
  drainTimestamps: Map<string, number>
): RuleResult {
  const evidence: string[] = [];
  
  const recentIntents = nearIntents.filter(ni => {
    const drainTime = drainTimestamps.get(ni.sourceWallet);
    if (!drainTime) return false;
    
    return ni.minutesAfterDrain <= CONFIG.NEAR_INTENTS.POST_DRAIN_WINDOW_MINUTES;
  });
  
  if (recentIntents.length > 0) {
    evidence.push(`${recentIntents.length} intent(s) within ${CONFIG.NEAR_INTENTS.POST_DRAIN_WINDOW_MINUTES} minutes of drain`);
  } else {
    evidence.push(`No intents within ${CONFIG.NEAR_INTENTS.POST_DRAIN_WINDOW_MINUTES} minutes post-drain window`);
  }
  
  const passed = recentIntents.length > 0;
  
  return {
    ruleName: 'Rule 4.3: Temporal Proximity',
    passed,
    score: passed ? 5 : 0,
    evidence,
    metrics: {
      recentIntentCount: recentIntents.length,
      totalIntentCount: nearIntents.length,
    },
  };
}

// ============================================
// RULE SET 5: EXCHANGE EXIT DETECTION
// ============================================

/**
 * Detect exchange parking behavior.
 */
export function evaluateExchangeExit(
  destinations: string[],
  nearIntents: NearIntentTransaction[],
  aggregationWallets: string[],
  userPriorExchangeInteractions: Set<string>
): ExchangeExitEvaluation {
  // Check for known exchange destinations
  for (const dest of destinations) {
    const exchangeName = isKnownExchange(dest);
    if (exchangeName) {
      // Check routing path
      const routingPath: string[] = [];
      
      // Check if came via Near Intents
      const viaIntent = nearIntents.some(ni => ni.targetChain !== 'solana');
      if (viaIntent) {
        routingPath.push('Near Intents');
      }
      
      // Check if came via aggregation wallet
      const viaAggregation = aggregationWallets.some(agg => destinations.includes(agg));
      if (viaAggregation) {
        routingPath.push('Aggregation Wallet');
      }
      
      routingPath.push(dest);
      
      // Check for prior user interaction
      const hasPriorInteraction = userPriorExchangeInteractions.has(dest);
      
      return {
        isExchangeExit: true,
        exchangeName,
        depositAddress: dest,
        routingPath,
        hasPriorUserInteraction: hasPriorInteraction,
        isEscalationEligible: !hasPriorInteraction && (viaIntent || viaAggregation),
      };
    }
  }
  
  return {
    isExchangeExit: false,
    routingPath: [],
    hasPriorUserInteraction: false,
    isEscalationEligible: false,
  };
}

// ============================================
// CONFIDENCE SCORE CALCULATION
// ============================================

/**
 * Calculate overall confidence score based on rule evaluations.
 */
export function calculateConfidenceScore(
  seedCompromise: SeedCompromiseEvaluation,
  sweeperBot: SweeperBotEvaluation,
  nearIntents: NearIntentsEvaluation,
  exchangeExit: ExchangeExitEvaluation
): { score: number; level: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT' } {
  let score = 0;
  
  // +30 Multi-wallet drain
  if (seedCompromise.allRulesPassed) {
    score += CONFIG.CONFIDENCE.MULTI_WALLET_DRAIN;
  }
  
  // +20 Native SOL drained (from Rule 1.3)
  if (seedCompromise.rule1_3_drainPattern.passed) {
    score += CONFIG.CONFIDENCE.NATIVE_SOL_DRAINED;
  }
  
  // +20 Destination reuse (from Rule 1.5)
  if (seedCompromise.rule1_5_destinationCorrelation.passed) {
    score += CONFIG.CONFIDENCE.DESTINATION_REUSE;
  }
  
  // +15 Automated sweeper behavior
  if (sweeperBot.isSweeperBot) {
    score += CONFIG.CONFIDENCE.AUTOMATED_SWEEPER;
  }
  
  // +10 Near Intents post-drain usage
  if (nearIntents.isPostDrainObfuscation) {
    score += CONFIG.CONFIDENCE.NEAR_INTENTS_POST_DRAIN;
  }
  
  // +5 Exchange exit detected
  if (exchangeExit.isExchangeExit) {
    score += CONFIG.CONFIDENCE.EXCHANGE_EXIT;
  }
  
  // Determine level
  let level: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT';
  if (score >= CONFIG.CONFIDENCE.HIGH_THRESHOLD) {
    level = 'HIGH';
  } else if (score >= CONFIG.CONFIDENCE.MEDIUM_THRESHOLD) {
    level = 'MEDIUM';
  } else {
    level = 'INSUFFICIENT';
  }
  
  return { score, level };
}

// ============================================
// BUILD ATTACKER WALLETS LIST
// ============================================

export function buildAttackerWalletList(
  destinations: string[],
  clusterEvals: Map<string, AttackerClusterEvaluation>,
  nearIntents: NearIntentTransaction[]
): SolanaAttackerWallet[] {
  const attackerWallets: SolanaAttackerWallet[] = [];
  const now = new Date().toISOString();
  
  for (const dest of destinations) {
    const eval_ = clusterEvals.get(dest);
    if (!eval_?.isAttackerInfrastructure) continue;
    
    // Determine role
    let role: SolanaAttackerWallet['role'] = 'UNKNOWN';
    const exchangeName = isKnownExchange(dest);
    
    if (exchangeName) {
      role = 'EXCHANGE_DEPOSIT';
    } else if (nearIntents.some(ni => ni.sourceWallet === dest)) {
      role = 'NEAR_ROUTER';
    } else if (eval_.rule3_1_victimAggregation.passed) {
      role = 'AGGREGATION';
    }
    
    attackerWallets.push({
      address: dest,
      role,
      victimCount: (eval_.rule3_1_victimAggregation.metrics?.uniqueSources as number) || 0,
      totalReceivedSOL: 0, // Would need to calculate
      totalReceivedUSD: 0, // Would need to calculate
      firstSeen: now,
      lastSeen: now,
      confidence: eval_.clusterConfidence,
      isLabeledScammer: eval_.clusterConfidence >= 90,
    });
  }
  
  return attackerWallets;
}




