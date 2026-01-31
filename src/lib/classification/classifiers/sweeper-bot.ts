// ============================================
// SWEEPER BOT CLASSIFIER
// ============================================
//
// A Sweeper Bot is an AUTOMATED SYSTEM that drains funds immediately
// after they arrive in a compromised wallet.
//
// KEY CHARACTERISTICS:
// 1. Immediate outbound transfers after inbound funds (< 60 seconds default)
// 2. Time delta between in/out is configurable but very short
// 3. Multiple recipient hops or consolidation address
// 4. Consistent gas patterns (automated behavior)
// 5. Pattern repeats across multiple deposits
//
// WHAT DOES NOT HAPPEN:
// - No dust-only transfers (significant value moves)
// - No address similarity patterns (that's poisoning)
// - Usually no user-initiated transactions
//
// EXPLICITLY PREVENT: Labeling address poisoning as sweeper bot
// ============================================

import type {
  ClassifierResult,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationConfig,
  GasPatternInfo,
} from '../types';

// ============================================
// GAS PATTERN ANALYSIS
// ============================================

/**
 * Analyze gas patterns to detect automated behavior
 */
export function analyzeGasPatterns(
  transactions: ClassificationTransaction[]
): GasPatternInfo {
  const outbound = transactions.filter(t => !t.isInbound && t.gasPrice);
  
  if (outbound.length < 2) {
    return {
      avgGasPrice: '0',
      gasConsistency: 0,
      priorityFeePattern: 'UNKNOWN',
      isAutomated: false,
    };
  }
  
  // Calculate gas statistics
  const gasPrices = outbound.map(t => BigInt(t.gasPrice || '0'));
  const avgGas = gasPrices.reduce((a, b) => a + b, BigInt(0)) / BigInt(gasPrices.length);
  
  // Calculate consistency (how similar are the gas prices?)
  const deviations = gasPrices.map(g => {
    const diff = g > avgGas ? g - avgGas : avgGas - g;
    return Number(diff * BigInt(100) / (avgGas || BigInt(1)));
  });
  
  const avgDeviation = deviations.reduce((a, b) => a + b, 0) / deviations.length;
  const consistency = Math.max(0, 100 - avgDeviation);
  
  // Automated bots typically have very consistent gas patterns (>80%)
  const isAutomated = consistency > 80 && outbound.length >= 3;
  
  // Determine priority fee pattern
  let priorityFeePattern: 'FIXED' | 'VARIABLE' | 'UNKNOWN' = 'UNKNOWN';
  if (consistency > 90) {
    priorityFeePattern = 'FIXED';
  } else if (consistency > 50) {
    priorityFeePattern = 'VARIABLE';
  }
  
  return {
    avgGasPrice: avgGas.toString(),
    gasConsistency: Math.round(consistency),
    priorityFeePattern,
    isAutomated,
  };
}

// ============================================
// SWEEP PATTERN DETECTION
// ============================================

interface SweepEvent {
  inbound: ClassificationTransaction | ClassificationTokenTransfer;
  outbound: ClassificationTransaction | ClassificationTokenTransfer;
  timeDelta: number; // seconds
  valueIn: string;
  valueOut: string;
}

/**
 * Find sweep patterns: inbound quickly followed by outbound
 */
function findSweepPatterns(
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[],
  maxTimeDelta: number
): SweepEvent[] {
  const sweepEvents: SweepEvent[] = [];
  
  // Combine and sort all transactions by timestamp
  const allInbound = [
    ...transactions.filter(t => t.isInbound),
    ...tokenTransfers.filter(t => t.isInbound),
  ].sort((a, b) => a.timestamp - b.timestamp);
  
  const allOutbound = [
    ...transactions.filter(t => !t.isInbound),
    ...tokenTransfers.filter(t => !t.isInbound),
  ].sort((a, b) => a.timestamp - b.timestamp);
  
  // For each inbound, find immediate outbound
  for (const inbound of allInbound) {
    // Skip dust transfers (those are for address poisoning, not sweeper)
    if ('isDust' in inbound && inbound.isDust) {
      continue;
    }
    
    // Find outbound within time window
    for (const outbound of allOutbound) {
      const timeDelta = outbound.timestamp - inbound.timestamp;
      
      // Outbound must be after inbound and within window
      if (timeDelta >= 0 && timeDelta <= maxTimeDelta) {
        sweepEvents.push({
          inbound,
          outbound,
          timeDelta,
          valueIn: inbound.value,
          valueOut: outbound.value,
        });
        break; // Only count first matching outbound per inbound
      }
    }
  }
  
  return sweepEvents;
}

/**
 * Check if outbound addresses show consolidation pattern
 */
function detectConsolidationPattern(
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[]
): { isConsolidation: boolean; consolidationAddresses: string[]; percentage: number } {
  const outbound = [
    ...transactions.filter(t => !t.isInbound),
    ...tokenTransfers.filter(t => !t.isInbound),
  ];
  
  if (outbound.length < 2) {
    return { isConsolidation: false, consolidationAddresses: [], percentage: 0 };
  }
  
  // Count destinations
  const destCounts = new Map<string, number>();
  for (const tx of outbound) {
    const dest = tx.to.toLowerCase();
    destCounts.set(dest, (destCounts.get(dest) || 0) + 1);
  }
  
  // Find top destinations
  const sorted = [...destCounts.entries()].sort((a, b) => b[1] - a[1]);
  
  // If top 2 destinations account for >70% of outbound, it's consolidation
  const top2Count = (sorted[0]?.[1] || 0) + (sorted[1]?.[1] || 0);
  const percentage = (top2Count / outbound.length) * 100;
  
  const isConsolidation = percentage >= 70;
  const consolidationAddresses = sorted.slice(0, 2).map(s => s[0]);
  
  return { isConsolidation, consolidationAddresses, percentage };
}

// ============================================
// NEGATIVE CONSTRAINT HELPERS
// ============================================

import { calculateAddressSimilarity } from './address-poisoning';

/**
 * Check if any addresses show visual similarity (poisoning indicator)
 */
function checkForAddressSimilarity(
  tokenTransfers: ClassificationTokenTransfer[],
  transactions: ClassificationTransaction[],
  threshold: number
): { hasSimilarity: boolean; details: string } {
  const inboundDust = tokenTransfers.filter(t => t.isInbound && t.isDust);
  const outbound = [...transactions.filter(t => !t.isInbound), ...tokenTransfers.filter(t => !t.isInbound)];
  
  for (const dust of inboundDust) {
    for (const out of outbound) {
      const similarity = calculateAddressSimilarity(dust.from, out.to);
      if (similarity.prefixMatch + similarity.suffixMatch >= threshold) {
        return {
          hasSimilarity: true,
          details: `Address ${dust.from.slice(0, 8)}... similar to ${out.to.slice(0, 8)}... (${similarity.prefixMatch + similarity.suffixMatch} chars match)`,
        };
      }
    }
  }
  
  return { hasSimilarity: false, details: '' };
}

/**
 * Check if wallet has dusting history (poisoning indicator)
 */
function checkDustingHistory(
  tokenTransfers: ClassificationTokenTransfer[],
  minDustTransfers: number
): { hasDusting: boolean; count: number; durationDays: number } {
  const inboundDust = tokenTransfers.filter(t => t.isInbound && t.isDust);
  
  if (inboundDust.length < minDustTransfers) {
    return { hasDusting: false, count: inboundDust.length, durationDays: 0 };
  }
  
  // Calculate duration
  const timestamps = inboundDust.map(t => t.timestamp).sort((a, b) => a - b);
  const durationSeconds = timestamps[timestamps.length - 1] - timestamps[0];
  const durationDays = durationSeconds / 86400;
  
  return {
    hasDusting: true,
    count: inboundDust.length,
    durationDays,
  };
}

/**
 * Check if outbound transfer appears to be user-signed (not automated)
 * User-signed = long time gap, single recipient, not part of automated pattern
 */
function isUserSignedTransfer(
  inboundTimestamp: number,
  outboundTimestamp: number,
  sweeperThreshold: number
): { isUserSigned: boolean; timeDelta: number } {
  const timeDelta = outboundTimestamp - inboundTimestamp;
  
  // If time gap is > sweeper threshold, it's likely user-initiated
  // Sweeper bots act within seconds, not hours/days
  const isUserSigned = timeDelta > sweeperThreshold;
  
  return { isUserSigned, timeDelta };
}

/**
 * Count unique outbound recipients
 */
function countUniqueRecipients(
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[]
): number {
  const recipients = new Set<string>();
  
  for (const tx of transactions) {
    if (!tx.isInbound && tx.to) {
      recipients.add(tx.to.toLowerCase());
    }
  }
  
  for (const transfer of tokenTransfers) {
    if (!transfer.isInbound && transfer.to) {
      recipients.add(transfer.to.toLowerCase());
    }
  }
  
  return recipients.size;
}

// ============================================
// CLASSIFICATION DEBUG TRACE
// ============================================

export interface SweeperBotDecisionTrace {
  /** Reasons sweeper bot was disqualified */
  rejectedBecause: string[];
  /** Reasons sweeper bot passed checks (if detected) */
  acceptedBecause: string[];
  /** All negative constraints checked */
  negativeConstraints: {
    hasAddressSimilarity: boolean;
    hasDustingHistory: boolean;
    isUserSignedTransfer: boolean;
    timeDeltaExceedsThreshold: boolean;
    singleRecipient: boolean;
  };
}

// ============================================
// MAIN CLASSIFIER
// ============================================

/**
 * Classify if an attack is SWEEPER_BOT.
 * 
 * REQUIRED CONDITIONS (ALL must apply):
 * 1. Immediate outbound transfers after inbound (< configurable threshold)
 * 2. Multiple recipient hops or consolidation address
 * 3. Known sweeper gas patterns OR consistent automation
 * 
 * EXCLUSION CONDITIONS (ANY disqualifies SWEEPER_BOT):
 * - hasAddressSimilarity === true (address poisoning pattern)
 * - hasDustingHistory === true (address poisoning pattern)
 * - outboundTx.isUserSigned === true (manual transfer)
 * - timeDeltaInboundToOutbound > SWEEPER_THRESHOLD
 * - recipientCount === 1 (single destination, not consolidation pattern)
 * 
 * HARD RULE: If ANY exclusion condition is met → SWEEPER_BOT MUST BE DISQUALIFIED
 */
export function classifySweeperBot(
  walletAddress: string,
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[],
  config: ClassificationConfig
): ClassifierResult & { decisionTrace?: SweeperBotDecisionTrace } {
  const positiveIndicators: string[] = [];
  const ruledOutIndicators: string[] = [];
  const evidence: { transactionHashes: string[]; addresses: string[]; timestamps: number[] } = {
    transactionHashes: [],
    addresses: [],
    timestamps: [],
  };
  
  // Initialize decision trace for debugging
  const decisionTrace: SweeperBotDecisionTrace = {
    rejectedBecause: [],
    acceptedBecause: [],
    negativeConstraints: {
      hasAddressSimilarity: false,
      hasDustingHistory: false,
      isUserSignedTransfer: false,
      timeDeltaExceedsThreshold: false,
      singleRecipient: false,
    },
  };
  
  // ============================================
  // NEGATIVE CONSTRAINTS CHECK (MUST BE FIRST)
  // ============================================
  // If ANY of these are true, SWEEPER_BOT is DISQUALIFIED
  
  // Constraint 1: Check for address similarity (poisoning pattern)
  const similarityCheck = checkForAddressSimilarity(
    tokenTransfers,
    transactions,
    config.addressSimilarityThreshold
  );
  decisionTrace.negativeConstraints.hasAddressSimilarity = similarityCheck.hasSimilarity;
  
  if (similarityCheck.hasSimilarity) {
    decisionTrace.rejectedBecause.push(`Address similarity detected: ${similarityCheck.details}`);
    ruledOutIndicators.push('DISQUALIFIED: Address similarity pattern detected (ADDRESS_POISONING)');
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators,
      evidence,
      reasoning: 'SWEEPER_BOT disqualified: Address similarity detected. This is an ADDRESS_POISONING pattern.',
      decisionTrace,
    };
  }
  
  // Constraint 2: Check for dusting history (poisoning pattern)
  const dustingCheck = checkDustingHistory(tokenTransfers, config.minDustTransfersForPoisoning);
  decisionTrace.negativeConstraints.hasDustingHistory = dustingCheck.hasDusting;
  
  if (dustingCheck.hasDusting) {
    decisionTrace.rejectedBecause.push(
      `Dusting history detected: ${dustingCheck.count} dust transfers over ${dustingCheck.durationDays.toFixed(1)} days`
    );
    ruledOutIndicators.push('DISQUALIFIED: Dusting history detected (ADDRESS_POISONING)');
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators,
      evidence,
      reasoning: 'SWEEPER_BOT disqualified: Dusting history detected. This is an ADDRESS_POISONING pattern.',
      decisionTrace,
    };
  }
  
  // Constraint 3: Count unique recipients
  const recipientCount = countUniqueRecipients(transactions, tokenTransfers);
  decisionTrace.negativeConstraints.singleRecipient = recipientCount === 1;
  
  // Single recipient with non-dust transfers is NOT sweeper bot pattern
  // (Sweeper bots typically consolidate to known addresses in patterns)
  if (recipientCount === 1) {
    const outbound = [...transactions.filter(t => !t.isInbound), ...tokenTransfers.filter(t => !t.isInbound)];
    const hasSignificantOutbound = outbound.some(t => 
      BigInt(t.value || '0') > BigInt(config.dustValueThreshold)
    );
    
    if (hasSignificantOutbound && outbound.length === 1) {
      decisionTrace.rejectedBecause.push('Single recipient with single significant outbound - likely manual transfer');
      ruledOutIndicators.push('DISQUALIFIED: Single outbound to single recipient (likely user-initiated)');
      return {
        detected: false,
        confidence: 0,
        positiveIndicators: [],
        ruledOutIndicators,
        evidence,
        reasoning: 'SWEEPER_BOT disqualified: Single outbound transfer to single recipient suggests user-initiated transaction, not automated sweeper.',
        decisionTrace,
      };
    }
  }
  
  // ============================================
  // LEGACY EXCLUSION CHECK: Address Poisoning Pattern
  // ============================================
  
  // If we see dust transfers from similar addresses, this is NOT sweeper bot
  const inboundDust = tokenTransfers.filter(t => t.isInbound && t.isDust);
  if (inboundDust.length > 0) {
    // Check if there are non-dust outbounds (sweeper signature)
    const nonDustOutbound = [
      ...transactions.filter(t => !t.isInbound && BigInt(t.value || '0') > BigInt(config.dustValueThreshold)),
      ...tokenTransfers.filter(t => !t.isInbound && !t.isDust),
    ];
    
    if (nonDustOutbound.length === 0) {
      decisionTrace.rejectedBecause.push('Only dust transfers detected - address poisoning pattern');
      ruledOutIndicators.push('Only dust transfers detected - address poisoning pattern, not sweeper');
      return {
        detected: false,
        confidence: 0,
        positiveIndicators: [],
        ruledOutIndicators,
        evidence,
        reasoning: 'Dust-only transfers detected. This pattern indicates address poisoning, not sweeper bot.',
        decisionTrace,
      };
    }
  }
  
  // ============================================
  // STEP 1: Find sweep patterns
  // ============================================
  
  const sweepEvents = findSweepPatterns(
    transactions,
    tokenTransfers,
    config.sweeperTimeDeltaSeconds
  );
  
  if (sweepEvents.length === 0) {
    decisionTrace.rejectedBecause.push('No immediate outbound after inbound detected');
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators: ['No immediate outbound after inbound detected'],
      evidence,
      reasoning: 'No sweep pattern detected. Sweeper bots immediately transfer out funds after receipt.',
      decisionTrace,
    };
  }
  
  // ============================================
  // Constraint 4: Check if transfers are user-signed (time delta check)
  // ============================================
  
  // Check if ALL outbound transfers have time deltas > threshold
  // If ANY significant outbound happens long after inbound, it's user-initiated
  const allInbound = [...transactions.filter(t => t.isInbound), ...tokenTransfers.filter(t => t.isInbound)];
  const allOutbound = [...transactions.filter(t => !t.isInbound), ...tokenTransfers.filter(t => !t.isInbound)];
  
  let hasSlowTransfer = false;
  let maxTimeDelta = 0;
  
  for (const outbound of allOutbound) {
    // Find the most recent inbound before this outbound
    const priorInbound = allInbound
      .filter(i => i.timestamp <= outbound.timestamp)
      .sort((a, b) => b.timestamp - a.timestamp)[0];
    
    if (priorInbound) {
      const userSignedCheck = isUserSignedTransfer(
        priorInbound.timestamp,
        outbound.timestamp,
        config.sweeperTimeDeltaSeconds
      );
      
      if (userSignedCheck.timeDelta > maxTimeDelta) {
        maxTimeDelta = userSignedCheck.timeDelta;
      }
      
      if (userSignedCheck.isUserSigned) {
        hasSlowTransfer = true;
        decisionTrace.negativeConstraints.isUserSignedTransfer = true;
        decisionTrace.negativeConstraints.timeDeltaExceedsThreshold = true;
      }
    }
  }
  
  // If the primary large outbound is user-signed (slow), disqualify
  if (hasSlowTransfer && sweepEvents.length <= 1) {
    decisionTrace.rejectedBecause.push(
      `Outbound transfer time delta (${maxTimeDelta}s) exceeds sweeper threshold (${config.sweeperTimeDeltaSeconds}s)`
    );
    ruledOutIndicators.push(`DISQUALIFIED: Time delta ${maxTimeDelta}s > ${config.sweeperTimeDeltaSeconds}s (user-initiated)`);
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators,
      evidence,
      reasoning: `SWEEPER_BOT disqualified: Outbound occurred ${maxTimeDelta} seconds after inbound, exceeding the ${config.sweeperTimeDeltaSeconds}s threshold for automated sweeping.`,
      decisionTrace,
    };
  }
  
  // Add sweep events to evidence
  for (const event of sweepEvents) {
    evidence.transactionHashes.push(event.inbound.hash, event.outbound.hash);
    evidence.timestamps.push(event.inbound.timestamp, event.outbound.timestamp);
    if ('to' in event.outbound) {
      evidence.addresses.push(event.outbound.to);
    }
  }
  
  positiveIndicators.push(
    `${sweepEvents.length} sweep event(s) detected (in→out < ${config.sweeperTimeDeltaSeconds}s)`
  );
  
  // ============================================
  // STEP 2: Check for repeated pattern
  // ============================================
  
  const hasRepeatedPattern = sweepEvents.length >= config.minSweeperPatternCount;
  
  if (!hasRepeatedPattern) {
    positiveIndicators.push('Single sweep event (pattern not confirmed)');
  } else {
    positiveIndicators.push(`Repeated sweep pattern: ${sweepEvents.length} occurrences`);
  }
  
  // Calculate average time delta
  const avgTimeDelta = sweepEvents.reduce((sum, e) => sum + e.timeDelta, 0) / sweepEvents.length;
  positiveIndicators.push(`Average sweep time: ${avgTimeDelta.toFixed(1)} seconds`);
  
  // ============================================
  // STEP 3: Check consolidation pattern
  // ============================================
  
  const consolidation = detectConsolidationPattern(transactions, tokenTransfers);
  
  if (consolidation.isConsolidation) {
    positiveIndicators.push(
      `Consolidation pattern: ${consolidation.percentage.toFixed(0)}% of funds to ${consolidation.consolidationAddresses.length} address(es)`
    );
    evidence.addresses.push(...consolidation.consolidationAddresses);
  } else {
    ruledOutIndicators.push('No consolidation pattern detected');
  }
  
  // ============================================
  // STEP 4: Analyze gas patterns
  // ============================================
  
  const gasPatterns = analyzeGasPatterns(transactions);
  
  if (gasPatterns.isAutomated) {
    positiveIndicators.push(
      `Automated gas pattern: ${gasPatterns.gasConsistency}% consistency`
    );
  } else if (gasPatterns.gasConsistency > 50) {
    positiveIndicators.push(
      `Semi-consistent gas: ${gasPatterns.gasConsistency}% consistency`
    );
  } else {
    ruledOutIndicators.push('Gas patterns not consistent with automation');
  }
  
  // ============================================
  // STEP 5: Calculate confidence
  // ============================================
  
  let confidence = 0;
  
  // Sweep pattern (base 30%)
  if (sweepEvents.length > 0) {
    confidence += 30;
  }
  
  // Repeated pattern (+25%)
  if (hasRepeatedPattern) {
    confidence += 25;
  }
  
  // Consolidation pattern (+20%)
  if (consolidation.isConsolidation) {
    confidence += 20;
  }
  
  // Automated gas (+15%)
  if (gasPatterns.isAutomated) {
    confidence += 15;
  } else if (gasPatterns.gasConsistency > 50) {
    confidence += 8;
  }
  
  // Very fast sweep (+10%)
  if (avgTimeDelta < 30) {
    confidence += 10;
    positiveIndicators.push('Very fast sweep (<30 seconds)');
  }
  
  // Cap confidence
  confidence = Math.min(confidence, 95);
  
  // ============================================
  // STEP 6: Determine detection
  // ============================================
  
  // SWEEPER_BOT requires:
  // - At least 2 sweep events (repeated pattern)
  // - OR 1 sweep event + consolidation + automated gas
  let detected = hasRepeatedPattern || 
                 (sweepEvents.length >= 1 && consolidation.isConsolidation && gasPatterns.isAutomated);
  
  // ============================================
  // STEP 7: REGRESSION GUARD (HARD RULE)
  // ============================================
  // If classification === SWEEPER_BOT, these assertions MUST pass:
  // - noAddressSimilarity
  // - noDustingHistory
  // - isAutomatedDrain
  // If any assertion fails → fallback to false
  
  if (detected) {
    // Re-verify all negative constraints
    const finalSimilarityCheck = checkForAddressSimilarity(
      tokenTransfers,
      transactions,
      config.addressSimilarityThreshold
    );
    
    const finalDustingCheck = checkDustingHistory(
      tokenTransfers,
      config.minDustTransfersForPoisoning
    );
    
    // HARD RULE: Fail if any poisoning signal exists
    if (finalSimilarityCheck.hasSimilarity) {
      detected = false;
      decisionTrace.rejectedBecause.push('REGRESSION_GUARD: Address similarity still detected');
      ruledOutIndicators.push('REGRESSION_GUARD: Address similarity detected - cannot be SWEEPER_BOT');
    }
    
    if (finalDustingCheck.hasDusting) {
      detected = false;
      decisionTrace.rejectedBecause.push('REGRESSION_GUARD: Dusting history still detected');
      ruledOutIndicators.push('REGRESSION_GUARD: Dusting history detected - cannot be SWEEPER_BOT');
    }
    
    // Must have automated pattern for sweeper bot
    if (!gasPatterns.isAutomated && !hasRepeatedPattern) {
      detected = false;
      decisionTrace.rejectedBecause.push('REGRESSION_GUARD: No automated drain pattern confirmed');
      ruledOutIndicators.push('REGRESSION_GUARD: No automated pattern - likely not SWEEPER_BOT');
    }
    
    if (detected) {
      decisionTrace.acceptedBecause.push(
        'Passed all negative constraints',
        'Automated sweep pattern confirmed',
        `${sweepEvents.length} sweep events with ${avgTimeDelta.toFixed(1)}s avg response`
      );
    }
  }
  
  // ============================================
  // STEP 8: Add ruled-out indicators
  // ============================================
  
  ruledOutIndicators.push(
    'No address similarity pattern (not address poisoning)',
    'No approval-based drain pattern'
  );
  
  return {
    detected,
    confidence: detected ? confidence : 0, // Zero confidence if not detected
    positiveIndicators: detected ? positiveIndicators : [],
    ruledOutIndicators,
    evidence,
    reasoning: detected
      ? `Sweeper bot detected. ${sweepEvents.length} immediate sweep event(s) with ` +
        `${avgTimeDelta.toFixed(1)}s average response time. ` +
        (consolidation.isConsolidation ? 'Funds consolidate to few addresses. ' : '') +
        (gasPatterns.isAutomated ? 'Automated gas patterns confirm bot behavior.' : '')
      : 'Sweeper bot not confirmed. Pattern does not match automated sweeper behavior.',
    decisionTrace,
  };
}

// Note: Functions are already exported inline above
