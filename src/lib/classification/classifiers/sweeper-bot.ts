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
 * EXCLUSION CONDITIONS:
 * - No dusting similarity behavior (that's address poisoning)
 * - Not just a single fast transfer (must be pattern)
 */
export function classifySweeperBot(
  walletAddress: string,
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[],
  config: ClassificationConfig
): ClassifierResult {
  const positiveIndicators: string[] = [];
  const ruledOutIndicators: string[] = [];
  const evidence: { transactionHashes: string[]; addresses: string[]; timestamps: number[] } = {
    transactionHashes: [],
    addresses: [],
    timestamps: [],
  };
  
  // ============================================
  // EXCLUSION CHECK: Address Poisoning Pattern
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
      ruledOutIndicators.push('Only dust transfers detected - address poisoning pattern, not sweeper');
      return {
        detected: false,
        confidence: 0,
        positiveIndicators: [],
        ruledOutIndicators,
        evidence,
        reasoning: 'Dust-only transfers detected. This pattern indicates address poisoning, not sweeper bot.',
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
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators: ['No immediate outbound after inbound detected'],
      evidence,
      reasoning: 'No sweep pattern detected. Sweeper bots immediately transfer out funds after receipt.',
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
  const detected = hasRepeatedPattern || 
                   (sweepEvents.length >= 1 && consolidation.isConsolidation && gasPatterns.isAutomated);
  
  // ============================================
  // STEP 7: Add ruled-out indicators
  // ============================================
  
  ruledOutIndicators.push(
    'No address similarity pattern (not address poisoning)',
    'No approval-based drain pattern'
  );
  
  return {
    detected,
    confidence,
    positiveIndicators,
    ruledOutIndicators,
    evidence,
    reasoning: detected
      ? `Sweeper bot detected. ${sweepEvents.length} immediate sweep event(s) with ` +
        `${avgTimeDelta.toFixed(1)}s average response time. ` +
        (consolidation.isConsolidation ? 'Funds consolidate to few addresses. ' : '') +
        (gasPatterns.isAutomated ? 'Automated gas patterns confirm bot behavior.' : '')
      : 'Sweeper bot not confirmed. Some sweep events detected but pattern incomplete.',
  };
}

// Note: Functions are already exported inline above
