// ============================================
// WALLET CORRELATION ENGINE
// ============================================
// Groups wallets by correlation factors to detect
// multi-wallet attacks with high confidence.
//
// Correlation Factors:
// - Time proximity of drains
// - Destination address reuse
// - Identical transfer sequencing
// - Similar gas patterns
// - Full balance extraction behavior

import {
  IncidentWallet,
  CorrelationResult,
  CorrelationFactor,
  CorrelationFactorType,
  CorrelationConfig,
  DEFAULT_CORRELATION_CONFIG,
  TimeCorrelation,
  DestinationCorrelation,
  BehaviorCorrelation,
  generateCorrelationId,
} from './types';

// ============================================
// MAIN CORRELATION FUNCTION
// ============================================

/**
 * Correlate a group of wallets to determine if they are part of the same attack.
 */
export function correlateWallets(
  wallets: IncidentWallet[],
  config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG
): CorrelationResult {
  const correlationId = generateCorrelationId();
  
  // If only one wallet, it's a single incident
  if (wallets.length < config.minWalletsForMultiWallet) {
    return createSingleWalletResult(correlationId, wallets, config);
  }
  
  // Analyze correlation factors
  const timeAnalysis = analyzeTimeCorrelation(wallets, config);
  const destinationAnalysis = analyzeDestinationCorrelation(wallets, config);
  const behaviorAnalysis = analyzeBehaviorCorrelation(wallets);
  
  // Calculate correlation factors
  const correlationFactors = calculateCorrelationFactors(
    wallets,
    timeAnalysis,
    destinationAnalysis,
    behaviorAnalysis
  );
  
  // Calculate overall correlation strength
  const correlationStrength = calculateCorrelationStrength(correlationFactors);
  
  // Determine if this is a multi-wallet attack
  const { isMultiWalletAttack, multiWalletConfidence } = determineMultiWalletAttack(
    correlationFactors,
    timeAnalysis,
    destinationAnalysis,
    behaviorAnalysis,
    config
  );
  
  return {
    correlationId,
    wallets,
    correlationFactors,
    correlationStrength,
    timeAnalysis,
    destinationAnalysis,
    behaviorAnalysis,
    isMultiWalletAttack,
    multiWalletConfidence,
  };
}

// ============================================
// TIME CORRELATION ANALYSIS
// ============================================

function analyzeTimeCorrelation(
  wallets: IncidentWallet[],
  config: CorrelationConfig
): TimeCorrelation {
  // Sort wallets by drain timestamp
  const sortedWallets = [...wallets].sort(
    (a, b) => new Date(a.drainTimestamp).getTime() - new Date(b.drainTimestamp).getTime()
  );
  
  const timestamps = sortedWallets.map(w => new Date(w.drainTimestamp).getTime());
  const earliestDrain = new Date(timestamps[0]).toISOString();
  const latestDrain = new Date(timestamps[timestamps.length - 1]).toISOString();
  
  const totalWindowMs = timestamps[timestamps.length - 1] - timestamps[0];
  const totalWindowMinutes = totalWindowMs / (1000 * 60);
  
  // Calculate average time between drains
  let totalTimeBetween = 0;
  for (let i = 1; i < timestamps.length; i++) {
    totalTimeBetween += timestamps[i] - timestamps[i - 1];
  }
  const averageTimeBetweenDrains = timestamps.length > 1
    ? (totalTimeBetween / (timestamps.length - 1)) / (1000 * 60) // in minutes
    : 0;
  
  return {
    earliestDrain,
    latestDrain,
    totalWindowMinutes,
    withinConfiguredWindow: totalWindowMinutes <= config.drainTimeWindowMinutes,
    averageTimeBetweenDrains,
    drainSequenceOrder: sortedWallets.map(w => w.address),
  };
}

// ============================================
// DESTINATION CORRELATION ANALYSIS
// ============================================

function analyzeDestinationCorrelation(
  wallets: IncidentWallet[],
  config: CorrelationConfig
): DestinationCorrelation {
  // Collect all destination addresses
  const allDestinations: string[] = [];
  const destinationCounts: Record<string, number> = {};
  
  for (const wallet of wallets) {
    for (const dest of wallet.destinationAddresses) {
      const normalized = dest.toLowerCase();
      allDestinations.push(normalized);
      destinationCounts[normalized] = (destinationCounts[normalized] || 0) + 1;
    }
  }
  
  // Find unique and shared destinations
  const uniqueDestinations = [...new Set(allDestinations)];
  const sharedDestinations = uniqueDestinations.filter(d => destinationCounts[d] > 1);
  
  // Find primary destination (most used)
  let primaryDestination: string | undefined;
  let maxCount = 0;
  for (const [dest, count] of Object.entries(destinationCounts)) {
    if (count > maxCount) {
      maxCount = count;
      primaryDestination = dest;
    }
  }
  
  // Check if destination is an exchange
  const destinationIsExchange = uniqueDestinations.some(
    d => config.knownExchangeAddresses.map(a => a.toLowerCase()).includes(d)
  );
  
  // Check if destination is a known attacker (would need external data)
  const destinationIsKnownAttacker = false; // TODO: Integrate with attacker database
  
  return {
    uniqueDestinations,
    sharedDestinations,
    destinationReuseCount: sharedDestinations.length,
    primaryDestination,
    destinationIsExchange,
    destinationIsKnownAttacker,
  };
}

// ============================================
// BEHAVIOR CORRELATION ANALYSIS
// ============================================

function analyzeBehaviorCorrelation(wallets: IncidentWallet[]): BehaviorCorrelation {
  // Check if all drains were full balance
  const allFullBalanceDrains = wallets.every(w => w.wasFullBalance);
  
  // Check if all drains included native assets
  const allIncludeNativeAssets = wallets.every(w =>
    w.drainedAssets.some(a => a.type === 'NATIVE')
  );
  
  // Check for similar gas patterns
  const similarGasPatterns = checkSimilarGasPatterns(wallets);
  
  // Check for identical transfer sequencing
  const identicalTransferSequencing = checkIdenticalTransferSequencing(wallets);
  
  // Check that there's no shared approval target that explains all drains
  const noSharedApprovalTarget = !hasSharedApprovalTarget(wallets);
  
  // Check that there's no shared contract exploit
  const noSharedContractExploit = !hasSharedContractExploit(wallets);
  
  return {
    allFullBalanceDrains,
    allIncludeNativeAssets,
    similarGasPatterns,
    identicalTransferSequencing,
    noSharedApprovalTarget,
    noSharedContractExploit,
  };
}

function checkSimilarGasPatterns(wallets: IncidentWallet[]): boolean {
  if (wallets.length < 2) return false;
  
  // Get gas prices and compare
  const gasPrices = wallets.map(w => BigInt(w.gasPrice || '0'));
  if (gasPrices.some(g => g === BigInt(0))) return false;
  
  // Calculate average
  const sum = gasPrices.reduce((a, b) => a + b, BigInt(0));
  const avg = sum / BigInt(gasPrices.length);
  
  // Check if all are within 20% of average
  const tolerance = avg / BigInt(5); // 20%
  return gasPrices.every(g => {
    const diff = g > avg ? g - avg : avg - g;
    return diff <= tolerance;
  });
}

function checkIdenticalTransferSequencing(wallets: IncidentWallet[]): boolean {
  if (wallets.length < 2) return false;
  
  // Compare transfer step patterns
  const patterns = wallets.map(w => {
    return w.transferSequence.map(s => `${s.from.slice(-8)}->${s.to.slice(-8)}:${s.asset}`).join('|');
  });
  
  // Check if more than 50% have the same pattern
  const patternCounts: Record<string, number> = {};
  for (const pattern of patterns) {
    patternCounts[pattern] = (patternCounts[pattern] || 0) + 1;
  }
  
  const maxCount = Math.max(...Object.values(patternCounts));
  return maxCount >= wallets.length * 0.5;
}

function hasSharedApprovalTarget(wallets: IncidentWallet[]): boolean {
  // Check if there's a malicious approval target that all wallets share
  if (wallets.length < 2) return false;
  
  // Collect all approval spenders
  const approvalsByWallet: Record<string, Set<string>> = {};
  for (const wallet of wallets) {
    approvalsByWallet[wallet.address] = new Set(
      wallet.relevantApprovals.map(a => a.spender.toLowerCase())
    );
  }
  
  // Find intersection of all approval spenders
  const walletAddresses = Object.keys(approvalsByWallet);
  if (walletAddresses.length === 0) return false;
  
  let sharedSpenders = approvalsByWallet[walletAddresses[0]];
  for (let i = 1; i < walletAddresses.length; i++) {
    const currentSpenders = approvalsByWallet[walletAddresses[i]];
    sharedSpenders = new Set([...sharedSpenders].filter(x => currentSpenders.has(x)));
  }
  
  // If there's a shared spender that could explain all drains, return true
  return sharedSpenders.size > 0;
}

function hasSharedContractExploit(wallets: IncidentWallet[]): boolean {
  // Check if all wallets interacted with the same contract before drain
  if (wallets.length < 2) return false;
  
  // Collect contract interactions by wallet
  const interactionsByWallet: Record<string, Set<string>> = {};
  for (const wallet of wallets) {
    interactionsByWallet[wallet.address] = new Set(
      wallet.priorContractInteractions
        .filter(i => !i.isLegitimateProtocol)
        .map(i => i.contractAddress.toLowerCase())
    );
  }
  
  // Find intersection
  const walletAddresses = Object.keys(interactionsByWallet);
  if (walletAddresses.length === 0) return false;
  
  let sharedContracts = interactionsByWallet[walletAddresses[0]];
  for (let i = 1; i < walletAddresses.length; i++) {
    const currentContracts = interactionsByWallet[walletAddresses[i]];
    sharedContracts = new Set([...sharedContracts].filter(x => currentContracts.has(x)));
  }
  
  return sharedContracts.size > 0;
}

// ============================================
// CORRELATION FACTOR CALCULATION
// ============================================

function calculateCorrelationFactors(
  wallets: IncidentWallet[],
  timeAnalysis: TimeCorrelation,
  destinationAnalysis: DestinationCorrelation,
  behaviorAnalysis: BehaviorCorrelation
): CorrelationFactor[] {
  const factors: CorrelationFactor[] = [];
  const walletAddresses = wallets.map(w => w.address);
  
  // TIME_PROXIMITY
  if (timeAnalysis.withinConfiguredWindow) {
    const strength = calculateTimeProximityStrength(timeAnalysis);
    factors.push({
      type: 'TIME_PROXIMITY',
      strength,
      description: `All drains occurred within ${timeAnalysis.totalWindowMinutes.toFixed(1)} minutes`,
      affectedWallets: walletAddresses,
      evidence: [
        `Earliest drain: ${timeAnalysis.earliestDrain}`,
        `Latest drain: ${timeAnalysis.latestDrain}`,
        `Average time between drains: ${timeAnalysis.averageTimeBetweenDrains.toFixed(1)} minutes`,
      ],
    });
  }
  
  // DESTINATION_REUSE
  if (destinationAnalysis.sharedDestinations.length > 0) {
    const strength = Math.min(100, destinationAnalysis.destinationReuseCount * 30 + 40);
    factors.push({
      type: 'DESTINATION_REUSE',
      strength,
      description: `${destinationAnalysis.sharedDestinations.length} destination address(es) reused across wallets`,
      affectedWallets: walletAddresses,
      evidence: destinationAnalysis.sharedDestinations.map(d => `Shared destination: ${d}`),
    });
  }
  
  // TRANSFER_SEQUENCING
  if (behaviorAnalysis.identicalTransferSequencing) {
    factors.push({
      type: 'TRANSFER_SEQUENCING',
      strength: 75,
      description: 'Identical transfer sequencing pattern detected across wallets',
      affectedWallets: walletAddresses,
      evidence: ['Transfer patterns match across multiple wallets'],
    });
  }
  
  // GAS_PATTERN_MATCH
  if (behaviorAnalysis.similarGasPatterns) {
    factors.push({
      type: 'GAS_PATTERN_MATCH',
      strength: 60,
      description: 'Similar gas patterns detected across wallets',
      affectedWallets: walletAddresses,
      evidence: ['Gas prices within 20% tolerance across all drain transactions'],
    });
  }
  
  // FULL_BALANCE_DRAIN
  if (behaviorAnalysis.allFullBalanceDrains) {
    factors.push({
      type: 'FULL_BALANCE_DRAIN',
      strength: 85,
      description: 'All wallets experienced full balance extraction',
      affectedWallets: walletAddresses,
      evidence: ['Every wallet was drained of its entire balance'],
    });
  }
  
  // NO_PRIOR_APPROVAL
  if (behaviorAnalysis.noSharedApprovalTarget) {
    factors.push({
      type: 'NO_PRIOR_APPROVAL',
      strength: 70,
      description: 'No shared malicious approval target that explains all drains',
      affectedWallets: walletAddresses,
      evidence: ['Drains cannot be attributed to a shared token approval'],
    });
  }
  
  return factors;
}

function calculateTimeProximityStrength(timeAnalysis: TimeCorrelation): number {
  // Closer drains = higher strength
  if (timeAnalysis.totalWindowMinutes <= 5) return 100;
  if (timeAnalysis.totalWindowMinutes <= 15) return 95;
  if (timeAnalysis.totalWindowMinutes <= 30) return 85;
  if (timeAnalysis.totalWindowMinutes <= 60) return 70;
  if (timeAnalysis.totalWindowMinutes <= 90) return 55;
  return 40;
}

function calculateCorrelationStrength(factors: CorrelationFactor[]): number {
  if (factors.length === 0) return 0;
  
  // Weighted average based on factor importance
  const weights: Record<CorrelationFactorType, number> = {
    TIME_PROXIMITY: 1.5,
    DESTINATION_REUSE: 2.0,
    TRANSFER_SEQUENCING: 1.2,
    GAS_PATTERN_MATCH: 0.8,
    FULL_BALANCE_DRAIN: 1.3,
    NO_PRIOR_APPROVAL: 1.0,
    SAME_ATTACKER_INFRASTRUCTURE: 1.8,
  };
  
  let weightedSum = 0;
  let totalWeight = 0;
  
  for (const factor of factors) {
    const weight = weights[factor.type] || 1.0;
    weightedSum += factor.strength * weight;
    totalWeight += weight;
  }
  
  return Math.min(100, Math.round(weightedSum / totalWeight));
}

// ============================================
// MULTI-WALLET ATTACK DETERMINATION
// ============================================

function determineMultiWalletAttack(
  factors: CorrelationFactor[],
  timeAnalysis: TimeCorrelation,
  destinationAnalysis: DestinationCorrelation,
  behaviorAnalysis: BehaviorCorrelation,
  config: CorrelationConfig
): { isMultiWalletAttack: boolean; multiWalletConfidence: number } {
  let confidence = 0;
  
  // Base confidence from correlation factors
  const hasTimeProximity = factors.some(f => f.type === 'TIME_PROXIMITY' && f.strength >= 50);
  const hasDestinationReuse = factors.some(f => f.type === 'DESTINATION_REUSE' && f.strength >= 50);
  const hasFullBalanceDrain = factors.some(f => f.type === 'FULL_BALANCE_DRAIN');
  const hasNoSharedApproval = factors.some(f => f.type === 'NO_PRIOR_APPROVAL');
  
  // Calculate confidence
  if (hasTimeProximity) confidence += 25;
  if (hasDestinationReuse) confidence += 30;
  if (hasFullBalanceDrain) confidence += 15;
  if (hasNoSharedApproval) confidence += 15;
  if (behaviorAnalysis.allIncludeNativeAssets) confidence += 10;
  if (behaviorAnalysis.noSharedContractExploit) confidence += 10;
  
  // Bonus for very tight time windows
  if (timeAnalysis.totalWindowMinutes <= 10) confidence += 10;
  
  // Penalty for potential legitimate explanations
  if (destinationAnalysis.destinationIsExchange) {
    // Could be user depositing to exchange - reduce confidence
    confidence -= 20;
  }
  
  // Cap at 100
  confidence = Math.min(100, Math.max(0, confidence));
  
  // Determine if it's a multi-wallet attack
  const isMultiWalletAttack = 
    hasTimeProximity &&
    hasDestinationReuse &&
    behaviorAnalysis.noSharedApprovalTarget &&
    behaviorAnalysis.noSharedContractExploit &&
    confidence >= config.lowConfidenceThreshold;
  
  return { isMultiWalletAttack, multiWalletConfidence: confidence };
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function createSingleWalletResult(
  correlationId: string,
  wallets: IncidentWallet[],
  config: CorrelationConfig
): CorrelationResult {
  const wallet = wallets[0];
  
  return {
    correlationId,
    wallets,
    correlationFactors: [],
    correlationStrength: 0,
    timeAnalysis: {
      earliestDrain: wallet?.drainTimestamp || new Date().toISOString(),
      latestDrain: wallet?.drainTimestamp || new Date().toISOString(),
      totalWindowMinutes: 0,
      withinConfiguredWindow: true,
      averageTimeBetweenDrains: 0,
      drainSequenceOrder: wallets.map(w => w.address),
    },
    destinationAnalysis: {
      uniqueDestinations: wallet?.destinationAddresses || [],
      sharedDestinations: [],
      destinationReuseCount: 0,
      primaryDestination: wallet?.destinationAddresses[0],
      destinationIsExchange: false,
      destinationIsKnownAttacker: false,
    },
    behaviorAnalysis: {
      allFullBalanceDrains: wallet?.wasFullBalance || false,
      allIncludeNativeAssets: wallet?.drainedAssets.some(a => a.type === 'NATIVE') || false,
      similarGasPatterns: false,
      identicalTransferSequencing: false,
      noSharedApprovalTarget: true,
      noSharedContractExploit: true,
    },
    isMultiWalletAttack: false,
    multiWalletConfidence: 0,
  };
}

export { correlateWallets };

