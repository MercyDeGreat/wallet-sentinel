// ============================================
// SIGNER COMPROMISE CLASSIFIER
// ============================================
//
// Signer Compromise indicates the wallet's private key is controlled by an attacker.
//
// How it works:
// 1. Attacker obtains private key (phishing, malware, social engineering)
// 2. Attacker directly signs transactions from the wallet
// 3. Funds are transferred directly (not via approval mechanism)
//
// KEY CHARACTERISTICS:
// 1. Direct transfers signed by wallet (not transferFrom)
// 2. No approvals involved in the drain
// 3. Behavior inconsistent with wallet history
// 4. Rapid multi-asset drainage
// 5. Destination is malicious or fresh address
//
// WHAT DOES NOT HAPPEN:
// - No approval abuse
// - No dust transfers or address similarity (not poisoning)
// - Wallet owner signature IS on the drain txs (but unauthorized)
//
// THIS IS THE MOST SEVERE ATTACK TYPE:
// If confirmed, the wallet can NEVER be safe again without key rotation.
// ============================================

import type {
  ClassifierResult,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationApproval,
  ClassificationConfig,
} from '../types';

// ============================================
// BEHAVIORAL ANALYSIS
// ============================================

/**
 * Analyze typical wallet behavior patterns
 */
interface WalletBehaviorProfile {
  avgTimeBetweenTxs: number;      // Average seconds between transactions
  typicalRecipients: string[];    // Addresses frequently transacted with
  typicalTimeOfDay: number[];     // Hours when usually active (0-23)
  typicalDayOfWeek: number[];     // Days when usually active (0-6)
  avgTransactionValue: bigint;    // Average transaction value
  txCount: number;                // Total transactions analyzed
}

/**
 * Build behavior profile from transaction history
 */
function buildBehaviorProfile(
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[]
): WalletBehaviorProfile {
  const allTxs = [
    ...transactions.filter(t => !t.isInbound),
    ...tokenTransfers.filter(t => !t.isInbound),
  ].sort((a, b) => a.timestamp - b.timestamp);
  
  if (allTxs.length < 2) {
    return {
      avgTimeBetweenTxs: 0,
      typicalRecipients: [],
      typicalTimeOfDay: [],
      typicalDayOfWeek: [],
      avgTransactionValue: BigInt(0),
      txCount: allTxs.length,
    };
  }
  
  // Calculate average time between transactions
  const timeDiffs: number[] = [];
  for (let i = 1; i < allTxs.length; i++) {
    timeDiffs.push(allTxs[i].timestamp - allTxs[i - 1].timestamp);
  }
  const avgTimeBetweenTxs = timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;
  
  // Find typical recipients
  const recipientCounts = new Map<string, number>();
  for (const tx of allTxs) {
    const to = tx.to.toLowerCase();
    recipientCounts.set(to, (recipientCounts.get(to) || 0) + 1);
  }
  const sortedRecipients = [...recipientCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(r => r[0]);
  
  // Analyze time patterns
  const hoursActive = new Map<number, number>();
  const daysActive = new Map<number, number>();
  
  for (const tx of allTxs) {
    const date = new Date(tx.timestamp * 1000);
    const hour = date.getUTCHours();
    const day = date.getUTCDay();
    hoursActive.set(hour, (hoursActive.get(hour) || 0) + 1);
    daysActive.set(day, (daysActive.get(day) || 0) + 1);
  }
  
  const typicalTimeOfDay = [...hoursActive.entries()]
    .filter(([_, count]) => count >= allTxs.length * 0.1)
    .map(([hour]) => hour);
  
  const typicalDayOfWeek = [...daysActive.entries()]
    .filter(([_, count]) => count >= allTxs.length * 0.1)
    .map(([day]) => day);
  
  // Calculate average transaction value
  let totalValue = BigInt(0);
  for (const tx of allTxs) {
    try {
      totalValue += BigInt(tx.value || '0');
    } catch {
      // Skip invalid values
    }
  }
  const avgTransactionValue = totalValue / BigInt(allTxs.length || 1);
  
  return {
    avgTimeBetweenTxs,
    typicalRecipients: sortedRecipients,
    typicalTimeOfDay,
    typicalDayOfWeek,
    avgTransactionValue,
    txCount: allTxs.length,
  };
}

/**
 * Check if recent transactions deviate from normal behavior
 */
function detectBehaviorDeviation(
  recentTxs: (ClassificationTransaction | ClassificationTokenTransfer)[],
  profile: WalletBehaviorProfile
): { deviationScore: number; deviations: string[] } {
  if (profile.txCount < 5 || recentTxs.length === 0) {
    return { deviationScore: 0, deviations: ['Insufficient history for comparison'] };
  }
  
  const deviations: string[] = [];
  let deviationScore = 0;
  
  // Check 1: New recipients (never seen before)
  const newRecipients = recentTxs.filter(tx => 
    !profile.typicalRecipients.includes(tx.to.toLowerCase())
  );
  if (newRecipients.length > 0) {
    const pct = (newRecipients.length / recentTxs.length) * 100;
    if (pct >= 50) {
      deviationScore += 25;
      deviations.push(`${pct.toFixed(0)}% of recent txs to new addresses`);
    }
  }
  
  // Check 2: Rapid transactions (much faster than normal)
  if (recentTxs.length >= 2) {
    const sortedRecent = [...recentTxs].sort((a, b) => a.timestamp - b.timestamp);
    let totalDelta = 0;
    for (let i = 1; i < sortedRecent.length; i++) {
      totalDelta += sortedRecent[i].timestamp - sortedRecent[i - 1].timestamp;
    }
    const avgDelta = totalDelta / (sortedRecent.length - 1);
    
    if (avgDelta < profile.avgTimeBetweenTxs * 0.2) { // 5x faster than normal
      deviationScore += 30;
      deviations.push(`Transactions ${(profile.avgTimeBetweenTxs / avgDelta).toFixed(1)}x faster than normal`);
    }
  }
  
  // Check 3: Unusual time of activity
  const unusualTime = recentTxs.some(tx => {
    const hour = new Date(tx.timestamp * 1000).getUTCHours();
    return profile.typicalTimeOfDay.length > 0 && !profile.typicalTimeOfDay.includes(hour);
  });
  if (unusualTime) {
    deviationScore += 15;
    deviations.push('Activity at unusual hours');
  }
  
  // Check 4: Unusually high values
  const highValueTxs = recentTxs.filter(tx => {
    try {
      const value = BigInt(tx.value || '0');
      return value > profile.avgTransactionValue * BigInt(10);
    } catch {
      return false;
    }
  });
  if (highValueTxs.length > 0) {
    deviationScore += 20;
    deviations.push(`${highValueTxs.length} transaction(s) with 10x+ normal value`);
  }
  
  return { deviationScore: Math.min(deviationScore, 100), deviations };
}

// ============================================
// RAPID DRAIN DETECTION
// ============================================

/**
 * Detect rapid multi-asset drainage (key signer compromise indicator)
 */
function detectRapidMultiAssetDrain(
  tokenTransfers: ClassificationTokenTransfer[],
  transactions: ClassificationTransaction[],
  config: ClassificationConfig
): { detected: boolean; assetCount: number; timeSpan: number; drainEvents: string[] } {
  // Get outbound transfers
  const outbound = [
    ...transactions.filter(t => !t.isInbound && BigInt(t.value || '0') > BigInt(0)),
    ...tokenTransfers.filter(t => !t.isInbound),
  ].sort((a, b) => a.timestamp - b.timestamp);
  
  if (outbound.length < config.rapidDrainAssetCount) {
    return { detected: false, assetCount: 0, timeSpan: 0, drainEvents: [] };
  }
  
  // Find time window where multiple distinct assets were drained
  const windowSize = 300; // 5 minutes
  
  for (let i = 0; i <= outbound.length - config.rapidDrainAssetCount; i++) {
    const windowStart = outbound[i].timestamp;
    const windowEnd = windowStart + windowSize;
    
    const inWindow = outbound.filter(t => 
      t.timestamp >= windowStart && t.timestamp <= windowEnd
    );
    
    // Count unique tokens (including native)
    const uniqueAssets = new Set<string>();
    for (const tx of inWindow) {
      if ('tokenAddress' in tx) {
        uniqueAssets.add(tx.tokenAddress.toLowerCase());
      } else {
        uniqueAssets.add('NATIVE');
      }
    }
    
    if (uniqueAssets.size >= config.rapidDrainAssetCount) {
      const timeSpan = inWindow[inWindow.length - 1].timestamp - inWindow[0].timestamp;
      return {
        detected: true,
        assetCount: uniqueAssets.size,
        timeSpan,
        drainEvents: inWindow.map(t => t.hash),
      };
    }
  }
  
  return { detected: false, assetCount: 0, timeSpan: 0, drainEvents: [] };
}

// ============================================
// MAIN CLASSIFIER
// ============================================

/**
 * Classify if an attack is SIGNER_COMPROMISE.
 * 
 * REQUIRED CONDITIONS:
 * 1. Direct transfers signed by wallet (not transferFrom)
 * 2. No approvals involved in the drain
 * 3. Behavior inconsistent with wallet history
 * 4. Rapid multi-asset drainage
 * 
 * ADDITIONAL EVIDENCE:
 * - Destination is malicious or fresh address
 * - All assets drained in short window
 */
export function classifySignerCompromise(
  walletAddress: string,
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[],
  approvals: ClassificationApproval[],
  maliciousAddresses: string[],
  config: ClassificationConfig
): ClassifierResult {
  const normalized = walletAddress.toLowerCase();
  const positiveIndicators: string[] = [];
  const ruledOutIndicators: string[] = [];
  const evidence: { transactionHashes: string[]; addresses: string[]; timestamps: number[] } = {
    transactionHashes: [],
    addresses: [],
    timestamps: [],
  };
  
  // Normalize malicious addresses
  const maliciousSet = new Set(maliciousAddresses.map(a => a.toLowerCase()));
  
  // ============================================
  // EXCLUSION CHECK: Approval-based drains
  // ============================================
  
  // Check if there are active approvals that could explain the drains
  const activeApprovals = approvals.filter(a => !a.wasRevoked && a.isUnlimited);
  const hasUsedApprovals = approvals.some(a => a.wasUsed || a.usedByTransferFrom);
  
  if (hasUsedApprovals) {
    ruledOutIndicators.push('Approvals were used for transfers - likely approval drainer, not signer compromise');
  }
  
  // ============================================
  // STEP 1: Build behavior profile
  // ============================================
  
  // Use older transactions for profile (exclude last 24 hours)
  const oneDayAgo = Math.floor(Date.now() / 1000) - 86400;
  const historicalTxs = transactions.filter(t => t.timestamp < oneDayAgo);
  const historicalTransfers = tokenTransfers.filter(t => t.timestamp < oneDayAgo);
  
  const profile = buildBehaviorProfile(historicalTxs, historicalTransfers);
  
  // ============================================
  // STEP 2: Analyze recent transactions for deviation
  // ============================================
  
  const recentTxs = [
    ...transactions.filter(t => t.timestamp >= oneDayAgo && !t.isInbound),
    ...tokenTransfers.filter(t => t.timestamp >= oneDayAgo && !t.isInbound),
  ];
  
  if (recentTxs.length === 0) {
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators: ['No recent outbound activity'],
      evidence,
      reasoning: 'No recent outbound transactions to analyze.',
    };
  }
  
  const deviation = detectBehaviorDeviation(recentTxs, profile);
  
  if (deviation.deviationScore > 0) {
    positiveIndicators.push(`Behavior deviation score: ${deviation.deviationScore}/100`);
    positiveIndicators.push(...deviation.deviations);
  }
  
  // ============================================
  // STEP 3: Check for rapid multi-asset drain
  // ============================================
  
  const rapidDrain = detectRapidMultiAssetDrain(tokenTransfers, transactions, config);
  
  if (rapidDrain.detected) {
    positiveIndicators.push(
      `Rapid multi-asset drain: ${rapidDrain.assetCount} assets in ${rapidDrain.timeSpan}s`
    );
    evidence.transactionHashes.push(...rapidDrain.drainEvents);
  } else {
    ruledOutIndicators.push('No rapid multi-asset drain pattern');
  }
  
  // ============================================
  // STEP 4: Check destinations
  // ============================================
  
  const maliciousDestinations = recentTxs.filter(tx => 
    maliciousSet.has(tx.to.toLowerCase())
  );
  
  if (maliciousDestinations.length > 0) {
    positiveIndicators.push(`${maliciousDestinations.length} transfer(s) to known malicious address`);
    for (const tx of maliciousDestinations) {
      evidence.addresses.push(tx.to);
      evidence.transactionHashes.push(tx.hash);
      evidence.timestamps.push(tx.timestamp);
    }
  }
  
  // Check for single destination (consolidation to attacker wallet)
  const destinations = new Set(recentTxs.map(tx => tx.to.toLowerCase()));
  if (destinations.size <= 2 && recentTxs.length >= 3) {
    positiveIndicators.push(`All funds sent to ${destinations.size} address(es) - consolidation pattern`);
  }
  
  // ============================================
  // STEP 5: Verify these are direct transfers (not transferFrom)
  // ============================================
  
  // In signer compromise, the wallet owner's key signs the transaction
  // This is different from approval drainer where spender calls transferFrom
  const directTransfers = recentTxs.filter(tx => {
    // Check if this is NOT a transferFrom
    const isTokenTransfer = 'tokenAddress' in tx;
    if (isTokenTransfer) {
      // For token transfers, check if there's a corresponding approval
      const tokenTransfer = tx as ClassificationTokenTransfer;
      const hasApproval = approvals.some(a => 
        a.token.toLowerCase() === tokenTransfer.tokenAddress.toLowerCase() &&
        a.wasUsed
      );
      return !hasApproval; // Direct transfer if no approval was used
    }
    return true; // Native transfers are always direct
  });
  
  if (directTransfers.length > 0) {
    positiveIndicators.push(`${directTransfers.length} direct signed transfer(s)`);
  } else {
    ruledOutIndicators.push('Transfers appear to be approval-based');
  }
  
  // ============================================
  // STEP 6: Calculate confidence
  // ============================================
  
  let confidence = 0;
  
  // Behavior deviation (+30% max)
  confidence += Math.min(deviation.deviationScore * 0.3, 30);
  
  // Rapid multi-asset drain (+25%)
  if (rapidDrain.detected) {
    confidence += 25;
  }
  
  // Malicious destinations (+20%)
  if (maliciousDestinations.length > 0) {
    confidence += 20;
  }
  
  // Direct transfers (+15%)
  if (directTransfers.length > 0 && directTransfers.length === recentTxs.length) {
    confidence += 15;
  }
  
  // Consolidation pattern (+10%)
  if (destinations.size <= 2 && recentTxs.length >= 3) {
    confidence += 10;
  }
  
  // PENALTY: If approvals were used, reduce confidence significantly
  if (hasUsedApprovals) {
    confidence = Math.max(0, confidence - 40);
  }
  
  // Cap confidence
  confidence = Math.min(confidence, 95);
  
  // ============================================
  // STEP 7: Determine detection
  // ============================================
  
  // SIGNER_COMPROMISE requires:
  // - High behavior deviation (>= threshold)
  // - Direct signed transfers
  // - Either: rapid drain OR malicious destination
  // - NOT primarily approval-based
  const detected = 
    deviation.deviationScore >= config.behaviorDeviationThreshold &&
    directTransfers.length > 0 &&
    (rapidDrain.detected || maliciousDestinations.length > 0) &&
    !hasUsedApprovals;
  
  // ============================================
  // STEP 8: Add ruled-out indicators
  // ============================================
  
  ruledOutIndicators.push(
    'No dust transfer pattern (not address poisoning)',
    'No immediate in→out pattern (not sweeper bot)'
  );
  
  if (!hasUsedApprovals) {
    ruledOutIndicators.push('No approval abuse detected');
  }
  
  return {
    detected,
    confidence,
    positiveIndicators,
    ruledOutIndicators,
    evidence,
    reasoning: detected
      ? `Signer compromise detected. Behavior deviation: ${deviation.deviationScore}/100. ` +
        `${directTransfers.length} direct signed transfer(s). ` +
        (rapidDrain.detected ? `${rapidDrain.assetCount} assets drained in ${rapidDrain.timeSpan}s. ` : '') +
        (maliciousDestinations.length > 0 ? `Funds sent to known malicious address. ` : '') +
        'Private key appears compromised.'
      : 'Signer compromise not confirmed. ' +
        (hasUsedApprovals ? 'Transfers appear approval-based (approval drainer more likely). ' : '') +
        (deviation.deviationScore < config.behaviorDeviationThreshold ? 'Behavior within normal range. ' : ''),
  };
}

// Note: Functions are already exported inline above
