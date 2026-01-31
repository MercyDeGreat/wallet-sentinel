// ============================================
// APPROVAL DRAINER CLASSIFIER
// ============================================
//
// An Approval Drainer exploits ERC20/721/1155 token approvals to steal funds.
//
// How it works:
// 1. Victim grants token approval (approve/setApprovalForAll) to malicious contract
// 2. Attacker uses transferFrom to move tokens without victim's direct action
// 3. Funds leave wallet without user-initiated transaction
//
// KEY CHARACTERISTICS:
// 1. Active unlimited or high-value approvals exist
// 2. Transfers executed via transferFrom (not direct transfer)
// 3. Drainer address matches known patterns
// 4. Funds leave without corresponding user transaction
//
// WHAT DOES NOT HAPPEN:
// - No direct signed transfers by the wallet
// - Wallet owner didn't initiate the drain transaction
//
// DISTINGUISHING FROM OTHER TYPES:
// - Not sweeper: no immediate in→out pattern
// - Not poisoning: no address similarity, no dust
// - Not signer compromise: victim didn't sign the drain tx
// ============================================

import type {
  ClassifierResult,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationApproval,
  ClassificationConfig,
} from '../types';

// ============================================
// APPROVAL ANALYSIS
// ============================================

/**
 * Check if an approval is "dangerous" (unlimited or very high value)
 */
export function isDangerousApproval(
  approval: ClassificationApproval,
  minValueThreshold: string
): boolean {
  if (approval.isUnlimited) {
    return true;
  }
  
  try {
    const amount = BigInt(approval.amount);
    const threshold = BigInt(minValueThreshold);
    return amount >= threshold;
  } catch {
    return false;
  }
}

/**
 * Check if a transfer was likely executed via transferFrom
 * by matching it against approvals
 */
function wasTransferFromApproval(
  transfer: ClassificationTokenTransfer,
  approvals: ClassificationApproval[],
  transactions: ClassificationTransaction[]
): { isTransferFrom: boolean; matchingApproval?: ClassificationApproval; spender?: string } {
  // Find approvals for this token
  const tokenApprovals = approvals.filter(a => 
    a.token.toLowerCase() === transfer.tokenAddress.toLowerCase() &&
    !a.wasRevoked &&
    a.timestamp < transfer.timestamp
  );
  
  if (tokenApprovals.length === 0) {
    return { isTransferFrom: false };
  }
  
  // Check if the transfer was NOT initiated by the wallet owner
  // (i.e., no corresponding transaction from the wallet at that time)
  const walletInitiatedAtTime = transactions.find(t =>
    !t.isInbound &&
    Math.abs(t.timestamp - transfer.timestamp) < 60 && // Within 1 minute
    t.hash === transfer.hash
  );
  
  // If wallet didn't initiate, it was likely transferFrom
  if (!walletInitiatedAtTime) {
    // Find the spender from approvals
    const matchingApproval = tokenApprovals.find(a => a.wasUsed || a.usedByTransferFrom);
    
    return {
      isTransferFrom: true,
      matchingApproval: matchingApproval || tokenApprovals[0],
      spender: matchingApproval?.spender || tokenApprovals[0]?.spender,
    };
  }
  
  return { isTransferFrom: false };
}

// ============================================
// DRAIN PATTERN DETECTION
// ============================================

interface ApprovalDrainEvent {
  approval: ClassificationApproval;
  transfer: ClassificationTokenTransfer;
  timeDelta: number;
  tokenSymbol: string;
  tokenAddress: string;
  spender: string;
}

/**
 * Find approval→drain patterns
 */
function findApprovalDrainPatterns(
  approvals: ClassificationApproval[],
  tokenTransfers: ClassificationTokenTransfer[],
  transactions: ClassificationTransaction[]
): ApprovalDrainEvent[] {
  const drainEvents: ApprovalDrainEvent[] = [];
  
  // Only consider dangerous (unlimited/high-value) approvals
  const dangerousApprovals = approvals.filter(a => !a.wasRevoked && a.isUnlimited);
  
  for (const approval of dangerousApprovals) {
    // Find outbound transfers of this token after approval
    const tokenDrains = tokenTransfers.filter(t =>
      !t.isInbound &&
      t.tokenAddress.toLowerCase() === approval.token.toLowerCase() &&
      t.timestamp > approval.timestamp
    );
    
    for (const drain of tokenDrains) {
      const transferFromCheck = wasTransferFromApproval(drain, [approval], transactions);
      
      if (transferFromCheck.isTransferFrom) {
        drainEvents.push({
          approval,
          transfer: drain,
          timeDelta: drain.timestamp - approval.timestamp,
          tokenSymbol: approval.tokenSymbol,
          tokenAddress: approval.token,
          spender: approval.spender,
        });
      }
    }
  }
  
  return drainEvents;
}

// ============================================
// MAIN CLASSIFIER
// ============================================

/**
 * Classify if an attack is APPROVAL_DRAINER.
 * 
 * REQUIRED CONDITIONS:
 * 1. Active unlimited or high-value approvals exist
 * 2. Transfers executed via transferFrom (not direct transfer)
 * 3. Funds leave without user-initiated transaction
 * 
 * ADDITIONAL EVIDENCE:
 * - Drainer address matches known malicious patterns
 * - Multiple tokens drained via same spender
 */
export function classifyApprovalDrainer(
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
  
  // Normalize malicious addresses for comparison
  const maliciousSet = new Set(maliciousAddresses.map(a => a.toLowerCase()));
  
  // ============================================
  // STEP 1: Find dangerous approvals
  // ============================================
  
  const dangerousApprovals = approvals.filter(a => 
    !a.wasRevoked && isDangerousApproval(a, config.minApprovalValueForDrainer)
  );
  
  if (dangerousApprovals.length === 0) {
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators: ['No active dangerous approvals found'],
      evidence,
      reasoning: 'No dangerous (unlimited/high-value) approvals detected.',
    };
  }
  
  positiveIndicators.push(`${dangerousApprovals.length} dangerous approval(s) active`);
  
  // Check if any approvals are to known malicious addresses
  const maliciousApprovals = dangerousApprovals.filter(a => 
    maliciousSet.has(a.spender.toLowerCase())
  );
  
  if (maliciousApprovals.length > 0) {
    positiveIndicators.push(`${maliciousApprovals.length} approval(s) to known malicious address`);
    for (const ma of maliciousApprovals) {
      evidence.addresses.push(ma.spender);
      evidence.transactionHashes.push(ma.hash);
    }
  }
  
  // ============================================
  // STEP 2: Find approval→drain patterns
  // ============================================
  
  const drainEvents = findApprovalDrainPatterns(approvals, tokenTransfers, transactions);
  
  if (drainEvents.length === 0 && maliciousApprovals.length === 0) {
    // Have dangerous approvals but no drains yet
    return {
      detected: false,
      confidence: 20, // Low confidence - potential risk but not confirmed drain
      positiveIndicators,
      ruledOutIndicators: ['No drain activity detected yet'],
      evidence,
      reasoning: 'Dangerous approvals exist but no drain activity detected. Monitor for abuse.',
    };
  }
  
  if (drainEvents.length > 0) {
    positiveIndicators.push(`${drainEvents.length} token drain(s) via transferFrom`);
    
    for (const event of drainEvents) {
      evidence.transactionHashes.push(event.approval.hash, event.transfer.hash);
      evidence.addresses.push(event.spender);
      evidence.timestamps.push(event.approval.timestamp, event.transfer.timestamp);
    }
    
    // Check for multiple tokens drained via same spender
    const spenderCounts = new Map<string, number>();
    for (const event of drainEvents) {
      const spender = event.spender.toLowerCase();
      spenderCounts.set(spender, (spenderCounts.get(spender) || 0) + 1);
    }
    
    const multiTokenDrainer = [...spenderCounts.entries()].find(([_, count]) => count >= 2);
    if (multiTokenDrainer) {
      positiveIndicators.push(`Multi-token drain: ${multiTokenDrainer[1]} tokens via same spender`);
    }
  }
  
  // ============================================
  // STEP 3: Check if drains were NOT user-initiated
  // ============================================
  
  // Count how many drains have NO corresponding wallet transaction
  const uninitaitedDrains = drainEvents.filter(event => {
    const correspondingTx = transactions.find(t =>
      t.hash === event.transfer.hash &&
      !t.isInbound
    );
    return !correspondingTx;
  });
  
  if (uninitaitedDrains.length > 0) {
    positiveIndicators.push(`${uninitaitedDrains.length} drain(s) without user transaction`);
  } else if (drainEvents.length > 0) {
    ruledOutIndicators.push('Drains may have been user-initiated');
  }
  
  // ============================================
  // STEP 4: Calculate confidence
  // ============================================
  
  let confidence = 0;
  
  // Dangerous approvals (base 20%)
  if (dangerousApprovals.length > 0) {
    confidence += 20;
  }
  
  // Malicious spender approval (+25%)
  if (maliciousApprovals.length > 0) {
    confidence += 25;
  }
  
  // Drain events (+30%)
  if (drainEvents.length > 0) {
    confidence += 30;
  }
  
  // Multiple drains (+10%)
  if (drainEvents.length >= 3) {
    confidence += 10;
  }
  
  // Non-user-initiated drains (+15%)
  if (uninitaitedDrains.length > 0) {
    confidence += 15;
  }
  
  // Cap confidence
  confidence = Math.min(confidence, 95);
  
  // ============================================
  // STEP 5: Determine detection
  // ============================================
  
  // APPROVAL_DRAINER requires:
  // - Either: malicious approval exists
  // - Or: drain events via transferFrom detected
  const detected = maliciousApprovals.length > 0 || drainEvents.length > 0;
  
  // ============================================
  // STEP 6: Add ruled-out indicators
  // ============================================
  
  ruledOutIndicators.push(
    'No direct wallet signature on drain transactions',
    'No sweeper bot pattern (different mechanism)',
    'No address similarity attack'
  );
  
  return {
    detected,
    confidence,
    positiveIndicators,
    ruledOutIndicators,
    evidence,
    reasoning: detected
      ? `Approval drainer detected. ${dangerousApprovals.length} dangerous approval(s) with ` +
        `${drainEvents.length} confirmed drain(s) via transferFrom. ` +
        (maliciousApprovals.length > 0 ? `Approval to known malicious address: ${maliciousApprovals[0].spender.slice(0, 10)}...` : '')
      : 'Approval drainer not confirmed. Dangerous approvals exist, monitor for abuse.',
  };
}

// Note: Functions are already exported inline above
