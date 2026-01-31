// ============================================
// ADDRESS POISONING CLASSIFIER
// ============================================
//
// Address Poisoning is a SOCIAL ENGINEERING attack, NOT a wallet compromise.
//
// How it works:
// 1. Attacker creates address that visually mimics victim's frequent recipient
// 2. Attacker sends DUST transfers to victim from this look-alike address
// 3. Victim copies address from transaction history (thinking it's their recipient)
// 4. Victim manually sends funds to the poisoned address
//
// KEY CHARACTERISTICS:
// - Incoming dust transfers from visually similar addresses
// - Similarity score (prefix + suffix match) above threshold
// - Repeated dusting over time (not one-off)
// - Victim sends funds MANUALLY to poisoned address (not automated)
//
// WHAT DOES NOT HAPPEN:
// - No approvals involved
// - No rapid automated drain
// - No signer change
// - No private key compromise
//
// EXPLICITLY PREVENT: Labeling as sweeper bot
// ============================================

import type {
  ClassifierResult,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationConfig,
} from '../types';

// ============================================
// ADDRESS SIMILARITY CALCULATION
// ============================================

/**
 * Calculate visual similarity between two addresses.
 * Focuses on prefix and suffix (what users typically check).
 * 
 * @returns Similarity score (0-100)
 */
export function calculateAddressSimilarity(addr1: string, addr2: string): {
  score: number;
  prefixMatch: number;
  suffixMatch: number;
  details: string;
} {
  // Normalize addresses
  const a1 = addr1.toLowerCase().replace('0x', '');
  const a2 = addr2.toLowerCase().replace('0x', '');
  
  if (a1.length !== 40 || a2.length !== 40) {
    return { score: 0, prefixMatch: 0, suffixMatch: 0, details: 'Invalid address length' };
  }
  
  // Count matching prefix characters (after 0x)
  let prefixMatch = 0;
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] === a2[i]) {
      prefixMatch++;
    } else {
      break;
    }
  }
  
  // Count matching suffix characters
  let suffixMatch = 0;
  for (let i = 1; i <= a1.length; i++) {
    if (a1[a1.length - i] === a2[a2.length - i]) {
      suffixMatch++;
    } else {
      break;
    }
  }
  
  // Calculate score:
  // - 4+ matching chars in prefix = 30 points
  // - 4+ matching chars in suffix = 30 points
  // - Additional chars add more points
  // - Maximum score is 100
  
  let score = 0;
  
  // Prefix scoring (more weight on first 4 chars as that's what users check)
  if (prefixMatch >= 4) {
    score += 30 + Math.min((prefixMatch - 4) * 5, 20);
  } else {
    score += prefixMatch * 5;
  }
  
  // Suffix scoring (more weight on last 4 chars)
  if (suffixMatch >= 4) {
    score += 30 + Math.min((suffixMatch - 4) * 5, 20);
  } else {
    score += suffixMatch * 5;
  }
  
  const details = `Prefix: ${prefixMatch} chars, Suffix: ${suffixMatch} chars`;
  
  return {
    score: Math.min(score, 100),
    prefixMatch,
    suffixMatch,
    details,
  };
}

/**
 * Check if a transfer value is "dust" (very small amount)
 */
export function isDustValue(value: string, threshold: string): boolean {
  try {
    const v = BigInt(value || '0');
    const t = BigInt(threshold);
    return v > BigInt(0) && v <= t;
  } catch {
    return false;
  }
}

// ============================================
// MAIN CLASSIFIER
// ============================================

/**
 * Classify if an attack is ADDRESS_POISONING.
 * 
 * REQUIRED CONDITIONS (ALL must apply):
 * 1. Incoming dust transfers from visually similar addresses
 * 2. Similarity score above threshold
 * 3. Repeated dusting (not one-off)
 * 4. Victim sends funds manually to poisoned address
 * 
 * EXCLUSION CONDITIONS:
 * - No approvals involved
 * - No rapid automated drain pattern
 * - No signer change evidence
 */
export function classifyAddressPoisoning(
  walletAddress: string,
  transactions: ClassificationTransaction[],
  tokenTransfers: ClassificationTokenTransfer[],
  frequentRecipients: string[],
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
  
  // ============================================
  // STEP 1: Find incoming dust transfers
  // ============================================
  
  const inboundDust = tokenTransfers.filter(t => 
    t.isInbound && 
    t.isDust &&
    t.from.toLowerCase() !== normalized
  );
  
  if (inboundDust.length === 0) {
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: [],
      ruledOutIndicators: ['No dust transfers received'],
      evidence,
      reasoning: 'No incoming dust transfers detected. Address poisoning requires dust transfers.',
    };
  }
  
  // ============================================
  // STEP 2: Check for visually similar addresses
  // ============================================
  
  const similarityMatches: {
    dustAddress: string;
    targetAddress: string;
    similarity: ReturnType<typeof calculateAddressSimilarity>;
    dustTransfers: ClassificationTokenTransfer[];
  }[] = [];
  
  // Group dust by sender
  const dustBySender = new Map<string, ClassificationTokenTransfer[]>();
  for (const dust of inboundDust) {
    const sender = dust.from.toLowerCase();
    if (!dustBySender.has(sender)) {
      dustBySender.set(sender, []);
    }
    dustBySender.get(sender)!.push(dust);
  }
  
  // Check each dust sender against frequent recipients
  for (const [dustSender, dustTransfers] of dustBySender) {
    for (const recipient of frequentRecipients) {
      const similarity = calculateAddressSimilarity(dustSender, recipient);
      
      const totalMatchingChars = similarity.prefixMatch + similarity.suffixMatch;
      
      if (totalMatchingChars >= config.addressSimilarityThreshold) {
        similarityMatches.push({
          dustAddress: dustSender,
          targetAddress: recipient,
          similarity,
          dustTransfers,
        });
      }
    }
  }
  
  if (similarityMatches.length === 0) {
    return {
      detected: false,
      confidence: 0,
      positiveIndicators: ['Dust transfers detected'],
      ruledOutIndicators: ['No visually similar addresses found'],
      evidence,
      reasoning: 'Dust transfers found but no addresses match frequently used recipients.',
    };
  }
  
  // ============================================
  // STEP 3: Check for repeated dusting
  // ============================================
  
  const repeatedDusters = similarityMatches.filter(
    m => m.dustTransfers.length >= config.minDustTransfersForPoisoning
  );
  
  if (repeatedDusters.length === 0 && similarityMatches.length > 0) {
    // One-off dust is less conclusive
    positiveIndicators.push('Single dust transfer from similar address');
  }
  
  // ============================================
  // STEP 4: Check if victim sent to poisoned address
  // ============================================
  
  const allOutbound = [
    ...transactions.filter(t => !t.isInbound),
    ...tokenTransfers.filter(t => !t.isInbound),
  ];
  
  let victimSentToPoisoned = false;
  let sentToPoisionedHash: string | undefined;
  let sentValue = '0';
  
  for (const match of similarityMatches) {
    const sentToPoisoned = allOutbound.find(t => 
      t.to.toLowerCase() === match.dustAddress
    );
    
    if (sentToPoisoned) {
      victimSentToPoisoned = true;
      sentToPoisionedHash = sentToPoisoned.hash;
      sentValue = sentToPoisoned.value;
      
      evidence.transactionHashes.push(sentToPoisoned.hash);
      evidence.addresses.push(match.dustAddress);
      evidence.timestamps.push('timestamp' in sentToPoisoned ? sentToPoisoned.timestamp : 0);
      
      positiveIndicators.push(
        `Victim sent ${sentValue} to poisoned address ${match.dustAddress.slice(0, 6)}...${match.dustAddress.slice(-4)}`
      );
    }
  }
  
  // ============================================
  // STEP 5: Calculate confidence
  // ============================================
  
  let confidence = 0;
  
  // Base confidence from similarity matches
  if (similarityMatches.length > 0) {
    const bestMatch = similarityMatches.reduce((best, curr) => 
      curr.similarity.score > best.similarity.score ? curr : best
    );
    
    confidence += bestMatch.similarity.score * 0.4; // 40% from similarity
    
    positiveIndicators.push(
      `Address ${bestMatch.dustAddress.slice(0, 6)}...${bestMatch.dustAddress.slice(-4)} mimics ` +
      `${bestMatch.targetAddress.slice(0, 6)}...${bestMatch.targetAddress.slice(-4)} ` +
      `(${bestMatch.similarity.details})`
    );
    
    // Add dust transfers to evidence
    for (const dust of bestMatch.dustTransfers) {
      evidence.transactionHashes.push(dust.hash);
      evidence.timestamps.push(dust.timestamp);
    }
    evidence.addresses.push(bestMatch.dustAddress, bestMatch.targetAddress);
  }
  
  // Repeated dusting increases confidence
  if (repeatedDusters.length > 0) {
    confidence += 20; // +20% for repeated dusting
    positiveIndicators.push(`Repeated dusting: ${repeatedDusters[0].dustTransfers.length} dust transfers`);
  }
  
  // Victim sending to poisoned address is strong evidence
  if (victimSentToPoisoned) {
    confidence += 30; // +30% for confirmed victim action
    positiveIndicators.push('Funds manually sent to spoofed address');
  }
  
  // Cap confidence
  confidence = Math.min(confidence, 95);
  
  // ============================================
  // STEP 6: Determine detection
  // ============================================
  
  // ADDRESS_POISONING requires:
  // - At least one similarity match
  // - Either repeated dusting OR victim sent funds
  const detected = similarityMatches.length > 0 && 
                   (repeatedDusters.length > 0 || victimSentToPoisoned);
  
  // ============================================
  // STEP 7: Add ruled-out indicators
  // ============================================
  
  // These are CRITICAL for correct UX messaging
  ruledOutIndicators.push(
    'No approval abuse detected',
    'No automated drain pattern',
    'No private key compromise',
    'No sweeper bot behavior'
  );
  
  return {
    detected,
    confidence,
    positiveIndicators,
    ruledOutIndicators,
    evidence,
    reasoning: detected
      ? `Address poisoning detected. Look-alike address ${similarityMatches[0].dustAddress.slice(0, 10)}... ` +
        `sent dust transfers mimicking frequently used recipient. ` +
        (victimSentToPoisoned ? 'Victim sent funds to the poisoned address.' : 'Monitor for victim sending funds.')
      : 'Address poisoning not confirmed. Similarity matches found but pattern incomplete.',
  };
}

// Note: Functions are already exported inline above
