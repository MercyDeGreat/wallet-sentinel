// ============================================
// ATTACK CLASSIFIER
// ============================================
// Deterministic classification of attacks with high confidence
// and low false positive rate.
//
// Classifications:
// - SEED_SIGNER_COMPROMISE: Multi-wallet drain from compromised seed
// - APPROVAL_BASED_DRAIN: Drain via malicious token approvals
// - CONTRACT_EXPLOIT: Drain via smart contract vulnerability
// - SINGLE_WALLET_INCIDENT: Isolated incident
// - UNKNOWN_INSUFFICIENT_EVIDENCE: Cannot determine

import {
  AttackClassification,
  AttackClassificationResult,
  AttackClassificationReasoning,
  RejectedClassification,
  ClassificationEvidence,
  CorrelationResult,
  IncidentWallet,
  CorrelationConfig,
  DEFAULT_CORRELATION_CONFIG,
  getConfidenceLevel,
} from './types';

// ============================================
// MAIN CLASSIFICATION FUNCTION
// ============================================

/**
 * Classify an attack based on correlation results and wallet data.
 * Prioritizes correctness over sensitivity - will return UNKNOWN if uncertain.
 */
export function classifyAttack(
  correlation: CorrelationResult,
  config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG
): AttackClassificationResult {
  const wallets = correlation.wallets;
  
  // Collect evidence for each potential classification
  const seedSignerEvidence = evaluateSeedSignerCompromise(correlation, config);
  const approvalDrainEvidence = evaluateApprovalBasedDrain(wallets);
  const contractExploitEvidence = evaluateContractExploit(wallets);
  
  // Score each classification
  const scores = {
    SEED_SIGNER_COMPROMISE: seedSignerEvidence.score,
    APPROVAL_BASED_DRAIN: approvalDrainEvidence.score,
    CONTRACT_EXPLOIT: contractExploitEvidence.score,
    SINGLE_WALLET_INCIDENT: wallets.length === 1 ? 80 : 0,
    UNKNOWN_INSUFFICIENT_EVIDENCE: 0,
  };
  
  // Find the highest scoring classification
  let bestClassification: AttackClassification = 'UNKNOWN_INSUFFICIENT_EVIDENCE';
  let bestScore = 0;
  
  for (const [classification, score] of Object.entries(scores)) {
    if (score > bestScore) {
      bestScore = score;
      bestClassification = classification as AttackClassification;
    }
  }
  
  // If best score is too low, classify as unknown
  if (bestScore < config.lowConfidenceThreshold) {
    bestClassification = 'UNKNOWN_INSUFFICIENT_EVIDENCE';
    bestScore = 100 - bestScore; // High confidence that we don't know
  }
  
  // Build reasoning
  const reasoning = buildReasoning(
    correlation,
    seedSignerEvidence,
    approvalDrainEvidence,
    contractExploitEvidence
  );
  
  // Build rejected classifications
  const rejectedClassifications = buildRejectedClassifications(
    bestClassification,
    scores,
    seedSignerEvidence,
    approvalDrainEvidence,
    contractExploitEvidence
  );
  
  // Collect all evidence
  const supportingEvidence = getEvidenceForClassification(
    bestClassification,
    seedSignerEvidence,
    approvalDrainEvidence,
    contractExploitEvidence
  ).filter(e => e.type === 'SUPPORTING');
  
  const contradictingEvidence = getEvidenceForClassification(
    bestClassification,
    seedSignerEvidence,
    approvalDrainEvidence,
    contractExploitEvidence
  ).filter(e => e.type === 'CONTRADICTING');
  
  // Generate summary
  const summary = generateClassificationSummary(
    bestClassification,
    bestScore,
    wallets.length,
    reasoning
  );
  
  return {
    classification: bestClassification,
    confidence: getConfidenceLevel(bestScore, config),
    confidenceScore: bestScore,
    reasoning,
    rejectedClassifications,
    summary,
    supportingEvidence,
    contradictingEvidence,
  };
}

// ============================================
// SEED/SIGNER COMPROMISE EVALUATION
// ============================================

interface ClassificationEvaluation {
  score: number;
  evidence: ClassificationEvidence[];
  factors: Record<string, boolean>;
}

function evaluateSeedSignerCompromise(
  correlation: CorrelationResult,
  config: CorrelationConfig
): ClassificationEvaluation {
  const wallets = correlation.wallets;
  const evidence: ClassificationEvidence[] = [];
  let score = 0;
  
  const factors: Record<string, boolean> = {
    multiWalletDrain: false,
    withinTimeWindow: false,
    noSharedMaliciousContract: false,
    noSharedApprovalTarget: false,
    fundsRoutedToSameDestination: false,
    includesNativeAssets: false,
    fullBalanceExtractions: false,
  };
  
  // REQUIREMENT 1: Two or more wallets
  if (wallets.length >= config.minWalletsForMultiWallet) {
    factors.multiWalletDrain = true;
    score += 15;
    evidence.push({
      type: 'SUPPORTING',
      category: 'MULTI_WALLET',
      description: `${wallets.length} wallets affected in this incident`,
      weight: 15,
    });
  } else {
    evidence.push({
      type: 'CONTRADICTING',
      category: 'SINGLE_WALLET',
      description: 'Only one wallet affected - not multi-wallet',
      weight: 50,
    });
    return { score: 0, evidence, factors }; // Cannot be seed compromise with single wallet
  }
  
  // REQUIREMENT 2: Drained within time window
  if (correlation.timeAnalysis.withinConfiguredWindow) {
    factors.withinTimeWindow = true;
    const timeProximityBonus = correlation.timeAnalysis.totalWindowMinutes <= 10 ? 20 : 15;
    score += timeProximityBonus;
    evidence.push({
      type: 'SUPPORTING',
      category: 'TIME_PROXIMITY',
      description: `All drains within ${correlation.timeAnalysis.totalWindowMinutes.toFixed(1)} minutes`,
      weight: timeProximityBonus,
    });
  } else {
    evidence.push({
      type: 'CONTRADICTING',
      category: 'TIME_SPREAD',
      description: `Drains spread over ${correlation.timeAnalysis.totalWindowMinutes.toFixed(1)} minutes - exceeds ${config.drainTimeWindowMinutes} minute threshold`,
      weight: 30,
    });
  }
  
  // REQUIREMENT 3: No shared malicious contract interaction
  if (correlation.behaviorAnalysis.noSharedContractExploit) {
    factors.noSharedMaliciousContract = true;
    score += 15;
    evidence.push({
      type: 'SUPPORTING',
      category: 'NO_SHARED_CONTRACT',
      description: 'No shared malicious contract that could explain all drains',
      weight: 15,
    });
  } else {
    evidence.push({
      type: 'CONTRADICTING',
      category: 'SHARED_CONTRACT',
      description: 'Shared contract interaction detected - may be contract exploit',
      weight: 25,
    });
  }
  
  // REQUIREMENT 4: No shared token approval target
  if (correlation.behaviorAnalysis.noSharedApprovalTarget) {
    factors.noSharedApprovalTarget = true;
    score += 15;
    evidence.push({
      type: 'SUPPORTING',
      category: 'NO_SHARED_APPROVAL',
      description: 'No shared approval target that could explain all drains',
      weight: 15,
    });
  } else {
    evidence.push({
      type: 'CONTRADICTING',
      category: 'SHARED_APPROVAL',
      description: 'Shared approval target detected - may be approval-based drain',
      weight: 25,
    });
  }
  
  // REQUIREMENT 5: Funds routed to same destination
  if (correlation.destinationAnalysis.sharedDestinations.length > 0) {
    factors.fundsRoutedToSameDestination = true;
    score += 20;
    evidence.push({
      type: 'SUPPORTING',
      category: 'SHARED_DESTINATION',
      description: `Funds from all wallets routed to ${correlation.destinationAnalysis.sharedDestinations.length} shared destination(s)`,
      weight: 20,
      address: correlation.destinationAnalysis.primaryDestination,
    });
  }
  
  // REQUIREMENT 6: Includes native assets
  if (correlation.behaviorAnalysis.allIncludeNativeAssets) {
    factors.includesNativeAssets = true;
    score += 10;
    evidence.push({
      type: 'SUPPORTING',
      category: 'NATIVE_ASSETS',
      description: 'Native assets (ETH/BNB/SOL) were drained - not approval-limited',
      weight: 10,
    });
  }
  
  // BONUS: Full balance extraction
  if (correlation.behaviorAnalysis.allFullBalanceDrains) {
    factors.fullBalanceExtractions = true;
    score += 10;
    evidence.push({
      type: 'SUPPORTING',
      category: 'FULL_BALANCE',
      description: 'All wallets experienced full balance extraction',
      weight: 10,
    });
  }
  
  // Apply penalties for legitimate explanations
  if (correlation.destinationAnalysis.destinationIsExchange) {
    score -= 15;
    evidence.push({
      type: 'CONTRADICTING',
      category: 'EXCHANGE_DESTINATION',
      description: 'Destination is a known exchange - could be legitimate user action',
      weight: 15,
    });
  }
  
  // Check for potential dApp/bridge link
  const hasLegitimateProtocolInteraction = wallets.some(w =>
    w.priorContractInteractions.some(i => i.isLegitimateProtocol)
  );
  
  if (hasLegitimateProtocolInteraction) {
    score -= 10;
    evidence.push({
      type: 'CONTRADICTING',
      category: 'LEGITIMATE_PROTOCOL',
      description: 'Some wallets interacted with legitimate protocols - may not be compromise',
      weight: 10,
    });
  }
  
  return { score: Math.max(0, Math.min(100, score)), evidence, factors };
}

// ============================================
// APPROVAL-BASED DRAIN EVALUATION
// ============================================

function evaluateApprovalBasedDrain(wallets: IncidentWallet[]): ClassificationEvaluation {
  const evidence: ClassificationEvidence[] = [];
  let score = 0;
  
  const factors: Record<string, boolean> = {
    maliciousApprovalFound: false,
    drainFollowedApproval: false,
    approvalTargetKnownMalicious: false,
  };
  
  // Count wallets with suspicious approvals
  let walletsWithMaliciousApprovals = 0;
  let walletsWithDrainAfterApproval = 0;
  
  for (const wallet of wallets) {
    const suspiciousApprovals = wallet.relevantApprovals.filter(a => 
      a.isUnlimited && !a.wasRevoked
    );
    
    if (suspiciousApprovals.length > 0) {
      walletsWithMaliciousApprovals++;
      
      // Check if drain followed approval
      const drainTime = new Date(wallet.drainTimestamp).getTime();
      const approvalTimes = suspiciousApprovals.map(a => 
        new Date(a.approvalTimestamp).getTime()
      );
      
      const drainFollowed = approvalTimes.some(t => drainTime > t);
      if (drainFollowed) {
        walletsWithDrainAfterApproval++;
      }
    }
  }
  
  // Score based on approval patterns
  if (walletsWithMaliciousApprovals > 0) {
    factors.maliciousApprovalFound = true;
    const ratio = walletsWithMaliciousApprovals / wallets.length;
    score += Math.round(ratio * 40);
    evidence.push({
      type: 'SUPPORTING',
      category: 'MALICIOUS_APPROVAL',
      description: `${walletsWithMaliciousApprovals}/${wallets.length} wallets have suspicious unlimited approvals`,
      weight: Math.round(ratio * 40),
    });
  }
  
  if (walletsWithDrainAfterApproval > 0) {
    factors.drainFollowedApproval = true;
    const ratio = walletsWithDrainAfterApproval / wallets.length;
    score += Math.round(ratio * 30);
    evidence.push({
      type: 'SUPPORTING',
      category: 'DRAIN_AFTER_APPROVAL',
      description: `${walletsWithDrainAfterApproval}/${wallets.length} wallets were drained after granting approval`,
      weight: Math.round(ratio * 30),
    });
  }
  
  // Check for shared approval target
  const allSpenders = new Set<string>();
  for (const wallet of wallets) {
    for (const approval of wallet.relevantApprovals) {
      allSpenders.add(approval.spender.toLowerCase());
    }
  }
  
  // If all wallets approved the same spender, strong indicator
  if (allSpenders.size === 1 && wallets.length > 1) {
    factors.approvalTargetKnownMalicious = true;
    score += 30;
    evidence.push({
      type: 'SUPPORTING',
      category: 'SHARED_SPENDER',
      description: 'All wallets approved the same malicious spender',
      weight: 30,
      address: [...allSpenders][0],
    });
  }
  
  return { score: Math.min(100, score), evidence, factors };
}

// ============================================
// CONTRACT EXPLOIT EVALUATION
// ============================================

function evaluateContractExploit(wallets: IncidentWallet[]): ClassificationEvaluation {
  const evidence: ClassificationEvidence[] = [];
  let score = 0;
  
  const factors: Record<string, boolean> = {
    sharedContractInteraction: false,
    contractKnownVulnerable: false,
    exploitPatternMatched: false,
  };
  
  // Find shared contract interactions
  const contractsByWallet: Map<string, Set<string>> = new Map();
  
  for (const wallet of wallets) {
    const contracts = new Set(
      wallet.priorContractInteractions.map(i => i.contractAddress.toLowerCase())
    );
    contractsByWallet.set(wallet.address, contracts);
  }
  
  // Find intersection of all contract interactions
  const walletAddresses = [...contractsByWallet.keys()];
  if (walletAddresses.length > 0) {
    let sharedContracts = contractsByWallet.get(walletAddresses[0]) || new Set();
    
    for (let i = 1; i < walletAddresses.length; i++) {
      const currentContracts = contractsByWallet.get(walletAddresses[i]) || new Set();
      sharedContracts = new Set([...sharedContracts].filter(x => currentContracts.has(x)));
    }
    
    if (sharedContracts.size > 0) {
      factors.sharedContractInteraction = true;
      score += 40;
      evidence.push({
        type: 'SUPPORTING',
        category: 'SHARED_CONTRACT',
        description: `${sharedContracts.size} shared contract(s) interacted with by all wallets`,
        weight: 40,
        address: [...sharedContracts][0],
      });
      
      // Check if any shared contract is non-legitimate
      const nonLegitimate = [...sharedContracts].filter(addr => {
        return wallets.some(w =>
          w.priorContractInteractions.some(i =>
            i.contractAddress.toLowerCase() === addr && !i.isLegitimateProtocol
          )
        );
      });
      
      if (nonLegitimate.length > 0) {
        factors.contractKnownVulnerable = true;
        score += 30;
        evidence.push({
          type: 'SUPPORTING',
          category: 'SUSPICIOUS_CONTRACT',
          description: 'Shared contract is not a known legitimate protocol',
          weight: 30,
          address: nonLegitimate[0],
        });
      }
    }
  }
  
  return { score: Math.min(100, score), evidence, factors };
}

// ============================================
// REASONING BUILDER
// ============================================

function buildReasoning(
  correlation: CorrelationResult,
  seedSignerEvidence: ClassificationEvaluation,
  approvalDrainEvidence: ClassificationEvaluation,
  contractExploitEvidence: ClassificationEvaluation
): AttackClassificationReasoning {
  return {
    // Seed/Signer compromise factors
    multiWalletDrain: seedSignerEvidence.factors.multiWalletDrain || false,
    withinTimeWindow: seedSignerEvidence.factors.withinTimeWindow || false,
    noSharedMaliciousContract: seedSignerEvidence.factors.noSharedMaliciousContract || false,
    noSharedApprovalTarget: seedSignerEvidence.factors.noSharedApprovalTarget || false,
    fundsRoutedToSameDestination: seedSignerEvidence.factors.fundsRoutedToSameDestination || false,
    includesNativeAssets: seedSignerEvidence.factors.includesNativeAssets || false,
    fullBalanceExtractions: seedSignerEvidence.factors.fullBalanceExtractions || false,
    
    // Approval-based drain factors
    maliciousApprovalFound: approvalDrainEvidence.factors.maliciousApprovalFound || false,
    drainFollowedApproval: approvalDrainEvidence.factors.drainFollowedApproval || false,
    approvalTargetKnownMalicious: approvalDrainEvidence.factors.approvalTargetKnownMalicious || false,
    
    // Contract exploit factors
    sharedContractInteraction: contractExploitEvidence.factors.sharedContractInteraction || false,
    contractKnownVulnerable: contractExploitEvidence.factors.contractKnownVulnerable || false,
    exploitPatternMatched: contractExploitEvidence.factors.exploitPatternMatched || false,
    
    // Why NOT other classifications
    whyNotApprovalDrain: !approvalDrainEvidence.factors.maliciousApprovalFound
      ? 'No suspicious unlimited approvals found that could explain the drains'
      : undefined,
    whyNotContractExploit: !contractExploitEvidence.factors.sharedContractInteraction
      ? 'No shared contract interaction that could be exploited'
      : undefined,
    whyNotSeedCompromise: !seedSignerEvidence.factors.multiWalletDrain
      ? 'Only one wallet affected - seed compromise requires multiple wallets'
      : undefined,
  };
}

// ============================================
// REJECTED CLASSIFICATIONS BUILDER
// ============================================

function buildRejectedClassifications(
  chosen: AttackClassification,
  scores: Record<string, number>,
  seedSignerEvidence: ClassificationEvaluation,
  approvalDrainEvidence: ClassificationEvaluation,
  contractExploitEvidence: ClassificationEvaluation
): RejectedClassification[] {
  const rejected: RejectedClassification[] = [];
  
  const classifications: AttackClassification[] = [
    'SEED_SIGNER_COMPROMISE',
    'APPROVAL_BASED_DRAIN',
    'CONTRACT_EXPLOIT',
    'SINGLE_WALLET_INCIDENT',
  ];
  
  for (const classification of classifications) {
    if (classification === chosen) continue;
    
    let reason = '';
    const contradictingFactors: string[] = [];
    
    switch (classification) {
      case 'SEED_SIGNER_COMPROMISE':
        reason = 'Evidence insufficient for seed/signer compromise';
        if (!seedSignerEvidence.factors.multiWalletDrain) {
          contradictingFactors.push('Single wallet incident');
        }
        if (!seedSignerEvidence.factors.withinTimeWindow) {
          contradictingFactors.push('Drains spread over too long a time window');
        }
        if (!seedSignerEvidence.factors.noSharedApprovalTarget) {
          contradictingFactors.push('Shared approval target exists');
        }
        break;
        
      case 'APPROVAL_BASED_DRAIN':
        reason = 'No evidence of approval-based drain mechanism';
        if (!approvalDrainEvidence.factors.maliciousApprovalFound) {
          contradictingFactors.push('No suspicious unlimited approvals found');
        }
        if (!approvalDrainEvidence.factors.drainFollowedApproval) {
          contradictingFactors.push('Drains did not follow approval transactions');
        }
        break;
        
      case 'CONTRACT_EXPLOIT':
        reason = 'No evidence of smart contract exploit';
        if (!contractExploitEvidence.factors.sharedContractInteraction) {
          contradictingFactors.push('No shared contract interaction detected');
        }
        break;
        
      case 'SINGLE_WALLET_INCIDENT':
        reason = 'Multiple wallets affected';
        contradictingFactors.push('Multiple wallets involved in incident');
        break;
    }
    
    rejected.push({
      classification,
      reason,
      contradictingFactors,
    });
  }
  
  return rejected;
}

// ============================================
// EVIDENCE COLLECTOR
// ============================================

function getEvidenceForClassification(
  classification: AttackClassification,
  seedSignerEvidence: ClassificationEvaluation,
  approvalDrainEvidence: ClassificationEvaluation,
  contractExploitEvidence: ClassificationEvaluation
): ClassificationEvidence[] {
  switch (classification) {
    case 'SEED_SIGNER_COMPROMISE':
      return seedSignerEvidence.evidence;
    case 'APPROVAL_BASED_DRAIN':
      return approvalDrainEvidence.evidence;
    case 'CONTRACT_EXPLOIT':
      return contractExploitEvidence.evidence;
    default:
      return [];
  }
}

// ============================================
// SUMMARY GENERATOR
// ============================================

function generateClassificationSummary(
  classification: AttackClassification,
  score: number,
  walletCount: number,
  reasoning: AttackClassificationReasoning
): string {
  const confidenceText = score >= 85 ? 'High' : score >= 60 ? 'Medium' : 'Low';
  
  switch (classification) {
    case 'SEED_SIGNER_COMPROMISE':
      return `${confidenceText} confidence seed/signer compromise detected. ${walletCount} wallet(s) were drained within a short time window. Funds were routed to the same destination address. This pattern is consistent with a compromised seed phrase or private key that controls multiple wallets. No shared approval or contract exploit explains the drains.`;
      
    case 'APPROVAL_BASED_DRAIN':
      return `${confidenceText} confidence approval-based drain detected. Wallets granted unlimited token approvals to a suspicious address, which was subsequently used to drain funds. This is a common phishing attack pattern.`;
      
    case 'CONTRACT_EXPLOIT':
      return `${confidenceText} confidence contract exploit detected. All affected wallets interacted with a shared smart contract that may have been exploited. Further investigation of the contract is recommended.`;
      
    case 'SINGLE_WALLET_INCIDENT':
      return `Single wallet incident. Only one wallet was affected. Cause may be approval-based drain, phishing, or other single-target attack.`;
      
    case 'UNKNOWN_INSUFFICIENT_EVIDENCE':
    default:
      return `Insufficient evidence to determine attack classification with confidence. The incident does not match known attack patterns clearly. Manual investigation is recommended.`;
  }
}

export { classifyAttack };

