// ============================================
// ETHEREUM WALLET COMPROMISE DETECTOR
// ============================================
// Conservative detection that errs on the side of caution.
// A wallet is ONLY marked SAFE if ALL safety checks pass.
//
// PRINCIPLE: If ANY uncertainty exists → NOT SAFE
//
// Detection Categories:
// A. Approval-Based Compromise
// B. Attacker Behavior Correlation
// C. Time-Based Anomaly Analysis
// D. User Intent Validation
// E. Safe Label Hard Constraints

import { Chain, SecurityStatus, CompromiseReasonCode, CompromiseEvidence } from '@/types';
import { isMaliciousAddress, isDrainerRecipient, isLegitimateContract } from './malicious-database';
import { isSafeContract, isENSContract, isDeFiProtocol } from './safe-contracts';

// ============================================
// INTERFACES
// ============================================

export interface TransactionForAnalysis {
  hash: string;
  from: string;
  to: string;
  value: string;
  input: string;
  timestamp: number;
  blockNumber: number;
  methodId?: string;
  isError?: boolean;
  gasUsed?: string;
}

export interface ApprovalForAnalysis {
  token: string;
  tokenSymbol: string;
  spender: string;
  owner: string;
  amount: string;
  isUnlimited: boolean;
  timestamp: number;
  transactionHash: string;
  blockNumber: number;
  // Enhanced fields
  spenderIsEOA?: boolean;
  spenderIsVerified?: boolean;
  wasRevoked?: boolean;
  revokedTimestamp?: number;
}

export interface TokenTransferForAnalysis {
  from: string;
  to: string;
  value: string;
  hash: string;
  timestamp: number;
  tokenSymbol: string;
  tokenAddress: string;
}

export interface CompromiseAnalysisResult {
  // Final determination
  securityStatus: SecurityStatus;
  
  // Evidence supporting the determination
  evidence: CompromiseEvidence[];
  
  // Reason codes for quick filtering
  reasonCodes: CompromiseReasonCode[];
  
  // Overall confidence (0-100)
  confidence: number;
  
  // Human-readable summary
  summary: string;
  
  // Safety check results
  safetyChecks: SafetyCheckResults;
  
  // Can this wallet be marked SAFE?
  canBeSafe: boolean;
  safetyBlockers: string[];
}

export interface SafetyCheckResults {
  noMaliciousApprovals: boolean;
  noAttackerLinkedTxs: boolean;
  noUnexplainedAssetLoss: boolean;
  noIndirectDrainerExposure: boolean;
  noTimingAnomalies: boolean;
  noSuspiciousApprovalPatterns: boolean;
  allChecksPass: boolean;
}

// ============================================
// CONSTANTS
// ============================================

// Time thresholds
const RAPID_DRAIN_WINDOW_SECONDS = 3600; // 1 hour - drain within this time of approval is suspicious
const MULTI_ASSET_DRAIN_WINDOW_SECONDS = 1800; // 30 minutes - multiple assets drained
const INACTIVE_PERIOD_THRESHOLD_DAYS = 30; // Days of inactivity before sudden activity is suspicious

// Approval thresholds
const UNLIMITED_APPROVAL_THRESHOLD = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff') / BigInt(2);

// Known attacker clusters (addresses linked to multiple victims)
const KNOWN_ATTACKER_CLUSTERS = new Set([
  // Add known attacker wallet clusters here
  '0x0000000000000000000000000000000000000000', // Placeholder
]);

// ============================================
// MAIN ANALYSIS FUNCTION
// ============================================

export async function analyzeWalletCompromise(
  walletAddress: string,
  chain: Chain,
  transactions: TransactionForAnalysis[],
  approvals: ApprovalForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[],
  currentBalance: string
): Promise<CompromiseAnalysisResult> {
  const normalized = walletAddress.toLowerCase();
  const evidence: CompromiseEvidence[] = [];
  const reasonCodes: CompromiseReasonCode[] = [];
  const safetyBlockers: string[] = [];

  // ============================================
  // A. APPROVAL-BASED COMPROMISE DETECTION
  // ============================================
  const approvalEvidence = analyzeApprovals(normalized, approvals, tokenTransfers, transactions);
  evidence.push(...approvalEvidence.evidence);
  reasonCodes.push(...approvalEvidence.reasonCodes);
  if (approvalEvidence.blockers.length > 0) {
    safetyBlockers.push(...approvalEvidence.blockers);
  }

  // ============================================
  // B. ATTACKER BEHAVIOR CORRELATION
  // ============================================
  const attackerEvidence = analyzeAttackerCorrelation(normalized, chain, transactions, tokenTransfers);
  evidence.push(...attackerEvidence.evidence);
  reasonCodes.push(...attackerEvidence.reasonCodes);
  if (attackerEvidence.blockers.length > 0) {
    safetyBlockers.push(...attackerEvidence.blockers);
  }

  // ============================================
  // C. TIME-BASED ANOMALY ANALYSIS
  // ============================================
  const timingEvidence = analyzeTimingAnomalies(normalized, transactions, tokenTransfers, approvals);
  evidence.push(...timingEvidence.evidence);
  reasonCodes.push(...timingEvidence.reasonCodes);
  if (timingEvidence.blockers.length > 0) {
    safetyBlockers.push(...timingEvidence.blockers);
  }

  // ============================================
  // D. USER INTENT VALIDATION
  // ============================================
  const intentEvidence = validateUserIntent(normalized, transactions, approvals, tokenTransfers);
  evidence.push(...intentEvidence.evidence);
  reasonCodes.push(...intentEvidence.reasonCodes);
  if (intentEvidence.blockers.length > 0) {
    safetyBlockers.push(...intentEvidence.blockers);
  }

  // ============================================
  // E. SAFE LABEL HARD CONSTRAINTS
  // ============================================
  const safetyChecks = performSafetyChecks(evidence, reasonCodes, approvals, transactions, tokenTransfers, normalized, chain);

  // ============================================
  // DETERMINE FINAL STATUS
  // ============================================
  const { status, confidence, summary } = determineSecurityStatus(
    evidence,
    reasonCodes,
    safetyChecks,
    safetyBlockers
  );

  return {
    securityStatus: status,
    evidence,
    reasonCodes,
    confidence,
    summary,
    safetyChecks,
    canBeSafe: safetyChecks.allChecksPass && safetyBlockers.length === 0,
    safetyBlockers,
  };
}

// ============================================
// A. APPROVAL-BASED COMPROMISE DETECTION
// ============================================

function analyzeApprovals(
  walletAddress: string,
  approvals: ApprovalForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[],
  transactions: TransactionForAnalysis[]
): { evidence: CompromiseEvidence[]; reasonCodes: CompromiseReasonCode[]; blockers: string[] } {
  const evidence: CompromiseEvidence[] = [];
  const reasonCodes: CompromiseReasonCode[] = [];
  const blockers: string[] = [];

  for (const approval of approvals) {
    const spenderNormalized = approval.spender.toLowerCase();
    
    // CHECK 1: Unlimited approval to EOA (not a contract)
    if (approval.isUnlimited && approval.spenderIsEOA) {
      evidence.push({
        code: 'UNLIMITED_APPROVAL_EOA',
        severity: 'CRITICAL',
        description: `Unlimited approval granted to EOA ${spenderNormalized.slice(0, 10)}... for ${approval.tokenSymbol}. EOAs should not have unlimited approvals.`,
        relatedTxHash: approval.transactionHash,
        relatedAddress: spenderNormalized,
        timestamp: new Date(approval.timestamp * 1000).toISOString(),
        confidence: 95,
      });
      reasonCodes.push('UNLIMITED_APPROVAL_EOA');
      blockers.push(`Unlimited approval to EOA: ${spenderNormalized.slice(0, 10)}...`);
    }

    // CHECK 2: Unlimited approval to unverified contract
    if (approval.isUnlimited && !approval.spenderIsVerified && !isSafeContract(spenderNormalized)) {
      if (!isLegitimateContract(spenderNormalized) && !isDeFiProtocol(spenderNormalized)) {
        evidence.push({
          code: 'UNLIMITED_APPROVAL_UNVERIFIED',
          severity: 'HIGH',
          description: `Unlimited approval to unverified contract ${spenderNormalized.slice(0, 10)}... for ${approval.tokenSymbol}.`,
          relatedTxHash: approval.transactionHash,
          relatedAddress: spenderNormalized,
          timestamp: new Date(approval.timestamp * 1000).toISOString(),
          confidence: 80,
        });
        reasonCodes.push('UNLIMITED_APPROVAL_UNVERIFIED');
        blockers.push(`Unlimited approval to unverified contract: ${spenderNormalized.slice(0, 10)}...`);
      }
    }

    // CHECK 2b: ANY approval to unverified contract is a safety blocker (conservative)
    // Even if not unlimited, approvals to unverified contracts create uncertainty
    if (!approval.spenderIsVerified && !isSafeContract(spenderNormalized)) {
      if (!isLegitimateContract(spenderNormalized) && !isDeFiProtocol(spenderNormalized)) {
        evidence.push({
          code: 'SUSPICIOUS_APPROVAL_PATTERN',
          severity: 'MEDIUM',
          description: `Approval to unverified contract ${spenderNormalized.slice(0, 10)}... for ${approval.tokenSymbol}. Cannot verify legitimacy.`,
          relatedTxHash: approval.transactionHash,
          relatedAddress: spenderNormalized,
          timestamp: new Date(approval.timestamp * 1000).toISOString(),
          confidence: 50,
        });
        reasonCodes.push('SUSPICIOUS_APPROVAL_PATTERN');
        blockers.push(`Approval to unverified contract: ${spenderNormalized.slice(0, 10)}...`);
      }
    }

    // CHECK 3: Approval followed by drain (attacker-controlled transfer)
    const drainAfterApproval = tokenTransfers.find(transfer => {
      const transferTime = transfer.timestamp;
      const approvalTime = approval.timestamp;
      const timeDelta = transferTime - approvalTime;
      
      // Transfer within 1 hour of approval, from wallet, to unknown address
      return (
        timeDelta > 0 &&
        timeDelta <= RAPID_DRAIN_WINDOW_SECONDS &&
        transfer.from.toLowerCase() === walletAddress &&
        transfer.tokenAddress.toLowerCase() === approval.token.toLowerCase() &&
        !isSafeContract(transfer.to.toLowerCase()) &&
        !isLegitimateContract(transfer.to.toLowerCase())
      );
    });

    if (drainAfterApproval) {
      evidence.push({
        code: 'APPROVAL_THEN_DRAIN',
        severity: 'CRITICAL',
        description: `Token ${approval.tokenSymbol} was transferred out within ${Math.round((drainAfterApproval.timestamp - approval.timestamp) / 60)} minutes of approval.`,
        relatedTxHash: drainAfterApproval.hash,
        relatedAddress: drainAfterApproval.to,
        timestamp: new Date(drainAfterApproval.timestamp * 1000).toISOString(),
        confidence: 90,
      });
      reasonCodes.push('APPROVAL_THEN_DRAIN');
      blockers.push(`Drain detected after approval: ${drainAfterApproval.hash.slice(0, 10)}...`);
    }

    // CHECK 4: Approval revoked AFTER asset loss (post-incident signal)
    if (approval.wasRevoked && approval.revokedTimestamp) {
      // Check if assets were lost before revocation
      const lostAssets = tokenTransfers.filter(transfer => {
        return (
          transfer.timestamp < approval.revokedTimestamp! &&
          transfer.timestamp > approval.timestamp &&
          transfer.from.toLowerCase() === walletAddress &&
          transfer.tokenAddress.toLowerCase() === approval.token.toLowerCase()
        );
      });

      if (lostAssets.length > 0) {
        evidence.push({
          code: 'POST_INCIDENT_REVOKE',
          severity: 'HIGH',
          description: `Approval for ${approval.tokenSymbol} was revoked AFTER ${lostAssets.length} transfer(s) occurred. This indicates post-incident cleanup.`,
          relatedTxHash: approval.transactionHash,
          relatedAddress: spenderNormalized,
          confidence: 85,
        });
        reasonCodes.push('POST_INCIDENT_REVOKE');
        blockers.push(`Post-incident revocation detected for ${approval.tokenSymbol}`);
      }
    }

    // CHECK 5: Approval to known drainer/malicious address
    const maliciousInfo = isMaliciousAddress(spenderNormalized, 'ethereum');
    if (maliciousInfo || isDrainerRecipient(spenderNormalized)) {
      evidence.push({
        code: 'ATTACKER_LINKED_ADDRESS',
        severity: 'CRITICAL',
        description: `Approval granted to known malicious address: ${maliciousInfo?.name || 'Drainer'}`,
        relatedTxHash: approval.transactionHash,
        relatedAddress: spenderNormalized,
        timestamp: new Date(approval.timestamp * 1000).toISOString(),
        confidence: 99,
      });
      reasonCodes.push('ATTACKER_LINKED_ADDRESS');
      blockers.push(`Approval to known malicious address: ${spenderNormalized.slice(0, 10)}...`);
    }
  }

  return { evidence, reasonCodes, blockers };
}

// ============================================
// B. ATTACKER BEHAVIOR CORRELATION
// ============================================

function analyzeAttackerCorrelation(
  walletAddress: string,
  chain: Chain,
  transactions: TransactionForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[]
): { evidence: CompromiseEvidence[]; reasonCodes: CompromiseReasonCode[]; blockers: string[] } {
  const evidence: CompromiseEvidence[] = [];
  const reasonCodes: CompromiseReasonCode[] = [];
  const blockers: string[] = [];

  // Collect all addresses this wallet has interacted with
  const interactedAddresses = new Set<string>();
  
  for (const tx of transactions) {
    if (tx.from.toLowerCase() === walletAddress) {
      interactedAddresses.add(tx.to.toLowerCase());
    }
    if (tx.to.toLowerCase() === walletAddress) {
      interactedAddresses.add(tx.from.toLowerCase());
    }
  }

  for (const transfer of tokenTransfers) {
    if (transfer.from.toLowerCase() === walletAddress) {
      interactedAddresses.add(transfer.to.toLowerCase());
    }
    if (transfer.to.toLowerCase() === walletAddress) {
      interactedAddresses.add(transfer.from.toLowerCase());
    }
  }

  // CHECK 1: Interaction with known drainer/sweeper clusters
  for (const addr of interactedAddresses) {
    const maliciousInfo = isMaliciousAddress(addr, chain);
    if (maliciousInfo) {
      evidence.push({
        code: 'DRAINER_CLUSTER_INTERACTION',
        severity: 'CRITICAL',
        description: `Wallet interacted with known malicious address: ${maliciousInfo.name} (${addr.slice(0, 10)}...)`,
        relatedAddress: addr,
        confidence: 95,
      });
      reasonCodes.push('DRAINER_CLUSTER_INTERACTION');
      blockers.push(`Interaction with known drainer: ${addr.slice(0, 10)}...`);
    }

    if (isDrainerRecipient(addr)) {
      evidence.push({
        code: 'DRAINER_CLUSTER_INTERACTION',
        severity: 'HIGH',
        description: `Wallet sent funds to known drainer recipient: ${addr.slice(0, 10)}...`,
        relatedAddress: addr,
        confidence: 90,
      });
      reasonCodes.push('DRAINER_CLUSTER_INTERACTION');
      blockers.push(`Sent funds to drainer recipient: ${addr.slice(0, 10)}...`);
    }

    // Check attacker clusters
    if (KNOWN_ATTACKER_CLUSTERS.has(addr)) {
      evidence.push({
        code: 'SHARED_ATTACKER_PATTERN',
        severity: 'CRITICAL',
        description: `Wallet interacted with address linked to multiple victim attacks: ${addr.slice(0, 10)}...`,
        relatedAddress: addr,
        confidence: 92,
      });
      reasonCodes.push('SHARED_ATTACKER_PATTERN');
      blockers.push(`Interaction with multi-victim attacker: ${addr.slice(0, 10)}...`);
    }
  }

  // CHECK 2: Funds sent to unknown addresses (not safe contracts, not exchanges)
  const outgoingToUnknown = tokenTransfers.filter(transfer => {
    if (transfer.from.toLowerCase() !== walletAddress) return false;
    const to = transfer.to.toLowerCase();
    return !isSafeContract(to) && !isLegitimateContract(to) && !isDeFiProtocol(to);
  });

  if (outgoingToUnknown.length > 0) {
    // Group by destination
    const destCounts = new Map<string, number>();
    for (const t of outgoingToUnknown) {
      const dest = t.to.toLowerCase();
      destCounts.set(dest, (destCounts.get(dest) || 0) + 1);
    }

    // If funds sent to multiple unknown addresses, flag
    if (destCounts.size >= 3) {
      evidence.push({
        code: 'UNKNOWN_RECIPIENT_DRAIN',
        severity: 'MEDIUM',
        description: `Funds sent to ${destCounts.size} unknown addresses. Review these recipients.`,
        confidence: 60,
      });
      reasonCodes.push('UNKNOWN_RECIPIENT_DRAIN');
      blockers.push(`Funds sent to ${destCounts.size} unknown addresses`);
    }
  }

  return { evidence, reasonCodes, blockers };
}

// ============================================
// C. TIME-BASED ANOMALY ANALYSIS
// ============================================

function analyzeTimingAnomalies(
  walletAddress: string,
  transactions: TransactionForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[],
  approvals: ApprovalForAnalysis[]
): { evidence: CompromiseEvidence[]; reasonCodes: CompromiseReasonCode[]; blockers: string[] } {
  const evidence: CompromiseEvidence[] = [];
  const reasonCodes: CompromiseReasonCode[] = [];
  const blockers: string[] = [];

  // Sort transactions by timestamp
  const sortedTxs = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
  const sortedTransfers = [...tokenTransfers].sort((a, b) => a.timestamp - b.timestamp);

  // CHECK 1: Sudden asset outflows shortly after approvals
  for (const approval of approvals) {
    const outflowsAfterApproval = sortedTransfers.filter(t => {
      const timeDelta = t.timestamp - approval.timestamp;
      return (
        timeDelta > 0 &&
        timeDelta <= RAPID_DRAIN_WINDOW_SECONDS &&
        t.from.toLowerCase() === walletAddress
      );
    });

    if (outflowsAfterApproval.length >= 2) {
      evidence.push({
        code: 'SUDDEN_OUTFLOW_POST_APPROVAL',
        severity: 'HIGH',
        description: `${outflowsAfterApproval.length} outgoing transfers within 1 hour of approval. Possible drain in progress.`,
        relatedTxHash: approval.transactionHash,
        timestamp: new Date(approval.timestamp * 1000).toISOString(),
        confidence: 75,
      });
      reasonCodes.push('SUDDEN_OUTFLOW_POST_APPROVAL');
      blockers.push(`Rapid outflows after approval detected`);
    }
  }

  // CHECK 2: Multiple asset types drained within short window
  const outgoingTransfers = sortedTransfers.filter(t => t.from.toLowerCase() === walletAddress);
  
  // Group transfers by 30-minute windows
  const windowGroups = new Map<number, TokenTransferForAnalysis[]>();
  for (const transfer of outgoingTransfers) {
    const windowKey = Math.floor(transfer.timestamp / MULTI_ASSET_DRAIN_WINDOW_SECONDS);
    if (!windowGroups.has(windowKey)) {
      windowGroups.set(windowKey, []);
    }
    windowGroups.get(windowKey)!.push(transfer);
  }

  for (const [windowKey, transfers] of windowGroups) {
    const uniqueTokens = new Set(transfers.map(t => t.tokenAddress.toLowerCase()));
    if (uniqueTokens.size >= 3) {
      evidence.push({
        code: 'MULTI_ASSET_RAPID_DRAIN',
        severity: 'CRITICAL',
        description: `${uniqueTokens.size} different tokens transferred out within 30 minutes. Classic drain pattern.`,
        timestamp: new Date(windowKey * MULTI_ASSET_DRAIN_WINDOW_SECONDS * 1000).toISOString(),
        confidence: 88,
      });
      reasonCodes.push('MULTI_ASSET_RAPID_DRAIN');
      blockers.push(`Multi-asset rapid drain detected: ${uniqueTokens.size} tokens`);
    }
  }

  // CHECK 3: Activity after long inactivity period
  if (sortedTxs.length >= 2) {
    for (let i = 1; i < sortedTxs.length; i++) {
      const gap = sortedTxs[i].timestamp - sortedTxs[i - 1].timestamp;
      const gapDays = gap / (24 * 60 * 60);
      
      if (gapDays >= INACTIVE_PERIOD_THRESHOLD_DAYS) {
        // Check if the activity after the gap is outgoing
        const txAfterGap = sortedTxs[i];
        if (txAfterGap.from.toLowerCase() === walletAddress) {
          const isToKnownSafe = isSafeContract(txAfterGap.to.toLowerCase()) || 
                                isLegitimateContract(txAfterGap.to.toLowerCase());
          
          if (!isToKnownSafe) {
            evidence.push({
              code: 'INACTIVE_PERIOD_DRAIN',
              severity: 'MEDIUM',
              description: `Outgoing transaction after ${Math.round(gapDays)} days of inactivity to unknown address.`,
              relatedTxHash: txAfterGap.hash,
              relatedAddress: txAfterGap.to,
              timestamp: new Date(txAfterGap.timestamp * 1000).toISOString(),
              confidence: 55,
            });
            reasonCodes.push('INACTIVE_PERIOD_DRAIN');
            blockers.push(`Activity after ${Math.round(gapDays)} days of inactivity`);
          }
        }
      }
    }
  }

  return { evidence, reasonCodes, blockers };
}

// ============================================
// D. USER INTENT VALIDATION
// ============================================

function validateUserIntent(
  walletAddress: string,
  transactions: TransactionForAnalysis[],
  approvals: ApprovalForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[]
): { evidence: CompromiseEvidence[]; reasonCodes: CompromiseReasonCode[]; blockers: string[] } {
  const evidence: CompromiseEvidence[] = [];
  const reasonCodes: CompromiseReasonCode[] = [];
  const blockers: string[] = [];

  // DO NOT assume transactions are user-initiated just because:
  // - Gas was paid by the wallet
  // - The contract is known (OpenSea, ENS, routers)
  
  // CHECK: Approval-to-transfer causality
  // If there's an approval and then a transferFrom, the user may not have initiated the transfer
  
  for (const approval of approvals) {
    if (approval.isUnlimited || BigInt(approval.amount) > UNLIMITED_APPROVAL_THRESHOLD) {
      // Check if this approval was followed by transfers via transferFrom
      const spender = approval.spender.toLowerCase();
      
      // Look for transactions where spender called transferFrom
      const spenderInitiatedTransfers = transactions.filter(tx => {
        if (tx.from.toLowerCase() !== spender) return false;
        if (!tx.input) return false;
        
        // Check for transferFrom signature (0x23b872dd)
        const methodId = tx.input.slice(0, 10).toLowerCase();
        return methodId === '0x23b872dd';
      });

      if (spenderInitiatedTransfers.length > 0) {
        // Verify this wasn't to a known safe protocol
        const suspicious = spenderInitiatedTransfers.filter(tx => {
          return !isSafeContract(tx.to.toLowerCase()) && !isLegitimateContract(tx.to.toLowerCase());
        });

        if (suspicious.length > 0) {
          evidence.push({
            code: 'APPROVAL_THEN_DRAIN',
            severity: 'HIGH',
            description: `Spender ${spender.slice(0, 10)}... executed ${suspicious.length} transferFrom call(s) after receiving approval.`,
            relatedAddress: spender,
            confidence: 82,
          });
          reasonCodes.push('APPROVAL_THEN_DRAIN');
          blockers.push(`Spender-initiated transfers detected`);
        }
      }
    }
  }

  // CHECK: Unexplained asset loss
  // If wallet balance decreased significantly without clear user-initiated transactions
  const totalOutgoing = tokenTransfers
    .filter(t => t.from.toLowerCase() === walletAddress)
    .reduce((sum, t) => sum + BigInt(t.value || '0'), BigInt(0));

  const totalIncoming = tokenTransfers
    .filter(t => t.to.toLowerCase() === walletAddress)
    .reduce((sum, t) => sum + BigInt(t.value || '0'), BigInt(0));

  if (totalOutgoing > totalIncoming * BigInt(10)) {
    // Significant net outflow
    const outgoingToUnknown = tokenTransfers.filter(t => {
      if (t.from.toLowerCase() !== walletAddress) return false;
      const to = t.to.toLowerCase();
      return !isSafeContract(to) && !isLegitimateContract(to);
    });

    if (outgoingToUnknown.length > 0) {
      evidence.push({
        code: 'UNEXPLAINED_ASSET_LOSS',
        severity: 'MEDIUM',
        description: `Significant asset outflow to ${outgoingToUnknown.length} unknown address(es). Verify these were intentional.`,
        confidence: 50,
      });
      reasonCodes.push('UNEXPLAINED_ASSET_LOSS');
      blockers.push(`Unexplained asset loss detected`);
    }
  }

  return { evidence, reasonCodes, blockers };
}

// ============================================
// E. SAFE LABEL HARD CONSTRAINTS
// ============================================

function performSafetyChecks(
  evidence: CompromiseEvidence[],
  reasonCodes: CompromiseReasonCode[],
  approvals: ApprovalForAnalysis[],
  transactions: TransactionForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[],
  walletAddress: string,
  chain: Chain
): SafetyCheckResults {
  // CHECK 1: No malicious approvals
  const hasMaliciousApprovals = reasonCodes.some(code => 
    code === 'UNLIMITED_APPROVAL_EOA' ||
    code === 'UNLIMITED_APPROVAL_UNVERIFIED' ||
    code === 'ATTACKER_LINKED_ADDRESS'
  );

  // CHECK 2: No attacker-linked transactions
  const hasAttackerLinkedTxs = reasonCodes.some(code =>
    code === 'DRAINER_CLUSTER_INTERACTION' ||
    code === 'SHARED_ATTACKER_PATTERN'
  );

  // CHECK 3: No unexplained asset loss
  const hasUnexplainedLoss = reasonCodes.some(code =>
    code === 'UNEXPLAINED_ASSET_LOSS' ||
    code === 'APPROVAL_THEN_DRAIN' ||
    code === 'UNKNOWN_RECIPIENT_DRAIN'
  );

  // CHECK 4: No indirect drainer exposure
  const hasIndirectExposure = reasonCodes.some(code =>
    code === 'INDIRECT_DRAINER_EXPOSURE'
  );

  // CHECK 5: No timing anomalies
  const hasTimingAnomalies = reasonCodes.some(code =>
    code === 'SUDDEN_OUTFLOW_POST_APPROVAL' ||
    code === 'INACTIVE_PERIOD_DRAIN' ||
    code === 'MULTI_ASSET_RAPID_DRAIN'
  );

  // CHECK 6: No suspicious approval patterns
  const hasSuspiciousApprovals = reasonCodes.some(code =>
    code === 'SUSPICIOUS_APPROVAL_PATTERN' ||
    code === 'POST_INCIDENT_REVOKE'
  );

  const allChecksPass = 
    !hasMaliciousApprovals &&
    !hasAttackerLinkedTxs &&
    !hasUnexplainedLoss &&
    !hasIndirectExposure &&
    !hasTimingAnomalies &&
    !hasSuspiciousApprovals;

  return {
    noMaliciousApprovals: !hasMaliciousApprovals,
    noAttackerLinkedTxs: !hasAttackerLinkedTxs,
    noUnexplainedAssetLoss: !hasUnexplainedLoss,
    noIndirectDrainerExposure: !hasIndirectExposure,
    noTimingAnomalies: !hasTimingAnomalies,
    noSuspiciousApprovalPatterns: !hasSuspiciousApprovals,
    allChecksPass,
  };
}

// ============================================
// DETERMINE FINAL STATUS
// ============================================

function determineSecurityStatus(
  evidence: CompromiseEvidence[],
  reasonCodes: CompromiseReasonCode[],
  safetyChecks: SafetyCheckResults,
  safetyBlockers: string[]
): { status: SecurityStatus; confidence: number; summary: string } {
  // Calculate overall confidence from evidence
  const avgConfidence = evidence.length > 0
    ? evidence.reduce((sum, e) => sum + e.confidence, 0) / evidence.length
    : 0;

  // Count by severity
  const criticalCount = evidence.filter(e => e.severity === 'CRITICAL').length;
  const highCount = evidence.filter(e => e.severity === 'HIGH').length;
  const mediumCount = evidence.filter(e => e.severity === 'MEDIUM').length;
  const lowCount = evidence.filter(e => e.severity === 'LOW').length;

  // ============================================
  // FINAL CHECK BEFORE RETURNING SAFE:
  // "Would this wallet still be safe if the owner lost control of approvals?"
  // ============================================

  // CONFIRMED COMPROMISED: Strong evidence of compromise
  if (criticalCount >= 1 || (highCount >= 2 && avgConfidence >= 75)) {
    const topReasons = reasonCodes.slice(0, 3).join(', ');
    return {
      status: 'COMPROMISED',
      confidence: Math.min(99, avgConfidence + 10),
      summary: `CONFIRMED COMPROMISED: ${criticalCount} critical and ${highCount} high severity indicators detected. Reasons: ${topReasons}. Immediate action required.`,
    };
  }

  // AT_RISK: Clear risk indicators present
  if (highCount >= 1 || (mediumCount >= 2 && avgConfidence >= 60)) {
    const topReasons = reasonCodes.slice(0, 3).join(', ');
    return {
      status: 'AT_RISK',
      confidence: avgConfidence,
      summary: `AT RISK: ${highCount} high and ${mediumCount} medium severity indicators detected. Reasons: ${topReasons}. Review and secure immediately.`,
    };
  }

  // POTENTIALLY_COMPROMISED: ANY evidence at all means we cannot confirm safety
  // This is the core conservative principle: if there's ANY doubt, don't say SAFE
  if (evidence.length > 0) {
    const blockerText = safetyBlockers.length > 0 
      ? `Safety blockers: ${safetyBlockers.slice(0, 3).join('; ')}`
      : `${mediumCount} medium and ${lowCount} low severity indicators found`;
    return {
      status: 'POTENTIALLY_COMPROMISED',
      confidence: Math.max(30, avgConfidence),
      summary: `POTENTIALLY COMPROMISED: Cannot confirm safety. ${blockerText}. Manual review recommended.`,
    };
  }

  // POTENTIALLY_COMPROMISED: Safety blockers exist
  if (safetyBlockers.length > 0) {
    return {
      status: 'POTENTIALLY_COMPROMISED',
      confidence: 40,
      summary: `POTENTIALLY COMPROMISED: Safety blockers detected: ${safetyBlockers.slice(0, 3).join('; ')}. Cannot confirm this wallet is safe.`,
    };
  }

  // POTENTIALLY_COMPROMISED: Safety checks didn't pass
  if (!safetyChecks.allChecksPass) {
    const failedChecks: string[] = [];
    if (!safetyChecks.noMaliciousApprovals) failedChecks.push('malicious approvals');
    if (!safetyChecks.noAttackerLinkedTxs) failedChecks.push('attacker-linked txs');
    if (!safetyChecks.noUnexplainedAssetLoss) failedChecks.push('unexplained asset loss');
    if (!safetyChecks.noIndirectDrainerExposure) failedChecks.push('drainer exposure');
    if (!safetyChecks.noTimingAnomalies) failedChecks.push('timing anomalies');
    if (!safetyChecks.noSuspiciousApprovalPatterns) failedChecks.push('suspicious approvals');
    
    return {
      status: 'POTENTIALLY_COMPROMISED',
      confidence: 35,
      summary: `POTENTIALLY COMPROMISED: Safety checks failed: ${failedChecks.join(', ')}. Cannot confirm safety.`,
    };
  }

  // SAFE: ONLY if ALL of the following are true:
  // - Zero evidence of any kind
  // - Zero safety blockers
  // - All safety checks pass
  // - No approvals to unknown contracts (checked via blockers)
  if (safetyChecks.allChecksPass && evidence.length === 0 && safetyBlockers.length === 0) {
    return {
      status: 'SAFE',
      confidence: 95,
      summary: 'SAFE: All safety checks passed. No malicious approvals, no attacker interactions, no unexplained losses detected.',
    };
  }

  // Default to POTENTIALLY_COMPROMISED - when in doubt, don't mark safe
  return {
    status: 'POTENTIALLY_COMPROMISED',
    confidence: 30,
    summary: 'POTENTIALLY COMPROMISED: Unable to fully verify wallet safety. Review recommended.',
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  analyzeWalletCompromise as default,
  RAPID_DRAIN_WINDOW_SECONDS,
  MULTI_ASSET_DRAIN_WINDOW_SECONDS,
  UNLIMITED_APPROVAL_THRESHOLD,
};

