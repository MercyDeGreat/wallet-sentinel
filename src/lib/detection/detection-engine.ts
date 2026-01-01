// ============================================
// WALLET SENTINEL - CORE DETECTION ENGINE
// ============================================
// This is the main security analysis engine that coordinates
// threat detection across all supported chains.
// All operations are READ-ONLY and defensive.

import {
  AttackType,
  Chain,
  DetectedThreat,
  RiskLevel,
  SecurityStatus,
  TokenApproval,
  SuspiciousTransaction,
  WalletAnalysisResult,
} from '@/types';
import {
  isMaliciousAddress,
  isInfiniteApproval,
  DRAINER_PATTERNS,
  getAttackTypeFromPattern,
} from './malicious-database';

// ============================================
// RISK SCORING SYSTEM
// ============================================

interface RiskFactors {
  maliciousInteractions: number;
  infiniteApprovals: number;
  suspiciousTransactions: number;
  recentDrainActivity: number;
  highRiskApprovals: number;
  unknownContractInteractions: number;
}

export function calculateRiskScore(factors: RiskFactors): number {
  let score = 0;

  // Malicious interactions are heavily weighted
  score += factors.maliciousInteractions * 30;
  // Infinite approvals are dangerous
  score += factors.infiniteApprovals * 15;
  // Suspicious transactions
  score += factors.suspiciousTransactions * 10;
  // Recent drain activity is critical
  score += factors.recentDrainActivity * 40;
  // High-risk approvals
  score += factors.highRiskApprovals * 20;
  // Unknown contracts add minor risk
  score += factors.unknownContractInteractions * 5;

  // Clamp to 0-100
  return Math.min(100, Math.max(0, score));
}

export function determineSecurityStatus(riskScore: number, threats: DetectedThreat[]): SecurityStatus {
  // Check for critical active threats
  const hasCriticalThreat = threats.some(
    (t) => t.severity === 'CRITICAL' && t.ongoingRisk
  );

  if (hasCriticalThreat || riskScore >= 70) {
    return 'COMPROMISED';
  }

  if (riskScore >= 30 || threats.length > 0) {
    return 'AT_RISK';
  }

  return 'SAFE';
}

// ============================================
// THREAT DETECTION HEURISTICS
// ============================================

export interface TransactionData {
  hash: string;
  from: string;
  to: string;
  value: string;
  input: string;
  timestamp: number;
  blockNumber: number;
  methodId?: string;
}

export interface ApprovalData {
  token: string;
  tokenName: string;
  tokenSymbol: string;
  spender: string;
  amount: string;
  timestamp: number;
  transactionHash: string;
}

export function detectDrainerPatterns(
  transactions: TransactionData[],
  chain: Chain
): DetectedThreat[] {
  const threats: DetectedThreat[] = [];
  
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions : [];
  if (safeTxs.length === 0) return threats;

  // Pattern 1: Rapid outflow detection
  const rapidOutflow = detectRapidOutflow(safeTxs);
  if (rapidOutflow) {
    threats.push(rapidOutflow);
  }

  // Pattern 2: Approval followed by drain
  const approvalDrain = detectApprovalDrain(safeTxs);
  if (approvalDrain) {
    threats.push(approvalDrain);
  }

  // Pattern 3: Known malicious contract interaction
  const maliciousInteractions = detectMaliciousInteractions(safeTxs, chain);
  threats.push(...maliciousInteractions);

  // Pattern 4: Sandwich attack detection
  const sandwichAttack = detectSandwichPattern(safeTxs);
  if (sandwichAttack) {
    threats.push(sandwichAttack);
  }

  return threats;
}

function detectRapidOutflow(transactions: TransactionData[]): DetectedThreat | null {
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
  if (safeTxs.length === 0) return null;
  
  // Sort transactions by timestamp
  const sorted = [...safeTxs].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));

  // Look for multiple outbound transfers in short window
  const windowMinutes = 10;
  const threshold = 5;

  for (let i = 0; i < sorted.length; i++) {
    const currentTx = sorted[i];
    if (!currentTx?.timestamp || !currentTx?.from) continue;
    
    const windowStart = currentTx.timestamp;
    const windowEnd = windowStart + windowMinutes * 60;

    const txsInWindow = sorted.filter(
      (tx) => tx?.timestamp && tx.timestamp >= windowStart && tx.timestamp <= windowEnd
    );

    // Check if these are outbound transfers
    const outboundTxs = txsInWindow.filter(
      (tx) => tx?.from?.toLowerCase?.() === currentTx.from.toLowerCase() &&
             BigInt(tx?.value || '0') > BigInt(0)
    );

    if (outboundTxs.length >= threshold) {
      return {
        id: `rapid-outflow-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: 'CRITICAL',
        title: 'Rapid Asset Outflow Detected',
        description: `${outboundTxs.length} outbound transactions detected within ${windowMinutes} minutes. This pattern is consistent with wallet drainer activity.`,
        technicalDetails: `Transactions: ${outboundTxs.map((tx) => tx?.hash || 'unknown').join(', ')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [...new Set(outboundTxs.map((tx) => tx?.to).filter(Boolean) as string[])],
        relatedTransactions: outboundTxs.map((tx) => tx?.hash).filter(Boolean) as string[],
        ongoingRisk: true,
      };
    }
  }

  return null;
}

function detectApprovalDrain(transactions: TransactionData[]): DetectedThreat | null {
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
  if (safeTxs.length === 0) return null;
  
  // Look for approval followed by transferFrom pattern
  const approvalSigs = ['0x095ea7b3', '0xa22cb465'];
  const transferSigs = ['0x23b872dd', '0x42842e0e'];

  const approvals = safeTxs.filter((tx) =>
    tx?.input && approvalSigs.some((sig) => tx.input.startsWith(sig))
  );

  for (const approval of approvals) {
    if (!approval?.timestamp || !approval?.hash) continue;
    
    // Look for transfers shortly after approval
    const windowSeconds = 300; // 5 minutes
    const transfers = safeTxs.filter(
      (tx) =>
        tx?.timestamp &&
        tx.timestamp > approval.timestamp &&
        tx.timestamp <= approval.timestamp + windowSeconds &&
        tx?.input &&
        transferSigs.some((sig) => tx.input.startsWith(sig))
    );

    if (transfers.length > 0) {
      return {
        id: `approval-drain-${Date.now()}`,
        type: 'APPROVAL_HIJACK',
        severity: 'HIGH',
        title: 'Approval Abuse Detected',
        description: 'An approval was granted and immediately used to transfer assets. This is a common drainer pattern.',
        technicalDetails: `Approval TX: ${approval.hash}, Drain TXs: ${transfers.map((tx) => tx?.hash || 'unknown').join(', ')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [approval.to, ...transfers.map((tx) => tx?.to)].filter(Boolean) as string[],
        relatedTransactions: [approval.hash, ...transfers.map((tx) => tx?.hash)].filter(Boolean) as string[],
        ongoingRisk: true,
      };
    }
  }

  return null;
}

function detectMaliciousInteractions(
  transactions: TransactionData[],
  chain: Chain
): DetectedThreat[] {
  const threats: DetectedThreat[] = [];
  
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];

  for (const tx of safeTxs) {
    if (!tx?.to || !tx?.hash) continue;
    
    const maliciousContract = isMaliciousAddress(tx.to, chain);
    if (maliciousContract) {
      threats.push({
        id: `malicious-interaction-${tx.hash}`,
        type: maliciousContract.type,
        severity: 'CRITICAL',
        title: 'Interaction with Known Malicious Contract',
        description: `This wallet interacted with a known malicious contract: ${maliciousContract.name || tx.to}`,
        technicalDetails: `Contract: ${tx.to}, Type: ${maliciousContract.type}, Confirmed: ${maliciousContract.confirmationLevel}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [tx.to],
        relatedTransactions: [tx.hash],
        ongoingRisk: maliciousContract.type === 'WALLET_DRAINER',
      });
    }
  }

  return threats;
}

function detectSandwichPattern(transactions: TransactionData[]): DetectedThreat | null {
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
  if (safeTxs.length < 3) return null;
  
  // Look for sandwich attack patterns
  // Front-run -> Victim -> Back-run
  const sorted = [...safeTxs].sort((a, b) => (a?.blockNumber || 0) - (b?.blockNumber || 0));

  for (let i = 1; i < sorted.length - 1; i++) {
    const prev = sorted[i - 1];
    const curr = sorted[i];
    const next = sorted[i + 1];

    // Skip if any transaction is missing required fields
    if (!prev?.blockNumber || !curr?.blockNumber || !next?.blockNumber) continue;
    if (!prev?.from || !curr?.from || !next?.from) continue;
    if (!prev?.hash || !curr?.hash || !next?.hash) continue;

    // Check if same block and similar addresses in prev/next
    if (
      prev.blockNumber === curr.blockNumber &&
      curr.blockNumber === next.blockNumber &&
      prev.from === next.from &&
      prev.from !== curr.from
    ) {
      // Potential sandwich
      return {
        id: `sandwich-${Date.now()}`,
        type: 'MEV_SANDWICH_DRAIN',
        severity: 'HIGH',
        title: 'MEV Sandwich Attack Detected',
        description: 'Your transaction was sandwiched by MEV bots, potentially causing value extraction.',
        technicalDetails: `Block: ${curr.blockNumber}, Sandwich by: ${prev.from}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [prev.from],
        relatedTransactions: [prev.hash, curr.hash, next.hash],
        ongoingRisk: false,
      };
    }
  }

  return null;
}

// ============================================
// APPROVAL ANALYSIS
// ============================================

export function analyzeApprovals(approvals: ApprovalData[], chain: Chain): TokenApproval[] {
  // Safe array guard
  const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];
  
  return safeApprovals.map((approval) => {
    const isUnlimited = isInfiniteApproval(approval?.amount || '0');
    const isMalicious = approval?.spender ? isMaliciousAddress(approval.spender, chain) !== null : false;

    let riskLevel: RiskLevel = 'LOW';
    let riskReason: string | undefined;

    if (isMalicious) {
      riskLevel = 'CRITICAL';
      riskReason = 'Approved spender is a known malicious contract';
    } else if (isUnlimited) {
      riskLevel = 'HIGH';
      riskReason = 'Unlimited approval amount - spender can drain all tokens';
    }

    return {
      id: `approval-${approval.transactionHash}`,
      token: {
        address: approval.token,
        symbol: approval.tokenSymbol,
        name: approval.tokenName,
        decimals: 18,
        standard: 'ERC20',
        verified: true,
      },
      spender: approval.spender,
      amount: approval.amount,
      isUnlimited,
      riskLevel,
      riskReason,
      grantedAt: new Date(approval.timestamp * 1000).toISOString(),
      isMalicious,
    };
  });
}

// ============================================
// BEHAVIORAL INFERENCE
// ============================================

export function inferPrivateKeyCompromise(transactions: TransactionData[]): DetectedThreat | null {
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
  if (safeTxs.length === 0) return null;
  
  // Behavioral signals that suggest private key compromise:
  // 1. Multiple chains drained simultaneously
  // 2. All assets moved to single address
  // 3. Transactions signed at unusual times
  // 4. No prior interaction with destination

  const outboundTxs = safeTxs.filter(
    (tx) => tx?.value && BigInt(tx.value || '0') > BigInt(0)
  );

  if (outboundTxs.length === 0) return null;

  // Check if all assets went to same destination
  const destinations = [...new Set(outboundTxs.map((tx) => tx?.to?.toLowerCase?.()).filter(Boolean) as string[])];

  if (destinations.length === 1 && outboundTxs.length >= 3) {
    // Check time clustering
    const timestamps = outboundTxs.map((tx) => tx?.timestamp || 0).filter(t => t > 0).sort((a, b) => a - b);
    if (timestamps.length < 2) return null;
    
    const timeRange = timestamps[timestamps.length - 1] - timestamps[0];

    // All transactions within 1 hour
    if (timeRange < 3600) {
      return {
        id: `key-compromise-${Date.now()}`,
        type: 'PRIVATE_KEY_LEAK',
        severity: 'CRITICAL',
        title: 'Possible Private Key Compromise',
        description: 'Multiple assets were transferred to a single address in a short timeframe. This pattern suggests your private key may have been compromised.',
        technicalDetails: `All assets sent to: ${destinations[0]}, Total txs: ${outboundTxs.length}, Time window: ${Math.round(timeRange / 60)} minutes`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: destinations,
        relatedTransactions: outboundTxs.map((tx) => tx?.hash).filter(Boolean) as string[],
        ongoingRisk: true,
      };
    }
  }

  return null;
}

// ============================================
// SUMMARY GENERATION
// ============================================

export function generateAnalysisSummary(
  status: SecurityStatus,
  threats: DetectedThreat[],
  approvals: TokenApproval[]
): string {
  // Safe array guards
  const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
  const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];
  
  if (status === 'SAFE') {
    return 'No significant security threats detected. Your wallet appears to be in good standing. Continue practicing safe wallet hygiene.';
  }

  if (status === 'AT_RISK') {
    const riskCount = safeThreats.length + safeApprovals.filter((a) => a?.riskLevel === 'HIGH').length;
    return `${riskCount} potential security concern${riskCount > 1 ? 's' : ''} detected. Review the identified risks below and consider taking preventive action.`;
  }

  // COMPROMISED
  const criticalThreats = safeThreats.filter((t) => t?.severity === 'CRITICAL');
  return `URGENT: ${criticalThreats.length} critical security threat${criticalThreats.length > 1 ? 's' : ''} detected. Immediate action recommended. Review the recovery plan below to protect remaining assets.`;
}


