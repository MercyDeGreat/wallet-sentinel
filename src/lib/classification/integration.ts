// ============================================
// ATTACK CLASSIFICATION ENGINE - INTEGRATION
// ============================================
//
// This module bridges the Attack Classification Engine with
// the existing detection pipeline in Securnex.
//
// It converts detection results into classification input format
// and enriches the output with accurate attack type labels.
// ============================================

import type { Chain, DetectedThreat, TokenApproval, CompromiseEvidence, WalletAnalysisResult } from '@/types';
import type {
  AttackType,
  AttackClassification,
  AttackClassificationInput,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationApproval,
} from './types';
import { AttackClassificationEngine, classifyAttack } from './AttackClassificationEngine';

// ============================================
// CONVERSION UTILITIES
// ============================================

/**
 * Convert existing transaction data to classification format
 */
export function convertToClassificationTransaction(
  tx: {
    hash: string;
    from: string;
    to: string;
    value?: string;
    timestamp?: number;
    blockNumber?: number;
    methodId?: string;
    gasUsed?: string;
    gasPrice?: string;
    input?: string;
  },
  walletAddress: string
): ClassificationTransaction {
  const normalized = walletAddress.toLowerCase();
  const isInbound = tx.to?.toLowerCase() === normalized;
  
  return {
    hash: tx.hash,
    from: tx.from,
    to: tx.to,
    value: tx.value || '0',
    timestamp: tx.timestamp || Math.floor(Date.now() / 1000),
    blockNumber: tx.blockNumber || 0,
    methodId: tx.methodId,
    gasUsed: tx.gasUsed,
    gasPrice: tx.gasPrice,
    input: tx.input,
    isInbound,
  };
}

/**
 * Convert existing token transfer data to classification format
 */
export function convertToClassificationTokenTransfer(
  transfer: {
    hash: string;
    from: string;
    to: string;
    value?: string;
    timestamp?: number;
    blockNumber?: number;
    tokenAddress: string;
    tokenSymbol?: string;
    tokenType?: 'ERC20' | 'ERC721' | 'ERC1155';
  },
  walletAddress: string,
  dustThreshold: string = '100000000000000' // 0.0001 ETH default
): ClassificationTokenTransfer {
  const normalized = walletAddress.toLowerCase();
  const isInbound = transfer.to?.toLowerCase() === normalized;
  const value = transfer.value || '0';
  
  // Determine if dust
  let isDust = false;
  try {
    const v = BigInt(value);
    const t = BigInt(dustThreshold);
    isDust = v > BigInt(0) && v <= t;
  } catch {
    isDust = false;
  }
  
  return {
    hash: transfer.hash,
    from: transfer.from,
    to: transfer.to,
    value,
    timestamp: transfer.timestamp || Math.floor(Date.now() / 1000),
    blockNumber: transfer.blockNumber,
    tokenAddress: transfer.tokenAddress,
    tokenSymbol: transfer.tokenSymbol || 'UNKNOWN',
    tokenType: transfer.tokenType || 'ERC20',
    isInbound,
    isDust,
  };
}

/**
 * Convert existing approval data to classification format
 */
export function convertToClassificationApproval(
  approval: TokenApproval | {
    hash?: string;
    token: string;
    tokenSymbol?: string;
    spender: string;
    owner?: string;
    amount?: string;
    isUnlimited?: boolean;
    timestamp?: number;
    blockNumber?: number;
    wasRevoked?: boolean;
    revokedTimestamp?: number;
    wasUsed?: boolean;
    usedByTransferFrom?: boolean;
  },
  walletAddress: string
): ClassificationApproval {
  // Handle TokenApproval interface (which has 'id' instead of 'hash')
  const hash = 'id' in approval ? approval.id : (approval.hash || '');
  const token = 'token' in approval && typeof approval.token === 'object' 
    ? approval.token.address 
    : (approval.token || '');
  const tokenSymbol = 'token' in approval && typeof approval.token === 'object'
    ? approval.token.symbol
    : (approval.tokenSymbol || 'UNKNOWN');
  
  return {
    hash,
    token,
    tokenSymbol,
    spender: approval.spender,
    owner: approval.owner || walletAddress,
    amount: approval.amount || '0',
    isUnlimited: approval.isUnlimited || false,
    timestamp: approval.timestamp || Math.floor(Date.now() / 1000),
    blockNumber: approval.blockNumber || 0,
    wasRevoked: approval.wasRevoked || false,
    revokedTimestamp: approval.revokedTimestamp,
    wasUsed: approval.wasUsed || false,
    usedByTransferFrom: approval.usedByTransferFrom || false,
  };
}

/**
 * Extract frequent recipients from transaction history
 */
export function extractFrequentRecipients(
  transactions: ClassificationTransaction[],
  minCount: number = 3
): string[] {
  const outbound = transactions.filter(t => !t.isInbound);
  const recipientCounts = new Map<string, number>();
  
  for (const tx of outbound) {
    const to = tx.to.toLowerCase();
    recipientCounts.set(to, (recipientCounts.get(to) || 0) + 1);
  }
  
  return [...recipientCounts.entries()]
    .filter(([_, count]) => count >= minCount)
    .sort((a, b) => b[1] - a[1])
    .map(([addr]) => addr);
}

// ============================================
// MAIN INTEGRATION FUNCTION
// ============================================

/**
 * Classify attack type from existing analysis result.
 * This enriches the existing WalletAnalysisResult with accurate attack classification.
 */
export async function classifyAttackFromAnalysis(
  analysisResult: WalletAnalysisResult,
  rawTransactions: Array<{
    hash: string;
    from: string;
    to: string;
    value?: string;
    timestamp?: number;
    blockNumber?: number;
    methodId?: string;
    gasUsed?: string;
    gasPrice?: string;
    input?: string;
  }>,
  rawTokenTransfers: Array<{
    hash: string;
    from: string;
    to: string;
    value?: string;
    timestamp?: number;
    blockNumber?: number;
    tokenAddress: string;
    tokenSymbol?: string;
    tokenType?: 'ERC20' | 'ERC721' | 'ERC1155';
  }>,
  maliciousAddresses: string[] = []
): Promise<AttackClassification> {
  const walletAddress = analysisResult.address;
  const chain = analysisResult.chain;
  
  // Convert transactions
  const transactions = rawTransactions.map(tx => 
    convertToClassificationTransaction(tx, walletAddress)
  );
  
  // Convert token transfers
  const tokenTransfers = rawTokenTransfers.map(transfer =>
    convertToClassificationTokenTransfer(transfer, walletAddress)
  );
  
  // Convert approvals
  const approvals = analysisResult.approvals.map(approval =>
    convertToClassificationApproval(approval, walletAddress)
  );
  
  // Extract frequent recipients
  const frequentRecipients = extractFrequentRecipients(transactions);
  
  // Collect malicious addresses from detected threats
  const allMalicious = new Set(maliciousAddresses.map(a => a.toLowerCase()));
  for (const threat of analysisResult.detectedThreats) {
    threat.relatedAddresses.forEach(addr => allMalicious.add(addr.toLowerCase()));
  }
  
  // Build classification input
  const input: AttackClassificationInput = {
    walletAddress,
    chain,
    transactions,
    tokenTransfers,
    approvals,
    maliciousAddresses: [...allMalicious],
    frequentRecipients,
    currentTimestamp: Math.floor(Date.now() / 1000),
  };
  
  // Run classification
  return classifyAttack(input);
}

/**
 * Map attack classification type to existing threat attack type
 */
export function mapClassificationToThreatType(
  classificationType: AttackType
): import('@/types').AttackType {
  switch (classificationType) {
    case 'SWEEPER_BOT':
      return 'WALLET_DRAINER';
    case 'APPROVAL_DRAINER':
      return 'APPROVAL_HIJACK';
    case 'SIGNER_COMPROMISE':
      return 'PRIVATE_KEY_LEAK';
    case 'ADDRESS_POISONING':
      return 'PHISHING_SIGNATURE'; // Closest match - social engineering
    case 'SUSPICIOUS_ACTIVITY':
      return 'UNKNOWN';
    case 'NO_COMPROMISE':
      return 'UNKNOWN';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Enrich detected threats with accurate attack classification.
 * Updates threat titles and descriptions based on classification.
 */
export function enrichThreatsWithClassification(
  threats: DetectedThreat[],
  classification: AttackClassification
): DetectedThreat[] {
  if (classification.type === 'NO_COMPROMISE') {
    return threats;
  }
  
  return threats.map(threat => {
    // Update threat based on classification
    const enriched = { ...threat };
    
    // Add classification info to technical details
    enriched.technicalDetails = [
      enriched.technicalDetails,
      `Classification: ${classification.type} (${classification.confidence}% confidence)`,
      `Indicators: ${classification.indicators.slice(0, 3).join('; ')}`,
    ].filter(Boolean).join('\n');
    
    // Update title for address poisoning (common misclassification)
    if (classification.type === 'ADDRESS_POISONING') {
      if (threat.type === 'WALLET_DRAINER' || threat.title.toLowerCase().includes('sweeper')) {
        enriched.title = 'Address Poisoning Attack';
        enriched.description = classification.display.summary;
        enriched.type = 'PHISHING_SIGNATURE';
        enriched.severity = 'MEDIUM'; // Downgrade - not a compromise
        enriched.ongoingRisk = false;
        
        // Add attacker info if not present
        if (!enriched.attackerInfo) {
          enriched.attackerInfo = {
            address: classification.technicalDetails?.involvedAddresses?.[0] || '',
            type: 'PHISHING',
            confidence: classification.confidence,
          };
        } else {
          enriched.attackerInfo.type = 'PHISHING';
          enriched.attackerInfo.confidence = classification.confidence;
        }
      }
    }
    
    // Ensure sweeper bot is correctly labeled
    if (classification.type === 'SWEEPER_BOT') {
      enriched.attackerInfo = {
        ...enriched.attackerInfo,
        type: 'SWEEPER_BOT',
        confidence: classification.confidence,
      };
    }
    
    // Ensure approval drainer is correctly labeled
    if (classification.type === 'APPROVAL_DRAINER') {
      enriched.attackerInfo = {
        ...enriched.attackerInfo,
        type: 'DRAINER',
        confidence: classification.confidence,
      };
    }
    
    return enriched;
  });
}

/**
 * Create a complete analysis result with classification.
 * This is the main entry point for using the classification engine.
 */
export async function analyzeWithClassification(
  baseAnalysis: WalletAnalysisResult,
  rawTransactions: Array<{
    hash: string;
    from: string;
    to: string;
    value?: string;
    timestamp?: number;
    blockNumber?: number;
    methodId?: string;
    gasUsed?: string;
    gasPrice?: string;
    input?: string;
  }>,
  rawTokenTransfers: Array<{
    hash: string;
    from: string;
    to: string;
    value?: string;
    timestamp?: number;
    blockNumber?: number;
    tokenAddress: string;
    tokenSymbol?: string;
    tokenType?: 'ERC20' | 'ERC721' | 'ERC1155';
  }>,
  maliciousAddresses: string[] = []
): Promise<{
  analysis: WalletAnalysisResult;
  classification: AttackClassification;
}> {
  // Run classification
  const classification = await classifyAttackFromAnalysis(
    baseAnalysis,
    rawTransactions,
    rawTokenTransfers,
    maliciousAddresses
  );
  
  // Enrich threats with classification
  const enrichedThreats = enrichThreatsWithClassification(
    baseAnalysis.detectedThreats,
    classification
  );
  
  // Update analysis with classification
  const analysis: WalletAnalysisResult = {
    ...baseAnalysis,
    detectedThreats: enrichedThreats,
    summary: classification.type !== 'NO_COMPROMISE' 
      ? `${classification.display.headline}: ${classification.display.summary}`
      : baseAnalysis.summary,
  };
  
  return {
    analysis,
    classification,
  };
}

// Note: Functions are already exported inline above
