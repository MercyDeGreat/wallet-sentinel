// ============================================
// CONSERVATIVE WALLET ANALYZER
// ============================================
// This module provides an extra-conservative analysis mode
// specifically designed to minimize false positives.
//
// PRINCIPLE: Treat ALL transactions as POTENTIALLY NORMAL
// unless there is STRONG evidence of malicious activity.
//
// Only flag a transaction as SUSPICIOUS if ALL of the following are true:
// 1. Funds are sent to unknown or unverified addresses
// 2. Interaction with contracts identified as malicious, drainer, or sweeper bots
// 3. Automated sweeps occur from the wallet WITHOUT owner initiation signals
//
// DO NOT mark as compromised:
// - Normal user-initiated activity
// - Quick outflows after deposits (normal user behavior)
// - NFT mints, presales, and bids
// - Deposits to or withdrawals from exchanges
// - Interactions with widely-recognized smart contracts

import { Chain, RiskLevel, AttackType, SecurityStatus } from '@/types';
import {
  LabeledTransaction,
  TransactionSummary,
  WalletRiskReport,
  labelTransactions,
  generateRiskReport,
  TransactionInput,
  TransactionType,
  EXCHANGE_HOT_WALLETS,
} from './transaction-labeler';
import {
  isSafeContract,
  SafeContract,
  checkAddressSafety,
} from './safe-contracts';
import { isKnownDrainer } from './drainer-addresses';
import { isMaliciousAddress, isLegitimateContract } from './malicious-database';

// ============================================
// CONSERVATIVE ANALYSIS SETTINGS
// ============================================

export interface ConservativeAnalysisConfig {
  // Minimum number of suspicious transactions to flag wallet as AT_RISK
  minSuspiciousForAtRisk: number;
  
  // Minimum confidence to flag a transaction as SUSPICIOUS
  minConfidenceForSuspicious: number;
  
  // Whether to allow flagging quick outflows (disabled by default)
  allowQuickOutflowFlagging: boolean;
  
  // Whether to require multiple independent malicious indicators
  requireMultipleIndicators: boolean;
  
  // Maximum legitimate activity ratio above which wallet is considered SAFE
  safeThresholdPercent: number;
}

const DEFAULT_CONSERVATIVE_CONFIG: ConservativeAnalysisConfig = {
  minSuspiciousForAtRisk: 2,
  minConfidenceForSuspicious: 90,
  allowQuickOutflowFlagging: false,
  requireMultipleIndicators: true,
  safeThresholdPercent: 90,
};

// ============================================
// ENHANCED TRANSACTION LABEL WITH EXPLANATION
// ============================================

export interface ExplainedTransaction extends LabeledTransaction {
  // Why this label was assigned
  explanation: string;
  
  // What evidence was considered
  evidenceChecked: string[];
  
  // What criteria PASSED (for LEGITIMATE)
  passedCriteria: string[];
  
  // What criteria FAILED (for SUSPICIOUS)
  failedCriteria: string[];
  
  // Is this a user-initiated action?
  isUserInitiated: boolean;
  
  // Is this interaction with a whitelisted entity?
  isWhitelisted: boolean;
}

// ============================================
// USER INTENT SIGNALS
// ============================================
// These patterns indicate user-initiated activity

const USER_INTENT_SIGNALS = {
  // Method signatures that indicate user action
  userActionMethods: new Set([
    '0x1249c58b', // mint()
    '0xa0712d68', // mint(uint256)
    '0x40c10f19', // mint(address,uint256)
    '0xfb0f3ee1', // fulfillBasicOrder (NFT purchase)
    '0x87201b41', // fulfillOrder (NFT purchase)
    '0x38ed1739', // swapExactTokensForTokens
    '0x7ff36ab5', // swapExactETHForTokens
    '0x04e45aaf', // exactInputSingle
    '0xb858183f', // exactInput
    '0xd0e30db0', // deposit()
    '0xa694fc3a', // stake(uint256)
    '0xe8eda9df', // deposit (Aave)
  ]),
  
  // Interaction with any of these = user-initiated
  trustedProtocolCategories: [
    'NFT_MARKETPLACE',
    'NFT_MINT_CONTRACT',
    'DEX_ROUTER',
    'AGGREGATOR',
    'BRIDGE',
    'STAKING',
    'LENDING',
    'ENS',
  ],
};

// ============================================
// CONSERVATIVE TRANSACTION ANALYZER
// ============================================

/**
 * Analyze a single transaction with maximum conservatism.
 * Returns LEGITIMATE unless there is strong evidence of malicious activity.
 */
export function analyzeTransactionConservatively(
  tx: TransactionInput,
  walletAddress: string,
  chain: Chain,
  config: ConservativeAnalysisConfig = DEFAULT_CONSERVATIVE_CONFIG
): ExplainedTransaction {
  const normalizedWallet = walletAddress.toLowerCase();
  const normalizedTo = tx.to?.toLowerCase() || '';
  const normalizedFrom = tx.from?.toLowerCase() || '';
  const methodId = tx.input?.slice(0, 10).toLowerCase() || '';
  
  const evidenceChecked: string[] = [];
  const passedCriteria: string[] = [];
  const failedCriteria: string[] = [];
  
  // ============================================
  // STEP 1: Check if destination is whitelisted
  // ============================================
  evidenceChecked.push('Checking destination against whitelist');
  
  // Check safe contracts
  const safeContract = isSafeContract(normalizedTo);
  if (safeContract) {
    passedCriteria.push(`Destination is verified safe contract: ${safeContract.name}`);
    return createLegitimateResult(tx, {
      label: 'LEGITIMATE',
      type: getTransactionTypeFromContract(safeContract, methodId),
      confidence: 98,
      reason: `Verified safe contract: ${safeContract.name}`,
      explanation: `This transaction interacts with ${safeContract.name}, a verified ${safeContract.category} contract. This is normal, legitimate activity.`,
      evidenceChecked,
      passedCriteria,
      failedCriteria: [],
      isUserInitiated: true,
      isWhitelisted: true,
    });
  }
  
  // Check legitimate contracts
  const legitimateName = isLegitimateContract(normalizedTo);
  if (legitimateName) {
    passedCriteria.push(`Destination is known legitimate contract: ${legitimateName}`);
    return createLegitimateResult(tx, {
      label: 'LEGITIMATE',
      type: 'NORMAL_TRANSFER',
      confidence: 92,
      reason: `Known legitimate contract: ${legitimateName}`,
      explanation: `This transaction interacts with ${legitimateName}, a recognized legitimate contract.`,
      evidenceChecked,
      passedCriteria,
      failedCriteria: [],
      isUserInitiated: true,
      isWhitelisted: true,
    });
  }
  
  // Check exchanges
  const exchangeName = EXCHANGE_HOT_WALLETS.get(normalizedTo) || EXCHANGE_HOT_WALLETS.get(normalizedFrom);
  if (exchangeName) {
    passedCriteria.push(`Transaction involves exchange: ${exchangeName}`);
    return createLegitimateResult(tx, {
      label: 'LEGITIMATE',
      type: EXCHANGE_HOT_WALLETS.get(normalizedFrom) ? 'EXCHANGE_WITHDRAWAL' : 'EXCHANGE_DEPOSIT',
      confidence: 95,
      reason: `Exchange transaction: ${exchangeName}`,
      explanation: `This is a deposit to or withdrawal from ${exchangeName}. Exchange transactions are normal user activity.`,
      evidenceChecked,
      passedCriteria,
      failedCriteria: [],
      isUserInitiated: true,
      isWhitelisted: true,
    });
  }
  
  // ============================================
  // STEP 2: Check if method indicates user action
  // ============================================
  evidenceChecked.push('Checking method signature for user intent');
  
  if (USER_INTENT_SIGNALS.userActionMethods.has(methodId)) {
    passedCriteria.push(`Method signature indicates user action: ${methodId}`);
    return createLegitimateResult(tx, {
      label: 'LEGITIMATE',
      type: getTypeFromMethodId(methodId),
      confidence: 85,
      reason: `User-initiated action detected (method: ${methodId})`,
      explanation: 'This transaction uses a method signature commonly associated with user-initiated actions (mint, swap, deposit, stake, etc.).',
      evidenceChecked,
      passedCriteria,
      failedCriteria: [],
      isUserInitiated: true,
      isWhitelisted: false,
    });
  }
  
  // ============================================
  // STEP 3: Check against malicious database
  // ============================================
  evidenceChecked.push('Checking against malicious address database');
  
  // Only flag if destination is CONFIRMED malicious
  if (isKnownDrainer(normalizedTo)) {
    failedCriteria.push('Destination is in confirmed drainer database');
    return createSuspiciousResult(tx, {
      label: 'SUSPICIOUS',
      type: 'DRAINER_INTERACTION',
      confidence: 98,
      reason: 'Transaction to CONFIRMED drainer address',
      explanation: 'This transaction sends funds to an address that is in our confirmed drainer database. This is a verified threat.',
      evidenceChecked,
      passedCriteria: [],
      failedCriteria,
      isUserInitiated: false,
      isWhitelisted: false,
    });
  }
  
  const malicious = isMaliciousAddress(normalizedTo, chain);
  if (malicious) {
    // Double-check: is this actually a safe contract that was incorrectly in malicious list?
    if (isSafeContract(normalizedTo) || isLegitimateContract(normalizedTo)) {
      // False positive prevention
      passedCriteria.push('Address is in safe contracts despite being flagged');
      return createLegitimateResult(tx, {
        label: 'LEGITIMATE',
        type: 'NORMAL_TRANSFER',
        confidence: 85,
        reason: 'Address flagged but verified as safe contract',
        explanation: 'This address was in the malicious database but has been verified as a legitimate contract.',
        evidenceChecked,
        passedCriteria,
        failedCriteria: [],
        isUserInitiated: true,
        isWhitelisted: true,
      });
    }
    
    failedCriteria.push(`Destination is flagged malicious: ${malicious.type}`);
    return createSuspiciousResult(tx, {
      label: 'SUSPICIOUS',
      type: 'DRAINER_INTERACTION',
      confidence: 95,
      reason: `Interaction with malicious contract: ${malicious.name || normalizedTo}`,
      explanation: `This transaction interacts with a contract flagged as malicious (type: ${malicious.type}). Review this transaction carefully.`,
      evidenceChecked,
      passedCriteria: [],
      failedCriteria,
      isUserInitiated: false,
      isWhitelisted: false,
    });
  }
  
  // ============================================
  // STEP 4: Simple transfers are legitimate
  // ============================================
  evidenceChecked.push('Checking if simple ETH transfer');
  
  if (!tx.input || tx.input === '0x' || tx.input === '0x00') {
    passedCriteria.push('Simple ETH transfer with no contract interaction');
    return createLegitimateResult(tx, {
      label: 'LEGITIMATE',
      type: 'NORMAL_TRANSFER',
      confidence: 75,
      reason: 'Simple ETH transfer - no contract interaction',
      explanation: 'This is a simple ETH transfer without any smart contract interaction. These are typically user-initiated fund movements.',
      evidenceChecked,
      passedCriteria,
      failedCriteria: [],
      isUserInitiated: true,
      isWhitelisted: false,
    });
  }
  
  // ============================================
  // STEP 5: Default to NEEDS_REVIEW (not SUSPICIOUS)
  // ============================================
  // Conservative default: unknown != suspicious
  return {
    hash: tx.hash,
    label: 'NEEDS_REVIEW',
    type: 'UNKNOWN',
    confidence: 40,
    reason: 'Unknown contract - requires manual review',
    explanation: 'This transaction interacts with a contract not in our database. This does NOT mean it is malicious - manual review recommended.',
    evidenceChecked,
    passedCriteria: [],
    failedCriteria: [],
    isUserInitiated: false,
    isWhitelisted: false,
    details: {
      isVerifiedContract: false,
      isStandardMethod: false,
      isInbound: normalizedTo === normalizedWallet,
      isOutbound: normalizedFrom === normalizedWallet,
      value: tx.value,
      isWhitelistedDestination: false,
      isExchangeTransaction: false,
      isProtocolInteraction: false,
    },
  };
}

// ============================================
// FULL CONSERVATIVE WALLET ANALYSIS
// ============================================

export interface ConservativeAnalysisResult {
  walletAddress: string;
  chain: Chain;
  timestamp: string;
  
  // Overall assessment
  securityStatus: SecurityStatus;
  riskLevel: RiskLevel;
  
  // Transaction analysis
  transactions: {
    total: number;
    legitimate: number;
    suspicious: number;
    needsReview: number;
    legitimatePercentage: number;
  };
  
  // Labeled transactions
  labeledTransactions: ExplainedTransaction[];
  
  // Only TRUE threats with explanations
  confirmedThreats: {
    hash: string;
    type: string;
    confidence: number;
    reason: string;
    explanation: string;
  }[];
  
  // Legitimate activity breakdown
  legitimateActivity: {
    exchangeTransactions: ExplainedTransaction[];
    dexActivity: ExplainedTransaction[];
    nftActivity: ExplainedTransaction[];
    stakingActivity: ExplainedTransaction[];
    normalTransfers: ExplainedTransaction[];
  };
  
  // Final summary
  summary: string;
  recommendation: string;
  
  // Explicit statement about false positive prevention
  falsePositiveNote: string;
}

/**
 * Perform conservative analysis on a wallet.
 * 
 * This function treats all transactions as POTENTIALLY NORMAL and only
 * flags truly malicious activity with high confidence.
 */
export function analyzeWalletConservatively(
  walletAddress: string,
  chain: Chain,
  transactions: TransactionInput[],
  config: ConservativeAnalysisConfig = DEFAULT_CONSERVATIVE_CONFIG
): ConservativeAnalysisResult {
  const labeled: ExplainedTransaction[] = transactions.map(tx =>
    analyzeTransactionConservatively(tx, walletAddress, chain, config)
  );
  
  const legitimate = labeled.filter(t => t.label === 'LEGITIMATE');
  const suspicious = labeled.filter(t => t.label === 'SUSPICIOUS');
  const needsReview = labeled.filter(t => t.label === 'NEEDS_REVIEW');
  
  const legitimatePercentage = transactions.length > 0
    ? (legitimate.length / transactions.length) * 100
    : 100;
  
  // Determine security status conservatively
  let securityStatus: SecurityStatus = 'SAFE';
  let riskLevel: RiskLevel = 'LOW';
  
  if (suspicious.length >= config.minSuspiciousForAtRisk) {
    // Only AT_RISK if multiple suspicious AND all high confidence
    const highConfidenceSuspicious = suspicious.filter(
      t => t.confidence >= config.minConfidenceForSuspicious
    );
    
    if (highConfidenceSuspicious.length >= config.minSuspiciousForAtRisk) {
      securityStatus = 'AT_RISK';
      riskLevel = 'MEDIUM';
      
      // Only COMPROMISED if very high confidence threats
      if (highConfidenceSuspicious.length >= 3 && 
          highConfidenceSuspicious.every(t => t.confidence >= 95)) {
        securityStatus = 'COMPROMISED';
        riskLevel = 'HIGH';
      }
    }
  }
  
  // If > 90% legitimate, force SAFE regardless
  if (legitimatePercentage >= config.safeThresholdPercent && suspicious.length <= 1) {
    securityStatus = 'SAFE';
    riskLevel = 'LOW';
  }
  
  // Build confirmed threats (only SUSPICIOUS with high confidence)
  const confirmedThreats = suspicious
    .filter(t => t.confidence >= 90)
    .map(t => ({
      hash: t.hash,
      type: t.type,
      confidence: t.confidence,
      reason: t.reason,
      explanation: t.explanation,
    }));
  
  // Categorize legitimate activity
  const legitimateActivity = {
    exchangeTransactions: legitimate.filter(t => 
      t.type === 'EXCHANGE_DEPOSIT' || t.type === 'EXCHANGE_WITHDRAWAL'
    ),
    dexActivity: legitimate.filter(t =>
      t.type.includes('DEX') || t.type.includes('SWAP')
    ),
    nftActivity: legitimate.filter(t =>
      t.type.includes('NFT') || t.type === 'PRESALE_BID' || t.type === 'AUCTION_BID'
    ),
    stakingActivity: legitimate.filter(t =>
      t.type.includes('STAKING')
    ),
    normalTransfers: legitimate.filter(t =>
      t.type === 'NORMAL_TRANSFER' || t.type === 'TOKEN_TRANSFER'
    ),
  };
  
  // Generate summary and recommendation
  const summary = generateConservativeSummary(
    securityStatus,
    confirmedThreats.length,
    legitimate.length,
    transactions.length
  );
  
  const recommendation = generateConservativeRecommendation(
    securityStatus,
    confirmedThreats,
    legitimateActivity
  );
  
  return {
    walletAddress,
    chain,
    timestamp: new Date().toISOString(),
    securityStatus,
    riskLevel,
    transactions: {
      total: transactions.length,
      legitimate: legitimate.length,
      suspicious: suspicious.length,
      needsReview: needsReview.length,
      legitimatePercentage,
    },
    labeledTransactions: labeled,
    confirmedThreats,
    legitimateActivity,
    summary,
    recommendation,
    falsePositiveNote: 
      'This analysis uses conservative detection to minimize false positives. ' +
      'Transactions are only flagged as suspicious if there is STRONG evidence ' +
      'of malicious activity. Normal user behavior (quick outflows, high frequency) ' +
      'is NOT flagged unless combined with other malicious indicators.',
  };
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function createLegitimateResult(
  tx: TransactionInput,
  partial: Omit<ExplainedTransaction, 'details' | 'hash'>
): ExplainedTransaction {
  return {
    hash: tx.hash,
    ...partial,
    details: {
      isVerifiedContract: partial.isWhitelisted,
      isStandardMethod: partial.isUserInitiated,
      isInbound: false, // Will be set by caller if needed
      isOutbound: false,
      value: tx.value,
      isWhitelistedDestination: partial.isWhitelisted,
      isExchangeTransaction: partial.type.includes('EXCHANGE'),
      isProtocolInteraction: partial.isWhitelisted,
    },
  };
}

function createSuspiciousResult(
  tx: TransactionInput,
  partial: Omit<ExplainedTransaction, 'details' | 'hash'>
): ExplainedTransaction {
  return {
    hash: tx.hash,
    ...partial,
    details: {
      isVerifiedContract: false,
      isStandardMethod: false,
      isInbound: false,
      isOutbound: true,
      value: tx.value,
      isWhitelistedDestination: false,
      isExchangeTransaction: false,
      isProtocolInteraction: false,
      riskFlags: partial.failedCriteria,
      attackType: 'WALLET_DRAINER',
    },
  };
}

function getTransactionTypeFromContract(
  contract: SafeContract,
  methodId: string
): TransactionType {
  switch (contract.category) {
    case 'NFT_MARKETPLACE':
      return methodId.startsWith('0xfb0f3ee1') ? 'NFT_PURCHASE' : 'NFT_SALE';
    case 'NFT_MINT_CONTRACT':
      return 'NFT_MINT';
    case 'DEX_ROUTER':
    case 'AGGREGATOR':
      return 'DEX_SWAP';
    case 'BRIDGE':
      return 'BRIDGE_DEPOSIT';
    case 'STAKING':
      return 'STAKING_DEPOSIT';
    case 'LENDING':
      return 'LENDING_DEPOSIT';
    case 'ENS':
      return 'ENS_REGISTRATION';
    default:
      return 'NORMAL_TRANSFER';
  }
}

function getTypeFromMethodId(methodId: string): TransactionType {
  const methodTypes: Record<string, TransactionType> = {
    '0x1249c58b': 'NFT_MINT',
    '0xa0712d68': 'NFT_MINT',
    '0x40c10f19': 'NFT_MINT',
    '0xfb0f3ee1': 'NFT_PURCHASE',
    '0x87201b41': 'NFT_PURCHASE',
    '0x38ed1739': 'DEX_SWAP',
    '0x7ff36ab5': 'DEX_SWAP',
    '0x04e45aaf': 'DEX_SWAP',
    '0xb858183f': 'DEX_SWAP',
    '0xd0e30db0': 'DEX_DEPOSIT',
    '0xa694fc3a': 'STAKING_DEPOSIT',
    '0xe8eda9df': 'LENDING_DEPOSIT',
  };
  
  return methodTypes[methodId] || 'NORMAL_TRANSFER';
}

function generateConservativeSummary(
  status: SecurityStatus,
  threatCount: number,
  legitimateCount: number,
  totalCount: number
): string {
  if (status === 'SAFE') {
    return `No confirmed malicious activity detected. ${legitimateCount} of ${totalCount} transactions ` +
           `(${((legitimateCount / totalCount) * 100).toFixed(1)}%) are verified as legitimate user activity. ` +
           'This wallet shows normal behavior.';
  }
  
  if (status === 'AT_RISK') {
    return `${threatCount} suspicious transaction(s) detected out of ${totalCount} total. ` +
           'These specific transactions warrant review. The majority of activity appears legitimate.';
  }
  
  return `ALERT: ${threatCount} high-confidence suspicious transactions detected. ` +
         'Review the flagged transactions below for details.';
}

function generateConservativeRecommendation(
  status: SecurityStatus,
  confirmedThreats: { hash: string; explanation: string }[],
  legitimateActivity: { exchangeTransactions: ExplainedTransaction[] }
): string {
  if (status === 'SAFE') {
    return 'No action required. Continue normal wallet usage with standard security practices.';
  }
  
  if (status === 'AT_RISK') {
    const threatHashes = confirmedThreats.map(t => t.hash.slice(0, 10) + '...').join(', ');
    return `Review the following transaction(s): ${threatHashes}. ` +
           'If these were user-initiated, no action is needed. ' +
           'If unfamiliar, consider revoking any related approvals.';
  }
  
  return 'Immediate review recommended. Check the confirmed threats below and ' +
         'consider moving assets to a fresh wallet if compromise is confirmed.';
}

// Note: All exports are inline (export function, export interface, etc.)

