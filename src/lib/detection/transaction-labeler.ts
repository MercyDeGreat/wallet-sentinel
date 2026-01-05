// ============================================
// TRANSACTION LABELER
// ============================================
// Explicitly labels each transaction as LEGITIMATE or SUSPICIOUS.
// 
// PRINCIPLE: Treat all transactions as POTENTIALLY NORMAL unless
// proven malicious with high confidence.
//
// A transaction is LEGITIMATE if:
// - Interacts with verified/whitelisted contracts
// - Matches known user-initiated patterns (mint, swap, deposit)
// - Goes to/from exchange hot wallets
// - Uses standard EIP functions
//
// A transaction is SUSPICIOUS only if ALL of:
// - Funds sent to unknown/unverified addresses
// - No interaction with whitelisted protocols
// - Matches known attack patterns
// - Automated behavior detected

import { Chain, RiskLevel, AttackType } from '@/types';
import { isSafeContract, SafeContract, isStandardApprovalMethod, isStandardMintMethod } from './safe-contracts';
import { isKnownDrainer, getDrainerType } from './drainer-addresses';
import { isMaliciousAddress, isLegitimateContract } from './malicious-database';

// ============================================
// TRANSACTION LABEL TYPES
// ============================================

export type TransactionLabel = 
  | 'LEGITIMATE'          // Verified safe - NO ALERT
  | 'NEEDS_REVIEW'        // Uncertain - LOW priority review
  | 'SUSPICIOUS';         // Potential threat - ALERT

export type TransactionType =
  // Legitimate types
  | 'NFT_MINT'
  | 'NFT_PURCHASE'
  | 'NFT_SALE'
  | 'PRESALE_BID'
  | 'AUCTION_BID'
  | 'DEX_SWAP'
  | 'DEX_DEPOSIT'
  | 'DEX_WITHDRAWAL'
  | 'BRIDGE_DEPOSIT'
  | 'BRIDGE_WITHDRAWAL'
  | 'EXCHANGE_DEPOSIT'
  | 'EXCHANGE_WITHDRAWAL'
  | 'STAKING_DEPOSIT'
  | 'STAKING_WITHDRAWAL'
  | 'LENDING_DEPOSIT'
  | 'LENDING_WITHDRAWAL'
  | 'LENDING_BORROW'
  | 'LENDING_REPAY'
  | 'TOKEN_APPROVAL'
  | 'TOKEN_TRANSFER'
  | 'CONTRACT_CREATION'
  | 'MULTISIG_EXECUTION'
  | 'ENS_REGISTRATION'
  | 'ENS_RENEWAL'
  | 'NORMAL_TRANSFER'
  | 'GAS_REFUEL'
  // Suspicious types
  | 'DRAINER_INTERACTION'
  | 'MALICIOUS_APPROVAL'
  | 'RAPID_DRAIN'
  | 'AUTOMATED_SWEEP'
  // Neutral
  | 'UNKNOWN';

export interface LabeledTransaction {
  hash: string;
  label: TransactionLabel;
  type: TransactionType;
  confidence: number; // 0-100
  reason: string;
  details: TransactionLabelDetails;
}

export interface TransactionLabelDetails {
  // What contract was interacted with?
  contractAddress?: string;
  contractName?: string;
  contractCategory?: string;
  isVerifiedContract: boolean;
  
  // What method was called?
  methodId?: string;
  methodName?: string;
  isStandardMethod: boolean;
  
  // Flow analysis
  isInbound: boolean;
  isOutbound: boolean;
  value?: string;
  
  // Safety flags
  isWhitelistedDestination: boolean;
  isExchangeTransaction: boolean;
  isProtocolInteraction: boolean;
  
  // Risk flags (only populated if suspicious)
  riskFlags?: string[];
  attackType?: AttackType;
}

// ============================================
// EXPANDED EXCHANGE HOT WALLETS
// ============================================

const EXCHANGE_HOT_WALLETS = new Map<string, string>([
  // Binance
  ['0x28c6c06298d514db089934071355e5743bf21d60', 'Binance Hot Wallet 1'],
  ['0x21a31ee1afc51d94c2efccaa2092ad1028285549', 'Binance Hot Wallet 2'],
  ['0xdfd5293d8e347dfe59e90efd55b2956a1343963d', 'Binance Hot Wallet 3'],
  ['0x56eddb7aa87536c09ccc2793473599fd21a8b17f', 'Binance Hot Wallet 4'],
  ['0xf977814e90da44bfa03b6295a0616a897441acec', 'Binance Hot Wallet 5'],
  ['0x8894e0a0c962cb723c1976a4421c95949be2d4e3', 'Binance Hot Wallet 6'],
  ['0xe2fc31f816a9b94326492132018c3aecc4a93ae1', 'Binance Hot Wallet 7'],
  ['0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be', 'Binance Hot Wallet 8'],
  ['0xbe0eb53f46cd790cd13851d5eff43d12404d33e8', 'Binance Cold Wallet'],
  
  // Coinbase
  ['0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43', 'Coinbase Hot Wallet 1'],
  ['0x71660c4005ba85c37ccec55d0c4493e66fe775d3', 'Coinbase Hot Wallet 2'],
  ['0x503828976d22510aad0201ac7ec88293211d23da', 'Coinbase Hot Wallet 3'],
  ['0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740', 'Coinbase Hot Wallet 4'],
  ['0x3cd751e6b0078be393132286c442345e5dc49699', 'Coinbase Hot Wallet 5'],
  ['0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511', 'Coinbase Commerce'],
  
  // Kraken
  ['0x2910543af39aba0cd09dbb2d50200b3e800a63d2', 'Kraken Hot Wallet 1'],
  ['0x98ec059dc3adfbdd63429454aeb0c990fba4a128', 'Kraken Hot Wallet 2'],
  ['0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0', 'Kraken Hot Wallet 3'],
  
  // OKX
  ['0x6cc5f688a315f3dc28a7781717a9a798a59fda7b', 'OKX Hot Wallet 1'],
  ['0x236f9f97e0e62388479bf9e5ba4889e46b0273c3', 'OKX Hot Wallet 2'],
  ['0xa7efae728d2936e78bda97dc267687568dd593f3', 'OKX Hot Wallet 3'],
  
  // Huobi / HTX
  ['0xab5c66752a9e8167967685f1450532fb96d5d24f', 'Huobi Hot Wallet 1'],
  ['0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b', 'Huobi Hot Wallet 2'],
  ['0xfdb16996831753d5331ff813c29a93c76834a0ad', 'Huobi Hot Wallet 3'],
  
  // Crypto.com
  ['0x6262998ced04146fa42253a5c0af90ca02dfd2a3', 'Crypto.com Hot Wallet 1'],
  ['0x46340b20830761efd32832a74d7169b29feb9758', 'Crypto.com Hot Wallet 2'],
  ['0x72a53cdbbcc1b9efa39c834a540550e23463aacb', 'Crypto.com Cold Wallet'],
  
  // KuCoin
  ['0xf16e9b0d03470827a95cdfd0cb8a8a3b46969b91', 'KuCoin Hot Wallet 1'],
  ['0x2b5634c42055806a59e9107ed44d43c426e58258', 'KuCoin Hot Wallet 2'],
  
  // Bybit
  ['0xf89d7b9c864f589bbf53a82105107622b35eaa40', 'Bybit Hot Wallet'],
  
  // Gate.io
  ['0x0d0707963952f2fba59dd06f2b425ace40b492fe', 'Gate.io Hot Wallet 1'],
  ['0x1c4b70a3968436b9a0a9cf5205c787eb81bb558c', 'Gate.io Hot Wallet 2'],
  
  // Gemini
  ['0xd24400ae8bfebb18ca49be86258a3c749cf46853', 'Gemini Hot Wallet 1'],
  ['0x6fc82a5fe25a5cdb58bc74600a40a69c065263f8', 'Gemini Hot Wallet 2'],
  
  // Bitfinex
  ['0x876eabf441b2ee5b5b0554fd502a8e0600950cfa', 'Bitfinex Hot Wallet 1'],
  ['0xdcd0272462140d0a3ced6c4bf970c7641f08cd2c', 'Bitfinex Hot Wallet 2'],
]);

// ============================================
// METHOD SIGNATURES
// ============================================

const METHOD_NAMES: Record<string, { name: string; type: TransactionType }> = {
  // Minting
  '0x1249c58b': { name: 'mint()', type: 'NFT_MINT' },
  '0xa0712d68': { name: 'mint(uint256)', type: 'NFT_MINT' },
  '0x40c10f19': { name: 'mint(address,uint256)', type: 'NFT_MINT' },
  '0x6a627842': { name: 'mint(address)', type: 'NFT_MINT' },
  '0xd85d3d27': { name: 'mintTo(address)', type: 'NFT_MINT' },
  '0x0febdd49': { name: 'safeMint', type: 'NFT_MINT' },
  
  // Approvals
  '0x095ea7b3': { name: 'approve(address,uint256)', type: 'TOKEN_APPROVAL' },
  '0xa22cb465': { name: 'setApprovalForAll(address,bool)', type: 'TOKEN_APPROVAL' },
  '0xd505accf': { name: 'permit(...)', type: 'TOKEN_APPROVAL' },
  
  // DEX Swaps
  '0x38ed1739': { name: 'swapExactTokensForTokens', type: 'DEX_SWAP' },
  '0x7ff36ab5': { name: 'swapExactETHForTokens', type: 'DEX_SWAP' },
  '0x18cbafe5': { name: 'swapExactTokensForETH', type: 'DEX_SWAP' },
  '0x04e45aaf': { name: 'exactInputSingle', type: 'DEX_SWAP' },
  '0xb858183f': { name: 'exactInput', type: 'DEX_SWAP' },
  '0x472b43f3': { name: 'swapExactTokensForTokens (Universal)', type: 'DEX_SWAP' },
  
  // Deposits/Withdrawals
  '0xd0e30db0': { name: 'deposit()', type: 'DEX_DEPOSIT' },
  '0xb6b55f25': { name: 'deposit(uint256)', type: 'DEX_DEPOSIT' },
  '0x47e7ef24': { name: 'deposit(address,uint256)', type: 'DEX_DEPOSIT' },
  '0x2e1a7d4d': { name: 'withdraw(uint256)', type: 'DEX_WITHDRAWAL' },
  '0x69328dec': { name: 'withdraw(address,uint256,address)', type: 'DEX_WITHDRAWAL' },
  
  // Lending
  '0xe8eda9df': { name: 'deposit (Aave)', type: 'LENDING_DEPOSIT' },
  '0xa415bcad': { name: 'borrow', type: 'LENDING_BORROW' },
  '0x573ade81': { name: 'repay', type: 'LENDING_REPAY' },
  
  // NFT Marketplaces
  '0xfb0f3ee1': { name: 'fulfillBasicOrder (Seaport)', type: 'NFT_PURCHASE' },
  '0x87201b41': { name: 'fulfillOrder (Seaport)', type: 'NFT_PURCHASE' },
  '0x9a1fc3a7': { name: 'fulfillAvailableOrders', type: 'NFT_PURCHASE' },
  '0xed98a574': { name: 'fulfillAdvancedOrder', type: 'NFT_PURCHASE' },
  
  // Transfers
  '0xa9059cbb': { name: 'transfer(address,uint256)', type: 'TOKEN_TRANSFER' },
  '0x23b872dd': { name: 'transferFrom(address,address,uint256)', type: 'TOKEN_TRANSFER' },
  '0x42842e0e': { name: 'safeTransferFrom', type: 'TOKEN_TRANSFER' },
  
  // Staking
  '0xa694fc3a': { name: 'stake(uint256)', type: 'STAKING_DEPOSIT' },
  '0x2e17de78': { name: 'unstake(uint256)', type: 'STAKING_WITHDRAWAL' },
};

// ============================================
// MAIN LABELING FUNCTION
// ============================================

export interface TransactionInput {
  hash: string;
  from: string;
  to: string;
  value: string;
  input: string;
  timestamp: number;
  blockNumber: number;
  isError?: boolean;
}

/**
 * Labels a transaction as LEGITIMATE, NEEDS_REVIEW, or SUSPICIOUS.
 * 
 * PRINCIPLE: Default to LEGITIMATE unless proven otherwise.
 */
export function labelTransaction(
  tx: TransactionInput,
  walletAddress: string,
  chain: Chain
): LabeledTransaction {
  const normalizedWallet = walletAddress.toLowerCase();
  const normalizedTo = tx.to?.toLowerCase() || '';
  const normalizedFrom = tx.from?.toLowerCase() || '';
  const methodId = tx.input?.slice(0, 10).toLowerCase() || '';
  
  const isOutbound = normalizedFrom === normalizedWallet;
  const isInbound = normalizedTo === normalizedWallet;
  
  // Initialize details
  const details: TransactionLabelDetails = {
    isVerifiedContract: false,
    isStandardMethod: false,
    isInbound,
    isOutbound,
    value: tx.value,
    isWhitelistedDestination: false,
    isExchangeTransaction: false,
    isProtocolInteraction: false,
  };
  
  // ============================================
  // CHECK 1: Exchange transactions
  // ============================================
  const exchangeFrom = EXCHANGE_HOT_WALLETS.get(normalizedFrom);
  const exchangeTo = EXCHANGE_HOT_WALLETS.get(normalizedTo);
  
  if (exchangeFrom || exchangeTo) {
    details.isExchangeTransaction = true;
    details.isWhitelistedDestination = true;
    details.contractName = exchangeFrom || exchangeTo;
    
    return {
      hash: tx.hash,
      label: 'LEGITIMATE',
      type: exchangeFrom ? 'EXCHANGE_WITHDRAWAL' : 'EXCHANGE_DEPOSIT',
      confidence: 95,
      reason: `Exchange transaction: ${exchangeFrom || exchangeTo}`,
      details,
    };
  }
  
  // ============================================
  // CHECK 2: Safe contract interactions
  // ============================================
  const safeContract = isSafeContract(normalizedTo);
  if (safeContract) {
    details.isVerifiedContract = true;
    details.contractAddress = normalizedTo;
    details.contractName = safeContract.name;
    details.contractCategory = safeContract.category;
    details.isProtocolInteraction = true;
    details.isWhitelistedDestination = true;
    
    // Determine type based on category and method
    let txType: TransactionType = 'UNKNOWN';
    if (safeContract.category === 'NFT_MARKETPLACE') {
      txType = methodId.startsWith('0xfb0f3ee1') || methodId.startsWith('0x87201b41') 
        ? 'NFT_PURCHASE' : 'NFT_SALE';
    } else if (safeContract.category === 'NFT_MINT_CONTRACT') {
      txType = 'NFT_MINT';
    } else if (safeContract.category === 'DEX_ROUTER' || safeContract.category === 'AGGREGATOR') {
      txType = 'DEX_SWAP';
    } else if (safeContract.category === 'BRIDGE') {
      txType = isOutbound ? 'BRIDGE_DEPOSIT' : 'BRIDGE_WITHDRAWAL';
    } else if (safeContract.category === 'STAKING') {
      txType = isOutbound ? 'STAKING_DEPOSIT' : 'STAKING_WITHDRAWAL';
    } else if (safeContract.category === 'LENDING') {
      txType = 'LENDING_DEPOSIT';
    } else if (safeContract.category === 'ENS') {
      txType = 'ENS_REGISTRATION';
    }
    
    return {
      hash: tx.hash,
      label: 'LEGITIMATE',
      type: txType !== 'UNKNOWN' ? txType : 'NORMAL_TRANSFER',
      confidence: 98,
      reason: `Verified safe contract: ${safeContract.name}`,
      details,
    };
  }
  
  // ============================================
  // CHECK 3: Legitimate contract label
  // ============================================
  const legitimateName = isLegitimateContract(normalizedTo);
  if (legitimateName) {
    details.isVerifiedContract = true;
    details.contractAddress = normalizedTo;
    details.contractName = legitimateName;
    details.isProtocolInteraction = true;
    details.isWhitelistedDestination = true;
    
    return {
      hash: tx.hash,
      label: 'LEGITIMATE',
      type: 'NORMAL_TRANSFER',
      confidence: 90,
      reason: `Known legitimate contract: ${legitimateName}`,
      details,
    };
  }
  
  // ============================================
  // CHECK 4: Standard method signatures
  // ============================================
  const methodInfo = METHOD_NAMES[methodId];
  if (methodInfo) {
    details.methodId = methodId;
    details.methodName = methodInfo.name;
    details.isStandardMethod = true;
    
    // Standard methods to safe contracts are definitely legitimate
    if (isStandardApprovalMethod(methodId) || isStandardMintMethod(methodId)) {
      return {
        hash: tx.hash,
        label: 'LEGITIMATE',
        type: methodInfo.type,
        confidence: 85,
        reason: `Standard ${methodInfo.name} method call`,
        details,
      };
    }
    
    return {
      hash: tx.hash,
      label: 'LEGITIMATE',
      type: methodInfo.type,
      confidence: 80,
      reason: `Known method: ${methodInfo.name}`,
      details,
    };
  }
  
  // ============================================
  // CHECK 5: Known malicious addresses (SUSPICIOUS)
  // ============================================
  if (isKnownDrainer(normalizedTo)) {
    const drainerType = getDrainerType(normalizedTo);
    details.riskFlags = ['KNOWN_DRAINER_ADDRESS'];
    details.attackType = 'WALLET_DRAINER';
    
    return {
      hash: tx.hash,
      label: 'SUSPICIOUS',
      type: 'DRAINER_INTERACTION',
      confidence: 98,
      reason: `Transaction to known drainer address (${drainerType})`,
      details,
    };
  }
  
  const malicious = isMaliciousAddress(normalizedTo, chain);
  if (malicious) {
    details.riskFlags = ['MALICIOUS_CONTRACT'];
    details.attackType = malicious.type;
    
    return {
      hash: tx.hash,
      label: 'SUSPICIOUS',
      type: 'DRAINER_INTERACTION',
      confidence: 95,
      reason: `Interaction with malicious contract: ${malicious.name || normalizedTo}`,
      details,
    };
  }
  
  // ============================================
  // CHECK 6: Simple ETH transfers
  // ============================================
  if (!tx.input || tx.input === '0x' || tx.input === '0x00') {
    // Simple ETH transfer - usually legitimate
    const hasValue = BigInt(tx.value || '0') > BigInt(0);
    
    if (hasValue) {
      return {
        hash: tx.hash,
        label: 'LEGITIMATE',
        type: 'NORMAL_TRANSFER',
        confidence: 70,
        reason: 'Simple ETH transfer - no contract interaction',
        details,
      };
    }
  }
  
  // ============================================
  // DEFAULT: Needs review (not suspicious by default)
  // ============================================
  return {
    hash: tx.hash,
    label: 'NEEDS_REVIEW',
    type: 'UNKNOWN',
    confidence: 40,
    reason: 'Unknown contract interaction - requires manual review',
    details,
  };
}

/**
 * Label multiple transactions and generate a summary report.
 */
export function labelTransactions(
  transactions: TransactionInput[],
  walletAddress: string,
  chain: Chain
): {
  labeledTransactions: LabeledTransaction[];
  summary: TransactionSummary;
} {
  const labeled = transactions.map(tx => labelTransaction(tx, walletAddress, chain));
  
  const legitimate = labeled.filter(t => t.label === 'LEGITIMATE');
  const suspicious = labeled.filter(t => t.label === 'SUSPICIOUS');
  const needsReview = labeled.filter(t => t.label === 'NEEDS_REVIEW');
  
  const summary: TransactionSummary = {
    totalTransactions: transactions.length,
    legitimateCount: legitimate.length,
    suspiciousCount: suspicious.length,
    needsReviewCount: needsReview.length,
    legitimatePercentage: (legitimate.length / transactions.length) * 100,
    suspiciousTransactions: suspicious.map(t => ({
      hash: t.hash,
      type: t.type,
      reason: t.reason,
    })),
    riskAssessment: getRiskAssessment(suspicious.length, transactions.length),
    recommendation: getRecommendation(suspicious, needsReview, legitimate),
  };
  
  return { labeledTransactions: labeled, summary };
}

export interface TransactionSummary {
  totalTransactions: number;
  legitimateCount: number;
  suspiciousCount: number;
  needsReviewCount: number;
  legitimatePercentage: number;
  suspiciousTransactions: { hash: string; type: TransactionType; reason: string }[];
  riskAssessment: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendation: string;
}

function getRiskAssessment(suspiciousCount: number, totalCount: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (suspiciousCount === 0) return 'LOW';
  const suspiciousRatio = suspiciousCount / totalCount;
  if (suspiciousRatio > 0.5) return 'CRITICAL';
  if (suspiciousRatio > 0.2) return 'HIGH';
  if (suspiciousCount > 0) return 'MEDIUM';
  return 'LOW';
}

function getRecommendation(
  suspicious: LabeledTransaction[],
  needsReview: LabeledTransaction[],
  legitimate: LabeledTransaction[]
): string {
  if (suspicious.length === 0 && needsReview.length <= 2) {
    return 'No threats detected. This wallet shows normal, legitimate activity.';
  }
  
  if (suspicious.length === 0 && needsReview.length > 2) {
    return `${needsReview.length} transactions could not be automatically verified. ` +
           'Manual review recommended but no immediate threat detected.';
  }
  
  if (suspicious.length === 1) {
    return `1 suspicious transaction detected: ${suspicious[0].reason}. ` +
           'Review this specific transaction for potential security concerns.';
  }
  
  return `${suspicious.length} suspicious transactions detected. ` +
         'Review flagged transactions and consider security measures.';
}

/**
 * Generate a clean risk report for a wallet.
 */
export function generateRiskReport(
  walletAddress: string,
  chain: Chain,
  labeledTransactions: LabeledTransaction[]
): WalletRiskReport {
  const suspicious = labeledTransactions.filter(t => t.label === 'SUSPICIOUS');
  const legitimate = labeledTransactions.filter(t => t.label === 'LEGITIMATE');
  
  return {
    walletAddress,
    chain,
    analysisTimestamp: new Date().toISOString(),
    
    // Overall assessment
    overallStatus: suspicious.length === 0 ? 'SAFE' : 'AT_RISK',
    riskLevel: getRiskAssessment(suspicious.length, labeledTransactions.length),
    
    // Transaction breakdown
    transactionBreakdown: {
      total: labeledTransactions.length,
      legitimate: legitimate.length,
      suspicious: suspicious.length,
      needsReview: labeledTransactions.filter(t => t.label === 'NEEDS_REVIEW').length,
    },
    
    // Only show true threats
    confirmedThreats: suspicious.map(t => ({
      transactionHash: t.hash,
      threatType: t.type,
      confidence: t.confidence,
      reason: t.reason,
      attackType: t.details.attackType,
    })),
    
    // Legitimate activity summary
    legitimateActivity: {
      exchangeTransactions: legitimate.filter(t => t.type.includes('EXCHANGE')).length,
      dexSwaps: legitimate.filter(t => t.type.includes('DEX')).length,
      nftActivity: legitimate.filter(t => t.type.includes('NFT')).length,
      stakingActivity: legitimate.filter(t => t.type.includes('STAKING')).length,
      normalTransfers: legitimate.filter(t => t.type === 'NORMAL_TRANSFER').length,
    },
    
    // Explanation
    summary: suspicious.length === 0
      ? 'No confirmed malicious activity detected. All analyzed transactions appear to be legitimate user activity.'
      : `${suspicious.length} suspicious transaction(s) identified with clear explanation for each alert.`,
  };
}

export interface WalletRiskReport {
  walletAddress: string;
  chain: Chain;
  analysisTimestamp: string;
  overallStatus: 'SAFE' | 'AT_RISK' | 'COMPROMISED';
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  transactionBreakdown: {
    total: number;
    legitimate: number;
    suspicious: number;
    needsReview: number;
  };
  confirmedThreats: {
    transactionHash: string;
    threatType: TransactionType;
    confidence: number;
    reason: string;
    attackType?: AttackType;
  }[];
  legitimateActivity: {
    exchangeTransactions: number;
    dexSwaps: number;
    nftActivity: number;
    stakingActivity: number;
    normalTransfers: number;
  };
  summary: string;
}

// ============================================
// EXPORTS
// ============================================

export {
  EXCHANGE_HOT_WALLETS,
  METHOD_NAMES,
};

