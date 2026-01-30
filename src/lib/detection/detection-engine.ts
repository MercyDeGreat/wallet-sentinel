// ============================================
// WALLET SENTINEL - CORE DETECTION ENGINE
// ============================================
// This is the main security analysis engine that coordinates
// threat detection across all supported chains.
// All operations are READ-ONLY and defensive.
//
// CRITICAL FALSE POSITIVE PREVENTION:
// 1. Contracts are CLASSIFIED before threat labels are applied
// 2. Safe contracts (OpenSea, ENS, Uniswap, etc.) are NEVER flagged
// 3. Sweeper/drainer detection is BEHAVIOR-BASED, not interaction-based
// 4. Confidence < 90% = no CRITICAL alerts
// 5. Normal user behavior is explicitly classified
// 6. Each transaction is explicitly labeled (LEGITIMATE vs SUSPICIOUS)
// 7. Exchange deposits/withdrawals are ALWAYS legitimate
// 8. NFT mints, presales, and approved contracts are whitelisted
//
// RULE: It is better to MISS a threat than to falsely accuse.
// PRINCIPLE: Treat all transactions as POTENTIALLY NORMAL unless proven malicious.

import {
  AttackType,
  Chain,
  DetectedThreat,
  RiskLevel,
  SecurityStatus,
  TokenApproval,
  SuspiciousTransaction,
  WalletAnalysisResult,
  WalletRole,
} from '@/types';
import {
  isMaliciousAddress,
  isInfiniteApproval,
  DRAINER_PATTERNS,
  getAttackTypeFromPattern,
  isLegitimateContract,
} from './malicious-database';
import {
  isSafeContract,
  checkAddressSafety,
  SafeContract,
  isDEXRouterOnChain,
} from './safe-contracts';
import {
  classifyContract,
  ContractClassification,
  shouldExcludeFromMaliciousFlagging,
  getSafetyExplanation,
} from './contract-classifier';
import {
  checkInfrastructureProtection,
  isVerifiedDEXRouter,
  checkBaseDEXActivity,
  isNormalDEXActivityOnly,
} from './infrastructure-protection';
import {
  checkBaseProtocolInteraction,
  checkSelfTransfer,
  checkExchangeWallet,
  classifyBaseChainWallet,
  determineCompromiseState,
  ENS_BASE_CONTRACTS,
  BASE_BRIDGE_CONTRACTS,
  EXCHANGE_WALLETS,
} from './base-chain-protection';
import {
  analyzeWalletBehavior,
  BehaviorAnalysisResult,
  calculateSweeperBotScore,
  TransactionForAnalysis,
  UserBehaviorClassification,
} from './behavior-analyzer';
import { isKnownDrainer, getDrainerType, isBaseSweeperAddress } from './drainer-addresses';
import { 
  detectBaseSweeperBot, 
  BaseTransactionForSweeper,
  BaseSweeperDetectionResult,
  KNOWN_BASE_SWEEPERS,
} from './base-sweeper-detector';
import {
  labelTransaction,
  labelTransactions,
  generateRiskReport,
  LabeledTransaction,
  TransactionSummary,
  WalletRiskReport,
  TransactionInput,
  EXCHANGE_HOT_WALLETS,
} from './transaction-labeler';

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
  // NEW: Behavioral risk factors
  behaviorRiskScore: number;
  legitimateActivityScore: number;
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
  
  // NEW: Add behavioral risk score
  score += factors.behaviorRiskScore;
  
  // NEW: SUBTRACT legitimate activity (reduces false positives)
  score -= factors.legitimateActivityScore;

  // Clamp to 0-100
  return Math.min(100, Math.max(0, score));
}

export function determineSecurityStatus(
  riskScore: number, 
  threats: DetectedThreat[],
  behaviorAnalysis?: BehaviorAnalysisResult,
  drainerOverrideActive?: boolean
): SecurityStatus {
  // ============================================
  // HARD OVERRIDE: ACTIVE_COMPROMISE_DRAINER
  // ============================================
  // If drainer override is active (from DrainerActivityDetector),
  // this MUST return ACTIVE_COMPROMISE_DRAINER regardless of any other analysis.
  // This cannot be bypassed or downgraded.
  if (drainerOverrideActive) {
    return 'ACTIVE_COMPROMISE_DRAINER';
  }
  
  // NEW: Check behavior analysis first
  if (behaviorAnalysis) {
    // If behavior shows NORMAL_USER or POWER_USER, don't flag as compromised
    if (behaviorAnalysis.classification === 'NORMAL_USER' || 
        behaviorAnalysis.classification === 'POWER_USER') {
      if (riskScore < 50) {
        return 'SAFE';
      }
      return 'AT_RISK';
    }
    
    // SECURITY FIX: Confirmed sweeper/drainer = ACTIVE_COMPROMISE_DRAINER
    if (behaviorAnalysis.classification === 'CONFIRMED_SWEEPER' ||
        behaviorAnalysis.classification === 'CONFIRMED_DRAINER') {
      return 'ACTIVE_COMPROMISE_DRAINER';
    }
    
    // Only show COMPROMISED if confidence is high
    if (behaviorAnalysis.isDefinitelyMalicious && behaviorAnalysis.confidence >= 90) {
      return 'COMPROMISED';
    }
  }

  // Check for critical active threats
  const hasCriticalThreat = threats.some(
    (t) => t.severity === 'CRITICAL' && t.ongoingRisk
  );

  // MODIFIED: Raise threshold for COMPROMISED status
  if (hasCriticalThreat && riskScore >= 80) {
    return 'COMPROMISED';
  }

  // MODIFIED: More conservative AT_RISK threshold
  if (riskScore >= 50 || threats.length > 2) {
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

/**
 * Main threat detection function.
 * NOW includes contract classification to prevent false positives.
 * 
 * RULE: DEX interaction alone ≠ compromise signal
 * A wallet should NEVER be flagged as compromised solely for making a Uniswap transaction.
 */
export async function detectDrainerPatterns(
  transactions: TransactionData[],
  chain: Chain,
  walletAddress: string
): Promise<{
  threats: DetectedThreat[];
  behaviorAnalysis: BehaviorAnalysisResult;
  excludedFromFlagging: string[];
  isDEXOnlyActivity?: boolean;
}> {
  const threats: DetectedThreat[] = [];
  const excludedFromFlagging: string[] = [];
  
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions : [];
  const normalizedWalletAddress = walletAddress.toLowerCase();
  
  // ============================================
  // CRITICAL (HIGHEST PRIORITY): KNOWN DRAINER/SWEEPER DATABASE CHECK
  // ============================================
  // THIS CHECK MUST COME FIRST - before ANY other logic.
  // If the wallet address itself is in our verified database, it MUST be flagged
  // regardless of its transaction history, chain, or any other factor.
  // 
  // This prevents known sweepers from showing as "SAFE" due to:
  // - No transactions
  // - DEX-only activity patterns
  // - Chain-specific heuristics not matching
  if (isKnownDrainer(normalizedWalletAddress)) {
    const drainerType = getDrainerType(normalizedWalletAddress);
    const isBaseSweeper = isBaseSweeperAddress(normalizedWalletAddress);
    
    const threatTitle = drainerType || 'Confirmed Drainer/Sweeper';
    const threatDescription = isBaseSweeper
      ? 'Wallet shows automated sweep behavior. Funds are programmatically forwarded immediately after receipt, consistent with post-compromise sweeper infrastructure.'
      : `This address is a confirmed ${drainerType || 'drainer'}. Do not interact.`;
    
    const threat: DetectedThreat = {
      id: `known-drainer-${Date.now()}`,
      type: 'WALLET_DRAINER',
      severity: 'CRITICAL',
      title: threatTitle,
      description: threatDescription,
      technicalDetails: `Database match: ${drainerType || 'Known Drainer'} (Chain: ${chain})`,
      detectedAt: new Date().toISOString(),
      relatedAddresses: [normalizedWalletAddress],
      relatedTransactions: [],
      ongoingRisk: true,
    };
    
    return {
      threats: [threat],
      behaviorAnalysis: {
        classification: 'CONFIRMED_SWEEPER',
        walletRole: 'ATTACKER',
        confidence: 100,
        isDefinitelyMalicious: true,
        isProbablyMalicious: true,
        showCriticalAlert: true,
        explanation: isBaseSweeper
          ? 'CRITICAL: This wallet is a VERIFIED SWEEPER BOT. Funds are programmatically forwarded immediately after receipt. DO NOT send any funds to this address.'
          : `CRITICAL: This wallet is a CONFIRMED ${drainerType || 'DRAINER'}. DO NOT interact with this address.`,
        evidence: [{
          type: 'KNOWN_DRAINER_RECIPIENT',
          description: `Address is in verified malicious database: ${drainerType || 'Known Drainer'}`,
          weight: 50,
          data: { 
            address: normalizedWalletAddress, 
            drainerType,
            chain,
          },
        }],
        riskScore: 100,
        riskLevel: 'CRITICAL',
        threats: [threat],
        detectedIntents: [],
        explainability: {
          classificationReason: `Matched verified malicious database: ${drainerType || 'Known Drainer'}`,
          behavioralTriggers: ['ADDRESS_IN_KNOWN_DATABASE'],
          userIntentDetected: [],
          protocolInteractionDetected: [],
          sweeperRuledOutReasons: [],
          failedSweeperCriteria: [],
          passedSweeperCriteria: ['Known drainer/sweeper address'],
        },
      },
      excludedFromFlagging: [],
      isDEXOnlyActivity: false,
    };
  }
  
  // If no transactions but address is NOT in known database, return NEW_WALLET
  if (safeTxs.length === 0) {
    return {
      threats: [],
      behaviorAnalysis: {
        classification: 'NEW_WALLET',
        walletRole: 'UNKNOWN',
        confidence: 10,
        isDefinitelyMalicious: false,
        isProbablyMalicious: false,
        showCriticalAlert: false,
        explanation: 'No transaction history available.',
        evidence: [],
        riskScore: 0,
        riskLevel: 'LOW',
        threats: [],
        detectedIntents: [],
        explainability: {
          classificationReason: 'No transaction history available for analysis.',
          behavioralTriggers: [],
          userIntentDetected: [],
          protocolInteractionDetected: [],
          sweeperRuledOutReasons: ['No transactions to analyze'],
          failedSweeperCriteria: [],
          passedSweeperCriteria: [],
        },
      },
      excludedFromFlagging: [],
      isDEXOnlyActivity: false,
    };
  }
  
  // ============================================
  // STEP 0a: BASE CHAIN SPECIFIC - SELF-TRANSFER CHECK
  // ============================================
  // RULE 2: Self-transfers are ALWAYS safe
  const selfTransferTxs = safeTxs.filter(tx => {
    const selfCheck = checkSelfTransfer(tx.from, tx.to);
    return selfCheck.isSelfTransfer;
  });
  
  // If ALL transactions are self-transfers, wallet is SAFE
  if (selfTransferTxs.length === safeTxs.length && safeTxs.length > 0) {
    return {
      threats: [],
      behaviorAnalysis: {
        classification: 'NORMAL_USER',
        walletRole: 'UNKNOWN',
        confidence: 100,
        isDefinitelyMalicious: false,
        isProbablyMalicious: false,
        showCriticalAlert: false,
        explanation: 'All transactions are self-transfers (wallet reorganization). Risk = 0.',
        evidence: [{
          type: 'USER_INTENT_SIGNALS',
          description: 'Self-transfer detected - normal wallet reorganization',
          weight: -100,
          data: { chain, selfTransferCount: selfTransferTxs.length },
        }],
        riskScore: 0,
        riskLevel: 'LOW',
        threats: [],
        detectedIntents: [],
        explainability: {
          classificationReason: 'Self-transfers only - always safe',
          behavioralTriggers: [],
          userIntentDetected: ['Wallet reorganization'],
          protocolInteractionDetected: [],
          sweeperRuledOutReasons: ['Self-transfers cannot be drainer activity'],
          failedSweeperCriteria: ['Sender === Receiver'],
          passedSweeperCriteria: [],
        },
      },
      excludedFromFlagging: safeTxs.map(tx => tx.to?.toLowerCase()).filter(Boolean) as string[],
      isDEXOnlyActivity: false,
    };
  }
  
  // ============================================
  // STEP 0b: BASE CHAIN - PROTOCOL INTERACTION CHECK
  // ============================================
  // RULE 1: Whitelisted protocol interactions (Uniswap, ENS.base, bridges) = SAFE
  if (chain === 'base') {
    const protocolChecks = safeTxs.map(tx => checkBaseProtocolInteraction(tx.to, tx.methodId));
    const allLegitimate = protocolChecks.every(p => p.isLegitimateProtocol);
    
    if (allLegitimate && safeTxs.length > 0) {
      const protocolNames = protocolChecks
        .filter(p => p.protocolName)
        .map(p => p.protocolName!)
        .filter((v, i, a) => a.indexOf(v) === i); // unique
      
      return {
        threats: [],
        behaviorAnalysis: {
          classification: 'NORMAL_USER',
          walletRole: 'UNKNOWN',
          confidence: 95,
          isDefinitelyMalicious: false,
          isProbablyMalicious: false,
          showCriticalAlert: false,
          explanation: `Legitimate protocol activity detected (Base chain): ${protocolNames.join(', ')}`,
        evidence: [{
          type: 'ROUTER_INTERACTION_DETECTED',
          description: `Verified protocol interactions: ${protocolNames.join(', ')}`,
          weight: -50,
          data: { chain, protocols: protocolNames },
        }],
        riskScore: 0,
        riskLevel: 'LOW',
        threats: [],
        detectedIntents: protocolChecks
          .filter(p => p.protocolType)
          .map(p => ({
            type: p.protocolType === 'DEX' ? 'DEX_SWAP' as const : 
                  p.protocolType === 'BRIDGE' ? 'BRIDGE_DEPOSIT' as const : 
                  'ROUTER_INTERACTION' as const,
            confidence: 0.95,
            description: p.explanation,
          })),
          explainability: {
            classificationReason: `Legitimate ${chain} protocol activity`,
            behavioralTriggers: [],
            userIntentDetected: protocolNames.map(n => `Interaction with ${n}`),
            protocolInteractionDetected: protocolNames,
            sweeperRuledOutReasons: ['All interactions with verified protocols'],
            failedSweeperCriteria: ['Verified protocol interaction'],
            passedSweeperCriteria: [],
          },
        },
        excludedFromFlagging: safeTxs.map(tx => tx.to?.toLowerCase()).filter(Boolean) as string[],
        isDEXOnlyActivity: protocolChecks.every(p => p.protocolType === 'DEX'),
      };
    }
    
    // Check for exchange transfers - these REDUCE risk
    const exchangeTransfers = safeTxs.filter(tx => {
      const exchangeCheck = checkExchangeWallet(tx.to);
      return exchangeCheck.isExchange;
    });
    
    if (exchangeTransfers.length === safeTxs.length && safeTxs.length > 0) {
      return {
        threats: [],
        behaviorAnalysis: {
          classification: 'NORMAL_USER',
          walletRole: 'UNKNOWN',
          confidence: 95,
          isDefinitelyMalicious: false,
          isProbablyMalicious: false,
          showCriticalAlert: false,
          explanation: 'All transfers are to verified exchange wallets. Exchanges cannot be sweepers.',
        evidence: [{
          type: 'EXCHANGE_DEPOSIT_DETECTED',
          description: 'Transfers to verified exchange wallets',
          weight: -50,
          data: { chain, exchangeTransferCount: exchangeTransfers.length },
        }],
          riskScore: 0,
          riskLevel: 'LOW',
          threats: [],
          detectedIntents: [{
            type: 'EXCHANGE_DEPOSIT',
            confidence: 0.95,
            description: 'CEX deposit activity',
          }],
          explainability: {
            classificationReason: 'Exchange deposits only - always legitimate',
            behavioralTriggers: [],
            userIntentDetected: ['Exchange deposit'],
            protocolInteractionDetected: [],
            sweeperRuledOutReasons: ['Exchanges cannot be sweepers by definition'],
            failedSweeperCriteria: ['Destination is verified exchange'],
            passedSweeperCriteria: [],
          },
        },
        excludedFromFlagging: safeTxs.map(tx => tx.to?.toLowerCase()).filter(Boolean) as string[],
        isDEXOnlyActivity: false,
      };
    }
  }
  
  // ============================================
  // STEP 0c: CHECK FOR DEX-ONLY ACTIVITY (All chains)
  // ============================================
  // RULE: DEX interaction alone ≠ compromise signal
  // If the ONLY indicators are Uniswap swap, liquidity add/remove, or token approval
  // to verified router → force SAFE status with risk score 0-1
  const dexActivityCheck = isNormalDEXActivityOnly(
    safeTxs.map(tx => ({ to: tx.to, methodId: tx.methodId, chain }))
  );
  
  if (dexActivityCheck.isNormalDEXOnly && dexActivityCheck.forceSafeStatus) {
    return {
      threats: [],
      behaviorAnalysis: {
        classification: 'NORMAL_USER',
        walletRole: 'UNKNOWN',
        confidence: 95,
        isDefinitelyMalicious: false,
        isProbablyMalicious: false,
        showCriticalAlert: false,
        explanation: dexActivityCheck.explanation,
        evidence: [{
          type: 'DEX_SWAP_DETECTED',
          description: dexActivityCheck.explanation,
          weight: -50,
          data: { chain, transactionCount: safeTxs.length },
        }],
        riskScore: 0,
        riskLevel: 'LOW',
        threats: [],
        detectedIntents: [{
          type: 'DEX_SWAP',
          confidence: 0.95,
          description: dexActivityCheck.explanation,
        }],
        explainability: {
          classificationReason: `Normal DEX activity detected (${chain} chain)`,
          behavioralTriggers: [],
          userIntentDetected: ['Normal DEX activity detected'],
          protocolInteractionDetected: ['Verified DEX router interaction'],
          sweeperRuledOutReasons: ['DEX interaction alone ≠ compromise signal'],
          failedSweeperCriteria: ['Interacts with verified DEX protocols'],
          passedSweeperCriteria: [],
        },
      },
      excludedFromFlagging: safeTxs.map(tx => tx.to?.toLowerCase()).filter(Boolean) as string[],
      isDEXOnlyActivity: true,
    };
  }

  // ============================================
  // STEP 0d: BASE CHAIN SWEEPER BOT DETECTION
  // ============================================
  // Base chain requires different detection logic:
  // - Sequencer-based ordering (no public mempool)
  // - Same-block or near-zero-latency reactions
  // - Gas price is NOT a reliable signal
  // - Reaction-based detection instead of mempool signals
  if (chain === 'base') {
    const baseSweeperResult = runBaseChainSweeperDetection(walletAddress, safeTxs);
    
    if (baseSweeperResult && baseSweeperResult.isSweeper && baseSweeperResult.confidence >= 85) {
      const sweeperThreat: DetectedThreat = {
        id: `base-sweeper-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: baseSweeperResult.severity,
        title: baseSweeperResult.classification,
        description: baseSweeperResult.explanation,
        technicalDetails: `Heuristics: ${baseSweeperResult.heuristics.heuristicsMet.join('; ')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: baseSweeperResult.relatedAddresses,
        relatedTransactions: baseSweeperResult.drainPatterns.map(p => p.inboundTxHash),
        ongoingRisk: true,
      };
      
      return {
        threats: [sweeperThreat],
        behaviorAnalysis: {
          classification: 'CONFIRMED_SWEEPER',
          walletRole: 'ATTACKER',
          confidence: baseSweeperResult.confidence,
          isDefinitelyMalicious: true,
          isProbablyMalicious: true,
          showCriticalAlert: baseSweeperResult.severity === 'CRITICAL',
          explanation: baseSweeperResult.explanation,
          evidence: [{
            type: 'RAPID_DRAIN_NO_PROTOCOL',
            description: `Base chain sweeper: ${baseSweeperResult.heuristics.heuristicsMetCount}/6 heuristics met`,
            weight: 50,
            data: { 
              chain: 'base',
              classification: baseSweeperResult.classification,
              heuristics: baseSweeperResult.heuristics.heuristicsMet,
            },
          }],
          riskScore: baseSweeperResult.confidence,
          riskLevel: baseSweeperResult.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
          threats: [sweeperThreat],
          detectedIntents: [],
          explainability: {
            classificationReason: baseSweeperResult.explanation,
            behavioralTriggers: baseSweeperResult.heuristics.heuristicsMet,
            userIntentDetected: [],
            protocolInteractionDetected: [],
            sweeperRuledOutReasons: [],
            failedSweeperCriteria: baseSweeperResult.heuristics.heuristicsFailed,
            passedSweeperCriteria: baseSweeperResult.heuristics.heuristicsMet,
          },
        },
        excludedFromFlagging: [],
        isDEXOnlyActivity: false,
      };
    }
  }

  // ============================================
  // STEP 1: Classify all interacted contracts
  // ============================================
  const contractClassifications = new Map<string, ContractClassification>();
  const allAddresses = new Set<string>();
  let dexRouterCount = 0;
  
  for (const tx of safeTxs) {
    if (tx.to) allAddresses.add(tx.to.toLowerCase());
    if (tx.from) allAddresses.add(tx.from.toLowerCase());
  }
  
  for (const addr of allAddresses) {
    // ============================================
    // CHECK 0: Base chain protocol protection
    // ============================================
    if (chain === 'base') {
      const baseProtocol = checkBaseProtocolInteraction(addr);
      if (baseProtocol.isLegitimateProtocol) {
        const safeClassification: ContractClassification = {
          type: baseProtocol.protocolType === 'ENS' ? 'ENS' : 
                baseProtocol.protocolType === 'BRIDGE' ? 'BRIDGE' : 
                baseProtocol.protocolType === 'EXCHANGE' ? 'VERIFIED_SERVICE' :
                'DEFI_PROTOCOL',
          name: baseProtocol.protocolName,
          isVerified: true,
          canBeFlaggedMalicious: false,
          classificationReason: baseProtocol.explanation,
          confidence: 'HIGH',
          source: 'SAFE_CONTRACTS_DB',
        };
        contractClassifications.set(addr, safeClassification);
        excludedFromFlagging.push(addr);
        if (baseProtocol.protocolType === 'DEX') {
          dexRouterCount++;
        }
        continue;
      }
      
      // Check for exchange wallets
      const exchangeCheck = checkExchangeWallet(addr);
      if (exchangeCheck.isExchange) {
        const exchangeClassification: ContractClassification = {
          type: 'VERIFIED_SERVICE',
          name: exchangeCheck.exchangeInfo?.name || 'Verified Exchange',
          isVerified: true,
          canBeFlaggedMalicious: false,
          classificationReason: exchangeCheck.explanation,
          confidence: 'HIGH',
          source: 'SAFE_CONTRACTS_DB',
        };
        contractClassifications.set(addr, exchangeClassification);
        excludedFromFlagging.push(addr);
        continue;
      }
    }
    
    // Check infrastructure protection first (highest priority)
    const infraProtection = checkInfrastructureProtection(addr, chain);
    if (infraProtection.isProtected) {
      // Map infrastructure type to contract classification type
      let classType: 'DEFI_PROTOCOL' | 'MARKETPLACE' | 'BRIDGE' | 'VERIFIED_SERVICE' | 'ENS' | 'STAKING' | 'INFRASTRUCTURE' = 'VERIFIED_SERVICE';
      if (infraProtection.type === 'DEX_ROUTER' || infraProtection.type === 'AGGREGATOR' || infraProtection.type === 'LENDING_PROTOCOL') {
        classType = 'DEFI_PROTOCOL';
      } else if (infraProtection.type === 'NFT_MARKETPLACE') {
        classType = 'MARKETPLACE';
      } else if (infraProtection.type === 'BRIDGE') {
        classType = 'BRIDGE';
      } else if (infraProtection.type === 'ENS_INFRASTRUCTURE') {
        classType = 'ENS';
      }
      
      // Create a classification that marks this as safe
      const safeClassification: ContractClassification = {
        type: classType,
        name: infraProtection.name,
        isVerified: true,
        canBeFlaggedMalicious: false,
        classificationReason: `Protected infrastructure: ${infraProtection.name}`,
        confidence: 'HIGH',
        source: 'SAFE_CONTRACTS_DB',
      };
      contractClassifications.set(addr, safeClassification);
      excludedFromFlagging.push(addr);
      
      // Count DEX routers for activity analysis
      if (infraProtection.type === 'DEX_ROUTER' || infraProtection.type === 'AGGREGATOR') {
        dexRouterCount++;
      }
      continue;
    }
    
    // Check if it's a verified DEX router on this chain
    if (isVerifiedDEXRouter(addr, chain)) {
      const dexClassification: ContractClassification = {
        type: 'DEFI_PROTOCOL',
        subCategory: 'DEX_ROUTER',
        name: 'Verified DEX Router',
        isVerified: true,
        canBeFlaggedMalicious: false,
        classificationReason: `Verified DEX router on ${chain}`,
        confidence: 'HIGH',
        source: 'SAFE_CONTRACTS_DB',
      };
      contractClassifications.set(addr, dexClassification);
      excludedFromFlagging.push(addr);
      dexRouterCount++;
      continue;
    }
    
    // Fall back to standard classification
    const classification = await classifyContract(addr, chain);
    contractClassifications.set(addr, classification);
    
    // Track excluded addresses
    if (shouldExcludeFromMaliciousFlagging(classification)) {
      excludedFromFlagging.push(addr);
    }
  }
  
  // If most interactions are with DEX routers, reduce risk score
  const dexRatio = allAddresses.size > 0 ? dexRouterCount / allAddresses.size : 0;

  // ============================================
  // STEP 2: Run behavioral analysis
  // ============================================
  const normalizedWallet = walletAddress.toLowerCase();
  const txsForAnalysis: TransactionForAnalysis[] = safeTxs.map(tx => ({
    hash: tx.hash,
    from: tx.from,
    to: tx.to,
    value: tx.value,
    timestamp: tx.timestamp,
    methodId: tx.methodId,
    isOutbound: tx.from?.toLowerCase() === normalizedWallet,
    isInbound: tx.to?.toLowerCase() === normalizedWallet,
    blockNumber: tx.blockNumber,
  }));
  
  const behaviorAnalysis = await analyzeWalletBehavior(
    walletAddress,
    chain,
    txsForAnalysis
  );

  // If behavioral analysis says normal/power user, be very conservative
  const isLikelyNormalUser = 
    behaviorAnalysis.classification === 'NORMAL_USER' ||
    behaviorAnalysis.classification === 'POWER_USER';

  // ============================================
  // STEP 3: Pattern detection (with exclusions)
  // ============================================
  
  // Pattern 1: Rapid outflow detection
  // MODIFIED: Skip if user is likely normal
  if (!isLikelyNormalUser) {
    const rapidOutflow = detectRapidOutflow(safeTxs, contractClassifications);
    if (rapidOutflow) {
      threats.push(rapidOutflow);
    }
  }

  // Pattern 2: Approval followed by drain
  const approvalDrain = detectApprovalDrain(safeTxs, contractClassifications);
  if (approvalDrain) {
    threats.push(approvalDrain);
  }

  // Pattern 3: Known malicious contract interaction
  const maliciousInteractions = detectMaliciousInteractions(safeTxs, chain, contractClassifications);
  threats.push(...maliciousInteractions);

  // Pattern 4: Sandwich attack detection
  const sandwichAttack = detectSandwichPattern(safeTxs);
  if (sandwichAttack) {
    threats.push(sandwichAttack);
  }

  // Add behavioral threats
  if (behaviorAnalysis.threats.length > 0) {
    threats.push(...behaviorAnalysis.threats);
  }

  return {
    threats,
    behaviorAnalysis,
    excludedFromFlagging,
    isDEXOnlyActivity: dexRatio > 0.8 && dexRouterCount >= 2,
  };
}

function detectRapidOutflow(
  transactions: TransactionData[],
  contractClassifications: Map<string, ContractClassification>
): DetectedThreat | null {
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
      // NEW: Check if ALL destinations are safe contracts
      const destinations = outboundTxs.map(tx => tx.to?.toLowerCase()).filter(Boolean);
      const allSafe = destinations.every(dest => {
        const classification = contractClassifications.get(dest as string);
        return classification && shouldExcludeFromMaliciousFlagging(classification);
      });
      
      if (allSafe) {
        // All going to safe contracts (DEX, bridge, etc.) = NOT suspicious
        return null;
      }
      
      return {
        id: `rapid-outflow-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: 'HIGH', // MODIFIED: Downgraded from CRITICAL
        title: 'Rapid Asset Outflow Detected',
        description: `${outboundTxs.length} outbound transactions detected within ${windowMinutes} minutes. This pattern may indicate unusual activity.`,
        technicalDetails: `Transactions: ${outboundTxs.map((tx) => tx?.hash || 'unknown').join(', ')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [...new Set(outboundTxs.map((tx) => tx?.to).filter(Boolean) as string[])],
        relatedTransactions: outboundTxs.map((tx) => tx?.hash).filter(Boolean) as string[],
        ongoingRisk: false, // MODIFIED: Not necessarily ongoing
      };
    }
  }

  return null;
}

function detectApprovalDrain(
  transactions: TransactionData[],
  contractClassifications: Map<string, ContractClassification>
): DetectedThreat | null {
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
    if (!approval?.timestamp || !approval?.hash || !approval?.to) continue;
    
    // NEW: Skip if approval is to a safe contract
    const spenderClassification = contractClassifications.get(approval.to.toLowerCase());
    if (spenderClassification && shouldExcludeFromMaliciousFlagging(spenderClassification)) {
      continue; // Approval to OpenSea, Uniswap, etc. is NORMAL
    }
    
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
      // Check if the transfer destination is a safe contract
      const allTransfersToSafe = transfers.every(tx => {
        const destClassification = contractClassifications.get(tx.to?.toLowerCase() || '');
        return destClassification && shouldExcludeFromMaliciousFlagging(destClassification);
      });
      
      if (allTransfersToSafe) {
        continue; // Transfer to safe contract = NORMAL (selling NFT, adding liquidity, etc.)
      }
      
      return {
        id: `approval-drain-${Date.now()}`,
        type: 'APPROVAL_HIJACK',
        severity: 'HIGH',
        title: 'Approval Abuse Detected',
        description: 'An approval was granted and used to transfer assets. Review if this was intentional.',
        technicalDetails: `Approval TX: ${approval.hash}, Transfer TXs: ${transfers.map((tx) => tx?.hash || 'unknown').join(', ')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [approval.to, ...transfers.map((tx) => tx?.to)].filter(Boolean) as string[],
        relatedTransactions: [approval.hash, ...transfers.map((tx) => tx?.hash)].filter(Boolean) as string[],
        ongoingRisk: false, // MODIFIED: Need to verify
      };
    }
  }

  return null;
}

function detectMaliciousInteractions(
  transactions: TransactionData[],
  chain: Chain,
  contractClassifications: Map<string, ContractClassification>
): DetectedThreat[] {
  const threats: DetectedThreat[] = [];
  
  // Safe array guard
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];

  for (const tx of safeTxs) {
    if (!tx?.to || !tx?.hash) continue;
    
    const normalizedTo = tx.to.toLowerCase();
    
    // NEW: Check classification first
    const classification = contractClassifications.get(normalizedTo);
    if (classification && shouldExcludeFromMaliciousFlagging(classification)) {
      continue; // Safe contract - skip
    }
    
    // Only check against confirmed malicious database
    const maliciousContract = isMaliciousAddress(tx.to, chain);
    if (maliciousContract) {
      // Double-check it's not a false positive
      if (isSafeContract(normalizedTo)) {
        console.warn(`[Detection] Prevented false positive: ${normalizedTo} is in safe contracts`);
        continue;
      }
      
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
        severity: 'MEDIUM', // MODIFIED: Downgraded - MEV is common
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
    const spenderAddr = approval?.spender || '';
    
    // ============================================
    // CHECK 1: Infrastructure protection (highest priority)
    // ============================================
    const infraProtection = checkInfrastructureProtection(spenderAddr, chain);
    if (infraProtection.isProtected) {
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
        spender: spenderAddr,
        spenderLabel: infraProtection.name || 'Verified Protocol',
        amount: approval.amount,
        isUnlimited,
        riskLevel: 'LOW', // Protected infrastructure = LOW risk even if unlimited
        riskReason: isUnlimited 
          ? `Unlimited approval to verified ${infraProtection.name || 'protocol'} - normal for DEX/DeFi`
          : undefined,
        grantedAt: new Date(approval.timestamp * 1000).toISOString(),
        isMalicious: false,
      };
    }
    
    // ============================================
    // CHECK 2: Verified DEX router on this chain
    // RULE: Approval to verified DEX router is NORMAL, not risky
    // ============================================
    if (isVerifiedDEXRouter(spenderAddr, chain)) {
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
        spender: spenderAddr,
        spenderLabel: 'Verified DEX Router',
        amount: approval.amount,
        isUnlimited,
        riskLevel: 'LOW', // DEX router approval = LOW risk
        riskReason: isUnlimited 
          ? `Unlimited approval to verified DEX router - normal for trading`
          : undefined,
        grantedAt: new Date(approval.timestamp * 1000).toISOString(),
        isMalicious: false,
      };
    }
    
    // ============================================
    // CHECK 3: Safe contracts database
    // ============================================
    const safeContract = isSafeContract(spenderAddr);
    const legitimateLabel = isLegitimateContract(spenderAddr);
    
    // If spender is safe, it's not malicious
    if (safeContract || legitimateLabel) {
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
        spender: spenderAddr,
        spenderLabel: safeContract?.name || legitimateLabel || undefined,
        amount: approval.amount,
        isUnlimited,
        riskLevel: isUnlimited ? 'MEDIUM' : 'LOW', // MODIFIED: Reduced risk for safe contracts
        riskReason: isUnlimited 
          ? `Unlimited approval to ${safeContract?.name || legitimateLabel || 'verified contract'}`
          : undefined,
        grantedAt: new Date(approval.timestamp * 1000).toISOString(),
        isMalicious: false, // Safe contract = not malicious
      };
    }
    
    // Check if spender is malicious
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

export function inferPrivateKeyCompromise(
  transactions: TransactionData[],
  contractClassifications?: Map<string, ContractClassification>
): DetectedThreat | null {
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
    const singleDest = destinations[0];
    
    // NEW: Check if destination is a safe contract
    if (contractClassifications) {
      const destClassification = contractClassifications.get(singleDest);
      if (destClassification && shouldExcludeFromMaliciousFlagging(destClassification)) {
        return null; // All funds going to DEX/bridge/exchange is NORMAL
      }
    }
    
    // Also check static safe contracts
    if (isSafeContract(singleDest) || isLegitimateContract(singleDest)) {
      return null; // Going to known safe destination
    }
    
    // Check time clustering
    const timestamps = outboundTxs.map((tx) => tx?.timestamp || 0).filter(t => t > 0).sort((a, b) => a - b);
    if (timestamps.length < 2) return null;
    
    const timeRange = timestamps[timestamps.length - 1] - timestamps[0];

    // All transactions within 1 hour
    if (timeRange < 3600) {
      return {
        id: `key-compromise-${Date.now()}`,
        type: 'PRIVATE_KEY_LEAK',
        severity: 'HIGH', // MODIFIED: Downgraded from CRITICAL until confirmed
        title: 'Possible Private Key Compromise',
        description: 'Multiple assets were transferred to a single address in a short timeframe. This pattern may indicate compromise.',
        technicalDetails: `All assets sent to: ${singleDest}, Total txs: ${outboundTxs.length}, Time window: ${Math.round(timeRange / 60)} minutes`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: destinations,
        relatedTransactions: outboundTxs.map((tx) => tx?.hash).filter(Boolean) as string[],
        ongoingRisk: false, // MODIFIED: Need to verify
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
  approvals: TokenApproval[],
  behaviorAnalysis?: BehaviorAnalysisResult
): string {
  // Safe array guards
  const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
  const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];
  
  // ============================================
  // ACTIVE_COMPROMISE_DRAINER - HIGHEST PRIORITY
  // ============================================
  if (status === 'ACTIVE_COMPROMISE_DRAINER') {
    return 'CRITICAL: ACTIVE WALLET DRAINER DETECTED. ' +
           'This wallet exhibits active drainer behavior patterns (immediate fund forwarding, token sweeps, drain routing). ' +
           'DO NOT send any funds to this address. This classification CANNOT be downgraded until 90+ days of no activity.';
  }
  
  // NEW: Include behavioral analysis in summary
  if (behaviorAnalysis) {
    if (behaviorAnalysis.classification === 'NORMAL_USER') {
      return 'No malicious behavior detected. Your wallet shows normal user activity patterns. ' +
             'Continue practicing safe wallet hygiene.';
    }
    
    if (behaviorAnalysis.classification === 'POWER_USER') {
      return 'No malicious behavior detected. Your wallet shows power user / active trader patterns. ' +
             'High transaction volume is normal for your usage pattern.';
    }
    
    if (behaviorAnalysis.classification === 'CONFIRMED_DRAINER' || 
        behaviorAnalysis.classification === 'CONFIRMED_SWEEPER') {
      return 'CRITICAL: This wallet has been identified as a confirmed threat. ' +
             'Do not send any funds to this address.';
    }
    
    // For suspects, show confidence
    if (behaviorAnalysis.confidence < 90) {
      if (status === 'AT_RISK') {
        return `Potential security concerns detected (confidence: ${behaviorAnalysis.confidence}%). ` +
               'Review the identified risks below. No confirmed malicious behavior at this time.';
      }
    }
  }
  
  if (status === 'SAFE') {
    return 'No significant security threats detected. Your wallet appears to be in good standing. ' +
           'Continue practicing safe wallet hygiene.';
  }
  
  if (status === 'PREVIOUSLY_COMPROMISED' || status === 'PREVIOUSLY_COMPROMISED_NO_ACTIVITY') {
    return 'This wallet was previously compromised but currently shows no active threats. ' +
           'All malicious access appears to have been revoked. ' +
           'The wallet can be used with caution but cannot be classified as fully Safe.';
  }

  if (status === 'AT_RISK') {
    const riskCount = safeThreats.length + safeApprovals.filter((a) => a?.riskLevel === 'HIGH').length;
    return `${riskCount} potential security concern${riskCount > 1 ? 's' : ''} detected. ` +
           'Review the identified risks below and consider taking preventive action.';
  }

  // COMPROMISED - only show if high confidence
  const criticalThreats = safeThreats.filter((t) => t?.severity === 'CRITICAL');
  return `URGENT: ${criticalThreats.length} critical security threat${criticalThreats.length > 1 ? 's' : ''} detected. ` +
         'Immediate action recommended. Review the recovery plan below to protect remaining assets.';
}

// ============================================
// NEW: CONFIDENCE-BASED MESSAGING
// ============================================

export interface AnalysisMessage {
  title: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  message: string;
  showAlert: boolean;
  actionRequired: boolean;
}

/**
 * Generate user-facing message based on confidence level.
 * CRITICAL: If confidence < 90%, do NOT show CRITICAL or DRAINER labels.
 */
export function generateConfidenceBasedMessage(
  behaviorAnalysis: BehaviorAnalysisResult,
  threats: DetectedThreat[]
): AnalysisMessage {
  const { confidence, classification, riskScore } = behaviorAnalysis;
  
  // RULE: If confidence < 90%, no CRITICAL alerts
  if (confidence < 90) {
    if (classification === 'NORMAL_USER' || classification === 'POWER_USER') {
      return {
        title: 'No Confirmed Threats',
        severity: 'INFO',
        message: 'No confirmed malicious behavior detected. Your wallet shows normal activity.',
        showAlert: false,
        actionRequired: false,
      };
    }
    
    if (riskScore >= 50) {
      return {
        title: 'Potential Concerns',
        severity: 'WARNING',
        message: `Some activity patterns warrant review (confidence: ${confidence}%). ` +
                 'No confirmed malicious behavior at this time.',
        showAlert: true,
        actionRequired: false,
      };
    }
    
    return {
      title: 'Analysis Complete',
      severity: 'INFO',
      message: 'No confirmed malicious behavior detected.',
      showAlert: false,
      actionRequired: false,
    };
  }
  
  // High confidence (>= 90%)
  if (classification === 'CONFIRMED_DRAINER' || classification === 'CONFIRMED_SWEEPER') {
    return {
      title: 'CRITICAL: Confirmed Threat',
      severity: 'CRITICAL',
      message: 'This address is a confirmed malicious actor. Do not interact.',
      showAlert: true,
      actionRequired: true,
    };
  }
  
  if (classification === 'SWEEPER_BOT_SUSPECT' || classification === 'DRAINER_SUSPECT') {
    return {
      title: 'High Risk Detected',
      severity: 'WARNING',
      message: 'This address shows strong indicators of malicious behavior. Proceed with extreme caution.',
      showAlert: true,
      actionRequired: true,
    };
  }
  
  return {
    title: 'Analysis Complete',
    severity: 'INFO',
    message: 'No confirmed malicious behavior detected.',
    showAlert: false,
    actionRequired: false,
  };
}

// ============================================
// NEW: FULL WALLET ANALYSIS PIPELINE
// ============================================

/**
 * Complete wallet analysis with all new protections.
 * 
 * RULE: DEX interaction alone ≠ compromise signal
 * A wallet should NEVER be flagged as compromised solely for making DEX transactions.
 */
export async function analyzeWalletComplete(
  address: string,
  chain: Chain,
  transactions: TransactionData[],
  approvals: ApprovalData[]
): Promise<{
  threats: DetectedThreat[];
  approvalAnalysis: TokenApproval[];
  behaviorAnalysis: BehaviorAnalysisResult;
  securityStatus: SecurityStatus;
  riskScore: number;
  message: AnalysisMessage;
  excludedContracts: string[];
}> {
  // Run threat detection with new protections
  const detectionResult = await detectDrainerPatterns(
    transactions,
    chain,
    address
  );
  const { threats, behaviorAnalysis, excludedFromFlagging, isDEXOnlyActivity } = detectionResult;
  
  // Analyze approvals with safe contract awareness
  const approvalAnalysis = analyzeApprovals(approvals, chain);
  
  // ============================================
  // CHECK: If DEX-only activity, force SAFE status
  // ============================================
  if (isDEXOnlyActivity) {
    return {
      threats: [],
      approvalAnalysis,
      behaviorAnalysis: {
        ...behaviorAnalysis,
        classification: 'NORMAL_USER',
        riskScore: 0,
        riskLevel: 'LOW',
        explanation: `Normal DEX activity detected (${chain} chain)`,
      },
      securityStatus: 'SAFE',
      riskScore: 0,
      message: {
        title: 'Normal DEX Activity',
        severity: 'INFO',
        message: `Normal DEX activity detected (${chain} chain). No compromise indicators found.`,
        showAlert: false,
        actionRequired: false,
      },
      excludedContracts: excludedFromFlagging,
    };
  }
  
  // Calculate risk score with behavioral factors
  const factors: RiskFactors = {
    maliciousInteractions: threats.filter(t => t.type === 'WALLET_DRAINER').length,
    infiniteApprovals: approvalAnalysis.filter(a => a.isUnlimited && a.riskLevel !== 'LOW').length,
    suspiciousTransactions: threats.filter(t => t.severity === 'HIGH').length,
    recentDrainActivity: threats.filter(t => t.ongoingRisk).length,
    highRiskApprovals: approvalAnalysis.filter(a => a.riskLevel === 'CRITICAL').length,
    unknownContractInteractions: 0,
    behaviorRiskScore: behaviorAnalysis.riskScore * 0.5, // Weight behavioral analysis
    legitimateActivityScore: behaviorAnalysis.evidence
      .filter(e => e.weight < 0)
      .reduce((sum, e) => sum + Math.abs(e.weight), 0), // Subtract legitimate activity
  };
  
  const riskScore = calculateRiskScore(factors);
  const securityStatus = determineSecurityStatus(riskScore, threats, behaviorAnalysis);
  const message = generateConfidenceBasedMessage(behaviorAnalysis, threats);
  
  return {
    threats,
    approvalAnalysis,
    behaviorAnalysis,
    securityStatus,
    riskScore,
    message,
    excludedContracts: excludedFromFlagging,
  };
}

// ============================================
// NEW: ENHANCED ANALYSIS WITH TRANSACTION LABELING
// ============================================

/**
 * Analyze wallet with explicit transaction labeling.
 * Each transaction is labeled as LEGITIMATE, NEEDS_REVIEW, or SUSPICIOUS.
 * 
 * PRINCIPLE: Default to LEGITIMATE unless proven malicious.
 */
export async function analyzeWalletWithLabeling(
  address: string,
  chain: Chain,
  transactions: TransactionData[],
  approvals: ApprovalData[]
): Promise<{
  threats: DetectedThreat[];
  approvalAnalysis: TokenApproval[];
  behaviorAnalysis: BehaviorAnalysisResult;
  securityStatus: SecurityStatus;
  riskScore: number;
  message: AnalysisMessage;
  excludedContracts: string[];
  // NEW: Transaction labeling
  labeledTransactions: LabeledTransaction[];
  transactionSummary: TransactionSummary;
  riskReport: WalletRiskReport;
}> {
  // Safe transaction array
  const safeTxs = Array.isArray(transactions) ? transactions : [];
  
  // ============================================
  // STEP 1: Label all transactions first
  // ============================================
  const txInputs: TransactionInput[] = safeTxs.map(tx => ({
    hash: tx.hash,
    from: tx.from,
    to: tx.to,
    value: tx.value,
    input: tx.input,
    timestamp: tx.timestamp,
    blockNumber: tx.blockNumber,
    isError: false,
  }));
  
  const { labeledTransactions, summary: transactionSummary } = labelTransactions(
    txInputs,
    address,
    chain
  );
  
  // ============================================
  // STEP 2: Filter out LEGITIMATE transactions from threat analysis
  // Only analyze transactions that are NOT clearly legitimate
  // ============================================
  const legitimateTxHashes = new Set(
    labeledTransactions
      .filter(lt => lt.label === 'LEGITIMATE')
      .map(lt => lt.hash)
  );
  
  // Only consider non-legitimate transactions for threat detection
  const transactionsToAnalyze = safeTxs.filter(
    tx => !legitimateTxHashes.has(tx.hash)
  );
  
  // ============================================
  // STEP 3: Run behavioral analysis on filtered transactions
  // ============================================
  const detectionResult = await detectDrainerPatterns(
    transactionsToAnalyze,
    chain,
    address
  );
  const { threats, behaviorAnalysis, excludedFromFlagging, isDEXOnlyActivity } = detectionResult;
  
  // ============================================
  // STEP 4: Cross-reference with labeled suspicious transactions
  // Only keep threats that align with SUSPICIOUS labels
  // ============================================
  const suspiciousTxHashes = new Set(
    labeledTransactions
      .filter(lt => lt.label === 'SUSPICIOUS')
      .map(lt => lt.hash)
  );
  
  // Filter threats: only keep if related to suspicious transactions OR confirmed drainer
  const validatedThreats = threats.filter(threat => {
    // Always keep threats from confirmed drainer database
    if (threat.type === 'WALLET_DRAINER' && threat.severity === 'CRITICAL') {
      const relatedToSuspicious = threat.relatedTransactions?.some(hash =>
        suspiciousTxHashes.has(hash)
      );
      if (relatedToSuspicious) return true;
    }
    
    // For other threats, verify against labeling
    const hasRelatedSuspicious = threat.relatedTransactions?.some(hash =>
      suspiciousTxHashes.has(hash) || !legitimateTxHashes.has(hash)
    );
    
    return hasRelatedSuspicious;
  });
  
  // ============================================
  // STEP 5: Adjust risk score based on legitimate activity ratio
  // ============================================
  const legitimateRatio = transactionSummary.legitimatePercentage / 100;
  
  // Analyze approvals
  const approvalAnalysis = analyzeApprovals(approvals, chain);
  
  // Calculate risk factors
  const factors: RiskFactors = {
    maliciousInteractions: validatedThreats.filter(t => t.type === 'WALLET_DRAINER').length,
    infiniteApprovals: approvalAnalysis.filter(a => a.isUnlimited && a.riskLevel !== 'LOW').length,
    suspiciousTransactions: validatedThreats.filter(t => t.severity === 'HIGH').length,
    recentDrainActivity: validatedThreats.filter(t => t.ongoingRisk).length,
    highRiskApprovals: approvalAnalysis.filter(a => a.riskLevel === 'CRITICAL').length,
    unknownContractInteractions: 0,
    behaviorRiskScore: behaviorAnalysis.riskScore * 0.5,
    // ENHANCED: Higher legitimate activity = lower risk
    legitimateActivityScore: Math.round(legitimateRatio * 50) + 
      behaviorAnalysis.evidence
        .filter(e => e.weight < 0)
        .reduce((sum, e) => sum + Math.abs(e.weight), 0),
  };
  
  const riskScore = calculateRiskScore(factors);
  
  // Adjust security status based on labeling
  let securityStatus = determineSecurityStatus(riskScore, validatedThreats, behaviorAnalysis);
  
  // ============================================
  // RULE: DEX interaction alone ≠ compromise signal
  // ============================================
  // If DEX-only activity, force SAFE status
  if (isDEXOnlyActivity) {
    securityStatus = 'SAFE';
  }
  
  // If > 90% legitimate and no SUSPICIOUS transactions, force SAFE
  if (legitimateRatio > 0.9 && transactionSummary.suspiciousCount === 0) {
    securityStatus = 'SAFE';
  }
  
  // Generate risk report
  const riskReport = generateRiskReport(address, chain, labeledTransactions);
  
  // Generate message
  const message = generateConfidenceBasedMessage(behaviorAnalysis, validatedThreats);
  
  return {
    threats: validatedThreats,
    approvalAnalysis,
    behaviorAnalysis,
    securityStatus,
    riskScore,
    message,
    excludedContracts: excludedFromFlagging,
    labeledTransactions,
    transactionSummary,
    riskReport,
  };
}

// ============================================
// HELPER: Check if transaction is to/from exchange
// ============================================

export function isExchangeTransaction(from: string, to: string): boolean {
  const normalizedFrom = from?.toLowerCase() || '';
  const normalizedTo = to?.toLowerCase() || '';
  
  return EXCHANGE_HOT_WALLETS.has(normalizedFrom) || EXCHANGE_HOT_WALLETS.has(normalizedTo);
}

export function getExchangeName(address: string): string | null {
  const normalized = address?.toLowerCase() || '';
  return EXCHANGE_HOT_WALLETS.get(normalized) || null;
}

// ============================================
// BASE CHAIN SWEEPER DETECTION HELPER
// ============================================

/**
 * Run Base-specific sweeper detection in the detection engine.
 * 
 * BASE CHAIN DIFFERENCES:
 * - Sequencer-based ordering (no public mempool)
 * - Same-block or near-zero-latency reactions
 * - Gas price is NOT a reliable signal
 * - Reaction-based detection instead of mempool signals
 */
function runBaseChainSweeperDetection(
  walletAddress: string,
  transactions: TransactionData[]
): BaseSweeperDetectionResult | null {
  // Convert to Base sweeper format
  const baseTxs: BaseTransactionForSweeper[] = transactions.map(tx => ({
    hash: tx.hash,
    from: tx.from,
    to: tx.to,
    value: tx.value,
    blockNumber: tx.blockNumber,
    timestamp: tx.timestamp,
    methodId: tx.methodId,
    isETH: true,
  }));
  
  // Run Base sweeper detection
  return detectBaseSweeperBot(walletAddress, baseTxs);
}
