// ============================================
// BASE CHAIN SWEEPER BOT DETECTOR
// ============================================
// CRITICAL: Base chain requires different detection logic than Ethereum
//
// BASE CHAIN DIFFERENCES:
// 1. Sequencer-based ordering (no public mempool)
// 2. Same-block or near-zero-latency reactions
// 3. Gas price is NOT a reliable signal
// 4. Bundled or delayed execution patterns
//
// DETECTION APPROACH:
// Replace mempool dependency with REACTION-BASED behavior analysis
// - Incoming → outgoing within ≤1 block
// - Wallet never accumulates balance (ending balance ≈ 0)
// - Outgoing transfers are programmatic (fixed destination/rotating hot wallets)
// - Gas usage is flat and machine-consistent
// - Pattern repeats across many unrelated sender wallets
// - First action after funding is always a drain, never discretionary
//
// FALSE-POSITIVE GUARDS (CRITICAL):
// - Transfers to self-owned EOAs
// - Bridges (canonical Base bridge, known L2 gateways)
// - CEX deposit wallets
// - Legit contracts (OpenSea, Uniswap, mint contracts)
// - One-off "send then move" human behavior
// - Sweeper flag requires REPETITION + AUTOMATION

import { Chain } from '@/types';
import { 
  BASE_BRIDGE_CONTRACTS, 
  EXCHANGE_WALLETS, 
  isBaseNFTPlatform,
  isCoinbaseLinkedWallet,
  isPublicBaseRelayer,
} from './base-chain-protection';
import { 
  isSafeContract, 
  isDEXRouter, 
  isNFTMarketplace,
  isDeFiProtocol,
} from './safe-contracts';
import { checkInfrastructureProtection } from './infrastructure-protection';

// ============================================
// BASE SWEEPER DETECTION CONFIGURATION
// ============================================

export interface BaseSweeperConfig {
  // Minimum number of heuristics that must be true to flag (≥2)
  minHeuristicsRequired: number;
  
  // Block distance threshold for "immediate" reaction
  maxBlocksForImmediate: number;
  
  // Minimum number of drain patterns required
  minDrainPatterns: number;
  
  // Minimum unique senders to qualify as "programmatic"
  minUniqueSenders: number;
  
  // Maximum ending balance ratio to qualify as "never accumulates"
  maxEndingBalanceRatio: number;
  
  // Gas variance threshold for "machine-consistent"
  maxGasVariancePercent: number;
  
  // Minimum repetition count across unrelated wallets
  minCrossWalletRepetition: number;
}

export const BASE_SWEEPER_CONFIG: BaseSweeperConfig = {
  minHeuristicsRequired: 2,       // ≥2 heuristics must be true
  maxBlocksForImmediate: 1,       // Within 1 block
  minDrainPatterns: 3,            // At least 3 drain cycles
  minUniqueSenders: 5,            // At least 5 different senders
  maxEndingBalanceRatio: 0.05,    // ≈0 balance = less than 5% retained
  maxGasVariancePercent: 10,      // Machine-like = <10% variance
  minCrossWalletRepetition: 3,    // Same pattern across 3+ wallets
};

// ============================================
// TRANSACTION INTERFACES
// ============================================

export interface BaseTransactionForSweeper {
  hash: string;
  from: string;
  to: string;
  value: string;
  blockNumber: number;
  timestamp: number;
  gasUsed?: number;
  gasPrice?: string;
  methodId?: string;
  isETH?: boolean;
  tokenAddress?: string;
  tokenSymbol?: string;
}

// ============================================
// SWEEPER HEURISTICS RESULT
// ============================================

export interface BaseSweeperHeuristics {
  // Heuristic 1: Incoming → outgoing within ≤1 block
  hasImmediateReaction: boolean;
  immediateReactionCount: number;
  
  // Heuristic 2: Never accumulates balance (ending ≈ 0)
  neverAccumulatesBalance: boolean;
  averageEndingBalanceRatio: number;
  
  // Heuristic 3: Programmatic destination (fixed or rotating hot wallets)
  hasProgrammaticDestination: boolean;
  uniqueDestinationCount: number;
  topDestinationRatio: number;
  
  // Heuristic 4: Gas usage is flat and machine-consistent
  hasMachineConsistentGas: boolean;
  gasUsageVariance: number;
  
  // Heuristic 5: Repeats across many unrelated senders
  hasMultipleUnrelatedSenders: boolean;
  uniqueSenderCount: number;
  
  // Heuristic 6: First action is always drain, never discretionary
  firstActionAlwaysDrain: boolean;
  
  // Summary
  heuristicsMetCount: number;
  heuristicsMet: string[];
  heuristicsFailed: string[];
}

// ============================================
// BASE SWEEPER DETECTION RESULT
// ============================================

export interface BaseSweeperDetectionResult {
  isSweeper: boolean;
  confidence: number;
  chain: 'base';
  
  // Classification
  classification: 'Active Sweeper Bot (Base)' | 'Suspected Sweeper' | 'Not a Sweeper';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  
  // Heuristics breakdown
  heuristics: BaseSweeperHeuristics;
  
  // Explanation
  explanation: string;
  
  // False positive guards that passed
  falsePositiveGuards: {
    isSelfTransfer: boolean;
    isBridge: boolean;
    isCEXDeposit: boolean;
    isLegitContract: boolean;
    isOneOffBehavior: boolean;
  };
  
  // Related data
  drainPatterns: DrainPattern[];
  relatedAddresses: string[];
}

export interface DrainPattern {
  inboundTxHash: string;
  outboundTxHash: string;
  inboundBlock: number;
  outboundBlock: number;
  blockDifference: number;
  inboundFrom: string;
  outboundTo: string;
  valueIn: string;
  valueOut: string;
  timestamp: number;
  isSameBlock: boolean;
}

// ============================================
// KNOWN BASE SWEEPER ADDRESSES
// ============================================
// These are CONFIRMED sweeper bot addresses on Base chain

export const KNOWN_BASE_SWEEPERS = new Set([
  // Confirmed sweeper from user report
  '0x7fcd4c52a0da9e18ec1d43ae50cd376c2b469e17',
]);

// ============================================
// FALSE POSITIVE EXCLUSION ADDRESSES
// ============================================

function isExcludedDestination(address: string, chain: Chain): boolean {
  const normalized = address?.toLowerCase() || '';
  if (!normalized) return false;
  
  // 1. Check bridges
  if (BASE_BRIDGE_CONTRACTS.has(normalized)) {
    return true;
  }
  
  // 2. Check CEX deposit wallets
  if (EXCHANGE_WALLETS.has(normalized)) {
    return true;
  }
  
  // 3. Check NFT platforms
  if (isBaseNFTPlatform(normalized).isPlatform) {
    return true;
  }
  
  // 4. Check Coinbase-linked wallets
  if (isCoinbaseLinkedWallet(normalized)) {
    return true;
  }
  
  // 5. Check public relayers
  if (isPublicBaseRelayer(normalized)) {
    return true;
  }
  
  // 6. Check DEX routers
  if (isDEXRouter(normalized)) {
    return true;
  }
  
  // 7. Check NFT marketplaces
  if (isNFTMarketplace(normalized)) {
    return true;
  }
  
  // 8. Check DeFi protocols
  if (isDeFiProtocol(normalized)) {
    return true;
  }
  
  // 9. Check safe contracts
  if (isSafeContract(normalized)) {
    return true;
  }
  
  // 10. Check infrastructure protection
  const infraCheck = checkInfrastructureProtection(normalized, chain);
  if (infraCheck.isProtected) {
    return true;
  }
  
  return false;
}

// ============================================
// MAIN BASE SWEEPER DETECTION FUNCTION
// ============================================

/**
 * Detect sweeper bot behavior on Base chain.
 * 
 * CRITICAL: This uses reaction-based detection instead of mempool signals.
 * Base chain has sequencer-based ordering, so we detect:
 * - Same-block or ≤1 block reaction times
 * - Pattern repetition across multiple senders
 * - Never-accumulate balance behavior
 * - Machine-consistent gas usage
 */
export function detectBaseSweeperBot(
  walletAddress: string,
  transactions: BaseTransactionForSweeper[],
  config: BaseSweeperConfig = BASE_SWEEPER_CONFIG
): BaseSweeperDetectionResult {
  const normalized = walletAddress.toLowerCase();
  
  // ============================================
  // PHASE 0: Check if known sweeper
  // ============================================
  if (KNOWN_BASE_SWEEPERS.has(normalized)) {
    return createKnownSweeperResult(normalized, transactions);
  }
  
  // ============================================
  // PHASE 1: Build transaction analysis
  // ============================================
  const inbound = transactions.filter(tx => 
    tx.to?.toLowerCase() === normalized
  ).sort((a, b) => a.blockNumber - b.blockNumber);
  
  const outbound = transactions.filter(tx => 
    tx.from?.toLowerCase() === normalized
  ).sort((a, b) => a.blockNumber - b.blockNumber);
  
  // Need sufficient data
  if (inbound.length < 3 || outbound.length < 3) {
    return createNotSweeperResult('Insufficient transaction history for analysis');
  }
  
  // ============================================
  // PHASE 2: Detect drain patterns
  // ============================================
  const drainPatterns = detectDrainPatterns(normalized, inbound, outbound, config);
  
  // ============================================
  // PHASE 3: Calculate heuristics
  // ============================================
  const heuristics = calculateHeuristics(
    normalized,
    inbound,
    outbound,
    drainPatterns,
    config
  );
  
  // ============================================
  // PHASE 4: Apply false positive guards
  // ============================================
  const falsePositiveGuards = checkFalsePositiveGuards(
    normalized,
    inbound,
    outbound,
    drainPatterns
  );
  
  // If any exclusion applies, significantly reduce confidence
  const hasExclusion = Object.values(falsePositiveGuards).some(v => v);
  
  // ============================================
  // PHASE 5: Make final determination
  // ============================================
  const { isSweeper, confidence, classification, severity, explanation } = 
    determineSweeperStatus(heuristics, drainPatterns, falsePositiveGuards, hasExclusion, config);
  
  // Collect related addresses
  const relatedAddresses = [
    ...new Set([
      ...drainPatterns.map(p => p.inboundFrom),
      ...drainPatterns.map(p => p.outboundTo),
    ])
  ].filter(a => a !== normalized);
  
  return {
    isSweeper,
    confidence,
    chain: 'base',
    classification,
    severity,
    heuristics,
    explanation,
    falsePositiveGuards,
    drainPatterns,
    relatedAddresses,
  };
}

// ============================================
// DRAIN PATTERN DETECTION
// ============================================

function detectDrainPatterns(
  walletAddress: string,
  inbound: BaseTransactionForSweeper[],
  outbound: BaseTransactionForSweeper[],
  config: BaseSweeperConfig
): DrainPattern[] {
  const patterns: DrainPattern[] = [];
  
  // For each inbound, find the nearest subsequent outbound
  for (const inTx of inbound) {
    // Find outbound transactions that occur at or after the inbound
    const candidateOutbound = outbound.filter(outTx => 
      outTx.blockNumber >= inTx.blockNumber &&
      // Must be within reasonable time (same block to +5 blocks)
      outTx.blockNumber <= inTx.blockNumber + 5
    );
    
    if (candidateOutbound.length === 0) continue;
    
    // Take the closest outbound
    const outTx = candidateOutbound[0];
    const blockDiff = outTx.blockNumber - inTx.blockNumber;
    
    // Only count as drain pattern if within threshold
    if (blockDiff <= config.maxBlocksForImmediate) {
      patterns.push({
        inboundTxHash: inTx.hash,
        outboundTxHash: outTx.hash,
        inboundBlock: inTx.blockNumber,
        outboundBlock: outTx.blockNumber,
        blockDifference: blockDiff,
        inboundFrom: inTx.from?.toLowerCase() || '',
        outboundTo: outTx.to?.toLowerCase() || '',
        valueIn: inTx.value,
        valueOut: outTx.value,
        timestamp: inTx.timestamp,
        isSameBlock: blockDiff === 0,
      });
    }
  }
  
  return patterns;
}

// ============================================
// HEURISTICS CALCULATION
// ============================================

function calculateHeuristics(
  walletAddress: string,
  inbound: BaseTransactionForSweeper[],
  outbound: BaseTransactionForSweeper[],
  drainPatterns: DrainPattern[],
  config: BaseSweeperConfig
): BaseSweeperHeuristics {
  const heuristicsMet: string[] = [];
  const heuristicsFailed: string[] = [];
  
  // ============================================
  // Heuristic 1: Immediate reaction (≤1 block)
  // ============================================
  const immediateReactionCount = drainPatterns.filter(p => 
    p.blockDifference <= config.maxBlocksForImmediate
  ).length;
  
  const hasImmediateReaction = immediateReactionCount >= config.minDrainPatterns;
  if (hasImmediateReaction) {
    heuristicsMet.push(`Immediate reaction: ${immediateReactionCount} drain patterns within ${config.maxBlocksForImmediate} block(s)`);
  } else {
    heuristicsFailed.push(`Only ${immediateReactionCount} immediate reactions (need ${config.minDrainPatterns}+)`);
  }
  
  // ============================================
  // Heuristic 2: Never accumulates balance
  // ============================================
  // Calculate the ratio of total outbound to total inbound
  const totalInboundValue = inbound.reduce((sum, tx) => 
    sum + BigInt(tx.value || '0'), BigInt(0)
  );
  const totalOutboundValue = outbound.reduce((sum, tx) => 
    sum + BigInt(tx.value || '0'), BigInt(0)
  );
  
  const endingBalanceRatio = totalInboundValue > BigInt(0)
    ? Number((totalInboundValue - totalOutboundValue) * BigInt(10000) / totalInboundValue) / 10000
    : 0;
  
  // Absolute value - sweepers drain everything
  const absRatio = Math.abs(endingBalanceRatio);
  const neverAccumulatesBalance = absRatio <= config.maxEndingBalanceRatio;
  
  if (neverAccumulatesBalance) {
    heuristicsMet.push(`Never accumulates: ${(absRatio * 100).toFixed(1)}% balance retained (threshold: ${config.maxEndingBalanceRatio * 100}%)`);
  } else {
    heuristicsFailed.push(`Retains ${(absRatio * 100).toFixed(1)}% balance (threshold: ${config.maxEndingBalanceRatio * 100}%)`);
  }
  
  // ============================================
  // Heuristic 3: Programmatic destination
  // ============================================
  const outboundDestinations = new Map<string, number>();
  for (const tx of outbound) {
    const dest = tx.to?.toLowerCase() || '';
    if (dest && dest !== walletAddress) {
      outboundDestinations.set(dest, (outboundDestinations.get(dest) || 0) + 1);
    }
  }
  
  const uniqueDestinationCount = outboundDestinations.size;
  const totalOutboundTxs = outbound.length;
  
  // Find top destination ratio
  const topDestinationCount = Math.max(...outboundDestinations.values(), 0);
  const topDestinationRatio = totalOutboundTxs > 0 
    ? topDestinationCount / totalOutboundTxs 
    : 0;
  
  // Programmatic = either fixed destination (>80% to same address) OR rotating hot wallets (few destinations)
  const hasProgrammaticDestination = 
    topDestinationRatio >= 0.8 || // Fixed destination
    (uniqueDestinationCount <= 3 && uniqueDestinationCount > 0); // Few rotating wallets
  
  if (hasProgrammaticDestination) {
    heuristicsMet.push(`Programmatic destination: ${uniqueDestinationCount} unique destination(s), top gets ${(topDestinationRatio * 100).toFixed(0)}%`);
  } else {
    heuristicsFailed.push(`${uniqueDestinationCount} destinations with ${(topDestinationRatio * 100).toFixed(0)}% to top (not programmatic)`);
  }
  
  // ============================================
  // Heuristic 4: Machine-consistent gas
  // ============================================
  const gasUsages = outbound
    .filter(tx => tx.gasUsed !== undefined && tx.gasUsed > 0)
    .map(tx => tx.gasUsed!);
  
  let gasUsageVariance = 100; // Default high variance
  if (gasUsages.length >= 3) {
    const mean = gasUsages.reduce((a, b) => a + b, 0) / gasUsages.length;
    const variance = gasUsages.reduce((sum, g) => sum + Math.pow(g - mean, 2), 0) / gasUsages.length;
    const stdDev = Math.sqrt(variance);
    gasUsageVariance = mean > 0 ? (stdDev / mean) * 100 : 100;
  }
  
  const hasMachineConsistentGas = gasUsageVariance <= config.maxGasVariancePercent;
  
  if (hasMachineConsistentGas) {
    heuristicsMet.push(`Machine-consistent gas: ${gasUsageVariance.toFixed(1)}% variance (threshold: ${config.maxGasVariancePercent}%)`);
  } else {
    heuristicsFailed.push(`Gas variance ${gasUsageVariance.toFixed(1)}% (threshold: ${config.maxGasVariancePercent}%)`);
  }
  
  // ============================================
  // Heuristic 5: Multiple unrelated senders
  // ============================================
  const uniqueSenders = new Set(
    inbound
      .map(tx => tx.from?.toLowerCase())
      .filter(from => from && from !== walletAddress)
  );
  const uniqueSenderCount = uniqueSenders.size;
  
  const hasMultipleUnrelatedSenders = uniqueSenderCount >= config.minUniqueSenders;
  
  if (hasMultipleUnrelatedSenders) {
    heuristicsMet.push(`Multiple senders: ${uniqueSenderCount} unique senders (threshold: ${config.minUniqueSenders})`);
  } else {
    heuristicsFailed.push(`Only ${uniqueSenderCount} unique senders (need ${config.minUniqueSenders}+)`);
  }
  
  // ============================================
  // Heuristic 6: First action is always drain
  // ============================================
  // For each inbound, check if the first action is an outbound (drain)
  let drainFirstCount = 0;
  let totalChecked = 0;
  
  for (const inTx of inbound) {
    // Find transactions after this inbound
    const actionsAfter = [...inbound, ...outbound]
      .filter(tx => tx.blockNumber >= inTx.blockNumber && tx.hash !== inTx.hash)
      .sort((a, b) => a.blockNumber - b.blockNumber);
    
    if (actionsAfter.length === 0) continue;
    
    const firstAction = actionsAfter[0];
    totalChecked++;
    
    // Check if first action is outbound (drain)
    if (firstAction.from?.toLowerCase() === walletAddress) {
      drainFirstCount++;
    }
  }
  
  const drainFirstRatio = totalChecked > 0 ? drainFirstCount / totalChecked : 0;
  const firstActionAlwaysDrain = drainFirstRatio >= 0.9; // 90%+ first actions are drains
  
  if (firstActionAlwaysDrain) {
    heuristicsMet.push(`First action drain: ${(drainFirstRatio * 100).toFixed(0)}% of first actions are drains`);
  } else {
    heuristicsFailed.push(`Only ${(drainFirstRatio * 100).toFixed(0)}% first actions are drains (need 90%+)`);
  }
  
  return {
    hasImmediateReaction,
    immediateReactionCount,
    neverAccumulatesBalance,
    averageEndingBalanceRatio: absRatio,
    hasProgrammaticDestination,
    uniqueDestinationCount,
    topDestinationRatio,
    hasMachineConsistentGas,
    gasUsageVariance,
    hasMultipleUnrelatedSenders,
    uniqueSenderCount,
    firstActionAlwaysDrain,
    heuristicsMetCount: heuristicsMet.length,
    heuristicsMet,
    heuristicsFailed,
  };
}

// ============================================
// FALSE POSITIVE GUARDS
// ============================================

function checkFalsePositiveGuards(
  walletAddress: string,
  inbound: BaseTransactionForSweeper[],
  outbound: BaseTransactionForSweeper[],
  drainPatterns: DrainPattern[]
): BaseSweeperDetectionResult['falsePositiveGuards'] {
  // 1. Self-transfers
  const selfTransferCount = outbound.filter(tx => 
    tx.to?.toLowerCase() === walletAddress
  ).length;
  const isSelfTransfer = selfTransferCount > outbound.length * 0.5;
  
  // 2. Bridge destinations
  const bridgeDestCount = drainPatterns.filter(p => 
    BASE_BRIDGE_CONTRACTS.has(p.outboundTo)
  ).length;
  const isBridge = bridgeDestCount > drainPatterns.length * 0.5;
  
  // 3. CEX deposit destinations
  const cexDestCount = drainPatterns.filter(p =>
    EXCHANGE_WALLETS.has(p.outboundTo)
  ).length;
  const isCEXDeposit = cexDestCount > drainPatterns.length * 0.5;
  
  // 4. Legitimate contract destinations
  const legitDestCount = drainPatterns.filter(p =>
    isExcludedDestination(p.outboundTo, 'base')
  ).length;
  const isLegitContract = legitDestCount > drainPatterns.length * 0.5;
  
  // 5. One-off behavior (not enough repetition)
  const isOneOffBehavior = drainPatterns.length < 3;
  
  return {
    isSelfTransfer,
    isBridge,
    isCEXDeposit,
    isLegitContract,
    isOneOffBehavior,
  };
}

// ============================================
// FINAL DETERMINATION
// ============================================

function determineSweeperStatus(
  heuristics: BaseSweeperHeuristics,
  drainPatterns: DrainPattern[],
  falsePositiveGuards: BaseSweeperDetectionResult['falsePositiveGuards'],
  hasExclusion: boolean,
  config: BaseSweeperConfig
): {
  isSweeper: boolean;
  confidence: number;
  classification: BaseSweeperDetectionResult['classification'];
  severity: BaseSweeperDetectionResult['severity'];
  explanation: string;
} {
  const heuristicsMetCount = heuristics.heuristicsMetCount;
  
  // Count strong heuristics (the most indicative ones)
  const strongHeuristics = [
    heuristics.hasImmediateReaction,
    heuristics.neverAccumulatesBalance,
    heuristics.hasMultipleUnrelatedSenders,
    heuristics.firstActionAlwaysDrain,
  ].filter(Boolean).length;
  
  // ============================================
  // EXCLUSION CHECK: Apply false positive guards
  // ============================================
  if (hasExclusion) {
    const excludedReasons: string[] = [];
    if (falsePositiveGuards.isSelfTransfer) excludedReasons.push('self-transfers');
    if (falsePositiveGuards.isBridge) excludedReasons.push('bridge activity');
    if (falsePositiveGuards.isCEXDeposit) excludedReasons.push('CEX deposits');
    if (falsePositiveGuards.isLegitContract) excludedReasons.push('legitimate contracts');
    if (falsePositiveGuards.isOneOffBehavior) excludedReasons.push('insufficient repetition');
    
    return {
      isSweeper: false,
      confidence: 0,
      classification: 'Not a Sweeper',
      severity: 'LOW',
      explanation: `Not a sweeper: ${excludedReasons.join(', ')}`,
    };
  }
  
  // ============================================
  // SWEEPER DETECTION THRESHOLDS
  // ============================================
  
  // CONFIRMED SWEEPER: ≥4 heuristics met including ≥3 strong ones
  if (heuristicsMetCount >= 4 && strongHeuristics >= 3 && drainPatterns.length >= config.minDrainPatterns) {
    return {
      isSweeper: true,
      confidence: 95,
      classification: 'Active Sweeper Bot (Base)',
      severity: 'CRITICAL',
      explanation: `ACTIVE SWEEPER BOT: ${heuristicsMetCount}/6 heuristics met (${strongHeuristics} strong). ` +
        `${drainPatterns.length} drain patterns detected with ${heuristics.immediateReactionCount} immediate reactions. ` +
        `Funds are programmatically forwarded immediately after receipt, consistent with post-compromise sweeper infrastructure.`,
    };
  }
  
  // SUSPECTED SWEEPER: ≥2 heuristics met (minimum threshold)
  if (heuristicsMetCount >= config.minHeuristicsRequired && drainPatterns.length >= 2) {
    const confidence = 50 + (heuristicsMetCount * 10);
    return {
      isSweeper: true,
      confidence: Math.min(85, confidence),
      classification: 'Suspected Sweeper',
      severity: 'HIGH',
      explanation: `Suspected sweeper: ${heuristicsMetCount}/6 heuristics met. ` +
        `${drainPatterns.length} drain patterns. ${heuristics.heuristicsMet.join('. ')}`,
    };
  }
  
  // NOT A SWEEPER
  return {
    isSweeper: false,
    confidence: 0,
    classification: 'Not a Sweeper',
    severity: 'LOW',
    explanation: `Not a sweeper: Only ${heuristicsMetCount}/${config.minHeuristicsRequired} required heuristics met. ` +
      `Failed: ${heuristics.heuristicsFailed.slice(0, 3).join('; ')}`,
  };
}

// ============================================
// HELPER: Create known sweeper result
// ============================================

function createKnownSweeperResult(
  address: string,
  transactions: BaseTransactionForSweeper[]
): BaseSweeperDetectionResult {
  const inbound = transactions.filter(tx => tx.to?.toLowerCase() === address);
  const outbound = transactions.filter(tx => tx.from?.toLowerCase() === address);
  
  return {
    isSweeper: true,
    confidence: 100,
    chain: 'base',
    classification: 'Active Sweeper Bot (Base)',
    severity: 'CRITICAL',
    heuristics: {
      hasImmediateReaction: true,
      immediateReactionCount: inbound.length,
      neverAccumulatesBalance: true,
      averageEndingBalanceRatio: 0,
      hasProgrammaticDestination: true,
      uniqueDestinationCount: new Set(outbound.map(tx => tx.to?.toLowerCase())).size,
      topDestinationRatio: 1,
      hasMachineConsistentGas: true,
      gasUsageVariance: 0,
      hasMultipleUnrelatedSenders: true,
      uniqueSenderCount: new Set(inbound.map(tx => tx.from?.toLowerCase())).size,
      firstActionAlwaysDrain: true,
      heuristicsMetCount: 6,
      heuristicsMet: ['KNOWN SWEEPER ADDRESS IN DATABASE'],
      heuristicsFailed: [],
    },
    explanation: `CONFIRMED SWEEPER BOT: This wallet (${address.slice(0, 10)}...) is in the verified sweeper database for Base chain. ` +
      `Wallet shows automated sweep behavior on Base. Funds are programmatically forwarded immediately after receipt, ` +
      `consistent with post-compromise sweeper infrastructure.`,
    falsePositiveGuards: {
      isSelfTransfer: false,
      isBridge: false,
      isCEXDeposit: false,
      isLegitContract: false,
      isOneOffBehavior: false,
    },
    drainPatterns: [],
    relatedAddresses: [
      ...new Set([
        ...inbound.map(tx => tx.from?.toLowerCase() || ''),
        ...outbound.map(tx => tx.to?.toLowerCase() || ''),
      ])
    ].filter(a => a && a !== address),
  };
}

// ============================================
// HELPER: Create not-sweeper result
// ============================================

function createNotSweeperResult(reason: string): BaseSweeperDetectionResult {
  return {
    isSweeper: false,
    confidence: 0,
    chain: 'base',
    classification: 'Not a Sweeper',
    severity: 'LOW',
    heuristics: {
      hasImmediateReaction: false,
      immediateReactionCount: 0,
      neverAccumulatesBalance: false,
      averageEndingBalanceRatio: 1,
      hasProgrammaticDestination: false,
      uniqueDestinationCount: 0,
      topDestinationRatio: 0,
      hasMachineConsistentGas: false,
      gasUsageVariance: 100,
      hasMultipleUnrelatedSenders: false,
      uniqueSenderCount: 0,
      firstActionAlwaysDrain: false,
      heuristicsMetCount: 0,
      heuristicsMet: [],
      heuristicsFailed: [reason],
    },
    explanation: reason,
    falsePositiveGuards: {
      isSelfTransfer: false,
      isBridge: false,
      isCEXDeposit: false,
      isLegitContract: false,
      isOneOffBehavior: true,
    },
    drainPatterns: [],
    relatedAddresses: [],
  };
}

// ============================================
// CHAIN-AWARE WRAPPER
// ============================================

/**
 * Chain-aware sweeper detection.
 * On Base: Uses reaction-based detection (no mempool signals)
 * On Ethereum: Uses standard mempool-based detection
 */
export function detectSweeperBotChainAware(
  walletAddress: string,
  chain: Chain,
  transactions: BaseTransactionForSweeper[],
  config?: Partial<BaseSweeperConfig>
): BaseSweeperDetectionResult | null {
  // Only handle Base chain in this module
  if (chain !== 'base') {
    return null; // Let standard detection handle other chains
  }
  
  const mergedConfig = { ...BASE_SWEEPER_CONFIG, ...config };
  return detectBaseSweeperBot(walletAddress, transactions, mergedConfig);
}

// ============================================
// EXPORTS
// ============================================

export {
  detectBaseSweeperBot as default,
  isExcludedDestination,
};
