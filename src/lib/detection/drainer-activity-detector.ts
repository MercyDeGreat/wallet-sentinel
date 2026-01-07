// ============================================
// DRAINER ACTIVITY DETECTOR - HARD OVERRIDE SYSTEM
// ============================================
// This module implements the MANDATORY HARD OVERRIDE rule for wallet drainer detection.
//
// SECURITY RULE (2024-01 CRITICAL FIX):
// If ANY of the following drainer signals are detected within the last 90 days,
// the wallet MUST be classified as ACTIVE_COMPROMISE_DRAINER.
// This classification OVERRIDES:
//   - "Safe"
//   - "Previously Compromised (Resolved)"
//   - Any historical resolution state
//
// RATIONALE: FALSE NEGATIVES ARE WORSE THAN FALSE POSITIVES.
// An active drainer being labeled as "Safe" is a critical security failure.
//
// SIGNALS THAT TRIGGER HARD OVERRIDE:
// 1. Immediate outbound transfers within seconds of inbound funds
// 2. Gas-funded third-party transaction execution
// 3. Token approvals followed by rapid balance drain
// 4. ERC20 / ERC721 / ERC1155 sweep patterns
// 5. Repeated drain routing to known aggregation or laundering hubs
// 6. Multi-token zeroing behavior

import { Chain, CompromiseReasonCode } from '@/types';
import type { 
  DrainerOverrideResult, 
  DrainerBehaviorDetection, 
  DrainerActivityRecency,
  DrainerActivityRecencyInfo,
  DrainerBehaviorSignal,
} from '@/types';
import { isMaliciousAddress, isDrainerRecipient } from './malicious-database';
import { isKnownDrainer, getDrainerType } from './drainer-addresses';
import { isSafeContract, isNFTMarketplace, isDeFiProtocol } from './safe-contracts';

// ============================================
// CONFIGURATION CONSTANTS
// ============================================

// Recency thresholds in days
const RECENCY_CRITICAL_DAYS = 1;    // <24h = CRITICAL
const RECENCY_HIGH_DAYS = 7;        // <7d = HIGH
const RECENCY_MEDIUM_DAYS = 30;     // <30d = MEDIUM
const RECENCY_LOW_DAYS = 90;        // <90d = LOW (still ACTIVE)
// ≥90d = HISTORICAL (can be considered "Previously Compromised")

// Timing thresholds in seconds
const IMMEDIATE_OUTBOUND_THRESHOLD_SECONDS = 60;     // 1 minute
const RAPID_DRAIN_THRESHOLD_SECONDS = 300;           // 5 minutes
const SWEEP_WINDOW_BLOCKS = 3;                        // Within 3 blocks

// Confidence multipliers based on recency
const RECENCY_CONFIDENCE_MULTIPLIERS: Record<DrainerActivityRecency, number> = {
  'CRITICAL': 1.0,
  'HIGH': 0.9,
  'MEDIUM': 0.7,
  'LOW': 0.5,
  'HISTORICAL': 0.2,
  'NONE': 0,
};

// ============================================
// TRANSACTION INTERFACES
// ============================================

export interface TransactionForDrainerAnalysis {
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
  gasPrice?: string;
}

export interface TokenTransferForDrainerAnalysis {
  from: string;
  to: string;
  value: string;
  hash: string;
  timestamp: number;
  tokenSymbol: string;
  tokenAddress: string;
  blockNumber?: number;
  tokenType?: 'ERC20' | 'ERC721' | 'ERC1155';
}

export interface ApprovalForDrainerAnalysis {
  token: string;
  tokenSymbol: string;
  spender: string;
  owner: string;
  amount: string;
  isUnlimited: boolean;
  timestamp: number;
  transactionHash: string;
  blockNumber: number;
  wasRevoked?: boolean;
  revokedTimestamp?: number;
}

// ============================================
// ADDRESS NORMALIZATION UTILITY
// ============================================
// Ensures lowercase / checksum duplicates resolve to ONE entity

export function normalizeAddress(address: string | undefined | null): string {
  if (!address) return '';
  return address.toLowerCase().trim();
}

export function normalizeAddresses(addresses: (string | undefined | null)[]): string[] {
  return addresses
    .map(normalizeAddress)
    .filter((a): a is string => a !== '');
}

export function areAddressesEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  return normalizeAddress(a) === normalizeAddress(b);
}

// ============================================
// KNOWN AGGREGATION / LAUNDERING HUBS
// ============================================
// These are addresses known to be used for aggregating drained funds

const KNOWN_AGGREGATION_HUBS = new Set([
  // Tornado Cash related (historical, service is down but addresses still flagged)
  '0x722122df12d4e14e13ac3b6895a86e84145b6967',
  '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b',
  '0xd96f2b1c14db8458374d9aca76e26c3d18364307',
  
  // Known drainer aggregation wallets (add verified addresses here)
  // These should be regularly updated based on on-chain analysis
]);

// ============================================
// MAIN DRAINER ACTIVITY DETECTOR
// ============================================

/**
 * Analyze wallet for active drainer behavior and determine if HARD OVERRIDE should apply.
 * 
 * CRITICAL: If this function returns `shouldOverride: true`, the wallet MUST be
 * classified as ACTIVE_COMPROMISE_DRAINER regardless of any other analysis.
 */
export function detectDrainerActivity(
  walletAddress: string,
  chain: Chain,
  transactions: TransactionForDrainerAnalysis[],
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  approvals: ApprovalForDrainerAnalysis[],
  currentTimestamp: number = Math.floor(Date.now() / 1000)
): DrainerOverrideResult {
  const normalized = normalizeAddress(walletAddress);
  const detectedSignals: DrainerBehaviorDetection[] = [];
  const downgradeBlockers: string[] = [];
  
  // ============================================
  // SIGNAL 1: Immediate outbound transfers after inbound
  // ============================================
  const immediateOutboundSignals = detectImmediateOutboundTransfers(
    normalized,
    transactions,
    tokenTransfers,
    currentTimestamp
  );
  detectedSignals.push(...immediateOutboundSignals);
  
  // ============================================
  // SIGNAL 2: Gas-funded third-party execution
  // ============================================
  const gasFundedSignals = detectGasFundedExecution(
    normalized,
    transactions,
    currentTimestamp
  );
  detectedSignals.push(...gasFundedSignals);
  
  // ============================================
  // SIGNAL 3: Approval followed by rapid drain
  // ============================================
  const approvalDrainSignals = detectApprovalRapidDrain(
    normalized,
    chain,
    approvals,
    tokenTransfers,
    currentTimestamp
  );
  detectedSignals.push(...approvalDrainSignals);
  
  // ============================================
  // SIGNAL 4: ERC20/721/1155 sweep patterns
  // ============================================
  const sweepSignals = detectSweepPatterns(
    normalized,
    tokenTransfers,
    currentTimestamp
  );
  detectedSignals.push(...sweepSignals);
  
  // ============================================
  // SIGNAL 5: Drain to aggregation/laundering hubs
  // ============================================
  const aggregationSignals = detectDrainToAggregationHub(
    normalized,
    transactions,
    tokenTransfers,
    currentTimestamp
  );
  detectedSignals.push(...aggregationSignals);
  
  // ============================================
  // SIGNAL 6: Multi-token zeroing behavior
  // ============================================
  const multiTokenZeroingSignals = detectMultiTokenZeroing(
    normalized,
    tokenTransfers,
    currentTimestamp
  );
  detectedSignals.push(...multiTokenZeroingSignals);
  
  // ============================================
  // CALCULATE RECENCY
  // ============================================
  const recency = calculateRecency(detectedSignals, currentTimestamp);
  
  // ============================================
  // DETERMINE OVERRIDE
  // ============================================
  // If ANY signal detected within 90 days, MUST override
  const shouldOverride = detectedSignals.length > 0 && recency.isActive;
  
  // Calculate overall confidence (weighted by recency)
  const baseConfidence = detectedSignals.length > 0
    ? Math.min(100, detectedSignals.reduce((sum, s) => sum + s.confidence, 0) / detectedSignals.length)
    : 0;
  const confidence = Math.round(baseConfidence * recency.confidenceMultiplier);
  
  // ============================================
  // DETERMINE DOWNGRADE BLOCKERS
  // ============================================
  // These conditions MUST ALL be true to allow downgrade from ACTIVE to HISTORICAL
  
  if (detectedSignals.length > 0) {
    downgradeBlockers.push(`${detectedSignals.length} drainer signal(s) detected`);
  }
  
  if (recency.isActive) {
    downgradeBlockers.push(`Last activity: ${recency.daysSinceLastActivity} days ago (must be ≥90 days)`);
  }
  
  // Check for active approvals
  const activeApprovals = approvals.filter(a => !a.wasRevoked && a.isUnlimited);
  if (activeApprovals.length > 0) {
    downgradeBlockers.push(`${activeApprovals.length} active unlimited approval(s) exist`);
  }
  
  // Check for known drainer interaction
  const drainerInteractions = transactions.filter(tx => {
    const to = normalizeAddress(tx.to);
    return isKnownDrainer(to) || isMaliciousAddress(to, chain) !== null;
  });
  if (drainerInteractions.length > 0) {
    downgradeBlockers.push(`Interacted with ${drainerInteractions.length} known drainer address(es)`);
  }
  
  // ============================================
  // GENERATE OVERRIDE REASON
  // ============================================
  let overrideReason = '';
  if (shouldOverride) {
    const signalTypes = [...new Set(detectedSignals.map(s => s.signal))];
    overrideReason = `ACTIVE DRAINER DETECTED: ${signalTypes.length} signal type(s) within ${recency.daysSinceLastActivity} days. ` +
      `Signals: ${signalTypes.join(', ')}. ` +
      `This wallet MUST be classified as ACTIVE_COMPROMISE_DRAINER.`;
  } else if (detectedSignals.length > 0 && !recency.isActive) {
    overrideReason = `Historical drainer activity detected (${recency.daysSinceLastActivity} days ago). ` +
      `May be classified as PREVIOUSLY_COMPROMISED if all other conditions are met.`;
  } else {
    overrideReason = 'No drainer activity signals detected.';
  }
  
  return {
    shouldOverride,
    detectedSignals,
    recency,
    confidence,
    canEverBeSafe: detectedSignals.length === 0,
    canBePreviouslyCompromised: detectedSignals.length > 0 && !recency.isActive && downgradeBlockers.length <= 1,
    overrideReason,
    downgradeBlockers,
  };
}

// ============================================
// SIGNAL DETECTION FUNCTIONS
// ============================================

/**
 * SIGNAL 1: Detect immediate outbound transfers within seconds of inbound funds.
 * Classic sweeper bot / drainer behavior.
 */
function detectImmediateOutboundTransfers(
  walletAddress: string,
  transactions: TransactionForDrainerAnalysis[],
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  currentTimestamp: number
): DrainerBehaviorDetection[] {
  const signals: DrainerBehaviorDetection[] = [];
  const normalized = normalizeAddress(walletAddress);
  
  // Find inbound transactions
  const inbound = transactions.filter(tx => 
    normalizeAddress(tx.to) === normalized && 
    BigInt(tx.value || '0') > BigInt(0)
  );
  
  // Find outbound transactions
  const outbound = transactions.filter(tx => 
    normalizeAddress(tx.from) === normalized
  );
  
  for (const inTx of inbound) {
    // Find outbound within threshold
    const rapidOutbound = outbound.find(outTx => {
      const timeDiff = outTx.timestamp - inTx.timestamp;
      return timeDiff > 0 && timeDiff <= IMMEDIATE_OUTBOUND_THRESHOLD_SECONDS;
    });
    
    if (rapidOutbound) {
      // Check if outbound destination is safe (exchange, protocol, etc.)
      const destNormalized = normalizeAddress(rapidOutbound.to);
      if (isSafeContract(destNormalized) || isNFTMarketplace(destNormalized) || isDeFiProtocol(destNormalized)) {
        // Safe destination - likely legitimate activity
        continue;
      }
      
      // Check recency
      const daysSince = (currentTimestamp - rapidOutbound.timestamp) / (24 * 60 * 60);
      if (daysSince <= RECENCY_LOW_DAYS) {
        signals.push({
          signal: 'IMMEDIATE_OUTBOUND_TRANSFER',
          detectedAt: new Date(rapidOutbound.timestamp * 1000).toISOString(),
          txHash: rapidOutbound.hash,
          confidence: 85,
          details: `Outbound transfer ${Math.round(rapidOutbound.timestamp - inTx.timestamp)}s after inbound. ` +
            `Destination: ${destNormalized.slice(0, 10)}...`,
          relatedAddresses: [destNormalized],
        });
      }
    }
  }
  
  // Also check token transfers
  const tokenInbound = tokenTransfers.filter(t => 
    normalizeAddress(t.to) === normalized
  );
  const tokenOutbound = tokenTransfers.filter(t => 
    normalizeAddress(t.from) === normalized
  );
  
  for (const inTx of tokenInbound) {
    const rapidOutbound = tokenOutbound.find(outTx => {
      const timeDiff = outTx.timestamp - inTx.timestamp;
      return timeDiff > 0 && timeDiff <= IMMEDIATE_OUTBOUND_THRESHOLD_SECONDS;
    });
    
    if (rapidOutbound) {
      const destNormalized = normalizeAddress(rapidOutbound.to);
      if (isSafeContract(destNormalized) || isNFTMarketplace(destNormalized) || isDeFiProtocol(destNormalized)) {
        continue;
      }
      
      const daysSince = (currentTimestamp - rapidOutbound.timestamp) / (24 * 60 * 60);
      if (daysSince <= RECENCY_LOW_DAYS) {
        signals.push({
          signal: 'IMMEDIATE_OUTBOUND_TRANSFER',
          detectedAt: new Date(rapidOutbound.timestamp * 1000).toISOString(),
          txHash: rapidOutbound.hash,
          confidence: 80,
          details: `Token ${rapidOutbound.tokenSymbol} transferred out ${Math.round(rapidOutbound.timestamp - inTx.timestamp)}s after receiving.`,
          relatedAddresses: [destNormalized],
        });
      }
    }
  }
  
  return signals;
}

/**
 * SIGNAL 2: Detect gas-funded third-party transaction execution.
 * When wallet receives gas and immediately executes transactions.
 */
function detectGasFundedExecution(
  walletAddress: string,
  transactions: TransactionForDrainerAnalysis[],
  currentTimestamp: number
): DrainerBehaviorDetection[] {
  const signals: DrainerBehaviorDetection[] = [];
  const normalized = normalizeAddress(walletAddress);
  
  // Find small ETH inflows that could be gas funding
  const potentialGasFunding = transactions.filter(tx => {
    const value = BigInt(tx.value || '0');
    // Small amounts (< 0.1 ETH) could be gas funding
    return normalizeAddress(tx.to) === normalized && 
           value > BigInt(0) && 
           value < BigInt('100000000000000000'); // 0.1 ETH
  });
  
  // Find subsequent outbound transactions
  const outbound = transactions.filter(tx => 
    normalizeAddress(tx.from) === normalized
  );
  
  for (const gasTx of potentialGasFunding) {
    // Look for multiple outbound transactions shortly after
    const subsequentTxs = outbound.filter(tx => {
      const timeDiff = tx.timestamp - gasTx.timestamp;
      return timeDiff > 0 && timeDiff <= RAPID_DRAIN_THRESHOLD_SECONDS;
    });
    
    // If 3+ outbound transactions after gas funding, suspicious
    if (subsequentTxs.length >= 3) {
      const daysSince = (currentTimestamp - gasTx.timestamp) / (24 * 60 * 60);
      if (daysSince <= RECENCY_LOW_DAYS) {
        signals.push({
          signal: 'GAS_FUNDED_EXECUTION',
          detectedAt: new Date(gasTx.timestamp * 1000).toISOString(),
          txHash: gasTx.hash,
          confidence: 75,
          details: `Received small ETH (potential gas funding), followed by ${subsequentTxs.length} outbound transactions within 5 minutes.`,
          relatedAddresses: normalizeAddresses(subsequentTxs.map(tx => tx.to)),
        });
      }
    }
  }
  
  return signals;
}

/**
 * SIGNAL 3: Detect approval followed by rapid balance drain.
 */
function detectApprovalRapidDrain(
  walletAddress: string,
  chain: Chain,
  approvals: ApprovalForDrainerAnalysis[],
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  currentTimestamp: number
): DrainerBehaviorDetection[] {
  const signals: DrainerBehaviorDetection[] = [];
  const normalized = normalizeAddress(walletAddress);
  
  for (const approval of approvals) {
    const spender = normalizeAddress(approval.spender);
    
    // Skip approvals to safe contracts
    if (isSafeContract(spender) || isDeFiProtocol(spender) || isNFTMarketplace(spender)) {
      continue;
    }
    
    // Check if spender is known malicious
    const isMaliciousSpender = isMaliciousAddress(spender, chain) !== null || 
                               isKnownDrainer(spender) ||
                               isDrainerRecipient(spender);
    
    // Find token transfers of the approved token after approval
    const tokenAddress = normalizeAddress(approval.token);
    const drainsAfterApproval = tokenTransfers.filter(t => {
      const from = normalizeAddress(t.from);
      const transferToken = normalizeAddress(t.tokenAddress);
      const timeDiff = t.timestamp - approval.timestamp;
      
      return from === normalized &&
             transferToken === tokenAddress &&
             timeDiff > 0 &&
             timeDiff <= RAPID_DRAIN_THRESHOLD_SECONDS;
    });
    
    if (drainsAfterApproval.length > 0) {
      const daysSince = (currentTimestamp - approval.timestamp) / (24 * 60 * 60);
      if (daysSince <= RECENCY_LOW_DAYS) {
        signals.push({
          signal: 'APPROVAL_RAPID_DRAIN',
          detectedAt: new Date(approval.timestamp * 1000).toISOString(),
          txHash: approval.transactionHash,
          confidence: isMaliciousSpender ? 95 : 80,
          details: `Approval for ${approval.tokenSymbol} to ${spender.slice(0, 10)}... ` +
            `followed by ${drainsAfterApproval.length} drain(s) within 5 minutes.` +
            (isMaliciousSpender ? ' Spender is KNOWN MALICIOUS.' : ''),
          relatedAddresses: [spender, ...normalizeAddresses(drainsAfterApproval.map(d => d.to))],
        });
      }
    }
  }
  
  return signals;
}

/**
 * SIGNAL 4: Detect ERC20/721/1155 sweep patterns.
 */
function detectSweepPatterns(
  walletAddress: string,
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  currentTimestamp: number
): DrainerBehaviorDetection[] {
  const signals: DrainerBehaviorDetection[] = [];
  const normalized = normalizeAddress(walletAddress);
  
  // Group outbound transfers by block
  const outbound = tokenTransfers.filter(t => normalizeAddress(t.from) === normalized);
  const byBlock = new Map<number, TokenTransferForDrainerAnalysis[]>();
  
  for (const t of outbound) {
    const block = t.blockNumber || 0;
    if (!byBlock.has(block)) {
      byBlock.set(block, []);
    }
    byBlock.get(block)!.push(t);
  }
  
  // Sort blocks
  const sortedBlocks = [...byBlock.keys()].sort((a, b) => a - b);
  
  // Look for sweep within SWEEP_WINDOW_BLOCKS
  for (let i = 0; i < sortedBlocks.length; i++) {
    const startBlock = sortedBlocks[i];
    const endBlockIndex = sortedBlocks.findIndex(b => b > startBlock + SWEEP_WINDOW_BLOCKS);
    const endIndex = endBlockIndex === -1 ? sortedBlocks.length : endBlockIndex;
    
    // Collect all transfers in window
    const windowTransfers: TokenTransferForDrainerAnalysis[] = [];
    for (let j = i; j < endIndex; j++) {
      windowTransfers.push(...(byBlock.get(sortedBlocks[j]) || []));
    }
    
    // Check for sweep pattern: multiple different tokens to same/few destinations
    const uniqueTokens = new Set(windowTransfers.map(t => normalizeAddress(t.tokenAddress)));
    const destinations = new Set(windowTransfers.map(t => normalizeAddress(t.to)));
    
    if (uniqueTokens.size >= 2 && destinations.size <= 2 && windowTransfers.length >= 2) {
      // Check token types
      const erc20Count = windowTransfers.filter(t => t.tokenType === 'ERC20').length;
      const erc721Count = windowTransfers.filter(t => t.tokenType === 'ERC721').length;
      const erc1155Count = windowTransfers.filter(t => t.tokenType === 'ERC1155').length;
      
      const latestTimestamp = Math.max(...windowTransfers.map(t => t.timestamp));
      const daysSince = (currentTimestamp - latestTimestamp) / (24 * 60 * 60);
      
      if (daysSince <= RECENCY_LOW_DAYS) {
        let signal: DrainerBehaviorSignal = 'ERC20_SWEEP_PATTERN';
        if (erc721Count > 0) signal = 'ERC721_SWEEP_PATTERN';
        if (erc1155Count > 0) signal = 'ERC1155_SWEEP_PATTERN';
        
        signals.push({
          signal,
          detectedAt: new Date(latestTimestamp * 1000).toISOString(),
          txHash: windowTransfers[0].hash,
          confidence: 90,
          details: `${uniqueTokens.size} tokens swept to ${destinations.size} address(es) within ${SWEEP_WINDOW_BLOCKS} blocks. ` +
            `Types: ERC20=${erc20Count}, ERC721=${erc721Count}, ERC1155=${erc1155Count}.`,
          relatedAddresses: [...destinations],
        });
      }
    }
  }
  
  return signals;
}

/**
 * SIGNAL 5: Detect drain routing to known aggregation/laundering hubs.
 */
function detectDrainToAggregationHub(
  walletAddress: string,
  transactions: TransactionForDrainerAnalysis[],
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  currentTimestamp: number
): DrainerBehaviorDetection[] {
  const signals: DrainerBehaviorDetection[] = [];
  const normalized = normalizeAddress(walletAddress);
  
  // Check transactions
  for (const tx of transactions) {
    if (normalizeAddress(tx.from) !== normalized) continue;
    
    const dest = normalizeAddress(tx.to);
    if (KNOWN_AGGREGATION_HUBS.has(dest)) {
      const daysSince = (currentTimestamp - tx.timestamp) / (24 * 60 * 60);
      if (daysSince <= RECENCY_LOW_DAYS) {
        signals.push({
          signal: 'DRAIN_TO_AGGREGATION_HUB',
          detectedAt: new Date(tx.timestamp * 1000).toISOString(),
          txHash: tx.hash,
          confidence: 95,
          details: `Funds sent to known aggregation/laundering hub: ${dest.slice(0, 10)}...`,
          relatedAddresses: [dest],
        });
      }
    }
  }
  
  // Check token transfers
  for (const t of tokenTransfers) {
    if (normalizeAddress(t.from) !== normalized) continue;
    
    const dest = normalizeAddress(t.to);
    if (KNOWN_AGGREGATION_HUBS.has(dest)) {
      const daysSince = (currentTimestamp - t.timestamp) / (24 * 60 * 60);
      if (daysSince <= RECENCY_LOW_DAYS) {
        signals.push({
          signal: 'DRAIN_TO_AGGREGATION_HUB',
          detectedAt: new Date(t.timestamp * 1000).toISOString(),
          txHash: t.hash,
          confidence: 95,
          details: `Token ${t.tokenSymbol} sent to known aggregation/laundering hub: ${dest.slice(0, 10)}...`,
          relatedAddresses: [dest],
        });
      }
    }
  }
  
  return signals;
}

/**
 * SIGNAL 6: Detect multi-token zeroing behavior.
 * When multiple token balances are zeroed rapidly.
 */
function detectMultiTokenZeroing(
  walletAddress: string,
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  currentTimestamp: number
): DrainerBehaviorDetection[] {
  const signals: DrainerBehaviorDetection[] = [];
  const normalized = normalizeAddress(walletAddress);
  
  // Group outbound transfers by time window (30 minutes)
  const WINDOW_SECONDS = 30 * 60;
  const outbound = tokenTransfers
    .filter(t => normalizeAddress(t.from) === normalized)
    .sort((a, b) => a.timestamp - b.timestamp);
  
  if (outbound.length < 3) return signals;
  
  // Find windows with multiple different tokens being drained
  for (let i = 0; i < outbound.length; i++) {
    const windowStart = outbound[i].timestamp;
    const windowEnd = windowStart + WINDOW_SECONDS;
    
    const windowTransfers = outbound.filter(t => 
      t.timestamp >= windowStart && t.timestamp <= windowEnd
    );
    
    const uniqueTokens = new Set(windowTransfers.map(t => normalizeAddress(t.tokenAddress)));
    
    // If 3+ different tokens drained in 30 minutes
    if (uniqueTokens.size >= 3) {
      const daysSince = (currentTimestamp - windowStart) / (24 * 60 * 60);
      if (daysSince <= RECENCY_LOW_DAYS) {
        signals.push({
          signal: 'MULTI_TOKEN_ZEROING',
          detectedAt: new Date(windowStart * 1000).toISOString(),
          txHash: windowTransfers[0].hash,
          confidence: 85,
          details: `${uniqueTokens.size} different tokens drained within 30 minutes. Classic drainer pattern.`,
          relatedAddresses: normalizeAddresses(windowTransfers.map(t => t.to)),
        });
        
        // Skip ahead to avoid duplicate signals
        i = outbound.findIndex(t => t.timestamp > windowEnd) - 1;
        if (i < 0) break;
      }
    }
  }
  
  return signals;
}

// ============================================
// RECENCY CALCULATION
// ============================================

function calculateRecency(
  signals: DrainerBehaviorDetection[],
  currentTimestamp: number
): DrainerActivityRecencyInfo {
  if (signals.length === 0) {
    return {
      recency: 'NONE',
      daysSinceLastActivity: Infinity,
      isActive: false,
      confidenceMultiplier: 0,
    };
  }
  
  // Find most recent signal
  const timestamps = signals.map(s => new Date(s.detectedAt).getTime() / 1000);
  const mostRecent = Math.max(...timestamps);
  const daysSince = (currentTimestamp - mostRecent) / (24 * 60 * 60);
  
  // Find the signal with the most recent timestamp
  const mostRecentSignal = signals.find(s => 
    new Date(s.detectedAt).getTime() / 1000 === mostRecent
  );
  
  let recency: DrainerActivityRecency;
  let isActive = true;
  
  if (daysSince < RECENCY_CRITICAL_DAYS) {
    recency = 'CRITICAL';
  } else if (daysSince < RECENCY_HIGH_DAYS) {
    recency = 'HIGH';
  } else if (daysSince < RECENCY_MEDIUM_DAYS) {
    recency = 'MEDIUM';
  } else if (daysSince < RECENCY_LOW_DAYS) {
    recency = 'LOW';
  } else {
    recency = 'HISTORICAL';
    isActive = false;
  }
  
  return {
    recency,
    daysSinceLastActivity: Math.floor(daysSince),
    lastActivityTimestamp: mostRecentSignal?.detectedAt,
    lastActivityTxHash: mostRecentSignal?.txHash,
    isActive,
    confidenceMultiplier: RECENCY_CONFIDENCE_MULTIPLIERS[recency],
  };
}

// ============================================
// ADDITIONAL EXPORTS (functions are already exported inline)
// ============================================
// Note: detectDrainerActivity, calculateRecency are exported inline where defined
// These are constant exports only

export {
  RECENCY_CRITICAL_DAYS,
  RECENCY_HIGH_DAYS,
  RECENCY_MEDIUM_DAYS,
  RECENCY_LOW_DAYS,
  KNOWN_AGGREGATION_HUBS,
};

