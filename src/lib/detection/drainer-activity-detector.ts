// ============================================
// DRAINER ACTIVITY DETECTOR - STRICT CRITERIA SYSTEM
// ============================================
// CRITICAL FALSE POSITIVE FIX (2024-01):
// 
// This module has been COMPLETELY REFACTORED to eliminate false positives.
// The previous version flagged:
//   - 1inch, OpenSea, Aztec
//   - Relayers/routers
//   - Self-transfers
//   - Active wallets (deployers, traders)
//   - Treeverse deployer
//
// NEW RULES:
// 1. Context classification MUST run BEFORE drainer detection
// 2. Speed-only heuristics are REMOVED as primary evidence
// 3. A wallet is ONLY flagged as a drainer if ALL conditions are met:
//    - Funds from MULTIPLE unrelated victims
//    - Evidence of approval/signer compromise
//    - Outflows to consolidation/laundering patterns
//    - NO interaction with DEX/NFT/legitimate protocols
// 4. Deployer wallets are PROTECTED
// 5. False positives are MORE DAMAGING than missed low-confidence drainers

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
import { 
  isSafeContract, 
  isNFTMarketplace, 
  isDeFiProtocol,
  isDEXRouter,
  isInfrastructureContract,
} from './safe-contracts';
import {
  classifyWalletContext,
  isTransactionToSafeDestination,
  isSelfTransfer,
  ContextClassificationResult,
} from './context-classifier';

// ============================================
// CONFIGURATION CONSTANTS
// ============================================

// Recency thresholds in days - UNCHANGED
const RECENCY_CRITICAL_DAYS = 1;
const RECENCY_HIGH_DAYS = 7;
const RECENCY_MEDIUM_DAYS = 30;
const RECENCY_LOW_DAYS = 90;

// REMOVED: Speed thresholds are NO LONGER primary evidence
// Speed is ONLY supporting evidence when combined with OTHER signals

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
// MINIMUM THRESHOLDS FOR DRAINER CLASSIFICATION
// ============================================
// ALL of these must be met to classify as a drainer

const MIN_UNIQUE_VICTIMS = 3;           // Must have funds from at least 3 unrelated sources
const MIN_APPROVAL_ABUSE_EVIDENCE = 1;  // At least 1 approval-based drain
const MIN_CONSOLIDATION_PATTERNS = 1;   // At least 1 pattern of consolidation/laundering
const MAX_LEGITIMATE_INTERACTIONS = 0;  // Must have ZERO DEX/NFT/bridge interactions

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

const KNOWN_AGGREGATION_HUBS = new Set([
  // Tornado Cash related (historical)
  '0x722122df12d4e14e13ac3b6895a86e84145b6967',
  '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b',
  '0xd96f2b1c14db8458374d9aca76e26c3d18364307',
]);

// ============================================
// STRICT DRAINER CRITERIA RESULT
// ============================================

interface StrictDrainerCriteria {
  hasMultipleVictims: boolean;
  victimCount: number;
  hasApprovalAbuse: boolean;
  approvalAbuseCount: number;
  hasConsolidationPattern: boolean;
  consolidationDestinations: string[];
  hasNoLegitimateInteractions: boolean;
  legitimateInteractionCount: number;
  allCriteriaMet: boolean;
  failedCriteria: string[];
}

// ============================================
// MAIN DRAINER ACTIVITY DETECTOR
// ============================================

/**
 * Analyze wallet for active drainer behavior with STRICT CRITERIA.
 * 
 * CRITICAL CHANGE: This function now implements a multi-phase analysis:
 * 1. Context Classification (can short-circuit to SAFE)
 * 2. Known Drainer Check (only for verified addresses)
 * 3. Strict Behavioral Analysis (ALL criteria must be met)
 * 
 * FALSE POSITIVES ARE MORE DAMAGING THAN MISSED LOW-CONFIDENCE DRAINERS.
 */
export function detectDrainerActivity(
  walletAddress: string,
  chain: Chain,
  transactions: TransactionForDrainerAnalysis[],
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  approvals: ApprovalForDrainerAnalysis[],
  currentTimestamp: number = Math.floor(Date.now() / 1000),
  options?: {
    ens?: string;
    isDeployer?: boolean;
    bidirectionalPeers?: string[];
  }
): DrainerOverrideResult {
  const normalized = normalizeAddress(walletAddress);
  const detectedSignals: DrainerBehaviorDetection[] = [];
  const downgradeBlockers: string[] = [];
  
  // ============================================
  // PHASE 1: CONTEXT CLASSIFICATION
  // ============================================
  // This phase can SHORT-CIRCUIT the entire analysis if the wallet
  // is clearly NOT a drainer (DEX trader, protocol, deployer, etc.)
  
  const interactedAddresses = [
    ...transactions.map(t => t.to),
    ...tokenTransfers.map(t => t.to),
  ].filter(Boolean);
  
  const transactionMethods = transactions
    .map(t => t.methodId || t.input?.slice(0, 10))
    .filter(Boolean) as string[];
  
  const inboundCount = transactions.filter(t => 
    normalizeAddress(t.to) === normalized
  ).length + tokenTransfers.filter(t => 
    normalizeAddress(t.to) === normalized
  ).length;
  
  const outboundCount = transactions.filter(t => 
    normalizeAddress(t.from) === normalized
  ).length + tokenTransfers.filter(t => 
    normalizeAddress(t.from) === normalized
  ).length;
  
  const contextResult = classifyWalletContext(
    walletAddress,
    chain,
    interactedAddresses,
    transactionMethods,
    {
      ens: options?.ens,
      isDeployer: options?.isDeployer,
      bidirectionalPeers: options?.bidirectionalPeers,
      outboundCount,
      inboundCount,
    }
  );
  
  // If context classification says to skip drainer detection, return SAFE
  if (contextResult.skipDrainerDetection) {
    return {
      shouldOverride: false,
      detectedSignals: [],
      recency: {
        recency: 'NONE',
        daysSinceLastActivity: Infinity,
        isActive: false,
        confidenceMultiplier: 0,
      },
      confidence: 0,
      canEverBeSafe: true,
      canBePreviouslyCompromised: false,
      overrideReason: `Context: ${contextResult.reason}`,
      downgradeBlockers: [],
      contextClassification: contextResult,
    };
  }
  
  // ============================================
  // PHASE 2: KNOWN DRAINER CHECK
  // ============================================
  // ONLY flag if the address is in our VERIFIED malicious database
  
  if (isKnownDrainer(normalized)) {
    const drainerType = getDrainerType(normalized) || 'Known Drainer';
    detectedSignals.push({
      signal: 'APPROVAL_RAPID_DRAIN',
      detectedAt: new Date().toISOString(),
      txHash: 'N/A - Known Drainer',
      confidence: 100,
      details: `Address is in verified drainer database: ${drainerType}`,
      relatedAddresses: [],
    });
    
    return {
      shouldOverride: true,
      detectedSignals,
      recency: {
        recency: 'CRITICAL',
        daysSinceLastActivity: 0,
        isActive: true,
        confidenceMultiplier: 1.0,
      },
      confidence: 100,
      canEverBeSafe: false,
      canBePreviouslyCompromised: false,
      overrideReason: `VERIFIED DRAINER: Address is in malicious database (${drainerType})`,
      downgradeBlockers: ['Address is in verified drainer database'],
      contextClassification: contextResult,
    };
  }
  
  // ============================================
  // PHASE 3: STRICT BEHAVIORAL ANALYSIS
  // ============================================
  // ALL criteria must be met to flag as drainer:
  // 1. Funds from MULTIPLE unrelated victims
  // 2. Evidence of approval/signer compromise
  // 3. Outflows to consolidation/laundering patterns
  // 4. NO interaction with DEX/NFT/legitimate protocols
  
  const strictCriteria = analyzeStrictDrainerCriteria(
    normalized,
    chain,
    transactions,
    tokenTransfers,
    approvals,
    currentTimestamp
  );
  
  // ============================================
  // DECISION: ALL CRITERIA MUST BE MET
  // ============================================
  
  if (strictCriteria.allCriteriaMet) {
    // This is a HIGH-CONFIDENCE drainer
    detectedSignals.push({
      signal: 'MULTI_TOKEN_ZEROING',
      detectedAt: new Date().toISOString(),
      txHash: transactions[0]?.hash || 'N/A',
      confidence: 95,
      details: `Strict drainer criteria met: ${strictCriteria.victimCount} victims, ` +
        `${strictCriteria.approvalAbuseCount} approval abuses, ` +
        `funds routed to ${strictCriteria.consolidationDestinations.length} consolidation address(es)`,
      relatedAddresses: strictCriteria.consolidationDestinations,
    });
    
    const recency = calculateRecencyFromTimestamps(
      tokenTransfers.map(t => t.timestamp),
      currentTimestamp
    );
    
    return {
      shouldOverride: true,
      detectedSignals,
      recency,
      confidence: 95,
      canEverBeSafe: false,
      canBePreviouslyCompromised: !recency.isActive,
      overrideReason: `HIGH-CONFIDENCE DRAINER: All strict criteria met. ` +
        `${strictCriteria.victimCount} victims, ${strictCriteria.approvalAbuseCount} approval abuses.`,
      downgradeBlockers: ['All strict drainer criteria met'],
      contextClassification: contextResult,
    };
  }
  
  // ============================================
  // NOT A DRAINER: Criteria not met
  // ============================================
  // If any criteria failed, this is NOT a drainer
  
  return {
    shouldOverride: false,
    detectedSignals: [],
    recency: {
      recency: 'NONE',
      daysSinceLastActivity: Infinity,
      isActive: false,
      confidenceMultiplier: 0,
    },
    confidence: 0,
    canEverBeSafe: true,
    canBePreviouslyCompromised: false,
    overrideReason: `NOT A DRAINER: Failed criteria: ${strictCriteria.failedCriteria.join(', ')}`,
    downgradeBlockers: [],
    contextClassification: contextResult,
  };
}

// ============================================
// STRICT DRAINER CRITERIA ANALYSIS
// ============================================

function analyzeStrictDrainerCriteria(
  walletAddress: string,
  chain: Chain,
  transactions: TransactionForDrainerAnalysis[],
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  approvals: ApprovalForDrainerAnalysis[],
  currentTimestamp: number
): StrictDrainerCriteria {
  const failedCriteria: string[] = [];
  
  // ============================================
  // CRITERION 1: Funds from MULTIPLE unrelated victims
  // ============================================
  // A drainer receives funds from many different addresses
  // that are NOT related (not same owner, not protocols)
  
  const inboundSources = new Set<string>();
  
  // Check ETH inflows
  for (const tx of transactions) {
    if (normalizeAddress(tx.to) === walletAddress && BigInt(tx.value || '0') > BigInt(0)) {
      const from = normalizeAddress(tx.from);
      // Exclude self-transfers and safe protocols
      if (from !== walletAddress && !isSafeContract(from)) {
        inboundSources.add(from);
      }
    }
  }
  
  // Check token inflows
  for (const t of tokenTransfers) {
    if (normalizeAddress(t.to) === walletAddress) {
      const from = normalizeAddress(t.from);
      if (from !== walletAddress && !isSafeContract(from)) {
        inboundSources.add(from);
      }
    }
  }
  
  const victimCount = inboundSources.size;
  const hasMultipleVictims = victimCount >= MIN_UNIQUE_VICTIMS;
  
  if (!hasMultipleVictims) {
    failedCriteria.push(`Only ${victimCount} unique sources (need ${MIN_UNIQUE_VICTIMS}+)`);
  }
  
  // ============================================
  // CRITERION 2: Evidence of approval/signer compromise
  // ============================================
  // Look for approvals to malicious spenders followed by drains
  
  let approvalAbuseCount = 0;
  
  for (const approval of approvals) {
    const spender = normalizeAddress(approval.spender);
    
    // Skip approvals to safe contracts (DEXes, bridges, etc.)
    if (isSafeContract(spender) || isDEXRouter(spender) || 
        isDeFiProtocol(spender) || isNFTMarketplace(spender)) {
      continue;
    }
    
    // Check if spender is known malicious
    const isMaliciousSpender = isMaliciousAddress(spender, chain) !== null ||
                               isKnownDrainer(spender) ||
                               isDrainerRecipient(spender);
    
    if (isMaliciousSpender) {
      approvalAbuseCount++;
    }
    
    // Check if approval was followed by drain from the approved token
    const tokenAddress = normalizeAddress(approval.token);
    const drainAfterApproval = tokenTransfers.find(t => {
      const from = normalizeAddress(t.from);
      const token = normalizeAddress(t.tokenAddress);
      return from === walletAddress && 
             token === tokenAddress && 
             t.timestamp > approval.timestamp;
    });
    
    if (drainAfterApproval) {
      approvalAbuseCount++;
    }
  }
  
  const hasApprovalAbuse = approvalAbuseCount >= MIN_APPROVAL_ABUSE_EVIDENCE;
  
  if (!hasApprovalAbuse) {
    failedCriteria.push(`Only ${approvalAbuseCount} approval abuses (need ${MIN_APPROVAL_ABUSE_EVIDENCE}+)`);
  }
  
  // ============================================
  // CRITERION 3: Outflows to consolidation/laundering
  // ============================================
  // Drainers route funds to specific aggregation wallets or mixers
  
  const consolidationDestinations: string[] = [];
  
  // Check for outflows to known aggregation hubs
  for (const tx of transactions) {
    if (normalizeAddress(tx.from) === walletAddress) {
      const to = normalizeAddress(tx.to);
      if (KNOWN_AGGREGATION_HUBS.has(to)) {
        consolidationDestinations.push(to);
      }
    }
  }
  
  for (const t of tokenTransfers) {
    if (normalizeAddress(t.from) === walletAddress) {
      const to = normalizeAddress(t.to);
      if (KNOWN_AGGREGATION_HUBS.has(to) || isKnownDrainer(to)) {
        consolidationDestinations.push(to);
      }
    }
  }
  
  // Check for pattern: many outflows to same few addresses (consolidation)
  const outboundDestinations = new Map<string, number>();
  for (const tx of transactions) {
    if (normalizeAddress(tx.from) === walletAddress) {
      const to = normalizeAddress(tx.to);
      if (!isSafeContract(to)) {
        outboundDestinations.set(to, (outboundDestinations.get(to) || 0) + 1);
      }
    }
  }
  for (const t of tokenTransfers) {
    if (normalizeAddress(t.from) === walletAddress) {
      const to = normalizeAddress(t.to);
      if (!isSafeContract(to)) {
        outboundDestinations.set(to, (outboundDestinations.get(to) || 0) + 1);
      }
    }
  }
  
  // If most outflows go to 1-2 addresses, that's consolidation
  const sortedDestinations = [...outboundDestinations.entries()]
    .sort((a, b) => b[1] - a[1]);
  
  if (sortedDestinations.length > 0) {
    const topDestination = sortedDestinations[0];
    const totalOutbound = [...outboundDestinations.values()].reduce((a, b) => a + b, 0);
    
    // If top destination receives 50%+ of outflows, it's consolidation
    if (topDestination[1] / totalOutbound >= 0.5) {
      consolidationDestinations.push(topDestination[0]);
    }
  }
  
  const hasConsolidationPattern = consolidationDestinations.length >= MIN_CONSOLIDATION_PATTERNS;
  
  if (!hasConsolidationPattern) {
    failedCriteria.push('No consolidation/laundering pattern detected');
  }
  
  // ============================================
  // CRITERION 4: NO legitimate protocol interactions
  // ============================================
  // Real drainers don't use DEXes, NFT marketplaces, or bridges
  // (They just drain and consolidate)
  
  let legitimateInteractionCount = 0;
  
  for (const tx of transactions) {
    const to = normalizeAddress(tx.to);
    if (normalizeAddress(tx.from) === walletAddress) {
      if (isDEXRouter(to) || isNFTMarketplace(to) || isDeFiProtocol(to) ||
          isSafeContract(to) || isInfrastructureContract(to)) {
        legitimateInteractionCount++;
      }
    }
  }
  
  const hasNoLegitimateInteractions = legitimateInteractionCount <= MAX_LEGITIMATE_INTERACTIONS;
  
  if (!hasNoLegitimateInteractions) {
    failedCriteria.push(`${legitimateInteractionCount} legitimate protocol interactions (drainers have 0)`);
  }
  
  // ============================================
  // ALL CRITERIA MUST BE MET
  // ============================================
  
  const allCriteriaMet = hasMultipleVictims && 
                         hasApprovalAbuse && 
                         hasConsolidationPattern && 
                         hasNoLegitimateInteractions;
  
  return {
    hasMultipleVictims,
    victimCount,
    hasApprovalAbuse,
    approvalAbuseCount,
    hasConsolidationPattern,
    consolidationDestinations: [...new Set(consolidationDestinations)],
    hasNoLegitimateInteractions,
    legitimateInteractionCount,
    allCriteriaMet,
    failedCriteria,
  };
}

// ============================================
// RECENCY CALCULATION
// ============================================

function calculateRecencyFromTimestamps(
  timestamps: number[],
  currentTimestamp: number
): DrainerActivityRecencyInfo {
  if (timestamps.length === 0) {
    return {
      recency: 'NONE',
      daysSinceLastActivity: Infinity,
      isActive: false,
      confidenceMultiplier: 0,
    };
  }
  
  const mostRecent = Math.max(...timestamps);
  const daysSince = (currentTimestamp - mostRecent) / (24 * 60 * 60);
  
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
    lastActivityTimestamp: new Date(mostRecent * 1000).toISOString(),
    isActive,
    confidenceMultiplier: RECENCY_CONFIDENCE_MULTIPLIERS[recency],
  };
}

// ============================================
// LEGACY SIGNAL DETECTION FUNCTIONS (DISABLED)
// ============================================
// These functions are PRESERVED for reference but are NO LONGER USED
// as primary evidence. Speed-only heuristics caused too many false positives.

/**
 * @deprecated Speed-only heuristics are no longer primary evidence.
 * Immediate outbound detection now REQUIRES additional context.
 */
function detectImmediateOutboundTransfers_DISABLED(
  walletAddress: string,
  transactions: TransactionForDrainerAnalysis[],
  tokenTransfers: TokenTransferForDrainerAnalysis[],
  currentTimestamp: number
): DrainerBehaviorDetection[] {
  // DISABLED: This caused false positives on active traders, relayers, and deployers
  // Speed alone is NOT evidence of drainer behavior
  return [];
}

// ============================================
// EXPORTS
// ============================================

export {
  RECENCY_CRITICAL_DAYS,
  RECENCY_HIGH_DAYS,
  RECENCY_MEDIUM_DAYS,
  RECENCY_LOW_DAYS,
  KNOWN_AGGREGATION_HUBS,
};
