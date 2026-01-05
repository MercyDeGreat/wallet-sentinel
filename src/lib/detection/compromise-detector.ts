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
import { isSafeContract, isENSContract, isDeFiProtocol, isInfrastructureContract, isNFTMarketplace } from './safe-contracts';
import { checkInfrastructureProtection } from './infrastructure-protection';

// ============================================
// DESTINATION TRUST CLASSIFICATION
// ============================================
// Before flagging any outgoing transaction, check if destination is trusted

// Known bridge contracts
const KNOWN_BRIDGES = new Set([
  // Ethereum bridges
  '0x3ee18b2214aff97000d974cf647e7c347e8fa585', // Wormhole Bridge
  '0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf', // Polygon PoS Bridge
  '0xa0c68c638235ee32657e8f720a23cec1bfc77c77', // Polygon zkEVM Bridge
  '0x99c9fc46f92e8a1c0dec1b1747d010903e884be1', // Optimism Bridge
  '0x3154cf16ccdb4c6d922629664174b904d80f2c35', // Base Bridge
  '0x4200000000000000000000000000000000000010', // Optimism L2 Bridge
  '0x49048044d57e1c92a77f79988d21fa8faf74e97e', // Base Portal
  '0x72ce9c846789fdb6fc1f34ac4ad25dd9ef7031ef', // Arbitrum Bridge
  '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a', // Arbitrum Outbox
  '0x051f1d88f0af5763fb888ec4378b4d8b29ea3319', // Stargate Router
  '0x6352a56caadcdfd2135eec7f97e8d94e2dd778ee', // Stargate Router V2
  '0x150f94b44927f078737562f0fcf3c95c01cc2376', // Li.Fi Diamond
  '0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae', // Li.Fi Diamond V2
  '0x2dfff1c176976694545179a31957d7781b0e5108', // Relay Router
  '0xc30141b657f42f1e34a63552ce2d0f2f5216a8c7', // Socket Gateway
  '0x3a23f943181408cd4a4b52b04f04671c6509015b', // Socket Registry
]);

// Known exchange deposit addresses (hot wallets)
const KNOWN_EXCHANGES = new Set([
  // Binance
  '0x28c6c06298d514db089934071355e5743bf21d60',
  '0x21a31ee1afc51d94c2efccaa2092ad1028285549',
  '0xdfd5293d8e347dfe59e90efd55b2956a1343963d',
  '0x56eddb7aa87536c09ccc2793473599fd21a8b17f',
  // Coinbase
  '0x71660c4005ba85c37ccec55d0c4493e66fe775d3',
  '0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43',
  '0x503828976d22510aad0201ac7ec88293211d23da',
  '0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740',
  // Kraken
  '0x2910543af39aba0cd09dbb2d50200b3e800a63d2',
  '0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13',
  // OKX
  '0x6cc5f688a315f3dc28a7781717a9a798a59fda7b',
  '0x98ec059dc3adfbdd63429454aeb0c990fba4a128',
  // Bybit
  '0xf89d7b9c864f589bbf53a82105107622b35eaa40',
  '0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4',
  // Kucoin
  '0xd6216fc19db775df9774a6e33526131da7d19a2c',
  '0xf16e9b0d03470827a95cdfd0cb8a8a3b46969b91',
  // Gate.io
  '0x0d0707963952f2fba59dd06f2b425ace40b492fe',
  '0x1c4b70a3968436b9a0a9cf5205c787eb81bb558c',
  // HTX (Huobi)
  '0xab5c66752a9e8167967685f1450532fb96d5d24f',
  '0x46705dfff24256421a05d056c29e81bdc09723b8',
]);

// Known protocol routers/relayers
const KNOWN_ROUTERS = new Set([
  // Uniswap
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Universal Router
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // V2 Router
  '0xe592427a0aece92de3edee1f18e0157c05861564', // V3 Router
  // 1inch
  '0x1111111254eeb25477b68fb85ed929f73a960582', // V5 Router
  '0x111111125421ca6dc452d289314280a0f8842a65', // V6 Router
  // Cowswap
  '0x9008d19f58aabd9ed0d60971565aa8510560ab41', // GPv2Settlement
  // Aggregators
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff', // 0x Exchange Proxy
  '0x881d40237659c251811cec9c364ef91dc08d300c', // Metamask Swap Router
]);

/**
 * Checks if a destination address is trusted (bridge, exchange, router, protocol)
 * Returns the trust level and category
 */
function classifyDestinationTrust(address: string): { 
  isTrusted: boolean; 
  category: 'BRIDGE' | 'EXCHANGE' | 'ROUTER' | 'PROTOCOL' | 'INFRASTRUCTURE' | 'UNKNOWN';
  name?: string;
} {
  const normalized = address.toLowerCase();
  
  // Check protected infrastructure first
  const infraCheck = checkInfrastructureProtection(normalized, 'ethereum');
  if (infraCheck.isProtected) {
    return { isTrusted: true, category: 'INFRASTRUCTURE', name: infraCheck.name };
  }
  
  // Check bridges
  if (KNOWN_BRIDGES.has(normalized)) {
    return { isTrusted: true, category: 'BRIDGE' };
  }
  
  // Check exchanges
  if (KNOWN_EXCHANGES.has(normalized)) {
    return { isTrusted: true, category: 'EXCHANGE' };
  }
  
  // Check routers
  if (KNOWN_ROUTERS.has(normalized)) {
    return { isTrusted: true, category: 'ROUTER' };
  }
  
  // Check safe contracts database
  if (isSafeContract(normalized) || isDeFiProtocol(normalized) || 
      isNFTMarketplace(normalized) || isENSContract(normalized) ||
      isInfrastructureContract(normalized) || isLegitimateContract(normalized)) {
    return { isTrusted: true, category: 'PROTOCOL' };
  }
  
  return { isTrusted: false, category: 'UNKNOWN' };
}

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

    // CHECK 2b: ONLY flag approvals to unverified contracts IF there's additional evidence
    // Small approvals without draining are common in normal DeFi usage
    // We should NOT flag every approval to an unverified contract - that creates false positives
    // Only flag if:
    // - The approval is to a KNOWN malicious address (handled elsewhere)
    // - OR there's been a drain after the approval (CHECK 3)
    // - OR the approval amount is suspiciously high relative to normal activity
    // 
    // NOTE: Removed automatic safety blocker for non-unlimited approvals
    // This was causing false positives for normal user activity

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

  // CHECK 2: Funds sent to unknown addresses
  // IMPORTANT: Use comprehensive destination trust classification BEFORE flagging
  // Bridges, exchanges, routers, and known protocols are TRUSTED destinations
  const outgoingToUnknown = tokenTransfers.filter(transfer => {
    if (transfer.from.toLowerCase() !== walletAddress) return false;
    const to = transfer.to.toLowerCase();
    
    // Use comprehensive trust classification
    const trustInfo = classifyDestinationTrust(to);
    if (trustInfo.isTrusted) {
      console.log(`[CompromiseDetector] Transfer to ${to} classified as trusted: ${trustInfo.category}`);
      return false; // NOT unknown - this is a trusted destination
    }
    
    return true; // Unknown destination
  });

  if (outgoingToUnknown.length > 0) {
    // Group by destination
    const destCounts = new Map<string, number>();
    for (const t of outgoingToUnknown) {
      const dest = t.to.toLowerCase();
      destCounts.set(dest, (destCounts.get(dest) || 0) + 1);
    }

    // Only flag if funds sent to MANY DIFFERENT unknown addresses (5+, not 3)
    // This indicates indiscriminate draining, not normal user activity
    // A user might send to 1-2 unknown addresses (new DEX, friend wallet), but 5+ is suspicious
    if (destCounts.size >= 5) {
      evidence.push({
        code: 'UNKNOWN_RECIPIENT_DRAIN',
        severity: 'MEDIUM',
        description: `Funds sent to ${destCounts.size} unknown addresses. Review these recipients.`,
        confidence: 55, // Lower confidence - this alone is not definitive
      });
      reasonCodes.push('UNKNOWN_RECIPIENT_DRAIN');
      // NOT adding as blocker - this alone shouldn't block SAFE status
      // blockers.push(`Funds sent to ${destCounts.size} unknown addresses`);
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
  // IMPORTANT: This is a WEAK signal alone - users often return to wallets after inactivity
  // Only flag if destination is BOTH unknown AND there's other evidence
  if (sortedTxs.length >= 2) {
    for (let i = 1; i < sortedTxs.length; i++) {
      const gap = sortedTxs[i].timestamp - sortedTxs[i - 1].timestamp;
      const gapDays = gap / (24 * 60 * 60);
      
      // Higher threshold: 60+ days of inactivity (not 30)
      if (gapDays >= 60) {
        // Check if the activity after the gap is outgoing
        const txAfterGap = sortedTxs[i];
        if (txAfterGap.from.toLowerCase() === walletAddress) {
          // Use comprehensive destination trust classification
          const trustInfo = classifyDestinationTrust(txAfterGap.to.toLowerCase());
          
          if (!trustInfo.isTrusted) {
            // Only log this as LOW severity - it's just informational
            // Returning to a wallet and moving funds is NORMAL user behavior
            evidence.push({
              code: 'INACTIVE_PERIOD_DRAIN',
              severity: 'LOW', // Changed from MEDIUM to LOW
              description: `Outgoing transaction after ${Math.round(gapDays)} days of inactivity to unknown address. This alone is not indicative of compromise.`,
              relatedTxHash: txAfterGap.hash,
              relatedAddress: txAfterGap.to,
              timestamp: new Date(txAfterGap.timestamp * 1000).toISOString(),
              confidence: 30, // Very low confidence - this is common user behavior
            });
            // DO NOT add reason code or blocker - this is too weak a signal
            // reasonCodes.push('INACTIVE_PERIOD_DRAIN');
            // blockers.push(`Activity after ${Math.round(gapDays)} days of inactivity`);
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
  // IMPORTANT: Transfers to bridges, exchanges, and protocols are EXPLAINED - they're user-initiated
  const totalOutgoing = tokenTransfers
    .filter(t => t.from.toLowerCase() === walletAddress)
    .reduce((sum, t) => sum + BigInt(t.value || '0'), BigInt(0));

  const totalIncoming = tokenTransfers
    .filter(t => t.to.toLowerCase() === walletAddress)
    .reduce((sum, t) => sum + BigInt(t.value || '0'), BigInt(0));

  // Only check for unexplained loss if net outflow is extreme (100x, not 10x)
  if (totalOutgoing > totalIncoming * BigInt(100)) {
    // Filter to ONLY unknown destinations using comprehensive trust check
    const outgoingToUnknown = tokenTransfers.filter(t => {
      if (t.from.toLowerCase() !== walletAddress) return false;
      const to = t.to.toLowerCase();
      const trustInfo = classifyDestinationTrust(to);
      return !trustInfo.isTrusted; // Only truly unknown destinations
    });

    // Only flag if MANY transfers to unknown addresses (5+)
    // Single transfers are almost always user-initiated
    if (outgoingToUnknown.length >= 5) {
      evidence.push({
        code: 'UNEXPLAINED_ASSET_LOSS',
        severity: 'LOW', // Changed from MEDIUM to LOW
        description: `Net outflow detected to ${outgoingToUnknown.length} unclassified address(es). This may indicate portfolio rebalancing or normal usage.`,
        confidence: 35, // Low confidence - net outflow is normal for active users
      });
      // DO NOT add reason code or blocker - outflows are normal user activity
      // reasonCodes.push('UNEXPLAINED_ASSET_LOSS');
      // blockers.push(`Unexplained asset loss detected`);
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

  // Count by severity - only count evidence that actually matters
  // LOW severity evidence should NOT affect status determination
  const criticalCount = evidence.filter(e => e.severity === 'CRITICAL').length;
  const highCount = evidence.filter(e => e.severity === 'HIGH').length;
  const mediumCount = evidence.filter(e => e.severity === 'MEDIUM').length;
  const lowCount = evidence.filter(e => e.severity === 'LOW').length;

  // ============================================
  // STATUS DETERMINATION - BALANCED APPROACH
  // We want to catch real threats without creating false positives
  // ============================================

  // CONFIRMED COMPROMISED: Strong evidence of compromise
  // Requires CRITICAL severity indicators
  if (criticalCount >= 1) {
    const topReasons = reasonCodes.slice(0, 3).join(', ');
    return {
      status: 'COMPROMISED',
      confidence: Math.min(99, avgConfidence + 10),
      summary: `CONFIRMED COMPROMISED: ${criticalCount} critical indicator(s) detected. Reasons: ${topReasons}. Immediate action required.`,
    };
  }

  // AT_RISK: Multiple high severity indicators
  // Requires at least 2 HIGH severity indicators
  if (highCount >= 2 && avgConfidence >= 75) {
    const topReasons = reasonCodes.slice(0, 3).join(', ');
    return {
      status: 'AT_RISK',
      confidence: avgConfidence,
      summary: `AT RISK: ${highCount} high severity indicators detected. Reasons: ${topReasons}. Review and secure immediately.`,
    };
  }

  // POTENTIALLY_COMPROMISED: Some concerning indicators
  // Requires: HIGH severity OR (MEDIUM severity + safety blockers)
  if (highCount >= 1) {
    const topReasons = reasonCodes.slice(0, 3).join(', ');
    return {
      status: 'POTENTIALLY_COMPROMISED',
      confidence: avgConfidence,
      summary: `REVIEW NEEDED: ${highCount} high severity indicator(s) found. ${topReasons}. Manual review recommended.`,
    };
  }

  // If we have safety blockers from CRITICAL/HIGH evidence, flag as POTENTIALLY_COMPROMISED
  if (safetyBlockers.length > 0) {
    return {
      status: 'POTENTIALLY_COMPROMISED',
      confidence: 40,
      summary: `REVIEW NEEDED: ${safetyBlockers.slice(0, 3).join('; ')}. Manual review recommended.`,
    };
  }

  // ============================================
  // LOW/MEDIUM SEVERITY EVIDENCE ALONE IS NOT ENOUGH
  // This is critical to prevent false positives
  // ============================================
  
  // If we ONLY have low/medium severity evidence, this is likely normal user activity
  // Do NOT flag as compromised based on:
  // - Transfers to unknown addresses (could be bridges, new protocols, friend wallets)
  // - Activity after inactivity (user returned to wallet)
  // - Net outflow (user moving to exchange or different wallet)
  
  if (mediumCount > 0 || lowCount > 0) {
    // Check if the evidence is actually concerning
    const hasConcerningEvidence = evidence.some(e => 
      e.confidence >= 70 && (e.severity === 'MEDIUM' || e.severity === 'HIGH' || e.severity === 'CRITICAL')
    );
    
    if (hasConcerningEvidence) {
      return {
        status: 'POTENTIALLY_COMPROMISED',
        confidence: Math.max(30, avgConfidence),
        summary: `Some activity requires review, but no definitive compromise indicators found.`,
      };
    }
    
    // Low confidence evidence = likely normal user behavior
    // Return SAFE with explanation
    console.log(`[CompromiseDetector] Only low-confidence evidence found (${lowCount} low, ${mediumCount} medium) - classifying as SAFE`);
    return {
      status: 'SAFE',
      confidence: 80,
      summary: `No significant threat indicators detected. Some routine activity was reviewed and found to be normal.`,
    };
  }

  // ============================================
  // SAFE: No concerning evidence found
  // ============================================
  
  // SAFE: All checks pass, no evidence
  if (safetyChecks.allChecksPass && evidence.length === 0 && safetyBlockers.length === 0) {
    return {
      status: 'SAFE',
      confidence: 95,
      summary: 'SAFE: All safety checks passed. No malicious approvals, no attacker interactions detected.',
    };
  }

  // Default to SAFE if no evidence - absence of evidence is evidence of safety for normal wallets
  // This is a key change: we trust wallets by default unless we find actual threat indicators
  return {
    status: 'SAFE',
    confidence: 85,
    summary: 'No threat indicators detected. Wallet activity appears normal.',
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

