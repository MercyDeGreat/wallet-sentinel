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

import { Chain, SecurityStatus, CompromiseReasonCode, CompromiseEvidence, HistoricalIncident, DrainerOverrideResult } from '@/types';
import { isMaliciousAddress, isDrainerRecipient, isLegitimateContract } from './malicious-database';
import { isSafeContract, isENSContract, isDeFiProtocol, isInfrastructureContract, isNFTMarketplace, isNFTMintContract, isNFTMintTransaction, isStandardMintMethod, isBaseNFTActivity, isPaidMintTransaction } from './safe-contracts';
import { checkInfrastructureProtection } from './infrastructure-protection';
import { checkBaseProtocolInteraction, checkSelfTransfer, checkExchangeWallet } from './base-chain-protection';
import { 
  detectDrainerActivity, 
  normalizeAddress,
  TransactionForDrainerAnalysis,
  TokenTransferForDrainerAnalysis,
  ApprovalForDrainerAnalysis,
} from './drainer-activity-detector';

// ============================================
// HISTORICAL VS ACTIVE COMPROMISE DETECTION
// ============================================
// A wallet should be marked ACTIVELY_COMPROMISED only if:
// - Active unlimited or high-risk approval exists
// - Known drainer contract still has allowance
// - Automated outflows continue without user initiation
// - Private key reuse detected
//
// If historical exploit occurred but all threats remediated:
// - Mark as PREVIOUSLY_COMPROMISED
// - Show historical incident details
// - Explain current safety status

// Known airdrop drainer contracts (BNB Chain)
const KNOWN_AIRDROP_DRAINERS = new Set([
  // ICE Token drainers
  '0x1234567890abcdef1234567890abcdef12345678', // Placeholder - add real addresses
]);

// BNB Chain specific airdrop contracts that are often exploited
const BNB_AIRDROP_CONTRACTS = new Set([
  // Add known airdrop contracts here
]);

/**
 * Check if a malicious approval is still active
 */
function isApprovalStillActive(
  approval: ApprovalForAnalysis,
  allApprovals: ApprovalForAnalysis[]
): boolean {
  // If explicitly marked as revoked
  if (approval.wasRevoked) {
    return false;
  }
  
  // Check if there's a subsequent approval to the same spender with 0 amount (revocation)
  const laterRevocation = allApprovals.find(a => 
    a.spender.toLowerCase() === approval.spender.toLowerCase() &&
    a.token.toLowerCase() === approval.token.toLowerCase() &&
    a.timestamp > approval.timestamp &&
    (a.amount === '0' || BigInt(a.amount) === BigInt(0))
  );
  
  return !laterRevocation;
}

/**
 * Classify an incident as active or historical
 */
function classifyThreatTiming(
  evidence: CompromiseEvidence,
  approvals: ApprovalForAnalysis[],
  transactions: TransactionForAnalysis[],
  currentTimestamp: number
): { isActive: boolean; isHistorical: boolean; remediated: boolean; remediationDetails?: string } {
  const evidenceTimestamp = evidence.timestamp ? new Date(evidence.timestamp).getTime() / 1000 : 0;
  const daysSinceIncident = (currentTimestamp - evidenceTimestamp) / (24 * 60 * 60);
  
  // ============================================
  // RULE 0: LOW severity evidence is NEVER considered "active"
  // ============================================
  // LOW severity = informational only, should not trigger alerts
  if (evidence.severity === 'LOW') {
    return {
      isActive: false,
      isHistorical: true,
      remediated: true,
      remediationDetails: 'Low severity - informational only'
    };
  }
  
  // ============================================
  // RULE 1: Approval-related - check if approval still active
  // ============================================
  if (evidence.code === 'UNLIMITED_APPROVAL_EOA' || 
      evidence.code === 'UNLIMITED_APPROVAL_UNVERIFIED' ||
      evidence.code === 'ATTACKER_LINKED_ADDRESS') {
    
    const relatedApproval = approvals.find(a => 
      a.spender.toLowerCase() === evidence.relatedAddress?.toLowerCase()
    );
    
    if (relatedApproval) {
      const stillActive = isApprovalStillActive(relatedApproval, approvals);
      if (!stillActive) {
        return {
          isActive: false,
          isHistorical: true,
          remediated: true,
          remediationDetails: 'Malicious approval has been revoked'
        };
      }
    }
  }
  
  // ============================================
  // RULE 2: Check for RECENT malicious activity (7 days)
  // ============================================
  const recentMaliciousActivity = transactions.some(tx => {
    const txTime = tx.timestamp;
    const daysSinceTx = (currentTimestamp - txTime) / (24 * 60 * 60);
    const isMalicious = isMaliciousAddress(tx.to?.toLowerCase(), 'ethereum') ||
                        isDrainerRecipient(tx.to?.toLowerCase());
    return daysSinceTx <= 7 && isMalicious;
  });
  
  if (recentMaliciousActivity) {
    return { isActive: true, isHistorical: false, remediated: false };
  }
  
  // ============================================
  // RULE 3: Old incidents (> 30 days) are historical
  // ============================================
  if (daysSinceIncident > 30) {
    return {
      isActive: false,
      isHistorical: true,
      remediated: true,
      remediationDetails: `No malicious activity in ${Math.floor(daysSinceIncident)} days`
    };
  }
  
  // ============================================
  // RULE 4: MEDIUM severity within 7 days = potentially active
  // ============================================
  if (evidence.severity === 'MEDIUM' && daysSinceIncident <= 7) {
    return { isActive: true, isHistorical: false, remediated: false };
  }
  
  // ============================================
  // DEFAULT: Only CRITICAL/HIGH within 7 days are truly active
  // Everything else is historical
  // ============================================
  const isHighSeverity = evidence.severity === 'CRITICAL' || evidence.severity === 'HIGH';
  if (isHighSeverity && daysSinceIncident <= 7) {
    return { isActive: true, isHistorical: false, remediated: false };
  }
  
  return { isActive: false, isHistorical: true, remediated: daysSinceIncident > 30 };
}

/**
 * Detect airdrop drain incidents (common on BNB Chain)
 */
function detectAirdropDrainIncident(
  walletAddress: string,
  chain: Chain,
  transactions: TransactionForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[],
  approvals: ApprovalForAnalysis[]
): HistoricalIncident | null {
  // Look for pattern: approval to unknown contract followed by token drain
  // Common in airdrop exploits
  
  for (const approval of approvals) {
    const spenderLower = approval.spender.toLowerCase();
    
    // Check if this is a known drainer or suspicious airdrop contract
    const maliciousInfo = isMaliciousAddress(spenderLower, chain);
    if (!maliciousInfo && !KNOWN_AIRDROP_DRAINERS.has(spenderLower)) {
      continue;
    }
    
    // Look for token transfers after this approval to the drainer
    const drainTransfers = tokenTransfers.filter(t => 
      t.from.toLowerCase() === walletAddress.toLowerCase() &&
      t.timestamp >= approval.timestamp &&
      t.timestamp <= approval.timestamp + 3600 // Within 1 hour
    );
    
    if (drainTransfers.length > 0) {
      const isStillActive = isApprovalStillActive(approval, approvals);
      
      return {
        type: 'AIRDROP_DRAIN',
        timestamp: new Date(approval.timestamp * 1000).toISOString(),
        txHash: approval.transactionHash,
        maliciousAddress: spenderLower,
        maliciousContractName: maliciousInfo?.name || 'Unknown Airdrop Drainer',
        chain,
        approvalStillActive: isStillActive,
        assetsLost: drainTransfers.map(t => ({
          token: t.tokenAddress,
          symbol: t.tokenSymbol,
          amount: t.value,
        })),
        explanation: isStillActive 
          ? `Airdrop claim contract drained tokens. WARNING: Approval is still active!`
          : `Historical airdrop drain. The malicious approval has been revoked.`,
      };
    }
  }
  
  return null;
}

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
  category: 'BRIDGE' | 'EXCHANGE' | 'ROUTER' | 'PROTOCOL' | 'INFRASTRUCTURE' | 'NFT_MINT' | 'UNKNOWN';
  name?: string;
} {
  const normalized = address.toLowerCase();
  
  // Check protected infrastructure first
  const infraCheck = checkInfrastructureProtection(normalized, 'ethereum');
  if (infraCheck.isProtected) {
    return { isTrusted: true, category: 'INFRASTRUCTURE', name: infraCheck.name };
  }
  
  // ============================================
  // BASE CHAIN SPECIFIC PROTECTION
  // ============================================
  const baseProtocol = checkBaseProtocolInteraction(normalized);
  if (baseProtocol.isLegitimateProtocol) {
    return { isTrusted: true, category: 'PROTOCOL', name: baseProtocol.protocolName };
  }
  
  // Check exchange wallets (CEX hot wallets)
  const exchangeCheck = checkExchangeWallet(normalized);
  if (exchangeCheck.isExchange) {
    return { isTrusted: true, category: 'EXCHANGE', name: exchangeCheck.exchangeInfo?.name };
  }
  
  // ============================================
  // NFT MINT CONTRACTS - ALWAYS TRUSTED
  // ============================================
  if (isNFTMintContract(normalized) || isNFTMintTransaction(normalized)) {
    return { isTrusted: true, category: 'NFT_MINT' };
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
  blockNumber?: number;       // Optional: Block number of the transfer
  tokenType?: 'ERC20' | 'ERC721' | 'ERC1155'; // Optional: Token type
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
  
  // ============================================
  // HISTORICAL VS ACTIVE COMPROMISE TRACKING
  // ============================================
  historicalCompromise?: {
    hasHistoricalIncident: boolean;
    isCurrentlyActive: boolean;
    incidents: Array<{
      type: 'AIRDROP_DRAIN' | 'APPROVAL_EXPLOIT' | 'PHISHING' | 'SWEEPER_ATTACK' | 'UNKNOWN';
      timestamp: string;
      txHash: string;
      maliciousAddress: string;
      explanation: string;
      approvalStillActive: boolean;
      chain: Chain;
    }>;
    remediationStatus: {
      allApprovalsRevoked: boolean;
      noActiveDrainerAccess: boolean;
      noOngoingDrains: boolean;
      lastMaliciousActivity?: string;
      daysSinceLastIncident?: number;
    };
  };
  
  // Active threats (require immediate action)
  activeThreats: CompromiseEvidence[];
  
  // Historical threats (no longer active, remediated)
  historicalThreats: CompromiseEvidence[];
  
  // Detailed reasoning output (for debugging/transparency)
  riskReasoning?: import('@/types').RiskReasoningOutput;
  
  // ============================================
  // COMPROMISE RESOLUTION INFO (NEW)
  // ============================================
  // Provides granular sub-status for "Previously Compromised" wallets
  // Used for UI badges - does NOT affect risk score
  compromiseResolution?: import('@/types').CompromiseResolutionInfo;
  
  // ============================================
  // DRAINER OVERRIDE RESULT (SECURITY FIX 2024-01)
  // ============================================
  // If drainerOverride.shouldOverride is TRUE, the wallet MUST be
  // classified as ACTIVE_COMPROMISE_DRAINER regardless of any other analysis.
  // This is a HARD OVERRIDE that cannot be bypassed.
  drainerOverride?: DrainerOverrideResult;
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
  const normalized = normalizeAddress(walletAddress);
  const evidence: CompromiseEvidence[] = [];
  const reasonCodes: CompromiseReasonCode[] = [];
  const safetyBlockers: string[] = [];
  const currentTimestamp = Math.floor(Date.now() / 1000);
  
  // ============================================
  // STEP 0: DRAINER ACTIVITY DETECTION (HARD OVERRIDE)
  // ============================================
  // This MUST run first and its result supersedes all other analysis.
  // If shouldOverride is TRUE, the wallet MUST be classified as
  // ACTIVE_COMPROMISE_DRAINER regardless of any other factors.
  
  console.log(`[CompromiseDetector] Running drainer activity detection for ${normalized.slice(0, 10)}...`);
  
  // Convert to drainer analysis format
  const txsForDrainer: TransactionForDrainerAnalysis[] = transactions.map(tx => ({
    hash: tx.hash,
    from: tx.from,
    to: tx.to,
    value: tx.value,
    input: tx.input,
    timestamp: tx.timestamp,
    blockNumber: tx.blockNumber,
    methodId: tx.methodId,
    isError: tx.isError,
    gasUsed: tx.gasUsed,
  }));
  
  const transfersForDrainer: TokenTransferForDrainerAnalysis[] = tokenTransfers.map(t => ({
    from: t.from,
    to: t.to,
    value: t.value,
    hash: t.hash,
    timestamp: t.timestamp,
    tokenSymbol: t.tokenSymbol,
    tokenAddress: t.tokenAddress,
    blockNumber: t.blockNumber,
    tokenType: t.tokenType,
  }));
  
  const approvalsForDrainer: ApprovalForDrainerAnalysis[] = approvals.map(a => ({
    token: a.token,
    tokenSymbol: a.tokenSymbol,
    spender: a.spender,
    owner: a.owner,
    amount: a.amount,
    isUnlimited: a.isUnlimited,
    timestamp: a.timestamp,
    transactionHash: a.transactionHash,
    blockNumber: a.blockNumber,
    wasRevoked: a.wasRevoked,
    revokedTimestamp: a.revokedTimestamp,
  }));
  
  const drainerOverride = detectDrainerActivity(
    normalized,
    chain,
    txsForDrainer,
    transfersForDrainer,
    approvalsForDrainer,
    currentTimestamp
  );
  
  console.log(`[CompromiseDetector] Drainer override result: shouldOverride=${drainerOverride.shouldOverride}, ` +
    `signals=${drainerOverride.detectedSignals.length}, confidence=${drainerOverride.confidence}, ` +
    `recency=${drainerOverride.recency.recency} (${drainerOverride.recency.daysSinceLastActivity} days)`);
  
  // Add drainer signals to evidence
  for (const signal of drainerOverride.detectedSignals) {
    evidence.push({
      code: 'SWEEPER_BOT_DETECTED' as CompromiseReasonCode,
      severity: 'CRITICAL',
      description: signal.details,
      relatedTxHash: signal.txHash,
      timestamp: signal.detectedAt,
      confidence: signal.confidence,
      isHistorical: !drainerOverride.recency.isActive,
      isActiveThreat: drainerOverride.recency.isActive,
    });
    if (!reasonCodes.includes('SWEEPER_BOT_DETECTED')) {
      reasonCodes.push('SWEEPER_BOT_DETECTED');
    }
    safetyBlockers.push(`Drainer signal detected: ${signal.signal}`);
  }
  
  // If hard override triggered, we still run the full analysis but will override the final status
  if (drainerOverride.shouldOverride) {
    console.log(`[CompromiseDetector] *** HARD OVERRIDE TRIGGERED *** Wallet MUST be ACTIVE_COMPROMISE_DRAINER`);
  }

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
  // F. HISTORICAL VS ACTIVE THREAT CLASSIFICATION
  // ============================================
  // Note: currentTimestamp already defined at the start of this function
  const activeThreats: CompromiseEvidence[] = [];
  const historicalThreats: CompromiseEvidence[] = [];
  
  console.log(`[CompromiseDetector] Classifying ${evidence.length} evidence items for ${normalized.slice(0, 10)}...`);
  
  // Classify each evidence item
  for (const ev of evidence) {
    const timing = classifyThreatTiming(ev, approvals, transactions, currentTimestamp);
    
    console.log(`[CompromiseDetector] Evidence: ${ev.code}, severity: ${ev.severity}, isActive: ${timing.isActive}, isHistorical: ${timing.isHistorical}`);
    
    // Add classification to evidence
    ev.isHistorical = timing.isHistorical;
    ev.isActiveThreat = timing.isActive;
    ev.wasRemediated = timing.remediated;
    ev.remediationDetails = timing.remediationDetails;
    
    if (timing.isActive) {
      activeThreats.push(ev);
    } else {
      historicalThreats.push(ev);
    }
  }
  
  console.log(`[CompromiseDetector] Result: ${activeThreats.length} active, ${historicalThreats.length} historical threats for ${normalized.slice(0, 10)}...`)
  
  // Check for airdrop drain incident (common on BNB Chain)
  const airdropIncident = detectAirdropDrainIncident(normalized, chain, transactions, tokenTransfers, approvals);
  
  // Check if any malicious approvals are still active
  const hasActiveMaliciousApproval = approvals.some(a => {
    const isMalicious = isMaliciousAddress(a.spender.toLowerCase(), chain) || 
                        isDrainerRecipient(a.spender.toLowerCase());
    return isMalicious && isApprovalStillActive(a, approvals);
  });
  
  // Check for ongoing drain activity (within last 7 days)
  const sevenDaysAgo = currentTimestamp - (7 * 24 * 60 * 60);
  const hasOngoingDrains = tokenTransfers.some(t => {
    if (t.from.toLowerCase() !== normalized) return false;
    if (t.timestamp < sevenDaysAgo) return false;
    const isMaliciousDest = isMaliciousAddress(t.to.toLowerCase(), chain) || 
                            isDrainerRecipient(t.to.toLowerCase());
    return isMaliciousDest;
  });
  
  // Find last malicious activity timestamp
  const maliciousTxTimestamps = [
    ...evidence.filter(e => e.timestamp).map(e => new Date(e.timestamp!).getTime() / 1000),
    ...tokenTransfers
      .filter(t => isMaliciousAddress(t.to.toLowerCase(), chain) || isDrainerRecipient(t.to.toLowerCase()))
      .map(t => t.timestamp)
  ];
  const lastMaliciousActivity = maliciousTxTimestamps.length > 0 
    ? new Date(Math.max(...maliciousTxTimestamps) * 1000).toISOString()
    : undefined;
  const daysSinceLastIncident = lastMaliciousActivity 
    ? Math.floor((currentTimestamp - Math.max(...maliciousTxTimestamps)) / (24 * 60 * 60))
    : undefined;
  
  // ============================================
  // G. CONFIRMED DRAINER INTERACTION CHECK (CRITICAL!)
  // ============================================
  // If wallet has EVER interacted with a confirmed drainer,
  // it can NEVER be marked SAFE - only PREVIOUSLY_COMPROMISED at best.
  const drainerCheck = checkConfirmedDrainerInteraction(transactions, tokenTransfers, approvals, chain);
  
  if (drainerCheck.hasConfirmedDrainerInteraction) {
    console.log(`[CompromiseDetector] CONFIRMED DRAINER INTERACTION detected! Contracts: ${drainerCheck.drainerContractsInteracted.join(', ')}`);
    
    // Add evidence for drainer interaction
    evidence.push({
      code: 'CONFIRMED_DRAINER_INTERACTION',
      severity: 'CRITICAL',
      description: `Wallet has interacted with confirmed drainer contract(s): ${drainerCheck.drainerTypes.join(', ')}. This interaction is permanently recorded and prevents SAFE status.`,
      relatedTxHash: drainerCheck.firstInteractionTxHash,
      timestamp: drainerCheck.firstInteractionTimestamp,
      confidence: 100,
      isHistorical: true,
      isActiveThreat: false,
    });
    reasonCodes.push('CONFIRMED_DRAINER_INTERACTION');
    safetyBlockers.push(`Historical drainer interaction detected: ${drainerCheck.drainerTypes.join(', ')}`);
  }
  
  // ============================================
  // H. ASSET SWEEP DETECTION
  // ============================================
  const sweepCheck = detectAssetSweep(transactions, tokenTransfers, normalized);
  
  if (sweepCheck.assetSweepDetected) {
    console.log(`[CompromiseDetector] ASSET SWEEP detected! ${sweepCheck.sweepTransactions.length} transactions within ${sweepCheck.sweepBlockRange?.end ? sweepCheck.sweepBlockRange.end - sweepCheck.sweepBlockRange.start : 0} blocks`);
    
    evidence.push({
      code: 'ASSET_SWEEP_DETECTED',
      severity: 'CRITICAL',
      description: `Rapid multi-asset sweep detected. ${sweepCheck.assetsSwept.length} assets drained within ≤3 blocks to ${sweepCheck.sweepDestination?.slice(0, 10)}...`,
      relatedTxHash: sweepCheck.sweepTransactions[0],
      confidence: 95,
      isHistorical: true,
      isActiveThreat: false,
    });
    reasonCodes.push('ASSET_SWEEP_DETECTED');
    safetyBlockers.push(`Asset sweep detected: ${sweepCheck.assetsSwept.length} assets drained rapidly`);
  }
  
  // Build historical compromise info
  const hasHistoricalIncident = evidence.length > 0 || airdropIncident !== null || drainerCheck.hasConfirmedDrainerInteraction;
  const isCurrentlyActive = activeThreats.length > 0 || hasActiveMaliciousApproval || hasOngoingDrains;
  
  const historicalCompromise = hasHistoricalIncident ? {
    hasHistoricalIncident: true,
    isCurrentlyActive,
    incidents: airdropIncident ? [{
      type: airdropIncident.type,
      timestamp: airdropIncident.timestamp,
      txHash: airdropIncident.txHash,
      maliciousAddress: airdropIncident.maliciousAddress,
      explanation: airdropIncident.explanation,
      approvalStillActive: airdropIncident.approvalStillActive,
      chain: airdropIncident.chain,
    }] : [],
    remediationStatus: {
      allApprovalsRevoked: !hasActiveMaliciousApproval,
      noActiveDrainerAccess: !hasActiveMaliciousApproval,
      noOngoingDrains: !hasOngoingDrains,
      lastMaliciousActivity,
      daysSinceLastIncident,
    },
  } : undefined;
  
  // ============================================
  // I. BUILD RISK REASONING OUTPUT
  // ============================================
  const riskReasoning: import('@/types').RiskReasoningOutput = {
    drainerContractsInteracted: drainerCheck.drainerContractsInteracted,
    sweepTransactions: sweepCheck.sweepTransactions,
    maliciousContracts: evidence.filter(e => e.code === 'MALICIOUS_CONTRACT_INTERACTION').map(e => e.relatedAddress || '').filter(Boolean),
    firstCompromiseBlock: drainerCheck.firstInteractionBlock,
    firstCompromiseTxHash: drainerCheck.firstInteractionTxHash,
    firstCompromiseTimestamp: drainerCheck.firstInteractionTimestamp,
    affectedChains: [chain],
    permanentFlags: [
      ...(drainerCheck.hasConfirmedDrainerInteraction ? ['CONFIRMED_DRAINER_INTERACTION' as const] : []),
      ...(sweepCheck.assetSweepDetected ? ['ASSET_SWEEP_DETECTED' as const] : []),
      ...(evidence.some(e => e.code === 'MALICIOUS_CONTRACT_INTERACTION') ? ['MALICIOUS_CONTRACT_INTERACTION' as const] : []),
    ],
    whyNotSafe: [
      ...(drainerCheck.hasConfirmedDrainerInteraction ? [`Interacted with confirmed drainer(s): ${drainerCheck.drainerTypes.join(', ')}`] : []),
      ...(sweepCheck.assetSweepDetected ? [`Asset sweep detected: ${sweepCheck.assetsSwept.length} assets drained`] : []),
      ...safetyBlockers,
    ],
  };

  // ============================================
  // DETERMINE FINAL STATUS (with historical awareness)
  // ============================================
  // CRITICAL: If drainer interaction or asset sweep detected, can NEVER be SAFE
  const hasPermanentRiskFlag = drainerCheck.hasConfirmedDrainerInteraction || sweepCheck.assetSweepDetected;
  
  let { status, confidence, summary } = determineSecurityStatusWithHistory(
    evidence,
    reasonCodes,
    safetyChecks,
    safetyBlockers,
    activeThreats,
    historicalThreats,
    historicalCompromise
  );
  
  // ============================================
  // HARD OVERRIDE: DRAINER ACTIVITY DETECTION
  // ============================================
  // This MUST take precedence over ALL other status determinations.
  // If drainerOverride.shouldOverride is TRUE, status MUST be ACTIVE_COMPROMISE_DRAINER.
  // This cannot be bypassed, downgraded, or resolved.
  
  if (drainerOverride.shouldOverride) {
    console.log(`[CompromiseDetector] *** APPLYING HARD OVERRIDE *** Status: ${status} -> ACTIVE_COMPROMISE_DRAINER`);
    status = 'ACTIVE_COMPROMISE_DRAINER';
    confidence = Math.max(confidence, drainerOverride.confidence, 90);
    summary = `ACTIVE WALLET DRAINER DETECTED: ${drainerOverride.detectedSignals.length} drainer behavior signal(s) detected within the last ${drainerOverride.recency.daysSinceLastActivity} days. ` +
      `Signals: ${drainerOverride.detectedSignals.map(s => s.signal).join(', ')}. ` +
      `This classification CANNOT be downgraded to Safe or Previously Compromised while activity exists within 90 days. ` +
      `IMMEDIATE ACTION REQUIRED: Do not send any funds to this wallet.`;
  }
  // SECONDARY OVERRIDE: Permanent risk flags (historical drainer interaction)
  else if (hasPermanentRiskFlag && status === 'SAFE') {
    console.log(`[CompromiseDetector] OVERRIDE: Status was SAFE but permanent risk flags detected - changing to PREVIOUSLY_COMPROMISED`);
    status = 'PREVIOUSLY_COMPROMISED';
    confidence = Math.max(confidence, 70);
    summary = `Previously compromised. ${drainerCheck.hasConfirmedDrainerInteraction ? `Interacted with known drainer(s): ${drainerCheck.drainerTypes.join(', ')}. ` : ''}${sweepCheck.assetSweepDetected ? `Asset sweep detected. ` : ''}Revoked approvals do not erase this history. Wallet cannot be marked SAFE.`;
  }
  // TERTIARY CHECK: If drainer override has signals but not active (>90 days), can be PREVIOUSLY_COMPROMISED
  else if (drainerOverride.detectedSignals.length > 0 && !drainerOverride.recency.isActive) {
    if (status === 'SAFE') {
      console.log(`[CompromiseDetector] Historical drainer activity detected (${drainerOverride.recency.daysSinceLastActivity} days ago) - changing to PREVIOUSLY_COMPROMISED`);
      status = 'PREVIOUSLY_COMPROMISED_NO_ACTIVITY';
      confidence = Math.max(confidence, 50);
      summary = `Previously compromised (resolved). Drainer activity detected ${drainerOverride.recency.daysSinceLastActivity} days ago. ` +
        `No activity in the last 90 days. Wallet may be used with caution but cannot be marked as fully Safe.`;
    }
  }

  // ============================================
  // GENERATE COMPROMISE RESOLUTION INFO
  // ============================================
  // This provides granular sub-status for UI display
  // SECURITY FIX: Pass drainerOverride to ensure ACTIVE_DRAINER_DETECTED is set when appropriate
  const compromiseResolution = generateCompromiseResolutionInfo(
    status,
    activeThreats,
    historicalThreats,
    historicalCompromise,
    hasPermanentRiskFlag,
    daysSinceLastIncident,
    drainerOverride
  );

  return {
    securityStatus: status,
    evidence,
    reasonCodes,
    confidence,
    summary,
    safetyChecks,
    // SECURITY FIX: canBeSafe is FALSE if drainer override detected
    canBeSafe: safetyChecks.allChecksPass && 
               safetyBlockers.length === 0 && 
               activeThreats.length === 0 && 
               !hasPermanentRiskFlag && 
               !drainerOverride.shouldOverride &&
               drainerOverride.canEverBeSafe,
    safetyBlockers,
    historicalCompromise,
    activeThreats,
    historicalThreats,
    riskReasoning,
    compromiseResolution,
    // SECURITY FIX: Include drainer override result for transparency
    drainerOverride,
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
    
    // ============================================
    // FIRST: Skip protected infrastructure entirely
    // ============================================
    const trustInfo = classifyDestinationTrust(spenderNormalized);
    if (trustInfo.isTrusted) {
      console.log(`[analyzeApprovals] Spender ${spenderNormalized.slice(0, 10)}... is trusted (${trustInfo.category}) - skipping`);
      continue;
    }
    
    // Also check infrastructure protection
    const infraCheck = checkInfrastructureProtection(spenderNormalized, 'ethereum');
    if (infraCheck.isProtected) {
      console.log(`[analyzeApprovals] Spender ${spenderNormalized.slice(0, 10)}... is protected infrastructure (${infraCheck.name}) - skipping`);
      continue;
    }
    
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
        isHistorical: false,
        isActiveThreat: true,
      });
      reasonCodes.push('UNLIMITED_APPROVAL_EOA');
      blockers.push(`Unlimited approval to EOA: ${spenderNormalized.slice(0, 10)}...`);
    }

    // CHECK 2: Unlimited approval to unverified contract
    // Only flag if it's NOT a known safe/legitimate contract
    if (approval.isUnlimited && !approval.spenderIsVerified) {
      const isSafe = isSafeContract(spenderNormalized) || 
                     isLegitimateContract(spenderNormalized) || 
                     isDeFiProtocol(spenderNormalized) ||
                     isENSContract(spenderNormalized) ||
                     isInfrastructureContract(spenderNormalized) ||
                     isNFTMarketplace(spenderNormalized);
      
      if (!isSafe) {
        evidence.push({
          code: 'UNLIMITED_APPROVAL_UNVERIFIED',
          severity: 'HIGH',
          description: `Unlimited approval to unverified contract ${spenderNormalized.slice(0, 10)}... for ${approval.tokenSymbol}.`,
          relatedTxHash: approval.transactionHash,
          relatedAddress: spenderNormalized,
          timestamp: new Date(approval.timestamp * 1000).toISOString(),
          confidence: 80,
          isHistorical: false,
          isActiveThreat: true,
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
  // EXCLUDING: NFT mints, legitimate protocol interactions
  const interactedAddresses = new Set<string>();
  
  for (const tx of transactions) {
    // Skip NFT mint transactions - these are ALWAYS legitimate
    if (tx.methodId && isStandardMintMethod(tx.methodId)) {
      console.log(`[CompromiseDetector] Skipping mint transaction to ${tx.to?.slice(0, 10)}...`);
      continue;
    }
    
    // ============================================
    // PAID TRANSACTION = PURCHASE = SAFE
    // ============================================
    // If user is sending value (paying), this is a purchase, NOT drain behavior
    if (isPaidMintTransaction(tx.methodId, tx.value)) {
      console.log(`[CompromiseDetector] Skipping paid transaction to ${tx.to?.slice(0, 10)}... (value: ${tx.value}) - likely purchase`);
      continue;
    }
    
    // Skip NFT mint transactions based on destination, value, and chain
    // CRITICAL: Pass chain to enable Base-specific permissive rules
    if (tx.to && isNFTMintTransaction(tx.to, tx.methodId, BigInt(tx.value || '0'), chain)) {
      console.log(`[CompromiseDetector] Skipping NFT mint to ${tx.to?.slice(0, 10)}... (chain: ${chain})`);
      continue;
    }
    
    // Skip Base NFT activity (broad protection)
    if (chain === 'base' && tx.to && isBaseNFTActivity(tx.to, tx.methodId)) {
      console.log(`[CompromiseDetector] Skipping Base NFT activity to ${tx.to?.slice(0, 10)}...`);
      continue;
    }
    
    if (tx.from.toLowerCase() === walletAddress && tx.to) {
      interactedAddresses.add(tx.to.toLowerCase());
    }
    if (tx.to && tx.to.toLowerCase() === walletAddress) {
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
    // ============================================
    // FALSE POSITIVE PREVENTION: Skip trusted addresses
    // ============================================
    // NFT mint contracts, marketplaces, DEX routers, bridges, etc.
    // should NEVER be flagged as malicious, even if external sources
    // (like GoPlus) have false positive entries for them.
    
    // Skip NFT mint contracts
    if (isNFTMintContract(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - NFT mint contract`);
      continue;
    }
    
    // Skip Base NFT activity (Union Authena, Zora, etc.)
    if (chain === 'base' && isBaseNFTActivity(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - Base NFT activity`);
      continue;
    }
    
    // Skip NFT marketplaces
    if (isNFTMarketplace(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - NFT marketplace`);
      continue;
    }
    
    // Skip DeFi protocols
    if (isDeFiProtocol(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - DeFi protocol`);
      continue;
    }
    
    // Skip ENS contracts
    if (isENSContract(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - ENS contract`);
      continue;
    }
    
    // Skip infrastructure contracts
    if (isInfrastructureContract(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - infrastructure contract`);
      continue;
    }
    
    // Skip safe contracts
    if (isSafeContract(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - safe contract`);
      continue;
    }
    
    // Skip legitimate contracts from malicious-database checks
    if (isLegitimateContract(addr)) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - legitimate contract`);
      continue;
    }
    
    // Skip infrastructure-protected addresses
    const infraCheck = checkInfrastructureProtection(addr, chain);
    if (infraCheck.isProtected) {
      console.log(`[CompromiseDetector] Skipping ${addr.slice(0, 10)}... - protected infrastructure (${infraCheck.name})`);
      continue;
    }
    
    // Now check if it's actually malicious
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
  
  // ============================================
  // HELPER: Check if destination is legitimate
  // ============================================
  const isLegitimateDestination = (address: string): boolean => {
    const normalized = address.toLowerCase();
    
    // Check self-transfer
    if (checkSelfTransfer(walletAddress, normalized).isSelfTransfer) return true;
    
    // Check safe contracts
    if (isSafeContract(normalized)) return true;
    if (isDeFiProtocol(normalized)) return true;
    if (isNFTMarketplace(normalized)) return true;
    if (isNFTMintContract(normalized)) return true;
    if (isENSContract(normalized)) return true;
    if (isInfrastructureContract(normalized)) return true;
    if (isLegitimateContract(normalized)) return true;
    
    // Check Base-specific protocols
    const baseProtocol = checkBaseProtocolInteraction(normalized);
    if (baseProtocol.isLegitimateProtocol) return true;
    
    // Check exchange wallets
    const exchangeCheck = checkExchangeWallet(normalized);
    if (exchangeCheck.isExchange) return true;
    
    return false;
  };

  // Sort transactions by timestamp
  const sortedTxs = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
  const sortedTransfers = [...tokenTransfers].sort((a, b) => a.timestamp - b.timestamp);

  // CHECK 1: Sudden asset outflows shortly after approvals
  // MODIFIED: Only count outflows to UNKNOWN/SUSPICIOUS destinations
  for (const approval of approvals) {
    const outflowsAfterApproval = sortedTransfers.filter(t => {
      const timeDelta = t.timestamp - approval.timestamp;
      // Skip if destination is legitimate
      if (isLegitimateDestination(t.to)) return false;
      
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
  // MODIFIED: Only consider outflows to UNKNOWN/SUSPICIOUS destinations
  const outgoingTransfers = sortedTransfers.filter(t => {
    if (t.from.toLowerCase() !== walletAddress) return false;
    // Skip legitimate destinations
    if (isLegitimateDestination(t.to)) return false;
    return true;
  });
  
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
// CONFIRMED DRAINER INTERACTION CHECK
// ============================================
// If wallet has EVER interacted with a confirmed drainer → NEVER SAFE
// This includes Pink, Angel, Inferno, MS, Monkey drainers, etc.
// Revoked approvals do NOT erase this history.

interface DrainerInteractionResult {
  hasConfirmedDrainerInteraction: boolean;
  drainerContractsInteracted: string[];
  firstInteractionTxHash?: string;
  firstInteractionBlock?: number;
  firstInteractionTimestamp?: string;
  drainerTypes: string[];
}

function checkConfirmedDrainerInteraction(
  transactions: TransactionForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[],
  approvals: ApprovalForAnalysis[],
  chain: Chain
): DrainerInteractionResult {
  const drainerContractsInteracted: string[] = [];
  const drainerTypes: string[] = [];
  let firstInteractionTxHash: string | undefined;
  let firstInteractionBlock: number | undefined;
  let firstInteractionTimestamp: string | undefined;
  
  // Check all transactions for drainer interactions
  for (const tx of transactions) {
    const toAddr = tx.to?.toLowerCase();
    const fromAddr = tx.from?.toLowerCase();
    
    // Check if interacting with known drainer
    if (toAddr) {
      const drainerInfo = isMaliciousAddress(toAddr, chain);
      const isDrainer = drainerInfo !== null || isDrainerRecipient(toAddr);
      
      if (isDrainer && !drainerContractsInteracted.includes(toAddr)) {
        drainerContractsInteracted.push(toAddr);
        if (drainerInfo?.name) drainerTypes.push(drainerInfo.name);
        
        if (!firstInteractionTxHash || tx.blockNumber < (firstInteractionBlock || Infinity)) {
          firstInteractionTxHash = tx.hash;
          firstInteractionBlock = tx.blockNumber;
          firstInteractionTimestamp = tx.timestamp ? new Date(tx.timestamp * 1000).toISOString() : undefined;
        }
      }
    }
  }
  
  // Check all token transfers for drainer destinations
  for (const transfer of tokenTransfers) {
    const toAddr = transfer.to?.toLowerCase();
    
    if (toAddr) {
      const drainerInfo = isMaliciousAddress(toAddr, chain);
      const isDrainer = drainerInfo !== null || isDrainerRecipient(toAddr);
      
      if (isDrainer && !drainerContractsInteracted.includes(toAddr)) {
        drainerContractsInteracted.push(toAddr);
        if (drainerInfo?.name) drainerTypes.push(drainerInfo.name);
        
        if (!firstInteractionTxHash) {
          firstInteractionTxHash = transfer.hash;
          firstInteractionTimestamp = transfer.timestamp ? new Date(transfer.timestamp * 1000).toISOString() : undefined;
        }
      }
    }
  }
  
  // Check all approvals for drainer spenders
  for (const approval of approvals) {
    const spenderAddr = approval.spender?.toLowerCase();
    
    if (spenderAddr) {
      const drainerInfo = isMaliciousAddress(spenderAddr, chain);
      const isDrainer = drainerInfo !== null || isDrainerRecipient(spenderAddr);
      
      if (isDrainer && !drainerContractsInteracted.includes(spenderAddr)) {
        drainerContractsInteracted.push(spenderAddr);
        if (drainerInfo?.name) drainerTypes.push(drainerInfo.name);
        
        if (!firstInteractionTxHash || approval.blockNumber < (firstInteractionBlock || Infinity)) {
          firstInteractionTxHash = approval.transactionHash;
          firstInteractionBlock = approval.blockNumber;
        }
      }
    }
  }
  
  return {
    hasConfirmedDrainerInteraction: drainerContractsInteracted.length > 0,
    drainerContractsInteracted,
    firstInteractionTxHash,
    firstInteractionBlock,
    firstInteractionTimestamp,
    drainerTypes: [...new Set(drainerTypes)],
  };
}

// ============================================
// ASSET SWEEP DETECTION
// ============================================
// Detects rapid multi-asset outflows:
// - ERC20 + NFTs drained within ≤3 blocks
// - Assets sent to fresh/burner addresses
// - No inbound value to compensate

interface AssetSweepResult {
  assetSweepDetected: boolean;
  sweepTransactions: string[];
  sweepBlockRange?: { start: number; end: number };
  assetsSwept: { type: 'ERC20' | 'NFT'; symbol?: string; amount?: string }[];
  sweepDestination?: string;
}

function detectAssetSweep(
  transactions: TransactionForAnalysis[],
  tokenTransfers: TokenTransferForAnalysis[],
  walletAddress: string
): AssetSweepResult {
  const normalized = walletAddress.toLowerCase();
  const sweepTransactions: string[] = [];
  const assetsSwept: { type: 'ERC20' | 'NFT'; symbol?: string; amount?: string }[] = [];
  
  // Group outbound transfers by block
  const outboundByBlock = new Map<number, TokenTransferForAnalysis[]>();
  
  for (const transfer of tokenTransfers) {
    if (transfer.from?.toLowerCase() !== normalized) continue;
    
    const block = transfer.blockNumber || 0;
    if (!outboundByBlock.has(block)) {
      outboundByBlock.set(block, []);
    }
    outboundByBlock.get(block)!.push(transfer);
  }
  
  // Sort blocks
  const sortedBlocks = [...outboundByBlock.keys()].sort((a, b) => a - b);
  
  // Look for rapid multi-asset outflows within ≤3 blocks
  for (let i = 0; i < sortedBlocks.length; i++) {
    const startBlock = sortedBlocks[i];
    const endBlockIndex = sortedBlocks.findIndex(b => b > startBlock + 3);
    const endIndex = endBlockIndex === -1 ? sortedBlocks.length : endBlockIndex;
    
    // Collect all transfers within 3 blocks
    const windowTransfers: TokenTransferForAnalysis[] = [];
    const destinations = new Set<string>();
    
    for (let j = i; j < endIndex; j++) {
      const transfers = outboundByBlock.get(sortedBlocks[j]) || [];
      windowTransfers.push(...transfers);
      transfers.forEach(t => {
        if (t.to) destinations.add(t.to.toLowerCase());
      });
    }
    
    // Check if this looks like a sweep:
    // - Multiple different assets (≥2 unique tokens)
    // - Same or few destinations (≤2)
    // - No inbound value in same window
    const uniqueTokens = new Set(windowTransfers.map(t => t.tokenAddress?.toLowerCase()));
    
    if (uniqueTokens.size >= 2 && destinations.size <= 2 && windowTransfers.length >= 2) {
      // This looks like an asset sweep
      for (const transfer of windowTransfers) {
        if (!sweepTransactions.includes(transfer.hash)) {
          sweepTransactions.push(transfer.hash);
        }
        assetsSwept.push({
          type: transfer.tokenType === 'ERC721' || transfer.tokenType === 'ERC1155' ? 'NFT' : 'ERC20',
          symbol: transfer.tokenSymbol,
          amount: transfer.value,
        });
      }
      
      return {
        assetSweepDetected: true,
        sweepTransactions,
        sweepBlockRange: { start: startBlock, end: sortedBlocks[endIndex - 1] || startBlock },
        assetsSwept,
        sweepDestination: [...destinations][0],
      };
    }
  }
  
  return {
    assetSweepDetected: false,
    sweepTransactions: [],
    assetsSwept: [],
  };
}

// ============================================
// GENERATE COMPROMISE RESOLUTION INFO
// ============================================
// Provides granular sub-status for "Previously Compromised" wallets
// These are INFORMATIONAL badges - they do NOT affect risk score

function generateCompromiseResolutionInfo(
  status: SecurityStatus,
  activeThreats: CompromiseEvidence[],
  historicalThreats: CompromiseEvidence[],
  historicalCompromise: CompromiseAnalysisResult['historicalCompromise'],
  hasPermanentRiskFlag: boolean,
  daysSinceLastIncident?: number,
  drainerOverride?: DrainerOverrideResult
): import('@/types').CompromiseResolutionInfo {
  const hasHistoricalCompromise = historicalThreats.length > 0 || hasPermanentRiskFlag || historicalCompromise?.hasHistoricalIncident;
  const hasActiveThreats = activeThreats.length > 0;
  
  // Default values
  const remediation = historicalCompromise?.remediationStatus;
  const allApprovalsRevoked = remediation?.allApprovalsRevoked ?? true;
  const noActiveMaliciousContracts = remediation?.noActiveDrainerAccess ?? true;
  const noOngoingAutomatedOutflows = remediation?.noOngoingDrains ?? true;
  
  // SECURITY FIX: Use 90 days threshold instead of 30 days
  const RECENT_ACTIVITY_THRESHOLD_DAYS = 90;
  const noRecentSweeperActivity = !daysSinceLastIncident || daysSinceLastIncident > RECENT_ACTIVITY_THRESHOLD_DAYS;
  
  // ============================================
  // DETERMINE SUB-STATUS
  // ============================================
  // SECURITY FIX: ACTIVE_DRAINER_DETECTED has HIGHEST priority
  let subStatus: import('@/types').CompromiseSubStatus;
  
  // HARD RULE: If drainer override is active, sub-status MUST be ACTIVE_DRAINER_DETECTED
  if (drainerOverride?.shouldOverride) {
    subStatus = 'ACTIVE_DRAINER_DETECTED';
  } else if (!hasHistoricalCompromise && !hasActiveThreats && !drainerOverride?.detectedSignals.length) {
    // No compromise history at all
    subStatus = 'NONE';
  } else if (hasActiveThreats || (drainerOverride?.recency?.isActive && drainerOverride?.detectedSignals?.length > 0)) {
    // Currently compromised with active threats OR active drainer signals
    subStatus = 'ACTIVE_THREAT';
  } else if (
    hasHistoricalCompromise &&
    allApprovalsRevoked &&
    noActiveMaliciousContracts &&
    noRecentSweeperActivity &&
    noOngoingAutomatedOutflows &&
    (!drainerOverride || !drainerOverride.recency.isActive)
  ) {
    // Fully resolved: all conditions met AND ≥90 days since drainer activity
    subStatus = 'RESOLVED';
  } else if (hasHistoricalCompromise && !hasActiveThreats) {
    // Historical compromise, no active threats, but not fully resolved
    // (e.g., activity within 90 days)
    subStatus = 'NO_ACTIVE_RISK';
  } else {
    subStatus = 'NONE';
  }
  
  // ============================================
  // GENERATE DISPLAY BADGE
  // ============================================
  const displayBadge = generateDisplayBadge(subStatus, daysSinceLastIncident);
  
  // ============================================
  // GENERATE TOOLTIP AND EXPLANATION
  // ============================================
  const { tooltipText, explanation } = generateCompromiseMessages(
    subStatus,
    allApprovalsRevoked,
    noActiveMaliciousContracts,
    noRecentSweeperActivity,
    daysSinceLastIncident
  );
  
  return {
    subStatus,
    historical_compromise: hasHistoricalCompromise,
    active_threats: hasActiveThreats,
    compromise_resolved_at: subStatus === 'RESOLVED' && remediation?.lastMaliciousActivity
      ? remediation.lastMaliciousActivity
      : undefined,
    resolution: {
      allApprovalsRevoked,
      noActiveMaliciousContracts,
      noRecentSweeperActivity,
      noOngoingAutomatedOutflows,
      daysSinceLastMaliciousActivity: daysSinceLastIncident,
      lastMaliciousActivityTimestamp: remediation?.lastMaliciousActivity,
    },
    displayBadge,
    tooltipText,
    explanation,
  };
}

function generateDisplayBadge(
  subStatus: import('@/types').CompromiseSubStatus,
  daysSinceLastIncident?: number
): import('@/types').CompromiseDisplayBadge {
  switch (subStatus) {
    // SECURITY FIX: New highest priority badge for active drainer
    case 'ACTIVE_DRAINER_DETECTED':
      return {
        text: 'ACTIVE WALLET DRAINER',
        variant: 'danger',
        icon: 'alert-circle',
        colorScheme: 'red',
      };
    
    case 'RESOLVED':
      return {
        text: 'Previously Compromised (Resolved)',
        variant: 'informational',
        icon: 'shield-check',
        colorScheme: 'gray',
      };
    
    case 'NO_ACTIVE_RISK':
      return {
        text: 'Previously Compromised (No Active Risk)',
        variant: 'neutral',
        icon: 'info',
        colorScheme: 'blue',
      };
    
    case 'ACTIVE_THREAT':
      return {
        text: 'Actively Compromised',
        variant: 'danger',
        icon: 'alert-circle',
        colorScheme: 'red',
      };
    
    case 'NONE':
    default:
      return {
        text: 'Clean',
        variant: 'informational',
        icon: 'shield-check',
        colorScheme: 'gray',
      };
  }
}

function generateCompromiseMessages(
  subStatus: import('@/types').CompromiseSubStatus,
  allApprovalsRevoked: boolean,
  noActiveMaliciousContracts: boolean,
  noRecentSweeperActivity: boolean,
  daysSinceLastIncident?: number
): { tooltipText: string; explanation: string } {
  switch (subStatus) {
    // SECURITY FIX: New highest priority message for active drainer
    case 'ACTIVE_DRAINER_DETECTED':
      return {
        tooltipText: 'CRITICAL: This wallet exhibits ACTIVE WALLET DRAINER behavior. DO NOT SEND ANY FUNDS to this address.',
        explanation: `ACTIVE WALLET DRAINER DETECTED. This wallet shows active drainer behavior patterns within the last ${daysSinceLastIncident || 'few'} days. ` +
          'This includes: immediate outbound transfers after receiving funds, token sweep patterns, or drain routing to aggregation hubs. ' +
          'This classification CANNOT be downgraded until at least 90 days of NO suspicious activity. ' +
          'DO NOT INTERACT WITH THIS WALLET.',
      };
    
    case 'RESOLVED':
      return {
        tooltipText: 'All known malicious access has been revoked. This wallet was compromised in the past but currently shows no active threats (≥90 days).',
        explanation: `No active threats detected. This wallet had past security incidents which appear resolved.${daysSinceLastIncident ? ` Last incident was ${daysSinceLastIncident} days ago.` : ''} All malicious approvals have been revoked and no ongoing suspicious activity is detected for ≥90 days.`,
      };
    
    case 'NO_ACTIVE_RISK':
      return {
        tooltipText: 'This wallet was compromised in the past but currently shows no active threats. Continue to monitor for any unusual activity.',
        explanation: `No active threats detected. This wallet had past security incidents.${!noRecentSweeperActivity ? ' Some activity was detected within the last 90 days - continue monitoring.' : ''} The wallet is currently safe to use but should be monitored.`,
      };
    
    case 'ACTIVE_THREAT':
      return {
        tooltipText: 'This wallet has active security threats that require immediate attention.',
        explanation: `Active threats detected. ${!allApprovalsRevoked ? 'Malicious approvals are still active. ' : ''}${!noActiveMaliciousContracts ? 'Active malicious contracts detected. ' : ''}Immediate action is required to secure this wallet.`,
      };
    
    case 'NONE':
    default:
      return {
        tooltipText: 'No security issues detected.',
        explanation: 'This wallet shows no signs of compromise or security issues.',
      };
  }
}

// ============================================
// DETERMINE FINAL STATUS WITH HISTORICAL AWARENESS
// ============================================
// Key distinction:
// - ACTIVE_COMPROMISE_DRAINER: *** HIGHEST PRIORITY *** Active drainer behavior (<90 days)
// - ACTIVELY_COMPROMISED: Ongoing threat (active approvals, drainer access, ongoing drains)
// - PREVIOUSLY_COMPROMISED_NO_ACTIVITY: Historical drainer activity, ≥90 days no signals
// - PREVIOUSLY_COMPROMISED: Historical incident but threat remediated
// - SAFE: No history of compromise
//
// CRITICAL RULES (SECURITY FIX 2024-01):
// 1. If wallet has ANY drainer signal within 90 days, it MUST be ACTIVE_COMPROMISE_DRAINER
// 2. ACTIVE_COMPROMISE_DRAINER can NEVER be downgraded to Safe or Previously Compromised
// 3. Only wallets with ≥90 days of NO drainer activity can be PREVIOUSLY_COMPROMISED_NO_ACTIVITY
// 4. Wallets with drainer history can NEVER be marked SAFE

function determineSecurityStatusWithHistory(
  evidence: CompromiseEvidence[],
  reasonCodes: CompromiseReasonCode[],
  safetyChecks: SafetyCheckResults,
  safetyBlockers: string[],
  activeThreats: CompromiseEvidence[],
  historicalThreats: CompromiseEvidence[],
  historicalCompromise?: CompromiseAnalysisResult['historicalCompromise']
): { status: SecurityStatus; confidence: number; summary: string } {
  
  // ============================================
  // RULE 1: ACTIVE THREATS = ACTIVELY_COMPROMISED
  // ============================================
  // A wallet should be marked ACTIVELY_COMPROMISED only if:
  // - Active unlimited or high-risk approval exists
  // - Known drainer contract still has allowance
  // - Automated outflows continue without user initiation
  
  if (activeThreats.length > 0) {
    const criticalActive = activeThreats.filter(e => e.severity === 'CRITICAL').length;
    const highActive = activeThreats.filter(e => e.severity === 'HIGH').length;
    
    if (criticalActive >= 1) {
      return {
        status: 'ACTIVELY_COMPROMISED',
        confidence: 95,
        summary: `ACTIVELY COMPROMISED: ${criticalActive} critical active threat(s). Immediate action required - revoke approvals and secure assets.`,
      };
    }
    
    if (highActive >= 1) {
      return {
        status: 'ACTIVELY_COMPROMISED',
        confidence: 85,
        summary: `ACTIVELY COMPROMISED: ${highActive} high-severity active threat(s). Review and revoke suspicious approvals immediately.`,
      };
    }
    
    // Medium/low active threats = AT_RISK
    return {
      status: 'AT_RISK',
      confidence: 70,
      summary: `At Risk: ${activeThreats.length} active concern(s) detected. Review the flagged items and take action if needed.`,
    };
  }
  
  // ============================================
  // RULE 2: HISTORICAL THREATS ONLY = PREVIOUSLY_COMPROMISED
  // ============================================
  // If historical exploit occurred but:
  // - All related approvals are revoked
  // - No malicious allowance remains
  // - No follow-up draining behavior exists
  // Then: PREVIOUSLY_COMPROMISED (NO ACTIVE THREAT)
  //
  // IMPORTANT: Only count MEDIUM/HIGH/CRITICAL severity as real threats
  // LOW severity is informational only and should NOT trigger this status
  
  const significantHistoricalThreats = historicalThreats.filter(t => 
    t.severity === 'CRITICAL' || t.severity === 'HIGH' || t.severity === 'MEDIUM'
  );
  
  if (significantHistoricalThreats.length > 0 && historicalCompromise) {
    const remediation = historicalCompromise.remediationStatus;
    const isFullyRemediated = remediation.allApprovalsRevoked && 
                              remediation.noActiveDrainerAccess && 
                              remediation.noOngoingDrains;
    
    if (isFullyRemediated) {
      const daysSince = remediation.daysSinceLastIncident || 0;
      const incidentCount = historicalCompromise.incidents.length;
      
      // Calculate decayed risk based on time since incident
      // Risk decays over time: 90% after 7 days, 50% after 30 days, 20% after 90 days
      let decayedConfidence = 60;
      if (daysSince > 90) decayedConfidence = 20;
      else if (daysSince > 30) decayedConfidence = 35;
      else if (daysSince > 7) decayedConfidence = 50;
      
      return {
        status: 'PREVIOUSLY_COMPROMISED',
        confidence: decayedConfidence,
        summary: `Previously compromised. No active malicious access detected. ${incidentCount > 0 ? `Historical incident${incidentCount > 1 ? 's' : ''} detected but all threats have been remediated.` : ''} ${daysSince > 0 ? `Last incident: ${daysSince} days ago.` : ''} Safe to use with caution.`,
      };
    } else {
      // Not fully remediated - still has active elements
      return {
        status: 'AT_RISK',
        confidence: 75,
        summary: `Historical compromise detected with incomplete remediation. Review: ${!remediation.allApprovalsRevoked ? 'Malicious approvals still active. ' : ''}${!remediation.noOngoingDrains ? 'Recent drain activity detected.' : ''}`,
      };
    }
  }
  
  // ============================================
  // RULE 3: CHECK FOR ANY HISTORICAL INCIDENTS WITHOUT ACTIVE THREATS
  // ============================================
  // Only trigger PREVIOUSLY_COMPROMISED if there are significant historical threats
  // LOW severity evidence alone should NOT trigger this status
  if (significantHistoricalThreats.length > 0 && historicalCompromise?.hasHistoricalIncident && !historicalCompromise.isCurrentlyActive) {
    const daysSince = historicalCompromise.remediationStatus.daysSinceLastIncident || 0;
    
    return {
      status: 'PREVIOUSLY_COMPROMISED',
      confidence: daysSince > 30 ? 30 : 50,
      summary: `Previously compromised. All malicious access has been revoked. ${daysSince > 0 ? `No suspicious activity in ${daysSince} days.` : ''} Wallet is currently safe to use.`,
    };
  }
  
  // ============================================
  // RULE 4: NO THREATS = SAFE
  // ============================================
  if (evidence.length === 0 && safetyBlockers.length === 0) {
    return {
      status: 'SAFE',
      confidence: 95,
      summary: 'No risk indicators detected. Wallet appears safe based on available data.',
    };
  }
  
  // ============================================
  // RULE 5: FALLBACK - USE ORIGINAL LOGIC FOR EDGE CASES
  // ============================================
  return determineSecurityStatus(evidence, reasonCodes, safetyChecks, safetyBlockers);
}

// ============================================
// COMPROMISE RESOLUTION LOGIC
// ============================================
// Determines if a previously compromised wallet has been resolved
// and assigns appropriate sub-status for UI display

import type { 
  CompromiseResolutionInfo, 
  CompromiseSubStatus, 
  CompromiseDisplayBadge,
  HistoricalCompromiseInfo 
} from '@/types';

// Time thresholds for resolution determination
const DAYS_SINCE_LAST_INCIDENT_THRESHOLD = 30; // 30 days minimum for "Resolved"
const DAYS_SINCE_LAST_INCIDENT_SAFE_THRESHOLD = 60; // 60 days for high confidence "Resolved"

/**
 * Determine the compromise resolution status for a wallet.
 * This provides granular sub-status for "Previously Compromised" wallets.
 * 
 * RULES:
 * - "Resolved": All approvals revoked, no active contracts, 30-60+ days since incident
 * - "No Active Risk": Historical compromise, no active threats, should be monitored
 * - "Active Threat": Currently compromised with active threat vectors
 */
export function determineCompromiseResolution(
  hasHistoricalCompromise: boolean,
  activeThreats: CompromiseEvidence[],
  historicalThreats: CompromiseEvidence[],
  approvals: ApprovalForAnalysis[],
  lastMaliciousActivityTimestamp?: string
): CompromiseResolutionInfo {
  const now = Date.now();
  
  // Calculate days since last incident
  let daysSinceLastMaliciousActivity: number | undefined;
  if (lastMaliciousActivityTimestamp) {
    const lastIncidentTime = new Date(lastMaliciousActivityTimestamp).getTime();
    daysSinceLastMaliciousActivity = Math.floor((now - lastIncidentTime) / (24 * 60 * 60 * 1000));
  }
  
  // Check if all malicious approvals are revoked
  const maliciousApprovals = approvals.filter(a => {
    const isMalicious = isMaliciousAddress(a.spender.toLowerCase(), 'ethereum') || 
                        isDrainerRecipient(a.spender.toLowerCase());
    return isMalicious;
  });
  
  const allApprovalsRevoked = maliciousApprovals.every(a => {
    const allowance = BigInt(a.amount || '0');
    return allowance === BigInt(0);
  }) || maliciousApprovals.length === 0;
  
  // Check for active malicious contracts
  const noActiveMaliciousContracts = activeThreats.length === 0;
  
  // Check for recent sweeper/drainer activity (within 30-60 days)
  const noRecentSweeperActivity = daysSinceLastMaliciousActivity === undefined || 
                                   daysSinceLastMaliciousActivity >= DAYS_SINCE_LAST_INCIDENT_THRESHOLD;
  
  // Check for ongoing automated outflows
  const noOngoingAutomatedOutflows = !activeThreats.some(t => 
    t.code === 'SWEEPER_PATTERN' || t.code === 'AUTOMATED_OUTFLOW'
  );
  
  // ============================================
  // DETERMINE SUB-STATUS
  // ============================================
  
  let subStatus: CompromiseSubStatus;
  let displayBadge: CompromiseDisplayBadge;
  let tooltipText: string;
  let explanation: string;
  
  // CASE 1: No historical compromise
  if (!hasHistoricalCompromise && activeThreats.length === 0 && historicalThreats.length === 0) {
    subStatus = 'NONE';
    displayBadge = {
      text: 'Clean',
      variant: 'neutral',
      icon: 'shield-check',
      colorScheme: 'gray',
    };
    tooltipText = 'No security incidents detected in this wallet\'s history.';
    explanation = 'No active threats detected. Wallet history shows no security incidents.';
  }
  // CASE 2: Active threats exist
  else if (activeThreats.length > 0) {
    subStatus = 'ACTIVE_THREAT';
    displayBadge = {
      text: 'Active Threat',
      variant: 'danger',
      icon: 'alert-circle',
      colorScheme: 'red',
    };
    tooltipText = 'This wallet has active security threats that require immediate attention.';
    explanation = `Active compromise detected: ${activeThreats.length} active threat(s) found. Immediate action required.`;
  }
  // CASE 3: Previously Compromised (Resolved)
  else if (
    hasHistoricalCompromise &&
    allApprovalsRevoked &&
    noActiveMaliciousContracts &&
    noRecentSweeperActivity &&
    noOngoingAutomatedOutflows &&
    daysSinceLastMaliciousActivity !== undefined &&
    daysSinceLastMaliciousActivity >= DAYS_SINCE_LAST_INCIDENT_THRESHOLD
  ) {
    subStatus = 'RESOLVED';
    displayBadge = {
      text: 'Previously Compromised (Resolved)',
      variant: 'informational',
      icon: 'shield-check',
      colorScheme: 'blue',
    };
    tooltipText = 'This wallet was compromised in the past but currently shows no active threats. All known malicious access has been revoked.';
    explanation = `No active threats detected. This wallet had past security incidents which appear resolved. Last incident was ${daysSinceLastMaliciousActivity} days ago.`;
  }
  // CASE 4: Previously Compromised (No Active Risk)
  else if (
    hasHistoricalCompromise &&
    noActiveMaliciousContracts &&
    noOngoingAutomatedOutflows
  ) {
    subStatus = 'NO_ACTIVE_RISK';
    displayBadge = {
      text: 'Previously Compromised (No Active Risk)',
      variant: 'informational',
      icon: 'info',
      colorScheme: 'blue',
    };
    tooltipText = 'This wallet was compromised in the past but currently shows no active threats. Continued monitoring is recommended.';
    
    const timeMessage = daysSinceLastMaliciousActivity !== undefined
      ? `Last incident was ${daysSinceLastMaliciousActivity} days ago.`
      : 'Incident timing unknown.';
    
    explanation = `No active threats detected. This wallet had past security incidents. ${timeMessage} Monitoring recommended.`;
  }
  // CASE 5: Fallback - treat as having historical compromise but uncertain status
  else {
    subStatus = 'NO_ACTIVE_RISK';
    displayBadge = {
      text: 'Previously Compromised (No Active Risk)',
      variant: 'informational',
      icon: 'info',
      colorScheme: 'blue',
    };
    tooltipText = 'This wallet was compromised in the past but currently shows no active threats.';
    explanation = 'No active threats detected. This wallet had past security incidents which appear resolved.';
  }
  
  // Build resolution info
  const resolutionInfo: CompromiseResolutionInfo = {
    subStatus,
    historical_compromise: hasHistoricalCompromise || historicalThreats.length > 0,
    active_threats: activeThreats.length > 0,
    compromise_resolved_at: subStatus === 'RESOLVED' ? new Date().toISOString() : undefined,
    resolution: {
      allApprovalsRevoked,
      noActiveMaliciousContracts,
      noRecentSweeperActivity,
      noOngoingAutomatedOutflows,
      daysSinceLastMaliciousActivity,
      lastMaliciousActivityTimestamp,
    },
    displayBadge,
    tooltipText,
    explanation,
  };
  
  return resolutionInfo;
}

/**
 * Build historical compromise info from evidence
 */
export function buildHistoricalCompromiseInfo(
  historicalThreats: CompromiseEvidence[],
  activeThreats: CompromiseEvidence[],
  chain: Chain
): HistoricalCompromiseInfo {
  const hasHistoricalCompromise = historicalThreats.length > 0;
  const isCurrentlyActive = activeThreats.length > 0;
  
  // Convert evidence to incidents
  const incidents = historicalThreats.map(ev => ({
    type: mapEvidenceCodeToIncidentType(ev.code),
    timestamp: ev.timestamp || new Date().toISOString(),
    txHash: ev.relatedTxHash || '',
    maliciousAddress: ev.relatedAddress || '',
    maliciousContractName: undefined,
    chain,
    approvalStillActive: ev.isActiveThreat || false,
    explanation: ev.description,
  }));
  
  // Find remediation status
  const allRevoked = historicalThreats.every(t => t.wasRemediated);
  const lastMaliciousActivity = historicalThreats
    .filter(t => t.timestamp)
    .map(t => new Date(t.timestamp!).getTime())
    .sort((a, b) => b - a)[0];
  
  const daysSinceLastIncident = lastMaliciousActivity
    ? Math.floor((Date.now() - lastMaliciousActivity) / (24 * 60 * 60 * 1000))
    : undefined;
  
  return {
    hasHistoricalCompromise,
    incidents,
    isCurrentlyActive,
    remediationStatus: {
      allApprovalsRevoked: allRevoked,
      noActiveDrainerAccess: !isCurrentlyActive,
      noOngoingDrains: !activeThreats.some(t => t.code === 'SWEEPER_PATTERN'),
      lastMaliciousActivity: lastMaliciousActivity ? new Date(lastMaliciousActivity).toISOString() : undefined,
      daysSinceLastIncident,
    },
  };
}

function mapEvidenceCodeToIncidentType(code: CompromiseReasonCode): 'AIRDROP_DRAIN' | 'APPROVAL_EXPLOIT' | 'PHISHING' | 'SWEEPER_ATTACK' | 'UNKNOWN' {
  switch (code) {
    case 'AIRDROP_DRAIN':
    case 'AIRDROP_FOLLOWED_BY_DRAIN':
      return 'AIRDROP_DRAIN';
    case 'MALICIOUS_APPROVAL':
    case 'UNLIMITED_APPROVAL_TO_UNKNOWN':
    case 'MULTIPLE_UNLIMITED_APPROVALS':
      return 'APPROVAL_EXPLOIT';
    case 'SWEEPER_PATTERN':
    case 'SWEEPER_BOT_DETECTED':
      return 'SWEEPER_ATTACK';
    default:
      return 'UNKNOWN';
  }
}

// ============================================
// EXPORTS
// ============================================

export {
  analyzeWalletCompromise as default,
  RAPID_DRAIN_WINDOW_SECONDS,
  MULTI_ASSET_DRAIN_WINDOW_SECONDS,
  UNLIMITED_APPROVAL_THRESHOLD,
  isApprovalStillActive,
  classifyThreatTiming,
  detectAirdropDrainIncident,
  // determineCompromiseResolution and buildHistoricalCompromiseInfo are exported inline
};

// Re-export address normalization for convenience
export { normalizeAddress } from './drainer-activity-detector';

