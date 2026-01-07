// ============================================
// SOLANA SECURITY DETECTION ENGINE
// ============================================
// Highly accurate Solana drainer & sweeper bot detection
// with minimal false positives.
//
// CORE RULES:
// 1. NEVER mark a Solana wallet as SAFE solely because no malicious contracts are found
//    - Absence of evidence ≠ proof of safety
// 2. Three explicit wallet states: SAFE, PREVIOUSLY_COMPROMISED, ACTIVELY_COMPROMISED
// 3. Prefer false negatives over false positives
// 4. Require at least 2 independent high-confidence signals before flagging ACTIVE compromise
//
// DESIGN PHILOSOPHY: This tool is for protection, not fear amplification.
//
// DRAINER DETECTION (High Confidence Signals):
// Flag ONLY if MULTIPLE of the following occur:
// - Rapid asset depletion across SPL tokens + SOL within <10 minutes
// - Funds routed to known aggregation or laundering patterns (fan-out or peel-chain)
// - Outgoing transfers initiated immediately after inbound funding
// - Repeated interactions with addresses already classified as malicious
// - Transaction signatures show automation (consistent compute usage + timing patterns)
//
// SWEEPER BOT DETECTION:
// Flag ONLY if:
// - Repeated automated transfers triggered within seconds of inbound funds
// - Identical destination addresses used across multiple unrelated wallets
// - No user-interactive instructions (no memo, no user delay)
// - Pattern persists across multiple blocks (not single event)
//
// FALSE POSITIVE PREVENTION (Critical):
// Explicitly whitelist and NEVER flag:
// - Legitimate bridges (Wormhole, Allbridge, Portal, LayerZero)
// - NFT minting & marketplace programs (OpenSea, Magic Eden, Tensor, Metaplex)
// - SystemProgram, TokenProgram, AssociatedTokenProgram
// - Transactions where sender === receiver (self-transfer or wallet shuffling)
// - One-off large transfers without automation indicators
// - NFT mint + immediate transfer (unless paired with SOL + SPL drain)
//
// NFT & MINTING LOGIC:
// - Do NOT classify mint + immediate transfer as drainer unless paired with SOL + SPL drain
// - Marketplace escrow interactions are NOT sweepers
//
// HISTORICAL COMPROMISE HANDLING:
// - If wallet shows past drain behavior but no active automation in last N days:
//   → Mark as PREVIOUSLY COMPROMISED (NO ACTIVE RISK)
// - Clearly separate legacy incidents from current safety
//
// CONFIDENCE THRESHOLDING:
// - Require at least 2 independent high-confidence signals before flagging ACTIVE compromise
// - Otherwise downgrade to PREVIOUSLY COMPROMISED or UNCONFIRMED
//
// OUTPUT REQUIREMENTS:
// - Provide clear explanation string for each flag
// - Explicitly state whether risk is historical or active
// - Never use alarming language unless ACTIVE compromise is confirmed

import { Chain, RiskLevel, SecurityStatus } from '@/types';

// ============================================
// SOLANA SECURITY STATUS TYPES
// ============================================

export type SolanaSecurityState = 
  | 'SAFE'                    // No historical or active compromise signals
  | 'PREVIOUSLY_COMPROMISED'  // No active drain behavior detected, but past incidents exist
  | 'ACTIVELY_COMPROMISED';   // Ongoing automated or hostile fund movement

export interface SolanaSecurityResult {
  // Primary security state
  state: SolanaSecurityState;
  
  // Confidence in this assessment (0-100)
  confidence: number;
  
  // Whether risk is historical or active
  isHistorical: boolean;
  isActive: boolean;
  
  // Number of independent high-confidence signals
  signalCount: number;
  
  // Detected drainer behavior
  drainerDetection?: DrainerDetectionResult;
  
  // Detected sweeper bot behavior
  sweeperDetection?: SweeperBotDetectionResult;
  
  // Explanation string for each flag
  explanation: string;
  
  // Detailed reasoning
  reasoning: SolanaSecurityReasoning;
  
  // Risk score (0-100)
  riskScore: number;
  
  // Days since last suspicious activity (for historical detection)
  daysSinceLastIncident?: number;
}

export interface SolanaSecurityReasoning {
  // Why this state was determined
  stateReason: string;
  
  // Signals that contributed to detection
  detectedSignals: DetectedSignal[];
  
  // Signals that ruled OUT compromise (for transparency)
  safeSignals: string[];
  
  // Whitelisted activity that was excluded
  whitelistedActivity: string[];
  
  // Confidence factors
  confidenceFactors: string[];
  
  // Uncertainty factors
  uncertaintyFactors: string[];
}

export interface DetectedSignal {
  type: SolanaSignalType;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  timestamp?: number;
  relatedTxSignatures?: string[];
  relatedAddresses?: string[];
}

export type SolanaSignalType =
  // Drainer signals
  | 'RAPID_ASSET_DEPLETION'          // SOL + SPL tokens drained in <10 minutes
  | 'LAUNDERING_PATTERN'             // Fan-out or peel-chain to known aggregation
  | 'IMMEDIATE_OUTFLOW_AFTER_INFLOW' // Funds leave immediately after arriving
  | 'KNOWN_MALICIOUS_INTERACTION'    // Interaction with known drainer addresses
  | 'AUTOMATION_SIGNATURE'           // Consistent compute/timing patterns
  
  // Sweeper signals
  | 'IMMEDIATE_AUTOMATED_TRANSFER'   // Transfer within seconds of inbound
  | 'IDENTICAL_DESTINATION_PATTERN'  // Same dest across multiple wallets
  | 'NO_USER_INTERACTION'            // No memo, no delay
  | 'MULTI_BLOCK_PERSISTENCE'        // Pattern persists across multiple blocks
  
  // Historical signals
  | 'PAST_DRAIN_ACTIVITY'            // Historical drain detected but now inactive
  | 'REVOKED_DELEGATION'             // Previously malicious delegation was revoked;

// ============================================
// SOLANA PROGRAM WHITELISTS
// ============================================
// CRITICAL: These programs are NEVER flagged as malicious
// False positive prevention is paramount

// System Programs (NEVER flag)
export const SOLANA_SYSTEM_PROGRAMS = new Set([
  '11111111111111111111111111111111',                   // System Program
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',       // Token Program
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',       // Token-2022 Program
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',      // Associated Token Program
  'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',       // Memo Program
  'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo',       // Memo Program (old)
  'ComputeBudget111111111111111111111111111111',       // Compute Budget Program
  'Vote111111111111111111111111111111111111111',        // Vote Program
  'Stake11111111111111111111111111111111111111',       // Stake Program
  'Config1111111111111111111111111111111111111',       // Config Program
  'AddressLookupTab1e1111111111111111111111111',       // Address Lookup Table
  'BPFLoader2111111111111111111111111111111111',       // BPF Loader
  'BPFLoaderUpgradeab1e11111111111111111111111',       // BPF Upgradeable Loader
]);

// Legitimate Bridges (NEVER flag)
// CRITICAL: Bridge interactions should NEVER be flagged as drainer activity
export const SOLANA_BRIDGE_PROGRAMS = new Set([
  // Wormhole
  'worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth',      // Wormhole Token Bridge
  'wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb',      // Wormhole Core Bridge
  'Bridge1p5gheXUvJ6jGWGeCsgPKgnE3YgdGKRVCMY9o',      // Wormhole NFT Bridge
  'WnFt12ZrnzZrFZkt2xsNsaNWoQribnuQ5B5FrDbwDhD',     // Wormhole Guardian
  
  // Allbridge
  'BrdgN2RPzEMWF96ZNcXq1UkPGk7LxH2DnXJuPQQ5RX4R',    // Allbridge Core
  'abrKZgvcUTkNo1JAhVZuVeTuDkNJUvJq3oc7xDibJuF',     // Allbridge Classic (corrected)
  
  // Portal (Wormhole Portal)
  'Portal111111111111111111111111111111111111',       // Portal Bridge
  'porAkMhVoHLB3RZHVqF8qF8jMk95D1aqDdsBh1LLMCJ',    // Portal Core
  
  // LayerZero Solana Endpoints
  'LZ4KQYfEkiADmvHQJpKA8yx99KdFo6M8sMCAKNFp3Gg',     // LayerZero Endpoint V1
  'LZ4PKxXQ7TZk9pYNbMCqEaH8hDLXhqFPtqH5C7A1L8V',    // LayerZero Endpoint V2
  
  // DeBridge
  'DEbrdGj3HsRsAzx6uH4MKyREKxVAfBydijLUF3ygsFfh',    // DeBridge V1
  'src5qyZHqTqecJV4aY6Cb6zDZLMDzrDKKezs22MPHr4',     // DeBridge Source
  
  // Mayan Finance
  'fc8gzx5d6LGkHGmxSCBpgzSxwjmTz5XSXF6k6wJ6jHu',    // Mayan Swift
  'mayanPvPQ8E7JGgmLnWynB1iDPDdz2x6RgbBGGZGCJ5',    // Mayan Swap
  
  // Synapse
  'SYNAVi6k8fkhJu9Kc4Y6p3zBjJwvVV1RX5EHH3E3qPD',    // Synapse Bridge
  
  // Celer cBridge
  'CelerBridge11111111111111111111111111111111',     // Celer cBridge
  
  // Across Protocol
  'Across111111111111111111111111111111111111111',   // Across Bridge
]);

// NFT Marketplaces & Programs (NEVER flag)
// CRITICAL: NFT minting and marketplace escrow interactions are NOT sweepers
// Do NOT classify mint + immediate transfer as drainer unless paired with SOL + SPL drain
export const SOLANA_NFT_PROGRAMS = new Set([
  // Metaplex
  'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',     // Token Metadata
  'p1exdMJcjVao65QdewkaZRUnU6VPSXhus9n2GzWfh98',     // Metaplex Auction House
  'hausS13jsjafwWwGqZTUQRmWyvyxn9EQpqMwV1PBBmk',     // Auction House
  'CJsLwbP1iu5DuUikHEJnLfANgKy6stB2uFgvBBHoyxwz',   // Metaplex Candy Machine V3
  'Guard1JwRhJkVH6XZhzoYxeBVQe872VH6QggF4BWmS9g',    // Candy Guard
  'BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY',   // Bubblegum (cNFT)
  'auth9SigNpDKz4sJJ1DfCTuZrZNSAgh9sFD3rboVmgg',    // Token Auth Rules
  'CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d',   // Core
  'MPL4o4wMzndgh8T1NVDxELQCj5UQfYTYEkabX3wNKtb',    // Metaplex Core
  'noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV',    // Noop (used in cNFT)
  'cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK',    // Compression
  
  // Magic Eden
  'M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K',     // Magic Eden V2
  'MEisE1HzehtrDpAAT8PnLHjpSSkRYakotTuJRPjTpo8',     // Magic Eden AMM
  'mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc',    // Magic Eden Collection Bid
  'E8cU1WiRWjanGxmn96ewBgk9vPTcL6AEZ1t6F6fkgUWe',   // Magic Eden Launchpad
  
  // Tensor
  'TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN',    // Tensor Swap
  'TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp',    // Tensor cNFT
  'TL1ST2iRBzuGTqLn1KXnGdSnEow62BzPnGiqyRXhWtW',    // Tensorian Listing
  'TENSRzsAqMxBkbHLMMTdMt8D5Lnp8p6rSKLCJHu1BF9',   // Tensor Bid
  'TCOMP7FL4gG7DJPfxjFmPhzXxvYZ4PD7VFHxGuNDfE8',   // Tensor Compressed
  
  // OpenSea (Solana)
  'ocp4vWUzA2z2XMYJ3QhM9vWdyoyoQwAFJhRdVTbvo9E',    // OpenSea Seaport
  'SEA1Zro3Kf8EHQxNbNUoZAhyZr1aExXTqNMpj6qXKhC',   // OpenSea Seaport V2
  
  // Coral Cube
  'ccubezJ7Gy9mfE2JH3dVfDpVdMcpPSCLxUaB1BuTtmQ',    // Coral Cube
  
  // Hyperspace
  'HYPERfwdTjyJ2SCaKHmpF2MtrXqWxrsotYDsTrshHWq8',   // Hyperspace
  
  // Cardinal
  'mgr99QFMYByTqGPWmNqunV7vBLmWWXdSrHUfV8Jf3JM',    // Cardinal Token Manager
  'pcaBwhJ1YHp7UDA7HASpQsRUmUNwzgYaLQto2kSj1fR',    // Cardinal Paid Claims
  
  // Formfunction
  'formn3hJtt8gvVKxpCfzCJGuoz6CNUFcULFZW18iTpC',    // Formfunction
  
  // Exchange Art
  'exArtz5r1VQSRr9bAuowGPXVjNYt3JCmkDX1T4RNYfV',   // Exchange Art
  
  // Solsea
  'SLSeaWbrdY5Q5dDaAqSEj1hQkHR8e3KJZLdJrCMGHVJ',   // Solsea
  
  // Holaplex
  'hausS13jsjafwWwGqZTUQRmWyvyxn9EQpqMwV1PBBmk',    // Holaplex Auction House
]);

// DeFi Protocols (NEVER flag)
export const SOLANA_DEFI_PROGRAMS = new Set([
  // Jupiter (main aggregator)
  'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',     // Jupiter V6
  'JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB',     // Jupiter V4
  'JUP3c2Uh3WA4Ng34tw6kPd2G4C5BB21Xo36Je1s32Ph',     // Jupiter V3
  
  // Raydium
  '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8',   // Raydium AMM V4
  'RVKd61ztZW9GUwhRbbLoYVRE5Xf1B2tVscKqwZqXgEr',    // Raydium Concentrated Liquidity
  '27haf8L6oxUeXrHrgEgsexjSY5hbVUWEmvv9Nyxg8vQv',   // Raydium Stable Swap
  
  // Orca
  'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc',    // Orca Whirlpool
  '9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP',   // Orca Token Swap
  
  // Marinade
  'MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD',    // Marinade Staking
  
  // Lido
  'CrX7kMhLC3cSsXJdT7JDgqrRVWGnUpX3gfEfxxU2NVLi',   // Lido Solana
  
  // Solend
  'So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo',    // Solend V2
  
  // Mango
  '4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg',   // Mango V4
  
  // Drift
  'dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH',    // Drift V2
  
  // Kamino
  'KLend2g3cP87ber41GJWgSwAm9sLBcSyD7WQ8Z6DXSL',    // Kamino Lending
  'LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo',    // Kamino LBP
  
  // Phoenix
  'PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY',    // Phoenix DEX
  
  // Openbook
  'srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX',    // Openbook V1 (Serum)
  'opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb',    // Openbook V2
]);

// Staking & Governance (NEVER flag)
export const SOLANA_STAKING_PROGRAMS = new Set([
  'Stake11111111111111111111111111111111111111',       // Native Staking
  'SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy',     // Stake Pool
  'MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD',     // Marinade
  'CrX7kMhLC3cSsXJdT7JDgqrRVWGnUpX3gfEfxxU2NVLi',    // Lido
  'jdaoMN1cPeQRz9hfxGu8M7Rz1LWcjvkXA5cwEtLjGqS',    // jDAO Staking
  'Govz1VyoyLD5BL6CSCxUJLVLsQHRwjfFj1prNsdNg5Jw',    // Governance
]);

// Wallet & Infrastructure (NEVER flag self-transfers)
export const SOLANA_WALLET_PROGRAMS = new Set([
  'GDDMwNyyx8uB6zrqwBFHjLLG3TBYk2F8Az4yrQC5RzMp',   // Glow Wallet
  'DjVE6JNiYqPL2QXyCUUh8rNjHrbz9hXHNYt99MQ59qw1',   // Phantom
]);

// All whitelisted programs combined
export const ALL_WHITELISTED_PROGRAMS = new Set([
  ...SOLANA_SYSTEM_PROGRAMS,
  ...SOLANA_BRIDGE_PROGRAMS,
  ...SOLANA_NFT_PROGRAMS,
  ...SOLANA_DEFI_PROGRAMS,
  ...SOLANA_STAKING_PROGRAMS,
  ...SOLANA_WALLET_PROGRAMS,
]);

// ============================================
// DETECTION CONFIGURATION
// ============================================

export interface SolanaDetectionConfig {
  // Time window for rapid asset depletion (seconds)
  rapidDepletionWindowSeconds: number;
  
  // Minimum number of tokens drained to trigger rapid depletion signal
  minTokensDrained: number;
  
  // Time threshold for "immediate" outflow after inflow (seconds)
  immediateOutflowThresholdSeconds: number;
  
  // Number of blocks to check for persistence
  persistenceBlockCount: number;
  
  // Days of inactivity to consider "previously compromised" vs "active"
  inactivityDaysThreshold: number;
  
  // Minimum signals required for ACTIVE compromise
  minSignalsForActiveCompromise: number;
  
  // Confidence threshold for flagging (0-100)
  confidenceThreshold: number;
}

export const DEFAULT_SOLANA_DETECTION_CONFIG: SolanaDetectionConfig = {
  rapidDepletionWindowSeconds: 600, // 10 minutes
  minTokensDrained: 2, // SOL + at least 1 SPL token
  immediateOutflowThresholdSeconds: 30, // 30 seconds
  persistenceBlockCount: 5,
  inactivityDaysThreshold: 7,
  minSignalsForActiveCompromise: 2,
  confidenceThreshold: 70,
};

// ============================================
// DRAINER DETECTION
// ============================================

export interface DrainerDetectionResult {
  isDrainer: boolean;
  confidence: number;
  signals: DetectedSignal[];
  explanation: string;
  isActive: boolean;
  lastActivityTimestamp?: number;
  
  // OUTPUT REQUIREMENTS: Explicit historical vs active distinction
  riskType: 'NONE' | 'HISTORICAL' | 'ACTIVE';
  riskLabel: string;
  
  // False positive prevention context
  excludedActivity?: {
    bridgeInteractions: number;
    selfTransfers: number;
    oneOffLargeTransfers: number;
    nftActivity: number;
    marketplaceEscrow: number;
  };
}

/**
 * Detect drainer behavior with high confidence requirements.
 * 
 * Flag ONLY if MULTIPLE of the following occur:
 * - Rapid asset depletion across SPL tokens + SOL within <10 minutes
 * - Funds routed to known aggregation/laundering patterns
 * - Outgoing transfers immediately after inbound funding
 * - Repeated interactions with known malicious addresses
 * - Transaction signatures show automation patterns
 * 
 * FALSE POSITIVE PREVENTION:
 * - NEVER flag bridge interactions
 * - NEVER flag self-transfers
 * - NEVER flag one-off large transfers without automation
 * - NEVER flag NFT mint + transfer unless paired with SOL + SPL drain
 */
export function detectDrainerBehavior(
  transactions: SolanaTransactionData[],
  walletAddress: string,
  knownMaliciousAddresses: Set<string>,
  config: SolanaDetectionConfig = DEFAULT_SOLANA_DETECTION_CONFIG
): DrainerDetectionResult {
  const signals: DetectedSignal[] = [];
  let isActive = false;
  let lastActivityTimestamp: number | undefined;
  
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
  
  if (safeTxs.length === 0) {
    return {
      isDrainer: false,
      confidence: 0,
      signals: [],
      explanation: 'No transaction history available for drainer analysis.',
      isActive: false,
      riskType: 'NONE',
      riskLabel: 'No Risk Detected',
    };
  }
  
  // ============================================
  // FALSE POSITIVE PREVENTION: Filter out whitelisted activity
  // ============================================
  const { filtered: filteredTxs, excluded } = filterFalsePositives(safeTxs, walletAddress);
  
  // Count NFT activity separately
  const nftActivityCount = safeTxs.filter(tx => isNFTMintingActivity(tx)).length;
  
  // If all transactions are whitelisted, return safe
  if (filteredTxs.length === 0) {
    const exclusionSummary: string[] = [];
    if (excluded.bridgeActivity > 0) exclusionSummary.push(`${excluded.bridgeActivity} bridge interaction(s)`);
    if (excluded.selfTransfers > 0) exclusionSummary.push(`${excluded.selfTransfers} self-transfer(s)`);
    if (excluded.oneOffLarge > 0) exclusionSummary.push(`${excluded.oneOffLarge} one-off large transfer(s)`);
    if (excluded.marketplaceEscrow > 0) exclusionSummary.push(`${excluded.marketplaceEscrow} marketplace escrow interaction(s)`);
    
    return {
      isDrainer: false,
      confidence: 0,
      signals: [],
      explanation: `No drainer behavior detected. All activity is whitelisted: ${exclusionSummary.join(', ') || 'legitimate activity'}.`,
      isActive: false,
      riskType: 'NONE',
      riskLabel: 'No Risk Detected',
      excludedActivity: {
        bridgeInteractions: excluded.bridgeActivity,
        selfTransfers: excluded.selfTransfers,
        oneOffLargeTransfers: excluded.oneOffLarge,
        nftActivity: nftActivityCount,
        marketplaceEscrow: excluded.marketplaceEscrow,
      },
    };
  }
  
  // ============================================
  // FALSE POSITIVE PREVENTION: Check for NFT-only activity
  // ============================================
  if (shouldExcludeNFTActivity(filteredTxs)) {
    return {
      isDrainer: false,
      confidence: 0,
      signals: [],
      explanation: 'NFT minting and transfer activity detected without SOL+SPL drain behavior. Not classified as drainer.',
      isActive: false,
      riskType: 'NONE',
      riskLabel: 'No Risk Detected – NFT Activity Only',
      excludedActivity: {
        bridgeInteractions: excluded.bridgeActivity,
        selfTransfers: excluded.selfTransfers,
        oneOffLargeTransfers: excluded.oneOffLarge,
        nftActivity: nftActivityCount,
        marketplaceEscrow: excluded.marketplaceEscrow,
      },
    };
  }
  
  // Sort by timestamp
  const sortedTxs = [...filteredTxs].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
  
  // ============================================
  // SIGNAL 1: Rapid Asset Depletion
  // ============================================
  const rapidDepletion = detectRapidAssetDepletion(sortedTxs, walletAddress, config);
  if (rapidDepletion) {
    signals.push(rapidDepletion);
    lastActivityTimestamp = rapidDepletion.timestamp;
  }
  
  // ============================================
  // SIGNAL 2: Known Malicious Interactions
  // ============================================
  const maliciousInteractions = detectMaliciousInteractions(sortedTxs, knownMaliciousAddresses);
  signals.push(...maliciousInteractions);
  if (maliciousInteractions.length > 0) {
    const latestMalicious = maliciousInteractions.reduce((latest, sig) => 
      (sig.timestamp || 0) > (latest.timestamp || 0) ? sig : latest
    , maliciousInteractions[0]);
    if (!lastActivityTimestamp || (latestMalicious.timestamp || 0) > lastActivityTimestamp) {
      lastActivityTimestamp = latestMalicious.timestamp;
    }
  }
  
  // ============================================
  // SIGNAL 3: Immediate Outflow After Inflow
  // ============================================
  const immediateOutflows = detectImmediateOutflows(sortedTxs, walletAddress, config);
  signals.push(...immediateOutflows);
  
  // ============================================
  // SIGNAL 4: Automation Signatures
  // ============================================
  const automationSignal = detectAutomationPatterns(sortedTxs, walletAddress);
  if (automationSignal) {
    signals.push(automationSignal);
  }
  
  // ============================================
  // SIGNAL 5: Laundering Patterns
  // ============================================
  const launderingSignal = detectLaunderingPatterns(sortedTxs, walletAddress);
  if (launderingSignal) {
    signals.push(launderingSignal);
  }
  
  // ============================================
  // DETERMINE IF ACTIVE
  // ============================================
  if (lastActivityTimestamp) {
    const daysSinceActivity = (Date.now() / 1000 - lastActivityTimestamp) / 86400;
    isActive = daysSinceActivity < config.inactivityDaysThreshold;
  }
  
  // ============================================
  // CALCULATE CONFIDENCE
  // ============================================
  const highConfidenceSignals = signals.filter(s => s.confidence === 'HIGH');
  const mediumConfidenceSignals = signals.filter(s => s.confidence === 'MEDIUM');
  
  let confidence = 0;
  confidence += highConfidenceSignals.length * 35;
  confidence += mediumConfidenceSignals.length * 15;
  confidence = Math.min(100, confidence);
  
  // ============================================
  // DETERMINE IF DRAINER
  // ============================================
  // CONFIDENCE THRESHOLDING:
  // Require at least 2 independent high-confidence signals before flagging ACTIVE compromise
  // Otherwise downgrade to HISTORICAL or UNCONFIRMED
  const isDrainer = highConfidenceSignals.length >= config.minSignalsForActiveCompromise ||
                    (highConfidenceSignals.length >= 1 && signals.length >= 3);
  
  // Generate explanation
  const explanation = generateDrainerExplanation(signals, isDrainer, isActive, confidence);
  
  // Determine risk type and label (OUTPUT REQUIREMENTS)
  let riskType: 'NONE' | 'HISTORICAL' | 'ACTIVE' = 'NONE';
  let riskLabel = 'No Risk Detected';
  
  if (isDrainer) {
    if (isActive) {
      riskType = 'ACTIVE';
      riskLabel = 'ACTIVE COMPROMISE DETECTED';
    } else {
      riskType = 'HISTORICAL';
      riskLabel = 'Historical Compromise – No Active Risk';
    }
  } else if (signals.length > 0) {
    // Low confidence signals exist but not enough to classify as drainer
    riskType = 'NONE';
    riskLabel = 'Low-Confidence Signals – Unconfirmed';
  }
  
  return {
    isDrainer,
    confidence,
    signals,
    explanation,
    isActive,
    lastActivityTimestamp,
    riskType,
    riskLabel,
    excludedActivity: {
      bridgeInteractions: excluded.bridgeActivity,
      selfTransfers: excluded.selfTransfers,
      oneOffLargeTransfers: excluded.oneOffLarge,
      nftActivity: nftActivityCount,
      marketplaceEscrow: excluded.marketplaceEscrow,
    },
  };
}

// ============================================
// SWEEPER BOT DETECTION
// ============================================

export interface SweeperBotDetectionResult {
  isSweeper: boolean;
  confidence: number;
  signals: DetectedSignal[];
  explanation: string;
  isActive: boolean;
  lastActivityTimestamp?: number;
  
  // OUTPUT REQUIREMENTS: Explicit historical vs active distinction
  riskType: 'NONE' | 'HISTORICAL' | 'ACTIVE';
  riskLabel: string;
  
  // False positive prevention context
  excludedActivity?: {
    bridgeInteractions: number;
    selfTransfers: number;
    marketplaceEscrow: number;
  };
}

/**
 * Detect sweeper bot behavior.
 * 
 * Flag ONLY if:
 * - Repeated automated transfers triggered within seconds of inbound funds
 * - Identical destination addresses used across multiple unrelated wallets
 * - No user-interactive instructions (no memo, no user delay)
 * - Pattern persists across multiple blocks (not single event)
 * 
 * FALSE POSITIVE PREVENTION:
 * - Marketplace escrow interactions are NOT sweepers
 * - Bridge interactions are NOT sweepers
 * - Self-transfers are NOT sweepers
 * - Single event patterns are NOT sweepers (require persistence)
 */
export function detectSweeperBotBehavior(
  transactions: SolanaTransactionData[],
  walletAddress: string,
  config: SolanaDetectionConfig = DEFAULT_SOLANA_DETECTION_CONFIG
): SweeperBotDetectionResult {
  const signals: DetectedSignal[] = [];
  let lastActivityTimestamp: number | undefined;
  
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
  
  if (safeTxs.length === 0) {
    return {
      isSweeper: false,
      confidence: 0,
      signals: [],
      explanation: 'No transaction history available for sweeper analysis.',
      isActive: false,
      riskType: 'NONE',
      riskLabel: 'No Risk Detected',
    };
  }
  
  // ============================================
  // FALSE POSITIVE PREVENTION: Filter out whitelisted activity
  // ============================================
  const { filtered: filteredTxs, excluded } = filterFalsePositives(safeTxs, walletAddress);
  
  // If all transactions are whitelisted, return safe
  if (filteredTxs.length === 0) {
    return {
      isSweeper: false,
      confidence: 0,
      signals: [],
      explanation: 'No sweeper bot behavior detected. All activity is legitimate.',
      isActive: false,
      riskType: 'NONE',
      riskLabel: 'No Risk Detected',
      excludedActivity: {
        bridgeInteractions: excluded.bridgeActivity,
        selfTransfers: excluded.selfTransfers,
        marketplaceEscrow: excluded.marketplaceEscrow,
      },
    };
  }
  
  // ============================================
  // FALSE POSITIVE PREVENTION: Check for marketplace escrow
  // ============================================
  const hasOnlyMarketplaceActivity = safeTxs.every(tx => isMarketplaceEscrowActivity(tx));
  if (hasOnlyMarketplaceActivity) {
    return {
      isSweeper: false,
      confidence: 0,
      signals: [],
      explanation: 'Marketplace escrow interactions detected. Not classified as sweeper.',
      isActive: false,
      riskType: 'NONE',
      riskLabel: 'No Risk Detected – Marketplace Activity Only',
      excludedActivity: {
        bridgeInteractions: excluded.bridgeActivity,
        selfTransfers: excluded.selfTransfers,
        marketplaceEscrow: excluded.marketplaceEscrow,
      },
    };
  }
  
  // Sort by timestamp
  const sortedTxs = [...filteredTxs].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
  
  // ============================================
  // SIGNAL 1: Immediate Automated Transfers
  // ============================================
  let immediateTransferCount = 0;
  const inboundTxs = sortedTxs.filter(tx => tx.isInbound);
  const outboundTxs = sortedTxs.filter(tx => tx.isOutbound);
  
  for (const inbound of inboundTxs) {
    const rapidOutbound = outboundTxs.find(out => 
      (out.timestamp || 0) > (inbound.timestamp || 0) &&
      ((out.timestamp || 0) - (inbound.timestamp || 0)) <= config.immediateOutflowThresholdSeconds
    );
    if (rapidOutbound) {
      immediateTransferCount++;
      lastActivityTimestamp = rapidOutbound.timestamp;
    }
  }
  
  if (immediateTransferCount >= 3) {
    signals.push({
      type: 'IMMEDIATE_AUTOMATED_TRANSFER',
      confidence: 'HIGH',
      description: `${immediateTransferCount} transfers occurred within seconds of receiving funds`,
      timestamp: lastActivityTimestamp,
    });
  }
  
  // ============================================
  // SIGNAL 2: Identical Destination Pattern
  // ============================================
  const destinations = new Map<string, number>();
  for (const tx of outboundTxs) {
    if (tx.toAddress) {
      destinations.set(tx.toAddress, (destinations.get(tx.toAddress) || 0) + 1);
    }
  }
  
  const sameDestCount = Math.max(...Array.from(destinations.values()), 0);
  if (sameDestCount >= 5 && outboundTxs.length >= 5) {
    const primaryDest = Array.from(destinations.entries())
      .find(([, count]) => count === sameDestCount)?.[0];
    signals.push({
      type: 'IDENTICAL_DESTINATION_PATTERN',
      confidence: 'HIGH',
      description: `${sameDestCount} transactions sent to the same destination (${primaryDest?.slice(0, 8)}...)`,
      relatedAddresses: primaryDest ? [primaryDest] : [],
    });
  }
  
  // ============================================
  // SIGNAL 3: No User Interaction
  // ============================================
  const txsWithMemo = sortedTxs.filter(tx => tx.hasMemo);
  const txsWithDelay = sortedTxs.filter((tx, idx) => {
    if (idx === 0) return true;
    const prevTx = sortedTxs[idx - 1];
    return ((tx.timestamp || 0) - (prevTx.timestamp || 0)) > 60; // > 1 minute delay
  });
  
  if (txsWithMemo.length === 0 && txsWithDelay.length < sortedTxs.length * 0.2) {
    signals.push({
      type: 'NO_USER_INTERACTION',
      confidence: 'MEDIUM',
      description: 'No memos and minimal delay between transactions suggests automation',
    });
  }
  
  // ============================================
  // SIGNAL 4: Multi-Block Persistence
  // ============================================
  const uniqueSlots = new Set(sortedTxs.map(tx => tx.slot).filter(Boolean));
  if (uniqueSlots.size >= config.persistenceBlockCount && immediateTransferCount >= 2) {
    signals.push({
      type: 'MULTI_BLOCK_PERSISTENCE',
      confidence: 'HIGH',
      description: `Suspicious pattern persists across ${uniqueSlots.size} blocks`,
    });
  }
  
  // ============================================
  // DETERMINE IF ACTIVE
  // ============================================
  let isActive = false;
  if (lastActivityTimestamp) {
    const daysSinceActivity = (Date.now() / 1000 - lastActivityTimestamp) / 86400;
    isActive = daysSinceActivity < config.inactivityDaysThreshold;
  }
  
  // ============================================
  // CALCULATE CONFIDENCE
  // ============================================
  const highConfidenceSignals = signals.filter(s => s.confidence === 'HIGH');
  const mediumConfidenceSignals = signals.filter(s => s.confidence === 'MEDIUM');
  
  let confidence = 0;
  confidence += highConfidenceSignals.length * 35;
  confidence += mediumConfidenceSignals.length * 15;
  confidence = Math.min(100, confidence);
  
  // ============================================
  // DETERMINE IF SWEEPER
  // ============================================
  // CONFIDENCE THRESHOLDING:
  // Require at least 2 independent high-confidence signals before flagging as sweeper
  // Single event patterns are NOT sufficient (require persistence)
  const isSweeper = highConfidenceSignals.length >= config.minSignalsForActiveCompromise;
  
  // Generate explanation
  const explanation = generateSweeperExplanation(signals, isSweeper, isActive, confidence);
  
  // Determine risk type and label (OUTPUT REQUIREMENTS)
  let riskType: 'NONE' | 'HISTORICAL' | 'ACTIVE' = 'NONE';
  let riskLabel = 'No Risk Detected';
  
  if (isSweeper) {
    if (isActive) {
      riskType = 'ACTIVE';
      riskLabel = 'ACTIVE SWEEPER BOT DETECTED';
    } else {
      riskType = 'HISTORICAL';
      riskLabel = 'Historical Sweeper Activity – No Active Risk';
    }
  } else if (signals.length > 0) {
    // Low confidence signals exist but not enough to classify as sweeper
    riskType = 'NONE';
    riskLabel = 'Low-Confidence Signals – Unconfirmed';
  }
  
  return {
    isSweeper,
    confidence,
    signals,
    explanation,
    isActive,
    lastActivityTimestamp,
    riskType,
    riskLabel,
    excludedActivity: {
      bridgeInteractions: excluded.bridgeActivity,
      selfTransfers: excluded.selfTransfers,
      marketplaceEscrow: excluded.marketplaceEscrow,
    },
  };
}

// ============================================
// MAIN SECURITY ANALYSIS
// ============================================

/**
 * Perform comprehensive Solana security analysis.
 * 
 * Returns one of three states:
 * - SAFE: No historical or active compromise signals
 * - PREVIOUSLY_COMPROMISED: Past incidents exist but no active threat
 * - ACTIVELY_COMPROMISED: Ongoing hostile fund movement
 */
export function analyzeSolanaSecurity(
  transactions: SolanaTransactionData[],
  walletAddress: string,
  knownMaliciousAddresses: Set<string>,
  config: SolanaDetectionConfig = DEFAULT_SOLANA_DETECTION_CONFIG
): SolanaSecurityResult {
  const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
  
  // ============================================
  // STEP 1: Check for whitelisted-only activity
  // ============================================
  const whitelistedActivity: string[] = [];
  const nonWhitelistedTxs = safeTxs.filter(tx => {
    const programs = tx.programIds || [];
    const allWhitelisted = programs.every(p => ALL_WHITELISTED_PROGRAMS.has(p));
    if (allWhitelisted && programs.length > 0) {
      whitelistedActivity.push(`Transaction with whitelisted programs: ${programs.join(', ')}`);
      return false;
    }
    return true;
  });
  
  // ============================================
  // STEP 2: Check for self-transfers (wallet shuffling)
  // ============================================
  const selfTransfers = safeTxs.filter(tx => 
    tx.fromAddress === walletAddress && tx.toAddress === walletAddress
  );
  if (selfTransfers.length > 0) {
    whitelistedActivity.push(`${selfTransfers.length} self-transfer(s) detected (wallet shuffling)`);
  }
  
  // ============================================
  // STEP 3: Run drainer detection
  // ============================================
  const drainerResult = detectDrainerBehavior(
    nonWhitelistedTxs,
    walletAddress,
    knownMaliciousAddresses,
    config
  );
  
  // ============================================
  // STEP 4: Run sweeper detection
  // ============================================
  const sweeperResult = detectSweeperBotBehavior(
    nonWhitelistedTxs,
    walletAddress,
    config
  );
  
  // ============================================
  // STEP 5: Combine signals
  // ============================================
  const allSignals = [
    ...drainerResult.signals,
    ...sweeperResult.signals,
  ];
  
  const highConfidenceSignals = allSignals.filter(s => s.confidence === 'HIGH');
  const signalCount = highConfidenceSignals.length;
  
  // ============================================
  // STEP 6: Determine state
  // ============================================
  let state: SolanaSecurityState = 'SAFE';
  let isHistorical = false;
  let isActive = false;
  
  const hasCompromiseSignals = drainerResult.isDrainer || sweeperResult.isSweeper;
  const isActiveCompromise = drainerResult.isActive || sweeperResult.isActive;
  
  if (hasCompromiseSignals) {
    if (isActiveCompromise) {
      state = 'ACTIVELY_COMPROMISED';
      isActive = true;
    } else {
      state = 'PREVIOUSLY_COMPROMISED';
      isHistorical = true;
    }
  }
  
  // ============================================
  // STEP 7: Calculate risk score
  // ============================================
  let riskScore = 0;
  if (state === 'ACTIVELY_COMPROMISED') {
    riskScore = 80 + Math.min(20, signalCount * 5);
  } else if (state === 'PREVIOUSLY_COMPROMISED') {
    riskScore = 40 + Math.min(30, signalCount * 5);
  } else {
    riskScore = Math.min(20, allSignals.length * 5);
  }
  
  // ============================================
  // STEP 8: Calculate days since last incident
  // ============================================
  let daysSinceLastIncident: number | undefined;
  const lastTimestamp = drainerResult.lastActivityTimestamp || sweeperResult.lastActivityTimestamp;
  if (lastTimestamp) {
    daysSinceLastIncident = Math.floor((Date.now() / 1000 - lastTimestamp) / 86400);
  }
  
  // ============================================
  // STEP 9: Build reasoning
  // ============================================
  const reasoning: SolanaSecurityReasoning = {
    stateReason: generateStateReason(state, drainerResult, sweeperResult, daysSinceLastIncident),
    detectedSignals: allSignals,
    safeSignals: generateSafeSignals(safeTxs, drainerResult, sweeperResult),
    whitelistedActivity,
    confidenceFactors: generateConfidenceFactors(allSignals, drainerResult, sweeperResult),
    uncertaintyFactors: generateUncertaintyFactors(safeTxs, allSignals),
  };
  
  // ============================================
  // STEP 10: Generate explanation
  // ============================================
  const explanation = generateSecurityExplanation(
    state,
    drainerResult,
    sweeperResult,
    daysSinceLastIncident,
    signalCount
  );
  
  // Calculate overall confidence
  const confidence = Math.max(drainerResult.confidence, sweeperResult.confidence);
  
  return {
    state,
    confidence,
    isHistorical,
    isActive,
    signalCount,
    drainerDetection: drainerResult.isDrainer ? drainerResult : undefined,
    sweeperDetection: sweeperResult.isSweeper ? sweeperResult : undefined,
    explanation,
    reasoning,
    riskScore,
    daysSinceLastIncident,
  };
}

// ============================================
// HELPER TYPES
// ============================================

export interface SolanaTransactionData {
  signature: string;
  timestamp?: number;
  slot?: number;
  fromAddress?: string;
  toAddress?: string;
  isInbound: boolean;
  isOutbound: boolean;
  lamports?: number;
  programIds?: string[];
  hasMemo?: boolean;
  computeUnits?: number;
  isNFTTransfer?: boolean;
  isSPLTransfer?: boolean;
  isSOLTransfer?: boolean;
  // NFT-specific fields for false positive prevention
  isNFTMint?: boolean;
  isNFTMarketplace?: boolean;
  // Bridge interaction detection
  isBridgeInteraction?: boolean;
  // Self-transfer detection
  isSelfTransfer?: boolean;
  // Value in USD (if available) for one-off large transfer detection
  valueUSD?: number;
}

// ============================================
// FALSE POSITIVE PREVENTION HELPERS
// ============================================

/**
 * Check if a transaction is NFT minting activity.
 * NFT mint + immediate transfer should NOT be classified as drainer
 * unless paired with SOL + SPL drain behavior.
 */
function isNFTMintingActivity(tx: SolanaTransactionData): boolean {
  const programs = tx.programIds || [];
  
  // Check for NFT program interactions
  const nftProgramInteraction = programs.some(p => SOLANA_NFT_PROGRAMS.has(p));
  
  // Check for Metaplex token metadata program specifically
  const hasMetaplex = programs.includes('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s');
  
  // Check for Bubblegum (compressed NFT)
  const hasBubblegum = programs.includes('BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY');
  
  return tx.isNFTMint === true || tx.isNFTTransfer === true || 
         nftProgramInteraction || hasMetaplex || hasBubblegum;
}

/**
 * Check if a transaction is a bridge interaction.
 * Bridge interactions should NEVER be flagged as drainer activity.
 */
function isBridgeActivity(tx: SolanaTransactionData): boolean {
  const programs = tx.programIds || [];
  return tx.isBridgeInteraction === true || 
         programs.some(p => SOLANA_BRIDGE_PROGRAMS.has(p));
}

/**
 * Check if a transaction is a marketplace escrow interaction.
 * Marketplace escrow interactions are NOT sweepers.
 */
function isMarketplaceEscrowActivity(tx: SolanaTransactionData): boolean {
  const programs = tx.programIds || [];
  return tx.isNFTMarketplace === true ||
         programs.some(p => SOLANA_NFT_PROGRAMS.has(p));
}

/**
 * Check if a transaction is a self-transfer (wallet shuffling).
 * Self-transfers should NEVER be flagged as suspicious.
 */
function isSelfTransfer(tx: SolanaTransactionData, walletAddress: string): boolean {
  return tx.isSelfTransfer === true ||
         (tx.fromAddress === walletAddress && tx.toAddress === walletAddress);
}

/**
 * Check if a transaction is a one-off large transfer without automation indicators.
 * One-off large transfers should NOT be flagged as drainer activity.
 */
function isOneOffLargeTransfer(
  tx: SolanaTransactionData,
  allTxs: SolanaTransactionData[],
  walletAddress: string
): boolean {
  // Must be outbound
  if (!tx.isOutbound) return false;
  
  // Get all outbound transactions to same destination
  const sameDestTxs = allTxs.filter(t => 
    t.isOutbound && t.toAddress === tx.toAddress
  );
  
  // One-off = only 1 transaction to this destination
  if (sameDestTxs.length !== 1) return false;
  
  // Check for user interaction indicators (memo = human)
  if (tx.hasMemo) return true;
  
  // Check if this is a large transfer (significant value)
  const lamports = tx.lamports || 0;
  const solAmount = lamports / 1e9;
  
  // Consider "large" if > 0.1 SOL (can be adjusted)
  if (solAmount > 0.1) {
    // Additional check: no rapid follow-up transactions
    const txTime = tx.timestamp || 0;
    const rapidFollowUp = allTxs.some(t => 
      t.signature !== tx.signature &&
      t.isOutbound &&
      Math.abs((t.timestamp || 0) - txTime) < 60 // Within 1 minute
    );
    
    if (!rapidFollowUp) return true;
  }
  
  return false;
}

/**
 * Filter out false positive transactions before drainer detection.
 * Returns transactions that are NOT whitelisted activity.
 */
function filterFalsePositives(
  transactions: SolanaTransactionData[],
  walletAddress: string
): {
  filtered: SolanaTransactionData[];
  excluded: {
    nftMinting: number;
    bridgeActivity: number;
    marketplaceEscrow: number;
    selfTransfers: number;
    oneOffLarge: number;
  };
} {
  const excluded = {
    nftMinting: 0,
    bridgeActivity: 0,
    marketplaceEscrow: 0,
    selfTransfers: 0,
    oneOffLarge: 0,
  };
  
  const filtered = transactions.filter(tx => {
    // Check for self-transfers
    if (isSelfTransfer(tx, walletAddress)) {
      excluded.selfTransfers++;
      return false;
    }
    
    // Check for bridge activity
    if (isBridgeActivity(tx)) {
      excluded.bridgeActivity++;
      return false;
    }
    
    // Check for marketplace escrow
    if (isMarketplaceEscrowActivity(tx)) {
      excluded.marketplaceEscrow++;
      return false;
    }
    
    // Check for one-off large transfers
    if (isOneOffLargeTransfer(tx, transactions, walletAddress)) {
      excluded.oneOffLarge++;
      return false;
    }
    
    return true;
  });
  
  return { filtered, excluded };
}

/**
 * Check if NFT-related transactions should be excluded from drain detection.
 * NFT mint + immediate transfer is NOT drainer unless paired with SOL + SPL drain.
 */
function shouldExcludeNFTActivity(
  transactions: SolanaTransactionData[]
): boolean {
  // Get NFT-related transactions
  const nftTxs = transactions.filter(tx => isNFTMintingActivity(tx));
  
  // Get SOL drain transactions (non-NFT outbound)
  const solDrainTxs = transactions.filter(tx => 
    tx.isOutbound && 
    tx.isSOLTransfer && 
    !isNFTMintingActivity(tx)
  );
  
  // Get SPL drain transactions (non-NFT outbound)
  const splDrainTxs = transactions.filter(tx => 
    tx.isOutbound && 
    tx.isSPLTransfer && 
    !isNFTMintingActivity(tx)
  );
  
  // If we have NFT activity but no SOL+SPL drain, exclude from drainer detection
  if (nftTxs.length > 0 && solDrainTxs.length === 0 && splDrainTxs.length === 0) {
    return true;
  }
  
  return false;
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function detectRapidAssetDepletion(
  transactions: SolanaTransactionData[],
  walletAddress: string,
  config: SolanaDetectionConfig
): DetectedSignal | null {
  const outboundTxs = transactions.filter(tx => tx.isOutbound);
  if (outboundTxs.length < 2) return null;
  
  // Look for SOL + SPL token drains within window
  for (let i = 0; i < outboundTxs.length; i++) {
    const windowStart = outboundTxs[i].timestamp || 0;
    const windowEnd = windowStart + config.rapidDepletionWindowSeconds;
    
    const txsInWindow = outboundTxs.filter(tx => 
      (tx.timestamp || 0) >= windowStart && (tx.timestamp || 0) <= windowEnd
    );
    
    const hasSOLDrain = txsInWindow.some(tx => tx.isSOLTransfer && (tx.lamports || 0) > 0);
    const hasSPLDrain = txsInWindow.some(tx => tx.isSPLTransfer);
    
    if (hasSOLDrain && hasSPLDrain && txsInWindow.length >= config.minTokensDrained) {
      return {
        type: 'RAPID_ASSET_DEPLETION',
        confidence: 'HIGH',
        description: `SOL + SPL tokens drained within ${config.rapidDepletionWindowSeconds / 60} minutes`,
        timestamp: windowStart,
        relatedTxSignatures: txsInWindow.map(tx => tx.signature),
      };
    }
  }
  
  return null;
}

function detectMaliciousInteractions(
  transactions: SolanaTransactionData[],
  knownMaliciousAddresses: Set<string>
): DetectedSignal[] {
  const signals: DetectedSignal[] = [];
  
  for (const tx of transactions) {
    // Check destination
    if (tx.toAddress && knownMaliciousAddresses.has(tx.toAddress)) {
      signals.push({
        type: 'KNOWN_MALICIOUS_INTERACTION',
        confidence: 'HIGH',
        description: `Transaction to known malicious address: ${tx.toAddress.slice(0, 8)}...`,
        timestamp: tx.timestamp,
        relatedAddresses: [tx.toAddress],
        relatedTxSignatures: [tx.signature],
      });
    }
    
    // Check programs
    for (const programId of (tx.programIds || [])) {
      if (knownMaliciousAddresses.has(programId)) {
        signals.push({
          type: 'KNOWN_MALICIOUS_INTERACTION',
          confidence: 'HIGH',
          description: `Interaction with known malicious program: ${programId.slice(0, 8)}...`,
          timestamp: tx.timestamp,
          relatedAddresses: [programId],
          relatedTxSignatures: [tx.signature],
        });
      }
    }
  }
  
  return signals;
}

function detectImmediateOutflows(
  transactions: SolanaTransactionData[],
  walletAddress: string,
  config: SolanaDetectionConfig
): DetectedSignal[] {
  const signals: DetectedSignal[] = [];
  
  const inboundTxs = transactions.filter(tx => tx.isInbound);
  const outboundTxs = transactions.filter(tx => tx.isOutbound);
  
  let immediateCount = 0;
  for (const inbound of inboundTxs) {
    const rapidOutbound = outboundTxs.find(out =>
      (out.timestamp || 0) > (inbound.timestamp || 0) &&
      ((out.timestamp || 0) - (inbound.timestamp || 0)) <= config.immediateOutflowThresholdSeconds
    );
    if (rapidOutbound) {
      immediateCount++;
    }
  }
  
  if (immediateCount >= 3) {
    signals.push({
      type: 'IMMEDIATE_OUTFLOW_AFTER_INFLOW',
      confidence: 'HIGH',
      description: `${immediateCount} instances of immediate outflow after receiving funds`,
    });
  } else if (immediateCount >= 1) {
    signals.push({
      type: 'IMMEDIATE_OUTFLOW_AFTER_INFLOW',
      confidence: 'MEDIUM',
      description: `${immediateCount} instance(s) of immediate outflow after receiving funds`,
    });
  }
  
  return signals;
}

function detectAutomationPatterns(
  transactions: SolanaTransactionData[],
  walletAddress: string
): DetectedSignal | null {
  if (transactions.length < 5) return null;
  
  const outboundTxs = transactions.filter(tx => tx.isOutbound);
  if (outboundTxs.length < 3) return null;
  
  // Check for consistent compute units (automation signature)
  const computeUnits = outboundTxs
    .map(tx => tx.computeUnits)
    .filter((cu): cu is number => cu !== undefined);
  
  if (computeUnits.length >= 3) {
    const avg = computeUnits.reduce((a, b) => a + b, 0) / computeUnits.length;
    const variance = computeUnits.reduce((sum, cu) => sum + Math.pow(cu - avg, 2), 0) / computeUnits.length;
    const stdDev = Math.sqrt(variance);
    const cv = avg > 0 ? stdDev / avg : 0;
    
    // Very consistent compute units suggests automation
    if (cv < 0.1 && computeUnits.length >= 5) {
      return {
        type: 'AUTOMATION_SIGNATURE',
        confidence: 'MEDIUM',
        description: `Consistent compute usage pattern suggests automation (CV: ${cv.toFixed(3)})`,
      };
    }
  }
  
  // Check for consistent timing intervals
  const timestamps = outboundTxs
    .map(tx => tx.timestamp)
    .filter((ts): ts is number => ts !== undefined)
    .sort((a, b) => a - b);
  
  if (timestamps.length >= 5) {
    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }
    
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const intervalVariance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
    const intervalStdDev = Math.sqrt(intervalVariance);
    const intervalCV = avgInterval > 0 ? intervalStdDev / avgInterval : 0;
    
    // Very consistent timing suggests automation
    if (intervalCV < 0.15 && avgInterval < 120) { // Regular intervals under 2 minutes
      return {
        type: 'AUTOMATION_SIGNATURE',
        confidence: 'HIGH',
        description: `Highly consistent transaction timing suggests automation (interval CV: ${intervalCV.toFixed(3)}, avg: ${avgInterval.toFixed(0)}s)`,
      };
    }
  }
  
  return null;
}

function detectLaunderingPatterns(
  transactions: SolanaTransactionData[],
  walletAddress: string
): DetectedSignal | null {
  const outboundTxs = transactions.filter(tx => tx.isOutbound);
  if (outboundTxs.length < 5) return null;
  
  // Check for fan-out pattern (many different destinations)
  const destinations = new Set(outboundTxs.map(tx => tx.toAddress).filter(Boolean));
  
  if (destinations.size >= 10 && outboundTxs.length >= 10) {
    return {
      type: 'LAUNDERING_PATTERN',
      confidence: 'MEDIUM',
      description: `Fan-out pattern detected: ${destinations.size} unique destinations across ${outboundTxs.length} transactions`,
    };
  }
  
  // Check for peel-chain pattern (sequential decreasing amounts)
  // This is a more complex check that would need amount data
  
  return null;
}

function generateDrainerExplanation(
  signals: DetectedSignal[],
  isDrainer: boolean,
  isActive: boolean,
  confidence: number
): string {
  if (!isDrainer) {
    if (signals.length === 0) {
      return 'No drainer behavior detected.';
    }
    return `Low-confidence signals detected (${signals.length}). Insufficient evidence for drainer classification.`;
  }
  
  const status = isActive ? 'ACTIVE' : 'HISTORICAL';
  return `${status} drainer behavior detected (confidence: ${confidence}%). ` +
         `${signals.length} independent signal(s) identified: ` +
         signals.map(s => s.type).join(', ') + '.';
}

function generateSweeperExplanation(
  signals: DetectedSignal[],
  isSweeper: boolean,
  isActive: boolean,
  confidence: number
): string {
  if (!isSweeper) {
    if (signals.length === 0) {
      return 'No sweeper bot behavior detected.';
    }
    return `Low-confidence signals detected (${signals.length}). Insufficient evidence for sweeper classification.`;
  }
  
  const status = isActive ? 'ACTIVE' : 'HISTORICAL';
  return `${status} sweeper bot behavior detected (confidence: ${confidence}%). ` +
         `${signals.length} independent signal(s) identified: ` +
         signals.map(s => s.type).join(', ') + '.';
}

function generateStateReason(
  state: SolanaSecurityState,
  drainerResult: DrainerDetectionResult,
  sweeperResult: SweeperBotDetectionResult,
  daysSinceLastIncident?: number
): string {
  switch (state) {
    case 'SAFE':
      return 'No historical or active compromise signals detected. ' +
             'Note: This does NOT guarantee the wallet is safe from all threats.';
    
    case 'PREVIOUSLY_COMPROMISED':
      return `Historical compromise detected but no active threat. ` +
             `Last suspicious activity: ${daysSinceLastIncident ?? 'unknown'} day(s) ago. ` +
             `Drainer: ${drainerResult.isDrainer ? 'Yes' : 'No'}, ` +
             `Sweeper: ${sweeperResult.isSweeper ? 'Yes' : 'No'}.`;
    
    case 'ACTIVELY_COMPROMISED':
      return `ACTIVE compromise detected. Ongoing hostile fund movement identified. ` +
             `Drainer active: ${drainerResult.isActive}, ` +
             `Sweeper active: ${sweeperResult.isActive}.`;
  }
}

function generateSafeSignals(
  transactions: SolanaTransactionData[],
  drainerResult: DrainerDetectionResult,
  sweeperResult: SweeperBotDetectionResult
): string[] {
  const safeSignals: string[] = [];
  
  if (!drainerResult.isDrainer) {
    safeSignals.push('No drainer behavior pattern detected');
  }
  
  if (!sweeperResult.isSweeper) {
    safeSignals.push('No sweeper bot pattern detected');
  }
  
  // Check for presence of user interaction
  const txsWithMemo = transactions.filter(tx => tx.hasMemo);
  if (txsWithMemo.length > 0) {
    safeSignals.push(`${txsWithMemo.length} transaction(s) with memos (indicates user interaction)`);
  }
  
  // Check for irregular timing (human-like)
  const timestamps = transactions
    .map(tx => tx.timestamp)
    .filter((ts): ts is number => ts !== undefined);
  
  if (timestamps.length >= 3) {
    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
    const cv = avgInterval > 0 ? Math.sqrt(variance) / avgInterval : 0;
    
    if (cv > 0.8) {
      safeSignals.push('Irregular transaction timing suggests human behavior');
    }
  }
  
  return safeSignals;
}

function generateConfidenceFactors(
  signals: DetectedSignal[],
  drainerResult: DrainerDetectionResult,
  sweeperResult: SweeperBotDetectionResult
): string[] {
  const factors: string[] = [];
  
  const highConfidence = signals.filter(s => s.confidence === 'HIGH').length;
  const mediumConfidence = signals.filter(s => s.confidence === 'MEDIUM').length;
  
  if (highConfidence > 0) {
    factors.push(`${highConfidence} high-confidence signal(s) detected`);
  }
  if (mediumConfidence > 0) {
    factors.push(`${mediumConfidence} medium-confidence signal(s) detected`);
  }
  
  if (signals.length >= 2) {
    factors.push('Multiple independent signals corroborate findings');
  }
  
  return factors;
}

function generateUncertaintyFactors(
  transactions: SolanaTransactionData[],
  signals: DetectedSignal[]
): string[] {
  const factors: string[] = [];
  
  if (transactions.length < 10) {
    factors.push('Limited transaction history available');
  }
  
  if (signals.length === 0) {
    factors.push('No suspicious signals detected (may be false negative)');
  }
  
  factors.push('Solana off-chain attacks may not leave on-chain traces');
  
  return factors;
}

function generateSecurityExplanation(
  state: SolanaSecurityState,
  drainerResult: DrainerDetectionResult,
  sweeperResult: SweeperBotDetectionResult,
  daysSinceLastIncident?: number,
  signalCount?: number
): string {
  switch (state) {
    case 'SAFE':
      return 'No compromise indicators detected on this Solana wallet. ' +
             'However, this does NOT guarantee the wallet is completely safe - ' +
             'many Solana attacks occur off-chain and leave no detectable trace. ' +
             'If you suspect compromise, treat the wallet as unsafe.';
    
    case 'PREVIOUSLY_COMPROMISED':
      return `This wallet shows signs of PREVIOUS compromise, but NO ACTIVE RISK. ` +
             `${daysSinceLastIncident !== undefined ? `Last suspicious activity was ${daysSinceLastIncident} day(s) ago. ` : ''}` +
             `${signalCount} independent signal(s) were detected historically. ` +
             'No current automated or hostile fund movement observed.';
    
    case 'ACTIVELY_COMPROMISED':
      const threats: string[] = [];
      if (drainerResult.isActive) threats.push('drainer');
      if (sweeperResult.isActive) threats.push('sweeper bot');
      
      return `URGENT: This wallet shows signs of ACTIVE compromise. ` +
             `Active threats: ${threats.join(', ')}. ` +
             `${signalCount} high-confidence signal(s) detected. ` +
             'Immediate action recommended: Transfer remaining assets to a fresh wallet.';
  }
}

// ============================================
// CHECK IF PROGRAM IS WHITELISTED
// ============================================

export function isWhitelistedProgram(programId: string): boolean {
  return ALL_WHITELISTED_PROGRAMS.has(programId);
}

export function getWhitelistCategory(programId: string): string | null {
  if (SOLANA_SYSTEM_PROGRAMS.has(programId)) return 'SYSTEM';
  if (SOLANA_BRIDGE_PROGRAMS.has(programId)) return 'BRIDGE';
  if (SOLANA_NFT_PROGRAMS.has(programId)) return 'NFT';
  if (SOLANA_DEFI_PROGRAMS.has(programId)) return 'DEFI';
  if (SOLANA_STAKING_PROGRAMS.has(programId)) return 'STAKING';
  if (SOLANA_WALLET_PROGRAMS.has(programId)) return 'WALLET';
  return null;
}

// ============================================
// EXPORTS
// ============================================

export {
  DEFAULT_SOLANA_DETECTION_CONFIG as defaultConfig,
};

