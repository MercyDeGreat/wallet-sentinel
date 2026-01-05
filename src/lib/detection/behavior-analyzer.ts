// ============================================
// BEHAVIORAL ANALYSIS ENGINE v2.0
// ============================================
// Intent-aware sweeper bot detection with protocol recognition.
//
// CRITICAL FALSE POSITIVE PREVENTION:
// The current logic falsely labels NORMAL transactions as "Sweeper Bots"
// (e.g., Aztec presale bids, NFT mints, DEX deposits, bridge deposits).
//
// DO NOT classify as sweeper bot based SOLELY on:
// - Inflow → immediate outflow
// - High transaction frequency  
// - Single-asset forwarding behavior
//
// BEFORE labeling sweeper bot, require ALL of the following:
// 1. Outflows go to MULTIPLE UNRELATED recipient addresses
// 2. NO interaction with known protocols / verified contracts
// 3. Repeated pattern across MULTIPLE BLOCKS AND ASSETS
// 4. Absence of known user intent signals
//
// CONFIDENCE THRESHOLD: Only show "Sweeper Bot" if confidence ≥ 0.85

import { Chain, RiskLevel, WalletRole, AttackType, DetectedThreat } from '@/types';
import { isSafeContract, SafeContract } from './safe-contracts';
import { isKnownDrainer } from './drainer-addresses';
import { isLegitimateContract } from './malicious-database';

// ============================================
// ENHANCED CLASSIFICATION TYPES
// ============================================

export type UserBehaviorClassification =
  | 'NORMAL_USER'             // Regular user activity - NO ALERT
  | 'POWER_USER'              // High-frequency trader - NO ALERT
  | 'LIKELY_USER_AUTOMATION'  // Automated but legitimate - NO ALERT
  | 'NEW_WALLET'              // Limited history - NO ALERT
  | 'NEEDS_MANUAL_REVIEW'     // Unclear - LOW PRIORITY REVIEW
  | 'SWEEPER_BOT_SUSPECT'     // Shows some patterns - MEDIUM ALERT (confidence < 0.85)
  | 'CONFIRMED_SWEEPER'       // Confirmed sweeper - HIGH ALERT (confidence ≥ 0.85)
  | 'DRAINER_SUSPECT'         // Shows drainer patterns
  | 'CONFIRMED_DRAINER'       // Confirmed drainer
  | 'COMPROMISED_VICTIM'      // Wallet was drained by someone else
  | 'UNKNOWN';

// ============================================
// INTENT CLASSIFICATION
// ============================================

export type UserIntentType =
  | 'PRESALE_BID'            // Aztec, Blur bid, Seaport auction
  | 'NFT_MINT'               // NFT mint operation
  | 'DEX_DEPOSIT'            // Uniswap, Pendle, Curve deposit
  | 'DEX_SWAP'               // DEX swap
  | 'BRIDGE_DEPOSIT'         // Bridge transfer
  | 'EXCHANGE_DEPOSIT'       // CEX deposit forwarding
  | 'STAKING'                // Staking deposit
  | 'LENDING_DEPOSIT'        // Aave, Compound deposit
  | 'NFT_PURCHASE'           // OpenSea, Blur purchase
  | 'AGGREGATOR_SWAP'        // 1inch, 0x aggregator
  | 'ROUTER_INTERACTION'     // Router/relayer
  | 'GAS_REFUEL'             // Gas station/refuel
  | 'WALLET_CONSOLIDATION'   // User consolidating wallets
  | 'UNKNOWN_INTENT';

export interface DetectedIntent {
  type: UserIntentType;
  confidence: number; // 0-1
  protocol?: string;
  contractAddress?: string;
  description: string;
}

// ============================================
// KNOWN PROTOCOL ADDRESSES
// ============================================

const PRESALE_CONTRACTS = new Set([
  // Aztec
  '0x...', // Placeholder - add actual Aztec presale contracts
  // Blur Bid Pool
  '0x0000000000a39bb272e79075ade125fd351887ac',
  '0x29469395eaf6f95920e59f858042f0e28d98a20b',
  // Seaport variants
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
  '0x00000000006c3852cbef3e08e8df289169ede581',
  '0x0000000000000068f116a894984e2db1123eb395',
]);

const DEX_PROTOCOLS = new Set([
  // Uniswap
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
  '0xe592427a0aece92de3edee1f18e0157c05861564',
  '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad',
  // Pendle
  '0x0000000001e4ef00d069e71d6ba041b0a16f7ea0',
  '0x888888888889758f76e7103c6cbf23abbf58f946',
  // Curve
  '0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7',
  '0xd51a44d3fae010294c616388b506acda1bfaae46',
  // Balancer
  '0xba12222222228d8ba445958a75a0704d566bf2c8',
  // SushiSwap
  '0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f',
  // PancakeSwap
  '0x10ed43c718714eb63d5aa57b78b54704e256024e',
  '0x13f4ea83d0bd40e75c8222255bc855a974568dd4',
]);

const BRIDGE_CONTRACTS = new Set([
  '0x3ee18b2214aff97000d974cf647e7c347e8fa585', // Wormhole
  '0x99c9fc46f92e8a1c0dec1b1747d010903e884be1', // Optimism Gateway
  '0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f', // Arbitrum Inbox
  '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a', // Arbitrum Bridge
  '0x3154cf16ccdb4c6d922629664174b904d80f2c35', // Base Bridge
  '0x49048044d57e1c92a77f79988d21fa8faf74e97e', // Base Optimism Portal
  '0x32400084c286cf3e17e7b677ea9583e60a000324', // zkSync Era
  '0xabea9132b05a70803a4e85094fd0e1800777fbef', // zkSync Lite
  '0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf', // Polygon Bridge
  '0xa0c68c638235ee32657e8f720a23cec1bfc77c77', // Polygon ERC20 Bridge
]);

const EXCHANGE_HOT_WALLETS = new Set([
  // Binance
  '0x28c6c06298d514db089934071355e5743bf21d60',
  '0x21a31ee1afc51d94c2efccaa2092ad1028285549',
  '0xdfd5293d8e347dfe59e90efd55b2956a1343963d',
  '0x56eddb7aa87536c09ccc2793473599fd21a8b17f',
  '0xf977814e90da44bfa03b6295a0616a897441acec',
  // Coinbase
  '0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43',
  '0x71660c4005ba85c37ccec55d0c4493e66fe775d3',
  // Kraken
  '0x2910543af39aba0cd09dbb2d50200b3e800a63d2',
  '0x98ec059dc3adfbdd63429454aeb0c990fba4a128',
  // OKX
  '0x6cc5f688a315f3dc28a7781717a9a798a59fda7b',
  // Huobi
  '0xe2fc31f816a9b94326492132018c3aecc4a93ae1',
  '0xab5c66752a9e8167967685f1450532fb96d5d24f',
  // Crypto.com
  '0x6262998ced04146fa42253a5c0af90ca02dfd2a3',
  '0x46340b20830761efd32832a74d7169b29feb9758',
]);

const AGGREGATORS_ROUTERS = new Set([
  '0x1111111254eeb25477b68fb85ed929f73a960582', // 1inch V5
  '0x111111125421ca6dc452d289314280a0f8842a65', // 1inch V6
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff', // 0x Exchange
  '0x00000000009726632680fb29d3f7a9734e3010e2', // Rainbow Router
  '0x6131b5fae19ea4f9d964eac0408e4408b66337b5', // KyberSwap
  '0x881d40237659c251811cec9c364ef91dc08d300c', // MetaMask Swap
  '0x74de5d4fcbf63e00296fd95d33236b9794016631', // MetaMask Bridge
  '0x000000000022d473030f116ddee9f6b43ac78ba3', // Permit2
]);

const NFT_MARKETPLACES = new Set([
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // OpenSea Seaport 1.1
  '0x00000000006c3852cbef3e08e8df289169ede581', // OpenSea Seaport 1.4
  '0x0000000000000068f116a894984e2db1123eb395', // OpenSea Seaport 1.5
  '0x00000000000001ad428e4906ae43d8f9852d0dd6', // Seaport 1.6
  '0x000000000000ad05ccc4f10045630fb830b95127', // Blur
  '0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5', // Blur Exchange
  '0x59728544b08ab483533076417fbbb2fd0b17ce3a', // LooksRare
  '0x74312363e45dcaba76c59ec49a7aa8a65a67eed3', // X2Y2
]);

const STAKING_PROTOCOLS = new Set([
  '0xae7ab96520de3a18e5e111b5eaab095312d7fe84', // Lido stETH
  '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0', // wstETH
  '0xbe9895146f7af43049ca1c1ae358b0541ea49704', // cbETH
  '0xae78736cd615f374d3085123a210448e74fc6393', // rETH
  '0xac3e018457b222d93114458476f3e3416abbe38f', // sfrxETH
  '0xf403c135812408bfbe8713b5a23a04b3d48aae31', // Convex
]);

const LENDING_PROTOCOLS = new Set([
  '0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9', // Aave V2
  '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2', // Aave V3
  '0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b', // Compound
]);

// ============================================
// METHOD SIGNATURES FOR INTENT DETECTION
// ============================================

const MINT_SELECTORS = new Set([
  '0x1249c58b', // mint()
  '0xa0712d68', // mint(uint256)
  '0x40c10f19', // mint(address,uint256)
  '0x6a627842', // mint(address)
  '0xd85d3d27', // mintTo(address)
  '0x0febdd49', // safeMint
  '0x731133e9', // mint(address,uint256,uint256,bytes) - ERC1155
]);

const DEX_SWAP_SELECTORS = new Set([
  '0x38ed1739', // swapExactTokensForTokens
  '0x7ff36ab5', // swapExactETHForTokens
  '0x18cbafe5', // swapExactTokensForETH
  '0xfb3bdb41', // swapETHForExactTokens
  '0x5c11d795', // swapExactTokensForTokensSupportingFeeOnTransferTokens
  '0xb6f9de95', // swapExactETHForTokensSupportingFeeOnTransferTokens
  '0x791ac947', // swapExactTokensForETHSupportingFeeOnTransferTokens
  '0x04e45aaf', // exactInputSingle (Uniswap V3)
  '0xb858183f', // exactInput (Uniswap V3)
  '0x472b43f3', // swapExactTokensForTokens (Universal Router)
]);

const DEPOSIT_SELECTORS = new Set([
  '0xd0e30db0', // deposit()
  '0xb6b55f25', // deposit(uint256)
  '0x47e7ef24', // deposit(address,uint256)
  '0x6e553f65', // deposit(uint256,address)
  '0xe8eda9df', // deposit(address,uint256,address,uint16) - Aave
  '0xa415bcad', // borrow
  '0x69328dec', // withdraw
]);

const BID_SELECTORS = new Set([
  '0xfb0f3ee1', // fulfillBasicOrder (Seaport)
  '0x87201b41', // fulfillOrder (Seaport)
  '0x9a1fc3a7', // fulfillAvailableOrders
  '0xed98a574', // fulfillAdvancedOrder
]);

// ============================================
// BEHAVIOR ANALYSIS RESULT
// ============================================

export interface BehaviorAnalysisResult {
  // Final classification
  classification: UserBehaviorClassification;
  
  // Wallet role (victim, attacker, etc.)
  walletRole: WalletRole;
  
  // Confidence in this classification (0-100)
  confidence: number;
  
  // Is this definitely malicious?
  isDefinitelyMalicious: boolean;
  
  // Is this probably malicious?
  isProbablyMalicious: boolean;
  
  // Should we show a CRITICAL alert?
  showCriticalAlert: boolean;
  
  // Human-readable explanation
  explanation: string;
  
  // Detailed evidence
  evidence: BehaviorEvidence[];
  
  // Risk score (0-100)
  riskScore: number;
  
  // Risk level for display
  riskLevel: RiskLevel;
  
  // Detected threats (only for actual threats, not false positives)
  threats: DetectedThreat[];
  
  // NEW: Detected user intents
  detectedIntents: DetectedIntent[];
  
  // NEW: Explainability
  explainability: SweeperExplainability;
}

export interface SweeperExplainability {
  // Why this classification was made
  classificationReason: string;
  
  // Behavioral triggers that contributed to classification
  behavioralTriggers: string[];
  
  // Why user intent was ruled IN (protecting from false positive)
  userIntentDetected: string[];
  
  // Why protocol interaction was ruled IN (protecting from false positive)
  protocolInteractionDetected: string[];
  
  // Why sweeper was ruled OUT (if applicable)
  sweeperRuledOutReasons: string[];
  
  // Criteria that FAILED for sweeper classification
  failedSweeperCriteria: string[];
  
  // Criteria that PASSED for sweeper classification
  passedSweeperCriteria: string[];
}

export interface BehaviorEvidence {
  type: BehaviorEvidenceType;
  description: string;
  weight: number; // -50 to +50 (negative = reduces risk, positive = increases risk)
  data?: Record<string, unknown>;
}

export type BehaviorEvidenceType =
  // POSITIVE (increases risk) - ONLY count if NO protocol interaction
  | 'RAPID_DRAIN_NO_PROTOCOL'       // +40: Rapid drain to unknown addresses (NOT protocols)
  | 'MULTI_DEST_RANDOM_DRAIN'       // +45: Drains to MULTIPLE UNRELATED destinations
  | 'PROGRAMMATIC_TIMING'           // +25: Transactions at exact intervals
  | 'NO_PROTOCOL_INTERACTION'       // +30: Never touches any known protocol
  | 'KNOWN_DRAINER_RECIPIENT'       // +50: Sends to known drainer wallet
  | 'CROSS_WALLET_DRAIN_PATTERN'    // +45: Same pattern across multiple victim wallets
  | 'MULTI_ASSET_INDISCRIMINATE'    // +35: Drains random tokens indiscriminately
  | 'REPEATED_ACROSS_BLOCKS'        // +30: Same pattern repeated across many blocks
  
  // NEGATIVE (decreases risk) - Protocol Recognition
  | 'PRESALE_BID_DETECTED'          // -50: Aztec, Blur bid, Seaport auction
  | 'NFT_MINT_DETECTED'             // -50: NFT mint operation
  | 'DEX_DEPOSIT_DETECTED'          // -50: DEX deposit (Pendle, Uniswap, Curve)
  | 'DEX_SWAP_DETECTED'             // -40: DEX swap
  | 'BRIDGE_DEPOSIT_DETECTED'       // -50: Bridge transfer
  | 'EXCHANGE_DEPOSIT_DETECTED'     // -50: CEX deposit forwarding
  | 'STAKING_DETECTED'              // -40: Staking deposit
  | 'LENDING_DETECTED'              // -40: Lending protocol
  | 'NFT_MARKETPLACE_DETECTED'      // -40: OpenSea, Blur purchase
  | 'AGGREGATOR_DETECTED'           // -40: 1inch, 0x aggregator
  | 'ROUTER_INTERACTION_DETECTED'   // -35: Router/relayer
  | 'VERIFIED_CONTRACT_INTERACTION' // -30: Any verified contract
  | 'LONG_WALLET_HISTORY'           // -20: Old wallet with diverse activity
  | 'MANUAL_TRANSACTION_TIMING'     // -15: Irregular timing (human)
  | 'SINGLE_PURPOSE_DESTINATION'    // -25: Funds go to ONE known destination
  | 'USER_INTENT_SIGNALS'           // -35: Clear user intent detected
  
  // NEUTRAL
  | 'FAST_FUND_MOVEMENT'            // 0: Moving funds quickly is NOT suspicious alone
  | 'HIGH_TRANSACTION_VOLUME'       // 0: High volume alone is NOT suspicious
  | 'SINGLE_ASSET_FORWARD';         // 0: Forwarding single asset is NOT suspicious alone

// ============================================
// SWEEPER BOT INDICATORS (Stricter)
// ============================================

export interface SweeperBotIndicators {
  // REQUIRED: Outflows to MULTIPLE UNRELATED destinations
  multipleUnrelatedDestinations: boolean;
  uniqueDestinationCount: number;
  
  // REQUIRED: NO protocol interaction
  hasNoProtocolInteraction: boolean;
  protocolsInteracted: string[];
  
  // REQUIRED: Repeated pattern across multiple blocks
  repeatedAcrossBlocks: boolean;
  blockSpan: number;
  
  // REQUIRED: Absence of user intent signals
  hasUserIntentSignals: boolean;
  detectedIntents: UserIntentType[];
  
  // Supporting indicators
  avgDrainTimeAfterDeposit?: number;
  transactionsPerHour: number;
  identicalPatternCount: number;
  multiAssetDrain: boolean;
  sendsToKnownDrainers: boolean;
}

export interface SweeperBotScore {
  score: number; // 0-100
  isSweeperBot: boolean;
  confidence: number; // 0-1, must be ≥ 0.85 to show "Sweeper Bot"
  indicators: SweeperBotIndicators;
  failedCriteria: string[];
  passedCriteria: string[];
  // NEW: Explainability
  ruledOutReasons: string[];
}

// ============================================
// TRANSACTION DATA FOR ANALYSIS
// ============================================

export interface TransactionForAnalysis {
  hash: string;
  from: string;
  to: string;
  value: string;
  timestamp: number;
  methodId?: string;
  isOutbound: boolean;
  isInbound: boolean;
  gasUsed?: number;
  blockNumber?: number;
}

// ============================================
// PROTOCOL RECOGNITION LAYER
// ============================================

function recognizeProtocol(address: string): { isKnown: boolean; protocol?: string; category?: string } {
  if (!address) return { isKnown: false };
  
  const normalized = address.toLowerCase();
  
  // Check safe contracts first
  const safeContract = isSafeContract(normalized);
  if (safeContract) {
    return { isKnown: true, protocol: safeContract.name, category: safeContract.category };
  }
  
  // Check legitimate contracts
  const legitimateName = isLegitimateContract(normalized);
  if (legitimateName) {
    return { isKnown: true, protocol: legitimateName, category: 'LEGITIMATE' };
  }
  
  // Check specific categories
  if (PRESALE_CONTRACTS.has(normalized)) {
    return { isKnown: true, protocol: 'Presale Contract', category: 'PRESALE' };
  }
  if (DEX_PROTOCOLS.has(normalized)) {
    return { isKnown: true, protocol: 'DEX', category: 'DEX' };
  }
  if (BRIDGE_CONTRACTS.has(normalized)) {
    return { isKnown: true, protocol: 'Bridge', category: 'BRIDGE' };
  }
  if (EXCHANGE_HOT_WALLETS.has(normalized)) {
    return { isKnown: true, protocol: 'Exchange', category: 'EXCHANGE' };
  }
  if (AGGREGATORS_ROUTERS.has(normalized)) {
    return { isKnown: true, protocol: 'Aggregator/Router', category: 'AGGREGATOR' };
  }
  if (NFT_MARKETPLACES.has(normalized)) {
    return { isKnown: true, protocol: 'NFT Marketplace', category: 'NFT_MARKETPLACE' };
  }
  if (STAKING_PROTOCOLS.has(normalized)) {
    return { isKnown: true, protocol: 'Staking', category: 'STAKING' };
  }
  if (LENDING_PROTOCOLS.has(normalized)) {
    return { isKnown: true, protocol: 'Lending', category: 'LENDING' };
  }
  
  return { isKnown: false };
}

// ============================================
// INTENT-AWARE TRANSACTION FILTER
// ============================================

function detectTransactionIntent(tx: TransactionForAnalysis): DetectedIntent | null {
  const methodId = tx.methodId?.toLowerCase().slice(0, 10);
  const toAddress = tx.to?.toLowerCase();
  
  if (!toAddress) return null;
  
  // Check method signatures first
  if (methodId) {
    if (MINT_SELECTORS.has(methodId)) {
      return {
        type: 'NFT_MINT',
        confidence: 0.95,
        contractAddress: toAddress,
        description: 'NFT mint operation detected',
      };
    }
    
    if (DEX_SWAP_SELECTORS.has(methodId)) {
      return {
        type: 'DEX_SWAP',
        confidence: 0.9,
        contractAddress: toAddress,
        description: 'DEX swap operation detected',
      };
    }
    
    if (DEPOSIT_SELECTORS.has(methodId)) {
      const protocol = recognizeProtocol(toAddress);
      if (protocol.category === 'DEX') {
        return {
          type: 'DEX_DEPOSIT',
          confidence: 0.9,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `DEX deposit to ${protocol.protocol}`,
        };
      }
      if (protocol.category === 'STAKING') {
        return {
          type: 'STAKING',
          confidence: 0.9,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Staking deposit to ${protocol.protocol}`,
        };
      }
      if (protocol.category === 'LENDING') {
        return {
          type: 'LENDING_DEPOSIT',
          confidence: 0.9,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Lending deposit to ${protocol.protocol}`,
        };
      }
    }
    
    if (BID_SELECTORS.has(methodId)) {
      return {
        type: 'PRESALE_BID',
        confidence: 0.95,
        contractAddress: toAddress,
        description: 'Presale/auction bid detected (Seaport)',
      };
    }
  }
  
  // Check by destination address
  const protocol = recognizeProtocol(toAddress);
  
  if (protocol.isKnown) {
    switch (protocol.category) {
      case 'PRESALE':
        return {
          type: 'PRESALE_BID',
          confidence: 0.9,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Presale interaction with ${protocol.protocol}`,
        };
      case 'DEX':
        return {
          type: 'DEX_DEPOSIT',
          confidence: 0.85,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `DEX interaction with ${protocol.protocol}`,
        };
      case 'BRIDGE':
        return {
          type: 'BRIDGE_DEPOSIT',
          confidence: 0.95,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Bridge deposit to ${protocol.protocol}`,
        };
      case 'EXCHANGE':
        return {
          type: 'EXCHANGE_DEPOSIT',
          confidence: 0.95,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Exchange deposit to ${protocol.protocol}`,
        };
      case 'NFT_MARKETPLACE':
        return {
          type: 'NFT_PURCHASE',
          confidence: 0.9,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `NFT marketplace interaction with ${protocol.protocol}`,
        };
      case 'AGGREGATOR':
        return {
          type: 'AGGREGATOR_SWAP',
          confidence: 0.9,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Aggregator interaction with ${protocol.protocol}`,
        };
      case 'STAKING':
        return {
          type: 'STAKING',
          confidence: 0.9,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Staking interaction with ${protocol.protocol}`,
        };
      case 'LENDING':
        return {
          type: 'LENDING_DEPOSIT',
          confidence: 0.85,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Lending interaction with ${protocol.protocol}`,
        };
      default:
        return {
          type: 'ROUTER_INTERACTION',
          confidence: 0.8,
          protocol: protocol.protocol,
          contractAddress: toAddress,
          description: `Verified protocol interaction with ${protocol.protocol}`,
        };
    }
  }
  
  return null;
}

// ============================================
// MAIN BEHAVIORAL ANALYSIS FUNCTION
// ============================================

export async function analyzeWalletBehavior(
  address: string,
  chain: Chain,
  transactions: TransactionForAnalysis[],
  options?: {
    includeApprovalAnalysis?: boolean;
    knownDrainerAddresses?: Set<string>;
  }
): Promise<BehaviorAnalysisResult> {
  const evidence: BehaviorEvidence[] = [];
  const detectedIntents: DetectedIntent[] = [];
  const explainability: SweeperExplainability = {
    classificationReason: '',
    behavioralTriggers: [],
    userIntentDetected: [],
    protocolInteractionDetected: [],
    sweeperRuledOutReasons: [],
    failedSweeperCriteria: [],
    passedSweeperCriteria: [],
  };
  
  let riskScore = 0;
  
  // Normalize address
  const normalizedAddress = address.toLowerCase();
  
  // Safe guard for empty transactions
  const safeTxs = Array.isArray(transactions) 
    ? transactions.filter(tx => tx != null) 
    : [];

  // ============================================
  // STEP 1: Check if address is in known drainer database
  // ============================================
  if (isKnownDrainer(normalizedAddress)) {
    return createConfirmedDrainerResult(address, explainability);
  }

  // ============================================
  // STEP 2: PROTOCOL RECOGNITION LAYER
  // Run BEFORE any risk classification
  // ============================================
  const protocolInteractions: string[] = [];
  let hasAnyProtocolInteraction = false;
  
  for (const tx of safeTxs) {
    // Detect intent for each transaction
    const intent = detectTransactionIntent(tx);
    if (intent) {
      detectedIntents.push(intent);
      hasAnyProtocolInteraction = true;
    }
    
    // Check if destination is known protocol
    const protocol = recognizeProtocol(tx.to);
    if (protocol.isKnown && protocol.protocol) {
      protocolInteractions.push(protocol.protocol);
      hasAnyProtocolInteraction = true;
    }
  }

  // ============================================
  // STEP 3: INTENT-AWARE FILTERING
  // If clear user intent detected, drastically reduce risk
  // ============================================
  const uniqueIntents = [...new Set(detectedIntents.map(i => i.type))];
  
  for (const intentType of uniqueIntents) {
    const intentEvidence = getIntentEvidence(intentType, detectedIntents);
    if (intentEvidence) {
      evidence.push(intentEvidence);
      explainability.userIntentDetected.push(intentEvidence.description);
      riskScore += intentEvidence.weight;
    }
  }
  
  // Record protocol interactions
  const uniqueProtocols = [...new Set(protocolInteractions)];
  if (uniqueProtocols.length > 0) {
    evidence.push({
      type: 'VERIFIED_CONTRACT_INTERACTION',
      description: `Interacts with verified protocols: ${uniqueProtocols.slice(0, 5).join(', ')}`,
      weight: -30,
      data: { protocols: uniqueProtocols },
    });
    explainability.protocolInteractionDetected.push(
      `Interacted with ${uniqueProtocols.length} verified protocols`
    );
    riskScore -= 30;
  }

  // ============================================
  // STEP 4: Check STRICT sweeper criteria
  // ALL must be true to even consider sweeper classification
  // ============================================
  const sweeperIndicators = analyzeStrictSweeperCriteria(
    safeTxs,
    normalizedAddress,
    hasAnyProtocolInteraction,
    uniqueIntents,
    options?.knownDrainerAddresses
  );
  
  // Record which criteria passed/failed
  explainability.passedSweeperCriteria = sweeperIndicators.passedCriteria;
  explainability.failedSweeperCriteria = sweeperIndicators.failedCriteria;
  
  // If ANY required criterion fails, rule out sweeper bot
  const requiredCriteriaMet = 
    sweeperIndicators.multipleUnrelatedDestinations &&
    sweeperIndicators.hasNoProtocolInteraction &&
    sweeperIndicators.repeatedAcrossBlocks &&
    !sweeperIndicators.hasUserIntentSignals;
  
  if (!requiredCriteriaMet) {
    // Add ruled-out reasons
    if (!sweeperIndicators.multipleUnrelatedDestinations) {
      explainability.sweeperRuledOutReasons.push(
        'Funds go to single or related destinations (not indiscriminate draining)'
      );
    }
    if (!sweeperIndicators.hasNoProtocolInteraction) {
      explainability.sweeperRuledOutReasons.push(
        `Interacts with known protocols: ${sweeperIndicators.protocolsInteracted.join(', ')}`
      );
    }
    if (!sweeperIndicators.repeatedAcrossBlocks) {
      explainability.sweeperRuledOutReasons.push(
        'Pattern not repeated across multiple blocks/assets'
      );
    }
    if (sweeperIndicators.hasUserIntentSignals) {
      explainability.sweeperRuledOutReasons.push(
        `User intent detected: ${sweeperIndicators.detectedIntents.join(', ')}`
      );
    }
  }

  // ============================================
  // STEP 5: Additional evidence analysis
  // ============================================
  
  // Analyze timing patterns
  const timingEvidence = analyzeTransactionTiming(safeTxs);
  evidence.push(...timingEvidence);
  for (const e of timingEvidence) {
    riskScore += e.weight;
    if (e.weight > 0) {
      explainability.behavioralTriggers.push(e.description);
    }
  }
  
  // Analyze fund flow (only add risk if NO protocol interaction)
  if (!hasAnyProtocolInteraction) {
    const flowEvidence = analyzeNonProtocolFlows(safeTxs, normalizedAddress, options?.knownDrainerAddresses);
    evidence.push(...flowEvidence);
    for (const e of flowEvidence) {
      riskScore += e.weight;
      if (e.weight > 0) {
        explainability.behavioralTriggers.push(e.description);
      }
    }
  }
  
  // Check wallet history diversity
  const historyEvidence = analyzeWalletHistory(safeTxs);
  evidence.push(...historyEvidence);
  for (const e of historyEvidence) {
    riskScore += e.weight;
  }

  // ============================================
  // STEP 6: Calculate final classification
  // ============================================
  
  // Clamp risk score
  riskScore = Math.max(0, Math.min(100, riskScore));
  
  // Calculate confidence
  const confidence = calculateConfidence(
    evidence,
    requiredCriteriaMet,
    sweeperIndicators.sendsToKnownDrainers
  );
  
  // Determine classification
  const classification = determineClassification(
    riskScore,
    confidence,
    evidence,
    requiredCriteriaMet,
    sweeperIndicators,
    detectedIntents
  );
  
  // Generate explanation
  explainability.classificationReason = generateClassificationReason(
    classification.classification,
    explainability
  );
  
  // Only show critical alert if confidence >= 0.85 AND is confirmed sweeper
  const showCriticalAlert = 
    confidence >= 85 && 
    classification.classification === 'CONFIRMED_SWEEPER';

  return {
    classification: classification.classification,
    walletRole: classification.walletRole,
    confidence,
    isDefinitelyMalicious: confidence >= 85 && classification.classification === 'CONFIRMED_SWEEPER',
    isProbablyMalicious: confidence >= 70 && riskScore >= 60 && requiredCriteriaMet,
    showCriticalAlert,
    explanation: generateExplanation(classification.classification, evidence, confidence, explainability),
    evidence,
    riskScore,
    riskLevel: getRiskLevel(riskScore, confidence, hasAnyProtocolInteraction),
    threats: classification.threats,
    detectedIntents,
    explainability,
  };
}

// ============================================
// STRICT SWEEPER CRITERIA ANALYSIS
// ============================================

function analyzeStrictSweeperCriteria(
  transactions: TransactionForAnalysis[],
  walletAddress: string,
  hasProtocolInteraction: boolean,
  detectedIntentTypes: UserIntentType[],
  knownDrainerAddresses?: Set<string>
): SweeperBotIndicators & { passedCriteria: string[]; failedCriteria: string[] } {
  const passedCriteria: string[] = [];
  const failedCriteria: string[] = [];
  
  const outboundTxs = transactions.filter(tx => tx.isOutbound);
  const inboundTxs = transactions.filter(tx => tx.isInbound);
  
  // ============================================
  // CRITERION 1: Multiple UNRELATED destinations
  // ============================================
  const destinations = new Map<string, number>();
  for (const tx of outboundTxs) {
    if (tx.to) {
      const dest = tx.to.toLowerCase();
      destinations.set(dest, (destinations.get(dest) || 0) + 1);
    }
  }
  
  // Check if destinations are unrelated (not protocols, not exchanges)
  let unrelatedDestCount = 0;
  const protocolsInteracted: string[] = [];
  
  for (const [dest] of destinations) {
    const protocol = recognizeProtocol(dest);
    if (protocol.isKnown) {
      if (protocol.protocol) {
        protocolsInteracted.push(protocol.protocol);
      }
    } else {
      unrelatedDestCount++;
    }
  }
  
  const multipleUnrelatedDestinations = unrelatedDestCount >= 3;
  if (multipleUnrelatedDestinations) {
    passedCriteria.push(`Sends to ${unrelatedDestCount} unrelated addresses`);
  } else {
    failedCriteria.push(`Only ${unrelatedDestCount} unrelated destinations (need ≥3)`);
  }
  
  // ============================================
  // CRITERION 2: NO protocol interaction
  // ============================================
  const hasNoProtocolInteraction = !hasProtocolInteraction && protocolsInteracted.length === 0;
  if (hasNoProtocolInteraction) {
    passedCriteria.push('No interaction with known protocols');
  } else {
    failedCriteria.push(`Interacts with protocols: ${protocolsInteracted.join(', ')}`);
  }
  
  // ============================================
  // CRITERION 3: Repeated pattern across multiple blocks
  // ============================================
  const blocks = new Set(transactions.map(tx => tx.blockNumber).filter(Boolean));
  const blockSpan = blocks.size;
  
  // Check for repeated drain pattern
  let repeatCount = 0;
  for (const inbound of inboundTxs) {
    const rapidOutbound = outboundTxs.find(out =>
      out.timestamp > inbound.timestamp &&
      out.timestamp - inbound.timestamp < 120 // 2 minutes
    );
    if (rapidOutbound) {
      repeatCount++;
    }
  }
  
  const repeatedAcrossBlocks = blockSpan >= 5 && repeatCount >= 3;
  if (repeatedAcrossBlocks) {
    passedCriteria.push(`Pattern repeated across ${blockSpan} blocks, ${repeatCount} drain instances`);
  } else {
    failedCriteria.push(`Only ${blockSpan} blocks, ${repeatCount} drain instances (need more)`);
  }
  
  // ============================================
  // CRITERION 4: Absence of user intent signals
  // ============================================
  const hasUserIntentSignals = detectedIntentTypes.length > 0;
  if (!hasUserIntentSignals) {
    passedCriteria.push('No user intent signals detected');
  } else {
    failedCriteria.push(`User intent detected: ${detectedIntentTypes.join(', ')}`);
  }
  
  // ============================================
  // Supporting indicators
  // ============================================
  
  // Average drain time
  let totalDrainTime = 0;
  let drainCount = 0;
  for (const inbound of inboundTxs) {
    const rapidOutbound = outboundTxs.find(out =>
      out.timestamp > inbound.timestamp
    );
    if (rapidOutbound) {
      totalDrainTime += rapidOutbound.timestamp - inbound.timestamp;
      drainCount++;
    }
  }
  const avgDrainTime = drainCount > 0 ? totalDrainTime / drainCount : undefined;
  
  // Transactions per hour
  let txPerHour = 0;
  if (transactions.length >= 2) {
    const sorted = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
    const timeSpanHours = (sorted[sorted.length - 1].timestamp - sorted[0].timestamp) / 3600;
    if (timeSpanHours > 0) {
      txPerHour = transactions.length / timeSpanHours;
    }
  }
  
  // Multi-asset drain
  const multiAssetDrain = false; // Would need token info to determine
  
  // Sends to known drainers
  let sendsToKnownDrainers = false;
  if (knownDrainerAddresses && knownDrainerAddresses.size > 0) {
    sendsToKnownDrainers = outboundTxs.some(tx =>
      tx.to && knownDrainerAddresses.has(tx.to.toLowerCase())
    );
  }
  if (sendsToKnownDrainers) {
    passedCriteria.push('Sends to known drainer addresses');
  }
  
  return {
    multipleUnrelatedDestinations,
    uniqueDestinationCount: destinations.size,
    hasNoProtocolInteraction,
    protocolsInteracted,
    repeatedAcrossBlocks,
    blockSpan,
    hasUserIntentSignals,
    detectedIntents: detectedIntentTypes,
    avgDrainTimeAfterDeposit: avgDrainTime,
    transactionsPerHour: txPerHour,
    identicalPatternCount: repeatCount,
    multiAssetDrain,
    sendsToKnownDrainers,
    passedCriteria,
    failedCriteria,
  };
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function getIntentEvidence(intentType: UserIntentType, intents: DetectedIntent[]): BehaviorEvidence | null {
  const count = intents.filter(i => i.type === intentType).length;
  
  const intentMap: Record<UserIntentType, { type: BehaviorEvidenceType; weight: number; desc: string }> = {
    'PRESALE_BID': { type: 'PRESALE_BID_DETECTED', weight: -50, desc: `Presale/auction bid detected (${count} txs)` },
    'NFT_MINT': { type: 'NFT_MINT_DETECTED', weight: -50, desc: `NFT mint detected (${count} txs)` },
    'DEX_DEPOSIT': { type: 'DEX_DEPOSIT_DETECTED', weight: -50, desc: `DEX deposit detected (${count} txs)` },
    'DEX_SWAP': { type: 'DEX_SWAP_DETECTED', weight: -40, desc: `DEX swap detected (${count} txs)` },
    'BRIDGE_DEPOSIT': { type: 'BRIDGE_DEPOSIT_DETECTED', weight: -50, desc: `Bridge deposit detected (${count} txs)` },
    'EXCHANGE_DEPOSIT': { type: 'EXCHANGE_DEPOSIT_DETECTED', weight: -50, desc: `Exchange deposit detected (${count} txs)` },
    'STAKING': { type: 'STAKING_DETECTED', weight: -40, desc: `Staking detected (${count} txs)` },
    'LENDING_DEPOSIT': { type: 'LENDING_DETECTED', weight: -40, desc: `Lending deposit detected (${count} txs)` },
    'NFT_PURCHASE': { type: 'NFT_MARKETPLACE_DETECTED', weight: -40, desc: `NFT marketplace activity (${count} txs)` },
    'AGGREGATOR_SWAP': { type: 'AGGREGATOR_DETECTED', weight: -40, desc: `Aggregator swap detected (${count} txs)` },
    'ROUTER_INTERACTION': { type: 'ROUTER_INTERACTION_DETECTED', weight: -35, desc: `Router interaction detected (${count} txs)` },
    'GAS_REFUEL': { type: 'USER_INTENT_SIGNALS', weight: -25, desc: 'Gas refuel detected' },
    'WALLET_CONSOLIDATION': { type: 'SINGLE_PURPOSE_DESTINATION', weight: -25, desc: 'Wallet consolidation pattern' },
    'UNKNOWN_INTENT': { type: 'USER_INTENT_SIGNALS', weight: -10, desc: 'Possible user intent detected' },
  };
  
  const mapping = intentMap[intentType];
  if (!mapping) return null;
  
  return {
    type: mapping.type,
    description: mapping.desc,
    weight: mapping.weight,
    data: { intentType, count },
  };
}

function analyzeTransactionTiming(transactions: TransactionForAnalysis[]): BehaviorEvidence[] {
  const evidence: BehaviorEvidence[] = [];
  
  if (transactions.length < 5) {
    return evidence;
  }

  const sorted = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
  
  const intervals: number[] = [];
  for (let i = 1; i < sorted.length; i++) {
    intervals.push(sorted[i].timestamp - sorted[i - 1].timestamp);
  }
  
  if (intervals.length < 3) return evidence;

  const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
  const stdDev = Math.sqrt(variance);
  const coefficientOfVariation = avgInterval > 0 ? stdDev / avgInterval : 0;
  
  // Very low variation suggests programmatic, but NOT necessarily malicious
  if (coefficientOfVariation < 0.1 && avgInterval < 60) {
    evidence.push({
      type: 'PROGRAMMATIC_TIMING',
      description: `Very consistent timing (CV: ${coefficientOfVariation.toFixed(3)}, avg: ${avgInterval.toFixed(0)}s)`,
      weight: 25, // Reduced from 30 - timing alone is not conclusive
      data: { avgInterval, stdDev, cv: coefficientOfVariation },
    });
  }
  
  // High variation strongly suggests human behavior
  if (coefficientOfVariation > 0.8) {
    evidence.push({
      type: 'MANUAL_TRANSACTION_TIMING',
      description: 'Irregular timing strongly suggests human behavior',
      weight: -15,
      data: { cv: coefficientOfVariation },
    });
  }

  return evidence;
}

function analyzeNonProtocolFlows(
  transactions: TransactionForAnalysis[],
  walletAddress: string,
  knownDrainerAddresses?: Set<string>
): BehaviorEvidence[] {
  const evidence: BehaviorEvidence[] = [];
  
  const outboundTxs = transactions.filter(tx => tx.isOutbound);
  const inboundTxs = transactions.filter(tx => tx.isInbound);
  
  // Check for draining to known drainers
  if (knownDrainerAddresses && knownDrainerAddresses.size > 0) {
    const drainerDests = outboundTxs.filter(tx =>
      tx.to && knownDrainerAddresses.has(tx.to.toLowerCase())
    );
    
    if (drainerDests.length > 0) {
      evidence.push({
        type: 'KNOWN_DRAINER_RECIPIENT',
        description: `Sends to known drainer addresses (${drainerDests.length} txs)`,
        weight: 50,
        data: { count: drainerDests.length },
      });
    }
  }
  
  // Check for rapid drain to UNKNOWN addresses (not protocols)
  let rapidDrainToUnknown = 0;
  for (const inbound of inboundTxs) {
    const rapidOutbound = outboundTxs.find(out => {
      if (out.timestamp <= inbound.timestamp) return false;
      if (out.timestamp - inbound.timestamp > 60) return false;
      
      // Check if destination is unknown
      const protocol = recognizeProtocol(out.to);
      return !protocol.isKnown;
    });
    
    if (rapidOutbound) {
      rapidDrainToUnknown++;
    }
  }
  
  if (rapidDrainToUnknown >= 3) {
    evidence.push({
      type: 'RAPID_DRAIN_NO_PROTOCOL',
      description: `Rapid drain to unknown addresses (${rapidDrainToUnknown} instances)`,
      weight: 40,
      data: { count: rapidDrainToUnknown },
    });
  }
  
  return evidence;
}

function analyzeWalletHistory(transactions: TransactionForAnalysis[]): BehaviorEvidence[] {
  const evidence: BehaviorEvidence[] = [];
  
  if (transactions.length > 50) {
    const uniqueContracts = new Set(
      transactions.map(tx => tx.to?.toLowerCase()).filter(Boolean)
    );
    
    // Check how many are known protocols
    let knownProtocolCount = 0;
    for (const addr of uniqueContracts) {
      if (recognizeProtocol(addr as string).isKnown) {
        knownProtocolCount++;
      }
    }
    
    if (knownProtocolCount >= 5) {
      evidence.push({
        type: 'LONG_WALLET_HISTORY',
        description: `Diverse wallet history: ${uniqueContracts.size} unique addresses, ${knownProtocolCount} known protocols`,
        weight: -20,
        data: { uniqueContracts: uniqueContracts.size, knownProtocols: knownProtocolCount },
      });
    }
  }
  
  return evidence;
}

function calculateConfidence(
  evidence: BehaviorEvidence[],
  requiredCriteriaMet: boolean,
  sendsToKnownDrainers: boolean
): number {
  const evidenceCount = evidence.length;
  const absoluteWeightSum = evidence.reduce((sum, e) => sum + Math.abs(e.weight), 0);
  
  // Base confidence from evidence
  let confidence = Math.min(40, evidenceCount * 4);
  
  // Add confidence from strong evidence
  confidence += Math.min(30, absoluteWeightSum / 6);
  
  // If sends to known drainer, high confidence
  if (sendsToKnownDrainers) {
    confidence += 25;
  }
  
  // If required criteria NOT met, cap confidence low
  if (!requiredCriteriaMet) {
    confidence = Math.min(60, confidence);
  }
  
  // Cap at 95% unless confirmed drainer
  const hasConfirmedDrainer = evidence.some(e => e.type === 'KNOWN_DRAINER_RECIPIENT');
  if (!hasConfirmedDrainer) {
    confidence = Math.min(90, confidence);
  }
  
  return Math.round(confidence);
}

interface ClassificationResult {
  classification: UserBehaviorClassification;
  walletRole: WalletRole;
  threats: DetectedThreat[];
}

function determineClassification(
  riskScore: number,
  confidence: number,
  evidence: BehaviorEvidence[],
  requiredCriteriaMet: boolean,
  indicators: SweeperBotIndicators,
  detectedIntents: DetectedIntent[]
): ClassificationResult {
  const threats: DetectedThreat[] = [];
  
  // Check for strong user intent (protects from false positive)
  const hasStrongUserIntent = detectedIntents.some(i => i.confidence >= 0.9);
  const hasProtocolInteraction = !indicators.hasNoProtocolInteraction;
  
  // If user intent or protocol interaction detected, heavily prefer non-sweeper classification
  if (hasStrongUserIntent || hasProtocolInteraction) {
    // Can still be NEEDS_MANUAL_REVIEW if risk score is very high
    if (riskScore >= 70 && indicators.sendsToKnownDrainers) {
      return {
        classification: 'NEEDS_MANUAL_REVIEW',
        walletRole: 'UNKNOWN',
        threats: [],
      };
    }
    
    // Otherwise, classify as normal activity
    if (detectedIntents.length > 5 || evidence.some(e => e.type === 'LONG_WALLET_HISTORY')) {
      return {
        classification: 'POWER_USER',
        walletRole: 'UNKNOWN',
        threats: [],
      };
    }
    
    if (evidence.some(e => e.type === 'PROGRAMMATIC_TIMING')) {
      return {
        classification: 'LIKELY_USER_AUTOMATION',
        walletRole: 'UNKNOWN',
        threats: [],
      };
    }
    
    return {
      classification: 'NORMAL_USER',
      walletRole: 'UNKNOWN',
      threats: [],
    };
  }
  
  // Only consider sweeper if ALL required criteria are met
  if (requiredCriteriaMet) {
    // Confidence >= 0.85 = Confirmed Sweeper
    if (confidence >= 85 && riskScore >= 70) {
      threats.push({
        id: `sweeper-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: 'CRITICAL',
        title: 'Confirmed Sweeper Bot',
        description: 'This wallet exhibits all indicators of sweeper bot behavior.',
        technicalDetails: evidence.filter(e => e.weight > 0).map(e => e.description).join('; '),
        detectedAt: new Date().toISOString(),
        relatedAddresses: [],
        relatedTransactions: [],
        ongoingRisk: true,
      });
      
      return {
        classification: 'CONFIRMED_SWEEPER',
        walletRole: 'ATTACKER',
        threats,
      };
    }
    
    // Confidence < 0.85 but criteria met = Suspect
    if (confidence >= 60 && riskScore >= 50) {
      return {
        classification: 'SWEEPER_BOT_SUSPECT',
        walletRole: 'UNKNOWN',
        threats: [],
      };
    }
  }
  
  // Not enough evidence for any sweeper classification
  if (evidence.some(e => e.type === 'LONG_WALLET_HISTORY')) {
    return {
      classification: 'POWER_USER',
      walletRole: 'UNKNOWN',
      threats: [],
    };
  }
  
  if (riskScore < 30) {
    return {
      classification: 'NORMAL_USER',
      walletRole: 'UNKNOWN',
      threats: [],
    };
  }
  
  if (riskScore >= 40 && riskScore < 60) {
    return {
      classification: 'NEEDS_MANUAL_REVIEW',
      walletRole: 'UNKNOWN',
      threats: [],
    };
  }
  
  return {
    classification: 'UNKNOWN',
    walletRole: 'UNKNOWN',
    threats: [],
  };
}

function generateClassificationReason(
  classification: UserBehaviorClassification,
  explainability: SweeperExplainability
): string {
  switch (classification) {
    case 'NORMAL_USER':
      if (explainability.userIntentDetected.length > 0) {
        return `Normal user activity. User intent detected: ${explainability.userIntentDetected[0]}`;
      }
      if (explainability.protocolInteractionDetected.length > 0) {
        return `Normal user activity. ${explainability.protocolInteractionDetected[0]}`;
      }
      return 'Normal user activity pattern with no suspicious indicators.';
      
    case 'POWER_USER':
      return 'Active trader/power user with diverse protocol interactions.';
      
    case 'LIKELY_USER_AUTOMATION':
      return 'Automated transactions but interacting with legitimate protocols. Likely user-controlled automation (bot trading, scheduled transactions).';
      
    case 'NEEDS_MANUAL_REVIEW':
      return `Unable to definitively classify. ${explainability.failedSweeperCriteria.length} sweeper criteria failed, but some suspicious patterns present.`;
      
    case 'SWEEPER_BOT_SUSPECT':
      return `Shows sweeper patterns but confidence below threshold. Failed criteria: ${explainability.failedSweeperCriteria.slice(0, 2).join('; ')}`;
      
    case 'CONFIRMED_SWEEPER':
      return `All sweeper criteria met with high confidence. Passed: ${explainability.passedSweeperCriteria.join('; ')}`;
      
    default:
      return 'Classification pending further analysis.';
  }
}

function generateExplanation(
  classification: UserBehaviorClassification,
  evidence: BehaviorEvidence[],
  confidence: number,
  explainability: SweeperExplainability
): string {
  switch (classification) {
    case 'NORMAL_USER':
      if (explainability.userIntentDetected.length > 0) {
        return `No malicious behavior detected. ${explainability.userIntentDetected[0]}. ` +
               'This appears to be normal user-initiated activity.';
      }
      return 'No malicious behavior detected. This wallet shows normal user activity patterns.';
    
    case 'POWER_USER':
      return 'This wallet belongs to a power user or active trader. ' +
             `Diverse protocol interactions detected: ${explainability.protocolInteractionDetected[0] || 'multiple protocols'}.`;
    
    case 'LIKELY_USER_AUTOMATION':
      return 'This wallet shows automated transaction patterns, but interactions are with ' +
             'legitimate protocols. This is likely user-controlled automation (trading bot, scheduled transactions), NOT a sweeper bot.';
    
    case 'NEW_WALLET':
      return 'New wallet with limited transaction history. Insufficient data for classification.';
    
    case 'NEEDS_MANUAL_REVIEW':
      return `Classification uncertain (confidence: ${confidence}%). ` +
             `Some suspicious patterns detected but sweeper criteria not fully met. ` +
             `Ruled out because: ${explainability.sweeperRuledOutReasons[0] || 'insufficient evidence'}.`;
    
    case 'SWEEPER_BOT_SUSPECT':
      return `This wallet shows some sweeper-like patterns (confidence: ${confidence}%), ` +
             `but does not meet all required criteria. ${explainability.failedSweeperCriteria[0] || 'More data needed.'}`;
    
    case 'CONFIRMED_SWEEPER':
      return `CRITICAL (confidence: ${confidence}%): This wallet meets ALL sweeper bot criteria. ` +
             `${explainability.passedSweeperCriteria.join('. ')}.`;
    
    default:
      return 'Unable to determine behavior pattern. No immediate concern detected.';
  }
}

function getRiskLevel(riskScore: number, confidence: number, hasProtocolInteraction: boolean): RiskLevel {
  // If has protocol interaction, cap risk level lower
  if (hasProtocolInteraction) {
    if (riskScore >= 70) return 'MEDIUM';
    return 'LOW';
  }
  
  // Low confidence = lower risk level
  if (confidence < 60) {
    if (riskScore >= 70) return 'MEDIUM';
    return 'LOW';
  }
  
  if (confidence < 85) {
    if (riskScore >= 80) return 'HIGH';
    if (riskScore >= 50) return 'MEDIUM';
    return 'LOW';
  }
  
  // High confidence
  if (riskScore >= 80) return 'CRITICAL';
  if (riskScore >= 60) return 'HIGH';
  if (riskScore >= 40) return 'MEDIUM';
  return 'LOW';
}

function createConfirmedDrainerResult(
  address: string,
  explainability: SweeperExplainability
): BehaviorAnalysisResult {
  explainability.classificationReason = 'Address is in confirmed drainer database.';
  explainability.behavioralTriggers = ['Address match in malicious database'];
  
  return {
    classification: 'CONFIRMED_DRAINER',
    walletRole: 'ATTACKER',
    confidence: 100,
    isDefinitelyMalicious: true,
    isProbablyMalicious: true,
    showCriticalAlert: true,
    explanation: 'This address is in the confirmed drainer database.',
    evidence: [{
      type: 'KNOWN_DRAINER_RECIPIENT',
      description: 'Address is in confirmed malicious database',
      weight: 50,
    }],
    riskScore: 100,
    riskLevel: 'CRITICAL',
    threats: [{
      id: `known-drainer-${Date.now()}`,
      type: 'WALLET_DRAINER',
      severity: 'CRITICAL',
      title: 'Known Drainer Address',
      description: 'This address is a confirmed wallet drainer.',
      technicalDetails: `Address: ${address}`,
      detectedAt: new Date().toISOString(),
      relatedAddresses: [address],
      relatedTransactions: [],
      ongoingRisk: true,
    }],
    detectedIntents: [],
    explainability,
  };
}

// ============================================
// SWEEPER BOT SCORE CALCULATOR
// ============================================

export function calculateSweeperBotScore(
  transactions: TransactionForAnalysis[],
  walletAddress: string,
  knownDrainerAddresses?: Set<string>
): SweeperBotScore {
  const safeTxs = Array.isArray(transactions) 
    ? transactions.filter(tx => tx != null) 
    : [];
  
  if (safeTxs.length < 5) {
    return {
      score: 0,
      isSweeperBot: false,
      confidence: 0,
      indicators: {
        multipleUnrelatedDestinations: false,
        uniqueDestinationCount: 0,
        hasNoProtocolInteraction: false,
        protocolsInteracted: [],
        repeatedAcrossBlocks: false,
        blockSpan: 0,
        hasUserIntentSignals: false,
        detectedIntents: [],
        transactionsPerHour: 0,
        identicalPatternCount: 0,
        multiAssetDrain: false,
        sendsToKnownDrainers: false,
      },
      passedCriteria: [],
      failedCriteria: ['Insufficient transaction history (need ≥5 transactions)'],
      ruledOutReasons: ['Not enough data to analyze'],
    };
  }

  // Check for user intents
  const detectedIntentTypes: UserIntentType[] = [];
  let hasProtocolInteraction = false;
  
  for (const tx of safeTxs) {
    const intent = detectTransactionIntent(tx);
    if (intent) {
      detectedIntentTypes.push(intent.type);
      hasProtocolInteraction = true;
    } else {
      const protocol = recognizeProtocol(tx.to);
      if (protocol.isKnown) {
        hasProtocolInteraction = true;
      }
    }
  }

  // Analyze strict criteria
  const criteriaResult = analyzeStrictSweeperCriteria(
    safeTxs,
    walletAddress.toLowerCase(),
    hasProtocolInteraction,
    detectedIntentTypes,
    knownDrainerAddresses
  );
  
  // Calculate score
  let score = 0;
  const ruledOutReasons: string[] = [];
  
  // CRITICAL: If has protocol interaction, significantly reduce score
  if (hasProtocolInteraction) {
    ruledOutReasons.push('Interacts with known protocols - likely legitimate user');
    score = Math.max(0, score - 40);
  }
  
  // If has user intent, significantly reduce score
  if (criteriaResult.hasUserIntentSignals) {
    ruledOutReasons.push(`User intent detected: ${criteriaResult.detectedIntents.join(', ')}`);
    score = Math.max(0, score - 30);
  }
  
  // Add score only if criteria pass
  if (criteriaResult.multipleUnrelatedDestinations) score += 25;
  if (criteriaResult.hasNoProtocolInteraction) score += 25;
  if (criteriaResult.repeatedAcrossBlocks) score += 25;
  if (criteriaResult.sendsToKnownDrainers) score += 30;
  if (!criteriaResult.hasUserIntentSignals) score += 15;
  
  // Calculate confidence
  const allCriteriaMet = 
    criteriaResult.multipleUnrelatedDestinations &&
    criteriaResult.hasNoProtocolInteraction &&
    criteriaResult.repeatedAcrossBlocks &&
    !criteriaResult.hasUserIntentSignals;
  
  let confidence = 0;
  if (allCriteriaMet) {
    confidence = criteriaResult.sendsToKnownDrainers ? 0.95 : 0.75;
  } else if (criteriaResult.passedCriteria.length >= 3) {
    confidence = 0.6;
  } else if (criteriaResult.passedCriteria.length >= 2) {
    confidence = 0.4;
  }
  
  // Must have confidence >= 0.85 to be labeled sweeper
  const isSweeperBot = score >= 60 && confidence >= 0.85;
  
  // Add ruled-out reasons from failed criteria
  for (const failed of criteriaResult.failedCriteria) {
    if (!ruledOutReasons.includes(failed)) {
      ruledOutReasons.push(failed);
    }
  }

  return {
    score: Math.min(100, Math.max(0, score)),
    isSweeperBot,
    confidence,
    indicators: {
      ...criteriaResult,
    },
    passedCriteria: criteriaResult.passedCriteria,
    failedCriteria: criteriaResult.failedCriteria,
    ruledOutReasons,
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  analyzeWalletBehavior as default,
  recognizeProtocol,
  detectTransactionIntent,
};
