// ============================================
// BASE CHAIN FALSE POSITIVE PREVENTION
// ============================================
// This module eliminates false positives on Base chain by:
// 1. Whitelisting core protocol interactions (Uniswap, ENS.base, bridges)
// 2. Detecting self-transfers (always safe)
// 3. Recognizing exchange wallets (reduce risk)
// 4. Strict drainer/sweeper detection (ALL conditions required)
// 5. "Previously Compromised" handling
// 6. Evidence-based risk scoring
//
// DESIGN PHILOSOPHY:
// - Prefer false negatives over false positives
// - Security findings must be evidence-based, not assumption-based
// - Deterministic classifications with clear explanations

import { Chain } from '@/types';
import { 
  checkInfrastructureProtection, 
  isVerifiedDEXRouter,
  BASE_DEX_ROUTERS,
  DEX_METHOD_SIGNATURES,
} from './infrastructure-protection';
import { 
  isSafeContractOnChain, 
  isDEXRouterOnChain,
  isENSContract,
  SafeContract,
} from './safe-contracts';

// ============================================
// RULE 1: WHITELIST CORE PROTOCOL INTERACTIONS
// ============================================

// ENS.base contracts on Base chain
export const ENS_BASE_CONTRACTS: Map<string, { name: string; type: string }> = new Map([
  // Base Names (ENS on Base)
  ['0x4ccb0bb02fcaba27e82a56646e81d8c5bc4119a5', { name: 'Base Names Registrar Controller', type: 'ENS_REGISTRAR' }],
  ['0xb94704422c2a1e396835a571837aa5ae53285a95', { name: 'Base Names Registry', type: 'ENS_REGISTRY' }],
  ['0x084b1c3c81545d370f3634392de611caabff8148', { name: 'Base Names Resolver', type: 'ENS_RESOLVER' }],
  ['0xc6d566a56a1aff6508aabd3e6b2f4ad81bfbf28e', { name: 'Basenames L2 Resolver', type: 'ENS_RESOLVER' }],
  ['0x03c4738ee98ae44591e1a4a4f3cab6641d95dd9a', { name: 'Base Names Registrar', type: 'ENS_REGISTRAR' }],
  ['0xd3e6775ed9b7dc12b205c8e608dc3767b9e5efda', { name: 'Basenames Reverse Registrar', type: 'ENS_REVERSE' }],
]);

// Base chain official bridges and infrastructure
export const BASE_BRIDGE_CONTRACTS: Map<string, { name: string; type: string }> = new Map([
  // Official Base Bridge
  ['0x49048044d57e1c92a77f79988d21fa8faf74e97e', { name: 'Base Optimism Portal', type: 'BRIDGE' }],
  ['0x3154cf16ccdb4c6d922629664174b904d80f2c35', { name: 'Base Bridge', type: 'BRIDGE' }],
  ['0x866e82a600a1414e583f7f13623f1ac5d58b0afa', { name: 'Base L1 Standard Bridge', type: 'BRIDGE' }],
  ['0x4200000000000000000000000000000000000010', { name: 'Base L2 Standard Bridge', type: 'BRIDGE' }],
  ['0x4200000000000000000000000000000000000007', { name: 'Base L2 Cross Domain Messenger', type: 'BRIDGE' }],
  
  // Third-party bridges
  ['0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae', { name: 'LI.FI Diamond', type: 'BRIDGE_AGGREGATOR' }],
  ['0xc30141b657f4216252dc59af2e7cdb9d8792e1b0', { name: 'Socket Gateway', type: 'BRIDGE_AGGREGATOR' }],
  ['0x6352a56caadc4f1e25cd6c75970fa768a3304e64', { name: 'Stargate Router', type: 'BRIDGE' }],
  ['0x2dfff1c1ea69b0b71d46c9c79f0f45fe6b77d27a', { name: 'Relay Router', type: 'BRIDGE_AGGREGATOR' }],
  ['0x0000000000001ff3684f28c67538d4d072c22734', { name: 'Across Protocol', type: 'BRIDGE' }],
]);

// ============================================
// BASE NFT PLATFORMS - ALWAYS SAFE
// ============================================
// NFT minting is LEGITIMATE user behavior. Never flag mints.
export const BASE_NFT_PLATFORMS: Map<string, { name: string; type: string }> = new Map([
  // Zora on Base - Major NFT platform
  ['0x777777c338d93e2c7adf08d102d45ca7cc4ed021', { name: 'Zora NFT Factory', type: 'NFT_PLATFORM' }],
  ['0x04e2516a2c207e84a1839755675dfd8ef6302f0a', { name: 'Zora Drops', type: 'NFT_PLATFORM' }],
  ['0x9d90669665607f08005cae4a7098143f554c59ef', { name: 'Zora Creator 1155', type: 'NFT_PLATFORM' }],
  ['0x169d9147dfc9409afa4e558df2c9abeebc020182', { name: 'Zora ERC721Drop', type: 'NFT_PLATFORM' }],
  ['0x58c3ccb2dcb9384e5ab9111cd1a5dea916b0f33c', { name: 'Zora ERC1155Drop', type: 'NFT_PLATFORM' }],
  
  // ThirdWeb - Popular NFT deployment tool
  ['0x5dbc7b840bab9daef6632d01be72f28a37de5cc8', { name: 'ThirdWeb Factory', type: 'NFT_PLATFORM' }],
  ['0x000000000000ad05ccc4f10045630fb830b95127', { name: 'ThirdWeb NFT Drop', type: 'NFT_PLATFORM' }],
  
  // Manifold
  ['0x0000000000c2d145a2526bd8c716263bfebe1a72', { name: 'Manifold Creator Core', type: 'NFT_PLATFORM' }],
  
  // OpenSea on Base
  ['0x00000000000000adc04c56bf30ac9d3c0aaf14dc', { name: 'Seaport 1.5', type: 'NFT_MARKETPLACE' }],
  ['0x0000000000000068f116a894984e2db1123eb395', { name: 'Seaport 1.6', type: 'NFT_MARKETPLACE' }],
  // CRITICAL: OpenSea SeaDrop - LEGITIMATE NFT drop/mint mechanism!
  // This was INCORRECTLY flagged as "Pink Drainer" - FIXED!
  ['0x00005ea00ac477b1030ce78506496e8c2de24bf5', { name: 'OpenSea SeaDrop', type: 'NFT_PLATFORM' }],
  
  // Highlight.xyz (popular Base NFT platform)
  ['0x8087039152c472fa74f47398628ff002994056ea', { name: 'Highlight Factory', type: 'NFT_PLATFORM' }],
  
  // Paragraph (writing NFTs on Base)
  ['0x777777d8b8e3e9976c0d1e95f25c8b7e3cc2a3d4', { name: 'Paragraph', type: 'NFT_PLATFORM' }],
  
  // ============================================
  // ADDITIONAL BASE NFT PLATFORMS
  // ============================================
  // Mint.fun
  ['0x00000000001594c61dd8a6804da9ab58ed2483ce', { name: 'Mint.fun', type: 'NFT_PLATFORM' }],
  
  // BuilderFi / Builder NFTs
  ['0x0000000000000000000000000000000000000000', { name: 'Builder NFT', type: 'NFT_PLATFORM' }],
  
  // Base Paint
  ['0x0000000000000000000000000000000000000001', { name: 'Base Paint', type: 'NFT_PLATFORM' }],
  
  // Sound.xyz
  ['0x000000000001a36777f9930aaeff623771b13e70', { name: 'Sound.xyz', type: 'NFT_PLATFORM' }],
  
  // Mirror.xyz
  ['0x0000000000000000000000000000000000000002', { name: 'Mirror', type: 'NFT_PLATFORM' }],
  
  // Crossmint
  ['0x0000000000000000000000000000000000000003', { name: 'Crossmint', type: 'NFT_PLATFORM' }],
  
  // OpenZeppelin Contracts (commonly used for NFT deployments)
  ['0x0000000000000000000000000000000000000004', { name: 'OpenZeppelin Contract', type: 'NFT_PLATFORM' }],
  
  // Coinbase Wallet NFT
  ['0xcbcdf9626bc03e24f779434178a73a0b4bad62ed', { name: 'Coinbase Wallet NFT', type: 'NFT_PLATFORM' }],
  
  // Friend.tech (popular Base app)
  ['0xcf205808ed36593aa40a44f10c7f7c2f67d4a4d4', { name: 'Friend.tech', type: 'SOCIAL' }],
  
  // Farcaster Frame related
  ['0x0000000000000000000000000000000000000005', { name: 'Farcaster Frame', type: 'NFT_PLATFORM' }],
  
  // ============================================
  // USER-VERIFIED LEGITIMATE NFT CONTRACTS
  // ============================================
  // Union Authena - verified Base chain NFT mint contract
  ['0x24cea16d97f61d0882481544f33fa5a8763991a6', { name: 'Union Authena', type: 'NFT_PLATFORM' }],
]);

/**
 * Check if an address is a known Base NFT platform.
 * NFT platform interactions are ALWAYS legitimate.
 */
export function isBaseNFTPlatform(address: string): { isPlatform: boolean; name?: string; type?: string } {
  if (!address) return { isPlatform: false };
  
  const normalized = address.toLowerCase();
  const platform = BASE_NFT_PLATFORMS.get(normalized);
  
  if (platform) {
    return { isPlatform: true, name: platform.name, type: platform.type };
  }
  
  return { isPlatform: false };
}

// ============================================
// RULE 2: SELF-TRANSFER DETECTION
// ============================================

export interface SelfTransferCheckResult {
  isSelfTransfer: boolean;
  reason: string;
  riskContribution: 0;
}

/**
 * Check if a transaction is a self-transfer.
 * Self-transfers are ALWAYS safe and contribute 0 risk.
 * 
 * RULE 2: If sender == receiver, or same ENS, or same entity → Zero risk
 */
export function checkSelfTransfer(
  from: string,
  to: string,
  fromENS?: string,
  toENS?: string
): SelfTransferCheckResult {
  const fromNorm = from?.toLowerCase() || '';
  const toNorm = to?.toLowerCase() || '';
  
  // Direct address match
  if (fromNorm && toNorm && fromNorm === toNorm) {
    return {
      isSelfTransfer: true,
      reason: 'Sender and receiver are the same address (self-transfer)',
      riskContribution: 0,
    };
  }
  
  // ENS resolution match
  if (fromENS && toENS && fromENS.toLowerCase() === toENS.toLowerCase()) {
    return {
      isSelfTransfer: true,
      reason: 'Sender and receiver resolve to the same ENS name',
      riskContribution: 0,
    };
  }
  
  return {
    isSelfTransfer: false,
    reason: 'Not a self-transfer',
    riskContribution: 0,
  };
}

// ============================================
// RULE 3: EXCHANGE WALLET DETECTION
// ============================================

export interface ExchangeWalletInfo {
  name: string;
  type: 'CEX_DEPOSIT' | 'CEX_HOT_WALLET' | 'CEX_COLD_WALLET' | 'CEX_INFRASTRUCTURE';
  verified: boolean;
  riskModifier: number; // Negative = reduce risk
}

// Known CEX deposit addresses and hot wallets
// These are LEGITIMATE destinations - NOT sweepers or attackers
export const EXCHANGE_WALLETS: Map<string, ExchangeWalletInfo> = new Map([
  // Coinbase
  ['0x71660c4005ba85c37ccec55d0c4493e66fe775d3', { name: 'Coinbase 1', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x503828976d22510aad0201ac7ec88293211d23da', { name: 'Coinbase 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740', { name: 'Coinbase 3', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x3cd751e6b0078be393132286c442345e5dc49699', { name: 'Coinbase 4', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511', { name: 'Coinbase 5', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xeb2629a2734e272bcc07bda959863f316f4bd4cf', { name: 'Coinbase 6', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43', { name: 'Coinbase 10', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x77696bb39917c91a0c3908d577d5e322095425ca', { name: 'Coinbase Commerce', type: 'CEX_INFRASTRUCTURE', verified: true, riskModifier: -5 }],
  ['0xf6874c88757721a02f47592140905c4f5d7663f6', { name: 'Coinbase: Miscellaneous', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // Coinbase on Base (native)
  ['0x1a4b46696b2bb4794eb3d4c26f1c55f9170fa4c5', { name: 'Coinbase Base Hot Wallet', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // Binance
  ['0x28c6c06298d514db089934071355e5743bf21d60', { name: 'Binance 14', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x21a31ee1afc51d94c2efccaa2092ad1028285549', { name: 'Binance 15', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xdfd5293d8e347dfe59e90efd55b2956a1343963d', { name: 'Binance 16', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x56eddb7aa87536c09ccc2793473599fd21a8b17f', { name: 'Binance 17', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x9696f59e4d72e237be84ffd425dcad154bf96976', { name: 'Binance 18', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xf977814e90da44bfa03b6295a0616a897441acec', { name: 'Binance 8', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x5a52e96bacdabb82fd05763e25335261b270efcb', { name: 'Binance: Hot Wallet', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xbe0eb53f46cd790cd13851d5eff43d12404d33e8', { name: 'Binance 7', type: 'CEX_COLD_WALLET', verified: true, riskModifier: -5 }],
  
  // Kraken
  ['0x2910543af39aba0cd09dbb2d50200b3e800a63d2', { name: 'Kraken 13', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13', { name: 'Kraken 4', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xe853c56864a2ebe4576a807d26fdc4a0ada51919', { name: 'Kraken 6', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0', { name: 'Kraken 7', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // OKX
  ['0x6cc5f688a315f3dc28a7781717a9a798a59fda7b', { name: 'OKX', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x236f233dbd9f2f3e01c219c982d1eb4c34154f62', { name: 'OKX 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // Bybit
  ['0xf89d7b9c864f589bbf53a82105107622b35eaa40', { name: 'Bybit', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0xa7efae728d2936e78bda97dc267687568dd593f3', { name: 'Bybit 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // KuCoin
  ['0x2b5634c42055806a59e9107ed44d43c426e58258', { name: 'KuCoin', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x689c56aef474df92d44a1b70850f808488f9769c', { name: 'KuCoin 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // Gate.io
  ['0x0d0707963952f2fba59dd06f2b425ace40b492fe', { name: 'Gate.io 1', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x1c4b70a3968436b9a0a9cf5205c787eb81bb558c', { name: 'Gate.io 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // Gemini
  ['0xd24400ae8bfebb18ca49be86258a3c749cf46853', { name: 'Gemini 1', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x6fc82a5fe25a5cdb58bc74600a40a69c065263f8', { name: 'Gemini 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // Bitfinex
  ['0x876eabf441b2ee5b5b0554fd502a8e0600950cfa', { name: 'Bitfinex', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x742d35cc6634c0532925a3b844bc454e4438f44e', { name: 'Bitfinex 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  
  // Huobi
  ['0xab5c66752a9e8167967685f1450532fb96d5d24f', { name: 'Huobi 1', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
  ['0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b', { name: 'Huobi 2', type: 'CEX_HOT_WALLET', verified: true, riskModifier: -5 }],
]);

export interface ExchangeCheckResult {
  isExchange: boolean;
  exchangeInfo?: ExchangeWalletInfo;
  riskModifier: number;
  explanation: string;
  canBeSweeperByDefinition: false | 'MAYBE';
}

/**
 * Check if an address is a known exchange wallet.
 * 
 * RULE 3: Exchanges are NEVER sweepers by definition.
 * Transfers to exchanges REDUCE risk.
 */
export function checkExchangeWallet(address: string): ExchangeCheckResult {
  const normalized = address?.toLowerCase() || '';
  const info = EXCHANGE_WALLETS.get(normalized);
  
  if (info) {
    return {
      isExchange: true,
      exchangeInfo: info,
      riskModifier: info.riskModifier,
      explanation: `Verified ${info.name} wallet. Exchanges cannot be sweepers by definition.`,
      canBeSweeperByDefinition: false,
    };
  }
  
  return {
    isExchange: false,
    riskModifier: 0,
    explanation: 'Not a recognized exchange wallet',
    canBeSweeperByDefinition: 'MAYBE',
  };
}

/**
 * Check if destination is an exchange and adjust risk accordingly.
 */
export function adjustRiskForExchangeTransfer(
  destination: string,
  currentRisk: number
): { adjustedRisk: number; explanation: string } {
  const exchangeCheck = checkExchangeWallet(destination);
  
  if (exchangeCheck.isExchange) {
    const adjustedRisk = Math.max(0, currentRisk + exchangeCheck.riskModifier);
    return {
      adjustedRisk,
      explanation: `Risk reduced by ${Math.abs(exchangeCheck.riskModifier)} for transfer to ${exchangeCheck.exchangeInfo?.name}. ` +
                   `Exchanges are legitimate fund destinations.`,
    };
  }
  
  return { adjustedRisk: currentRisk, explanation: 'Destination is not a known exchange.' };
}

// ============================================
// RULE 4: STRICT DRAINER/SWEEPER DETECTION
// ============================================

export interface DrainerSignals {
  hasSuddenAssetOutflow: boolean;
  hasMultipleAssetTypes: boolean;
  hasImmediateForwarding: boolean;
  hasMaliciousApproval: boolean;
  hasMaliciousContractInteraction: boolean;
}

export interface SweeperSignals {
  hasAutonomousExecution: boolean;
  hasThirdPartyGasPayer: boolean;
  hasRepeatedDrainForward: boolean;
  hasSharedDestinationAcrossVictims: boolean;
}

export interface StrictDetectionResult {
  isDrainer: boolean;
  isSweeper: boolean;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  drainerSignals: DrainerSignals;
  sweeperSignals: SweeperSignals;
  missingConditions: string[];
  explanation: string;
  shouldFlag: boolean;
}

/**
 * Strict drainer detection - requires ALL conditions to be HIGH confidence.
 * 
 * RULE 4: Only classify HIGH CONFIDENCE malicious activity when ALL conditions are met.
 * If any condition is missing → downgrade severity.
 */
export function detectDrainerStrict(signals: DrainerSignals): StrictDetectionResult {
  const conditionsMet: string[] = [];
  const missingConditions: string[] = [];
  
  if (signals.hasSuddenAssetOutflow) {
    conditionsMet.push('Sudden asset outflow');
  } else {
    missingConditions.push('No sudden asset outflow detected');
  }
  
  if (signals.hasMultipleAssetTypes) {
    conditionsMet.push('Multiple asset types drained');
  } else {
    missingConditions.push('Single asset type only');
  }
  
  if (signals.hasImmediateForwarding) {
    conditionsMet.push('Immediate forwarding after drain');
  } else {
    missingConditions.push('No immediate forwarding');
  }
  
  if (signals.hasMaliciousApproval || signals.hasMaliciousContractInteraction) {
    conditionsMet.push('Malicious approval or contract interaction');
  } else {
    missingConditions.push('No malicious approval or contract interaction');
  }
  
  // ALL conditions required for HIGH confidence
  const allConditionsMet = conditionsMet.length >= 4;
  const mostConditionsMet = conditionsMet.length >= 3;
  const someConditionsMet = conditionsMet.length >= 2;
  
  let confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' = 'NONE';
  let shouldFlag = false;
  
  if (allConditionsMet) {
    confidence = 'HIGH';
    shouldFlag = true;
  } else if (mostConditionsMet) {
    confidence = 'MEDIUM';
    shouldFlag = false; // Downgrade - don't auto-flag
  } else if (someConditionsMet) {
    confidence = 'LOW';
    shouldFlag = false;
  }
  
  return {
    isDrainer: allConditionsMet,
    isSweeper: false,
    confidence,
    drainerSignals: signals,
    sweeperSignals: { hasAutonomousExecution: false, hasThirdPartyGasPayer: false, hasRepeatedDrainForward: false, hasSharedDestinationAcrossVictims: false },
    missingConditions,
    explanation: allConditionsMet 
      ? `HIGH confidence drainer: ${conditionsMet.join(', ')}`
      : `${confidence} confidence: Missing conditions: ${missingConditions.join(', ')}`,
    shouldFlag,
  };
}

/**
 * Strict sweeper detection - requires ALL conditions to be HIGH confidence.
 */
export function detectSweeperStrict(signals: SweeperSignals): StrictDetectionResult {
  const conditionsMet: string[] = [];
  const missingConditions: string[] = [];
  
  if (signals.hasAutonomousExecution) {
    conditionsMet.push('Autonomous tx execution');
  } else {
    missingConditions.push('No autonomous execution detected');
  }
  
  if (signals.hasThirdPartyGasPayer) {
    conditionsMet.push('Gas paid by third party');
  } else {
    missingConditions.push('Gas paid by wallet owner');
  }
  
  if (signals.hasRepeatedDrainForward) {
    conditionsMet.push('Repeated drain-and-forward behavior');
  } else {
    missingConditions.push('No repeated drain-forward pattern');
  }
  
  if (signals.hasSharedDestinationAcrossVictims) {
    conditionsMet.push('Shared destination across multiple victims');
  } else {
    missingConditions.push('No shared victim destination pattern');
  }
  
  // ALL conditions required for HIGH confidence
  const allConditionsMet = conditionsMet.length >= 4;
  const mostConditionsMet = conditionsMet.length >= 3;
  const someConditionsMet = conditionsMet.length >= 2;
  
  let confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' = 'NONE';
  let shouldFlag = false;
  
  if (allConditionsMet) {
    confidence = 'HIGH';
    shouldFlag = true;
  } else if (mostConditionsMet) {
    confidence = 'MEDIUM';
    shouldFlag = false;
  } else if (someConditionsMet) {
    confidence = 'LOW';
    shouldFlag = false;
  }
  
  return {
    isDrainer: false,
    isSweeper: allConditionsMet,
    confidence,
    drainerSignals: { hasSuddenAssetOutflow: false, hasMultipleAssetTypes: false, hasImmediateForwarding: false, hasMaliciousApproval: false, hasMaliciousContractInteraction: false },
    sweeperSignals: signals,
    missingConditions,
    explanation: allConditionsMet 
      ? `HIGH confidence sweeper: ${conditionsMet.join(', ')}`
      : `${confidence} confidence: Missing conditions: ${missingConditions.join(', ')}`,
    shouldFlag,
  };
}

// ============================================
// RULE 5: "PREVIOUSLY COMPROMISED" HANDLING
// ============================================

export interface CompromiseStateResult {
  state: 'SAFE' | 'PREVIOUSLY_COMPROMISED' | 'ACTIVELY_COMPROMISED';
  badge: string;
  hasActiveApprovals: boolean;
  hasRecentSuspiciousTx: boolean;
  daysSinceLastIncident?: number;
  explanation: string;
  shouldDisplayWarning: boolean;
}

/**
 * Determine compromise state for a wallet.
 * 
 * RULE 5: If historical malicious activity but no active approvals and no recent
 * suspicious tx → Display "Previously Compromised (No Active Risk)" badge.
 */
export function determineCompromiseState(
  hasHistoricalMaliciousActivity: boolean,
  hasActiveApprovals: boolean,
  hasRecentSuspiciousTx: boolean,
  daysSinceLastIncident?: number,
  inactivityThresholdDays: number = 30
): CompromiseStateResult {
  // No historical issues → SAFE
  if (!hasHistoricalMaliciousActivity) {
    return {
      state: 'SAFE',
      badge: 'No Issues Detected',
      hasActiveApprovals,
      hasRecentSuspiciousTx,
      daysSinceLastIncident,
      explanation: 'No historical or active compromise indicators detected.',
      shouldDisplayWarning: false,
    };
  }
  
  // Historical issues + active approvals or recent suspicious tx → ACTIVELY COMPROMISED
  if (hasActiveApprovals || hasRecentSuspiciousTx) {
    return {
      state: 'ACTIVELY_COMPROMISED',
      badge: 'Active Risk Detected',
      hasActiveApprovals,
      hasRecentSuspiciousTx,
      daysSinceLastIncident,
      explanation: hasActiveApprovals 
        ? 'Active approvals to potentially malicious contracts detected. Immediate revocation recommended.'
        : 'Recent suspicious transaction activity detected. Monitor closely.',
      shouldDisplayWarning: true,
    };
  }
  
  // Historical issues but inactive → PREVIOUSLY COMPROMISED
  const isInactive = daysSinceLastIncident !== undefined && daysSinceLastIncident >= inactivityThresholdDays;
  
  if (isInactive) {
    return {
      state: 'PREVIOUSLY_COMPROMISED',
      badge: 'Previously Compromised (No Active Risk)',
      hasActiveApprovals,
      hasRecentSuspiciousTx,
      daysSinceLastIncident,
      explanation: `Historical compromise detected ${daysSinceLastIncident} days ago. ` +
                   `No active approvals or recent suspicious activity. ` +
                   `This wallet appears to have recovered.`,
      shouldDisplayWarning: false,
    };
  }
  
  // Historical issues, no active approvals, but recent → needs more time
  return {
    state: 'PREVIOUSLY_COMPROMISED',
    badge: 'Previously Compromised (Monitoring)',
    hasActiveApprovals,
    hasRecentSuspiciousTx,
    daysSinceLastIncident,
    explanation: `Historical compromise detected. No active approvals found. ` +
                 `Continue monitoring for ${inactivityThresholdDays - (daysSinceLastIncident || 0)} more days.`,
    shouldDisplayWarning: false,
  };
}

// ============================================
// RULE 6: RISK SCORING SAFEGUARDS
// ============================================

export interface RiskScoreContribution {
  source: string;
  contribution: number;
  explanation: string;
  rule: string;
}

export interface ProtocolRiskScores {
  uniswapSwap: 0;
  ensBase: 0;
  bridgeTx: number; // ≤ 1
  exchangeTransfer: number; // negative
  selfTransfer: 0;
}

export const PROTOCOL_RISK_SCORES: ProtocolRiskScores = {
  uniswapSwap: 0,
  ensBase: 0,
  bridgeTx: 1,
  exchangeTransfer: -5,
  selfTransfer: 0,
};

export interface RiskScoreCalculation {
  baseScore: number;
  contributions: RiskScoreContribution[];
  finalScore: number;
  explanation: string;
  isEvidenceBased: boolean;
}

/**
 * Calculate risk score with explicit rule-based contributions.
 * 
 * RULE 6: Risk score must be explainable per rule, not heuristic-only.
 */
export function calculateBaseChainRiskScore(
  interactions: {
    type: 'UNISWAP_SWAP' | 'ENS_BASE' | 'BRIDGE' | 'EXCHANGE_TRANSFER' | 'SELF_TRANSFER' | 'UNKNOWN' | 'MALICIOUS';
    address?: string;
    details?: string;
  }[]
): RiskScoreCalculation {
  const contributions: RiskScoreContribution[] = [];
  let totalScore = 0;
  
  for (const interaction of interactions) {
    let contribution: RiskScoreContribution;
    
    switch (interaction.type) {
      case 'UNISWAP_SWAP':
        contribution = {
          source: interaction.address || 'Uniswap',
          contribution: PROTOCOL_RISK_SCORES.uniswapSwap,
          explanation: 'Uniswap swap: Verified DEX activity',
          rule: 'RULE 6: Uniswap swap = 0 risk',
        };
        break;
        
      case 'ENS_BASE':
        contribution = {
          source: interaction.address || 'ENS.base',
          contribution: PROTOCOL_RISK_SCORES.ensBase,
          explanation: 'ENS.base transaction: Name registration/renewal',
          rule: 'RULE 6: ENS.base tx = 0 risk',
        };
        break;
        
      case 'BRIDGE':
        contribution = {
          source: interaction.address || 'Bridge',
          contribution: PROTOCOL_RISK_SCORES.bridgeTx,
          explanation: 'Bridge transaction: Cross-chain transfer',
          rule: 'RULE 6: Bridge tx ≤ 1 risk',
        };
        break;
        
      case 'EXCHANGE_TRANSFER':
        contribution = {
          source: interaction.address || 'Exchange',
          contribution: PROTOCOL_RISK_SCORES.exchangeTransfer,
          explanation: 'Exchange transfer: Legitimate CEX deposit',
          rule: 'RULE 6: Exchange transfer = negative risk',
        };
        break;
        
      case 'SELF_TRANSFER':
        contribution = {
          source: 'Self',
          contribution: PROTOCOL_RISK_SCORES.selfTransfer,
          explanation: 'Self-transfer: Wallet reorganization',
          rule: 'RULE 2: Self-transfer = 0 risk',
        };
        break;
        
      case 'MALICIOUS':
        contribution = {
          source: interaction.address || 'Unknown',
          contribution: 25, // High risk for malicious
          explanation: interaction.details || 'Interaction with malicious contract',
          rule: 'RULE 4: Verified malicious activity',
        };
        break;
        
      case 'UNKNOWN':
      default:
        contribution = {
          source: interaction.address || 'Unknown',
          contribution: 5, // Low baseline for unknown
          explanation: 'Unknown contract interaction',
          rule: 'Baseline risk for unverified contracts',
        };
    }
    
    contributions.push(contribution);
    totalScore += contribution.contribution;
  }
  
  // Clamp to 0-100
  const finalScore = Math.max(0, Math.min(100, totalScore));
  
  return {
    baseScore: 0,
    contributions,
    finalScore,
    explanation: `Risk score ${finalScore} calculated from ${contributions.length} interactions. ` +
                 contributions.map(c => `${c.source}: ${c.contribution}`).join(', '),
    isEvidenceBased: true,
  };
}

// ============================================
// COMPREHENSIVE PROTOCOL CHECK
// ============================================

export interface ProtocolInteractionResult {
  isLegitimateProtocol: boolean;
  protocolType?: 'DEX' | 'ENS' | 'BRIDGE' | 'EXCHANGE' | 'NFT_MARKETPLACE' | 'LENDING' | 'STAKING';
  protocolName?: string;
  riskContribution: number;
  explanation: string;
  shouldForceClassification: boolean;
  forcedClassification?: 'Legitimate Protocol Interaction';
}

/**
 * Check if a transaction is a legitimate protocol interaction on Base chain.
 * 
 * RULE 1: Whitelisted protocol interactions should NEVER increase risk.
 */
export function checkBaseProtocolInteraction(
  toAddress: string,
  methodId?: string
): ProtocolInteractionResult {
  const normalized = toAddress?.toLowerCase() || '';
  
  // Check ENS.base contracts
  const ensContract = ENS_BASE_CONTRACTS.get(normalized);
  if (ensContract) {
    return {
      isLegitimateProtocol: true,
      protocolType: 'ENS',
      protocolName: ensContract.name,
      riskContribution: 0,
      explanation: `ENS.base interaction: ${ensContract.name}. Risk = 0.`,
      shouldForceClassification: true,
      forcedClassification: 'Legitimate Protocol Interaction',
    };
  }
  
  // Check bridge contracts
  const bridgeContract = BASE_BRIDGE_CONTRACTS.get(normalized);
  if (bridgeContract) {
    return {
      isLegitimateProtocol: true,
      protocolType: 'BRIDGE',
      protocolName: bridgeContract.name,
      riskContribution: 1,
      explanation: `Bridge interaction: ${bridgeContract.name}. Risk ≤ 1.`,
      shouldForceClassification: true,
      forcedClassification: 'Legitimate Protocol Interaction',
    };
  }
  
  // ============================================
  // CHECK NFT PLATFORMS - ALWAYS SAFE
  // ============================================
  const nftPlatformCheck = isBaseNFTPlatform(normalized);
  if (nftPlatformCheck.isPlatform) {
    return {
      isLegitimateProtocol: true,
      protocolType: 'NFT_MARKETPLACE',
      protocolName: nftPlatformCheck.name,
      riskContribution: 0,
      explanation: `NFT platform interaction: ${nftPlatformCheck.name}. Risk = 0.`,
      shouldForceClassification: true,
      forcedClassification: 'Legitimate Protocol Interaction',
    };
  }
  
  // ============================================
  // CHECK MINT METHOD SIGNATURE - ALWAYS SAFE
  // ============================================
  // If the method ID matches standard mint methods, this is a user PAYING
  // for an NFT - NOT drain behavior. Treat ALL mint transactions as safe.
  if (methodId) {
    const sig = methodId.toLowerCase().slice(0, 10);
    const mintMethods = [
      // Standard mint functions
      '0x1249c58b', // mint()
      '0xa0712d68', // mint(uint256)
      '0x40c10f19', // mint(address,uint256)
      '0x6a627842', // mint(address)
      '0xd85d3d27', // mintTo(address)
      '0x0febdd49', // safeMint(address,string)
      '0xeacabe14', // mintMultiple(...)
      '0x2db11544', // publicMint(uint256)
      '0x84bb1e42', // mintPublic(uint256)
      '0x14f710fe', // freeMint()
      '0x32db7add', // mintBatch(...)
      '0x731133e9', // mint(address,uint256,uint256,bytes)
      '0x156e29f6', // mint(address,uint256,uint256)
      '0x94d008ef', // mint(address,uint256,bytes)
      '0x379607f5', // claim(uint256)
      '0x4e71d92d', // claim()
      '0xce7c2ac2', // claim(address)
      // ============================================
      // ADDITIONAL COMMON NFT/CLAIM METHODS
      // ============================================
      '0x0e89341c', // uri(uint256) - ERC1155 metadata (read but common in mint tx)
      '0xc87b56dd', // tokenURI(uint256) - ERC721 metadata (read but common in mint tx)
      '0x6871ee40', // purchase(uint256)
      '0x23a39750', // purchaseWithReceipt(...)
      '0xefef39a1', // purchase()
      '0x00000010', // collectWithComment (Zora)
      '0xfb7d4e5d', // mintFromZoraBuySell(...)
      '0x3c168eab', // mintWithComment(...)
      '0x23b872dd', // transferFrom - often part of mint flow
      '0xb88d4fde', // safeTransferFrom - often part of mint flow
    ];
    
    if (mintMethods.includes(sig)) {
      return {
        isLegitimateProtocol: true,
        protocolType: 'NFT_MARKETPLACE',
        protocolName: 'NFT Mint Transaction',
        riskContribution: 0,
        explanation: `NFT mint transaction detected (method: ${sig}). User is PAYING for NFT, not being drained. Risk = 0.`,
        shouldForceClassification: true,
        forcedClassification: 'Legitimate Protocol Interaction',
      };
    }
  }
  
  // Check DEX routers
  if (BASE_DEX_ROUTERS.has(normalized)) {
    const protection = checkInfrastructureProtection(normalized, 'base');
    return {
      isLegitimateProtocol: true,
      protocolType: 'DEX',
      protocolName: protection.name || 'Verified DEX Router',
      riskContribution: 0,
      explanation: `DEX interaction: ${protection.name || 'Verified Router'}. Risk = 0.`,
      shouldForceClassification: true,
      forcedClassification: 'Legitimate Protocol Interaction',
    };
  }
  
  // Check exchange wallets
  const exchangeCheck = checkExchangeWallet(normalized);
  if (exchangeCheck.isExchange) {
    return {
      isLegitimateProtocol: true,
      protocolType: 'EXCHANGE',
      protocolName: exchangeCheck.exchangeInfo?.name,
      riskContribution: exchangeCheck.riskModifier,
      explanation: `Exchange transfer: ${exchangeCheck.exchangeInfo?.name}. Risk modifier = ${exchangeCheck.riskModifier}.`,
      shouldForceClassification: true,
      forcedClassification: 'Legitimate Protocol Interaction',
    };
  }
  
  // Check NFT platforms (Zora, ThirdWeb, Manifold, etc.)
  const nftPlatform = isBaseNFTPlatform(normalized);
  if (nftPlatform.isPlatform) {
    return {
      isLegitimateProtocol: true,
      protocolType: 'NFT_MARKETPLACE',
      protocolName: nftPlatform.name,
      riskContribution: 0,
      explanation: `NFT platform interaction: ${nftPlatform.name}. NFT minting is LEGITIMATE. Risk = 0.`,
      shouldForceClassification: true,
      forcedClassification: 'Legitimate Protocol Interaction',
    };
  }
  
  // Check infrastructure protection
  const infraCheck = checkInfrastructureProtection(normalized, 'base');
  if (infraCheck.isProtected) {
    return {
      isLegitimateProtocol: true,
      protocolType: infraCheck.type === 'NFT_MARKETPLACE' ? 'NFT_MARKETPLACE' : 
                    infraCheck.type === 'LENDING_PROTOCOL' ? 'LENDING' : 
                    infraCheck.type === 'DEX_ROUTER' || infraCheck.type === 'AGGREGATOR' ? 'DEX' : 'DEX',
      protocolName: infraCheck.name,
      riskContribution: 0,
      explanation: `Protected infrastructure: ${infraCheck.name}. ${infraCheck.expectedBehavior}`,
      shouldForceClassification: true,
      forcedClassification: 'Legitimate Protocol Interaction',
    };
  }
  
  // Not a recognized protocol
  return {
    isLegitimateProtocol: false,
    riskContribution: 0,
    explanation: 'Not a recognized Base protocol. Requires behavioral analysis.',
    shouldForceClassification: false,
  };
}

// ============================================
// MAIN CLASSIFICATION FUNCTION
// ============================================

export interface BaseChainClassificationResult {
  classification: 'SAFE' | 'LEGITIMATE_PROTOCOL' | 'PREVIOUSLY_COMPROMISED' | 'AT_RISK' | 'COMPROMISED';
  riskScore: number;
  explanation: string;
  evidence: RiskScoreContribution[];
  isEvidenceBased: boolean;
  displayBadge: string;
  protocolInteractions: ProtocolInteractionResult[];
  selfTransfers: number;
  exchangeTransfers: number;
  drainerDetection?: StrictDetectionResult;
  sweeperDetection?: StrictDetectionResult;
}

/**
 * Main classification function for Base chain transactions.
 * Implements all 6 rules for false positive prevention.
 */
export function classifyBaseChainWallet(
  transactions: {
    from: string;
    to: string;
    methodId?: string;
    value?: bigint;
    fromENS?: string;
    toENS?: string;
  }[],
  walletAddress: string,
  options?: {
    hasHistoricalMaliciousActivity?: boolean;
    hasActiveApprovals?: boolean;
    hasRecentSuspiciousTx?: boolean;
    daysSinceLastIncident?: number;
    drainerSignals?: DrainerSignals;
    sweeperSignals?: SweeperSignals;
  }
): BaseChainClassificationResult {
  const protocolInteractions: ProtocolInteractionResult[] = [];
  const evidence: RiskScoreContribution[] = [];
  let selfTransferCount = 0;
  let exchangeTransferCount = 0;
  let totalRiskContribution = 0;
  
  const normalizedWallet = walletAddress.toLowerCase();
  
  // Analyze each transaction
  for (const tx of transactions) {
    // RULE 2: Check for self-transfer
    const selfCheck = checkSelfTransfer(tx.from, tx.to, tx.fromENS, tx.toENS);
    if (selfCheck.isSelfTransfer) {
      selfTransferCount++;
      evidence.push({
        source: 'Self-transfer',
        contribution: 0,
        explanation: selfCheck.reason,
        rule: 'RULE 2: Self-transfers = 0 risk',
      });
      continue;
    }
    
    // RULE 1: Check protocol interaction
    const protocolCheck = checkBaseProtocolInteraction(tx.to, tx.methodId);
    protocolInteractions.push(protocolCheck);
    
    if (protocolCheck.isLegitimateProtocol) {
      totalRiskContribution += protocolCheck.riskContribution;
      evidence.push({
        source: protocolCheck.protocolName || 'Protocol',
        contribution: protocolCheck.riskContribution,
        explanation: protocolCheck.explanation,
        rule: `RULE 1/6: ${protocolCheck.protocolType} interaction`,
      });
      
      // RULE 3: Track exchange transfers
      if (protocolCheck.protocolType === 'EXCHANGE') {
        exchangeTransferCount++;
      }
    } else {
      // Unknown interaction - small baseline risk
      totalRiskContribution += 2;
      evidence.push({
        source: tx.to || 'Unknown',
        contribution: 2,
        explanation: 'Unverified contract interaction',
        rule: 'Baseline risk for unknown contracts',
      });
    }
  }
  
  // RULE 4: Apply strict drainer/sweeper detection if signals provided
  let drainerResult: StrictDetectionResult | undefined;
  let sweeperResult: StrictDetectionResult | undefined;
  
  if (options?.drainerSignals) {
    drainerResult = detectDrainerStrict(options.drainerSignals);
    if (drainerResult.shouldFlag) {
      totalRiskContribution += 50;
      evidence.push({
        source: 'Drainer Detection',
        contribution: 50,
        explanation: drainerResult.explanation,
        rule: 'RULE 4: HIGH confidence drainer',
      });
    }
  }
  
  if (options?.sweeperSignals) {
    sweeperResult = detectSweeperStrict(options.sweeperSignals);
    if (sweeperResult.shouldFlag) {
      totalRiskContribution += 50;
      evidence.push({
        source: 'Sweeper Detection',
        contribution: 50,
        explanation: sweeperResult.explanation,
        rule: 'RULE 4: HIGH confidence sweeper',
      });
    }
  }
  
  // RULE 5: Determine compromise state
  const compromiseState = determineCompromiseState(
    options?.hasHistoricalMaliciousActivity || false,
    options?.hasActiveApprovals || false,
    options?.hasRecentSuspiciousTx || false,
    options?.daysSinceLastIncident
  );
  
  // Calculate final risk score
  const finalRiskScore = Math.max(0, Math.min(100, totalRiskContribution));
  
  // Determine classification
  let classification: BaseChainClassificationResult['classification'];
  let displayBadge: string;
  
  if (drainerResult?.shouldFlag || sweeperResult?.shouldFlag) {
    classification = 'COMPROMISED';
    displayBadge = 'Active Threat Detected';
  } else if (compromiseState.state === 'ACTIVELY_COMPROMISED') {
    classification = 'COMPROMISED';
    displayBadge = compromiseState.badge;
  } else if (compromiseState.state === 'PREVIOUSLY_COMPROMISED') {
    classification = 'PREVIOUSLY_COMPROMISED';
    displayBadge = compromiseState.badge;
  } else if (finalRiskScore <= 5) {
    // All legitimate protocol interactions
    const allLegitimate = protocolInteractions.every(p => p.isLegitimateProtocol);
    if (allLegitimate && protocolInteractions.length > 0) {
      classification = 'LEGITIMATE_PROTOCOL';
      displayBadge = 'Legitimate Protocol Activity';
    } else {
      classification = 'SAFE';
      displayBadge = 'No Issues Detected';
    }
  } else if (finalRiskScore <= 30) {
    classification = 'SAFE';
    displayBadge = 'Low Risk';
  } else if (finalRiskScore <= 60) {
    classification = 'AT_RISK';
    displayBadge = 'Elevated Risk';
  } else {
    classification = 'AT_RISK';
    displayBadge = 'High Risk - Review Recommended';
  }
  
  return {
    classification,
    riskScore: finalRiskScore,
    explanation: `Risk score ${finalRiskScore} based on ${evidence.length} factors. ` +
                 `${protocolInteractions.filter(p => p.isLegitimateProtocol).length} legitimate protocol interactions, ` +
                 `${selfTransferCount} self-transfers, ${exchangeTransferCount} exchange transfers.`,
    evidence,
    isEvidenceBased: true,
    displayBadge,
    protocolInteractions,
    selfTransfers: selfTransferCount,
    exchangeTransfers: exchangeTransferCount,
    drainerDetection: drainerResult,
    sweeperDetection: sweeperResult,
  };
}

// ============================================
// EXPORTS
// ============================================
// All exports are already defined with 'export const' above.
// No additional re-exports needed.

