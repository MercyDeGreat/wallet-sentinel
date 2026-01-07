// ============================================
// CONTEXT CLASSIFIER - PRE-DRAINER FILTER
// ============================================
// This module runs BEFORE any drainer detection logic.
// It classifies wallet context to prevent false positives on:
//   - DEX routers (1inch, Uniswap, CowSwap)
//   - NFT marketplaces (OpenSea, Blur)
//   - Privacy/rollup/intent systems (Aztec, relayers)
//   - Verified deployers
//   - Protocol treasuries
//   - Self-transfers
//   - Ownership-linked transfers
//
// CRITICAL RULE:
// If ContextClassification is NOT 'UNKNOWN', drainer detection MUST be skipped.
// False positives are MORE DAMAGING than missed low-confidence drainers.

import { Chain } from '@/types';
import { 
  isSafeContract, 
  isNFTMarketplace, 
  isDeFiProtocol,
  isDEXRouter,
  isInfrastructureContract,
  isENSContract,
  SafeContract,
} from './safe-contracts';

// ============================================
// CONTEXT CLASSIFICATION ENUM
// ============================================

export type ContextClassification = 
  | 'SAFE_PROTOCOL'      // Known safe protocol (DEX, marketplace, bridge, etc.)
  | 'SELF_OWNED'         // Self-transfer or ownership-linked transfer
  | 'RELAY'              // Relayer, router, or intent system
  | 'DEPLOYER'           // Verified deployer wallet
  | 'HIGH_ACTIVITY'      // High-activity wallet (not malicious, just active)
  | 'UNKNOWN';           // Unknown - MAY proceed to drainer analysis

export interface ContextClassificationResult {
  classification: ContextClassification;
  confidence: number;      // 0-100
  reason: string;
  details?: string;
  skipDrainerDetection: boolean;
  safeContract?: SafeContract;
  suggestedStatus?: 'SAFE' | 'HIGH_ACTIVITY_WALLET' | null;
}

// ============================================
// KNOWN PRIVACY / ROLLUP / INTENT SYSTEMS
// ============================================
// These are LEGITIMATE systems that may look suspicious but are NOT drainers

const PRIVACY_ROLLUP_SYSTEMS = new Set([
  // Aztec (zkMoney, privacy)
  '0xff1f2b4adb9df6fc8eafecdcbf96a2b351680455', // Aztec RollupProcessor
  '0x737901bea3eeb88459df9ef1be8ff3ae1b42a2ba', // Aztec Connect
  '0xa92a22a14f7af10e3a181fb7dedb62a9eb4b6b70', // Aztec Deposit
  
  // Tornado Cash (historical - service down but patterns still exist)
  '0x722122df12d4e14e13ac3b6895a86e84145b6967',
  
  // Secret Network bridges
  '0xf4b00c937b4ec4bb5ac051c3c719036c668a31ec',
  
  // Railgun (privacy)
  '0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9',
  '0xee39ecf7dcfdfb5923b79c0f09fd47b59a1c823e',
  
  // Umbra (stealth addresses)
  '0xfb2dc580eed955b528407b4d36ffafe3da685401',
]);

// ============================================
// KNOWN RELAYER / ROUTER SYSTEMS
// ============================================
// These are meta-transaction relayers that execute on behalf of users

const RELAYER_SYSTEMS = new Set([
  // OpenGSN relayers
  '0xd216153c06e857cd7f72665e0af1d7d82172f494',
  
  // Biconomy
  '0x84a0856b038eaad1cc7e297cf34a7e72685a8693',
  '0x86c80a8aa58e0a4fa09a69624c31ab2a6cad56b8',
  
  // Gelato Network
  '0x3caca7b48d0573d793d3b0279b5f0029180e83b6',
  '0x2807b4ae232b624023f87d0e237a3b1bf200fd99',
  
  // Flashbots
  '0xdafea492d9c6733ae3d56b7ed1adb60692c98bc5', // Flashbots Builder
  
  // MEV Blocker
  '0x00000000009726632680fb29d3f7a9734e3010e2',
  
  // CoW Protocol (Batch Auction / Intent-based)
  '0x9008d19f58aabd9ed0d60971565aa8510560ab41', // CoW Settlement
  '0xc92e8bdf79f0507f65a392b0ab4667716bfe0110', // CoW VaultRelayer
  
  // Socket / Bungee relayers
  '0xc30141b657f4216252dc59af2e7cdb9d8792e1b0',
  
  // 1inch Resolver
  '0x1111111254eeb25477b68fb85ed929f73a960582',
  '0x111111125421ca6dc452d289314280a0f8842a65',
  
  // Permit2 (universal approval - many protocols use this)
  '0x000000000022d473030f116ddee9f6b43ac78ba3',
]);

// ============================================
// KNOWN DEPLOYER PATTERNS
// ============================================
// Deployer wallets have specific on-chain patterns

const KNOWN_DEPLOYERS = new Set([
  // Treeverse deployer
  '0x55c29a6d0bf39f35f9c72d42c5d29db7e2b4ae29',
  
  // OpenSea deployer
  '0xa5409ec958c83c3f309868babaca7c86dcb077c1',
  
  // Uniswap deployer
  '0x41653c7d61609d856f29355e404f310ec4142cfb',
  
  // Blur deployer
  '0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5',
  
  // Add more verified deployers as needed
]);

// ============================================
// CONTRACT PATTERNS THAT ARE NOT DRAINERS
// ============================================
// Some method signatures indicate legitimate contract behavior

const SAFE_METHOD_PATTERNS = new Set([
  // Standard ERC20
  '0xa9059cbb', // transfer
  '0x23b872dd', // transferFrom (when used normally)
  '0x095ea7b3', // approve
  
  // Standard ERC721
  '0x42842e0e', // safeTransferFrom
  '0xb88d4fde', // safeTransferFrom with data
  
  // Standard minting (covered elsewhere but included for completeness)
  '0x1249c58b', // mint()
  '0xa0712d68', // mint(uint256)
  '0x40c10f19', // mint(address,uint256)
  
  // Swap methods (DEX activity)
  '0x7ff36ab5', // swapExactETHForTokens
  '0x18cbafe5', // swapExactTokensForETH
  '0x38ed1739', // swapExactTokensForTokens
  '0x8803dbee', // swapTokensForExactTokens
  '0x5c11d795', // swapExactTokensForTokensSupportingFeeOnTransferTokens
  '0x791ac947', // swapExactTokensForETHSupportingFeeOnTransferTokens
  '0xfb3bdb41', // swapETHForExactTokens
  
  // Uniswap V3 multicall patterns
  '0xac9650d8', // multicall
  '0x5ae401dc', // multicall with deadline
  '0x04e45aaf', // exactInputSingle
  '0xb858183f', // exactInput
  '0xdb3e2198', // exactOutputSingle
  '0x09b81346', // exactOutput
  
  // Liquidity provision
  '0xe8e33700', // addLiquidity
  '0xf305d719', // addLiquidityETH
  '0xbaa2abde', // removeLiquidity
  '0x02751cec', // removeLiquidityETH
  
  // Bridge methods
  '0x0efe6a8b', // depositEth (bridge)
  '0xe11013dd', // depositETH (another variant)
  '0x9a2ac6d5', // depositETHTo
  '0xa44c80e3', // sendMessage (bridge)
]);

// ============================================
// SELF-TRANSFER / OWNERSHIP DETECTION
// ============================================

// Note: normalizeAddress is imported from drainer-activity-detector
// to avoid duplicate exports
function normalizeAddressLocal(address: string | undefined | null): string {
  if (!address) return '';
  return address.toLowerCase().trim();
}

/**
 * Check if two addresses are the same (self-transfer).
 * Self-transfers are NEVER drainer behavior.
 */
export function isSelfTransfer(from: string, to: string): boolean {
  return normalizeAddressLocal(from) === normalizeAddressLocal(to);
}

/**
 * Check if addresses share ownership signals.
 * Signals include: same ENS, same deployer, bidirectional transfers.
 * 
 * NOTE: This is a simplified check. In production, you'd query:
 * - ENS reverse resolution for both addresses
 * - Deployment history
 * - Historical bidirectional transfer patterns
 */
export function shareOwnershipSignals(
  address1: string,
  address2: string,
  // These would come from enriched data
  ens1?: string,
  ens2?: string,
  deployer1?: string,
  deployer2?: string,
  hasBidirectionalHistory?: boolean
): boolean {
  // Same address = definitely same owner
  if (normalizeAddressLocal(address1) === normalizeAddressLocal(address2)) {
    return true;
  }
  
  // Same ENS root domain suggests same owner
  if (ens1 && ens2) {
    const root1 = ens1.split('.').slice(-2).join('.');
    const root2 = ens2.split('.').slice(-2).join('.');
    if (root1 === root2 && root1.endsWith('.eth')) {
      return true;
    }
  }
  
  // Same deployer suggests same owner
  if (deployer1 && deployer2 && normalizeAddressLocal(deployer1) === normalizeAddressLocal(deployer2)) {
    return true;
  }
  
  // Bidirectional transfer history suggests same owner
  if (hasBidirectionalHistory) {
    return true;
  }
  
  return false;
}

// ============================================
// MAIN CONTEXT CLASSIFIER
// ============================================

/**
 * Classify the context of a wallet BEFORE drainer detection.
 * If classification is NOT 'UNKNOWN', drainer detection should be SKIPPED.
 * 
 * This is the FIRST LINE OF DEFENSE against false positives.
 */
export function classifyWalletContext(
  walletAddress: string,
  chain: Chain,
  interactedAddresses: string[] = [],
  transactionMethods: string[] = [],
  options?: {
    ens?: string;
    isDeployer?: boolean;
    hasHighTxVolume?: boolean;
    bidirectionalPeers?: string[];
    outboundCount?: number;
    inboundCount?: number;
  }
): ContextClassificationResult {
  const normalized = normalizeAddressLocal(walletAddress);
  
  // ============================================
  // CHECK 1: Is the wallet itself a known safe contract?
  // ============================================
  const walletAsSafeContract = isSafeContract(normalized);
  if (walletAsSafeContract) {
    return {
      classification: 'SAFE_PROTOCOL',
      confidence: 100,
      reason: `Wallet is a known safe contract: ${walletAsSafeContract.name}`,
      details: `Category: ${walletAsSafeContract.category}`,
      skipDrainerDetection: true,
      safeContract: walletAsSafeContract,
      suggestedStatus: 'SAFE',
    };
  }
  
  // ============================================
  // CHECK 2: Is the wallet a known deployer?
  // ============================================
  if (options?.isDeployer || KNOWN_DEPLOYERS.has(normalized)) {
    return {
      classification: 'DEPLOYER',
      confidence: 95,
      reason: 'Wallet is a verified deployer address',
      details: 'Deployer wallets have normal hub-like behavior and should NEVER be flagged as drainers.',
      skipDrainerDetection: true,
      suggestedStatus: 'SAFE',
    };
  }
  
  // ============================================
  // CHECK 3: Is the wallet a known relayer?
  // ============================================
  if (RELAYER_SYSTEMS.has(normalized)) {
    return {
      classification: 'RELAY',
      confidence: 100,
      reason: 'Wallet is a known relayer/router system',
      details: 'Relayers execute transactions on behalf of users and are NOT drainers.',
      skipDrainerDetection: true,
      suggestedStatus: 'SAFE',
    };
  }
  
  // ============================================
  // CHECK 4: Does the wallet interact primarily with safe protocols?
  // ============================================
  if (interactedAddresses.length > 0) {
    const safeInteractions = interactedAddresses.filter(addr => {
      const norm = normalizeAddressLocal(addr);
      return isSafeContract(norm) !== null ||
             isDEXRouter(norm) ||
             isNFTMarketplace(norm) ||
             isDeFiProtocol(norm) ||
             isInfrastructureContract(norm) ||
             isENSContract(norm) ||
             RELAYER_SYSTEMS.has(norm) ||
             PRIVACY_ROLLUP_SYSTEMS.has(norm);
    });
    
    const safeRatio = safeInteractions.length / interactedAddresses.length;
    
    // If 70%+ of interactions are with safe protocols, this is likely a power user
    if (safeRatio >= 0.7 && interactedAddresses.length >= 5) {
      return {
        classification: 'SAFE_PROTOCOL',
        confidence: Math.round(safeRatio * 100),
        reason: `${Math.round(safeRatio * 100)}% of interactions are with verified safe protocols`,
        details: `${safeInteractions.length}/${interactedAddresses.length} interactions with DEXes, marketplaces, bridges, or infrastructure.`,
        skipDrainerDetection: true,
        suggestedStatus: 'SAFE',
      };
    }
  }
  
  // ============================================
  // CHECK 5: Does the wallet interact with privacy/intent systems?
  // ============================================
  const privacyInteractions = interactedAddresses.filter(addr => 
    PRIVACY_ROLLUP_SYSTEMS.has(normalizeAddressLocal(addr))
  );
  if (privacyInteractions.length > 0) {
    return {
      classification: 'RELAY',
      confidence: 90,
      reason: 'Wallet interacts with privacy/rollup/intent systems',
      details: 'Aztec, Railgun, Umbra, or similar privacy-preserving protocols. These are legitimate, not drainers.',
      skipDrainerDetection: true,
      suggestedStatus: 'SAFE',
    };
  }
  
  // ============================================
  // CHECK 6: Are transaction methods primarily safe patterns?
  // ============================================
  if (transactionMethods.length > 0) {
    const safeMethods = transactionMethods.filter(m => {
      const sig = m.slice(0, 10).toLowerCase();
      return SAFE_METHOD_PATTERNS.has(sig);
    });
    
    const safeMethodRatio = safeMethods.length / transactionMethods.length;
    
    // If 80%+ of methods are safe, this is normal DeFi activity
    if (safeMethodRatio >= 0.8 && transactionMethods.length >= 10) {
      return {
        classification: 'SAFE_PROTOCOL',
        confidence: Math.round(safeMethodRatio * 100),
        reason: `${Math.round(safeMethodRatio * 100)}% of transactions use standard DeFi/NFT methods`,
        details: 'Wallet activity is consistent with normal DeFi usage, not drainer behavior.',
        skipDrainerDetection: true,
        suggestedStatus: 'SAFE',
      };
    }
  }
  
  // ============================================
  // CHECK 7: High-activity wallet (not malicious, just active)
  // ============================================
  // A wallet with balanced inbound/outbound is likely a power user, not a drainer
  if (options?.outboundCount && options?.inboundCount) {
    const total = options.outboundCount + options.inboundCount;
    const ratio = options.outboundCount / options.inboundCount;
    
    // Drainers have very high outbound:inbound ratios (many victims, few sources)
    // Normal users have balanced ratios (receiving and sending regularly)
    // Ratio close to 1 = balanced, ratio >> 1 = drainer-like
    
    if (total >= 50 && ratio >= 0.3 && ratio <= 3.0) {
      return {
        classification: 'HIGH_ACTIVITY',
        confidence: 75,
        reason: 'High-activity wallet with balanced transaction patterns',
        details: `${options.outboundCount} outbound, ${options.inboundCount} inbound transactions. Ratio: ${ratio.toFixed(2)}`,
        skipDrainerDetection: true,
        suggestedStatus: 'HIGH_ACTIVITY_WALLET',
      };
    }
  }
  
  // ============================================
  // CHECK 8: Bidirectional transfer peers (same ownership)
  // ============================================
  if (options?.bidirectionalPeers && options.bidirectionalPeers.length > 0) {
    return {
      classification: 'SELF_OWNED',
      confidence: 85,
      reason: 'Wallet has bidirectional transfer history with peer addresses',
      details: `${options.bidirectionalPeers.length} address(es) with two-way transfers, suggesting same ownership.`,
      skipDrainerDetection: true,
      suggestedStatus: 'SAFE',
    };
  }
  
  // ============================================
  // DEFAULT: Unknown context - proceed with caution
  // ============================================
  return {
    classification: 'UNKNOWN',
    confidence: 0,
    reason: 'Context could not be determined',
    details: 'Wallet will be analyzed for drainer patterns with STRICT criteria.',
    skipDrainerDetection: false,
    suggestedStatus: null,
  };
}

/**
 * Quick check if a transaction destination is safe.
 * Used to filter individual transactions before pattern analysis.
 */
export function isTransactionToSafeDestination(
  to: string,
  chain: Chain,
  methodId?: string
): boolean {
  const normalized = normalizeAddressLocal(to);
  
  // Known safe contract
  if (isSafeContract(normalized)) return true;
  
  // Relayer or privacy system
  if (RELAYER_SYSTEMS.has(normalized)) return true;
  if (PRIVACY_ROLLUP_SYSTEMS.has(normalized)) return true;
  
  // DEX/DeFi activity
  if (isDEXRouter(normalized)) return true;
  if (isDeFiProtocol(normalized)) return true;
  
  // NFT marketplace
  if (isNFTMarketplace(normalized)) return true;
  
  // Infrastructure
  if (isInfrastructureContract(normalized)) return true;
  
  // ENS
  if (isENSContract(normalized)) return true;
  
  // Safe method patterns
  if (methodId && SAFE_METHOD_PATTERNS.has(methodId.slice(0, 10).toLowerCase())) {
    return true;
  }
  
  return false;
}

// ============================================
// EXPORTS
// ============================================

export {
  PRIVACY_ROLLUP_SYSTEMS,
  RELAYER_SYSTEMS,
  KNOWN_DEPLOYERS,
  SAFE_METHOD_PATTERNS,
};

