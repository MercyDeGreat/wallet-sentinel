// ============================================
// INFRASTRUCTURE CONTRACT PROTECTION
// ============================================
// This module provides ABSOLUTE PROTECTION for verified infrastructure contracts.
// 
// CRITICAL RULE: If a contract is in this list, it can NEVER be classified as:
// - Sweeper Bot
// - Drainer
// - Pink Drainer
// - ANY malicious entity
//
// These contracts may have high transaction volume and rapid fund movement,
// but this is EXPECTED BEHAVIOR for infrastructure contracts.
//
// Classification Priority (MUST be applied in this order):
// 1. Check PROTECTED_INFRASTRUCTURE list → If match, STOP, return SAFE
// 2. Check safe-contracts.ts → If match, STOP, return SAFE
// 3. Check malicious-database.ts → If match, flag as malicious
// 4. Apply heuristic detection (sweeper, drainer, etc.)
//
// This module exists to PREVENT FALSE POSITIVES on legitimate protocols.

import { Chain } from '@/types';

// ============================================
// PROTECTION STATUS
// ============================================

export type InfrastructureType =
  | 'NFT_MARKETPLACE'        // OpenSea, Blur, LooksRare, X2Y2
  | 'DEX_ROUTER'             // Uniswap, SushiSwap, 1inch
  | 'BRIDGE'                 // Wormhole, LayerZero, Stargate
  | 'AGGREGATOR'             // LI.FI, Socket, Relay
  | 'LENDING_PROTOCOL'       // Aave, Compound, Morpho
  | 'EXCHANGE_INFRASTRUCTURE' // CEX hot wallets, deposit contracts
  | 'SETTLEMENT_CONTRACT'    // Protocol settlement/escrow
  | 'ENS_INFRASTRUCTURE'     // ENS registrar, resolver, etc.
  | 'RELAYER'                // Gas relayers, meta-tx relayers
  | 'ORACLE'                 // Chainlink, Pyth, etc.
  | 'MULTISIG'               // Gnosis Safe, etc.
  | 'VERIFIED_PROTOCOL';     // Other verified protocols

export interface ProtectedContract {
  address: string;
  name: string;
  type: InfrastructureType;
  chains: Chain[];
  verified: boolean;
  website?: string;
  description?: string;
  // Explicit flag that this contract can NEVER be malicious
  absoluteProtection: boolean;
}

export interface InfrastructureCheckResult {
  isProtected: boolean;
  type?: InfrastructureType;
  name?: string;
  reason: string;
  canBeSweeperBot: false | 'MAYBE';
  canBeDrainer: false | 'MAYBE';
  canBePinkDrainer: false | 'MAYBE';
  expectedBehavior?: string;
  confidenceNote?: string;
}

// ============================================
// PROTECTED INFRASTRUCTURE REGISTRY
// ============================================
// ABSOLUTE PROTECTION LIST - These contracts can NEVER be flagged as malicious.
// All addresses are lowercase for consistent matching.

export const PROTECTED_INFRASTRUCTURE: ProtectedContract[] = [
  // ============================================
  // OPENSEA / SEAPORT (NFT MARKETPLACE)
  // ============================================
  // CRITICAL: OpenSea contracts handle billions in NFT transactions.
  // High outflow behavior is EXPECTED - they're a marketplace!
  {
    address: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
    name: 'OpenSea Seaport 1.1',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://opensea.io',
    description: 'OpenSea Seaport protocol for NFT trading. High transaction volume is expected.',
    absoluteProtection: true,
  },
  {
    address: '0x00000000006c3852cbef3e08e8df289169ede581',
    name: 'OpenSea Seaport 1.4',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    website: 'https://opensea.io',
    absoluteProtection: true,
  },
  {
    address: '0x0000000000000068f116a894984e2db1123eb395',
    name: 'OpenSea Seaport 1.5',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    website: 'https://opensea.io',
    absoluteProtection: true,
  },
  {
    address: '0x00000000000001ad428e4906ae43d8f9852d0dd6',
    name: 'OpenSea Seaport 1.6',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    website: 'https://opensea.io',
    absoluteProtection: true,
  },
  {
    address: '0x1e0049783f008a0085193e00003d00cd54003c71',
    name: 'OpenSea Fee Collector',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://opensea.io',
    absoluteProtection: true,
  },
  {
    address: '0x00000000f9490004c11cef243f5400493c00ad63',
    name: 'OpenSea Conduit',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    website: 'https://opensea.io',
    description: 'OpenSea conduit for token approvals and transfers',
    absoluteProtection: true,
  },
  
  // ============================================
  // BLUR (NFT MARKETPLACE)
  // ============================================
  {
    address: '0x000000000000ad05ccc4f10045630fb830b95127',
    name: 'Blur Marketplace',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://blur.io',
    absoluteProtection: true,
  },
  {
    address: '0x29469395eaf6f95920e59f858042f0e28d98a20b',
    name: 'Blur Blend',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://blur.io',
    absoluteProtection: true,
  },
  {
    address: '0x0000000000a39bb272e79075ade125fd351887ac',
    name: 'Blur Pool',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://blur.io',
    absoluteProtection: true,
  },
  {
    address: '0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5',
    name: 'Blur Exchange',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://blur.io',
    absoluteProtection: true,
  },
  
  // ============================================
  // OTHER NFT MARKETPLACES
  // ============================================
  {
    address: '0x59728544b08ab483533076417fbbb2fd0b17ce3a',
    name: 'LooksRare Exchange',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://looksrare.org',
    absoluteProtection: true,
  },
  {
    address: '0x74312363e45dcaba76c59ec49a7aa8a65a67eed3',
    name: 'X2Y2 Exchange',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://x2y2.io',
    absoluteProtection: true,
  },
  {
    address: '0x9757f2d2b135150bbeb65308d4a91804107cd8d6',
    name: 'Rarible Exchange',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://rarible.com',
    absoluteProtection: true,
  },
  
  // ============================================
  // DEX ROUTERS
  // ============================================
  {
    address: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',
    name: 'Uniswap V2 Router',
    type: 'DEX_ROUTER',
    chains: ['ethereum'],
    verified: true,
    website: 'https://uniswap.org',
    absoluteProtection: true,
  },
  {
    address: '0xe592427a0aece92de3edee1f18e0157c05861564',
    name: 'Uniswap V3 Router',
    type: 'DEX_ROUTER',
    chains: ['ethereum'],
    verified: true,
    website: 'https://uniswap.org',
    absoluteProtection: true,
  },
  {
    address: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
    name: 'Uniswap Universal Router',
    type: 'DEX_ROUTER',
    chains: ['ethereum', 'base'],
    verified: true,
    website: 'https://uniswap.org',
    absoluteProtection: true,
  },
  {
    address: '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad',
    name: 'Uniswap Universal Router V2',
    type: 'DEX_ROUTER',
    chains: ['ethereum', 'base'],
    verified: true,
    website: 'https://uniswap.org',
    absoluteProtection: true,
  },
  {
    address: '0x1111111254eeb25477b68fb85ed929f73a960582',
    name: '1inch Aggregation Router V5',
    type: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://1inch.io',
    absoluteProtection: true,
  },
  {
    address: '0x111111125421ca6dc452d289314280a0f8842a65',
    name: '1inch Aggregation Router V6',
    type: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://1inch.io',
    absoluteProtection: true,
  },
  {
    address: '0xdef1c0ded9bec7f1a1670819833240f027b25eff',
    name: '0x Exchange Proxy',
    type: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://0x.org',
    absoluteProtection: true,
  },
  
  // ============================================
  // BRIDGES / CROSS-CHAIN
  // ============================================
  {
    address: '0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae',
    name: 'LI.FI Diamond',
    type: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://li.fi',
    absoluteProtection: true,
  },
  {
    address: '0x2dfff1c176976694545179a31957d7781b0e5108',
    name: 'Relay Router',
    type: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://relay.link',
    absoluteProtection: true,
  },
  {
    address: '0x6352a56caadcdfd2135eec7f97e8d94e2dd778ee',
    name: 'Stargate Router',
    type: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://stargate.finance',
    absoluteProtection: true,
  },
  {
    address: '0xc30141b657f42f1e34a63552ce2d0f2f5216a8c7',
    name: 'Socket Gateway',
    type: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://socket.tech',
    absoluteProtection: true,
  },
  
  // ============================================
  // ENS INFRASTRUCTURE
  // ============================================
  {
    address: '0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85',
    name: 'ENS Base Registrar',
    type: 'ENS_INFRASTRUCTURE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://ens.domains',
    absoluteProtection: true,
  },
  {
    address: '0x283af0b28c62c092c9727f1ee09c02ca627eb7f5',
    name: 'ENS ETH Registrar Controller',
    type: 'ENS_INFRASTRUCTURE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://ens.domains',
    absoluteProtection: true,
  },
  {
    address: '0x253553366da8546fc250f225fe3d25d0c782303b',
    name: 'ENS ETH Registrar Controller V2',
    type: 'ENS_INFRASTRUCTURE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://ens.domains',
    absoluteProtection: true,
  },
  
  // ============================================
  // LENDING PROTOCOLS
  // ============================================
  {
    address: '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2',
    name: 'Aave V3 Pool',
    type: 'LENDING_PROTOCOL',
    chains: ['ethereum'],
    verified: true,
    website: 'https://aave.com',
    absoluteProtection: true,
  },
  {
    address: '0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9',
    name: 'Aave V2 Lending Pool',
    type: 'LENDING_PROTOCOL',
    chains: ['ethereum'],
    verified: true,
    website: 'https://aave.com',
    absoluteProtection: true,
  },
  {
    address: '0xc3d688b66703497daa19211eedff47f25384cdc3',
    name: 'Compound V3 cUSDC',
    type: 'LENDING_PROTOCOL',
    chains: ['ethereum'],
    verified: true,
    website: 'https://compound.finance',
    absoluteProtection: true,
  },
  
  // ============================================
  // PERMIT2 / APPROVAL INFRASTRUCTURE
  // ============================================
  {
    address: '0x000000000022d473030f116ddee9f6b43ac78ba3',
    name: 'Uniswap Permit2',
    type: 'DEX_ROUTER',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://uniswap.org',
    description: 'Permit2 for efficient token approvals. High volume is expected.',
    absoluteProtection: true,
  },
];

// ============================================
// PROTECTION CHECK INDEX
// ============================================
// Build an index for fast O(1) lookups

const protectionIndex = new Map<string, ProtectedContract>();

// Initialize index
for (const contract of PROTECTED_INFRASTRUCTURE) {
  protectionIndex.set(contract.address.toLowerCase(), contract);
}

// ============================================
// MAIN PROTECTION CHECK FUNCTION
// ============================================

/**
 * Check if an address is protected infrastructure.
 * This MUST be called BEFORE any sweeper/drainer detection.
 * If this returns isProtected: true, the address can NEVER be flagged as malicious.
 */
export function checkInfrastructureProtection(
  address: string,
  chain?: Chain
): InfrastructureCheckResult {
  const normalized = address.toLowerCase();
  const contract = protectionIndex.get(normalized);

  if (contract) {
    // Check if the contract is valid for this chain
    if (chain && !contract.chains.includes(chain)) {
      // Contract exists but not for this chain - still provide protection note
      return {
        isProtected: true,
        type: contract.type,
        name: contract.name,
        reason: `${contract.name} - verified infrastructure contract`,
        canBeSweeperBot: false,
        canBeDrainer: false,
        canBePinkDrainer: false,
        expectedBehavior: getExpectedBehavior(contract.type),
        confidenceNote: `This is a verified ${contract.name} contract. High transaction volume and rapid fund movement is expected behavior.`,
      };
    }

    return {
      isProtected: true,
      type: contract.type,
      name: contract.name,
      reason: `${contract.name} - verified infrastructure contract`,
      canBeSweeperBot: false,
      canBeDrainer: false,
      canBePinkDrainer: false,
      expectedBehavior: getExpectedBehavior(contract.type),
      confidenceNote: `This is a verified ${contract.name} contract. High transaction volume and rapid fund movement is expected behavior.`,
    };
  }

  // Check for OpenSea pattern (vanity addresses starting with 0x000000...)
  if (isOpenSeaVanityAddress(normalized)) {
    return {
      isProtected: true,
      type: 'NFT_MARKETPLACE',
      name: 'OpenSea Contract',
      reason: 'OpenSea vanity address pattern detected',
      canBeSweeperBot: false,
      canBeDrainer: false,
      canBePinkDrainer: false,
      expectedBehavior: 'NFT marketplace settlement - high volume expected',
      confidenceNote: 'This appears to be an OpenSea infrastructure contract.',
    };
  }

  return {
    isProtected: false,
    reason: 'Address is not in protected infrastructure list',
    canBeSweeperBot: 'MAYBE',
    canBeDrainer: 'MAYBE',
    canBePinkDrainer: 'MAYBE',
  };
}

/**
 * Check if an address matches OpenSea's vanity address pattern.
 * OpenSea uses addresses starting with many zeros.
 */
function isOpenSeaVanityAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  
  // OpenSea Seaport contracts all start with 0x00000000
  if (normalized.startsWith('0x00000000')) {
    // Exclude known drainer addresses that also start with zeros
    const knownDrainers = [
      '0x00005ea00ac477b1030ce78506496e8c2de24bf5', // Pink Drainer
      '0x0000db5c8b030ae20308ac975898e09741e70000', // Inferno Drainer
      '0x00000000ae347930bd1e7b0f35588b92280f9e75', // Angel Drainer
      '0x0000000083fc54c35b9b83de16c67c73b1a7b000', // MS Drainer
      '0x00000000052e7f0c029b6e38e96f03c70d86bfe5', // Pussy Drainer
    ];
    
    if (knownDrainers.includes(normalized)) {
      return false; // This is a drainer, not OpenSea
    }
    
    // Additional check: legitimate Seaport has specific patterns
    const seaportPatterns = [
      '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // Seaport 1.1
      '0x00000000006c3852cbef3e08e8df289169ede581', // Seaport 1.4
      '0x0000000000000068f116a894984e2db1123eb395', // Seaport 1.5
      '0x00000000000001ad428e4906ae43d8f9852d0dd6', // Seaport 1.6
      '0x00000000f9490004c11cef243f5400493c00ad63', // Conduit
    ];
    
    if (seaportPatterns.includes(normalized)) {
      return true;
    }
    
    // For other 0x00000000 addresses, be more careful
    // Only protect if it's exactly a known pattern
    return false;
  }
  
  return false;
}

/**
 * Get expected behavior description for a type of infrastructure.
 */
function getExpectedBehavior(type: InfrastructureType): string {
  switch (type) {
    case 'NFT_MARKETPLACE':
      return 'NFT marketplace settlement - processes NFT trades between buyers and sellers. High transaction volume and rapid fund movement is normal.';
    case 'DEX_ROUTER':
      return 'Decentralized exchange router - processes token swaps. Funds flow through rapidly.';
    case 'BRIDGE':
      return 'Cross-chain bridge - transfers assets between blockchains. Rapid fund movement expected.';
    case 'AGGREGATOR':
      return 'Trading aggregator - routes trades through multiple sources. High volume expected.';
    case 'LENDING_PROTOCOL':
      return 'Lending protocol - handles deposits, borrows, and liquidations. Fund movement is normal.';
    case 'EXCHANGE_INFRASTRUCTURE':
      return 'Exchange infrastructure - processes deposits/withdrawals. Rapid forwarding expected.';
    case 'SETTLEMENT_CONTRACT':
      return 'Settlement contract - handles escrow and settlement. Fund movement is normal.';
    case 'ENS_INFRASTRUCTURE':
      return 'ENS infrastructure - handles domain registration and resolution.';
    case 'RELAYER':
      return 'Transaction relayer - submits transactions on behalf of users.';
    case 'ORACLE':
      return 'Price oracle - provides price feeds to other contracts.';
    case 'MULTISIG':
      return 'Multi-signature wallet - requires multiple approvals for transactions.';
    case 'VERIFIED_PROTOCOL':
      return 'Verified protocol - trusted smart contract with known behavior.';
    default:
      return 'Infrastructure contract - expected behavior varies.';
  }
}

// ============================================
// QUICK CHECK FUNCTIONS
// ============================================

/**
 * Quick check if address is a protected NFT marketplace.
 */
export function isProtectedMarketplace(address: string): boolean {
  const result = checkInfrastructureProtection(address);
  return result.isProtected && result.type === 'NFT_MARKETPLACE';
}

/**
 * Quick check if address is protected DEX/aggregator.
 */
export function isProtectedDEX(address: string): boolean {
  const result = checkInfrastructureProtection(address);
  return result.isProtected && (result.type === 'DEX_ROUTER' || result.type === 'AGGREGATOR');
}

/**
 * Quick check if address is protected bridge.
 */
export function isProtectedBridge(address: string): boolean {
  const result = checkInfrastructureProtection(address);
  return result.isProtected && result.type === 'BRIDGE';
}

/**
 * Quick check if address can NEVER be a sweeper bot.
 */
export function canNeverBeSweeperBot(address: string): boolean {
  const result = checkInfrastructureProtection(address);
  return result.canBeSweeperBot === false;
}

/**
 * Quick check if address can NEVER be a drainer.
 */
export function canNeverBeDrainer(address: string): boolean {
  const result = checkInfrastructureProtection(address);
  return result.canBeDrainer === false;
}

/**
 * Get all protected addresses (for testing).
 */
export function getAllProtectedAddresses(): string[] {
  return PROTECTED_INFRASTRUCTURE.map(c => c.address);
}

/**
 * Get protected contract by address.
 */
export function getProtectedContract(address: string): ProtectedContract | undefined {
  return protectionIndex.get(address.toLowerCase());
}

// ============================================
// EXPORTS
// ============================================

export {
  isOpenSeaVanityAddress,
  getExpectedBehavior,
};

