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
  {
    address: '0x39da41747a83aee658334415666f3ef92dd0d541',
    name: 'Blur Marketplace 2',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://blur.io',
    absoluteProtection: true,
  },
  
  // ============================================
  // TREEVERSE (NFT PROJECT)
  // ============================================
  {
    address: '0x1b829b926a14634d36625e60165c0770c09d02b2',
    name: 'Treeverse Founders Plot',
    type: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    website: 'https://treeverse.net',
    absoluteProtection: true,
  },
  {
    address: '0x55c29a6d0bf39f35f9c72d42c5d29db7e2b4ae29',
    name: 'Treeverse Deployer',
    type: 'SETTLEMENT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    website: 'https://treeverse.net',
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
  // DEX ROUTERS - ETHEREUM
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
    name: 'Uniswap V3 Router 02',
    type: 'DEX_ROUTER',
    chains: ['ethereum', 'base'],
    verified: true,
    website: 'https://uniswap.org',
    absoluteProtection: true,
  },
  {
    address: '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b',
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
  
  // ============================================
  // DEX ROUTERS - BASE CHAIN SPECIFIC
  // ============================================
  // CRITICAL: These are verified Uniswap/DEX contracts on Base.
  // DEX interaction alone ≠ compromise signal
  {
    address: '0x2626664c2603336e57b271c5c0b26f421741e481',
    name: 'Uniswap V3 SwapRouter02 (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://uniswap.org',
    description: 'Official Uniswap V3 router on Base chain - swaps are normal activity',
    absoluteProtection: true,
  },
  {
    address: '0x198ef79f1f515f02dfe9e3115ed9fc07183f02fc',
    name: 'Uniswap Universal Router (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://uniswap.org',
    description: 'Official Uniswap Universal Router on Base chain',
    absoluteProtection: true,
  },
  {
    address: '0x03a520b32c04bf3beef7beb72e919cf822ed34f1',
    name: 'Uniswap V3 Position Manager (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://uniswap.org',
    description: 'Uniswap V3 NFT Position Manager for liquidity positions on Base',
    absoluteProtection: true,
  },
  {
    address: '0x33128a8fc17869897dce68ed026d694621f6fdfd',
    name: 'Uniswap V3 Factory (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://uniswap.org',
    description: 'Uniswap V3 Factory contract on Base',
    absoluteProtection: true,
  },
  {
    address: '0x8909dc15e40173ff4699343b6eb8132c65e18ec6',
    name: 'Uniswap V3 Quoter V2 (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://uniswap.org',
    description: 'Uniswap V3 Quoter for price quotes on Base',
    absoluteProtection: true,
  },
  {
    address: '0xb4cb800910b228ed3d0834cf79d697127bbb00e5',
    name: 'Aerodrome Router (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://aerodrome.finance',
    description: 'Aerodrome DEX router - major Base DEX',
    absoluteProtection: true,
  },
  {
    address: '0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43',
    name: 'Aerodrome Router V2 (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://aerodrome.finance',
    description: 'Aerodrome V2 router on Base',
    absoluteProtection: true,
  },
  {
    address: '0x827922686190790b37229fd06084350e74485b72',
    name: 'BaseSwap Router (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://baseswap.fi',
    description: 'BaseSwap DEX router on Base',
    absoluteProtection: true,
  },
  {
    address: '0x8c1a3cf8f83074169fe5d7ad50b978e1cd6b37c7',
    name: 'SushiSwap RouteProcessor3 (Base)',
    type: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    website: 'https://sushi.com',
    description: 'SushiSwap router on Base chain',
    absoluteProtection: true,
  },
  
  // ============================================
  // BASE CHAIN NFT CONTRACTS - VERIFIED SAFE
  // ============================================
  {
    address: '0x24cea16d97f61d0882481544f33fa5a8763991a6',
    name: 'Union Authena (Base)',
    type: 'NFT_MARKETPLACE',
    chains: ['base'],
    verified: true,
    website: 'https://union.build',
    description: 'Union Authena NFT mint contract - verified legitimate Base NFT project',
    absoluteProtection: true,
  },
  
  // ============================================
  // DEX AGGREGATORS - MULTI-CHAIN
  // ============================================
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
  {
    address: '0xfbc22278a96299d91d41c453234d97b4f5eb9b2d',
    name: 'Odos Router V2',
    type: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://odos.xyz',
    absoluteProtection: true,
  },
  {
    address: '0x6131b5fae19ea4f9d964eac0408e4408b66337b5',
    name: 'KyberSwap Router',
    type: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://kyberswap.com',
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
  // ORBITER FINANCE BRIDGE
  // ============================================
  // Orbiter uses Maker EOA addresses for cross-chain bridging
  {
    address: '0x80c67432656d59144ceff962e8faf8926599bcf8',
    name: 'Orbiter Finance Maker 1',
    type: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://orbiter.finance',
    absoluteProtection: true,
  },
  {
    address: '0xe4edb277e41dc89ab076a1f049f4a3efa700bce8',
    name: 'Orbiter Finance Maker 2',
    type: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://orbiter.finance',
    absoluteProtection: true,
  },
  {
    address: '0x41d3d33156ae7c62c094aae2995003ae63f587b3',
    name: 'Orbiter Finance Maker 3',
    type: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://orbiter.finance',
    absoluteProtection: true,
  },
  {
    address: '0xd7aa9ba6caac7b0436c91396f22ca5a7f31664fc',
    name: 'Orbiter Finance Maker (Base)',
    type: 'BRIDGE',
    chains: ['base'],
    verified: true,
    website: 'https://orbiter.finance',
    absoluteProtection: true,
  },
  {
    address: '0x095d2918b03b2e86d68551dcf11302121fb626c9',
    name: 'Orbiter Finance Router',
    type: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    website: 'https://orbiter.finance',
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
  if (normalized.startsWith('0x00000000') || normalized.startsWith('0x00005ea')) {
    // Known legitimate OpenSea/Seaport patterns
    // CRITICAL: 0x00005ea00ac477b1030ce78506496e8c2de24bf5 is OpenSea SeaDrop - LEGITIMATE!
    const seaportPatterns = [
      '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // Seaport 1.1
      '0x00000000006c3852cbef3e08e8df289169ede581', // Seaport 1.4
      '0x0000000000000068f116a894984e2db1123eb395', // Seaport 1.5
      '0x00000000000001ad428e4906ae43d8f9852d0dd6', // Seaport 1.6
      '0x00000000f9490004c11cef243f5400493c00ad63', // Conduit
      '0x00005ea00ac477b1030ce78506496e8c2de24bf5', // SeaDrop - LEGITIMATE NFT drop mechanism!
    ];
    
    if (seaportPatterns.includes(normalized)) {
      return true;
    }
    
    // Exclude known drainer addresses that also start with zeros
    // NOTE: 0x00005ea... REMOVED - it's OpenSea SeaDrop (legitimate)!
    const knownDrainers = [
      '0x0000db5c8b030ae20308ac975898e09741e70000', // Inferno Drainer
      '0x00000000ae347930bd1e7b0f35588b92280f9e75', // Angel Drainer
      '0x0000000083fc54c35b9b83de16c67c73b1a7b000', // MS Drainer
      '0x00000000052e7f0c029b6e38e96f03c70d86bfe5', // Pussy Drainer
    ];
    
    if (knownDrainers.includes(normalized)) {
      return false; // This is a drainer, not OpenSea
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
// BASE CHAIN DEX ALLOWLIST
// ============================================
// Chain-aware DEX detection for Base chain
// RULE: DEX interaction alone ≠ compromise signal

const BASE_DEX_ROUTERS: Set<string> = new Set([
  // Uniswap on Base
  '0x2626664c2603336e57b271c5c0b26f421741e481', // SwapRouter02
  '0x198ef79f1f515f02dfe9e3115ed9fc07183f02fc', // Universal Router
  '0x03a520b32c04bf3beef7beb72e919cf822ed34f1', // Position Manager
  '0x33128a8fc17869897dce68ed026d694621f6fdfd', // V3 Factory
  '0x8909dc15e40173ff4699343b6eb8132c65e18ec6', // Quoter V2
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Router 02 (shared)
  '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b', // Universal Router (shared)
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad', // Universal Router V2 (shared)
  '0x000000000022d473030f116ddee9f6b43ac78ba3', // Permit2
  
  // Aerodrome (major Base DEX)
  '0xb4cb800910b228ed3d0834cf79d697127bbb00e5', // Router
  '0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43', // Router V2
  '0x420dd381b31aef6683db6b902084cb0ffece40da', // Voter
  
  // BaseSwap
  '0x827922686190790b37229fd06084350e74485b72',
  
  // SushiSwap
  '0x8c1a3cf8f83074169fe5d7ad50b978e1cd6b37c7',
  
  // Balancer
  '0x1b8128c3a1b7d20053d10763ff02466ca7ff99fc',
  
  // Aggregators
  '0xfbc22278a96299d91d41c453234d97b4f5eb9b2d', // Odos
  '0x6131b5fae19ea4f9d964eac0408e4408b66337b5', // KyberSwap
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff', // 0x
  '0x1111111254eeb25477b68fb85ed929f73a960582', // 1inch V5
  '0x111111125421ca6dc452d289314280a0f8842a65', // 1inch V6
]);

// DEX method signatures (swap, add/remove liquidity, etc.)
const DEX_METHOD_SIGNATURES: Set<string> = new Set([
  // Uniswap V2 style
  '0x38ed1739', // swapExactTokensForTokens
  '0x8803dbee', // swapTokensForExactTokens
  '0x7ff36ab5', // swapExactETHForTokens
  '0x4a25d94a', // swapTokensForExactETH
  '0x18cbafe5', // swapExactTokensForETH
  '0xfb3bdb41', // swapETHForExactTokens
  '0x5c11d795', // swapExactTokensForTokensSupportingFeeOnTransferTokens
  '0xb6f9de95', // swapExactETHForTokensSupportingFeeOnTransferTokens
  '0x791ac947', // swapExactTokensForETHSupportingFeeOnTransferTokens
  
  // Uniswap V3 style
  '0x04e45aaf', // exactInputSingle
  '0xb858183f', // exactInput
  '0x5023b4df', // exactOutputSingle
  '0x09b81346', // exactOutput
  '0x472b43f3', // swapExactTokensForTokens (Universal Router)
  
  // Liquidity
  '0xe8e33700', // addLiquidity
  '0xf305d719', // addLiquidityETH
  '0xbaa2abde', // removeLiquidity
  '0x02751cec', // removeLiquidityETH
  '0xaf2979eb', // removeLiquidityETHSupportingFeeOnTransferTokens
  '0x2195995c', // removeLiquidityETHWithPermit
  '0x5b0d5984', // removeLiquidityETHWithPermitSupportingFeeOnTransferTokens
  
  // V3 Liquidity
  '0x88316456', // mint (V3 position)
  '0x0c49ccbe', // decreaseLiquidity
  '0x219f5d17', // increaseLiquidity
  '0xfc6f7865', // collect
  
  // Universal Router
  '0x3593564c', // execute (Universal Router)
  '0x24856bc3', // execute (with deadline)
]);

// ============================================
// DEX ACTIVITY DETECTION
// ============================================

export interface DEXActivityResult {
  isDEXActivity: boolean;
  isVerifiedRouter: boolean;
  routerName?: string;
  activityType?: 'SWAP' | 'LIQUIDITY_ADD' | 'LIQUIDITY_REMOVE' | 'APPROVAL' | 'OTHER';
  chain: Chain;
  shouldFlagAsCompromise: false | 'MAYBE';
  explanation: string;
}

/**
 * Check if a transaction is DEX activity on Base chain.
 * 
 * RULE: DEX interaction alone ≠ compromise signal
 * 
 * Returns shouldFlagAsCompromise: false if this is legitimate DEX activity.
 */
export function checkBaseDEXActivity(
  toAddress: string,
  methodId?: string
): DEXActivityResult {
  const normalized = toAddress?.toLowerCase() || '';
  
  // Check if destination is a known Base DEX router
  if (BASE_DEX_ROUTERS.has(normalized)) {
    const contract = protectionIndex.get(normalized);
    const methodSig = methodId?.slice(0, 10).toLowerCase() || '';
    
    let activityType: DEXActivityResult['activityType'] = 'OTHER';
    if (methodSig) {
      if (methodSig.startsWith('0x38ed') || methodSig.startsWith('0x04e4') || 
          methodSig.startsWith('0x7ff3') || methodSig.startsWith('0x18cb') ||
          methodSig.startsWith('0xb858') || methodSig.startsWith('0x472b') ||
          methodSig.startsWith('0x3593')) {
        activityType = 'SWAP';
      } else if (methodSig.startsWith('0xe8e3') || methodSig.startsWith('0xf305') ||
                 methodSig.startsWith('0x8831') || methodSig.startsWith('0x219f')) {
        activityType = 'LIQUIDITY_ADD';
      } else if (methodSig.startsWith('0xbaa2') || methodSig.startsWith('0x02751') ||
                 methodSig.startsWith('0x0c49')) {
        activityType = 'LIQUIDITY_REMOVE';
      } else if (methodSig === '0x095ea7b3') {
        activityType = 'APPROVAL';
      }
    }
    
    return {
      isDEXActivity: true,
      isVerifiedRouter: true,
      routerName: contract?.name || 'Verified Base DEX Router',
      activityType,
      chain: 'base',
      shouldFlagAsCompromise: false,
      explanation: `Normal DEX activity detected (Base chain). Transaction to ${contract?.name || 'verified router'} is legitimate.`,
    };
  }
  
  // Check if method signature is DEX-related even if router not in list
  const methodSig = methodId?.slice(0, 10).toLowerCase() || '';
  if (methodSig && DEX_METHOD_SIGNATURES.has(methodSig)) {
    return {
      isDEXActivity: true,
      isVerifiedRouter: false,
      activityType: 'SWAP',
      chain: 'base',
      shouldFlagAsCompromise: 'MAYBE',
      explanation: 'DEX method signature detected but router not verified. Manual review recommended.',
    };
  }
  
  return {
    isDEXActivity: false,
    isVerifiedRouter: false,
    chain: 'base',
    shouldFlagAsCompromise: 'MAYBE',
    explanation: 'Not recognized as DEX activity.',
  };
}

/**
 * Check if activity is normal DEX usage that should NOT trigger compromise alerts.
 * 
 * RULE: If ONLY indicators are Uniswap swap, liquidity add/remove, or token approval
 * to verified router → force SAFE status with risk score 0-1.
 */
export function isNormalDEXActivityOnly(
  transactions: { to: string; methodId?: string; chain: Chain }[]
): { isNormalDEXOnly: boolean; explanation: string; forceSafeStatus: boolean } {
  if (transactions.length === 0) {
    return { isNormalDEXOnly: false, explanation: 'No transactions to analyze', forceSafeStatus: false };
  }
  
  let dexActivityCount = 0;
  let nonDEXActivityCount = 0;
  const dexRoutersUsed: string[] = [];
  
  for (const tx of transactions) {
    const toAddr = tx.to?.toLowerCase() || '';
    const chain = tx.chain;
    
    // Check chain-specific DEX routers
    let isDEXRouter = false;
    
    if (chain === 'base') {
      isDEXRouter = BASE_DEX_ROUTERS.has(toAddr);
    } else {
      // Check general protection
      const protection = checkInfrastructureProtection(toAddr, chain);
      isDEXRouter = protection.isProtected && 
                    (protection.type === 'DEX_ROUTER' || protection.type === 'AGGREGATOR');
    }
    
    if (isDEXRouter) {
      dexActivityCount++;
      const contract = protectionIndex.get(toAddr);
      if (contract?.name && !dexRoutersUsed.includes(contract.name)) {
        dexRoutersUsed.push(contract.name);
      }
    } else {
      nonDEXActivityCount++;
    }
  }
  
  // If ALL transactions are DEX activity → SAFE
  if (nonDEXActivityCount === 0 && dexActivityCount > 0) {
    return {
      isNormalDEXOnly: true,
      explanation: `Normal DEX activity detected (${transactions[0].chain} chain). ` +
                   `${dexActivityCount} transaction(s) to verified DEX routers: ${dexRoutersUsed.join(', ')}.`,
      forceSafeStatus: true,
    };
  }
  
  // If majority (>80%) is DEX activity → likely SAFE
  const dexRatio = dexActivityCount / (dexActivityCount + nonDEXActivityCount);
  if (dexRatio > 0.8 && dexActivityCount >= 3) {
    return {
      isNormalDEXOnly: true,
      explanation: `Predominantly DEX activity (${Math.round(dexRatio * 100)}%). ` +
                   `${dexActivityCount} DEX transactions, ${nonDEXActivityCount} other.`,
      forceSafeStatus: true,
    };
  }
  
  return {
    isNormalDEXOnly: false,
    explanation: `Mixed activity: ${dexActivityCount} DEX, ${nonDEXActivityCount} other transactions.`,
    forceSafeStatus: false,
  };
}

/**
 * Chain-aware DEX router check.
 * Returns true if address is a verified DEX router on the specified chain.
 */
export function isVerifiedDEXRouter(address: string, chain: Chain): boolean {
  const normalized = address?.toLowerCase() || '';
  
  if (chain === 'base') {
    return BASE_DEX_ROUTERS.has(normalized);
  }
  
  const contract = protectionIndex.get(normalized);
  if (!contract) return false;
  
  return contract.chains.includes(chain) && 
         (contract.type === 'DEX_ROUTER' || contract.type === 'AGGREGATOR');
}

/**
 * Get all verified DEX routers for a specific chain.
 */
export function getVerifiedDEXRouters(chain: Chain): string[] {
  if (chain === 'base') {
    return Array.from(BASE_DEX_ROUTERS);
  }
  
  return PROTECTED_INFRASTRUCTURE
    .filter(c => c.chains.includes(chain) && (c.type === 'DEX_ROUTER' || c.type === 'AGGREGATOR'))
    .map(c => c.address);
}

// ============================================
// CEX WALLET DETECTION
// ============================================
// Centralized Exchange hot wallets and deposit contracts
// CRITICAL: Transfers to/from CEX wallets are NEVER drainer activity!

const CEX_WALLETS: Map<string, { name: string; type: 'HOT_WALLET' | 'DEPOSIT' | 'COLD_WALLET' }> = new Map([
  // ============================================
  // BINANCE
  // ============================================
  ['0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be', { name: 'Binance', type: 'HOT_WALLET' }],
  ['0xd551234ae421e3bcba99a0da6d736074f22192ff', { name: 'Binance', type: 'HOT_WALLET' }],
  ['0x564286362092d8e7936f0549571a803b203aaced', { name: 'Binance', type: 'HOT_WALLET' }],
  ['0x0681d8db095565fe8a346fa0277bffde9c0edbbf', { name: 'Binance', type: 'HOT_WALLET' }],
  ['0xfe9e8709d3215310075d67e3ed32a380ccf451c8', { name: 'Binance', type: 'HOT_WALLET' }],
  ['0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67', { name: 'Binance', type: 'HOT_WALLET' }],
  ['0xbe0eb53f46cd790cd13851d5eff43d12404d33e8', { name: 'Binance Cold', type: 'COLD_WALLET' }],
  ['0xf977814e90da44bfa03b6295a0616a897441acec', { name: 'Binance 8', type: 'HOT_WALLET' }],
  ['0x28c6c06298d514db089934071355e5743bf21d60', { name: 'Binance 14', type: 'HOT_WALLET' }],
  ['0x21a31ee1afc51d94c2efccaa2092ad1028285549', { name: 'Binance 15', type: 'HOT_WALLET' }],
  ['0xdfd5293d8e347dfe59e90efd55b2956a1343963d', { name: 'Binance 16', type: 'HOT_WALLET' }],
  ['0x56eddb7aa87536c09ccc2793473599fd21a8b17f', { name: 'Binance 17', type: 'HOT_WALLET' }],
  ['0x5a52e96bacdabb82fd05763e25335261b270efcb', { name: 'Binance 28', type: 'HOT_WALLET' }],
  
  // ============================================
  // COINBASE
  // ============================================
  ['0x71660c4005ba85c37ccec55d0c4493e66fe775d3', { name: 'Coinbase', type: 'HOT_WALLET' }],
  ['0x503828976d22510aad0201ac7ec88293211d23da', { name: 'Coinbase', type: 'HOT_WALLET' }],
  ['0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740', { name: 'Coinbase', type: 'HOT_WALLET' }],
  ['0x3cd751e6b0078be393132286c442345e5dc49699', { name: 'Coinbase', type: 'HOT_WALLET' }],
  ['0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511', { name: 'Coinbase', type: 'HOT_WALLET' }],
  ['0xeb2629a2734e272bcc07bda959863f316f4bd4cf', { name: 'Coinbase', type: 'HOT_WALLET' }],
  ['0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43', { name: 'Coinbase 10', type: 'HOT_WALLET' }],
  ['0x77134cbc06cb00b66f4c7e623d5fdbf6777635ec', { name: 'Coinbase Commerce', type: 'HOT_WALLET' }],
  ['0xe0f0cfde7ee664943906f17f7f14342e76a5cec7', { name: 'Coinbase Commerce 2', type: 'HOT_WALLET' }],
  
  // ============================================
  // KRAKEN
  // ============================================
  ['0x2910543af39aba0cd09dbb2d50200b3e800a63d2', { name: 'Kraken', type: 'HOT_WALLET' }],
  ['0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13', { name: 'Kraken', type: 'HOT_WALLET' }],
  ['0xe853c56864a2ebe4576a807d26fdc4a0ada51919', { name: 'Kraken', type: 'HOT_WALLET' }],
  ['0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0', { name: 'Kraken', type: 'HOT_WALLET' }],
  ['0xfa52274dd61e1643d2205169732f29114bc240b3', { name: 'Kraken', type: 'HOT_WALLET' }],
  
  // ============================================
  // KUCOIN
  // ============================================
  ['0x2b5634c42055806a59e9107ed44d43c426e58258', { name: 'KuCoin', type: 'HOT_WALLET' }],
  ['0x689c56aef474df92d44a1b70850f808488f9769c', { name: 'KuCoin', type: 'HOT_WALLET' }],
  ['0xa1d8d972560c2f8144af871db508f0b0b10a3fbf', { name: 'KuCoin', type: 'HOT_WALLET' }],
  ['0x4ad64983349c49defe8d7a4686202d24b25d0ce8', { name: 'KuCoin', type: 'HOT_WALLET' }],
  
  // ============================================
  // OKX (OKEX)
  // ============================================
  ['0x6cc5f688a315f3dc28a7781717a9a798a59fda7b', { name: 'OKX', type: 'HOT_WALLET' }],
  ['0x236f9f97e0e62388479bf9e5ba4889e46b0273c3', { name: 'OKX', type: 'HOT_WALLET' }],
  ['0xa7efae728d2936e78bda97dc267687568dd593f3', { name: 'OKX', type: 'HOT_WALLET' }],
  ['0x5041ed759dd4afc3a72b8192c143f72f4724081a', { name: 'OKX', type: 'HOT_WALLET' }],
  ['0x98ec059dc3adfbdd63429454aeb0c990fba4a128', { name: 'OKX', type: 'HOT_WALLET' }],
  
  // ============================================
  // HUOBI (HTX)
  // ============================================
  ['0xab5c66752a9e8167967685f1450532fb96d5d24f', { name: 'Huobi', type: 'HOT_WALLET' }],
  ['0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b', { name: 'Huobi', type: 'HOT_WALLET' }],
  ['0xfdb16996831753d5331ff813c29a93c76834a0ad', { name: 'Huobi', type: 'HOT_WALLET' }],
  ['0xeee28d484628d41a82d01e21d12e2e78d69920da', { name: 'Huobi', type: 'HOT_WALLET' }],
  
  // ============================================
  // GEMINI
  // ============================================
  ['0xd24400ae8bfebb18ca49be86258a3c749cf46853', { name: 'Gemini', type: 'HOT_WALLET' }],
  ['0x6fc82a5fe25a5cdb58bc74600a40a69c065263f8', { name: 'Gemini', type: 'HOT_WALLET' }],
  ['0x61edcdf5bb737adffe5043706e7c5bb1f1a56eea', { name: 'Gemini', type: 'HOT_WALLET' }],
  
  // ============================================
  // BYBIT
  // ============================================
  ['0xf89d7b9c864f589bbf53a82105107622b35eaa40', { name: 'Bybit', type: 'HOT_WALLET' }],
  ['0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4', { name: 'Bybit', type: 'HOT_WALLET' }],
  
  // ============================================
  // CRYPTO.COM
  // ============================================
  ['0x6262998ced04146fa42253a5c0af90ca02dfd2a3', { name: 'Crypto.com', type: 'HOT_WALLET' }],
  ['0x46340b20830761efd32832a74d7169b29feb9758', { name: 'Crypto.com', type: 'HOT_WALLET' }],
  
  // ============================================
  // BITFINEX
  // ============================================
  ['0x1151314c646ce4e0efd76d1af4760ae66a9fe30f', { name: 'Bitfinex', type: 'HOT_WALLET' }],
  ['0x742d35cc6634c0532925a3b844bc454e4438f44e', { name: 'Bitfinex', type: 'HOT_WALLET' }],
  ['0x876eabf441b2ee5b5b0554fd502a8e0600950cfa', { name: 'Bitfinex', type: 'HOT_WALLET' }],
  
  // ============================================
  // GATE.IO
  // ============================================
  ['0x0d0707963952f2fba59dd06f2b425ace40b492fe', { name: 'Gate.io', type: 'HOT_WALLET' }],
  ['0x1c4b70a3968436b9a0a9cf5205c787eb81bb558c', { name: 'Gate.io', type: 'HOT_WALLET' }],
  
  // ============================================
  // BITSTAMP
  // ============================================
  ['0x00bdb5699745f5b860228c8f939abf1b9ae374ed', { name: 'Bitstamp', type: 'HOT_WALLET' }],
  
  // ============================================
  // ROBINHOOD
  // ============================================
  ['0x40b38765696e3d5d8d9d834d8aad4bb6e418e489', { name: 'Robinhood', type: 'HOT_WALLET' }],
]);

// ============================================
// CEX WALLET CHECK FUNCTIONS
// ============================================

export interface CEXWalletInfo {
  isCEXWallet: boolean;
  exchangeName?: string;
  walletType?: 'HOT_WALLET' | 'DEPOSIT' | 'COLD_WALLET';
}

/**
 * Check if an address is a known centralized exchange wallet.
 * CEX wallets should NEVER be flagged as drainers.
 */
export function isKnownCEXWallet(address: string): boolean {
  const normalized = address?.toLowerCase() || '';
  return CEX_WALLETS.has(normalized);
}

/**
 * Get detailed CEX wallet information.
 */
export function getCEXWalletInfo(address: string): CEXWalletInfo {
  const normalized = address?.toLowerCase() || '';
  const info = CEX_WALLETS.get(normalized);
  
  if (info) {
    return {
      isCEXWallet: true,
      exchangeName: info.name,
      walletType: info.type,
    };
  }
  
  return { isCEXWallet: false };
}

/**
 * Check if a transaction is a CEX deposit/withdrawal.
 * These should NEVER trigger drainer alerts.
 */
export function isCEXTransaction(fromAddress: string, toAddress: string): {
  isCEXActivity: boolean;
  type: 'DEPOSIT' | 'WITHDRAWAL' | 'NONE';
  exchangeName?: string;
} {
  const fromInfo = getCEXWalletInfo(fromAddress);
  const toInfo = getCEXWalletInfo(toAddress);
  
  if (toInfo.isCEXWallet) {
    return {
      isCEXActivity: true,
      type: 'DEPOSIT',
      exchangeName: toInfo.exchangeName,
    };
  }
  
  if (fromInfo.isCEXWallet) {
    return {
      isCEXActivity: true,
      type: 'WITHDRAWAL',
      exchangeName: fromInfo.exchangeName,
    };
  }
  
  return { isCEXActivity: false, type: 'NONE' };
}

/**
 * Get all known CEX wallet addresses.
 */
export function getAllCEXWallets(): string[] {
  return Array.from(CEX_WALLETS.keys());
}

// ============================================
// EXPORTS
// ============================================

export {
  isOpenSeaVanityAddress,
  getExpectedBehavior,
  BASE_DEX_ROUTERS,
  DEX_METHOD_SIGNATURES,
  CEX_WALLETS,
};

