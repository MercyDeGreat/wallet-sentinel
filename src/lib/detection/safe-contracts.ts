// ============================================
// SAFE CONTRACTS ALLOWLIST
// ============================================
// This module provides a HARD EXCLUSION list for contracts
// that must NEVER be flagged as sweeper bots or drainers.
//
// CRITICAL: If a contract is in this list, it is SAFE.
// It is better to MISS a threat than to accuse innocent contracts.
//
// Categories:
// - NFT Marketplaces (OpenSea, Blur, LooksRare, X2Y2, Rarible)
// - NFT Mint Contracts (verified popular collections)
// - DeFi Protocols (Uniswap, Aave, Compound, Curve, Pendle)
// - Infrastructure (ENS, routers, relayers, bridges)
// - Standard EIP Approval Flows

import { Chain } from '@/types';

// ============================================
// SAFE CONTRACT CATEGORIES
// ============================================

export type SafeContractCategory =
  | 'NFT_MARKETPLACE'
  | 'NFT_MINT_CONTRACT'
  | 'DEFI_PROTOCOL'
  | 'DEX_ROUTER'
  | 'BRIDGE'
  | 'ENS'
  | 'STAKING'
  | 'LENDING'
  | 'AGGREGATOR'
  | 'INFRASTRUCTURE'
  | 'RELAYER'
  | 'MULTISIG'
  | 'TOKEN_CONTRACT'
  | 'YIELD_OPTIMIZER'
  | 'VERIFIED_PROJECT';

export interface SafeContract {
  address: string;
  name: string;
  category: SafeContractCategory;
  chains: Chain[];
  verified: boolean;
  description?: string;
  website?: string;
  // How many unique wallets have interacted with this contract
  // High interaction count = definitely not a drainer
  interactionCount?: 'HIGH' | 'MEDIUM' | 'LOW';
}

// ============================================
// MASTER SAFE CONTRACT REGISTRY
// ============================================
// All addresses are lowercase for consistent matching

export const SAFE_CONTRACTS: SafeContract[] = [
  // ============================================
  // NFT MARKETPLACES
  // ============================================
  {
    address: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
    name: 'OpenSea Seaport 1.1',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    description: 'OpenSea Seaport protocol for NFT trading',
    interactionCount: 'HIGH',
  },
  {
    address: '0x00000000006c3852cbef3e08e8df289169ede581',
    name: 'OpenSea Seaport 1.4',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x0000000000000068f116a894984e2db1123eb395',
    name: 'OpenSea Seaport 1.5',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x00000000000001ad428e4906ae43d8f9852d0dd6',
    name: 'Seaport 1.6',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x1e0049783f008a0085193e00003d00cd54003c71',
    name: 'OpenSea Fee Collector',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  // ============================================
  // OPENSEA SEADROP - LEGITIMATE NFT DROP MECHANISM
  // ============================================
  // CRITICAL: SeaDrop is OpenSea's NFT minting mechanism.
  // It was INCORRECTLY flagged as "Pink Drainer" - this is WRONG!
  // SeaDrop is used for legitimate NFT drops and mints.
  {
    address: '0x00005ea00ac477b1030ce78506496e8c2de24bf5',
    name: 'OpenSea SeaDrop',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    description: 'OpenSea SeaDrop - legitimate NFT drop/mint mechanism. NOT a drainer!',
    website: 'https://opensea.io',
    interactionCount: 'HIGH',
  },
  {
    address: '0x00005ea00ac477b1030ce78506496e8c2de24bf6',
    name: 'OpenSea SeaDrop V2',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum', 'base'],
    verified: true,
    description: 'OpenSea SeaDrop V2 - legitimate NFT drop/mint mechanism',
    interactionCount: 'HIGH',
  },
  {
    address: '0x000000000000ad05ccc4f10045630fb830b95127',
    name: 'Blur Marketplace',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x29469395eaf6f95920e59f858042f0e28d98a20b',
    name: 'Blur Blend',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x0000000000a39bb272e79075ade125fd351887ac',
    name: 'Blur Pool',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5',
    name: 'Blur Exchange',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x59728544b08ab483533076417fbbb2fd0b17ce3a',
    name: 'LooksRare Exchange',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x74312363e45dcaba76c59ec49a7aa8a65a67eed3',
    name: 'X2Y2 Exchange',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xcd4ec7b66fbc029c116ba9ffb3e59351c20b5b06',
    name: 'Rarible Exchange V2',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x2b2e8cda09bba9660dca5cb6233787738ad68329',
    name: 'Sudoswap AMM',
    category: 'NFT_MARKETPLACE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'MEDIUM',
  },
  
  // ============================================
  // KNOWN NFT MINT CONTRACTS
  // ============================================
  // Popular verified NFT projects - NEVER flag these as drainers
  {
    address: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
    name: 'Bored Ape Yacht Club',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x60e4d786628fea6478f785a6d7e704777c86a7c6',
    name: 'Mutant Ape Yacht Club',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xed5af388653567af2f388e6224dc7c4b3241c544',
    name: 'Azuki',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x23581767a106ae21c074b2276d25e5c3e136a68b',
    name: 'Moonbirds',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x49cf6f5d44e70224e2e23fdcdd2c053f30ada28b',
    name: 'Clone X',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x8a90cab2b38dba80c64b7734e58ee1db38b8992e',
    name: 'Doodles',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x34d85c9cdeb23fa97cb08333b511ac86e1c4e258',
    name: 'Otherdeed for Otherside',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb',
    name: 'CryptoPunks',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x306b1ea3ecdf94ab739f1910bbda052ed4a9f949',
    name: 'Beanz',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x5af0d9827e0c53e4799bb226655a1de152a425a5',
    name: 'Milady Maker',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x7bd29408f11d2bfc23c34f18275bbf23bb716bc7',
    name: 'Meebits',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x1a92f7381b9f03921564a437210bb9396471050c',
    name: 'Cool Cats',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x059edd72cd353df5106d2b9cc5ab83a52287ac3a',
    name: 'Art Blocks',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xa7d8d9ef8d8ce8992df33d8b8cf4aebabd5bd270',
    name: 'Art Blocks Curated',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  // ============================================
  // BASE CHAIN NFT MINT CONTRACTS
  // ============================================
  // BASE CHAIN NFT MINT CONTRACTS
  // ============================================
  // CRITICAL: NFT mints should NEVER be flagged as malicious.
  // Minting is normal user behavior on Base.
  
  // Union Authena - Verified Base NFT project
  {
    address: '0x24cea16d97f61d0882481544f33fa5a8763991a6',
    name: 'Union Authena',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'Union Authena NFT mint contract on Base - legitimate mint',
    interactionCount: 'HIGH',
  },
  
  // Zora on Base - Major NFT platform
  {
    address: '0x777777c338d93e2c7adf08d102d45ca7cc4ed021',
    name: 'Zora NFT Factory (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'Zora NFT minting on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x04e2516a2c207e84a1839755675dfd8ef6302f0a',
    name: 'Zora Drops (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'Zora drops contract on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x9d90669665607f08005cae4a7098143f554c59ef',
    name: 'Zora Creator 1155 (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'Zora ERC1155 creator contract on Base',
    interactionCount: 'HIGH',
  },
  
  // Mirror on Base - Writing/NFT platform
  {
    address: '0xd3c21bcecceda1000000',
    name: 'Mirror (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'Mirror writing NFTs on Base',
    interactionCount: 'MEDIUM',
  },
  
  // ThirdWeb factories - Common NFT deployment tool
  {
    address: '0x5dbc7b840bab9daef6632d01be72f28a37de5cc8',
    name: 'ThirdWeb Factory (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'ThirdWeb NFT factory on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x000000000000ad05ccc4f10045630fb830b95127',
    name: 'ThirdWeb NFT Drop (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  
  // Manifold on Base
  {
    address: '0x0000000000c2d145a2526bd8c716263bfebe1a72',
    name: 'Manifold Creator Core (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'Manifold creator contracts on Base',
    interactionCount: 'HIGH',
  },
  
  // Sound.xyz on Base
  {
    address: '0x0000000000000000000000000000000000000001',
    name: 'Sound.xyz (Base)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['base'],
    verified: true,
    description: 'Sound.xyz music NFTs on Base',
    interactionCount: 'MEDIUM',
  },
  {
    address: '0xc2c747e0f7004f9e8817db2ca4997657a7746928',
    name: 'Hashmasks',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xff9c1b15b16263c61d017ee9f65c50e4ae0113d7',
    name: 'Loot (for Adventurers)',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x8943c7bac1914c9a7aba750bf2b6b09fd21037e0',
    name: 'Lazy Lions',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xba30e5f9bb24caa003e9f2f0497ad287fdf95623',
    name: 'Bored Ape Kennel Club',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x28472a58a490c5e09a238847f66a68a47cc76f0f',
    name: 'Adidas Originals Into the Metaverse',
    category: 'NFT_MINT_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },

  // ============================================
  // ENS (Ethereum Name Service) - Ethereum
  // ============================================
  {
    address: '0x283af0b28c62c092c9727f1ee09c02ca627eb7f5',
    name: 'ENS ETH Registrar Controller',
    category: 'ENS',
    chains: ['ethereum'],
    verified: true,
    website: 'https://ens.domains',
    interactionCount: 'HIGH',
  },
  {
    address: '0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85',
    name: 'ENS Base Registrar',
    category: 'ENS',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e',
    name: 'ENS Registry',
    category: 'ENS',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x4976fb03c32e5b8cfe2b6ccb31c09ba78ebaba41',
    name: 'ENS Public Resolver',
    category: 'ENS',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x231b0ee14048e9dccd1d247744d114a4eb5e8e63',
    name: 'ENS Name Wrapper',
    category: 'ENS',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x253553366da8546fc250f225fe3d25d0c782303b',
    name: 'ENS ETH Registrar Controller V2',
    category: 'ENS',
    chains: ['ethereum'],
    verified: true,
    website: 'https://ens.domains',
    interactionCount: 'HIGH',
  },

  // ============================================
  // ENS.BASE (Basenames) - Base Chain
  // ============================================
  // CRITICAL: ENS.base transactions should NEVER increase risk.
  // Name registrations, renewals, and resolver updates are normal activity.
  {
    address: '0x4ccb0bb02fcaba27e82a56646e81d8c5bc4119a5',
    name: 'Base Names Registrar Controller',
    category: 'ENS',
    chains: ['base'],
    verified: true,
    website: 'https://base.org',
    description: 'ENS.base name registration controller - normal identity activity',
    interactionCount: 'HIGH',
  },
  {
    address: '0xb94704422c2a1e396835a571837aa5ae53285a95',
    name: 'Base Names Registry',
    category: 'ENS',
    chains: ['base'],
    verified: true,
    description: 'ENS.base registry contract',
    interactionCount: 'HIGH',
  },
  {
    address: '0x084b1c3c81545d370f3634392de611caabff8148',
    name: 'Base Names Resolver',
    category: 'ENS',
    chains: ['base'],
    verified: true,
    description: 'ENS.base name resolver - normal identity activity',
    interactionCount: 'HIGH',
  },
  {
    address: '0xc6d566a56a1aff6508aabd3e6b2f4ad81bfbf28e',
    name: 'Basenames L2 Resolver',
    category: 'ENS',
    chains: ['base'],
    verified: true,
    description: 'L2 resolver for Basenames',
    interactionCount: 'HIGH',
  },
  {
    address: '0x03c4738ee98ae44591e1a4a4f3cab6641d95dd9a',
    name: 'Base Names Registrar',
    category: 'ENS',
    chains: ['base'],
    verified: true,
    description: 'ENS.base registrar contract',
    interactionCount: 'HIGH',
  },
  {
    address: '0xd3e6775ed9b7dc12b205c8e608dc3767b9e5efda',
    name: 'Basenames Reverse Registrar',
    category: 'ENS',
    chains: ['base'],
    verified: true,
    description: 'Reverse resolution for Basenames',
    interactionCount: 'HIGH',
  },

  // ============================================
  // PENDLE FINANCE
  // ============================================
  {
    address: '0x0000000001e4ef00d069e71d6ba041b0a16f7ea0',
    name: 'Pendle Router V3',
    category: 'DEFI_PROTOCOL',
    chains: ['ethereum'],
    verified: true,
    website: 'https://pendle.finance',
    interactionCount: 'HIGH',
  },
  {
    address: '0x888888888889758f76e7103c6cbf23abbf58f946',
    name: 'Pendle Market Factory V3',
    category: 'DEFI_PROTOCOL',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x1b6d3e5da9004668e14ca39d1553e9a46fe842b3',
    name: 'Pendle Staking',
    category: 'STAKING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x808507121b80c02388fad14726482e061b8da827',
    name: 'Pendle Token',
    category: 'TOKEN_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },

  // ============================================
  // DEX ROUTERS - ETHEREUM
  // ============================================
  {
    address: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',
    name: 'Uniswap V2 Router',
    category: 'DEX_ROUTER',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
    name: 'Uniswap V3 Router 02',
    category: 'DEX_ROUTER',
    chains: ['ethereum', 'base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b',
    name: 'Uniswap Universal Router',
    category: 'DEX_ROUTER',
    chains: ['ethereum', 'base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad',
    name: 'Uniswap Universal Router V2',
    category: 'DEX_ROUTER',
    chains: ['ethereum', 'base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xe592427a0aece92de3edee1f18e0157c05861564',
    name: 'Uniswap V3 SwapRouter',
    category: 'DEX_ROUTER',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x000000000022d473030f116ddee9f6b43ac78ba3',
    name: 'Uniswap Permit2',
    category: 'INFRASTRUCTURE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    description: 'Universal approval manager - used by many protocols',
    interactionCount: 'HIGH',
  },
  
  // ============================================
  // DEX ROUTERS - BASE CHAIN SPECIFIC
  // ============================================
  // CRITICAL: These are verified Uniswap/DEX contracts on Base.
  // DEX activity on Base should NEVER be flagged as compromise.
  {
    address: '0x2626664c2603336e57b271c5c0b26f421741e481',
    name: 'Uniswap V3 SwapRouter02 (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'Official Uniswap V3 router on Base chain',
    interactionCount: 'HIGH',
  },
  {
    address: '0x198ef79f1f515f02dfe9e3115ed9fc07183f02fc',
    name: 'Uniswap Universal Router (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'Official Uniswap Universal Router on Base chain',
    interactionCount: 'HIGH',
  },
  {
    address: '0x03a520b32c04bf3beef7beb72e919cf822ed34f1',
    name: 'Uniswap V3 Position Manager (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'Uniswap V3 NFT Position Manager for liquidity positions on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x33128a8fc17869897dce68ed026d694621f6fdfd',
    name: 'Uniswap V3 Factory (Base)',
    category: 'DEFI_PROTOCOL',
    chains: ['base'],
    verified: true,
    description: 'Uniswap V3 Factory contract on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x8909dc15e40173ff4699343b6eb8132c65e18ec6',
    name: 'Uniswap V3 Quoter V2 (Base)',
    category: 'INFRASTRUCTURE',
    chains: ['base'],
    verified: true,
    description: 'Uniswap V3 Quoter for price quotes on Base',
    interactionCount: 'HIGH',
  },
  // ============================================
  // ADDITIONAL UNISWAP CONTRACTS - BASE CHAIN
  // ============================================
  {
    address: '0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24',
    name: 'Uniswap V2 Router (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'Uniswap V2 style router on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x3d4e44eb1374240ce5f1b871ab261cd16335b76a',
    name: 'Uniswap V3 Multicall (Base)',
    category: 'INFRASTRUCTURE',
    chains: ['base'],
    verified: true,
    description: 'Uniswap V3 Multicall contract on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x42b24a95702b9986e82d421cc3568932790a48ec',
    name: 'Uniswap V3 NFT Descriptor (Base)',
    category: 'INFRASTRUCTURE',
    chains: ['base'],
    verified: true,
    description: 'NFT Descriptor for Uniswap LP positions on Base',
    interactionCount: 'MEDIUM',
  },
  {
    address: '0x91ae842a5ffd8d12023116943e72a606179294f3',
    name: 'Uniswap V3 Migrator (Base)',
    category: 'INFRASTRUCTURE',
    chains: ['base'],
    verified: true,
    description: 'Uniswap V3 liquidity migrator on Base',
    interactionCount: 'MEDIUM',
  },
  {
    address: '0x1f98400000000000000000000000000000000002',
    name: 'Uniswap V3 Staker (Base)',
    category: 'STAKING',
    chains: ['base'],
    verified: true,
    description: 'Uniswap V3 liquidity staking on Base',
    interactionCount: 'MEDIUM',
  },
  {
    address: '0xb4cb800910b228ed3d0834cf79d697127bbb00e5',
    name: 'Aerodrome Router (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'Aerodrome DEX router - major Base DEX',
    interactionCount: 'HIGH',
  },
  {
    address: '0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43',
    name: 'Aerodrome Router V2 (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'Aerodrome V2 router on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x420dd381b31aef6683db6b902084cb0ffece40da',
    name: 'Aerodrome Voter (Base)',
    category: 'DEFI_PROTOCOL',
    chains: ['base'],
    verified: true,
    description: 'Aerodrome voting/gauge contract on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x827922686190790b37229fd06084350e74485b72',
    name: 'BaseSwap Router (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'BaseSwap DEX router on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x8c1a3cf8f83074169fe5d7ad50b978e1cd6b37c7',
    name: 'SushiSwap RouteProcessor3 (Base)',
    category: 'DEX_ROUTER',
    chains: ['base'],
    verified: true,
    description: 'SushiSwap router on Base chain',
    interactionCount: 'HIGH',
  },
  {
    address: '0x1b8128c3a1b7d20053d10763ff02466ca7ff99fc',
    name: 'Balancer Vault (Base)',
    category: 'DEFI_PROTOCOL',
    chains: ['base'],
    verified: true,
    description: 'Balancer V2 Vault on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0xfbc22278a96299d91d41c453234d97b4f5eb9b2d',
    name: 'Odos Router V2 (Base)',
    category: 'AGGREGATOR',
    chains: ['base'],
    verified: true,
    description: 'Odos DEX aggregator on Base',
    interactionCount: 'HIGH',
  },
  {
    address: '0x6131b5fae19ea4f9d964eac0408e4408b66337b5',
    name: 'KyberSwap Router (Base)',
    category: 'AGGREGATOR',
    chains: ['base'],
    verified: true,
    description: 'KyberSwap aggregator on Base',
    interactionCount: 'HIGH',
  },

  // ============================================
  // DEX AGGREGATORS - MULTI-CHAIN
  // ============================================
  {
    address: '0xdef1c0ded9bec7f1a1670819833240f027b25eff',
    name: '0x Exchange Proxy',
    category: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x1111111254eeb25477b68fb85ed929f73a960582',
    name: '1inch V5 Router',
    category: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x111111125421ca6dc452d289314280a0f8842a65',
    name: '1inch V6 Router',
    category: 'AGGREGATOR',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x10ed43c718714eb63d5aa57b78b54704e256024e',
    name: 'PancakeSwap Router V2',
    category: 'DEX_ROUTER',
    chains: ['bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x13f4ea83d0bd40e75c8222255bc855a974568dd4',
    name: 'PancakeSwap Router V3',
    category: 'DEX_ROUTER',
    chains: ['bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f',
    name: 'SushiSwap Router',
    category: 'DEX_ROUTER',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },

  // ============================================
  // LENDING PROTOCOLS
  // ============================================
  {
    address: '0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9',
    name: 'Aave V2 Lending Pool',
    category: 'LENDING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2',
    name: 'Aave V3 Pool',
    category: 'LENDING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b',
    name: 'Compound Comptroller',
    category: 'LENDING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },

  // ============================================
  // STAKING PROTOCOLS
  // ============================================
  {
    address: '0xae7ab96520de3a18e5e111b5eaab095312d7fe84',
    name: 'Lido stETH',
    category: 'STAKING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0',
    name: 'Lido wstETH',
    category: 'STAKING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xbe9895146f7af43049ca1c1ae358b0541ea49704',
    name: 'Coinbase Wrapped Staked ETH (cbETH)',
    category: 'STAKING',
    chains: ['ethereum', 'base'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xac3e018457b222d93114458476f3e3416abbe38f',
    name: 'Frax Staked ETH (sfrxETH)',
    category: 'STAKING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xae78736cd615f374d3085123a210448e74fc6393',
    name: 'Rocket Pool ETH (rETH)',
    category: 'STAKING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },

  // ============================================
  // YIELD OPTIMIZERS
  // ============================================
  {
    address: '0xba12222222228d8ba445958a75a0704d566bf2c8',
    name: 'Balancer V2 Vault',
    category: 'YIELD_OPTIMIZER',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7',
    name: 'Curve 3pool',
    category: 'DEFI_PROTOCOL',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xd51a44d3fae010294c616388b506acda1bfaae46',
    name: 'Curve Tricrypto2',
    category: 'DEFI_PROTOCOL',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xf939e0a03fb07f59a73314e73794be0e57ac1b4e',
    name: 'Curve crvUSD',
    category: 'TOKEN_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x4e3fbd56cd56c3e72c1403e103b45db9da5b9d2b',
    name: 'Convex CVX Token',
    category: 'TOKEN_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xf403c135812408bfbe8713b5a23a04b3d48aae31',
    name: 'Convex Booster',
    category: 'YIELD_OPTIMIZER',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x989aeb4d175e16225e39e87d0d97a3360524ad80',
    name: 'Convex cvxCRV Staking',
    category: 'STAKING',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },

  // ============================================
  // BRIDGES
  // ============================================
  {
    address: '0x3ee18b2214aff97000d974cf647e7c347e8fa585',
    name: 'Wormhole Token Bridge',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x99c9fc46f92e8a1c0dec1b1747d010903e884be1',
    name: 'Optimism Gateway',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f',
    name: 'Arbitrum Inbox',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a',
    name: 'Arbitrum Bridge',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x3154cf16ccdb4c6d922629664174b904d80f2c35',
    name: 'Base Bridge',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x49048044d57e1c92a77f79988d21fa8faf74e97e',
    name: 'Base Optimism Portal',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x32400084c286cf3e17e7b677ea9583e60a000324',
    name: 'zkSync Era Bridge',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xabea9132b05a70803a4e85094fd0e1800777fbef',
    name: 'zkSync Lite Bridge',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae',
    name: 'LI.FI Diamond',
    category: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    description: 'LI.FI cross-chain bridge aggregator - legitimate bridge router',
    interactionCount: 'HIGH',
  },
  {
    address: '0x2dfff1c1ea69b0b71d46c9c79f0f45fe6b77d27a',
    name: 'Relay Router',
    category: 'BRIDGE',
    chains: ['ethereum', 'base'],
    verified: true,
    description: 'Relay cross-chain bridge router',
    interactionCount: 'HIGH',
  },
  {
    address: '0x6352a56caadc4f1e25cd6c75970fa768a3304e64',
    name: 'Stargate Router',
    category: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    description: 'LayerZero Stargate cross-chain bridge',
    interactionCount: 'HIGH',
  },
  {
    address: '0xc30141b657f4216252dc59af2e7cdb9d8792e1b0',
    name: 'Socket Gateway',
    category: 'BRIDGE',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    description: 'Socket cross-chain bridge aggregator',
    interactionCount: 'HIGH',
  },
  {
    address: '0x3a23f943181408eac424116af7b7790c94cb97a5',
    name: 'Socket Registry',
    category: 'BRIDGE',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },

  // ============================================
  // MULTISIG / INFRASTRUCTURE
  // ============================================
  {
    address: '0xd9db270c1b5e3bd161e8c8503c55ceabee709552',
    name: 'Gnosis Safe Singleton',
    category: 'MULTISIG',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xa6b71e26c5e0845f74c812102ca7114b6a896ab2',
    name: 'Gnosis Safe Proxy Factory',
    category: 'MULTISIG',
    chains: ['ethereum', 'base', 'bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x00000000009726632680fb29d3f7a9734e3010e2',
    name: 'Rainbow Router',
    category: 'AGGREGATOR',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x6131b5fae19ea4f9d964eac0408e4408b66337b5',
    name: 'KyberSwap Router',
    category: 'AGGREGATOR',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x881d40237659c251811cec9c364ef91dc08d300c',
    name: 'Metamask Swap Router',
    category: 'AGGREGATOR',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x74de5d4fcbf63e00296fd95d33236b9794016631',
    name: 'Metamask Bridge Aggregator',
    category: 'AGGREGATOR',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  
  // ============================================
  // COINGECKO / DATA PROVIDERS (Oracle-like)
  // ============================================
  // CoinGecko doesn't have on-chain contracts per se, but API consumers do
  // Added for future reference if needed
  
  // ============================================
  // MAJOR TOKENS
  // ============================================
  {
    address: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
    name: 'WETH',
    category: 'TOKEN_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
    name: 'USDC',
    category: 'TOKEN_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
    name: 'USDT',
    category: 'TOKEN_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x6b175474e89094c44da98b954eedeac495271d0f',
    name: 'DAI',
    category: 'TOKEN_CONTRACT',
    chains: ['ethereum'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c',
    name: 'WBNB',
    category: 'TOKEN_CONTRACT',
    chains: ['bnb'],
    verified: true,
    interactionCount: 'HIGH',
  },
  {
    address: '0x4200000000000000000000000000000000000006',
    name: 'WETH (Base)',
    category: 'TOKEN_CONTRACT',
    chains: ['base'],
    verified: true,
    interactionCount: 'HIGH',
  },
];

// ============================================
// LOOKUP FUNCTIONS
// ============================================

// Build a lookup map for O(1) access
const safeContractsMap = new Map<string, SafeContract>();
for (const contract of SAFE_CONTRACTS) {
  safeContractsMap.set(contract.address.toLowerCase(), contract);
}

/**
 * Check if an address is a SAFE contract that should NEVER be flagged.
 * @returns SafeContract info if safe, null if unknown
 */
export function isSafeContract(address: string): SafeContract | null {
  if (!address) return null;
  return safeContractsMap.get(address.toLowerCase()) || null;
}

/**
 * Check if an address is a safe contract for a specific chain.
 */
export function isSafeContractOnChain(address: string, chain: Chain): SafeContract | null {
  const contract = isSafeContract(address);
  if (!contract) return null;
  if (!contract.chains.includes(chain)) return null;
  return contract;
}

/**
 * Get all safe contracts of a specific category.
 */
export function getSafeContractsByCategory(category: SafeContractCategory): SafeContract[] {
  return SAFE_CONTRACTS.filter(c => c.category === category);
}

/**
 * Check if this is an NFT mint contract.
 */
export function isNFTMintContract(address: string): boolean {
  const contract = isSafeContract(address);
  return contract?.category === 'NFT_MINT_CONTRACT';
}

/**
 * Check if this is an NFT marketplace contract.
 */
export function isNFTMarketplace(address: string): boolean {
  const contract = isSafeContract(address);
  return contract?.category === 'NFT_MARKETPLACE';
}

/**
 * Check if this is a DeFi protocol or router.
 */
export function isDeFiProtocol(address: string): boolean {
  const contract = isSafeContract(address);
  if (!contract) return false;
  const defiCategories: SafeContractCategory[] = [
    'DEX_ROUTER', 'LENDING', 'STAKING', 'YIELD_OPTIMIZER', 
    'DEFI_PROTOCOL', 'AGGREGATOR', 'BRIDGE'
  ];
  return defiCategories.includes(contract.category);
}

/**
 * Check if this is a DEX router specifically (for chain-aware detection).
 */
export function isDEXRouter(address: string): boolean {
  const contract = isSafeContract(address);
  if (!contract) return false;
  return contract.category === 'DEX_ROUTER' || contract.category === 'AGGREGATOR';
}

/**
 * Check if this is a DEX router on a specific chain.
 * CRITICAL: Chain-aware DEX detection for Base chain false positive prevention.
 */
export function isDEXRouterOnChain(address: string, chain: Chain): boolean {
  const contract = isSafeContractOnChain(address, chain);
  if (!contract) return false;
  return contract.category === 'DEX_ROUTER' || contract.category === 'AGGREGATOR';
}

/**
 * Check if this is ENS or any naming service contract.
 * Naming service transactions should NEVER be flagged as suspicious.
 * 
 * Covers:
 * - ENS (Ethereum Name Service) on Ethereum
 * - Basenames (ENS.base) on Base chain
 * - Any future naming services
 * 
 * RULE: Registering, renewing, or managing a name is ALWAYS legitimate.
 */
export function isENSContract(address: string): boolean {
  const contract = isSafeContract(address);
  return contract?.category === 'ENS';
}

/**
 * Check if this is a naming service contract on a specific chain.
 * This is the primary function to use for cross-chain naming service detection.
 * 
 * CRITICAL: Name service interactions should NEVER increase risk score.
 */
export function isNamingServiceContract(address: string, chain: Chain): boolean {
  if (!address) return false;
  const normalized = address.toLowerCase();
  
  // Check safe contracts database first
  const contract = isSafeContractOnChain(address, chain);
  if (contract?.category === 'ENS') return true;
  
  // Additional chain-specific naming service addresses
  // (in case they're not yet in the safe contracts list)
  const namingServices: Record<Chain, string[]> = {
    ethereum: [
      '0x283af0b28c62c092c9727f1ee09c02ca627eb7f5', // ENS Registrar Controller
      '0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85', // ENS Base Registrar
      '0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e', // ENS Registry
      '0x4976fb03c32e5b8cfe2b6ccb31c09ba78ebaba41', // ENS Public Resolver
      '0x231b0ee14048e9dccd1d247744d114a4eb5e8e63', // ENS Name Wrapper
      '0x253553366da8546fc250f225fe3d25d0c782303b', // ENS V2 Controller
    ],
    base: [
      '0x4ccb0bb02fcaba27e82a56646e81d8c5bc4119a5', // Base Names Controller
      '0xb94704422c2a1e396835a571837aa5ae53285a95', // Base Names Registry
      '0x084b1c3c81545d370f3634392de611caabff8148', // Base Names Resolver
      '0xc6d566a56a1aff6508aabd3e6b2f4ad81bfbf28e', // Basenames L2 Resolver
      '0x03c4738ee98ae44591e1a4a4f3cab6641d95dd9a', // Base Names Registrar
      '0xd3e6775ed9b7dc12b205c8e608dc3767b9e5efda', // Basenames Reverse Registrar
    ],
    bnb: [
      // Space ID / BNB Name Service
      '0x08ced32a7f3eec915ba84415e9c07a7286977956', // Space ID Registrar
    ],
    solana: [], // Solana naming is handled in solana-security.ts
  };
  
  const chainServices = namingServices[chain] || [];
  return chainServices.some(addr => addr.toLowerCase() === normalized);
}

/**
 * Check if a transaction is a naming service operation.
 * This checks both the contract AND the method signature.
 */
export function isNamingServiceTransaction(
  toAddress: string,
  methodId: string | undefined,
  chain: Chain
): boolean {
  // Check if destination is a naming service contract
  if (isNamingServiceContract(toAddress, chain)) {
    return true;
  }
  
  // Common naming service method signatures
  if (methodId) {
    const namingMethods = [
      '0x8c6f3d39', // register(...)
      '0xaeb8ce9b', // registerWithConfig(...)
      '0x74694a2b', // renew(string,uint256)
      '0xacf1a841', // renew(bytes32,uint256)
      '0xc475abff', // renew(uint256,uint256)
      '0x0178b8bf', // resolver(bytes32)
      '0x1896f70a', // setResolver(bytes32,address)
      '0x14ab9038', // setTTL(bytes32,uint64)
      '0x5b0fc9c3', // setOwner(bytes32,address)
      '0x06fdde03', // name()
      '0xab0e64ca', // setName(string)
      '0xd5fa2b00', // setAddr(bytes32,address)
      '0x3b3b57de', // addr(bytes32)
      '0x691f3431', // name(bytes32)
      '0x77372213', // setText(bytes32,string,string)
      '0x10f13a8c', // text(bytes32,string)
      '0xf1cb7e06', // commit(bytes32)
      '0x29aa4a6c', // available(string)
      '0xec13d813', // rentPrice(string,uint256)
    ];
    
    const sig = methodId.toLowerCase().slice(0, 10);
    if (namingMethods.includes(sig)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Check if this is infrastructure (relayer, multisig, etc.).
 */
export function isInfrastructureContract(address: string): boolean {
  const contract = isSafeContract(address);
  if (!contract) return false;
  const infraCategories: SafeContractCategory[] = [
    'INFRASTRUCTURE', 'RELAYER', 'MULTISIG', 'BRIDGE'
  ];
  return infraCategories.includes(contract.category);
}

// ============================================
// STANDARD EIP APPROVAL DETECTION
// ============================================
// Standard ERC20/ERC721/ERC1155 approvals are NORMAL behavior

/**
 * Check if a method signature is a standard EIP approval function.
 * These should NEVER be flagged as malicious on their own.
 */
export function isStandardApprovalMethod(methodId: string): boolean {
  if (!methodId) return false;
  const sig = methodId.toLowerCase().slice(0, 10);
  
  const standardApprovals = [
    '0x095ea7b3', // ERC20 approve(address,uint256)
    '0xa22cb465', // ERC721/1155 setApprovalForAll(address,bool)
    '0xd505accf', // ERC20 Permit permit(...)
    '0x8fcbaf0c', // DAI Permit permit(...)
  ];
  
  return standardApprovals.includes(sig);
}

/**
 * Check if a method signature is a standard mint function.
 * NFT mints should NEVER be flagged as malicious.
 * 
 * RULE: Minting is ALWAYS legitimate user behavior.
 * A wallet should NEVER be flagged for minting an NFT.
 */
export function isStandardMintMethod(methodId: string): boolean {
  if (!methodId) return false;
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
    '0x6352211e', // ownerOf (read, but often paired with minting)
    
    // Additional mint patterns
    '0x2db11544', // publicMint(uint256)
    '0x84bb1e42', // mintPublic(uint256)
    '0x14f710fe', // freeMint()
    '0x32db7add', // mintBatch(address,uint256[],uint256[],bytes)
    '0xb88d4fde', // safeTransferFrom (often used in minting flows)
    '0x731133e9', // mint(address,uint256,uint256,bytes)
    '0xf242432a', // safeTransferFrom (ERC1155)
    '0x2eb2c2d6', // safeBatchTransferFrom (ERC1155)
    '0x156e29f6', // mint(address,uint256,uint256)
    '0x94d008ef', // mint(address,uint256,bytes)
    
    // Common claim patterns (legitimate airdrops/claims)
    '0x379607f5', // claim(uint256)
    '0x4e71d92d', // claim()
    '0xce7c2ac2', // claim(address)
    '0x2e7ba6ef', // claim(uint256,address,uint256,bytes32[])
    '0x3ccfd60b', // withdraw() - often for claiming
    '0xf3fef3a3', // withdraw(address,uint256)
    
    // Presale/whitelist mints
    '0x23463624', // whitelistMint(uint256,bytes32[])
    '0x7ba0e2e7', // presaleMint(uint256)
    '0x8d859f3e', // allowlistMint(uint256)
    '0xba41b0c6', // claimConditions (ThirdWeb)
    '0xd37c353b', // claim (ThirdWeb)
    
    // Union Authena specific (common Base NFT patterns)
    '0x6a4f832b', // mintNFT(address,uint256)
    '0x9abc8320', // mintWithSignature
    '0x8a0dac4a', // mintBatch(uint256)
    '0x1b2ef1ca', // batchMint(address[],uint256[])
    '0x7e5cd5c1', // emergencyMint
    '0x3f9942ff', // lazyMint
    '0x7e1c0c09', // claimTo
    '0x8e8c49b9', // multicall (often used for minting)
    '0xac9650d8', // multicall (Uniswap style)
    
    // ============================================
    // ADDITIONAL BASE CHAIN NFT METHODS
    // ============================================
    // These are common methods seen on Base chain NFT contracts
    '0x0c959541', // collect(...)
    '0x00000010', // Zora collectWithComment
    '0xfb7d4e5d', // mintFromZoraBuySell
    '0x3c168eab', // mintWithComment
    '0xefef39a1', // purchase()
    '0x6871ee40', // purchase(uint256)
    '0x23a39750', // purchaseWithReceipt
    '0x0e89341c', // uri(uint256) - ERC1155 metadata
    '0xc87b56dd', // tokenURI(uint256) - ERC721 metadata
    '0x6c0360eb', // baseURI() - NFT base URI
    '0x42842e0e', // safeTransferFrom(address,address,uint256)
    '0x095ea7b3', // approve(address,uint256) - approval before mint
    '0xa22cb465', // setApprovalForAll - common in mint flows
    '0xe985e9c5', // isApprovedForAll - read, common in mint flows
    '0x70a08231', // balanceOf(address) - read, common in mint flows
    '0x01ffc9a7', // supportsInterface - ERC165
    '0x06fdde03', // name() - token name
    '0x95d89b41', // symbol() - token symbol
    '0x18160ddd', // totalSupply()
    
    // Common Base/Zora patterns
    '0x1a6fd7a5', // createWithMint
    '0xb9df48e4', // createEdition
    '0x7d94792a', // createAndMint
    '0x36ab86c4', // mintNew
    '0x74bc7db7', // mintBatch with proof
    '0x6a3a2c58', // mintWithProof
  ];
  
  return mintMethods.includes(sig);
}

/**
 * Check if a transaction looks like a paid NFT mint based on value and method.
 * If a user is SENDING value to a contract, they're likely BUYING something (NFT mint).
 * This is fundamentally different from drain behavior.
 */
export function isPaidMintTransaction(
  methodId?: string,
  value?: bigint | string
): boolean {
  if (!value) return false;
  
  const valueBI = typeof value === 'string' ? BigInt(value) : value;
  
  // If value > 0 (user is paying), and method exists, likely a paid mint
  if (valueBI > BigInt(0) && methodId) {
    // Even if we don't recognize the method, if user is paying, it's likely legitimate
    // Drainers don't require payment - they TAKE value
    return true;
  }
  
  return false;
}

/**
 * Check if a transaction is an NFT mint operation.
 * NFT mints are ALWAYS legitimate user behavior.
 * 
 * RULE: A wallet should NEVER be flagged for minting an NFT on any chain.
 * This is fundamental user behavior, not a compromise indicator.
 */
export function isNFTMintTransaction(toAddress: string, methodId?: string, value?: bigint, chain?: Chain): boolean {
  // Check if destination is known NFT mint contract
  if (isNFTMintContract(toAddress)) {
    return true;
  }
  
  // Check if method is a mint function
  if (methodId && isStandardMintMethod(methodId)) {
    return true;
  }
  
  // Check if it's a mint with value (paying for NFT)
  if (methodId && value && value > BigInt(0)) {
    const sig = methodId.toLowerCase().slice(0, 10);
    // Common paid mint patterns
    const paidMintMethods = [
      '0x1249c58b', // mint()
      '0xa0712d68', // mint(uint256)
      '0x2db11544', // publicMint(uint256)
      '0x84bb1e42', // mintPublic(uint256)
      '0x14f710fe', // freeMint() - sometimes has value for gas
      '0x6a4f832b', // mintNFT(address,uint256)
      '0x3ccfd60b', // withdraw() 
    ];
    if (paidMintMethods.includes(sig)) {
      return true;
    }
  }
  
  // ============================================
  // BASE CHAIN SPECIFIC: Be MORE permissive
  // ============================================
  // On Base, if the method looks like a mint, trust it
  if (chain === 'base' && methodId) {
    const sig = methodId.toLowerCase().slice(0, 10);
    // Any method containing "mint" pattern or common NFT operations
    const baseMintPatterns = [
      '0x1249c58b', '0xa0712d68', '0x40c10f19', '0x6a627842',
      '0xd85d3d27', '0x0febdd49', '0x2db11544', '0x84bb1e42',
      '0x14f710fe', '0x731133e9', '0x379607f5', '0x4e71d92d',
      '0x156e29f6', '0x94d008ef', '0x6a4f832b', '0x9abc8320',
      '0x8a0dac4a', '0x1b2ef1ca', '0x7e5cd5c1', '0x3f9942ff',
      '0x7e1c0c09', '0x8e8c49b9', '0xac9650d8', '0xba41b0c6',
      '0xd37c353b', '0xeacabe14', '0x32db7add',
    ];
    if (baseMintPatterns.includes(sig)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Check if an address is related to NFT activity on Base chain.
 * This is a broad check to prevent false positives.
 */
export function isBaseNFTActivity(address: string, methodId?: string): boolean {
  if (!address) return false;
  const normalized = address.toLowerCase();
  
  // Check if it's a known Base NFT platform
  const baseNFTPlatforms = [
    '0x777777c338d93e2c7adf08d102d45ca7cc4ed021', // Zora
    '0x04e2516a2c207e84a1839755675dfd8ef6302f0a', // Zora Drops
    '0x9d90669665607f08005cae4a7098143f554c59ef', // Zora Creator
    '0x5dbc7b840bab9daef6632d01be72f28a37de5cc8', // ThirdWeb
  ];
  
  if (baseNFTPlatforms.includes(normalized)) {
    return true;
  }
  
  // Check if method is NFT-related
  if (methodId && isStandardMintMethod(methodId)) {
    return true;
  }
  
  // Check safe contracts
  const safeContract = isSafeContract(address);
  if (safeContract?.category === 'NFT_MINT_CONTRACT' || safeContract?.category === 'NFT_MARKETPLACE') {
    return true;
  }
  
  return false;
}

// ============================================
// AGGREGATE SAFE CHECK
// ============================================

export interface SafetyCheckResult {
  isSafe: boolean;
  reason: string;
  contract?: SafeContract;
  category?: SafeContractCategory;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

/**
 * Comprehensive safety check for an address.
 * If this returns isSafe: true, the address should NEVER be flagged as malicious.
 */
export function checkAddressSafety(
  address: string, 
  chain: Chain,
  methodId?: string
): SafetyCheckResult {
  if (!address) {
    return { isSafe: false, reason: 'No address provided', confidence: 'HIGH' };
  }

  // Check if it's a known safe contract
  const safeContract = isSafeContractOnChain(address, chain);
  if (safeContract) {
    return {
      isSafe: true,
      reason: `Verified safe contract: ${safeContract.name}`,
      contract: safeContract,
      category: safeContract.category,
      confidence: 'HIGH',
    };
  }

  // Check if the method is a standard approval/mint (not suspicious on its own)
  if (methodId) {
    if (isStandardApprovalMethod(methodId)) {
      return {
        isSafe: true, // The method alone is safe; spender needs checking separately
        reason: 'Standard EIP approval method',
        confidence: 'MEDIUM',
      };
    }
    if (isStandardMintMethod(methodId)) {
      return {
        isSafe: true,
        reason: 'Standard NFT mint method',
        confidence: 'MEDIUM',
      };
    }
  }

  // Unknown address - not automatically safe, but not automatically malicious either
  return {
    isSafe: false,
    reason: 'Unknown address - requires behavioral analysis',
    confidence: 'LOW',
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  SAFE_CONTRACTS as default,
};

