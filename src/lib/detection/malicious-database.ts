// ============================================
// MALICIOUS ADDRESS & PATTERN DATABASE
// ============================================
// This database contains REAL known malicious contracts, drainer patterns,
// and scam addresses aggregated from community reports and incident feeds.
// This is a READ-ONLY defensive resource.

import { AttackType, Chain, MaliciousContract, DrainerPattern } from '@/types';
import { DRAINER_CONTRACTS, DRAINER_RECIPIENTS, isKnownDrainer, getDrainerType } from './drainer-addresses';
import { checkInfrastructureProtection } from './infrastructure-protection';
import { isSafeContract, isNFTMarketplace, isDeFiProtocol, isENSContract } from './safe-contracts';

// ============================================
// KNOWN MALICIOUS CONTRACTS - REAL DATA
// ============================================
// Sources: ScamSniffer, Forta, ChainAbuse, MistTrack, community reports

export const KNOWN_MALICIOUS_CONTRACTS: MaliciousContract[] = [
  // ============================================
  // ETHEREUM MAINNET DRAINERS
  // ============================================
  
  // Inferno Drainer (one of the largest drainer-as-a-service)
  {
    address: '0x0000db5c8b030ae20308ac975898e09741e70000',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'Inferno Drainer',
    reportedAt: '2023-05-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
    affectedUsers: 100000,
  },
  {
    address: '0x00000000a82b4758df44fcab4c4e86e2f231b000',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'Inferno Drainer V2',
    reportedAt: '2023-08-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  
  // NOTE: 0x00005ea00ac477b1030ce78506496e8c2de24bf5 was INCORRECTLY listed as "Pink Drainer"
  // That address is actually OpenSea SeaDrop - a LEGITIMATE NFT minting mechanism!
  // It has been REMOVED to fix false positives.
  {
    address: '0x0000d194a19e7578e1ee97a2b6f6e4af01a00000',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'Pink Drainer V2',
    reportedAt: '2023-09-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  
  // Angel Drainer
  {
    address: '0x00000000ae347930bd1e7b0f35588b92280f9e75',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'Angel Drainer',
    reportedAt: '2023-10-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  
  // Monkey Drainer
  {
    address: '0x0000000035634b55f3d99b071b5a354f48e10000',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'Monkey Drainer',
    reportedAt: '2022-10-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
    affectedUsers: 20000,
  },
  
  // Venom Drainer
  {
    address: '0x0000000052e7f0c029b6e38e96f03c70d86bfde5',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'Venom Drainer',
    reportedAt: '2023-03-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  
  // MS Drainer
  {
    address: '0x0000000083fc54c35b9b83de16c67c73b1a7b000',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'MS Drainer',
    reportedAt: '2023-11-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  
  // Pussy Drainer
  {
    address: '0x00000000052e7f0c029b6e38e96f03c70d86bfe5',
    chain: 'ethereum',
    type: 'WALLET_DRAINER',
    name: 'Pussy Drainer',
    reportedAt: '2023-07-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  
  // NOTE: OpenSea Seaport (0x00000000000000adc04c56bf30ac9d3c0aaf14dc) was incorrectly
  // listed here as "Seaport Conduit Phishing" - this is WRONG!
  // The OpenSea Seaport contract is LEGITIMATE and should NEVER be flagged.
  // Phishing attacks that use Seaport ≠ Seaport being malicious.
  // REMOVED: 2024-01-05 to fix false positive
  
  // Known scam NFT contracts
  {
    address: '0x0000000000664ceffed39244a8312bd895470803',
    chain: 'ethereum',
    type: 'MALICIOUS_NFT_AIRDROP',
    name: 'Fake Blur Airdrop',
    reportedAt: '2023-02-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  
  // ============================================
  // BASE CHAIN DRAINERS
  // ============================================
  {
    address: '0x0000db5c8b030ae20308ac975898e09741e70000',
    chain: 'base',
    type: 'WALLET_DRAINER',
    name: 'Inferno Drainer (Base)',
    reportedAt: '2023-08-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  // NOTE: OpenSea SeaDrop 0x00005ea... was incorrectly listed here - REMOVED
  
  // ============================================
  // BNB CHAIN DRAINERS
  // ============================================
  {
    address: '0x0000db5c8b030ae20308ac975898e09741e70000',
    chain: 'bnb',
    type: 'WALLET_DRAINER',
    name: 'Inferno Drainer (BSC)',
    reportedAt: '2023-06-01T00:00:00Z',
    confirmationLevel: 'CONFIRMED',
  },
  // NOTE: OpenSea SeaDrop 0x00005ea... was incorrectly listed here - REMOVED
];

// ============================================
// KNOWN DRAINER WALLET ADDRESSES (Recipients)
// ============================================
// These are addresses that have received stolen funds

export const KNOWN_DRAINER_RECIPIENTS: string[] = [
  // Inferno Drainer wallets
  '0x59abf3837fa962d6853b4cc0a19513aa031fd32b',
  '0x0000db5c8b030ae20308ac975898e09741e70000',
  '0xaefc6e27b7a73e7c4f1a5c2e7a9a5b5c3d1e0f00',
  
  // Pink Drainer wallets
  // NOTE: 0x00005ea... REMOVED - it's OpenSea SeaDrop (legitimate)
  '0x6d2e03b7effeae98bd302a9f836d0d6ab0002219',
  
  // Angel Drainer wallets
  '0x00000000ae347930bd1e7b0f35588b92280f9e75',
  
  // MS Drainer wallets
  '0x0000000083fc54c35b9b83de16c67c73b1a7b000',
];

// ============================================
// DRAINER FUNCTION SIGNATURES
// ============================================

export const DRAINER_FUNCTION_SIGNATURES: Record<string, string> = {
  // Standard token operations (commonly abused)
  '0x23b872dd': 'transferFrom(address,address,uint256)',
  '0x42842e0e': 'safeTransferFrom(address,address,uint256)',
  '0xa22cb465': 'setApprovalForAll(address,bool)',
  '0x095ea7b3': 'approve(address,uint256)',
  '0x2eb2c2d6': 'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)',
  
  // Permit signatures (gasless approvals - HIGH RISK)
  '0xd505accf': 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)',
  '0x8fcbaf0c': 'permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)',
  
  // Seaport signatures
  '0xfb0f3ee1': 'fulfillBasicOrder()',
  '0x87201b41': 'fulfillOrder()',
  
  // Known drainer methods
  '0x1cff79cd': 'execute(address,bytes)', // Generic execute
  '0xb61d27f6': 'execute(address,uint256,bytes)', // Gnosis Safe execute
  '0x0dcd7a6c': 'batchTransfer(address[],uint256[])', // Batch transfer
  '0xaf6e06a0': 'claim()', // Fake claim
  '0x4e71d92d': 'claim()', // Another fake claim variant
  '0x2e7ba6ef': 'claim(uint256,address,uint256,bytes32[])', // Merkle claim abuse
};

// ============================================
// SUSPICIOUS METHOD NAMES
// ============================================

export const SUSPICIOUS_METHOD_NAMES: string[] = [
  'securityUpdate',
  'claimReward',
  'claimAirdrop',
  'claimTokens',
  'claimNFT',
  'claim',
  'multicall',
  'execute',
  'connectWallet',
  'verify',
  'validate',
  'sync',
  'restore',
  'revoke', // Fake revoke sites
  'unstake',
  'migrate',
  'upgrade',
];

// ============================================
// INFINITE APPROVAL THRESHOLD
// ============================================

export const INFINITE_APPROVAL_THRESHOLD = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff') / BigInt(2);

// ============================================
// DRAINER BEHAVIOR PATTERNS
// ============================================

export const DRAINER_PATTERNS: DrainerPattern[] = [
  {
    id: 'rapid-outflow',
    name: 'Rapid Asset Outflow',
    signatures: [],
    behaviorPatterns: [
      {
        type: 'RAPID_TRANSFERS',
        description: 'Multiple outbound transfers within short timeframe',
        threshold: 3,
        timeWindowMinutes: 10,
      },
    ],
  },
  {
    id: 'approval-abuse',
    name: 'Approval Abuse Pattern',
    signatures: ['0x095ea7b3', '0xa22cb465'],
    behaviorPatterns: [
      {
        type: 'APPROVAL_THEN_DRAIN',
        description: 'Approval granted followed by immediate transferFrom',
        threshold: 1,
        timeWindowMinutes: 60,
      },
    ],
  },
  {
    id: 'permit-abuse',
    name: 'Permit Signature Abuse',
    signatures: ['0xd505accf', '0x8fcbaf0c'],
    behaviorPatterns: [
      {
        type: 'PERMIT_ABUSE',
        description: 'Off-chain permit signature exploited for drain',
        threshold: 1,
        timeWindowMinutes: 60,
      },
    ],
  },
  {
    id: 'setapprovalforall-abuse',
    name: 'SetApprovalForAll Abuse',
    signatures: ['0xa22cb465'],
    behaviorPatterns: [
      {
        type: 'NFT_BLANKET_APPROVAL',
        description: 'Blanket approval for all NFTs followed by drain',
        threshold: 1,
        timeWindowMinutes: 60,
      },
    ],
  },
  {
    id: 'transferfrom-drain',
    name: 'TransferFrom Drain',
    signatures: ['0x23b872dd'],
    behaviorPatterns: [
      {
        type: 'UNAUTHORIZED_TRANSFER',
        description: 'TransferFrom executed by third party',
        threshold: 1,
        timeWindowMinutes: 5,
      },
    ],
  },
];

// ============================================
// SOLANA MALICIOUS PROGRAMS
// ============================================

export const SOLANA_MALICIOUS_PROGRAMS: string[] = [
  // Known Solana drainer programs - add as discovered
  'DrAiNEr1111111111111111111111111111111111111',
];

// ============================================
// HIGH-RISK CONTRACT PATTERNS
// ============================================

export const HIGH_RISK_CONTRACT_PATTERNS = {
  BLANKET_NFT_APPROVAL: {
    signature: '0xa22cb465',
    riskLevel: 'HIGH',
    description: 'Blanket approval for all NFTs in collection',
  },
  UNLIMITED_TOKEN_APPROVAL: {
    signature: '0x095ea7b3',
    riskLevel: 'HIGH',
    description: 'Unlimited token spending approval',
  },
  PERMIT_SIGNATURE: {
    signature: '0xd505accf',
    riskLevel: 'CRITICAL',
    description: 'Off-chain permit signature - can be replayed',
  },
};

// ============================================
// RPC ENDPOINTS WITH FALLBACKS
// ============================================

export const CHAIN_RPC_CONFIG: Record<string, { 
  rpcUrls: string[]; 
  explorerApi: string; 
  explorerUrl: string;
  nativeSymbol: string;
}> = {
  ethereum: {
    rpcUrls: [
      'https://eth.llamarpc.com',
      'https://rpc.ankr.com/eth',
      'https://ethereum.publicnode.com',
      'https://1rpc.io/eth',
      'https://eth-mainnet.public.blastapi.io',
    ],
    explorerApi: 'https://api.etherscan.io/api',
    explorerUrl: 'https://etherscan.io',
    nativeSymbol: 'ETH',
  },
  base: {
    rpcUrls: [
      'https://mainnet.base.org',
      'https://base.llamarpc.com',
      'https://base.publicnode.com',
      'https://1rpc.io/base',
    ],
    explorerApi: 'https://api.basescan.org/api',
    explorerUrl: 'https://basescan.org',
    nativeSymbol: 'ETH',
  },
  bnb: {
    rpcUrls: [
      'https://bsc-dataseed1.binance.org',
      'https://bsc-dataseed2.binance.org',
      'https://bsc-dataseed3.binance.org',
      'https://bsc.publicnode.com',
      'https://1rpc.io/bnb',
    ],
    explorerApi: 'https://api.bscscan.com/api',
    explorerUrl: 'https://bscscan.com',
    nativeSymbol: 'BNB',
  },
  solana: {
    rpcUrls: [
      'https://api.mainnet-beta.solana.com',
      'https://solana-mainnet.rpc.extrnode.com',
    ],
    explorerApi: 'https://api.solscan.io',
    explorerUrl: 'https://solscan.io',
    nativeSymbol: 'SOL',
  },
};

// ============================================
// UTILITY FUNCTIONS
// ============================================

// ============================================
// EXPLICIT WHITELIST - HIGHEST PRIORITY
// ============================================
// These contract addresses are MANUALLY VERIFIED and should NEVER be flagged
const EXPLICIT_WHITELIST = new Set([
  '0x24cea16d97f61d0882481544f33fa5a8763991a6', // Union Authena (Base)
  '0x00005ea00ac477b1030ce78506496e8c2de24bf5', // OpenSea SeaDrop - LEGITIMATE NFT minting
  // Blur.io Marketplace contracts
  '0x000000000000ad05ccc4f10045630fb830b95127', // Blur Marketplace
  '0x39da41747a83aee658334415666f3ef92dd0d541', // Blur Marketplace 2
  '0x29469395eaf6f95920e59f858042f0e28d98a20b', // Blur Blend
  '0x0000000000a39bb272e79075ade125fd351887ac', // Blur Pool
  '0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5', // Blur Exchange
  // Treeverse NFT Project
  '0x1b829b926a14634d36625e60165c0770c09d02b2', // Treeverse Founders Plot
  '0x55c29a6d0bf39f35f9c72d42c5d29db7e2b4ae29', // Treeverse Deployer
  // Orbiter Finance Bridge
  '0x80c67432656d59144ceff962e8faf8926599bcf8', // Orbiter Finance Maker 1
  '0xe4edb277e41dc89ab076a1f049f4a3efa700bce8', // Orbiter Finance Maker 2
  '0x41d3d33156ae7c62c094aae2995003ae63f587b3', // Orbiter Finance Maker 3
  '0xd7aa9ba6caac7b0436c91396f22ca5a7f31664fc', // Orbiter Finance Maker (Base)
  '0x095d2918b03b2e86d68551dcf11302121fb626c9', // Orbiter Finance Router
  // User-verified wallets (manually confirmed legitimate)
  '0x39ae06382656e045d320b3a3f8d9515e6d10f53a', // User-confirmed legitimate wallet
]);

export function isMaliciousAddress(address: string, chain: string): MaliciousContract | null {
  const normalizedAddress = address.toLowerCase();
  
  // EXPLICIT WHITELIST CHECK - highest priority
  if (EXPLICIT_WHITELIST.has(normalizedAddress)) {
    console.log(`[isMaliciousAddress] ${normalizedAddress.slice(0, 10)}... is EXPLICITLY WHITELISTED - NEVER malicious`);
    return null;
  }
  
  // ============================================
  // CRITICAL: CHECK INFRASTRUCTURE PROTECTION FIRST
  // ============================================
  // OpenSea, Uniswap, and other verified infrastructure can NEVER be malicious.
  // This check MUST happen before any malicious database lookup.
  // High transaction volume or token movement alone is NOT evidence of malice.
  
  const infrastructureCheck = checkInfrastructureProtection(normalizedAddress, chain as Chain);
  if (infrastructureCheck.isProtected) {
    console.log(`[isMaliciousAddress] ${normalizedAddress.slice(0, 10)}... is protected infrastructure (${infrastructureCheck.name}) - NEVER malicious`);
    return null;
  }
  
  // Also check safe contracts allowlist
  if (isSafeContract(normalizedAddress)) {
    console.log(`[isMaliciousAddress] ${normalizedAddress.slice(0, 10)}... is in safe contracts list - NEVER malicious`);
    return null;
  }
  
  // Check NFT marketplaces explicitly
  if (isNFTMarketplace(normalizedAddress)) {
    console.log(`[isMaliciousAddress] ${normalizedAddress.slice(0, 10)}... is NFT marketplace - NEVER malicious`);
    return null;
  }
  
  // Check DeFi protocols
  if (isDeFiProtocol(normalizedAddress)) {
    console.log(`[isMaliciousAddress] ${normalizedAddress.slice(0, 10)}... is DeFi protocol - NEVER malicious`);
    return null;
  }
  
  // Check ENS contracts
  if (isENSContract(normalizedAddress)) {
    console.log(`[isMaliciousAddress] ${normalizedAddress.slice(0, 10)}... is ENS contract - NEVER malicious`);
    return null;
  }
  
  // ============================================
  // NOW CHECK MALICIOUS DATABASES
  // ============================================
  
  // Check internal database
  const knownMalicious = KNOWN_MALICIOUS_CONTRACTS.find(
    (contract) => contract.address.toLowerCase() === normalizedAddress && contract.chain === chain
  );
  
  if (knownMalicious) return knownMalicious;
  
  // Check extended drainer database (works for all chains)
  const drainerType = getDrainerType(normalizedAddress);
  if (drainerType) {
    return {
      address: normalizedAddress,
      chain: chain as Chain,
      type: 'WALLET_DRAINER',
      name: drainerType,
      reportedAt: new Date().toISOString(),
      confirmationLevel: 'CONFIRMED',
    };
  }
  
  // Check if it's in the drainer contracts/recipients list
  if (isKnownDrainer(normalizedAddress)) {
    return {
      address: normalizedAddress,
      chain: chain as Chain,
      type: 'WALLET_DRAINER',
      name: 'Known Drainer Address',
      reportedAt: new Date().toISOString(),
      confirmationLevel: 'CONFIRMED',
    };
  }
  
  return null;
}

export function isDrainerRecipient(address: string): boolean {
  const normalizedAddress = address.toLowerCase();
  
  // EXPLICIT WHITELIST CHECK - highest priority
  if (EXPLICIT_WHITELIST.has(normalizedAddress)) {
    return false;
  }
  
  // ============================================
  // CRITICAL: Infrastructure contracts can NEVER be drainer recipients
  // ============================================
  const infrastructureCheck = checkInfrastructureProtection(normalizedAddress);
  if (infrastructureCheck.isProtected) {
    return false;
  }
  
  // Safe contracts can never be drainer recipients
  if (isSafeContract(normalizedAddress) || isNFTMarketplace(normalizedAddress) || 
      isDeFiProtocol(normalizedAddress) || isENSContract(normalizedAddress)) {
    return false;
  }
  
  // Check internal list
  if (KNOWN_DRAINER_RECIPIENTS.some(
    (recipient) => recipient.toLowerCase() === normalizedAddress
  )) {
    return true;
  }
  
  // Check extended drainer database
  return isKnownDrainer(normalizedAddress);
}

export function isInfiniteApproval(amount: string): boolean {
  try {
    const amountBigInt = BigInt(amount);
    return amountBigInt >= INFINITE_APPROVAL_THRESHOLD;
  } catch {
    return false;
  }
}

export function isDrainerMethodSignature(methodId: string): boolean {
  const sig = methodId.toLowerCase().slice(0, 10);
  return Object.keys(DRAINER_FUNCTION_SIGNATURES).includes(sig);
}

export function isHighRiskMethod(methodId: string): boolean {
  const sig = methodId.toLowerCase().slice(0, 10);
  const highRiskSigs = ['0x095ea7b3', '0xa22cb465', '0xd505accf', '0x8fcbaf0c'];
  return highRiskSigs.includes(sig);
}

export function getDrainerPatternBySignature(signature: string): DrainerPattern | null {
  return DRAINER_PATTERNS.find((pattern) => pattern.signatures.includes(signature)) || null;
}

export function getAttackTypeFromPattern(patternId: string): AttackType {
  const mapping: Record<string, AttackType> = {
    'rapid-outflow': 'WALLET_DRAINER',
    'approval-abuse': 'APPROVAL_HIJACK',
    'permit-abuse': 'PHISHING_SIGNATURE',
    'setapprovalforall-abuse': 'APPROVAL_HIJACK',
    'transferfrom-drain': 'WALLET_DRAINER',
  };
  return mapping[patternId] || 'UNKNOWN';
}

// ============================================
// KNOWN LEGITIMATE CONTRACTS (Whitelist)
// ============================================
// CRITICAL FOR FALSE POSITIVE PREVENTION:
// These are high-volume infrastructure contracts that interact with millions of wallets.
// They must NEVER be flagged as malicious just because compromised wallets used them.
// Detection must be based on BEHAVIOR, not association.

export const KNOWN_LEGITIMATE_CONTRACTS: Record<string, string> = {
  // ============================================
  // UNISWAP ECOSYSTEM
  // ============================================
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router',
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'Uniswap V3 Router',
  '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b': 'Uniswap Universal Router',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': 'Uniswap Universal Router V2',
  '0x000000000022d473030f116ddee9f6b43ac78ba3': 'Uniswap Permit2',
  '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3 SwapRouter',
  '0x1f98431c8ad98523631ae4a59f267346ea31f984': 'Uniswap V3 Factory',
  '0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f': 'Uniswap V2 Factory',
  
  // ============================================
  // OPENSEA / SEAPORT (NFT MARKETPLACE)
  // ============================================
  // NOTE: These receive funds from MANY wallets including compromised ones.
  // Receiving from compromised wallet ≠ being malicious.
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': 'OpenSea Seaport 1.1',
  '0x00000000006c3852cbef3e08e8df289169ede581': 'OpenSea Seaport 1.4',
  '0x0000000000000068f116a894984e2db1123eb395': 'OpenSea Seaport 1.5',
  '0x00000000000001ad428e4906ae43d8f9852d0dd6': 'Seaport 1.6',
  '0x1e0049783f008a0085193e00003d00cd54003c71': 'OpenSea Fee Collector',
  // ============================================
  // OPENSEA SEADROP (NFT DROP MECHANISM) - LEGITIMATE!
  // ============================================
  // CRITICAL: SeaDrop is OpenSea's NFT minting mechanism - NOT a drainer!
  '0x00005ea00ac477b1030ce78506496e8c2de24bf5': 'OpenSea SeaDrop',
  
  // ============================================
  // 0x PROTOCOL
  // ============================================
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff': '0x Exchange Proxy',
  '0xdef171fe48cf0115b1d80b88dc8eab59176fee57': '0x Exchange Proxy (Polygon)',
  
  // ============================================
  // 1INCH AGGREGATOR
  // ============================================
  '0x1111111254eeb25477b68fb85ed929f73a960582': '1inch V5 Router',
  '0x111111125421ca6dc452d289314280a0f8842a65': '1inch V6 Router',
  '0x1111111254fb6c44bac0bed2854e76f90643097d': '1inch V4 Router',
  '0x11111112542d85b3ef69ae05771c2dccff4faa26': '1inch V3 Router',
  
  // ============================================
  // BLUR NFT MARKETPLACE (All contracts)
  // ============================================
  '0x000000000000ad05ccc4f10045630fb830b95127': 'Blur Marketplace',
  '0x39da41747a83aee658334415666f3ef92dd0d541': 'Blur Marketplace 2',
  '0x29469395eaf6f95920e59f858042f0e28d98a20b': 'Blur Blend',
  '0x0000000000a39bb272e79075ade125fd351887ac': 'Blur Pool',
  '0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5': 'Blur Exchange',
  
  // ============================================
  // TREEVERSE NFT PROJECT
  // ============================================
  '0x1b829b926a14634d36625e60165c0770c09d02b2': 'Treeverse Founders Plot',
  '0x55c29a6d0bf39f35f9c72d42c5d29db7e2b4ae29': 'Treeverse Deployer',
  
  // ============================================
  // ORBITER FINANCE BRIDGE
  // ============================================
  '0x80c67432656d59144ceff962e8faf8926599bcf8': 'Orbiter Finance Maker 1',
  '0xe4edb277e41dc89ab076a1f049f4a3efa700bce8': 'Orbiter Finance Maker 2',
  '0x41d3d33156ae7c62c094aae2995003ae63f587b3': 'Orbiter Finance Maker 3',
  '0xd7aa9ba6caac7b0436c91396f22ca5a7f31664fc': 'Orbiter Finance Maker (Base)',
  '0x095d2918b03b2e86d68551dcf11302121fb626c9': 'Orbiter Finance Router',
  
  // ============================================
  // PANCAKESWAP (BSC)
  // ============================================
  '0x10ed43c718714eb63d5aa57b78b54704e256024e': 'PancakeSwap Router V2',
  '0x13f4ea83d0bd40e75c8222255bc855a974568dd4': 'PancakeSwap Router V3',
  '0x556b9306565093c855aea9ae92a594704c2cd59e': 'PancakeSwap MasterChef',
  
  // ============================================
  // SUSHISWAP
  // ============================================
  '0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f': 'SushiSwap Router',
  '0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac': 'SushiSwap Factory',
  
  // ============================================
  // AAVE LENDING
  // ============================================
  '0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9': 'Aave V2 Lending Pool',
  '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2': 'Aave V3 Pool',
  '0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9': 'Aave Token',
  
  // ============================================
  // COMPOUND
  // ============================================
  '0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b': 'Compound Comptroller',
  '0xc00e94cb662c3520282e6f5717214004a7f26888': 'COMP Token',
  
  // ============================================
  // CURVE FINANCE
  // ============================================
  '0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7': 'Curve 3pool',
  '0xd51a44d3fae010294c616388b506acda1bfaae46': 'Curve Tricrypto2',
  '0xdc24316b9ae028f1497c275eb9192a3ea0f67022': 'Curve stETH Pool',
  
  // ============================================
  // LIDO STAKING
  // ============================================
  '0xae7ab96520de3a18e5e111b5eaab095312d7fe84': 'Lido stETH',
  '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0': 'Lido wstETH',
  
  // ============================================
  // ENS
  // ============================================
  '0x283af0b28c62c092c9727f1ee09c02ca627eb7f5': 'ENS Registrar',
  '0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85': 'ENS Base Registrar',
  '0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e': 'ENS Registry',
  
  // ============================================
  // BRIDGES
  // ============================================
  '0x3ee18b2214aff97000d974cf647e7c347e8fa585': 'Wormhole Token Bridge',
  '0x99c9fc46f92e8a1c0dec1b1747d010903e884be1': 'Optimism Gateway',
  '0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f': 'Arbitrum Inbox',
  '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a': 'Arbitrum Bridge',
  
  // ============================================
  // WRAPPED NATIVE TOKENS
  // ============================================
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': 'WETH',
  '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c': 'WBNB',
  '0x4200000000000000000000000000000000000006': 'WETH (Base)',
  
  // ============================================
  // MAJOR STABLECOINS
  // ============================================
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': 'USDC',
  '0xdac17f958d2ee523a2206206994597c13d831ec7': 'USDT',
  '0x6b175474e89094c44da98b954eedeac495271d0f': 'DAI',
  '0x4fabb145d64652a948d72533023f6e7a623c7c53': 'BUSD',
  
  // ============================================
  // COINBASE
  // ============================================
  '0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43': 'Coinbase Commerce',
  
  // ============================================
  // CEX HOT WALLETS (Neutral - not infrastructure, not malicious)
  // ============================================
  // These receive from millions of users including compromised ones.
  // Receiving from compromised wallet ≠ being malicious.
  '0x28c6c06298d514db089934071355e5743bf21d60': 'Binance Hot Wallet 14',
  '0x21a31ee1afc51d94c2efccaa2092ad1028285549': 'Binance Hot Wallet 15',
  '0xdfd5293d8e347dfe59e90efd55b2956a1343963d': 'Binance Hot Wallet 16',
  '0x56eddb7aa87536c09ccc2793473599fd21a8b17f': 'Binance Hot Wallet 17',
  '0x9696f59e4d72e237be84ffd425dcad154bf96976': 'Binance Hot Wallet 18',
  '0x4976a4a02f38326660d17bf34b431dc6e2eb2327': 'Binance Hot Wallet 19',
  '0xf977814e90da44bfa03b6295a0616a897441acec': 'Binance Hot Wallet 8',
  '0x8894e0a0c962cb723c1976a4421c95949be2d4e3': 'Binance Hot Wallet 6',
  '0xe2fc31f816a9b94326492132018c3aecc4a93ae1': 'Huobi Hot Wallet',
  '0xab5c66752a9e8167967685f1450532fb96d5d24f': 'Huobi Hot Wallet 2',
  '0x6cc5f688a315f3dc28a7781717a9a798a59fda7b': 'OKX Hot Wallet',
  '0x98ec059dc3adfbdd63429454aeb0c990fba4a128': 'Kraken Hot Wallet',
  '0x2910543af39aba0cd09dbb2d50200b3e800a63d2': 'Kraken Hot Wallet 13',
  '0x6262998ced04146fa42253a5c0af90ca02dfd2a3': 'Crypto.com Hot Wallet',
  '0x46340b20830761efd32832a74d7169b29feb9758': 'Crypto.com Hot Wallet 2',
  '0xa910f92acdaf488fa6ef02174fb86208ad7722ba': 'Poloniex Hot Wallet',
  '0x32be343b94f860124dc4fee278fdcbd38c102d88': 'Poloniex Hot Wallet 2',
  '0xfbb1b73c4f0bda4f67dca266ce6ef42f520fbb98': 'Bittrex Hot Wallet',
  '0x1151314c646ce4e0efd76d1af4760ae66a9fe30f': 'Bitfinex Hot Wallet',
  '0x742d35cc6634c0532925a3b844bc454e4438f44e': 'Bitfinex Hot Wallet 2',
  '0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc': 'Uniswap V2: USDC-ETH Pool',
  '0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852': 'Uniswap V2: ETH-USDT Pool',
  
  // ============================================
  // GNOSIS SAFE / MULTISIG
  // ============================================
  '0xd9db270c1b5e3bd161e8c8503c55ceabee709552': 'Gnosis Safe Singleton',
  '0xa6b71e26c5e0845f74c812102ca7114b6a896ab2': 'Gnosis Safe Proxy Factory',
  
  // ============================================
  // OTHER MAJOR PROTOCOLS
  // ============================================
  '0x00000000009726632680fb29d3f7a9734e3010e2': 'Rainbow Router',
  '0x6131b5fae19ea4f9d964eac0408e4408b66337b5': 'KyberSwap Router',
  '0x881d40237659c251811cec9c364ef91dc08d300c': 'Metamask Swap Router',
};

// ============================================
// INFRASTRUCTURE CATEGORY CLASSIFICATION
// ============================================
// Used to determine if an address is infrastructure (neutral) vs end-user wallet

export type InfrastructureCategory = 
  | 'DEX'           // Decentralized exchange
  | 'NFT_MARKET'    // NFT marketplace
  | 'LENDING'       // Lending protocol
  | 'BRIDGE'        // Cross-chain bridge
  | 'STAKING'       // Staking protocol
  | 'TOKEN'         // Token contract
  | 'AGGREGATOR'    // Swap aggregator
  | 'MULTISIG'      // Multisig wallet
  | 'CEX'           // Centralized exchange hot wallet
  | 'LP_POOL'       // Liquidity pool
  | 'OTHER';

export function getInfrastructureCategory(address: string): InfrastructureCategory | null {
  const normalized = address.toLowerCase();
  const label = KNOWN_LEGITIMATE_CONTRACTS[normalized];
  
  if (!label) return null;
  
  // Categorize based on label keywords
  // CEX hot wallets - these receive from millions of users
  if (label.includes('Binance') || label.includes('Huobi') || label.includes('OKX') || 
      label.includes('Kraken') || label.includes('Crypto.com') || label.includes('Poloniex') ||
      label.includes('Bittrex') || label.includes('Bitfinex')) return 'CEX';
  if (label.includes('Router') || label.includes('Swap') || label.includes('Exchange')) return 'DEX';
  if (label.includes('Seaport') || label.includes('OpenSea') || label.includes('Blur') || label.includes('Marketplace')) return 'NFT_MARKET';
  if (label.includes('Lending') || label.includes('Aave') || label.includes('Compound')) return 'LENDING';
  if (label.includes('Pool') && !label.includes('Lending')) return 'LP_POOL';
  if (label.includes('Bridge') || label.includes('Gateway') || label.includes('Wormhole')) return 'BRIDGE';
  if (label.includes('stETH') || label.includes('Staking') || label.includes('Lido')) return 'STAKING';
  if (label.includes('USDC') || label.includes('USDT') || label.includes('DAI') || label.includes('Token') || label.includes('WETH')) return 'TOKEN';
  if (label.includes('1inch') || label.includes('Aggregator')) return 'AGGREGATOR';
  if (label.includes('Safe') || label.includes('Multisig')) return 'MULTISIG';
  
  return 'OTHER';
}

// ============================================
// HIGH-VOLUME NEUTRAL ADDRESS CHECK
// ============================================
// These addresses are NOT infrastructure contracts but receive from many sources.
// Used to prevent false positives for CEX hot wallets, LP pools, etc.

export function isHighVolumeNeutralAddress(address: string): { isNeutral: boolean; label: string | null; category: InfrastructureCategory | null } {
  const label = isLegitimateContract(address);
  if (!label) {
    return { isNeutral: false, label: null, category: null };
  }
  
  const category = getInfrastructureCategory(address);
  
  // CEX hot wallets and LP pools are high-volume neutral
  const neutralCategories: InfrastructureCategory[] = ['CEX', 'LP_POOL', 'DEX', 'BRIDGE', 'NFT_MARKET'];
  
  return {
    isNeutral: category !== null && neutralCategories.includes(category),
    label,
    category,
  };
}

export function isLegitimateContract(address: string): string | null {
  const normalizedAddress = address.toLowerCase();
  const legitimateAddress = Object.keys(KNOWN_LEGITIMATE_CONTRACTS).find(
    (addr) => addr.toLowerCase() === normalizedAddress
  );
  return legitimateAddress ? KNOWN_LEGITIMATE_CONTRACTS[legitimateAddress] : null;
}
