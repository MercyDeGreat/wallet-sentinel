// ============================================
// COMPREHENSIVE DRAINER ADDRESS DATABASE
// ============================================
// This file contains VERIFIED malicious drainer contract addresses and recipient wallets.
// Only addresses that are CONFIRMED malicious should be in this list.
// Legitimate contracts (Uniswap, 0x, Blur, etc.) must NOT be included.

// Known drainer contract addresses (multi-chain) - VERIFIED MALICIOUS ONLY
export const DRAINER_CONTRACTS: string[] = [
  // ============================================
  // INFERNO DRAINER FAMILY - CONFIRMED MALICIOUS
  // ============================================
  '0x0000db5c8b030ae20308ac975898e09741e70000',
  '0x00000000a82b4758df44fcab4c4e86e2f231b000',
  
  // ============================================
  // PINK DRAINER FAMILY - CONFIRMED MALICIOUS
  // ============================================
  // NOTE: 0x00005ea00ac477b1030ce78506496e8c2de24bf5 was INCORRECTLY listed here.
  // That address is OpenSea SeaDrop - a LEGITIMATE NFT drop mechanism!
  // It has been REMOVED from this list to fix false positives.
  '0x0000d194a19e7578e1ee97a2b6f6e4af01a00000',
  
  // ============================================
  // ANGEL DRAINER FAMILY - CONFIRMED MALICIOUS
  // ============================================
  '0x00000000ae347930bd1e7b0f35588b92280f9e75',
  
  // ============================================
  // MONKEY DRAINER FAMILY - CONFIRMED MALICIOUS
  // ============================================
  '0x0000000035634b55f3d99b071b5a354f48e10000',
  
  // ============================================
  // VENOM DRAINER FAMILY - CONFIRMED MALICIOUS
  // ============================================
  '0x0000000052e7f0c029b6e38e96f03c70d86bfde5',
  
  // ============================================
  // MS DRAINER FAMILY - CONFIRMED MALICIOUS
  // ============================================
  '0x0000000083fc54c35b9b83de16c67c73b1a7b000',
];

// Known drainer recipient wallets (where stolen funds are sent) - VERIFIED ONLY
export const DRAINER_RECIPIENTS: string[] = [
  // ============================================
  // INFERNO DRAINER RECIPIENTS - CONFIRMED
  // ============================================
  '0x59abf3837fa962d6853b4cc0a19513aa031fd32b',
  '0x0000db5c8b030ae20308ac975898e09741e70000',
  
  // ============================================
  // PINK DRAINER RECIPIENTS - CONFIRMED
  // ============================================
  // NOTE: 0x00005ea00ac477b1030ce78506496e8c2de24bf5 REMOVED - it's OpenSea SeaDrop!
  '0x6d2e03b7effeae98bd302a9f836d0d6ab0002219',
  
  // ============================================
  // ANGEL DRAINER RECIPIENTS - CONFIRMED
  // ============================================
  '0x00000000ae347930bd1e7b0f35588b92280f9e75',
  
  // ============================================
  // MS DRAINER RECIPIENTS - CONFIRMED
  // ============================================
  '0x0000000083fc54c35b9b83de16c67c73b1a7b000',
  
  // ============================================
  // VERIFIED SWEEPER BOT ADDRESSES (Multi-Chain)
  // ============================================
  // CRITICAL: This address MUST be flagged on ALL chains (Ethereum, Base, etc.)
  // It shows automated sweep behavior - funds are forwarded immediately after receipt
  '0x7fcd4c52a0da9e18ec1d43ae50cd376c2b469e17',
  
  // ============================================
  // REPORTED ACTIVE DRAINERS - SECURITY TEAM VERIFIED
  // ============================================
  // These addresses were reported as active drainers by security engineers.
  // They exhibit drainer behavior patterns but may evade behavioral detection
  // due to limited on-chain data or patterns that mimic legitimate activity.
  // Adding them to the known drainer list ensures they are always flagged.
  '0x3b09a3c9add7d0262e6e9724d7e823cd767a0c74',
  '0x463452c356322d463b84891ebda33daed274cb40',
  '0xa42297ff42a3b65091967945131cd1db962afae4',
  '0xe072358070506a4dda5521b19260011a490a5aaa',
  '0xc22b8126ca21616424a22bf012fd1b7cf48f02b1',
  '0x109252d00b2fa8c79a74caa96d9194eef6c99581',
  '0x30cfa51ffb82727515708ce7dd8c69d121648445',
  '0x4735fbecf1db342282ad5baef585ee301b1bce25',
  '0xf2dd8eb79625109e2dd87c4243708e1485a85655',
];

// ============================================
// SWEEPER BOT ADDRESSES - VERIFIED (MULTI-CHAIN)
// ============================================
// These addresses exhibit sweeper bot behavior and should be detected on ALL chains.
// Originally identified on Base chain but sweeper bots operate across chains.
// 
// CRITICAL: These addresses are checked by isKnownDrainer() which is chain-agnostic.
// They will be flagged on Ethereum, Base, and all other supported chains.
//
// Detection criteria:
// - Incoming ETH/tokens → immediate outgoing within ≤1 block
// - Never accumulates balance (ends ≈0 after each inbound)
// - Programmatic destinations (fixed or rotating hot wallets)
// - Machine-consistent gas usage
// - Pattern repeats across multiple unrelated sender wallets
export const BASE_SWEEPER_ADDRESSES: string[] = [
  // VERIFIED SWEEPER: Originally reported on Base, but detected on ALL chains
  // This wallet programmatically forwards funds immediately after receipt
  '0x7fcd4c52a0da9e18ec1d43ae50cd376c2b469e17',
];

// Combined check for Base sweeper addresses
export function isBaseSweeperAddress(address: string): boolean {
  if (!address) return false;
  const normalized = address.toLowerCase();
  return BASE_SWEEPER_ADDRESSES.some(s => s.toLowerCase() === normalized);
}

// Function to check if an address is a known drainer
// ============================================
// EXPLICIT WHITELIST - NEVER FLAG THESE
// ============================================
const EXPLICIT_WHITELIST = new Set([
  '0x24cea16d97f61d0882481544f33fa5a8763991a6', // Union Authena (Base)
  '0x00005ea00ac477b1030ce78506496e8c2de24bf5', // OpenSea SeaDrop - LEGITIMATE NFT drop mechanism
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
  // User-verified wallets
  '0x39ae06382656e045d320b3a3f8d9515e6d10f53a', // User-confirmed legitimate wallet
]);

export function isKnownDrainer(address: string): boolean {
  if (!address) return false;
  const normalized = address.toLowerCase();
  
  // WHITELIST CHECK
  if (EXPLICIT_WHITELIST.has(normalized)) {
    console.log(`[isKnownDrainer] ${normalized.slice(0, 10)}... is WHITELISTED - returning false`);
    return false;
  }
  
  // Check each database
  const inDrainerContracts = DRAINER_CONTRACTS.some(d => d.toLowerCase() === normalized);
  const inDrainerRecipients = DRAINER_RECIPIENTS.some(d => d.toLowerCase() === normalized);
  const inSweeperAddresses = BASE_SWEEPER_ADDRESSES.some(s => s.toLowerCase() === normalized);
  
  const isKnown = inDrainerContracts || inDrainerRecipients || inSweeperAddresses;
  
  // Debug logging for the specific sweeper address
  if (normalized === '0x7fcd4c52a0da9e18ec1d43ae50cd376c2b469e17') {
    console.log(`[isKnownDrainer] *** SWEEPER CHECK ***`);
    console.log(`[isKnownDrainer] Address: ${normalized}`);
    console.log(`[isKnownDrainer] In DRAINER_CONTRACTS: ${inDrainerContracts}`);
    console.log(`[isKnownDrainer] In DRAINER_RECIPIENTS: ${inDrainerRecipients}`);
    console.log(`[isKnownDrainer] In BASE_SWEEPER_ADDRESSES: ${inSweeperAddresses}`);
    console.log(`[isKnownDrainer] Final result: ${isKnown}`);
  }
  
  if (isKnown) {
    console.log(`[isKnownDrainer] ${normalized.slice(0, 10)}... IS KNOWN DRAINER`);
  }
  
  return isKnown;
}

// Function to get drainer type
export function getDrainerType(address: string): string | null {
  if (!address) return null;
  const normalized = address.toLowerCase();
  
  // WHITELIST CHECK
  if (EXPLICIT_WHITELIST.has(normalized)) return null;
  
  // Check for sweeper bot addresses FIRST (these are detected on ALL chains)
  if (isBaseSweeperAddress(normalized)) return 'Active Sweeper Bot';
  
  // Check specific patterns in the address
  if (normalized.includes('db5c8b030ae20308ac975898e09741e7')) return 'Inferno Drainer';
  // REMOVED: 5ea00ac477b1030ce78506496e8c2de2 pattern - this matched OpenSea SeaDrop!
  // if (normalized.includes('5ea00ac477b1030ce78506496e8c2de2')) return 'Pink Drainer';
  if (normalized.includes('ae347930bd1e7b0f35588b92280f9e75')) return 'Angel Drainer';
  if (normalized.includes('35634b55f3d99b071b5a354f48e1')) return 'Monkey Drainer';
  if (normalized.includes('52e7f0c029b6e38e96f03c70d86bfde5')) return 'Venom Drainer';
  if (normalized.includes('83fc54c35b9b83de16c67c73b1a7b')) return 'MS Drainer';
  
  if (isKnownDrainer(address)) return 'Known Drainer';
  
  return null;
}

// NOTE: Pattern-based detection has been removed to prevent false positives.
// Only addresses explicitly in the lists above will be flagged as malicious.
