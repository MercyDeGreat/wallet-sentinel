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
  '0x00005ea00ac477b1030ce78506496e8c2de24bf5',
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
  '0x00005ea00ac477b1030ce78506496e8c2de24bf5',
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

// Function to check if an address is a known drainer
// ============================================
// EXPLICIT WHITELIST - NEVER FLAG THESE
// ============================================
const EXPLICIT_WHITELIST = new Set([
  '0x24cea16d97f61d0882481544f33fa5a8763991a6', // Union Authena (Base)
]);

export function isKnownDrainer(address: string): boolean {
  if (!address) return false;
  const normalized = address.toLowerCase();
  
  // WHITELIST CHECK
  if (EXPLICIT_WHITELIST.has(normalized)) return false;
  
  return DRAINER_CONTRACTS.some(d => d.toLowerCase() === normalized) ||
         DRAINER_RECIPIENTS.some(d => d.toLowerCase() === normalized);
}

// Function to get drainer type
export function getDrainerType(address: string): string | null {
  if (!address) return null;
  const normalized = address.toLowerCase();
  
  // WHITELIST CHECK
  if (EXPLICIT_WHITELIST.has(normalized)) return null;
  
  // Check specific patterns in the address
  if (normalized.includes('db5c8b030ae20308ac975898e09741e7')) return 'Inferno Drainer';
  if (normalized.includes('5ea00ac477b1030ce78506496e8c2de2')) return 'Pink Drainer';
  if (normalized.includes('ae347930bd1e7b0f35588b92280f9e75')) return 'Angel Drainer';
  if (normalized.includes('35634b55f3d99b071b5a354f48e1')) return 'Monkey Drainer';
  if (normalized.includes('52e7f0c029b6e38e96f03c70d86bfde5')) return 'Venom Drainer';
  if (normalized.includes('83fc54c35b9b83de16c67c73b1a7b')) return 'MS Drainer';
  
  if (isKnownDrainer(address)) return 'Known Drainer';
  
  return null;
}

// NOTE: Pattern-based detection has been removed to prevent false positives.
// Only addresses explicitly in the lists above will be flagged as malicious.
