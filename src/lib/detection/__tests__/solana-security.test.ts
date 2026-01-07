// ============================================
// SOLANA SECURITY DETECTION TESTS
// ============================================
// Tests for Solana drainer & sweeper bot detection
// with three-state security model.
//
// KEY REQUIREMENTS:
// 1. NEVER mark SAFE solely because no malicious contracts found
// 2. Three explicit states: SAFE, PREVIOUSLY_COMPROMISED, ACTIVELY_COMPROMISED
// 3. Require at least 2 independent high-confidence signals for ACTIVE compromise
// 4. Prefer false negatives over false positives
// 5. Comprehensive whitelisting for legitimate protocols

import { describe, test, expect } from 'vitest';
import {
  analyzeSolanaSecurity,
  detectDrainerBehavior,
  detectSweeperBotBehavior,
  isWhitelistedProgram,
  getWhitelistCategory,
  SOLANA_SYSTEM_PROGRAMS,
  SOLANA_BRIDGE_PROGRAMS,
  SOLANA_NFT_PROGRAMS,
  SOLANA_DEFI_PROGRAMS,
  SOLANA_STAKING_PROGRAMS,
  DEFAULT_SOLANA_DETECTION_CONFIG,
  SolanaTransactionData,
  SolanaSecurityState,
} from '../solana-security';

// ============================================
// WHITELIST TESTS
// ============================================

describe('Solana Program Whitelists', () => {
  describe('System Programs', () => {
    test('TokenProgram is whitelisted', () => {
      expect(isWhitelistedProgram('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')).toBe(true);
      expect(getWhitelistCategory('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')).toBe('SYSTEM');
    });

    test('SystemProgram is whitelisted', () => {
      expect(isWhitelistedProgram('11111111111111111111111111111111')).toBe(true);
      expect(getWhitelistCategory('11111111111111111111111111111111')).toBe('SYSTEM');
    });

    test('Token-2022 is whitelisted', () => {
      expect(isWhitelistedProgram('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')).toBe(true);
    });

    test('AssociatedTokenProgram is whitelisted', () => {
      expect(isWhitelistedProgram('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')).toBe(true);
    });

    test('Memo programs are whitelisted', () => {
      expect(isWhitelistedProgram('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')).toBe(true);
      expect(isWhitelistedProgram('Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo')).toBe(true);
    });
  });

  describe('Bridge Programs', () => {
    test('Wormhole Token Bridge is whitelisted', () => {
      expect(isWhitelistedProgram('worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth')).toBe(true);
      expect(getWhitelistCategory('worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth')).toBe('BRIDGE');
    });

    test('Wormhole Core Bridge is whitelisted', () => {
      expect(isWhitelistedProgram('wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb')).toBe(true);
    });

    test('DeBridge is whitelisted', () => {
      expect(isWhitelistedProgram('DEbrdGj3HsRsAzx6uH4MKyREKxVAfBydijLUF3ygsFfh')).toBe(true);
    });
  });

  describe('NFT Programs', () => {
    test('Metaplex Token Metadata is whitelisted', () => {
      expect(isWhitelistedProgram('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s')).toBe(true);
      expect(getWhitelistCategory('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s')).toBe('NFT');
    });

    test('Magic Eden V2 is whitelisted', () => {
      expect(isWhitelistedProgram('M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K')).toBe(true);
    });

    test('Tensor Swap is whitelisted', () => {
      expect(isWhitelistedProgram('TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN')).toBe(true);
    });

    test('Bubblegum (cNFT) is whitelisted', () => {
      expect(isWhitelistedProgram('BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY')).toBe(true);
    });
  });

  describe('DeFi Programs', () => {
    test('Jupiter V6 is whitelisted', () => {
      expect(isWhitelistedProgram('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4')).toBe(true);
      expect(getWhitelistCategory('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4')).toBe('DEFI');
    });

    test('Raydium AMM V4 is whitelisted', () => {
      expect(isWhitelistedProgram('675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8')).toBe(true);
    });

    test('Orca Whirlpool is whitelisted', () => {
      expect(isWhitelistedProgram('whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc')).toBe(true);
    });

    test('Marinade Staking is whitelisted', () => {
      expect(isWhitelistedProgram('MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD')).toBe(true);
    });

    test('Drift V2 is whitelisted', () => {
      expect(isWhitelistedProgram('dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH')).toBe(true);
    });
  });

  describe('Unknown Programs', () => {
    test('Unknown program is NOT whitelisted', () => {
      expect(isWhitelistedProgram('UnknownProgramId12345678901234567890')).toBe(false);
      expect(getWhitelistCategory('UnknownProgramId12345678901234567890')).toBe(null);
    });
  });
});

// ============================================
// THREE-STATE MODEL TESTS
// ============================================

describe('Three-State Security Model', () => {
  const mockWalletAddress = 'MockWallet123456789012345678901234567890';
  const emptyMaliciousSet = new Set<string>();

  test('Empty transaction history returns SAFE (not flagged)', () => {
    const result = analyzeSolanaSecurity([], mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    expect(result.isActive).toBe(false);
    expect(result.isHistorical).toBe(false);
    // Explanation should NOT be alarming
    expect(result.explanation).not.toMatch(/urgent/i);
    expect(result.explanation).not.toMatch(/immediately/i);
  });

  test('Normal activity returns SAFE', () => {
    const normalTxs: SolanaTransactionData[] = [
      {
        signature: 'sig1',
        timestamp: Date.now() / 1000 - 86400, // 1 day ago
        isInbound: true,
        isOutbound: false,
        programIds: ['11111111111111111111111111111111'],
        hasMemo: true,
      },
      {
        signature: 'sig2',
        timestamp: Date.now() / 1000 - 43200, // 12 hours ago
        isInbound: false,
        isOutbound: true,
        programIds: ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'],
        hasMemo: false,
      },
    ];

    const result = analyzeSolanaSecurity(normalTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    expect(result.riskScore).toBeLessThanOrEqual(20);
  });

  test('PREVIOUSLY_COMPROMISED state for historical drainer activity', () => {
    // Create transactions that show drainer behavior but are old (> 7 days)
    const oldTimestamp = Date.now() / 1000 - 10 * 86400; // 10 days ago
    
    const historicalDrainTxs: SolanaTransactionData[] = [];
    
    // Simulate rapid outflows 10 days ago
    for (let i = 0; i < 10; i++) {
      historicalDrainTxs.push({
        signature: `drain-${i}`,
        timestamp: oldTimestamp + i * 10, // Within 2 minutes
        isInbound: false,
        isOutbound: true,
        isSOLTransfer: i < 2,
        isSPLTransfer: i >= 2,
        lamports: 1000000000,
        toAddress: 'MaliciousDest123456789012345678901234567890',
        programIds: [],
      });
    }
    
    // Add interaction with known malicious address
    const maliciousSet = new Set(['MaliciousDest123456789012345678901234567890']);
    
    const result = analyzeSolanaSecurity(historicalDrainTxs, mockWalletAddress, maliciousSet);
    
    // Should be PREVIOUSLY_COMPROMISED since activity is old
    expect(result.state).toBe('PREVIOUSLY_COMPROMISED');
    expect(result.isHistorical).toBe(true);
    expect(result.isActive).toBe(false);
    expect(result.daysSinceLastIncident).toBeGreaterThan(7);
    // Explanation should mention "no active risk" or similar
    expect(result.explanation.toLowerCase()).toMatch(/no active/i);
  });

  test('ACTIVELY_COMPROMISED state for recent drainer activity', () => {
    // Create transactions that show drainer behavior recently (< 7 days)
    const recentTimestamp = Date.now() / 1000 - 86400; // 1 day ago
    
    const activeDrainTxs: SolanaTransactionData[] = [];
    
    // Simulate rapid outflows 1 day ago
    for (let i = 0; i < 10; i++) {
      activeDrainTxs.push({
        signature: `drain-${i}`,
        timestamp: recentTimestamp + i * 10, // Within 2 minutes
        isInbound: false,
        isOutbound: true,
        isSOLTransfer: i < 2,
        isSPLTransfer: i >= 2,
        lamports: 1000000000,
        toAddress: 'MaliciousDest123456789012345678901234567890',
        programIds: [],
      });
    }
    
    // Add inbound followed by immediate outbound (sweeper pattern)
    activeDrainTxs.push({
      signature: 'inbound-1',
      timestamp: recentTimestamp - 100,
      isInbound: true,
      isOutbound: false,
      lamports: 5000000000,
      programIds: [],
    });
    
    const maliciousSet = new Set(['MaliciousDest123456789012345678901234567890']);
    
    const result = analyzeSolanaSecurity(activeDrainTxs, mockWalletAddress, maliciousSet);
    
    // Should be ACTIVELY_COMPROMISED since activity is recent
    expect(result.state).toBe('ACTIVELY_COMPROMISED');
    expect(result.isActive).toBe(true);
    expect(result.isHistorical).toBe(false);
    // Explanation should be urgent
    expect(result.explanation.toLowerCase()).toMatch(/active|urgent/i);
  });
});

// ============================================
// DRAINER DETECTION TESTS
// ============================================

describe('Drainer Detection', () => {
  const mockWalletAddress = 'MockWallet123456789012345678901234567890';
  const emptyMaliciousSet = new Set<string>();

  test('Requires multiple signals for high confidence', () => {
    // Single signal should NOT be enough
    const singleSignalTxs: SolanaTransactionData[] = [
      {
        signature: 'tx1',
        timestamp: Date.now() / 1000 - 100,
        isInbound: false,
        isOutbound: true,
        isSOLTransfer: true,
        lamports: 1000000000,
        toAddress: 'SomeDestination',
        programIds: [],
      },
    ];
    
    const result = detectDrainerBehavior(singleSignalTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.isDrainer).toBe(false);
    expect(result.confidence).toBeLessThan(70);
  });

  test('Rapid asset depletion detected correctly', () => {
    const now = Date.now() / 1000;
    
    const rapidDrainTxs: SolanaTransactionData[] = [
      // SOL drain
      {
        signature: 'sol-drain',
        timestamp: now - 300,
        isInbound: false,
        isOutbound: true,
        isSOLTransfer: true,
        lamports: 5000000000,
        toAddress: 'Dest1',
        programIds: [],
      },
      // SPL drain 1
      {
        signature: 'spl-drain-1',
        timestamp: now - 250,
        isInbound: false,
        isOutbound: true,
        isSPLTransfer: true,
        toAddress: 'Dest1',
        programIds: ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'],
      },
      // SPL drain 2
      {
        signature: 'spl-drain-2',
        timestamp: now - 200,
        isInbound: false,
        isOutbound: true,
        isSPLTransfer: true,
        toAddress: 'Dest1',
        programIds: ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'],
      },
    ];
    
    const result = detectDrainerBehavior(rapidDrainTxs, mockWalletAddress, emptyMaliciousSet);
    
    // Should detect rapid asset depletion signal
    expect(result.signals.some(s => s.type === 'RAPID_ASSET_DEPLETION')).toBe(true);
  });

  test('Known malicious interactions increase confidence', () => {
    const now = Date.now() / 1000;
    const maliciousAddress = 'KnownMaliciousAddr123456789012345678901234';
    const maliciousSet = new Set([maliciousAddress]);
    
    const maliciousTxs: SolanaTransactionData[] = [
      {
        signature: 'malicious-1',
        timestamp: now - 100,
        isInbound: false,
        isOutbound: true,
        toAddress: maliciousAddress,
        programIds: [],
      },
    ];
    
    const result = detectDrainerBehavior(maliciousTxs, mockWalletAddress, maliciousSet);
    
    expect(result.signals.some(s => s.type === 'KNOWN_MALICIOUS_INTERACTION')).toBe(true);
    expect(result.confidence).toBeGreaterThan(0);
  });
});

// ============================================
// SWEEPER BOT DETECTION TESTS
// ============================================

describe('Sweeper Bot Detection', () => {
  const mockWalletAddress = 'MockWallet123456789012345678901234567890';

  test('Immediate automated transfers detected', () => {
    const now = Date.now() / 1000;
    
    const sweeperTxs: SolanaTransactionData[] = [];
    
    // Create inbound -> immediate outbound pattern (3 times)
    for (let i = 0; i < 3; i++) {
      sweeperTxs.push({
        signature: `inbound-${i}`,
        timestamp: now - (300 * (i + 1)),
        isInbound: true,
        isOutbound: false,
        lamports: 1000000000,
        programIds: [],
      });
      sweeperTxs.push({
        signature: `outbound-${i}`,
        timestamp: now - (300 * (i + 1)) + 5, // 5 seconds later
        isInbound: false,
        isOutbound: true,
        lamports: 990000000,
        toAddress: 'SweeperDest123456789012345678901234567890',
        programIds: [],
      });
    }
    
    const result = detectSweeperBotBehavior(sweeperTxs, mockWalletAddress);
    
    expect(result.signals.some(s => s.type === 'IMMEDIATE_AUTOMATED_TRANSFER')).toBe(true);
  });

  test('Identical destination pattern detected', () => {
    const now = Date.now() / 1000;
    const sameDestination = 'SameDest123456789012345678901234567890';
    
    const samDestTxs: SolanaTransactionData[] = [];
    
    // 5 outbound transactions to same destination
    for (let i = 0; i < 5; i++) {
      samDestTxs.push({
        signature: `out-${i}`,
        timestamp: now - (100 * (i + 1)),
        slot: 100000 + i,
        isInbound: false,
        isOutbound: true,
        toAddress: sameDestination,
        programIds: [],
      });
    }
    
    const result = detectSweeperBotBehavior(samDestTxs, mockWalletAddress);
    
    expect(result.signals.some(s => s.type === 'IDENTICAL_DESTINATION_PATTERN')).toBe(true);
  });

  test('Single event is NOT flagged as sweeper', () => {
    const now = Date.now() / 1000;
    
    const singleEventTxs: SolanaTransactionData[] = [
      {
        signature: 'single-out',
        timestamp: now - 100,
        isInbound: false,
        isOutbound: true,
        toAddress: 'SomeDest123456789012345678901234567890',
        programIds: [],
      },
    ];
    
    const result = detectSweeperBotBehavior(singleEventTxs, mockWalletAddress);
    
    expect(result.isSweeper).toBe(false);
  });
});

// ============================================
// FALSE POSITIVE PREVENTION TESTS
// ============================================

describe('False Positive Prevention', () => {
  const mockWalletAddress = 'MockWallet123456789012345678901234567890';
  const emptyMaliciousSet = new Set<string>();

  test('Whitelisted DeFi activity is NOT flagged', () => {
    const now = Date.now() / 1000;
    
    const defiTxs: SolanaTransactionData[] = [];
    
    // Multiple Jupiter swaps (legitimate DeFi activity)
    for (let i = 0; i < 10; i++) {
      defiTxs.push({
        signature: `jupiter-${i}`,
        timestamp: now - (60 * (i + 1)),
        isInbound: false,
        isOutbound: true,
        programIds: ['JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'],
      });
    }
    
    const result = analyzeSolanaSecurity(defiTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    expect(result.riskScore).toBeLessThanOrEqual(20);
  });

  test('NFT minting activity is NOT flagged as drainer', () => {
    const now = Date.now() / 1000;
    
    const nftTxs: SolanaTransactionData[] = [];
    
    // Multiple NFT mints
    for (let i = 0; i < 5; i++) {
      nftTxs.push({
        signature: `mint-${i}`,
        timestamp: now - (30 * (i + 1)),
        isInbound: false,
        isOutbound: true,
        isNFTTransfer: true,
        programIds: ['metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s'],
      });
    }
    
    const result = analyzeSolanaSecurity(nftTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
  });

  test('Self-transfers are whitelisted', () => {
    const now = Date.now() / 1000;
    
    const selfTransferTxs: SolanaTransactionData[] = [
      {
        signature: 'self-1',
        timestamp: now - 100,
        fromAddress: mockWalletAddress,
        toAddress: mockWalletAddress,
        isInbound: true,
        isOutbound: true,
        programIds: [],
      },
    ];
    
    const result = analyzeSolanaSecurity(selfTransferTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    expect(result.reasoning.whitelistedActivity.length).toBeGreaterThan(0);
  });

  test('Bridge transactions are NOT flagged', () => {
    const now = Date.now() / 1000;
    
    const bridgeTxs: SolanaTransactionData[] = [
      {
        signature: 'bridge-1',
        timestamp: now - 100,
        isInbound: false,
        isOutbound: true,
        lamports: 5000000000,
        programIds: ['worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth'],
      },
    ];
    
    const result = analyzeSolanaSecurity(bridgeTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
  });

  test('One-off large transfer is NOT flagged', () => {
    const now = Date.now() / 1000;
    
    const largeTxs: SolanaTransactionData[] = [
      {
        signature: 'large-1',
        timestamp: now - 86400, // 1 day ago
        isInbound: false,
        isOutbound: true,
        isSOLTransfer: true,
        lamports: 100000000000, // 100 SOL
        toAddress: 'SomeAddress123456789012345678901234567890',
        programIds: [],
        hasMemo: true, // Has memo indicating user interaction
      },
    ];
    
    const result = analyzeSolanaSecurity(largeTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    // Should mention irregular timing as a safe signal
    expect(result.reasoning.safeSignals.length).toBeGreaterThan(0);
  });

  test('Marketplace escrow is NOT flagged as sweeper', () => {
    const now = Date.now() / 1000;
    
    const escrowTxs: SolanaTransactionData[] = [];
    
    // Multiple Magic Eden transactions
    for (let i = 0; i < 5; i++) {
      escrowTxs.push({
        signature: `me-${i}`,
        timestamp: now - (100 * (i + 1)),
        isInbound: false,
        isOutbound: true,
        toAddress: 'M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K',
        programIds: ['M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K'],
      });
    }
    
    const result = analyzeSolanaSecurity(escrowTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
  });
});

// ============================================
// CONFIDENCE THRESHOLDING TESTS
// ============================================

describe('Confidence Thresholding', () => {
  const mockWalletAddress = 'MockWallet123456789012345678901234567890';
  const emptyMaliciousSet = new Set<string>();

  test('Low confidence signals do NOT trigger ACTIVE compromise', () => {
    const now = Date.now() / 1000;
    
    // Create a situation with only medium-confidence signals
    const ambiguousTxs: SolanaTransactionData[] = [
      {
        signature: 'out-1',
        timestamp: now - 100,
        isInbound: false,
        isOutbound: true,
        toAddress: 'Dest1',
        programIds: [],
      },
      {
        signature: 'out-2',
        timestamp: now - 80,
        isInbound: false,
        isOutbound: true,
        toAddress: 'Dest2',
        programIds: [],
      },
    ];
    
    const result = analyzeSolanaSecurity(ambiguousTxs, mockWalletAddress, emptyMaliciousSet);
    
    // Should NOT be ACTIVELY_COMPROMISED without strong evidence
    expect(result.state).not.toBe('ACTIVELY_COMPROMISED');
  });

  test('Minimum 2 high-confidence signals required for ACTIVE compromise', () => {
    expect(DEFAULT_SOLANA_DETECTION_CONFIG.minSignalsForActiveCompromise).toBe(2);
  });
});

// ============================================
// OUTPUT REQUIREMENTS TESTS
// ============================================

describe('Output Requirements', () => {
  const mockWalletAddress = 'MockWallet123456789012345678901234567890';
  const emptyMaliciousSet = new Set<string>();

  test('Explanation is always provided', () => {
    const result = analyzeSolanaSecurity([], mockWalletAddress, emptyMaliciousSet);
    
    expect(result.explanation).toBeDefined();
    expect(result.explanation.length).toBeGreaterThan(0);
  });

  test('SAFE state does not use alarming language', () => {
    const result = analyzeSolanaSecurity([], mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    expect(result.explanation.toLowerCase()).not.toMatch(/urgent|immediately|critical|danger/i);
  });

  test('Reasoning includes safe signals', () => {
    const result = analyzeSolanaSecurity([], mockWalletAddress, emptyMaliciousSet);
    
    expect(result.reasoning).toBeDefined();
    expect(result.reasoning.safeSignals).toBeDefined();
  });

  test('Reasoning includes whitelisted activity', () => {
    const now = Date.now() / 1000;
    
    const whitelistedTxs: SolanaTransactionData[] = [
      {
        signature: 'jup-1',
        timestamp: now - 100,
        isInbound: false,
        isOutbound: true,
        programIds: ['JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'],
      },
    ];
    
    const result = analyzeSolanaSecurity(whitelistedTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.reasoning.whitelistedActivity.length).toBeGreaterThan(0);
  });

  test('Uncertainty factors are documented', () => {
    const result = analyzeSolanaSecurity([], mockWalletAddress, emptyMaliciousSet);
    
    expect(result.reasoning.uncertaintyFactors).toBeDefined();
    // Should always mention off-chain limitation
    expect(result.reasoning.uncertaintyFactors.some(f => f.toLowerCase().includes('off-chain'))).toBe(true);
  });
});

// ============================================
// REGRESSION TESTS
// ============================================

describe('Regression: Avoid Fear Amplification', () => {
  const mockWalletAddress = 'MockWallet123456789012345678901234567890';
  const emptyMaliciousSet = new Set<string>();

  test('Empty history does not trigger alarms', () => {
    const result = analyzeSolanaSecurity([], mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    expect(result.riskScore).toBeLessThanOrEqual(20);
    expect(result.explanation.toLowerCase()).not.toMatch(/compromised|attack|drain|stolen/i);
  });

  test('Normal DeFi user is not flagged', () => {
    const now = Date.now() / 1000;
    
    // Simulate a normal DeFi user
    const normalUserTxs: SolanaTransactionData[] = [
      // Received SOL
      { signature: 'receive-1', timestamp: now - 86400 * 7, isInbound: true, isOutbound: false, lamports: 10000000000, programIds: [] },
      // Swapped on Jupiter
      { signature: 'swap-1', timestamp: now - 86400 * 5, isInbound: false, isOutbound: true, programIds: ['JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'] },
      // Bought NFT on Magic Eden
      { signature: 'nft-buy-1', timestamp: now - 86400 * 3, isInbound: false, isOutbound: true, programIds: ['M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K'] },
      // Staked with Marinade
      { signature: 'stake-1', timestamp: now - 86400 * 2, isInbound: false, isOutbound: true, programIds: ['MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD'] },
      // Sent to friend (with memo)
      { signature: 'send-1', timestamp: now - 86400, isInbound: false, isOutbound: true, lamports: 1000000000, hasMemo: true, programIds: [] },
    ];
    
    const result = analyzeSolanaSecurity(normalUserTxs, mockWalletAddress, emptyMaliciousSet);
    
    expect(result.state).toBe('SAFE');
    expect(result.riskScore).toBeLessThanOrEqual(20);
  });
});

