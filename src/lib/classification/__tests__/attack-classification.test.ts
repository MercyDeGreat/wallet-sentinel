// ============================================
// ATTACK CLASSIFICATION ENGINE - UNIT TESTS
// ============================================
// 
// Tests for accurate attack type classification.
// 
// CRITICAL RULES BEING TESTED:
// 1. Never label address poisoning as sweeper bot
// 2. Never say "wallet compromised" without signer or approval proof
// 3. Always explain uncertainty
// 4. Classification ≠ Detection
// ============================================

import { describe, test, expect } from 'vitest';
import {
  AttackClassificationEngine,
  classifyAttack,
  calculateAddressSimilarity,
  isDustValue,
} from '../index';
import type {
  AttackClassificationInput,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationApproval,
} from '../types';

// ============================================
// HELPER FUNCTIONS FOR TEST DATA
// ============================================

function createMockTransaction(overrides: Partial<ClassificationTransaction> = {}): ClassificationTransaction {
  return {
    hash: '0x' + '1'.repeat(64),
    from: '0x' + '1'.repeat(40),
    to: '0x' + '2'.repeat(40),
    value: '1000000000000000000', // 1 ETH
    timestamp: Math.floor(Date.now() / 1000) - 3600,
    blockNumber: 19000000,
    isInbound: false,
    ...overrides,
  };
}

function createMockTokenTransfer(overrides: Partial<ClassificationTokenTransfer> = {}): ClassificationTokenTransfer {
  return {
    hash: '0x' + '2'.repeat(64),
    from: '0x' + '1'.repeat(40),
    to: '0x' + '2'.repeat(40),
    value: '1000000000000000000',
    timestamp: Math.floor(Date.now() / 1000) - 3600,
    tokenAddress: '0x' + '3'.repeat(40),
    tokenSymbol: 'TEST',
    tokenType: 'ERC20',
    isInbound: false,
    isDust: false,
    ...overrides,
  };
}

function createMockApproval(overrides: Partial<ClassificationApproval> = {}): ClassificationApproval {
  return {
    hash: '0x' + '4'.repeat(64),
    token: '0x' + '3'.repeat(40),
    tokenSymbol: 'TEST',
    spender: '0x' + '5'.repeat(40),
    owner: '0x' + '1'.repeat(40),
    amount: '115792089237316195423570985008687907853269984665640564039457584007913129639935', // Max uint256
    isUnlimited: true,
    timestamp: Math.floor(Date.now() / 1000) - 7200,
    blockNumber: 18999999,
    wasRevoked: false,
    wasUsed: false,
    usedByTransferFrom: false,
    ...overrides,
  };
}

function createMockInput(overrides: Partial<AttackClassificationInput> = {}): AttackClassificationInput {
  return {
    walletAddress: '0x1234567890123456789012345678901234567890',
    chain: 'ethereum',
    transactions: [],
    tokenTransfers: [],
    approvals: [],
    maliciousAddresses: [],
    frequentRecipients: [],
    currentTimestamp: Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

// ============================================
// TEST: ADDRESS SIMILARITY CALCULATION
// ============================================

describe('Address Similarity Calculation', () => {
  test('identical addresses have 100% similarity', () => {
    const addr = '0x1234567890abcdef1234567890abcdef12345678';
    const result = calculateAddressSimilarity(addr, addr);
    expect(result.score).toBe(100);
    expect(result.prefixMatch).toBe(40);
    expect(result.suffixMatch).toBe(40);
  });
  
  test('completely different addresses have 0% similarity', () => {
    const addr1 = '0x1234567890abcdef1234567890abcdef12345678';
    const addr2 = '0xfedcba0987654321fedcba0987654321fedcba09';
    const result = calculateAddressSimilarity(addr1, addr2);
    expect(result.score).toBe(0);
    expect(result.prefixMatch).toBe(0);
    expect(result.suffixMatch).toBe(0);
  });
  
  test('addresses with matching prefix are detected', () => {
    const addr1 = '0x1234567890abcdef1234567890abcdef12345678';
    const addr2 = '0x1234567800000000000000000000000000000000';
    const result = calculateAddressSimilarity(addr1, addr2);
    expect(result.prefixMatch).toBe(8);
    expect(result.score).toBeGreaterThan(30);
  });
  
  test('addresses with matching suffix are detected', () => {
    const addr1 = '0x1234567890abcdef1234567890abcdef12345678';
    const addr2 = '0x000000000000000000000000000000ef12345678';
    const result = calculateAddressSimilarity(addr1, addr2);
    expect(result.suffixMatch).toBe(10);
    expect(result.score).toBeGreaterThan(30);
  });
  
  test('typical poisoning address is detected (4+ matching chars)', () => {
    // Attacker creates: 0x1234...5678 to mimic victim's frequent recipient
    // Addresses must be exactly 42 chars (0x + 40 hex chars)
    const victimRecipient = '0x1234aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5678'; // 0x + 4 + 32 + 4 = 42
    const poisonAddress = '0x1234bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb5678'; // 0x + 4 + 32 + 4 = 42
    const result = calculateAddressSimilarity(victimRecipient, poisonAddress);
    expect(result.prefixMatch).toBe(4);
    expect(result.suffixMatch).toBe(4);
    expect(result.prefixMatch + result.suffixMatch).toBeGreaterThanOrEqual(4);
  });
});

// ============================================
// TEST: DUST VALUE DETECTION
// ============================================

describe('Dust Value Detection', () => {
  const threshold = '100000000000000'; // 0.0001 ETH
  
  test('zero value is not dust', () => {
    expect(isDustValue('0', threshold)).toBe(false);
  });
  
  test('very small value is dust', () => {
    expect(isDustValue('1000', threshold)).toBe(true);
    expect(isDustValue('100000000000', threshold)).toBe(true); // 0.0000001 ETH
  });
  
  test('value at threshold is dust', () => {
    expect(isDustValue(threshold, threshold)).toBe(true);
  });
  
  test('value above threshold is not dust', () => {
    expect(isDustValue('1000000000000000', threshold)).toBe(false); // 0.001 ETH
  });
  
  test('normal transaction value is not dust', () => {
    expect(isDustValue('1000000000000000000', threshold)).toBe(false); // 1 ETH
  });
});

// ============================================
// TEST: ADDRESS POISONING CLASSIFICATION
// ============================================

describe('Address Poisoning Classification', () => {
  test('detects address poisoning with dust from similar address', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const frequentRecipient = '0xabcd567890123456789012345678901234560000';
    const poisonAddress = '0xabcd111111111111111111111111111111110000';
    
    const input = createMockInput({
      walletAddress,
      frequentRecipients: [frequentRecipient],
      tokenTransfers: [
        // Dust from poisoned address (similar to frequent recipient)
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000', // Dust
          isInbound: true,
          isDust: true,
          timestamp: Math.floor(Date.now() / 1000) - 86400,
        }),
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000', // Dust
          isInbound: true,
          isDust: true,
          timestamp: Math.floor(Date.now() / 1000) - 43200,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    expect(result.type).toBe('ADDRESS_POISONING');
    expect(result.confidence).toBeGreaterThan(30);
    expect(result.ruledOut).toContain('No approval abuse detected');
    expect(result.ruledOut).toContain('No automated drain pattern');
  });
  
  test('does NOT classify as sweeper bot when poisoning pattern exists', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const frequentRecipient = '0xabcd567890123456789012345678901234560000';
    const poisonAddress = '0xabcd111111111111111111111111111111110000';
    
    const input = createMockInput({
      walletAddress,
      frequentRecipients: [frequentRecipient],
      tokenTransfers: [
        // Dust from poisoned address
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000',
          isInbound: true,
          isDust: true,
        }),
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000',
          isInbound: true,
          isDust: true,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    // CRITICAL: Must NOT be sweeper bot
    expect(result.type).not.toBe('SWEEPER_BOT');
  });
  
  test('includes what did NOT happen in explanation', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const frequentRecipient = '0xabcd567890123456789012345678901234560000';
    const poisonAddress = '0xabcd111111111111111111111111111111110000';
    
    const input = createMockInput({
      walletAddress,
      frequentRecipients: [frequentRecipient],
      tokenTransfers: [
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000',
          isInbound: true,
          isDust: true,
        }),
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000',
          isInbound: true,
          isDust: true,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    // Display should include what did NOT happen
    expect(result.display.whatDidNotHappen.length).toBeGreaterThan(0);
    expect(result.display.whatDidNotHappen.some(s => 
      s.toLowerCase().includes('private key') || 
      s.toLowerCase().includes('approval') ||
      s.toLowerCase().includes('automated')
    )).toBe(true);
  });
});

// ============================================
// TEST: SWEEPER BOT CLASSIFICATION
// ============================================

describe('Sweeper Bot Classification', () => {
  test('detects sweeper bot with immediate outbound after inbound', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const now = Math.floor(Date.now() / 1000);
    
    const input = createMockInput({
      walletAddress,
      transactions: [
        // Inbound
        createMockTransaction({
          from: '0xaaaa' + '0'.repeat(36),
          to: walletAddress,
          value: '1000000000000000000',
          isInbound: true,
          timestamp: now - 120,
          blockNumber: 19000000,
        }),
        // Immediate outbound (10 seconds later)
        createMockTransaction({
          from: walletAddress,
          to: '0xbbbb' + '0'.repeat(36),
          value: '990000000000000000',
          isInbound: false,
          timestamp: now - 110,
          blockNumber: 19000001,
          gasPrice: '50000000000',
        }),
        // Another inbound
        createMockTransaction({
          from: '0xcccc' + '0'.repeat(36),
          to: walletAddress,
          value: '2000000000000000000',
          isInbound: true,
          timestamp: now - 60,
          blockNumber: 19000010,
        }),
        // Another immediate outbound (15 seconds later)
        createMockTransaction({
          from: walletAddress,
          to: '0xbbbb' + '0'.repeat(36),
          value: '1990000000000000000',
          isInbound: false,
          timestamp: now - 45,
          blockNumber: 19000011,
          gasPrice: '50000000000',
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    expect(result.type).toBe('SWEEPER_BOT');
    expect(result.confidence).toBeGreaterThan(50);
    expect(result.indicators.some(i => i.includes('sweep'))).toBe(true);
  });
  
  test('does NOT classify as sweeper when only dust transfers', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const now = Math.floor(Date.now() / 1000);
    
    const input = createMockInput({
      walletAddress,
      tokenTransfers: [
        // Only dust transfers
        createMockTokenTransfer({
          from: '0xaaaa' + '0'.repeat(36),
          to: walletAddress,
          value: '1000', // Dust
          isInbound: true,
          isDust: true,
          timestamp: now - 120,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    expect(result.type).not.toBe('SWEEPER_BOT');
  });
});

// ============================================
// TEST: APPROVAL DRAINER CLASSIFICATION
// ============================================

describe('Approval Drainer Classification', () => {
  test('detects approval drainer with malicious approval', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const maliciousSpender = '0xdead' + '0'.repeat(36);
    const tokenAddress = '0x' + 'a'.repeat(40);
    const now = Math.floor(Date.now() / 1000);
    
    const input = createMockInput({
      walletAddress,
      maliciousAddresses: [maliciousSpender],
      approvals: [
        createMockApproval({
          owner: walletAddress,
          spender: maliciousSpender,
          token: tokenAddress,
          isUnlimited: true,
          timestamp: now - 7200,
          wasUsed: true,
          usedByTransferFrom: true,
        }),
      ],
      tokenTransfers: [
        // Token drained via transferFrom
        createMockTokenTransfer({
          from: walletAddress,
          to: maliciousSpender,
          tokenAddress: tokenAddress,
          value: '10000000000000000000000',
          isInbound: false,
          isDust: false,
          timestamp: now - 3600,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    expect(result.type).toBe('APPROVAL_DRAINER');
    expect(result.confidence).toBeGreaterThan(50);
    expect(result.ruledOut.some(r => 
      r.toLowerCase().includes('sweeper') || 
      r.toLowerCase().includes('signature')
    )).toBe(true);
  });
  
  test('does NOT say wallet compromised without approval evidence', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    
    const input = createMockInput({
      walletAddress,
      approvals: [], // No approvals
      transactions: [],
      tokenTransfers: [],
    });
    
    const result = await classifyAttack(input);
    
    expect(result.type).toBe('NO_COMPROMISE');
    expect(result.display.headline).not.toContain('Compromised');
  });
});

// ============================================
// TEST: SIGNER COMPROMISE CLASSIFICATION
// ============================================

describe('Signer Compromise Classification', () => {
  test('detects signer compromise with abnormal behavior', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const maliciousDest = '0xbad1' + '0'.repeat(36);
    const now = Math.floor(Date.now() / 1000);
    const oneDayAgo = now - 86400;
    
    // Build historical profile (normal activity for 30 days)
    const historicalTxs: ClassificationTransaction[] = [];
    const normalRecipient = '0xgood' + '0'.repeat(36);
    
    for (let i = 0; i < 20; i++) {
      historicalTxs.push(createMockTransaction({
        hash: '0x' + i.toString().padStart(64, '0'),
        from: walletAddress,
        to: normalRecipient,
        value: '100000000000000000', // 0.1 ETH
        timestamp: now - (30 * 86400) + (i * 86400), // Spread over 30 days
        isInbound: false,
      }));
    }
    
    // Recent suspicious activity (all to malicious, different times)
    const recentTxs: ClassificationTransaction[] = [
      createMockTransaction({
        hash: '0xrecent1' + '0'.repeat(56),
        from: walletAddress,
        to: maliciousDest,
        value: '5000000000000000000', // 5 ETH
        timestamp: now - 3600,
        isInbound: false,
      }),
      createMockTransaction({
        hash: '0xrecent2' + '0'.repeat(56),
        from: walletAddress,
        to: maliciousDest,
        value: '3000000000000000000', // 3 ETH
        timestamp: now - 3540,
        isInbound: false,
      }),
    ];
    
    const recentTransfers: ClassificationTokenTransfer[] = [
      createMockTokenTransfer({
        hash: '0xrecent3' + '0'.repeat(56),
        from: walletAddress,
        to: maliciousDest,
        value: '100000000000000000000',
        tokenAddress: '0x' + 'a'.repeat(40),
        tokenSymbol: 'USDC',
        timestamp: now - 3500,
        isInbound: false,
        isDust: false,
      }),
      createMockTokenTransfer({
        hash: '0xrecent4' + '0'.repeat(56),
        from: walletAddress,
        to: maliciousDest,
        value: '50000000000000000000',
        tokenAddress: '0x' + 'b'.repeat(40),
        tokenSymbol: 'USDT',
        timestamp: now - 3480,
        isInbound: false,
        isDust: false,
      }),
      createMockTokenTransfer({
        hash: '0xrecent5' + '0'.repeat(56),
        from: walletAddress,
        to: maliciousDest,
        value: '25000000000000000000',
        tokenAddress: '0x' + 'c'.repeat(40),
        tokenSymbol: 'DAI',
        timestamp: now - 3460,
        isInbound: false,
        isDust: false,
      }),
    ];
    
    const input = createMockInput({
      walletAddress,
      maliciousAddresses: [maliciousDest],
      transactions: [...historicalTxs, ...recentTxs],
      tokenTransfers: recentTransfers,
      approvals: [], // No approvals - key distinction from approval drainer
    });
    
    const result = await classifyAttack(input);
    
    // Should detect signer compromise due to:
    // - Behavior deviation (sending to new address)
    // - Rapid multi-asset drain
    // - Malicious destination
    // - No approval involvement
    expect(result.type).toBe('SIGNER_COMPROMISE');
    expect(result.confidence).toBeGreaterThan(60);
  });
  
  test('requires multiple signals for signer compromise', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    
    // Just one transaction to unknown address - not enough
    const input = createMockInput({
      walletAddress,
      transactions: [
        createMockTransaction({
          from: walletAddress,
          to: '0xunknown' + '0'.repeat(32),
          value: '1000000000000000000',
          timestamp: Math.floor(Date.now() / 1000) - 3600,
          isInbound: false,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    // Should NOT classify as signer compromise without strong evidence
    expect(result.type).not.toBe('SIGNER_COMPROMISE');
  });
});

// ============================================
// TEST: NO COMPROMISE CLASSIFICATION
// ============================================

describe('No Compromise Classification', () => {
  test('classifies clean wallet as NO_COMPROMISE', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    
    const input = createMockInput({
      walletAddress,
      transactions: [
        // Normal transaction history
        createMockTransaction({
          from: walletAddress,
          to: '0xfriend' + '0'.repeat(34),
          value: '1000000000000000000',
          isInbound: false,
        }),
        createMockTransaction({
          from: '0xfriend' + '0'.repeat(34),
          to: walletAddress,
          value: '500000000000000000',
          isInbound: true,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    expect(result.type).toBe('NO_COMPROMISE');
    expect(result.confidence).toBe(0);
    expect(result.display.severity).toBe('SAFE');
    expect(result.display.badgeColor).toBe('green');
  });
  
  test('empty wallet is NO_COMPROMISE', async () => {
    const input = createMockInput({
      walletAddress: '0x1234567890123456789012345678901234567890',
    });
    
    const result = await classifyAttack(input);
    
    expect(result.type).toBe('NO_COMPROMISE');
  });
});

// ============================================
// TEST: CONFLICT RESOLUTION
// ============================================

describe('Conflict Resolution', () => {
  test('address poisoning takes priority over sweeper when both detected', async () => {
    // This tests the HARD RULE: Never label address poisoning as sweeper bot
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const frequentRecipient = '0xabcd567890123456789012345678901234560000';
    const poisonAddress = '0xabcd111111111111111111111111111111110000';
    const now = Math.floor(Date.now() / 1000);
    
    const input = createMockInput({
      walletAddress,
      frequentRecipients: [frequentRecipient],
      tokenTransfers: [
        // Dust from poisoned address
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000',
          isInbound: true,
          isDust: true,
          timestamp: now - 7200,
        }),
        createMockTokenTransfer({
          from: poisonAddress,
          to: walletAddress,
          value: '1000',
          isInbound: true,
          isDust: true,
          timestamp: now - 3600,
        }),
      ],
      transactions: [
        // Some outbound (could look like sweep if analyzed wrong)
        createMockTransaction({
          from: walletAddress,
          to: '0xother' + '0'.repeat(35),
          value: '100000000000000000',
          isInbound: false,
          timestamp: now - 1800,
        }),
      ],
    });
    
    const result = await classifyAttack(input);
    
    // MUST be address poisoning, NOT sweeper
    expect(result.type).not.toBe('SWEEPER_BOT');
    if (result.type !== 'NO_COMPROMISE') {
      expect(result.type).toBe('ADDRESS_POISONING');
    }
  });
});

// ============================================
// TEST: UX DISPLAY OUTPUT
// ============================================

describe('UX Display Output', () => {
  test('display includes all required fields', async () => {
    const input = createMockInput({
      walletAddress: '0x1234567890123456789012345678901234567890',
    });
    
    const result = await classifyAttack(input);
    
    expect(result.display).toHaveProperty('emoji');
    expect(result.display).toHaveProperty('headline');
    expect(result.display).toHaveProperty('badgeText');
    expect(result.display).toHaveProperty('badgeColor');
    expect(result.display).toHaveProperty('severity');
    expect(result.display).toHaveProperty('summary');
    expect(result.display).toHaveProperty('whatHappened');
    expect(result.display).toHaveProperty('whatDidNotHappen');
    expect(result.display).toHaveProperty('recommendedActions');
    expect(result.display).toHaveProperty('confidenceText');
  });
  
  test('confidence text reflects actual confidence level', async () => {
    const input = createMockInput({
      walletAddress: '0x1234567890123456789012345678901234567890',
    });
    
    const result = await classifyAttack(input);
    
    // For NO_COMPROMISE, confidence should be 0
    expect(result.confidence).toBe(0);
    expect(result.display.confidenceText).toContain('%');
  });
});

// ============================================
// TEST: ENGINE CONFIGURATION
// ============================================

describe('Engine Configuration', () => {
  test('accepts custom configuration', () => {
    const engine = new AttackClassificationEngine({
      sweeperTimeDeltaSeconds: 120, // 2 minutes instead of 60
      addressSimilarityThreshold: 6, // Stricter threshold
    });
    
    const config = engine.getConfig();
    expect(config.sweeperTimeDeltaSeconds).toBe(120);
    expect(config.addressSimilarityThreshold).toBe(6);
  });
  
  test('configuration can be updated', () => {
    const engine = new AttackClassificationEngine();
    
    engine.setConfig({ sweeperTimeDeltaSeconds: 30 });
    
    const config = engine.getConfig();
    expect(config.sweeperTimeDeltaSeconds).toBe(30);
  });
});
