// ============================================
// DRAINER OVERRIDE UNIT TESTS
// ============================================
// Tests for the HARD OVERRIDE rule that ensures active wallet drainers
// are ALWAYS classified as ACTIVE_COMPROMISE_DRAINER.
//
// AFFECTED WALLETS (from bug report):
// These wallets were incorrectly classified as Safe or Previously Compromised.
// After the fix, they MUST be flagged as ACTIVE_COMPROMISE_DRAINER.
//
// 0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74
// 0x463452C356322D463B84891eBDa33DAED274cB40
// 0xa42297ff42a3b65091967945131cd1db962afae4
// 0xe072358070506a4DDA5521B19260011A490a5aaA
// 0xc22b8126ca21616424a22bf012fd1b7cf48f02b1
// 0x109252d00b2fa8c79a74caa96d9194eef6c99581
// 0x30cfa51ffb82727515708ce7dd8c69d121648445
// 0x4735fbecf1db342282ad5baef585ee301b1bce25
// 0xf2dd8eb79625109e2dd87c4243708e1485a85655

import { describe, it, expect } from 'vitest';
import {
  detectDrainerActivity,
  normalizeAddress,
  normalizeAddresses,
  areAddressesEqual,
  RECENCY_LOW_DAYS,
} from '../drainer-activity-detector';
import type {
  TransactionForDrainerAnalysis,
  TokenTransferForDrainerAnalysis,
  ApprovalForDrainerAnalysis,
} from '../drainer-activity-detector';
import type { DrainerOverrideResult, DrainerActivityRecency } from '@/types';

// ============================================
// TEST DATA: Simulated drainer behavior
// ============================================

// Generate timestamps relative to current time
const now = Math.floor(Date.now() / 1000);
const hoursAgo = (hours: number) => now - (hours * 60 * 60);
const daysAgo = (days: number) => now - (days * 24 * 60 * 60);

// Simulated immediate outbound transfer pattern (drainer behavior)
const createImmediateOutboundPattern = (walletAddress: string): {
  transactions: TransactionForDrainerAnalysis[];
  tokenTransfers: TokenTransferForDrainerAnalysis[];
} => {
  const normalized = normalizeAddress(walletAddress);
  const drainerDest = '0x1234567890abcdef1234567890abcdef12345678';
  
  return {
    transactions: [
      // Inbound ETH
      {
        hash: '0xabc1',
        from: '0x0000000000000000000000000000000000000001',
        to: normalized,
        value: '1000000000000000000', // 1 ETH
        input: '0x',
        timestamp: hoursAgo(2),
        blockNumber: 1000,
      },
      // Immediate outbound (30 seconds later)
      {
        hash: '0xabc2',
        from: normalized,
        to: drainerDest,
        value: '990000000000000000', // 0.99 ETH
        input: '0x',
        timestamp: hoursAgo(2) + 30, // 30 seconds after inbound
        blockNumber: 1001,
      },
    ],
    tokenTransfers: [],
  };
};

// Simulated multi-token sweep pattern
const createMultiTokenSweepPattern = (walletAddress: string): {
  transactions: TransactionForDrainerAnalysis[];
  tokenTransfers: TokenTransferForDrainerAnalysis[];
} => {
  const normalized = normalizeAddress(walletAddress);
  const drainerDest = '0x1234567890abcdef1234567890abcdef12345678';
  
  return {
    transactions: [],
    tokenTransfers: [
      // Token 1 sweep
      {
        from: normalized,
        to: drainerDest,
        value: '1000000000000000000',
        hash: '0xdef1',
        timestamp: hoursAgo(1),
        tokenSymbol: 'USDC',
        tokenAddress: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
        blockNumber: 2000,
        tokenType: 'ERC20',
      },
      // Token 2 sweep (same block)
      {
        from: normalized,
        to: drainerDest,
        value: '5000000000000000000',
        hash: '0xdef2',
        timestamp: hoursAgo(1) + 5,
        tokenSymbol: 'WETH',
        tokenAddress: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
        blockNumber: 2000,
        tokenType: 'ERC20',
      },
      // NFT sweep (same block)
      {
        from: normalized,
        to: drainerDest,
        value: '1',
        hash: '0xdef3',
        timestamp: hoursAgo(1) + 10,
        tokenSymbol: 'BAYC',
        tokenAddress: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
        blockNumber: 2001,
        tokenType: 'ERC721',
      },
    ],
  };
};

// Simulated approval-then-drain pattern
const createApprovalDrainPattern = (walletAddress: string): {
  transactions: TransactionForDrainerAnalysis[];
  tokenTransfers: TokenTransferForDrainerAnalysis[];
  approvals: ApprovalForDrainerAnalysis[];
} => {
  const normalized = normalizeAddress(walletAddress);
  const maliciousSpender = '0xdead000000000000000000000000000000000001';
  
  return {
    transactions: [],
    tokenTransfers: [
      // Drain after approval
      {
        from: normalized,
        to: maliciousSpender,
        value: '10000000000000000000',
        hash: '0xghi1',
        timestamp: daysAgo(3) + 120, // 2 minutes after approval
        tokenSymbol: 'USDT',
        tokenAddress: '0xdac17f958d2ee523a2206206994597c13d831ec7',
        blockNumber: 3001,
        tokenType: 'ERC20',
      },
    ],
    approvals: [
      {
        token: '0xdac17f958d2ee523a2206206994597c13d831ec7',
        tokenSymbol: 'USDT',
        spender: maliciousSpender,
        owner: normalized,
        amount: '115792089237316195423570985008687907853269984665640564039457584007913129639935', // Max uint256
        isUnlimited: true,
        timestamp: daysAgo(3),
        transactionHash: '0xghi0',
        blockNumber: 3000,
      },
    ],
  };
};

// ============================================
// UNIT TESTS
// ============================================

describe('DrainerActivityDetector', () => {
  describe('Address Normalization', () => {
    it('should normalize addresses to lowercase', () => {
      const checksumAddr = '0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74';
      const normalized = normalizeAddress(checksumAddr);
      expect(normalized).toBe('0x3b09a3c9add7d0262e6e9724d7e823cd767a0c74');
    });
    
    it('should handle null/undefined addresses', () => {
      expect(normalizeAddress(null)).toBe('');
      expect(normalizeAddress(undefined)).toBe('');
      expect(normalizeAddress('')).toBe('');
    });
    
    it('should correctly compare addresses with different cases', () => {
      const addr1 = '0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74';
      const addr2 = '0x3B09a3c9add7d0262e6e9724d7e823cd767a0c74';
      expect(areAddressesEqual(addr1, addr2)).toBe(true);
    });
    
    it('should normalize array of addresses', () => {
      const addresses = [
        '0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74',
        null,
        '0x463452C356322D463B84891eBDa33DAED274cB40',
        undefined,
      ];
      const normalized = normalizeAddresses(addresses);
      expect(normalized).toHaveLength(2);
      expect(normalized[0]).toBe('0x3b09a3c9add7d0262e6e9724d7e823cd767a0c74');
      expect(normalized[1]).toBe('0x463452c356322d463b84891ebda33daed274cb40');
    });
  });
  
  describe('Immediate Outbound Transfer Detection', () => {
    it('should detect immediate outbound transfers as drainer signal', () => {
      const wallet = '0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      expect(result.shouldOverride).toBe(true);
      expect(result.detectedSignals.length).toBeGreaterThan(0);
      expect(result.detectedSignals.some(s => s.signal === 'IMMEDIATE_OUTBOUND_TRANSFER')).toBe(true);
      expect(result.recency.isActive).toBe(true);
      expect(result.canEverBeSafe).toBe(false);
    });
    
    it('should flag wallet as ACTIVE_COMPROMISE_DRAINER', () => {
      const wallet = '0x463452C356322D463B84891eBDa33DAED274cB40';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      // This MUST trigger the override
      expect(result.shouldOverride).toBe(true);
      expect(result.overrideReason).toContain('ACTIVE DRAINER DETECTED');
    });
  });
  
  describe('Multi-Token Sweep Detection', () => {
    it('should detect multi-token sweeps as drainer signal', () => {
      const wallet = '0xa42297ff42a3b65091967945131cd1db962afae4';
      const { transactions, tokenTransfers } = createMultiTokenSweepPattern(wallet);
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      expect(result.shouldOverride).toBe(true);
      expect(result.detectedSignals.some(s => 
        s.signal === 'ERC20_SWEEP_PATTERN' || 
        s.signal === 'ERC721_SWEEP_PATTERN'
      )).toBe(true);
    });
  });
  
  describe('Approval-Then-Drain Detection', () => {
    it('should detect approval followed by rapid drain', () => {
      const wallet = '0xe072358070506a4DDA5521B19260011A490a5aaA';
      const { transactions, tokenTransfers, approvals } = createApprovalDrainPattern(wallet);
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        approvals,
        now
      );
      
      expect(result.shouldOverride).toBe(true);
      expect(result.detectedSignals.some(s => s.signal === 'APPROVAL_RAPID_DRAIN')).toBe(true);
    });
  });
  
  describe('Recency-Aware Weighting', () => {
    it('should classify <24h activity as CRITICAL', () => {
      const wallet = '0xc22b8126ca21616424a22bf012fd1b7cf48f02b1';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      // Modify both timestamps to be 12 hours ago, keeping the pattern intact
      transactions[0].timestamp = hoursAgo(12);
      transactions[1].timestamp = hoursAgo(12) + 30; // 30 seconds after inbound
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      expect(result.recency.recency).toBe('CRITICAL');
      expect(result.recency.isActive).toBe(true);
      expect(result.recency.confidenceMultiplier).toBe(1.0);
    });
    
    it('should classify <7d activity as HIGH', () => {
      const wallet = '0x109252d00b2fa8c79a74caa96d9194eef6c99581';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      // Modify timestamp to be 3 days ago
      transactions[0].timestamp = daysAgo(3);
      transactions[1].timestamp = daysAgo(3) + 30;
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      expect(result.recency.recency).toBe('HIGH');
      expect(result.recency.isActive).toBe(true);
      expect(result.shouldOverride).toBe(true);
    });
    
    it('should classify <30d activity as MEDIUM', () => {
      const wallet = '0x30cfa51ffb82727515708ce7dd8c69d121648445';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      // Modify timestamp to be 15 days ago
      transactions[0].timestamp = daysAgo(15);
      transactions[1].timestamp = daysAgo(15) + 30;
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      expect(result.recency.recency).toBe('MEDIUM');
      expect(result.recency.isActive).toBe(true);
      expect(result.shouldOverride).toBe(true);
    });
    
    it('should classify <90d activity as LOW but still ACTIVE', () => {
      const wallet = '0x4735fbecf1db342282ad5baef585ee301b1bce25';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      // Modify timestamp to be 60 days ago
      transactions[0].timestamp = daysAgo(60);
      transactions[1].timestamp = daysAgo(60) + 30;
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      expect(result.recency.recency).toBe('LOW');
      expect(result.recency.isActive).toBe(true); // STILL ACTIVE at 60 days
      expect(result.shouldOverride).toBe(true); // STILL TRIGGERS OVERRIDE
    });
    
    it('should classify ≥90d activity as HISTORICAL (not active)', () => {
      const wallet = '0xf2dd8eb79625109e2dd87c4243708e1485a85655';
      const normalized = normalizeAddress(wallet);
      const drainerDest = '0x1234567890abcdef1234567890abcdef12345678';
      
      // Create a historical pattern (100 days ago)
      const transactions: TransactionForDrainerAnalysis[] = [
        // Inbound ETH 100 days ago
        {
          hash: '0xold1',
          from: '0x0000000000000000000000000000000000000001',
          to: normalized,
          value: '1000000000000000000',
          input: '0x',
          timestamp: daysAgo(100),
          blockNumber: 1000,
        },
        // Immediate outbound 30 seconds later (still 100 days ago)
        {
          hash: '0xold2',
          from: normalized,
          to: drainerDest,
          value: '990000000000000000',
          input: '0x',
          timestamp: daysAgo(100) + 30,
          blockNumber: 1001,
        },
      ];
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        [],
        [],
        now
      );
      
      // Activity is 100 days old, so should be historical
      // Note: If no signals detected (because timestamps are too old to be in 90-day window),
      // recency will be 'NONE'. This is expected behavior - the detection window is 90 days.
      // For activity ≥90 days ago, signals are still detected but marked as historical.
      expect(result.recency.isActive).toBe(false);
      expect(result.shouldOverride).toBe(false); // Does NOT override after 90 days
    });
  });
  
  describe('Downgrade Prevention', () => {
    it('should NOT allow downgrade with active approvals', () => {
      const wallet = '0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      const approvals: ApprovalForDrainerAnalysis[] = [
        {
          token: '0xdac17f958d2ee523a2206206994597c13d831ec7',
          tokenSymbol: 'USDT',
          spender: '0xdead000000000000000000000000000000000001',
          owner: normalizeAddress(wallet),
          amount: '115792089237316195423570985008687907853269984665640564039457584007913129639935',
          isUnlimited: true,
          timestamp: daysAgo(30),
          transactionHash: '0xtest',
          blockNumber: 1000,
          wasRevoked: false, // NOT revoked
        },
      ];
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        approvals,
        now
      );
      
      expect(result.downgradeBlockers.some(b => b.includes('active unlimited approval'))).toBe(true);
    });
    
    it('should list all blockers preventing downgrade', () => {
      const wallet = '0x463452C356322D463B84891eBDa33DAED274cB40';
      const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        tokenTransfers,
        [],
        now
      );
      
      expect(result.downgradeBlockers.length).toBeGreaterThan(0);
      expect(result.downgradeBlockers.some(b => b.includes('drainer signal'))).toBe(true);
    });
  });
  
  describe('Safe Contract Exclusion', () => {
    it('should NOT flag transfers to safe contracts as drainer behavior', () => {
      const wallet = '0xa42297ff42a3b65091967945131cd1db962afae4';
      const normalized = normalizeAddress(wallet);
      
      // Transfer to Uniswap router (safe contract)
      const transactions: TransactionForDrainerAnalysis[] = [
        {
          hash: '0xinbound',
          from: '0x0000000000000000000000000000000000000001',
          to: normalized,
          value: '1000000000000000000',
          input: '0x',
          timestamp: hoursAgo(2),
          blockNumber: 1000,
        },
        {
          hash: '0xswap',
          from: normalized,
          to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap V2 Router
          value: '990000000000000000',
          input: '0x38ed1739', // swapExactTokensForTokens
          timestamp: hoursAgo(2) + 30, // 30 seconds after - would normally be flagged
          blockNumber: 1001,
        },
      ];
      
      const result = detectDrainerActivity(
        wallet,
        'ethereum',
        transactions,
        [],
        [],
        now
      );
      
      // Should NOT be flagged because destination is safe contract
      expect(result.detectedSignals.length).toBe(0);
      expect(result.shouldOverride).toBe(false);
      expect(result.canEverBeSafe).toBe(true);
    });
  });
  
  describe('Affected Wallet Addresses', () => {
    // These are the specific wallets from the bug report
    const affectedWallets = [
      '0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74',
      '0x463452C356322D463B84891eBDa33DAED274cB40',
      '0xa42297ff42a3b65091967945131cd1db962afae4',
      '0xe072358070506a4DDA5521B19260011A490a5aaA',
      '0xc22b8126ca21616424a22bf012fd1b7cf48f02b1',
      '0x109252d00b2fa8c79a74caa96d9194eef6c99581',
      '0x30cfa51ffb82727515708ce7dd8c69d121648445',
      '0x4735fbecf1db342282ad5baef585ee301b1bce25',
      '0xf2dd8eb79625109e2dd87c4243708e1485a85655',
    ];
    
    it.each(affectedWallets)(
      'should correctly detect drainer pattern for wallet %s with drainer behavior',
      (wallet) => {
        const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
        
        const result = detectDrainerActivity(
          wallet,
          'ethereum',
          transactions,
          tokenTransfers,
          [],
          now
        );
        
        // With drainer behavior pattern, MUST trigger override
        expect(result.shouldOverride).toBe(true);
        expect(result.detectedSignals.length).toBeGreaterThan(0);
        expect(result.canEverBeSafe).toBe(false);
        expect(result.overrideReason).toContain('ACTIVE DRAINER DETECTED');
      }
    );
    
    it('should normalize all affected addresses correctly', () => {
      for (const wallet of affectedWallets) {
        const normalized = normalizeAddress(wallet);
        expect(normalized).toBe(wallet.toLowerCase());
        expect(normalized).toMatch(/^0x[a-f0-9]{40}$/);
      }
    });
  });
});

describe('Hard Override Rule Enforcement', () => {
  it('should NEVER allow SAFE status with active drainer signals', () => {
    const wallet = '0x3b09A3c9aDD7D0262e6E9724D7e823Cd767a0c74';
    const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
    
    const result = detectDrainerActivity(
      wallet,
      'ethereum',
      transactions,
      tokenTransfers,
      [],
      now
    );
    
    // With active signals, canEverBeSafe MUST be false
    expect(result.canEverBeSafe).toBe(false);
    expect(result.shouldOverride).toBe(true);
  });
  
  it('should NEVER allow PREVIOUSLY_COMPROMISED status with <90 day activity', () => {
    const wallet = '0x463452C356322D463B84891eBDa33DAED274cB40';
    const { transactions, tokenTransfers } = createImmediateOutboundPattern(wallet);
    // Set activity to 30 days ago
    transactions[0].timestamp = daysAgo(30);
    transactions[1].timestamp = daysAgo(30) + 30;
    
    const result = detectDrainerActivity(
      wallet,
      'ethereum',
      transactions,
      tokenTransfers,
      [],
      now
    );
    
    // At 30 days, still active - cannot be "Previously Compromised"
    expect(result.recency.isActive).toBe(true);
    expect(result.canBePreviouslyCompromised).toBe(false);
    expect(result.shouldOverride).toBe(true);
  });
  
  it('should provide clear override reason explaining why classification cannot change', () => {
    const wallet = '0xa42297ff42a3b65091967945131cd1db962afae4';
    const { transactions, tokenTransfers } = createMultiTokenSweepPattern(wallet);
    
    const result = detectDrainerActivity(
      wallet,
      'ethereum',
      transactions,
      tokenTransfers,
      [],
      now
    );
    
    expect(result.overrideReason).toBeTruthy();
    expect(result.overrideReason).toContain('ACTIVE DRAINER DETECTED');
    expect(result.overrideReason).toContain('ACTIVE_COMPROMISE_DRAINER');
  });
});

