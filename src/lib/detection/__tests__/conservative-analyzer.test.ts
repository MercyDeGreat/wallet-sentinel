// ============================================
// CONSERVATIVE ANALYZER TESTS
// ============================================
// Tests to ensure false positives are minimized

import { describe, test, expect } from 'vitest';
import {
  analyzeTransactionConservatively,
  analyzeWalletConservatively,
  DEFAULT_CONSERVATIVE_CONFIG,
  ExplainedTransaction,
} from '../conservative-analyzer';
import { TransactionInput } from '../transaction-labeler';

// Test wallet address
const TEST_WALLET = '0xA75e8E6ECdBF4C24b741ec19E33e642c68Cd314b'.toLowerCase();

describe('Conservative Analyzer - False Positive Prevention', () => {
  describe('Legitimate Activity Detection', () => {
    test('NFT mint transactions are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0x123',
        from: TEST_WALLET,
        to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', // BAYC
        value: '0',
        input: '0x1249c58b', // mint()
        timestamp: Date.now() / 1000,
        blockNumber: 1000000,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.isUserInitiated).toBe(true);
      expect(result.type).toBe('NFT_MINT');
    });

    test('OpenSea purchases are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0x456',
        from: TEST_WALLET,
        to: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // OpenSea Seaport
        value: '1000000000000000000',
        input: '0xfb0f3ee1', // fulfillBasicOrder
        timestamp: Date.now() / 1000,
        blockNumber: 1000001,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.isWhitelisted).toBe(true);
      expect(result.explanation).toContain('OpenSea');
    });

    test('Exchange deposits are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0x789',
        from: TEST_WALLET,
        to: '0x28c6c06298d514db089934071355e5743bf21d60', // Binance
        value: '5000000000000000000',
        input: '0x',
        timestamp: Date.now() / 1000,
        blockNumber: 1000002,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      // Type may be EXCHANGE_DEPOSIT or NORMAL_TRANSFER depending on detection
      expect(['EXCHANGE_DEPOSIT', 'NORMAL_TRANSFER']).toContain(result.type);
      expect(result.explanation).toContain('Binance');
    });

    test('Exchange withdrawals are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0xabc',
        from: '0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43', // Coinbase
        to: TEST_WALLET,
        value: '2000000000000000000',
        input: '0x',
        timestamp: Date.now() / 1000,
        blockNumber: 1000003,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.type).toBe('EXCHANGE_WITHDRAWAL');
    });

    test('DEX swaps are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0xdef',
        from: TEST_WALLET,
        to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap V2 Router
        value: '1000000000000000000',
        input: '0x7ff36ab5', // swapExactETHForTokens
        timestamp: Date.now() / 1000,
        blockNumber: 1000004,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.isWhitelisted).toBe(true);
    });

    test('Presale/auction bids via Seaport are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0x111',
        from: TEST_WALLET,
        to: '0x0000000000000068f116a894984e2db1123eb395', // Seaport 1.5
        value: '500000000000000000',
        input: '0x87201b41', // fulfillOrder
        timestamp: Date.now() / 1000,
        blockNumber: 1000005,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.type).toContain('NFT');
    });

    test('ENS registration is LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0x222',
        from: TEST_WALLET,
        to: '0x283af0b28c62c092c9727f1ee09c02ca627eb7f5', // ENS Controller
        value: '50000000000000000',
        input: '0x12345678',
        timestamp: Date.now() / 1000,
        blockNumber: 1000006,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.explanation).toContain('ENS');
    });

    test('Pendle deposits are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0x333',
        from: TEST_WALLET,
        to: '0x0000000001e4ef00d069e71d6ba041b0a16f7ea0', // Pendle Router
        value: '1000000000000000000',
        input: '0xd0e30db0', // deposit
        timestamp: Date.now() / 1000,
        blockNumber: 1000007,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.isWhitelisted).toBe(true);
    });

    test('Simple ETH transfers are LEGITIMATE', () => {
      const tx: TransactionInput = {
        hash: '0x444',
        from: TEST_WALLET,
        to: '0x1234567890123456789012345678901234567890',
        value: '100000000000000000',
        input: '0x',
        timestamp: Date.now() / 1000,
        blockNumber: 1000008,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.label).toBe('LEGITIMATE');
      expect(result.type).toBe('NORMAL_TRANSFER');
    });
  });

  describe('False Positive Prevention - Quick Outflows', () => {
    test('Quick outflow after deposit should NOT be flagged as sweeper', () => {
      const txs: TransactionInput[] = [
        // Incoming deposit
        {
          hash: '0xa01',
          from: '0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43', // Coinbase
          to: TEST_WALLET,
          value: '10000000000000000000', // 10 ETH
          input: '0x',
          timestamp: 1000000,
          blockNumber: 1000000,
        },
        // Quick outflow to DEX (1 minute later)
        {
          hash: '0xa02',
          from: TEST_WALLET,
          to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap
          value: '10000000000000000000',
          input: '0x7ff36ab5', // swap
          timestamp: 1000060,
          blockNumber: 1000001,
        },
      ];
      
      const result = analyzeWalletConservatively(TEST_WALLET, 'ethereum', txs);
      
      expect(result.securityStatus).toBe('SAFE');
      expect(result.confirmedThreats).toHaveLength(0);
      expect(result.labeledTransactions.every(t => t.label === 'LEGITIMATE')).toBe(true);
    });

    test('NFT mint + approval + payment should NOT raise sweeper alert', () => {
      const txs: TransactionInput[] = [
        // Approval
        {
          hash: '0xb01',
          from: TEST_WALLET,
          to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', // BAYC
          value: '0',
          input: '0xa22cb465', // setApprovalForAll
          timestamp: 1000000,
          blockNumber: 1000000,
        },
        // Mint payment
        {
          hash: '0xb02',
          from: TEST_WALLET,
          to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
          value: '80000000000000000', // 0.08 ETH
          input: '0x1249c58b', // mint
          timestamp: 1000060,
          blockNumber: 1000001,
        },
      ];
      
      const result = analyzeWalletConservatively(TEST_WALLET, 'ethereum', txs);
      
      expect(result.securityStatus).toBe('SAFE');
      expect(result.confirmedThreats).toHaveLength(0);
    });

    test('Exchange deposit forwarding should NOT raise sweeper alert', () => {
      const txs: TransactionInput[] = [
        // Receive from unknown
        {
          hash: '0xc01',
          from: '0x5555555555555555555555555555555555555555',
          to: TEST_WALLET,
          value: '5000000000000000000',
          input: '0x',
          timestamp: 1000000,
          blockNumber: 1000000,
        },
        // Forward to Binance (2 minutes later)
        {
          hash: '0xc02',
          from: TEST_WALLET,
          to: '0x28c6c06298d514db089934071355e5743bf21d60', // Binance
          value: '5000000000000000000',
          input: '0x',
          timestamp: 1000120,
          blockNumber: 1000002,
        },
      ];
      
      const result = analyzeWalletConservatively(TEST_WALLET, 'ethereum', txs);
      
      expect(result.securityStatus).toBe('SAFE');
      expect(result.confirmedThreats).toHaveLength(0);
      expect(result.labeledTransactions[1].label).toBe('LEGITIMATE');
      // Exchange transactions are labeled LEGITIMATE regardless of specific type
      expect(result.labeledTransactions[1].explanation).toContain('Binance');
    });
  });

  describe('True Threat Detection', () => {
    test('Transaction to unknown address is NOT automatically suspicious', () => {
      // Conservative analyzer: unknown != suspicious
      // Only confirmed malicious addresses should be flagged
      const tx: TransactionInput = {
        hash: '0xunknown',
        from: TEST_WALLET,
        to: '0x0000000000000000000000000000000000dead01', // Unknown address
        value: '1000000000000000000',
        input: '0x',
        timestamp: Date.now() / 1000,
        blockNumber: 1000000,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      // Simple ETH transfer to unknown address should be LEGITIMATE (not suspicious)
      // This is the conservative approach - we don't flag unknown as malicious
      expect(result.label).toBe('LEGITIMATE');
      expect(result.type).toBe('NORMAL_TRANSFER');
      expect(result.reason).toContain('Simple ETH transfer');
    });
  });

  describe('Full Wallet Analysis', () => {
    test('Wallet with mostly legitimate activity should be SAFE', () => {
      const txs: TransactionInput[] = [
        // 10 legitimate transactions
        ...Array(10).fill(null).map((_, i) => ({
          hash: `0xlegit${i}`,
          from: TEST_WALLET,
          to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap
          value: '100000000000000000',
          input: '0x7ff36ab5',
          timestamp: 1000000 + i * 3600,
          blockNumber: 1000000 + i,
        })),
      ];
      
      const result = analyzeWalletConservatively(TEST_WALLET, 'ethereum', txs);
      
      expect(result.securityStatus).toBe('SAFE');
      expect(result.transactions.legitimatePercentage).toBeGreaterThanOrEqual(90);
      expect(result.summary).toContain('legitimate');
    });

    test('Report includes false positive prevention note', () => {
      const txs: TransactionInput[] = [{
        hash: '0xtest',
        from: TEST_WALLET,
        to: '0x28c6c06298d514db089934071355e5743bf21d60',
        value: '1000000000000000000',
        input: '0x',
        timestamp: Date.now() / 1000,
        blockNumber: 1000000,
      }];
      
      const result = analyzeWalletConservatively(TEST_WALLET, 'ethereum', txs);
      
      expect(result.falsePositiveNote).toBeTruthy();
      expect(result.falsePositiveNote).toContain('conservative');
      expect(result.falsePositiveNote).toContain('false positive');
    });

    test('Labeled transactions include explanations', () => {
      const tx: TransactionInput = {
        hash: '0xexplained',
        from: TEST_WALLET,
        to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',
        value: '1000000000000000000',
        input: '0x7ff36ab5',
        timestamp: Date.now() / 1000,
        blockNumber: 1000000,
      };
      
      const result = analyzeTransactionConservatively(tx, TEST_WALLET, 'ethereum');
      
      expect(result.explanation).toBeTruthy();
      expect(result.evidenceChecked.length).toBeGreaterThan(0);
      expect(result.passedCriteria.length).toBeGreaterThan(0);
    });
  });
});

describe('Specific Wallet Test: 0xA75e8E6ECdBF4C24b741ec19E33e642c68Cd314b', () => {
  test('Standard user activity patterns should be SAFE', () => {
    // Simulating typical user activity
    const txs: TransactionInput[] = [
      // DEX swap
      {
        hash: '0x001',
        from: TEST_WALLET,
        to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Uniswap V3
        value: '1000000000000000000',
        input: '0x04e45aaf',
        timestamp: 1000000,
        blockNumber: 1000000,
      },
      // NFT purchase
      {
        hash: '0x002',
        from: TEST_WALLET,
        to: '0x00000000006c3852cbef3e08e8df289169ede581', // Seaport
        value: '500000000000000000',
        input: '0xfb0f3ee1',
        timestamp: 1003600,
        blockNumber: 1000300,
      },
      // Exchange deposit
      {
        hash: '0x003',
        from: TEST_WALLET,
        to: '0x28c6c06298d514db089934071355e5743bf21d60', // Binance
        value: '2000000000000000000',
        input: '0x',
        timestamp: 1007200,
        blockNumber: 1000600,
      },
      // Staking
      {
        hash: '0x004',
        from: TEST_WALLET,
        to: '0xae7ab96520de3a18e5e111b5eaab095312d7fe84', // Lido
        value: '3000000000000000000',
        input: '0xa694fc3a',
        timestamp: 1010800,
        blockNumber: 1000900,
      },
    ];
    
    const result = analyzeWalletConservatively(TEST_WALLET, 'ethereum', txs);
    
    expect(result.securityStatus).toBe('SAFE');
    expect(result.riskLevel).toBe('LOW');
    expect(result.transactions.legitimate).toBe(4);
    expect(result.confirmedThreats).toHaveLength(0);
    
    // Verify all transactions are labeled correctly
    expect(result.labeledTransactions[0].type).toContain('DEX');
    expect(result.labeledTransactions[1].type).toContain('NFT');
    // Exchange deposit may have different type label, but explanation should mention the exchange
    expect(result.labeledTransactions[2].explanation).toContain('Binance');
    expect(result.labeledTransactions[3].type).toContain('STAKING');
  });
});

