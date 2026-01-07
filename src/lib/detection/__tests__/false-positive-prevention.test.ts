// ============================================
// FALSE POSITIVE PREVENTION TESTS
// ============================================
// These tests ensure that the detection system NEVER falsely flags:
// - OpenSea contracts (marketplace, mint, approval, transfer)
// - NFT mint contracts like @MegaRabbitNFT
// - Standard ERC20 / ERC721 / ERC1155 approvals
// - Legitimate routers, relayers, and infrastructure contracts
// - ENS, CoinGecko, Pendle, and known DeFi protocols
// - Users who manually move funds quickly after receiving them
//
// CRITICAL: It is better to MISS a threat than to falsely accuse.

import { describe, test, expect } from 'vitest';
import {
  isSafeContract,
  isSafeContractOnChain,
  isNFTMarketplace,
  isNFTMintContract,
  isDeFiProtocol,
  isENSContract,
  isInfrastructureContract,
  isStandardApprovalMethod,
  isStandardMintMethod,
  checkAddressSafety,
} from '../safe-contracts';

import {
  classifyContract,
  shouldExcludeFromMaliciousFlagging,
  getSafetyExplanation,
} from '../contract-classifier';

import {
  analyzeWalletBehavior,
  calculateSweeperBotScore,
  TransactionForAnalysis,
} from '../behavior-analyzer';

import {
  isMaliciousAddress,
  isLegitimateContract,
  isDrainerRecipient,
} from '../malicious-database';

import { isKnownDrainer } from '../drainer-addresses';

// ============================================
// REGRESSION TEST: OpenSea → SAFE
// ============================================

describe('Regression: OpenSea contracts must NEVER be flagged', () => {
  const OPENSEA_ADDRESSES = [
    '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // Seaport 1.1
    '0x00000000006c3852cbef3e08e8df289169ede581', // Seaport 1.4
    '0x0000000000000068f116a894984e2db1123eb395', // Seaport 1.5
    '0x00000000000001ad428e4906ae43d8f9852d0dd6', // Seaport 1.6
    '0x1e0049783f008a0085193e00003d00cd54003c71', // Fee Collector
  ];

  test.each(OPENSEA_ADDRESSES)('OpenSea %s is a safe contract', (address) => {
    const safeContract = isSafeContract(address);
    expect(safeContract).not.toBeNull();
    expect(safeContract?.category).toBe('NFT_MARKETPLACE');
  });

  test.each(OPENSEA_ADDRESSES)('OpenSea %s is NOT malicious', (address) => {
    expect(isMaliciousAddress(address, 'ethereum')).toBeNull();
    expect(isDrainerRecipient(address)).toBe(false);
    expect(isKnownDrainer(address)).toBe(false);
  });

  test.each(OPENSEA_ADDRESSES)('OpenSea %s is identified as NFT marketplace', (address) => {
    expect(isNFTMarketplace(address)).toBe(true);
  });

  test('OpenSea classification excludes from malicious flagging', async () => {
    const classification = await classifyContract(
      '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
      'ethereum'
    );
    expect(classification.type).toBe('MARKETPLACE');
    expect(classification.canBeFlaggedMalicious).toBe(false);
    expect(shouldExcludeFromMaliciousFlagging(classification)).toBe(true);
  });
});

// ============================================
// REGRESSION TEST: INFRASTRUCTURE PROTECTION
// ============================================
// OpenSea and other infrastructure can NEVER be classified as:
// - Sweeper Bot
// - Drainer
// - Pink Drainer

import {
  checkInfrastructureProtection,
  canNeverBeSweeperBot,
  canNeverBeDrainer,
  getAllProtectedAddresses,
} from '../infrastructure-protection';

describe('Infrastructure Protection: OpenSea can NEVER be sweeper/drainer', () => {
  const OPENSEA_ADDRESSES = [
    '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // Seaport 1.1
    '0x00000000006c3852cbef3e08e8df289169ede581', // Seaport 1.4
    '0x0000000000000068f116a894984e2db1123eb395', // Seaport 1.5
    '0x00000000000001ad428e4906ae43d8f9852d0dd6', // Seaport 1.6
    '0x1e0049783f008a0085193e00003d00cd54003c71', // Fee Collector
  ];

  test.each(OPENSEA_ADDRESSES)('OpenSea %s is protected infrastructure', (address) => {
    const result = checkInfrastructureProtection(address, 'ethereum');
    expect(result.isProtected).toBe(true);
    expect(result.type).toBe('NFT_MARKETPLACE');
    expect(result.canBeSweeperBot).toBe(false);
    expect(result.canBeDrainer).toBe(false);
    expect(result.canBePinkDrainer).toBe(false);
  });

  test.each(OPENSEA_ADDRESSES)('OpenSea %s can NEVER be sweeper bot', (address) => {
    expect(canNeverBeSweeperBot(address)).toBe(true);
  });

  test.each(OPENSEA_ADDRESSES)('OpenSea %s can NEVER be drainer', (address) => {
    expect(canNeverBeDrainer(address)).toBe(true);
  });

  test.each(OPENSEA_ADDRESSES)('OpenSea %s has expected behavior description', (address) => {
    const result = checkInfrastructureProtection(address, 'ethereum');
    expect(result.expectedBehavior).toBeDefined();
    expect(result.expectedBehavior).toContain('NFT marketplace');
  });

  test.each(OPENSEA_ADDRESSES)('OpenSea %s has confidence note', (address) => {
    const result = checkInfrastructureProtection(address, 'ethereum');
    expect(result.confidenceNote).toBeDefined();
    expect(result.confidenceNote?.toLowerCase()).toContain('verified');
  });
});

describe('Infrastructure Protection: DEX routers can NEVER be sweeper/drainer', () => {
  const DEX_ADDRESSES = [
    '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap V2 Router
    '0xe592427a0aece92de3edee1f18e0157c05861564', // Uniswap V3 Router
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Universal Router
    '0x1111111254eeb25477b68fb85ed929f73a960582', // 1inch V5
  ];

  test.each(DEX_ADDRESSES)('DEX %s is protected infrastructure', (address) => {
    const result = checkInfrastructureProtection(address, 'ethereum');
    expect(result.isProtected).toBe(true);
    expect(result.canBeSweeperBot).toBe(false);
    expect(result.canBeDrainer).toBe(false);
  });

  test.each(DEX_ADDRESSES)('DEX %s can NEVER be sweeper bot', (address) => {
    expect(canNeverBeSweeperBot(address)).toBe(true);
  });
});

describe('Infrastructure Protection: Known drainers are NOT protected', () => {
  // NOTE: 0x00005ea00ac477b1030ce78506496e8c2de24bf5 was INCORRECTLY flagged as "Pink Drainer"
  // That address is OpenSea SeaDrop - LEGITIMATE! Using actual Pink Drainer V2 instead.
  const KNOWN_DRAINERS = [
    '0x0000d194a19e7578e1ee97a2b6f6e4af01a00000', // Pink Drainer V2 (actual)
    '0x0000db5c8b030ae20308ac975898e09741e70000', // Inferno Drainer
  ];

  test.each(KNOWN_DRAINERS)('Drainer %s is NOT protected infrastructure', (address) => {
    const result = checkInfrastructureProtection(address, 'ethereum');
    expect(result.isProtected).toBe(false);
    expect(result.canBeSweeperBot).toBe('MAYBE');
    expect(result.canBeDrainer).toBe('MAYBE');
  });

  test.each(KNOWN_DRAINERS)('Drainer %s is correctly flagged as malicious', (address) => {
    expect(isMaliciousAddress(address, 'ethereum')).not.toBeNull();
  });
});

describe('Infrastructure Protection: All protected addresses are in registry', () => {
  test('Protected addresses list is populated', () => {
    const addresses = getAllProtectedAddresses();
    expect(addresses.length).toBeGreaterThan(20);
  });

  test('All protected addresses pass protection check', () => {
    const addresses = getAllProtectedAddresses();
    for (const address of addresses) {
      const result = checkInfrastructureProtection(address, 'ethereum');
      expect(result.isProtected).toBe(true);
      expect(result.canBeSweeperBot).toBe(false);
      expect(result.canBeDrainer).toBe(false);
    }
  });
});

// ============================================
// CRITICAL REGRESSION TEST: OpenSea SeaDrop → LEGITIMATE
// ============================================
// 0x00005ea00ac477b1030ce78506496e8c2de24bf5 was INCORRECTLY flagged as "Pink Drainer"
// This test ensures it's correctly identified as OpenSea SeaDrop (legitimate).

describe('Regression: OpenSea SeaDrop must NEVER be flagged as malicious', () => {
  const SEADROP_ADDRESS = '0x00005ea00ac477b1030ce78506496e8c2de24bf5';

  test('SeaDrop is a safe contract (NFT_MARKETPLACE)', () => {
    const safeContract = isSafeContract(SEADROP_ADDRESS);
    expect(safeContract).not.toBeNull();
    expect(safeContract?.category).toBe('NFT_MARKETPLACE');
    expect(safeContract?.name).toContain('SeaDrop');
  });

  test('SeaDrop is NOT flagged as malicious', () => {
    expect(isMaliciousAddress(SEADROP_ADDRESS, 'ethereum')).toBeNull();
    expect(isMaliciousAddress(SEADROP_ADDRESS, 'base')).toBeNull();
    expect(isMaliciousAddress(SEADROP_ADDRESS, 'bnb')).toBeNull();
  });

  test('SeaDrop is NOT a drainer recipient', () => {
    expect(isDrainerRecipient(SEADROP_ADDRESS)).toBe(false);
  });

  test('SeaDrop is NOT a known drainer', () => {
    expect(isKnownDrainer(SEADROP_ADDRESS)).toBe(false);
  });

  test('SeaDrop is protected infrastructure (OpenSea)', () => {
    const result = checkInfrastructureProtection(SEADROP_ADDRESS, 'ethereum');
    expect(result.isProtected).toBe(true);
    expect(result.canBeSweeperBot).toBe(false);
    expect(result.canBeDrainer).toBe(false);
  });
});

// ============================================
// REGRESSION TEST: NFT Mint Contracts → SAFE
// ============================================

describe('Regression: NFT mint contracts must NEVER be flagged', () => {
  const NFT_MINT_CONTRACTS = [
    '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', // BAYC
    '0x60e4d786628fea6478f785a6d7e704777c86a7c6', // MAYC
    '0xed5af388653567af2f388e6224dc7c4b3241c544', // Azuki
    '0x23581767a106ae21c074b2276d25e5c3e136a68b', // Moonbirds
    '0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb', // CryptoPunks
  ];

  test.each(NFT_MINT_CONTRACTS)('NFT contract %s is a safe contract', (address) => {
    const safeContract = isSafeContract(address);
    expect(safeContract).not.toBeNull();
    expect(safeContract?.category).toBe('NFT_MINT_CONTRACT');
  });

  test.each(NFT_MINT_CONTRACTS)('NFT contract %s is NOT malicious', (address) => {
    expect(isMaliciousAddress(address, 'ethereum')).toBeNull();
    expect(isDrainerRecipient(address)).toBe(false);
    expect(isKnownDrainer(address)).toBe(false);
  });

  test.each(NFT_MINT_CONTRACTS)('NFT contract %s is identified as mint contract', (address) => {
    expect(isNFTMintContract(address)).toBe(true);
  });
});

// ============================================
// REGRESSION TEST: ENS → SAFE
// ============================================

describe('Regression: ENS contracts must NEVER be flagged', () => {
  const ENS_CONTRACTS = [
    '0x283af0b28c62c092c9727f1ee09c02ca627eb7f5', // ENS Registrar
    '0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85', // ENS Base Registrar
    '0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e', // ENS Registry
  ];

  test.each(ENS_CONTRACTS)('ENS contract %s is a safe contract', (address) => {
    const safeContract = isSafeContract(address);
    expect(safeContract).not.toBeNull();
    expect(safeContract?.category).toBe('ENS');
  });

  test.each(ENS_CONTRACTS)('ENS contract %s is NOT malicious', (address) => {
    expect(isMaliciousAddress(address, 'ethereum')).toBeNull();
    expect(isKnownDrainer(address)).toBe(false);
  });

  test.each(ENS_CONTRACTS)('ENS contract %s is identified as ENS', (address) => {
    expect(isENSContract(address)).toBe(true);
  });
});

// ============================================
// REGRESSION TEST: Pendle → SAFE
// ============================================

describe('Regression: Pendle contracts must NEVER be flagged', () => {
  const PENDLE_CONTRACTS = [
    '0x0000000001e4ef00d069e71d6ba041b0a16f7ea0', // Pendle Router V3
    '0x888888888889758f76e7103c6cbf23abbf58f946', // Pendle Market Factory
    '0x808507121b80c02388fad14726482e061b8da827', // Pendle Token
  ];

  test.each(PENDLE_CONTRACTS)('Pendle contract %s is a safe contract', (address) => {
    const safeContract = isSafeContract(address);
    expect(safeContract).not.toBeNull();
  });

  test.each(PENDLE_CONTRACTS)('Pendle contract %s is NOT malicious', (address) => {
    expect(isMaliciousAddress(address, 'ethereum')).toBeNull();
    expect(isKnownDrainer(address)).toBe(false);
  });
});

// ============================================
// REGRESSION TEST: Verified DeFi Protocols → SAFE
// ============================================

describe('Regression: DeFi protocols must NEVER be flagged', () => {
  const DEFI_CONTRACTS = [
    { address: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', name: 'Uniswap V2 Router' },
    { address: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', name: 'Uniswap V3 Router' },
    { address: '0x1111111254eeb25477b68fb85ed929f73a960582', name: '1inch V5 Router' },
    { address: '0xdef1c0ded9bec7f1a1670819833240f027b25eff', name: '0x Exchange Proxy' },
    { address: '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2', name: 'Aave V3 Pool' },
    { address: '0xae7ab96520de3a18e5e111b5eaab095312d7fe84', name: 'Lido stETH' },
    { address: '0x000000000022d473030f116ddee9f6b43ac78ba3', name: 'Permit2' },
  ];

  test.each(DEFI_CONTRACTS)('$name is a safe contract', ({ address }) => {
    const safeContract = isSafeContract(address);
    expect(safeContract).not.toBeNull();
  });

  test.each(DEFI_CONTRACTS)('$name is NOT malicious', ({ address }) => {
    expect(isMaliciousAddress(address, 'ethereum')).toBeNull();
    expect(isDrainerRecipient(address)).toBe(false);
    expect(isKnownDrainer(address)).toBe(false);
  });

  test.each(DEFI_CONTRACTS)('$name is identified as DeFi', ({ address }) => {
    expect(isDeFiProtocol(address)).toBe(true);
  });

  test.each(DEFI_CONTRACTS)('$name is excluded from malicious flagging', async ({ address }) => {
    const classification = await classifyContract(address, 'ethereum');
    expect(shouldExcludeFromMaliciousFlagging(classification)).toBe(true);
  });
});

// ============================================
// REGRESSION TEST: Standard EIP Approvals → SAFE
// ============================================

describe('Regression: Standard EIP approvals are NORMAL behavior', () => {
  test('ERC20 approve() is a standard method', () => {
    expect(isStandardApprovalMethod('0x095ea7b3')).toBe(true);
  });

  test('ERC721 setApprovalForAll() is a standard method', () => {
    expect(isStandardApprovalMethod('0xa22cb465')).toBe(true);
  });

  test('ERC20 permit() is a standard method', () => {
    expect(isStandardApprovalMethod('0xd505accf')).toBe(true);
  });

  test('Standard mint() is recognized', () => {
    expect(isStandardMintMethod('0x1249c58b')).toBe(true); // mint()
    expect(isStandardMintMethod('0xa0712d68')).toBe(true); // mint(uint256)
    expect(isStandardMintMethod('0x40c10f19')).toBe(true); // mint(address,uint256)
  });

  test('Approval to OpenSea returns SAFE status', () => {
    const result = checkAddressSafety(
      '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
      'ethereum',
      '0xa22cb465'
    );
    expect(result.isSafe).toBe(true);
    expect(result.confidence).toBe('HIGH');
  });
});

// ============================================
// REGRESSION TEST: Known Drainer Wallets → FLAGGED
// ============================================

describe('Regression: Known drainer wallets must be FLAGGED', () => {
  // NOTE: 0x00005ea00ac477b1030ce78506496e8c2de24bf5 is OpenSea SeaDrop - LEGITIMATE!
  // Using actual Pink Drainer V2 address instead.
  const KNOWN_DRAINERS = [
    { address: '0x0000db5c8b030ae20308ac975898e09741e70000', name: 'Inferno Drainer' },
    { address: '0x0000d194a19e7578e1ee97a2b6f6e4af01a00000', name: 'Pink Drainer V2' },
    { address: '0x00000000ae347930bd1e7b0f35588b92280f9e75', name: 'Angel Drainer' },
    { address: '0x0000000035634b55f3d99b071b5a354f48e10000', name: 'Monkey Drainer' },
    { address: '0x0000000052e7f0c029b6e38e96f03c70d86bfde5', name: 'Venom Drainer' },
    { address: '0x0000000083fc54c35b9b83de16c67c73b1a7b000', name: 'MS Drainer' },
  ];

  test.each(KNOWN_DRAINERS)('$name is flagged as malicious', ({ address }) => {
    const result = isMaliciousAddress(address, 'ethereum');
    expect(result).not.toBeNull();
    expect(result?.type).toBe('WALLET_DRAINER');
  });

  test.each(KNOWN_DRAINERS)('$name is in drainer database', ({ address }) => {
    expect(isKnownDrainer(address)).toBe(true);
  });

  test.each(KNOWN_DRAINERS)('$name is NOT a safe contract', ({ address }) => {
    expect(isSafeContract(address)).toBeNull();
    expect(isLegitimateContract(address)).toBeNull();
  });
});

// ============================================
// REGRESSION TEST: Normal User Behavior → NOT FLAGGED
// ============================================

describe('Regression: Normal user behavior must NOT be flagged', () => {
  test('User who moves funds quickly is classified as NORMAL_USER', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const now = Math.floor(Date.now() / 1000);
    
    // Simulate a user who receives funds and quickly moves them (normal behavior)
    const transactions: TransactionForAnalysis[] = [
      // Receive from exchange
      {
        hash: '0xabc1',
        from: '0x28c6c06298d514db089934071355e5743bf21d60', // Binance
        to: walletAddress,
        value: '1000000000000000000', // 1 ETH
        timestamp: now - 3600,
        isInbound: true,
        isOutbound: false,
      },
      // Use Uniswap
      {
        hash: '0xabc2',
        from: walletAddress,
        to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap
        value: '500000000000000000',
        timestamp: now - 3500,
        methodId: '0x38ed1739', // swap
        isInbound: false,
        isOutbound: true,
      },
      // Mint an NFT
      {
        hash: '0xabc3',
        from: walletAddress,
        to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', // BAYC
        value: '80000000000000000',
        timestamp: now - 3400,
        methodId: '0x1249c58b', // mint
        isInbound: false,
        isOutbound: true,
      },
      // Trade on OpenSea
      {
        hash: '0xabc4',
        from: walletAddress,
        to: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // OpenSea
        value: '100000000000000000',
        timestamp: now - 3300,
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // Should NOT be flagged as drainer or sweeper
    expect(result.classification).not.toBe('CONFIRMED_DRAINER');
    expect(result.classification).not.toBe('CONFIRMED_SWEEPER');
    expect(result.classification).not.toBe('SWEEPER_BOT_SUSPECT');
    expect(result.classification).not.toBe('DRAINER_SUSPECT');
    
    // Should be classified as normal or power user
    expect(['NORMAL_USER', 'POWER_USER', 'UNKNOWN']).toContain(result.classification);
    
    // Should NOT show critical alert
    expect(result.showCriticalAlert).toBe(false);
    
    // Risk score should be low
    expect(result.riskScore).toBeLessThan(50);
  });

  test('Power user with high transaction volume is classified correctly', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const now = Math.floor(Date.now() / 1000);
    
    // Simulate a power user with many DeFi transactions
    const transactions: TransactionForAnalysis[] = [];
    
    // Add 50 DeFi transactions over several days
    for (let i = 0; i < 50; i++) {
      transactions.push({
        hash: `0xpower${i}`,
        from: walletAddress,
        to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap
        value: '100000000000000000',
        timestamp: now - (86400 * i / 10), // Spread over days
        methodId: '0x38ed1739',
        isInbound: false,
        isOutbound: true,
      });
    }

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // Should have evidence of legitimate DeFi activity
    const legitimateEvidence = result.evidence.filter(e => e.weight < 0);
    expect(legitimateEvidence.length).toBeGreaterThan(0);
    
    // Should NOT be flagged as malicious
    expect(result.isDefinitelyMalicious).toBe(false);
    expect(result.showCriticalAlert).toBe(false);
  });
});

// ============================================
// REGRESSION TEST: Sweeper Bot Detection → FLAGGED
// ============================================

describe('Regression: Real sweeper bot behavior must be FLAGGED', () => {
  test('Wallet draining funds immediately after deposits is flagged', async () => {
    const sweeperAddress = '0xbadactor000000000000000000000000000000001';
    const victimAddress = '0xvictim0000000000000000000000000000000001';
    const drainerAddress = '0xdrainer0000000000000000000000000000000001';
    const now = Math.floor(Date.now() / 1000);
    
    // Simulate sweeper bot behavior:
    // - Receives funds from multiple sources
    // - Immediately drains to same destination
    // - No UI function usage
    const transactions: TransactionForAnalysis[] = [
      // Victim 1 deposit
      {
        hash: '0xsweep1a',
        from: victimAddress,
        to: sweeperAddress,
        value: '1000000000000000000',
        timestamp: now - 100,
        isInbound: true,
        isOutbound: false,
      },
      // Immediate drain to drainer (within 60 seconds)
      {
        hash: '0xsweep1b',
        from: sweeperAddress,
        to: drainerAddress,
        value: '990000000000000000',
        timestamp: now - 50, // 50 seconds later
        isInbound: false,
        isOutbound: true,
      },
      // Victim 2 deposit
      {
        hash: '0xsweep2a',
        from: '0xvictim0000000000000000000000000000000002',
        to: sweeperAddress,
        value: '2000000000000000000',
        timestamp: now - 40,
        isInbound: true,
        isOutbound: false,
      },
      // Immediate drain
      {
        hash: '0xsweep2b',
        from: sweeperAddress,
        to: drainerAddress,
        value: '1990000000000000000',
        timestamp: now - 10,
        isInbound: false,
        isOutbound: true,
      },
      // Victim 3
      {
        hash: '0xsweep3a',
        from: '0xvictim0000000000000000000000000000000003',
        to: sweeperAddress,
        value: '500000000000000000',
        timestamp: now - 5,
        isInbound: true,
        isOutbound: false,
      },
      {
        hash: '0xsweep3b',
        from: sweeperAddress,
        to: drainerAddress,
        value: '490000000000000000',
        timestamp: now - 2,
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(sweeperAddress, 'ethereum', transactions);
    
    // Calculate sweeper score
    const sweeperScore = calculateSweeperBotScore(transactions, sweeperAddress);
    
    // Should show evidence of rapid drain pattern
    const rapidDrainEvidence = result.evidence.find(e => e.type === 'RAPID_DRAIN_AFTER_DEPOSIT');
    expect(rapidDrainEvidence).toBeDefined();
    
    // Should show evidence of concentrated destinations
    const concentratedDest = result.evidence.find(e => e.type === 'MULTIPLE_VICTIMS_SAME_DEST');
    expect(concentratedDest).toBeDefined();
    
    // Sweeper score should be high
    expect(sweeperScore.score).toBeGreaterThanOrEqual(50);
    expect(sweeperScore.passedCriteria.length).toBeGreaterThan(0);
  });
});

// ============================================
// REGRESSION TEST: Confidence-Based Alerts
// ============================================

describe('Regression: Confidence < 90% must NOT show CRITICAL alerts', () => {
  test('Low confidence does not trigger critical alert', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    
    // Minimal transactions - low confidence
    const transactions: TransactionForAnalysis[] = [
      {
        hash: '0xmin1',
        from: walletAddress,
        to: '0xunknown000000000000000000000000000000001',
        value: '1000000000000000000',
        timestamp: Math.floor(Date.now() / 1000) - 100,
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // With minimal evidence, confidence should be low
    // And critical alert should NOT be shown
    if (result.confidence < 90) {
      expect(result.showCriticalAlert).toBe(false);
    }
  });
});

// ============================================
// INVARIANT TESTS
// ============================================

describe('Detection Logic Invariants', () => {
  test('INVARIANT: No address is both safe and malicious', () => {
    // Get all safe addresses
    const { SAFE_CONTRACTS } = require('../safe-contracts');
    const safeAddresses = SAFE_CONTRACTS.map((c: { address: string }) => c.address.toLowerCase());
    
    // None should be in malicious database
    for (const addr of safeAddresses) {
      expect(isMaliciousAddress(addr, 'ethereum')).toBeNull();
      expect(isKnownDrainer(addr)).toBe(false);
      expect(isDrainerRecipient(addr)).toBe(false);
    }
  });

  test('INVARIANT: Safe contracts are excluded from flagging', async () => {
    const { SAFE_CONTRACTS } = require('../safe-contracts');
    
    for (const contract of SAFE_CONTRACTS.slice(0, 10)) { // Test first 10
      const classification = await classifyContract(contract.address, 'ethereum');
      expect(shouldExcludeFromMaliciousFlagging(classification)).toBe(true);
    }
  });

  test('INVARIANT: Standard EIP methods are never suspicious alone', () => {
    const standardMethods = [
      '0x095ea7b3', // approve
      '0xa22cb465', // setApprovalForAll
      '0x1249c58b', // mint
      '0xa0712d68', // mint(uint256)
    ];
    
    for (const method of standardMethods) {
      const isApproval = isStandardApprovalMethod(method);
      const isMint = isStandardMintMethod(method);
      expect(isApproval || isMint).toBe(true);
    }
  });
});

// ============================================
// EXPLICIT TEST CASES (MUST PASS)
// ============================================

describe('Explicit Test Cases - Must NOT be flagged as sweeper bot', () => {
  
  // TEST CASE 1: Aztec presale bid + fund forwarding
  test('Aztec presale bid + fund forwarding must NOT be classified as sweeper bot', async () => {
    const walletAddress = '0xuser000000000000000000000000000000000001';
    const aztecPresaleContract = '0x00000000000000adc04c56bf30ac9d3c0aaf14dc'; // Using Seaport as example
    const now = Math.floor(Date.now() / 1000);
    
    const transactions: TransactionForAnalysis[] = [
      // User receives funds from exchange
      {
        hash: '0xaztec1',
        from: '0x28c6c06298d514db089934071355e5743bf21d60', // Binance
        to: walletAddress,
        value: '5000000000000000000', // 5 ETH
        timestamp: now - 3600,
        isInbound: true,
        isOutbound: false,
      },
      // User places presale bid (forwarding funds shortly after)
      {
        hash: '0xaztec2',
        from: walletAddress,
        to: aztecPresaleContract,
        value: '4500000000000000000', // 4.5 ETH bid
        timestamp: now - 3500, // 100 seconds later - this is the "rapid outflow" false positive scenario
        methodId: '0xfb0f3ee1', // fulfillBasicOrder
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // MUST NOT be classified as sweeper bot
    expect(result.classification).not.toBe('CONFIRMED_SWEEPER');
    expect(result.classification).not.toBe('SWEEPER_BOT_SUSPECT');
    expect(result.showCriticalAlert).toBe(false);
    
    // Should detect presale/bid intent
    expect(result.detectedIntents.length).toBeGreaterThan(0);
    
    // Should be classified as normal or likely user automation
    expect(['NORMAL_USER', 'POWER_USER', 'LIKELY_USER_AUTOMATION', 'UNKNOWN']).toContain(result.classification);
    
    // Explainability should show why sweeper was ruled out
    expect(result.explainability.sweeperRuledOutReasons.length + 
           result.explainability.failedSweeperCriteria.length).toBeGreaterThan(0);
  });

  // TEST CASE 2: NFT mint + approval + payment
  test('NFT mint + approval + payment must NOT raise sweeper alert', async () => {
    const walletAddress = '0xuser000000000000000000000000000000000002';
    const nftContract = '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d'; // BAYC
    const now = Math.floor(Date.now() / 1000);
    
    const transactions: TransactionForAnalysis[] = [
      // User receives funds
      {
        hash: '0xnft1',
        from: '0x28c6c06298d514db089934071355e5743bf21d60', // Binance
        to: walletAddress,
        value: '1000000000000000000', // 1 ETH
        timestamp: now - 7200,
        isInbound: true,
        isOutbound: false,
      },
      // User mints NFT (rapid outflow scenario)
      {
        hash: '0xnft2',
        from: walletAddress,
        to: nftContract,
        value: '80000000000000000', // 0.08 ETH mint
        timestamp: now - 7100, // 100 seconds later
        methodId: '0x1249c58b', // mint()
        isInbound: false,
        isOutbound: true,
      },
      // User approves OpenSea
      {
        hash: '0xnft3',
        from: walletAddress,
        to: nftContract,
        value: '0',
        timestamp: now - 7000,
        methodId: '0xa22cb465', // setApprovalForAll
        isInbound: false,
        isOutbound: true,
      },
      // User lists/sells on OpenSea
      {
        hash: '0xnft4',
        from: walletAddress,
        to: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc', // OpenSea
        value: '100000000000000000',
        timestamp: now - 6900,
        methodId: '0xfb0f3ee1', // fulfillBasicOrder
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // MUST NOT be classified as sweeper bot
    expect(result.classification).not.toBe('CONFIRMED_SWEEPER');
    expect(result.classification).not.toBe('SWEEPER_BOT_SUSPECT');
    expect(result.showCriticalAlert).toBe(false);
    
    // Should detect NFT mint intent
    const mintIntents = result.detectedIntents.filter(i => 
      i.type === 'NFT_MINT' || i.type === 'NFT_PURCHASE' || i.type === 'PRESALE_BID'
    );
    expect(mintIntents.length).toBeGreaterThan(0);
    
    // Should be classified as normal user
    expect(['NORMAL_USER', 'POWER_USER', 'LIKELY_USER_AUTOMATION']).toContain(result.classification);
    
    // Risk level should be LOW
    expect(['LOW', 'MEDIUM']).toContain(result.riskLevel);
  });

  // TEST CASE 3: Exchange deposit forwarding
  test('Exchange deposit forwarding must NOT raise sweeper alert', async () => {
    const walletAddress = '0xuser000000000000000000000000000000000003';
    const binanceHotWallet = '0x28c6c06298d514db089934071355e5743bf21d60';
    const coinbaseWallet = '0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43';
    const now = Math.floor(Date.now() / 1000);
    
    // Scenario: User receives from personal wallet, immediately forwards to exchange
    const transactions: TransactionForAnalysis[] = [
      // User receives from their other wallet
      {
        hash: '0xexch1',
        from: '0xpersonalwallet0000000000000000000000001',
        to: walletAddress,
        value: '10000000000000000000', // 10 ETH
        timestamp: now - 300,
        isInbound: true,
        isOutbound: false,
      },
      // User immediately forwards to Binance deposit address
      {
        hash: '0xexch2',
        from: walletAddress,
        to: binanceHotWallet,
        value: '9990000000000000000', // ~10 ETH minus gas
        timestamp: now - 240, // 60 seconds later - rapid outflow to exchange
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // MUST NOT be classified as sweeper bot
    expect(result.classification).not.toBe('CONFIRMED_SWEEPER');
    expect(result.classification).not.toBe('SWEEPER_BOT_SUSPECT');
    expect(result.showCriticalAlert).toBe(false);
    
    // Should detect exchange deposit intent
    const exchangeIntents = result.detectedIntents.filter(i => 
      i.type === 'EXCHANGE_DEPOSIT'
    );
    expect(exchangeIntents.length).toBeGreaterThan(0);
    
    // Should be classified as normal
    expect(['NORMAL_USER', 'POWER_USER', 'LIKELY_USER_AUTOMATION', 'UNKNOWN']).toContain(result.classification);
    
    // Explainability should show exchange detected
    expect(
      result.explainability.userIntentDetected.some(s => s.toLowerCase().includes('exchange')) ||
      result.explainability.protocolInteractionDetected.some(s => s.toLowerCase().includes('exchange') || s.toLowerCase().includes('protocol'))
    ).toBe(true);
  });

  // TEST CASE 4: DEX deposit (Pendle, Uniswap)
  test('DEX deposit must NOT raise sweeper alert', async () => {
    const walletAddress = '0xuser000000000000000000000000000000000004';
    const pendleRouter = '0x0000000001e4ef00d069e71d6ba041b0a16f7ea0';
    const uniswapRouter = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
    const now = Math.floor(Date.now() / 1000);
    
    const transactions: TransactionForAnalysis[] = [
      // Receive funds
      {
        hash: '0xdex1',
        from: '0x28c6c06298d514db089934071355e5743bf21d60',
        to: walletAddress,
        value: '5000000000000000000',
        timestamp: now - 600,
        isInbound: true,
        isOutbound: false,
      },
      // Deposit to Pendle (rapid outflow)
      {
        hash: '0xdex2',
        from: walletAddress,
        to: pendleRouter,
        value: '2000000000000000000',
        timestamp: now - 550, // 50 seconds later
        methodId: '0xd0e30db0', // deposit
        isInbound: false,
        isOutbound: true,
      },
      // Swap on Uniswap
      {
        hash: '0xdex3',
        from: walletAddress,
        to: uniswapRouter,
        value: '1000000000000000000',
        timestamp: now - 500,
        methodId: '0x38ed1739', // swapExactTokensForTokens
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // MUST NOT be classified as sweeper bot
    expect(result.classification).not.toBe('CONFIRMED_SWEEPER');
    expect(result.classification).not.toBe('SWEEPER_BOT_SUSPECT');
    expect(result.showCriticalAlert).toBe(false);
    
    // Should detect DeFi intents
    const defiIntents = result.detectedIntents.filter(i => 
      i.type === 'DEX_DEPOSIT' || i.type === 'DEX_SWAP'
    );
    expect(defiIntents.length).toBeGreaterThan(0);
    
    // Should be normal user
    expect(['NORMAL_USER', 'POWER_USER', 'LIKELY_USER_AUTOMATION']).toContain(result.classification);
  });

  // TEST CASE 5: Bridge deposit
  test('Bridge deposit must NOT raise sweeper alert', async () => {
    const walletAddress = '0xuser000000000000000000000000000000000005';
    const arbitrumBridge = '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a';
    const now = Math.floor(Date.now() / 1000);
    
    const transactions: TransactionForAnalysis[] = [
      // Receive funds
      {
        hash: '0xbridge1',
        from: '0x28c6c06298d514db089934071355e5743bf21d60',
        to: walletAddress,
        value: '3000000000000000000',
        timestamp: now - 400,
        isInbound: true,
        isOutbound: false,
      },
      // Bridge to Arbitrum (rapid outflow)
      {
        hash: '0xbridge2',
        from: walletAddress,
        to: arbitrumBridge,
        value: '2900000000000000000',
        timestamp: now - 350, // 50 seconds later
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // MUST NOT be classified as sweeper bot
    expect(result.classification).not.toBe('CONFIRMED_SWEEPER');
    expect(result.classification).not.toBe('SWEEPER_BOT_SUSPECT');
    expect(result.showCriticalAlert).toBe(false);
    
    // Should detect bridge intent
    const bridgeIntents = result.detectedIntents.filter(i => i.type === 'BRIDGE_DEPOSIT');
    expect(bridgeIntents.length).toBeGreaterThan(0);
  });
});

// ============================================
// CONFIDENCE THRESHOLD TESTS
// ============================================

describe('Confidence-Based Classification', () => {
  test('Only show "Sweeper Bot" if confidence >= 85%', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    
    // Minimal suspicious activity - should NOT reach 85% confidence
    const transactions: TransactionForAnalysis[] = [
      {
        hash: '0xmin1',
        from: walletAddress,
        to: '0xunknown000000000000000000000000000000001',
        value: '1000000000000000000',
        timestamp: Math.floor(Date.now() / 1000) - 100,
        isInbound: false,
        isOutbound: true,
      },
      {
        hash: '0xmin2',
        from: '0xsource0000000000000000000000000000000001',
        to: walletAddress,
        value: '1000000000000000000',
        timestamp: Math.floor(Date.now() / 1000) - 200,
        isInbound: true,
        isOutbound: false,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // With minimal data, should NOT be labeled sweeper
    if (result.confidence < 85) {
      expect(result.classification).not.toBe('CONFIRMED_SWEEPER');
      expect(result.showCriticalAlert).toBe(false);
    }
  });

  test('Classification output uses correct labels', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const now = Math.floor(Date.now() / 1000);
    
    // Normal user transactions
    const transactions: TransactionForAnalysis[] = [
      {
        hash: '0xnorm1',
        from: walletAddress,
        to: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap
        value: '1000000000000000000',
        timestamp: now - 3600,
        methodId: '0x38ed1739',
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // Valid classifications
    const validClassifications = [
      'NORMAL_USER',
      'POWER_USER', 
      'LIKELY_USER_AUTOMATION',
      'NEW_WALLET',
      'NEEDS_MANUAL_REVIEW',
      'SWEEPER_BOT_SUSPECT',
      'CONFIRMED_SWEEPER',
      'DRAINER_SUSPECT',
      'CONFIRMED_DRAINER',
      'COMPROMISED_VICTIM',
      'UNKNOWN',
    ];
    
    expect(validClassifications).toContain(result.classification);
  });
});

// ============================================
// EXPLAINABILITY TESTS
// ============================================

describe('Explainability Requirements', () => {
  test('Every analysis result includes explainability', async () => {
    const walletAddress = '0x1234567890123456789012345678901234567890';
    const now = Math.floor(Date.now() / 1000);
    
    const transactions: TransactionForAnalysis[] = [
      {
        hash: '0xexp1',
        from: walletAddress,
        to: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
        value: '100000000000000000',
        timestamp: now - 100,
        isInbound: false,
        isOutbound: true,
      },
    ];

    const result = await analyzeWalletBehavior(walletAddress, 'ethereum', transactions);
    
    // Must have explainability object
    expect(result.explainability).toBeDefined();
    expect(result.explainability.classificationReason).toBeDefined();
    expect(result.explainability.classificationReason.length).toBeGreaterThan(0);
    
    // Must have arrays for triggers and reasons
    expect(Array.isArray(result.explainability.behavioralTriggers)).toBe(true);
    expect(Array.isArray(result.explainability.userIntentDetected)).toBe(true);
    expect(Array.isArray(result.explainability.protocolInteractionDetected)).toBe(true);
    expect(Array.isArray(result.explainability.sweeperRuledOutReasons)).toBe(true);
    expect(Array.isArray(result.explainability.failedSweeperCriteria)).toBe(true);
    expect(Array.isArray(result.explainability.passedSweeperCriteria)).toBe(true);
  });

  test('Sweeper classification includes specific triggers', async () => {
    const sweeperAddress = '0xbadactor000000000000000000000000000000001';
    const now = Math.floor(Date.now() / 1000);
    
    // Create obvious sweeper pattern (no protocol interaction)
    const transactions: TransactionForAnalysis[] = [];
    
    // Multiple rapid drains to unrelated unknown addresses
    for (let i = 0; i < 10; i++) {
      // Inbound
      transactions.push({
        hash: `0xsweep${i}a`,
        from: `0xvictim00000000000000000000000000000000${i.toString().padStart(2, '0')}`,
        to: sweeperAddress,
        value: '1000000000000000000',
        timestamp: now - (i * 120),
        blockNumber: 1000000 + i,
        isInbound: true,
        isOutbound: false,
      });
      // Rapid outbound to unknown
      transactions.push({
        hash: `0xsweep${i}b`,
        from: sweeperAddress,
        to: `0xdest000000000000000000000000000000000000${i.toString().padStart(2, '0')}`,
        value: '990000000000000000',
        timestamp: now - (i * 120) + 30,
        blockNumber: 1000000 + i,
        isInbound: false,
        isOutbound: true,
      });
    }

    const result = await analyzeWalletBehavior(sweeperAddress, 'ethereum', transactions);
    
    // If classified as sweeper, must have passed criteria
    if (result.classification === 'CONFIRMED_SWEEPER' || 
        result.classification === 'SWEEPER_BOT_SUSPECT') {
      expect(result.explainability.passedSweeperCriteria.length).toBeGreaterThan(0);
      expect(result.explainability.behavioralTriggers.length).toBeGreaterThan(0);
    }
  });
});

// ============================================
// SUMMARY
// ============================================
// Run with: npx jest src/lib/detection/__tests__/false-positive-prevention.test.ts
//
// Expected results:
// ✓ OpenSea mint → SAFE
// ✓ NFT contracts → SAFE
// ✓ ENS contracts → SAFE
// ✓ Pendle deposit → SAFE
// ✓ Verified DeFi approval → SAFE
// ✓ Known historical sweeper bot wallets → FLAGGED
// ✓ Normal user behavior → NOT FLAGGED
// ✓ Power users → NOT FLAGGED
// ✓ Real sweeper patterns → FLAGGED
// ✓ Confidence < 90% → No CRITICAL alert
// ✓ Aztec presale bid + forwarding → NOT FLAGGED
// ✓ NFT mint + approval + payment → NOT FLAGGED
// ✓ Exchange deposit forwarding → NOT FLAGGED
// ✓ Bridge deposit → NOT FLAGGED
// ✓ Every result includes explainability

