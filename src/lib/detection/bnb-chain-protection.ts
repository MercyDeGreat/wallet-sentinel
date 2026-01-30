// ============================================
// BNB CHAIN DRAINER DETECTION
// ============================================
// BNB Chain has HIGH SCAM DENSITY - Requires HIGHER detection thresholds
//
// 🔐 RULE: BNB Chain requires MORE evidence before flagging as drainer
//
// MUST OBSERVE:
// - Unlimited approvals
// - Token-agnostic sweeping
// - Immediate forwarding
// - Sink must NOT be:
//   - Binance hot wallet
//   - PancakeSwap router
//   - Known farm or pool
//
// EXPLICIT EXCLUSIONS:
// - PancakeSwap (all versions)
// - Binance infrastructure
// - Venus Protocol
// - Alpaca Finance
// - Legit farming contracts

import { Chain } from '@/types';

// ============================================
// BNB CHAIN SIGNAL THRESHOLDS (HIGHER)
// ============================================
// Due to high scam density, we require MORE signals

export const BNB_DETECTION_THRESHOLDS = {
  minSignalsForActiveDrainer: 4,     // Higher than ETH/Base (3)
  minVictimCount: 4,                  // Higher than ETH/Base (3)
  minApprovalAbuseCount: 2,           // Higher than ETH/Base (1)
  minConfidenceScore: 95,             // Higher than ETH/Base (90)
  minConsolidationPatterns: 2,        // Higher than ETH/Base (1)
};

// ============================================
// BINANCE INFRASTRUCTURE - NEVER FLAG
// ============================================

export const BINANCE_HOT_WALLETS: Map<string, string> = new Map([
  // Main Binance wallets
  ['0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be', 'Binance'],
  ['0xd551234ae421e3bcba99a0da6d736074f22192ff', 'Binance 2'],
  ['0x564286362092d8e7936f0549571a803b203aaced', 'Binance 3'],
  ['0x0681d8db095565fe8a346fa0277bffde9c0edbbf', 'Binance 4'],
  ['0xfe9e8709d3215310075d67e3ed32a380ccf451c8', 'Binance 5'],
  ['0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67', 'Binance 6'],
  ['0xbe0eb53f46cd790cd13851d5eff43d12404d33e8', 'Binance Cold'],
  ['0xf977814e90da44bfa03b6295a0616a897441acec', 'Binance 8'],
  ['0x28c6c06298d514db089934071355e5743bf21d60', 'Binance 14'],
  ['0x21a31ee1afc51d94c2efccaa2092ad1028285549', 'Binance 15'],
  ['0xdfd5293d8e347dfe59e90efd55b2956a1343963d', 'Binance 16'],
  ['0x56eddb7aa87536c09ccc2793473599fd21a8b17f', 'Binance 17'],
  ['0x5a52e96bacdabb82fd05763e25335261b270efcb', 'Binance 28'],
  
  // Binance.US
  ['0x34ea4138580435b5a521e460035edb19df1938c1', 'Binance.US'],
  
  // BNB Chain specific infrastructure
  ['0x8894e0a0c962cb723c1976a4421c95949be2d4e3', 'Binance: Hot Wallet 6'],
  ['0xe2fc31f816a9b94326492132018c3aecc4a93ae1', 'Binance: Hot Wallet 7'],
  ['0x01c952174c24e1210d26961d456a77a39e1f0bb0', 'Binance: Deposit Hot'],
]);

/**
 * Check if address is a Binance hot wallet.
 */
export function isBinanceHotWallet(address: string): boolean {
  return BINANCE_HOT_WALLETS.has(address?.toLowerCase() || '');
}

// ============================================
// PANCAKESWAP - NEVER FLAG
// ============================================

export const PANCAKESWAP_CONTRACTS: Map<string, { name: string; type: string }> = new Map([
  // PancakeSwap V2
  ['0x10ed43c718714eb63d5aa57b78b54704e256024e', { name: 'PancakeSwap Router V2', type: 'DEX_ROUTER' }],
  ['0x05ff2b0db69458a0750badebc4f9e13add608c7f', { name: 'PancakeSwap Router V1', type: 'DEX_ROUTER' }],
  ['0xca143ce32fe78f1f7019d7d551a6402fc5350c73', { name: 'PancakeSwap Factory V2', type: 'DEX_FACTORY' }],
  
  // PancakeSwap V3
  ['0x13f4ea83d0bd40e75c8222255bc855a974568dd4', { name: 'PancakeSwap Smart Router V3', type: 'DEX_ROUTER' }],
  ['0x1b81d678ffb9c0263b24a97847620c99d213eb14', { name: 'PancakeSwap Universal Router', type: 'DEX_ROUTER' }],
  ['0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865', { name: 'PancakeSwap Factory V3', type: 'DEX_FACTORY' }],
  ['0x46a15b0b27311cedf172ab29e4f4766fbe7f4364', { name: 'PancakeSwap Position Manager', type: 'DEX_POSITION' }],
  
  // MasterChef (Farming)
  ['0x73feaa1ee314f8c655e354234017be2193c9e24e', { name: 'PancakeSwap MasterChef V2', type: 'FARMING' }],
  ['0xa5f8c5dbd5f286960b9d90548680ae5ebff07652', { name: 'PancakeSwap MasterChef V3', type: 'FARMING' }],
  
  // IFO (Initial Farm Offering)
  ['0x1f546ad641b56b86fd9dceac473d1c7a357276b7', { name: 'PancakeSwap IFO', type: 'IFO' }],
  
  // NFT Marketplace
  ['0x17539cca21c7933df5c980172d22659b8c345c5a', { name: 'PancakeSwap NFT Market', type: 'NFT_MARKETPLACE' }],
  
  // Prediction
  ['0x18b2a687610328590bc8f2e5fedde3b582a49cda', { name: 'PancakeSwap Prediction V2', type: 'PREDICTION' }],
  
  // Lottery
  ['0x5af6d33de2ccec94efb1bdf8f92bd9e9d4e6b3c3', { name: 'PancakeSwap Lottery', type: 'LOTTERY' }],
  
  // CAKE Token
  ['0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82', { name: 'CAKE Token', type: 'TOKEN' }],
]);

/**
 * Check if address is a PancakeSwap contract.
 */
export function isPancakeSwapContract(address: string): { isPancakeSwap: boolean; name?: string; type?: string } {
  const normalized = address?.toLowerCase() || '';
  const contract = PANCAKESWAP_CONTRACTS.get(normalized);
  
  if (contract) {
    return { isPancakeSwap: true, name: contract.name, type: contract.type };
  }
  
  return { isPancakeSwap: false };
}

// ============================================
// BNB CHAIN DeFi PROTOCOLS - NEVER FLAG
// ============================================

export const BNB_DEFI_PROTOCOLS: Map<string, { name: string; type: string }> = new Map([
  // Venus Protocol (Lending)
  ['0xfd36e2c2a6789db23113685031d7f16329158384', { name: 'Venus Unitroller', type: 'LENDING' }],
  ['0xa07c5b74c9b40447a954e1466938b865b6bbea36', { name: 'Venus vBNB', type: 'LENDING' }],
  ['0xeca88125a5adbe82614ffc12d0db554e2e2867c8', { name: 'Venus vUSDC', type: 'LENDING' }],
  ['0x08ceb3f4a7ed3500ca0982bcd0fc7816688084c3', { name: 'Venus vUSDT', type: 'LENDING' }],
  ['0x151b1e2635a717bcdc836ecd6fbb62b674fe3e1d', { name: 'Venus XVS Vault', type: 'STAKING' }],
  
  // Alpaca Finance (Leveraged Yield)
  ['0xa625ab01b08ce023b2a342dbb12a16f2c8489a8f', { name: 'Alpaca Fair Launch', type: 'FARMING' }],
  ['0x7c9e73d4c71dae564d41f78d56439bb4ba87592f', { name: 'Alpaca BNB Vault', type: 'VAULT' }],
  ['0x158da805682bdc8ee32d52833ad41e74bb951e59', { name: 'Alpaca BUSD Vault', type: 'VAULT' }],
  
  // Biswap
  ['0x3a6d8ca21d1cf76f653a67577fa0d27453350dd8', { name: 'Biswap Router', type: 'DEX_ROUTER' }],
  ['0x858e3312ed3a876947ea49d572a7c42de08af7ee', { name: 'Biswap Factory', type: 'DEX_FACTORY' }],
  
  // MDEX
  ['0x62c1a0d92b09d0912f7bb9c96c5ecdc7f6b87059', { name: 'MDEX Router', type: 'DEX_ROUTER' }],
  
  // ApeSwap
  ['0xcf0febd3f17cef5b47b0cd257acf6025c5bff3b7', { name: 'ApeSwap Router', type: 'DEX_ROUTER' }],
  ['0x0841bd0b734e4f5853f0dd8d7ea041c241fb0da6', { name: 'ApeSwap Factory', type: 'DEX_FACTORY' }],
  
  // BakerySwap
  ['0xcde540d7eafe93ac5fe6233bee57e1270d3e330f', { name: 'BakerySwap Router', type: 'DEX_ROUTER' }],
  
  // Autofarm
  ['0x0895196562c7868c5be92459fae7f877ed450452', { name: 'AutoFarm', type: 'YIELD_OPTIMIZER' }],
  
  // Beefy Finance
  ['0x453d4ba9a2d594314df53830f9fb1f2d64f9f47f', { name: 'Beefy Vault Factory', type: 'YIELD_OPTIMIZER' }],
  
  // Wombat Exchange
  ['0x19609b03c976cca288fbdae5c21d4290e9a4add7', { name: 'Wombat Router', type: 'DEX_ROUTER' }],
  
  // Thena (ve(3,3) DEX)
  ['0xd4ae6eca985340dd434d38f470accce4dc78d109', { name: 'Thena Router V2', type: 'DEX_ROUTER' }],
  ['0x20a304a7d126758dfe6b243d0fc515f83bca8431', { name: 'Thena Gauge Factory', type: 'FARMING' }],
]);

/**
 * Check if address is a known BNB DeFi protocol.
 */
export function isBNBDeFiProtocol(address: string): { isProtocol: boolean; name?: string; type?: string } {
  const normalized = address?.toLowerCase() || '';
  const protocol = BNB_DEFI_PROTOCOLS.get(normalized);
  
  if (protocol) {
    return { isProtocol: true, name: protocol.name, type: protocol.type };
  }
  
  return { isProtocol: false };
}

// ============================================
// BNB CHAIN BRIDGES - NEVER FLAG
// ============================================

export const BNB_BRIDGES: Map<string, { name: string }> = new Map([
  // Binance Bridge
  ['0x000000000000000000000000000000000000d001', { name: 'BNB Bridge (Token Hub)' }],
  ['0x0000000000000000000000000000000000001004', { name: 'BNB Cross Chain Contract' }],
  
  // Third-party bridges
  ['0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae', { name: 'LI.FI Diamond' }],
  ['0xc30141b657f42f1e34a63552ce2d0f2f5216a8c7', { name: 'Socket Gateway' }],
  ['0x4a364f8c717caad9a442737eb7b8a55cc6cf18d8', { name: 'Stargate Router' }],
  ['0xe00bd3df25fb187d6abbb620b3dcf3d98c7e86a9', { name: 'Wormhole Token Bridge' }],
  ['0x98f3c9e6e3face36baad05fe09d375ef1464288b', { name: 'Wormhole Core' }],
  ['0x5a58505a96d1dbf8df91cb21b54419fc36e93fde', { name: 'Portal Token Bridge' }],
  ['0x43de2d77bf8027e25dbd179b491e8d64f38398aa', { name: 'DeBridge Gate' }],
  ['0x5d22045daceab03b158031ecb7d9d06fad24609b', { name: 'Multichain Router V6' }],
]);

/**
 * Check if address is a known BNB bridge.
 */
export function isBNBBridge(address: string): boolean {
  return BNB_BRIDGES.has(address?.toLowerCase() || '');
}

// ============================================
// BNB CHAIN DRAINER SIGNALS
// ============================================

export interface BNBDrainerSignals {
  // Standard signals
  hasUnlimitedApprovals: boolean;
  unlimitedApprovalCount: number;
  hasTokenAgnosticSweeping: boolean;     // Same pattern for multiple token types
  sweepedTokenCount: number;
  hasImmediateForwarding: boolean;
  forwardingDelaySeconds: number;
  
  // Sink analysis
  sinkAddress?: string;
  sinkIsBinanceHotWallet: boolean;
  sinkIsPancakeSwap: boolean;
  sinkIsKnownFarmOrPool: boolean;
  sinkIsLegitimate: boolean;             // Combined check
  
  // Victim analysis (BNB requires 4+)
  victimCount: number;
  
  // Multi-signal count
  totalSignalCount: number;
  meetsThreshold: boolean;
}

/**
 * Analyze transactions for BNB chain drainer patterns.
 * 
 * BNB CHAIN REQUIREMENTS:
 * - Unlimited approvals MUST be present
 * - Token-agnostic sweeping pattern
 * - Immediate forwarding
 * - Sink must NOT be Binance/PancakeSwap/Farm
 * - At least 4 signals required (higher than other chains)
 */
export function analyzeBNBDrainerPatterns(
  approvals: {
    token: string;
    spender: string;
    amount: string;
    isUnlimited: boolean;
  }[],
  outboundTransfers: {
    from: string;
    to: string;
    tokenAddress: string;
    timestamp: number;
  }[],
  inboundTimestamps: number[],
  victimAddresses: Set<string>
): BNBDrainerSignals {
  // ============================================
  // ANALYZE UNLIMITED APPROVALS
  // ============================================
  const unlimitedApprovals = approvals.filter(a => a.isUnlimited);
  const hasUnlimitedApprovals = unlimitedApprovals.length >= BNB_DETECTION_THRESHOLDS.minApprovalAbuseCount;
  
  // ============================================
  // ANALYZE TOKEN-AGNOSTIC SWEEPING
  // ============================================
  const tokenTypes = new Set(outboundTransfers.map(t => t.tokenAddress.toLowerCase()));
  const hasTokenAgnosticSweeping = tokenTypes.size >= 3; // 3+ different tokens
  
  // ============================================
  // ANALYZE IMMEDIATE FORWARDING
  // ============================================
  let minForwardingDelay = Infinity;
  for (const inbound of inboundTimestamps) {
    for (const outbound of outboundTransfers) {
      const delay = outbound.timestamp - inbound;
      if (delay > 0 && delay < minForwardingDelay) {
        minForwardingDelay = delay;
      }
    }
  }
  const hasImmediateForwarding = minForwardingDelay <= 300; // 5 minutes
  
  // ============================================
  // ANALYZE SINK DESTINATION
  // ============================================
  const destinationCounts = new Map<string, number>();
  for (const t of outboundTransfers) {
    const dest = t.to.toLowerCase();
    destinationCounts.set(dest, (destinationCounts.get(dest) || 0) + 1);
  }
  
  let topSink = '';
  let topCount = 0;
  for (const [addr, count] of destinationCounts) {
    if (count > topCount) {
      topSink = addr;
      topCount = count;
    }
  }
  
  // Check if sink is legitimate
  const sinkIsBinanceHotWallet = isBinanceHotWallet(topSink);
  const sinkIsPancakeSwap = isPancakeSwapContract(topSink).isPancakeSwap;
  const sinkIsKnownFarmOrPool = isBNBDeFiProtocol(topSink).isProtocol;
  const sinkIsBridge = isBNBBridge(topSink);
  
  const sinkIsLegitimate = sinkIsBinanceHotWallet || sinkIsPancakeSwap || sinkIsKnownFarmOrPool || sinkIsBridge;
  
  // ============================================
  // COUNT SIGNALS AND CHECK THRESHOLD
  // ============================================
  let signalCount = 0;
  
  if (hasUnlimitedApprovals) signalCount++;
  if (hasTokenAgnosticSweeping) signalCount++;
  if (hasImmediateForwarding) signalCount++;
  if (!sinkIsLegitimate && topSink) signalCount++; // Suspicious sink
  if (victimAddresses.size >= BNB_DETECTION_THRESHOLDS.minVictimCount) signalCount++;
  
  const meetsThreshold = signalCount >= BNB_DETECTION_THRESHOLDS.minSignalsForActiveDrainer &&
                         victimAddresses.size >= BNB_DETECTION_THRESHOLDS.minVictimCount &&
                         !sinkIsLegitimate;
  
  return {
    hasUnlimitedApprovals,
    unlimitedApprovalCount: unlimitedApprovals.length,
    hasTokenAgnosticSweeping,
    sweepedTokenCount: tokenTypes.size,
    hasImmediateForwarding,
    forwardingDelaySeconds: minForwardingDelay === Infinity ? -1 : minForwardingDelay,
    sinkAddress: topSink || undefined,
    sinkIsBinanceHotWallet,
    sinkIsPancakeSwap,
    sinkIsKnownFarmOrPool,
    sinkIsLegitimate,
    victimCount: victimAddresses.size,
    totalSignalCount: signalCount,
    meetsThreshold,
  };
}

// ============================================
// BNB CHAIN PROTOCOL CHECK
// ============================================

export interface BNBProtocolCheckResult {
  isLegitimateProtocol: boolean;
  protocolName?: string;
  protocolType?: string;
  riskContribution: number;
  explanation: string;
  canNeverBeDrainer: boolean;
}

/**
 * Check if a transaction is a legitimate BNB protocol interaction.
 * 
 * NEVER FLAG:
 * - PancakeSwap (all versions)
 * - Binance infrastructure
 * - Venus Protocol
 * - Alpaca Finance
 * - Legit farming contracts
 */
export function checkBNBProtocolInteraction(toAddress: string): BNBProtocolCheckResult {
  const normalized = toAddress?.toLowerCase() || '';
  
  // Check Binance wallets
  if (isBinanceHotWallet(normalized)) {
    return {
      isLegitimateProtocol: true,
      protocolName: BINANCE_HOT_WALLETS.get(normalized) || 'Binance',
      protocolType: 'EXCHANGE',
      riskContribution: -5,
      explanation: 'Binance hot wallet - CEX transfer is legitimate',
      canNeverBeDrainer: true,
    };
  }
  
  // Check PancakeSwap
  const pancakeCheck = isPancakeSwapContract(normalized);
  if (pancakeCheck.isPancakeSwap) {
    return {
      isLegitimateProtocol: true,
      protocolName: pancakeCheck.name,
      protocolType: pancakeCheck.type,
      riskContribution: 0,
      explanation: `PancakeSwap interaction: ${pancakeCheck.name}`,
      canNeverBeDrainer: true,
    };
  }
  
  // Check DeFi protocols
  const defiCheck = isBNBDeFiProtocol(normalized);
  if (defiCheck.isProtocol) {
    return {
      isLegitimateProtocol: true,
      protocolName: defiCheck.name,
      protocolType: defiCheck.type,
      riskContribution: 0,
      explanation: `BNB DeFi protocol: ${defiCheck.name}`,
      canNeverBeDrainer: true,
    };
  }
  
  // Check bridges
  if (isBNBBridge(normalized)) {
    const bridge = BNB_BRIDGES.get(normalized);
    return {
      isLegitimateProtocol: true,
      protocolName: bridge?.name,
      protocolType: 'BRIDGE',
      riskContribution: 1,
      explanation: `Bridge transaction: ${bridge?.name}`,
      canNeverBeDrainer: true,
    };
  }
  
  return {
    isLegitimateProtocol: false,
    riskContribution: 0,
    explanation: 'Not a recognized BNB protocol',
    canNeverBeDrainer: false,
  };
}

// ============================================
// BNB CHAIN DRAINER DETECTION RESULT
// ============================================

export interface BNBDrainerDetectionResult {
  isDrainer: boolean;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  signals: BNBDrainerSignals;
  missingCriteria: string[];
  explanation: string;
  shouldFlag: boolean;
}

/**
 * Detect BNB chain drainer with STRICT criteria.
 * 
 * REQUIREMENTS (ALL must be met for HIGH confidence):
 * 1. Unlimited approvals present (≥2)
 * 2. Token-agnostic sweeping (≥3 token types)
 * 3. Immediate forwarding (<5 min)
 * 4. Sink is NOT Binance/PancakeSwap/Farm
 * 5. At least 4 victims
 * 6. At least 4 independent signals
 */
export function detectBNBDrainerStrict(signals: BNBDrainerSignals): BNBDrainerDetectionResult {
  const missingCriteria: string[] = [];
  
  // Check each criterion
  if (!signals.hasUnlimitedApprovals) {
    missingCriteria.push(`Only ${signals.unlimitedApprovalCount} unlimited approvals (need ≥${BNB_DETECTION_THRESHOLDS.minApprovalAbuseCount})`);
  }
  
  if (!signals.hasTokenAgnosticSweeping) {
    missingCriteria.push(`Only ${signals.sweepedTokenCount} token types swept (need ≥3)`);
  }
  
  if (!signals.hasImmediateForwarding) {
    missingCriteria.push('No immediate forwarding pattern detected');
  }
  
  if (signals.sinkIsLegitimate) {
    missingCriteria.push(`Sink is legitimate: ${signals.sinkIsBinanceHotWallet ? 'Binance' : signals.sinkIsPancakeSwap ? 'PancakeSwap' : 'Known Protocol'}`);
  }
  
  if (signals.victimCount < BNB_DETECTION_THRESHOLDS.minVictimCount) {
    missingCriteria.push(`Only ${signals.victimCount} victims (need ≥${BNB_DETECTION_THRESHOLDS.minVictimCount})`);
  }
  
  if (signals.totalSignalCount < BNB_DETECTION_THRESHOLDS.minSignalsForActiveDrainer) {
    missingCriteria.push(`Only ${signals.totalSignalCount} signals (need ≥${BNB_DETECTION_THRESHOLDS.minSignalsForActiveDrainer})`);
  }
  
  // Determine confidence
  let confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' = 'NONE';
  let shouldFlag = false;
  
  if (signals.meetsThreshold && missingCriteria.length === 0) {
    confidence = 'HIGH';
    shouldFlag = true;
  } else if (signals.totalSignalCount >= 3 && !signals.sinkIsLegitimate) {
    confidence = 'MEDIUM';
    shouldFlag = false; // Don't auto-flag MEDIUM on BNB
  } else if (signals.totalSignalCount >= 2) {
    confidence = 'LOW';
    shouldFlag = false;
  }
  
  return {
    isDrainer: shouldFlag,
    confidence,
    signals,
    missingCriteria,
    explanation: shouldFlag
      ? `HIGH confidence BNB drainer: ${signals.totalSignalCount} signals, ${signals.victimCount} victims, sink is NOT legitimate`
      : `${confidence} confidence: Missing criteria: ${missingCriteria.slice(0, 2).join('; ')}`,
    shouldFlag,
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  BNB_DETECTION_THRESHOLDS as BNB_THRESHOLDS,
};
