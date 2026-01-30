// ============================================
// SECURNEX MULTI-CHAIN DRAINER DETECTION ORCHESTRATOR
// ============================================
// Coordinates drainer detection across Ethereum, Base, BNB Chain, and Solana
// with chain-specific detection engines and shared utilities.
//
// 🔐 CORE OBJECTIVE: Detect real wallet drainers only
//
// ❌ NEVER FLAG:
// - Legitimate dApps (Uniswap, OpenSea, 1inch, ENS, bridges)
// - CEX hot wallets or deposit wallets
// - User self-initiated transfers (including rapid transfers)
// - Wallet-to-wallet transfers owned by the same user
// - Standard approval + swap flows
// - Known relayers, aggregators, or routers
//
// ✅ DETECTION MUST BE:
// - Evidence-based
// - Chain-specific
// - High confidence only
// - Multi-signal (never single heuristic)
//
// 🧠 GLOBAL DESIGN RULES:
// 1. NO single-signal verdicts - require ≥3 independent malicious signals
// 2. Allow-list before detection - check known protocols first
// 3. User-initiated intent overrides - never flag user flows
// 4. Past compromise ≠ active drainer
//
// 🛠️ IMPLEMENTATION:
// - Modular chain-isolated engines
// - Shared utilities (allow-list, reputation, clustering)
// - Chain logic NEVER blindly reused

import { Chain, SecurityStatus, RiskLevel } from '@/types';
import type {
  DrainerOverrideResult,
  DrainerBehaviorDetection,
  DrainerActivityRecencyInfo,
} from '@/types';

// ============================================
// OUTPUT CLASSIFICATION (MANDATORY)
// ============================================
// Only these 4 verdicts are allowed:

export type SecurnexVerdict =
  | 'ACTIVE_WALLET_DRAINER_DETECTED'    // Very rare - requires overwhelming evidence
  | 'PREVIOUSLY_COMPROMISED_RESOLVED'   // Historical compromise, no active threat
  | 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE' // Some signals but not enough for conviction
  | 'NO_ACTIVE_THREAT_DETECTED';        // Default - absence of evidence

export interface SecurnexAnalysisResult {
  // The verdict (one of 4 allowed values)
  verdict: SecurnexVerdict;
  
  // Confidence in verdict (0-100)
  confidence: number;
  
  // Chain analyzed
  chain: Chain;
  
  // Wallet address
  walletAddress: string;
  
  // Timestamp of analysis
  timestamp: string;
  
  // Number of independent malicious signals detected
  signalCount: number;
  
  // Signals that were detected
  detectedSignals: DrainerBehaviorDetection[];
  
  // Signals that WOULD have been detected but were excluded (allow-list)
  excludedSignals: ExcludedSignal[];
  
  // Explanation of the verdict
  explanation: string;
  
  // For ACTIVE_WALLET_DRAINER_DETECTED only: immediate action required
  immediateAction?: string;
  
  // For PREVIOUSLY_COMPROMISED_RESOLVED: when was the last incident
  lastIncidentTimestamp?: string;
  daysSinceLastIncident?: number;
  
  // Was allow-list checked? (MUST be true)
  allowListChecked: boolean;
  
  // Matched allow-list entries
  matchedAllowList: AllowListMatch[];
  
  // Did context classification run? (MUST be true before detection)
  contextClassificationRan: boolean;
  
  // Raw detection output (for debugging)
  rawDetectionOutput?: DrainerOverrideResult;
}

export interface ExcludedSignal {
  signalType: string;
  reason: string;
  matchedAllowListEntry?: string;
}

export interface AllowListMatch {
  address: string;
  name: string;
  category: AllowListCategory;
  chain: Chain;
}

export type AllowListCategory =
  | 'DEX_ROUTER'
  | 'DEX_AGGREGATOR'
  | 'NFT_MARKETPLACE'
  | 'BRIDGE'
  | 'ENS'
  | 'CEX_WALLET'
  | 'KNOWN_RELAYER'
  | 'STAKING_PROTOCOL'
  | 'LENDING_PROTOCOL'
  | 'MULTISIG'
  | 'VERIFIED_CONTRACT';

// ============================================
// MULTI-SIGNAL THRESHOLD CONFIGURATION
// ============================================
// RULE: A wallet is NOT malicious unless ≥3 independent signals exist

export interface SignalThresholds {
  // Minimum signals required for ACTIVE_WALLET_DRAINER_DETECTED
  minSignalsForActiveDrainer: number;
  
  // Minimum signals required for SUSPICIOUS_PATTERN_LOW_CONFIDENCE
  minSignalsForSuspicious: number;
  
  // Minimum confidence required for ACTIVE_WALLET_DRAINER_DETECTED
  minConfidenceForActiveDrainer: number;
  
  // Days of inactivity to consider "resolved"
  daysForResolved: number;
}

export const DEFAULT_SIGNAL_THRESHOLDS: SignalThresholds = {
  minSignalsForActiveDrainer: 3,       // MANDATORY: ≥3 independent signals
  minSignalsForSuspicious: 1,
  minConfidenceForActiveDrainer: 90,   // Very high confidence required
  daysForResolved: 90,
};

// ============================================
// CHAIN-SPECIFIC CONFIGURATION
// ============================================
// Each chain has different detection characteristics

export interface ChainDetectionConfig {
  chain: Chain;
  
  // Signal thresholds (may vary by chain)
  thresholds: SignalThresholds;
  
  // Additional checks required for this chain
  additionalChecks: string[];
  
  // Explicit exclusions for this chain
  explicitExclusions: string[];
  
  // Notes on chain-specific detection
  notes: string;
}

export const CHAIN_CONFIGS: Record<Chain, ChainDetectionConfig> = {
  ethereum: {
    chain: 'ethereum',
    thresholds: {
      ...DEFAULT_SIGNAL_THRESHOLDS,
    },
    additionalChecks: [
      'Malicious approval OR permit signature',
      'Non-interactive asset outflow',
      'Destination: newly created OR known drainer cluster OR aggregation sink',
      'Transfer bypasses standard routers',
      'Identical pattern across ≥3 unrelated wallets',
    ],
    explicitExclusions: [
      'Uniswap', '1inch', 'OpenSea', 'Blur', 'ENS', 'bridges',
      'Approvals without execution', 'Self-transfers',
      'MEV or gas-optimized bundling',
    ],
    notes: 'EVM – High Signal Availability',
  },
  
  base: {
    chain: 'base',
    thresholds: {
      ...DEFAULT_SIGNAL_THRESHOLDS,
      // Base may have more aggressive automation - extra safeguards
      minSignalsForActiveDrainer: 3,
    },
    additionalChecks: [
      'Repeated ERC20 sweeps in same block',
      'Contract-less EOAs acting as sinks',
      'Abnormal call traces',
      'No UI-linked router',
      'Cross-wallet repetition',
    ],
    explicitExclusions: [
      'ENS.base (Basenames)',
      'Official Base bridge',
      'Coinbase-linked wallets',
      'Public Base infra relayers',
      'Aerodrome', 'BaseSwap', 'Uniswap on Base',
    ],
    notes: 'EVM – More Aggressive Automation - Extra Safeguards Required',
  },
  
  bnb: {
    chain: 'bnb',
    thresholds: {
      ...DEFAULT_SIGNAL_THRESHOLDS,
      // BNB Chain has high scam density - require HIGHER threshold
      minSignalsForActiveDrainer: 4,
      minConfidenceForActiveDrainer: 95,
    },
    additionalChecks: [
      'Unlimited approvals',
      'Token-agnostic sweeping',
      'Immediate forwarding',
      'Sink NOT Binance hot wallet',
      'Sink NOT PancakeSwap router',
      'Sink NOT known farm or pool',
    ],
    explicitExclusions: [
      'PancakeSwap',
      'Binance infrastructure',
      'Legit farming contracts',
      'Venus Protocol', 'Alpaca Finance',
    ],
    notes: 'EVM – High Scam Density - Higher Threshold Required',
  },
  
  solana: {
    chain: 'solana',
    thresholds: {
      ...DEFAULT_SIGNAL_THRESHOLDS,
      // Solana has low explicit signals - STRICT rules
      minSignalsForActiveDrainer: 3,
      minConfidenceForActiveDrainer: 95,
    },
    additionalChecks: [
      'SPL delegate authority abused',
      'Assets moved without wallet-initiated instruction',
      'Same drain instruction across many wallets',
      'Destination wallet linked to prior drains',
    ],
    explicitExclusions: [
      'OpenSea (Solana)',
      'Magic Eden',
      'Verified mint programs',
      'Self-transfers',
      'Legit bridges (Wormhole, Portal, DeBridge)',
      'Jupiter', 'Raydium', 'Orca',
    ],
    notes: 'Non-EVM – Low Explicit Signals - Absence ≠ Proof. If evidence incomplete → NO_ACTIVE_THREAT_DETECTED',
  },
};

// ============================================
// DETECTION INPUT TYPES
// ============================================

export interface TransactionForAnalysis {
  hash: string;
  from: string;
  to: string;
  value: string;
  input: string;
  timestamp: number;
  blockNumber: number;
  methodId?: string;
  isError?: boolean;
}

export interface TokenTransferForAnalysis {
  from: string;
  to: string;
  value: string;
  hash: string;
  timestamp: number;
  tokenSymbol: string;
  tokenAddress: string;
  tokenType?: 'ERC20' | 'ERC721' | 'ERC1155';
}

export interface ApprovalForAnalysis {
  token: string;
  tokenSymbol: string;
  spender: string;
  owner: string;
  amount: string;
  isUnlimited: boolean;
  timestamp: number;
  transactionHash: string;
  wasRevoked?: boolean;
}

// ============================================
// MULTI-CHAIN ORCHESTRATOR CLASS
// ============================================

export class SecurnexMultiChainOrchestrator {
  private config: Record<Chain, ChainDetectionConfig>;
  
  constructor(customConfig?: Partial<Record<Chain, ChainDetectionConfig>>) {
    this.config = {
      ...CHAIN_CONFIGS,
      ...customConfig,
    };
  }
  
  /**
   * Main entry point for multi-chain drainer detection.
   * 
   * CRITICAL: This method enforces ALL design rules:
   * 1. Allow-list check FIRST
   * 2. Context classification BEFORE detection
   * 3. Multi-signal requirement (≥3)
   * 4. Chain-specific logic
   * 5. Output classification enforcement
   */
  async analyzeWallet(
    walletAddress: string,
    chain: Chain,
    transactions: TransactionForAnalysis[],
    tokenTransfers: TokenTransferForAnalysis[],
    approvals: ApprovalForAnalysis[],
    options?: {
      ens?: string;
      isDeployer?: boolean;
      bidirectionalPeers?: string[];
    }
  ): Promise<SecurnexAnalysisResult> {
    const normalized = walletAddress.toLowerCase();
    const chainConfig = this.config[chain];
    const timestamp = new Date().toISOString();
    
    // ============================================
    // PHASE 1: ALLOW-LIST CHECK (MANDATORY FIRST)
    // ============================================
    const allowListMatches = await this.checkAllowList(
      normalized,
      chain,
      transactions,
      tokenTransfers
    );
    
    // If wallet itself is on allow-list, hard exit
    const walletOnAllowList = allowListMatches.find(m => 
      m.address.toLowerCase() === normalized
    );
    
    if (walletOnAllowList) {
      return this.createNoThreatResult(
        normalized,
        chain,
        timestamp,
        `Wallet is on allow-list: ${walletOnAllowList.name} (${walletOnAllowList.category})`,
        allowListMatches,
        true, // allowListChecked
        true  // contextClassificationRan
      );
    }
    
    // ============================================
    // PHASE 2: CONTEXT CLASSIFICATION (BEFORE DETECTION)
    // ============================================
    const contextResult = this.classifyWalletContext(
      normalized,
      chain,
      transactions,
      tokenTransfers,
      options
    );
    
    // If context says skip detection (DEX trader, protocol, deployer, etc.)
    if (contextResult.skipDetection) {
      return this.createNoThreatResult(
        normalized,
        chain,
        timestamp,
        `Context: ${contextResult.reason}`,
        allowListMatches,
        true,
        true
      );
    }
    
    // ============================================
    // PHASE 3: USER-INITIATED INTENT CHECK
    // ============================================
    // If ALL transactions are user-initiated flows → never flag
    const userIntentCheck = this.checkUserInitiatedIntent(
      transactions,
      tokenTransfers,
      allowListMatches
    );
    
    if (userIntentCheck.allUserInitiated) {
      return this.createNoThreatResult(
        normalized,
        chain,
        timestamp,
        `All activity is user-initiated: ${userIntentCheck.reason}`,
        allowListMatches,
        true,
        true
      );
    }
    
    // ============================================
    // PHASE 4: CHAIN-SPECIFIC DETECTION
    // ============================================
    const detectionResult = await this.runChainSpecificDetection(
      normalized,
      chain,
      chainConfig,
      transactions,
      tokenTransfers,
      approvals,
      allowListMatches
    );
    
    // ============================================
    // PHASE 5: SIGNAL COUNTING & THRESHOLDING
    // ============================================
    const signalCount = detectionResult.signals.length;
    const highConfidenceSignals = detectionResult.signals.filter(s => s.confidence >= 80);
    const thresholds = chainConfig.thresholds;
    
    // ============================================
    // PHASE 6: VERDICT DETERMINATION
    // ============================================
    let verdict: SecurnexVerdict;
    let confidence: number;
    let explanation: string;
    
    // RULE: ≥3 independent high-confidence signals required for ACTIVE_WALLET_DRAINER
    if (
      signalCount >= thresholds.minSignalsForActiveDrainer &&
      highConfidenceSignals.length >= thresholds.minSignalsForActiveDrainer &&
      detectionResult.confidence >= thresholds.minConfidenceForActiveDrainer &&
      detectionResult.isActive
    ) {
      verdict = 'ACTIVE_WALLET_DRAINER_DETECTED';
      confidence = detectionResult.confidence;
      explanation = `CRITICAL: ${signalCount} independent malicious signals detected. ` +
        `Patterns: ${detectionResult.signals.map(s => s.signal).join(', ')}. ` +
        `This is a confirmed active drainer.`;
    } else if (
      signalCount >= thresholds.minSignalsForSuspicious &&
      !detectionResult.isActive &&
      detectionResult.daysSinceLastIncident !== undefined &&
      detectionResult.daysSinceLastIncident >= thresholds.daysForResolved
    ) {
      // Historical compromise, now resolved
      verdict = 'PREVIOUSLY_COMPROMISED_RESOLVED';
      confidence = Math.min(detectionResult.confidence, 80);
      explanation = `Historical compromise detected but no active threat. ` +
        `Last incident: ${detectionResult.daysSinceLastIncident} days ago. ` +
        `All malicious access appears revoked.`;
    } else if (
      signalCount >= thresholds.minSignalsForSuspicious &&
      signalCount < thresholds.minSignalsForActiveDrainer
    ) {
      // Some signals but not enough for conviction
      verdict = 'SUSPICIOUS_PATTERN_LOW_CONFIDENCE';
      confidence = Math.min(detectionResult.confidence, 60);
      explanation = `${signalCount} suspicious signal(s) detected but insufficient evidence ` +
        `for drainer classification. Required: ≥${thresholds.minSignalsForActiveDrainer} independent signals.`;
    } else {
      // Default: no threat
      verdict = 'NO_ACTIVE_THREAT_DETECTED';
      confidence = 100 - (signalCount * 10);
      explanation = signalCount > 0
        ? `${signalCount} minor signal(s) detected but no drainer behavior confirmed.`
        : 'No drainer behavior patterns detected. Wallet appears safe.';
    }
    
    return {
      verdict,
      confidence,
      chain,
      walletAddress: normalized,
      timestamp,
      signalCount,
      detectedSignals: detectionResult.signals,
      excludedSignals: detectionResult.excludedSignals,
      explanation,
      immediateAction: verdict === 'ACTIVE_WALLET_DRAINER_DETECTED'
        ? 'URGENT: Do NOT send any funds to this address. This is a confirmed drainer.'
        : undefined,
      lastIncidentTimestamp: detectionResult.lastIncidentTimestamp,
      daysSinceLastIncident: detectionResult.daysSinceLastIncident,
      allowListChecked: true,
      matchedAllowList: allowListMatches,
      contextClassificationRan: true,
      rawDetectionOutput: detectionResult.rawResult,
    };
  }
  
  // ============================================
  // ALLOW-LIST CHECKING
  // ============================================
  
  private async checkAllowList(
    walletAddress: string,
    chain: Chain,
    transactions: TransactionForAnalysis[],
    tokenTransfers: TokenTransferForAnalysis[]
  ): Promise<AllowListMatch[]> {
    const matches: AllowListMatch[] = [];
    const checkedAddresses = new Set<string>();
    
    // Collect all addresses to check
    const addressesToCheck = new Set<string>();
    addressesToCheck.add(walletAddress.toLowerCase());
    
    for (const tx of transactions) {
      if (tx.to) addressesToCheck.add(tx.to.toLowerCase());
      if (tx.from) addressesToCheck.add(tx.from.toLowerCase());
    }
    
    for (const tt of tokenTransfers) {
      if (tt.to) addressesToCheck.add(tt.to.toLowerCase());
      if (tt.from) addressesToCheck.add(tt.from.toLowerCase());
    }
    
    // Check each address against allow-list
    // This uses the existing safe-contracts.ts infrastructure
    const { isSafeContractOnChain, isNamingServiceContract } = await import('./safe-contracts');
    const { checkInfrastructureProtection, isVerifiedDEXRouter, isKnownCEXWallet } = await import('./infrastructure-protection');
    const { checkExchangeWallet } = await import('./base-chain-protection');
    
    for (const addr of addressesToCheck) {
      if (checkedAddresses.has(addr)) continue;
      checkedAddresses.add(addr);
      
      // Check safe contracts
      const safeContract = isSafeContractOnChain(addr, chain);
      if (safeContract) {
        matches.push({
          address: addr,
          name: safeContract.name,
          category: this.mapCategoryToAllowListCategory(safeContract.category),
          chain,
        });
        continue;
      }
      
      // Check infrastructure protection
      const infraCheck = checkInfrastructureProtection(addr, chain);
      if (infraCheck.isProtected) {
        matches.push({
          address: addr,
          name: infraCheck.name || 'Protected Infrastructure',
          category: this.mapInfraTypeToCategory(infraCheck.type),
          chain,
        });
        continue;
      }
      
      // Check DEX routers
      if (isVerifiedDEXRouter(addr, chain)) {
        matches.push({
          address: addr,
          name: 'Verified DEX Router',
          category: 'DEX_ROUTER',
          chain,
        });
        continue;
      }
      
      // Check naming services (ENS, Basenames, etc.)
      if (isNamingServiceContract(addr, chain)) {
        matches.push({
          address: addr,
          name: chain === 'base' ? 'Basenames' : 'ENS',
          category: 'ENS',
          chain,
        });
        continue;
      }
      
      // Check CEX wallets
      const cexCheck = checkExchangeWallet(addr);
      if (cexCheck.isExchange) {
        matches.push({
          address: addr,
          name: cexCheck.exchangeInfo?.name || 'Exchange Wallet',
          category: 'CEX_WALLET',
          chain,
        });
        continue;
      }
      
      // Check if known CEX wallet
      if (isKnownCEXWallet(addr)) {
        matches.push({
          address: addr,
          name: 'Known CEX Wallet',
          category: 'CEX_WALLET',
          chain,
        });
      }
    }
    
    return matches;
  }
  
  private mapCategoryToAllowListCategory(category: string): AllowListCategory {
    const mapping: Record<string, AllowListCategory> = {
      'NFT_MARKETPLACE': 'NFT_MARKETPLACE',
      'NFT_MINT_CONTRACT': 'NFT_MARKETPLACE',
      'DEFI_PROTOCOL': 'DEX_ROUTER',
      'DEX_ROUTER': 'DEX_ROUTER',
      'BRIDGE': 'BRIDGE',
      'ENS': 'ENS',
      'STAKING': 'STAKING_PROTOCOL',
      'LENDING': 'LENDING_PROTOCOL',
      'AGGREGATOR': 'DEX_AGGREGATOR',
      'INFRASTRUCTURE': 'KNOWN_RELAYER',
      'RELAYER': 'KNOWN_RELAYER',
      'MULTISIG': 'MULTISIG',
      'TOKEN_CONTRACT': 'VERIFIED_CONTRACT',
      'YIELD_OPTIMIZER': 'STAKING_PROTOCOL',
      'VERIFIED_PROJECT': 'VERIFIED_CONTRACT',
    };
    return mapping[category] || 'VERIFIED_CONTRACT';
  }
  
  private mapInfraTypeToCategory(type: string | undefined): AllowListCategory {
    if (!type) return 'VERIFIED_CONTRACT';
    const mapping: Record<string, AllowListCategory> = {
      'DEX_ROUTER': 'DEX_ROUTER',
      'AGGREGATOR': 'DEX_AGGREGATOR',
      'NFT_MARKETPLACE': 'NFT_MARKETPLACE',
      'BRIDGE': 'BRIDGE',
      'ENS_INFRASTRUCTURE': 'ENS',
      'LENDING_PROTOCOL': 'LENDING_PROTOCOL',
    };
    return mapping[type] || 'VERIFIED_CONTRACT';
  }
  
  // ============================================
  // CONTEXT CLASSIFICATION
  // ============================================
  
  private classifyWalletContext(
    walletAddress: string,
    chain: Chain,
    transactions: TransactionForAnalysis[],
    tokenTransfers: TokenTransferForAnalysis[],
    options?: {
      ens?: string;
      isDeployer?: boolean;
      bidirectionalPeers?: string[];
    }
  ): { skipDetection: boolean; reason: string } {
    const normalized = walletAddress.toLowerCase();
    
    // Check if deployer
    if (options?.isDeployer) {
      return {
        skipDetection: true,
        reason: 'Wallet is a contract deployer - protected from drainer classification',
      };
    }
    
    // Check if has ENS (indicates legitimate user)
    if (options?.ens) {
      // ENS alone doesn't skip detection, but it's a strong signal
    }
    
    // Check for bidirectional relationships (likely same owner)
    if (options?.bidirectionalPeers && options.bidirectionalPeers.length > 0) {
      return {
        skipDetection: true,
        reason: 'Wallet has bidirectional transfer relationships - likely self-owned wallets',
      };
    }
    
    // Check if all transactions are to/from safe destinations
    const allToSafe = transactions.every(tx => {
      // Self-transfer
      if (tx.from.toLowerCase() === tx.to?.toLowerCase()) return true;
      // Will be checked in allow-list
      return false;
    });
    
    if (allToSafe && transactions.length > 0) {
      return {
        skipDetection: true,
        reason: 'All transactions are self-transfers',
      };
    }
    
    // Check self-transfer ratio
    const selfTransfers = transactions.filter(tx => 
      tx.from.toLowerCase() === normalized && tx.to?.toLowerCase() === normalized
    );
    if (selfTransfers.length === transactions.length && transactions.length > 0) {
      return {
        skipDetection: true,
        reason: 'All transactions are self-transfers (wallet reorganization)',
      };
    }
    
    return { skipDetection: false, reason: '' };
  }
  
  // ============================================
  // USER-INITIATED INTENT CHECK
  // ============================================
  
  private checkUserInitiatedIntent(
    transactions: TransactionForAnalysis[],
    tokenTransfers: TokenTransferForAnalysis[],
    allowListMatches: AllowListMatch[]
  ): { allUserInitiated: boolean; reason: string } {
    const allowListAddresses = new Set(allowListMatches.map(m => m.address.toLowerCase()));
    
    // Known user-action method signatures
    const userActionMethods = new Set([
      '0x1249c58b', // mint()
      '0xa0712d68', // mint(uint256)
      '0x40c10f19', // mint(address,uint256)
      '0xfb0f3ee1', // fulfillBasicOrder
      '0x87201b41', // fulfillOrder
      '0x38ed1739', // swapExactTokensForTokens
      '0x7ff36ab5', // swapExactETHForTokens
      '0x04e45aaf', // exactInputSingle
      '0xb858183f', // exactInput
      '0xd0e30db0', // deposit()
      '0xa694fc3a', // stake(uint256)
      '0xe8eda9df', // deposit (Aave)
      '0x74694a2b', // renew (ENS)
      '0xaeb8ce9b', // registerWithConfig (ENS)
      '0x8c6f3d39', // register
    ]);
    
    // Check if all transactions are to allow-listed addresses or use user-action methods
    let userInitiatedCount = 0;
    for (const tx of transactions) {
      const toAddress = tx.to?.toLowerCase() || '';
      const methodId = tx.methodId || tx.input?.slice(0, 10);
      
      if (allowListAddresses.has(toAddress)) {
        userInitiatedCount++;
        continue;
      }
      
      if (methodId && userActionMethods.has(methodId.toLowerCase())) {
        userInitiatedCount++;
        continue;
      }
    }
    
    if (transactions.length > 0 && userInitiatedCount === transactions.length) {
      return {
        allUserInitiated: true,
        reason: `All ${transactions.length} transactions are user-initiated (mints, swaps, stakes, etc.)`,
      };
    }
    
    return { allUserInitiated: false, reason: '' };
  }
  
  // ============================================
  // CHAIN-SPECIFIC DETECTION
  // ============================================
  
  private async runChainSpecificDetection(
    walletAddress: string,
    chain: Chain,
    config: ChainDetectionConfig,
    transactions: TransactionForAnalysis[],
    tokenTransfers: TokenTransferForAnalysis[],
    approvals: ApprovalForAnalysis[],
    allowListMatches: AllowListMatch[]
  ): Promise<{
    signals: DrainerBehaviorDetection[];
    excludedSignals: ExcludedSignal[];
    confidence: number;
    isActive: boolean;
    lastIncidentTimestamp?: string;
    daysSinceLastIncident?: number;
    rawResult?: DrainerOverrideResult;
  }> {
    // Import chain-specific detectors
    const { detectDrainerActivity } = await import('./drainer-activity-detector');
    
    // Convert transactions to detector format
    const txsForDetector = transactions.map(tx => ({
      hash: tx.hash,
      from: tx.from,
      to: tx.to || '',
      value: tx.value,
      input: tx.input,
      timestamp: tx.timestamp,
      blockNumber: tx.blockNumber,
      methodId: tx.methodId,
      isError: tx.isError,
    }));
    
    const transfersForDetector = tokenTransfers.map(t => ({
      from: t.from,
      to: t.to,
      value: t.value,
      hash: t.hash,
      timestamp: t.timestamp,
      tokenSymbol: t.tokenSymbol,
      tokenAddress: t.tokenAddress,
      tokenType: t.tokenType,
    }));
    
    const approvalsForDetector = approvals.map(a => ({
      token: a.token,
      tokenSymbol: a.tokenSymbol,
      spender: a.spender,
      owner: a.owner,
      amount: a.amount,
      isUnlimited: a.isUnlimited,
      timestamp: a.timestamp,
      transactionHash: a.transactionHash,
      blockNumber: 0,
      wasRevoked: a.wasRevoked,
    }));
    
    // Run detection
    const result = detectDrainerActivity(
      walletAddress,
      chain,
      txsForDetector,
      transfersForDetector,
      approvalsForDetector,
      Math.floor(Date.now() / 1000)
    );
    
    // Filter signals that hit allow-list
    const allowListAddresses = new Set(allowListMatches.map(m => m.address.toLowerCase()));
    const excludedSignals: ExcludedSignal[] = [];
    const validSignals: DrainerBehaviorDetection[] = [];
    
    for (const signal of result.detectedSignals) {
      // Check if any related address is on allow-list
      const hitAllowList = signal.relatedAddresses.some(addr => 
        allowListAddresses.has(addr.toLowerCase())
      );
      
      if (hitAllowList) {
        const matchedEntry = allowListMatches.find(m => 
          signal.relatedAddresses.some(a => a.toLowerCase() === m.address.toLowerCase())
        );
        excludedSignals.push({
          signalType: signal.signal,
          reason: 'Related address is on allow-list',
          matchedAllowListEntry: matchedEntry?.name,
        });
      } else {
        validSignals.push(signal);
      }
    }
    
    return {
      signals: validSignals,
      excludedSignals,
      confidence: result.confidence,
      isActive: result.recency.isActive,
      lastIncidentTimestamp: result.recency.lastActivityTimestamp,
      daysSinceLastIncident: result.recency.daysSinceLastActivity,
      rawResult: result,
    };
  }
  
  // ============================================
  // HELPER: CREATE NO-THREAT RESULT
  // ============================================
  
  private createNoThreatResult(
    walletAddress: string,
    chain: Chain,
    timestamp: string,
    explanation: string,
    allowListMatches: AllowListMatch[],
    allowListChecked: boolean,
    contextClassificationRan: boolean
  ): SecurnexAnalysisResult {
    return {
      verdict: 'NO_ACTIVE_THREAT_DETECTED',
      confidence: 100,
      chain,
      walletAddress,
      timestamp,
      signalCount: 0,
      detectedSignals: [],
      excludedSignals: [],
      explanation,
      allowListChecked,
      matchedAllowList: allowListMatches,
      contextClassificationRan,
    };
  }
}

// ============================================
// HARD-FAIL VALIDATION
// ============================================
// These conditions auto-reject any detection result

export interface HardFailValidation {
  passed: boolean;
  failedRules: string[];
}

/**
 * Validate that a detection result does NOT trigger any hard-fail conditions.
 * 
 * HARD FAIL CONDITIONS (AUTO-REJECT):
 * - Flags Uniswap, OpenSea, ENS, bridges
 * - Flags self-transfers
 * - Flags CEX wallets
 * - Uses single heuristic detection
 * - Uses ETH logic on Solana
 */
export function validateHardFailConditions(
  result: SecurnexAnalysisResult,
  chain: Chain
): HardFailValidation {
  const failedRules: string[] = [];
  
  // Rule 1: Cannot flag known safe protocols
  const safeProtocolNames = [
    'uniswap', 'opensea', 'ens', 'blur', '1inch', 'pancakeswap',
    'aave', 'compound', 'wormhole', 'stargate', 'lido', 'rocket pool',
    'magic eden', 'tensor', 'jupiter', 'raydium', 'orca',
  ];
  
  for (const match of result.matchedAllowList) {
    const nameLower = match.name.toLowerCase();
    if (safeProtocolNames.some(p => nameLower.includes(p))) {
      if (result.verdict === 'ACTIVE_WALLET_DRAINER_DETECTED') {
        failedRules.push(`HARD FAIL: Flagged ${match.name} as drainer`);
      }
    }
  }
  
  // Rule 2: Cannot flag self-transfers as drainer
  if (result.explanation.toLowerCase().includes('self-transfer') && 
      result.verdict === 'ACTIVE_WALLET_DRAINER_DETECTED') {
    failedRules.push('HARD FAIL: Flagged self-transfers as drainer');
  }
  
  // Rule 3: Cannot flag CEX wallets as drainer
  const cexMatches = result.matchedAllowList.filter(m => m.category === 'CEX_WALLET');
  if (cexMatches.length > 0 && result.verdict === 'ACTIVE_WALLET_DRAINER_DETECTED') {
    failedRules.push(`HARD FAIL: Flagged CEX wallet (${cexMatches[0].name}) as drainer`);
  }
  
  // Rule 4: Cannot use single heuristic for ACTIVE_WALLET_DRAINER
  if (result.verdict === 'ACTIVE_WALLET_DRAINER_DETECTED' && result.signalCount < 3) {
    failedRules.push(`HARD FAIL: Single-signal detection (only ${result.signalCount} signals, need ≥3)`);
  }
  
  // Rule 5: Cannot use ETH-specific logic on Solana
  if (chain === 'solana') {
    const evmSignals = result.detectedSignals.filter(s => 
      s.signal.includes('ERC20') || 
      s.signal.includes('ERC721') ||
      s.signal.includes('APPROVAL') // EVM-specific approval concept
    );
    if (evmSignals.length > 0) {
      failedRules.push('HARD FAIL: Used EVM-specific logic on Solana');
    }
  }
  
  return {
    passed: failedRules.length === 0,
    failedRules,
  };
}

// ============================================
// EXPORTS
// ============================================

export const createOrchestrator = (
  customConfig?: Partial<Record<Chain, ChainDetectionConfig>>
) => new SecurnexMultiChainOrchestrator(customConfig);

export default SecurnexMultiChainOrchestrator;
