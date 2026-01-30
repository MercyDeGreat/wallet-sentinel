// ============================================
// SECURNEX HARD-FAIL VALIDATOR
// ============================================
// Implements AUTO-REJECT conditions for false positive prevention
//
// HARD FAIL CONDITIONS (AUTO-REJECT PR):
// 1. Flags Uniswap, OpenSea, ENS, bridges
// 2. Flags self-transfers
// 3. Flags CEX wallets
// 4. Uses single heuristic detection
// 5. Uses ETH logic on Solana
//
// If ANY of these conditions are met, the detection result is REJECTED.

import { Chain } from '@/types';
import { SecurnexVerdict } from './verdict-enforcer';

// ============================================
// PROTECTED PROTOCOL NAMES
// ============================================
// These protocols should NEVER be flagged as drainers

const PROTECTED_PROTOCOLS = new Set([
  // DEX Routers
  'uniswap',
  'sushiswap',
  '1inch',
  'pancakeswap',
  '0x',
  'paraswap',
  'kyberswap',
  'odos',
  'cowswap',
  'balancer',
  'curve',
  'aerodrome',
  'baseswap',
  'jupiter',
  'raydium',
  'orca',
  
  // NFT Marketplaces
  'opensea',
  'blur',
  'looksrare',
  'x2y2',
  'rarible',
  'magic eden',
  'tensor',
  'zora',
  'foundation',
  'superrare',
  
  // ENS / Naming
  'ens',
  'basenames',
  'space id',
  'unstoppable domains',
  'bonfida',
  
  // Bridges
  'wormhole',
  'stargate',
  'layerzero',
  'across',
  'hop',
  'synapse',
  'celer',
  'multichain',
  'socket',
  'li.fi',
  'relay',
  'orbiter',
  'debridge',
  'portal',
  
  // Lending
  'aave',
  'compound',
  'morpho',
  'venus',
  'benqi',
  'radiant',
  'spark',
  'maker',
  
  // Staking
  'lido',
  'rocket pool',
  'coinbase staking',
  'mantle staking',
  
  // Other DeFi
  'yearn',
  'convex',
  'beefy',
  'alpaca',
  'autofarm',
  
  // CEX Infrastructure
  'binance',
  'coinbase',
  'kraken',
  'okx',
  'huobi',
  'kucoin',
  'bybit',
  'gemini',
  'bitfinex',
  'ftx', // Historical
  
  // Infrastructure
  'permit2',
  'seaport',
  'seadrop',
  'conduit',
  'gnosis safe',
  'safe',
]);

// ============================================
// HARD FAIL CONDITIONS
// ============================================

export type HardFailReason =
  | 'FLAGS_PROTECTED_PROTOCOL'
  | 'FLAGS_SELF_TRANSFER'
  | 'FLAGS_CEX_WALLET'
  | 'SINGLE_HEURISTIC_DETECTION'
  | 'USES_ETH_LOGIC_ON_SOLANA'
  | 'INSUFFICIENT_SIGNALS'
  | 'ALLOW_LIST_BYPASS';

export interface HardFailCondition {
  reason: HardFailReason;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  autoReject: boolean;
}

export const HARD_FAIL_CONDITIONS: HardFailCondition[] = [
  {
    reason: 'FLAGS_PROTECTED_PROTOCOL',
    description: 'Flagged a protected protocol (Uniswap, OpenSea, ENS, bridges, etc.) as malicious',
    severity: 'CRITICAL',
    autoReject: true,
  },
  {
    reason: 'FLAGS_SELF_TRANSFER',
    description: 'Flagged a self-transfer (sender == receiver) as malicious',
    severity: 'CRITICAL',
    autoReject: true,
  },
  {
    reason: 'FLAGS_CEX_WALLET',
    description: 'Flagged a centralized exchange wallet as malicious',
    severity: 'CRITICAL',
    autoReject: true,
  },
  {
    reason: 'SINGLE_HEURISTIC_DETECTION',
    description: 'Classified as active drainer using only a single heuristic/signal',
    severity: 'CRITICAL',
    autoReject: true,
  },
  {
    reason: 'USES_ETH_LOGIC_ON_SOLANA',
    description: 'Applied EVM-specific detection logic to Solana chain',
    severity: 'HIGH',
    autoReject: true,
  },
  {
    reason: 'INSUFFICIENT_SIGNALS',
    description: 'Classified as active drainer with fewer than 3 independent signals',
    severity: 'CRITICAL',
    autoReject: true,
  },
  {
    reason: 'ALLOW_LIST_BYPASS',
    description: 'Flagged an address that matched the allow-list',
    severity: 'CRITICAL',
    autoReject: true,
  },
];

// ============================================
// VALIDATION INPUT
// ============================================

export interface ValidationInput {
  // Verdict being validated
  verdict: SecurnexVerdict;
  
  // Chain context
  chain: Chain;
  
  // Detection details
  signalCount: number;
  signals: Array<{
    type: string;
    relatedAddresses: string[];
  }>;
  
  // Protocol interactions
  flaggedAddresses: string[];
  flaggedProtocolNames: string[];
  
  // Transaction context
  hasSelfTransfers: boolean;
  selfTransferCount: number;
  
  // CEX context
  involvesCEXWallet: boolean;
  cexWalletName?: string;
  
  // Allow-list context
  matchedAllowList: boolean;
  allowListMatches: string[];
}

// ============================================
// VALIDATION RESULT
// ============================================

export interface HardFailValidationResult {
  passed: boolean;
  failedConditions: HardFailCondition[];
  errors: string[];
  warnings: string[];
  shouldAutoReject: boolean;
  correctedVerdict?: SecurnexVerdict;
  explanation: string;
}

// ============================================
// MAIN VALIDATION FUNCTION
// ============================================

/**
 * Validate a detection result against hard-fail conditions.
 * 
 * If any CRITICAL hard-fail condition is met, the result is REJECTED
 * and should be corrected to NO_ACTIVE_THREAT_DETECTED.
 */
export function validateHardFailConditions(input: ValidationInput): HardFailValidationResult {
  const failedConditions: HardFailCondition[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  
  // Only check if verdict is ACTIVE_WALLET_DRAINER_DETECTED
  // Other verdicts don't need hard-fail validation
  if (input.verdict !== 'ACTIVE_WALLET_DRAINER_DETECTED') {
    return {
      passed: true,
      failedConditions: [],
      errors: [],
      warnings: [],
      shouldAutoReject: false,
      explanation: `Verdict ${input.verdict} does not require hard-fail validation.`,
    };
  }
  
  // ============================================
  // CHECK 1: Protected Protocol Flag
  // ============================================
  for (const protocolName of input.flaggedProtocolNames) {
    const normalized = protocolName.toLowerCase();
    for (const protected_ of PROTECTED_PROTOCOLS) {
      if (normalized.includes(protected_)) {
        failedConditions.push(HARD_FAIL_CONDITIONS[0]); // FLAGS_PROTECTED_PROTOCOL
        errors.push(`HARD FAIL: Flagged protected protocol "${protocolName}" as drainer`);
        break;
      }
    }
  }
  
  // Also check flagged addresses against protected protocols
  for (const addr of input.flaggedAddresses) {
    // This would typically check against the safe-contracts database
    // For now, we rely on the protocol names check above
  }
  
  // ============================================
  // CHECK 2: Self-Transfer Flag
  // ============================================
  if (input.hasSelfTransfers && input.selfTransferCount > 0) {
    // If the ONLY activity is self-transfers, this should never be a drainer
    // This is a hard fail if we're flagging as drainer
    failedConditions.push(HARD_FAIL_CONDITIONS[1]); // FLAGS_SELF_TRANSFER
    errors.push(`HARD FAIL: Flagged wallet with ${input.selfTransferCount} self-transfer(s) as drainer`);
  }
  
  // ============================================
  // CHECK 3: CEX Wallet Flag
  // ============================================
  if (input.involvesCEXWallet) {
    failedConditions.push(HARD_FAIL_CONDITIONS[2]); // FLAGS_CEX_WALLET
    errors.push(`HARD FAIL: Flagged CEX wallet (${input.cexWalletName || 'unknown'}) as drainer`);
  }
  
  // ============================================
  // CHECK 4: Single Heuristic Detection
  // ============================================
  if (input.signalCount < 2) {
    failedConditions.push(HARD_FAIL_CONDITIONS[3]); // SINGLE_HEURISTIC_DETECTION
    errors.push(`HARD FAIL: Single-signal detection (only ${input.signalCount} signal)`);
  }
  
  // ============================================
  // CHECK 5: ETH Logic on Solana
  // ============================================
  if (input.chain === 'solana') {
    const evmSignalTypes = ['APPROVAL', 'ERC20', 'ERC721', 'ERC1155', 'PERMIT'];
    
    for (const signal of input.signals) {
      for (const evmType of evmSignalTypes) {
        if (signal.type.toUpperCase().includes(evmType)) {
          failedConditions.push(HARD_FAIL_CONDITIONS[4]); // USES_ETH_LOGIC_ON_SOLANA
          errors.push(`HARD FAIL: Used EVM signal type "${signal.type}" on Solana`);
          break;
        }
      }
    }
  }
  
  // ============================================
  // CHECK 6: Insufficient Signals
  // ============================================
  if (input.signalCount < 3) {
    failedConditions.push(HARD_FAIL_CONDITIONS[5]); // INSUFFICIENT_SIGNALS
    errors.push(`HARD FAIL: Only ${input.signalCount} signals (need ≥3 for active drainer)`);
  }
  
  // ============================================
  // CHECK 7: Allow-List Bypass
  // ============================================
  if (input.matchedAllowList && input.allowListMatches.length > 0) {
    failedConditions.push(HARD_FAIL_CONDITIONS[6]); // ALLOW_LIST_BYPASS
    errors.push(`HARD FAIL: Flagged address that matched allow-list: ${input.allowListMatches.join(', ')}`);
  }
  
  // ============================================
  // DETERMINE RESULT
  // ============================================
  
  const shouldAutoReject = failedConditions.some(c => c.autoReject);
  const passed = failedConditions.length === 0;
  
  let explanation: string;
  let correctedVerdict: SecurnexVerdict | undefined;
  
  if (passed) {
    explanation = 'All hard-fail validations passed. Verdict is valid.';
  } else if (shouldAutoReject) {
    explanation = `AUTO-REJECT: ${failedConditions.length} hard-fail condition(s) violated. ` +
      `Verdict must be corrected to NO_ACTIVE_THREAT_DETECTED.`;
    correctedVerdict = 'NO_ACTIVE_THREAT_DETECTED';
  } else {
    explanation = `${failedConditions.length} validation warning(s). Review recommended.`;
  }
  
  return {
    passed,
    failedConditions,
    errors,
    warnings,
    shouldAutoReject,
    correctedVerdict,
    explanation,
  };
}

// ============================================
// QUICK VALIDATION HELPERS
// ============================================

/**
 * Quick check if a protocol name is protected.
 */
export function isProtectedProtocol(name: string): boolean {
  const normalized = name.toLowerCase();
  for (const protected_ of PROTECTED_PROTOCOLS) {
    if (normalized.includes(protected_)) {
      return true;
    }
  }
  return false;
}

/**
 * Quick check if detection would fail validation.
 * Use this BEFORE assigning ACTIVE_WALLET_DRAINER verdict.
 */
export function wouldFailValidation(
  chain: Chain,
  signalCount: number,
  matchedAllowList: boolean,
  involvesCEXWallet: boolean,
  involvesSelfTransfer: boolean
): { wouldFail: boolean; reason?: string } {
  if (matchedAllowList) {
    return { wouldFail: true, reason: 'Matched allow-list' };
  }
  
  if (involvesCEXWallet) {
    return { wouldFail: true, reason: 'Involves CEX wallet' };
  }
  
  if (involvesSelfTransfer) {
    return { wouldFail: true, reason: 'Involves self-transfer' };
  }
  
  if (signalCount < 3) {
    return { wouldFail: true, reason: `Insufficient signals (${signalCount} < 3)` };
  }
  
  return { wouldFail: false };
}

/**
 * Auto-correct a verdict if it would fail validation.
 * Returns the original verdict if valid, or corrected verdict if not.
 */
export function autoCorrectVerdict(
  proposedVerdict: SecurnexVerdict,
  input: ValidationInput
): { verdict: SecurnexVerdict; wasCorrect: boolean; correction?: string } {
  if (proposedVerdict !== 'ACTIVE_WALLET_DRAINER_DETECTED') {
    return { verdict: proposedVerdict, wasCorrect: true };
  }
  
  const validation = validateHardFailConditions(input);
  
  if (validation.passed) {
    return { verdict: proposedVerdict, wasCorrect: true };
  }
  
  if (validation.correctedVerdict) {
    return {
      verdict: validation.correctedVerdict,
      wasCorrect: false,
      correction: validation.explanation,
    };
  }
  
  // Default correction
  return {
    verdict: 'NO_ACTIVE_THREAT_DETECTED',
    wasCorrect: false,
    correction: `Hard-fail validation failed: ${validation.errors[0]}`,
  };
}

// ============================================
// TEST HELPERS
// ============================================

/**
 * Run all hard-fail validations as a test suite.
 * Returns a report of which conditions passed/failed.
 */
export function runValidationTestSuite(input: ValidationInput): {
  totalConditions: number;
  passedConditions: number;
  failedConditions: number;
  results: Array<{ condition: HardFailCondition; passed: boolean; error?: string }>;
} {
  const validation = validateHardFailConditions(input);
  
  const results = HARD_FAIL_CONDITIONS.map(condition => {
    const failed = validation.failedConditions.some(f => f.reason === condition.reason);
    const error = validation.errors.find(e => e.includes(condition.reason));
    
    return {
      condition,
      passed: !failed,
      error: error,
    };
  });
  
  return {
    totalConditions: HARD_FAIL_CONDITIONS.length,
    passedConditions: results.filter(r => r.passed).length,
    failedConditions: results.filter(r => !r.passed).length,
    results,
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  PROTECTED_PROTOCOLS,
  HARD_FAIL_CONDITIONS as HARD_FAIL_CONDITION_LIST,
};
