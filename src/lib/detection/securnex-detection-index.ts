// ============================================
// SECURNEX MULTI-CHAIN DRAINER DETECTION SYSTEM
// ============================================
//
// 🔐 CORE OBJECTIVE: Detect real wallet drainers with ZERO false positives
//
// ============================================
// ARCHITECTURE OVERVIEW
// ============================================
//
// This detection system is organized into chain-isolated engines with shared utilities:
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │                    SecurnexMultiChainOrchestrator                    │
// │                         (Entry Point)                                │
// └─────────────────────────────────────────────────────────────────────┘
//                                    │
//          ┌────────────────────────┼────────────────────────┐
//          │                        │                        │
//          ▼                        ▼                        ▼
// ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
// │  EVM Analyzer   │    │  Solana Analyzer │    │  Verdict        │
// │  (ETH/Base/BNB) │    │  (SPL/PDA-aware) │    │  Enforcer       │
// └─────────────────┘    └─────────────────┘    └─────────────────┘
//          │                        │                        │
//          │                        │                        ▼
//          │                        │             ┌─────────────────┐
//          │                        │             │  Hard-Fail      │
//          │                        │             │  Validator      │
//          │                        │             └─────────────────┘
//          │                        │
//          ▼                        ▼
// ┌─────────────────────────────────────────────────────────────────────┐
// │                        Shared Utilities                              │
// │  • Allow-list (safe-contracts, infrastructure-protection)            │
// │  • CEX Wallet Detection                                              │
// │  • Multi-Signal Detection (≥3 signals required)                      │
// │  • Context Classification                                            │
// └─────────────────────────────────────────────────────────────────────┘
//
// ============================================
// CHAIN-SPECIFIC DETECTION
// ============================================
//
// ETHEREUM (EVM - High Signal Availability):
//   - Requires: malicious approval OR permit signature
//   - Requires: non-interactive asset outflow
//   - Requires: suspicious destination pattern
//   - Requires: ≥3 unrelated wallets with same pattern
//   - Excludes: Uniswap, 1inch, OpenSea, Blur, ENS, bridges
//
// BASE (EVM - More Aggressive Automation):
//   - Same as ETH + Base-specific checks
//   - Detects: repeated ERC20 sweeps in same block
//   - Detects: contract-less EOAs acting as sinks
//   - Excludes: ENS.base, Official Base bridge, Coinbase wallets
//
// BNB (EVM - High Scam Density):
//   - HIGHER thresholds (4 signals, 95% confidence)
//   - Requires: unlimited approvals + token-agnostic sweeping
//   - Sink must NOT be Binance/PancakeSwap/Farm
//   - Excludes: PancakeSwap, Venus, Alpaca, Binance infrastructure
//
// SOLANA (Non-EVM - Low Explicit Signals):
//   - Uses three-state model (SAFE/PREVIOUSLY/ACTIVE)
//   - Detects: SPL delegate authority abuse
//   - Detects: unauthorized SetAuthority
//   - Detects: PDA drain patterns
//   - Excludes: Magic Eden, Jupiter, Raydium, Wormhole
//   - DEFAULT: NO_ACTIVE_THREAT if evidence incomplete
//
// ============================================
// OUTPUT CLASSIFICATION (4 VERDICTS ONLY)
// ============================================
//
// 1. ACTIVE_WALLET_DRAINER_DETECTED (very rare)
//    - Requires ≥3 independent signals
//    - Requires ≥90% confidence
//    - Requires recent activity (<90 days)
//
// 2. PREVIOUSLY_COMPROMISED_RESOLVED
//    - Historical compromise detected
//    - No active approvals
//    - No recent suspicious activity
//
// 3. SUSPICIOUS_PATTERN_LOW_CONFIDENCE
//    - Some signals but not enough for conviction
//    - 1-2 signals detected
//    - Confidence <90%
//
// 4. NO_ACTIVE_THREAT_DETECTED (default)
//    - No drainer patterns found
//    - Matched allow-list
//    - Protected infrastructure
//
// ============================================
// HARD-FAIL CONDITIONS (AUTO-REJECT)
// ============================================
//
// Detection is REJECTED if ANY of these occur:
// 1. Flags Uniswap, OpenSea, ENS, bridges
// 2. Flags self-transfers
// 3. Flags CEX wallets
// 4. Uses single heuristic detection
// 5. Uses ETH logic on Solana

// ============================================
// EXPORTS
// ============================================

// Main Orchestrator
export { 
  SecurnexMultiChainOrchestrator,
  createOrchestrator,
  type SecurnexAnalysisResult,
  type SecurnexVerdict as OrchestratorVerdict,
  type AllowListCategory,
  type AllowListMatch,
  type ChainDetectionConfig,
  type SignalThresholds,
  CHAIN_CONFIGS,
  DEFAULT_SIGNAL_THRESHOLDS,
  validateHardFailConditions as validateOrchestratorResult,
} from './multi-chain-orchestrator';

// Verdict Enforcement
export {
  type SecurnexVerdict,
  type VerdictInput,
  type VerdictOutput,
  type VerdictRequirements,
  VERDICT_REQUIREMENTS,
  ALLOWED_VERDICTS,
  determineVerdict,
  validateVerdict,
  convertLegacyStatus,
  isValidVerdict,
  getVerdictColor,
  getVerdictIcon,
  getVerdictDescription,
} from './verdict-enforcer';

// Hard-Fail Validation
export {
  type HardFailReason,
  type HardFailCondition,
  type ValidationInput,
  type HardFailValidationResult,
  validateHardFailConditions,
  isProtectedProtocol,
  wouldFailValidation,
  autoCorrectVerdict,
  runValidationTestSuite,
  PROTECTED_PROTOCOLS,
} from './hard-fail-validator';

// Drainer Activity Detection
export {
  detectDrainerActivity,
  type TransactionForDrainerAnalysis,
  type TokenTransferForDrainerAnalysis,
  type ApprovalForDrainerAnalysis,
  type IndependentSignalType,
  type IndependentSignal,
  CHAIN_SIGNAL_THRESHOLDS,
  normalizeAddress,
  normalizeAddresses,
  areAddressesEqual,
} from './drainer-activity-detector';

// Base Chain Protection
export {
  checkBaseProtocolInteraction,
  checkSelfTransfer,
  checkExchangeWallet,
  analyzeBaseSweeperPatterns,
  detectBaseSweeperStrict,
  classifyBaseChainWallet,
  isBaseNFTPlatform,
  isCoinbaseLinkedWallet,
  isPublicBaseRelayer,
  type BaseSweeperSignals,
  type BaseChainClassificationResult,
  type ProtocolInteractionResult,
  type ExchangeCheckResult,
  ENS_BASE_CONTRACTS,
  BASE_BRIDGE_CONTRACTS,
  BASE_NFT_PLATFORMS,
  EXCHANGE_WALLETS,
} from './base-chain-protection';

// BNB Chain Protection
export {
  analyzeBNBDrainerPatterns,
  detectBNBDrainerStrict,
  checkBNBProtocolInteraction,
  isBinanceHotWallet,
  isPancakeSwapContract,
  isBNBDeFiProtocol,
  isBNBBridge,
  type BNBDrainerSignals,
  type BNBDrainerDetectionResult,
  type BNBProtocolCheckResult,
  BNB_DETECTION_THRESHOLDS,
  BINANCE_HOT_WALLETS,
  PANCAKESWAP_CONTRACTS,
  BNB_DEFI_PROTOCOLS,
  BNB_BRIDGES,
} from './bnb-chain-protection';

// Infrastructure Protection
export {
  checkInfrastructureProtection,
  isVerifiedDEXRouter,
  isProtectedMarketplace,
  isProtectedDEX,
  isProtectedBridge,
  canNeverBeSweeperBot,
  canNeverBeDrainer,
  checkBaseDEXActivity,
  isNormalDEXActivityOnly,
  isKnownCEXWallet,
  getCEXWalletInfo,
  isCEXTransaction,
  type InfrastructureType,
  type ProtectedContract,
  type InfrastructureCheckResult,
  type DEXActivityResult,
  type CEXWalletInfo,
  PROTECTED_INFRASTRUCTURE,
  BASE_DEX_ROUTERS,
  DEX_METHOD_SIGNATURES,
} from './infrastructure-protection';

// Safe Contracts
export {
  isSafeContract,
  isSafeContractOnChain,
  isNFTMarketplace,
  isDeFiProtocol,
  isDEXRouter,
  isDEXRouterOnChain,
  isInfrastructureContract,
  isENSContract,
  isNamingServiceContract,
  isNamingServiceTransaction,
  isStandardMintMethod,
  isNFTMintTransaction,
  isPaidMintTransaction,
  isBaseNFTActivity,
  checkAddressSafety,
  type SafeContract,
} from './safe-contracts';

// Malicious Database
export {
  isMaliciousAddress,
  isDrainerRecipient,
} from './malicious-database';

export {
  DRAINER_CONTRACTS,
  DRAINER_RECIPIENTS,
  isKnownDrainer,
  getDrainerType,
} from './drainer-addresses';

// Context Classification
export {
  classifyWalletContext,
  isTransactionToSafeDestination,
  isSelfTransfer as isSelfTransferContext,
  type ContextClassificationResult,
} from './context-classifier';

// ============================================
// USAGE EXAMPLE
// ============================================
//
// import { 
//   createOrchestrator, 
//   validateHardFailConditions,
//   autoCorrectVerdict 
// } from '@/lib/detection/securnex-detection-index';
//
// // Create orchestrator
// const orchestrator = createOrchestrator();
//
// // Analyze wallet
// const result = await orchestrator.analyzeWallet(
//   walletAddress,
//   'ethereum',
//   transactions,
//   tokenTransfers,
//   approvals
// );
//
// // Validate result
// const validation = validateHardFailConditions(result);
// if (!validation.passed) {
//   console.error('Detection failed validation:', validation.errors);
// }
//
// // Auto-correct if needed
// const { verdict, wasCorrect, correction } = autoCorrectVerdict(
//   result.verdict,
//   { /* validation input */ }
// );
