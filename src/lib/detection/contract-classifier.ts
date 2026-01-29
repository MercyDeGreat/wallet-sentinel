// ============================================
// CONTRACT CLASSIFICATION ENGINE
// ============================================
// Classifies contracts BEFORE applying threat labels.
// This prevents false positives by understanding what type of contract
// we're dealing with before making any judgments.
//
// Classification Hierarchy:
// 1. MARKETPLACE - NFT marketplaces (OpenSea, Blur, etc.)
// 2. NFT_MINT - NFT mint contracts
// 3. DEFI_PROTOCOL - DeFi protocols (Uniswap, Aave, etc.)
// 4. INFRASTRUCTURE - Routers, relayers, bridges, multisigs
// 5. TOKEN_CONTRACT - ERC20/721/1155 tokens
// 6. USER_WALLET - EOA (Externally Owned Account)
// 7. UNKNOWN_CONTRACT - Unverified smart contract
// 8. VERIFIED_SERVICE - Other verified high-interaction contracts
//
// CRITICAL RULE:
// Only UNKNOWN_CONTRACT and UNKNOWN wallets can be flagged as sweeper/drainer.
// All other categories are EXCLUDED from malicious labeling by default.

import { Chain, RiskLevel } from '@/types';
import { 
  isSafeContract, 
  SafeContract, 
  SafeContractCategory,
  checkAddressSafety,
  isStandardApprovalMethod,
  isStandardMintMethod,
} from './safe-contracts';
import { isLegitimateContract, getInfrastructureCategory, InfrastructureCategory } from './malicious-database';

// ============================================
// CONTRACT CLASSIFICATION TYPES
// ============================================

export type ContractClassificationType =
  | 'MARKETPLACE'
  | 'NFT_MINT'
  | 'DEFI_PROTOCOL'
  | 'INFRASTRUCTURE'
  | 'TOKEN_CONTRACT'
  | 'USER_WALLET'  // EOA
  | 'UNKNOWN_CONTRACT'
  | 'VERIFIED_SERVICE'
  | 'CEX_HOT_WALLET'
  | 'BRIDGE'
  | 'ENS'
  | 'STAKING';

export interface ContractClassification {
  // Primary classification
  type: ContractClassificationType;
  
  // Sub-category for more detail
  subCategory?: SafeContractCategory | InfrastructureCategory;
  
  // Name if known
  name?: string;
  
  // Whether this is verified (source code available)
  isVerified: boolean;
  
  // Whether this contract can ever be flagged as malicious
  canBeFlaggedMalicious: boolean;
  
  // Why was this classification made
  classificationReason: string;
  
  // Confidence in this classification
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  
  // Source of classification data
  source: 'SAFE_CONTRACTS_DB' | 'LEGITIMATE_CONTRACTS_DB' | 'BYTECODE_ANALYSIS' | 'HEURISTIC' | 'UNKNOWN';
}

// ============================================
// CLASSIFICATION LOGIC
// ============================================

/**
 * Classify a contract or address.
 * This MUST be called before applying any threat labels.
 */
export async function classifyContract(
  address: string,
  chain: Chain,
  options?: {
    isContract?: boolean;
    bytecode?: string;
    methodId?: string;
    transactionCount?: number;
  }
): Promise<ContractClassification> {
  if (!address) {
    return {
      type: 'UNKNOWN_CONTRACT',
      isVerified: false,
      canBeFlaggedMalicious: true,
      classificationReason: 'No address provided',
      confidence: 'LOW',
      source: 'UNKNOWN',
    };
  }

  const normalizedAddress = address.toLowerCase();

  // ============================================
  // STEP 1: Check Safe Contracts Database
  // ============================================
  const safeContract = isSafeContract(normalizedAddress);
  if (safeContract) {
    return classifyFromSafeContract(safeContract);
  }

  // ============================================
  // STEP 2: Check Legacy Legitimate Contracts
  // ============================================
  const legitimateName = isLegitimateContract(normalizedAddress);
  if (legitimateName) {
    const infraCategory = getInfrastructureCategory(normalizedAddress);
    return classifyFromLegitimateContract(legitimateName, infraCategory);
  }

  // ============================================
  // STEP 3: Check if it's an EOA (not a contract)
  // ============================================
  if (options?.isContract === false) {
    return classifyAsUserWallet(normalizedAddress, options.transactionCount);
  }

  // ============================================
  // STEP 4: Analyze bytecode if available
  // ============================================
  if (options?.bytecode) {
    const bytecodeClassification = classifyFromBytecode(options.bytecode);
    if (bytecodeClassification) {
      return bytecodeClassification;
    }
  }

  // ============================================
  // STEP 5: Method-based heuristics
  // ============================================
  if (options?.methodId) {
    if (isStandardMintMethod(options.methodId)) {
      return {
        type: 'NFT_MINT',
        isVerified: false,
        canBeFlaggedMalicious: false, // Mint methods are normal
        classificationReason: 'Standard NFT mint method detected',
        confidence: 'MEDIUM',
        source: 'HEURISTIC',
      };
    }
    if (isStandardApprovalMethod(options.methodId)) {
      // Approval method alone doesn't tell us contract type
      // but it's a normal operation
      return {
        type: 'TOKEN_CONTRACT',
        isVerified: false,
        canBeFlaggedMalicious: false, // Standard approval is normal
        classificationReason: 'Standard EIP approval method',
        confidence: 'LOW',
        source: 'HEURISTIC',
      };
    }
  }

  // ============================================
  // STEP 6: High transaction count heuristic
  // ============================================
  if (options?.transactionCount && options.transactionCount > 10000) {
    return {
      type: 'VERIFIED_SERVICE',
      isVerified: false,
      canBeFlaggedMalicious: false, // High-volume contracts are unlikely drainers
      classificationReason: `High transaction count (${options.transactionCount}) indicates legitimate service`,
      confidence: 'MEDIUM',
      source: 'HEURISTIC',
    };
  }

  // ============================================
  // STEP 7: Unknown - this CAN be flagged if behavior warrants
  // ============================================
  return {
    type: 'UNKNOWN_CONTRACT',
    isVerified: false,
    canBeFlaggedMalicious: true, // Only unknown contracts can be flagged
    classificationReason: 'Unknown contract - requires behavioral analysis',
    confidence: 'LOW',
    source: 'UNKNOWN',
  };
}

// ============================================
// CLASSIFICATION HELPERS
// ============================================

function classifyFromSafeContract(contract: SafeContract): ContractClassification {
  const categoryToType: Record<SafeContractCategory, ContractClassificationType> = {
    'NFT_MARKETPLACE': 'MARKETPLACE',
    'NFT_MINT_CONTRACT': 'NFT_MINT',
    'DEFI_PROTOCOL': 'DEFI_PROTOCOL',
    'DEX_ROUTER': 'DEFI_PROTOCOL',
    'BRIDGE': 'BRIDGE',
    'ENS': 'ENS',
    'STAKING': 'STAKING',
    'LENDING': 'DEFI_PROTOCOL',
    'AGGREGATOR': 'DEFI_PROTOCOL',
    'INFRASTRUCTURE': 'INFRASTRUCTURE',
    'RELAYER': 'INFRASTRUCTURE',
    'MULTISIG': 'INFRASTRUCTURE',
    'TOKEN_CONTRACT': 'TOKEN_CONTRACT',
    'YIELD_OPTIMIZER': 'DEFI_PROTOCOL',
    'VERIFIED_PROJECT': 'VERIFIED_SERVICE',
  };

  return {
    type: categoryToType[contract.category] || 'VERIFIED_SERVICE',
    subCategory: contract.category,
    name: contract.name,
    isVerified: contract.verified,
    canBeFlaggedMalicious: false, // Safe contracts are NEVER malicious
    classificationReason: `Known safe contract: ${contract.name}`,
    confidence: 'HIGH',
    source: 'SAFE_CONTRACTS_DB',
  };
}

function classifyFromLegitimateContract(
  name: string, 
  infraCategory: InfrastructureCategory | null
): ContractClassification {
  const categoryToType: Record<InfrastructureCategory, ContractClassificationType> = {
    'DEX': 'DEFI_PROTOCOL',
    'NFT_MARKET': 'MARKETPLACE',
    'LENDING': 'DEFI_PROTOCOL',
    'BRIDGE': 'BRIDGE',
    'STAKING': 'STAKING',
    'TOKEN': 'TOKEN_CONTRACT',
    'AGGREGATOR': 'DEFI_PROTOCOL',
    'MULTISIG': 'INFRASTRUCTURE',
    'CEX': 'CEX_HOT_WALLET',
    'LP_POOL': 'DEFI_PROTOCOL',
    'OTHER': 'VERIFIED_SERVICE',
  };

  return {
    type: infraCategory ? categoryToType[infraCategory] : 'VERIFIED_SERVICE',
    subCategory: infraCategory || undefined,
    name,
    isVerified: true,
    canBeFlaggedMalicious: false, // Legitimate contracts are NEVER malicious
    classificationReason: `Known legitimate contract: ${name}`,
    confidence: 'HIGH',
    source: 'LEGITIMATE_CONTRACTS_DB',
  };
}

function classifyAsUserWallet(
  address: string, 
  transactionCount?: number
): ContractClassification {
  // EOAs can potentially be malicious (if they're attacker wallets)
  // but we need behavioral analysis to determine this
  return {
    type: 'USER_WALLET',
    isVerified: false,
    canBeFlaggedMalicious: true, // User wallets can be attacker wallets
    classificationReason: 'Externally Owned Account (user wallet)',
    confidence: transactionCount && transactionCount > 100 ? 'HIGH' : 'MEDIUM',
    source: 'HEURISTIC',
  };
}

function classifyFromBytecode(bytecode: string): ContractClassification | null {
  const byteLower = bytecode.toLowerCase();

  // ============================================
  // Common Contract Signatures in Bytecode
  // ============================================
  
  // ERC20 selectors
  const erc20Selectors = [
    'a9059cbb', // transfer
    '095ea7b3', // approve
    '23b872dd', // transferFrom
    '70a08231', // balanceOf
    '18160ddd', // totalSupply
  ];
  
  // ERC721 selectors
  const erc721Selectors = [
    '6352211e', // ownerOf
    '42842e0e', // safeTransferFrom
    'a22cb465', // setApprovalForAll
    'e985e9c5', // isApprovedForAll
  ];
  
  // DEX Router selectors
  const dexSelectors = [
    '38ed1739', // swapExactTokensForTokens
    '7ff36ab5', // swapExactETHForTokens
    'e8e33700', // addLiquidity
  ];
  
  // Gnosis Safe selectors
  const safeSelectors = [
    '6a761202', // execTransaction
  ];
  
  // Count matches
  const hasERC20 = erc20Selectors.filter(s => byteLower.includes(s)).length >= 3;
  const hasERC721 = erc721Selectors.filter(s => byteLower.includes(s)).length >= 2;
  const hasDEX = dexSelectors.filter(s => byteLower.includes(s)).length >= 2;
  const hasSafe = safeSelectors.filter(s => byteLower.includes(s)).length >= 1;

  if (hasSafe) {
    return {
      type: 'INFRASTRUCTURE',
      subCategory: 'MULTISIG',
      isVerified: false,
      canBeFlaggedMalicious: false, // Multisigs are not drainers
      classificationReason: 'Gnosis Safe / multisig pattern detected',
      confidence: 'MEDIUM',
      source: 'BYTECODE_ANALYSIS',
    };
  }

  if (hasDEX) {
    return {
      type: 'DEFI_PROTOCOL',
      subCategory: 'DEX_ROUTER',
      isVerified: false,
      canBeFlaggedMalicious: false, // DEX routers are not drainers
      classificationReason: 'DEX router pattern detected',
      confidence: 'MEDIUM',
      source: 'BYTECODE_ANALYSIS',
    };
  }

  if (hasERC721) {
    return {
      type: 'NFT_MINT',
      isVerified: false,
      canBeFlaggedMalicious: false, // NFT contracts are normal
      classificationReason: 'ERC721 token pattern detected',
      confidence: 'MEDIUM',
      source: 'BYTECODE_ANALYSIS',
    };
  }

  if (hasERC20) {
    return {
      type: 'TOKEN_CONTRACT',
      isVerified: false,
      canBeFlaggedMalicious: false, // Token contracts are normal
      classificationReason: 'ERC20 token pattern detected',
      confidence: 'MEDIUM',
      source: 'BYTECODE_ANALYSIS',
    };
  }

  return null; // Can't classify from bytecode
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Quick check if a contract should be excluded from malicious flagging.
 * Use this before applying any threat labels.
 */
export function shouldExcludeFromMaliciousFlagging(
  classification: ContractClassification
): boolean {
  return !classification.canBeFlaggedMalicious;
}

/**
 * Get a human-readable explanation for why a contract is safe.
 */
export function getSafetyExplanation(classification: ContractClassification): string {
  if (classification.canBeFlaggedMalicious) {
    return 'This address requires behavioral analysis to determine safety.';
  }

  switch (classification.type) {
    case 'MARKETPLACE':
      return `This is a verified NFT marketplace (${classification.name || 'unknown'}). ` +
             'NFT marketplaces process millions of transactions and are not drainers.';
    case 'NFT_MINT':
      return `This is an NFT mint contract (${classification.name || 'unknown'}). ` +
             'Minting NFTs is normal user behavior, not a security threat.';
    case 'DEFI_PROTOCOL':
      return `This is a verified DeFi protocol (${classification.name || 'unknown'}). ` +
             'DeFi protocols are infrastructure, not malicious actors.';
    case 'INFRASTRUCTURE':
      return `This is infrastructure (${classification.name || 'unknown'}). ` +
             'Infrastructure contracts facilitate normal blockchain operations.';
    case 'TOKEN_CONTRACT':
      return 'This is a token contract. Token contracts are standard EIP implementations.';
    case 'CEX_HOT_WALLET':
      return `This is a centralized exchange hot wallet (${classification.name || 'unknown'}). ` +
             'CEX wallets receive funds from millions of users and are not malicious.';
    case 'BRIDGE':
      return `This is a cross-chain bridge (${classification.name || 'unknown'}). ` +
             'Bridges facilitate cross-chain transfers and are not drainers.';
    case 'ENS':
      return 'This is an ENS (Ethereum Name Service) contract. ENS is core Ethereum infrastructure.';
    case 'STAKING':
      return `This is a staking contract (${classification.name || 'unknown'}). ` +
             'Staking protocols are legitimate DeFi services.';
    case 'VERIFIED_SERVICE':
      return `This is a verified service (${classification.name || 'unknown'}). ` +
             'High-volume verified contracts are not drainers.';
    case 'USER_WALLET':
      return 'This is a user wallet. Behavioral analysis is required to determine if malicious.';
    case 'UNKNOWN_CONTRACT':
      return 'This is an unknown contract. Behavioral analysis is required to determine if malicious.';
    default:
      return 'Classification pending.';
  }
}

/**
 * Get the maximum risk level that should be assigned to a classified contract.
 * Safe contracts should never exceed LOW risk from the classification itself.
 */
export function getMaxRiskLevelForClassification(
  classification: ContractClassification
): RiskLevel {
  if (classification.canBeFlaggedMalicious) {
    return 'CRITICAL'; // Unknown contracts can be any risk level
  }
  return 'LOW'; // Safe contracts are always low risk from classification
}

// ============================================
// BATCH CLASSIFICATION
// ============================================

/**
 * Classify multiple addresses at once (for transaction analysis).
 */
export async function classifyMultipleContracts(
  addresses: string[],
  chain: Chain
): Promise<Map<string, ContractClassification>> {
  const results = new Map<string, ContractClassification>();
  
  for (const address of addresses) {
    const classification = await classifyContract(address, chain);
    results.set(address.toLowerCase(), classification);
  }
  
  return results;
}

// ============================================
// EXPORTS
// ============================================

export {
  classifyContract as default,
};




