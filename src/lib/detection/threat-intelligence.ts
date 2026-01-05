// ============================================
// THREAT INTELLIGENCE MODULE
// ============================================
// Integrates external threat feeds and advanced detection techniques
// to catch zero-day drainers and evasion techniques.
//
// Sources:
// - GoPlus Labs API (free tier)
// - Contract bytecode analysis
// - Permit2 allowance monitoring
// - Contract verification status
//
// This supplements the static database with dynamic detection.

import { Chain, RiskLevel } from '@/types';
import { CHAIN_RPC_CONFIG } from './malicious-database';

// ============================================
// TYPES
// ============================================

export interface ThreatIntelResult {
  isMalicious: boolean;
  confidence: number; // 0-100
  source: string;
  details: string;
  riskLevel: RiskLevel;
}

export interface ContractAnalysis {
  isContract: boolean;
  isVerified: boolean;
  isProxy: boolean;
  proxyImplementation?: string;
  implementationIsMalicious?: boolean;
  contractType?: ContractType;
  deployedAt?: string;
  transactionCount?: number;
}

export type ContractType = 
  | 'EOA'           // Externally Owned Account (regular wallet)
  | 'TOKEN'         // ERC20/721/1155 token
  | 'DEX_ROUTER'    // DEX swap router
  | 'DEX_POOL'      // Liquidity pool
  | 'VAULT'         // Yield vault (Yearn, Convex)
  | 'BRIDGE'        // Cross-chain bridge
  | 'MULTISIG'      // Gnosis Safe or similar
  | 'PROXY'         // Proxy contract (upgradeable)
  | 'NFT_MARKET'    // NFT marketplace
  | 'UNKNOWN';

// ============================================
// GOPLUS LABS API INTEGRATION
// ============================================
// Free tier: 100 requests/day
// Provides real-time threat intelligence

interface GoPlusAddressResponse {
  code: number;
  message: string;
  result: {
    [address: string]: {
      cybercrime?: string;
      money_laundering?: string;
      number_of_malicious_contracts_created?: string;
      financial_crime?: string;
      darkweb_transactions?: string;
      phishing_activities?: string;
      fake_kyc?: string;
      blacklist_doubt?: string;
      data_source?: string;
      stealing_attack?: string;
      blackmail_activities?: string;
      sanctioned?: string;
      malicious_mining_activities?: string;
      mixer?: string;
      honeypot_related_address?: string;
    };
  };
}

export async function checkGoPlusAddressSecurity(
  address: string,
  chainId: number = 1
): Promise<ThreatIntelResult | null> {
  try {
    const url = `https://api.gopluslabs.io/api/v1/address_security/${address}?chain_id=${chainId}`;
    
    const response = await fetch(url, {
      signal: AbortSignal.timeout(5000),
      headers: { 'Accept': 'application/json' },
    });
    
    if (!response.ok) return null;
    
    const data: GoPlusAddressResponse = await response.json();
    
    if (data.code !== 1 || !data.result[address.toLowerCase()]) {
      return null;
    }
    
    const result = data.result[address.toLowerCase()];
    
    // Calculate risk based on flags
    const riskFactors: string[] = [];
    let riskScore = 0;
    
    if (result.cybercrime === '1') { riskFactors.push('Cybercrime'); riskScore += 30; }
    if (result.stealing_attack === '1') { riskFactors.push('Stealing Attack'); riskScore += 40; }
    if (result.phishing_activities === '1') { riskFactors.push('Phishing'); riskScore += 35; }
    if (result.money_laundering === '1') { riskFactors.push('Money Laundering'); riskScore += 25; }
    if (result.blacklist_doubt === '1') { riskFactors.push('Blacklisted'); riskScore += 20; }
    if (result.honeypot_related_address === '1') { riskFactors.push('Honeypot Related'); riskScore += 30; }
    if (result.sanctioned === '1') { riskFactors.push('Sanctioned'); riskScore += 50; }
    if (result.malicious_mining_activities === '1') { riskFactors.push('Malicious Mining'); riskScore += 15; }
    
    const numMaliciousContracts = parseInt(result.number_of_malicious_contracts_created || '0');
    if (numMaliciousContracts > 0) {
      riskFactors.push(`Created ${numMaliciousContracts} malicious contracts`);
      riskScore += Math.min(40, numMaliciousContracts * 10);
    }
    
    if (riskFactors.length === 0) {
      return null; // Clean address
    }
    
    const confidence = Math.min(100, riskScore);
    
    return {
      isMalicious: riskScore >= 30,
      confidence,
      source: 'GoPlus Labs',
      details: riskFactors.join(', '),
      riskLevel: riskScore >= 50 ? 'CRITICAL' : riskScore >= 30 ? 'HIGH' : 'MEDIUM',
    };
  } catch (error) {
    console.log('[GoPlus] API check failed:', error);
    return null;
  }
}

// ============================================
// GOPLUS TOKEN SECURITY CHECK
// ============================================
// Checks if a token contract is malicious (honeypot, etc.)

interface GoPlusTokenResponse {
  code: number;
  result: {
    [address: string]: {
      is_honeypot?: string;
      is_blacklisted?: string;
      is_proxy?: string;
      is_mintable?: string;
      can_take_back_ownership?: string;
      hidden_owner?: string;
      selfdestruct?: string;
      external_call?: string;
      buy_tax?: string;
      sell_tax?: string;
      is_anti_whale?: string;
      slippage_modifiable?: string;
      is_true_token?: string;
      is_airdrop_scam?: string;
    };
  };
}

export async function checkGoPlusTokenSecurity(
  tokenAddress: string,
  chainId: number = 1
): Promise<ThreatIntelResult | null> {
  try {
    const url = `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${tokenAddress}`;
    
    const response = await fetch(url, {
      signal: AbortSignal.timeout(5000),
      headers: { 'Accept': 'application/json' },
    });
    
    if (!response.ok) return null;
    
    const data: GoPlusTokenResponse = await response.json();
    
    if (data.code !== 1 || !data.result[tokenAddress.toLowerCase()]) {
      return null;
    }
    
    const result = data.result[tokenAddress.toLowerCase()];
    
    const riskFactors: string[] = [];
    let riskScore = 0;
    
    if (result.is_honeypot === '1') { riskFactors.push('Honeypot'); riskScore += 50; }
    if (result.is_airdrop_scam === '1') { riskFactors.push('Airdrop Scam'); riskScore += 40; }
    if (result.hidden_owner === '1') { riskFactors.push('Hidden Owner'); riskScore += 20; }
    if (result.can_take_back_ownership === '1') { riskFactors.push('Can Reclaim Ownership'); riskScore += 25; }
    if (result.selfdestruct === '1') { riskFactors.push('Has Selfdestruct'); riskScore += 15; }
    
    const sellTax = parseFloat(result.sell_tax || '0');
    if (sellTax > 0.1) { riskFactors.push(`High Sell Tax: ${(sellTax * 100).toFixed(1)}%`); riskScore += 30; }
    
    if (riskFactors.length === 0) return null;
    
    return {
      isMalicious: riskScore >= 40,
      confidence: Math.min(100, riskScore),
      source: 'GoPlus Labs (Token)',
      details: riskFactors.join(', '),
      riskLevel: riskScore >= 50 ? 'CRITICAL' : riskScore >= 30 ? 'HIGH' : 'MEDIUM',
    };
  } catch (error) {
    return null;
  }
}

// ============================================
// BYTECODE ANALYSIS - PROXY DETECTION
// ============================================
// Detects minimal proxy clones (EIP-1167) that point to known drainers
// Attackers deploy new proxy addresses to evade static lists

// EIP-1167 Minimal Proxy bytecode pattern
const EIP1167_PATTERN = /^0x363d3d373d3d3d363d73([a-f0-9]{40})5af43d82803e903d91602b57fd5bf3$/i;

// EIP-1967 Transparent Proxy storage slot for implementation
const EIP1967_IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';

export async function analyzeContractBytecode(
  address: string,
  chain: Chain,
  knownMaliciousAddresses: Set<string>
): Promise<ContractAnalysis> {
  const result: ContractAnalysis = {
    isContract: false,
    isVerified: false,
    isProxy: false,
  };
  
  try {
    // Get RPC URL for the chain
    const rpcUrl = CHAIN_RPC_CONFIG[chain]?.rpcUrls?.[0];
    if (!rpcUrl) return result;
    
    // Fetch bytecode
    const response = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_getCode',
        params: [address, 'latest'],
      }),
      signal: AbortSignal.timeout(5000),
    });
    
    const data = await response.json();
    const bytecode = data.result || '0x';
    
    // Check if it's a contract
    if (bytecode === '0x' || bytecode.length <= 2) {
      result.isContract = false;
      result.contractType = 'EOA';
      return result;
    }
    
    result.isContract = true;
    
    // Check for EIP-1167 minimal proxy
    const minimalProxyMatch = bytecode.match(EIP1167_PATTERN);
    if (minimalProxyMatch) {
      result.isProxy = true;
      result.proxyImplementation = '0x' + minimalProxyMatch[1].toLowerCase();
      
      // Check if implementation is a known malicious address
      if (knownMaliciousAddresses.has(result.proxyImplementation)) {
        result.implementationIsMalicious = true;
      }
      
      result.contractType = 'PROXY';
      return result;
    }
    
    // Check for common contract patterns
    result.contractType = identifyContractType(bytecode);
    
    // Check contract verification status
    result.isVerified = await checkContractVerification(address, chain);
    
    return result;
  } catch (error) {
    console.log('[Bytecode] Analysis failed:', error);
    return result;
  }
}

function identifyContractType(bytecode: string): ContractType {
  // Common function selectors in bytecode
  const selectors = {
    // ERC20
    transfer: '0xa9059cbb',
    approve: '0x095ea7b3',
    balanceOf: '0x70a08231',
    totalSupply: '0x18160ddd',
    
    // DEX Router
    swapExactTokensForTokens: '0x38ed1739',
    swapExactETHForTokens: '0x7ff36ab5',
    addLiquidity: '0xe8e33700',
    
    // NFT
    safeTransferFrom: '0x42842e0e',
    setApprovalForAll: '0xa22cb465',
    ownerOf: '0x6352211e',
    
    // Gnosis Safe
    execTransaction: '0x6a761202',
    
    // Vault
    deposit: '0xb6b55f25',
    withdraw: '0x2e1a7d4d',
    harvest: '0x4641257d',
  };
  
  const byteLower = bytecode.toLowerCase();
  
  // Count matches
  const hasTransfer = byteLower.includes(selectors.transfer.slice(2));
  const hasApprove = byteLower.includes(selectors.approve.slice(2));
  const hasBalanceOf = byteLower.includes(selectors.balanceOf.slice(2));
  const hasTotalSupply = byteLower.includes(selectors.totalSupply.slice(2));
  const hasSwap = byteLower.includes(selectors.swapExactTokensForTokens.slice(2)) ||
                  byteLower.includes(selectors.swapExactETHForTokens.slice(2));
  const hasNFT = byteLower.includes(selectors.ownerOf.slice(2));
  const hasSafe = byteLower.includes(selectors.execTransaction.slice(2));
  const hasVault = byteLower.includes(selectors.deposit.slice(2)) &&
                   byteLower.includes(selectors.withdraw.slice(2));
  
  if (hasSafe) return 'MULTISIG';
  if (hasSwap) return 'DEX_ROUTER';
  if (hasVault) return 'VAULT';
  if (hasNFT && hasApprove) return 'NFT_MARKET';
  if (hasTransfer && hasApprove && hasBalanceOf && hasTotalSupply) return 'TOKEN';
  
  return 'UNKNOWN';
}

// ============================================
// CONTRACT VERIFICATION CHECK
// ============================================
// Unverified contracts are higher risk

export async function checkContractVerification(
  address: string,
  chain: Chain
): Promise<boolean> {
  try {
    const explorerApi = CHAIN_RPC_CONFIG[chain]?.explorerApi;
    if (!explorerApi) return false;
    
    const apiKey = process.env[`${chain.toUpperCase()}_EXPLORER_API_KEY`] || '';
    const url = `${explorerApi}?module=contract&action=getabi&address=${address}&apikey=${apiKey}`;
    
    const response = await fetch(url, {
      signal: AbortSignal.timeout(5000),
      headers: { 'Accept': 'application/json' },
    });
    
    const data = await response.json();
    
    // Status '1' means ABI is available (verified)
    return data.status === '1';
  } catch (error) {
    return false;
  }
}

// ============================================
// PERMIT2 ALLOWANCE MONITORING
// ============================================
// Permit2 allows gasless approvals via off-chain signatures
// These are invisible until executed - high risk

const PERMIT2_ADDRESS = '0x000000000022d473030f116ddee9f6b43ac78ba3';

// Permit2 AllowanceTransfer event topic
const PERMIT_TOPIC = '0x0c0a3bb8f8939c5e5cfca3bf6e4c75c4b30fc9d8b4f4f4c3e7be2f38a6f89a5f';

export interface Permit2Allowance {
  token: string;
  spender: string;
  amount: string;
  expiration: number;
  nonce: number;
}

export async function getPermit2Allowances(
  userAddress: string,
  chain: Chain
): Promise<Permit2Allowance[]> {
  // Note: This requires indexing Permit2 events or using Permit2's view functions
  // For now, we'll check if user has interacted with Permit2
  const allowances: Permit2Allowance[] = [];
  
  try {
    const explorerApi = CHAIN_RPC_CONFIG[chain]?.explorerApi;
    if (!explorerApi) return allowances;
    
    const apiKey = process.env[`${chain.toUpperCase()}_EXPLORER_API_KEY`] || '';
    
    // Get transactions to Permit2
    const url = `${explorerApi}?module=account&action=txlist&address=${userAddress}&startblock=0&endblock=99999999&sort=desc&apikey=${apiKey}`;
    
    const response = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      headers: { 'Accept': 'application/json' },
    });
    
    const data = await response.json();
    
    if (data.status !== '1' || !Array.isArray(data.result)) {
      return allowances;
    }
    
    // Count Permit2 interactions
    const permit2Txs = data.result.filter((tx: any) => 
      tx.to?.toLowerCase() === PERMIT2_ADDRESS.toLowerCase()
    );
    
    if (permit2Txs.length > 0) {
      console.log(`[Permit2] User has ${permit2Txs.length} Permit2 interactions`);
      // Flag for further analysis
    }
    
    return allowances;
  } catch (error) {
    return allowances;
  }
}

// ============================================
// AGGREGATED THREAT CHECK
// ============================================
// Combines all threat intelligence sources

export interface AggregatedThreatCheck {
  address: string;
  chain: Chain;
  
  // GoPlus results
  goPlusResult?: ThreatIntelResult;
  
  // Bytecode analysis
  contractAnalysis?: ContractAnalysis;
  
  // Overall assessment
  overallRiskScore: number;
  overallRiskLevel: RiskLevel;
  isDefinitelyMalicious: boolean;
  isProbablyMalicious: boolean;
  requiresManualReview: boolean;
  
  // Evidence
  riskFactors: string[];
}

export async function performAggregatedThreatCheck(
  address: string,
  chain: Chain,
  knownMaliciousAddresses: Set<string>
): Promise<AggregatedThreatCheck> {
  const result: AggregatedThreatCheck = {
    address,
    chain,
    overallRiskScore: 0,
    overallRiskLevel: 'LOW',
    isDefinitelyMalicious: false,
    isProbablyMalicious: false,
    requiresManualReview: false,
    riskFactors: [],
  };
  
  // Check static database first (fast)
  if (knownMaliciousAddresses.has(address.toLowerCase())) {
    result.isDefinitelyMalicious = true;
    result.overallRiskScore = 100;
    result.overallRiskLevel = 'CRITICAL';
    result.riskFactors.push('Address in known malicious database');
    return result;
  }
  
  // Get chain ID for API calls
  const chainIdMap: Record<string, number> = {
    ethereum: 1,
    base: 8453,
    bnb: 56,
  };
  const chainId = chainIdMap[chain] || 1;
  
  // Run checks in parallel
  const [goPlusResult, contractAnalysis] = await Promise.all([
    checkGoPlusAddressSecurity(address, chainId),
    analyzeContractBytecode(address, chain, knownMaliciousAddresses),
  ]);
  
  result.goPlusResult = goPlusResult || undefined;
  result.contractAnalysis = contractAnalysis;
  
  // Calculate overall risk
  let riskScore = 0;
  
  // GoPlus results
  if (goPlusResult?.isMalicious) {
    riskScore += goPlusResult.confidence * 0.8;
    result.riskFactors.push(`GoPlus: ${goPlusResult.details}`);
  }
  
  // Bytecode analysis - proxy to known malicious
  if (contractAnalysis?.implementationIsMalicious) {
    riskScore += 90;
    result.riskFactors.push(`Proxy clone of known malicious contract: ${contractAnalysis.proxyImplementation}`);
    result.isDefinitelyMalicious = true;
  }
  
  // Unverified contract with unknown type
  if (contractAnalysis?.isContract && !contractAnalysis.isVerified && contractAnalysis.contractType === 'UNKNOWN') {
    riskScore += 15;
    result.riskFactors.push('Unverified contract with unknown purpose');
    result.requiresManualReview = true;
  }
  
  // Set final assessment
  result.overallRiskScore = Math.min(100, riskScore);
  
  if (riskScore >= 80) {
    result.overallRiskLevel = 'CRITICAL';
    result.isDefinitelyMalicious = true;
  } else if (riskScore >= 50) {
    result.overallRiskLevel = 'HIGH';
    result.isProbablyMalicious = true;
  } else if (riskScore >= 25) {
    result.overallRiskLevel = 'MEDIUM';
    result.requiresManualReview = true;
  }
  
  return result;
}

// ============================================
// HELPER: Build known malicious set from database
// ============================================

export function buildKnownMaliciousSet(): Set<string> {
  // Import from drainer-addresses.ts
  const { DRAINER_CONTRACTS, DRAINER_RECIPIENTS } = require('./drainer-addresses');
  
  const set = new Set<string>();
  
  for (const addr of DRAINER_CONTRACTS) {
    set.add(addr.toLowerCase());
  }
  for (const addr of DRAINER_RECIPIENTS) {
    set.add(addr.toLowerCase());
  }
  
  return set;
}




