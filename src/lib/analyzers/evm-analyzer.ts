// ============================================
// EVM CHAIN ANALYZER (Ethereum, Base, BNB)
// ============================================
// Behavioral threat detection with directional analysis.
// 
// CRITICAL FALSE POSITIVE PREVENTION:
// - Receiving funds from compromised wallets ≠ being malicious
// - High-volume addresses (service fee receivers) are NOT drainers
// - Must analyze WHO initiated malicious calls, WHO benefited
// - Infrastructure contracts (OpenSea, Uniswap) must never be flagged
//
// All operations are READ-ONLY.

import { ethers } from 'ethers';
import {
  Chain,
  DetectedThreat,
  TokenApproval,
  SuspiciousTransaction,
  RiskLevel,
  WalletAnalysisResult,
  SecurityRecommendation,
  RecoveryPlan,
  RecoveryStep,
  AttackType,
  WalletRole,
  RiskScoreBreakdown,
  RiskFactor,
  RiskFactorType,
  DirectionalAnalysis,
  SecurityStatus,
} from '@/types';
import {
  CHAIN_RPC_CONFIG,
  isMaliciousAddress,
  isDrainerRecipient,
  isInfiniteApproval,
  isLegitimateContract,
  getInfrastructureCategory,
  isHighVolumeNeutralAddress,
} from '../detection/malicious-database';
import {
  performAggregatedThreatCheck,
  buildKnownMaliciousSet,
  checkGoPlusAddressSecurity,
  analyzeContractBytecode,
  type AggregatedThreatCheck,
  type ContractAnalysis,
} from '../detection/threat-intelligence';
import {
  isSafeContract,
  isDeFiProtocol,
  isNFTMarketplace,
  isNFTMintContract,
  isENSContract,
  isInfrastructureContract,
} from '../detection/safe-contracts';
import { EXCHANGE_HOT_WALLETS } from '../detection/transaction-labeler';
import {
  analyzeWalletCompromise,
  type TransactionForAnalysis,
  type ApprovalForAnalysis,
  type TokenTransferForAnalysis,
  type CompromiseAnalysisResult,
} from '../detection/compromise-detector';
import {
  classifyAddress,
  analyzeSweeperSignals,
  determineSweeperVerdict,
  analyzeBehavioralSweeperPattern,
  type AddressClassification,
  type SweeperSignals,
  type SweeperVerdict,
  type BehavioralSweeperAnalysis,
} from '../detection/address-classifier';
import {
  checkInfrastructureProtection,
  canNeverBeSweeperBot,
  canNeverBeDrainer,
  type InfrastructureCheckResult,
} from '../detection/infrastructure-protection';

// ============================================
// INTERFACES
// ============================================

interface TransactionData {
  hash: string;
  from: string;
  to: string;
  value: string;
  input: string;
  timestamp: number;
  blockNumber: number;
  methodId: string;
  isError: boolean;
  gasUsed?: string;
}

interface TokenTransfer {
  from: string;
  to: string;
  value: string;
  hash: string;
  timestamp: number;
  tokenSymbol: string;
  tokenAddress: string;
}

interface ApprovalEvent {
  token: string;
  tokenName: string;
  tokenSymbol: string;
  spender: string;
  owner: string;
  amount: string;
  timestamp: number;
  transactionHash: string;
  blockNumber: number;
}

// ============================================
// EVM ANALYZER CLASS
// ============================================

export class EVMAnalyzer {
  private chain: Chain;
  private provider: ethers.JsonRpcProvider | null = null;
  private explorerApiUrl: string;
  private explorerApiKey: string;
  private rpcUrls: string[];
  private currentRpcIndex: number = 0;

  constructor(chain: Chain) {
    if (chain === 'solana') {
      throw new Error('EVMAnalyzer does not support Solana. Use SolanaAnalyzer instead.');
    }

    this.chain = chain;
    const config = CHAIN_RPC_CONFIG[chain];
    this.rpcUrls = config.rpcUrls;
    this.explorerApiUrl = config.explorerApi;
    this.explorerApiKey = process.env[`${chain.toUpperCase()}_EXPLORER_API_KEY`] || '';
  }

  private async getProvider(): Promise<ethers.JsonRpcProvider> {
    for (let i = 0; i < this.rpcUrls.length; i++) {
      const rpcIndex = (this.currentRpcIndex + i) % this.rpcUrls.length;
      const rpcUrl = this.rpcUrls[rpcIndex];
      
      try {
        const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, {
          staticNetwork: true,
          batchMaxCount: 1,
        });
        
        await Promise.race([
          provider.getBlockNumber(),
          new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000)),
        ]);
        
        this.currentRpcIndex = rpcIndex;
        this.provider = provider;
        return provider;
      } catch (error) {
        continue;
      }
    }
    
    throw new Error('All RPC endpoints failed');
  }

  async analyzeWallet(address: string): Promise<WalletAnalysisResult> {
    if (!ethers.isAddress(address)) {
      throw new Error('Invalid Ethereum address');
    }

    const normalizedAddress = address.toLowerCase();
    const threats: DetectedThreat[] = [];

    // ============================================
    // STEP 0: CHECK IF ADDRESS IS KNOWN MALICIOUS OR PROTECTED
    // ============================================
    // This must happen BEFORE any other analysis to:
    // 1. Flag known drainers when directly scanned
    // 2. Protect infrastructure from false positives
    
    // Check if this IS a known malicious address (drainer, sweeper, etc.)
    const maliciousInfo = isMaliciousAddress(normalizedAddress, this.chain);
    if (maliciousInfo) {
      console.log(`[ANALYZE] ${normalizedAddress}: IS a known malicious address (${maliciousInfo.name})`);
      threats.push({
        id: `known-malicious-${Date.now()}`,
        type: maliciousInfo.type || 'WALLET_DRAINER',
        severity: 'CRITICAL',
        title: `⚠️ KNOWN MALICIOUS ADDRESS: ${maliciousInfo.name}`,
        description: `This address is a confirmed malicious contract/wallet. It has been used to steal funds from victims. DO NOT send any funds to this address or approve any transactions from it.`,
        technicalDetails: `Name: ${maliciousInfo.name}\nType: ${maliciousInfo.type || 'DRAINER'}\nConfirmation: CONFIRMED\nReported: ${maliciousInfo.reportedAt || 'Unknown'}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [normalizedAddress],
        relatedTransactions: [],
        ongoingRisk: true,
      });
    }
    
    // Check if this IS a drainer recipient (wallet that receives stolen funds)
    if (isDrainerRecipient(normalizedAddress)) {
      console.log(`[ANALYZE] ${normalizedAddress}: IS a known drainer recipient`);
      threats.push({
        id: `drainer-recipient-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: 'CRITICAL',
        title: '⚠️ KNOWN DRAINER FUND RECIPIENT',
        description: 'This address is known to receive stolen funds from drainer contracts. It is associated with theft operations.',
        technicalDetails: `This address has been identified as receiving funds from confirmed drainer contracts.`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [normalizedAddress],
        relatedTransactions: [],
        ongoingRisk: true,
      });
    }
    
    // Check if this is protected infrastructure
    const infrastructureCheck = checkInfrastructureProtection(normalizedAddress, this.chain);
    if (infrastructureCheck.isProtected) {
      console.log(`[ANALYZE] ${normalizedAddress}: Protected infrastructure (${infrastructureCheck.name})`);
      // Protected infrastructure = definitely SAFE, skip detailed analysis
    }

    // Fetch all data in parallel
    const [transactions, tokenTransfers, approvalEvents, currentBalance] = await Promise.all([
      this.fetchTransactionHistory(normalizedAddress),
      this.fetchTokenTransfers(normalizedAddress),
      this.fetchApprovalEvents(normalizedAddress),
      this.fetchCurrentBalance(normalizedAddress),
    ]);

    console.log(`[ANALYZE] ${normalizedAddress}: ${transactions.length} txs, ${tokenTransfers.length} transfers, ${approvalEvents.length} approvals, balance: ${currentBalance}`);

    // ============================================
    // COMPREHENSIVE THREAT DETECTION
    // ============================================

    // If infrastructure is protected, skip heuristic detection
    // (only check if it interacted with OTHER malicious addresses)
    if (!infrastructureCheck.isProtected) {
    // 0. EXTERNAL THREAT INTELLIGENCE CHECK (GoPlus, bytecode analysis)
    // This catches zero-day drainers and proxy clones not in our static database
    const externalThreats = await this.checkExternalThreatIntelligence(transactions, tokenTransfers, normalizedAddress);
    threats.push(...externalThreats);
    } else {
      console.log(`[ANALYZE] ${normalizedAddress}: Skipping heuristic detection for protected infrastructure`);
    }

    // Skip heuristic threat detection for protected infrastructure
    if (!infrastructureCheck.isProtected) {
    // 1. DETECT COMPLETE WALLET DRAIN (Private Key Compromise or Drainer)
    const drainThreat = this.detectWalletDrain(transactions, tokenTransfers, currentBalance, normalizedAddress);
    if (drainThreat) threats.push(drainThreat);

    // 2. DETECT KNOWN MALICIOUS INTERACTIONS
      const maliciousThreats = await this.detectMaliciousInteractions(transactions, tokenTransfers, normalizedAddress, approvalEvents);
    threats.push(...maliciousThreats);

    // 3. DETECT SUSPICIOUS APPROVAL PATTERNS
    const approvalThreats = this.detectApprovalAbuse(approvalEvents, tokenTransfers, normalizedAddress);
    threats.push(...approvalThreats);

    // 4. DETECT SWEEPER BOT (Private Key Compromise with Active Monitoring)
    const sweeperThreat = this.detectSweeperBot(transactions, tokenTransfers, currentBalance, normalizedAddress);
    if (sweeperThreat) threats.push(sweeperThreat);
    }

    // ============================================
    // ANALYZE CURRENT APPROVALS
    // ============================================
    
    const analyzedApprovals = this.analyzeApprovals(approvalEvents);

    // Flag active malicious approvals
    for (const approval of analyzedApprovals) {
      if (approval.isMalicious) {
        threats.push({
          id: `active-malicious-approval-${approval.id}`,
          type: 'APPROVAL_HIJACK',
          severity: 'CRITICAL',
          title: 'Active Approval to Malicious Contract',
          description: `You have an active approval allowing a known malicious contract to spend your ${approval.token.symbol} tokens.`,
          technicalDetails: `Spender: ${approval.spender}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [approval.spender],
          relatedTransactions: [],
          ongoingRisk: true,
        });
      }
    }

    // ============================================
    // CALCULATE RESULTS
    // ============================================

    // ============================================
    // PERFORM DIRECTIONAL ANALYSIS FOR CLASSIFICATION
    // ============================================
    // This is CRITICAL for preventing false positives.
    // A wallet is NOT malicious just because it received from compromised wallets.
    
    const directionalAnalysis = this.analyzeTransactionDirection(transactions, tokenTransfers, normalizedAddress);
    
    // Build classification based on behavioral analysis
    const classification = this.buildWalletClassification(
      directionalAnalysis,
      threats,
      normalizedAddress,
      transactions
    );
    
    // ============================================
    // COMPREHENSIVE COMPROMISE ANALYSIS
    // ============================================
    // This is the NEW conservative detection that ensures:
    // - SAFE is only returned when ALL safety checks pass
    // - Any uncertainty results in POTENTIALLY_COMPROMISED
    // - Clear evidence results in COMPROMISED
    
    const compromiseAnalysis = await this.performCompromiseAnalysis(
      normalizedAddress,
      transactions,
      approvalEvents,
      tokenTransfers,
      currentBalance
    );
    
    // Add compromise evidence to threats if detected
    // CRITICAL: Preserve historical vs active status from evidence!
    if (compromiseAnalysis.evidence.length > 0) {
      for (const ev of compromiseAnalysis.evidence) {
        if (ev.severity === 'CRITICAL' || ev.severity === 'HIGH') {
          // Use the evidence's own classification flags
          const isHistorical = ev.isHistorical === true || ev.isActiveThreat === false;
          const isActive = ev.isActiveThreat === true && !ev.isHistorical;
          
          // Determine the threat category based on evidence flags
          let category: 'ACTIVE_RISK' | 'HISTORICAL_EXPOSURE' | 'RESOLVED' = 'ACTIVE_RISK';
          if (isHistorical) {
            category = ev.wasRemediated ? 'RESOLVED' : 'HISTORICAL_EXPOSURE';
          }
          
          // Create user-friendly display label for historical threats
          let displayLabel: string | undefined;
          if (isHistorical) {
            if (ev.wasRemediated) {
              displayLabel = `✓ Previously revoked – no active risk`;
            } else {
              displayLabel = `ℹ️ Historical: ${this.getCompromiseThreatTitle(ev.code)} (no current access)`;
            }
          }
          
          threats.push({
            id: `compromise-${ev.code}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            type: this.mapCompromiseCodeToAttackType(ev.code),
            severity: isHistorical ? 'LOW' : ev.severity, // Downgrade historical threats to LOW
            title: displayLabel || this.getCompromiseThreatTitle(ev.code),
            description: isHistorical 
              ? `${ev.description}\n\n⚠️ This is a HISTORICAL event. No active malicious access exists.`
              : ev.description,
            technicalDetails: `Code: ${ev.code}\nConfidence: ${ev.confidence}%${ev.relatedAddress ? `\nRelated Address: ${ev.relatedAddress}` : ''}${isHistorical ? '\n\n✓ Historical event - excluded from risk score.' : ''}`,
            detectedAt: ev.timestamp || new Date().toISOString(),
            relatedAddresses: ev.relatedAddress ? [ev.relatedAddress] : [],
            relatedTransactions: ev.relatedTxHash ? [ev.relatedTxHash] : [],
            ongoingRisk: isActive,
            // Critical: Set the historical/resolved fields
            category,
            isHistorical,
            approvalRevoked: ev.wasRemediated,
            excludeFromRiskScore: isHistorical,
            displayLabel,
          });
        }
      }
    }
    
    const riskScore = this.calculateRiskScore(threats, analyzedApprovals);
    const riskLevel = this.determineRiskLevel(riskScore, threats);
    
    // USE COMPROMISE ANALYSIS FOR SECURITY STATUS (more conservative)
    const securityStatus = this.determineSecurityStatusConservative(
      riskScore,
      threats,
      compromiseAnalysis
    );
    
    const suspiciousTransactions = this.buildSuspiciousTransactions(transactions, threats);
    const recommendations = this.generateRecommendations(threats, analyzedApprovals, securityStatus);
    const recoveryPlan = securityStatus !== 'SAFE' ? this.generateRecoveryPlan(threats, analyzedApprovals) : undefined;
    
    // Generate human-readable classification reason
    const classificationReason = this.generateClassificationReason(classification, directionalAnalysis);

    console.log(`[ANALYZE] Completed. Status: ${securityStatus}, Role: ${classification.role}, Score: ${riskScore}, Threats: ${threats.length}`);

    return {
      address: normalizedAddress,
      chain: this.chain,
      timestamp: new Date().toISOString(),
      
      // Core security assessment
      securityStatus,
      riskScore,
      
      // Classification (prevents false positives)
      classification,
      riskLevel,
      classificationReason,
      
      // Detailed analysis
      summary: this.generateSummary(securityStatus, threats, analyzedApprovals),
      detectedThreats: threats,
      approvals: analyzedApprovals,
      suspiciousTransactions,
      recommendations,
      recoveryPlan,
      educationalContent: this.generateEducationalContent(threats),
      
      // Directional analysis for transparency
      directionalAnalysis,
    };
  }

  // ============================================
  // CORE DETECTION: WALLET DRAIN
  // ============================================

  private detectWalletDrain(
    transactions: TransactionData[],
    tokenTransfers: TokenTransfer[],
    currentBalance: string,
    userAddress: string
  ): DetectedThreat | null {
    // ============================================
    // STEP 0: INFRASTRUCTURE PROTECTION CHECK
    // ============================================
    // If this address IS protected infrastructure (OpenSea, Uniswap, etc.),
    // it can NEVER be classified as a drainer - short-circuit immediately.
    const infrastructureCheck = checkInfrastructureProtection(userAddress, this.chain);
    if (infrastructureCheck.isProtected) {
      console.log(`[detectWalletDrain] ${userAddress}: Protected infrastructure (${infrastructureCheck.name}) - cannot be drainer`);
      return null;
    }

    // ============================================
    // CRITICAL FALSE POSITIVE PREVENTION
    // ============================================
    // Sending assets to safe contracts/exchanges is NORMAL user activity:
    // - DEX swaps (Uniswap, SushiSwap, etc.)
    // - Exchange deposits (Binance, Coinbase, etc.)
    // - NFT purchases (OpenSea, Blur, etc.)
    // - Staking (Lido, Rocket Pool, etc.)
    // - Bridge deposits (Arbitrum, Optimism, etc.)
    
    // Skip if no activity
    if (transactions.length === 0 && tokenTransfers.length === 0) return null;

    // Parse current balance
    let balanceWei: bigint;
    try {
      balanceWei = BigInt(currentBalance || '0');
    } catch {
      balanceWei = BigInt(0);
    }

    // Helper: Check if address is a safe/legitimate destination
    const isSafeDestination = (address: string): boolean => {
      const normalized = address.toLowerCase();
      // CRITICAL: Check infrastructure protection FIRST
      // OpenSea, Uniswap, etc. can NEVER be flagged as drainer destinations
      const infraCheck = checkInfrastructureProtection(normalized, this.chain);
      if (infraCheck.isProtected) return true;
      // Check comprehensive safe contracts
      if (isSafeContract(normalized)) return true;
      // Check exchange hot wallets
      if (EXCHANGE_HOT_WALLETS.has(normalized)) return true;
      // Check legacy legitimate contracts
      if (isLegitimateContract(normalized)) return true;
      // Check specific categories
      if (isDeFiProtocol(normalized)) return true;
      if (isNFTMarketplace(normalized)) return true;
      if (isENSContract(normalized)) return true;
      if (isInfrastructureContract(normalized)) return true;
      return false;
    };

    // Collect all outbound transfers
    const outboundTransfers: { to: string; hash: string; timestamp: number; type: string; value: string }[] = [];

    // Native ETH transfers
    for (const tx of transactions) {
      if (!tx?.from || !tx?.to) continue;
      if (tx.from.toLowerCase() === userAddress) {
        const value = BigInt(tx.value || '0');
        if (value > BigInt(0)) {
          outboundTransfers.push({
            to: tx.to.toLowerCase(),
            hash: tx.hash,
            timestamp: tx.timestamp,
            type: 'native',
            value: tx.value,
          });
        }
      }
    }

    // Token transfers
    for (const transfer of tokenTransfers) {
      if (!transfer?.from || !transfer?.to) continue;
      if (transfer.from.toLowerCase() === userAddress) {
        outboundTransfers.push({
          to: transfer.to.toLowerCase(),
          hash: transfer.hash,
          timestamp: transfer.timestamp,
          type: `token:${transfer.tokenSymbol}`,
          value: transfer.value,
        });
      }
    }

    if (outboundTransfers.length === 0) return null;

    // ============================================
    // FIRST: Calculate ratio of safe vs unknown destinations
    // If most outbound goes to safe destinations, this is NORMAL
    // ============================================
    const safeOutbound = outboundTransfers.filter(t => isSafeDestination(t.to));
    const safeRatio = outboundTransfers.length > 0 ? safeOutbound.length / outboundTransfers.length : 1;
    
    // If > 60% of outbound goes to safe destinations, NOT a drain
    if (safeRatio > 0.6) {
      console.log(`[detectWalletDrain] ${userAddress}: ${(safeRatio * 100).toFixed(0)}% outbound to safe destinations - NOT a drain`);
      return null;
    }

    // Check if wallet is currently empty
    const isCurrentlyEmpty = balanceWei < BigInt('1000000000000000'); // < 0.001 ETH

    // Analyze outbound pattern (excluding safe destinations)
    const destinationCounts: Record<string, { count: number; types: Set<string>; hashes: string[]; timestamps: number[] }> = {};
    
    for (const transfer of outboundTransfers) {
      // CRITICAL: Skip safe destinations
      if (isSafeDestination(transfer.to)) continue;
      
      if (!destinationCounts[transfer.to]) {
        destinationCounts[transfer.to] = { count: 0, types: new Set(), hashes: [], timestamps: [] };
      }
      destinationCounts[transfer.to].count++;
      destinationCounts[transfer.to].types.add(transfer.type);
      destinationCounts[transfer.to].hashes.push(transfer.hash);
      destinationCounts[transfer.to].timestamps.push(transfer.timestamp);
    }

    // If no suspicious destinations remain, NOT a drain
    if (Object.keys(destinationCounts).length === 0) {
      return null;
    }

    // Find suspicious patterns
    for (const [destination, data] of Object.entries(destinationCounts)) {
      // Double-check: Skip known legitimate contracts
      if (isSafeDestination(destination)) continue;

      // Check for known drainer - this is the ONLY high-confidence case
      const isMalicious = isMaliciousAddress(destination, this.chain) || isDrainerRecipient(destination);
      
      // PATTERN 1: Confirmed drainer address
      if (isMalicious) {
        return {
          id: `drain-confirmed-${Date.now()}`,
          type: 'WALLET_DRAINER',
          severity: 'CRITICAL',
          title: 'Assets Sent to Known Drainer Address',
          description: `${data.count} transfer(s) were made to a known drainer/scam address (${destination.slice(0, 10)}...). Your assets have likely been stolen.`,
          technicalDetails: `Drainer: ${destination}, Transfers: ${data.count}, Asset types: ${Array.from(data.types).join(', ')}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: data.hashes.slice(0, 10),
          ongoingRisk: true,
        };
      }

      // For other patterns, be VERY conservative
      // Only flag if multiple asset types AND many transfers AND wallet is empty
      const hasMultipleAssetTypes = data.types.size >= 3; // Require 3+ asset types
      const hasNativeAndTokens = data.types.has('native') && 
        Array.from(data.types).filter(t => t.startsWith('token:')).length >= 2; // Native + 2 tokens

      const timestamps = data.timestamps.sort((a, b) => a - b);
      const timeSpan = timestamps.length > 1 ? (timestamps[timestamps.length - 1] - timestamps[0]) : 0;
      const isRapid = timeSpan <= 15 * 60; // Stricter: 15 minutes

      // PATTERN 2: Multiple different asset types to same UNKNOWN address quickly
      // AND wallet is now empty - very strong indicator
      if (hasNativeAndTokens && isRapid && data.count >= 4 && isCurrentlyEmpty) {
        return {
          id: `drain-pattern-${Date.now()}`,
          type: 'PRIVATE_KEY_LEAK',
          severity: 'HIGH', // Downgraded from CRITICAL
          title: 'Possible Wallet Drain Detected',
          description: `${data.count} different assets were sent to the same unknown address (${destination.slice(0, 10)}...) within ${Math.ceil(timeSpan / 60)} minutes. Your wallet balance is now nearly zero. Review these transactions.`,
          technicalDetails: `Destination: ${destination}, Time span: ${Math.ceil(timeSpan / 60)} minutes, Assets: ${Array.from(data.types).join(', ')}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: data.hashes.slice(0, 10),
          ongoingRisk: false, // Changed to false - need more evidence
        };
      }

      // PATTERN 3: Many transfers to same UNKNOWN address quickly
      // Require more transfers to trigger (8+)
      if (data.count >= 8 && isRapid) {
        return {
          id: `suspicious-outflow-${Date.now()}`,
          type: 'WALLET_DRAINER',
          severity: 'MEDIUM', // Downgraded
          title: 'Unusual Asset Outflow Detected',
          description: `${data.count} transfers to the same unknown address (${destination.slice(0, 10)}...) within a short time period. Review these transactions.`,
          technicalDetails: `Destination: ${destination}, Transfers: ${data.count}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: data.hashes.slice(0, 10),
          ongoingRisk: false,
        };
      }
    }

    // REMOVED: "Wallet emptied" pattern - too many false positives
    // Users often empty wallets intentionally when:
    // - Moving to new wallet
    // - Depositing to exchange
    // - Consolidating funds

    return null;
  }

  // ============================================
  // DETECTION: SWEEPER BOT (Private Key Compromise)
  // ============================================
  // 
  // CRITICAL FALSE POSITIVE PREVENTION:
  // DO NOT flag as sweeper bot when:
  // 1. Wallet is self-managed (consistent auto-forwarding to SAME address)
  // 2. Outgoing transactions are to known infrastructure (ENS, routers, exchanges)
  // 3. No evidence of malicious approvals or drainer interactions
  //
  // ONLY flag as sweeper when:
  // 1. Outflows are preceded by malicious approvals/drainer calls
  // 2. Funds go to MULTIPLE different unknown addresses (indicates loss of control)
  // 3. Pattern matches known attacker behavior

  // ============================================
  // CONTEXT-AWARE SWEEPER BOT DETECTION
  // ============================================
  // This function uses address role classification and multiple
  // independent signals to avoid false positives for:
  // - Exchange deposit addresses
  // - Bridges and relayers
  // - Router / infrastructure contracts
  // - User-controlled wallets that actively manage funds
  //
  // RULE: Rapid forwarding alone is NOT evidence of a sweeper bot.
  // Multiple independent malicious signals are REQUIRED.
  //
  // CRITICAL: Infrastructure contracts (OpenSea, Uniswap, etc.) can NEVER
  // be classified as sweeper bots, drainers, or Pink Drainer.

  private detectSweeperBot(
    transactions: TransactionData[],
    tokenTransfers: TokenTransfer[],
    currentBalance: string,
    userAddress: string
  ): DetectedThreat | null {
    // ============================================
    // STEP 0: INFRASTRUCTURE PROTECTION CHECK
    // ============================================
    // This MUST be checked FIRST. If the wallet is interacting with
    // protected infrastructure, we apply special handling.
    const infrastructureCheck = checkInfrastructureProtection(userAddress, this.chain);
    if (infrastructureCheck.isProtected) {
      console.log(`[detectSweeperBot] ${userAddress}: Protected infrastructure (${infrastructureCheck.name}) - cannot be sweeper bot`);
      return null;
    }

    if (transactions.length < 4) return null;

    // Parse current balance
    let balanceWei: bigint;
    try {
      balanceWei = BigInt(currentBalance || '0');
    } catch {
      balanceWei = BigInt(0);
    }

    // ============================================
    // HELPER: Check if destination is legitimate
    // ============================================
    const isLegitimateDestination = (address: string, methodId?: string): boolean => {
      const normalized = address.toLowerCase();
      
      // CRITICAL: Check infrastructure protection FIRST
      // OpenSea, Uniswap, etc. can NEVER be flagged as malicious destinations
      const infraCheck = checkInfrastructureProtection(normalized, this.chain);
      if (infraCheck.isProtected) return true;
      
      // Check safe contracts (comprehensive allowlist)
      if (isSafeContract(normalized)) return true;
      if (isDeFiProtocol(normalized)) return true;
      if (isNFTMarketplace(normalized)) return true;
      if (isNFTMintContract(normalized)) return true;
      if (isENSContract(normalized)) return true;
      if (isInfrastructureContract(normalized)) return true;
      if (EXCHANGE_HOT_WALLETS.has(normalized)) return true;
      if (isLegitimateContract(normalized)) return true;
      
      // Check if method indicates user action
      if (methodId) {
        const userActionMethods = new Set([
          '0x7ff36ab5', '0x38ed1739', '0x18cbafe5', // Uniswap V2
          '0x04e45aaf', '0xb858183f', '0x472b43f3', // Uniswap V3
          '0xd0e30db0', '0xb6b55f25', '0xa694fc3a', // deposit, stake
          '0xe8eda9df', // Aave deposit
          '0x1249c58b', '0xa0712d68', '0x40c10f19', // mint
          '0xfb0f3ee1', '0x87201b41', // Seaport
        ]);
        if (userActionMethods.has(methodId.toLowerCase().slice(0, 10))) return true;
      }
      
      return false;
    };

    // Build timeline of in/out transactions
    const timeline: { type: 'in' | 'out'; to: string; from: string; value: bigint; timestamp: number; hash: string; methodId?: string }[] = [];

    for (const tx of transactions) {
      if (!tx?.from || !tx?.to || !tx?.hash) continue;
      const value = BigInt(tx.value || '0');
      if (value === BigInt(0)) continue;

      if (tx.to.toLowerCase() === userAddress) {
        timeline.push({ type: 'in', to: tx.to, from: tx.from.toLowerCase(), value, timestamp: tx.timestamp, hash: tx.hash });
      } else if (tx.from.toLowerCase() === userAddress) {
        timeline.push({ type: 'out', to: tx.to.toLowerCase(), from: tx.from, value, timestamp: tx.timestamp, hash: tx.hash, methodId: tx.methodId });
      }
    }

    timeline.sort((a, b) => a.timestamp - b.timestamp);

    // ============================================
    // CONTEXT GATHERING
    // ============================================
    const outgoingTxs = timeline.filter(t => t.type === 'out');
    const incomingTxs = timeline.filter(t => t.type === 'in');
    const uniqueSenders = new Set(incomingTxs.map(t => t.from)).size;
    const uniqueRecipients = new Set(outgoingTxs.map(t => t.to)).size;
    const destinationAddresses = [...new Set(outgoingTxs.map(t => t.to))];
    
    // Find primary recipient
    const destCounts = new Map<string, number>();
    for (const tx of outgoingTxs) {
      destCounts.set(tx.to, (destCounts.get(tx.to) || 0) + 1);
    }
    let primaryRecipient = '';
    let primaryCount = 0;
    for (const [dest, count] of destCounts) {
      if (count > primaryCount) {
        primaryRecipient = dest;
        primaryCount = count;
      }
    }
    
    const forwardsToSameAddress = primaryCount / Math.max(outgoingTxs.length, 1) > 0.8;
    const hasProtocolInteraction = transactions.some(tx => 
      tx.input && tx.input.length > 10 && isLegitimateDestination(tx.to, tx.input.slice(0, 10))
    );
    
    // Calculate average time to forward
    let totalTimeDelta = 0;
    let forwardCount = 0;
    for (let i = 0; i < timeline.length - 1; i++) {
      if (timeline[i].type === 'in') {
        for (let j = i + 1; j < timeline.length && j <= i + 5; j++) {
          if (timeline[j].type === 'out') {
            totalTimeDelta += timeline[j].timestamp - timeline[i].timestamp;
            forwardCount++;
            break;
          }
        }
      }
    }
    const avgTimeToForward = forwardCount > 0 ? totalTimeDelta / forwardCount : 0;

    // ============================================
    // STEP 1: BEHAVIORAL SWEEPER ANALYSIS (PRIMARY - RUN FIRST!)
    // ============================================
    // This MUST run BEFORE any early exits based on destination classification.
    // A sweeper bot sending to "exchange infrastructure" is STILL a sweeper bot!
    const behavioralAnalysis = analyzeBehavioralSweeperPattern(
      transactions.map(tx => ({
        hash: tx.hash,
        from: tx.from,
        to: tx.to || '',
        value: tx.value,
        timestamp: tx.timestamp,
        input: tx.input,
      })),
      userAddress,
      currentBalance
    );
    
    console.log(`[detectSweeperBot] ${userAddress}: Behavioral analysis - isLikelySweeper: ${behavioralAnalysis.isLikelySweeper}, confidence: ${behavioralAnalysis.confidence}%, recommendation: ${behavioralAnalysis.recommendation}`);
    
    // ============================================
    // STEP 1.5: IF BEHAVIORAL EVIDENCE EXISTS, FLAG IMMEDIATELY
    // ============================================
    // Do NOT allow early exits to bypass behavioral sweeper patterns
    // CRITICAL: Even 40% confidence behavioral evidence is significant - 
    // known address lists should NOT override behavioral detection!
    if (behavioralAnalysis.isLikelySweeper && behavioralAnalysis.confidence >= 40) {
      const detectedIndicators = behavioralAnalysis.indicators.filter(i => i.detected);
      console.log(`[detectSweeperBot] ${userAddress}: BEHAVIORAL SWEEPER DETECTED (${behavioralAnalysis.confidence}%) - ${detectedIndicators.length} indicators - OVERRIDING destination checks`);
      
      // Build evidence
      const evidenceTxHashes = behavioralAnalysis.sweepEvents.slice(0, 5).map(e => e.outboundTxHash);
      const topDest = behavioralAnalysis.sweepEvents.length > 0 
        ? behavioralAnalysis.sweepEvents[0].destinationAddress 
        : primaryRecipient || 'unknown';
      
      // CRITICAL: Per requirements, ≥2 behavioral indicators = COMPROMISED
      // Use CRITICAL severity to ensure COMPROMISED status
      const detectedCount = detectedIndicators.length;
      const severity = detectedCount >= 2 ? 'CRITICAL' : 
                       behavioralAnalysis.confidence >= 50 ? 'HIGH' : 'MEDIUM';
      
      return {
        id: `behavioral-sweeper-${Date.now()}`,
        type: 'PRIVATE_KEY_LEAK' as AttackType,
        severity,
        title: '🚨 AUTOMATED BALANCE DRAINING DETECTED (Sweeper Bot)',
        description: `This wallet shows automated fund draining behavior. ${behavioralAnalysis.evidenceSummary} Any funds sent to this wallet are being automatically swept. The private key is likely compromised.`,
        technicalDetails: `Behavioral Analysis:\n${detectedIndicators.map(i => `• ${i.type}: ${i.evidence}`).join('\n')}\n\nConfidence: ${behavioralAnalysis.confidence}%\nSweep Events: ${behavioralAnalysis.sweepEvents.length}\nRecommendation: ${behavioralAnalysis.recommendation}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [topDest],
        relatedTransactions: evidenceTxHashes,
        ongoingRisk: true,
        attackerInfo: {
          address: topDest,
          type: 'SWEEPER_BOT',
          confidence: behavioralAnalysis.confidence,
          evidenceCount: detectedIndicators.length,
          firstSeenAt: new Date().toISOString(),
        },
        category: 'ACTIVE_RISK',
        isHistorical: false,
        excludeFromRiskScore: false,
      };
    }

    // ============================================
    // STEP 2: CLASSIFY THE PRIMARY DESTINATION ADDRESS
    // ============================================
    // Only apply these checks if behavioral analysis didn't find strong evidence
    const primaryDestClassification = primaryRecipient 
      ? classifyAddress(primaryRecipient, this.chain, {
          incomingCount: incomingTxs.length,
          outgoingCount: outgoingTxs.length,
          uniqueSenders,
          uniqueRecipients,
          avgTimeToForward,
          forwardsToSameAddress,
          primaryRecipient,
          hasProtocolInteraction,
        })
      : null;

    // ============================================
    // STEP 3: CHECK IF THIS IS EXCHANGE/INFRASTRUCTURE BEHAVIOR
    // ============================================
    // ONLY skip if behavioral analysis showed NO sweeper patterns
    if (!behavioralAnalysis.isLikelySweeper && primaryDestClassification && 
        (primaryDestClassification.role === 'EXCHANGE_INFRASTRUCTURE' ||
         primaryDestClassification.role === 'PROTOCOL_ROUTER' ||
         primaryDestClassification.role === 'DEFI_PROTOCOL' ||
         primaryDestClassification.role === 'INFRASTRUCTURE')) {
      console.log(`[detectSweeperBot] ${userAddress}: Primary destination ${primaryRecipient.slice(0, 10)}... is ${primaryDestClassification.role} - NOT a sweeper`);
      return null;
    }

    // ============================================
    // STEP 4: LEGITIMATE DESTINATION RATIO CHECK
    // ============================================
    const legitimateOutgoingCount = outgoingTxs.filter(t => isLegitimateDestination(t.to, t.methodId)).length;
    const legitimateRatio = outgoingTxs.length > 0 ? legitimateOutgoingCount / outgoingTxs.length : 1;
    
    // Only apply this check if behavioral analysis showed NO sweeper patterns
    if (!behavioralAnalysis.isLikelySweeper && legitimateRatio > 0.7) {
      console.log(`[detectSweeperBot] ${userAddress}: ${(legitimateRatio * 100).toFixed(0)}% outgoing to legitimate destinations - NOT a sweeper victim`);
      return null;
    }

    // ============================================
    // STEP 5: AUTO-FORWARDING DETECTION (non-malicious)
    // ============================================
    // Only apply this check if behavioral analysis showed NO sweeper patterns
    if (!behavioralAnalysis.isLikelySweeper && forwardsToSameAddress && uniqueRecipients <= 3) {
      // Classify the wallet's behavior pattern
      const walletClassification = classifyAddress(userAddress, this.chain, {
        incomingCount: incomingTxs.length,
        outgoingCount: outgoingTxs.length,
        uniqueSenders,
        uniqueRecipients,
        avgTimeToForward,
        forwardsToSameAddress,
        primaryRecipient,
        hasProtocolInteraction,
      });
      
      if (walletClassification.role === 'AUTOMATED_FORWARDER' || 
          walletClassification.role === 'EXCHANGE_INFRASTRUCTURE') {
        console.log(`[detectSweeperBot] ${userAddress}: Classified as ${walletClassification.role} - NOT a sweeper victim`);
        return null;
      }
    }

    // ============================================
    // STEP 6: GATHER MALICIOUS SIGNALS
    // ============================================
    const hasMaliciousApprovals = transactions.some(tx => {
      if (!tx.input || tx.input.length < 10) return false;
      const methodId = tx.input.slice(0, 10).toLowerCase();
      if (methodId === '0x095ea7b3' || methodId === '0xa22cb465') {
        const spender = tx.input.slice(34, 74).toLowerCase();
        return isMaliciousAddress(`0x${spender}`, this.chain) !== null || isDrainerRecipient(`0x${spender}`);
      }
      return false;
    });

    const hasDrainerInteraction = transactions.some(tx => {
      if (!tx?.to) return false;
      return isMaliciousAddress(tx.to, this.chain) !== null || isDrainerRecipient(tx.to);
    });

    // Check for permit signatures (potential abuse)
    const hasPermitSignatures = transactions.some(tx => {
      if (!tx.input || tx.input.length < 10) return false;
      const methodId = tx.input.slice(0, 10).toLowerCase();
      return methodId === '0xd505accf' || methodId === '0x8fcbaf0c'; // permit() signatures
    });

    // ============================================
    // STEP 6.5: ANALYZE SWEEPER SIGNALS (COMBINED)
    // ============================================
    // Analyze sweeper signals using the new system (includes behavioral + label-based)
    const sweeperSignals = analyzeSweeperSignals(userAddress, this.chain, {
      hasDrainerInteraction,
      hasUnauthorizedApprovals: hasMaliciousApprovals,
      hasPermitSignatures,
      lostAssetsWithoutInitiation: false, // Would need deeper analysis
      destinationAddresses,
      hasKnownAttackerLink: hasDrainerInteraction,
      calledMaliciousContracts: hasDrainerInteraction,
      behavioralAnalysis, // Pass behavioral analysis results
    });

    // ============================================
    // STEP 6: APPLY MULTIPLE SIGNAL REQUIREMENT
    // ============================================
    // RULE: If ≥2 BEHAVIORAL signals OR ≥2 label-based signals = potential sweeper
    // CRITICAL: Behavioral signals can INDEPENDENTLY trigger detection!
    const hasSufficientBehavioralEvidence = sweeperSignals.behavioralSignalCount >= 2;
    const hasSufficientLabelEvidence = sweeperSignals.signalCount - sweeperSignals.behavioralSignalCount >= 2;
    
    if (!hasSufficientBehavioralEvidence && !hasSufficientLabelEvidence && sweeperSignals.signalCount < 2) {
      console.log(`[detectSweeperBot] ${userAddress}: Only ${sweeperSignals.signalCount} signal(s) (${sweeperSignals.behavioralSignalCount} behavioral) - insufficient for classification`);
      return null;
    }
    
    console.log(`[detectSweeperBot] ${userAddress}: ${sweeperSignals.signalCount} signals detected (${sweeperSignals.behavioralSignalCount} behavioral) - proceeding with analysis`);

    // ============================================
    // STEP 7: DETECT SWEEP PATTERNS
    // ============================================
    const sweepEvents: { inTx: string; outTx: string; sweeperAddress: string; timeDelta: number; confidence: number }[] = [];
    const sweeperAddresses: Record<string, number> = {};

    for (let i = 0; i < timeline.length - 1; i++) {
      const current = timeline[i];
      if (current.type !== 'in') continue;

      for (let j = i + 1; j < timeline.length && j <= i + 10; j++) {
        const next = timeline[j];
        if (next.type !== 'out') continue;
        if (isLegitimateDestination(next.to, next.methodId)) continue;
        
        const timeDelta = next.timestamp - current.timestamp;
        const MAX_SWEEP_WINDOW = 3600;
        
        if (timeDelta >= 0 && timeDelta <= MAX_SWEEP_WINDOW) {
          const confidenceScore = Math.max(0.3, 1 - (timeDelta / MAX_SWEEP_WINDOW) * 0.7);
          sweepEvents.push({
            inTx: current.hash,
            outTx: next.hash,
            sweeperAddress: next.to,
            timeDelta,
            confidence: confidenceScore,
          });
          sweeperAddresses[next.to] = (sweeperAddresses[next.to] || 0) + confidenceScore;
          break;
        }
      }
    }

    // ============================================
    // STEP 8: DETERMINE VERDICT USING NEW SYSTEM
    // ============================================
    const confirmedSweeper = Object.entries(sweeperAddresses).find(([addr, score]) => {
      return score >= 2.5 && !isLegitimateDestination(addr);
    });

    if (confirmedSweeper) {
      const [sweeperAddress, confidenceScore] = confirmedSweeper;
      
      // Classify the sweeper address
      const sweeperClassification = classifyAddress(sweeperAddress, this.chain);
      
      // Get final verdict from the new system
      const verdict = determineSweeperVerdict(sweeperClassification, sweeperSignals);
      
      // If verdict says no sweeper, return null
      if (!verdict.isSweeperBot) {
        console.log(`[detectSweeperBot] ${userAddress}: Verdict is ${verdict.verdict} - ${verdict.userMessage}`);
        return null;
      }
      
      // ============================================
      // CONFIDENCE FAILSAFE: < 85% = no critical alert
      // ============================================
      if (verdict.confidence < 85 && verdict.alertSeverity === 'CRITICAL') {
        console.log(`[detectSweeperBot] ${userAddress}: Confidence ${verdict.confidence}% < 85% - downgrading alert`);
        return {
          id: `sweeper-suspected-${Date.now()}`,
          type: 'WALLET_DRAINER',
          severity: 'MEDIUM',
          title: '⚠️ Unusual Fund Movement Pattern',
          description: verdict.userMessage,
          technicalDetails: verdict.technicalDetails.join('\n'),
          detectedAt: new Date().toISOString(),
          relatedAddresses: [sweeperAddress],
          relatedTransactions: sweepEvents.map(e => e.outTx).slice(0, 10),
          ongoingRisk: false,
        };
      }

      const relevantEvents = sweepEvents.filter(e => e.sweeperAddress === sweeperAddress);
      const sweepCount = relevantEvents.length;
      const avgTimeDelta = sweepCount > 0 
        ? relevantEvents.reduce((sum, e) => sum + e.timeDelta, 0) / sweepCount 
        : 0;
      const isCurrentlyEmpty = balanceWei < BigInt('1000000000000000');

      return {
        id: `sweeper-bot-${Date.now()}`,
        type: 'PRIVATE_KEY_LEAK',
        severity: verdict.alertSeverity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        title: verdict.verdict === 'CONFIRMED_SWEEPER' 
          ? '🚨 SWEEPER BOT DETECTED - Private Key Compromised'
          : '⚠️ Suspected Sweeper Bot Activity',
        description: verdict.userMessage,
        technicalDetails: `Destination Address: ${sweeperAddress}\nSweep Events: ${sweepCount}\nAverage Response Time: ${Math.round(avgTimeDelta)}s\nWallet Empty: ${isCurrentlyEmpty ? 'Yes' : 'No'}\nConfidence: ${verdict.confidence}%\nSignals: ${sweeperSignals.signalCount}\n\n${verdict.technicalDetails.join('\n')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [sweeperAddress],
        relatedTransactions: sweepEvents.map(e => e.outTx).slice(0, 10),
        ongoingRisk: verdict.verdict === 'CONFIRMED_SWEEPER',
        attackerInfo: {
          address: sweeperAddress,
          type: 'SWEEPER_BOT',
          sweepCount,
          avgResponseTime: Math.round(avgTimeDelta),
        },
      };
    }

    // ============================================
    // LARGE SINGLE SWEEP CHECK (with context awareness)
    // ============================================
    const largeIncoming = timeline.filter(t => t.type === 'in' && t.value > BigInt('100000000000000000'));
    
    for (const incoming of largeIncoming) {
      const incomingIdx = timeline.indexOf(incoming);
      
      for (let j = incomingIdx + 1; j < timeline.length && j <= incomingIdx + 3; j++) {
        const outgoing = timeline[j];
        if (outgoing.type !== 'out') continue;
        if (isLegitimateDestination(outgoing.to, outgoing.methodId)) continue;
        
        const timeDelta = outgoing.timestamp - incoming.timestamp;
        const valueRatio = Number(outgoing.value) / Number(incoming.value);
        
        // Stricter: Only flag if >90% value sent out within 10 minutes to UNKNOWN address
        if (timeDelta >= 0 && timeDelta <= 600 && valueRatio > 0.9) {
          return {
            id: `rapid-sweep-${Date.now()}`,
            type: 'PRIVATE_KEY_LEAK',
            severity: 'CRITICAL',
            title: '⚠️ Rapid Fund Sweep Detected',
            description: `${ethers.formatEther(incoming.value)} ETH was received and ${(valueRatio * 100).toFixed(1)}% was immediately sent out within ${Math.round(timeDelta / 60)} minutes to an unknown address. This pattern strongly suggests your private key is compromised.`,
            technicalDetails: `Sweeper Address: ${outgoing.to}\nIncoming TX: ${incoming.hash}\nOutgoing TX: ${outgoing.hash}\nTime Delta: ${timeDelta}s`,
            detectedAt: new Date().toISOString(),
            relatedAddresses: [outgoing.to],
            relatedTransactions: [incoming.hash, outgoing.hash],
            ongoingRisk: true,
          };
        }
      }
    }

    return null;
  }

  // ============================================
  // DETECTION: MALICIOUS CONTRACT INTERACTIONS
  // ============================================
  // 
  // CRITICAL FALSE POSITIVE PREVENTION:
  // This method now uses DIRECTIONAL analysis to distinguish:
  // - VICTIM: Lost funds to drainer (should be warned, not flagged as attacker)
  // - ATTACKER: Initiated malicious calls or received stolen funds
  // - NEUTRAL: Interacted with same contracts as compromised wallets (NOT flagged)
  // - SERVICE: Receives fees from many wallets (NOT flagged - e.g., 20% fee receiver)
  //
  // The key insight is: receiving funds ≠ malicious behavior
  // Only flag when there is ACTIVE malicious behavior by the analyzed wallet.

  private async detectMaliciousInteractions(
    transactions: TransactionData[],
    tokenTransfers: TokenTransfer[],
    userAddress: string,
    approvalEvents: ApprovalEvent[]
  ): Promise<DetectedThreat[]> {
    const threats: DetectedThreat[] = [];
    const flaggedAddresses = new Set<string>();

    // ============================================
    // STEP 0: INFRASTRUCTURE PROTECTION CHECK
    // ============================================
    // If this wallet IS protected infrastructure (OpenSea, Uniswap, etc.),
    // it can NEVER be classified as malicious - return empty threats.
    const infrastructureCheck = checkInfrastructureProtection(userAddress, this.chain);
    if (infrastructureCheck.isProtected) {
      console.log(`[detectMaliciousInteractions] ${userAddress}: Protected infrastructure (${infrastructureCheck.name}) - skipping malicious detection`);
      return threats; // Empty - infrastructure cannot be malicious
    }

    // Perform directional analysis to understand wallet's role
    const directionalAnalysis = this.analyzeTransactionDirection(transactions, tokenTransfers, userAddress);

    // ============================================
    // CASE 1: User SENT assets TO a known malicious address
    // ============================================
    // This could mean:
    // - User was phished (VICTIM)
    // - User interacted with scam site (VICTIM)
    // Severity: HIGH (user lost funds, but they are the victim)
    
    for (const tx of transactions) {
      if (!tx?.to || !tx?.from || !tx?.hash) continue;
      
      // Only check OUTBOUND transactions (user initiated)
      if (tx.from.toLowerCase() !== userAddress) continue;
      
      const destination = tx.to.toLowerCase();
      
      // Skip if destination is protected infrastructure
      // CRITICAL: OpenSea, Uniswap etc. can NEVER be flagged as malicious destinations
      const destInfraCheck = checkInfrastructureProtection(destination, this.chain);
      if (destInfraCheck.isProtected) continue;
      
      // Skip if destination is legitimate infrastructure (secondary check)
      if (isLegitimateContract(destination)) continue;
      
      const malicious = isMaliciousAddress(destination, this.chain);
      
      if (malicious && !flaggedAddresses.has(destination)) {
        flaggedAddresses.add(destination);
        
        // ============================================
        // HISTORICAL VS ACTIVE CHECK:
        // Past interaction with drainer ≠ current compromise
        // Only flag as ACTIVE if there's a current exploit vector
        // ============================================
        
        // Check if user has any ACTIVE approvals to this malicious address
        const hasActiveApproval = approvalEvents.some(a => 
          a.spender.toLowerCase() === destination &&
          BigInt(a.amount || '0') > BigInt(0)
        );
        
        // This is a HISTORICAL interaction if:
        // - No active approvals to this address
        // - Transaction is in the past (it always is)
        const isHistorical = !hasActiveApproval;
        
        threats.push({
          id: `victim-sent-to-drainer-${tx.hash}`,
          type: malicious.type || 'WALLET_DRAINER',
          severity: isHistorical ? 'LOW' : 'HIGH', // Downgrade historical to LOW
          title: isHistorical 
            ? `ℹ️ Historical Interaction: ${malicious.name || 'Known Malicious Address'}`
            : `⚠️ Active Risk: Interacted with ${malicious.name || 'Known Malicious Contract'}`,
          description: isHistorical
            ? `You previously interacted with "${malicious.name || 'a known malicious address'}". No active approvals detected – this is historical exposure only.`
            : `You sent a transaction to "${malicious.name || 'a known malicious contract'}" and may still have active approvals. Review your approvals immediately.`,
          technicalDetails: `Address: ${destination}\nTransaction: ${tx.hash}\nStatus: ${isHistorical ? 'HISTORICAL (no active access)' : 'ACTIVE RISK'}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: [tx.hash],
          ongoingRisk: !isHistorical,
          // NEW: Historical vs Active categorization
          category: isHistorical ? 'HISTORICAL_EXPOSURE' : 'ACTIVE_RISK',
          isHistorical,
          displayLabel: isHistorical ? 'Previously interacted – no active access' : undefined,
          excludeFromRiskScore: isHistorical, // Historical events don't affect risk score
        });
      }
    }

    // ============================================
    // CASE 2: User SENT tokens TO a known malicious address
    // ============================================
    // UPDATED: Now checks for active vs historical exposure
    
    for (const transfer of tokenTransfers) {
      if (!transfer?.to || !transfer?.from || !transfer?.hash) continue;
      
      // Only check OUTBOUND transfers
      if (transfer.from.toLowerCase() !== userAddress) continue;
      
      const destination = transfer.to.toLowerCase();
      if (flaggedAddresses.has(destination)) continue;
      if (isLegitimateContract(destination)) continue;
      
      const maliciousInfo = isMaliciousAddress(destination, this.chain);
      const isDrainer = isDrainerRecipient(destination);
      
      if (maliciousInfo || isDrainer) {
        flaggedAddresses.add(destination);
        
        // Check for active approvals (same as above)
        const hasActiveApproval = approvalEvents.some(a => 
          a.spender.toLowerCase() === destination &&
          BigInt(a.amount || '0') > BigInt(0)
        );
        
        const isHistorical = !hasActiveApproval;
        const drainerName = maliciousInfo?.name || 'known drainer';
        
        threats.push({
          id: `victim-token-sent-${transfer.hash}`,
          type: 'WALLET_DRAINER',
          severity: isHistorical ? 'LOW' : 'HIGH',
          title: isHistorical 
            ? `ℹ️ Historical Token Transfer to ${drainerName}`
            : `⚠️ Tokens Sent to Active Malicious Address`,
          description: isHistorical
            ? `${transfer.tokenSymbol} tokens were previously sent to ${drainerName}. No active approvals remain – this is historical exposure.`
            : `${transfer.tokenSymbol} tokens were sent to ${drainerName}. Active approvals may still exist – review immediately.`,
          technicalDetails: `Destination: ${destination}\nToken: ${transfer.tokenSymbol}\nStatus: ${isHistorical ? 'HISTORICAL' : 'ACTIVE RISK'}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: [transfer.hash],
          ongoingRisk: !isHistorical,
          category: isHistorical ? 'HISTORICAL_EXPOSURE' : 'ACTIVE_RISK',
          isHistorical,
          displayLabel: isHistorical ? 'Previously sent – no active access' : undefined,
          excludeFromRiskScore: isHistorical,
        });
      }
    }

    // ============================================
    // CASE 3: User RECEIVED from a malicious address
    // ============================================
    // This is DIFFERENT - receiving funds is NOT malicious behavior!
    // Reasons someone might receive from a malicious address:
    // - Refund from a scam they interacted with
    // - Payment from a service (the payer could be compromised)
    // - Airdrop (dust attack - common but not user's fault)
    //
    // We add LOW severity INFO, not a threat
    // WHY: A legitimate service fee receiver gets paid by MANY wallets.
    //      If one of those wallets was compromised, it doesn't make the receiver malicious.
    
    let inboundFromMaliciousCount = 0;
    
    for (const tx of transactions) {
      if (!tx?.to || !tx?.from || !tx?.hash) continue;
      
      // Check INBOUND transactions
      if (tx.to.toLowerCase() !== userAddress) continue;
      
      const sender = tx.from.toLowerCase();
      if (isLegitimateContract(sender)) continue;
      
      const malicious = isMaliciousAddress(sender, this.chain) || isDrainerRecipient(sender);
      if (malicious) {
        inboundFromMaliciousCount++;
      }
    }

    // Only add a LOW severity note if there were inbound txs from malicious addresses
    // This is NOT a threat - just informational
    if (inboundFromMaliciousCount > 0 && inboundFromMaliciousCount <= 3) {
      // Don't add as threat - just note for context
      console.log(`[INFO] Wallet received ${inboundFromMaliciousCount} tx(s) from flagged addresses - NOT flagging as malicious`);
    }

    // ============================================
    // CASE 4: Pattern detection for ATTACKER behavior
    // ============================================
    // Only flag as attacker if there's evidence of malicious INITIATION:
    // - Wallet called approve() on behalf of victim
    // - Wallet used transferFrom() to drain assets
    // - Wallet deployed known drainer bytecode
    //
    // IMPROVED: Now checks contract type to avoid flagging legitimate vaults/aggregators
    
    // Check for transferFrom calls where this wallet was the initiator (potential drainer)
    const transferFromCalls = transactions.filter(tx => {
      if (tx.from.toLowerCase() !== userAddress) return false;
      // transferFrom selector: 0x23b872dd
      return tx.methodId?.startsWith('0x23b872dd');
    });

    // Only flag if threshold exceeded AND it's not a known contract type
    if (transferFromCalls.length >= 10) {
      // ============================================
      // FALSE POSITIVE PREVENTION: Check contract type and verification
      // ============================================
      // WHY: New DEXs, vaults, and aggregators use transferFrom legitimately.
      //      Before flagging, we check:
      //      1. Is it a known legitimate contract type?
      //      2. Is the contract verified on Etherscan?
      //      3. Is it a high-volume neutral address (CEX, LP pool)?
      
      const contractType = await this.getContractType(userAddress);
      const legitimateTypes = ['VAULT', 'DEX_ROUTER', 'DEX_POOL', 'TOKEN', 'MULTISIG', 'NFT_MARKET'];
      
      // Check if it's a high-volume neutral address (CEX, LP pool, etc.)
      const neutralCheck = isHighVolumeNeutralAddress(userAddress);
      
      // Check contract verification status (verified = less suspicious)
      const isVerifiedContract = await this.checkContractVerification(userAddress);
      
      // Skip flagging if:
      // 1. It's a known legitimate type
      // 2. It's a high-volume neutral address
      // 3. It's a verified contract with DEX/vault patterns
      const shouldSkip = 
        legitimateTypes.includes(contractType) ||
        neutralCheck.isNeutral ||
        (isVerifiedContract && ['DEX_ROUTER', 'VAULT', 'TOKEN'].includes(contractType));
      
      if (!shouldSkip) {
        // Additional check: Did all transfers go to the same beneficiary? (drainer pattern)
        const recipients = new Set<string>();
        for (const tx of transferFromCalls) {
          // Extract recipient from transferFrom calldata if possible
          if (tx.input && tx.input.length >= 138) {
            // transferFrom(from, to, amount) - 'to' is at bytes 36-68 (after selector + from)
            const to = '0x' + tx.input.slice(34, 74).toLowerCase();
            recipients.add(to);
          }
        }
        
        // High confidence if single recipient (classic drainer pattern)
        const singleRecipient = recipients.size === 1;
        
        // Additional safety: If verified and multiple recipients, lower severity
        const severity: RiskLevel = singleRecipient 
          ? 'CRITICAL' 
          : (isVerifiedContract ? 'MEDIUM' : 'HIGH');
        
        threats.push({
          id: `potential-drainer-behavior-${Date.now()}`,
          type: 'WALLET_DRAINER',
          severity,
          title: singleRecipient 
            ? '🚨 Drainer Contract Detected'
            : '⚠️ Potential Drainer Behavior Detected',
          description: singleRecipient
            ? `This wallet initiated ${transferFromCalls.length} transferFrom calls, all sending tokens to the same address. This is a strong drainer pattern.`
            : `This wallet initiated ${transferFromCalls.length} transferFrom calls, which is a pattern consistent with drainer contracts pulling tokens from victims.`,
          technicalDetails: `TransferFrom calls: ${transferFromCalls.length}\nUnique recipients: ${recipients.size}\nContract type: ${contractType}\nVerified: ${isVerifiedContract ? 'Yes' : 'No'}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: Array.from(recipients).slice(0, 5),
          relatedTransactions: transferFromCalls.slice(0, 5).map(tx => tx.hash),
          ongoingRisk: true,
        });
      }
    }

    return threats;
  }

  // ============================================
  // CONTRACT TYPE DETECTION (for false positive prevention)
  // ============================================
  
  private async getContractType(address: string): Promise<string> {
    try {
      // First check if it's in our whitelist
      const legitimateLabel = isLegitimateContract(address);
      if (legitimateLabel) {
        const category = getInfrastructureCategory(address);
        if (category) return category;
      }
      
      // Otherwise, analyze bytecode
      const knownMalicious = buildKnownMaliciousSet();
      const analysis = await analyzeContractBytecode(address, this.chain, knownMalicious);
      
      return analysis.contractType || 'UNKNOWN';
    } catch (error) {
      return 'UNKNOWN';
    }
  }
  
  // ============================================
  // CONTRACT VERIFICATION CHECK
  // ============================================
  // WHY: Verified contracts on Etherscan are less suspicious.
  // Drainers typically use unverified contracts to hide their code.
  // If a contract is verified AND has legitimate function signatures,
  // it's much less likely to be a drainer.
  
  private async checkContractVerification(address: string): Promise<boolean> {
    try {
      const apiKey = this.explorerApiKey || '';
      const url = `${this.explorerApiUrl}?module=contract&action=getabi&address=${address}&apikey=${apiKey}`;
      
      const response = await fetch(url, {
        signal: AbortSignal.timeout(5000),
        headers: { 'Accept': 'application/json' },
      });
      
      const data = await response.json();
      
      // Status '1' means ABI is available (contract is verified)
      return data.status === '1';
    } catch (error) {
      // On error, assume not verified (safer default)
      return false;
    }
  }

  // ============================================
  // EXTERNAL THREAT INTELLIGENCE
  // ============================================
  // Checks addresses against external threat feeds (GoPlus Labs)
  // and analyzes bytecode for proxy clones of known drainers.
  // This catches zero-day attacks not in our static database.

  private async checkExternalThreatIntelligence(
    transactions: TransactionData[],
    tokenTransfers: TokenTransfer[],
    userAddress: string
  ): Promise<DetectedThreat[]> {
    const threats: DetectedThreat[] = [];
    const checkedAddresses = new Set<string>();
    const knownMalicious = buildKnownMaliciousSet();
    
    // Get chain ID for API calls
    const chainIdMap: Record<string, number> = {
      ethereum: 1,
      base: 8453,
      bnb: 56,
    };
    const chainId = chainIdMap[this.chain] || 1;
    
    // Collect unique addresses the user interacted with (limit to prevent rate limiting)
    const addressesToCheck: string[] = [];
    
    for (const tx of transactions.slice(0, 50)) {
      if (!tx?.to || !tx?.from) continue;
      
      // Check addresses user SENT to (potential scams they interacted with)
      if (tx.from.toLowerCase() === userAddress && !checkedAddresses.has(tx.to.toLowerCase())) {
        // Skip known legitimate
        if (!isLegitimateContract(tx.to)) {
          addressesToCheck.push(tx.to.toLowerCase());
          checkedAddresses.add(tx.to.toLowerCase());
        }
      }
    }
    
    // Limit API calls (GoPlus free tier: 100/day)
    const maxChecks = Math.min(5, addressesToCheck.length);
    
    for (let i = 0; i < maxChecks; i++) {
      const address = addressesToCheck[i];
      
      try {
        // Run threat checks in parallel
        const [goPlusResult, bytecodeAnalysis] = await Promise.all([
          checkGoPlusAddressSecurity(address, chainId),
          analyzeContractBytecode(address, this.chain, knownMalicious),
        ]);
        
        // GoPlus flagged as malicious
        if (goPlusResult?.isMalicious) {
          threats.push({
            id: `external-intel-goplus-${address.slice(0, 10)}`,
            type: 'WALLET_DRAINER',
            severity: goPlusResult.riskLevel,
            title: `🔍 External Threat Intel: ${goPlusResult.details.split(',')[0]}`,
            description: `GoPlus Labs flagged this address as malicious: ${goPlusResult.details}. You interacted with this address.`,
            technicalDetails: `Address: ${address}\nSource: ${goPlusResult.source}\nConfidence: ${goPlusResult.confidence}%`,
            detectedAt: new Date().toISOString(),
            relatedAddresses: [address],
            relatedTransactions: transactions.filter(tx => tx.to?.toLowerCase() === address).slice(0, 5).map(tx => tx.hash),
            ongoingRisk: true,
          });
        }
        
        // Bytecode analysis: proxy clone of known drainer
        if (bytecodeAnalysis?.implementationIsMalicious) {
          threats.push({
            id: `proxy-clone-${address.slice(0, 10)}`,
            type: 'WALLET_DRAINER',
            severity: 'CRITICAL',
            title: '🚨 Proxy Clone of Known Drainer Detected',
            description: `This contract is a minimal proxy (clone) pointing to a known drainer implementation. This is a common evasion technique.`,
            technicalDetails: `Proxy Address: ${address}\nMalicious Implementation: ${bytecodeAnalysis.proxyImplementation}`,
            detectedAt: new Date().toISOString(),
            relatedAddresses: [address, bytecodeAnalysis.proxyImplementation || ''],
            relatedTransactions: transactions.filter(tx => tx.to?.toLowerCase() === address).slice(0, 5).map(tx => tx.hash),
            ongoingRisk: true,
          });
        }
        
        // Unverified contract with suspicious pattern
        // CRITICAL: Do NOT flag if destination is a trusted category (bridge, exchange, router)
        if (bytecodeAnalysis?.isContract && 
            !bytecodeAnalysis.isVerified && 
            bytecodeAnalysis.contractType === 'UNKNOWN') {
          
          // First check if this is actually a trusted destination
          const infraCheck = checkInfrastructureProtection(address, this.chain);
          if (infraCheck.isProtected) {
            console.log(`[ThreatIntel] ${address} is protected infrastructure (${infraCheck.name}) - skipping unverified warning`);
            continue; // Skip - this is trusted infrastructure
          }
          
          // Check if it's a safe contract, exchange, or router
          if (isSafeContract(address) || isLegitimateContract(address) || 
              isDeFiProtocol(address) || EXCHANGE_HOT_WALLETS.has(address)) {
            console.log(`[ThreatIntel] ${address} is trusted destination - skipping unverified warning`);
            continue; // Skip - trusted destination
          }
          
          // Only flag if BOTH:
          // 1. User sent significant value (> 1 ETH, not 0.1)
          // 2. The destination has NO interaction history with the user
          const sentValue = transactions
            .filter(tx => tx.to?.toLowerCase() === address && tx.from?.toLowerCase() === userAddress)
            .reduce((sum, tx) => sum + BigInt(tx.value || '0'), BigInt(0));
          
          const txCount = transactions.filter(tx => 
            tx.to?.toLowerCase() === address || tx.from?.toLowerCase() === address
          ).length;
          
          // Higher threshold (1 ETH) and only if suspicious patterns exist
          // Single transaction is likely user-initiated, not malicious
          if (sentValue > BigInt('1000000000000000000') && txCount <= 1) { // > 1 ETH AND only 1 tx
            // This is informational, NOT a threat - user sent to unknown contract
            // DO NOT add as threat - this causes false positives
            // Instead, just log it for awareness
            console.log(`[ThreatIntel] ${userAddress} sent ${ethers.formatEther(sentValue)} ETH to unverified contract ${address} - noting for awareness (NOT flagging)`);
            // NOT adding to threats - sending to unverified contract is NOT inherently malicious
          }
        }
      } catch (error) {
        // Continue on error - external APIs may be unavailable
        console.log(`[ThreatIntel] Check failed for ${address}:`, error);
      }
    }
    
    return threats;
  }

  // ============================================
  // DIRECTIONAL ANALYSIS
  // ============================================
  // Analyzes the flow direction to determine wallet's role
  
  private analyzeTransactionDirection(
    transactions: TransactionData[],
    tokenTransfers: TokenTransfer[],
    userAddress: string
  ): DirectionalAnalysis {
    let sentToMaliciousCount = 0;
    let sentToMaliciousValue = BigInt(0);
    let receivedFromMaliciousCount = 0;
    let receivedFromMaliciousValue = BigInt(0);
    const maliciousFunctionsCalled: string[] = [];
    const maliciousApprovals: string[] = [];
    const drainerAddresses: string[] = [];
    
    // Analyze transactions
    for (const tx of transactions) {
      if (!tx?.from || !tx?.to) continue;
      
      const isOutbound = tx.from.toLowerCase() === userAddress;
      const isInbound = tx.to.toLowerCase() === userAddress;
      const counterparty = isOutbound ? tx.to.toLowerCase() : tx.from.toLowerCase();
      
      const isMaliciousCounterparty = isMaliciousAddress(counterparty, this.chain) || isDrainerRecipient(counterparty);
      
      if (isMaliciousCounterparty) {
        if (isOutbound) {
          sentToMaliciousCount++;
          sentToMaliciousValue += BigInt(tx.value || '0');
          
          // Check if it was an approve call
          if (tx.methodId?.startsWith('0x095ea7b3') || tx.methodId?.startsWith('0xa22cb465')) {
            maliciousApprovals.push(counterparty);
          }
        }
        if (isInbound) {
          receivedFromMaliciousCount++;
          receivedFromMaliciousValue += BigInt(tx.value || '0');
        }
      }
    }
    
    // Check for transferFrom drains (someone else initiated transfer FROM this wallet)
    for (const transfer of tokenTransfers) {
      if (!transfer?.from || !transfer?.to) continue;
      
      // If tokens left this wallet but the wallet didn't initiate the tx
      if (transfer.from.toLowerCase() === userAddress) {
        const destination = transfer.to.toLowerCase();
        const isMaliciousDest = isMaliciousAddress(destination, this.chain) || isDrainerRecipient(destination);
        if (isMaliciousDest && !drainerAddresses.includes(destination)) {
          drainerAddresses.push(destination);
        }
      }
    }
    
    // Determine wallet role based on evidence
    let walletRole: WalletRole = 'UNKNOWN';
    let roleConfidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    
    // Check if this is an infrastructure contract
    if (isLegitimateContract(userAddress)) {
      walletRole = 'INFRASTRUCTURE';
      roleConfidence = 'HIGH';
    }
    // Check if wallet was drained (victim)
    else if (drainerAddresses.length > 0 || (sentToMaliciousCount > 0 && maliciousApprovals.length > 0)) {
      walletRole = 'VICTIM';
      roleConfidence = sentToMaliciousCount >= 2 ? 'HIGH' : 'MEDIUM';
    }
    // Check if wallet only received from malicious (indirect exposure, NOT malicious)
    else if (receivedFromMaliciousCount > 0 && sentToMaliciousCount === 0) {
      walletRole = 'SERVICE_RECEIVER'; // Could be legitimate fee receiver
      roleConfidence = 'MEDIUM';
    }
    // Mixed interactions
    else if (sentToMaliciousCount > 0) {
      walletRole = 'VICTIM'; // Sent to scam = victim
      roleConfidence = 'MEDIUM';
    }
    
    return {
      sentToMalicious: sentToMaliciousCount > 0,
      sentToMaliciousCount,
      sentToMaliciousValue: sentToMaliciousValue.toString(),
      receivedFromMalicious: receivedFromMaliciousCount > 0,
      receivedFromMaliciousCount,
      receivedFromMaliciousValue: receivedFromMaliciousValue.toString(),
      calledMaliciousFunction: maliciousFunctionsCalled.length > 0,
      maliciousFunctionsCalled,
      approvedMaliciousSpender: maliciousApprovals.length > 0,
      maliciousApprovals,
      drainedViaTransferFrom: drainerAddresses.length > 0,
      drainerAddresses,
      walletRole,
      roleConfidence,
    };
  }

  // ============================================
  // WALLET CLASSIFICATION (Critical for False Positive Prevention)
  // ============================================
  // 
  // RULE 1: Receiving funds from compromised wallets ≠ being malicious
  // RULE 2: Interacting with same contracts as victims ≠ guilt
  // RULE 3: High-volume receivers (service fees) are neutral
  // RULE 4: Only ACTIVE malicious behavior = malicious classification
  
  private buildWalletClassification(
    directionalAnalysis: DirectionalAnalysis,
    threats: DetectedThreat[],
    userAddress: string,
    transactions: TransactionData[]
  ): import('@/types').WalletClassification {
    const evidence: import('@/types').ClassificationEvidence[] = [];
    
    // Check if this is an infrastructure contract (OpenSea, Uniswap, etc.)
    // WHY: These contracts interact with millions of wallets, including compromised ones.
    //      They should NEVER be flagged as malicious due to association.
    const isInfrastructure = isLegitimateContract(userAddress);
    if (isInfrastructure) {
      evidence.push({
        type: 'INFRASTRUCTURE_USAGE',
        description: `This is a known infrastructure contract: ${isInfrastructure}`,
        weight: 'HIGH',
      });
      
      return {
        role: 'INFRASTRUCTURE',
        confidence: 'HIGH',
        evidence,
        isMalicious: false,
        isInfrastructure: true,
        isServiceFeeReceiver: false,
      };
    }
    
    // Check for service fee receiver pattern
    // WHY: A wallet that receives small amounts from many different wallets is likely
    //      a legitimate service (20% fee receiver, treasury, etc.), NOT a drainer.
    //      Even if some of those sending wallets were later compromised, this doesn't
    //      make the receiver malicious.
    const isServiceFeeReceiver = this.detectServiceFeePattern(transactions, userAddress);
    if (isServiceFeeReceiver && !directionalAnalysis.sentToMalicious) {
      evidence.push({
        type: 'HIGH_VOLUME_RECEIVER',
        description: 'Receives payments from many unique wallets without initiating drains',
        weight: 'HIGH',
      });
      
      // Additional check: Did this wallet initiate any malicious activity?
      const initiatedDrains = threats.some(t => 
        t.title?.includes('Drainer Behavior') || 
        t.title?.includes('Drainer Contract')
      );
      
      if (!initiatedDrains) {
        return {
          role: 'SERVICE_RECEIVER',
          confidence: directionalAnalysis.receivedFromMaliciousCount > 5 ? 'HIGH' : 'MEDIUM',
          evidence,
          isMalicious: false,
          isInfrastructure: false,
          isServiceFeeReceiver: true,
        };
      }
    }
    
    // Check for ATTACKER behavior (initiated drains)
    // WHY: Only classify as attacker if there's evidence of ACTIVE malicious behavior:
    //      - Called transferFrom to pull tokens from victims
    //      - Deployed drainer contracts
    //      - All drained funds went to this wallet
    const hasDrainerBehavior = threats.some(t => 
      t.title?.includes('Drainer Behavior') || 
      t.title?.includes('Drainer Contract Detected')
    );
    
    if (hasDrainerBehavior) {
      evidence.push({
        type: 'INITIATED_DRAIN',
        description: 'This wallet initiated transferFrom calls consistent with drainer behavior',
        weight: 'HIGH',
        transactions: threats.filter(t => t.title?.includes('Drainer')).flatMap(t => t.relatedTransactions),
      });
      
      return {
        role: 'ATTACKER',
        confidence: 'HIGH',
        evidence,
        isMalicious: true,
        isInfrastructure: false,
        isServiceFeeReceiver: false,
      };
    }
    
    // Check for VICTIM behavior (was drained or sent to malicious)
    // WHY: Users who SENT to drainers or APPROVED malicious spenders are victims, not attackers.
    if (directionalAnalysis.drainedViaTransferFrom || 
        directionalAnalysis.sentToMalicious ||
        directionalAnalysis.approvedMaliciousSpender) {
      
      if (directionalAnalysis.drainedViaTransferFrom) {
        evidence.push({
          type: 'OUTBOUND_TO_DRAINER',
          description: 'Assets were drained from this wallet via transferFrom',
          weight: 'HIGH',
          addresses: directionalAnalysis.drainerAddresses,
        });
      }
      
      if (directionalAnalysis.approvedMaliciousSpender) {
        evidence.push({
          type: 'APPROVED_MALICIOUS',
          description: 'Approved a malicious spender (victim of phishing)',
          weight: 'HIGH',
          addresses: directionalAnalysis.maliciousApprovals,
        });
      }
      
      return {
        role: 'VICTIM',
        confidence: directionalAnalysis.drainedViaTransferFrom ? 'HIGH' : 'MEDIUM',
        evidence,
        isMalicious: false,  // CRITICAL: Victims are NOT malicious
        isInfrastructure: false,
        isServiceFeeReceiver: false,
      };
    }
    
    // Check for INDIRECT EXPOSURE (only received from malicious, no other involvement)
    // WHY: Receiving funds from a compromised wallet is NOT malicious behavior.
    //      The sender could be:
    //      - A refund from a service
    //      - A payment from a customer (who happened to be compromised)
    //      - An airdrop/dust attack
    //      None of these make the receiver malicious.
    if (directionalAnalysis.receivedFromMalicious && !directionalAnalysis.sentToMalicious) {
      // ============================================
      // DUST ATTACK SUPPRESSION
      // ============================================
      // WHY: Dust attacks are unsolicited tiny transfers from attackers.
      // They're common and not the user's fault. We suppress warnings for:
      // - Low count (< 3 transactions)
      // - Low total value
      const isDustAttack = directionalAnalysis.receivedFromMaliciousCount <= 2;
      const receivedValue = BigInt(directionalAnalysis.receivedFromMaliciousValue || '0');
      const isLowValue = receivedValue < BigInt('10000000000000000'); // < 0.01 ETH
      
      if (isDustAttack && isLowValue) {
        // Suppress warning for dust attacks - treat as UNKNOWN (safe)
        evidence.push({
          type: 'INBOUND_FROM_DRAINER',
          description: 'Received small/unsolicited transfer from flagged address (dust attack) - this is common and NOT your fault',
          weight: 'LOW',
        });
        
        return {
          role: 'UNKNOWN',  // Treat as normal user, not even INDIRECT_EXPOSURE
          confidence: 'HIGH',
          evidence,
          isMalicious: false,
          isInfrastructure: false,
          isServiceFeeReceiver: false,
        };
      }
      
      evidence.push({
        type: 'INBOUND_FROM_DRAINER',
        description: `Received ${directionalAnalysis.receivedFromMaliciousCount} transaction(s) from flagged addresses - NOT indicative of malicious behavior`,
        weight: 'LOW',  // LOW weight because this is NOT malicious
      });
      
      return {
        role: 'INDIRECT_EXPOSURE',
        confidence: 'MEDIUM',
        evidence,
        isMalicious: false,  // CRITICAL: Receiving funds ≠ malicious
        isInfrastructure: false,
        isServiceFeeReceiver: false,
      };
    }
    
    // No significant malicious indicators
    if (threats.length === 0) {
      evidence.push({
        type: 'NORMAL_ACTIVITY',
        description: 'No malicious activity detected',
        weight: 'HIGH',
      });
      
      return {
        role: 'UNKNOWN',  // Unknown in this context means "normal user"
        confidence: 'HIGH',
        evidence,
        isMalicious: false,
        isInfrastructure: false,
        isServiceFeeReceiver: false,
      };
    }
    
    // Default: Unknown role with whatever threats were detected
    return {
      role: 'UNKNOWN',
      confidence: 'LOW',
      evidence,
      isMalicious: false,
      isInfrastructure: false,
      isServiceFeeReceiver: false,
    };
  }
  
  // ============================================
  // SERVICE FEE RECEIVER DETECTION
  // ============================================
  // Detects wallets that receive fees from many unique senders.
  // These are NOT malicious - they are legitimate service receivers.
  
  private detectServiceFeePattern(
    transactions: TransactionData[],
    userAddress: string
  ): boolean {
    // Count unique senders
    const uniqueSenders = new Set<string>();
    let totalReceived = 0;
    
    for (const tx of transactions) {
      if (!tx?.to || !tx?.from) continue;
      
      // Only look at incoming transactions
      if (tx.to.toLowerCase() !== userAddress) continue;
      
      uniqueSenders.add(tx.from.toLowerCase());
      totalReceived++;
    }
    
    // SERVICE FEE PATTERN:
    // - Receives from 10+ unique addresses
    // - More incoming than outgoing (receiver, not sender)
    // - No signs of drainer behavior
    //
    // WHY: A drainer typically RECEIVES from victims via transferFrom (not direct send)
    //      and then sends to consolidation wallets. A fee receiver gets direct payments
    //      from many unique senders.
    
    const incomingRatio = totalReceived / Math.max(transactions.length, 1);
    
    return uniqueSenders.size >= 10 && incomingRatio >= 0.3;
  }
  
  // ============================================
  // RISK LEVEL DETERMINATION
  // ============================================
  
  private determineRiskLevel(riskScore: number, threats: DetectedThreat[]): RiskLevel {
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    
    // ============================================
    // ONLY COUNT ACTIVE THREATS (exclude historical/resolved)
    // ============================================
    const activeThreats = safeThreats.filter(t => 
      !t.excludeFromRiskScore && 
      !t.isHistorical && 
      t.category !== 'HISTORICAL_EXPOSURE' && 
      t.category !== 'RESOLVED' &&
      !t.approvalRevoked
    );
    
    // Check for critical ACTIVE threats only
    const hasCritical = activeThreats.some(t => t?.severity === 'CRITICAL');
    if (hasCritical || riskScore >= 75) return 'CRITICAL';
    
    // Check for high ACTIVE threats
    const hasHigh = activeThreats.some(t => t?.severity === 'HIGH');
    if (hasHigh || riskScore >= 50) return 'HIGH';
    
    // Check for medium threats
    if (riskScore >= 25) return 'MEDIUM';
    
    return 'LOW';
  }
  
  // ============================================
  // CLASSIFICATION REASON (Human-readable)
  // ============================================
  
  private generateClassificationReason(
    classification: import('@/types').WalletClassification,
    directionalAnalysis: DirectionalAnalysis
  ): string {
    switch (classification.role) {
      case 'INFRASTRUCTURE':
        return `This is a known infrastructure contract (${classification.evidence[0]?.description || 'DEX/Bridge/Router'}). It cannot be classified as malicious due to user interactions.`;
        
      case 'SERVICE_RECEIVER':
        return `This wallet receives payments from many unique addresses without initiating any malicious activity. It is classified as a legitimate service fee receiver, not a drainer.`;
        
      case 'ATTACKER':
        return `This wallet shows evidence of initiating drain attacks by calling transferFrom to pull tokens from victim wallets.`;
        
      case 'VICTIM':
        if (directionalAnalysis.drainedViaTransferFrom) {
          return `This wallet was drained via transferFrom by ${directionalAnalysis.drainerAddresses.length} malicious address(es). The owner is a victim, not an attacker.`;
        }
        if (directionalAnalysis.approvedMaliciousSpender) {
          return `This wallet approved a malicious spender, likely due to phishing. The owner is a victim.`;
        }
        return `This wallet sent transactions to known malicious addresses, indicating the owner was likely scammed.`;
        
      case 'INDIRECT_EXPOSURE':
        return `This wallet received ${directionalAnalysis.receivedFromMaliciousCount} transaction(s) from flagged addresses but showed no malicious behavior. Receiving funds is NOT evidence of wrongdoing.`;
        
      default:
        // Check for dust attack suppression
        if (classification.evidence.some(e => e.description?.includes('dust attack'))) {
          return 'This wallet received a small unsolicited transfer from a flagged address (dust attack). This is extremely common and does NOT indicate compromise. No action needed.';
        }
        if (classification.evidence.some(e => e.type === 'NORMAL_ACTIVITY')) {
          return 'No malicious activity detected. This wallet appears to be operating normally.';
        }
        return 'Insufficient data to determine wallet role. No definitive malicious behavior detected.';
    }
  }

  // ============================================
  // DETECTION: APPROVAL ABUSE
  // ============================================
  // CRITICAL UPDATE: Now checks if approvals are still ACTIVE on-chain.
  // Revoked approvals (allowance = 0) are marked as RESOLVED, not active threats.

  private detectApprovalAbuse(
    approvalEvents: ApprovalEvent[],
    tokenTransfers: TokenTransfer[],
    userAddress: string
  ): DetectedThreat[] {
    const threats: DetectedThreat[] = [];
    const processedApprovals = new Set<string>(); // Prevent duplicates

    for (const approval of approvalEvents) {
      if (!approval?.spender) continue;

      const spenderNormalized = approval.spender.toLowerCase();
      const approvalKey = `${approval.token}-${spenderNormalized}`;
      
      // Prevent duplicate detection for same token-spender pair
      if (processedApprovals.has(approvalKey)) continue;
      processedApprovals.add(approvalKey);
      
      // ============================================
      // INFRASTRUCTURE PROTECTION: Skip protected contracts
      // ============================================
      // OpenSea, Uniswap, etc. can NEVER be flagged as malicious spenders.
      const infraCheck = checkInfrastructureProtection(spenderNormalized, this.chain);
      if (infraCheck.isProtected) {
        console.log(`[detectApprovalAbuse] Spender ${spenderNormalized.slice(0, 10)}... is protected infrastructure (${infraCheck.name}) - skipping`);
        continue;
      }
      
      // Secondary check: legitimate contracts
      if (isLegitimateContract(spenderNormalized)) {
        continue;
      }

      const maliciousInfo = isMaliciousAddress(spenderNormalized, this.chain);
      const isDrainer = isDrainerRecipient(spenderNormalized);
      
      if (maliciousInfo || isDrainer) {
        // ============================================
        // CRITICAL: Check if approval is still ACTIVE
        // ============================================
        // Look for a subsequent approval to 0 (revocation) or check current value
        const currentApprovalValue = BigInt(approval.amount || '0');
        const isRevoked = currentApprovalValue === BigInt(0);
        
        // Also check if there's a more recent approval to 0 for this spender
        const laterRevocation = approvalEvents.find(a => 
          a.token.toLowerCase() === approval.token.toLowerCase() &&
          a.spender.toLowerCase() === spenderNormalized &&
          a.blockNumber > approval.blockNumber &&
          BigInt(a.amount || '0') === BigInt(0)
        );
        
        const wasRevoked = isRevoked || !!laterRevocation;
        const drainerName = maliciousInfo?.name || 'known drainer';
        
        if (wasRevoked) {
          // ============================================
          // RESOLVED: Approval was revoked - mark as historical
          // ============================================
          console.log(`[detectApprovalAbuse] Approval to ${drainerName} (${spenderNormalized.slice(0, 10)}...) was REVOKED - marking as resolved`);
          
          threats.push({
            id: `approval-resolved-${approval.transactionHash}`,
            type: 'APPROVAL_HIJACK',
            severity: 'LOW', // Downgraded - no longer an active threat
            title: `✓ Previously Revoked: Approval to ${drainerName}`,
            description: `You previously approved ${drainerName} to spend your ${approval.tokenSymbol || 'tokens'}, but this approval has been revoked. No active risk remains.`,
            technicalDetails: `Spender: ${approval.spender}\nToken: ${approval.token}\nStatus: REVOKED - No active access`,
            detectedAt: new Date().toISOString(),
            relatedAddresses: [approval.spender],
            relatedTransactions: [approval.transactionHash],
            ongoingRisk: false,
            // Historical/Resolved categorization
            category: 'RESOLVED',
            isHistorical: true,
            approvalRevoked: true,
            currentAllowance: '0',
            displayLabel: 'Previously revoked – no active risk',
            excludeFromRiskScore: true, // CRITICAL: Does NOT affect risk score
            remediation: {
              isRemediated: true,
              remediatedAt: laterRevocation ? new Date(laterRevocation.blockNumber * 1000).toISOString() : undefined,
              remediationMethod: 'APPROVAL_REVOKED',
              currentOnChainState: {
                allowance: '0',
                hasAccess: false,
              },
            },
          });
        } else {
          // ============================================
          // ACTIVE THREAT: Approval still exists
          // ============================================
        threats.push({
          id: `approval-abuse-${approval.transactionHash}`,
          type: 'APPROVAL_HIJACK',
          severity: 'CRITICAL',
            title: `⚠️ ACTIVE: Approval to ${drainerName}`,
            description: `You have an ACTIVE approval allowing ${drainerName} to spend your ${approval.tokenSymbol || 'tokens'}. Revoke this approval immediately!`,
            technicalDetails: `Spender: ${approval.spender}\nToken: ${approval.token}\nStatus: ACTIVE - Can drain your tokens`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [approval.spender],
          relatedTransactions: [approval.transactionHash],
          ongoingRisk: true,
            category: 'ACTIVE_RISK',
            isHistorical: false,
            approvalRevoked: false,
            currentAllowance: approval.amount,
            excludeFromRiskScore: false, // This DOES affect risk score
        });
        }
      }
    }

    return threats;
  }

  // ============================================
  // DATA FETCHING
  // ============================================

  private async fetchTransactionHistory(address: string): Promise<TransactionData[]> {
    const sources = [
      () => this.fetchFromBlockscout(address),
      () => this.fetchFromEtherscan(address),
    ];

    for (const fetchFn of sources) {
      try {
        const result = await fetchFn();
        if (result.length > 0) {
          console.log(`[FETCH] Got ${result.length} transactions`);
          return result;
        }
      } catch (error) {
        console.log('[FETCH] Source failed, trying next...');
      }
    }

    console.log('[FETCH] All sources failed for transactions');
    return [];
  }

  private async fetchFromEtherscan(address: string): Promise<TransactionData[]> {
    const url = `${this.explorerApiUrl}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=desc&apikey=${this.explorerApiKey}`;
    
    const response = await fetch(url, { 
      signal: AbortSignal.timeout(15000),
      headers: { 'Accept': 'application/json' }
    });
    
    const data = await response.json();

    if (data.status !== '1' || !Array.isArray(data.result)) {
      throw new Error(data.message || 'API error');
    }

    return data.result.slice(0, 200).filter((tx: any) => tx?.hash).map((tx: any) => ({
      hash: tx.hash,
      from: (tx.from || '').toLowerCase(),
      to: (tx.to || '').toLowerCase(),
      value: tx.value || '0',
      input: tx.input || '0x',
      timestamp: parseInt(tx.timeStamp) || 0,
      blockNumber: parseInt(tx.blockNumber) || 0,
      methodId: (tx.input || '').slice(0, 10) || '0x',
      isError: tx.isError === '1',
      gasUsed: tx.gasUsed,
    }));
  }

  private async fetchFromBlockscout(address: string): Promise<TransactionData[]> {
    let baseUrl = '';
    
    if (this.chain === 'ethereum') {
      baseUrl = 'https://eth.blockscout.com/api/v2';
    } else if (this.chain === 'base') {
      baseUrl = 'https://base.blockscout.com/api/v2';
    } else if (this.chain === 'bnb') {
      baseUrl = 'https://bsc.blockscout.com/api/v2';
    } else {
      throw new Error('Chain not supported');
    }

    const url = `${baseUrl}/addresses/${address}/transactions`;
    console.log(`[FETCH] Trying Blockscout: ${url}`);
    
    const response = await fetch(url, { 
      signal: AbortSignal.timeout(20000),
      headers: { 'Accept': 'application/json', 'User-Agent': 'WalletSentinel/1.0' }
    });
    
    if (!response.ok) throw new Error(`Blockscout error: ${response.status}`);
    
    const data = await response.json();
    console.log(`[FETCH] Blockscout returned ${data.items?.length || 0} items`);

    if (!data.items || !Array.isArray(data.items)) {
      throw new Error('No items');
    }

    return data.items.slice(0, 200).filter((tx: any) => tx?.hash).map((tx: any) => {
      const fromAddr = typeof tx.from === 'object' ? tx.from?.hash : tx.from;
      const toAddr = typeof tx.to === 'object' ? tx.to?.hash : tx.to;
      
      return {
        hash: tx.hash,
        from: (fromAddr || '').toLowerCase(),
        to: (toAddr || '').toLowerCase(),
        value: tx.value || '0',
        input: tx.raw_input || tx.input || '0x',
        timestamp: tx.timestamp ? Math.floor(new Date(tx.timestamp).getTime() / 1000) : 0,
        blockNumber: tx.block_number || tx.block || 0,
        methodId: tx.method || (tx.raw_input?.slice(0, 10) || '0x'),
        isError: tx.status === 'error',
        gasUsed: tx.gas_used?.toString() || '0',
      };
    });
  }

  private async fetchTokenTransfers(address: string): Promise<TokenTransfer[]> {
    const sources = [
      () => this.fetchTokensFromBlockscout(address),
      () => this.fetchTokensFromEtherscan(address),
    ];

    for (const fetchFn of sources) {
      try {
        const result = await fetchFn();
        if (result.length > 0) {
          console.log(`[FETCH] Got ${result.length} token transfers`);
          return result;
        }
      } catch (error) {
        console.log('[FETCH] Token source failed, trying next...');
      }
    }

    console.log('[FETCH] All token sources exhausted');
    return [];
  }

  private async fetchTokensFromEtherscan(address: string): Promise<TokenTransfer[]> {
    const url = `${this.explorerApiUrl}?module=account&action=tokentx&address=${address}&startblock=0&endblock=99999999&sort=desc&apikey=${this.explorerApiKey}`;
    
    const response = await fetch(url, { 
      signal: AbortSignal.timeout(15000),
      headers: { 'Accept': 'application/json' }
    });
    
    const data = await response.json();

    if (data.status !== '1' || !Array.isArray(data.result)) {
      throw new Error('No token transfers');
    }

    return data.result.slice(0, 200).filter((tx: any) => tx?.hash).map((tx: any) => ({
      from: (tx.from || '').toLowerCase(),
      to: (tx.to || '').toLowerCase(),
      value: tx.value || '0',
      hash: tx.hash,
      timestamp: parseInt(tx.timeStamp) || 0,
      tokenSymbol: tx.tokenSymbol || 'UNKNOWN',
      tokenAddress: (tx.contractAddress || '').toLowerCase(),
    }));
  }

  private async fetchTokensFromBlockscout(address: string): Promise<TokenTransfer[]> {
    let baseUrl = '';
    
    if (this.chain === 'ethereum') {
      baseUrl = 'https://eth.blockscout.com/api/v2';
    } else if (this.chain === 'base') {
      baseUrl = 'https://base.blockscout.com/api/v2';
    } else if (this.chain === 'bnb') {
      baseUrl = 'https://bsc.blockscout.com/api/v2';
    } else {
      throw new Error('Chain not supported');
    }

    const url = `${baseUrl}/addresses/${address}/token-transfers`;
    
    const response = await fetch(url, { 
      signal: AbortSignal.timeout(15000),
      headers: { 'Accept': 'application/json', 'User-Agent': 'WalletSentinel/1.0' }
    });
    
    if (!response.ok) throw new Error(`Blockscout error: ${response.status}`);
    
    const data = await response.json();

    if (!data.items || !Array.isArray(data.items)) return [];

    return data.items.slice(0, 200).filter((tx: any) => tx?.tx_hash).map((tx: any) => ({
      from: (tx.from?.hash || '').toLowerCase(),
      to: (tx.to?.hash || '').toLowerCase(),
      value: tx.total?.value || '0',
      hash: tx.tx_hash,
      timestamp: tx.timestamp ? Math.floor(new Date(tx.timestamp).getTime() / 1000) : 0,
      tokenSymbol: tx.token?.symbol || 'UNKNOWN',
      tokenAddress: (tx.token?.address || '').toLowerCase(),
    }));
  }

  private async fetchCurrentBalance(address: string): Promise<string> {
    try {
      let baseUrl = '';
      if (this.chain === 'ethereum') baseUrl = 'https://eth.blockscout.com/api/v2';
      else if (this.chain === 'base') baseUrl = 'https://base.blockscout.com/api/v2';
      else if (this.chain === 'bnb') baseUrl = 'https://bsc.blockscout.com/api/v2';

      if (baseUrl) {
        const response = await fetch(`${baseUrl}/addresses/${address}`, { 
          signal: AbortSignal.timeout(10000),
          headers: { 'Accept': 'application/json', 'User-Agent': 'WalletSentinel/1.0' }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.coin_balance) return data.coin_balance;
        }
      }
    } catch {}

    try {
      const url = `${this.explorerApiUrl}?module=account&action=balance&address=${address}&tag=latest&apikey=${this.explorerApiKey}`;
      const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
      const data = await response.json();
      if (data.status === '1' && data.result) return data.result;
    } catch {}
    
    return '0';
  }

  private async fetchApprovalEvents(address: string): Promise<ApprovalEvent[]> {
    try {
      let baseUrl = '';
      if (this.chain === 'ethereum') baseUrl = 'https://eth.blockscout.com/api/v2';
      else if (this.chain === 'base') baseUrl = 'https://base.blockscout.com/api/v2';
      else if (this.chain === 'bnb') baseUrl = 'https://bsc.blockscout.com/api/v2';

      if (baseUrl) {
        const response = await fetch(`${baseUrl}/addresses/${address}/transactions`, { 
          signal: AbortSignal.timeout(15000),
          headers: { 'Accept': 'application/json', 'User-Agent': 'WalletSentinel/1.0' }
        });
        
        if (response.ok) {
          const data = await response.json();
          const approvals: ApprovalEvent[] = [];
          
          if (data.items && Array.isArray(data.items)) {
            for (const tx of data.items) {
              const input = tx.raw_input || '';
              if (input.startsWith('0x095ea7b3') || input.startsWith('0xa22cb465')) {
                const spender = input.length >= 74 ? '0x' + input.slice(34, 74) : '';
                const toAddr = typeof tx.to === 'object' ? tx.to?.hash : tx.to;
                approvals.push({
                  token: (toAddr || '').toLowerCase(),
                  tokenName: 'Unknown',
                  tokenSymbol: 'UNK',
                  spender: spender.toLowerCase(),
                  owner: address.toLowerCase(),
                  amount: input.length >= 138 ? '0x' + input.slice(74, 138) : '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                  timestamp: tx.timestamp ? Math.floor(new Date(tx.timestamp).getTime() / 1000) : 0,
                  transactionHash: tx.hash,
                  blockNumber: tx.block || 0,
                });
              }
            }
          }
          
          if (approvals.length > 0) return approvals;
        }
      }
    } catch {}

    return [];
  }

  // ============================================
  // APPROVAL ANALYSIS
  // ============================================

  private analyzeApprovals(approvalEvents: ApprovalEvent[]): TokenApproval[] {
    const approvals: TokenApproval[] = [];
    const processed = new Set<string>();

    for (const event of approvalEvents) {
      const key = `${event.token}-${event.spender}`;
      if (processed.has(key)) continue;
      processed.add(key);

      let amount: string;
      try {
        amount = BigInt(event.amount).toString();
        if (amount === '0') continue;
      } catch {
        continue;
      }

      const isUnlimited = isInfiniteApproval(amount);
      const maliciousSpender = isMaliciousAddress(event.spender, this.chain);
      const legitimateSpender = isLegitimateContract(event.spender);
      const drainerRecipient = isDrainerRecipient(event.spender);

      let riskLevel: RiskLevel = 'LOW';
      let riskReason: string | undefined;

      if (maliciousSpender || drainerRecipient) {
        riskLevel = 'CRITICAL';
        riskReason = 'Approved to known malicious address';
      } else if (isUnlimited && !legitimateSpender) {
        riskLevel = 'HIGH';
        riskReason = 'Unlimited approval to unverified contract';
      } else if (isUnlimited) {
        riskLevel = 'MEDIUM';
        riskReason = `Unlimited approval to ${legitimateSpender}`;
      }

      approvals.push({
        id: `approval-${event.transactionHash}-${event.spender}`,
        token: {
          address: event.token,
          symbol: event.tokenSymbol || 'UNK',
          name: event.tokenName || 'Unknown',
          decimals: 18,
          standard: 'ERC20',
          verified: false,
        },
        spender: event.spender,
        spenderLabel: legitimateSpender || maliciousSpender?.name,
        amount,
        isUnlimited,
        riskLevel,
        riskReason,
        grantedAt: new Date(event.timestamp * 1000).toISOString(),
        isMalicious: !!(maliciousSpender || drainerRecipient),
      });
    }

    return approvals.sort((a, b) => {
      const order: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return order[a.riskLevel] - order[b.riskLevel];
    });
  }

  // ============================================
  // WEIGHTED RISK SCORING
  // ============================================
  // 
  // CRITICAL FALSE POSITIVE PREVENTION:
  // - Indirect exposure (interacting with same contracts as compromised wallets) = LOW score
  // - Receiving funds from compromised wallets = MINIMAL score (not malicious behavior)
  // - Only ACTIVE malicious behavior scores HIGH
  //
  // Scoring weights:
  // - Direct malicious call: +40
  // - Sent TO drainer: +35 (victim behavior, needs warning)
  // - Approval to malicious: +30
  // - Drained via transferFrom: +30 (victim)
  // - Received FROM drainer: +5 (NOT malicious - could be refund/airdrop/payment)
  // - Used legitimate DEX: -5 (normal behavior)
  // - Infrastructure contract: 0 (auto-safe)

  private calculateRiskScore(threats: DetectedThreat[], approvals: TokenApproval[]): number {
    const breakdown = this.calculateRiskBreakdown(threats, approvals);
    return breakdown.totalScore;
  }

  private calculateRiskBreakdown(threats: DetectedThreat[], approvals: TokenApproval[]): RiskScoreBreakdown {
    const factors: RiskFactor[] = [];
    let threatScore = 0;
    let behaviorScore = 0;
    let approvalScore = 0;
    let exposureScore = 0;

    // Safe array guards
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];

    // ============================================
    // THREAT SCORING (based on severity and type)
    // ============================================
    // CRITICAL UPDATE: Only count ACTIVE threats toward risk score.
    // Historical/resolved threats are excluded.
    for (const threat of safeThreats) {
      // ============================================
      // SKIP HISTORICAL/RESOLVED THREATS
      // ============================================
      // These events happened in the past and are no longer active risks.
      // They should NOT affect the risk score.
      if (threat.excludeFromRiskScore === true) {
        console.log(`[RiskScore] Excluding "${threat.title}" from risk score (historical/resolved)`);
        continue;
      }
      
      if (threat.isHistorical === true || threat.category === 'HISTORICAL_EXPOSURE' || threat.category === 'RESOLVED') {
        console.log(`[RiskScore] Excluding "${threat.title}" from risk score (category: ${threat.category || 'historical'})`);
        continue;
      }
      
      // Also skip if approval was revoked (current allowance = 0)
      if (threat.approvalRevoked === true || threat.currentAllowance === '0') {
        console.log(`[RiskScore] Excluding "${threat.title}" from risk score (approval revoked)`);
        continue;
      }
      
      let weight = 0;
      let factorType: RiskFactorType = 'INDIRECT_CONTACT';

      // Private key compromise is the most severe
      if (threat.type === 'PRIVATE_KEY_LEAK') {
        weight = 50;
        factorType = 'TIME_CLUSTERED_DRAIN';
        factors.push({
          id: `threat-${threat.id}`,
          type: factorType,
          weight,
          description: threat.title,
          evidence: threat.relatedTransactions,
        });
      }
      // Drainer interaction (user is victim)
      else if (threat.type === 'WALLET_DRAINER') {
        // Check if this is victim behavior vs attacker behavior
        if (threat.title.includes('Potential Drainer Behavior')) {
          weight = 45; // This wallet IS a drainer
          factorType = 'TRANSFERFROM_INITIATED';
        } else {
          // ONLY count if ongoing risk - historical interactions = 0
          weight = threat.ongoingRisk ? 30 : 0; // User is victim but no ongoing risk = 0
          factorType = 'SENT_TO_DRAINER';
        }
        
        // Don't add factor if weight is 0
        if (weight > 0) {
        factors.push({
          id: `threat-${threat.id}`,
          type: factorType,
          weight,
          description: threat.title,
          evidence: threat.relatedTransactions,
        });
        }
      }
      // Approval issues
      else if (threat.type === 'APPROVAL_HIJACK') {
        // ONLY count if ongoing risk (active approval)
        // Revoked approvals = 0 weight
        weight = threat.ongoingRisk ? 35 : 0;
        factorType = 'APPROVAL_TO_MALICIOUS';
        
        if (weight > 0) {
        factors.push({
          id: `threat-${threat.id}`,
          type: factorType,
          weight,
          description: threat.title,
          evidence: threat.relatedAddresses,
        });
        }
      }
      // Other threats
      else {
        switch (threat.severity) {
          case 'CRITICAL': weight = threat.ongoingRisk ? 25 : 15; break;
          case 'HIGH': weight = threat.ongoingRisk ? 15 : 10; break;
          case 'MEDIUM': weight = 8; break;
          case 'LOW': weight = 3; break;
        }
      }

      threatScore += weight;
    }

    // ============================================
    // APPROVAL SCORING
    // ============================================
    for (const approval of safeApprovals) {
      if (approval.isMalicious) {
        approvalScore += 25;
        factors.push({
          id: `approval-${approval.id}`,
          type: 'APPROVAL_TO_MALICIOUS',
          weight: 25,
          description: `Active approval to malicious address: ${approval.spender.slice(0, 10)}...`,
        });
      } else if (approval.riskLevel === 'CRITICAL') {
        approvalScore += 15;
      } else if (approval.riskLevel === 'HIGH') {
        approvalScore += 8;
      }
    }

    // ============================================
    // CALCULATE TOTAL
    // ============================================
    const totalScore = Math.min(100, Math.max(0, threatScore + behaviorScore + approvalScore + exposureScore));

    return {
      threatScore,
      behaviorScore,
      approvalScore,
      exposureScore,
      totalScore,
      factors,
    };
  }

  private determineSecurityStatus(riskScore: number, threats: DetectedThreat[]): SecurityStatus {
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    
    // Check for definitive compromise indicators
    const hasKeyCompromise = safeThreats.some(t => t?.type === 'PRIVATE_KEY_LEAK');
    const hasActiveDrainerBehavior = safeThreats.some(t => 
      t?.type === 'WALLET_DRAINER' && t?.title?.includes('Potential Drainer Behavior')
    );
    const hasCriticalOngoing = safeThreats.some(t => t?.severity === 'CRITICAL' && t?.ongoingRisk);

    // Definitive compromise: key leak, active drainer behavior, or critical ongoing threat
    if (hasKeyCompromise || hasActiveDrainerBehavior || (hasCriticalOngoing && riskScore >= 50)) {
      return 'COMPROMISED';
    }
    
    // At risk: victim of drainer, has risky approvals, or moderate score
    const isVictimOfDrainer = safeThreats.some(t => 
      t?.type === 'WALLET_DRAINER' && !t?.title?.includes('Potential Drainer Behavior')
    );
    
    if (isVictimOfDrainer || riskScore >= 25 || safeThreats.length > 0) {
      return 'AT_RISK';
    }
    
    return 'SAFE';
  }

  // ============================================
  // CONSERVATIVE SECURITY STATUS DETERMINATION
  // ============================================
  // A wallet can only be labeled SAFE if:
  // - No malicious approvals exist
  // - No abnormal execution patterns exist
  // - No attacker-linked addresses have interacted with it
  // - No known post-compromise behaviors are detected
  //
  // If ANY uncertainty exists → POTENTIALLY_COMPROMISED
  
  private determineSecurityStatusConservative(
    riskScore: number,
    threats: DetectedThreat[],
    compromiseAnalysis: CompromiseAnalysisResult
  ): SecurityStatus {
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    
    // ============================================
    // SEPARATE ACTIVE VS HISTORICAL THREATS
    // ============================================
    // CRITICAL: Only ACTIVE threats should affect security status.
    // Historical/resolved threats are informational only.
    const activeThreats = safeThreats.filter(t => 
      !t.excludeFromRiskScore && 
      !t.isHistorical && 
      t.category !== 'HISTORICAL_EXPOSURE' && 
      t.category !== 'RESOLVED' &&
      !t.approvalRevoked
    );
    
    const historicalThreats = safeThreats.filter(t => 
      t.excludeFromRiskScore || 
      t.isHistorical || 
      t.category === 'HISTORICAL_EXPOSURE' || 
      t.category === 'RESOLVED' ||
      t.approvalRevoked
    );
    
    console.log(`[SECURITY] Threats breakdown: ${activeThreats.length} active, ${historicalThreats.length} historical/resolved`);
    
    // ============================================
    // CRITICAL RULE 0: Only ACTIVE CRITICAL threats override everything
    // ============================================
    // If we detected CRITICAL ACTIVE threats (e.g., wallet is a known drainer),
    // that takes absolute priority over compromise analysis
    const criticalActiveThreats = activeThreats.filter(t => t?.severity === 'CRITICAL');
    if (criticalActiveThreats.length > 0) {
      console.log(`[SECURITY] ${criticalActiveThreats.length} CRITICAL ACTIVE threat(s) detected - marking ACTIVELY_COMPROMISED`);
      return 'ACTIVELY_COMPROMISED';
    }
    
    // ============================================
    // RULE: 0 ACTIVE threats + 0 risk score = Check for historical
    // ============================================
    if (activeThreats.length === 0 && riskScore === 0) {
      // If there are historical threats but no active ones, use PREVIOUSLY_COMPROMISED
      if (historicalThreats.length > 0) {
        console.log(`[SECURITY] No active threats but ${historicalThreats.length} historical - marking PREVIOUSLY_COMPROMISED`);
        return 'PREVIOUSLY_COMPROMISED';
      }
      
      // Truly clean - no threats at all
      if (compromiseAnalysis.evidence.length === 0) {
        console.log(`[SECURITY] No threats, no risk score, no evidence - wallet is SAFE`);
        return 'SAFE';
      }
    }
    
    // ============================================
    // RULE 1: Handle new status types from compromise analysis
    // ============================================
    
    // ACTIVELY_COMPROMISED: Ongoing active threat - immediate action required
    if (compromiseAnalysis.securityStatus === 'ACTIVELY_COMPROMISED') {
      console.log(`[SECURITY] Wallet marked ACTIVELY_COMPROMISED: ${compromiseAnalysis.summary}`);
      return 'ACTIVELY_COMPROMISED';
    }
    
    // PREVIOUSLY_COMPROMISED: Historical incident but no active threat
    if (compromiseAnalysis.securityStatus === 'PREVIOUSLY_COMPROMISED') {
      console.log(`[SECURITY] Wallet marked PREVIOUSLY_COMPROMISED: ${compromiseAnalysis.summary}`);
      return 'PREVIOUSLY_COMPROMISED';
    }
    
    // ============================================
    // RULE 2: HIGH severity ACTIVE threats = AT_RISK
    // ============================================
    const highActiveThreats = activeThreats.filter(t => t?.severity === 'HIGH');
    if (highActiveThreats.length > 0) {
      console.log(`[SECURITY] ${highActiveThreats.length} HIGH ACTIVE threat(s) detected - marking AT_RISK`);
      return 'AT_RISK';
    }
    
    // ============================================
    // RULE 3: Compromise analysis takes priority (only for actual risks)
    // ============================================
    if (compromiseAnalysis.securityStatus === 'COMPROMISED') {
      console.log(`[SECURITY] Wallet marked COMPROMISED by compromise analysis: ${compromiseAnalysis.summary}`);
      return 'ACTIVELY_COMPROMISED'; // Map legacy COMPROMISED to ACTIVELY_COMPROMISED
    }
    
    if (compromiseAnalysis.securityStatus === 'AT_RISK') {
      console.log(`[SECURITY] Wallet marked AT_RISK by compromise analysis: ${compromiseAnalysis.summary}`);
      return 'AT_RISK';
    }
    
    // SAFE from compromise analysis - but only if no significant threats exist
    // The compromise analysis has already done all the necessary checks
    if (compromiseAnalysis.securityStatus === 'SAFE') {
      console.log(`[SECURITY] Compromise analysis returned SAFE - trusting that determination`);
      return 'SAFE';
    }
    
    // POTENTIALLY_COMPROMISED requires at least one concrete risk signal
    // Do NOT return this if there are no actual threats
    if (compromiseAnalysis.securityStatus === 'POTENTIALLY_COMPROMISED') {
      // Additional check: only mark POTENTIALLY_COMPROMISED if there's actual evidence
      const hasConcreteEvidence = compromiseAnalysis.evidence.some(e => 
        e.severity === 'HIGH' || e.severity === 'CRITICAL' ||
        (e.severity === 'MEDIUM' && e.confidence >= 70)
      );
      
      if (hasConcreteEvidence) {
        console.log(`[SECURITY] Wallet marked POTENTIALLY_COMPROMISED with concrete evidence: ${compromiseAnalysis.summary}`);
        return 'POTENTIALLY_COMPROMISED';
      } else {
        // No concrete evidence - treat as SAFE
        console.log(`[SECURITY] Compromise analysis returned POTENTIALLY_COMPROMISED but no concrete evidence found - treating as SAFE`);
        return 'SAFE';
      }
    }
    
    // ============================================
    // FALLBACK RULES: Only apply if compromise analysis didn't give a clear answer
    // ============================================
    
    // If we got here without a clear determination, use threat-based rules
    if (safeThreats.length > 0) {
      const hasCritical = safeThreats.some(t => t?.severity === 'CRITICAL');
      const hasHigh = safeThreats.some(t => t?.severity === 'HIGH');
      
      if (hasCritical) {
        return 'ACTIVELY_COMPROMISED';
      }
      if (hasHigh) {
        return 'AT_RISK';
      }
      // MEDIUM/LOW threats alone = SAFE (they're informational only)
      console.log(`[SECURITY] Only medium/low severity threats found - not blocking SAFE status`);
    }
    
    // If risk score is very high, that's a signal
    if (riskScore >= 50) {
      return 'ACTIVELY_COMPROMISED';
    }
    if (riskScore >= 25) {
      return 'AT_RISK';
    }
    
    // ============================================
    // DEFAULT: No threats, no risks = SAFE
    // ============================================
    console.log(`[SECURITY] No significant threats found - wallet is SAFE`);
    return 'SAFE';
  }

  // ============================================
  // COMPROMISE ANALYSIS INTEGRATION
  // ============================================
  
  private async performCompromiseAnalysis(
    walletAddress: string,
    transactions: TransactionData[],
    approvals: ApprovalEvent[],
    tokenTransfers: TokenTransfer[],
    currentBalance: string
  ): Promise<CompromiseAnalysisResult> {
    // Convert to the format expected by compromise detector
    const txsForAnalysis: TransactionForAnalysis[] = transactions.map(tx => ({
      hash: tx.hash,
      from: tx.from,
      to: tx.to,
      value: tx.value,
      input: tx.input,
      timestamp: tx.timestamp,
      blockNumber: tx.blockNumber,
      methodId: tx.input?.slice(0, 10),
      isError: tx.isError,
      gasUsed: tx.gasUsed,
    }));
    
    const approvalsForAnalysis: ApprovalForAnalysis[] = approvals.map(a => ({
      token: a.token,
      tokenSymbol: a.tokenSymbol || 'Unknown',
      spender: a.spender,
      owner: walletAddress,
      amount: a.amount || '0',
      isUnlimited: BigInt(a.amount || '0') > BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
      timestamp: a.timestamp,
      transactionHash: a.transactionHash || '',
      blockNumber: a.blockNumber,
      spenderIsEOA: !isSafeContract(a.spender.toLowerCase()) && !isDeFiProtocol(a.spender.toLowerCase()),
      spenderIsVerified: !!isSafeContract(a.spender.toLowerCase()) || !!isDeFiProtocol(a.spender.toLowerCase()),
      wasRevoked: false, // ApprovalEvent doesn't have this field
    }));
    
    const transfersForAnalysis: TokenTransferForAnalysis[] = tokenTransfers.map(t => ({
      from: t.from,
      to: t.to,
      value: t.value,
      hash: t.hash,
      timestamp: t.timestamp,
      tokenSymbol: t.tokenSymbol || 'Unknown',
      tokenAddress: t.tokenAddress,
    }));
    
    return analyzeWalletCompromise(
      walletAddress,
      this.chain,
      txsForAnalysis,
      approvalsForAnalysis,
      transfersForAnalysis,
      currentBalance
    );
  }
  
  private mapCompromiseCodeToAttackType(code: string): AttackType {
    const mapping: Record<string, AttackType> = {
      'UNLIMITED_APPROVAL_EOA': 'APPROVAL_HIJACK',
      'UNLIMITED_APPROVAL_UNVERIFIED': 'APPROVAL_HIJACK',
      'APPROVAL_THEN_DRAIN': 'WALLET_DRAINER',
      'POST_INCIDENT_REVOKE': 'WALLET_DRAINER',
      'DRAINER_CLUSTER_INTERACTION': 'WALLET_DRAINER',
      'SHARED_ATTACKER_PATTERN': 'WALLET_DRAINER',
      'SUDDEN_OUTFLOW_POST_APPROVAL': 'WALLET_DRAINER',
      'INACTIVE_PERIOD_DRAIN': 'PRIVATE_KEY_LEAK',
      'MULTI_ASSET_RAPID_DRAIN': 'PRIVATE_KEY_LEAK',
      'ATTACKER_LINKED_ADDRESS': 'WALLET_DRAINER',
      'UNEXPLAINED_ASSET_LOSS': 'WALLET_DRAINER',
      'INDIRECT_DRAINER_EXPOSURE': 'WALLET_DRAINER',
      'SUSPICIOUS_APPROVAL_PATTERN': 'APPROVAL_HIJACK',
      'TIMING_ANOMALY': 'WALLET_DRAINER',
      'UNKNOWN_RECIPIENT_DRAIN': 'WALLET_DRAINER',
    };
    return mapping[code] || 'WALLET_DRAINER';
  }
  
  private getCompromiseThreatTitle(code: string): string {
    const titles: Record<string, string> = {
      'UNLIMITED_APPROVAL_EOA': 'Unlimited Approval to EOA Address',
      'UNLIMITED_APPROVAL_UNVERIFIED': 'Unlimited Approval to Unverified Contract',
      'APPROVAL_THEN_DRAIN': 'Assets Drained After Approval',
      'POST_INCIDENT_REVOKE': 'Post-Incident Approval Revocation',
      'DRAINER_CLUSTER_INTERACTION': 'Interaction with Known Drainer',
      'SHARED_ATTACKER_PATTERN': 'Part of Multi-Victim Attack Pattern',
      'SUDDEN_OUTFLOW_POST_APPROVAL': 'Rapid Asset Outflow After Approval',
      'INACTIVE_PERIOD_DRAIN': 'Activity After Long Inactivity',
      'MULTI_ASSET_RAPID_DRAIN': 'Multiple Assets Drained Rapidly',
      'ATTACKER_LINKED_ADDRESS': 'Interaction with Attacker-Linked Address',
      'UNEXPLAINED_ASSET_LOSS': 'Unexplained Asset Loss Detected',
      'INDIRECT_DRAINER_EXPOSURE': 'Indirect Exposure to Drainer',
      'SUSPICIOUS_APPROVAL_PATTERN': 'Suspicious Approval Pattern',
      'TIMING_ANOMALY': 'Suspicious Timing Anomaly',
      'UNKNOWN_RECIPIENT_DRAIN': 'Funds Sent to Unknown Recipient',
    };
    return titles[code] || 'Compromise Indicator Detected';
  }

  // ============================================
  // OUTPUT GENERATION
  // ============================================

  private buildSuspiciousTransactions(transactions: TransactionData[], threats: DetectedThreat[]): SuspiciousTransaction[] {
    const suspicious: SuspiciousTransaction[] = [];
    
    for (const threat of threats) {
      for (const txHash of threat.relatedTransactions) {
        if (!txHash) continue;
        const tx = transactions.find(t => t?.hash?.toLowerCase() === txHash.toLowerCase());
        if (tx) {
          suspicious.push({
            hash: tx.hash,
            timestamp: new Date(tx.timestamp * 1000).toISOString(),
            type: threat.type,
            from: tx.from,
            to: tx.to,
            value: tx.value,
            riskLevel: threat.severity,
            flags: [threat.title],
            description: threat.description,
          });
        }
      }
    }

    return suspicious;
  }

  private generateSummary(status: SecurityStatus, threats: DetectedThreat[], approvals: TokenApproval[]): string {
    // ============================================
    // SAFE STATUS - Clear positive messaging
    // ============================================
    if (status === 'SAFE') {
      return 'No risk indicators detected. Wallet appears safe based on available data.';
    }
    
    // ============================================
    // PREVIOUSLY_COMPROMISED - Historical incident, no active threat
    // ============================================
    if (status === 'PREVIOUSLY_COMPROMISED') {
      const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
      const historicalCount = safeThreats.filter(t => 
        t.isHistorical || t.category === 'HISTORICAL_EXPOSURE' || t.category === 'RESOLVED'
      ).length;
      const resolvedCount = safeThreats.filter(t => t.category === 'RESOLVED' || t.approvalRevoked).length;
      
      if (resolvedCount > 0) {
        return `Previously at risk. ${resolvedCount} issue(s) have been remediated (approvals revoked). No active malicious access detected. Safe to use with normal caution.`;
      }
      return `Historical exposure detected. ${historicalCount} past interaction(s) with flagged addresses, but no active risk. Approvals have been revoked.`;
    }
    
    // ============================================
    // INCOMPLETE DATA - Only when data is actually missing
    // ============================================
    if (status === 'INCOMPLETE_DATA') {
      return 'Scan incomplete. Some data could not be verified. Try again later.';
    }
    
    // ============================================
    // POTENTIALLY_COMPROMISED - Requires at least one concrete signal
    // ============================================
    if (status === 'POTENTIALLY_COMPROMISED') {
      const safeThreats = Array.isArray(threats) ? threats : [];
      // CRITICAL: If there are 0 indicators, this should NEVER show
      // This is a safety check - the logic should not reach here with 0 threats
      if (safeThreats.length === 0) {
        // This case should not happen - log it and return SAFE message
        console.warn(`[WARNING] POTENTIALLY_COMPROMISED with 0 threats - this should not happen, returning SAFE message`);
        return 'No risk indicators detected. Wallet appears safe based on available data.';
      }
      return `${safeThreats.length} indicator(s) require review. Check the detected issues and take action if needed.`;
    }
    
    if (status === 'AT_RISK') {
      const safeThreats = Array.isArray(threats) ? threats : [];
      return `${safeThreats.length} potential security concern(s) detected. Review the identified risks and consider taking action.`;
    }
    
    // ============================================
    // ACTIVELY_COMPROMISED - Ongoing active threat
    // ============================================
    if (status === 'ACTIVELY_COMPROMISED') {
      const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
      const activeThreats = safeThreats.filter(t => !t.isHistorical);
      return `🚨 ACTIVELY COMPROMISED: ${activeThreats.length} active threat(s) detected. Malicious access is still present. Revoke approvals and secure assets IMMEDIATELY.`;
    }
    
    // ============================================
    // COMPROMISED (legacy) - Maps to ACTIVELY_COMPROMISED
    // ============================================
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const drainerThreats = safeThreats.filter(t => t?.type === 'WALLET_DRAINER' || t?.type === 'PRIVATE_KEY_LEAK');
    if (drainerThreats.length > 0) {
      return `🚨 CRITICAL: This wallet shows signs of compromise. ${drainerThreats.length} drainer/key compromise incident(s) detected. Immediate action required.`;
    }
    return `🚨 CRITICAL: ${safeThreats.length} critical security threat(s) detected. Review immediately.`;
  }

  private generateRecommendations(threats: DetectedThreat[], approvals: TokenApproval[], status: SecurityStatus): SecurityRecommendation[] {
    const recommendations: SecurityRecommendation[] = [];
    
    // Safe array guards
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];

    const maliciousApprovals = safeApprovals.filter(a => a?.isMalicious);
    if (maliciousApprovals.length > 0) {
      recommendations.push({
        id: 'revoke-malicious',
        priority: 'CRITICAL',
        category: 'IMMEDIATE',
        title: 'Revoke Malicious Approvals IMMEDIATELY',
        description: `You have ${maliciousApprovals.length} approval(s) to known malicious contracts.`,
        actionable: true,
        actionType: 'REVOKE_APPROVAL',
      });
    }

    if (safeThreats.some(t => t?.type === 'WALLET_DRAINER' || t?.type === 'PRIVATE_KEY_LEAK')) {
      recommendations.push({
        id: 'move-assets',
        priority: 'CRITICAL',
        category: 'IMMEDIATE',
        title: 'Transfer Remaining Assets to Fresh Wallet',
        description: 'This wallet may be compromised. Move any remaining assets to a NEW wallet immediately.',
        actionable: true,
        actionType: 'TRANSFER_ASSETS',
      });
    }

    recommendations.push({
      id: 'regular-audit',
      priority: 'LOW',
      category: 'LONG_TERM',
      title: 'Regular Security Audits',
      description: 'Review your wallet approvals and transactions regularly.',
      actionable: false,
    });

    return recommendations;
  }

  private generateRecoveryPlan(threats: DetectedThreat[], approvals: TokenApproval[]): RecoveryPlan {
    const steps: RecoveryStep[] = [];
    let order = 1;
    
    // Safe array guards
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];

    const maliciousApprovals = safeApprovals.filter(a => a?.isMalicious);
    if (maliciousApprovals.length > 0) {
      steps.push({
        order: order++,
        title: 'Revoke Malicious Approvals',
        description: `Immediately revoke ${maliciousApprovals.length} approval(s) to known malicious contracts.`,
        action: { type: 'REVOKE_APPROVAL' },
        priority: 'IMMEDIATE',
      });
    }

    const isCompromised = safeThreats.some(t => t?.type === 'WALLET_DRAINER' || t?.type === 'PRIVATE_KEY_LEAK' || (t?.severity === 'CRITICAL' && t?.ongoingRisk));

    if (isCompromised) {
      steps.push({
        order: order++,
        title: 'Transfer All Remaining Assets',
        description: 'Move ALL remaining assets to a new wallet with a fresh seed phrase.',
        action: { type: 'TRANSFER_ASSETS' },
        priority: 'IMMEDIATE',
      });
      steps.push({
        order: order++,
        title: 'Create New Secure Wallet',
        description: 'Generate a completely new wallet. NEVER reuse the old seed phrase.',
        action: { type: 'MANUAL' },
        priority: 'HIGH',
      });
    }

    return {
      urgencyLevel: isCompromised ? 'CRITICAL' : 'HIGH',
      estimatedTimeMinutes: steps.length * 5,
      steps,
      warnings: [
        'Never share your seed phrase with anyone',
        'Verify all transaction details before signing',
        'Be cautious of "recovery services" - they are often scams',
      ],
      safeWalletRequired: isCompromised,
    };
  }

  private generateEducationalContent(threats: DetectedThreat[]) {
    // Safe array guard
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    
    const primaryType = safeThreats[0]?.type || 'UNKNOWN';
    const hasSweeperBot = safeThreats.some(t => t?.attackerInfo?.type === 'SWEEPER_BOT');

    const explanations: Record<string, any> = {
      WALLET_DRAINER: {
        whatHappened: 'Your wallet was targeted by a wallet drainer - malicious software designed to steal cryptocurrency.',
        howItWorks: 'Drainers work by tricking you into signing malicious transactions or approvals, then using those permissions to transfer your assets.',
        ongoingDamage: 'If the attacker has your private key, they can drain any new funds deposited.',
        recoverableInfo: 'Assets already stolen cannot be recovered. Focus on protecting remaining assets.',
      },
      PRIVATE_KEY_LEAK: hasSweeperBot ? {
        whatHappened: '🚨 SWEEPER BOT DETECTED: Your private key is compromised and an automated bot is monitoring your wallet 24/7.',
        howItWorks: 'The attacker runs a program that watches your wallet for incoming funds. Within seconds of any deposit, their bot automatically creates and signs a transaction to steal the funds. Because they have your private key, there is NO WAY to stop this.',
        ongoingDamage: 'ANY funds sent to this wallet will be stolen within seconds. The bot never sleeps - it monitors continuously.',
        recoverableInfo: 'This wallet is PERMANENTLY COMPROMISED and cannot be recovered. You MUST abandon it and create a completely new wallet with a fresh seed phrase. Never use or deposit to this address again.',
      } : {
        whatHappened: 'Your private key or seed phrase was likely compromised, giving the attacker full control.',
        howItWorks: 'Key leaks happen through phishing, malware, fake wallet apps, or accidentally exposing your key.',
        ongoingDamage: 'The attacker has COMPLETE control. Any funds deposited can be stolen instantly.',
        recoverableInfo: 'This wallet is permanently compromised. NEVER use it again.',
      },
      APPROVAL_HIJACK: {
        whatHappened: 'A malicious actor gained permission to spend your tokens through a token approval.',
        howItWorks: 'Attackers create fake dApps that request approvals, then use them to steal assets.',
        ongoingDamage: 'The attacker can drain approved tokens until you revoke the approval.',
        recoverableInfo: 'Revoke the malicious approval immediately.',
      },
    };

    // Special tips for sweeper bot attacks
    const sweeperBotTips = hasSweeperBot ? [
      { title: '🚨 ABANDON THIS WALLET IMMEDIATELY', description: 'Create a new wallet with a fresh seed phrase. This wallet cannot be saved.', importance: 'CRITICAL' as RiskLevel },
      { title: 'Never deposit to this address again', description: 'Any funds sent here will be stolen within seconds by the sweeper bot.', importance: 'CRITICAL' as RiskLevel },
      { title: 'How did this happen?', description: 'Your seed phrase was likely exposed through phishing, malware, fake wallet apps, or unsafe storage. Review your security practices.', importance: 'HIGH' as RiskLevel },
      { title: 'Protect your new wallet', description: 'Use a hardware wallet, never enter your seed phrase online, and verify all websites.', importance: 'HIGH' as RiskLevel },
    ] : [];

    return {
      attackExplanation: explanations[primaryType] || {
        whatHappened: 'Suspicious activity was detected on your wallet.',
        howItWorks: 'The specific attack pattern could not be determined.',
        ongoingDamage: 'Monitor your wallet closely.',
        recoverableInfo: 'Consider moving assets to a fresh wallet.',
      },
      preventionTips: hasSweeperBot ? sweeperBotTips : [
        { title: 'Never share your seed phrase', description: 'No legitimate service will ever ask for it.', importance: 'CRITICAL' as RiskLevel },
        { title: 'Verify before signing', description: 'Read transaction details carefully.', importance: 'HIGH' as RiskLevel },
        { title: 'Use hardware wallets', description: 'Keep high-value assets in cold storage.', importance: 'HIGH' as RiskLevel },
      ],
      securityChecklist: hasSweeperBot ? [
        { id: '1', category: 'URGENT', item: 'Create a new wallet with fresh seed phrase', completed: false },
        { id: '2', category: 'URGENT', item: 'Stop using this compromised wallet', completed: false },
        { id: '3', category: 'URGENT', item: 'Update all accounts that use this address', completed: false },
        { id: '4', category: 'Security', item: 'Use hardware wallet for new wallet', completed: false },
        { id: '5', category: 'Security', item: 'Enable 2FA on all crypto accounts', completed: false },
      ] : [
        { id: '1', category: 'Wallet', item: 'Use hardware wallet', completed: false },
        { id: '2', category: 'Wallet', item: 'Backup seed phrase securely', completed: false },
        { id: '3', category: 'Approvals', item: 'Review approvals regularly', completed: false },
      ],
    };
  }

  generateRevokeTransaction(tokenAddress: string, spenderAddress: string): { to: string; data: string } {
    const iface = new ethers.Interface(['function approve(address spender, uint256 amount)']);
    const data = iface.encodeFunctionData('approve', [spenderAddress, 0]);
    return { to: tokenAddress, data };
  }
}
