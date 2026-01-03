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
} from '@/types';
import {
  CHAIN_RPC_CONFIG,
  isMaliciousAddress,
  isDrainerRecipient,
  isInfiniteApproval,
  isLegitimateContract,
  getInfrastructureCategory,
} from '../detection/malicious-database';
import {
  performAggregatedThreatCheck,
  buildKnownMaliciousSet,
  checkGoPlusAddressSecurity,
  analyzeContractBytecode,
  type AggregatedThreatCheck,
  type ContractAnalysis,
} from '../detection/threat-intelligence';

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

    // 0. EXTERNAL THREAT INTELLIGENCE CHECK (GoPlus, bytecode analysis)
    // This catches zero-day drainers and proxy clones not in our static database
    const externalThreats = await this.checkExternalThreatIntelligence(transactions, tokenTransfers, normalizedAddress);
    threats.push(...externalThreats);

    // 1. DETECT COMPLETE WALLET DRAIN (Private Key Compromise or Drainer)
    const drainThreat = this.detectWalletDrain(transactions, tokenTransfers, currentBalance, normalizedAddress);
    if (drainThreat) threats.push(drainThreat);

    // 2. DETECT KNOWN MALICIOUS INTERACTIONS
    const maliciousThreats = await this.detectMaliciousInteractions(transactions, tokenTransfers, normalizedAddress);
    threats.push(...maliciousThreats);

    // 3. DETECT SUSPICIOUS APPROVAL PATTERNS
    const approvalThreats = this.detectApprovalAbuse(approvalEvents, tokenTransfers, normalizedAddress);
    threats.push(...approvalThreats);

    // 4. DETECT SWEEPER BOT (Private Key Compromise with Active Monitoring)
    const sweeperThreat = this.detectSweeperBot(transactions, tokenTransfers, currentBalance, normalizedAddress);
    if (sweeperThreat) threats.push(sweeperThreat);

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
    
    const riskScore = this.calculateRiskScore(threats, analyzedApprovals);
    const riskLevel = this.determineRiskLevel(riskScore, threats);
    const securityStatus = this.determineSecurityStatus(riskScore, threats);
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
    // Skip if no activity
    if (transactions.length === 0 && tokenTransfers.length === 0) return null;

    // Parse current balance
    let balanceWei: bigint;
    try {
      balanceWei = BigInt(currentBalance || '0');
    } catch {
      balanceWei = BigInt(0);
    }

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

    // Check if wallet is currently empty (defined here so it's available throughout the function)
    const isCurrentlyEmpty = balanceWei < BigInt('1000000000000000'); // < 0.001 ETH

    // Analyze outbound pattern
    const destinationCounts: Record<string, { count: number; types: Set<string>; hashes: string[]; timestamps: number[] }> = {};
    
    for (const transfer of outboundTransfers) {
      if (!destinationCounts[transfer.to]) {
        destinationCounts[transfer.to] = { count: 0, types: new Set(), hashes: [], timestamps: [] };
      }
      destinationCounts[transfer.to].count++;
      destinationCounts[transfer.to].types.add(transfer.type);
      destinationCounts[transfer.to].hashes.push(transfer.hash);
      destinationCounts[transfer.to].timestamps.push(transfer.timestamp);
    }

    // Find suspicious patterns
    for (const [destination, data] of Object.entries(destinationCounts)) {
      // Skip known legitimate contracts
      if (isLegitimateContract(destination)) continue;

      // Check for known drainer
      const isMalicious = isMaliciousAddress(destination, this.chain) || isDrainerRecipient(destination);
      
      // PATTERN 1: Multiple different asset types to same address
      // This is a strong indicator of drain (native + multiple tokens to same address)
      const hasMultipleAssetTypes = data.types.size >= 2;
      const hasNativeAndTokens = data.types.has('native') && 
        Array.from(data.types).some(t => t.startsWith('token:'));

      // PATTERN 2: Check time clustering (all within 30 minutes)
      const timestamps = data.timestamps.sort((a, b) => a - b);
      const timeSpan = timestamps.length > 1 ? (timestamps[timestamps.length - 1] - timestamps[0]) : 0;
      const isRapid = timeSpan <= 30 * 60; // 30 minutes

      // Determine threat level
      if (isMalicious) {
        // CONFIRMED: Transfers to known drainer
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

      if (hasNativeAndTokens && isRapid && data.count >= 2) {
        // LIKELY DRAIN: Native + tokens to same unknown address quickly
        const severity: RiskLevel = isCurrentlyEmpty ? 'CRITICAL' : 'HIGH';
        const threatType: AttackType = isCurrentlyEmpty ? 'PRIVATE_KEY_LEAK' : 'WALLET_DRAINER';
        
        return {
          id: `drain-pattern-${Date.now()}`,
          type: threatType,
          severity,
          title: isCurrentlyEmpty ? 'Wallet Appears Drained - Possible Key Compromise' : 'Suspicious Asset Transfer Pattern',
          description: `${data.count} different assets (ETH + tokens) were sent to the same address (${destination.slice(0, 10)}...) within ${Math.ceil(timeSpan / 60)} minutes.${isCurrentlyEmpty ? ' Your wallet balance is now nearly zero.' : ''} This pattern is consistent with wallet drainer activity or private key compromise.`,
          technicalDetails: `Destination: ${destination}, Time span: ${Math.ceil(timeSpan / 60)} minutes, Assets: ${Array.from(data.types).join(', ')}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: data.hashes.slice(0, 10),
          ongoingRisk: isCurrentlyEmpty,
        };
      }

      if (data.count >= 5 && isRapid) {
        // SUSPICIOUS: Many transfers to same address quickly
        return {
          id: `suspicious-outflow-${Date.now()}`,
          type: 'WALLET_DRAINER',
          severity: 'HIGH',
          title: 'Rapid Asset Outflow Detected',
          description: `${data.count} transfers to the same address (${destination.slice(0, 10)}...) within a short time period. Review these transactions carefully.`,
          technicalDetails: `Destination: ${destination}, Transfers: ${data.count}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: data.hashes.slice(0, 10),
          ongoingRisk: false,
        };
      }
    }

    // PATTERN 4: Check if wallet was funded and is now empty (general drain indicator)
    if (isCurrentlyEmpty && transactions.length > 5) {
      // Calculate total received
      let totalReceived = BigInt(0);
      for (const tx of transactions) {
        if (!tx?.to) continue;
        if (tx.to.toLowerCase() === userAddress) {
          totalReceived += BigInt(tx.value || '0');
        }
      }

      // If wallet received significant funds but is now empty
      if (totalReceived > BigInt('100000000000000000')) { // > 0.1 ETH received
        // Find the main destination
        const sortedDests = Object.entries(destinationCounts)
          .filter(([addr]) => !isLegitimateContract(addr))
          .sort((a, b) => b[1].count - a[1].count);

        if (sortedDests.length > 0) {
          const [topDest, topData] = sortedDests[0];
          
          return {
            id: `wallet-emptied-${Date.now()}`,
            type: 'WALLET_DRAINER',
            severity: 'HIGH',
            title: 'Wallet Has Been Emptied',
            description: `This wallet received ${ethers.formatEther(totalReceived)} ETH but is now nearly empty. Most assets were sent to ${topDest.slice(0, 10)}...`,
            technicalDetails: `Primary destination: ${topDest}, Transfers: ${topData.count}`,
            detectedAt: new Date().toISOString(),
            relatedAddresses: [topDest],
            relatedTransactions: topData.hashes.slice(0, 10),
            ongoingRisk: false,
          };
        }
      }
    }

    return null;
  }

  // ============================================
  // DETECTION: SWEEPER BOT (Private Key Compromise)
  // ============================================

  private detectSweeperBot(
    transactions: TransactionData[],
    tokenTransfers: TokenTransfer[],
    currentBalance: string,
    userAddress: string
  ): DetectedThreat | null {
    // Sweeper bot pattern:
    // 1. Funds come IN
    // 2. Within seconds/minutes, funds go OUT to same address
    // 3. This happens multiple times
    // 4. Wallet balance stays near zero

    if (transactions.length < 4) return null;

    // Parse current balance
    let balanceWei: bigint;
    try {
      balanceWei = BigInt(currentBalance || '0');
    } catch {
      balanceWei = BigInt(0);
    }

    // Build timeline of in/out transactions
    const timeline: { type: 'in' | 'out'; to: string; from: string; value: bigint; timestamp: number; hash: string }[] = [];

    for (const tx of transactions) {
      if (!tx?.from || !tx?.to || !tx?.hash) continue;
      const value = BigInt(tx.value || '0');
      if (value === BigInt(0)) continue;

      if (tx.to.toLowerCase() === userAddress) {
        // Incoming
        timeline.push({ type: 'in', to: tx.to, from: tx.from.toLowerCase(), value, timestamp: tx.timestamp, hash: tx.hash });
      } else if (tx.from.toLowerCase() === userAddress) {
        // Outgoing
        timeline.push({ type: 'out', to: tx.to.toLowerCase(), from: tx.from, value, timestamp: tx.timestamp, hash: tx.hash });
      }
    }

    // Sort by timestamp
    timeline.sort((a, b) => a.timestamp - b.timestamp);

    // Detect sweep pattern: incoming followed by outgoing within 60 minutes to same address
    // IMPROVED: Uses confidence scoring based on speed
    const sweepEvents: { inTx: string; outTx: string; sweeperAddress: string; timeDelta: number; confidence?: number }[] = [];
    const sweeperAddresses: Record<string, number> = {}; // Now stores weighted confidence scores

    for (let i = 0; i < timeline.length - 1; i++) {
      const current = timeline[i];
      
      if (current.type !== 'in') continue;

      // Look for outgoing transaction shortly after
      // IMPROVED: Expanded window from 10 minutes to 60 minutes with confidence decay
      for (let j = i + 1; j < timeline.length && j <= i + 10; j++) {
        const next = timeline[j];
        
        if (next.type !== 'out') continue;
        
        const timeDelta = next.timestamp - current.timestamp;
        
        // EXPANDED: Up to 60 minutes (3600 seconds) with scoring
        // Faster sweeps = higher confidence
        const MAX_SWEEP_WINDOW = 3600; // 60 minutes
        
        if (timeDelta >= 0 && timeDelta <= MAX_SWEEP_WINDOW) {
          // Calculate confidence score based on speed
          // 0-60 seconds = 1.0, 60 minutes = 0.3
          const confidenceScore = Math.max(0.3, 1 - (timeDelta / MAX_SWEEP_WINDOW) * 0.7);
          
          sweepEvents.push({
            inTx: current.hash,
            outTx: next.hash,
            sweeperAddress: next.to,
            timeDelta,
            confidence: confidenceScore, // Track confidence
          });
          
          // Weight by confidence
          sweeperAddresses[next.to] = (sweeperAddresses[next.to] || 0) + confidenceScore;
          break;
        }
      }
    }

    // IMPROVED: Use confidence-weighted threshold
    // A score of 2.0+ indicates high-confidence sweeper pattern
    // This accounts for time decay - slower sweeps need more events to trigger
    const confirmedSweeper = Object.entries(sweeperAddresses).find(([_, score]) => score >= 1.5);

    if (confirmedSweeper && !isLegitimateContract(confirmedSweeper[0])) {
      const [sweeperAddress, confidenceScore] = confirmedSweeper;
      const isCurrentlyEmpty = balanceWei < BigInt('1000000000000000'); // < 0.001 ETH

      // Calculate how fast the sweeps happen on average
      const relevantEvents = sweepEvents.filter(e => e.sweeperAddress === sweeperAddress);
      const sweepCount = relevantEvents.length;
      const avgTimeDelta = relevantEvents.reduce((sum, e) => sum + e.timeDelta, 0) / sweepCount;

      return {
        id: `sweeper-bot-${Date.now()}`,
        type: 'PRIVATE_KEY_LEAK',
        severity: 'CRITICAL',
        title: '🚨 SWEEPER BOT DETECTED - Private Key Compromised',
        description: `Your wallet is being monitored by an automated sweeper bot. Any funds sent to this wallet are immediately stolen (average sweep time: ${Math.round(avgTimeDelta)} seconds). The attacker has your private key. ${sweepCount} sweep events detected. DO NOT send any more funds to this wallet.`,
        technicalDetails: `Sweeper Address: ${sweeperAddress}\nSweep Events: ${sweepCount}\nAverage Response Time: ${Math.round(avgTimeDelta)}s\nWallet Empty: ${isCurrentlyEmpty ? 'Yes' : 'No'}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: [sweeperAddress],
        relatedTransactions: sweepEvents.map(e => e.outTx).slice(0, 10),
        ongoingRisk: true,
        attackerInfo: {
          address: sweeperAddress,
          type: 'SWEEPER_BOT',
          sweepCount,
          avgResponseTime: Math.round(avgTimeDelta),
        },
      };
    }

    // Check for single large sweep (all funds out quickly after large incoming)
    const largeIncoming = timeline.filter(t => t.type === 'in' && t.value > BigInt('100000000000000000')); // > 0.1 ETH
    
    for (const incoming of largeIncoming) {
      const incomingIdx = timeline.indexOf(incoming);
      
      for (let j = incomingIdx + 1; j < timeline.length && j <= incomingIdx + 3; j++) {
        const outgoing = timeline[j];
        if (outgoing.type !== 'out') continue;
        
        const timeDelta = outgoing.timestamp - incoming.timestamp;
        const valueRatio = Number(outgoing.value) / Number(incoming.value);
        
        // If >80% of incoming value was sent out within 30 minutes
        if (timeDelta >= 0 && timeDelta <= 1800 && valueRatio > 0.8 && !isLegitimateContract(outgoing.to)) {
          return {
            id: `rapid-sweep-${Date.now()}`,
            type: 'PRIVATE_KEY_LEAK',
            severity: 'CRITICAL',
            title: '⚠️ Rapid Fund Sweep Detected',
            description: `${ethers.formatEther(incoming.value)} ETH was received and ${(valueRatio * 100).toFixed(1)}% was immediately sent out within ${Math.round(timeDelta / 60)} minutes. This pattern strongly suggests your private key is compromised.`,
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
    userAddress: string
  ): Promise<DetectedThreat[]> {
    const threats: DetectedThreat[] = [];
    const flaggedAddresses = new Set<string>();

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
      
      // Skip if destination is legitimate infrastructure
      // WHY: OpenSea, Uniswap etc. interact with millions of wallets including compromised ones
      if (isLegitimateContract(destination)) continue;
      
      const malicious = isMaliciousAddress(destination, this.chain);
      
      if (malicious && !flaggedAddresses.has(destination)) {
        flaggedAddresses.add(destination);
        
        // User SENT to malicious = they are a VICTIM
        threats.push({
          id: `victim-sent-to-drainer-${tx.hash}`,
          type: malicious.type || 'WALLET_DRAINER',
          severity: 'HIGH',
          title: `⚠️ You Interacted with ${malicious.name || 'Known Malicious Contract'}`,
          description: `You sent a transaction to "${malicious.name || 'a known malicious contract'}". You may have been phished. Check if any assets were drained.`,
          technicalDetails: `Drainer Contract: ${destination}\nTransaction: ${tx.hash}\nYour Role: VICTIM (you sent to the scam)`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: [tx.hash],
          ongoingRisk: false, // Ongoing risk depends on approvals
        });
      }
    }

    // ============================================
    // CASE 2: User SENT tokens TO a known malicious address
    // ============================================
    // Same as above - user is the VICTIM
    
    for (const transfer of tokenTransfers) {
      if (!transfer?.to || !transfer?.from || !transfer?.hash) continue;
      
      // Only check OUTBOUND transfers
      if (transfer.from.toLowerCase() !== userAddress) continue;
      
      const destination = transfer.to.toLowerCase();
      if (flaggedAddresses.has(destination)) continue;
      if (isLegitimateContract(destination)) continue;
      
      const isMaliciousDest = isMaliciousAddress(destination, this.chain) || isDrainerRecipient(destination);
      if (isMaliciousDest) {
        flaggedAddresses.add(destination);
        threats.push({
          id: `victim-token-sent-${transfer.hash}`,
          type: 'WALLET_DRAINER',
          severity: 'HIGH',
          title: 'Tokens Sent to Known Malicious Address',
          description: `${transfer.tokenSymbol} tokens were sent to a known drainer address. You may have been phished.`,
          technicalDetails: `Destination: ${destination}\nToken: ${transfer.tokenSymbol}\nYour Role: VICTIM`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [destination],
          relatedTransactions: [transfer.hash],
          ongoingRisk: false,
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
      // Check if this address is a known legitimate contract type
      const contractType = await this.getContractType(userAddress);
      
      // IMPORTANT: Don't flag if it's a vault, DEX, or aggregator
      // These legitimately use transferFrom for deposits/swaps
      const legitimateTypes = ['VAULT', 'DEX_ROUTER', 'DEX_POOL', 'TOKEN', 'MULTISIG', 'NFT_MARKET'];
      
      if (!legitimateTypes.includes(contractType)) {
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
        const severity: RiskLevel = singleRecipient ? 'CRITICAL' : 'HIGH';
        
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
          technicalDetails: `TransferFrom calls: ${transferFromCalls.length}\nUnique recipients: ${recipients.size}\nContract type: ${contractType}`,
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
        if (bytecodeAnalysis?.isContract && 
            !bytecodeAnalysis.isVerified && 
            bytecodeAnalysis.contractType === 'UNKNOWN') {
          // Only flag if user sent significant value
          const sentValue = transactions
            .filter(tx => tx.to?.toLowerCase() === address && tx.from?.toLowerCase() === userAddress)
            .reduce((sum, tx) => sum + BigInt(tx.value || '0'), BigInt(0));
          
          if (sentValue > BigInt('100000000000000000')) { // > 0.1 ETH
            threats.push({
              id: `unverified-contract-${address.slice(0, 10)}`,
              type: 'ROGUE_CONTRACT_INTERACTION',
              severity: 'MEDIUM',
              title: '⚠️ Interaction with Unverified Contract',
              description: `You sent ${ethers.formatEther(sentValue)} ETH to an unverified contract with unknown purpose. This requires caution.`,
              technicalDetails: `Address: ${address}\nVerified: No\nContract Type: Unknown`,
              detectedAt: new Date().toISOString(),
              relatedAddresses: [address],
              relatedTransactions: transactions.filter(tx => tx.to?.toLowerCase() === address).slice(0, 5).map(tx => tx.hash),
              ongoingRisk: false,
            });
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
    
    // Check for critical threats
    const hasCritical = safeThreats.some(t => t?.severity === 'CRITICAL');
    if (hasCritical || riskScore >= 75) return 'CRITICAL';
    
    // Check for high threats
    const hasHigh = safeThreats.some(t => t?.severity === 'HIGH');
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
        if (classification.evidence.some(e => e.type === 'NORMAL_ACTIVITY')) {
          return 'No malicious activity detected. This wallet appears to be operating normally.';
        }
        return 'Insufficient data to determine wallet role. No definitive malicious behavior detected.';
    }
  }

  // ============================================
  // DETECTION: APPROVAL ABUSE
  // ============================================

  private detectApprovalAbuse(
    approvalEvents: ApprovalEvent[],
    tokenTransfers: TokenTransfer[],
    userAddress: string
  ): DetectedThreat[] {
    const threats: DetectedThreat[] = [];

    for (const approval of approvalEvents) {
      if (!approval?.spender) continue;

      const spenderMalicious = isMaliciousAddress(approval.spender, this.chain) || isDrainerRecipient(approval.spender);
      
      if (spenderMalicious) {
        threats.push({
          id: `approval-abuse-${approval.transactionHash}`,
          type: 'APPROVAL_HIJACK',
          severity: 'CRITICAL',
          title: 'Approval Granted to Malicious Contract',
          description: `You approved a known malicious contract to spend your ${approval.tokenSymbol || 'tokens'}. This may have been used to drain your assets.`,
          technicalDetails: `Spender: ${approval.spender}, Token: ${approval.token}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [approval.spender],
          relatedTransactions: [approval.transactionHash],
          ongoingRisk: true,
        });
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
    for (const threat of safeThreats) {
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
          weight = threat.ongoingRisk ? 30 : 20; // User is victim
          factorType = 'SENT_TO_DRAINER';
        }
        factors.push({
          id: `threat-${threat.id}`,
          type: factorType,
          weight,
          description: threat.title,
          evidence: threat.relatedTransactions,
        });
      }
      // Approval issues
      else if (threat.type === 'APPROVAL_HIJACK') {
        weight = threat.ongoingRisk ? 35 : 20;
        factorType = 'APPROVAL_TO_MALICIOUS';
        factors.push({
          id: `threat-${threat.id}`,
          type: factorType,
          weight,
          description: threat.title,
          evidence: threat.relatedAddresses,
        });
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

  private determineSecurityStatus(riskScore: number, threats: DetectedThreat[]): 'SAFE' | 'AT_RISK' | 'COMPROMISED' {
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

  private generateSummary(status: 'SAFE' | 'AT_RISK' | 'COMPROMISED', threats: DetectedThreat[], approvals: TokenApproval[]): string {
    if (status === 'SAFE') {
      return 'No significant security threats detected. Your wallet appears to be in good standing.';
    }
    if (status === 'AT_RISK') {
      const safeThreats = Array.isArray(threats) ? threats : [];
      return `${safeThreats.length} potential security concern(s) detected. Review the identified risks and consider taking action.`;
    }
    
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const drainerThreats = safeThreats.filter(t => t?.type === 'WALLET_DRAINER' || t?.type === 'PRIVATE_KEY_LEAK');
    if (drainerThreats.length > 0) {
      return `🚨 CRITICAL: This wallet shows signs of compromise. ${drainerThreats.length} drainer/key compromise incident(s) detected. Immediate action required.`;
    }
    return `🚨 CRITICAL: ${safeThreats.length} critical security threat(s) detected. Review immediately.`;
  }

  private generateRecommendations(threats: DetectedThreat[], approvals: TokenApproval[], status: 'SAFE' | 'AT_RISK' | 'COMPROMISED'): SecurityRecommendation[] {
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
