// ============================================
// EVM CHAIN ANALYZER (Ethereum, Base, BNB)
// ============================================
// Enhanced detection for wallet compromise, drainers, and approval abuse.
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
} from '@/types';
import {
  CHAIN_RPC_CONFIG,
  isMaliciousAddress,
  isDrainerRecipient,
  isInfiniteApproval,
  isLegitimateContract,
} from '../detection/malicious-database';

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

    // 1. DETECT COMPLETE WALLET DRAIN (Private Key Compromise or Drainer)
    const drainThreat = this.detectWalletDrain(transactions, tokenTransfers, currentBalance, normalizedAddress);
    if (drainThreat) threats.push(drainThreat);

    // 2. DETECT KNOWN MALICIOUS INTERACTIONS
    const maliciousThreats = this.detectMaliciousInteractions(transactions, tokenTransfers, normalizedAddress);
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

    const riskScore = this.calculateRiskScore(threats, analyzedApprovals);
    const securityStatus = this.determineSecurityStatus(riskScore, threats);
    const suspiciousTransactions = this.buildSuspiciousTransactions(transactions, threats);
    const recommendations = this.generateRecommendations(threats, analyzedApprovals, securityStatus);
    const recoveryPlan = securityStatus !== 'SAFE' ? this.generateRecoveryPlan(threats, analyzedApprovals) : undefined;

    console.log(`[ANALYZE] Completed. Status: ${securityStatus}, Score: ${riskScore}, Threats: ${threats.length}`);

    return {
      address: normalizedAddress,
      chain: this.chain,
      timestamp: new Date().toISOString(),
      securityStatus,
      riskScore,
      summary: this.generateSummary(securityStatus, threats, analyzedApprovals),
      detectedThreats: threats,
      approvals: analyzedApprovals,
      suspiciousTransactions,
      recommendations,
      recoveryPlan,
      educationalContent: this.generateEducationalContent(threats),
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

    // Detect sweep pattern: incoming followed by outgoing within 10 minutes to same address
    const sweepEvents: { inTx: string; outTx: string; sweeperAddress: string; timeDelta: number }[] = [];
    const sweeperAddresses: Record<string, number> = {};

    for (let i = 0; i < timeline.length - 1; i++) {
      const current = timeline[i];
      
      if (current.type !== 'in') continue;

      // Look for outgoing transaction shortly after
      for (let j = i + 1; j < timeline.length && j <= i + 5; j++) {
        const next = timeline[j];
        
        if (next.type !== 'out') continue;
        
        const timeDelta = next.timestamp - current.timestamp;
        
        // If outgoing is within 10 minutes of incoming
        if (timeDelta >= 0 && timeDelta <= 600) {
          sweepEvents.push({
            inTx: current.hash,
            outTx: next.hash,
            sweeperAddress: next.to,
            timeDelta,
          });
          
          sweeperAddresses[next.to] = (sweeperAddresses[next.to] || 0) + 1;
          break;
        }
      }
    }

    // If we found 2+ sweep events to the same address, it's a sweeper bot
    const confirmedSweeper = Object.entries(sweeperAddresses).find(([_, count]) => count >= 2);

    if (confirmedSweeper && !isLegitimateContract(confirmedSweeper[0])) {
      const [sweeperAddress, sweepCount] = confirmedSweeper;
      const isCurrentlyEmpty = balanceWei < BigInt('1000000000000000'); // < 0.001 ETH

      // Calculate how fast the sweeps happen on average
      const avgTimeDelta = sweepEvents
        .filter(e => e.sweeperAddress === sweeperAddress)
        .reduce((sum, e) => sum + e.timeDelta, 0) / sweepCount;

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

  private detectMaliciousInteractions(
    transactions: TransactionData[],
    tokenTransfers: TokenTransfer[],
    userAddress: string
  ): DetectedThreat[] {
    const threats: DetectedThreat[] = [];
    const flaggedAddresses = new Set<string>();

    // Check transactions
    for (const tx of transactions) {
      if (!tx?.to || !tx?.from || !tx?.hash) continue;
      
      const interactedWith = tx.from.toLowerCase() === userAddress ? tx.to : tx.from;
      const malicious = isMaliciousAddress(interactedWith, this.chain);
      
      if (malicious && !flaggedAddresses.has(interactedWith.toLowerCase())) {
        flaggedAddresses.add(interactedWith.toLowerCase());
        threats.push({
          id: `malicious-tx-${tx.hash}`,
          type: malicious.type || 'WALLET_DRAINER',
          severity: 'CRITICAL',
          title: `Interaction with ${malicious.name || 'Known Malicious Contract'}`,
          description: `This wallet interacted with "${malicious.name || 'a known malicious contract'}". This is a confirmed threat.`,
          technicalDetails: `Contract: ${interactedWith}, TX: ${tx.hash}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [interactedWith],
          relatedTransactions: [tx.hash],
          ongoingRisk: true,
        });
      }
    }

    // Check token transfers
    for (const transfer of tokenTransfers) {
      if (!transfer?.to || !transfer?.from || !transfer?.hash) continue;
      
      const destination = transfer.to.toLowerCase();
      if (flaggedAddresses.has(destination)) continue;
      
      if (transfer.from.toLowerCase() === userAddress) {
        const isMalicious = isMaliciousAddress(destination, this.chain) || isDrainerRecipient(destination);
        if (isMalicious) {
          flaggedAddresses.add(destination);
          threats.push({
            id: `malicious-transfer-${transfer.hash}`,
            type: 'WALLET_DRAINER',
            severity: 'CRITICAL',
            title: 'Tokens Sent to Known Malicious Address',
            description: `${transfer.tokenSymbol} tokens were sent to a known drainer address.`,
            technicalDetails: `Destination: ${destination}, Token: ${transfer.tokenSymbol}`,
            detectedAt: new Date().toISOString(),
            relatedAddresses: [destination],
            relatedTransactions: [transfer.hash],
            ongoingRisk: true,
          });
        }
      }
    }

    return threats;
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
  // SCORING & STATUS
  // ============================================

  private calculateRiskScore(threats: DetectedThreat[], approvals: TokenApproval[]): number {
    let score = 0;

    for (const threat of threats) {
      switch (threat.severity) {
        case 'CRITICAL': score += threat.ongoingRisk ? 40 : 25; break;
        case 'HIGH': score += threat.ongoingRisk ? 25 : 15; break;
        case 'MEDIUM': score += 10; break;
        case 'LOW': score += 5; break;
      }
    }

    for (const approval of approvals) {
      if (approval.isMalicious) score += 30;
      else if (approval.riskLevel === 'CRITICAL') score += 20;
      else if (approval.riskLevel === 'HIGH') score += 10;
    }

    return Math.min(100, score);
  }

  private determineSecurityStatus(riskScore: number, threats: DetectedThreat[]): 'SAFE' | 'AT_RISK' | 'COMPROMISED' {
    const hasCritical = threats.some(t => t.severity === 'CRITICAL' && t.ongoingRisk);
    const hasKeyCompromise = threats.some(t => t.type === 'PRIVATE_KEY_LEAK');
    const hasDrainer = threats.some(t => t.type === 'WALLET_DRAINER');

    if (hasCritical || hasKeyCompromise || hasDrainer || riskScore >= 50) {
      return 'COMPROMISED';
    }
    if (riskScore >= 20 || threats.length > 0) {
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
      return `${threats.length} potential security concern(s) detected. Review the identified risks and consider taking action.`;
    }
    
    const drainerThreats = threats.filter(t => t.type === 'WALLET_DRAINER' || t.type === 'PRIVATE_KEY_LEAK');
    if (drainerThreats.length > 0) {
      return `🚨 CRITICAL: This wallet shows signs of compromise. ${drainerThreats.length} drainer/key compromise incident(s) detected. Immediate action required.`;
    }
    return `🚨 CRITICAL: ${threats.length} critical security threat(s) detected. Review immediately.`;
  }

  private generateRecommendations(threats: DetectedThreat[], approvals: TokenApproval[], status: 'SAFE' | 'AT_RISK' | 'COMPROMISED'): SecurityRecommendation[] {
    const recommendations: SecurityRecommendation[] = [];

    const maliciousApprovals = approvals.filter(a => a.isMalicious);
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

    if (threats.some(t => t.type === 'WALLET_DRAINER' || t.type === 'PRIVATE_KEY_LEAK')) {
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

    const maliciousApprovals = approvals.filter(a => a.isMalicious);
    if (maliciousApprovals.length > 0) {
      steps.push({
        order: order++,
        title: 'Revoke Malicious Approvals',
        description: `Immediately revoke ${maliciousApprovals.length} approval(s) to known malicious contracts.`,
        action: { type: 'REVOKE_APPROVAL' },
        priority: 'IMMEDIATE',
      });
    }

    const isCompromised = threats.some(t => t.type === 'WALLET_DRAINER' || t.type === 'PRIVATE_KEY_LEAK' || (t.severity === 'CRITICAL' && t.ongoingRisk));

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
    const primaryType = threats[0]?.type || 'UNKNOWN';
    const hasSweeperBot = threats.some(t => t.attackerInfo?.type === 'SWEEPER_BOT');

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
