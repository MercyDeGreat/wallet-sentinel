// ============================================
// SOLANA CHAIN ANALYZER
// ============================================
// Handles security analysis for Solana blockchain.
// All operations are READ-ONLY.
//
// CRITICAL: Solana compromise detection has LIMITATIONS:
// - Solana compromises are often OFF-CHAIN (phishing, session hijacks)
// - These attacks may NOT leave on-chain artifacts
// - Absence of evidence is NOT proof of safety
// - NEVER mark Solana wallets as "Fully Safe" or "Clean"
//
// THREE EXPLICIT WALLET STATES:
// - SAFE: No historical or active compromise signals
// - PREVIOUSLY_COMPROMISED: No active drain behavior detected, but past incidents exist
// - ACTIVELY_COMPROMISED: Ongoing automated or hostile fund movement
//
// DESIGN PHILOSOPHY: Prefer false negatives over false positives.
// This tool is for protection, not fear amplification.

import {
  Connection,
  PublicKey,
  ParsedTransactionWithMeta,
  ParsedInstruction,
} from '@solana/web3.js';
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
  SecurityStatus,
  ChainAwareSecurityLabel,
  ChainAnalysisMetadata,
  SOLANA_SECURITY_DISCLAIMER,
  CHAIN_ANALYSIS_METADATA,
  SECONDARY_TAGS,
  SecondaryTagInfo,
} from '@/types';
import { CHAIN_RPC_CONFIG, SOLANA_MALICIOUS_PROGRAMS } from '../detection/malicious-database';
import {
  analyzeSolanaSecurity,
  SolanaSecurityResult,
  SolanaSecurityState,
  SolanaTransactionData,
  isWhitelistedProgram,
  getWhitelistCategory,
  DEFAULT_SOLANA_DETECTION_CONFIG,
} from '../detection/solana-security';

// Known Solana program IDs
const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

// Suspicious program patterns
const SUSPICIOUS_PROGRAM_PATTERNS = [
  'drain',
  'claim',
  'airdrop',
  'reward',
];

export class SolanaAnalyzer {
  private connection: Connection;
  private explorerApiUrl: string;

  constructor() {
    const config = CHAIN_RPC_CONFIG.solana;
    // Use the first RPC URL from the array, with fallback
    const rpcUrl = config.rpcUrls?.[0] || 'https://api.mainnet-beta.solana.com';
    this.connection = new Connection(rpcUrl, 'confirmed');
    this.explorerApiUrl = config.explorerApi;
  }

  async analyzeWallet(address: string): Promise<WalletAnalysisResult> {
    // Validate Solana address
    let publicKey: PublicKey;
    try {
      publicKey = new PublicKey(address);
    } catch {
      throw new Error('Invalid Solana address');
    }

    // Fetch data in parallel
    const [transactions, tokenAccounts, balance] = await Promise.all([
      this.fetchTransactionHistory(publicKey),
      this.fetchTokenAccounts(publicKey),
      this.connection.getBalance(publicKey),
    ]);

    // ============================================
    // NEW: Convert to SolanaTransactionData for enhanced detection
    // ============================================
    const solanaTransactions = this.convertToSolanaTransactionData(transactions, address);
    
    // Build set of known malicious addresses
    const knownMaliciousAddresses = new Set(SOLANA_MALICIOUS_PROGRAMS);
    
    // ============================================
    // NEW: Run enhanced Solana security analysis
    // ============================================
    const securityResult = analyzeSolanaSecurity(
      solanaTransactions,
      address,
      knownMaliciousAddresses,
      DEFAULT_SOLANA_DETECTION_CONFIG
    );

    // Analyze threats (combine old and new detection)
    const threats: DetectedThreat[] = [];

    // Check for malicious program interactions
    const maliciousProgramThreats = this.detectMaliciousProgramInteractions(transactions);
    threats.push(...maliciousProgramThreats);

    // Check for delegate abuse
    const delegateThreats = await this.detectDelegateAbuse(tokenAccounts, publicKey);
    threats.push(...delegateThreats);

    // ============================================
    // NEW: Add threats from enhanced drainer/sweeper detection
    // ============================================
    if (securityResult.drainerDetection?.isDrainer) {
      threats.push({
        id: `drainer-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: securityResult.drainerDetection.isActive ? 'CRITICAL' : 'HIGH',
        title: securityResult.drainerDetection.isActive 
          ? 'Active Drainer Behavior Detected' 
          : 'Historical Drainer Activity Detected',
        description: securityResult.drainerDetection.explanation,
        technicalDetails: `Confidence: ${securityResult.drainerDetection.confidence}%, ` +
          `Signals: ${securityResult.drainerDetection.signals.map(s => s.type).join(', ')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: securityResult.drainerDetection.signals
          .flatMap(s => s.relatedAddresses || []),
        relatedTransactions: securityResult.drainerDetection.signals
          .flatMap(s => s.relatedTxSignatures || []),
        ongoingRisk: securityResult.drainerDetection.isActive,
        // NEW: Historical vs Active classification
        category: securityResult.drainerDetection.isActive ? 'ACTIVE_RISK' : 'HISTORICAL_EXPOSURE',
        isHistorical: !securityResult.drainerDetection.isActive,
        excludeFromRiskScore: !securityResult.drainerDetection.isActive,
        displayLabel: securityResult.drainerDetection.isActive 
          ? undefined 
          : 'Historical – no active risk',
      });
    }
    
    if (securityResult.sweeperDetection?.isSweeper) {
      threats.push({
        id: `sweeper-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: securityResult.sweeperDetection.isActive ? 'CRITICAL' : 'HIGH',
        title: securityResult.sweeperDetection.isActive 
          ? 'Active Sweeper Bot Detected' 
          : 'Historical Sweeper Activity Detected',
        description: securityResult.sweeperDetection.explanation,
        technicalDetails: `Confidence: ${securityResult.sweeperDetection.confidence}%, ` +
          `Signals: ${securityResult.sweeperDetection.signals.map(s => s.type).join(', ')}`,
        detectedAt: new Date().toISOString(),
        relatedAddresses: securityResult.sweeperDetection.signals
          .flatMap(s => s.relatedAddresses || []),
        relatedTransactions: securityResult.sweeperDetection.signals
          .flatMap(s => s.relatedTxSignatures || []),
        ongoingRisk: securityResult.sweeperDetection.isActive,
        // NEW: Historical vs Active classification
        category: securityResult.sweeperDetection.isActive ? 'ACTIVE_RISK' : 'HISTORICAL_EXPOSURE',
        isHistorical: !securityResult.sweeperDetection.isActive,
        excludeFromRiskScore: !securityResult.sweeperDetection.isActive,
        displayLabel: securityResult.sweeperDetection.isActive 
          ? undefined 
          : 'Historical – no active risk',
      });
    }

    // Check for suspicious airdrops (only if not already flagged as drainer/sweeper)
    if (!securityResult.drainerDetection?.isDrainer && !securityResult.sweeperDetection?.isSweeper) {
      const airdropThreats = this.detectSuspiciousAirdrops(transactions, address);
      threats.push(...airdropThreats);
    }

    // Analyze token account delegations (similar to EVM approvals)
    const approvals = await this.analyzeTokenDelegations(tokenAccounts, publicKey);

    // ============================================
    // NEW: Use three-state security model
    // ============================================
    const riskScore = securityResult.riskScore;
    const securityStatus = this.determineSecurityStatusFromSolanaResult(securityResult, threats);

    // Generate chain-aware status (Solana-specific with new states)
    const chainAwareStatus = this.generateChainAwareStatusFromSecurityResult(securityResult, threats);
    const analysisMetadata = this.getAnalysisMetadata();

    // Generate suspicious transactions list
    const suspiciousTransactions = this.identifySuspiciousTransactions(transactions, threats);

    // Generate recommendations
    const recommendations = this.generateRecommendations(threats, approvals, securityStatus);

    // Generate recovery plan only for ACTIVE compromise
    const recoveryPlan = securityResult.state === 'ACTIVELY_COMPROMISED'
      ? this.generateRecoveryPlan(threats, approvals)
      : undefined;

    // ============================================
    // NEW: Enhanced classification with three-state model
    // ============================================
    const classification: import('@/types').WalletClassification = {
      role: this.determineWalletRoleFromSecurityResult(securityResult),
      confidence: securityResult.confidence >= 80 ? 'HIGH' : 
                  securityResult.confidence >= 50 ? 'MEDIUM' : 'LOW',
      evidence: this.buildClassificationEvidence(securityResult, threats),
      isMalicious: false, // User wallet is never "malicious" - it's a victim
      isInfrastructure: false,
      isServiceFeeReceiver: false,
    };
    
    // Generate classification reason with explicit historical/active distinction
    const classificationReason = this.generateClassificationReason(securityResult);
    
    const riskLevel: import('@/types').RiskLevel = 
      securityResult.state === 'ACTIVELY_COMPROMISED' ? 'CRITICAL' :
      securityResult.state === 'PREVIOUSLY_COMPROMISED' ? 'MEDIUM' : 'LOW';

    return {
      address,
      chain: 'solana',
      timestamp: new Date().toISOString(),
      
      // Core security assessment
      securityStatus,
      riskScore,
      
      // Chain-aware status (Solana specific with new three-state model)
      chainAwareStatus,
      analysisMetadata,
      chainDisclaimer: SOLANA_SECURITY_DISCLAIMER,
      
      // Classification (prevents false positives)
      classification,
      riskLevel,
      classificationReason,
      
      // Detailed analysis
      summary: this.generateSummaryFromSecurityResult(securityResult, threats, approvals),
      detectedThreats: threats,
      approvals,
      suspiciousTransactions,
      recommendations,
      recoveryPlan,
      educationalContent: this.generateEducationalContent(threats),
    };
  }

  /**
   * Convert ParsedTransactionWithMeta to SolanaTransactionData for enhanced detection.
   */
  private convertToSolanaTransactionData(
    transactions: ParsedTransactionWithMeta[],
    walletAddress: string
  ): SolanaTransactionData[] {
    const normalizedWallet = walletAddress.toLowerCase();
    
    return transactions.map(tx => {
      const signature = tx.transaction.signatures[0];
      const timestamp = tx.blockTime || undefined;
      const slot = tx.slot;
      
      // Get account keys
      const accountKeys = tx.transaction.message.accountKeys || [];
      const fromAddress = accountKeys[0]?.pubkey?.toString?.();
      
      // Determine if inbound/outbound based on balance changes
      const preBalances = tx.meta?.preBalances || [];
      const postBalances = tx.meta?.postBalances || [];
      const isOutbound = preBalances[0] > postBalances[0];
      const isInbound = preBalances[0] < postBalances[0];
      
      // Get program IDs
      const programIds = tx.transaction.message.instructions
        .map(i => i.programId.toString())
        .filter(Boolean);
      
      // Check for memo
      const hasMemo = programIds.some(p => 
        p === 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr' ||
        p === 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo'
      );
      
      // Calculate lamports transferred
      const lamports = Math.abs((postBalances[0] || 0) - (preBalances[0] || 0));
      
      // Detect transfer types
      const isSOLTransfer = lamports > 0 && !programIds.includes('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
      const isSPLTransfer = programIds.includes('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
      const isNFTTransfer = programIds.some(p => 
        p === 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s' ||
        p === 'BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY'
      );
      
      // Get compute units if available
      const computeUnits = tx.meta?.computeUnitsConsumed;
      
      // Determine destination (simplified - second account key if outbound)
      const toAddress = isOutbound && accountKeys.length > 1 
        ? accountKeys[1]?.pubkey?.toString?.() 
        : undefined;
      
      return {
        signature,
        timestamp,
        slot,
        fromAddress,
        toAddress,
        isInbound,
        isOutbound,
        lamports,
        programIds,
        hasMemo,
        computeUnits,
        isNFTTransfer,
        isSPLTransfer,
        isSOLTransfer,
      };
    });
  }

  /**
   * Determine security status from Solana security result.
   */
  private determineSecurityStatusFromSolanaResult(
    result: SolanaSecurityResult,
    threats: DetectedThreat[]
  ): SecurityStatus {
    switch (result.state) {
      case 'ACTIVELY_COMPROMISED':
        return 'COMPROMISED';
      case 'PREVIOUSLY_COMPROMISED':
        return 'PREVIOUSLY_COMPROMISED';
      case 'SAFE':
      default:
        // Even if "SAFE", check for other threats
        if (threats.some(t => t.severity === 'CRITICAL' && t.ongoingRisk)) {
          return 'COMPROMISED';
        }
        if (threats.length > 0) {
          return 'AT_RISK';
        }
        return 'SAFE';
    }
  }

  /**
   * Generate chain-aware status from security result.
   */
  private generateChainAwareStatusFromSecurityResult(
    result: SolanaSecurityResult,
    threats: DetectedThreat[]
  ): ChainAwareSecurityLabel {
    switch (result.state) {
      case 'ACTIVELY_COMPROMISED':
        return {
          status: 'COMPROMISED',
          displayLabel: 'Active Compromise Detected',
          shortLabel: 'ACTIVE THREAT',
          description: result.explanation,
          isDefinitiveSafe: false,
        };
      
      case 'PREVIOUSLY_COMPROMISED':
        return {
          status: 'PREVIOUSLY_COMPROMISED',
          displayLabel: 'Previously Compromised – No Active Risk',
          shortLabel: 'HISTORICAL',
          description: result.explanation,
          disclaimer: 'Historical compromise detected but no current active threat. ' +
                      'If you suspect ongoing issues, treat the wallet as unsafe.',
          isDefinitiveSafe: false,
        };
      
      case 'SAFE':
      default:
        return {
          status: 'NO_ONCHAIN_RISK_DETECTED',
          displayLabel: 'No On-Chain Risk Detected',
          shortLabel: 'NO RISK DETECTED',
          description: 'No detectable on-chain security threats found. ' +
                       'This does NOT guarantee the wallet is safe from all threats.',
          disclaimer: SOLANA_SECURITY_DISCLAIMER,
          isDefinitiveSafe: false, // NEVER true for Solana
          secondaryTags: [SECONDARY_TAGS.HISTORICAL_OFFCHAIN_COMPROMISE_POSSIBLE],
        };
    }
  }

  /**
   * Determine wallet role from security result.
   */
  private determineWalletRoleFromSecurityResult(result: SolanaSecurityResult): import('@/types').WalletRole {
    if (result.state === 'ACTIVELY_COMPROMISED') {
      return 'VICTIM';
    }
    if (result.state === 'PREVIOUSLY_COMPROMISED') {
      return 'VICTIM';
    }
    return 'UNKNOWN';
  }

  /**
   * Build classification evidence from security result.
   */
  private buildClassificationEvidence(
    result: SolanaSecurityResult,
    threats: DetectedThreat[]
  ): import('@/types').ClassificationEvidence[] {
    const evidence: import('@/types').ClassificationEvidence[] = [];
    
    if (result.state === 'SAFE') {
      evidence.push({
        type: 'NORMAL_ACTIVITY',
        description: 'No compromise signals detected',
        weight: 'HIGH',
      });
      
      for (const safe of result.reasoning.safeSignals) {
        evidence.push({
          type: 'NORMAL_ACTIVITY',
          description: safe,
          weight: 'MEDIUM',
        });
      }
    } else {
      for (const signal of result.reasoning.detectedSignals) {
        evidence.push({
          type: signal.type.includes('DRAINER') || signal.type.includes('SWEEPER') 
            ? 'OUTBOUND_TO_DRAINER' 
            : 'UNKNOWN',
          description: signal.description,
          weight: signal.confidence === 'HIGH' ? 'HIGH' : 
                  signal.confidence === 'MEDIUM' ? 'MEDIUM' : 'LOW',
        });
      }
    }
    
    return evidence;
  }

  /**
   * Generate classification reason from security result.
   */
  private generateClassificationReason(result: SolanaSecurityResult): string {
    switch (result.state) {
      case 'ACTIVELY_COMPROMISED':
        return `ACTIVE compromise detected. ${result.signalCount} high-confidence signal(s) identified. ` +
               result.reasoning.stateReason;
      
      case 'PREVIOUSLY_COMPROMISED':
        return `Historical compromise detected but NO ACTIVE RISK. ` +
               `${result.daysSinceLastIncident !== undefined 
                 ? `Last suspicious activity was ${result.daysSinceLastIncident} day(s) ago. ` 
                 : ''}` +
               'No current automated or hostile fund movement observed.';
      
      case 'SAFE':
      default:
        return 'No compromise signals detected on this Solana wallet. ' +
               'Note: Many Solana attacks occur off-chain and may not leave detectable traces. ' +
               'If you suspect compromise, treat the wallet as unsafe.';
    }
  }

  /**
   * Generate summary from security result.
   */
  private generateSummaryFromSecurityResult(
    result: SolanaSecurityResult,
    threats: DetectedThreat[],
    approvals: TokenApproval[]
  ): string {
    switch (result.state) {
      case 'ACTIVELY_COMPROMISED':
        return `URGENT: Active compromise detected on your Solana wallet. ` +
               `${result.signalCount} independent signal(s) identified. ` +
               'Immediate action required: Transfer remaining assets to a fresh wallet.';
      
      case 'PREVIOUSLY_COMPROMISED':
        return `Your Solana wallet shows signs of PREVIOUS compromise, but NO ACTIVE RISK. ` +
               `${result.daysSinceLastIncident !== undefined 
                 ? `Last suspicious activity was ${result.daysSinceLastIncident} day(s) ago. ` 
                 : ''}` +
               'No current automated or hostile fund movement observed. ' +
               'Continue monitoring but no immediate action required.';
      
      case 'SAFE':
      default:
        return 'No detectable on-chain security threats found on your Solana wallet. ' +
               'Note: Many Solana attacks occur off-chain and may not leave on-chain traces. ' +
               'Continue practicing safe wallet hygiene.';
    }
  }

  private async fetchTransactionHistory(publicKey: PublicKey): Promise<ParsedTransactionWithMeta[]> {
    try {
      const signatures = await this.connection.getSignaturesForAddress(publicKey, { limit: 100 });

      const transactions = await Promise.all(
        signatures.slice(0, 50).map(async (sig) => {
          try {
            return await this.connection.getParsedTransaction(sig.signature, {
              maxSupportedTransactionVersion: 0,
            });
          } catch {
            return null;
          }
        })
      );

      return transactions.filter((tx): tx is ParsedTransactionWithMeta => tx !== null);
    } catch (error) {
      console.error('Error fetching Solana transactions:', error);
      return [];
    }
  }

  private async fetchTokenAccounts(publicKey: PublicKey): Promise<any[]> {
    try {
      const tokenAccounts = await this.connection.getParsedTokenAccountsByOwner(publicKey, {
        programId: new PublicKey(TOKEN_PROGRAM_ID),
      });

      return tokenAccounts.value;
    } catch (error) {
      console.error('Error fetching token accounts:', error);
      return [];
    }
  }

  private detectMaliciousProgramInteractions(transactions: ParsedTransactionWithMeta[]): DetectedThreat[] {
    const threats: DetectedThreat[] = [];
    
    // Safe array guard
    const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];

    for (const tx of safeTxs) {
      if (!tx?.transaction?.message?.instructions) continue;

      for (const instruction of tx.transaction.message.instructions) {
        const programId = instruction.programId.toString();

        // Check against known malicious programs
        if (SOLANA_MALICIOUS_PROGRAMS.includes(programId)) {
          threats.push({
            id: `malicious-program-${tx.transaction.signatures[0]}`,
            type: 'COMPROMISED_PROGRAM_AUTHORITY',
            severity: 'CRITICAL',
            title: 'Interaction with Known Malicious Program',
            description: `Transaction interacted with a known malicious Solana program.`,
            technicalDetails: `Program: ${programId}, Signature: ${tx.transaction.signatures[0]}`,
            detectedAt: new Date().toISOString(),
            relatedAddresses: [programId],
            relatedTransactions: [tx.transaction.signatures[0]],
            ongoingRisk: true,
          });
        }
      }
    }

    return threats;
  }

  private async detectDelegateAbuse(tokenAccounts: any[], owner: PublicKey): Promise<DetectedThreat[]> {
    const threats: DetectedThreat[] = [];
    
    // Safe array guard
    const safeAccounts = Array.isArray(tokenAccounts) ? tokenAccounts.filter(a => a != null) : [];

    for (const account of safeAccounts) {
      const info = account.account.data.parsed?.info;
      if (!info) continue;

      // Check if token account has a delegate
      if (info.delegate && info.delegatedAmount) {
        const delegatedAmount = BigInt(info.delegatedAmount.amount || 0);

        if (delegatedAmount > BigInt(0)) {
          // Check if delegate is malicious
          if (SOLANA_MALICIOUS_PROGRAMS.includes(info.delegate)) {
            threats.push({
              id: `delegate-abuse-${account.pubkey.toString()}`,
              type: 'APPROVAL_HIJACK',
              severity: 'CRITICAL',
              title: 'Token Delegated to Malicious Account',
              description: 'A token account has been delegated to a known malicious address.',
              technicalDetails: `Token Account: ${account.pubkey.toString()}, Delegate: ${info.delegate}`,
              detectedAt: new Date().toISOString(),
              relatedAddresses: [info.delegate],
              relatedTransactions: [],
              ongoingRisk: true,
            });
          }
        }
      }
    }

    return threats;
  }

  private detectRapidOutflows(transactions: ParsedTransactionWithMeta[], address: string): DetectedThreat[] {
    const threats: DetectedThreat[] = [];
    
    // Safe array guard
    const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
    if (safeTxs.length === 0) return threats;

    // Group transactions by time window
    const windowMinutes = 10;
    const sortedTxs = [...safeTxs]
      .filter((tx) => tx?.blockTime)
      .sort((a, b) => (a?.blockTime || 0) - (b?.blockTime || 0));

    // Look for multiple outbound transfers in short window
    for (let i = 0; i < sortedTxs.length; i++) {
      const currentTx = sortedTxs[i];
      if (!currentTx) continue;
      
      const windowStart = currentTx.blockTime || 0;
      const windowEnd = windowStart + windowMinutes * 60;

      const txsInWindow = sortedTxs.filter(
        (tx) => tx && (tx.blockTime || 0) >= windowStart && (tx.blockTime || 0) <= windowEnd
      );

      // Count outbound transfers
      let outboundCount = 0;
      for (const tx of txsInWindow) {
        const preBalances = tx.meta?.preBalances || [];
        const postBalances = tx.meta?.postBalances || [];

        // First account is usually the fee payer/signer
        if (preBalances[0] > postBalances[0]) {
          outboundCount++;
        }
      }

      if (outboundCount >= 5) {
        threats.push({
          id: `rapid-outflow-${Date.now()}`,
          type: 'WALLET_DRAINER',
          severity: 'CRITICAL',
          title: 'Rapid Asset Outflow Detected',
          description: `${outboundCount} outbound transactions detected within ${windowMinutes} minutes. This pattern is consistent with wallet drainer activity.`,
          technicalDetails: `Time window: ${new Date(windowStart * 1000).toISOString()}`,
          detectedAt: new Date().toISOString(),
          relatedAddresses: [],
          relatedTransactions: txsInWindow.map((tx) => tx.transaction.signatures[0]),
          ongoingRisk: true,
        });
        break; // Only report once
      }
    }

    return threats;
  }

  private detectSuspiciousAirdrops(transactions: ParsedTransactionWithMeta[], address: string): DetectedThreat[] {
    const threats: DetectedThreat[] = [];

    for (const tx of transactions) {
      if (!tx.transaction?.message?.instructions) continue;

      // Check for unsolicited token transfers to this wallet
      for (const instruction of tx.transaction.message.instructions) {
        if ('parsed' in instruction && instruction.parsed?.type === 'transfer') {
          const info = instruction.parsed.info;

          // If receiving tokens from unknown source with memo
          if (info.destination === address) {
            // Check for suspicious memo
            const memoInstruction = tx.transaction.message.instructions.find(
              (i) => i.programId.toString() === MEMO_PROGRAM_ID
            );

            if (memoInstruction && 'parsed' in memoInstruction) {
              const memoText = String(memoInstruction.parsed || '').toLowerCase();

              if (SUSPICIOUS_PROGRAM_PATTERNS.some((pattern) => memoText.includes(pattern))) {
                threats.push({
                  id: `suspicious-airdrop-${tx.transaction.signatures[0]}`,
                  type: 'MALICIOUS_NFT_AIRDROP',
                  severity: 'MEDIUM',
                  title: 'Suspicious Airdrop Detected',
                  description: 'Received tokens with suspicious memo. This may be a phishing attempt.',
                  technicalDetails: `Signature: ${tx.transaction.signatures[0]}`,
                  detectedAt: new Date().toISOString(),
                  relatedAddresses: [],
                  relatedTransactions: [tx.transaction.signatures[0]],
                  ongoingRisk: false,
                });
              }
            }
          }
        }
      }
    }

    return threats;
  }

  private async analyzeTokenDelegations(tokenAccounts: any[], owner: PublicKey): Promise<TokenApproval[]> {
    const approvals: TokenApproval[] = [];

    for (const account of tokenAccounts) {
      const info = account.account.data.parsed?.info;
      if (!info || !info.delegate) continue;

      const delegatedAmount = BigInt(info.delegatedAmount?.amount || 0);
      if (delegatedAmount === BigInt(0)) continue;

      const isMalicious = SOLANA_MALICIOUS_PROGRAMS.includes(info.delegate);

      approvals.push({
        id: `delegation-${account.pubkey.toString()}`,
        token: {
          address: info.mint,
          symbol: 'SPL',
          name: 'SPL Token',
          decimals: info.tokenAmount?.decimals || 9,
          standard: 'SPL',
          verified: false,
        },
        spender: info.delegate,
        amount: delegatedAmount.toString(),
        isUnlimited: false, // Solana delegations have specific amounts
        riskLevel: isMalicious ? 'CRITICAL' : 'MEDIUM',
        riskReason: isMalicious
          ? 'Delegated to known malicious address'
          : 'Active token delegation',
        grantedAt: new Date().toISOString(),
        isMalicious,
      });
    }

    return approvals;
  }

  private calculateRiskScore(threats: DetectedThreat[], approvals: TokenApproval[]): number {
    let score = 0;
    
    // Safe array guards
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];

    // Critical threats
    score += safeThreats.filter((t) => t?.severity === 'CRITICAL').length * 30;
    // High threats
    score += safeThreats.filter((t) => t?.severity === 'HIGH').length * 20;
    // Medium threats
    score += safeThreats.filter((t) => t?.severity === 'MEDIUM').length * 10;
    // Malicious approvals
    score += safeApprovals.filter((a) => a?.isMalicious).length * 25;
    // Any active delegations
    score += safeApprovals.length * 5;

    return Math.min(100, Math.max(0, score));
  }

  private determineSecurityStatus(riskScore: number, threats: DetectedThreat[]): SecurityStatus {
    // Safe array guard
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const hasCritical = safeThreats.some((t) => t?.severity === 'CRITICAL' && t?.ongoingRisk);

    // IMPORTANT: For Solana, we still return 'SAFE' as the status type,
    // but the UI will display it differently using chainAwareStatus
    if (hasCritical || riskScore >= 70) return 'COMPROMISED';
    if (riskScore >= 30 || safeThreats.length > 0) return 'AT_RISK';
    return 'SAFE';
  }

  /**
   * Generate chain-aware security label for Solana.
   * CRITICAL: Solana should NEVER be labeled as "Fully Safe" or "Clean"
   * because off-chain compromises may not leave on-chain traces.
   */
  private generateChainAwareStatus(
    securityStatus: SecurityStatus,
    threats: DetectedThreat[]
  ): ChainAwareSecurityLabel {
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    
    switch (securityStatus) {
      case 'COMPROMISED':
        return {
          status: 'COMPROMISED',
          displayLabel: 'On-Chain Compromise Detected',
          shortLabel: 'COMPROMISED',
          description: 'Strong on-chain evidence of wallet compromise has been detected.',
          isDefinitiveSafe: false,
        };
      
      case 'AT_RISK':
        return {
          status: 'AT_RISK',
          displayLabel: 'On-Chain Risk Indicators Found',
          shortLabel: 'AT RISK',
          description: `${safeThreats.length} potential on-chain security concern${safeThreats.length !== 1 ? 's' : ''} detected.`,
          disclaimer: SOLANA_SECURITY_DISCLAIMER,
          isDefinitiveSafe: false,
        };
      
      case 'SAFE':
      default:
        // CRITICAL: Solana "SAFE" status must be reframed
        // Absence of on-chain evidence ≠ wallet is safe
        return {
          status: 'NO_ONCHAIN_RISK_DETECTED',
          displayLabel: 'No On-Chain Risk Detected',
          shortLabel: 'NO RISK DETECTED',
          description: 'No detectable on-chain security threats found. ' +
                       'This does NOT guarantee the wallet is safe from all threats.',
          disclaimer: SOLANA_SECURITY_DISCLAIMER,
          isDefinitiveSafe: false, // NEVER true for Solana
          // Secondary tag: Indicate that off-chain compromise is always possible for Solana
          // This does NOT affect risk score - it's purely informational
          secondaryTags: [SECONDARY_TAGS.HISTORICAL_OFFCHAIN_COMPROMISE_POSSIBLE],
        };
    }
  }

  /**
   * Get analysis metadata for Solana chain.
   */
  private getAnalysisMetadata(): ChainAnalysisMetadata {
    return CHAIN_ANALYSIS_METADATA.solana;
  }

  private identifySuspiciousTransactions(
    transactions: ParsedTransactionWithMeta[],
    threats: DetectedThreat[]
  ): SuspiciousTransaction[] {
    // Safe array guards
    const safeTxs = Array.isArray(transactions) ? transactions.filter(tx => tx != null) : [];
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    
    const suspiciousSigs = new Set(safeThreats.flatMap((t) => Array.isArray(t?.relatedTransactions) ? t.relatedTransactions : []));

    return safeTxs
      .filter((tx) => tx?.transaction?.signatures?.[0] && suspiciousSigs.has(tx.transaction.signatures[0]))
      .map((tx) => {
        const sig = tx.transaction.signatures[0];
        const relatedThreat = safeThreats.find((t) =>
          Array.isArray(t?.relatedTransactions) && t.relatedTransactions.includes(sig)
        );

        return {
          hash: sig,
          timestamp: tx.blockTime
            ? new Date(tx.blockTime * 1000).toISOString()
            : new Date().toISOString(),
          type: relatedThreat?.type || 'UNKNOWN',
          from: tx.transaction?.message?.accountKeys?.[0]?.pubkey?.toString?.() || '',
          to: tx.transaction?.message?.accountKeys?.[1]?.pubkey?.toString?.() || '',
          riskLevel: relatedThreat?.severity || 'MEDIUM',
          flags: relatedThreat ? [relatedThreat.title] : [],
          description: relatedThreat?.description || 'Suspicious activity detected',
        };
      });
  }

  private generateRecommendations(
    threats: DetectedThreat[],
    approvals: TokenApproval[],
    status: SecurityStatus
  ): SecurityRecommendation[] {
    const recommendations: SecurityRecommendation[] = [];
    
    // Safe array guard
    const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];

    // Malicious delegations
    const maliciousDelegations = safeApprovals.filter((a) => a?.isMalicious);
    if (maliciousDelegations.length > 0) {
      recommendations.push({
        id: 'revoke-delegations',
        priority: 'CRITICAL',
        category: 'IMMEDIATE',
        title: 'Revoke Malicious Token Delegations',
        description: `You have ${maliciousDelegations.length} token account${maliciousDelegations.length > 1 ? 's' : ''} delegated to malicious addresses.`,
        actionable: true,
        actionType: 'DELEGATE_REVOKE',
      });
    }

    // Active drainer
    if (threats.some((t) => t.type === 'WALLET_DRAINER' && t.ongoingRisk)) {
      recommendations.push({
        id: 'move-assets',
        priority: 'CRITICAL',
        category: 'IMMEDIATE',
        title: 'Transfer Assets to Fresh Wallet',
        description: 'Create a new Solana wallet and transfer all remaining assets immediately.',
        actionable: true,
        actionType: 'TRANSFER_ASSETS',
      });
    }

    // Close empty token accounts (cleanup)
    recommendations.push({
      id: 'close-token-accounts',
      priority: 'LOW',
      category: 'LONG_TERM',
      title: 'Close Unused Token Accounts',
      description: 'Close empty token accounts to reclaim rent SOL. This also removes potential attack surface.',
      actionable: true,
      actionType: 'CLOSE_ACCOUNT',
    });

    // General security
    recommendations.push({
      id: 'use-hardware-wallet',
      priority: 'MEDIUM',
      category: 'SHORT_TERM',
      title: 'Use Hardware Wallet',
      description: 'Consider using a Ledger or other hardware wallet for better key security.',
      actionable: false,
    });

    return recommendations;
  }

  private generateRecoveryPlan(
    threats: DetectedThreat[],
    approvals: TokenApproval[]
  ): RecoveryPlan {
    const steps: RecoveryStep[] = [];
    let order = 1;
    
    // Safe array guards
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const safeApprovals = Array.isArray(approvals) ? approvals.filter(a => a != null) : [];

    // Step 1: Revoke malicious delegations
    const maliciousDelegations = safeApprovals.filter((a) => a?.isMalicious);
    if (maliciousDelegations.length > 0) {
      steps.push({
        order: order++,
        title: 'Revoke Token Delegations',
        description: `Revoke ${maliciousDelegations.length} malicious token delegation${maliciousDelegations.length > 1 ? 's' : ''}.`,
        action: {
          type: 'DELEGATE_REVOKE',
        },
        priority: 'IMMEDIATE',
      });
    }

    // Step 2: Transfer assets if ongoing risk
    if (safeThreats.some((t) => t?.ongoingRisk)) {
      steps.push({
        order: order++,
        title: 'Transfer All Assets',
        description: 'Move all SOL and tokens to a new, secure wallet.',
        action: {
          type: 'TRANSFER_ASSETS',
        },
        priority: 'IMMEDIATE',
      });
    }

    // Step 3: Close token accounts
    steps.push({
      order: order++,
      title: 'Close Token Accounts',
      description: 'Close all token accounts on the compromised wallet to reclaim rent.',
      action: {
        type: 'CLOSE_ACCOUNT',
      },
      priority: 'HIGH',
    });

    return {
      urgencyLevel: safeThreats.some((t) => t?.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
      estimatedTimeMinutes: steps.length * 3,
      steps,
      warnings: [
        'Verify you are on the official Solana wallet or dApp',
        'Never share your seed phrase',
        'Be cautious of anyone offering "recovery services"',
      ],
      safeWalletRequired: true,
    };
  }

  private generateSummary(
    status: SecurityStatus,
    threats: DetectedThreat[],
    approvals: TokenApproval[]
  ): string {
    // CRITICAL: Solana summaries must NOT claim the wallet is "safe"
    // Absence of on-chain evidence ≠ absence of compromise
    
    if (status === 'SAFE') {
      // Changed from "No significant security threats detected" to emphasize limitations
      return 'No detectable on-chain security threats found on your Solana wallet. ' +
             'Note: Many Solana attacks occur off-chain and may not leave on-chain traces. ' +
             'Continue practicing safe wallet hygiene.';
    }

    if (status === 'AT_RISK') {
      return `${threats.length} potential on-chain security concern${threats.length !== 1 ? 's' : ''} detected. ` +
             'Review the findings and take preventive action.';
    }

    return `URGENT: Critical on-chain security threats detected on your Solana wallet. ` +
           'Immediate action required to protect remaining assets.';
  }

  private generateEducationalContent(threats: DetectedThreat[]) {
    const safeThreats = Array.isArray(threats) ? threats.filter(t => t != null) : [];
    const hasThreats = safeThreats.length > 0;
    
    return {
      attackExplanation: {
        whatHappened: hasThreats 
          ? 'On-chain suspicious activity was detected on your Solana wallet.'
          : 'No on-chain threats were detected, but this does not guarantee your wallet is completely safe.',
        howItWorks: 'Solana-specific attacks can include:\n' +
          '• On-chain: Malicious program interactions, token delegation abuse, phishing airdrops\n' +
          '• Off-chain: Phishing signatures, session/cookie hijacks, compromised browser extensions\n\n' +
          'IMPORTANT: Off-chain attacks often leave NO on-chain trace and cannot be detected by this analysis.',
        ongoingDamage: hasThreats 
          ? 'If delegations or program authorities are still active, your assets may still be at risk.'
          : 'Even without detected on-chain threats, your wallet may have been compromised through off-chain means ' +
            '(phishing, session hijack). If you suspect compromise, treat the wallet as unsafe.',
        recoverableInfo: 'If you suspect any compromise: Transfer remaining assets to a fresh wallet immediately ' +
          'and revoke all delegations. Do not reuse seed phrases or private keys.',
      },
      preventionTips: [
        {
          title: 'Understand Solana Detection Limitations',
          description: 'This analysis only detects on-chain threats. Phishing signatures and session hijacks ' +
                       'may not leave any on-chain trace. Always verify transactions independently.',
          importance: 'CRITICAL' as RiskLevel,
        },
        {
          title: 'Verify Program IDs',
          description: 'Always verify the program ID before signing Solana transactions. Use official documentation.',
          importance: 'HIGH' as RiskLevel,
        },
        {
          title: 'Be Cautious of Airdrops',
          description: 'Do not interact with unsolicited token airdrops. They may be phishing attempts.',
          importance: 'HIGH' as RiskLevel,
        },
        {
          title: 'Review Token Account Delegations',
          description: 'Regularly check if any of your token accounts have active delegations.',
          importance: 'MEDIUM' as RiskLevel,
        },
        {
          title: 'Use Trusted Applications Only',
          description: 'Only connect your wallet to verified dApps. Revoke access from applications you no longer use.',
          importance: 'HIGH' as RiskLevel,
        },
        {
          title: 'Monitor Browser Extensions',
          description: 'Malicious browser extensions can steal session data. Only use trusted extensions and keep them updated.',
          importance: 'MEDIUM' as RiskLevel,
        },
      ],
      securityChecklist: [
        { id: '1', category: 'Wallet', item: 'Use hardware wallet for significant holdings', completed: false, chainSpecific: ['solana'] as Chain[] },
        { id: '2', category: 'Wallet', item: 'Backup seed phrase securely offline', completed: false },
        { id: '3', category: 'Transactions', item: 'Verify program IDs before signing', completed: false, chainSpecific: ['solana'] as Chain[] },
        { id: '4', category: 'Tokens', item: 'Close unused token accounts', completed: false, chainSpecific: ['solana'] as Chain[] },
        { id: '5', category: 'Security', item: 'Avoid clicking airdrop links', completed: false },
        { id: '6', category: 'Security', item: 'Review and revoke unnecessary app connections', completed: false, chainSpecific: ['solana'] as Chain[] },
        { id: '7', category: 'Security', item: 'Understand that "no threats detected" ≠ "safe" for Solana', completed: false, chainSpecific: ['solana'] as Chain[] },
      ],
    };
  }
}

