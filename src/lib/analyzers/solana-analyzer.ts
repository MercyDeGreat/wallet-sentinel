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

    // Analyze threats
    const threats: DetectedThreat[] = [];

    // Check for malicious program interactions
    const maliciousProgramThreats = this.detectMaliciousProgramInteractions(transactions);
    threats.push(...maliciousProgramThreats);

    // Check for delegate abuse
    const delegateThreats = await this.detectDelegateAbuse(tokenAccounts, publicKey);
    threats.push(...delegateThreats);

    // Check for rapid outflows
    const outflowThreats = this.detectRapidOutflows(transactions, address);
    threats.push(...outflowThreats);

    // Check for suspicious airdrops
    const airdropThreats = this.detectSuspiciousAirdrops(transactions, address);
    threats.push(...airdropThreats);

    // Analyze token account delegations (similar to EVM approvals)
    const approvals = await this.analyzeTokenDelegations(tokenAccounts, publicKey);

    // Calculate risk score
    const riskScore = this.calculateRiskScore(threats, approvals);
    const securityStatus = this.determineSecurityStatus(riskScore, threats);

    // Generate chain-aware status (Solana-specific)
    const chainAwareStatus = this.generateChainAwareStatus(securityStatus, threats);
    const analysisMetadata = this.getAnalysisMetadata();

    // Generate suspicious transactions list
    const suspiciousTransactions = this.identifySuspiciousTransactions(transactions, threats);

    // Generate recommendations
    const recommendations = this.generateRecommendations(threats, approvals, securityStatus);

    // Generate recovery plan
    const recoveryPlan = securityStatus !== 'SAFE'
      ? this.generateRecoveryPlan(threats, approvals)
      : undefined;

    // Build default classification for Solana
    // Solana analysis is simpler - no directional analysis for now
    const classification: import('@/types').WalletClassification = {
      role: threats.length === 0 ? 'UNKNOWN' : 'VICTIM',
      confidence: 'MEDIUM',
      evidence: threats.length === 0 
        ? [{ type: 'NORMAL_ACTIVITY', description: 'No on-chain malicious activity detected', weight: 'HIGH' as const }]
        : [{ type: 'OUTBOUND_TO_DRAINER', description: 'Potential threat detected', weight: 'MEDIUM' as const }],
      isMalicious: false,
      isInfrastructure: false,
      isServiceFeeReceiver: false,
    };
    
    // Updated classification reason for Solana
    const classificationReason = threats.length === 0
      ? 'No on-chain malicious activity detected. Note: Solana compromises may occur off-chain and leave no trace.'
      : 'Potential security threats detected. Review the identified risks.';
    
    const riskLevel: import('@/types').RiskLevel = 
      riskScore >= 75 ? 'CRITICAL' :
      riskScore >= 50 ? 'HIGH' :
      riskScore >= 25 ? 'MEDIUM' : 'LOW';

    return {
      address,
      chain: 'solana',
      timestamp: new Date().toISOString(),
      
      // Core security assessment
      securityStatus,
      riskScore,
      
      // Chain-aware status (NEW - Solana specific)
      chainAwareStatus,
      analysisMetadata,
      chainDisclaimer: SOLANA_SECURITY_DISCLAIMER,
      
      // Classification (prevents false positives)
      classification,
      riskLevel,
      classificationReason,
      
      // Detailed analysis
      summary: this.generateSummary(securityStatus, threats, approvals),
      detectedThreats: threats,
      approvals,
      suspiciousTransactions,
      recommendations,
      recoveryPlan,
      educationalContent: this.generateEducationalContent(threats),
    };
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

