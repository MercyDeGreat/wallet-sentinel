// ============================================
// SOLANA CHAIN ANALYZER
// ============================================
// Handles security analysis for Solana blockchain.
// All operations are READ-ONLY.

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

    // Generate suspicious transactions list
    const suspiciousTransactions = this.identifySuspiciousTransactions(transactions, threats);

    // Generate recommendations
    const recommendations = this.generateRecommendations(threats, approvals, securityStatus);

    // Generate recovery plan
    const recoveryPlan = securityStatus !== 'SAFE'
      ? this.generateRecoveryPlan(threats, approvals)
      : undefined;

    return {
      address,
      chain: 'solana',
      timestamp: new Date().toISOString(),
      securityStatus,
      riskScore,
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

    for (const tx of transactions) {
      if (!tx.transaction?.message?.instructions) continue;

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

    for (const account of tokenAccounts) {
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

    // Group transactions by time window
    const windowMinutes = 10;
    const sortedTxs = [...transactions]
      .filter((tx) => tx.blockTime)
      .sort((a, b) => (a.blockTime || 0) - (b.blockTime || 0));

    // Look for multiple outbound transfers in short window
    for (let i = 0; i < sortedTxs.length; i++) {
      const windowStart = sortedTxs[i].blockTime || 0;
      const windowEnd = windowStart + windowMinutes * 60;

      const txsInWindow = sortedTxs.filter(
        (tx) => (tx.blockTime || 0) >= windowStart && (tx.blockTime || 0) <= windowEnd
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

    // Critical threats
    score += threats.filter((t) => t.severity === 'CRITICAL').length * 30;
    // High threats
    score += threats.filter((t) => t.severity === 'HIGH').length * 20;
    // Medium threats
    score += threats.filter((t) => t.severity === 'MEDIUM').length * 10;
    // Malicious approvals
    score += approvals.filter((a) => a.isMalicious).length * 25;
    // Any active delegations
    score += approvals.length * 5;

    return Math.min(100, Math.max(0, score));
  }

  private determineSecurityStatus(riskScore: number, threats: DetectedThreat[]): SecurityStatus {
    const hasCritical = threats.some((t) => t.severity === 'CRITICAL' && t.ongoingRisk);

    if (hasCritical || riskScore >= 70) return 'COMPROMISED';
    if (riskScore >= 30 || threats.length > 0) return 'AT_RISK';
    return 'SAFE';
  }

  private identifySuspiciousTransactions(
    transactions: ParsedTransactionWithMeta[],
    threats: DetectedThreat[]
  ): SuspiciousTransaction[] {
    const suspiciousSigs = new Set(threats.flatMap((t) => t.relatedTransactions));

    return transactions
      .filter((tx) => suspiciousSigs.has(tx.transaction.signatures[0]))
      .map((tx) => {
        const relatedThreat = threats.find((t) =>
          t.relatedTransactions.includes(tx.transaction.signatures[0])
        );

        return {
          hash: tx.transaction.signatures[0],
          timestamp: tx.blockTime
            ? new Date(tx.blockTime * 1000).toISOString()
            : new Date().toISOString(),
          type: relatedThreat?.type || 'UNKNOWN',
          from: tx.transaction.message.accountKeys[0]?.pubkey.toString() || '',
          to: tx.transaction.message.accountKeys[1]?.pubkey.toString() || '',
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

    // Malicious delegations
    const maliciousDelegations = approvals.filter((a) => a.isMalicious);
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

    // Step 1: Revoke malicious delegations
    const maliciousDelegations = approvals.filter((a) => a.isMalicious);
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
    if (threats.some((t) => t.ongoingRisk)) {
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
      urgencyLevel: threats.some((t) => t.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
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
    if (status === 'SAFE') {
      return 'No significant security threats detected on your Solana wallet. Continue practicing safe wallet hygiene.';
    }

    if (status === 'AT_RISK') {
      return `${threats.length} potential security concern${threats.length !== 1 ? 's' : ''} detected. Review the findings and take preventive action.`;
    }

    return `URGENT: Critical security threats detected on your Solana wallet. Immediate action required to protect remaining assets.`;
  }

  private generateEducationalContent(threats: DetectedThreat[]) {
    return {
      attackExplanation: {
        whatHappened: 'Suspicious activity was detected on your Solana wallet.',
        howItWorks: 'Solana-specific attacks can include malicious program interactions, token delegation abuse, and phishing airdrops.',
        ongoingDamage: 'If delegations or program authorities are still active, your assets may still be at risk.',
        recoverableInfo: 'Transfer remaining assets to a fresh wallet and revoke all delegations.',
      },
      preventionTips: [
        {
          title: 'Verify Program IDs',
          description: 'Always verify the program ID before signing Solana transactions. Use official documentation.',
          importance: 'HIGH' as RiskLevel,
        },
        {
          title: 'Be Cautious of Airdrops',
          description: 'Do not interact with unsolicited token airdrops. They may be phishing attempts.',
          importance: 'MEDIUM' as RiskLevel,
        },
        {
          title: 'Review Token Account Delegations',
          description: 'Regularly check if any of your token accounts have active delegations.',
          importance: 'MEDIUM' as RiskLevel,
        },
      ],
      securityChecklist: [
        { id: '1', category: 'Wallet', item: 'Use hardware wallet for significant holdings', completed: false, chainSpecific: ['solana'] },
        { id: '2', category: 'Wallet', item: 'Backup seed phrase securely offline', completed: false },
        { id: '3', category: 'Transactions', item: 'Verify program IDs before signing', completed: false, chainSpecific: ['solana'] },
        { id: '4', category: 'Tokens', item: 'Close unused token accounts', completed: false, chainSpecific: ['solana'] },
        { id: '5', category: 'Security', item: 'Avoid clicking airdrop links', completed: false },
      ],
    };
  }
}

