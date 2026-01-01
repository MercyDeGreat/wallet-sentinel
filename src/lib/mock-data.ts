// ============================================
// MOCK DATA FOR TESTING AND DEVELOPMENT
// ============================================
// Use these mock responses to test the UI without making real API calls

import { WalletAnalysisResult, Chain } from '@/types';

/**
 * Generate a mock safe wallet analysis
 */
export function getMockSafeAnalysis(address: string, chain: Chain): WalletAnalysisResult {
  return {
    address: address.toLowerCase(),
    chain,
    timestamp: new Date().toISOString(),
    securityStatus: 'SAFE',
    riskScore: 5,
    summary: 'No significant security threats detected. Your wallet appears to be in good standing. Continue practicing safe wallet hygiene.',
    detectedThreats: [],
    approvals: [
      {
        id: 'approval-1',
        token: {
          address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
          symbol: 'USDC',
          name: 'USD Coin',
          decimals: 6,
          standard: 'ERC20',
          verified: true,
        },
        spender: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',
        spenderLabel: 'Uniswap V2 Router',
        amount: '1000000000',
        isUnlimited: false,
        riskLevel: 'LOW',
        grantedAt: '2024-01-01T00:00:00.000Z',
        isMalicious: false,
      },
    ],
    suspiciousTransactions: [],
    recommendations: [
      {
        id: 'regular-audits',
        priority: 'LOW',
        category: 'LONG_TERM',
        title: 'Schedule Regular Security Audits',
        description: 'Periodically review your wallet approvals and transaction history to catch potential threats early.',
        actionable: false,
      },
    ],
    educationalContent: {
      attackExplanation: {
        whatHappened: 'No attacks detected on this wallet.',
        howItWorks: 'Your wallet shows no signs of compromise or malicious activity.',
        ongoingDamage: 'None - your wallet appears to be secure.',
        recoverableInfo: 'All assets appear to be safe.',
      },
      preventionTips: [
        {
          title: 'Keep up the good work',
          description: 'Continue practicing safe wallet hygiene and stay vigilant.',
          importance: 'LOW',
        },
      ],
      securityChecklist: [
        { id: '1', category: 'Wallet Security', item: 'Use a hardware wallet for significant holdings', completed: false },
        { id: '2', category: 'Wallet Security', item: 'Backup seed phrase in secure offline location', completed: false },
      ],
    },
  };
}

/**
 * Generate a mock at-risk wallet analysis
 */
export function getMockAtRiskAnalysis(address: string, chain: Chain): WalletAnalysisResult {
  return {
    address: address.toLowerCase(),
    chain,
    timestamp: new Date().toISOString(),
    securityStatus: 'AT_RISK',
    riskScore: 45,
    summary: '2 potential security concerns detected. Review the identified risks below and consider taking preventive action.',
    detectedThreats: [
      {
        id: 'threat-1',
        type: 'APPROVAL_HIJACK',
        severity: 'HIGH',
        title: 'High-Risk Token Approval Detected',
        description: 'An unlimited approval was granted to an unverified contract. This could allow the contract to drain your tokens.',
        technicalDetails: 'Token: USDT, Spender: 0x1234...5678, Amount: Unlimited',
        detectedAt: new Date().toISOString(),
        relatedAddresses: ['0x1234567890abcdef1234567890abcdef12345678'],
        relatedTransactions: ['0xabc123def456abc123def456abc123def456abc123def456abc123def456abc1'],
        ongoingRisk: true,
      },
    ],
    approvals: [
      {
        id: 'approval-high-risk',
        token: {
          address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
          symbol: 'USDT',
          name: 'Tether USD',
          decimals: 6,
          standard: 'ERC20',
          verified: true,
        },
        spender: '0x1234567890abcdef1234567890abcdef12345678',
        spenderLabel: 'Unknown Contract',
        amount: '115792089237316195423570985008687907853269984665640564039457584007913129639935',
        isUnlimited: true,
        riskLevel: 'HIGH',
        riskReason: 'Unlimited approval to unverified contract',
        grantedAt: '2024-01-10T00:00:00.000Z',
        isMalicious: false,
      },
    ],
    suspiciousTransactions: [],
    recommendations: [
      {
        id: 'revoke-approvals',
        priority: 'HIGH',
        category: 'IMMEDIATE',
        title: 'Revoke High-Risk Token Approvals',
        description: 'You have 1 high-risk approval that should be revoked to prevent unauthorized token transfers.',
        actionable: true,
        actionType: 'REVOKE_APPROVAL',
      },
    ],
    recoveryPlan: {
      urgencyLevel: 'MEDIUM',
      estimatedTimeMinutes: 5,
      steps: [
        {
          order: 1,
          title: 'Revoke High-Risk Approval',
          description: 'Revoke the unlimited USDT approval to the unknown contract.',
          action: {
            type: 'REVOKE_APPROVAL',
            tokenAddress: '0xdac17f958d2ee523a2206206994597c13d831ec7',
            contractAddress: '0x1234567890abcdef1234567890abcdef12345678',
          },
          priority: 'HIGH',
        },
      ],
      warnings: [
        'Verify all transaction details before signing',
      ],
      safeWalletRequired: false,
    },
    educationalContent: {
      attackExplanation: {
        whatHappened: 'A high-risk token approval was detected that could potentially be exploited.',
        howItWorks: 'Unlimited token approvals allow the approved contract to transfer any amount of your tokens at any time.',
        ongoingDamage: 'The approved contract can drain your tokens until the approval is revoked.',
        recoverableInfo: 'Revoke the approval to prevent any future unauthorized transfers.',
      },
      preventionTips: [
        {
          title: 'Limit token approvals',
          description: 'Only approve the exact amount needed, not unlimited.',
          importance: 'HIGH',
        },
      ],
      securityChecklist: [
        { id: '1', category: 'Approvals', item: 'Review and revoke unnecessary token approvals', completed: false },
      ],
    },
  };
}

/**
 * Generate a mock compromised wallet analysis
 */
export function getMockCompromisedAnalysis(address: string, chain: Chain): WalletAnalysisResult {
  return {
    address: address.toLowerCase(),
    chain,
    timestamp: new Date().toISOString(),
    securityStatus: 'COMPROMISED',
    riskScore: 85,
    summary: 'URGENT: 2 critical security threats detected. Immediate action recommended. Review the recovery plan below to protect remaining assets.',
    detectedThreats: [
      {
        id: 'threat-drainer',
        type: 'WALLET_DRAINER',
        severity: 'CRITICAL',
        title: 'Wallet Drainer Attack Detected',
        description: 'Multiple assets were rapidly transferred out of this wallet to a known malicious address. This pattern is consistent with wallet drainer activity.',
        technicalDetails: 'Destination: 0xdead...beef, Assets drained: ETH, USDC, NFTs',
        detectedAt: new Date().toISOString(),
        relatedAddresses: ['0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'],
        relatedTransactions: [
          '0xabc123def456abc123def456abc123def456abc123def456abc123def456abc1',
          '0xdef456abc123def456abc123def456abc123def456abc123def456abc123def4',
        ],
        ongoingRisk: true,
        recoverableAssets: [
          {
            token: {
              address: '0x0000000000000000000000000000000000000000',
              symbol: 'ETH',
              name: 'Ethereum',
              decimals: 18,
              standard: 'NATIVE',
              verified: true,
            },
            balance: '0.05',
            balanceUsd: 100,
            isRecoverable: true,
            recoveryMethod: 'Transfer to safe wallet immediately',
          },
        ],
      },
      {
        id: 'threat-malicious-approval',
        type: 'APPROVAL_HIJACK',
        severity: 'CRITICAL',
        title: 'Active Approval to Malicious Contract',
        description: 'You have an active approval allowing a known malicious contract to spend your tokens.',
        technicalDetails: 'Token: USDC, Spender: Known drainer contract',
        detectedAt: new Date().toISOString(),
        relatedAddresses: ['0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'],
        relatedTransactions: [],
        ongoingRisk: true,
      },
    ],
    approvals: [
      {
        id: 'approval-malicious',
        token: {
          address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
          symbol: 'USDC',
          name: 'USD Coin',
          decimals: 6,
          standard: 'ERC20',
          verified: true,
        },
        spender: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        spenderLabel: 'Known Malicious Contract',
        amount: '115792089237316195423570985008687907853269984665640564039457584007913129639935',
        isUnlimited: true,
        riskLevel: 'CRITICAL',
        riskReason: 'Approved spender is a known malicious contract',
        grantedAt: '2024-01-15T00:00:00.000Z',
        isMalicious: true,
      },
    ],
    suspiciousTransactions: [
      {
        hash: '0xabc123def456abc123def456abc123def456abc123def456abc123def456abc1',
        timestamp: new Date().toISOString(),
        type: 'WALLET_DRAINER',
        from: address.toLowerCase(),
        to: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        value: '1000000000000000000',
        riskLevel: 'CRITICAL',
        flags: ['Rapid asset outflow', 'Known malicious destination'],
        description: 'Assets transferred to known drainer address',
      },
    ],
    recommendations: [
      {
        id: 'revoke-malicious',
        priority: 'CRITICAL',
        category: 'IMMEDIATE',
        title: 'Revoke Malicious Approvals',
        description: 'Revoke all approvals to known malicious contracts immediately.',
        actionable: true,
        actionType: 'REVOKE_APPROVAL',
      },
      {
        id: 'move-assets',
        priority: 'CRITICAL',
        category: 'IMMEDIATE',
        title: 'Move Remaining Assets',
        description: 'Transfer remaining assets to a fresh, secure wallet immediately.',
        actionable: true,
        actionType: 'TRANSFER_ASSETS',
      },
      {
        id: 'abandon-wallet',
        priority: 'CRITICAL',
        category: 'IMMEDIATE',
        title: 'Stop Using This Wallet',
        description: 'Do not deposit any more funds to this wallet. Create a new wallet with a fresh seed phrase.',
        actionable: false,
      },
    ],
    recoveryPlan: {
      urgencyLevel: 'CRITICAL',
      estimatedTimeMinutes: 10,
      steps: [
        {
          order: 1,
          title: 'Revoke Malicious Approvals',
          description: 'Immediately revoke all approvals to the known malicious contract.',
          action: {
            type: 'REVOKE_APPROVAL',
            tokenAddress: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
            contractAddress: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
          },
          priority: 'IMMEDIATE',
        },
        {
          order: 2,
          title: 'Transfer Remaining Assets',
          description: 'Move all remaining ETH and tokens to a new, secure wallet.',
          action: {
            type: 'TRANSFER_ASSETS',
          },
          priority: 'IMMEDIATE',
        },
        {
          order: 3,
          title: 'Create New Wallet',
          description: 'Generate a new wallet with a completely new seed phrase. Consider using a hardware wallet.',
          action: {
            type: 'MANUAL',
          },
          priority: 'HIGH',
        },
      ],
      warnings: [
        'Never share your seed phrase or private key with anyone',
        'Verify all transaction details before signing',
        'Be cautious of phishing sites mimicking recovery tools',
        'Do not trust anyone offering "recovery services"',
      ],
      safeWalletRequired: true,
    },
    educationalContent: {
      attackExplanation: {
        whatHappened: 'A wallet drainer is a malicious smart contract designed to steal assets from your wallet by exploiting approvals or permissions you granted.',
        howItWorks: 'Drainers typically work by: 1) Tricking users into signing malicious transactions or approvals, 2) Using those permissions to transfer assets to attacker-controlled wallets, 3) Often disguising as legitimate DeFi protocols or NFT mints.',
        ongoingDamage: 'If approvals are still active, the drainer can continue to steal any tokens deposited to your wallet.',
        recoverableInfo: 'Assets already transferred cannot be recovered. However, you can prevent future loss by revoking approvals and moving remaining assets.',
      },
      preventionTips: [
        {
          title: 'Never share your seed phrase',
          description: 'No legitimate service will ever ask for your seed phrase.',
          importance: 'CRITICAL',
        },
        {
          title: 'Use hardware wallets',
          description: 'Hardware wallets keep your private keys offline.',
          importance: 'HIGH',
        },
        {
          title: 'Review before signing',
          description: 'Always carefully review what you are signing.',
          importance: 'HIGH',
        },
      ],
      securityChecklist: [
        { id: '1', category: 'Recovery', item: 'Revoke all malicious approvals', completed: false },
        { id: '2', category: 'Recovery', item: 'Transfer remaining assets to safe wallet', completed: false },
        { id: '3', category: 'Recovery', item: 'Create new wallet with fresh seed phrase', completed: false },
        { id: '4', category: 'Recovery', item: 'Never use the compromised wallet again', completed: false },
      ],
    },
  };
}

/**
 * Get mock analysis based on address pattern (for demo purposes)
 */
export function getMockAnalysis(address: string, chain: Chain): WalletAnalysisResult {
  // Use address hash to determine mock response type
  const lastChar = address.slice(-1).toLowerCase();
  
  if (['0', '1', '2', '3', '4'].includes(lastChar)) {
    return getMockSafeAnalysis(address, chain);
  } else if (['5', '6', '7', '8'].includes(lastChar)) {
    return getMockAtRiskAnalysis(address, chain);
  } else {
    return getMockCompromisedAnalysis(address, chain);
  }
}


