// ============================================
// ADDRESS ROLE CLASSIFIER
// ============================================
// Classifies addresses into roles to prevent false positives
// when detecting sweeper bots and other malicious activity.
//
// PRINCIPLE: Context matters. Rapid forwarding ≠ malicious.
// Exchange deposit addresses, bridges, and routers all forward funds quickly.

import { Chain } from '@/types';
import { isSafeContract, isDeFiProtocol, isNFTMarketplace, isENSContract, isInfrastructureContract } from './safe-contracts';
import { isMaliciousAddress, isDrainerRecipient, isLegitimateContract, isHighVolumeNeutralAddress } from './malicious-database';
import { EXCHANGE_HOT_WALLETS } from './transaction-labeler';

// ============================================
// ADDRESS ROLE TYPES
// ============================================

export type AddressRole =
  | 'EXCHANGE_INFRASTRUCTURE'     // Exchange deposit / hot wallet
  | 'PROTOCOL_ROUTER'             // DEX router, bridge, relayer
  | 'DEFI_PROTOCOL'               // Lending, staking, yield protocols
  | 'NFT_MARKETPLACE'             // OpenSea, Blur, etc.
  | 'INFRASTRUCTURE'              // ENS, registrars, oracles
  | 'USER_CONTROLLED'             // Regular user wallet (default)
  | 'AUTOMATED_FORWARDER'         // Automated but non-malicious forwarding
  | 'CONFIRMED_SWEEPER_BOT'       // Confirmed malicious sweeper
  | 'SUSPECTED_SWEEPER_BOT'       // Suspected but not confirmed
  | 'UNKNOWN';                    // Needs more evidence

export interface AddressClassification {
  address: string;
  role: AddressRole;
  confidence: number;         // 0-100
  isKnownEntity: boolean;     // True if address is in a known database
  entityName?: string;        // Name if known (e.g., "Binance Hot Wallet")
  riskLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  allowsRapidForwarding: boolean;  // True if rapid forwarding is expected behavior
  evidenceReasons: string[];  // Why this classification was made
  shouldTriggerAlert: boolean;
  alertMessage?: string;
}

// ============================================
// SWEEPER BOT SIGNALS
// ============================================
// Multiple independent signals required for sweeper classification

export interface SweeperSignals {
  hasKnownDrainerInteraction: boolean;
  hasUnauthorizedApprovals: boolean;
  hasPermitAbuse: boolean;
  hasVictimPattern: boolean;           // Assets lost without user-initiated tx
  hasKnownAttackerLinkage: boolean;    // Connected to known attacker wallets
  hasMaliciousContractCall: boolean;
  forwardsToMultipleUnknownAddresses: boolean;
  destinationIsKnownDrainer: boolean;
  signalCount: number;
  details: string[];
}

// ============================================
// KNOWN EXCHANGE PATTERNS
// ============================================

// Common exchange deposit address patterns
const EXCHANGE_PATTERNS = {
  // Addresses that receive from many users and forward to aggregation wallets
  highInflowLowOutflowAddresses: new Set<string>([
    // These would be populated from on-chain analysis
  ]),
  
  // Known exchange hot wallet ranges (simplified)
  exchangeLabels: new Map<string, string>([
    // Add known exchange addresses here
    ['0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be', 'Binance Hot Wallet'],
    ['0xd551234ae421e3bcba99a0da6d736074f22192ff', 'Binance Hot Wallet 2'],
    ['0x28c6c06298d514db089934071355e5743bf21d60', 'Binance Hot Wallet 14'],
    ['0x21a31ee1afc51d94c2efccaa2092ad1028285549', 'Binance Hot Wallet 15'],
    ['0xdfd5293d8e347dfe59e90efd55b2956a1343963d', 'Binance Hot Wallet 16'],
    ['0x56eddb7aa87536c09ccc2793473599fd21a8b17f', 'Binance Hot Wallet 17'],
    ['0x9696f59e4d72e237be84ffd425dcad154bf96976', 'Binance Hot Wallet 18'],
    ['0x4976a4a02f38326660d17bf34b431dc6e2eb2327', 'Binance Hot Wallet 19'],
    ['0xbe0eb53f46cd790cd13851d5eff43d12404d33e8', 'Binance Cold Wallet'],
    ['0xf977814e90da44bfa03b6295a0616a897441acec', 'Binance Cold Wallet 8'],
    ['0x503828976d22510aad0201ac7ec88293211d23da', 'Coinbase Hot Wallet'],
    ['0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740', 'Coinbase Hot Wallet 2'],
    ['0x71660c4005ba85c37ccec55d0c4493e66fe775d3', 'Coinbase Hot Wallet 3'],
    ['0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43', 'Coinbase Hot Wallet 4'],
    ['0x77134cbc06cb00b66f4c7e623d5fdbf6777635ec', 'Coinbase Hot Wallet 5'],
    ['0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13', 'Coinbase Vault'],
    ['0xe0F0CfDe7Ee664943906f17F7f14342E76A5cEc7', 'Kraken Hot Wallet'],
    ['0x2910543af39aba0cd09dbb2d50200b3e800a63d2', 'Kraken Hot Wallet 13'],
    ['0x0a73573cf2903580c19e2f3fb8ac7d862999afce', 'Kraken Hot Wallet 17'],
    ['0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0', 'Kraken Hot Wallet 18'],
    ['0xfa52274dd61e1643d2205169732f29114bc240b3', 'OKX Hot Wallet'],
    ['0x236f9f97e0e62388479bf9e5ba4889e46b0273c3', 'OKX Hot Wallet 2'],
    ['0xa7efae728d2936e78bda97dc267687568dd593f3', 'OKX Hot Wallet 3'],
    ['0x6cc5f688a315f3dc28a7781717a9a798a59fda7b', 'OKX Cold Wallet'],
    ['0x75e89d5979e4f6fba9f97c104c2f0afb3f1dcb88', 'MEXC Hot Wallet'],
    ['0x0211f3cedbef3143223d3acf0e589747933e8527', 'MEXC Hot Wallet 2'],
    ['0x3cc936b795a188f0e246cbb2d74c5bd190aecf18', 'MEXC Hot Wallet 3'],
    ['0xfc7d7f62ee3c6ef1beca49f3bdf7ab0e0cb1dedc', 'Bybit Hot Wallet'],
    ['0xf89d7b9c864f589bbf53a82105107622b35eaa40', 'Bybit Hot Wallet 2'],
    ['0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4', 'Bybit Hot Wallet 3'],
    ['0xee5b5b923ffce93a870b3104b7ca09c3db80047a', 'Huobi Hot Wallet'],
    ['0x46340b20830761efd32832a74d7169b29feb9758', 'Huobi Hot Wallet 2'],
    ['0x5401dbf7da53e1c9dbf484e3d69505815f2f5e6e', 'Huobi Hot Wallet 3'],
    ['0xab5c66752a9e8167967685f1450532fb96d5d24f', 'Huobi Hot Wallet 14'],
    ['0x1062a747393198f70f71ec65a582423dba7e5ab3', 'KuCoin Hot Wallet'],
    ['0xf16e9b0d03470827a95cdfd0cb8a8a3b46969b91', 'KuCoin Hot Wallet 2'],
    ['0x738cf6903e6c4e699d1c2dd9ab8b67fcdb3121ea', 'KuCoin Hot Wallet 3'],
    ['0x236f233dbd74a6b1890fad464cc38dc6c9e71bfc', 'Gemini Hot Wallet'],
  ]),
};

// ============================================
// MAIN CLASSIFICATION FUNCTION
// ============================================

export function classifyAddress(
  address: string,
  chain: Chain,
  transactionContext?: {
    incomingCount?: number;
    outgoingCount?: number;
    uniqueSenders?: number;
    uniqueRecipients?: number;
    avgTimeToForward?: number;
    forwardsToSameAddress?: boolean;
    primaryRecipient?: string;
    hasProtocolInteraction?: boolean;
  }
): AddressClassification {
  const normalized = address.toLowerCase();
  const evidence: string[] = [];
  
  // ============================================
  // CHECK 1: Known Exchange Infrastructure
  // ============================================
  if (EXCHANGE_HOT_WALLETS.has(normalized)) {
    const label = EXCHANGE_PATTERNS.exchangeLabels.get(normalized);
    return {
      address: normalized,
      role: 'EXCHANGE_INFRASTRUCTURE',
      confidence: 99,
      isKnownEntity: true,
      entityName: label || 'Known Exchange',
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: ['Address is a known exchange hot wallet'],
      shouldTriggerAlert: false,
    };
  }
  
  // Check extended exchange labels
  const exchangeLabel = EXCHANGE_PATTERNS.exchangeLabels.get(normalized);
  if (exchangeLabel) {
    return {
      address: normalized,
      role: 'EXCHANGE_INFRASTRUCTURE',
      confidence: 99,
      isKnownEntity: true,
      entityName: exchangeLabel,
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: [`Identified as ${exchangeLabel}`],
      shouldTriggerAlert: false,
    };
  }
  
  // ============================================
  // CHECK 2: Protocol Routers / Infrastructure
  // ============================================
  if (isSafeContract(normalized)) {
    evidence.push('Address is a verified safe contract');
    return {
      address: normalized,
      role: 'PROTOCOL_ROUTER',
      confidence: 95,
      isKnownEntity: true,
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: evidence,
      shouldTriggerAlert: false,
    };
  }
  
  if (isDeFiProtocol(normalized)) {
    evidence.push('Address is a known DeFi protocol');
    return {
      address: normalized,
      role: 'DEFI_PROTOCOL',
      confidence: 95,
      isKnownEntity: true,
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: evidence,
      shouldTriggerAlert: false,
    };
  }
  
  if (isInfrastructureContract(normalized)) {
    evidence.push('Address is infrastructure contract');
    return {
      address: normalized,
      role: 'INFRASTRUCTURE',
      confidence: 90,
      isKnownEntity: true,
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: evidence,
      shouldTriggerAlert: false,
    };
  }
  
  if (isNFTMarketplace(normalized)) {
    evidence.push('Address is NFT marketplace');
    return {
      address: normalized,
      role: 'NFT_MARKETPLACE',
      confidence: 95,
      isKnownEntity: true,
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: evidence,
      shouldTriggerAlert: false,
    };
  }
  
  if (isENSContract(normalized)) {
    evidence.push('Address is ENS contract');
    return {
      address: normalized,
      role: 'INFRASTRUCTURE',
      confidence: 95,
      isKnownEntity: true,
      entityName: 'ENS',
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: evidence,
      shouldTriggerAlert: false,
    };
  }
  
  if (isLegitimateContract(normalized)) {
    evidence.push('Address is a legitimate contract');
    return {
      address: normalized,
      role: 'PROTOCOL_ROUTER',
      confidence: 85,
      isKnownEntity: true,
      riskLevel: 'NONE',
      allowsRapidForwarding: true,
      evidenceReasons: evidence,
      shouldTriggerAlert: false,
    };
  }
  
  if (isHighVolumeNeutralAddress(normalized)) {
    evidence.push('Address is a high-volume neutral address');
    return {
      address: normalized,
      role: 'EXCHANGE_INFRASTRUCTURE',
      confidence: 80,
      isKnownEntity: true,
      riskLevel: 'LOW',
      allowsRapidForwarding: true,
      evidenceReasons: evidence,
      shouldTriggerAlert: false,
    };
  }
  
  // ============================================
  // CHECK 3: Known Malicious Addresses
  // ============================================
  const maliciousInfo = isMaliciousAddress(normalized, chain);
  if (maliciousInfo) {
    return {
      address: normalized,
      role: 'CONFIRMED_SWEEPER_BOT',
      confidence: 99,
      isKnownEntity: true,
      entityName: maliciousInfo.name,
      riskLevel: 'CRITICAL',
      allowsRapidForwarding: false,
      evidenceReasons: [`Known malicious address: ${maliciousInfo.name}`],
      shouldTriggerAlert: true,
      alertMessage: `This address has been confirmed as a malicious actor: ${maliciousInfo.name}`,
    };
  }
  
  if (isDrainerRecipient(normalized)) {
    return {
      address: normalized,
      role: 'CONFIRMED_SWEEPER_BOT',
      confidence: 95,
      isKnownEntity: true,
      entityName: 'Known Drainer Recipient',
      riskLevel: 'CRITICAL',
      allowsRapidForwarding: false,
      evidenceReasons: ['Address is a known drainer fund recipient'],
      shouldTriggerAlert: true,
      alertMessage: 'This address is known to receive stolen funds from drainer contracts.',
    };
  }
  
  // ============================================
  // CHECK 4: Behavioral Classification
  // ============================================
  if (transactionContext) {
    const {
      incomingCount = 0,
      outgoingCount = 0,
      uniqueSenders = 0,
      uniqueRecipients = 0,
      avgTimeToForward = 0,
      forwardsToSameAddress = false,
      primaryRecipient,
      hasProtocolInteraction = false,
    } = transactionContext;
    
    // Exchange-like pattern: many senders, few recipients, fast forwarding
    if (uniqueSenders >= 10 && uniqueRecipients <= 3 && avgTimeToForward < 3600) {
      // Check if primary recipient is an exchange or known entity
      if (primaryRecipient) {
        const recipientLabel = EXCHANGE_PATTERNS.exchangeLabels.get(primaryRecipient.toLowerCase());
        if (recipientLabel || EXCHANGE_HOT_WALLETS.has(primaryRecipient.toLowerCase())) {
          evidence.push('Pattern matches exchange deposit address behavior');
          evidence.push(`Forwards to ${recipientLabel || 'exchange hot wallet'}`);
          return {
            address: normalized,
            role: 'EXCHANGE_INFRASTRUCTURE',
            confidence: 75,
            isKnownEntity: false,
            entityName: 'Probable Exchange Deposit Address',
            riskLevel: 'LOW',
            allowsRapidForwarding: true,
            evidenceReasons: evidence,
            shouldTriggerAlert: false,
            alertMessage: 'This address behaves like an exchange deposit address. Rapid forwarding is expected and NOT malicious.',
          };
        }
      }
    }
    
    // Automated forwarder: consistently sends to the same address
    if (forwardsToSameAddress && outgoingCount >= 3 && hasProtocolInteraction) {
      evidence.push('Consistent forwarding to same destination');
      evidence.push('Has protocol interaction (not just raw transfers)');
      return {
        address: normalized,
        role: 'AUTOMATED_FORWARDER',
        confidence: 70,
        isKnownEntity: false,
        riskLevel: 'LOW',
        allowsRapidForwarding: true,
        evidenceReasons: evidence,
        shouldTriggerAlert: false,
        alertMessage: 'Automated fund forwarding detected. This behavior is commonly used by exchanges and infrastructure wallets and does not indicate compromise by itself.',
      };
    }
    
    // User-controlled wallet: diverse activity
    if (hasProtocolInteraction && uniqueRecipients >= 3) {
      evidence.push('Diverse transaction patterns');
      evidence.push('Interacts with protocols');
      return {
        address: normalized,
        role: 'USER_CONTROLLED',
        confidence: 60,
        isKnownEntity: false,
        riskLevel: 'NONE',
        allowsRapidForwarding: false,
        evidenceReasons: evidence,
        shouldTriggerAlert: false,
      };
    }
  }
  
  // ============================================
  // DEFAULT: Unknown - needs more evidence
  // ============================================
  return {
    address: normalized,
    role: 'UNKNOWN',
    confidence: 30,
    isKnownEntity: false,
    riskLevel: 'LOW',
    allowsRapidForwarding: false,
    evidenceReasons: ['Insufficient data to classify address'],
    shouldTriggerAlert: false,
  };
}

// ============================================
// SWEEPER SIGNAL ANALYSIS
// ============================================

export function analyzeSweeperSignals(
  address: string,
  chain: Chain,
  context: {
    hasDrainerInteraction: boolean;
    hasUnauthorizedApprovals: boolean;
    hasPermitSignatures: boolean;
    lostAssetsWithoutInitiation: boolean;
    destinationAddresses: string[];
    hasKnownAttackerLink: boolean;
    calledMaliciousContracts: boolean;
  }
): SweeperSignals {
  const signals: SweeperSignals = {
    hasKnownDrainerInteraction: context.hasDrainerInteraction,
    hasUnauthorizedApprovals: context.hasUnauthorizedApprovals,
    hasPermitAbuse: context.hasPermitSignatures,
    hasVictimPattern: context.lostAssetsWithoutInitiation,
    hasKnownAttackerLinkage: context.hasKnownAttackerLink,
    hasMaliciousContractCall: context.calledMaliciousContracts,
    forwardsToMultipleUnknownAddresses: false,
    destinationIsKnownDrainer: false,
    signalCount: 0,
    details: [],
  };
  
  // Check destination addresses
  let unknownDestinations = 0;
  for (const dest of context.destinationAddresses) {
    if (isDrainerRecipient(dest) || isMaliciousAddress(dest, chain)) {
      signals.destinationIsKnownDrainer = true;
      signals.details.push(`Destination ${dest.slice(0, 10)}... is a known drainer`);
    } else if (!isKnownSafeDestination(dest)) {
      unknownDestinations++;
    }
  }
  
  if (unknownDestinations >= 3) {
    signals.forwardsToMultipleUnknownAddresses = true;
    signals.details.push(`Forwards to ${unknownDestinations} unknown addresses`);
  }
  
  // Count signals
  if (signals.hasKnownDrainerInteraction) {
    signals.signalCount++;
    signals.details.push('Interacted with known drainer contract');
  }
  if (signals.hasUnauthorizedApprovals) {
    signals.signalCount++;
    signals.details.push('Has unauthorized token approvals');
  }
  if (signals.hasPermitAbuse) {
    signals.signalCount++;
    signals.details.push('Permit signature abuse detected');
  }
  if (signals.hasVictimPattern) {
    signals.signalCount++;
    signals.details.push('Assets lost without user-initiated transaction');
  }
  if (signals.hasKnownAttackerLinkage) {
    signals.signalCount++;
    signals.details.push('Connected to known attacker wallet');
  }
  if (signals.hasMaliciousContractCall) {
    signals.signalCount++;
    signals.details.push('Called malicious contract function');
  }
  if (signals.forwardsToMultipleUnknownAddresses) {
    signals.signalCount++;
    // Don't count this alone - needs corroboration
  }
  if (signals.destinationIsKnownDrainer) {
    signals.signalCount++;
  }
  
  return signals;
}

// ============================================
// HELPER: Check if destination is known safe
// ============================================

function isKnownSafeDestination(address: string): boolean {
  const normalized = address.toLowerCase();
  return (
    !!isSafeContract(normalized) ||
    !!isDeFiProtocol(normalized) ||
    !!isNFTMarketplace(normalized) ||
    !!isENSContract(normalized) ||
    !!isInfrastructureContract(normalized) ||
    !!isLegitimateContract(normalized) ||
    EXCHANGE_HOT_WALLETS.has(normalized) ||
    EXCHANGE_PATTERNS.exchangeLabels.has(normalized)
  );
}

// ============================================
// SWEEPER BOT VERDICT
// ============================================

export interface SweeperVerdict {
  isSweeperBot: boolean;
  confidence: number;
  verdict: 'CONFIRMED_SWEEPER' | 'SUSPECTED_SWEEPER' | 'AUTOMATED_FORWARDER' | 'EXCHANGE_BEHAVIOR' | 'NO_EVIDENCE';
  shouldAlert: boolean;
  alertSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  userMessage: string;
  technicalDetails: string[];
  recommendation: string;
}

export function determineSweeperVerdict(
  addressClassification: AddressClassification,
  signals: SweeperSignals
): SweeperVerdict {
  // ============================================
  // RULE 1: Known infrastructure = NEVER sweeper
  // ============================================
  if (addressClassification.role === 'EXCHANGE_INFRASTRUCTURE' ||
      addressClassification.role === 'PROTOCOL_ROUTER' ||
      addressClassification.role === 'DEFI_PROTOCOL' ||
      addressClassification.role === 'NFT_MARKETPLACE' ||
      addressClassification.role === 'INFRASTRUCTURE') {
    return {
      isSweeperBot: false,
      confidence: 95,
      verdict: addressClassification.role === 'EXCHANGE_INFRASTRUCTURE' ? 'EXCHANGE_BEHAVIOR' : 'NO_EVIDENCE',
      shouldAlert: false,
      alertSeverity: 'INFORMATIONAL',
      userMessage: `This address is classified as ${addressClassification.entityName || addressClassification.role}. Rapid fund forwarding is expected behavior and does not indicate a security threat.`,
      technicalDetails: addressClassification.evidenceReasons,
      recommendation: 'No action required. This is normal operational behavior.',
    };
  }
  
  // ============================================
  // RULE 2: Confirmed drainer = ALWAYS alert
  // ============================================
  if (addressClassification.role === 'CONFIRMED_SWEEPER_BOT') {
    return {
      isSweeperBot: true,
      confidence: 99,
      verdict: 'CONFIRMED_SWEEPER',
      shouldAlert: true,
      alertSeverity: 'CRITICAL',
      userMessage: '🚨 CONFIRMED THREAT: This address is a known malicious sweeper bot. Your private key may be compromised. DO NOT send any more funds to this wallet.',
      technicalDetails: [...addressClassification.evidenceReasons, ...signals.details],
      recommendation: 'Immediately transfer any remaining assets to a new wallet with a fresh seed phrase.',
    };
  }
  
  // ============================================
  // RULE 3: Multiple signals required for sweeper classification
  // ============================================
  if (signals.signalCount >= 2) {
    // High confidence if destination is known drainer
    if (signals.destinationIsKnownDrainer) {
      return {
        isSweeperBot: true,
        confidence: 90,
        verdict: 'CONFIRMED_SWEEPER',
        shouldAlert: true,
        alertSeverity: 'CRITICAL',
        userMessage: '🚨 SWEEPER BOT DETECTED: Multiple malicious indicators found. Funds are being forwarded to a known attacker address.',
        technicalDetails: signals.details,
        recommendation: 'Your wallet is likely compromised. Create a new wallet with a fresh seed phrase immediately.',
      };
    }
    
    // High confidence with multiple corroborating signals
    if (signals.signalCount >= 3) {
      return {
        isSweeperBot: true,
        confidence: 85,
        verdict: 'CONFIRMED_SWEEPER',
        shouldAlert: true,
        alertSeverity: 'CRITICAL',
        userMessage: '🚨 PROBABLE SWEEPER BOT: Multiple independent indicators suggest this wallet is being monitored by an automated attacker.',
        technicalDetails: signals.details,
        recommendation: 'High likelihood of compromise. Move assets to a new wallet.',
      };
    }
    
    // Moderate confidence with 2 signals
    return {
      isSweeperBot: true,
      confidence: 70,
      verdict: 'SUSPECTED_SWEEPER',
      shouldAlert: true,
      alertSeverity: 'HIGH',
      userMessage: '⚠️ SUSPICIOUS ACTIVITY: Potential sweeper bot behavior detected. This warrants investigation.',
      technicalDetails: signals.details,
      recommendation: 'Review recent transactions carefully. Consider moving assets if you did not initiate the activity.',
    };
  }
  
  // ============================================
  // RULE 4: Single signal = NOT enough for sweeper verdict
  // ============================================
  if (signals.signalCount === 1) {
    return {
      isSweeperBot: false,
      confidence: 40,
      verdict: 'NO_EVIDENCE',
      shouldAlert: false,
      alertSeverity: 'LOW',
      userMessage: 'Some unusual activity detected, but insufficient evidence for compromise. This may be normal user behavior.',
      technicalDetails: signals.details,
      recommendation: 'Continue monitoring. No immediate action required.',
    };
  }
  
  // ============================================
  // RULE 5: Automated forwarder (not malicious)
  // ============================================
  if (addressClassification.role === 'AUTOMATED_FORWARDER') {
    return {
      isSweeperBot: false,
      confidence: 75,
      verdict: 'AUTOMATED_FORWARDER',
      shouldAlert: false,
      alertSeverity: 'INFORMATIONAL',
      userMessage: 'Automated fund forwarding detected. This behavior is commonly used by exchanges, bridges, and infrastructure wallets and does not indicate compromise by itself.',
      technicalDetails: addressClassification.evidenceReasons,
      recommendation: 'If you set up this forwarding, no action needed. If unexpected, review your wallet security.',
    };
  }
  
  // ============================================
  // RULE 6: No evidence of malicious activity
  // ============================================
  return {
    isSweeperBot: false,
    confidence: 80,
    verdict: 'NO_EVIDENCE',
    shouldAlert: false,
    alertSeverity: 'INFORMATIONAL',
    userMessage: 'No confirmed sweeper bot activity detected. Rapid fund forwarding alone does not indicate compromise.',
    technicalDetails: ['No malicious signals detected'],
    recommendation: 'No action required. Continue normal security practices.',
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  EXCHANGE_PATTERNS,
  isKnownSafeDestination,
};

