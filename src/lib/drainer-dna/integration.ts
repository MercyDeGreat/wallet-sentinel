// ============================================
// DRAINER DNA INTEGRATION HELPERS
// ============================================
// Utilities to integrate the Drainer DNA Fingerprinting
// system with Securnex's existing detection infrastructure.
//
// This module provides:
// - Transaction data adapters
// - Existing detection enhancement
// - API response formatting

import { Chain, DetectedThreat, WalletAnalysisResult } from '@/types';
import {
  DrainerAttribution,
  DrainerFingerprint,
  ExtractionTransaction,
  ExtractionTokenTransfer,
  ExtractionApproval,
} from './types';
import { getDrainerDNAService } from './service';
import { generateAlertHeadline, generateShortSummary, formatStolenAmount } from './attribution';

// ============================================
// TRANSACTION DATA ADAPTERS
// ============================================

/**
 * Adapt raw transaction data from Etherscan/similar APIs
 * to the Drainer DNA extraction format.
 */
export function adaptTransactionData(
  rawTransactions: Array<{
    hash: string;
    from: string;
    to: string;
    value: string;
    input?: string;
    gasUsed?: string;
    gasPrice?: string;
    timeStamp: string | number;
    blockNumber: string | number;
    methodId?: string;
    isError?: string | boolean;
  }>
): ExtractionTransaction[] {
  return rawTransactions.map(tx => ({
    hash: tx.hash,
    from: tx.from,
    to: tx.to || '',
    value: tx.value,
    input: tx.input || '0x',
    gas_used: tx.gasUsed || '0',
    gas_price: tx.gasPrice || '0',
    timestamp: typeof tx.timeStamp === 'string' ? parseInt(tx.timeStamp) : tx.timeStamp,
    block_number: typeof tx.blockNumber === 'string' ? parseInt(tx.blockNumber) : tx.blockNumber,
    method_id: tx.methodId || tx.input?.slice(0, 10),
    is_error: tx.isError === '1' || tx.isError === true,
  }));
}

/**
 * Adapt token transfer data from Etherscan/similar APIs.
 */
export function adaptTokenTransferData(
  rawTransfers: Array<{
    hash: string;
    from: string;
    to: string;
    contractAddress: string;
    tokenSymbol?: string;
    value: string;
    timeStamp: string | number;
    blockNumber?: string | number;
    tokenType?: string;
  }>
): ExtractionTokenTransfer[] {
  return rawTransfers.map(t => ({
    hash: t.hash,
    from: t.from,
    to: t.to,
    token_address: t.contractAddress,
    token_symbol: t.tokenSymbol || 'UNKNOWN',
    value: t.value,
    timestamp: typeof t.timeStamp === 'string' ? parseInt(t.timeStamp) : t.timeStamp,
    block_number: t.blockNumber 
      ? (typeof t.blockNumber === 'string' ? parseInt(t.blockNumber) : t.blockNumber)
      : 0,
    token_type: (t.tokenType as 'ERC20' | 'ERC721' | 'ERC1155') || 'ERC20',
  }));
}

/**
 * Adapt approval data from parsed events.
 */
export function adaptApprovalData(
  rawApprovals: Array<{
    hash: string;
    owner: string;
    spender: string;
    tokenAddress: string;
    tokenSymbol?: string;
    amount: string;
    isUnlimited?: boolean;
    timestamp: number;
    blockNumber: number;
  }>
): ExtractionApproval[] {
  const UNLIMITED_THRESHOLD = BigInt('0xffffffffffffffffffffffffffffffff');
  
  return rawApprovals.map(a => ({
    hash: a.hash,
    owner: a.owner,
    spender: a.spender,
    token_address: a.tokenAddress,
    token_symbol: a.tokenSymbol || 'UNKNOWN',
    amount: a.amount,
    is_unlimited: a.isUnlimited ?? (BigInt(a.amount) >= UNLIMITED_THRESHOLD),
    timestamp: a.timestamp,
    block_number: a.blockNumber,
  }));
}

// ============================================
// DETECTION ENHANCEMENT
// ============================================

/**
 * Enhance a WalletAnalysisResult with Drainer DNA attribution.
 */
export async function enhanceWithDrainerDNA(
  analysisResult: WalletAnalysisResult,
  transactionData: {
    transactions: ExtractionTransaction[];
    tokenTransfers: ExtractionTokenTransfer[];
    approvals: ExtractionApproval[];
  }
): Promise<{
  result: WalletAnalysisResult;
  drainerDNA: {
    isDrainer: boolean;
    attribution: DrainerAttribution | null;
    fingerprint: DrainerFingerprint | null;
  } | null;
}> {
  const service = getDrainerDNAService();
  
  try {
    const dnaResult = await service.analyzeAddress(
      analysisResult.address,
      analysisResult.chain,
      transactionData
    );
    
    if (!dnaResult.success) {
      return {
        result: analysisResult,
        drainerDNA: null,
      };
    }
    
    // If drainer detected, enhance the analysis result
    if (dnaResult.is_drainer && dnaResult.attribution) {
      // Add drainer DNA info to the summary
      const enhancedSummary = `${analysisResult.summary}\n\n` +
        `🧬 DRAINER DNA MATCH: ${generateAlertHeadline(dnaResult.attribution)}\n` +
        `${generateShortSummary(dnaResult.attribution)}`;
      
      // Create a new threat entry for the drainer DNA match
      const drainerThreat: DetectedThreat = {
        id: `drainer-dna-${Date.now()}`,
        type: 'WALLET_DRAINER',
        severity: dnaResult.attribution.risk_level === 'CRITICAL' ? 'CRITICAL' :
                  dnaResult.attribution.risk_level === 'HIGH' ? 'HIGH' : 'MEDIUM',
        title: generateAlertHeadline(dnaResult.attribution),
        description: `This address matches the behavioral signature of ${dnaResult.attribution.attribution.family} (${dnaResult.attribution.attribution.variant}). ` +
                     `This drainer family has affected ${dnaResult.attribution.attribution.wallets_affected.toLocaleString()} wallets.`,
        technicalDetails: dnaResult.attribution.why_this_match.join('\n'),
        detectedAt: dnaResult.attribution.analyzed_at,
        relatedAddresses: dnaResult.attribution.related_addresses,
        relatedTransactions: [],
        ongoingRisk: dnaResult.attribution.attribution.is_active,
        attackerInfo: {
          address: analysisResult.address,
          type: 'DRAINER',
          confidence: dnaResult.attribution.attribution.confidence,
        },
      };
      
      return {
        result: {
          ...analysisResult,
          summary: enhancedSummary,
          detectedThreats: [drainerThreat, ...analysisResult.detectedThreats],
        },
        drainerDNA: {
          isDrainer: true,
          attribution: dnaResult.attribution,
          fingerprint: dnaResult.fingerprint,
        },
      };
    }
    
    return {
      result: analysisResult,
      drainerDNA: {
        isDrainer: false,
        attribution: null,
        fingerprint: null,
      },
    };
  } catch (error) {
    console.error('[DrainerDNA] Enhancement failed:', error);
    return {
      result: analysisResult,
      drainerDNA: null,
    };
  }
}

// ============================================
// API RESPONSE FORMATTERS
// ============================================

/**
 * Format Drainer DNA result for API response.
 */
export function formatDrainerDNAForAPI(
  attribution: DrainerAttribution | null,
  fingerprint: DrainerFingerprint | null
): object | null {
  if (!attribution) return null;
  
  return {
    threat_type: 'drainer',
    attribution: {
      family: attribution.attribution.family,
      variant: attribution.attribution.variant,
      confidence: attribution.attribution.confidence,
      wallets_affected: attribution.attribution.wallets_affected,
      chains: attribution.attribution.chains,
      active_since: attribution.attribution.active_since,
    },
    why_this_match: attribution.why_this_match,
    signature_summary: {
      approval_pattern: attribution.signature_summary.approval_pattern,
      timing_pattern: attribution.signature_summary.timing_pattern,
      routing_pattern: attribution.signature_summary.routing_pattern,
    },
    risk_level: attribution.risk_level,
    ...(fingerprint && {
      fingerprint_id: fingerprint.fingerprint_id,
      fingerprint_version: fingerprint.version,
    }),
  };
}

/**
 * Generate UI-ready display data from attribution.
 */
export function generateDisplayData(attribution: DrainerAttribution): {
  headline: string;
  subtitle: string;
  stats: Array<{ label: string; value: string }>;
  badges: Array<{ text: string; color: 'red' | 'orange' | 'yellow' | 'blue' }>;
} {
  const { family, variant, confidence, wallets_affected, chains, active_since, total_stolen_usd, is_active } = attribution.attribution;
  
  return {
    headline: `⚠️ Drainer DNA Match`,
    subtitle: `Matches ${family} – ${variant}`,
    stats: [
      { label: 'Victims', value: wallets_affected.toLocaleString() },
      { label: 'Chains', value: chains.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(', ') },
      { label: 'Active Since', value: active_since },
      { label: 'Confidence', value: `${confidence}%` },
      ...(total_stolen_usd > 0 ? [{ label: 'Total Stolen', value: formatStolenAmount(total_stolen_usd) }] : []),
    ],
    badges: [
      { text: family, color: 'red' as const },
      { text: variant, color: 'orange' as const },
      ...(is_active ? [{ text: 'Active', color: 'red' as const }] : []),
      { text: `${confidence}% match`, color: confidence >= 85 ? 'red' as const : 'yellow' as const },
    ],
  };
}

// ============================================
// QUICK CHECK HELPERS
// ============================================

/**
 * Quick check if an address is a known drainer (no behavioral analysis).
 */
export function isKnownDrainerAddress(address: string): boolean {
  const service = getDrainerDNAService();
  return service.isKnownDrainerAddress(address);
}

/**
 * Get family info for a known drainer address.
 */
export function getKnownDrainerFamily(address: string): { familyId: string; familyName: string } | null {
  const service = getDrainerDNAService();
  return service.getKnownDrainerFamily(address);
}

// All functions are exported inline above
