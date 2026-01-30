// ============================================
// DRAINER DNA EXTRACTION PIPELINE
// ============================================
// Extracts behavioral and structural features from
// transaction data to build drainer fingerprints.
//
// Pipeline stages:
// 1. Extract approval abuse patterns
// 2. Extract transaction sequencing
// 3. Extract timing patterns
// 4. Extract routing behavior
// 5. Extract code features
// 6. Normalize into feature vector

import { Chain } from '@/types';
import {
  FingerprintFeatures,
  DrainerFeatureVector,
  FingerprintExtractionInput,
  ExtractionTransaction,
  ExtractionTokenTransfer,
  ExtractionApproval,
  ApprovalBehavior,
  ApprovalTarget,
  TransferTiming,
  GasProfile,
  RoutingBehavior,
  DestinationCluster,
  CodeFeatures,
  CallPattern,
  VictimSelectionPattern,
  EvasionTechnique,
  PhishingMethod,
} from './types';

// ============================================
// CONSTANTS
// ============================================

const UNLIMITED_APPROVAL_THRESHOLD = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff') / BigInt(2);
const PERMIT2_ADDRESS = '0x000000000022d473030f116ddee9f6b43ac78ba3';
const RAPID_DRAIN_THRESHOLD_SECONDS = 300; // 5 minutes
const SAME_BLOCK_THRESHOLD = 0; // Same block

// Known method selectors
const METHOD_SELECTORS = {
  approve: '0x095ea7b3',
  transfer: '0xa9059cbb',
  transferFrom: '0x23b872dd',
  setApprovalForAll: '0xa22cb465',
  safeTransferFrom: '0x42842e0e',
  safeTransferFromWithData: '0xb88d4fde',
  permit: '0xd505accf',
  permit2_permit: '0x2b67b570',
};

// ============================================
// MAIN EXTRACTION FUNCTION
// ============================================

/**
 * Extract fingerprint features from transaction data.
 */
export function extractFingerprintFeatures(
  input: FingerprintExtractionInput
): FingerprintFeatures {
  const { transactions, token_transfers, approvals, wallet_address, chain } = input;
  
  // Extract each feature category
  const call_patterns = extractCallPatterns(transactions);
  const method_sequences = extractMethodSequences(transactions);
  const function_selectors = extractFunctionSelectors(transactions);
  const approval_behavior = extractApprovalBehavior(approvals, token_transfers, transactions);
  const transfer_timing = extractTransferTiming(approvals, token_transfers, transactions);
  const gas_profile = extractGasProfile(transactions);
  const routing_behavior = extractRoutingBehavior(wallet_address, token_transfers, transactions, chain);
  const code_features = extractCodeFeatures(transactions, input.internal_transactions);
  const victim_selection = extractVictimSelectionPattern(transactions, token_transfers, approvals);
  const evasion_techniques = detectEvasionTechniques(transactions, token_transfers, routing_behavior);
  
  return {
    call_patterns,
    method_sequences,
    function_selectors,
    approval_behavior,
    transfer_timing,
    gas_profile,
    routing_behavior,
    code_features,
    victim_selection,
    evasion_techniques,
  };
}

// ============================================
// CALL PATTERN EXTRACTION
// ============================================

function extractCallPatterns(transactions: ExtractionTransaction[]): CallPattern[] {
  const patterns: CallPattern[] = [];
  const patternCounts = new Map<string, { sequence: string[]; count: number }>();
  
  // Group transactions by time windows (10 minutes)
  const windowSize = 600;
  const windows: ExtractionTransaction[][] = [];
  let currentWindow: ExtractionTransaction[] = [];
  let windowStart = transactions[0]?.timestamp || 0;
  
  for (const tx of transactions.sort((a, b) => a.timestamp - b.timestamp)) {
    if (tx.timestamp - windowStart > windowSize && currentWindow.length > 0) {
      windows.push(currentWindow);
      currentWindow = [];
      windowStart = tx.timestamp;
    }
    currentWindow.push(tx);
  }
  if (currentWindow.length > 0) {
    windows.push(currentWindow);
  }
  
  // Extract method sequences from each window
  for (const window of windows) {
    const methods = window
      .map(tx => getMethodName(tx.method_id || tx.input?.slice(0, 10)))
      .filter(Boolean) as string[];
    
    if (methods.length >= 2) {
      const signature = methods.join('→');
      const existing = patternCounts.get(signature);
      if (existing) {
        existing.count++;
      } else {
        patternCounts.set(signature, { sequence: methods, count: 1 });
      }
    }
  }
  
  // Convert to CallPattern objects
  let patternIndex = 0;
  for (const [signature, data] of patternCounts) {
    if (data.count >= 2) {
      patterns.push({
        pattern_id: `CP_${patternIndex++}`,
        description: `${signature} (observed ${data.count}x)`,
        method_sequence: data.sequence,
        frequency: data.count,
        confidence: Math.min(100, 50 + data.count * 10),
      });
    }
  }
  
  return patterns;
}

function getMethodName(selector: string | undefined): string | null {
  if (!selector) return null;
  const normalized = selector.toLowerCase();
  
  for (const [name, sel] of Object.entries(METHOD_SELECTORS)) {
    if (normalized === sel.toLowerCase()) return name;
  }
  
  return selector; // Return raw selector if unknown
}

// ============================================
// METHOD SEQUENCE EXTRACTION
// ============================================

function extractMethodSequences(transactions: ExtractionTransaction[]): string[][] {
  const sequences: string[][] = [];
  const sortedTxs = transactions.sort((a, b) => a.timestamp - b.timestamp);
  
  let currentSequence: string[] = [];
  let lastTimestamp = 0;
  
  for (const tx of sortedTxs) {
    const method = getMethodName(tx.method_id || tx.input?.slice(0, 10));
    if (!method) continue;
    
    // Start new sequence if gap > 10 minutes
    if (lastTimestamp > 0 && tx.timestamp - lastTimestamp > 600) {
      if (currentSequence.length >= 2) {
        sequences.push([...currentSequence]);
      }
      currentSequence = [];
    }
    
    currentSequence.push(method);
    lastTimestamp = tx.timestamp;
  }
  
  if (currentSequence.length >= 2) {
    sequences.push(currentSequence);
  }
  
  return sequences;
}

// ============================================
// FUNCTION SELECTOR EXTRACTION
// ============================================

function extractFunctionSelectors(transactions: ExtractionTransaction[]): string[] {
  const selectors = new Set<string>();
  
  for (const tx of transactions) {
    const selector = tx.method_id || tx.input?.slice(0, 10);
    if (selector && selector.length >= 10) {
      selectors.add(selector.toLowerCase());
    }
  }
  
  return [...selectors];
}

// ============================================
// APPROVAL BEHAVIOR EXTRACTION
// ============================================

function extractApprovalBehavior(
  approvals: ExtractionApproval[],
  transfers: ExtractionTokenTransfer[],
  transactions: ExtractionTransaction[]
): ApprovalBehavior {
  // Calculate unlimited approval rate
  const unlimitedCount = approvals.filter(a => a.is_unlimited).length;
  const unlimitedRate = approvals.length > 0 ? unlimitedCount / approvals.length : 0;
  
  // Identify approval targets
  const targetCounts = new Map<string, { count: number; type: 'TOKEN' | 'NFT' | 'DEFI' | 'UNKNOWN' }>();
  for (const approval of approvals) {
    const spender = approval.spender.toLowerCase();
    const existing = targetCounts.get(spender);
    if (existing) {
      existing.count++;
    } else {
      targetCounts.set(spender, { count: 1, type: 'UNKNOWN' });
    }
  }
  
  const approvalTargets: ApprovalTarget[] = [...targetCounts.entries()].map(([addr, data]) => ({
    contract_address: addr,
    contract_type: data.type,
    frequency: data.count,
  }));
  
  // Check for NFT targeting (setApprovalForAll)
  const targetsNfts = transactions.some(tx => {
    const selector = tx.method_id || tx.input?.slice(0, 10);
    return selector?.toLowerCase() === METHOD_SELECTORS.setApprovalForAll;
  });
  
  // Check for high-value token targeting
  const targetsHighValue = approvals.some(a => a.is_unlimited);
  
  // Calculate average time to drain after approval
  const drainDelays: number[] = [];
  for (const approval of approvals) {
    const subsequentDrain = transfers.find(t =>
      t.token_address.toLowerCase() === approval.token_address.toLowerCase() &&
      t.from.toLowerCase() === approval.owner.toLowerCase() &&
      t.timestamp > approval.timestamp
    );
    
    if (subsequentDrain) {
      drainDelays.push(subsequentDrain.timestamp - approval.timestamp);
    }
  }
  
  const avgTimeToDrain = drainDelays.length > 0
    ? drainDelays.reduce((a, b) => a + b, 0) / drainDelays.length
    : 0;
  
  const rapidDrainAfterApproval = drainDelays.some(d => d < RAPID_DRAIN_THRESHOLD_SECONDS);
  
  // Check for Permit2 usage
  const usesPermit2 = transactions.some(tx =>
    tx.to.toLowerCase() === PERMIT2_ADDRESS.toLowerCase()
  );
  
  // Check for permit signatures
  const usesPermitSignatures = transactions.some(tx => {
    const selector = tx.method_id || tx.input?.slice(0, 10);
    return selector?.toLowerCase() === METHOD_SELECTORS.permit ||
           selector?.toLowerCase() === METHOD_SELECTORS.permit2_permit;
  });
  
  return {
    prefers_unlimited_approvals: unlimitedRate > 0.8,
    unlimited_approval_rate: unlimitedRate,
    approval_targets: approvalTargets,
    targets_high_value_tokens: targetsHighValue,
    targets_nfts: targetsNfts,
    targets_all_assets: targetsHighValue && targetsNfts,
    avoids_batch_revokes: true, // Assume true for drainers
    rapid_drain_after_approval: rapidDrainAfterApproval,
    avg_time_to_drain_seconds: avgTimeToDrain,
    uses_permit2: usesPermit2,
    uses_permit_signatures: usesPermitSignatures,
  };
}

// ============================================
// TRANSFER TIMING EXTRACTION
// ============================================

function extractTransferTiming(
  approvals: ExtractionApproval[],
  transfers: ExtractionTokenTransfer[],
  transactions: ExtractionTransaction[]
): TransferTiming {
  // Calculate drain delays from approval to transfer
  const drainDelays: number[] = [];
  const blockDelays: number[] = [];
  
  for (const approval of approvals) {
    const subsequentTransfers = transfers.filter(t =>
      t.token_address.toLowerCase() === approval.token_address.toLowerCase() &&
      t.from.toLowerCase() === approval.owner.toLowerCase() &&
      t.timestamp > approval.timestamp
    );
    
    for (const transfer of subsequentTransfers) {
      drainDelays.push(transfer.timestamp - approval.timestamp);
      if (transfer.block_number && approval.block_number) {
        blockDelays.push(transfer.block_number - approval.block_number);
      }
    }
  }
  
  const avgDelay = drainDelays.length > 0
    ? drainDelays.reduce((a, b) => a + b, 0) / drainDelays.length
    : 0;
  
  const minDelay = drainDelays.length > 0 ? Math.min(...drainDelays) : 0;
  const maxDelay = drainDelays.length > 0 ? Math.max(...drainDelays) : 0;
  
  const avgBlockDelay = blockDelays.length > 0
    ? blockDelays.reduce((a, b) => a + b, 0) / blockDelays.length
    : 0;
  
  // Calculate sweep window (time from first to last drain)
  const drainTimestamps = transfers
    .filter(t => t.from.toLowerCase() !== t.to.toLowerCase())
    .map(t => t.timestamp)
    .sort((a, b) => a - b);
  
  const sweepWindow = drainTimestamps.length >= 2
    ? drainTimestamps[drainTimestamps.length - 1] - drainTimestamps[0]
    : 0;
  
  // Detect same-block drains
  const sameBlockDrain = blockDelays.some(d => d === 0);
  
  // Detect batched sweeps (multiple tokens drained in sequence)
  const batchedSweeps = transfers.length > 1 && sweepWindow < 300;
  
  return {
    avg_delay_seconds: avgDelay,
    min_delay_seconds: minDelay,
    max_delay_seconds: maxDelay,
    sweep_window_seconds: sweepWindow,
    immediate_sweep: minDelay < 60,
    batched_sweeps: batchedSweeps,
    timed_sweeps: false, // Would need more analysis
    same_block_drain: sameBlockDrain,
    avg_block_delay: avgBlockDelay,
  };
}

// ============================================
// GAS PROFILE EXTRACTION
// ============================================

function extractGasProfile(transactions: ExtractionTransaction[]): GasProfile {
  if (transactions.length === 0) {
    return {
      gas_spike_pattern: false,
      priority_fee_style: 'NORMAL',
      avg_gas_used: 0,
      gas_variance: 0,
      uses_flashbots: false,
      uses_private_mempool: false,
      prefers_low_gas_periods: false,
    };
  }
  
  // Calculate gas metrics
  const gasUsedValues = transactions
    .map(tx => parseFloat(tx.gas_used || '0'))
    .filter(g => g > 0);
  
  const gasPriceValues = transactions
    .map(tx => parseFloat(tx.gas_price || '0'))
    .filter(g => g > 0);
  
  const avgGasUsed = gasUsedValues.length > 0
    ? gasUsedValues.reduce((a, b) => a + b, 0) / gasUsedValues.length
    : 0;
  
  // Calculate variance
  const variance = gasUsedValues.length > 1
    ? gasUsedValues.reduce((sum, g) => sum + Math.pow(g - avgGasUsed, 2), 0) / gasUsedValues.length
    : 0;
  const gasVariance = avgGasUsed > 0 ? Math.sqrt(variance) / avgGasUsed : 0;
  
  // Detect gas spike pattern (using above-average gas prices)
  const avgGasPrice = gasPriceValues.length > 0
    ? gasPriceValues.reduce((a, b) => a + b, 0) / gasPriceValues.length
    : 0;
  const gasSpikePattern = gasPriceValues.some(g => g > avgGasPrice * 2);
  
  // Determine priority fee style
  let priorityFeeStyle: 'AGGRESSIVE' | 'NORMAL' | 'CONSERVATIVE' | 'DYNAMIC' = 'NORMAL';
  if (gasSpikePattern) {
    priorityFeeStyle = 'AGGRESSIVE';
  } else if (gasVariance > 0.5) {
    priorityFeeStyle = 'DYNAMIC';
  } else if (avgGasPrice > 0 && gasPriceValues.every(g => g < avgGasPrice * 0.8)) {
    priorityFeeStyle = 'CONSERVATIVE';
  }
  
  return {
    gas_spike_pattern: gasSpikePattern,
    priority_fee_style: priorityFeeStyle,
    avg_gas_used: avgGasUsed,
    gas_variance: gasVariance,
    uses_flashbots: false, // Would need mempool analysis
    uses_private_mempool: false, // Would need mempool analysis
    prefers_low_gas_periods: priorityFeeStyle === 'CONSERVATIVE',
  };
}

// ============================================
// ROUTING BEHAVIOR EXTRACTION
// ============================================

function extractRoutingBehavior(
  walletAddress: string,
  transfers: ExtractionTokenTransfer[],
  transactions: ExtractionTransaction[],
  chain: Chain
): RoutingBehavior {
  const normalizedWallet = walletAddress.toLowerCase();
  
  // Find outbound destinations
  const outboundDestinations = new Map<string, { count: number; totalValue: number }>();
  
  for (const transfer of transfers) {
    if (transfer.from.toLowerCase() === normalizedWallet) {
      const dest = transfer.to.toLowerCase();
      const existing = outboundDestinations.get(dest);
      const value = parseFloat(transfer.value) || 0;
      
      if (existing) {
        existing.count++;
        existing.totalValue += value;
      } else {
        outboundDestinations.set(dest, { count: 1, totalValue: value });
      }
    }
  }
  
  for (const tx of transactions) {
    if (tx.from.toLowerCase() === normalizedWallet && tx.to) {
      const dest = tx.to.toLowerCase();
      const existing = outboundDestinations.get(dest);
      const value = parseFloat(tx.value) || 0;
      
      if (existing) {
        existing.count++;
        existing.totalValue += value;
      } else {
        outboundDestinations.set(dest, { count: 1, totalValue: value });
      }
    }
  }
  
  // Build destination clusters
  const destinationClusters: DestinationCluster[] = [];
  let clusterIndex = 0;
  
  for (const [addr, data] of outboundDestinations) {
    if (data.count >= 2) {
      destinationClusters.push({
        cluster_id: `DC_${clusterIndex++}`,
        addresses: [addr],
        total_received_usd: data.totalValue,
        transaction_count: data.count,
        cluster_type: 'UNKNOWN',
      });
    }
  }
  
  // Find primary destination
  const sortedDests = [...outboundDestinations.entries()]
    .sort((a, b) => b[1].count - a[1].count);
  const primaryDestination = sortedDests[0]?.[0] || '';
  
  // Estimate hop count
  const uniqueDestinations = outboundDestinations.size;
  const hopCount = Math.min(uniqueDestinations, 5);
  
  return {
    hop_count: hopCount,
    min_hops: 1,
    max_hops: Math.max(hopCount, 2),
    destination_clusters: destinationClusters,
    primary_destination: primaryDestination,
    uses_mixers: false, // Would need mixer address database
    uses_bridges: false, // Would need bridge address database
    uses_dex_swaps: false, // Would need DEX address database
    direct_to_cex: false, // Would need CEX address database
    uses_intermediary_wallets: uniqueDestinations > 1,
    intermediary_count: Math.max(0, uniqueDestinations - 1),
    bridges_to_chains: [],
    primary_exit_chain: chain,
  };
}

// ============================================
// CODE FEATURES EXTRACTION
// ============================================

function extractCodeFeatures(
  transactions: ExtractionTransaction[],
  internalTxs?: { call_type: string }[]
): CodeFeatures {
  // Check for delegatecall patterns
  const delegatecallPatterns = internalTxs?.some(tx => tx.call_type === 'delegatecall') || false;
  
  // Check for create2 usage
  const usesCreate2 = internalTxs?.some(tx => tx.call_type === 'create2') || false;
  
  return {
    proxy_usage: delegatecallPatterns,
    proxy_types: delegatecallPatterns ? ['CUSTOM'] : ['NONE'],
    bytecode_hashes: [],
    bytecode_similarity_clusters: [],
    delegatecall_patterns: delegatecallPatterns,
    uses_create2: usesCreate2,
    uses_selfdestruct: false,
    is_verified: false,
    has_source_code: false,
    opcode_frequency: {},
  };
}

// ============================================
// VICTIM SELECTION PATTERN EXTRACTION
// ============================================

function extractVictimSelectionPattern(
  transactions: ExtractionTransaction[],
  transfers: ExtractionTokenTransfer[],
  approvals: ExtractionApproval[]
): VictimSelectionPattern {
  // Check for NFT targeting
  const targetsNftHolders = transfers.some(t => t.token_type === 'ERC721' || t.token_type === 'ERC1155');
  
  // Check for high-value targeting
  const targetsHighValue = approvals.some(a => a.is_unlimited);
  
  // Analyze activity hours (UTC)
  const hours = transactions.map(tx => {
    const date = new Date(tx.timestamp * 1000);
    return date.getUTCHours();
  });
  
  const hourCounts = new Map<number, number>();
  for (const hour of hours) {
    hourCounts.set(hour, (hourCounts.get(hour) || 0) + 1);
  }
  
  const sortedHours = [...hourCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([hour]) => hour);
  
  // Find peak activity day
  const days = transactions.map(tx => {
    const date = new Date(tx.timestamp * 1000);
    return date.getUTCDay();
  });
  
  const dayCounts = new Map<number, number>();
  for (const day of days) {
    dayCounts.set(day, (dayCounts.get(day) || 0) + 1);
  }
  
  const peakDay = [...dayCounts.entries()]
    .sort((a, b) => b[1] - a[1])[0]?.[0] || 0;
  
  return {
    targets_high_value_wallets: targetsHighValue,
    targets_nft_holders: targetsNftHolders,
    targets_defi_users: false,
    targets_new_wallets: false,
    phishing_method: null,
    airdrop_scam: false,
    fake_mint: false,
    activity_hours_utc: sortedHours,
    peak_activity_day: peakDay,
  };
}

// ============================================
// EVASION TECHNIQUE DETECTION
// ============================================

function detectEvasionTechniques(
  transactions: ExtractionTransaction[],
  transfers: ExtractionTokenTransfer[],
  routing: RoutingBehavior
): EvasionTechnique[] {
  const techniques: EvasionTechnique[] = [];
  
  // Check for multi-hop routing
  if (routing.hop_count >= 3) {
    techniques.push({
      technique_id: 'MULTI_HOP_ROUTING',
      name: 'Multi-Hop Routing',
      description: 'Uses multiple intermediary wallets to obfuscate fund flow',
      detection_difficulty: 'MEDIUM',
    });
  }
  
  // Check for rapid fund movement
  const sortedTxs = transactions.sort((a, b) => a.timestamp - b.timestamp);
  if (sortedTxs.length >= 2) {
    const firstTx = sortedTxs[0];
    const lastTx = sortedTxs[sortedTxs.length - 1];
    if (lastTx.timestamp - firstTx.timestamp < 300) {
      techniques.push({
        technique_id: 'RAPID_EXECUTION',
        name: 'Rapid Execution',
        description: 'Completes drain within 5 minutes to avoid detection',
        detection_difficulty: 'LOW',
      });
    }
  }
  
  // Check for destination diversity
  if (routing.destination_clusters.length >= 3) {
    techniques.push({
      technique_id: 'DESTINATION_DIVERSITY',
      name: 'Destination Diversity',
      description: 'Spreads funds across multiple destinations',
      detection_difficulty: 'MEDIUM',
    });
  }
  
  return techniques;
}

// ============================================
// FEATURE VECTOR NORMALIZATION
// ============================================

/**
 * Normalize extracted features into a feature vector for clustering.
 */
export function normalizeToFeatureVector(
  sourceAddress: string,
  chain: Chain,
  features: FingerprintFeatures,
  rawMetrics: {
    total_victims: number;
    total_stolen_usd: number;
    active_days: number;
    unique_destinations: number;
  }
): DrainerFeatureVector {
  // Normalize timing features (0-1 scale)
  const maxDelay = 3600; // 1 hour max
  const avgDrainDelayNormalized = Math.min(1, features.transfer_timing.avg_delay_seconds / maxDelay);
  const sweepWindowNormalized = Math.min(1, features.transfer_timing.sweep_window_seconds / maxDelay);
  
  // Normalize gas features
  const gasAggressiveness = features.gas_profile.priority_fee_style === 'AGGRESSIVE' ? 1 :
    features.gas_profile.priority_fee_style === 'DYNAMIC' ? 0.5 : 0;
  const gasConsistency = 1 - Math.min(1, features.gas_profile.gas_variance);
  
  // Normalize routing features
  const maxHops = 10;
  const hopCountNormalized = Math.min(1, features.routing_behavior.hop_count / maxHops);
  
  return {
    source_address: sourceAddress,
    chain,
    extracted_at: new Date().toISOString(),
    features: {
      avg_drain_delay_normalized: avgDrainDelayNormalized,
      sweep_window_normalized: sweepWindowNormalized,
      same_block_drain: features.transfer_timing.same_block_drain ? 1 : 0,
      unlimited_approval_rate: features.approval_behavior.unlimited_approval_rate,
      rapid_drain_rate: features.approval_behavior.rapid_drain_after_approval ? 1 : 0,
      permit2_usage: features.approval_behavior.uses_permit2 ? 1 : 0,
      gas_aggressiveness: gasAggressiveness,
      gas_consistency: gasConsistency,
      hop_count_normalized: hopCountNormalized,
      uses_mixers: features.routing_behavior.uses_mixers ? 1 : 0,
      uses_bridges: features.routing_behavior.uses_bridges ? 1 : 0,
      direct_cex_rate: features.routing_behavior.direct_to_cex ? 1 : 0,
      proxy_usage: features.code_features.proxy_usage ? 1 : 0,
      delegatecall_usage: features.code_features.delegatecall_patterns ? 1 : 0,
      high_value_targeting: features.victim_selection.targets_high_value_wallets ? 1 : 0,
      nft_targeting: features.victim_selection.targets_nft_holders ? 1 : 0,
    },
    raw_metrics: rawMetrics,
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  UNLIMITED_APPROVAL_THRESHOLD,
  PERMIT2_ADDRESS,
  RAPID_DRAIN_THRESHOLD_SECONDS,
  METHOD_SELECTORS,
};
