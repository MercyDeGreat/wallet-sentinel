// ============================================
// DRAINER DNA ATTRIBUTION ENGINE
// ============================================
// Generates user-facing attribution results from
// drainer fingerprints for display in Securnex UI.
//
// Converts technical fingerprints into:
// - Human-readable family/variant names
// - Impact summaries
// - Match explanations
// - Risk assessments

import { Chain } from '@/types';
import {
  DrainerFingerprint,
  DrainerFamilyId,
  DrainerAttribution,
  ClusteringResult,
  FingerprintFeatures,
} from './types';
import { getDrainerFamilyProfile, getDrainerFamilyName } from './family-profiles';

// ============================================
// MAIN ATTRIBUTION FUNCTION
// ============================================

/**
 * Generate a complete attribution result from a drainer fingerprint.
 */
export function generateAttribution(
  fingerprint: DrainerFingerprint,
  clusteringResult: ClusteringResult
): DrainerAttribution {
  const familyProfile = getDrainerFamilyProfile(fingerprint.family_id);
  const humanFamilyName = formatFamilyName(fingerprint.family_id);
  const humanVariantName = formatVariantName(fingerprint.variant_id);
  
  // Determine if this is a new/unknown drainer
  const isNewDrainer = fingerprint.family_id === 'unknown';
  
  // Determine if still active (activity within 30 days)
  const isActive = fingerprint.last_activity_days_ago <= 30;
  
  // Generate match explanations
  const whyThisMatch = generateMatchExplanations(fingerprint, clusteringResult);
  
  // Generate signature summary
  const signatureSummary = generateSignatureSummary(fingerprint.fingerprint_features);
  
  // Assess risk level
  const riskLevel = assessRiskLevel(fingerprint, isActive);
  
  // Format dates
  const activeSince = formatDate(fingerprint.first_seen);
  const lastSeen = formatDate(fingerprint.last_seen);
  
  return {
    threat_type: 'drainer',
    is_new_drainer: isNewDrainer,
    attribution: {
      family: humanFamilyName,
      family_id: fingerprint.family_id,
      variant: humanVariantName,
      variant_id: fingerprint.variant_id,
      confidence: fingerprint.confidence_score,
      wallets_affected: fingerprint.wallet_count,
      total_stolen_usd: fingerprint.total_stolen_usd,
      chains: fingerprint.chains,
      primary_chain: fingerprint.primary_chain,
      active_since: activeSince,
      last_seen: lastSeen,
      is_active: isActive,
    },
    why_this_match: whyThisMatch,
    signature_summary: signatureSummary,
    related_addresses: familyProfile.known_aggregation_wallets,
    known_aliases: getKnownAliases(fingerprint.family_id),
    risk_level: riskLevel,
    analyzed_at: new Date().toISOString(),
  };
}

// ============================================
// NAME FORMATTING
// ============================================

function formatFamilyName(familyId: DrainerFamilyId): string {
  const nameMap: Record<DrainerFamilyId, string> = {
    pinkdrainer: 'PinkDrainer',
    infernodrainer: 'Inferno Drainer',
    angeldrainer: 'Angel Drainer',
    monkeydrainer: 'Monkey Drainer',
    venomdrainer: 'Venom Drainer',
    msdrainer: 'MS Drainer',
    acedrainer: 'Ace Drainer',
    chick_drainer: 'Chick Drainer',
    raccoon_stealer: 'Raccoon Stealer',
    unknown: 'Unknown Drainer',
  };
  
  return nameMap[familyId] || 'Unknown Drainer';
}

function formatVariantName(variantId: string): string {
  // Convert technical variant ID to human-readable format
  if (variantId.startsWith('v')) {
    const num = variantId.slice(1);
    return `Variant #${num}`;
  }
  
  if (variantId.includes('-')) {
    // Chain-specific variant like "base-v2"
    const parts = variantId.split('-');
    const chain = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);
    const version = parts[1]?.startsWith('v') ? `#${parts[1].slice(1)}` : parts[1];
    return `${chain} ${version ? `Variant ${version}` : 'Variant'}`;
  }
  
  return variantId;
}

function formatDate(isoString: string): string {
  try {
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return isoString;
  }
}

// ============================================
// MATCH EXPLANATION GENERATION
// ============================================

function generateMatchExplanations(
  fingerprint: DrainerFingerprint,
  clusteringResult: ClusteringResult
): string[] {
  const explanations: string[] = [];
  
  // Add clustering reasons
  for (const reason of clusteringResult.assignment_reasons.slice(0, 3)) {
    explanations.push(reason);
  }
  
  // Add destination cluster insight
  if (clusteringResult.routing_similarity >= 0.7) {
    const familyName = formatFamilyName(fingerprint.family_id);
    explanations.push(
      `Same destination cluster as ${Math.round(clusteringResult.routing_similarity * 100)}% of ${familyName} cases`
    );
  }
  
  // Add timing insight
  if (fingerprint.fingerprint_features.transfer_timing.same_block_drain) {
    explanations.push('Uses same-block drainage technique');
  }
  
  // Add approval insight
  if (fingerprint.fingerprint_features.approval_behavior.uses_permit2) {
    explanations.push('Utilizes Permit2 for gasless approvals');
  }
  
  // Add gas insight
  if (fingerprint.fingerprint_features.gas_profile.priority_fee_style === 'AGGRESSIVE') {
    explanations.push('Gas usage pattern matches known signature');
  }
  
  // Limit to 5 explanations
  return explanations.slice(0, 5);
}

// ============================================
// SIGNATURE SUMMARY GENERATION
// ============================================

function generateSignatureSummary(features: FingerprintFeatures): {
  approval_pattern: string;
  timing_pattern: string;
  routing_pattern: string;
  distinctive_features: string[];
} {
  // Generate approval pattern description
  let approvalPattern = '';
  if (features.approval_behavior.uses_permit2) {
    approvalPattern = 'Permit2 gasless approvals with rapid execution';
  } else if (features.approval_behavior.prefers_unlimited_approvals) {
    approvalPattern = 'Unlimited token approvals targeting high-value assets';
  } else {
    approvalPattern = 'Standard approval abuse pattern';
  }
  
  if (features.approval_behavior.targets_nfts) {
    approvalPattern += ', includes NFT setApprovalForAll';
  }
  
  // Generate timing pattern description
  let timingPattern = '';
  if (features.transfer_timing.same_block_drain) {
    timingPattern = 'Same-block drainage (automated MEV-style attack)';
  } else if (features.transfer_timing.immediate_sweep) {
    timingPattern = `Immediate sweep within ${Math.round(features.transfer_timing.avg_delay_seconds)}s of approval`;
  } else if (features.transfer_timing.batched_sweeps) {
    timingPattern = 'Batched multi-asset sweep pattern';
  } else {
    timingPattern = `Average ${Math.round(features.transfer_timing.avg_delay_seconds / 60)}min drain delay`;
  }
  
  // Generate routing pattern description
  let routingPattern = '';
  if (features.routing_behavior.uses_mixers) {
    routingPattern = 'Funds routed through mixing services';
  } else if (features.routing_behavior.direct_to_cex) {
    routingPattern = 'Direct exit to centralized exchanges';
  } else if (features.routing_behavior.uses_bridges) {
    routingPattern = `Cross-chain bridging to ${features.routing_behavior.bridges_to_chains.join(', ')}`;
  } else if (features.routing_behavior.hop_count >= 3) {
    routingPattern = `${features.routing_behavior.hop_count}-hop intermediary routing`;
  } else {
    routingPattern = 'Simple aggregation wallet routing';
  }
  
  // Generate distinctive features list
  const distinctiveFeatures: string[] = [];
  
  if (features.approval_behavior.uses_permit2) {
    distinctiveFeatures.push('Permit2 abuse');
  }
  if (features.transfer_timing.same_block_drain) {
    distinctiveFeatures.push('Same-block execution');
  }
  if (features.gas_profile.priority_fee_style === 'AGGRESSIVE') {
    distinctiveFeatures.push('Aggressive gas bidding');
  }
  if (features.routing_behavior.uses_mixers) {
    distinctiveFeatures.push('Mixer obfuscation');
  }
  if (features.code_features.proxy_usage) {
    distinctiveFeatures.push('Proxy contract deployment');
  }
  if (features.approval_behavior.targets_nfts && features.approval_behavior.targets_high_value_tokens) {
    distinctiveFeatures.push('Multi-asset targeting');
  }
  if (features.evasion_techniques.length > 0) {
    distinctiveFeatures.push(...features.evasion_techniques.slice(0, 2).map(t => t.name));
  }
  
  return {
    approval_pattern: approvalPattern,
    timing_pattern: timingPattern,
    routing_pattern: routingPattern,
    distinctive_features: distinctiveFeatures.slice(0, 5),
  };
}

// ============================================
// RISK ASSESSMENT
// ============================================

function assessRiskLevel(
  fingerprint: DrainerFingerprint,
  isActive: boolean
): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  let riskScore = 0;
  
  // Active status (major factor)
  if (isActive) riskScore += 40;
  
  // Confidence score
  if (fingerprint.confidence_score >= 85) riskScore += 25;
  else if (fingerprint.confidence_score >= 70) riskScore += 15;
  
  // Wallet count (scale of impact)
  if (fingerprint.wallet_count >= 1000) riskScore += 20;
  else if (fingerprint.wallet_count >= 100) riskScore += 10;
  
  // Sophisticated techniques
  const features = fingerprint.fingerprint_features;
  if (features.approval_behavior.uses_permit2) riskScore += 10;
  if (features.transfer_timing.same_block_drain) riskScore += 10;
  if (features.routing_behavior.uses_mixers) riskScore += 5;
  
  // Map score to risk level
  if (riskScore >= 70) return 'CRITICAL';
  if (riskScore >= 50) return 'HIGH';
  if (riskScore >= 30) return 'MEDIUM';
  return 'LOW';
}

// ============================================
// KNOWN ALIASES
// ============================================

function getKnownAliases(familyId: DrainerFamilyId): string[] {
  const aliasMap: Record<DrainerFamilyId, string[]> = {
    pinkdrainer: ['Pink', 'PinkD', 'Pink Drainer'],
    infernodrainer: ['Inferno', 'InfernoDrain'],
    angeldrainer: ['Angel', 'AngelD'],
    monkeydrainer: ['Monkey', 'MD'],
    venomdrainer: ['Venom'],
    msdrainer: ['MS', 'MultiSig Drainer'],
    acedrainer: ['Ace'],
    chick_drainer: ['Chick'],
    raccoon_stealer: ['Raccoon'],
    unknown: [],
  };
  
  return aliasMap[familyId] || [];
}

// ============================================
// UI DISPLAY HELPERS
// ============================================

/**
 * Generate a short summary line for compact display.
 */
export function generateShortSummary(attribution: DrainerAttribution): string {
  const { family, variant, wallets_affected, primary_chain } = attribution.attribution;
  return `${family} – ${variant} | ${wallets_affected.toLocaleString()} victims | ${primary_chain.charAt(0).toUpperCase() + primary_chain.slice(1)}`;
}

/**
 * Generate the main alert headline.
 */
export function generateAlertHeadline(attribution: DrainerAttribution): string {
  return `Matches ${attribution.attribution.family} – ${attribution.attribution.variant}`;
}

/**
 * Generate impact statistics for display.
 */
export function generateImpactStats(attribution: DrainerAttribution): {
  victims: string;
  chains: string;
  active_since: string;
  confidence: string;
} {
  const { wallets_affected, chains, active_since, confidence } = attribution.attribution;
  
  return {
    victims: `Seen in ${wallets_affected.toLocaleString()} wallets`,
    chains: `Active on ${chains.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(', ')}`,
    active_since: `Active since ${active_since}`,
    confidence: `Confidence: ${confidence}%`,
  };
}

/**
 * Format total stolen amount for display.
 */
export function formatStolenAmount(amount: number): string {
  if (amount >= 1000000000) {
    return `$${(amount / 1000000000).toFixed(1)}B`;
  }
  if (amount >= 1000000) {
    return `$${(amount / 1000000).toFixed(1)}M`;
  }
  if (amount >= 1000) {
    return `$${(amount / 1000).toFixed(1)}K`;
  }
  return `$${amount.toFixed(0)}`;
}

// ============================================
// API RESPONSE FORMATTER
// ============================================

/**
 * Format attribution for API response.
 */
export function formatAttributionForAPI(attribution: DrainerAttribution): object {
  return {
    threat_type: attribution.threat_type,
    attribution: {
      family: attribution.attribution.family,
      variant: attribution.attribution.variant,
      confidence: attribution.attribution.confidence,
      wallets_affected: attribution.attribution.wallets_affected,
      chains: attribution.attribution.chains,
      active_since: attribution.attribution.active_since,
    },
    why_this_match: attribution.why_this_match,
  };
}

// ============================================
// EXPORTS
// ============================================

export {
  formatFamilyName,
  formatVariantName,
  formatDate,
  assessRiskLevel,
};
