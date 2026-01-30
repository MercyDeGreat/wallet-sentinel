// ============================================
// DRAINER DNA VARIANT CLUSTERING
// ============================================
// Groups drainers by behavioral similarity and assigns
// family/variant identifications based on fingerprint matching.
//
// Clustering approach:
// 1. Compare feature vectors using weighted similarity
// 2. Match against known family profiles
// 3. Assign family_id and variant_id
// 4. Calculate confidence scores

import { Chain } from '@/types';
import {
  DrainerFamilyId,
  DrainerVariantId,
  DrainerFeatureVector,
  FingerprintFeatures,
  ClusteringResult,
  DrainerFingerprint,
  ConfidenceFactor,
} from './types';
import {
  DRAINER_FAMILY_PROFILES,
  getDrainerFamilyProfile,
  getDrainerFamilyName,
} from './family-profiles';

// ============================================
// SIMILARITY THRESHOLDS
// ============================================

const SIMILARITY_THRESHOLDS = {
  HIGH_CONFIDENCE: 0.85,    // ≥85% similarity = HIGH confidence match
  MEDIUM_CONFIDENCE: 0.70,  // ≥70% similarity = MEDIUM confidence match
  LOW_CONFIDENCE: 0.55,     // ≥55% similarity = LOW confidence match
  MINIMUM_MATCH: 0.50,      // <50% = no match
};

// Feature weights for similarity calculation
// Higher weight = more important for clustering
const FEATURE_WEIGHTS: Record<keyof DrainerFeatureVector['features'], number> = {
  avg_drain_delay_normalized: 0.8,
  sweep_window_normalized: 0.7,
  same_block_drain: 1.0,        // High weight - distinctive feature
  unlimited_approval_rate: 0.9,
  rapid_drain_rate: 0.85,
  permit2_usage: 1.0,           // High weight - modern drainer indicator
  gas_aggressiveness: 0.6,
  gas_consistency: 0.5,
  hop_count_normalized: 0.75,
  uses_mixers: 0.9,             // High weight - distinctive routing
  uses_bridges: 0.7,
  direct_cex_rate: 0.8,
  proxy_usage: 0.6,
  delegatecall_usage: 0.65,
  high_value_targeting: 0.7,
  nft_targeting: 0.8,
};

// ============================================
// MAIN CLUSTERING FUNCTION
// ============================================

/**
 * Cluster a drainer based on its feature vector and fingerprint features.
 * Returns the best matching family/variant assignment.
 */
export function clusterDrainer(
  featureVector: DrainerFeatureVector,
  fingerprintFeatures: FingerprintFeatures,
  destinationAddresses: string[]
): ClusteringResult {
  // Calculate similarity scores against all known family profiles
  const familyScores: Array<{
    familyId: DrainerFamilyId;
    variantId: DrainerVariantId;
    behavioralSimilarity: number;
    structuralSimilarity: number;
    routingSimilarity: number;
    totalScore: number;
    reasons: string[];
  }> = [];
  
  for (const [familyId, profile] of Object.entries(DRAINER_FAMILY_PROFILES)) {
    if (familyId === 'unknown') continue;
    
    const behavioralSimilarity = calculateBehavioralSimilarity(
      featureVector,
      fingerprintFeatures,
      profile.characteristic_features
    );
    
    const structuralSimilarity = calculateStructuralSimilarity(
      fingerprintFeatures,
      profile.characteristic_features
    );
    
    const routingSimilarity = calculateRoutingSimilarity(
      fingerprintFeatures,
      profile.characteristic_features,
      destinationAddresses,
      profile.known_aggregation_wallets
    );
    
    // Weighted total score
    const totalScore = (
      behavioralSimilarity * 0.45 +
      structuralSimilarity * 0.25 +
      routingSimilarity * 0.30
    );
    
    const reasons = generateMatchReasons(
      behavioralSimilarity,
      structuralSimilarity,
      routingSimilarity,
      fingerprintFeatures,
      profile.characteristic_features
    );
    
    // Find best matching variant
    const variantId = findBestVariant(
      featureVector,
      fingerprintFeatures,
      profile,
      totalScore
    );
    
    familyScores.push({
      familyId: familyId as DrainerFamilyId,
      variantId,
      behavioralSimilarity,
      structuralSimilarity,
      routingSimilarity,
      totalScore,
      reasons,
    });
  }
  
  // Sort by total score (descending)
  familyScores.sort((a, b) => b.totalScore - a.totalScore);
  
  const bestMatch = familyScores[0];
  
  // Determine confidence level
  let confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
  if (bestMatch.totalScore >= SIMILARITY_THRESHOLDS.HIGH_CONFIDENCE) {
    confidenceLevel = 'HIGH';
  } else if (bestMatch.totalScore >= SIMILARITY_THRESHOLDS.MEDIUM_CONFIDENCE) {
    confidenceLevel = 'MEDIUM';
  }
  
  // If no good match, return unknown
  if (bestMatch.totalScore < SIMILARITY_THRESHOLDS.MINIMUM_MATCH) {
    return {
      cluster_id: generateClusterId(),
      family_id: 'unknown',
      variant_id: 'new',
      similarity_score: bestMatch.totalScore,
      behavioral_similarity: bestMatch.behavioralSimilarity,
      structural_similarity: bestMatch.structuralSimilarity,
      routing_similarity: bestMatch.routingSimilarity,
      member_count: 1,
      member_addresses: [featureVector.source_address],
      confidence: Math.round(bestMatch.totalScore * 100),
      confidence_level: 'LOW',
      assignment_reasons: ['No matching family profile found', 'Classified as new/unknown drainer variant'],
    };
  }
  
  return {
    cluster_id: generateClusterId(),
    family_id: bestMatch.familyId,
    variant_id: bestMatch.variantId,
    similarity_score: bestMatch.totalScore,
    behavioral_similarity: bestMatch.behavioralSimilarity,
    structural_similarity: bestMatch.structuralSimilarity,
    routing_similarity: bestMatch.routingSimilarity,
    member_count: DRAINER_FAMILY_PROFILES[bestMatch.familyId]?.total_victims || 1,
    member_addresses: [featureVector.source_address],
    confidence: Math.round(bestMatch.totalScore * 100),
    confidence_level: confidenceLevel,
    assignment_reasons: bestMatch.reasons,
  };
}

// ============================================
// BEHAVIORAL SIMILARITY CALCULATION
// ============================================

function calculateBehavioralSimilarity(
  featureVector: DrainerFeatureVector,
  features: FingerprintFeatures,
  referenceFeatures: Partial<FingerprintFeatures>
): number {
  let totalWeight = 0;
  let weightedSimilarity = 0;
  
  // Compare approval behavior
  if (referenceFeatures.approval_behavior) {
    const ref = referenceFeatures.approval_behavior;
    const feat = features.approval_behavior;
    
    // Unlimited approval rate similarity
    const approvalSimilarity = 1 - Math.abs(ref.unlimited_approval_rate - feat.unlimited_approval_rate);
    weightedSimilarity += approvalSimilarity * FEATURE_WEIGHTS.unlimited_approval_rate;
    totalWeight += FEATURE_WEIGHTS.unlimited_approval_rate;
    
    // Permit2 usage match
    const permit2Match = ref.uses_permit2 === feat.uses_permit2 ? 1 : 0;
    weightedSimilarity += permit2Match * FEATURE_WEIGHTS.permit2_usage;
    totalWeight += FEATURE_WEIGHTS.permit2_usage;
    
    // Rapid drain match
    const rapidDrainMatch = ref.rapid_drain_after_approval === feat.rapid_drain_after_approval ? 1 : 0;
    weightedSimilarity += rapidDrainMatch * FEATURE_WEIGHTS.rapid_drain_rate;
    totalWeight += FEATURE_WEIGHTS.rapid_drain_rate;
  }
  
  // Compare transfer timing
  if (referenceFeatures.transfer_timing) {
    const ref = referenceFeatures.transfer_timing;
    const feat = features.transfer_timing;
    
    // Same block drain match
    const sameBlockMatch = ref.same_block_drain === feat.same_block_drain ? 1 : 0;
    weightedSimilarity += sameBlockMatch * FEATURE_WEIGHTS.same_block_drain;
    totalWeight += FEATURE_WEIGHTS.same_block_drain;
    
    // Delay similarity (normalized)
    const maxDelay = 3600;
    const delayDiff = Math.abs(ref.avg_delay_seconds - feat.avg_delay_seconds) / maxDelay;
    const delaySimilarity = 1 - Math.min(1, delayDiff);
    weightedSimilarity += delaySimilarity * FEATURE_WEIGHTS.avg_drain_delay_normalized;
    totalWeight += FEATURE_WEIGHTS.avg_drain_delay_normalized;
  }
  
  // Compare gas profile
  if (referenceFeatures.gas_profile) {
    const ref = referenceFeatures.gas_profile;
    const feat = features.gas_profile;
    
    // Priority fee style match
    const styleMatch = ref.priority_fee_style === feat.priority_fee_style ? 1 : 0.5;
    weightedSimilarity += styleMatch * FEATURE_WEIGHTS.gas_aggressiveness;
    totalWeight += FEATURE_WEIGHTS.gas_aggressiveness;
  }
  
  return totalWeight > 0 ? weightedSimilarity / totalWeight : 0;
}

// ============================================
// STRUCTURAL SIMILARITY CALCULATION
// ============================================

function calculateStructuralSimilarity(
  features: FingerprintFeatures,
  referenceFeatures: Partial<FingerprintFeatures>
): number {
  let matches = 0;
  let total = 0;
  
  if (referenceFeatures.code_features) {
    const ref = referenceFeatures.code_features;
    const feat = features.code_features;
    
    // Proxy usage match
    if (ref.proxy_usage === feat.proxy_usage) matches++;
    total++;
    
    // Delegatecall patterns match
    if (ref.delegatecall_patterns === feat.delegatecall_patterns) matches++;
    total++;
    
    // Create2 usage match
    if (ref.uses_create2 === feat.uses_create2) matches++;
    total++;
    
    // Bytecode hash match (if available)
    if (ref.bytecode_hashes && feat.bytecode_hashes) {
      const refSet = new Set(ref.bytecode_hashes.map(h => h.toLowerCase()));
      const hasMatch = feat.bytecode_hashes.some(h => refSet.has(h.toLowerCase()));
      if (hasMatch) {
        matches += 3; // High weight for bytecode match
      }
      total += 3;
    }
  }
  
  return total > 0 ? matches / total : 0.5;
}

// ============================================
// ROUTING SIMILARITY CALCULATION
// ============================================

function calculateRoutingSimilarity(
  features: FingerprintFeatures,
  referenceFeatures: Partial<FingerprintFeatures>,
  destinationAddresses: string[],
  knownAggregationWallets: string[]
): number {
  let weightedScore = 0;
  let totalWeight = 0;
  
  if (referenceFeatures.routing_behavior) {
    const ref = referenceFeatures.routing_behavior;
    const feat = features.routing_behavior;
    
    // Hop count similarity
    const hopDiff = Math.abs(ref.hop_count - feat.hop_count);
    const hopSimilarity = 1 - Math.min(1, hopDiff / 5);
    weightedScore += hopSimilarity * FEATURE_WEIGHTS.hop_count_normalized;
    totalWeight += FEATURE_WEIGHTS.hop_count_normalized;
    
    // Mixer usage match
    const mixerMatch = ref.uses_mixers === feat.uses_mixers ? 1 : 0;
    weightedScore += mixerMatch * FEATURE_WEIGHTS.uses_mixers;
    totalWeight += FEATURE_WEIGHTS.uses_mixers;
    
    // Bridge usage match
    const bridgeMatch = ref.uses_bridges === feat.uses_bridges ? 1 : 0;
    weightedScore += bridgeMatch * FEATURE_WEIGHTS.uses_bridges;
    totalWeight += FEATURE_WEIGHTS.uses_bridges;
    
    // Direct to CEX match
    const cexMatch = ref.direct_to_cex === feat.direct_to_cex ? 1 : 0;
    weightedScore += cexMatch * FEATURE_WEIGHTS.direct_cex_rate;
    totalWeight += FEATURE_WEIGHTS.direct_cex_rate;
  }
  
  // Check for destination cluster overlap
  if (knownAggregationWallets.length > 0 && destinationAddresses.length > 0) {
    const knownSet = new Set(knownAggregationWallets.map(a => a.toLowerCase()));
    const destSet = new Set(destinationAddresses.map(a => a.toLowerCase()));
    
    const overlap = [...destSet].filter(d => knownSet.has(d)).length;
    if (overlap > 0) {
      // Significant boost for destination cluster match
      weightedScore += 1.0;
      totalWeight += 1.0;
    }
  }
  
  return totalWeight > 0 ? weightedScore / totalWeight : 0.5;
}

// ============================================
// VARIANT MATCHING
// ============================================

function findBestVariant(
  featureVector: DrainerFeatureVector,
  features: FingerprintFeatures,
  profile: typeof DRAINER_FAMILY_PROFILES['pinkdrainer'],
  familyScore: number
): DrainerVariantId {
  if (profile.variants.length === 0) {
    return 'v1';
  }
  
  // Check chain-specific variants
  const chain = featureVector.chain;
  const chainSpecificVariants = profile.variants.filter(v => v.chains.includes(chain));
  
  if (chainSpecificVariants.length > 0) {
    // Return the most recent variant for this chain
    return chainSpecificVariants[chainSpecificVariants.length - 1].variant_id;
  }
  
  // Check for feature-specific variants
  for (const variant of profile.variants) {
    // Check distinctive features
    for (const distinctiveFeature of variant.distinctive_features) {
      // Match against known distinctive features
      if (distinctiveFeature.toLowerCase().includes('permit2') && features.approval_behavior.uses_permit2) {
        return variant.variant_id;
      }
      if (distinctiveFeature.toLowerCase().includes('cross-chain') && features.routing_behavior.bridges_to_chains.length > 0) {
        return variant.variant_id;
      }
      if (distinctiveFeature.toLowerCase().includes('same-block') && features.transfer_timing.same_block_drain) {
        return variant.variant_id;
      }
    }
  }
  
  // Default to latest variant
  return profile.variants[profile.variants.length - 1]?.variant_id || 'v1';
}

// ============================================
// MATCH REASON GENERATION
// ============================================

function generateMatchReasons(
  behavioralSimilarity: number,
  structuralSimilarity: number,
  routingSimilarity: number,
  features: FingerprintFeatures,
  referenceFeatures: Partial<FingerprintFeatures>
): string[] {
  const reasons: string[] = [];
  
  // Behavioral reasons
  if (behavioralSimilarity >= 0.8) {
    reasons.push('Identical approval drain sequence');
  } else if (behavioralSimilarity >= 0.6) {
    reasons.push('Similar approval abuse patterns');
  }
  
  // Timing reasons
  if (referenceFeatures.transfer_timing && features.transfer_timing) {
    if (referenceFeatures.transfer_timing.same_block_drain === features.transfer_timing.same_block_drain) {
      if (features.transfer_timing.same_block_drain) {
        reasons.push('Same-block drain technique matches');
      }
    }
    
    const delayDiff = Math.abs(
      referenceFeatures.transfer_timing.avg_delay_seconds - features.transfer_timing.avg_delay_seconds
    );
    if (delayDiff < 30) {
      reasons.push('Timing pattern matches known signature');
    }
  }
  
  // Routing reasons
  if (routingSimilarity >= 0.8) {
    reasons.push('Same destination cluster pattern');
  } else if (routingSimilarity >= 0.6) {
    reasons.push('Similar fund routing behavior');
  }
  
  // Gas reasons
  if (referenceFeatures.gas_profile && features.gas_profile) {
    if (referenceFeatures.gas_profile.priority_fee_style === features.gas_profile.priority_fee_style) {
      reasons.push('Gas usage pattern matches known signature');
    }
  }
  
  // Permit2 reasons
  if (features.approval_behavior.uses_permit2) {
    reasons.push('Uses Permit2 for gasless approvals');
  }
  
  // Structural reasons
  if (structuralSimilarity >= 0.7) {
    reasons.push('Contract structure matches family pattern');
  }
  
  return reasons.length > 0 ? reasons : ['General behavioral similarity'];
}

// ============================================
// CONFIDENCE FACTOR GENERATION
// ============================================

/**
 * Generate detailed confidence factors for a clustering result.
 */
export function generateConfidenceFactors(
  clusteringResult: ClusteringResult,
  features: FingerprintFeatures
): ConfidenceFactor[] {
  const factors: ConfidenceFactor[] = [];
  
  // Behavioral similarity factor
  factors.push({
    factor_id: 'BEHAVIORAL_MATCH',
    name: 'Behavioral Pattern Match',
    description: `${Math.round(clusteringResult.behavioral_similarity * 100)}% match with known ${getDrainerFamilyName(clusteringResult.family_id)} patterns`,
    weight: Math.round(clusteringResult.behavioral_similarity * 40),
    evidence: clusteringResult.assignment_reasons.filter(r => 
      r.includes('approval') || r.includes('drain') || r.includes('pattern')
    ),
  });
  
  // Routing similarity factor
  factors.push({
    factor_id: 'ROUTING_MATCH',
    name: 'Routing Behavior Match',
    description: `${Math.round(clusteringResult.routing_similarity * 100)}% match with known destination clusters`,
    weight: Math.round(clusteringResult.routing_similarity * 30),
    evidence: clusteringResult.assignment_reasons.filter(r => 
      r.includes('destination') || r.includes('routing')
    ),
  });
  
  // Structural similarity factor
  factors.push({
    factor_id: 'STRUCTURAL_MATCH',
    name: 'Code Structure Match',
    description: `${Math.round(clusteringResult.structural_similarity * 100)}% structural similarity`,
    weight: Math.round(clusteringResult.structural_similarity * 20),
    evidence: clusteringResult.assignment_reasons.filter(r => 
      r.includes('Contract') || r.includes('structure')
    ),
  });
  
  // Permit2 factor
  if (features.approval_behavior.uses_permit2) {
    factors.push({
      factor_id: 'PERMIT2_USAGE',
      name: 'Permit2 Abuse',
      description: 'Uses Permit2 for gasless token approvals (modern drainer indicator)',
      weight: 15,
      evidence: ['Permit2 contract interactions detected'],
    });
  }
  
  // Same-block drain factor
  if (features.transfer_timing.same_block_drain) {
    factors.push({
      factor_id: 'SAME_BLOCK_DRAIN',
      name: 'Same-Block Drainage',
      description: 'Drains assets in the same block as approval (automated attack)',
      weight: 12,
      evidence: ['Same-block drain transactions detected'],
    });
  }
  
  return factors;
}

// ============================================
// FINGERPRINT BUILDER
// ============================================

/**
 * Build a complete DrainerFingerprint from extracted features and clustering result.
 */
export function buildDrainerFingerprint(
  address: string,
  chain: Chain,
  features: FingerprintFeatures,
  featureVector: DrainerFeatureVector,
  clusteringResult: ClusteringResult,
  impactMetrics: {
    wallet_count: number;
    total_stolen_usd: number;
    first_seen?: string;
    last_seen?: string;
  }
): DrainerFingerprint {
  const now = new Date().toISOString();
  const firstSeen = impactMetrics.first_seen || now;
  const lastSeen = impactMetrics.last_seen || now;
  
  // Calculate days since last activity
  const lastSeenDate = new Date(lastSeen);
  const nowDate = new Date();
  const daysSinceLastActivity = Math.floor(
    (nowDate.getTime() - lastSeenDate.getTime()) / (1000 * 60 * 60 * 24)
  );
  
  // Get family profile for chains and cross-chain info
  const familyProfile = getDrainerFamilyProfile(clusteringResult.family_id);
  const chains: Chain[] = familyProfile.active_chains.length > 0 
    ? familyProfile.active_chains 
    : [chain];
  
  // Generate confidence factors
  const confidenceFactors = generateConfidenceFactors(clusteringResult, features);
  
  return {
    family_id: clusteringResult.family_id,
    variant_id: clusteringResult.variant_id,
    fingerprint_id: generateFingerprintId(address, chain),
    confidence_score: clusteringResult.confidence,
    confidence_factors: confidenceFactors,
    first_seen: firstSeen,
    last_seen: lastSeen,
    last_activity_days_ago: daysSinceLastActivity,
    chains,
    primary_chain: chain,
    cross_chain_activity: chains.length > 1,
    wallet_count: impactMetrics.wallet_count,
    total_stolen_usd: impactMetrics.total_stolen_usd,
    average_drain_usd: impactMetrics.wallet_count > 0 
      ? impactMetrics.total_stolen_usd / impactMetrics.wallet_count 
      : 0,
    fingerprint_features: features,
    created_at: now,
    updated_at: now,
    version: 1,
  };
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function generateClusterId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `CLU-${timestamp}-${random}`.toUpperCase();
}

function generateFingerprintId(address: string, chain: Chain): string {
  const addressPart = address.slice(2, 10).toUpperCase();
  const timestamp = Date.now().toString(36);
  return `FP-${chain.toUpperCase()}-${addressPart}-${timestamp}`.toUpperCase();
}

// ============================================
// EXPORTS
// ============================================

export {
  SIMILARITY_THRESHOLDS,
  FEATURE_WEIGHTS,
};
