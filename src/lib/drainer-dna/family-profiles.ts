// ============================================
// DRAINER FAMILY PROFILES DATABASE
// ============================================
// Reference profiles for known drainer families.
// These are used as baselines for clustering new drainers.
//
// Each profile contains characteristic behavioral and structural
// signatures that define a drainer family.

import { Chain } from '@/types';
import {
  DrainerFamilyId,
  DrainerFamilyProfile,
  DrainerVariantProfile,
  FingerprintFeatures,
} from './types';

// ============================================
// PINKDRAINER FAMILY
// ============================================
// One of the most prolific drainer families.
// Known for: Permit2 abuse, unlimited approvals, rapid sweeps

const PINKDRAINER_VARIANTS: DrainerVariantProfile[] = [
  {
    variant_id: 'v1',
    name: 'PinkDrainer v1',
    description: 'Original variant with basic approval drain',
    first_seen: '2023-06-01',
    chains: ['ethereum'],
    distinctive_features: [
      'Single-token targeting',
      'Direct CEX routing',
      'Basic setApprovalForAll abuse',
    ],
    bytecode_hashes: [],
  },
  {
    variant_id: 'v2',
    name: 'PinkDrainer v2',
    description: 'Enhanced with Permit2 support',
    first_seen: '2023-10-15',
    chains: ['ethereum', 'base'],
    distinctive_features: [
      'Permit2 integration',
      'Multi-token sweeps',
      'Intermediary routing',
    ],
    bytecode_hashes: [],
  },
  {
    variant_id: 'v3',
    name: 'PinkDrainer v3',
    description: 'Latest variant with cross-chain capability',
    first_seen: '2025-12-04',
    chains: ['ethereum', 'base', 'bnb'],
    distinctive_features: [
      'Cross-chain bridging',
      'Same-block drainage',
      'Advanced gas optimization',
      'Destination cluster rotation',
    ],
    bytecode_hashes: [],
  },
];

const PINKDRAINER_FEATURES: Partial<FingerprintFeatures> = {
  approval_behavior: {
    prefers_unlimited_approvals: true,
    unlimited_approval_rate: 0.95,
    approval_targets: [],
    targets_high_value_tokens: true,
    targets_nfts: true,
    targets_all_assets: true,
    avoids_batch_revokes: true,
    rapid_drain_after_approval: true,
    avg_time_to_drain_seconds: 45,
    uses_permit2: true,
    uses_permit_signatures: true,
  },
  transfer_timing: {
    avg_delay_seconds: 30,
    min_delay_seconds: 5,
    max_delay_seconds: 120,
    sweep_window_seconds: 60,
    immediate_sweep: true,
    batched_sweeps: true,
    timed_sweeps: false,
    same_block_drain: true,
    avg_block_delay: 0.5,
  },
  gas_profile: {
    gas_spike_pattern: true,
    priority_fee_style: 'AGGRESSIVE',
    avg_gas_used: 150000,
    gas_variance: 0.2,
    uses_flashbots: false,
    uses_private_mempool: true,
    prefers_low_gas_periods: false,
  },
  routing_behavior: {
    hop_count: 2,
    min_hops: 1,
    max_hops: 4,
    destination_clusters: [],
    primary_destination: '',
    uses_mixers: false,
    uses_bridges: true,
    uses_dex_swaps: true,
    direct_to_cex: false,
    uses_intermediary_wallets: true,
    intermediary_count: 2,
    bridges_to_chains: ['base', 'bnb'],
    primary_exit_chain: 'ethereum',
  },
  code_features: {
    proxy_usage: true,
    proxy_types: ['EIP1167_MINIMAL'],
    bytecode_hashes: [],
    bytecode_similarity_clusters: ['PINK_CLUSTER_001'],
    delegatecall_patterns: true,
    uses_create2: true,
    uses_selfdestruct: false,
    is_verified: false,
    has_source_code: false,
    opcode_frequency: {},
  },
};

const PINKDRAINER_PROFILE: DrainerFamilyProfile = {
  family_id: 'pinkdrainer',
  name: 'PinkDrainer',
  description: 'Sophisticated drainer family known for Permit2 abuse and rapid multi-asset sweeps. One of the most active drainer operations.',
  first_seen: '2023-06-01',
  first_seen_chain: 'ethereum',
  variants: PINKDRAINER_VARIANTS,
  characteristic_features: PINKDRAINER_FEATURES,
  known_contract_addresses: [
    '0x0000d194a19e7578e1ee97a2b6f6e4af01a00000',
  ],
  known_aggregation_wallets: [
    '0x6d2e03b7effeae98bd302a9f836d0d6ab0002219',
  ],
  total_victims: 15000,
  total_stolen_usd: 85000000,
  active_chains: ['ethereum', 'base', 'bnb'],
  is_active: true,
  last_activity: '2026-01-30',
};

// ============================================
// INFERNO DRAINER FAMILY
// ============================================
// Known for: High-volume operations, NFT focus, mixer usage

const INFERNO_VARIANTS: DrainerVariantProfile[] = [
  {
    variant_id: 'v1',
    name: 'Inferno Drainer v1',
    description: 'Initial NFT-focused variant',
    first_seen: '2023-01-15',
    chains: ['ethereum'],
    distinctive_features: [
      'NFT marketplace impersonation',
      'setApprovalForAll targeting',
      'Tornado Cash routing',
    ],
    bytecode_hashes: [],
  },
  {
    variant_id: 'v2',
    name: 'Inferno Drainer v2',
    description: 'Multi-chain expansion',
    first_seen: '2024-03-20',
    chains: ['ethereum', 'base', 'bnb'],
    distinctive_features: [
      'Cross-chain asset consolidation',
      'DEX swap obfuscation',
      'Timed sweep patterns',
    ],
    bytecode_hashes: [],
  },
];

const INFERNO_FEATURES: Partial<FingerprintFeatures> = {
  approval_behavior: {
    prefers_unlimited_approvals: true,
    unlimited_approval_rate: 0.98,
    approval_targets: [],
    targets_high_value_tokens: true,
    targets_nfts: true,
    targets_all_assets: false, // Primarily NFT focused
    avoids_batch_revokes: true,
    rapid_drain_after_approval: true,
    avg_time_to_drain_seconds: 120,
    uses_permit2: false,
    uses_permit_signatures: false,
  },
  transfer_timing: {
    avg_delay_seconds: 90,
    min_delay_seconds: 30,
    max_delay_seconds: 300,
    sweep_window_seconds: 180,
    immediate_sweep: false,
    batched_sweeps: true,
    timed_sweeps: true,
    same_block_drain: false,
    avg_block_delay: 3,
  },
  gas_profile: {
    gas_spike_pattern: false,
    priority_fee_style: 'NORMAL',
    avg_gas_used: 180000,
    gas_variance: 0.3,
    uses_flashbots: false,
    uses_private_mempool: false,
    prefers_low_gas_periods: true,
  },
  routing_behavior: {
    hop_count: 4,
    min_hops: 2,
    max_hops: 6,
    destination_clusters: [],
    primary_destination: '',
    uses_mixers: true, // Distinctive: uses mixers
    uses_bridges: true,
    uses_dex_swaps: true,
    direct_to_cex: false,
    uses_intermediary_wallets: true,
    intermediary_count: 4,
    bridges_to_chains: ['bnb', 'solana'],
    primary_exit_chain: 'bnb',
  },
  code_features: {
    proxy_usage: true,
    proxy_types: ['EIP1167_MINIMAL', 'CUSTOM'],
    bytecode_hashes: [],
    bytecode_similarity_clusters: ['INFERNO_CLUSTER_001'],
    delegatecall_patterns: true,
    uses_create2: true,
    uses_selfdestruct: true,
    is_verified: false,
    has_source_code: false,
    opcode_frequency: {},
  },
};

const INFERNO_PROFILE: DrainerFamilyProfile = {
  family_id: 'infernodrainer',
  name: 'Inferno Drainer',
  description: 'High-volume drainer operation known for NFT targeting and sophisticated fund obfuscation through mixers.',
  first_seen: '2023-01-15',
  first_seen_chain: 'ethereum',
  variants: INFERNO_VARIANTS,
  characteristic_features: INFERNO_FEATURES,
  known_contract_addresses: [
    '0x0000db5c8b030ae20308ac975898e09741e70000',
    '0x00000000a82b4758df44fcab4c4e86e2f231b000',
  ],
  known_aggregation_wallets: [
    '0x59abf3837fa962d6853b4cc0a19513aa031fd32b',
  ],
  total_victims: 25000,
  total_stolen_usd: 120000000,
  active_chains: ['ethereum', 'base', 'bnb'],
  is_active: true,
  last_activity: '2026-01-28',
};

// ============================================
// ANGEL DRAINER FAMILY
// ============================================
// Known for: Social engineering, fake airdrops, moderate routing

const ANGEL_VARIANTS: DrainerVariantProfile[] = [
  {
    variant_id: 'v1',
    name: 'Angel Drainer v1',
    description: 'Airdrop scam focused variant',
    first_seen: '2023-08-10',
    chains: ['ethereum'],
    distinctive_features: [
      'Fake airdrop claims',
      'Social media phishing',
      'Simple approval chains',
    ],
    bytecode_hashes: [],
  },
];

const ANGEL_FEATURES: Partial<FingerprintFeatures> = {
  approval_behavior: {
    prefers_unlimited_approvals: true,
    unlimited_approval_rate: 0.85,
    approval_targets: [],
    targets_high_value_tokens: true,
    targets_nfts: false,
    targets_all_assets: false,
    avoids_batch_revokes: false,
    rapid_drain_after_approval: true,
    avg_time_to_drain_seconds: 60,
    uses_permit2: false,
    uses_permit_signatures: true,
  },
  transfer_timing: {
    avg_delay_seconds: 45,
    min_delay_seconds: 15,
    max_delay_seconds: 180,
    sweep_window_seconds: 90,
    immediate_sweep: true,
    batched_sweeps: false,
    timed_sweeps: false,
    same_block_drain: false,
    avg_block_delay: 2,
  },
  gas_profile: {
    gas_spike_pattern: false,
    priority_fee_style: 'NORMAL',
    avg_gas_used: 120000,
    gas_variance: 0.25,
    uses_flashbots: false,
    uses_private_mempool: false,
    prefers_low_gas_periods: false,
  },
  routing_behavior: {
    hop_count: 2,
    min_hops: 1,
    max_hops: 3,
    destination_clusters: [],
    primary_destination: '',
    uses_mixers: false,
    uses_bridges: false,
    uses_dex_swaps: true,
    direct_to_cex: true, // Distinctive: often direct to CEX
    uses_intermediary_wallets: true,
    intermediary_count: 1,
    bridges_to_chains: [],
    primary_exit_chain: 'ethereum',
  },
  code_features: {
    proxy_usage: false,
    proxy_types: ['NONE'],
    bytecode_hashes: [],
    bytecode_similarity_clusters: ['ANGEL_CLUSTER_001'],
    delegatecall_patterns: false,
    uses_create2: false,
    uses_selfdestruct: false,
    is_verified: false,
    has_source_code: false,
    opcode_frequency: {},
  },
};

const ANGEL_PROFILE: DrainerFamilyProfile = {
  family_id: 'angeldrainer',
  name: 'Angel Drainer',
  description: 'Social engineering focused drainer known for fake airdrop campaigns and direct CEX exits.',
  first_seen: '2023-08-10',
  first_seen_chain: 'ethereum',
  variants: ANGEL_VARIANTS,
  characteristic_features: ANGEL_FEATURES,
  known_contract_addresses: [
    '0x00000000ae347930bd1e7b0f35588b92280f9e75',
  ],
  known_aggregation_wallets: [
    '0x00000000ae347930bd1e7b0f35588b92280f9e75',
  ],
  total_victims: 8000,
  total_stolen_usd: 35000000,
  active_chains: ['ethereum', 'base'],
  is_active: true,
  last_activity: '2026-01-25',
};

// ============================================
// MONKEY DRAINER FAMILY
// ============================================
// Known for: Earliest major drainer, simple patterns

const MONKEY_VARIANTS: DrainerVariantProfile[] = [
  {
    variant_id: 'v1',
    name: 'Monkey Drainer v1',
    description: 'Original Monkey Drainer implementation',
    first_seen: '2022-08-01',
    chains: ['ethereum'],
    distinctive_features: [
      'Simple approval mechanism',
      'Direct transfers',
      'Minimal obfuscation',
    ],
    bytecode_hashes: [],
  },
];

const MONKEY_FEATURES: Partial<FingerprintFeatures> = {
  approval_behavior: {
    prefers_unlimited_approvals: true,
    unlimited_approval_rate: 1.0,
    approval_targets: [],
    targets_high_value_tokens: true,
    targets_nfts: true,
    targets_all_assets: true,
    avoids_batch_revokes: false,
    rapid_drain_after_approval: true,
    avg_time_to_drain_seconds: 30,
    uses_permit2: false,
    uses_permit_signatures: false,
  },
  transfer_timing: {
    avg_delay_seconds: 20,
    min_delay_seconds: 5,
    max_delay_seconds: 60,
    sweep_window_seconds: 30,
    immediate_sweep: true,
    batched_sweeps: false,
    timed_sweeps: false,
    same_block_drain: true,
    avg_block_delay: 0,
  },
  routing_behavior: {
    hop_count: 1,
    min_hops: 1,
    max_hops: 2,
    destination_clusters: [],
    primary_destination: '',
    uses_mixers: false,
    uses_bridges: false,
    uses_dex_swaps: false,
    direct_to_cex: true,
    uses_intermediary_wallets: false,
    intermediary_count: 0,
    bridges_to_chains: [],
    primary_exit_chain: 'ethereum',
  },
};

const MONKEY_PROFILE: DrainerFamilyProfile = {
  family_id: 'monkeydrainer',
  name: 'Monkey Drainer',
  description: 'One of the earliest major drainer families. Known for simple but effective approval abuse patterns.',
  first_seen: '2022-08-01',
  first_seen_chain: 'ethereum',
  variants: MONKEY_VARIANTS,
  characteristic_features: MONKEY_FEATURES,
  known_contract_addresses: [
    '0x0000000035634b55f3d99b071b5a354f48e10000',
  ],
  known_aggregation_wallets: [],
  total_victims: 5000,
  total_stolen_usd: 24000000,
  active_chains: ['ethereum'],
  is_active: false, // Shut down
  last_activity: '2023-03-01',
};

// ============================================
// VENOM DRAINER FAMILY
// ============================================

const VENOM_VARIANTS: DrainerVariantProfile[] = [
  {
    variant_id: 'v1',
    name: 'Venom Drainer v1',
    description: 'Standard Venom implementation',
    first_seen: '2023-04-15',
    chains: ['ethereum', 'bnb'],
    distinctive_features: [
      'BNB chain focus',
      'Low gas optimization',
      'Quick exits',
    ],
    bytecode_hashes: [],
  },
];

const VENOM_FEATURES: Partial<FingerprintFeatures> = {
  approval_behavior: {
    prefers_unlimited_approvals: true,
    unlimited_approval_rate: 0.9,
    approval_targets: [],
    targets_high_value_tokens: true,
    targets_nfts: false,
    targets_all_assets: false,
    avoids_batch_revokes: true,
    rapid_drain_after_approval: true,
    avg_time_to_drain_seconds: 40,
    uses_permit2: false,
    uses_permit_signatures: false,
  },
  gas_profile: {
    gas_spike_pattern: false,
    priority_fee_style: 'CONSERVATIVE',
    avg_gas_used: 100000,
    gas_variance: 0.15,
    uses_flashbots: false,
    uses_private_mempool: false,
    prefers_low_gas_periods: true,
  },
};

const VENOM_PROFILE: DrainerFamilyProfile = {
  family_id: 'venomdrainer',
  name: 'Venom Drainer',
  description: 'BNB Chain focused drainer known for low-gas operations and quick exchange exits.',
  first_seen: '2023-04-15',
  first_seen_chain: 'bnb',
  variants: VENOM_VARIANTS,
  characteristic_features: VENOM_FEATURES,
  known_contract_addresses: [
    '0x0000000052e7f0c029b6e38e96f03c70d86bfde5',
  ],
  known_aggregation_wallets: [],
  total_victims: 6000,
  total_stolen_usd: 18000000,
  active_chains: ['ethereum', 'bnb'],
  is_active: true,
  last_activity: '2026-01-20',
};

// ============================================
// MS DRAINER FAMILY
// ============================================

const MS_VARIANTS: DrainerVariantProfile[] = [
  {
    variant_id: 'v1',
    name: 'MS Drainer v1',
    description: 'Multi-sig wallet targeted variant',
    first_seen: '2023-09-01',
    chains: ['ethereum'],
    distinctive_features: [
      'Multi-sig targeting',
      'Complex approval chains',
      'Delayed execution',
    ],
    bytecode_hashes: [],
  },
];

const MS_FEATURES: Partial<FingerprintFeatures> = {
  approval_behavior: {
    prefers_unlimited_approvals: true,
    unlimited_approval_rate: 0.92,
    approval_targets: [],
    targets_high_value_tokens: true,
    targets_nfts: true,
    targets_all_assets: true,
    avoids_batch_revokes: true,
    rapid_drain_after_approval: false, // Distinctive: delayed drain
    avg_time_to_drain_seconds: 300,
    uses_permit2: true,
    uses_permit_signatures: true,
  },
  transfer_timing: {
    avg_delay_seconds: 240,
    min_delay_seconds: 60,
    max_delay_seconds: 600,
    sweep_window_seconds: 300,
    immediate_sweep: false,
    batched_sweeps: true,
    timed_sweeps: true, // Distinctive: scheduled drains
    same_block_drain: false,
    avg_block_delay: 10,
  },
};

const MS_PROFILE: DrainerFamilyProfile = {
  family_id: 'msdrainer',
  name: 'MS Drainer',
  description: 'Sophisticated drainer targeting multi-sig wallets with delayed, scheduled drain patterns.',
  first_seen: '2023-09-01',
  first_seen_chain: 'ethereum',
  variants: MS_VARIANTS,
  characteristic_features: MS_FEATURES,
  known_contract_addresses: [
    '0x0000000083fc54c35b9b83de16c67c73b1a7b000',
  ],
  known_aggregation_wallets: [
    '0x0000000083fc54c35b9b83de16c67c73b1a7b000',
  ],
  total_victims: 3000,
  total_stolen_usd: 45000000,
  active_chains: ['ethereum', 'base'],
  is_active: true,
  last_activity: '2026-01-22',
};

// ============================================
// UNKNOWN FAMILY TEMPLATE
// ============================================

const UNKNOWN_PROFILE: DrainerFamilyProfile = {
  family_id: 'unknown',
  name: 'Unknown Drainer',
  description: 'Unclassified drainer that does not match known family signatures.',
  first_seen: '',
  first_seen_chain: 'ethereum',
  variants: [],
  characteristic_features: {},
  known_contract_addresses: [],
  known_aggregation_wallets: [],
  total_victims: 0,
  total_stolen_usd: 0,
  active_chains: [],
  is_active: false,
  last_activity: '',
};

// ============================================
// EXPORTS
// ============================================

/**
 * All known drainer family profiles.
 */
export const DRAINER_FAMILY_PROFILES: Record<DrainerFamilyId, DrainerFamilyProfile> = {
  pinkdrainer: PINKDRAINER_PROFILE,
  infernodrainer: INFERNO_PROFILE,
  angeldrainer: ANGEL_PROFILE,
  monkeydrainer: MONKEY_PROFILE,
  venomdrainer: VENOM_PROFILE,
  msdrainer: MS_PROFILE,
  acedrainer: UNKNOWN_PROFILE, // Placeholder
  chick_drainer: UNKNOWN_PROFILE, // Placeholder
  raccoon_stealer: UNKNOWN_PROFILE, // Placeholder
  unknown: UNKNOWN_PROFILE,
};

/**
 * Get a drainer family profile by ID.
 */
export function getDrainerFamilyProfile(familyId: DrainerFamilyId): DrainerFamilyProfile {
  return DRAINER_FAMILY_PROFILES[familyId] || DRAINER_FAMILY_PROFILES.unknown;
}

/**
 * Get all active drainer families.
 */
export function getActiveDrainerFamilies(): DrainerFamilyProfile[] {
  return Object.values(DRAINER_FAMILY_PROFILES).filter(p => p.is_active);
}

/**
 * Get human-readable family name.
 */
export function getDrainerFamilyName(familyId: DrainerFamilyId): string {
  const profile = getDrainerFamilyProfile(familyId);
  return profile.name;
}

/**
 * Get all known drainer contract addresses across all families.
 */
export function getAllKnownDrainerAddresses(): Set<string> {
  const addresses = new Set<string>();
  
  for (const profile of Object.values(DRAINER_FAMILY_PROFILES)) {
    for (const addr of profile.known_contract_addresses) {
      addresses.add(addr.toLowerCase());
    }
    for (const addr of profile.known_aggregation_wallets) {
      addresses.add(addr.toLowerCase());
    }
  }
  
  return addresses;
}
