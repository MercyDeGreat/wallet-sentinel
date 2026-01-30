// ============================================
// DRAINER DNA FINGERPRINTING - TYPE DEFINITIONS
// ============================================
// Forensic-grade drainer attribution system that identifies
// malicious drainers by behavioral + structural signatures,
// not just static addresses or labels.
//
// DESIGN PHILOSOPHY:
// - Work even when drainer address is new (behavioral matching)
// - Provide attribution like "Matches PinkDrainer – Variant #3"
// - Support multi-chain analysis (Ethereum, Base, BNB, Solana)
// - Handle proxies and intermediary routing

import { Chain } from '@/types';

// ============================================
// DRAINER FAMILY DEFINITIONS
// ============================================

/**
 * Known drainer families with their characteristic signatures.
 * Each family has distinct behavioral and structural patterns.
 */
export type DrainerFamilyId =
  | 'pinkdrainer'
  | 'infernodrainer'
  | 'angeldrainer'
  | 'monkeydrainer'
  | 'venomdrainer'
  | 'msdrainer'
  | 'acedrainer'
  | 'chick_drainer'
  | 'raccoon_stealer'
  | 'unknown';

/**
 * Variant identifier within a drainer family.
 * Variants represent evolution or regional adaptations.
 */
export type DrainerVariantId = string; // e.g., "v1", "v2", "v3", "base-variant"

// ============================================
// CORE FINGERPRINT SCHEMA
// ============================================

/**
 * Complete Drainer DNA Fingerprint
 * Normalized signature object for drainer identification.
 */
export interface DrainerFingerprint {
  // === IDENTIFICATION ===
  family_id: DrainerFamilyId;
  variant_id: DrainerVariantId;
  fingerprint_id: string; // Unique ID for this specific fingerprint
  
  // === CONFIDENCE ===
  confidence_score: number; // 0-100
  confidence_factors: ConfidenceFactor[];
  
  // === TEMPORAL DATA ===
  first_seen: string; // ISO timestamp
  last_seen: string; // ISO timestamp
  last_activity_days_ago: number;
  
  // === CHAIN DATA ===
  chains: Chain[];
  primary_chain: Chain;
  cross_chain_activity: boolean;
  
  // === IMPACT METRICS ===
  wallet_count: number; // Number of compromised wallets
  total_stolen_usd: number;
  average_drain_usd: number;
  
  // === BEHAVIORAL FEATURES ===
  fingerprint_features: FingerprintFeatures;
  
  // === METADATA ===
  created_at: string;
  updated_at: string;
  version: number;
}

/**
 * Behavioral and structural features that define a drainer signature.
 */
export interface FingerprintFeatures {
  // === CALL PATTERNS ===
  call_patterns: CallPattern[];
  method_sequences: string[][]; // Ordered sequences like ["approve", "transferFrom", "transfer"]
  function_selectors: string[]; // 4-byte function selectors used
  
  // === APPROVAL BEHAVIOR ===
  approval_behavior: ApprovalBehavior;
  
  // === TRANSFER TIMING ===
  transfer_timing: TransferTiming;
  
  // === GAS PROFILE ===
  gas_profile: GasProfile;
  
  // === ROUTING BEHAVIOR ===
  routing_behavior: RoutingBehavior;
  
  // === CODE FEATURES ===
  code_features: CodeFeatures;
  
  // === VICTIM SELECTION ===
  victim_selection: VictimSelectionPattern;
  
  // === EVASION TECHNIQUES ===
  evasion_techniques: EvasionTechnique[];
}

// ============================================
// CALL PATTERN ANALYSIS
// ============================================

export interface CallPattern {
  pattern_id: string;
  description: string;
  method_sequence: string[];
  frequency: number; // How often this pattern appears
  confidence: number;
}

// ============================================
// APPROVAL BEHAVIOR ANALYSIS
// ============================================

export interface ApprovalBehavior {
  // Approval characteristics
  prefers_unlimited_approvals: boolean;
  unlimited_approval_rate: number; // 0-1
  
  // Approval targets
  approval_targets: ApprovalTarget[];
  
  // Token targeting
  targets_high_value_tokens: boolean;
  targets_nfts: boolean;
  targets_all_assets: boolean;
  
  // Revocation evasion
  avoids_batch_revokes: boolean;
  rapid_drain_after_approval: boolean;
  avg_time_to_drain_seconds: number;
  
  // Permit2 abuse
  uses_permit2: boolean;
  uses_permit_signatures: boolean;
}

export interface ApprovalTarget {
  contract_address: string;
  contract_type: 'TOKEN' | 'NFT' | 'DEFI' | 'UNKNOWN';
  frequency: number;
}

// ============================================
// TRANSFER TIMING ANALYSIS
// ============================================

export interface TransferTiming {
  // Time deltas
  avg_delay_seconds: number; // Average time between compromise and drain
  min_delay_seconds: number;
  max_delay_seconds: number;
  
  // Sweep window
  sweep_window_seconds: number; // Total time to drain all assets
  
  // Patterns
  immediate_sweep: boolean; // < 60 seconds
  batched_sweeps: boolean; // Multiple sweeps in sequence
  timed_sweeps: boolean; // Scheduled/predictable timing
  
  // Block-based timing
  same_block_drain: boolean;
  avg_block_delay: number;
}

// ============================================
// GAS PROFILE ANALYSIS
// ============================================

export interface GasProfile {
  // Gas pricing strategy
  gas_spike_pattern: boolean; // Uses elevated gas during drain
  priority_fee_style: 'AGGRESSIVE' | 'NORMAL' | 'CONSERVATIVE' | 'DYNAMIC';
  
  // Gas usage characteristics
  avg_gas_used: number;
  gas_variance: number;
  
  // MEV protection
  uses_flashbots: boolean;
  uses_private_mempool: boolean;
  
  // Timing
  prefers_low_gas_periods: boolean;
}

// ============================================
// ROUTING BEHAVIOR ANALYSIS
// ============================================

export interface RoutingBehavior {
  // Hop patterns
  hop_count: number; // Average number of intermediate hops
  min_hops: number;
  max_hops: number;
  
  // Destination clusters
  destination_clusters: DestinationCluster[];
  primary_destination: string;
  
  // Routing strategies
  uses_mixers: boolean;
  uses_bridges: boolean;
  uses_dex_swaps: boolean;
  direct_to_cex: boolean;
  
  // Obfuscation
  uses_intermediary_wallets: boolean;
  intermediary_count: number;
  
  // Cross-chain behavior
  bridges_to_chains: Chain[];
  primary_exit_chain: Chain | null;
}

export interface DestinationCluster {
  cluster_id: string;
  addresses: string[];
  total_received_usd: number;
  transaction_count: number;
  cluster_type: 'AGGREGATION' | 'CEX' | 'BRIDGE' | 'MIXER' | 'UNKNOWN';
}

// ============================================
// CODE FEATURES ANALYSIS
// ============================================

export interface CodeFeatures {
  // Proxy patterns
  proxy_usage: boolean;
  proxy_types: ProxyType[];
  
  // Bytecode analysis
  bytecode_hashes: string[]; // Keccak256 hashes of contract bytecode
  bytecode_similarity_clusters: string[]; // IDs of similar bytecode groups
  
  // Execution patterns
  delegatecall_patterns: boolean;
  uses_create2: boolean;
  uses_selfdestruct: boolean;
  
  // Contract characteristics
  is_verified: boolean;
  has_source_code: boolean;
  compiler_version?: string;
  
  // Opcode fingerprint
  opcode_frequency: OpcodeFrequency;
}

export type ProxyType = 
  | 'EIP1167_MINIMAL'
  | 'EIP1967_TRANSPARENT'
  | 'UUPS'
  | 'BEACON'
  | 'CUSTOM'
  | 'NONE';

export interface OpcodeFrequency {
  // Key opcodes and their frequency
  [opcode: string]: number;
}

// ============================================
// VICTIM SELECTION PATTERNS
// ============================================

export interface VictimSelectionPattern {
  // Target characteristics
  targets_high_value_wallets: boolean;
  targets_nft_holders: boolean;
  targets_defi_users: boolean;
  targets_new_wallets: boolean;
  
  // Selection method
  phishing_method: PhishingMethod | null;
  airdrop_scam: boolean;
  fake_mint: boolean;
  
  // Geographic/temporal patterns
  activity_hours_utc: number[]; // Active hours in UTC
  peak_activity_day: number; // 0=Sunday, 6=Saturday
}

export type PhishingMethod =
  | 'FAKE_WEBSITE'
  | 'SOCIAL_ENGINEERING'
  | 'MALICIOUS_DAPP'
  | 'AIRDROP_CLAIM'
  | 'NFT_MINT'
  | 'TOKEN_CLAIM'
  | 'WALLET_CONNECT_ABUSE'
  | 'UNKNOWN';

// ============================================
// EVASION TECHNIQUES
// ============================================

export interface EvasionTechnique {
  technique_id: string;
  name: string;
  description: string;
  detection_difficulty: 'LOW' | 'MEDIUM' | 'HIGH';
}

// ============================================
// CONFIDENCE FACTORS
// ============================================

export interface ConfidenceFactor {
  factor_id: string;
  name: string;
  description: string;
  weight: number; // -100 to +100
  evidence: string[];
}

// ============================================
// FEATURE VECTOR FOR CLUSTERING
// ============================================

/**
 * Normalized feature vector for clustering and similarity comparison.
 * All values normalized to 0-1 range for consistent distance calculations.
 */
export interface DrainerFeatureVector {
  // Identification
  source_address: string;
  chain: Chain;
  extracted_at: string;
  
  // Behavioral features (normalized 0-1)
  features: {
    // Timing features
    avg_drain_delay_normalized: number;
    sweep_window_normalized: number;
    same_block_drain: number; // 0 or 1
    
    // Approval features
    unlimited_approval_rate: number;
    rapid_drain_rate: number;
    permit2_usage: number; // 0 or 1
    
    // Gas features
    gas_aggressiveness: number;
    gas_consistency: number;
    
    // Routing features
    hop_count_normalized: number;
    uses_mixers: number; // 0 or 1
    uses_bridges: number; // 0 or 1
    direct_cex_rate: number;
    
    // Code features
    proxy_usage: number; // 0 or 1
    delegatecall_usage: number; // 0 or 1
    
    // Victim features
    high_value_targeting: number;
    nft_targeting: number;
  };
  
  // Raw metrics for reference
  raw_metrics: {
    total_victims: number;
    total_stolen_usd: number;
    active_days: number;
    unique_destinations: number;
  };
}

// ============================================
// CLUSTERING RESULT
// ============================================

export interface ClusteringResult {
  cluster_id: string;
  family_id: DrainerFamilyId;
  variant_id: DrainerVariantId;
  
  // Similarity metrics
  similarity_score: number; // 0-1
  behavioral_similarity: number;
  structural_similarity: number;
  routing_similarity: number;
  
  // Cluster members
  member_count: number;
  member_addresses: string[];
  
  // Confidence
  confidence: number;
  confidence_level: 'HIGH' | 'MEDIUM' | 'LOW';
  
  // Why this assignment
  assignment_reasons: string[];
}

// ============================================
// ATTRIBUTION RESULT
// ============================================

/**
 * Final attribution result for display in Securnex UI.
 */
export interface DrainerAttribution {
  // Threat classification
  threat_type: 'drainer';
  is_new_drainer: boolean;
  
  // Attribution details
  attribution: {
    family: string; // Human-readable name like "PinkDrainer"
    family_id: DrainerFamilyId;
    variant: string; // e.g., "v3" or "Variant #3"
    variant_id: DrainerVariantId;
    confidence: number; // 0-100
    
    // Impact metrics
    wallets_affected: number;
    total_stolen_usd: number;
    
    // Chain data
    chains: Chain[];
    primary_chain: Chain;
    
    // Temporal data
    active_since: string; // Human-readable date
    last_seen: string;
    is_active: boolean;
  };
  
  // Evidence for this match
  why_this_match: string[];
  
  // Behavioral signature summary
  signature_summary: {
    approval_pattern: string;
    timing_pattern: string;
    routing_pattern: string;
    distinctive_features: string[];
  };
  
  // Related intelligence
  related_addresses: string[];
  known_aliases: string[];
  
  // Risk assessment
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  
  // Timestamps
  analyzed_at: string;
}

// ============================================
// DRAINER FAMILY PROFILES
// ============================================

/**
 * Static profile for a known drainer family.
 * Used as reference for clustering.
 */
export interface DrainerFamilyProfile {
  family_id: DrainerFamilyId;
  name: string;
  description: string;
  
  // First seen data
  first_seen: string;
  first_seen_chain: Chain;
  
  // Known variants
  variants: DrainerVariantProfile[];
  
  // Characteristic features
  characteristic_features: Partial<FingerprintFeatures>;
  
  // Known addresses
  known_contract_addresses: string[];
  known_aggregation_wallets: string[];
  
  // Statistics
  total_victims: number;
  total_stolen_usd: number;
  active_chains: Chain[];
  
  // Status
  is_active: boolean;
  last_activity: string;
}

export interface DrainerVariantProfile {
  variant_id: DrainerVariantId;
  name: string;
  description: string;
  first_seen: string;
  chains: Chain[];
  distinctive_features: string[];
  bytecode_hashes: string[];
}

// ============================================
// EXTRACTION INPUT TYPES
// ============================================

/**
 * Input data for fingerprint extraction from a compromised wallet.
 */
export interface FingerprintExtractionInput {
  // Target wallet
  wallet_address: string;
  chain: Chain;
  
  // Transaction data
  transactions: ExtractionTransaction[];
  token_transfers: ExtractionTokenTransfer[];
  approvals: ExtractionApproval[];
  
  // Optional context
  internal_transactions?: ExtractionInternalTx[];
  contract_creations?: ExtractionContractCreation[];
  
  // Time range
  analysis_start_block?: number;
  analysis_end_block?: number;
}

export interface ExtractionTransaction {
  hash: string;
  from: string;
  to: string;
  value: string;
  input: string;
  gas_used: string;
  gas_price: string;
  timestamp: number;
  block_number: number;
  method_id?: string;
  is_error: boolean;
}

export interface ExtractionTokenTransfer {
  hash: string;
  from: string;
  to: string;
  token_address: string;
  token_symbol: string;
  value: string;
  timestamp: number;
  block_number: number;
  token_type: 'ERC20' | 'ERC721' | 'ERC1155';
}

export interface ExtractionApproval {
  hash: string;
  owner: string;
  spender: string;
  token_address: string;
  token_symbol: string;
  amount: string;
  is_unlimited: boolean;
  timestamp: number;
  block_number: number;
}

export interface ExtractionInternalTx {
  hash: string;
  from: string;
  to: string;
  value: string;
  call_type: 'call' | 'delegatecall' | 'staticcall' | 'create' | 'create2';
  trace_address: string;
}

export interface ExtractionContractCreation {
  hash: string;
  creator: string;
  contract_address: string;
  bytecode: string;
  timestamp: number;
}

// ============================================
// DATABASE TYPES
// ============================================

/**
 * Stored fingerprint in the database.
 */
export interface StoredFingerprint {
  id: string;
  fingerprint: DrainerFingerprint;
  feature_vector: DrainerFeatureVector;
  clustering_result?: ClusteringResult;
  
  // Metadata
  created_at: string;
  updated_at: string;
  source_wallets: string[];
  
  // Search indices
  family_id: DrainerFamilyId;
  variant_id: DrainerVariantId;
  chains: Chain[];
  confidence_score: number;
}

// ============================================
// API RESPONSE TYPES
// ============================================

export interface DrainerDNAAnalysisResponse {
  success: boolean;
  address: string;
  chain: Chain;
  
  // Main result
  is_drainer: boolean;
  attribution: DrainerAttribution | null;
  fingerprint: DrainerFingerprint | null;
  
  // Processing info
  analysis_time_ms: number;
  data_sources: string[];
  
  // Errors/warnings
  warnings: string[];
  errors: string[];
}
