// ============================================
// DRAINER DNA SERVICE
// ============================================
// Main orchestration service for the Drainer DNA
// Fingerprinting system. Coordinates all four layers:
//
// 1. Schema & Types
// 2. Fingerprint Extraction Pipeline
// 3. Variant Clustering
// 4. Attribution & Output
//
// This service provides a unified API for:
// - Analyzing addresses for drainer attribution
// - Extracting fingerprints from transaction data
// - Comparing fingerprints against known families

import { Chain } from '@/types';
import {
  DrainerFingerprint,
  DrainerFeatureVector,
  DrainerAttribution,
  DrainerDNAAnalysisResponse,
  FingerprintExtractionInput,
  ClusteringResult,
  StoredFingerprint,
  ExtractionTransaction,
  ExtractionTokenTransfer,
  ExtractionApproval,
} from './types';
import { extractFingerprintFeatures, normalizeToFeatureVector } from './extraction-pipeline';
import { clusterDrainer, buildDrainerFingerprint } from './clustering';
import { generateAttribution, generateShortSummary, generateAlertHeadline } from './attribution';
import { getDrainerFamilyProfile, getAllKnownDrainerAddresses, DRAINER_FAMILY_PROFILES } from './family-profiles';

// ============================================
// DRAINER DNA SERVICE CLASS
// ============================================

export class DrainerDNAService {
  private fingerprintCache: Map<string, StoredFingerprint> = new Map();
  private knownDrainerAddresses: Set<string>;
  
  constructor() {
    this.knownDrainerAddresses = getAllKnownDrainerAddresses();
  }
  
  // ============================================
  // MAIN ANALYSIS ENTRY POINT
  // ============================================
  
  /**
   * Analyze an address for drainer attribution.
   * This is the main entry point for the Drainer DNA system.
   */
  async analyzeAddress(
    address: string,
    chain: Chain,
    transactionData: {
      transactions: ExtractionTransaction[];
      tokenTransfers: ExtractionTokenTransfer[];
      approvals: ExtractionApproval[];
    }
  ): Promise<DrainerDNAAnalysisResponse> {
    const startTime = Date.now();
    const normalizedAddress = address.toLowerCase();
    const warnings: string[] = [];
    const errors: string[] = [];
    
    try {
      // Check if address is in known drainer database
      const isKnownDrainer = this.isKnownDrainerAddress(normalizedAddress);
      
      // Prepare extraction input
      const extractionInput: FingerprintExtractionInput = {
        wallet_address: normalizedAddress,
        chain,
        transactions: transactionData.transactions,
        token_transfers: transactionData.tokenTransfers,
        approvals: transactionData.approvals,
      };
      
      // Step 1: Extract fingerprint features
      const features = extractFingerprintFeatures(extractionInput);
      
      // Step 2: Normalize to feature vector
      const destinationAddresses = this.extractDestinationAddresses(transactionData);
      const rawMetrics = this.calculateRawMetrics(transactionData);
      
      const featureVector = normalizeToFeatureVector(
        normalizedAddress,
        chain,
        features,
        rawMetrics
      );
      
      // Step 3: Cluster and identify family/variant
      const clusteringResult = clusterDrainer(
        featureVector,
        features,
        destinationAddresses
      );
      
      // If known drainer, boost confidence
      if (isKnownDrainer) {
        this.boostKnownDrainerConfidence(clusteringResult, normalizedAddress);
      }
      
      // Step 4: Build complete fingerprint
      const fingerprint = buildDrainerFingerprint(
        normalizedAddress,
        chain,
        features,
        featureVector,
        clusteringResult,
        {
          wallet_count: clusteringResult.member_count,
          total_stolen_usd: rawMetrics.total_stolen_usd,
          first_seen: this.findFirstTimestamp(transactionData),
          last_seen: this.findLastTimestamp(transactionData),
        }
      );
      
      // Step 5: Generate attribution
      const attribution = generateAttribution(fingerprint, clusteringResult);
      
      // Determine if this qualifies as a drainer
      const isDrainer = this.determineIsDrainer(clusteringResult, isKnownDrainer);
      
      // Cache the result
      this.cacheFingerprint(normalizedAddress, fingerprint, featureVector, clusteringResult);
      
      return {
        success: true,
        address: normalizedAddress,
        chain,
        is_drainer: isDrainer,
        attribution: isDrainer ? attribution : null,
        fingerprint: isDrainer ? fingerprint : null,
        analysis_time_ms: Date.now() - startTime,
        data_sources: ['transaction_history', 'approval_logs', 'family_profiles'],
        warnings,
        errors,
      };
    } catch (error) {
      errors.push(`Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      return {
        success: false,
        address: normalizedAddress,
        chain,
        is_drainer: false,
        attribution: null,
        fingerprint: null,
        analysis_time_ms: Date.now() - startTime,
        data_sources: [],
        warnings,
        errors,
      };
    }
  }
  
  // ============================================
  // QUICK CHECK METHODS
  // ============================================
  
  /**
   * Quick check if an address is a known drainer.
   * Does not perform full behavioral analysis.
   */
  isKnownDrainerAddress(address: string): boolean {
    return this.knownDrainerAddresses.has(address.toLowerCase());
  }
  
  /**
   * Get family info for a known drainer address.
   */
  getKnownDrainerFamily(address: string): { familyId: string; familyName: string } | null {
    const normalized = address.toLowerCase();
    
    for (const [familyId, profile] of Object.entries(DRAINER_FAMILY_PROFILES)) {
      const allAddresses = [
        ...profile.known_contract_addresses,
        ...profile.known_aggregation_wallets,
      ].map(a => a.toLowerCase());
      
      if (allAddresses.includes(normalized)) {
        return {
          familyId,
          familyName: profile.name,
        };
      }
    }
    
    return null;
  }
  
  // ============================================
  // COMPARISON METHODS
  // ============================================
  
  /**
   * Compare two fingerprints for similarity.
   */
  compareFingerprints(
    fp1: DrainerFingerprint,
    fp2: DrainerFingerprint
  ): {
    similarityScore: number;
    behavioralMatch: boolean;
    structuralMatch: boolean;
    routingMatch: boolean;
    sameFamily: boolean;
  } {
    // Calculate behavioral similarity
    const behavioralScore = this.compareBehavioralFeatures(
      fp1.fingerprint_features,
      fp2.fingerprint_features
    );
    
    // Calculate structural similarity
    const structuralScore = this.compareStructuralFeatures(
      fp1.fingerprint_features,
      fp2.fingerprint_features
    );
    
    // Calculate routing similarity
    const routingScore = this.compareRoutingFeatures(
      fp1.fingerprint_features,
      fp2.fingerprint_features
    );
    
    // Overall similarity
    const similarityScore = (behavioralScore * 0.45 + structuralScore * 0.25 + routingScore * 0.30);
    
    return {
      similarityScore,
      behavioralMatch: behavioralScore >= 0.7,
      structuralMatch: structuralScore >= 0.6,
      routingMatch: routingScore >= 0.7,
      sameFamily: fp1.family_id === fp2.family_id,
    };
  }
  
  // ============================================
  // PRIVATE HELPER METHODS
  // ============================================
  
  private extractDestinationAddresses(transactionData: {
    transactions: ExtractionTransaction[];
    tokenTransfers: ExtractionTokenTransfer[];
  }): string[] {
    const destinations = new Set<string>();
    
    for (const tx of transactionData.transactions) {
      if (tx.to) destinations.add(tx.to.toLowerCase());
    }
    
    for (const transfer of transactionData.tokenTransfers) {
      destinations.add(transfer.to.toLowerCase());
    }
    
    return [...destinations];
  }
  
  private calculateRawMetrics(transactionData: {
    transactions: ExtractionTransaction[];
    tokenTransfers: ExtractionTokenTransfer[];
    approvals: ExtractionApproval[];
  }): {
    total_victims: number;
    total_stolen_usd: number;
    active_days: number;
    unique_destinations: number;
  } {
    // Calculate unique victims (addresses that approved/sent)
    const victims = new Set<string>();
    for (const approval of transactionData.approvals) {
      victims.add(approval.owner.toLowerCase());
    }
    
    // Calculate unique destinations
    const destinations = new Set<string>();
    for (const transfer of transactionData.tokenTransfers) {
      destinations.add(transfer.to.toLowerCase());
    }
    
    // Calculate active days
    const timestamps = [
      ...transactionData.transactions.map(t => t.timestamp),
      ...transactionData.tokenTransfers.map(t => t.timestamp),
    ].filter(t => t > 0);
    
    let activeDays = 0;
    if (timestamps.length > 0) {
      const minTs = Math.min(...timestamps);
      const maxTs = Math.max(...timestamps);
      activeDays = Math.ceil((maxTs - minTs) / (24 * 60 * 60));
    }
    
    // Estimate total stolen (would need price data for accuracy)
    // For now, use transfer count as proxy
    const totalStolen = transactionData.tokenTransfers.length * 1000; // Placeholder
    
    return {
      total_victims: victims.size,
      total_stolen_usd: totalStolen,
      active_days: Math.max(1, activeDays),
      unique_destinations: destinations.size,
    };
  }
  
  private findFirstTimestamp(transactionData: {
    transactions: ExtractionTransaction[];
    tokenTransfers: ExtractionTokenTransfer[];
    approvals: ExtractionApproval[];
  }): string {
    const timestamps = [
      ...transactionData.transactions.map(t => t.timestamp),
      ...transactionData.tokenTransfers.map(t => t.timestamp),
      ...transactionData.approvals.map(a => a.timestamp),
    ].filter(t => t > 0);
    
    if (timestamps.length === 0) return new Date().toISOString();
    
    return new Date(Math.min(...timestamps) * 1000).toISOString();
  }
  
  private findLastTimestamp(transactionData: {
    transactions: ExtractionTransaction[];
    tokenTransfers: ExtractionTokenTransfer[];
    approvals: ExtractionApproval[];
  }): string {
    const timestamps = [
      ...transactionData.transactions.map(t => t.timestamp),
      ...transactionData.tokenTransfers.map(t => t.timestamp),
      ...transactionData.approvals.map(a => a.timestamp),
    ].filter(t => t > 0);
    
    if (timestamps.length === 0) return new Date().toISOString();
    
    return new Date(Math.max(...timestamps) * 1000).toISOString();
  }
  
  private boostKnownDrainerConfidence(
    clusteringResult: ClusteringResult,
    address: string
  ): void {
    const familyInfo = this.getKnownDrainerFamily(address);
    
    if (familyInfo) {
      // Override with known family
      clusteringResult.family_id = familyInfo.familyId as any;
      clusteringResult.confidence = Math.max(clusteringResult.confidence, 95);
      clusteringResult.confidence_level = 'HIGH';
      clusteringResult.assignment_reasons.unshift('Address in verified drainer database');
    } else {
      // Boost confidence for being in database
      clusteringResult.confidence = Math.max(clusteringResult.confidence, 85);
      clusteringResult.assignment_reasons.unshift('Address in known malicious database');
    }
  }
  
  private determineIsDrainer(
    clusteringResult: ClusteringResult,
    isKnownDrainer: boolean
  ): boolean {
    // Known drainer = definitely a drainer
    if (isKnownDrainer) return true;
    
    // High confidence clustering = drainer
    if (clusteringResult.confidence >= 70) return true;
    
    // Medium confidence with behavioral match = likely drainer
    if (clusteringResult.confidence >= 55 && clusteringResult.behavioral_similarity >= 0.6) {
      return true;
    }
    
    return false;
  }
  
  private cacheFingerprint(
    address: string,
    fingerprint: DrainerFingerprint,
    featureVector: DrainerFeatureVector,
    clusteringResult: ClusteringResult
  ): void {
    const stored: StoredFingerprint = {
      id: fingerprint.fingerprint_id,
      fingerprint,
      feature_vector: featureVector,
      clustering_result: clusteringResult,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      source_wallets: [address],
      family_id: fingerprint.family_id,
      variant_id: fingerprint.variant_id,
      chains: fingerprint.chains,
      confidence_score: fingerprint.confidence_score,
    };
    
    this.fingerprintCache.set(address.toLowerCase(), stored);
  }
  
  private compareBehavioralFeatures(
    f1: DrainerFingerprint['fingerprint_features'],
    f2: DrainerFingerprint['fingerprint_features']
  ): number {
    let score = 0;
    let total = 0;
    
    // Compare approval behavior
    if (f1.approval_behavior.uses_permit2 === f2.approval_behavior.uses_permit2) score++;
    total++;
    
    if (f1.approval_behavior.prefers_unlimited_approvals === f2.approval_behavior.prefers_unlimited_approvals) score++;
    total++;
    
    // Compare timing
    if (f1.transfer_timing.same_block_drain === f2.transfer_timing.same_block_drain) score++;
    total++;
    
    // Compare gas
    if (f1.gas_profile.priority_fee_style === f2.gas_profile.priority_fee_style) score++;
    total++;
    
    return total > 0 ? score / total : 0;
  }
  
  private compareStructuralFeatures(
    f1: DrainerFingerprint['fingerprint_features'],
    f2: DrainerFingerprint['fingerprint_features']
  ): number {
    let score = 0;
    let total = 0;
    
    if (f1.code_features.proxy_usage === f2.code_features.proxy_usage) score++;
    total++;
    
    if (f1.code_features.delegatecall_patterns === f2.code_features.delegatecall_patterns) score++;
    total++;
    
    return total > 0 ? score / total : 0;
  }
  
  private compareRoutingFeatures(
    f1: DrainerFingerprint['fingerprint_features'],
    f2: DrainerFingerprint['fingerprint_features']
  ): number {
    let score = 0;
    let total = 0;
    
    if (f1.routing_behavior.uses_mixers === f2.routing_behavior.uses_mixers) score++;
    total++;
    
    if (f1.routing_behavior.direct_to_cex === f2.routing_behavior.direct_to_cex) score++;
    total++;
    
    const hopDiff = Math.abs(f1.routing_behavior.hop_count - f2.routing_behavior.hop_count);
    if (hopDiff <= 1) score++;
    total++;
    
    return total > 0 ? score / total : 0;
  }
  
  // ============================================
  // CACHE MANAGEMENT
  // ============================================
  
  /**
   * Get cached fingerprint for an address.
   */
  getCachedFingerprint(address: string): StoredFingerprint | null {
    return this.fingerprintCache.get(address.toLowerCase()) || null;
  }
  
  /**
   * Clear the fingerprint cache.
   */
  clearCache(): void {
    this.fingerprintCache.clear();
  }
  
  /**
   * Get cache statistics.
   */
  getCacheStats(): { size: number; families: Record<string, number> } {
    const families: Record<string, number> = {};
    
    for (const stored of this.fingerprintCache.values()) {
      families[stored.family_id] = (families[stored.family_id] || 0) + 1;
    }
    
    return {
      size: this.fingerprintCache.size,
      families,
    };
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let drainerDNAServiceInstance: DrainerDNAService | null = null;

/**
 * Get the singleton DrainerDNAService instance.
 */
export function getDrainerDNAService(): DrainerDNAService {
  if (!drainerDNAServiceInstance) {
    drainerDNAServiceInstance = new DrainerDNAService();
  }
  return drainerDNAServiceInstance;
}

// DrainerDNAService is exported inline above
