// ============================================
// DRAINER DNA FINGERPRINTING SYSTEM
// ============================================
// Forensic-grade drainer attribution that identifies
// malicious drainers by behavioral + structural signatures.
//
// ARCHITECTURE:
// Layer 1: Schema & Types (types.ts)
// Layer 2: Extraction Pipeline (extraction-pipeline.ts)
// Layer 3: Variant Clustering (clustering.ts)
// Layer 4: Attribution & Output (attribution.ts)
// Orchestration: Service (service.ts)
//
// USAGE:
// ```typescript
// import { getDrainerDNAService } from '@/lib/drainer-dna';
//
// const service = getDrainerDNAService();
// const result = await service.analyzeAddress(address, chain, transactionData);
//
// if (result.is_drainer && result.attribution) {
//   console.log(`Matches ${result.attribution.attribution.family} – ${result.attribution.attribution.variant}`);
//   console.log(`Confidence: ${result.attribution.attribution.confidence}%`);
// }
// ```

// ============================================
// TYPE EXPORTS
// ============================================

export type {
  // Core types
  DrainerFamilyId,
  DrainerVariantId,
  DrainerFingerprint,
  FingerprintFeatures,
  DrainerFeatureVector,
  ClusteringResult,
  DrainerAttribution,
  DrainerDNAAnalysisResponse,
  StoredFingerprint,
  
  // Feature types
  CallPattern,
  ApprovalBehavior,
  ApprovalTarget,
  TransferTiming,
  GasProfile,
  RoutingBehavior,
  DestinationCluster,
  CodeFeatures,
  ProxyType,
  OpcodeFrequency,
  VictimSelectionPattern,
  PhishingMethod,
  EvasionTechnique,
  ConfidenceFactor,
  
  // Extraction input types
  FingerprintExtractionInput,
  ExtractionTransaction,
  ExtractionTokenTransfer,
  ExtractionApproval,
  ExtractionInternalTx,
  ExtractionContractCreation,
  
  // Family profile types
  DrainerFamilyProfile,
  DrainerVariantProfile,
} from './types';

// ============================================
// FAMILY PROFILE EXPORTS
// ============================================

export {
  DRAINER_FAMILY_PROFILES,
  getDrainerFamilyProfile,
  getActiveDrainerFamilies,
  getDrainerFamilyName,
  getAllKnownDrainerAddresses,
} from './family-profiles';

// ============================================
// EXTRACTION PIPELINE EXPORTS
// ============================================

export {
  extractFingerprintFeatures,
  normalizeToFeatureVector,
  UNLIMITED_APPROVAL_THRESHOLD,
  PERMIT2_ADDRESS,
  RAPID_DRAIN_THRESHOLD_SECONDS,
  METHOD_SELECTORS,
} from './extraction-pipeline';

// ============================================
// CLUSTERING EXPORTS
// ============================================

export {
  clusterDrainer,
  buildDrainerFingerprint,
  generateConfidenceFactors,
  SIMILARITY_THRESHOLDS,
  FEATURE_WEIGHTS,
} from './clustering';

// ============================================
// ATTRIBUTION EXPORTS
// ============================================

export {
  generateAttribution,
  generateShortSummary,
  generateAlertHeadline,
  generateImpactStats,
  formatStolenAmount,
  formatAttributionForAPI,
  formatFamilyName,
  formatVariantName,
  assessRiskLevel,
} from './attribution';

// ============================================
// SERVICE EXPORTS
// ============================================

export {
  DrainerDNAService,
  getDrainerDNAService,
} from './service';

// ============================================
// INTEGRATION HELPERS
// ============================================

export {
  adaptTransactionData,
  adaptTokenTransferData,
  adaptApprovalData,
  enhanceWithDrainerDNA,
  formatDrainerDNAForAPI,
  generateDisplayData,
  isKnownDrainerAddress,
  getKnownDrainerFamily,
} from './integration';
