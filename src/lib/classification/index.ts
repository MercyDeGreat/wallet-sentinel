// ============================================
// ATTACK CLASSIFICATION ENGINE - EXPORTS
// ============================================
//
// Securnex Post-Detection Classification System
//
// This module exports the Attack Classification Engine which
// accurately classifies attack types AFTER detection has occurred.
//
// USAGE:
// ```typescript
// import { AttackClassificationEngine, classifyAttack } from '@/lib/classification';
// 
// // Using the engine instance
// const engine = new AttackClassificationEngine();
// const result = await engine.classify(input);
// 
// // Or using the standalone function
// const result = await classifyAttack(input);
// ```
// ============================================

// Main engine
export {
  AttackClassificationEngine,
  classifyAttack,
  DEFAULT_CLASSIFICATION_CONFIG,
} from './AttackClassificationEngine';

// Types
export type {
  AttackType,
  AttackClassification,
  AttackClassificationInput,
  ClassificationConfig,
  ClassifierResult,
  AttackDisplayInfo,
  AttackTechnicalDetails,
  ClassificationTransaction,
  ClassificationTokenTransfer,
  ClassificationApproval,
  GasPatternInfo,
} from './types';

// UX Explanation utilities
export {
  generateAttackDisplayInfo,
  generateDetailedExplanation,
  generateWhyFlaggedContent,
  ATTACK_DISPLAY_CONFIG,
} from './ux-explanation';

// Individual classifiers (for advanced use)
export {
  classifyAddressPoisoning,
  calculateAddressSimilarity,
  isDustValue,
} from './classifiers/address-poisoning';

export {
  classifySweeperBot,
  analyzeGasPatterns,
} from './classifiers/sweeper-bot';

export {
  classifyApprovalDrainer,
  isDangerousApproval,
} from './classifiers/approval-drainer';

export {
  classifySignerCompromise,
} from './classifiers/signer-compromise';

// Integration utilities
export {
  convertToClassificationTransaction,
  convertToClassificationTokenTransfer,
  convertToClassificationApproval,
  extractFrequentRecipients,
  classifyAttackFromAnalysis,
  mapClassificationToThreatType,
  enrichThreatsWithClassification,
  analyzeWithClassification,
} from './integration';
