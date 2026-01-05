// ============================================
// DETECTION ENGINE EXPORTS
// ============================================
// Complete detection system with false-positive prevention

// Core detection engine
export * from './detection-engine';

// Malicious address database
export * from './malicious-database';

// Drainer address lists
export * from './drainer-addresses';

// Threat intelligence APIs
export * from './threat-intelligence';

// NEW: Safe contracts allowlist (prevents false positives)
export * from './safe-contracts';

// NEW: Contract classification (classify before flagging)
export * from './contract-classifier';

// NEW: Behavioral analysis (behavior-based detection)
export * from './behavior-analyzer';

// NEW: Transaction labeling (explicit LEGITIMATE vs SUSPICIOUS)
export * from './transaction-labeler';

// NEW: Conservative analyzer (maximum false-positive prevention)
export * from './conservative-analyzer';
