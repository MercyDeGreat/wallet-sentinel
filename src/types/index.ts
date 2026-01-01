// ============================================
// WALLET SENTINEL - TYPE DEFINITIONS
// ============================================

// Supported blockchain networks
export type Chain = 'ethereum' | 'base' | 'bnb' | 'solana';

// Security status levels
export type SecurityStatus = 'SAFE' | 'AT_RISK' | 'COMPROMISED';

// Attack type classifications
export type AttackType =
  | 'WALLET_DRAINER'
  | 'APPROVAL_HIJACK'
  | 'PRIVATE_KEY_LEAK'
  | 'PHISHING_SIGNATURE'
  | 'MALICIOUS_NFT_AIRDROP'
  | 'COMPROMISED_PROGRAM_AUTHORITY'
  | 'ROGUE_CONTRACT_INTERACTION'
  | 'MEV_SANDWICH_DRAIN'
  | 'UNKNOWN';

// Risk severity levels
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// Token standards
export type TokenStandard = 'ERC20' | 'ERC721' | 'ERC1155' | 'SPL' | 'NATIVE';

// ============================================
// WALLET ANALYSIS TYPES
// ============================================

export interface WalletAnalysisRequest {
  address: string;
  chain: Chain;
  includeApprovals?: boolean;
  includeTransactions?: boolean;
  includeRiskMonitoring?: boolean;
}

export interface WalletAnalysisResult {
  address: string;
  chain: Chain;
  timestamp: string;
  securityStatus: SecurityStatus;
  riskScore: number; // 0-100
  summary: string;
  detectedThreats: DetectedThreat[];
  approvals: TokenApproval[];
  suspiciousTransactions: SuspiciousTransaction[];
  recommendations: SecurityRecommendation[];
  recoveryPlan?: RecoveryPlan;
  educationalContent?: EducationalContent;
}

export interface DetectedThreat {
  id: string;
  type: AttackType;
  severity: RiskLevel;
  title: string;
  description: string;
  technicalDetails: string;
  detectedAt: string;
  relatedAddresses: string[];
  relatedTransactions: string[];
  ongoingRisk: boolean;
  recoverableAssets?: AssetInfo[];
}

export interface TokenApproval {
  id: string;
  token: TokenInfo;
  spender: string;
  spenderLabel?: string;
  amount: string;
  isUnlimited: boolean;
  riskLevel: RiskLevel;
  riskReason?: string;
  grantedAt: string;
  lastUsed?: string;
  isMalicious: boolean;
}

export interface TokenInfo {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  standard: TokenStandard;
  logoUrl?: string;
  verified: boolean;
}

export interface AssetInfo {
  token: TokenInfo;
  balance: string;
  balanceUsd?: number;
  isRecoverable: boolean;
  recoveryMethod?: string;
}

export interface SuspiciousTransaction {
  hash: string;
  timestamp: string;
  type: string;
  from: string;
  to: string;
  value?: string;
  riskLevel: RiskLevel;
  flags: string[];
  description: string;
}

// ============================================
// RECOVERY & CONTAINMENT TYPES
// ============================================

export interface RecoveryPlan {
  urgencyLevel: RiskLevel;
  estimatedTimeMinutes: number;
  steps: RecoveryStep[];
  warnings: string[];
  safeWalletRequired: boolean;
}

export interface RecoveryStep {
  order: number;
  title: string;
  description: string;
  action: RecoveryAction;
  estimatedGasCost?: string;
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  completed?: boolean;
}

export interface RecoveryAction {
  type: 'REVOKE_APPROVAL' | 'TRANSFER_ASSETS' | 'CLOSE_ACCOUNT' | 'DELEGATE_REVOKE' | 'MANUAL';
  contractAddress?: string;
  tokenAddress?: string;
  callData?: string;
  simulationResult?: TransactionSimulation;
}

export interface TransactionSimulation {
  success: boolean;
  gasEstimate: string;
  warnings: string[];
  assetChanges: AssetChange[];
  drainerInterception: boolean;
  safeToExecute: boolean;
}

export interface AssetChange {
  token: string;
  from: string;
  to: string;
  amount: string;
  direction: 'IN' | 'OUT';
}

// ============================================
// SECURITY RECOMMENDATIONS
// ============================================

export interface SecurityRecommendation {
  id: string;
  priority: RiskLevel;
  category: 'IMMEDIATE' | 'SHORT_TERM' | 'LONG_TERM';
  title: string;
  description: string;
  actionable: boolean;
  actionType?: string;
}

export interface EducationalContent {
  attackExplanation: AttackExplanation;
  preventionTips: PreventionTip[];
  securityChecklist: ChecklistItem[];
}

export interface AttackExplanation {
  whatHappened: string;
  howItWorks: string;
  ongoingDamage: string;
  recoverableInfo: string;
}

export interface PreventionTip {
  title: string;
  description: string;
  importance: RiskLevel;
}

export interface ChecklistItem {
  id: string;
  category: string;
  item: string;
  completed: boolean;
  chainSpecific?: Chain[];
}

// ============================================
// MALICIOUS DATABASE TYPES
// ============================================

export interface MaliciousContract {
  address: string;
  chain: Chain;
  type: AttackType;
  name?: string;
  reportedAt: string;
  confirmationLevel: 'CONFIRMED' | 'SUSPECTED' | 'COMMUNITY_REPORTED';
  incidentUrl?: string;
  affectedUsers?: number;
}

export interface DrainerPattern {
  id: string;
  name: string;
  signatures: string[];
  contractBytecodePatterns?: string[];
  behaviorPatterns: BehaviorPattern[];
}

export interface BehaviorPattern {
  type: string;
  description: string;
  threshold?: number;
  timeWindowMinutes?: number;
}

// ============================================
// API RESPONSE TYPES
// ============================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
  timestamp: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: string;
}

// ============================================
// LIVE MONITORING TYPES
// ============================================

export interface MonitoringAlert {
  id: string;
  type: 'ACTIVE_DRAIN' | 'NEW_APPROVAL' | 'SUSPICIOUS_TX' | 'DRAINER_CALLBACK';
  severity: RiskLevel;
  message: string;
  timestamp: string;
  requiresAction: boolean;
  timeToAct?: string;
}

export interface LiveMonitoringSession {
  sessionId: string;
  walletAddress: string;
  chain: Chain;
  startedAt: string;
  alerts: MonitoringAlert[];
  isActive: boolean;
}

