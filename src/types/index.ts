// ============================================
// SECURNEX - TYPE DEFINITIONS
// ============================================
// Security analysis types with behavioral risk scoring
// Prevents false positives through directional analysis

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

// ============================================
// WALLET ROLE CLASSIFICATION
// ============================================
// Critical for preventing false positives:
// - A wallet that RECEIVES from compromised wallets is NOT automatically malicious
// - Must analyze BEHAVIOR and DIRECTION of fund flow

export type WalletRole = 
  | 'VICTIM'              // Lost funds to drainer/attacker
  | 'ATTACKER'            // Initiated malicious transactions, received stolen funds
  | 'INFRASTRUCTURE'      // DEX, bridge, router - neutral intermediary
  | 'SERVICE_RECEIVER'    // Receives fees/payments from many sources (NOT malicious)
  | 'INDIRECT_EXPOSURE'   // Had contact with compromised wallet but no malicious behavior
  | 'UNKNOWN';            // Insufficient data to classify

// ============================================
// WEIGHTED RISK SCORING
// ============================================
// Replaces boolean isDrainer with nuanced scoring
// Indirect exposure should NOT trigger alerts

export interface RiskScoreBreakdown {
  // Base score from detected threats (0-100)
  threatScore: number;
  
  // Behavioral indicators (-20 to +40)
  behaviorScore: number;
  
  // Approval risk score (0-30)
  approvalScore: number;
  
  // Exposure penalty - minimal for indirect contact (0-10)
  exposureScore: number;
  
  // Final weighted score (0-100)
  totalScore: number;
  
  // Factors that contributed to the score
  factors: RiskFactor[];
}

export interface RiskFactor {
  id: string;
  type: RiskFactorType;
  weight: number;  // Positive = increases risk, Negative = decreases risk
  description: string;
  evidence?: string[];
}

export type RiskFactorType =
  | 'DIRECT_MALICIOUS_CALL'      // Wallet called a malicious function (HIGH weight)
  | 'RECEIVED_FROM_DRAINER'      // Received funds from drainer (MEDIUM weight - could be refund)
  | 'SENT_TO_DRAINER'            // Sent funds to drainer (HIGH weight)
  | 'APPROVAL_TO_MALICIOUS'      // Approved malicious spender (CRITICAL weight)
  | 'TRANSFERFROM_INITIATED'     // Used transferFrom to drain (CRITICAL weight)
  | 'INDIRECT_CONTACT'           // Interacted with wallet that was compromised (LOW weight)
  | 'HIGH_VOLUME_RECEIVER'       // Receives from many wallets (NEUTRAL - likely service)
  | 'INFRASTRUCTURE_USAGE'       // Used known DEX/bridge (NEGATIVE - reduces suspicion)
  | 'NORMAL_TRADING_PATTERN'     // Regular buy/sell pattern (NEGATIVE - reduces suspicion)
  | 'TIME_CLUSTERED_DRAIN'       // Multiple assets drained in short window (CRITICAL)
  | 'SWEEPER_PATTERN'            // Funds swept immediately after deposit (CRITICAL);

// ============================================
// TRANSACTION DIRECTION ANALYSIS
// ============================================
// Essential for distinguishing victim from attacker

export interface DirectionalAnalysis {
  // Did this wallet SEND assets to a malicious address?
  sentToMalicious: boolean;
  sentToMaliciousCount: number;
  sentToMaliciousValue: string;
  
  // Did this wallet RECEIVE assets from a malicious address?
  receivedFromMalicious: boolean;
  receivedFromMaliciousCount: number;
  receivedFromMaliciousValue: string;
  
  // Did this wallet CALL malicious contract functions?
  calledMaliciousFunction: boolean;
  maliciousFunctionsCalled: string[];
  
  // Did this wallet APPROVE a malicious spender?
  approvedMaliciousSpender: boolean;
  maliciousApprovals: string[];
  
  // Was this wallet DRAINED via transferFrom by another party?
  drainedViaTransferFrom: boolean;
  drainerAddresses: string[];
  
  // Conclusion
  walletRole: WalletRole;
  roleConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

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
  attackerInfo?: {
    address: string;
    type: 'SWEEPER_BOT' | 'DRAINER' | 'PHISHING' | 'UNKNOWN';
    sweepCount?: number;
    avgResponseTime?: number;
    totalStolen?: string;
  };
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


