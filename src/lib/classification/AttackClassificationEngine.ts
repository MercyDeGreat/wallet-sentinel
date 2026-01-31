// ============================================
// ATTACK CLASSIFICATION ENGINE
// ============================================
//
// Securnex Post-Detection Classification System
//
// PURPOSE: 
// This engine runs AFTER raw threat detection to accurately classify
// the specific attack type. Detection tells us "something is wrong";
// classification tells us "what exactly happened".
//
// SUPPORTED ATTACK TYPES:
// 1. ADDRESS_POISONING - Social engineering via look-alike addresses
// 2. SWEEPER_BOT - Automated immediate fund drainage
// 3. APPROVAL_DRAINER - Token approval exploitation
// 4. SIGNER_COMPROMISE - Private key theft
// 5. SUSPICIOUS_ACTIVITY - Multiple signals, unclear type
// 6. NO_COMPROMISE - No attack detected
//
// HARD RULES:
// - Never label address poisoning as sweeper bot
// - Never say "wallet compromised" without signer or approval proof
// - Always explain uncertainty
// - Classification ≠ Detection
// ============================================

import type { Chain, CompromiseEvidence } from '@/types';
import type {
  AttackType,
  AttackClassification,
  AttackClassificationInput,
  ClassificationConfig,
  ClassifierResult,
  DEFAULT_CLASSIFICATION_CONFIG,
  ATTACK_TYPE_PRIORITY,
} from './types';

import { classifyAddressPoisoning } from './classifiers/address-poisoning';
import { classifySweeperBot } from './classifiers/sweeper-bot';
import { classifyApprovalDrainer } from './classifiers/approval-drainer';
import { classifySignerCompromise } from './classifiers/signer-compromise';
import { 
  generateAttackDisplayInfo, 
  generateWhyFlaggedContent,
} from './ux-explanation';

// Re-export for convenience
export { DEFAULT_CLASSIFICATION_CONFIG } from './types';
export type { AttackType, AttackClassification, AttackClassificationInput } from './types';

// ============================================
// MAIN ENGINE CLASS
// ============================================

/**
 * Attack Classification Engine
 * 
 * Usage:
 * ```typescript
 * const engine = new AttackClassificationEngine();
 * const classification = await engine.classify(input);
 * console.log(classification.type); // e.g., 'ADDRESS_POISONING'
 * console.log(classification.explanation);
 * ```
 */
export class AttackClassificationEngine {
  private config: ClassificationConfig;
  
  constructor(config: Partial<ClassificationConfig> = {}) {
    // Merge with defaults
    this.config = {
      ...{
        addressSimilarityThreshold: 4,
        minDustTransfersForPoisoning: 2,
        dustValueThreshold: '100000000000000',
        sweeperTimeDeltaSeconds: 60,
        minSweeperPatternCount: 2,
        minApprovalValueForDrainer: '1000000000000000000',
        behaviorDeviationThreshold: 70,
        rapidDrainAssetCount: 3,
      },
      ...config,
    };
  }
  
  /**
   * Classify an attack based on the provided input data.
   * 
   * This method:
   * 1. Runs all individual classifiers
   * 2. Resolves conflicts using priority and confidence
   * 3. Generates human-readable explanations
   * 4. Returns a complete classification result
   */
  async classify(input: AttackClassificationInput): Promise<AttackClassification> {
    const startTime = Date.now();
    const currentTimestamp = input.currentTimestamp || Math.floor(Date.now() / 1000);
    
    // Run all classifiers in parallel
    const classifierResults = await this.runAllClassifiers(input);
    
    // Resolve to a single attack type
    const { attackType, winningResult, allPositiveIndicators, allRuledOutIndicators } = 
      this.resolveAttackType(classifierResults);
    
    // Generate display info
    const display = generateAttackDisplayInfo(
      attackType,
      winningResult?.confidence || 0,
      allPositiveIndicators,
      allRuledOutIndicators
    );
    
    // Generate "Why Securnex Flagged This" content
    const whyFlagged = generateWhyFlaggedContent(
      allPositiveIndicators,
      allRuledOutIndicators
    );
    
    // Build technical details
    const technicalDetails = this.buildTechnicalDetails(winningResult, classifierResults);
    
    // Build explanation
    const explanation = this.buildExplanation(attackType, winningResult, display);
    
    return {
      type: attackType,
      confidence: winningResult?.confidence || 0,
      explanation,
      indicators: whyFlagged.positiveSignals,
      ruledOut: whyFlagged.ruledOutSignals,
      technicalDetails,
      display,
      classifiedAt: new Date().toISOString(),
      chain: input.chain,
    };
  }
  
  /**
   * Run all individual classifiers
   */
  private async runAllClassifiers(
    input: AttackClassificationInput
  ): Promise<Map<AttackType, ClassifierResult>> {
    const results = new Map<AttackType, ClassifierResult>();
    
    // 1. Address Poisoning Classifier
    const poisoningResult = classifyAddressPoisoning(
      input.walletAddress,
      input.transactions,
      input.tokenTransfers,
      input.frequentRecipients || [],
      this.config
    );
    results.set('ADDRESS_POISONING', poisoningResult);
    
    // 2. Sweeper Bot Classifier
    const sweeperResult = classifySweeperBot(
      input.walletAddress,
      input.transactions,
      input.tokenTransfers,
      this.config
    );
    results.set('SWEEPER_BOT', sweeperResult);
    
    // 3. Approval Drainer Classifier
    const approvalResult = classifyApprovalDrainer(
      input.walletAddress,
      input.transactions,
      input.tokenTransfers,
      input.approvals,
      input.maliciousAddresses,
      this.config
    );
    results.set('APPROVAL_DRAINER', approvalResult);
    
    // 4. Signer Compromise Classifier
    const signerResult = classifySignerCompromise(
      input.walletAddress,
      input.transactions,
      input.tokenTransfers,
      input.approvals,
      input.maliciousAddresses,
      this.config
    );
    results.set('SIGNER_COMPROMISE', signerResult);
    
    return results;
  }
  
  /**
   * Resolve conflicts between multiple detected attack types.
   * Uses priority order and confidence scores.
   */
  private resolveAttackType(
    classifierResults: Map<AttackType, ClassifierResult>
  ): {
    attackType: AttackType;
    winningResult: ClassifierResult | null;
    allPositiveIndicators: string[];
    allRuledOutIndicators: string[];
  } {
    // Collect all positive and ruled out indicators
    const allPositiveIndicators: string[] = [];
    const allRuledOutIndicators: string[] = [];
    
    for (const [type, result] of classifierResults) {
      allPositiveIndicators.push(...result.positiveIndicators);
      allRuledOutIndicators.push(...result.ruledOutIndicators);
    }
    
    // Find all detected attack types
    const detectedTypes: { type: AttackType; result: ClassifierResult }[] = [];
    
    for (const [type, result] of classifierResults) {
      if (result.detected && result.confidence >= 40) { // Minimum confidence threshold
        detectedTypes.push({ type, result });
      }
    }
    
    // If no attacks detected, return NO_COMPROMISE
    if (detectedTypes.length === 0) {
      return {
        attackType: 'NO_COMPROMISE',
        winningResult: null,
        allPositiveIndicators,
        allRuledOutIndicators,
      };
    }
    
    // If only one attack type detected, use it
    if (detectedTypes.length === 1) {
      return {
        attackType: detectedTypes[0].type,
        winningResult: detectedTypes[0].result,
        allPositiveIndicators,
        allRuledOutIndicators,
      };
    }
    
    // Multiple attack types detected - resolve conflict
    // ============================================
    // CONFLICT RESOLUTION RULES:
    // 1. If ADDRESS_POISONING is detected, it CANNOT be SWEEPER_BOT
    //    (These are mutually exclusive patterns)
    // 2. SIGNER_COMPROMISE takes priority over others
    // 3. Higher confidence wins when priority is equal
    // ============================================
    
    // HARD RULE: Address poisoning excludes sweeper bot
    const hasPoisoning = detectedTypes.some(d => d.type === 'ADDRESS_POISONING');
    const hasSweeper = detectedTypes.some(d => d.type === 'SWEEPER_BOT');
    
    if (hasPoisoning && hasSweeper) {
      // Compare confidence - but poisoning pattern should win unless
      // sweeper has MUCH higher confidence (>20% difference)
      const poisoningConf = detectedTypes.find(d => d.type === 'ADDRESS_POISONING')!.result.confidence;
      const sweeperConf = detectedTypes.find(d => d.type === 'SWEEPER_BOT')!.result.confidence;
      
      if (sweeperConf > poisoningConf + 20) {
        // Sweeper has significantly higher confidence
        // But we should still verify it's not actually poisoning
        console.warn(
          `[AttackClassificationEngine] Conflict: Both ADDRESS_POISONING (${poisoningConf}%) and ` +
          `SWEEPER_BOT (${sweeperConf}%) detected. Sweeper has higher confidence but poisoning ` +
          `patterns should be verified.`
        );
      }
      
      // Default to poisoning if pattern exists - it's more specific
      // Filter out sweeper from candidates
      const filteredTypes = detectedTypes.filter(d => d.type !== 'SWEEPER_BOT');
      if (filteredTypes.length > 0) {
        return this.selectWinner(filteredTypes, allPositiveIndicators, allRuledOutIndicators);
      }
    }
    
    return this.selectWinner(detectedTypes, allPositiveIndicators, allRuledOutIndicators);
  }
  
  /**
   * Select the winning attack type from candidates
   */
  private selectWinner(
    candidates: { type: AttackType; result: ClassifierResult }[],
    allPositiveIndicators: string[],
    allRuledOutIndicators: string[]
  ): {
    attackType: AttackType;
    winningResult: ClassifierResult | null;
    allPositiveIndicators: string[];
    allRuledOutIndicators: string[];
  } {
    // Sort by priority (lower = higher priority), then by confidence
    const priorityMap: Record<AttackType, number> = {
      'SIGNER_COMPROMISE': 1,
      'APPROVAL_DRAINER': 2,
      'SWEEPER_BOT': 3,
      'ADDRESS_POISONING': 4,
      'SUSPICIOUS_ACTIVITY': 5,
      'NO_COMPROMISE': 6,
    };
    
    const sorted = [...candidates].sort((a, b) => {
      // First by priority
      const priorityDiff = priorityMap[a.type] - priorityMap[b.type];
      if (priorityDiff !== 0) return priorityDiff;
      
      // Then by confidence
      return b.result.confidence - a.result.confidence;
    });
    
    // If we have multiple high-confidence detections of different types,
    // and they're close in confidence, return SUSPICIOUS_ACTIVITY
    if (sorted.length >= 2) {
      const topTwo = sorted.slice(0, 2);
      const confDiff = Math.abs(topTwo[0].result.confidence - topTwo[1].result.confidence);
      
      // If top two are within 15% confidence and different priority levels
      if (confDiff <= 15 && priorityMap[topTwo[0].type] !== priorityMap[topTwo[1].type]) {
        // Ambiguous - return SUSPICIOUS_ACTIVITY with merged indicators
        return {
          attackType: 'SUSPICIOUS_ACTIVITY',
          winningResult: {
            detected: true,
            confidence: Math.max(topTwo[0].result.confidence, topTwo[1].result.confidence) - 10,
            positiveIndicators: [
              ...topTwo[0].result.positiveIndicators,
              ...topTwo[1].result.positiveIndicators,
            ],
            ruledOutIndicators: [],
            evidence: {
              transactionHashes: [
                ...topTwo[0].result.evidence.transactionHashes,
                ...topTwo[1].result.evidence.transactionHashes,
              ],
              addresses: [
                ...topTwo[0].result.evidence.addresses,
                ...topTwo[1].result.evidence.addresses,
              ],
              timestamps: [
                ...topTwo[0].result.evidence.timestamps,
                ...topTwo[1].result.evidence.timestamps,
              ],
            },
            reasoning: `Multiple attack patterns detected: ${topTwo[0].type} and ${topTwo[1].type}. ` +
              `Classification uncertain.`,
          },
          allPositiveIndicators,
          allRuledOutIndicators,
        };
      }
    }
    
    return {
      attackType: sorted[0].type,
      winningResult: sorted[0].result,
      allPositiveIndicators,
      allRuledOutIndicators,
    };
  }
  
  /**
   * Build technical details from classifier results
   */
  private buildTechnicalDetails(
    winningResult: ClassifierResult | null,
    allResults: Map<AttackType, ClassifierResult>
  ): AttackClassification['technicalDetails'] {
    if (!winningResult) {
      return undefined;
    }
    
    return {
      transactionHashes: [...new Set(winningResult.evidence.transactionHashes)],
      involvedAddresses: [...new Set(winningResult.evidence.addresses)],
      affectedTokens: [], // TODO: Extract from evidence
      blockRange: undefined, // TODO: Calculate from transactions
      timeDelta: undefined, // TODO: Calculate for sweeper
      similarityScore: undefined, // TODO: Include for poisoning
      gasPatterns: undefined, // TODO: Include for sweeper
    };
  }
  
  /**
   * Build the main explanation text
   */
  private buildExplanation(
    attackType: AttackType,
    result: ClassifierResult | null,
    display: AttackClassification['display']
  ): string {
    if (!result) {
      return 'No attack patterns detected. Wallet appears safe based on available data.';
    }
    
    return result.reasoning || display.summary;
  }
  
  /**
   * Update configuration
   */
  setConfig(config: Partial<ClassificationConfig>): void {
    this.config = {
      ...this.config,
      ...config,
    };
  }
  
  /**
   * Get current configuration
   */
  getConfig(): ClassificationConfig {
    return { ...this.config };
  }
}

// ============================================
// STANDALONE FUNCTION (for convenience)
// ============================================

/**
 * Classify an attack using the default configuration.
 * 
 * Usage:
 * ```typescript
 * const classification = await classifyAttack(input);
 * ```
 */
export async function classifyAttack(
  input: AttackClassificationInput,
  config?: Partial<ClassificationConfig>
): Promise<AttackClassification> {
  const engine = new AttackClassificationEngine(config);
  return engine.classify(input);
}

// Note: AttackClassificationEngine and classifyAttack are already exported inline above
