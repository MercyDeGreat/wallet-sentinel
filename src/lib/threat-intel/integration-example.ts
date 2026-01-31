// ============================================
// THREAT INTEL INTEGRATION EXAMPLE
// ============================================
// This file demonstrates how to integrate the ThreatIntelService
// into your wallet analysis pipeline.
//
// DO NOT use this file directly in production - it's for reference only.

import {
  getThreatIntelService,
  checkAddressThreat,
  checkDomainThreat,
  ThreatReport,
  OFF_CHAIN_LABELS,
  FeatureFlags,
} from './index';

// ============================================
// BASIC USAGE
// ============================================

/**
 * Example 1: Quick address check
 */
async function exampleQuickCheck() {
  // Check if threat intel is enabled
  if (!FeatureFlags.isRealThreatIntelEnabled()) {
    console.log('Threat intel is disabled. Set USE_REAL_THREAT_INTEL=true');
    return;
  }

  // Quick check using convenience function
  const report = await checkAddressThreat(
    '0x1234567890abcdef1234567890abcdef12345678',
    'ethereum'
  );

  if (report.threatDetected) {
    console.log('Threat detected!');
    console.log('Risk Level:', report.riskLevel);
    console.log('Risk Score:', report.overallRiskScore);
    console.log('Findings:', report.findings.length);
    
    // IMPORTANT: Always show off-chain label
    console.log('\n' + OFF_CHAIN_LABELS.label);
  } else {
    console.log('No threats detected');
  }
}

/**
 * Example 2: Using the service directly
 */
async function exampleServiceUsage() {
  const service = getThreatIntelService();

  // Check wallet address
  const walletReport = await service.checkAddress({
    value: '0x1234567890abcdef1234567890abcdef12345678',
    type: 'wallet',
    chain: 'ethereum',
  });

  // Check domain
  const domainReport = await service.checkAddress({
    value: 'suspicious-site.com',
    type: 'domain',
  });

  // Check contract
  const contractReport = await service.checkAddress({
    value: '0xabcdef1234567890abcdef1234567890abcdef12',
    type: 'contract',
    chain: 'base',
  });

  return { walletReport, domainReport, contractReport };
}

// ============================================
// INTEGRATION WITH WALLET ANALYSIS
// ============================================

import type { WalletAnalysisResult, OffChainThreatIntelligence } from '@/types';

/**
 * Example 3: Integrating with wallet analysis pipeline
 */
async function enhanceWalletAnalysisWithThreatIntel(
  analysisResult: WalletAnalysisResult
): Promise<WalletAnalysisResult> {
  // Skip if threat intel is disabled
  if (!FeatureFlags.isRealThreatIntelEnabled()) {
    return analysisResult;
  }

  try {
    const report = await checkAddressThreat(
      analysisResult.address,
      analysisResult.chain
    );

    // Convert ThreatReport to OffChainThreatIntelligence for WalletAnalysisResult
    const offChainIntel: OffChainThreatIntelligence = {
      riskDetected: report.threatDetected,
      signalCount: report.findings.length,
      sourceCount: report.queriedProviders.length,
      exposureScore: report.overallRiskScore / 100, // Normalize to 0-1
      exposureLevel: report.riskLevel === 'safe' ? 'none' :
                     report.riskLevel === 'suspicious' ? 'low' :
                     report.riskLevel === 'high_risk' ? 'high' : 'critical',
      headline: report.displaySummary.headline,
      explanation: report.displaySummary.explanation,
      guidance: report.displaySummary.guidance,
      statusLine: `${report.findings.length} off-chain report(s) from ${report.queriedProviders.length} provider(s)`,
      highestConfidence: report.findings.length > 0 
        ? (report.findings[0].confidence >= 80 ? 'high' :
           report.findings[0].confidence >= 50 ? 'medium' : 'low')
        : null,
      fullAssessment: report,
    };

    return {
      ...analysisResult,
      offChainIntelligence: offChainIntel,
    };
  } catch (error) {
    // Threat intel failure should NOT block wallet analysis
    console.error('[ThreatIntel] Failed to get off-chain intel:', error);
    return analysisResult;
  }
}

// ============================================
// DISPLAYING RESULTS IN UI
// ============================================

/**
 * Example 4: Preparing data for UI display
 */
function prepareForUIDisplay(report: ThreatReport) {
  const { displaySummary, findings, categorySummaries } = report;

  return {
    // Main banner content
    banner: {
      headline: displaySummary.headline,
      explanation: displaySummary.explanation,
      guidance: displaySummary.guidance,
      showWarning: displaySummary.showWarning,
      warningLevel: displaySummary.warningLevel,
    },

    // Risk indicators
    risk: {
      score: report.overallRiskScore,
      level: report.riskLevel,
      isHighRisk: report.riskLevel === 'high_risk' || report.riskLevel === 'critical',
    },

    // Provider info
    providers: {
      queried: report.queriedProviders,
      failed: report.failedProviders,
      agreementCount: report.crossSourceAgreement.agreementCount,
    },

    // Findings by category
    categories: categorySummaries.map(cat => ({
      name: cat.category,
      count: cat.count,
      severity: cat.maxSeverity,
      providers: cat.providers,
    })),

    // Individual findings (limit for performance)
    topFindings: findings.slice(0, 5),

    // CRITICAL: Off-chain labels
    offChainLabel: OFF_CHAIN_LABELS.label,
    offChainDisclaimer: OFF_CHAIN_LABELS.disclaimer,
  };
}

// ============================================
// CACHE MANAGEMENT
// ============================================

/**
 * Example 5: Cache operations
 */
async function cacheManagement() {
  const service = getThreatIntelService();

  // Get cache stats
  const stats = service.getCacheStats();
  console.log('Cache size:', stats.size);
  console.log('Hit rate:', (stats.hitRate * 100).toFixed(1) + '%');

  // Clear cache if needed
  await service.clearCache();
}

// ============================================
// PROVIDER HEALTH MONITORING
// ============================================

/**
 * Example 6: Monitor provider health
 */
async function monitorProviderHealth() {
  const service = getThreatIntelService();
  const providers = service.getProviders();

  for (const provider of providers) {
    const health = await provider.healthCheck();
    console.log(`${provider.name}: ${health.isHealthy ? 'Healthy' : 'Unhealthy'}`);
    if (!health.isHealthy) {
      console.log(`  Error: ${health.errorMessage}`);
      console.log(`  Consecutive failures: ${health.consecutiveFailures}`);
    }
    if (health.latencyMs) {
      console.log(`  Latency: ${health.latencyMs}ms`);
    }
  }
}

// ============================================
// EXPORTS FOR TESTING
// ============================================

export {
  exampleQuickCheck,
  exampleServiceUsage,
  enhanceWalletAnalysisWithThreatIntel,
  prepareForUIDisplay,
  cacheManagement,
  monitorProviderHealth,
};
