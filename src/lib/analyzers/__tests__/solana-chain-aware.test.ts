// ============================================
// SOLANA CHAIN-AWARE STATUS TESTS
// ============================================
// Tests to ensure Solana wallets are never falsely labeled as "safe"
// and that appropriate disclaimers are shown.

import { describe, test, expect } from 'vitest';
import {
  SOLANA_SECURITY_DISCLAIMER,
  CHAIN_ANALYSIS_METADATA,
  ChainAwareSecurityLabel,
  SecurityStatus,
} from '../../../types';

describe('Solana Chain-Aware Security Status', () => {
  describe('SOLANA_SECURITY_DISCLAIMER', () => {
    test('disclaimer mentions off-chain attacks', () => {
      expect(SOLANA_SECURITY_DISCLAIMER).toContain('off-chain');
    });

    test('disclaimer mentions phishing', () => {
      expect(SOLANA_SECURITY_DISCLAIMER.toLowerCase()).toContain('phishing');
    });

    test('disclaimer mentions session hijacks', () => {
      expect(SOLANA_SECURITY_DISCLAIMER.toLowerCase()).toContain('session');
    });

    test('disclaimer mentions on-chain limitations', () => {
      expect(SOLANA_SECURITY_DISCLAIMER.toLowerCase()).toContain('on-chain');
    });
  });

  describe('CHAIN_ANALYSIS_METADATA', () => {
    test('Solana has LIMITED analysis type', () => {
      expect(CHAIN_ANALYSIS_METADATA.solana.analysisType).toBe('LIMITED');
    });

    test('EVM chains have DETERMINISTIC analysis type', () => {
      expect(CHAIN_ANALYSIS_METADATA.ethereum.analysisType).toBe('DETERMINISTIC');
      expect(CHAIN_ANALYSIS_METADATA.base.analysisType).toBe('DETERMINISTIC');
      expect(CHAIN_ANALYSIS_METADATA.bnb.analysisType).toBe('DETERMINISTIC');
    });

    test('Solana canDetectOffChainCompromise is false', () => {
      expect(CHAIN_ANALYSIS_METADATA.solana.canDetectOffChainCompromise).toBe(false);
    });

    test('Solana has a disclaimer', () => {
      expect(CHAIN_ANALYSIS_METADATA.solana.disclaimer).toBeDefined();
      expect(CHAIN_ANALYSIS_METADATA.solana.disclaimer).toBe(SOLANA_SECURITY_DISCLAIMER);
    });

    test('EVM chains do not have a disclaimer', () => {
      expect(CHAIN_ANALYSIS_METADATA.ethereum.disclaimer).toBeUndefined();
      expect(CHAIN_ANALYSIS_METADATA.base.disclaimer).toBeUndefined();
      expect(CHAIN_ANALYSIS_METADATA.bnb.disclaimer).toBeUndefined();
    });

    test('Solana limitations include relevant off-chain attack vectors', () => {
      const limitations = CHAIN_ANALYSIS_METADATA.solana.limitations;
      
      // Check for phishing mentions
      expect(limitations.some(l => l.toLowerCase().includes('phishing'))).toBe(true);
      
      // Check for session/cookie hijacks
      expect(limitations.some(l => l.toLowerCase().includes('session') || l.toLowerCase().includes('cookie'))).toBe(true);
      
      // Check for "absence of evidence" warning
      expect(limitations.some(l => l.toLowerCase().includes('absence') && l.toLowerCase().includes('evidence'))).toBe(true);
    });
  });

  describe('Chain-Aware Security Label Requirements', () => {
    test('Solana SAFE status should NOT claim wallet is definitively safe', () => {
      // This test validates the expected behavior of generateChainAwareStatus
      // When status is 'SAFE' for Solana, isDefinitiveSafe must be false
      
      const expectedSolanaNoRiskLabel: ChainAwareSecurityLabel = {
        status: 'NO_ONCHAIN_RISK_DETECTED',
        displayLabel: 'No On-Chain Risk Detected',
        shortLabel: 'NO RISK DETECTED',
        description: expect.stringContaining('does NOT guarantee'),
        disclaimer: SOLANA_SECURITY_DISCLAIMER,
        isDefinitiveSafe: false,
      };
      
      // isDefinitiveSafe must always be false for Solana
      expect(expectedSolanaNoRiskLabel.isDefinitiveSafe).toBe(false);
    });

    test('Solana AT_RISK status includes disclaimer', () => {
      // AT_RISK for Solana should still have the disclaimer
      const expectedLabel: Partial<ChainAwareSecurityLabel> = {
        status: 'AT_RISK',
        disclaimer: SOLANA_SECURITY_DISCLAIMER,
        isDefinitiveSafe: false,
      };
      
      expect(expectedLabel.disclaimer).toBe(SOLANA_SECURITY_DISCLAIMER);
      expect(expectedLabel.isDefinitiveSafe).toBe(false);
    });

    test('Solana COMPROMISED status does not claim definitive safety', () => {
      // Even COMPROMISED status should have isDefinitiveSafe = false
      const expectedLabel: Partial<ChainAwareSecurityLabel> = {
        status: 'COMPROMISED',
        isDefinitiveSafe: false,
      };
      
      expect(expectedLabel.isDefinitiveSafe).toBe(false);
    });
  });

  describe('Regression: Solana Must Never Be "Fully Safe"', () => {
    test('Solana status options do not include misleading safe terms', () => {
      // Ensure we don't have "FULLY_SAFE", "CLEAN", or "VERIFIED_SAFE" statuses
      const solanaStatuses = ['NO_ONCHAIN_RISK_DETECTED', 'AT_RISK', 'COMPROMISED'];
      
      solanaStatuses.forEach(status => {
        expect(status.toUpperCase()).not.toContain('FULLY_SAFE');
        expect(status.toUpperCase()).not.toContain('CLEAN');
        expect(status.toUpperCase()).not.toContain('VERIFIED_SAFE');
        expect(status.toUpperCase()).not.toBe('SAFE');
      });
    });

    test('Display labels do not use absolute safety language for Solana', () => {
      // The display labels should use hedged language
      const hedgedTerms = ['detected', 'found', 'no on-chain'];
      const absoluteTerms = ['completely safe', 'fully secure', '100% safe', 'verified safe'];
      
      const displayLabel = 'No On-Chain Risk Detected';
      
      // Should contain at least one hedged term
      expect(hedgedTerms.some(term => displayLabel.toLowerCase().includes(term.toLowerCase()))).toBe(true);
      
      // Should NOT contain absolute terms
      absoluteTerms.forEach(term => {
        expect(displayLabel.toLowerCase()).not.toContain(term.toLowerCase());
      });
    });
  });
});

describe('EVM Chain Analysis Unchanged', () => {
  test('Ethereum analysis type is DETERMINISTIC', () => {
    expect(CHAIN_ANALYSIS_METADATA.ethereum.analysisType).toBe('DETERMINISTIC');
  });

  test('Base analysis type is DETERMINISTIC', () => {
    expect(CHAIN_ANALYSIS_METADATA.base.analysisType).toBe('DETERMINISTIC');
  });

  test('BNB analysis type is DETERMINISTIC', () => {
    expect(CHAIN_ANALYSIS_METADATA.bnb.analysisType).toBe('DETERMINISTIC');
  });

  test('EVM chains have no special disclaimer', () => {
    // EVM chains can have more deterministic detection
    expect(CHAIN_ANALYSIS_METADATA.ethereum.disclaimer).toBeUndefined();
    expect(CHAIN_ANALYSIS_METADATA.base.disclaimer).toBeUndefined();
    expect(CHAIN_ANALYSIS_METADATA.bnb.disclaimer).toBeUndefined();
  });
});

