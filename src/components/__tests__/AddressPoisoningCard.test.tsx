// ============================================
// ADDRESS POISONING CARD - UNIT TESTS
// ============================================
//
// Tests that the AddressPoisoningCard component:
// 1. Renders correctly for ADDRESS_POISONING classification
// 2. Uses exact copy as specified (no paraphrasing)
// 3. Displays dynamic indicators correctly
// 4. NEVER shows alarming language
// 5. Falls back gracefully when data is missing
//
// ============================================

import { describe, test, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { 
  AddressPoisoningCard, 
  AddressPoisoningBadge,
  AddressPoisoningTimelineEntry 
} from '../AddressPoisoningCard';
import type { AttackClassification } from '@/lib/classification/types';

// ============================================
// TEST DATA
// ============================================

const createMockClassification = (overrides?: Partial<AttackClassification>): AttackClassification => ({
  type: 'ADDRESS_POISONING',
  confidence: 85,
  explanation: 'Address poisoning attack detected. Look-alike address sent dust transfers.',
  indicators: [
    'Dust transfer from similar address',
    'Repeated dusting over 2 months',
    'Funds manually sent to spoofed address',
  ],
  ruledOut: [
    'No approval abuse detected',
    'No automated drain pattern',
    'No private key compromise',
  ],
  display: {
    emoji: '⚠️',
    headline: 'Address Poisoning Attack',
    badgeText: 'Address Poisoning',
    badgeColor: 'yellow',
    severity: 'WARNING',
    summary: 'Funds were sent to a look-alike address that previously dusted this wallet.',
    whatHappened: [
      'Dust transfers received from similar address',
      'Funds manually sent to spoofed address',
    ],
    whatDidNotHappen: [
      'No private key compromise',
      'No approval abuse',
      'No automated draining',
    ],
    recommendedActions: [
      'Always verify full address',
      'Use address book / ENS',
      'Clear transaction history clutter',
    ],
    confidenceText: 'High confidence (85%)',
  },
  technicalDetails: {
    transactionHashes: ['0x123...', '0x456...'],
    involvedAddresses: ['0xabc...', '0xdef...'],
    affectedTokens: [],
    similarityScore: 75,
  },
  classifiedAt: new Date().toISOString(),
  chain: 'ethereum',
  ...overrides,
});

const createSweeperClassification = (): AttackClassification => ({
  ...createMockClassification(),
  type: 'SWEEPER_BOT',
  display: {
    ...createMockClassification().display,
    headline: 'Sweeper Bot Detected',
    badgeText: 'Sweeper Bot',
    badgeColor: 'red',
    severity: 'CRITICAL',
  },
});

// ============================================
// RENDER TESTS
// ============================================

describe('AddressPoisoningCard', () => {
  describe('Render Conditions', () => {
    test('renders for ADDRESS_POISONING classification', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      // Should render the main headline
      expect(screen.getByText(/Address Poisoning Attack/i)).toBeDefined();
    });

    test('does NOT render for SWEEPER_BOT classification', () => {
      const classification = createSweeperClassification();
      const { container } = render(<AddressPoisoningCard classification={classification} />);
      
      // Should return null / empty
      expect(container.firstChild).toBeNull();
    });

    test('does NOT render for NO_COMPROMISE classification', () => {
      const classification = createMockClassification({ type: 'NO_COMPROMISE' });
      const { container } = render(<AddressPoisoningCard classification={classification} />);
      
      expect(container.firstChild).toBeNull();
    });
  });

  describe('Exact Copy Verification', () => {
    test('shows exact headline: "⚠️ Address Poisoning Attack"', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('⚠️ Address Poisoning Attack')).toBeDefined();
    });

    test('shows exact text: "No wallet compromise detected."', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('No wallet compromise detected.')).toBeDefined();
    });

    test('shows exact summary: "Funds were sent to a look-alike address..."', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText(/Funds were sent to a look-alike address that previously dusted this wallet/i)).toBeDefined();
    });

    test('shows exact recommendation: "Always verify full address"', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('Always verify full address')).toBeDefined();
    });

    test('shows exact recommendation: "Use address book / ENS"', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('Use address book / ENS')).toBeDefined();
    });

    test('shows exact recommendation: "Clear transaction history clutter"', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('Clear transaction history clutter')).toBeDefined();
    });
  });

  describe('UX Safety Rules - NEVER Show', () => {
    test('NEVER shows "ACTIVELY COMPROMISED"', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      // Search for any text containing "ACTIVELY COMPROMISED"
      const element = screen.queryByText(/ACTIVELY COMPROMISED/i);
      expect(element).toBeNull();
    });

    test('NEVER shows "Sweeper bot detected"', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      const element = screen.queryByText(/Sweeper bot detected/i);
      expect(element).toBeNull();
    });

    test('NEVER shows "Private key leaked"', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      const element = screen.queryByText(/Private key leaked/i);
      expect(element).toBeNull();
    });

    test('NEVER recommends revoking approvals', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      const element = screen.queryByText(/revoke/i);
      expect(element).toBeNull();
    });

    test('NEVER uses emergency language', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      // Check for various emergency terms
      expect(screen.queryByText(/EMERGENCY/i)).toBeNull();
      expect(screen.queryByText(/URGENT/i)).toBeNull();
      expect(screen.queryByText(/IMMEDIATELY/i)).toBeNull();
      expect(screen.queryByText(/CRITICAL/i)).toBeNull();
    });
  });

  describe('Safety Reassurance Display', () => {
    test('shows "What did NOT happen" section', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('What did NOT happen')).toBeDefined();
    });

    test('shows "No private key compromise" reassurance', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('No private key compromise')).toBeDefined();
    });

    test('shows "No approval abuse" reassurance', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('No approval abuse')).toBeDefined();
    });

    test('shows "No automated draining" reassurance', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('No automated draining')).toBeDefined();
    });
  });

  describe('Dynamic Indicator Injection', () => {
    test('shows similarity score when provided', () => {
      const classification = createMockClassification();
      render(
        <AddressPoisoningCard 
          classification={classification} 
          similarityScore={75}
        />
      );
      
      expect(screen.getByText(/75% match/i)).toBeDefined();
    });

    test('calculates duration from first dust timestamp', () => {
      const classification = createMockClassification();
      // 90 days ago
      const firstDustTimestamp = Math.floor(Date.now() / 1000) - (90 * 24 * 60 * 60);
      
      render(
        <AddressPoisoningCard 
          classification={classification} 
          firstDustTimestamp={firstDustTimestamp}
        />
      );
      
      // Should show "3+ months"
      expect(screen.getByText(/3\+ months/i)).toBeDefined();
    });

    test('shows dust transfer count when provided', () => {
      const classification = createMockClassification();
      render(
        <AddressPoisoningCard 
          classification={classification} 
          dustTransferCount={5}
        />
      );
      
      expect(screen.getByText(/5 dust transfers received/i)).toBeDefined();
    });

    test('falls back gracefully when data is missing', () => {
      const classification = createMockClassification();
      // No optional props provided
      render(<AddressPoisoningCard classification={classification} />);
      
      // Should still render without errors
      expect(screen.getByText('⚠️ Address Poisoning Attack')).toBeDefined();
      // Default fallback text for duration
      expect(screen.getByText(/Repeated over time|Repeated over/i)).toBeDefined();
    });
  });

  describe('Confidence Display', () => {
    test('shows confidence percentage', () => {
      const classification = createMockClassification({ confidence: 92 });
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText(/92%/)).toBeDefined();
    });

    test('shows low confidence value correctly', () => {
      const classification = createMockClassification({ confidence: 45 });
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText(/45%/)).toBeDefined();
    });
  });

  describe('Optional Sections', () => {
    test('hides recommendations when showRecommendations is false', () => {
      const classification = createMockClassification();
      render(
        <AddressPoisoningCard 
          classification={classification} 
          showRecommendations={false}
        />
      );
      
      // Recommendations should not be present
      expect(screen.queryByText('Recommendation:')).toBeNull();
      expect(screen.queryByText('Always verify full address')).toBeNull();
    });

    test('shows recommendations by default', () => {
      const classification = createMockClassification();
      render(<AddressPoisoningCard classification={classification} />);
      
      expect(screen.getByText('Recommendation:')).toBeDefined();
    });
  });
});

// ============================================
// BADGE VARIANT TESTS
// ============================================

describe('AddressPoisoningBadge', () => {
  test('renders for ADDRESS_POISONING', () => {
    const classification = createMockClassification();
    render(<AddressPoisoningBadge classification={classification} />);
    
    expect(screen.getByText('Address Poisoning')).toBeDefined();
  });

  test('shows "No Compromise" label', () => {
    const classification = createMockClassification();
    render(<AddressPoisoningBadge classification={classification} />);
    
    expect(screen.getByText(/No Compromise/i)).toBeDefined();
  });

  test('does NOT render for other classifications', () => {
    const classification = createSweeperClassification();
    const { container } = render(<AddressPoisoningBadge classification={classification} />);
    
    expect(container.firstChild).toBeNull();
  });
});

// ============================================
// TIMELINE VARIANT TESTS
// ============================================

describe('AddressPoisoningTimelineEntry', () => {
  test('renders for ADDRESS_POISONING', () => {
    const classification = createMockClassification();
    render(<AddressPoisoningTimelineEntry classification={classification} />);
    
    expect(screen.getByText('Address Poisoning')).toBeDefined();
  });

  test('shows timestamp when provided', () => {
    const classification = createMockClassification();
    render(
      <AddressPoisoningTimelineEntry 
        classification={classification} 
        timestamp="Jan 15, 2026"
      />
    );
    
    expect(screen.getByText('Jan 15, 2026')).toBeDefined();
  });

  test('does NOT render for other classifications', () => {
    const classification = createSweeperClassification();
    const { container } = render(<AddressPoisoningTimelineEntry classification={classification} />);
    
    expect(container.firstChild).toBeNull();
  });
});
