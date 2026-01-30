// ============================================
// MOCK INTEL PROVIDERS FOR DEVELOPMENT/DEMO
// ============================================
// These providers simulate real threat intelligence feeds.
// Replace with actual API integrations in production.
//
// PROVIDERS SIMULATED:
// - ChainPatrol (phishing intelligence)
// - PhishFort (brand protection)
// - ScamSniffer (scam domain attribution)
// - CommunityReports (open community reports)

import { BaseOTTIProvider, createSignal } from './base-provider';
import {
  OffChainThreatSignal,
  ProviderConfig,
  OffChainReportType,
  OffChainConfidenceLevel,
} from '../types';

// ============================================
// MOCK DATA STORE
// ============================================
// In production, this would be API calls to actual providers.
// This mock data demonstrates the system behavior.

interface MockSignalData {
  report_type: OffChainReportType;
  confidence_level: OffChainConfidenceLevel;
  context: string;
  evidence_url?: string;
  first_seen_days_ago: number;
  last_seen_days_ago?: number;
}

// Mock database of known phishing addresses
// In production: This would be fetched from actual threat intel APIs
const MOCK_PHISHING_DB: Map<string, MockSignalData[]> = new Map([
  // Example: Known phishing addresses (lowercase)
  ['0x1234567890abcdef1234567890abcdef12345678', [
    {
      report_type: 'phishing',
      confidence_level: 'high',
      context: 'Wallet listed in reported phishing flow targeting DeFi users',
      evidence_url: 'https://example.com/report/12345',
      first_seen_days_ago: 15,
      last_seen_days_ago: 2,
    },
  ]],
  ['0xdeadbeef00000000000000000000000000000001', [
    {
      report_type: 'impersonation',
      confidence_level: 'medium',
      context: 'Address associated with fake Uniswap support account',
      first_seen_days_ago: 30,
    },
    {
      report_type: 'fake_support',
      confidence_level: 'high',
      context: 'Confirmed fake support scam targeting users on Discord',
      evidence_url: 'https://example.com/report/67890',
      first_seen_days_ago: 25,
      last_seen_days_ago: 5,
    },
  ]],
  ['0xbadactor0000000000000000000000000000001', [
    {
      report_type: 'fake_mint',
      confidence_level: 'high',
      context: 'Address promoted fake NFT mint website',
      evidence_url: 'https://scam-detector.example/mint-scam-001',
      first_seen_days_ago: 7,
      last_seen_days_ago: 1,
    },
  ]],
  ['0xscammer00000000000000000000000000000001', [
    {
      report_type: 'giveaway_scam',
      confidence_level: 'medium',
      context: 'Address used in fake giveaway campaign on Twitter',
      first_seen_days_ago: 45,
    },
  ]],
]);

// ============================================
// MOCK CHAINPATROL PROVIDER
// ============================================

export class MockChainPatrolProvider extends BaseOTTIProvider {
  readonly name = 'ChainPatrol';
  readonly id = 'chainpatrol';

  constructor(config?: Partial<ProviderConfig>) {
    super({
      signal_ttl_days: 90,
      confidence_weight: 1.0,
      rate_limit: {
        requests_per_minute: 60,
        requests_per_day: 10000,
      },
      ...config,
    });
  }

  async queryAddress(address: string): Promise<OffChainThreatSignal[]> {
    // Simulate API latency
    await this.simulateLatency();

    const normalizedAddress = this.normalizeAddress(address);
    const mockData = MOCK_PHISHING_DB.get(normalizedAddress);

    if (!mockData) {
      return [];
    }

    // Filter to only phishing-related types this provider would report
    const relevantTypes: OffChainReportType[] = ['phishing', 'scam_page', 'fake_mint'];
    const relevantData = mockData.filter(d => relevantTypes.includes(d.report_type));

    return relevantData.map((data, index) => {
      const now = Date.now();
      const firstSeen = new Date(now - data.first_seen_days_ago * 24 * 60 * 60 * 1000).toISOString();
      const lastSeen = data.last_seen_days_ago 
        ? new Date(now - data.last_seen_days_ago * 24 * 60 * 60 * 1000).toISOString()
        : undefined;

      return createSignal({
        id: this.generateSignalId(normalizedAddress, `${data.report_type}-${index}`),
        source_name: this.name,
        report_type: data.report_type,
        confidence_level: data.confidence_level,
        first_seen_timestamp: firstSeen,
        last_seen_timestamp: lastSeen,
        reference_id: `CP-${normalizedAddress.slice(2, 10).toUpperCase()}-${index}`,
        evidence_url: data.evidence_url,
        context: data.context,
        metadata: {
          provider_version: '1.0.0',
          detection_method: 'behavioral_analysis',
        },
        decay: this.createDecayInfo(firstSeen, lastSeen, data.last_seen_days_ago ? 2 : 1),
      });
    });
  }

  async healthCheck(): Promise<boolean> {
    // Mock health check
    return true;
  }

  private async simulateLatency(): Promise<void> {
    const latency = Math.random() * 100 + 50; // 50-150ms
    await new Promise(resolve => setTimeout(resolve, latency));
  }
}

// ============================================
// MOCK PHISHFORT PROVIDER
// ============================================

export class MockPhishFortProvider extends BaseOTTIProvider {
  readonly name = 'PhishFort';
  readonly id = 'phishfort';

  constructor(config?: Partial<ProviderConfig>) {
    super({
      signal_ttl_days: 60,
      confidence_weight: 0.9,
      rate_limit: {
        requests_per_minute: 30,
        requests_per_day: 5000,
      },
      ...config,
    });
  }

  async queryAddress(address: string): Promise<OffChainThreatSignal[]> {
    await this.simulateLatency();

    const normalizedAddress = this.normalizeAddress(address);
    const mockData = MOCK_PHISHING_DB.get(normalizedAddress);

    if (!mockData) {
      return [];
    }

    // PhishFort focuses on impersonation and brand protection
    const relevantTypes: OffChainReportType[] = ['impersonation', 'fake_support', 'social_engineering'];
    const relevantData = mockData.filter(d => relevantTypes.includes(d.report_type));

    return relevantData.map((data, index) => {
      const now = Date.now();
      const firstSeen = new Date(now - data.first_seen_days_ago * 24 * 60 * 60 * 1000).toISOString();
      const lastSeen = data.last_seen_days_ago 
        ? new Date(now - data.last_seen_days_ago * 24 * 60 * 60 * 1000).toISOString()
        : undefined;

      return createSignal({
        id: this.generateSignalId(normalizedAddress, `${data.report_type}-${index}`),
        source_name: this.name,
        report_type: data.report_type,
        confidence_level: data.confidence_level,
        first_seen_timestamp: firstSeen,
        last_seen_timestamp: lastSeen,
        reference_id: `PF-${Date.now().toString(36).toUpperCase()}`,
        evidence_url: data.evidence_url,
        context: data.context,
        metadata: {
          brand_targeted: 'Unknown',
          platform: 'Discord/Twitter',
        },
        decay: this.createDecayInfo(firstSeen, lastSeen, 1),
      });
    });
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  private async simulateLatency(): Promise<void> {
    const latency = Math.random() * 150 + 75; // 75-225ms
    await new Promise(resolve => setTimeout(resolve, latency));
  }
}

// ============================================
// MOCK SCAMSNIFFER PROVIDER
// ============================================

export class MockScamSnifferProvider extends BaseOTTIProvider {
  readonly name = 'ScamSniffer';
  readonly id = 'scamsniffer';

  constructor(config?: Partial<ProviderConfig>) {
    super({
      signal_ttl_days: 120,
      confidence_weight: 1.1,
      rate_limit: {
        requests_per_minute: 100,
        requests_per_day: 50000,
      },
      ...config,
    });
  }

  async queryAddress(address: string): Promise<OffChainThreatSignal[]> {
    await this.simulateLatency();

    const normalizedAddress = this.normalizeAddress(address);
    const mockData = MOCK_PHISHING_DB.get(normalizedAddress);

    if (!mockData) {
      return [];
    }

    // ScamSniffer covers broad scam detection
    const relevantTypes: OffChainReportType[] = [
      'scam_page', 'fake_mint', 'giveaway_scam', 'honeypot', 'rug_pull'
    ];
    const relevantData = mockData.filter(d => relevantTypes.includes(d.report_type));

    return relevantData.map((data, index) => {
      const now = Date.now();
      const firstSeen = new Date(now - data.first_seen_days_ago * 24 * 60 * 60 * 1000).toISOString();
      const lastSeen = data.last_seen_days_ago 
        ? new Date(now - data.last_seen_days_ago * 24 * 60 * 60 * 1000).toISOString()
        : undefined;

      return createSignal({
        id: this.generateSignalId(normalizedAddress, `${data.report_type}-${index}`),
        source_name: this.name,
        report_type: data.report_type,
        confidence_level: data.confidence_level,
        first_seen_timestamp: firstSeen,
        last_seen_timestamp: lastSeen,
        reference_id: `SS-${normalizedAddress.slice(2, 8).toUpperCase()}-${Date.now().toString(36)}`,
        evidence_url: data.evidence_url,
        context: data.context,
        metadata: {
          scam_category: data.report_type,
          detection_source: 'automated_crawl',
        },
        decay: this.createDecayInfo(firstSeen, lastSeen, data.last_seen_days_ago ? 3 : 1),
      });
    });
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  private async simulateLatency(): Promise<void> {
    const latency = Math.random() * 80 + 40; // 40-120ms
    await new Promise(resolve => setTimeout(resolve, latency));
  }
}

// ============================================
// MOCK COMMUNITY REPORTS PROVIDER
// ============================================

export class MockCommunityReportsProvider extends BaseOTTIProvider {
  readonly name = 'Community Reports';
  readonly id = 'community';

  constructor(config?: Partial<ProviderConfig>) {
    super({
      signal_ttl_days: 30, // Community reports decay faster
      confidence_weight: 0.7, // Lower weight for unverified reports
      ...config,
    });
  }

  async queryAddress(address: string): Promise<OffChainThreatSignal[]> {
    await this.simulateLatency();

    const normalizedAddress = this.normalizeAddress(address);
    const mockData = MOCK_PHISHING_DB.get(normalizedAddress);

    if (!mockData) {
      return [];
    }

    // Community can report anything
    return mockData.slice(0, 1).map((data, index) => {
      const now = Date.now();
      const firstSeen = new Date(now - data.first_seen_days_ago * 24 * 60 * 60 * 1000).toISOString();

      return createSignal({
        id: this.generateSignalId(normalizedAddress, `community-${index}`),
        source_name: this.name,
        report_type: 'community_report',
        confidence_level: 'low', // Community reports start at low confidence
        first_seen_timestamp: firstSeen,
        context: `Community-reported suspicious activity: ${data.context}`,
        metadata: {
          report_count: Math.floor(Math.random() * 10) + 1,
          verified: false,
        },
        decay: this.createDecayInfo(firstSeen, undefined, 1),
      });
    });
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  private async simulateLatency(): Promise<void> {
    const latency = Math.random() * 50 + 25; // 25-75ms
    await new Promise(resolve => setTimeout(resolve, latency));
  }
}

// ============================================
// FACTORY FUNCTION
// ============================================

/**
 * Create all mock providers for development/demo
 */
export function createMockProviders(): BaseOTTIProvider[] {
  return [
    new MockChainPatrolProvider(),
    new MockPhishFortProvider(),
    new MockScamSnifferProvider(),
    new MockCommunityReportsProvider(),
  ];
}

/**
 * Add test data for a specific address
 * (For testing/demo purposes only)
 */
export function addMockTestData(address: string, data: MockSignalData[]): void {
  MOCK_PHISHING_DB.set(address.toLowerCase(), data);
}

/**
 * Clear mock test data for an address
 */
export function clearMockTestData(address: string): void {
  MOCK_PHISHING_DB.delete(address.toLowerCase());
}

/**
 * Get all addresses with mock data (for testing)
 */
export function getMockDataAddresses(): string[] {
  return Array.from(MOCK_PHISHING_DB.keys());
}
