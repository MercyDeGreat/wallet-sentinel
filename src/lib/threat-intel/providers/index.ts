// ============================================
// THREAT INTEL PROVIDERS EXPORTS
// ============================================
// Export all threat intelligence provider implementations.

// Base provider
export { BaseThreatProvider, createProviderConfig } from './base-provider';

// Production providers
export { ChainPatrolProvider, createChainPatrolProvider } from './chainpatrol';
export { ScamSnifferProvider, createScamSnifferProvider } from './scamsniffer';
export { PhishFortProvider, createPhishFortProvider } from './phishfort';
export { WalletGuardProvider, createWalletGuardProvider } from './walletguard';

// Re-export types for convenience
export type {
  ThreatProvider,
  ThreatProviderConfig,
  ProviderHealth,
  ProviderRateLimit,
} from '../types';

// ============================================
// PROVIDER FACTORY
// ============================================

import { ThreatProvider, ThreatProviderConfig } from '../types';
import { createChainPatrolProvider } from './chainpatrol';
import { createScamSnifferProvider } from './scamsniffer';
import { createPhishFortProvider } from './phishfort';
import { createWalletGuardProvider } from './walletguard';

/**
 * Available provider types.
 */
export type ProviderType = 'chainpatrol' | 'scamsniffer' | 'phishfort' | 'walletguard';

/**
 * Provider factory map.
 */
const PROVIDER_FACTORIES: Record<ProviderType, (config?: Partial<ThreatProviderConfig>) => ThreatProvider> = {
  chainpatrol: createChainPatrolProvider,
  scamsniffer: createScamSnifferProvider,
  phishfort: createPhishFortProvider,
  walletguard: createWalletGuardProvider,
};

/**
 * Create a provider by type.
 */
export function createProvider(
  type: ProviderType,
  config?: Partial<ThreatProviderConfig>
): ThreatProvider {
  const factory = PROVIDER_FACTORIES[type];
  if (!factory) {
    throw new Error(`Unknown provider type: ${type}`);
  }
  return factory(config);
}

/**
 * Create all production providers.
 * Only creates providers that have API keys configured.
 */
export function createAllProviders(
  configs?: Partial<Record<ProviderType, Partial<ThreatProviderConfig>>>
): ThreatProvider[] {
  const providers: ThreatProvider[] = [];
  
  const providerEnvKeys: Record<ProviderType, string> = {
    chainpatrol: 'CHAINPATROL_API_KEY',
    scamsniffer: 'SCAMSNIFFER_API_KEY',
    phishfort: 'PHISHFORT_API_KEY',
    walletguard: 'WALLETGUARD_API_KEY',
  };

  for (const [type, envKey] of Object.entries(providerEnvKeys)) {
    if (process.env[envKey]) {
      const config = configs?.[type as ProviderType];
      providers.push(createProvider(type as ProviderType, config));
    }
  }

  return providers;
}

/**
 * Get list of available provider types.
 */
export function getAvailableProviderTypes(): ProviderType[] {
  return Object.keys(PROVIDER_FACTORIES) as ProviderType[];
}

/**
 * Check which providers have API keys configured.
 */
export function getConfiguredProviders(): ProviderType[] {
  const providerEnvKeys: Record<ProviderType, string> = {
    chainpatrol: 'CHAINPATROL_API_KEY',
    scamsniffer: 'SCAMSNIFFER_API_KEY',
    phishfort: 'PHISHFORT_API_KEY',
    walletguard: 'WALLETGUARD_API_KEY',
  };

  return (Object.entries(providerEnvKeys) as [ProviderType, string][])
    .filter(([_, envKey]) => !!process.env[envKey])
    .map(([type]) => type);
}
