// ============================================
// CHAIN ANALYZERS EXPORTS
// ============================================

export { EVMAnalyzer } from './evm-analyzer';
export { SolanaAnalyzer } from './solana-analyzer';

import { Chain, WalletAnalysisResult } from '@/types';
import { EVMAnalyzer } from './evm-analyzer';
import { SolanaAnalyzer } from './solana-analyzer';

/**
 * Factory function to get the appropriate analyzer for a chain
 */
export function getAnalyzer(chain: Chain) {
  if (chain === 'solana') {
    return new SolanaAnalyzer();
  }
  return new EVMAnalyzer(chain);
}

/**
 * Analyze a wallet address on any supported chain
 */
export async function analyzeWallet(
  address: string,
  chain: Chain
): Promise<WalletAnalysisResult> {
  const analyzer = getAnalyzer(chain);
  return analyzer.analyzeWallet(address);
}




