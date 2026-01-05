// ============================================
// WEB3 CONFIGURATION
// ============================================
// Configuration for wallet connection and on-chain interactions.

import { mainnet, base, bsc } from 'wagmi/chains';
import { createPublicClient, http, type Chain as ViemChain } from 'viem';
import type { Chain } from '@/types';

// Chain IDs mapping
export const CHAIN_IDS: Record<string, number> = {
  ethereum: 1,
  base: 8453,
  bnb: 56,
  solana: 0, // Solana doesn't use EVM chain IDs
};

// ERC20 ABI for approval revocation
export const ERC20_ABI = [
  {
    name: 'approve',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'allowance',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'balanceOf',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'symbol',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'string' }],
  },
  {
    name: 'decimals',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint8' }],
  },
] as const;

// Chain name to viem chain mapping
export const VIEM_CHAINS: Record<string, ViemChain> = {
  ethereum: mainnet,
  base: base,
  bnb: bsc,
} as const;

// RPC URLs for direct blockchain queries
const RPC_URLS: Record<string, string> = {
  ethereum: 'https://eth.llamarpc.com',
  base: 'https://mainnet.base.org',
  bnb: 'https://bsc-dataseed1.binance.org',
};

// ============================================
// ON-CHAIN ALLOWANCE CHECKING
// ============================================
// Fetches the CURRENT on-chain allowance for a token approval.
// This is critical for determining if a threat is still active.

/**
 * Get the current on-chain allowance for a token
 * @param tokenAddress - The ERC20 token contract address
 * @param ownerAddress - The wallet address that granted the approval
 * @param spenderAddress - The address that was approved to spend
 * @param chain - The blockchain network
 * @returns The current allowance as a string, or null if failed
 */
export async function getCurrentAllowance(
  tokenAddress: string,
  ownerAddress: string,
  spenderAddress: string,
  chain: Chain
): Promise<{ allowance: string; isRevoked: boolean } | null> {
  if (chain === 'solana') {
    return null; // Solana uses different approval mechanism
  }

  const viemChain = VIEM_CHAINS[chain];
  const rpcUrl = RPC_URLS[chain];

  if (!viemChain || !rpcUrl) {
    console.warn(`[getCurrentAllowance] Unsupported chain: ${chain}`);
    return null;
  }

  try {
    const client = createPublicClient({
      chain: viemChain,
      transport: http(rpcUrl),
    });

    const allowance = await client.readContract({
      address: tokenAddress as `0x${string}`,
      abi: ERC20_ABI,
      functionName: 'allowance',
      args: [ownerAddress as `0x${string}`, spenderAddress as `0x${string}`],
    });

    const allowanceStr = allowance.toString();
    const isRevoked = allowanceStr === '0' || BigInt(allowanceStr) === BigInt(0);

    console.log(`[getCurrentAllowance] ${tokenAddress.slice(0, 10)}... owner=${ownerAddress.slice(0, 10)}... spender=${spenderAddress.slice(0, 10)}... allowance=${allowanceStr} revoked=${isRevoked}`);

    return {
      allowance: allowanceStr,
      isRevoked,
    };
  } catch (error) {
    console.error(`[getCurrentAllowance] Failed to fetch allowance:`, error);
    return null;
  }
}

/**
 * Batch check multiple approvals for their current on-chain state
 * @param approvals - Array of approval info to check
 * @param chain - The blockchain network
 * @returns Map of approval ID to current state
 */
export async function batchCheckAllowances(
  approvals: Array<{
    id: string;
    tokenAddress: string;
    ownerAddress: string;
    spenderAddress: string;
  }>,
  chain: Chain
): Promise<Map<string, { allowance: string; isRevoked: boolean }>> {
  const results = new Map<string, { allowance: string; isRevoked: boolean }>();

  // Process in parallel with rate limiting
  const batchSize = 5;
  for (let i = 0; i < approvals.length; i += batchSize) {
    const batch = approvals.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (approval) => {
        const result = await getCurrentAllowance(
          approval.tokenAddress,
          approval.ownerAddress,
          approval.spenderAddress,
          chain
        );
        return { id: approval.id, result };
      })
    );

    for (const { id, result } of batchResults) {
      if (result) {
        results.set(id, result);
      }
    }
  }

  return results;
}
