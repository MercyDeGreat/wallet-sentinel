// ============================================
// WEB3 CONFIGURATION
// ============================================
// Configuration for wallet connection and on-chain interactions.

import { mainnet, base, bsc } from 'wagmi/chains';

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
export const VIEM_CHAINS = {
  ethereum: mainnet,
  base: base,
  bnb: bsc,
} as const;
