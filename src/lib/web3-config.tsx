'use client';

import { getDefaultConfig } from '@rainbow-me/rainbowkit';
import { mainnet, base, bsc } from 'wagmi/chains';

export const config = getDefaultConfig({
  appName: 'Wallet Sentinel',
  projectId: 'wallet-sentinel-revoke', // WalletConnect project ID (get one at cloud.walletconnect.com for production)
  chains: [mainnet, base, bsc],
  ssr: true,
});

// ERC20 ABI for approve function
export const ERC20_ABI = [
  {
    name: 'approve',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'value', type: 'uint256' },
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
] as const;

// Chain ID mapping
export const CHAIN_IDS: Record<string, number> = {
  ethereum: 1,
  base: 8453,
  bnb: 56,
};

