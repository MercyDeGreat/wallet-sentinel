// ============================================
// UTILITY FUNCTIONS
// ============================================

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { Chain, RiskLevel, SecurityStatus } from '@/types';

/**
 * Merge Tailwind CSS classes with clsx
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a blockchain address for display
 */
export function formatAddress(address: string, length: number = 4): string {
  if (!address) return '';
  if (address.length <= length * 2 + 2) return address;
  return `${address.slice(0, length + 2)}...${address.slice(-length)}`;
}

/**
 * Format a transaction hash for display
 */
export function formatTxHash(hash: string, length: number = 8): string {
  if (!hash) return '';
  if (hash.length <= length * 2) return hash;
  return `${hash.slice(0, length)}...${hash.slice(-length)}`;
}

/**
 * Get the block explorer URL for an address
 */
export function getExplorerAddressUrl(chain: Chain, address: string): string {
  const explorers: Record<Chain, string> = {
    ethereum: 'https://etherscan.io/address/',
    base: 'https://basescan.org/address/',
    bnb: 'https://bscscan.com/address/',
    solana: 'https://solscan.io/account/',
  };
  return `${explorers[chain]}${address}`;
}

/**
 * Get the block explorer URL for a transaction
 */
export function getExplorerTxUrl(chain: Chain, hash: string): string {
  const explorers: Record<Chain, string> = {
    ethereum: 'https://etherscan.io/tx/',
    base: 'https://basescan.org/tx/',
    bnb: 'https://bscscan.com/tx/',
    solana: 'https://solscan.io/tx/',
  };
  return `${explorers[chain]}${hash}`;
}

/**
 * Get the display name for a chain
 */
export function getChainDisplayName(chain: Chain): string {
  const names: Record<Chain, string> = {
    ethereum: 'Ethereum',
    base: 'Base',
    bnb: 'BNB Chain',
    solana: 'Solana',
  };
  return names[chain] || chain;
}

/**
 * Get the chain icon/emoji
 */
export function getChainIcon(chain: Chain): string {
  const icons: Record<Chain, string> = {
    ethereum: '⟠',
    base: '🔵',
    bnb: '🟡',
    solana: '◎',
  };
  return icons[chain] || '🔗';
}

/**
 * Validate an EVM address
 */
export function isValidEvmAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/**
 * Validate a Solana address
 */
export function isValidSolanaAddress(address: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
}

/**
 * Validate a wallet address for a given chain
 */
export function isValidAddress(address: string, chain: Chain): boolean {
  if (chain === 'solana') {
    return isValidSolanaAddress(address);
  }
  return isValidEvmAddress(address);
}

/**
 * Get the color class for a risk level
 */
export function getRiskLevelColor(level: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    CRITICAL: 'text-red-400',
    HIGH: 'text-orange-400',
    MEDIUM: 'text-yellow-400',
    LOW: 'text-green-400',
  };
  return colors[level];
}

/**
 * Get the background color class for a risk level
 */
export function getRiskLevelBgColor(level: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    CRITICAL: 'bg-red-500/20',
    HIGH: 'bg-orange-500/20',
    MEDIUM: 'bg-yellow-500/20',
    LOW: 'bg-green-500/20',
  };
  return colors[level];
}

/**
 * Get the color class for a security status
 */
export function getSecurityStatusColor(status: SecurityStatus): string {
  const colors: Record<SecurityStatus, string> = {
    SAFE: 'text-status-safe',
    POTENTIALLY_COMPROMISED: 'text-orange-400',
    AT_RISK: 'text-status-warning',
    COMPROMISED: 'text-status-danger',
  };
  return colors[status];
}

/**
 * Format a large number for display
 */
export function formatLargeNumber(num: number | string): string {
  const n = typeof num === 'string' ? parseFloat(num) : num;
  
  if (isNaN(n)) return '0';
  
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(2)}K`;
  
  return n.toFixed(2);
}

/**
 * Format a token amount with decimals
 */
export function formatTokenAmount(amount: string, decimals: number): string {
  try {
    const value = BigInt(amount);
    const divisor = BigInt(10 ** decimals);
    const integerPart = value / divisor;
    const decimalPart = value % divisor;
    
    // Format decimal part with leading zeros
    const decimalStr = decimalPart.toString().padStart(decimals, '0').slice(0, 4);
    
    return `${integerPart.toLocaleString()}.${decimalStr}`;
  } catch {
    return '0';
  }
}

/**
 * Check if an approval amount is effectively unlimited
 */
export function isUnlimitedApproval(amount: string): boolean {
  try {
    const value = BigInt(amount);
    const threshold = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff') / BigInt(2);
    return value >= threshold;
  } catch {
    return false;
  }
}

/**
 * Delay execution (useful for animations)
 */
export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
      document.execCommand('copy');
      return true;
    } catch {
      return false;
    } finally {
      document.body.removeChild(textarea);
    }
  }
}

/**
 * Format a date for display
 */
export function formatDate(date: string | Date): string {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Format a date with time for display
 */
export function formatDateTime(date: string | Date): string {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Calculate time ago from a date
 */
export function timeAgo(date: string | Date): string {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  
  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return 'Just now';
}







