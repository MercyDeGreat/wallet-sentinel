// ============================================
// PRIVACY-PRESERVING HASH UTILITIES
// ============================================
// Uses Web Crypto API (available in Edge Runtime)

/**
 * Creates a SHA-256 hash of the input string
 * Used for privacy-preserving deduplication of IPs and user agents
 */
export async function sha256Hash(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Creates a composite user identifier hash
 * Combines IP + User-Agent for better uniqueness while preserving privacy
 */
export async function createUserHash(ip: string, userAgent: string): Promise<string> {
  const composite = `${ip}::${userAgent}`;
  return sha256Hash(composite);
}

/**
 * Normalize wallet address for consistent storage
 * - EVM: lowercase
 * - Solana: preserve case (base58)
 */
export function normalizeWalletAddress(address: string, chain: string): string {
  if (chain === 'solana') {
    return address.trim();
  }
  return address.trim().toLowerCase();
}

/**
 * Generate a unique scan ID
 * Format: scan_<timestamp>_<random>
 */
export function generateScanId(): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomUUID().split('-')[0];
  return `scan_${timestamp}_${random}`;
}
