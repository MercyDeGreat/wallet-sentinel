// ============================================
// ATTACKER INFRASTRUCTURE PROFILER
// ============================================
// Profiles attacker wallets and infrastructure,
// tracking aggregation wallets, routing patterns,
// and exchange exit routes.
//
// IMPORTANT: Only label as "scammer" if confidence ≥ 90.
// Attacker wallets are NOT victims - they receive drained funds.

import { Chain } from '@/types';
import {
  AttackerProfile,
  AttackerWallet,
  AttackerWalletRole,
  AttackerStats,
  RoutingPattern,
  RoutingStep,
  ExitLiquidity,
  CorrelationResult,
  IncidentWallet,
  KNOWN_EXCHANGES,
} from './types';

// ============================================
// MAIN PROFILER FUNCTION
// ============================================

/**
 * Build an attacker profile from correlated incident data.
 */
export function buildAttackerProfile(
  correlation: CorrelationResult,
  existingProfile?: AttackerProfile
): AttackerProfile {
  const profileId = existingProfile?.profileId || generateProfileId();
  const now = new Date().toISOString();
  
  // Extract attacker wallets from destinations
  const attackerWallets = identifyAttackerWallets(correlation);
  
  // Merge with existing profile if provided
  const mergedWallets = existingProfile
    ? mergeAttackerWallets(existingProfile.wallets, attackerWallets)
    : attackerWallets;
  
  // Calculate statistics
  const stats = calculateAttackerStats(correlation, mergedWallets);
  
  // Identify routing patterns
  const routingPatterns = identifyRoutingPatterns(correlation.wallets);
  
  // Identify exit liquidity
  const exitLiquidity = identifyExitLiquidity(correlation);
  
  // Calculate confidence
  const { confidence, labelAsScammer } = calculateAttackerConfidence(
    mergedWallets,
    stats,
    routingPatterns
  );
  
  return {
    profileId,
    wallets: mergedWallets,
    stats,
    routingPatterns,
    exitLiquidity,
    confidence,
    confidenceLevel: confidence >= 85 ? 'HIGH' : confidence >= 60 ? 'MEDIUM' : 'LOW',
    labelAsScammer,
    firstSeen: existingProfile?.firstSeen || now,
    lastSeen: now,
    isActive: true,
  };
}

// ============================================
// ATTACKER WALLET IDENTIFICATION
// ============================================

function identifyAttackerWallets(correlation: CorrelationResult): AttackerWallet[] {
  const attackerWallets: AttackerWallet[] = [];
  const walletRoles = new Map<string, AttackerWalletRole>();
  const walletStats = new Map<string, {
    totalReceived: number;
    linkedVictims: Set<string>;
    chains: Set<Chain>;
  }>();
  
  // Process each victim wallet's transfer sequence
  for (const wallet of correlation.wallets) {
    for (const step of wallet.transferSequence) {
      const toAddress = step.to.toLowerCase();
      
      // Skip if destination is the victim themselves
      if (toAddress === wallet.address.toLowerCase()) continue;
      
      // Determine role based on position in transfer sequence
      const role = determineWalletRole(step, wallet.transferSequence);
      
      // Update stats
      if (!walletStats.has(toAddress)) {
        walletStats.set(toAddress, {
          totalReceived: 0,
          linkedVictims: new Set(),
          chains: new Set(),
        });
      }
      
      const stats = walletStats.get(toAddress)!;
      stats.totalReceived += parseFloat(step.amount) || 0;
      stats.linkedVictims.add(wallet.address);
      stats.chains.add(wallet.chain);
      
      // Track role (prefer more specific roles)
      if (!walletRoles.has(toAddress) || shouldUpgradeRole(walletRoles.get(toAddress)!, role)) {
        walletRoles.set(toAddress, role);
      }
    }
  }
  
  // Build attacker wallet objects
  const now = new Date().toISOString();
  
  for (const [address, role] of walletRoles) {
    const stats = walletStats.get(address)!;
    
    // Determine chain (use first one if multiple)
    const chains = [...stats.chains];
    
    attackerWallets.push({
      address,
      chain: chains[0] || 'ethereum',
      role,
      totalReceivedFromVictims: stats.totalReceived,
      totalTransactions: correlation.wallets.reduce((count, w) =>
        count + w.transferSequence.filter(s => s.to.toLowerCase() === address).length, 0
      ),
      linkedVictimCount: stats.linkedVictims.size,
      firstSeen: now,
      lastSeen: now,
      confidence: calculateWalletConfidence(role, stats.linkedVictims.size),
    });
  }
  
  return attackerWallets;
}

function determineWalletRole(
  step: { order: number; to: string },
  sequence: Array<{ order: number; to: string }>
): AttackerWalletRole {
  const toAddress = step.to.toLowerCase();
  const maxOrder = Math.max(...sequence.map(s => s.order));
  
  // First destination in sequence is likely aggregation
  if (step.order === 1 && maxOrder > 1) {
    return 'AGGREGATION';
  }
  
  // Last destination might be exchange
  if (step.order === maxOrder) {
    // Check if it's a known exchange
    const isExchange = KNOWN_EXCHANGES.some(ex =>
      Object.values(ex.depositAddresses).flat().some(addr =>
        addr.toLowerCase() === toAddress
      )
    );
    if (isExchange) return 'EXCHANGE_DEPOSIT';
    return 'ROUTER';
  }
  
  // Middle steps are routers
  if (step.order > 1 && step.order < maxOrder) {
    return 'ROUTER';
  }
  
  return 'UNKNOWN';
}

function shouldUpgradeRole(currentRole: AttackerWalletRole, newRole: AttackerWalletRole): boolean {
  const priority: Record<AttackerWalletRole, number> = {
    EXCHANGE_DEPOSIT: 6,
    BRIDGE_STAGING: 5,
    AGGREGATION: 4,
    SWEEPER: 3,
    ROUTER: 2,
    UNKNOWN: 1,
  };
  
  return priority[newRole] > priority[currentRole];
}

function calculateWalletConfidence(role: AttackerWalletRole, linkedVictimCount: number): number {
  let confidence = 40; // Base confidence
  
  // More victims linked = higher confidence
  confidence += Math.min(30, linkedVictimCount * 10);
  
  // Role-based confidence
  switch (role) {
    case 'AGGREGATION':
      confidence += 20;
      break;
    case 'EXCHANGE_DEPOSIT':
      confidence += 15;
      break;
    case 'ROUTER':
      confidence += 10;
      break;
    case 'SWEEPER':
      confidence += 25;
      break;
  }
  
  return Math.min(100, confidence);
}

// ============================================
// WALLET MERGING
// ============================================

function mergeAttackerWallets(
  existing: AttackerWallet[],
  newWallets: AttackerWallet[]
): AttackerWallet[] {
  const merged = new Map<string, AttackerWallet>();
  
  // Add existing wallets
  for (const wallet of existing) {
    merged.set(wallet.address.toLowerCase(), wallet);
  }
  
  // Merge new wallets
  for (const wallet of newWallets) {
    const key = wallet.address.toLowerCase();
    const existingWallet = merged.get(key);
    
    if (existingWallet) {
      // Merge statistics
      merged.set(key, {
        ...existingWallet,
        totalReceivedFromVictims: existingWallet.totalReceivedFromVictims + wallet.totalReceivedFromVictims,
        totalTransactions: existingWallet.totalTransactions + wallet.totalTransactions,
        linkedVictimCount: existingWallet.linkedVictimCount + wallet.linkedVictimCount,
        lastSeen: wallet.lastSeen,
        confidence: Math.max(existingWallet.confidence, wallet.confidence),
      });
    } else {
      merged.set(key, wallet);
    }
  }
  
  return [...merged.values()];
}

// ============================================
// ATTACKER STATISTICS
// ============================================

function calculateAttackerStats(
  correlation: CorrelationResult,
  wallets: AttackerWallet[]
): AttackerStats {
  const totalVictims = correlation.wallets.length;
  
  const totalStolenUSD = correlation.wallets.reduce(
    (sum, w) => sum + w.totalDrainedValueUSD, 0
  );
  
  const chainsInvolved = [...new Set(correlation.wallets.map(w => w.chain))];
  
  // Calculate average time between attacks
  const timestamps = correlation.wallets
    .map(w => new Date(w.drainTimestamp).getTime())
    .sort((a, b) => a - b);
  
  let totalTimeBetween = 0;
  for (let i = 1; i < timestamps.length; i++) {
    totalTimeBetween += timestamps[i] - timestamps[i - 1];
  }
  const averageTimeBetweenAttacks = timestamps.length > 1
    ? (totalTimeBetween / (timestamps.length - 1)) / (1000 * 60) // in minutes
    : 0;
  
  return {
    totalVictims,
    totalStolenUSD,
    chainsInvolved,
    attackMethods: [], // Will be filled by classifier
    averageTimeBetweenAttacks,
    isOngoing: correlation.timeAnalysis.totalWindowMinutes < 60, // If within last hour
  };
}

// ============================================
// ROUTING PATTERN IDENTIFICATION
// ============================================

function identifyRoutingPatterns(wallets: IncidentWallet[]): RoutingPattern[] {
  const patterns: RoutingPattern[] = [];
  const patternCounts = new Map<string, number>();
  const patternSteps = new Map<string, RoutingStep[]>();
  
  for (const wallet of wallets) {
    const steps: RoutingStep[] = [];
    
    for (let i = 0; i < wallet.transferSequence.length; i++) {
      const transfer = wallet.transferSequence[i];
      
      steps.push({
        order: i + 1,
        type: determineTransferType(transfer),
        fromChain: wallet.chain,
        toChain: wallet.chain, // TODO: Detect cross-chain
        intermediaryAddress: transfer.to,
      });
    }
    
    // Create pattern signature
    const signature = steps.map(s => `${s.type}:${s.order}`).join('|');
    
    patternCounts.set(signature, (patternCounts.get(signature) || 0) + 1);
    if (!patternSteps.has(signature)) {
      patternSteps.set(signature, steps);
    }
  }
  
  // Build pattern objects for patterns used multiple times
  for (const [signature, count] of patternCounts) {
    if (count >= 2) {
      const steps = patternSteps.get(signature)!;
      
      patterns.push({
        patternId: generatePatternId(signature),
        description: generatePatternDescription(steps),
        steps,
        frequency: count,
        confidence: Math.min(90, 50 + count * 10),
      });
    }
  }
  
  return patterns;
}

function determineTransferType(
  transfer: { to: string; asset: string }
): 'TRANSFER' | 'SWAP' | 'BRIDGE' | 'DEPOSIT' {
  // Check if destination is a known exchange
  const isExchange = KNOWN_EXCHANGES.some(ex =>
    Object.values(ex.depositAddresses).flat().some(addr =>
      addr.toLowerCase() === transfer.to.toLowerCase()
    )
  );
  if (isExchange) return 'DEPOSIT';
  
  // Default to transfer
  return 'TRANSFER';
}

function generatePatternDescription(steps: RoutingStep[]): string {
  const stepDescriptions = steps.map(s => {
    switch (s.type) {
      case 'TRANSFER':
        return 'Transfer to intermediary';
      case 'SWAP':
        return 'Token swap';
      case 'BRIDGE':
        return `Bridge to ${s.toChain}`;
      case 'DEPOSIT':
        return 'Exchange deposit';
    }
  });
  
  return stepDescriptions.join(' → ');
}

function generatePatternId(signature: string): string {
  // Simple hash-like ID
  let hash = 0;
  for (let i = 0; i < signature.length; i++) {
    hash = ((hash << 5) - hash) + signature.charCodeAt(i);
    hash = hash & hash;
  }
  return `PAT-${Math.abs(hash).toString(36).substring(0, 8).toUpperCase()}`;
}

// ============================================
// EXIT LIQUIDITY IDENTIFICATION
// ============================================

function identifyExitLiquidity(correlation: CorrelationResult): ExitLiquidity[] {
  const exitPoints: ExitLiquidity[] = [];
  const destinationStats = new Map<string, {
    totalVolume: number;
    txCount: number;
    chain: Chain;
  }>();
  
  // Collect destination statistics
  for (const wallet of correlation.wallets) {
    for (const dest of wallet.destinationAddresses) {
      const key = dest.toLowerCase();
      if (!destinationStats.has(key)) {
        destinationStats.set(key, {
          totalVolume: 0,
          txCount: 0,
          chain: wallet.chain,
        });
      }
      const stats = destinationStats.get(key)!;
      stats.totalVolume += wallet.totalDrainedValueUSD;
      stats.txCount++;
    }
  }
  
  // Identify exit points
  for (const [address, stats] of destinationStats) {
    // Check if it's a known exchange
    const exchange = KNOWN_EXCHANGES.find(ex =>
      Object.values(ex.depositAddresses).flat().some(addr =>
        addr.toLowerCase() === address
      )
    );
    
    if (exchange) {
      exitPoints.push({
        type: exchange.type,
        name: exchange.name,
        address,
        chain: stats.chain,
        totalVolumeUSD: stats.totalVolume,
        transactionCount: stats.txCount,
        confidence: 90, // High confidence for known exchanges
      });
    } else if (stats.txCount >= 2) {
      // Unknown destination used multiple times
      exitPoints.push({
        type: 'UNKNOWN',
        name: 'Unknown Exit Point',
        address,
        chain: stats.chain,
        totalVolumeUSD: stats.totalVolume,
        transactionCount: stats.txCount,
        confidence: 50,
      });
    }
  }
  
  return exitPoints;
}

// ============================================
// CONFIDENCE CALCULATION
// ============================================

function calculateAttackerConfidence(
  wallets: AttackerWallet[],
  stats: AttackerStats,
  patterns: RoutingPattern[]
): { confidence: number; labelAsScammer: boolean } {
  let confidence = 0;
  
  // Number of victims
  if (stats.totalVictims >= 5) confidence += 25;
  else if (stats.totalVictims >= 2) confidence += 15;
  
  // Total stolen amount
  if (stats.totalStolenUSD >= 100000) confidence += 20;
  else if (stats.totalStolenUSD >= 10000) confidence += 15;
  else if (stats.totalStolenUSD >= 1000) confidence += 10;
  
  // Routing patterns detected
  if (patterns.length > 0) confidence += 15;
  
  // Multiple chains involved
  if (stats.chainsInvolved.length > 1) confidence += 10;
  
  // Aggregation wallet detected
  if (wallets.some(w => w.role === 'AGGREGATION')) confidence += 15;
  
  // Exchange deposits detected
  if (wallets.some(w => w.role === 'EXCHANGE_DEPOSIT')) confidence += 10;
  
  // Cap at 100
  confidence = Math.min(100, confidence);
  
  // Only label as scammer if confidence >= 90
  const labelAsScammer = confidence >= 90;
  
  return { confidence, labelAsScammer };
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function generateProfileId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `ATK-${timestamp}-${random}`.toUpperCase();
}

export { buildAttackerProfile };

