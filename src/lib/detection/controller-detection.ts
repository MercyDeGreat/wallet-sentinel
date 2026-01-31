// ============================================
// CONTROLLER DETECTION ENGINE
// ============================================
// 
// Identifies CONTROLLER (attacker) wallets in address poisoning attacks.
// 
// ATTACK FLOW:
// 1. Attacker creates poisoned address that mimics victim's frequent recipient
// 2. Attacker dusts victim's wallet from poisoned address
// 3. Victim mistakes poisoned address for real recipient and sends funds
// 4. Poisoned address forwards funds to CONTROLLER wallet
// 5. Controller consolidates and exits via bridges/mixers/CEX
//
// THIS ENGINE DETECTS:
// - Post-loss fund flow (N hops forward)
// - Controller wallet patterns (consolidation, fast forwarding, bridge usage)
// - Exit/laundering wallets
// - Cross-case correlation (same attacker across incidents)
//
// ROLE LABELS:
// - POISONED_ADDRESS: The decoy address that received victim funds
// - CONTROLLER_WALLET: The attacker's main operational wallet
// - EXIT_WALLET: Wallet used for laundering (bridges, mixers, CEX)
// ============================================

import { ethers } from 'ethers';

// ============================================
// TYPES
// ============================================

export type WalletRole = 
  | 'POISONED_ADDRESS'   // Decoy that received victim funds
  | 'CONTROLLER_WALLET'  // Main attacker operational wallet
  | 'EXIT_WALLET'        // Laundering endpoint (bridge/mixer/CEX)
  | 'INTERMEDIATE'       // Hop between poisoned and controller
  | 'UNKNOWN';

export interface ControllerCandidate {
  address: string;
  role: WalletRole;
  score: number; // 0-100
  signals: ControllerSignal[];
  hopDistance: number; // Distance from poisoned address
  receivedAmount: string;
  receivedFrom: string[];
  sentTo: string[];
  timing: {
    firstReceived: number;
    lastSent: number;
    avgForwardTime: number; // seconds
  };
  fingerprint?: ControllerFingerprint;
}

export interface ControllerSignal {
  type: ControllerSignalType;
  weight: 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';
  description: string;
  evidence?: string;
}

export type ControllerSignalType =
  | 'MULTIPLE_POISONED_SOURCES'  // Receives from multiple poisoned addresses
  | 'RAPID_FORWARDING'           // Fast consolidation (< 60 seconds)
  | 'HIGH_AMOUNT_FORWARDING'     // Forwards ≥90% of received
  | 'NO_DEFI_USAGE'              // No normal DeFi/NFT activity
  | 'BRIDGE_USAGE'               // Sends to known bridges
  | 'MIXER_USAGE'                // Sends to known mixers
  | 'CEX_DEPOSIT'                // Sends to CEX hot wallets
  | 'GAS_OPTIMIZED_BATCH'        // Gas-efficient batch transfers
  | 'REUSED_CONTROLLER'          // Seen in prior incidents
  | 'TIMING_PATTERN_MATCH';      // Same timing as known controllers

export interface ControllerFingerprint {
  id: string;
  avgForwardingTime: number;
  dustingInterval?: number;
  preferredChains: string[];
  preferredExits: string[];
  incidentCount: number;
  firstSeen: string;
  lastSeen: string;
}

export interface FlowTrace {
  poisonedAddress: string;
  victimAddress: string;
  victimLossAmount: string;
  victimLossTxHash: string;
  hops: FlowHop[];
  controllerCandidates: ControllerCandidate[];
  primaryController?: ControllerCandidate;
  exitWallets: ControllerCandidate[];
}

export interface FlowHop {
  hopNumber: number;
  from: string;
  to: string;
  amount: string;
  txHash: string;
  timestamp: number;
  timeDelta: number; // seconds since previous hop
  amountRatio: number; // ratio of received amount forwarded
}

export interface ControllerDetectionConfig {
  maxHops: number;           // Default: 3
  rapidForwardingThresholdSeconds: number;  // Default: 60
  highForwardingRatioThreshold: number;     // Default: 0.9 (90%)
  minScoreForController: number;            // Default: 60
}

// ============================================
// DEFAULT CONFIGURATION
// ============================================

export const DEFAULT_CONTROLLER_CONFIG: ControllerDetectionConfig = {
  maxHops: 3,
  rapidForwardingThresholdSeconds: 60,
  highForwardingRatioThreshold: 0.9,
  minScoreForController: 60,
};

// ============================================
// KNOWN EXIT ADDRESSES (Bridges, Mixers, CEX)
// ============================================

const KNOWN_BRIDGES: Set<string> = new Set([
  // Ethereum bridges
  '0x3ee18b2214aff97000d974cf647e7c347e8fa585'.toLowerCase(), // Wormhole
  '0x99c9fc46f92e8a1c0dec1b1747d010903e884be1'.toLowerCase(), // Optimism
  '0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f'.toLowerCase(), // Arbitrum
  '0x3154cf16ccdb4c6d922629664174b904d80f2c35'.toLowerCase(), // Base
  '0x72ce9c846789fdb6fc1f34ac4ad25dd9ef7031ef'.toLowerCase(), // Arbitrum Gateway
  '0x5fdcca53617f4d2b9134b29090c87d01058e27e9'.toLowerCase(), // Polygon Bridge
]);

const KNOWN_MIXERS: Set<string> = new Set([
  // Tornado Cash contracts
  '0x910cbd523d972eb0a6f4cae4618ad62622b39dbf'.toLowerCase(),
  '0xa160cdab225685da1d56aa342ad8841c3b53f291'.toLowerCase(),
  '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b'.toLowerCase(),
  '0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3'.toLowerCase(),
  '0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144'.toLowerCase(),
  '0x07687e702b410fa43f4cb4af7fa097918ffd2730'.toLowerCase(),
  '0x23773e65ed146a459791799d01336db287f25334'.toLowerCase(),
  '0x22aaa7720ddd5388a3c0a3333430953c68f1849b'.toLowerCase(),
]);

const KNOWN_CEX_WALLETS: Set<string> = new Set([
  // Binance
  '0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be'.toLowerCase(),
  '0xd551234ae421e3bcba99a0da6d736074f22192ff'.toLowerCase(),
  '0x564286362092d8e7936f0549571a803b203aaced'.toLowerCase(),
  // Coinbase
  '0x71660c4005ba85c37ccec55d0c4493e66fe775d3'.toLowerCase(),
  '0x503828976d22510aad0201ac7ec88293211d23da'.toLowerCase(),
  // Kraken
  '0x2910543af39aba0cd09dbb2d50200b3e800a63d2'.toLowerCase(),
  // OKX
  '0x6cc5f688a315f3dc28a7781717a9a798a59fda7b'.toLowerCase(),
]);

// ============================================
// KNOWN CONTROLLER FINGERPRINTS
// ============================================
// Stored fingerprints of known attackers for cross-case correlation

const KNOWN_CONTROLLER_FINGERPRINTS: Map<string, ControllerFingerprint> = new Map([
  // Example: Known address poisoning controller
  ['0x49a21fc945312c6fb4f8c6c4d224e74a5b96e9df'.toLowerCase(), {
    id: 'CONTROLLER-001',
    avgForwardingTime: 45,
    dustingInterval: 7200, // 2 hours
    preferredChains: ['ethereum', 'base'],
    preferredExits: ['binance', 'tornado'],
    incidentCount: 12,
    firstSeen: '2025-06-15T00:00:00Z',
    lastSeen: '2026-01-30T00:00:00Z',
  }],
]);

// ============================================
// CONTROLLER DETECTION ENGINE
// ============================================

export class ControllerDetectionEngine {
  private config: ControllerDetectionConfig;
  private provider: ethers.JsonRpcProvider | null = null;

  constructor(config: Partial<ControllerDetectionConfig> = {}) {
    this.config = { ...DEFAULT_CONTROLLER_CONFIG, ...config };
  }

  /**
   * Set the RPC provider for on-chain queries
   */
  setProvider(provider: ethers.JsonRpcProvider): void {
    this.provider = provider;
  }

  /**
   * Trace fund flow from poisoned address and detect controllers
   * 
   * @param poisonedAddress - The decoy address that received victim funds
   * @param victimAddress - The victim's wallet address
   * @param victimLossTxHash - The transaction where victim sent funds to poisoned address
   * @param victimLossAmount - Amount lost by victim
   * @param transactions - Transaction history to analyze
   */
  async traceAndDetectControllers(
    poisonedAddress: string,
    victimAddress: string,
    victimLossTxHash: string,
    victimLossAmount: string,
    transactions: {
      hash: string;
      from: string;
      to: string;
      value: string;
      timestamp: number;
    }[]
  ): Promise<FlowTrace> {
    const normalized = poisonedAddress.toLowerCase();
    
    // Initialize flow trace
    const flowTrace: FlowTrace = {
      poisonedAddress: normalized,
      victimAddress: victimAddress.toLowerCase(),
      victimLossAmount,
      victimLossTxHash,
      hops: [],
      controllerCandidates: [],
      exitWallets: [],
    };

    // Find the victim's loss transaction timestamp
    const lossTx = transactions.find(t => t.hash.toLowerCase() === victimLossTxHash.toLowerCase());
    const lossTimestamp = lossTx?.timestamp || 0;

    // ============================================
    // STEP 1: Trace N hops forward from poisoned address
    // ============================================
    const hops = this.traceForwardHops(
      normalized,
      victimLossAmount,
      lossTimestamp,
      transactions,
      this.config.maxHops
    );
    flowTrace.hops = hops;

    // ============================================
    // STEP 2: Analyze each destination and score
    // ============================================
    const destinationAddresses = new Set<string>();
    for (const hop of hops) {
      destinationAddresses.add(hop.to.toLowerCase());
    }

    for (const destAddress of destinationAddresses) {
      const candidate = this.analyzeDestination(
        destAddress,
        hops,
        transactions,
        normalized
      );
      
      if (candidate.score >= this.config.minScoreForController) {
        flowTrace.controllerCandidates.push(candidate);
      }
    }

    // ============================================
    // STEP 3: Identify primary controller and exits
    // ============================================
    flowTrace.controllerCandidates.sort((a, b) => b.score - a.score);
    
    if (flowTrace.controllerCandidates.length > 0) {
      // Highest scoring = primary controller
      const primary = flowTrace.controllerCandidates[0];
      if (primary.role === 'CONTROLLER_WALLET' || primary.role === 'INTERMEDIATE') {
        flowTrace.primaryController = primary;
      }
    }

    // Identify exit wallets
    flowTrace.exitWallets = flowTrace.controllerCandidates.filter(
      c => c.role === 'EXIT_WALLET'
    );

    return flowTrace;
  }

  /**
   * Trace forward hops from poisoned address
   */
  private traceForwardHops(
    startAddress: string,
    startAmount: string,
    startTimestamp: number,
    transactions: {
      hash: string;
      from: string;
      to: string;
      value: string;
      timestamp: number;
    }[],
    maxHops: number
  ): FlowHop[] {
    const hops: FlowHop[] = [];
    const visited = new Set<string>();
    visited.add(startAddress);

    let currentAddresses = [startAddress];
    let currentAmount = startAmount;
    let previousTimestamp = startTimestamp;
    let hopNumber = 0;

    while (hopNumber < maxHops && currentAddresses.length > 0) {
      hopNumber++;
      const nextAddresses: string[] = [];

      for (const currentAddr of currentAddresses) {
        // Find outbound transactions from current address after previous timestamp
        const outbound = transactions.filter(t => 
          t.from.toLowerCase() === currentAddr &&
          t.timestamp >= previousTimestamp &&
          !visited.has(t.to.toLowerCase())
        );

        for (const tx of outbound) {
          const toAddr = tx.to.toLowerCase();
          const timeDelta = tx.timestamp - previousTimestamp;
          
          // Calculate amount ratio
          let amountRatio = 0;
          try {
            const received = BigInt(currentAmount);
            const sent = BigInt(tx.value);
            if (received > BigInt(0)) {
              amountRatio = Number(sent * BigInt(100) / received) / 100;
            }
          } catch {
            amountRatio = 0;
          }

          hops.push({
            hopNumber,
            from: currentAddr,
            to: toAddr,
            amount: tx.value,
            txHash: tx.hash,
            timestamp: tx.timestamp,
            timeDelta,
            amountRatio,
          });

          visited.add(toAddr);
          nextAddresses.push(toAddr);
        }
      }

      currentAddresses = nextAddresses;
      if (hops.length > 0) {
        previousTimestamp = hops[hops.length - 1].timestamp;
        currentAmount = hops[hops.length - 1].amount;
      }
    }

    return hops;
  }

  /**
   * Analyze a destination address and generate controller score
   */
  private analyzeDestination(
    address: string,
    hops: FlowHop[],
    transactions: {
      hash: string;
      from: string;
      to: string;
      value: string;
      timestamp: number;
    }[],
    poisonedAddress: string
  ): ControllerCandidate {
    const signals: ControllerSignal[] = [];
    let score = 0;

    // Get hops TO this address
    const inboundHops = hops.filter(h => h.to === address);
    const outboundHops = hops.filter(h => h.from === address);
    
    // Calculate hop distance
    const hopDistance = inboundHops.length > 0 
      ? Math.min(...inboundHops.map(h => h.hopNumber))
      : 0;

    // Calculate received amount
    let receivedAmount = BigInt(0);
    try {
      for (const hop of inboundHops) {
        receivedAmount += BigInt(hop.amount);
      }
    } catch {
      receivedAmount = BigInt(0);
    }

    // Get unique senders
    const receivedFrom = [...new Set(inboundHops.map(h => h.from))];
    const sentTo = [...new Set(outboundHops.map(h => h.to))];

    // Calculate timing
    const timestamps = inboundHops.map(h => h.timestamp);
    const firstReceived = timestamps.length > 0 ? Math.min(...timestamps) : 0;
    const outTimestamps = outboundHops.map(h => h.timestamp);
    const lastSent = outTimestamps.length > 0 ? Math.max(...outTimestamps) : 0;
    const avgForwardTime = inboundHops.length > 0
      ? inboundHops.reduce((sum, h) => sum + h.timeDelta, 0) / inboundHops.length
      : 0;

    // ============================================
    // SIGNAL 1: Multiple poisoned sources
    // ============================================
    if (receivedFrom.length > 1) {
      signals.push({
        type: 'MULTIPLE_POISONED_SOURCES',
        weight: 'HIGH',
        description: `Receives funds from ${receivedFrom.length} different addresses`,
        evidence: receivedFrom.join(', '),
      });
      score += 25;
    }

    // ============================================
    // SIGNAL 2: Rapid forwarding
    // ============================================
    const hasRapidForwarding = inboundHops.some(
      h => h.timeDelta < this.config.rapidForwardingThresholdSeconds
    );
    if (hasRapidForwarding) {
      signals.push({
        type: 'RAPID_FORWARDING',
        weight: 'HIGH',
        description: `Forwards funds within ${this.config.rapidForwardingThresholdSeconds} seconds`,
        evidence: `Avg forward time: ${avgForwardTime.toFixed(0)}s`,
      });
      score += 20;
    }

    // ============================================
    // SIGNAL 3: High amount forwarding (≥90%)
    // ============================================
    const hasHighForwarding = inboundHops.some(
      h => h.amountRatio >= this.config.highForwardingRatioThreshold
    );
    if (hasHighForwarding) {
      signals.push({
        type: 'HIGH_AMOUNT_FORWARDING',
        weight: 'MEDIUM',
        description: `Forwards ≥${this.config.highForwardingRatioThreshold * 100}% of received funds`,
      });
      score += 15;
    }

    // ============================================
    // SIGNAL 4: Bridge usage
    // ============================================
    const bridgeDestinations = sentTo.filter(addr => KNOWN_BRIDGES.has(addr));
    if (bridgeDestinations.length > 0) {
      signals.push({
        type: 'BRIDGE_USAGE',
        weight: 'HIGH',
        description: `Sends funds to ${bridgeDestinations.length} known bridge(s)`,
        evidence: bridgeDestinations.join(', '),
      });
      score += 20;
    }

    // ============================================
    // SIGNAL 5: Mixer usage
    // ============================================
    const mixerDestinations = sentTo.filter(addr => KNOWN_MIXERS.has(addr));
    if (mixerDestinations.length > 0) {
      signals.push({
        type: 'MIXER_USAGE',
        weight: 'HIGH',
        description: `Sends funds to ${mixerDestinations.length} known mixer(s)`,
        evidence: mixerDestinations.join(', '),
      });
      score += 25;
    }

    // ============================================
    // SIGNAL 6: CEX deposit
    // ============================================
    const cexDestinations = sentTo.filter(addr => KNOWN_CEX_WALLETS.has(addr));
    if (cexDestinations.length > 0) {
      signals.push({
        type: 'CEX_DEPOSIT',
        weight: 'HIGH',
        description: `Deposits to ${cexDestinations.length} known exchange(s)`,
        evidence: cexDestinations.join(', '),
      });
      score += 20;
    }

    // ============================================
    // SIGNAL 7: Known controller (cross-case correlation)
    // ============================================
    const knownFingerprint = KNOWN_CONTROLLER_FINGERPRINTS.get(address);
    if (knownFingerprint) {
      signals.push({
        type: 'REUSED_CONTROLLER',
        weight: 'VERY_HIGH',
        description: `Known controller from ${knownFingerprint.incidentCount} prior incidents`,
        evidence: `First seen: ${knownFingerprint.firstSeen}`,
      });
      score += 35;
    }

    // ============================================
    // SIGNAL 8: Timing pattern match
    // ============================================
    // Check if timing matches known controller patterns
    for (const [, fingerprint] of KNOWN_CONTROLLER_FINGERPRINTS) {
      const timingDiff = Math.abs(avgForwardTime - fingerprint.avgForwardingTime);
      if (timingDiff < 10) { // Within 10 seconds of known pattern
        signals.push({
          type: 'TIMING_PATTERN_MATCH',
          weight: 'MEDIUM',
          description: `Timing pattern matches known controller (${fingerprint.id})`,
        });
        score += 10;
        break;
      }
    }

    // ============================================
    // Determine role
    // ============================================
    let role: WalletRole = 'UNKNOWN';
    
    if (address === poisonedAddress) {
      role = 'POISONED_ADDRESS';
    } else if (bridgeDestinations.length > 0 || mixerDestinations.length > 0 || cexDestinations.length > 0) {
      role = 'EXIT_WALLET';
    } else if (score >= 50 && (hasRapidForwarding || receivedFrom.length > 1)) {
      role = 'CONTROLLER_WALLET';
    } else if (hopDistance > 1) {
      role = 'INTERMEDIATE';
    }

    // Cap score
    score = Math.min(score, 100);

    return {
      address,
      role,
      score,
      signals,
      hopDistance,
      receivedAmount: receivedAmount.toString(),
      receivedFrom,
      sentTo,
      timing: {
        firstReceived,
        lastSent,
        avgForwardTime,
      },
      fingerprint: knownFingerprint,
    };
  }

  /**
   * Check if address is a known controller
   */
  isKnownController(address: string): boolean {
    return KNOWN_CONTROLLER_FINGERPRINTS.has(address.toLowerCase());
  }

  /**
   * Get controller fingerprint
   */
  getControllerFingerprint(address: string): ControllerFingerprint | undefined {
    return KNOWN_CONTROLLER_FINGERPRINTS.get(address.toLowerCase());
  }

  /**
   * Add a new controller fingerprint (for learning)
   */
  static addControllerFingerprint(address: string, fingerprint: ControllerFingerprint): void {
    KNOWN_CONTROLLER_FINGERPRINTS.set(address.toLowerCase(), fingerprint);
  }

  /**
   * Check if address is a known exit (bridge/mixer/CEX)
   */
  isKnownExit(address: string): { isExit: boolean; type?: 'BRIDGE' | 'MIXER' | 'CEX' } {
    const normalized = address.toLowerCase();
    
    if (KNOWN_BRIDGES.has(normalized)) {
      return { isExit: true, type: 'BRIDGE' };
    }
    if (KNOWN_MIXERS.has(normalized)) {
      return { isExit: true, type: 'MIXER' };
    }
    if (KNOWN_CEX_WALLETS.has(normalized)) {
      return { isExit: true, type: 'CEX' };
    }
    
    return { isExit: false };
  }
}

// ============================================
// FACTORY FUNCTION
// ============================================

export function createControllerDetectionEngine(
  config?: Partial<ControllerDetectionConfig>
): ControllerDetectionEngine {
  return new ControllerDetectionEngine(config);
}

// ============================================
// UTILITY: Generate UX Output
// ============================================

export function generateControllerAlertMessage(flowTrace: FlowTrace): {
  headline: string;
  summary: string;
  details: string[];
  poisonedAddress: string;
  controllerAddress?: string;
  exitAddresses: string[];
  priorIncidents?: number;
} {
  const details: string[] = [];
  
  details.push('• Funds were mistakenly sent to a look-alike address');
  details.push('• No signer or private key compromise detected');
  
  if (flowTrace.primaryController) {
    details.push('• The poisoned address forwarded funds to a controller wallet');
  }
  
  if (flowTrace.exitWallets.length > 0) {
    const exitTypes = flowTrace.exitWallets
      .map(e => e.signals.find(s => ['BRIDGE_USAGE', 'MIXER_USAGE', 'CEX_DEPOSIT'].includes(s.type))?.type)
      .filter(Boolean);
    if (exitTypes.includes('MIXER_USAGE')) {
      details.push('• Funds were sent through a mixer (likely unrecoverable)');
    } else if (exitTypes.includes('BRIDGE_USAGE')) {
      details.push('• Funds were bridged to another chain');
    } else if (exitTypes.includes('CEX_DEPOSIT')) {
      details.push('• Funds were deposited to a centralized exchange');
    }
  }

  const priorIncidents = flowTrace.primaryController?.fingerprint?.incidentCount;
  if (priorIncidents) {
    details.push(`• This controller was involved in ${priorIncidents} prior attacks`);
  }

  return {
    headline: '⚠️ Address Poisoning Attack',
    summary: 'Funds were sent to a look-alike (poisoned) address that forwarded them to an attacker-controlled wallet.',
    details,
    poisonedAddress: flowTrace.poisonedAddress,
    controllerAddress: flowTrace.primaryController?.address,
    exitAddresses: flowTrace.exitWallets.map(e => e.address),
    priorIncidents,
  };
}
