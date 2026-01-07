// ============================================
// EXCHANGE ESCALATION REPORT GENERATOR
// ============================================
// Generates comprehensive reports for exchange abuse portals.
// Reports are machine-readable and human-readable.
//
// Triggered when:
// - Destination touches a centralized exchange
// - Confidence score ≥ 80

import { Chain } from '@/types';
import {
  ExchangeEscalationReport,
  IncidentSummary,
  VictimInfo,
  AttackerInfo,
  TransactionEvidence,
  TimelineEvent,
  ExchangeSpecificData,
  CorrelationResult,
  AttackClassificationResult,
  AttackerProfile,
  CorrelationConfig,
  DEFAULT_CORRELATION_CONFIG,
  KNOWN_EXCHANGES,
  generateReportId,
} from './types';

// ============================================
// MAIN REPORT GENERATION FUNCTION
// ============================================

/**
 * Generate an exchange escalation report.
 * Only generates if confidence >= threshold and exchange deposit detected.
 */
export function generateExchangeReport(
  correlation: CorrelationResult,
  classification: AttackClassificationResult,
  attackerProfile: AttackerProfile,
  config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG
): ExchangeEscalationReport | null {
  // Check if we should generate a report
  const exchangeDeposit = findExchangeDeposit(correlation, attackerProfile);
  
  if (!exchangeDeposit) {
    return null; // No exchange deposit detected
  }
  
  if (classification.confidenceScore < config.exchangeEscalationThreshold) {
    return null; // Confidence too low
  }
  
  const reportId = generateReportId();
  const now = new Date().toISOString();
  
  // Build report sections
  const incidentSummary = buildIncidentSummary(correlation, classification);
  const victims = buildVictimList(correlation);
  const attackerInfo = buildAttackerInfo(correlation, attackerProfile, exchangeDeposit);
  const transactionEvidence = buildTransactionEvidence(correlation);
  const incidentTimeline = buildTimeline(correlation, exchangeDeposit);
  const exchangeData = buildExchangeSpecificData(exchangeDeposit, correlation);
  
  // Generate human-readable report
  const humanReadableReport = generateHumanReadableReport(
    incidentSummary,
    victims,
    attackerInfo,
    transactionEvidence,
    incidentTimeline,
    exchangeData,
    classification
  );
  
  // Generate machine-readable evidence
  const machineReadableEvidence = generateMachineReadableEvidence(
    correlation,
    classification,
    attackerProfile
  );
  
  return {
    reportId,
    generatedAt: now,
    reportVersion: '1.0.0',
    incidentSummary,
    attackClassification: classification,
    victims,
    attackerInfo,
    transactionEvidence,
    incidentTimeline,
    exchangeData,
    confidenceScore: classification.confidenceScore,
    escalationReady: true,
    escalationReadinessReason: 'All required evidence collected and exchange deposit confirmed.',
    humanReadableReport,
    machineReadableEvidence,
  };
}

// ============================================
// EXCHANGE DEPOSIT DETECTION
// ============================================

interface ExchangeDeposit {
  exchangeName: string;
  depositAddress: string;
  depositTxHashes: string[];
  totalDepositedUSD: number;
  firstDepositTimestamp: string;
  lastDepositTimestamp: string;
  chain: Chain;
  exchangeInfo: typeof KNOWN_EXCHANGES[0] | null;
}

function findExchangeDeposit(
  correlation: CorrelationResult,
  attackerProfile: AttackerProfile
): ExchangeDeposit | null {
  // Check attacker profile for exchange deposits
  const exchangeWallets = attackerProfile.wallets.filter(w => w.role === 'EXCHANGE_DEPOSIT');
  
  if (exchangeWallets.length === 0) {
    // Check destinations directly
    for (const dest of correlation.destinationAnalysis.uniqueDestinations) {
      const exchange = KNOWN_EXCHANGES.find(ex =>
        Object.values(ex.depositAddresses).flat().some(addr =>
          addr.toLowerCase() === dest.toLowerCase()
        )
      );
      
      if (exchange) {
        // Find transactions to this address
        const txs = collectTransactionsToAddress(correlation, dest);
        
        return {
          exchangeName: exchange.name,
          depositAddress: dest,
          depositTxHashes: txs.map(t => t.txHash),
          totalDepositedUSD: txs.reduce((sum, t) => sum + t.valueUSD, 0),
          firstDepositTimestamp: txs[0]?.timestamp || new Date().toISOString(),
          lastDepositTimestamp: txs[txs.length - 1]?.timestamp || new Date().toISOString(),
          chain: correlation.wallets[0]?.chain || 'ethereum',
          exchangeInfo: exchange,
        };
      }
    }
    return null;
  }
  
  // Use first exchange wallet found
  const exchangeWallet = exchangeWallets[0];
  const exchange = KNOWN_EXCHANGES.find(ex =>
    Object.values(ex.depositAddresses).flat().some(addr =>
      addr.toLowerCase() === exchangeWallet.address.toLowerCase()
    )
  );
  
  const txs = collectTransactionsToAddress(correlation, exchangeWallet.address);
  
  return {
    exchangeName: exchange?.name || 'Unknown Exchange',
    depositAddress: exchangeWallet.address,
    depositTxHashes: txs.map(t => t.txHash),
    totalDepositedUSD: exchangeWallet.totalReceivedFromVictims,
    firstDepositTimestamp: exchangeWallet.firstSeen,
    lastDepositTimestamp: exchangeWallet.lastSeen,
    chain: exchangeWallet.chain,
    exchangeInfo: exchange || null,
  };
}

function collectTransactionsToAddress(
  correlation: CorrelationResult,
  address: string
): Array<{ txHash: string; timestamp: string; valueUSD: number }> {
  const txs: Array<{ txHash: string; timestamp: string; valueUSD: number }> = [];
  
  for (const wallet of correlation.wallets) {
    for (const step of wallet.transferSequence) {
      if (step.to.toLowerCase() === address.toLowerCase()) {
        txs.push({
          txHash: step.txHash,
          timestamp: step.timestamp,
          valueUSD: parseFloat(step.amount) || 0,
        });
      }
    }
  }
  
  return txs.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

// ============================================
// INCIDENT SUMMARY BUILDER
// ============================================

function buildIncidentSummary(
  correlation: CorrelationResult,
  classification: AttackClassificationResult
): IncidentSummary {
  const totalLoss = correlation.wallets.reduce(
    (sum, w) => sum + w.totalDrainedValueUSD, 0
  );
  
  const chains = [...new Set(correlation.wallets.map(w => w.chain))];
  
  // Determine title based on classification
  let title: string;
  switch (classification.classification) {
    case 'SEED_SIGNER_COMPROMISE':
      title = 'Multi-Wallet Seed/Signer Compromise';
      break;
    case 'APPROVAL_BASED_DRAIN':
      title = 'Token Approval Exploit';
      break;
    case 'CONTRACT_EXPLOIT':
      title = 'Smart Contract Exploit';
      break;
    default:
      title = 'Wallet Drain Incident';
  }
  
  return {
    incidentId: correlation.correlationId,
    title,
    description: classification.summary,
    totalLossUSD: totalLoss,
    victimCount: correlation.wallets.length,
    chainsAffected: chains,
    incidentStart: correlation.timeAnalysis.earliestDrain,
    incidentEnd: correlation.timeAnalysis.latestDrain,
    status: correlation.timeAnalysis.totalWindowMinutes < 60 ? 'ONGOING' : 'COMPLETED',
  };
}

// ============================================
// VICTIM LIST BUILDER
// ============================================

function buildVictimList(correlation: CorrelationResult): VictimInfo[] {
  return correlation.wallets.map(wallet => ({
    walletAddress: wallet.address,
    chain: wallet.chain,
    lossUSD: wallet.totalDrainedValueUSD,
    drainTimestamp: wallet.drainTimestamp,
    assetsLost: wallet.drainedAssets,
    txHashes: [wallet.drainTxHash, ...wallet.transferSequence.map(s => s.txHash)],
  }));
}

// ============================================
// ATTACKER INFO BUILDER
// ============================================

function buildAttackerInfo(
  correlation: CorrelationResult,
  attackerProfile: AttackerProfile,
  exchangeDeposit: ExchangeDeposit
): AttackerInfo {
  // Find primary attacker wallet (aggregation or most used)
  const sortedWallets = [...attackerProfile.wallets].sort(
    (a, b) => b.linkedVictimCount - a.linkedVictimCount
  );
  
  const primaryWallet = sortedWallets[0]?.address || correlation.destinationAnalysis.primaryDestination || '';
  const additionalWallets = sortedWallets.slice(1).map(w => w.address);
  
  // Build routing path
  const routingPath: string[] = [];
  if (correlation.wallets[0]) {
    routingPath.push(correlation.wallets[0].address); // Victim
    for (const step of correlation.wallets[0].transferSequence) {
      if (!routingPath.includes(step.to)) {
        routingPath.push(step.to);
      }
    }
  }
  
  return {
    primaryWallet,
    additionalWallets,
    chainsUsed: [...new Set(attackerProfile.wallets.map(w => w.chain))],
    totalStolenUSD: attackerProfile.stats.totalStolenUSD,
    routingPath,
    exchangeDeposit: {
      exchangeName: exchangeDeposit.exchangeName,
      depositAddress: exchangeDeposit.depositAddress,
      depositTxHash: exchangeDeposit.depositTxHashes[0] || '',
      depositTimestamp: exchangeDeposit.firstDepositTimestamp,
      depositAmountUSD: exchangeDeposit.totalDepositedUSD,
    },
  };
}

// ============================================
// TRANSACTION EVIDENCE BUILDER
// ============================================

function buildTransactionEvidence(correlation: CorrelationResult): TransactionEvidence[] {
  const evidence: TransactionEvidence[] = [];
  
  for (const wallet of correlation.wallets) {
    // Add drain transaction
    evidence.push({
      txHash: wallet.drainTxHash,
      chain: wallet.chain,
      type: 'DRAIN',
      from: wallet.address,
      to: wallet.destinationAddresses[0] || '',
      asset: wallet.drainedAssets[0]?.symbol || 'UNKNOWN',
      amount: wallet.drainedAssets[0]?.amount || '0',
      valueUSD: wallet.totalDrainedValueUSD,
      timestamp: wallet.drainTimestamp,
      blockNumber: wallet.drainBlockNumber,
      description: `Initial drain from victim wallet ${wallet.address.slice(0, 10)}...`,
    });
    
    // Add transfer steps
    for (const step of wallet.transferSequence) {
      const isExchangeDeposit = KNOWN_EXCHANGES.some(ex =>
        Object.values(ex.depositAddresses).flat().some(addr =>
          addr.toLowerCase() === step.to.toLowerCase()
        )
      );
      
      evidence.push({
        txHash: step.txHash,
        chain: wallet.chain,
        type: isExchangeDeposit ? 'EXCHANGE_DEPOSIT' : 'TRANSFER',
        from: step.from,
        to: step.to,
        asset: step.asset,
        amount: step.amount,
        valueUSD: parseFloat(step.amount) || 0,
        timestamp: step.timestamp,
        blockNumber: step.blockNumber,
        description: isExchangeDeposit
          ? `Deposit to exchange address ${step.to.slice(0, 10)}...`
          : `Transfer to intermediary ${step.to.slice(0, 10)}...`,
      });
    }
  }
  
  // Sort by timestamp
  return evidence.sort((a, b) =>
    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
}

// ============================================
// TIMELINE BUILDER
// ============================================

function buildTimeline(
  correlation: CorrelationResult,
  exchangeDeposit: ExchangeDeposit
): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  
  // Add drain events
  for (const wallet of correlation.wallets) {
    events.push({
      timestamp: wallet.drainTimestamp,
      eventType: 'DRAIN',
      description: `Wallet ${wallet.address.slice(0, 10)}... drained of $${wallet.totalDrainedValueUSD.toLocaleString()} USD`,
      txHash: wallet.drainTxHash,
      walletAddress: wallet.address,
      significance: 'HIGH',
    });
  }
  
  // Add exchange deposit event
  events.push({
    timestamp: exchangeDeposit.firstDepositTimestamp,
    eventType: 'EXCHANGE_DEPOSIT',
    description: `Funds deposited to ${exchangeDeposit.exchangeName} ($${exchangeDeposit.totalDepositedUSD.toLocaleString()} USD)`,
    txHash: exchangeDeposit.depositTxHashes[0],
    significance: 'HIGH',
  });
  
  // Sort by timestamp
  return events.sort((a, b) =>
    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
}

// ============================================
// EXCHANGE-SPECIFIC DATA BUILDER
// ============================================

function buildExchangeSpecificData(
  exchangeDeposit: ExchangeDeposit,
  correlation: CorrelationResult
): ExchangeSpecificData {
  // Determine urgency based on recency and amount
  const hoursSinceDeposit = (Date.now() - new Date(exchangeDeposit.lastDepositTimestamp).getTime()) / (1000 * 60 * 60);
  
  let urgencyLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  if (hoursSinceDeposit < 1 && exchangeDeposit.totalDepositedUSD > 10000) {
    urgencyLevel = 'CRITICAL';
  } else if (hoursSinceDeposit < 6) {
    urgencyLevel = 'HIGH';
  } else if (hoursSinceDeposit < 24) {
    urgencyLevel = 'MEDIUM';
  } else {
    urgencyLevel = 'LOW';
  }
  
  // Determine requested action
  let requestedAction: 'FREEZE_FUNDS' | 'FLAG_ACCOUNT' | 'INVESTIGATE' | 'MONITOR';
  if (urgencyLevel === 'CRITICAL') {
    requestedAction = 'FREEZE_FUNDS';
  } else if (urgencyLevel === 'HIGH') {
    requestedAction = 'FLAG_ACCOUNT';
  } else if (urgencyLevel === 'MEDIUM') {
    requestedAction = 'INVESTIGATE';
  } else {
    requestedAction = 'MONITOR';
  }
  
  const complianceNotes = [
    `Total funds traced: $${exchangeDeposit.totalDepositedUSD.toLocaleString()} USD`,
    `Number of victims: ${correlation.wallets.length}`,
    `Time since deposit: ${hoursSinceDeposit.toFixed(1)} hours`,
    `Chains involved: ${[...new Set(correlation.wallets.map(w => w.chain))].join(', ')}`,
  ];
  
  return {
    exchangeName: exchangeDeposit.exchangeName,
    depositAddress: exchangeDeposit.depositAddress,
    depositTxHashes: exchangeDeposit.depositTxHashes,
    totalDepositedUSD: exchangeDeposit.totalDepositedUSD,
    firstDepositTimestamp: exchangeDeposit.firstDepositTimestamp,
    lastDepositTimestamp: exchangeDeposit.lastDepositTimestamp,
    complianceNotes,
    urgencyLevel,
    requestedAction,
  };
}

// ============================================
// HUMAN-READABLE REPORT GENERATOR
// ============================================

function generateHumanReadableReport(
  summary: IncidentSummary,
  victims: VictimInfo[],
  attackerInfo: AttackerInfo,
  transactionEvidence: TransactionEvidence[],
  timeline: TimelineEvent[],
  exchangeData: ExchangeSpecificData,
  classification: AttackClassificationResult
): string {
  const lines: string[] = [];
  
  // Header
  lines.push('═'.repeat(70));
  lines.push('EXCHANGE ESCALATION REPORT - SECURNEX SECURITY PLATFORM');
  lines.push('═'.repeat(70));
  lines.push('');
  
  // Incident Summary
  lines.push('INCIDENT SUMMARY');
  lines.push('─'.repeat(40));
  lines.push(`Incident ID: ${summary.incidentId}`);
  lines.push(`Title: ${summary.title}`);
  lines.push(`Status: ${summary.status}`);
  lines.push(`Total Loss: $${summary.totalLossUSD.toLocaleString()} USD`);
  lines.push(`Victims: ${summary.victimCount}`);
  lines.push(`Chains: ${summary.chainsAffected.join(', ')}`);
  lines.push(`Start: ${summary.incidentStart}`);
  lines.push(`End: ${summary.incidentEnd}`);
  lines.push('');
  
  // Attack Classification
  lines.push('ATTACK CLASSIFICATION');
  lines.push('─'.repeat(40));
  lines.push(`Classification: ${classification.classification.replace(/_/g, ' ')}`);
  lines.push(`Confidence: ${classification.confidence} (${classification.confidenceScore}/100)`);
  lines.push(`Summary: ${classification.summary}`);
  lines.push('');
  
  // Why NOT other classifications
  lines.push('CLASSIFICATION REASONING');
  lines.push('─'.repeat(40));
  if (classification.reasoning.whyNotApprovalDrain) {
    lines.push(`Why not approval drain: ${classification.reasoning.whyNotApprovalDrain}`);
  }
  if (classification.reasoning.whyNotContractExploit) {
    lines.push(`Why not contract exploit: ${classification.reasoning.whyNotContractExploit}`);
  }
  lines.push('');
  
  // Victim Wallets
  lines.push('VICTIM WALLETS');
  lines.push('─'.repeat(40));
  for (const victim of victims) {
    lines.push(`• ${victim.walletAddress}`);
    lines.push(`  Chain: ${victim.chain}`);
    lines.push(`  Loss: $${victim.lossUSD.toLocaleString()} USD`);
    lines.push(`  Drain Time: ${victim.drainTimestamp}`);
    lines.push(`  TX Hashes: ${victim.txHashes.join(', ')}`);
    lines.push('');
  }
  
  // Attacker Wallets
  lines.push('ATTACKER INFRASTRUCTURE');
  lines.push('─'.repeat(40));
  lines.push(`Primary Wallet: ${attackerInfo.primaryWallet}`);
  if (attackerInfo.additionalWallets.length > 0) {
    lines.push(`Additional Wallets: ${attackerInfo.additionalWallets.join(', ')}`);
  }
  lines.push(`Total Stolen: $${attackerInfo.totalStolenUSD.toLocaleString()} USD`);
  lines.push(`Routing Path: ${attackerInfo.routingPath.join(' → ')}`);
  lines.push('');
  
  // Exchange Deposit
  lines.push('EXCHANGE DEPOSIT DETAILS');
  lines.push('─'.repeat(40));
  lines.push(`Exchange: ${exchangeData.exchangeName}`);
  lines.push(`Deposit Address: ${exchangeData.depositAddress}`);
  lines.push(`Amount Deposited: $${exchangeData.totalDepositedUSD.toLocaleString()} USD`);
  lines.push(`First Deposit: ${exchangeData.firstDepositTimestamp}`);
  lines.push(`Last Deposit: ${exchangeData.lastDepositTimestamp}`);
  lines.push(`TX Hashes: ${exchangeData.depositTxHashes.join(', ')}`);
  lines.push('');
  
  // Urgency
  lines.push('ACTION REQUIRED');
  lines.push('─'.repeat(40));
  lines.push(`Urgency: ${exchangeData.urgencyLevel}`);
  lines.push(`Requested Action: ${exchangeData.requestedAction.replace(/_/g, ' ')}`);
  lines.push('');
  lines.push('Compliance Notes:');
  for (const note of exchangeData.complianceNotes) {
    lines.push(`• ${note}`);
  }
  lines.push('');
  
  // Timeline
  lines.push('INCIDENT TIMELINE (UTC)');
  lines.push('─'.repeat(40));
  for (const event of timeline) {
    const icon = event.significance === 'HIGH' ? '🔴' : event.significance === 'MEDIUM' ? '🟡' : '🟢';
    lines.push(`${icon} ${event.timestamp} - ${event.description}`);
    if (event.txHash) {
      lines.push(`   TX: ${event.txHash}`);
    }
  }
  lines.push('');
  
  // Footer
  lines.push('═'.repeat(70));
  lines.push('Generated by Securnex Security Platform');
  lines.push(`Report generated: ${new Date().toISOString()}`);
  lines.push('═'.repeat(70));
  
  return lines.join('\n');
}

// ============================================
// MACHINE-READABLE EVIDENCE GENERATOR
// ============================================

function generateMachineReadableEvidence(
  correlation: CorrelationResult,
  classification: AttackClassificationResult,
  attackerProfile: AttackerProfile
): object {
  return {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    platform: 'Securnex',
    
    incident: {
      correlationId: correlation.correlationId,
      classification: classification.classification,
      confidenceScore: classification.confidenceScore,
      confidenceLevel: classification.confidence,
    },
    
    victims: correlation.wallets.map(w => ({
      address: w.address,
      chain: w.chain,
      drainTxHash: w.drainTxHash,
      drainTimestamp: w.drainTimestamp,
      drainBlockNumber: w.drainBlockNumber,
      totalLossUSD: w.totalDrainedValueUSD,
      assets: w.drainedAssets.map(a => ({
        type: a.type,
        symbol: a.symbol,
        amount: a.amount,
        valueUSD: a.valueUSD,
        contractAddress: a.contractAddress,
      })),
    })),
    
    attackers: attackerProfile.wallets.map(w => ({
      address: w.address,
      chain: w.chain,
      role: w.role,
      totalReceived: w.totalReceivedFromVictims,
      linkedVictims: w.linkedVictimCount,
      confidence: w.confidence,
    })),
    
    transactions: correlation.wallets.flatMap(w => [
      {
        hash: w.drainTxHash,
        type: 'DRAIN',
        from: w.address,
        to: w.destinationAddresses[0],
        timestamp: w.drainTimestamp,
        blockNumber: w.drainBlockNumber,
      },
      ...w.transferSequence.map(s => ({
        hash: s.txHash,
        type: 'TRANSFER',
        from: s.from,
        to: s.to,
        timestamp: s.timestamp,
        blockNumber: s.blockNumber,
      })),
    ]),
    
    routing: {
      patterns: attackerProfile.routingPatterns,
      exitLiquidity: attackerProfile.exitLiquidity,
    },
    
    evidence: {
      supporting: classification.supportingEvidence,
      contradicting: classification.contradictingEvidence,
    },
  };
}

