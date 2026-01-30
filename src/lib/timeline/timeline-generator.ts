// ============================================
// WALLET STATUS TIMELINE GENERATOR
// ============================================
// Generates a chronological, human-readable timeline that explains:
// - WHAT happened
// - WHEN it happened  
// - WHAT changed
// - CURRENT wallet state
//
// CRITICAL RULE: Past compromise ≠ Active compromise
// Historical events MUST NOT mark wallet as actively compromised

import {
  TimelineEvent,
  TimelineEventType,
  TimelineEventSeverity,
  TimelineEventReference,
  WalletTimeline,
  TimelineGenerationInput,
  TIMELINE_EVENT_TEMPLATES,
  SecurityStatus,
  Chain,
  CompromiseEvidence,
} from '@/types';

// ============================================
// TIMELINE EVENT FACTORY
// ============================================

let eventIdCounter = 0;

function generateEventId(): string {
  return `evt_${Date.now()}_${++eventIdCounter}`;
}

/**
 * Create a timeline event with consistent structure
 */
function createTimelineEvent(
  eventType: TimelineEventType,
  timestamp: string,
  chain: Chain,
  description: string,
  options: {
    title?: string;
    severity?: TimelineEventSeverity;
    blockNumber?: number;
    technicalDetails?: string;
    references?: TimelineEventReference[];
    relatedEventIds?: string[];
    isExpandable?: boolean;
    isPersistent?: boolean;
    affectsCurrentStatus?: boolean;
  } = {}
): TimelineEvent {
  const template = TIMELINE_EVENT_TEMPLATES[eventType];
  
  return {
    id: generateEventId(),
    timestamp,
    blockNumber: options.blockNumber,
    eventType,
    severityAtTime: options.severity || template.severityDefault,
    title: options.title || template.titleTemplate,
    description,
    technicalDetails: options.technicalDetails,
    references: options.references || [],
    chain,
    relatedEventIds: options.relatedEventIds,
    isExpandable: options.isExpandable ?? (options.references?.length ?? 0) > 0,
    isPersistent: options.isPersistent ?? template.isPersistent,
    affectsCurrentStatus: options.affectsCurrentStatus ?? template.affectsStatus,
  };
}

// ============================================
// EVENT GENERATORS
// ============================================

/**
 * Generate COMPROMISE_ENTRY event from first malicious interaction
 */
function generateCompromiseEntryEvent(
  input: TimelineGenerationInput,
  maliciousTx: TimelineGenerationInput['transactions'][0]
): TimelineEvent {
  const contractLabel = maliciousTx.maliciousType || 'malicious contract';
  
  return createTimelineEvent(
    'COMPROMISE_ENTRY',
    maliciousTx.timestamp,
    input.chain,
    `Wallet interacted with a ${contractLabel}.`,
    {
      title: 'Wallet Compromised',
      severity: 'CRITICAL',
      blockNumber: maliciousTx.blockNumber,
      technicalDetails: `First malicious interaction detected. Contract: ${maliciousTx.to}`,
      references: [
        {
          type: 'transaction',
          value: maliciousTx.hash,
          label: 'Compromising Transaction',
          explorerUrl: getExplorerUrl(input.chain, 'tx', maliciousTx.hash),
        },
        {
          type: 'contract',
          value: maliciousTx.to,
          label: contractLabel,
          explorerUrl: getExplorerUrl(input.chain, 'address', maliciousTx.to),
        },
      ],
      isExpandable: true,
    }
  );
}

/**
 * Generate DRAIN_EVENT from sweep activity
 */
function generateDrainEvent(
  input: TimelineGenerationInput,
  sweepEvent: NonNullable<TimelineGenerationInput['drainerActivity']>['sweepEvents'][0]
): TimelineEvent {
  const timeSinceCompromise = input.drainerActivity?.firstDetected 
    ? getTimeDifference(input.drainerActivity.firstDetected, sweepEvent.timestamp)
    : null;
  
  const timeDescription = timeSinceCompromise 
    ? ` within ${timeSinceCompromise}`
    : '';
  
  return createTimelineEvent(
    'DRAIN_EVENT',
    sweepEvent.timestamp,
    input.chain,
    `Funds swept to known drainer address${timeDescription}.`,
    {
      title: 'Funds Drained',
      severity: 'CRITICAL',
      technicalDetails: `Amount: ${sweepEvent.amount}. Destination: ${sweepEvent.destination}`,
      references: [
        {
          type: 'transaction',
          value: sweepEvent.txHash,
          label: 'Drain Transaction',
          explorerUrl: getExplorerUrl(input.chain, 'tx', sweepEvent.txHash),
        },
        {
          type: 'address',
          value: sweepEvent.destination,
          label: 'Drainer Address',
          explorerUrl: getExplorerUrl(input.chain, 'address', sweepEvent.destination),
        },
      ],
      isExpandable: true,
    }
  );
}

/**
 * Generate APPROVAL_ABUSE event from malicious approval
 */
function generateApprovalAbuseEvent(
  input: TimelineGenerationInput,
  approval: TimelineGenerationInput['approvals'][0]
): TimelineEvent {
  const isUnlimited = approval.amount === 'unlimited' || 
    BigInt(approval.amount || '0') > BigInt('0xffffffffffffffff');
  
  return createTimelineEvent(
    'APPROVAL_ABUSE',
    approval.timestamp,
    input.chain,
    `Malicious ${isUnlimited ? 'unlimited ' : ''}approval granted to untrusted contract.`,
    {
      title: 'Malicious Approval Granted',
      severity: 'CRITICAL',
      technicalDetails: `Token: ${approval.token}. Spender: ${approval.spender}. Amount: ${isUnlimited ? 'Unlimited' : approval.amount}`,
      references: [
        {
          type: 'transaction',
          value: approval.txHash,
          label: 'Approval Transaction',
          explorerUrl: getExplorerUrl(input.chain, 'tx', approval.txHash),
        },
        {
          type: 'approval',
          value: approval.spender,
          label: 'Malicious Spender',
          explorerUrl: getExplorerUrl(input.chain, 'address', approval.spender),
        },
      ],
      isExpandable: true,
    }
  );
}

/**
 * Generate APPROVAL_REVOKED event
 */
function generateApprovalRevokedEvent(
  input: TimelineGenerationInput,
  approval: TimelineGenerationInput['approvals'][0]
): TimelineEvent | null {
  if (!approval.isRevoked || !approval.revokedAt) return null;
  
  return createTimelineEvent(
    'APPROVAL_REVOKED',
    approval.revokedAt,
    input.chain,
    'Malicious approval revoked.',
    {
      title: 'Approval Revoked',
      severity: 'MEDIUM',
      technicalDetails: `Revoked approval for spender: ${approval.spender}`,
      references: [
        {
          type: 'approval',
          value: approval.spender,
          label: 'Revoked Spender',
          explorerUrl: getExplorerUrl(input.chain, 'address', approval.spender),
        },
      ],
      isExpandable: true,
    }
  );
}

/**
 * Generate THREAT_CEASED event when attacker activity stops
 */
function generateThreatCeasedEvent(
  input: TimelineGenerationInput,
  lastActivityTimestamp: string
): TimelineEvent {
  const daysSince = getDaysSince(lastActivityTimestamp);
  const dateStr = formatDate(lastActivityTimestamp);
  
  return createTimelineEvent(
    'THREAT_CEASED',
    lastActivityTimestamp,
    input.chain,
    `No attacker activity observed after ${dateStr}.`,
    {
      title: 'Threat Activity Stopped',
      severity: 'HIGH',
      technicalDetails: `${daysSince} day(s) since last malicious activity.`,
      references: [],
      isExpandable: false,
    }
  );
}

/**
 * Generate REMEDIATION_ACTION event
 */
function generateRemediationEvent(
  chain: Chain,
  timestamp: string,
  action: string,
  details?: string
): TimelineEvent {
  return createTimelineEvent(
    'REMEDIATION_ACTION',
    timestamp,
    chain,
    action,
    {
      title: 'Recovery Action Taken',
      severity: 'MEDIUM',
      technicalDetails: details,
      isExpandable: !!details,
    }
  );
}

/**
 * Generate SAFE_STATE_CONFIRMED event
 */
function generateSafeStateEvent(
  chain: Chain,
  timestamp: string = new Date().toISOString()
): TimelineEvent {
  return createTimelineEvent(
    'SAFE_STATE_CONFIRMED',
    timestamp,
    chain,
    'No active threat detected. Wallet currently shows no compromise indicators.',
    {
      title: 'Wallet Safe',
      severity: 'SAFE',
      isExpandable: false,
      isPersistent: false,
    }
  );
}

/**
 * Generate RECOVERY_COMPLETE event
 */
function generateRecoveryCompleteEvent(
  chain: Chain,
  timestamp: string = new Date().toISOString()
): TimelineEvent {
  return createTimelineEvent(
    'RECOVERY_COMPLETE',
    timestamp,
    chain,
    'All malicious approvals revoked and no active threats remain. Recovery complete.',
    {
      title: 'Recovery Complete',
      severity: 'SAFE',
      isExpandable: false,
    }
  );
}

// ============================================
// MAIN TIMELINE GENERATOR
// ============================================

/**
 * Generate a complete wallet timeline from analysis data
 * 
 * RULES:
 * 1. Events are ordered chronologically (oldest first)
 * 2. Current status is derived from the LAST relevant event
 * 3. Historical compromise MUST NOT mark wallet as actively compromised
 * 4. Timeline persists even after status becomes SAFE
 */
export function generateWalletTimeline(input: TimelineGenerationInput): WalletTimeline {
  const events: TimelineEvent[] = [];
  
  // ============================================
  // STEP 1: IDENTIFY COMPROMISE ENTRY POINT
  // ============================================
  const maliciousTransactions = input.transactions
    .filter(tx => tx.isMalicious)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  const firstMaliciousTx = maliciousTransactions[0];
  let compromiseEntryEvent: TimelineEvent | null = null;
  
  if (firstMaliciousTx) {
    compromiseEntryEvent = generateCompromiseEntryEvent(input, firstMaliciousTx);
    events.push(compromiseEntryEvent);
  }
  
  // ============================================
  // STEP 2: ADD MALICIOUS APPROVAL EVENTS
  // ============================================
  const maliciousApprovals = input.approvals
    .filter(a => a.isMalicious)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  for (const approval of maliciousApprovals) {
    const approvalEvent = generateApprovalAbuseEvent(input, approval);
    
    // Link to compromise entry if close in time
    if (compromiseEntryEvent && isWithinMinutes(compromiseEntryEvent.timestamp, approval.timestamp, 60)) {
      approvalEvent.relatedEventIds = [compromiseEntryEvent.id];
    }
    
    events.push(approvalEvent);
    
    // Add revocation event if applicable
    const revocationEvent = generateApprovalRevokedEvent(input, approval);
    if (revocationEvent) {
      revocationEvent.relatedEventIds = [approvalEvent.id];
      events.push(revocationEvent);
    }
  }
  
  // ============================================
  // STEP 3: ADD DRAIN EVENTS
  // ============================================
  if (input.drainerActivity?.sweepEvents) {
    for (const sweep of input.drainerActivity.sweepEvents) {
      const drainEvent = generateDrainEvent(input, sweep);
      
      // Link to compromise entry
      if (compromiseEntryEvent) {
        drainEvent.relatedEventIds = [compromiseEntryEvent.id];
      }
      
      events.push(drainEvent);
    }
  }
  
  // ============================================
  // STEP 4: ADD THREAT CEASED EVENT
  // ============================================
  const hasHistoricalCompromise = events.some(e => 
    e.eventType === 'COMPROMISE_ENTRY' || 
    e.eventType === 'DRAIN_EVENT' || 
    e.eventType === 'APPROVAL_ABUSE'
  );
  
  const hasActiveThreats = input.currentAnalysis.hasActiveThreats;
  
  if (hasHistoricalCompromise && !hasActiveThreats) {
    // Find the last malicious activity timestamp
    const lastDrainerActivity = input.drainerActivity?.lastDetected;
    const lastMaliciousTxTime = maliciousTransactions.length > 0 
      ? maliciousTransactions[maliciousTransactions.length - 1].timestamp 
      : null;
    
    const lastActivityTime = [lastDrainerActivity, lastMaliciousTxTime]
      .filter(Boolean)
      .sort((a, b) => new Date(b!).getTime() - new Date(a!).getTime())[0];
    
    if (lastActivityTime) {
      events.push(generateThreatCeasedEvent(input, lastActivityTime));
    }
  }
  
  // ============================================
  // STEP 5: CHECK FOR REMEDIATION ACTIONS
  // ============================================
  const allMaliciousApprovalsRevoked = maliciousApprovals.length > 0 && 
    maliciousApprovals.every(a => a.isRevoked);
  
  if (allMaliciousApprovalsRevoked && maliciousApprovals.length > 0) {
    // Find the latest revocation timestamp
    const latestRevocation = maliciousApprovals
      .filter(a => a.revokedAt)
      .sort((a, b) => new Date(b.revokedAt!).getTime() - new Date(a.revokedAt!).getTime())[0];
    
    if (latestRevocation?.revokedAt) {
      events.push(generateRemediationEvent(
        input.chain,
        latestRevocation.revokedAt,
        'All malicious approvals revoked.',
        `${maliciousApprovals.length} malicious approval(s) were revoked.`
      ));
    }
  }
  
  // ============================================
  // STEP 6: ADD CURRENT STATUS EVENT
  // ============================================
  const now = new Date().toISOString();
  
  if (!hasActiveThreats) {
    if (hasHistoricalCompromise && allMaliciousApprovalsRevoked) {
      events.push(generateRecoveryCompleteEvent(input.chain, now));
    } else if (!hasHistoricalCompromise) {
      events.push(generateSafeStateEvent(input.chain, now));
    } else {
      // Historical compromise but not fully remediated - still show safe current state
      events.push(generateSafeStateEvent(input.chain, now));
    }
  }
  
  // ============================================
  // STEP 7: SORT AND FINALIZE
  // ============================================
  const sortedEvents = events.sort((a, b) => 
    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  
  // Determine current status from last relevant event
  const statusAffectingEvents = sortedEvents.filter(e => e.affectsCurrentStatus);
  const lastStatusEvent = statusAffectingEvents[statusAffectingEvents.length - 1];
  
  const currentStatus = deriveCurrentStatus(input.currentAnalysis.status, lastStatusEvent);
  
  return {
    walletAddress: input.walletAddress,
    chain: input.chain,
    events: sortedEvents,
    currentStatus: {
      status: currentStatus,
      derivedFromEventId: lastStatusEvent?.id || '',
      lastUpdated: now,
      summary: generateStatusSummary(currentStatus, hasHistoricalCompromise),
    },
    metadata: {
      firstEventTimestamp: sortedEvents[0]?.timestamp,
      lastEventTimestamp: sortedEvents[sortedEvents.length - 1]?.timestamp || now,
      totalEvents: sortedEvents.length,
      hasActiveThreats,
      hasHistoricalCompromise,
      isFullyRecovered: hasHistoricalCompromise && allMaliciousApprovalsRevoked && !hasActiveThreats,
    },
    generatedAt: now,
    analysisVersion: '2.0.0',
  };
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function getExplorerUrl(chain: Chain, type: 'tx' | 'address', value: string): string {
  const explorers: Record<Chain, string> = {
    ethereum: 'https://etherscan.io',
    base: 'https://basescan.org',
    bnb: 'https://bscscan.com',
    solana: 'https://solscan.io',
  };
  
  const base = explorers[chain] || explorers.ethereum;
  const path = type === 'tx' ? 'tx' : 'address';
  
  return `${base}/${path}/${value}`;
}

function getTimeDifference(start: string, end: string): string {
  const startTime = new Date(start).getTime();
  const endTime = new Date(end).getTime();
  const diffMs = endTime - startTime;
  
  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days} day${days > 1 ? 's' : ''}`;
  if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''}`;
  if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  return `${seconds} second${seconds !== 1 ? 's' : ''}`;
}

function getDaysSince(timestamp: string): number {
  const then = new Date(timestamp).getTime();
  const now = Date.now();
  return Math.floor((now - then) / (1000 * 60 * 60 * 24));
}

function formatDate(timestamp: string): string {
  return new Date(timestamp).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function isWithinMinutes(time1: string, time2: string, minutes: number): boolean {
  const t1 = new Date(time1).getTime();
  const t2 = new Date(time2).getTime();
  return Math.abs(t1 - t2) <= minutes * 60 * 1000;
}

function deriveCurrentStatus(
  analysisStatus: SecurityStatus,
  lastEvent: TimelineEvent | undefined
): SecurityStatus {
  // If analysis says safe and last event confirms, return safe
  if (analysisStatus === 'SAFE' && lastEvent?.eventType === 'SAFE_STATE_CONFIRMED') {
    return 'SAFE';
  }
  
  // If recovery is complete, return appropriate status
  if (lastEvent?.eventType === 'RECOVERY_COMPLETE') {
    return 'HISTORICALLY_COMPROMISED';
  }
  
  // Otherwise, trust the analysis status
  return analysisStatus;
}

function generateStatusSummary(status: SecurityStatus, hasHistory: boolean): string {
  switch (status) {
    case 'SAFE':
      return hasHistory 
        ? 'Wallet recovered. No active threats detected.'
        : 'No security issues detected. Wallet is safe.';
    
    case 'HISTORICALLY_COMPROMISED':
    case 'PREVIOUSLY_COMPROMISED':
    case 'PREVIOUSLY_COMPROMISED_NO_ACTIVITY':
      return 'Past compromise detected. No active attacker control. Safe to use with monitoring.';
    
    case 'RISK_EXPOSURE':
      return 'Risk exposure noted. No compromise confirmed.';
    
    case 'ACTIVELY_COMPROMISED':
    case 'ACTIVE_COMPROMISE_DRAINER':
      return 'Active threat detected. Immediate action required.';
    
    default:
      return 'Security status requires review.';
  }
}

// ============================================
// TIMELINE FORMATTING FOR UI
// ============================================

export interface FormattedTimelineEvent {
  id: string;
  date: string;
  time: string;
  title: string;
  description: string;
  severity: TimelineEventSeverity;
  emoji: string;
  colorClasses: {
    bg: string;
    border: string;
    text: string;
    icon: string;
  };
  isExpandable: boolean;
  technicalDetails?: string;
  references: TimelineEventReference[];
  isCurrent: boolean;
}

/**
 * Format timeline for UI display
 */
export function formatTimelineForUI(timeline: WalletTimeline): FormattedTimelineEvent[] {
  const { TIMELINE_SEVERITY_COLORS } = require('@/types');
  
  return timeline.events.map((event, index) => {
    const colors = TIMELINE_SEVERITY_COLORS[event.severityAtTime];
    const isLast = index === timeline.events.length - 1;
    const isCurrent = event.eventType === 'SAFE_STATE_CONFIRMED' || 
                      event.eventType === 'RECOVERY_COMPLETE' ||
                      (isLast && event.affectsCurrentStatus);
    
    return {
      id: event.id,
      date: formatDate(event.timestamp),
      time: new Date(event.timestamp).toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
      }),
      title: event.title,
      description: event.description,
      severity: event.severityAtTime,
      emoji: colors.emoji,
      colorClasses: {
        bg: colors.bg,
        border: colors.border,
        text: colors.text,
        icon: colors.icon,
      },
      isExpandable: event.isExpandable,
      technicalDetails: event.technicalDetails,
      references: event.references,
      isCurrent,
    };
  });
}

export default generateWalletTimeline;
