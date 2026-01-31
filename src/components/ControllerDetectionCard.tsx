'use client';

// ============================================
// CONTROLLER DETECTION CARD
// ============================================
// Displays the results of address poisoning controller analysis.
// Shows the attack flow: Poisoned → Controller → Exit
//
// UX REQUIREMENTS:
// - Clear, concise alerts
// - Show poisoned address and controller address
// - Include links/context if controller was involved in prior attacks
// - Non-alarmist messaging (no private key compromise)
// ============================================

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Eye,
  Shield,
  Repeat,
  Wallet,
  Activity,
  Clock,
  Target,
} from 'lucide-react';
import type { FlowTrace, ControllerCandidate, WalletRole } from '@/lib/detection/controller-detection';

interface ControllerDetectionCardProps {
  flowTrace: FlowTrace;
  chain?: string;
  explorerUrl?: string;
}

// Role display configuration
const ROLE_DISPLAY: Record<WalletRole, {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
  icon: React.ReactNode;
}> = {
  POISONED_ADDRESS: {
    label: 'Poisoned Address (Decoy)',
    color: 'text-amber-400',
    bgColor: 'bg-amber-500/10',
    borderColor: 'border-amber-500/30',
    icon: <Target className="w-4 h-4" />,
  },
  CONTROLLER_WALLET: {
    label: 'Controller Wallet',
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    icon: <Activity className="w-4 h-4" />,
  },
  EXIT_WALLET: {
    label: 'Exit / Laundering Wallet',
    color: 'text-purple-400',
    bgColor: 'bg-purple-500/10',
    borderColor: 'border-purple-500/30',
    icon: <ArrowRight className="w-4 h-4" />,
  },
  INTERMEDIATE: {
    label: 'Intermediate Hop',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    icon: <Repeat className="w-4 h-4" />,
  },
  UNKNOWN: {
    label: 'Unknown Role',
    color: 'text-gray-400',
    bgColor: 'bg-gray-500/10',
    borderColor: 'border-gray-500/30',
    icon: <Wallet className="w-4 h-4" />,
  },
};

export function ControllerDetectionCard({
  flowTrace,
  chain = 'ethereum',
  explorerUrl = 'https://etherscan.io',
}: ControllerDetectionCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const hasController = flowTrace.primaryController !== undefined;
  const hasExits = flowTrace.exitWallets.length > 0;
  const priorIncidents = flowTrace.primaryController?.fingerprint?.incidentCount;

  // Format address for display
  const formatAddress = (addr: string) => {
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
  };

  // Format ETH amount
  const formatAmount = (weiStr: string) => {
    try {
      const wei = BigInt(weiStr);
      const eth = Number(wei) / 1e18;
      return eth.toFixed(4);
    } catch {
      return '0';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card rounded-xl overflow-hidden border-l-4 border-l-amber-500"
    >
      {/* Header - Always visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-start gap-4 text-left hover:bg-sentinel-elevated/30 transition-colors"
      >
        {/* Icon */}
        <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 flex-shrink-0">
          <AlertTriangle className="w-5 h-5" />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <h3 className="font-display font-semibold text-amber-400">
            ⚠️ Address Poisoning Attack
          </h3>
          
          <p className="text-sm text-sentinel-muted mt-1">
            Funds were sent to a look-alike address that forwarded them to an attacker-controlled wallet.
          </p>

          {/* Quick summary */}
          <div className="mt-3 space-y-2">
            {/* Poisoned address */}
            <div className="flex items-center gap-2 text-sm">
              <span className="text-amber-400">Poisoned address:</span>
              <code className="px-2 py-0.5 bg-sentinel-surface rounded text-amber-300 font-mono text-xs">
                {formatAddress(flowTrace.poisonedAddress)}
              </code>
            </div>

            {/* Controller address */}
            {hasController && (
              <div className="flex items-center gap-2 text-sm">
                <span className="text-red-400">Attacker controller:</span>
                <code className="px-2 py-0.5 bg-sentinel-surface rounded text-red-300 font-mono text-xs">
                  {formatAddress(flowTrace.primaryController!.address)}
                </code>
                {priorIncidents && (
                  <span className="px-1.5 py-0.5 text-[10px] rounded bg-red-500/20 text-red-400">
                    {priorIncidents} prior attacks
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Key points - always visible */}
          <ul className="mt-3 space-y-1 text-xs text-sentinel-muted">
            <li className="flex items-center gap-2">
              <Shield className="w-3 h-3 text-green-400" />
              No signer or private key compromise detected
            </li>
            <li className="flex items-center gap-2">
              <Eye className="w-3 h-3 text-amber-400" />
              Funds were mistakenly sent to a look-alike address
            </li>
            {hasController && (
              <li className="flex items-center gap-2">
                <ArrowRight className="w-3 h-3 text-red-400" />
                Poisoned address forwarded funds to controller wallet
              </li>
            )}
          </ul>
        </div>

        {/* Expand indicator */}
        <div className="flex-shrink-0 text-sentinel-muted">
          {isExpanded ? (
            <ChevronUp className="w-5 h-5" />
          ) : (
            <ChevronDown className="w-5 h-5" />
          )}
        </div>
      </button>

      {/* Expanded Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-4">
              {/* Attack Flow Visualization */}
              <div className="p-4 bg-sentinel-surface rounded-lg">
                <h4 className="text-sm font-medium text-sentinel-muted mb-3 flex items-center gap-2">
                  <Activity className="w-4 h-4" />
                  Attack Flow
                </h4>
                
                <div className="flex items-center gap-2 flex-wrap">
                  {/* Victim */}
                  <AddressBox
                    label="Victim"
                    address={flowTrace.victimAddress}
                    amount={formatAmount(flowTrace.victimLossAmount)}
                    explorerUrl={explorerUrl}
                    color="blue"
                  />
                  
                  <ArrowRight className="w-4 h-4 text-sentinel-muted" />
                  
                  {/* Poisoned */}
                  <AddressBox
                    label="Poisoned"
                    address={flowTrace.poisonedAddress}
                    explorerUrl={explorerUrl}
                    color="amber"
                  />
                  
                  {hasController && (
                    <>
                      <ArrowRight className="w-4 h-4 text-sentinel-muted" />
                      
                      {/* Controller */}
                      <AddressBox
                        label="Controller"
                        address={flowTrace.primaryController!.address}
                        explorerUrl={explorerUrl}
                        color="red"
                        badge={priorIncidents ? `${priorIncidents} prior` : undefined}
                      />
                    </>
                  )}
                  
                  {hasExits && (
                    <>
                      <ArrowRight className="w-4 h-4 text-sentinel-muted" />
                      
                      {/* Exit */}
                      <AddressBox
                        label="Exit"
                        address={flowTrace.exitWallets[0].address}
                        explorerUrl={explorerUrl}
                        color="purple"
                        badge={getExitType(flowTrace.exitWallets[0])}
                      />
                    </>
                  )}
                </div>
              </div>

              {/* Flow Hops Detail */}
              {flowTrace.hops.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-sentinel-muted mb-3 flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    Fund Flow Trace ({flowTrace.hops.length} hop{flowTrace.hops.length !== 1 ? 's' : ''})
                  </h4>
                  
                  <div className="space-y-2">
                    {flowTrace.hops.map((hop, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-sentinel-surface rounded-lg text-xs"
                      >
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="px-1.5 py-0.5 bg-sentinel-elevated rounded text-sentinel-muted">
                            Hop {hop.hopNumber}
                          </span>
                          <code className="text-sentinel-text font-mono">
                            {formatAddress(hop.from)}
                          </code>
                          <ArrowRight className="w-3 h-3 text-sentinel-muted" />
                          <code className="text-sentinel-text font-mono">
                            {formatAddress(hop.to)}
                          </code>
                          <span className="text-sentinel-muted">
                            {formatAmount(hop.amount)} ETH
                          </span>
                          {hop.timeDelta < 60 && (
                            <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded">
                              ⚡ {hop.timeDelta}s
                            </span>
                          )}
                        </div>
                        <a
                          href={`${explorerUrl}/tx/${hop.txHash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 mt-1"
                        >
                          <ExternalLink className="w-3 h-3" />
                          View transaction
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Controller Candidates */}
              {flowTrace.controllerCandidates.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-sentinel-muted mb-3 flex items-center gap-2">
                    <Target className="w-4 h-4" />
                    Detected Wallets
                  </h4>
                  
                  <div className="space-y-2">
                    {flowTrace.controllerCandidates.map((candidate, idx) => (
                      <CandidateCard
                        key={idx}
                        candidate={candidate}
                        explorerUrl={explorerUrl}
                      />
                    ))}
                  </div>
                </div>
              )}

              {/* Disclaimer */}
              <div className="flex items-start gap-2 p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
                <Shield className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <p className="text-xs text-green-400">
                  <strong>No wallet compromise:</strong> This was a social engineering attack. 
                  Your private keys and seed phrase are safe. No approvals were abused.
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ============================================
// HELPER COMPONENTS
// ============================================

function AddressBox({
  label,
  address,
  amount,
  explorerUrl,
  color,
  badge,
}: {
  label: string;
  address: string;
  amount?: string;
  explorerUrl: string;
  color: 'blue' | 'amber' | 'red' | 'purple' | 'green';
  badge?: string;
}) {
  const colorClasses = {
    blue: 'border-blue-500/30 bg-blue-500/10 text-blue-400',
    amber: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
    red: 'border-red-500/30 bg-red-500/10 text-red-400',
    purple: 'border-purple-500/30 bg-purple-500/10 text-purple-400',
    green: 'border-green-500/30 bg-green-500/10 text-green-400',
  };

  return (
    <a
      href={`${explorerUrl}/address/${address}`}
      target="_blank"
      rel="noopener noreferrer"
      className={`p-2 rounded-lg border ${colorClasses[color]} hover:opacity-80 transition-opacity`}
    >
      <div className="text-[10px] uppercase tracking-wide opacity-70">{label}</div>
      <div className="font-mono text-xs mt-0.5">
        {address.slice(0, 6)}...{address.slice(-4)}
      </div>
      {amount && (
        <div className="text-[10px] mt-0.5 opacity-70">{amount} ETH</div>
      )}
      {badge && (
        <div className="mt-1">
          <span className="px-1 py-0.5 text-[9px] rounded bg-black/20">
            {badge}
          </span>
        </div>
      )}
    </a>
  );
}

function CandidateCard({
  candidate,
  explorerUrl,
}: {
  candidate: ControllerCandidate;
  explorerUrl: string;
}) {
  const roleDisplay = ROLE_DISPLAY[candidate.role];

  return (
    <div className={`p-3 rounded-lg border ${roleDisplay.borderColor} ${roleDisplay.bgColor}`}>
      <div className="flex items-center gap-2 flex-wrap">
        <span className={roleDisplay.color}>
          {roleDisplay.icon}
        </span>
        <span className={`text-sm font-medium ${roleDisplay.color}`}>
          {roleDisplay.label}
        </span>
        <span className="px-1.5 py-0.5 text-[10px] rounded bg-black/20 text-sentinel-text">
          Score: {candidate.score}
        </span>
        {candidate.fingerprint && (
          <span className="px-1.5 py-0.5 text-[10px] rounded bg-red-500/30 text-red-300">
            Known attacker
          </span>
        )}
      </div>
      
      <div className="mt-2 flex items-center gap-2">
        <code className="text-xs font-mono text-sentinel-text">
          {candidate.address}
        </code>
        <a
          href={`${explorerUrl}/address/${candidate.address}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-blue-400 hover:text-blue-300"
        >
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>

      {/* Signals */}
      {candidate.signals.length > 0 && (
        <div className="mt-2 space-y-1">
          {candidate.signals.slice(0, 3).map((signal, idx) => (
            <div key={idx} className="text-[10px] text-sentinel-muted flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full ${
                signal.weight === 'VERY_HIGH' ? 'bg-red-500' :
                signal.weight === 'HIGH' ? 'bg-orange-500' :
                signal.weight === 'MEDIUM' ? 'bg-amber-500' :
                'bg-blue-500'
              }`} />
              {signal.description}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function getExitType(exit: ControllerCandidate): string | undefined {
  for (const signal of exit.signals) {
    if (signal.type === 'BRIDGE_USAGE') return 'Bridge';
    if (signal.type === 'MIXER_USAGE') return 'Mixer';
    if (signal.type === 'CEX_DEPOSIT') return 'Exchange';
  }
  return undefined;
}

// ============================================
// EXPORTS
// ============================================

export default ControllerDetectionCard;
