'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  AlertCircle,
  ChevronDown,
  ExternalLink,
  Copy,
  Shield,
  Zap,
  Lock,
  FileWarning,
  Inbox,
  Code,
  Layers,
} from 'lucide-react';
import { DetectedThreat, AttackType, RiskLevel, Chain } from '@/types';

interface ThreatCardProps {
  threat: DetectedThreat;
  chain: Chain;
}

const attackTypeInfo: Record<AttackType, { icon: React.ElementType; color: string; label: string }> = {
  WALLET_DRAINER: { icon: Zap, color: 'text-red-400', label: 'Wallet Drainer' },
  APPROVAL_HIJACK: { icon: Lock, color: 'text-orange-400', label: 'Approval Hijack' },
  PRIVATE_KEY_LEAK: { icon: AlertCircle, color: 'text-red-500', label: 'Private Key Leak' },
  PHISHING_SIGNATURE: { icon: FileWarning, color: 'text-yellow-400', label: 'Phishing Signature' },
  MALICIOUS_NFT_AIRDROP: { icon: Inbox, color: 'text-purple-400', label: 'Malicious Airdrop' },
  COMPROMISED_PROGRAM_AUTHORITY: { icon: Code, color: 'text-cyan-400', label: 'Compromised Program' },
  ROGUE_CONTRACT_INTERACTION: { icon: Layers, color: 'text-pink-400', label: 'Rogue Contract' },
  MEV_SANDWICH_DRAIN: { icon: Layers, color: 'text-amber-400', label: 'MEV Sandwich' },
  UNKNOWN: { icon: Shield, color: 'text-gray-400', label: 'Unknown Threat' },
};

export function ThreatCard({ threat, chain }: ThreatCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);

  const typeInfo = attackTypeInfo[threat.type] || attackTypeInfo.UNKNOWN;
  const Icon = typeInfo.icon;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedAddress(text);
    setTimeout(() => setCopiedAddress(null), 2000);
  };

  const getExplorerUrl = (address: string) => {
    const explorers: Record<string, string> = {
      ethereum: 'https://etherscan.io/address/',
      base: 'https://basescan.org/address/',
      bnb: 'https://bscscan.com/address/',
      solana: 'https://solscan.io/account/',
    };
    return `${explorers[chain] || explorers.ethereum}${address}`;
  };

  const getTxExplorerUrl = (hash: string) => {
    const explorers: Record<string, string> = {
      ethereum: 'https://etherscan.io/tx/',
      base: 'https://basescan.org/tx/',
      bnb: 'https://bscscan.com/tx/',
      solana: 'https://solscan.io/tx/',
    };
    return `${explorers[chain] || explorers.ethereum}${hash}`;
  };

  return (
    <motion.div
      layout
      className={`glass-card rounded-xl overflow-hidden ${
        threat.severity === 'CRITICAL' ? 'border-l-4 border-l-status-danger' : ''
      }`}
    >
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-start gap-4 text-left hover:bg-sentinel-surface/50 transition-colors"
      >
        {/* Icon */}
        <div className={`p-2 rounded-lg bg-sentinel-surface ${typeInfo.color}`}>
          <Icon className="w-5 h-5" />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="font-display font-semibold text-sentinel-text">{threat.title}</h3>
            {threat.ongoingRisk && (
              <span className="px-2 py-0.5 text-xs bg-status-danger-bg text-status-danger rounded-full animate-pulse">
                Active Risk
              </span>
            )}
          </div>
          <p className="text-sm text-sentinel-muted line-clamp-2">{threat.description}</p>
          <div className="flex items-center gap-4 mt-2">
            <SeverityBadge severity={threat.severity} />
            <span className="text-xs text-sentinel-muted">{typeInfo.label}</span>
            <span className="text-xs text-sentinel-muted">
              Detected {new Date(threat.detectedAt).toLocaleDateString()}
            </span>
          </div>
        </div>

        {/* Expand/Collapse */}
        <ChevronDown
          className={`w-5 h-5 text-sentinel-muted transition-transform ${
            isExpanded ? 'rotate-180' : ''
          }`}
        />
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
            <div className="p-4 pt-0 space-y-4">
              {/* Technical Details */}
              <div className="terminal">
                <div className="terminal-header">
                  <div className="terminal-dot bg-red-500" />
                  <div className="terminal-dot bg-yellow-500" />
                  <div className="terminal-dot bg-green-500" />
                  <span className="text-xs text-sentinel-muted ml-2">Technical Details</span>
                </div>
                <div className="terminal-content text-xs">
                  <pre className="whitespace-pre-wrap break-all text-sentinel-muted">
                    {threat.technicalDetails}
                  </pre>
                </div>
              </div>

              {/* Related Addresses */}
              {threat.relatedAddresses.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2 text-sentinel-muted">Related Addresses</h4>
                  <div className="space-y-2">
                    {threat.relatedAddresses.map((address) => (
                      <div
                        key={address}
                        className="flex items-center gap-2 p-2 bg-sentinel-surface rounded-lg"
                      >
                        <span className="font-mono text-xs text-sentinel-text truncate flex-1">
                          {address}
                        </span>
                        <button
                          onClick={() => copyToClipboard(address)}
                          className="p-1 hover:bg-sentinel-elevated rounded transition-colors"
                          title="Copy address"
                        >
                          <Copy className={`w-4 h-4 ${copiedAddress === address ? 'text-status-safe' : 'text-sentinel-muted'}`} />
                        </button>
                        <a
                          href={getExplorerUrl(address)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1 hover:bg-sentinel-elevated rounded transition-colors"
                          title="View on explorer"
                        >
                          <ExternalLink className="w-4 h-4 text-sentinel-muted" />
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Related Transactions */}
              {threat.relatedTransactions.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2 text-sentinel-muted">Related Transactions</h4>
                  <div className="space-y-2">
                    {threat.relatedTransactions.slice(0, 5).map((hash) => (
                      <a
                        key={hash}
                        href={getTxExplorerUrl(hash)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 p-2 bg-sentinel-surface rounded-lg hover:bg-sentinel-elevated transition-colors"
                      >
                        <span className="font-mono text-xs text-blue-400 truncate flex-1">
                          {hash}
                        </span>
                        <ExternalLink className="w-4 h-4 text-sentinel-muted" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Recoverable Assets */}
              {threat.recoverableAssets && threat.recoverableAssets.length > 0 && (
                <div className="p-4 bg-status-safe-bg border border-status-safe/30 rounded-lg">
                  <h4 className="text-sm font-medium mb-2 text-status-safe flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Recoverable Assets
                  </h4>
                  <div className="space-y-2">
                    {threat.recoverableAssets.map((asset, index) => (
                      <div key={index} className="flex items-center justify-between text-sm">
                        <span>{asset.token.symbol}</span>
                        <span className="text-sentinel-muted">{asset.balance}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function SeverityBadge({ severity }: { severity: RiskLevel }) {
  const config = {
    CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Critical' },
    HIGH: { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'High' },
    MEDIUM: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Medium' },
    LOW: { bg: 'bg-blue-500/20', text: 'text-blue-400', label: 'Low' },
  };

  const { bg, text, label } = config[severity];

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${bg} ${text}`}>
      {label}
    </span>
  );
}

