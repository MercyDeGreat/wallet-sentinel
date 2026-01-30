'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  ChevronDown,
  ExternalLink,
  Copy,
  Fingerprint,
  Activity,
  Users,
  Clock,
  Shield,
  Zap,
  Globe,
  TrendingUp,
  Info,
} from 'lucide-react';
import { Chain } from '@/types';
import { DrainerAttribution } from '@/lib/drainer-dna/types';

interface DrainerDNACardProps {
  attribution: DrainerAttribution;
  chain: Chain;
}

export function DrainerDNACard({ attribution, chain }: DrainerDNACardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);
  
  const { 
    family, 
    variant, 
    confidence, 
    wallets_affected, 
    chains,
    active_since,
    is_active,
    total_stolen_usd,
  } = attribution.attribution;
  
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
  
  // Determine confidence badge styling
  const getConfidenceBadgeClass = () => {
    if (confidence >= 85) return 'bg-red-500/20 text-red-400 border-red-500/30';
    if (confidence >= 70) return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  };
  
  // Determine risk level badge
  const getRiskBadgeClass = () => {
    switch (attribution.risk_level) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400';
      case 'HIGH': return 'bg-orange-500/20 text-orange-400';
      case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400';
      default: return 'bg-blue-500/20 text-blue-400';
    }
  };
  
  // Format stolen amount
  const formatAmount = (amount: number): string => {
    if (amount >= 1000000000) return `$${(amount / 1000000000).toFixed(1)}B`;
    if (amount >= 1000000) return `$${(amount / 1000000).toFixed(1)}M`;
    if (amount >= 1000) return `$${(amount / 1000).toFixed(1)}K`;
    return `$${amount.toFixed(0)}`;
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="relative overflow-hidden rounded-xl bg-gradient-to-br from-red-950/40 via-sentinel-bg to-sentinel-surface border border-red-500/30"
    >
      {/* DNA Helix Background Pattern */}
      <div className="absolute inset-0 opacity-5 pointer-events-none">
        <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          <pattern id="dna-pattern" width="20" height="20" patternUnits="userSpaceOnUse">
            <path d="M 0 10 Q 5 0, 10 10 T 20 10" fill="none" stroke="currentColor" strokeWidth="0.5" />
            <path d="M 0 10 Q 5 20, 10 10 T 20 10" fill="none" stroke="currentColor" strokeWidth="0.5" />
          </pattern>
          <rect width="100%" height="100%" fill="url(#dna-pattern)" className="text-red-400" />
        </svg>
      </div>

      {/* Header Section */}
      <div className="relative p-5 border-b border-red-500/20">
        <div className="flex items-start gap-4">
          {/* DNA Icon */}
          <div className="p-3 rounded-xl bg-red-500/20 border border-red-500/30">
            <Fingerprint className="w-6 h-6 text-red-400" />
          </div>

          {/* Title & Status */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="px-2 py-0.5 text-xs font-medium bg-red-500/20 text-red-400 rounded-full border border-red-500/30 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                DRAINER DNA MATCH
              </span>
              {is_active && (
                <span className="px-2 py-0.5 text-xs bg-red-500/30 text-red-300 rounded-full animate-pulse">
                  Active Threat
                </span>
              )}
            </div>
            
            <h3 className="text-xl font-display font-bold text-sentinel-text mb-1">
              Matches {family} – {variant}
            </h3>
            
            <p className="text-sm text-sentinel-muted">
              Seen in <span className="text-red-400 font-semibold">{wallets_affected.toLocaleString()}</span> wallets
              {' • '}
              Active on {chains.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(', ')} since {active_since}
            </p>
          </div>

          {/* Confidence Badge */}
          <div className="text-right">
            <div className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border ${getConfidenceBadgeClass()}`}>
              <TrendingUp className="w-4 h-4" />
              <span className="font-semibold">{confidence}%</span>
            </div>
            <p className="text-xs text-sentinel-muted mt-1">Confidence</p>
          </div>
        </div>

        {/* Quick Stats Row */}
        <div className="flex items-center gap-6 mt-4 pt-4 border-t border-red-500/10">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-sentinel-muted" />
            <span className="text-sm">
              <span className="text-sentinel-text font-medium">{wallets_affected.toLocaleString()}</span>
              <span className="text-sentinel-muted"> victims</span>
            </span>
          </div>
          
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-sentinel-muted" />
            <span className="text-sm">
              <span className="text-sentinel-text font-medium">{chains.length}</span>
              <span className="text-sentinel-muted"> chains</span>
            </span>
          </div>
          
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-sentinel-muted" />
            <span className="text-sm text-sentinel-muted">
              Since {active_since}
            </span>
          </div>
          
          {total_stolen_usd > 0 && (
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-red-400" />
              <span className="text-sm">
                <span className="text-red-400 font-medium">{formatAmount(total_stolen_usd)}</span>
                <span className="text-sentinel-muted"> stolen</span>
              </span>
            </div>
          )}
          
          <div className="ml-auto">
            <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskBadgeClass()}`}>
              {attribution.risk_level} Risk
            </span>
          </div>
        </div>
      </div>

      {/* Why This Match Section */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-center justify-between text-left hover:bg-red-500/5 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-sentinel-muted" />
          <span className="text-sm font-medium text-sentinel-text">Why this match?</span>
          <span className="text-xs text-sentinel-muted">
            ({attribution.why_this_match.length} matching signals)
          </span>
        </div>
        <ChevronDown
          className={`w-5 h-5 text-sentinel-muted transition-transform ${isExpanded ? 'rotate-180' : ''}`}
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
            <div className="px-5 pb-5 space-y-5">
              {/* Match Reasons */}
              <div className="space-y-2">
                {attribution.why_this_match.map((reason, index) => (
                  <div
                    key={index}
                    className="flex items-start gap-3 p-3 bg-sentinel-surface/50 rounded-lg border border-sentinel-border/50"
                  >
                    <div className="p-1 rounded bg-red-500/20">
                      <Activity className="w-3 h-3 text-red-400" />
                    </div>
                    <span className="text-sm text-sentinel-text">{reason}</span>
                  </div>
                ))}
              </div>

              {/* Signature Summary */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium text-sentinel-muted flex items-center gap-2">
                  <Fingerprint className="w-4 h-4" />
                  Behavioral Signature
                </h4>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3 bg-sentinel-surface rounded-lg border border-sentinel-border/50">
                    <p className="text-xs text-sentinel-muted mb-1">Approval Pattern</p>
                    <p className="text-sm text-sentinel-text">{attribution.signature_summary.approval_pattern}</p>
                  </div>
                  
                  <div className="p-3 bg-sentinel-surface rounded-lg border border-sentinel-border/50">
                    <p className="text-xs text-sentinel-muted mb-1">Timing Pattern</p>
                    <p className="text-sm text-sentinel-text">{attribution.signature_summary.timing_pattern}</p>
                  </div>
                  
                  <div className="p-3 bg-sentinel-surface rounded-lg border border-sentinel-border/50">
                    <p className="text-xs text-sentinel-muted mb-1">Routing Pattern</p>
                    <p className="text-sm text-sentinel-text">{attribution.signature_summary.routing_pattern}</p>
                  </div>
                </div>

                {/* Distinctive Features */}
                {attribution.signature_summary.distinctive_features.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {attribution.signature_summary.distinctive_features.map((feature, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 text-xs bg-red-500/10 text-red-400 rounded border border-red-500/20"
                      >
                        {feature}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Related Addresses */}
              {attribution.related_addresses.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-sentinel-muted">Known Associated Addresses</h4>
                  <div className="space-y-2">
                    {attribution.related_addresses.slice(0, 3).map((address) => (
                      <div
                        key={address}
                        className="flex items-center gap-2 p-2 bg-sentinel-surface rounded-lg border border-sentinel-border/50"
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

              {/* Known Aliases */}
              {attribution.known_aliases.length > 0 && (
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-sentinel-muted">Also known as:</span>
                  <span className="text-sentinel-text">
                    {attribution.known_aliases.join(', ')}
                  </span>
                </div>
              )}

              {/* Warning Box */}
              <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                <div className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-red-400 mb-1">
                      ⚠️ This address matches the behavioral signature of {family}
                    </p>
                    <p className="text-xs text-sentinel-muted">
                      {family} is a known drainer family that has affected {wallets_affected.toLocaleString()} wallets.
                      Do not interact with this address or approve any transactions.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ============================================
// COMPACT DRAINER DNA BADGE
// ============================================
// Smaller inline badge for use in lists/tables

interface DrainerDNABadgeProps {
  attribution: DrainerAttribution;
  compact?: boolean;
}

export function DrainerDNABadge({ attribution, compact = false }: DrainerDNABadgeProps) {
  const { family, variant, confidence, wallets_affected } = attribution.attribution;
  
  if (compact) {
    return (
      <div className="inline-flex items-center gap-2 px-2 py-1 bg-red-500/20 rounded-lg border border-red-500/30">
        <Fingerprint className="w-3 h-3 text-red-400" />
        <span className="text-xs text-red-400 font-medium">{family}</span>
        <span className="text-xs text-red-300">{confidence}%</span>
      </div>
    );
  }
  
  return (
    <div className="flex items-center gap-3 p-3 bg-red-500/10 rounded-lg border border-red-500/30">
      <div className="p-2 bg-red-500/20 rounded-lg">
        <Fingerprint className="w-4 h-4 text-red-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-red-400">
          Matches {family} – {variant}
        </p>
        <p className="text-xs text-sentinel-muted">
          {wallets_affected.toLocaleString()} affected wallets • {confidence}% confidence
        </p>
      </div>
    </div>
  );
}
