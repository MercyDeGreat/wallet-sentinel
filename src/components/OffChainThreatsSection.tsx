'use client';

// ============================================
// OFF-CHAIN THREATS SECTION
// ============================================
// Enhanced UI component for displaying off-chain intelligence
// from Etherscan, HashDit, and other providers.
//
// FEATURES:
// - Collapsible section with expand/collapse toggle
// - Clear separation from on-chain events
// - Source attribution (e.g., "HashDit via Etherscan")
// - Report type indicators (phishing, scam, etc.)
// - Date reported
// - Confidence/report count
// - Highlight for new/recent reports
//
// OUTPUT FORMAT EXAMPLE:
// Off-Chain Threats:
// - ⚠️ Phishing Scam Report (HashDit via Etherscan) – Reported: 2026-01-25
// - ⚠️ Suspicious contract label (Etherscan community tag) – Reported: 2026-01-20
// ============================================

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Shield,
  Clock,
  RefreshCw,
  Globe,
  Eye,
  EyeOff,
  Sparkles,
  Info,
} from 'lucide-react';
import type {
  OTTIAssessment,
  OffChainThreatSignal,
  OffChainExposureScore,
} from '@/lib/otti/types';
import {
  getReportTypeLabel,
  getConfidenceLevelDisplay,
  getExposureLevelDisplay,
} from '@/lib/otti/types';

interface OffChainThreatsSectionProps {
  assessment: OTTIAssessment | null;
  onRefresh?: () => Promise<void>;
  isRefreshing?: boolean;
  defaultExpanded?: boolean;
}

/**
 * OffChainThreatsSection - Dedicated section for off-chain threat intelligence
 * 
 * DESIGN PRINCIPLES:
 * - Clear visual separation from on-chain analysis
 * - Non-alarmist but informative messaging
 * - Expandable detail view
 * - Source attribution for every signal
 */
export function OffChainThreatsSection({
  assessment,
  onRefresh,
  isRefreshing = false,
  defaultExpanded = false,
}: OffChainThreatsSectionProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  // No assessment or no signals
  if (!assessment || assessment.signals.length === 0) {
    return (
      <div className="glass-card rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-green-500/10 text-green-400">
            <Shield className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <h3 className="font-display font-semibold text-sentinel-text">
              Off-Chain Threats
            </h3>
            <p className="text-sm text-green-400">
              No off-chain threat reports detected
            </p>
          </div>
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="p-2 rounded-lg hover:bg-sentinel-surface transition-colors disabled:opacity-50"
              title="Refresh off-chain intelligence"
            >
              <RefreshCw className={`w-4 h-4 text-sentinel-muted ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>
    );
  }

  const { summary, signals, exposure_score } = assessment;
  const exposureDisplay = getExposureLevelDisplay(exposure_score.level);
  
  // Check for recent reports (within last 7 days)
  const recentSignals = signals.filter(s => {
    const lastSeen = s.last_seen_timestamp || s.first_seen_timestamp;
    const daysSince = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60 * 24);
    return daysSince <= 7;
  });
  const hasRecentReports = recentSignals.length > 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card rounded-xl overflow-hidden border-l-4 border-l-amber-500"
    >
      {/* Section Header - Always visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-start gap-4 text-left hover:bg-sentinel-elevated/30 transition-colors"
      >
        {/* Warning Icon */}
        <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 flex-shrink-0">
          <AlertTriangle className="w-5 h-5" />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-display font-semibold text-amber-400">
              Off-Chain Threats
            </h3>
            {hasRecentReports && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] rounded-full bg-red-500/20 text-red-400">
                <Sparkles className="w-3 h-3" />
                New reports
              </span>
            )}
          </div>
          
          <p className="text-sm text-sentinel-muted mt-1">
            {summary.signal_count} report{summary.signal_count !== 1 ? 's' : ''} from {summary.source_count} source{summary.source_count !== 1 ? 's' : ''}
          </p>

          {/* Quick preview of threats */}
          {!isExpanded && (
            <div className="mt-2 space-y-1">
              {signals.slice(0, 2).map((signal, idx) => (
                <ThreatPreviewLine key={idx} signal={signal} />
              ))}
              {signals.length > 2 && (
                <p className="text-xs text-sentinel-muted">
                  +{signals.length - 2} more report{signals.length - 2 !== 1 ? 's' : ''}...
                </p>
              )}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Exposure badge */}
          <div className={`px-2 py-1 rounded text-xs ${exposureDisplay.bgColor} ${exposureDisplay.color}`}>
            {exposureDisplay.label}
          </div>
          
          {/* Expand indicator */}
          {isExpanded ? (
            <ChevronUp className="w-5 h-5 text-sentinel-muted" />
          ) : (
            <ChevronDown className="w-5 h-5 text-sentinel-muted" />
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
              {/* On-chain safety reminder */}
              <div className="flex items-center gap-2 p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
                <Shield className="w-4 h-4 text-green-400" />
                <span className="text-sm text-green-400">
                  {summary.status_line}
                </span>
              </div>

              {/* Refresh button */}
              {onRefresh && (
                <div className="flex justify-end">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onRefresh();
                    }}
                    disabled={isRefreshing}
                    className="inline-flex items-center gap-2 px-3 py-1.5 text-xs bg-sentinel-surface rounded-lg hover:bg-sentinel-elevated transition-colors disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
                    Refresh intelligence
                  </button>
                </div>
              )}

              {/* Exposure Score */}
              <ExposureScoreCard score={exposure_score} />

              {/* User Guidance */}
              <div className="flex items-start gap-3 p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                <Info className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <p className="text-sm text-sentinel-muted">
                  {summary.guidance}
                </p>
              </div>

              {/* Threat List - Detailed */}
              <div>
                <h4 className="text-sm font-medium text-sentinel-muted mb-3 flex items-center gap-2">
                  <Eye className="w-4 h-4" />
                  Off-Chain Threat Reports
                </h4>
                <div className="space-y-2">
                  {signals.map((signal) => (
                    <ThreatDetailCard key={signal.id} signal={signal} />
                  ))}
                </div>
              </div>

              {/* Disclaimer */}
              <div className="flex items-start gap-2 p-3 bg-sentinel-surface rounded-lg">
                <EyeOff className="w-4 h-4 text-sentinel-muted mt-0.5 flex-shrink-0" />
                <p className="text-xs text-sentinel-muted">
                  <strong>Note:</strong> Off-chain reports do not affect on-chain security assessment. 
                  These signals come from external threat intelligence sources (Etherscan, HashDit, community reports) 
                  and may not reflect actual on-chain behavior. Last updated: {new Date(assessment.assessed_at).toLocaleString()}
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/**
 * Preview line for collapsed view
 */
function ThreatPreviewLine({ signal }: { signal: OffChainThreatSignal }) {
  const reportTypeLabel = getReportTypeLabel(signal.report_type);
  const reportDate = new Date(signal.first_seen_timestamp).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
  
  return (
    <div className="flex items-center gap-2 text-xs text-sentinel-muted">
      <span className="text-amber-400">⚠️</span>
      <span className="truncate">
        {reportTypeLabel} ({signal.source_name})
      </span>
      <span className="text-sentinel-muted/60">–</span>
      <span className="whitespace-nowrap">{reportDate}</span>
    </div>
  );
}

/**
 * Detailed threat card
 */
function ThreatDetailCard({ signal }: { signal: OffChainThreatSignal }) {
  const [showDetails, setShowDetails] = useState(false);
  const confidenceDisplay = getConfidenceLevelDisplay(signal.confidence_level);
  const reportTypeLabel = getReportTypeLabel(signal.report_type);
  
  const formatDate = (isoString: string) => {
    return new Date(isoString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };
  
  // Check if this is a recent report (within 7 days)
  const lastSeen = signal.last_seen_timestamp || signal.first_seen_timestamp;
  const daysSince = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60 * 24);
  const isRecent = daysSince <= 7;

  return (
    <div className={`bg-sentinel-surface rounded-lg overflow-hidden ${isRecent ? 'ring-1 ring-red-500/30' : ''}`}>
      <button
        onClick={() => setShowDetails(!showDetails)}
        className="w-full p-3 flex items-center gap-3 text-left hover:bg-sentinel-elevated/50 transition-colors"
      >
        {/* Icon */}
        <div className={`p-1.5 rounded ${isRecent ? 'bg-red-500/10 text-red-400' : 'bg-amber-500/10 text-amber-400'}`}>
          <AlertTriangle className="w-3.5 h-3.5" />
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-sentinel-text">
              ⚠️ {reportTypeLabel}
            </span>
            <span className={`px-1.5 py-0.5 text-[10px] rounded ${confidenceDisplay.bgColor} ${confidenceDisplay.color}`}>
              {confidenceDisplay.label}
            </span>
            {isRecent && (
              <span className="px-1.5 py-0.5 text-[10px] rounded bg-red-500/20 text-red-400">
                Recent
              </span>
            )}
            {signal.disputed && (
              <span className="px-1.5 py-0.5 text-[10px] rounded bg-gray-500/20 text-gray-400">
                Disputed
              </span>
            )}
          </div>
          
          {/* Source and date - Format: (HashDit via Etherscan) – Reported: 2026-01-25 */}
          <div className="text-xs text-sentinel-muted mt-0.5">
            ({signal.source_name}) – Reported: {formatDate(signal.first_seen_timestamp)}
          </div>
        </div>

        {/* Expand indicator */}
        <ChevronDown className={`w-4 h-4 text-sentinel-muted transition-transform ${showDetails ? 'rotate-180' : ''}`} />
      </button>

      {/* Expanded details */}
      <AnimatePresence>
        {showDetails && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-3 pb-3 space-y-2">
              {/* Context */}
              {signal.context && (
                <div className="text-xs text-sentinel-muted bg-sentinel-elevated/50 p-2 rounded">
                  <strong>Details:</strong> {signal.context}
                </div>
              )}

              {/* Timestamps */}
              <div className="flex items-center gap-4 text-xs text-sentinel-muted">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  First seen: {formatDate(signal.first_seen_timestamp)}
                </span>
                {signal.last_seen_timestamp && (
                  <span>
                    Last seen: {formatDate(signal.last_seen_timestamp)}
                  </span>
                )}
              </div>

              {/* Decay info */}
              <div className="text-xs text-sentinel-muted flex items-center gap-2">
                <span className={signal.decay.is_active ? 'text-amber-400' : 'text-gray-400'}>
                  {signal.decay.is_active 
                    ? `Expires in ${signal.decay.days_until_expiry} days`
                    : 'Expired'
                  }
                </span>
                {signal.decay.confirmation_count > 1 && (
                  <span>
                    • Confirmed {signal.decay.confirmation_count} times
                  </span>
                )}
              </div>

              {/* Evidence link */}
              {signal.evidence_url && (
                <a
                  href={signal.evidence_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" />
                  View on {signal.source_name.includes('Etherscan') ? 'Etherscan' : 'source'}
                </a>
              )}

              {/* Reference ID */}
              {signal.reference_id && (
                <div className="text-[10px] text-sentinel-muted font-mono bg-sentinel-elevated/30 px-2 py-1 rounded inline-block">
                  Ref: {signal.reference_id}
                </div>
              )}

              {/* Metadata preview */}
              {signal.metadata && Object.keys(signal.metadata).length > 0 && (
                <div className="text-[10px] text-sentinel-muted">
                  Chain: {String((signal.metadata as Record<string, unknown>).chain || 'Unknown')}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/**
 * Exposure Score visualization
 */
function ExposureScoreCard({ score }: { score: OffChainExposureScore }) {
  const display = getExposureLevelDisplay(score.level);
  const percentage = Math.round(score.score * 100);

  return (
    <div className={`p-4 rounded-lg border ${display.borderColor} ${display.bgColor}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-sentinel-muted">
          Off-chain Exposure Score
        </span>
        <span className={`text-lg font-bold ${display.color}`}>
          {(score.score).toFixed(2)}
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-2 bg-sentinel-surface rounded-full overflow-hidden mb-2">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          className={`h-full rounded-full ${
            score.level === 'none' ? 'bg-green-500' :
            score.level === 'low' ? 'bg-blue-500' :
            score.level === 'moderate' ? 'bg-amber-500' :
            score.level === 'high' ? 'bg-orange-500' :
            'bg-red-500'
          }`}
        />
      </div>

      {/* Level indicator */}
      <div className="flex items-center justify-between text-xs">
        <span className={`px-2 py-0.5 rounded ${display.bgColor} ${display.color}`}>
          {display.label} Exposure
        </span>
        <span className="text-sentinel-muted">
          (Does NOT affect on-chain risk score)
        </span>
      </div>

      {/* Contributing factors */}
      {score.factors.length > 0 && (
        <div className="mt-3 pt-3 border-t border-sentinel-border">
          <div className="text-xs text-sentinel-muted mb-1.5">Contributing factors:</div>
          <ul className="space-y-1">
            {score.factors.map((factor, i) => (
              <li key={i} className="text-xs text-sentinel-muted flex items-center gap-1.5">
                <span className="w-1 h-1 bg-sentinel-muted/50 rounded-full" />
                {factor.description}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ============================================
// EXPORTS
// ============================================

export default OffChainThreatsSection;
