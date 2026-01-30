'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Shield,
  Info,
  Clock,
  Eye,
  Globe,
  Users,
  FileWarning,
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

interface OffChainThreatBannerProps {
  assessment: OTTIAssessment;
  defaultExpanded?: boolean;
}

/**
 * OffChainThreatBanner - Non-alarmist banner for off-chain threat reports
 * 
 * DESIGN PRINCIPLES:
 * - NEVER shows "SCAM WALLET", "MALICIOUS", or "COMPROMISED"
 * - Clearly separates on-chain safety from off-chain reports
 * - Provides expandable detail view
 * - Uses amber/orange colors (NOT red) to indicate caution without alarm
 */
export function OffChainThreatBanner({ 
  assessment, 
  defaultExpanded = false 
}: OffChainThreatBannerProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  // Don't render if no off-chain risk detected
  if (!assessment.off_chain_risk_detected || !assessment.summary.show_warning) {
    return null;
  }

  const { summary, signals, exposure_score } = assessment;
  const exposureDisplay = getExposureLevelDisplay(exposure_score.level);

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card rounded-xl overflow-hidden border-l-4 border-l-amber-500 bg-amber-500/5"
    >
      {/* Banner Header - Always visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-start gap-4 text-left hover:bg-amber-500/5 transition-colors"
      >
        {/* Warning Icon */}
        <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 flex-shrink-0">
          <AlertTriangle className="w-5 h-5" />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <h3 className="font-display font-semibold text-amber-400 mb-1">
            {summary.headline}
          </h3>
          <p className="text-sm text-sentinel-muted line-clamp-2">
            {summary.explanation}
          </p>
          
          {/* Quick stats */}
          <div className="flex items-center gap-4 mt-2 flex-wrap">
            <span className="inline-flex items-center gap-1 text-xs text-sentinel-muted">
              <Eye className="w-3.5 h-3.5" />
              {summary.signal_count} report{summary.signal_count !== 1 ? 's' : ''}
            </span>
            <span className="inline-flex items-center gap-1 text-xs text-sentinel-muted">
              <Globe className="w-3.5 h-3.5" />
              {summary.source_count} source{summary.source_count !== 1 ? 's' : ''}
            </span>
            {summary.highest_confidence && (
              <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded ${
                getConfidenceLevelDisplay(summary.highest_confidence).bgColor
              } ${getConfidenceLevelDisplay(summary.highest_confidence).color}`}>
                {getConfidenceLevelDisplay(summary.highest_confidence).label} confidence
              </span>
            )}
          </div>
        </div>

        {/* Expand/Collapse indicator */}
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
              {/* Status Line */}
              <div className="flex items-center gap-2 p-3 bg-sentinel-surface rounded-lg">
                <Shield className="w-4 h-4 text-green-400" />
                <span className="text-sm text-sentinel-text">
                  {summary.status_line}
                </span>
              </div>

              {/* Exposure Score */}
              <ExposureScoreCard score={exposure_score} />

              {/* User Guidance */}
              <div className="flex items-start gap-3 p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                <Info className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <p className="text-sm text-sentinel-muted">
                  {summary.guidance}
                </p>
              </div>

              {/* Signal Details */}
              <div>
                <h4 className="text-sm font-medium text-sentinel-muted mb-3 flex items-center gap-2">
                  <FileWarning className="w-4 h-4" />
                  Off-Chain Threat Signals
                </h4>
                <div className="space-y-2">
                  {signals.map((signal) => (
                    <SignalCard key={signal.id} signal={signal} />
                  ))}
                </div>
              </div>

              {/* Disclaimer */}
              <p className="text-xs text-sentinel-muted italic">
                ℹ️ Off-chain reports do not affect on-chain security assessment. 
                These signals come from external threat intelligence sources and 
                may not reflect actual on-chain behavior.
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/**
 * Exposure Score Card - Visual display of off-chain exposure
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
          {display.label}
        </span>
        <span className="text-sentinel-muted">
          (Does NOT affect on-chain risk score)
        </span>
      </div>

      {/* Factors */}
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

/**
 * Individual Signal Card
 */
function SignalCard({ signal }: { signal: OffChainThreatSignal }) {
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

  return (
    <div className="bg-sentinel-surface rounded-lg overflow-hidden">
      <button
        onClick={() => setShowDetails(!showDetails)}
        className="w-full p-3 flex items-center gap-3 text-left hover:bg-sentinel-elevated/50 transition-colors"
      >
        {/* Source icon */}
        <div className="p-1.5 rounded bg-sentinel-elevated">
          <Users className="w-3.5 h-3.5 text-sentinel-muted" />
        </div>

        {/* Main info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-sentinel-text">
              {signal.source_name}
            </span>
            <span className={`px-1.5 py-0.5 text-[10px] rounded ${confidenceDisplay.bgColor} ${confidenceDisplay.color}`}>
              {confidenceDisplay.label}
            </span>
            {signal.disputed && (
              <span className="px-1.5 py-0.5 text-[10px] rounded bg-gray-500/20 text-gray-400">
                Disputed
              </span>
            )}
          </div>
          <div className="text-xs text-sentinel-muted mt-0.5">
            {reportTypeLabel}
          </div>
        </div>

        {/* Expand indicator */}
        <ChevronDown className={`w-4 h-4 text-sentinel-muted transition-transform ${
          showDetails ? 'rotate-180' : ''
        }`} />
      </button>

      {/* Details */}
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
                  <strong>Context:</strong> {signal.context}
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
              <div className="text-xs text-sentinel-muted">
                <span className={`${signal.decay.is_active ? 'text-amber-400' : 'text-gray-400'}`}>
                  {signal.decay.is_active 
                    ? `Expires in ${signal.decay.days_until_expiry} days`
                    : 'Expired'
                  }
                </span>
                {signal.decay.confirmation_count > 1 && (
                  <span className="ml-2">
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
                  View evidence
                </a>
              )}

              {/* Reference ID */}
              {signal.reference_id && (
                <div className="text-[10px] text-sentinel-muted font-mono">
                  Ref: {signal.reference_id}
                </div>
              )}

              {/* On-chain impact notice */}
              <div className="text-[10px] text-green-400 bg-green-500/5 px-2 py-1 rounded">
                ✓ On-chain impact: None observed
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/**
 * Compact version of the OTTI banner for overview tab
 */
export function CompactOffChainBanner({ 
  assessment,
  onClick,
}: { 
  assessment: OTTIAssessment;
  onClick?: () => void;
}) {
  if (!assessment.off_chain_risk_detected || !assessment.summary.show_warning) {
    return null;
  }

  const { summary, exposure_score } = assessment;
  const exposureDisplay = getExposureLevelDisplay(exposure_score.level);

  return (
    <button
      onClick={onClick}
      className="w-full glass-card rounded-lg p-3 flex items-center gap-3 text-left hover:bg-amber-500/5 transition-colors border border-amber-500/20"
    >
      <div className="p-1.5 rounded bg-amber-500/10 text-amber-400">
        <AlertTriangle className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-amber-400 truncate">
          {summary.headline}
        </div>
        <div className="text-xs text-sentinel-muted">
          {summary.signal_count} report{summary.signal_count !== 1 ? 's'  : ''} from {summary.source_count} source{summary.source_count !== 1 ? 's' : ''}
        </div>
      </div>
      <div className={`px-2 py-1 rounded text-xs ${exposureDisplay.bgColor} ${exposureDisplay.color}`}>
        {exposureDisplay.label}
      </div>
    </button>
  );
}
