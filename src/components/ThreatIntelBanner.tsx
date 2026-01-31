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
  Database,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import type {
  ThreatReport,
  ThreatFinding,
  ThreatCategory,
  ThreatSeverity,
  OverallRiskLevel,
  CategorySummary,
} from '@/lib/threat-intel/types';
import {
  OFF_CHAIN_LABELS,
  getSeverityColor,
  getRiskLevelColor,
  getSeverityLabel,
  getCategoryLabel,
} from '@/lib/threat-intel/types';

interface ThreatIntelBannerProps {
  report: ThreatReport;
  defaultExpanded?: boolean;
}

/**
 * ThreatIntelBanner - Production banner for displaying off-chain threat intelligence
 * 
 * CRITICAL UX REQUIREMENTS:
 * - Clearly labeled as "off-chain signal" from external providers
 * - NEVER shows "COMPROMISED" or "MALICIOUS WALLET"
 * - Always shows disclaimer about off-chain vs on-chain
 * - Uses amber/orange colors for caution without alarm
 */
export function ThreatIntelBanner({ 
  report, 
  defaultExpanded = false 
}: ThreatIntelBannerProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  // Don't render if no threats detected
  if (!report.threatDetected) {
    return null;
  }

  const { displaySummary, findings, categorySummaries, crossSourceAgreement } = report;
  const riskColors = getRiskLevelColor(report.riskLevel);

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass-card rounded-xl overflow-hidden border-l-4 ${riskColors.border.replace('border-', 'border-l-')} ${riskColors.bg}`}
    >
      {/* Banner Header - Always visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className={`w-full p-4 flex items-start gap-4 text-left hover:${riskColors.bg} transition-colors`}
      >
        {/* Warning Icon */}
        <div className={`p-2 rounded-lg ${riskColors.bg} ${riskColors.text} flex-shrink-0`}>
          <AlertTriangle className="w-5 h-5" />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <h3 className={`font-display font-semibold ${riskColors.text} mb-1`}>
            {displaySummary.headline}
          </h3>
          <p className="text-sm text-sentinel-muted line-clamp-2">
            {displaySummary.explanation}
          </p>
          
          {/* Quick stats */}
          <div className="flex items-center gap-4 mt-2 flex-wrap">
            <span className="inline-flex items-center gap-1 text-xs text-sentinel-muted">
              <Eye className="w-3.5 h-3.5" />
              {findings.length} finding{findings.length !== 1 ? 's' : ''}
            </span>
            <span className="inline-flex items-center gap-1 text-xs text-sentinel-muted">
              <Globe className="w-3.5 h-3.5" />
              {report.queriedProviders.length} provider{report.queriedProviders.length !== 1 ? 's' : ''}
            </span>
            {crossSourceAgreement.agreementCount >= 2 && (
              <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-400">
                <Users className="w-3 h-3" />
                Multi-source confirmed
              </span>
            )}
          </div>

          {/* Off-chain label - REQUIRED */}
          <div className="mt-2">
            <span className="text-[10px] text-amber-400/80 bg-amber-500/10 px-2 py-0.5 rounded">
              {OFF_CHAIN_LABELS.shortLabel}
            </span>
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
              {/* Risk Score */}
              <RiskScoreCard 
                score={report.overallRiskScore} 
                level={report.riskLevel}
              />

              {/* User Guidance */}
              <div className="flex items-start gap-3 p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                <Info className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <p className="text-sm text-sentinel-muted">
                  {displaySummary.guidance}
                </p>
              </div>

              {/* Category Summaries */}
              {categorySummaries.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-sentinel-muted mb-3 flex items-center gap-2">
                    <FileWarning className="w-4 h-4" />
                    Threat Categories
                  </h4>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {categorySummaries.map((summary) => (
                      <CategoryCard key={summary.category} summary={summary} />
                    ))}
                  </div>
                </div>
              )}

              {/* Provider Status */}
              <ProviderStatusCard 
                queriedProviders={report.queriedProviders}
                failedProviders={report.failedProviders}
                agreement={crossSourceAgreement}
              />

              {/* Individual Findings (collapsed by default) */}
              <FindingsSection findings={findings} />

              {/* CRITICAL: Off-chain Disclaimer */}
              <div className="p-3 bg-sentinel-surface rounded-lg border border-sentinel-border">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-sentinel-muted mt-0.5 flex-shrink-0" />
                  <div className="text-xs text-sentinel-muted">
                    <p className="font-medium text-sentinel-text mb-1">
                      {OFF_CHAIN_LABELS.label}
                    </p>
                    <p className="italic">
                      {OFF_CHAIN_LABELS.disclaimer}
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

/**
 * Risk Score Card
 */
function RiskScoreCard({ score, level }: { score: number; level: OverallRiskLevel }) {
  const colors = getRiskLevelColor(level);

  return (
    <div className={`p-4 rounded-lg border ${colors.border} ${colors.bg}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-sentinel-muted">
          Off-chain Risk Score
        </span>
        <span className={`text-lg font-bold ${colors.text}`}>
          {score}
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-2 bg-sentinel-surface rounded-full overflow-hidden mb-2">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          className={`h-full rounded-full ${
            level === 'safe' ? 'bg-green-500' :
            level === 'suspicious' ? 'bg-amber-500' :
            level === 'high_risk' ? 'bg-orange-500' :
            'bg-red-500'
          }`}
        />
      </div>

      {/* Level indicator */}
      <div className="flex items-center justify-between text-xs">
        <span className={`px-2 py-0.5 rounded ${colors.bg} ${colors.text} capitalize`}>
          {level.replace('_', ' ')}
        </span>
        <span className="text-sentinel-muted">
          (Separate from on-chain risk)
        </span>
      </div>
    </div>
  );
}

/**
 * Category Summary Card
 */
function CategoryCard({ summary }: { summary: CategorySummary }) {
  const severityColors = getSeverityColor(summary.maxSeverity);

  return (
    <div className={`p-3 rounded-lg border ${severityColors.border} ${severityColors.bg}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm font-medium text-sentinel-text">
          {getCategoryLabel(summary.category)}
        </span>
        <span className={`text-xs px-1.5 py-0.5 rounded ${severityColors.bg} ${severityColors.text}`}>
          {getSeverityLabel(summary.maxSeverity)}
        </span>
      </div>
      <div className="flex items-center gap-2 text-xs text-sentinel-muted">
        <span>{summary.count} finding{summary.count !== 1 ? 's' : ''}</span>
        <span>•</span>
        <span>{summary.providers.join(', ')}</span>
      </div>
    </div>
  );
}

/**
 * Provider Status Card
 */
function ProviderStatusCard({
  queriedProviders,
  failedProviders,
  agreement,
}: {
  queriedProviders: string[];
  failedProviders: string[];
  agreement: ThreatReport['crossSourceAgreement'];
}) {
  return (
    <div className="p-3 bg-sentinel-surface rounded-lg">
      <h5 className="text-xs font-medium text-sentinel-muted mb-2 flex items-center gap-2">
        <Database className="w-3.5 h-3.5" />
        Intelligence Sources
      </h5>
      <div className="flex flex-wrap gap-2">
        {queriedProviders.map((provider) => {
          const failed = failedProviders.includes(provider);
          return (
            <span
              key={provider}
              className={`inline-flex items-center gap-1 text-xs px-2 py-1 rounded ${
                failed 
                  ? 'bg-red-500/10 text-red-400' 
                  : 'bg-green-500/10 text-green-400'
              }`}
            >
              {failed ? (
                <XCircle className="w-3 h-3" />
              ) : (
                <CheckCircle2 className="w-3 h-3" />
              )}
              {provider}
            </span>
          );
        })}
      </div>
      {agreement.agreementCount >= 2 && (
        <div className="mt-2 text-xs text-amber-400">
          ⚠️ {agreement.agreementCount} providers agree on threat detection
        </div>
      )}
    </div>
  );
}

/**
 * Findings Section (collapsible)
 */
function FindingsSection({ findings }: { findings: ThreatFinding[] }) {
  const [showAll, setShowAll] = useState(false);
  const visibleFindings = showAll ? findings : findings.slice(0, 3);

  return (
    <div>
      <h4 className="text-sm font-medium text-sentinel-muted mb-3 flex items-center gap-2">
        <Eye className="w-4 h-4" />
        Detailed Findings ({findings.length})
      </h4>
      <div className="space-y-2">
        {visibleFindings.map((finding, index) => (
          <FindingCard key={`${finding.provider}-${finding.category}-${index}`} finding={finding} />
        ))}
      </div>
      {findings.length > 3 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="mt-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          {showAll ? 'Show less' : `Show ${findings.length - 3} more findings`}
        </button>
      )}
    </div>
  );
}

/**
 * Individual Finding Card
 */
function FindingCard({ finding }: { finding: ThreatFinding }) {
  const [showDetails, setShowDetails] = useState(false);
  const severityColors = getSeverityColor(finding.severity);

  const formatDate = (isoString?: string) => {
    if (!isoString) return 'Unknown';
    return new Date(isoString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  return (
    <div className="bg-sentinel-elevated rounded-lg overflow-hidden">
      <button
        onClick={() => setShowDetails(!showDetails)}
        className="w-full p-3 flex items-center gap-3 text-left hover:bg-sentinel-surface transition-colors"
      >
        {/* Provider indicator */}
        <div className="p-1.5 rounded bg-sentinel-surface">
          <Globe className="w-3.5 h-3.5 text-sentinel-muted" />
        </div>

        {/* Main info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-sentinel-text">
              {finding.provider}
            </span>
            <span className={`px-1.5 py-0.5 text-[10px] rounded ${severityColors.bg} ${severityColors.text}`}>
              {getSeverityLabel(finding.severity)}
            </span>
            <span className="px-1.5 py-0.5 text-[10px] rounded bg-sentinel-surface text-sentinel-muted">
              {finding.confidence}% confidence
            </span>
          </div>
          <div className="text-xs text-sentinel-muted mt-0.5">
            {getCategoryLabel(finding.category)}
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
              {/* Description */}
              <div className="text-xs text-sentinel-muted bg-sentinel-surface p-2 rounded">
                {finding.description}
              </div>

              {/* Timestamps */}
              <div className="flex items-center gap-4 text-xs text-sentinel-muted">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  First reported: {formatDate(finding.firstReportedAt)}
                </span>
                {finding.lastSeenAt && (
                  <span>
                    Last seen: {formatDate(finding.lastSeenAt)}
                  </span>
                )}
              </div>

              {/* Tags */}
              {finding.tags && finding.tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {finding.tags.map((tag) => (
                    <span 
                      key={tag}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-sentinel-surface text-sentinel-muted"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              {/* Reference link */}
              {finding.referenceUrl && (
                <a
                  href={finding.referenceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" />
                  View source
                </a>
              )}

              {/* Off-chain notice */}
              <div className="text-[10px] text-green-400 bg-green-500/5 px-2 py-1 rounded">
                ✓ This is an off-chain report. No on-chain malicious activity detected.
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/**
 * Compact version for overview tabs
 */
export function CompactThreatIntelBanner({ 
  report,
  onClick,
}: { 
  report: ThreatReport;
  onClick?: () => void;
}) {
  if (!report.threatDetected) {
    return null;
  }

  const colors = getRiskLevelColor(report.riskLevel);

  return (
    <button
      onClick={onClick}
      className={`w-full glass-card rounded-lg p-3 flex items-center gap-3 text-left hover:${colors.bg} transition-colors border ${colors.border}`}
    >
      <div className={`p-1.5 rounded ${colors.bg} ${colors.text}`}>
        <AlertTriangle className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <div className={`text-sm font-medium ${colors.text} truncate`}>
          {report.displaySummary.headline}
        </div>
        <div className="text-xs text-sentinel-muted">
          {report.findings.length} finding{report.findings.length !== 1 ? 's' : ''} from {report.queriedProviders.length} provider{report.queriedProviders.length !== 1 ? 's' : ''}
        </div>
      </div>
      <div className={`px-2 py-1 rounded text-xs ${colors.bg} ${colors.text} capitalize`}>
        {report.riskLevel.replace('_', ' ')}
      </div>
    </button>
  );
}

/**
 * Empty state when no threats found
 */
export function NoThreatsFound({ providerCount }: { providerCount: number }) {
  return (
    <div className="glass-card rounded-xl p-4 flex items-center gap-4 border border-green-500/20 bg-green-500/5">
      <div className="p-2 rounded-lg bg-green-500/10 text-green-400">
        <Shield className="w-5 h-5" />
      </div>
      <div>
        <h3 className="font-medium text-green-400 mb-0.5">
          No off-chain threat reports found
        </h3>
        <p className="text-sm text-sentinel-muted">
          Checked {providerCount} security intelligence provider{providerCount !== 1 ? 's' : ''}. 
          No reports found for this address.
        </p>
        <p className="text-xs text-sentinel-muted mt-1 italic">
          This does not guarantee the address is safe. Always verify through official channels.
        </p>
      </div>
    </div>
  );
}
