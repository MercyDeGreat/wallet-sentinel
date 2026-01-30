'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronDown,
  ChevronUp,
  AlertCircle,
  AlertTriangle,
  Info,
  CheckCircle,
  Shield,
  ExternalLink,
  Eye,
  EyeOff,
} from 'lucide-react';
import { SecurityExplanation as SecurityExplanationType } from '@/lib/explanation/types';

interface SecurityExplanationProps {
  explanation: SecurityExplanationType;
  showGuidance?: boolean;
  defaultExpanded?: boolean;
}

/**
 * SecurityExplanation Component
 * 
 * Displays probabilistic, evidence-aware security messaging
 * with toggle sections for positive and negative signals.
 * 
 * CORE UX RULES:
 * 1. NEVER claim attacker control unless direct evidence exists
 * 2. Separate "suspicious activity" from "confirmed compromise"
 * 3. Always explain WHY something was flagged
 * 4. Always explain WHAT WAS NOT observed
 * 5. Default to calm, non-alarmist language
 */
export function SecurityExplanation({ 
  explanation, 
  showGuidance = true,
  defaultExpanded = false 
}: SecurityExplanationProps) {
  const [isPositiveExpanded, setIsPositiveExpanded] = useState(defaultExpanded);
  const [isNegativeExpanded, setIsNegativeExpanded] = useState(defaultExpanded);

  const severityConfig = getSeverityConfig(explanation.headline.severity);

  return (
    <div className="space-y-4">
      {/* Main Status Card */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className={`rounded-xl border-l-4 ${severityConfig.borderColor} ${severityConfig.bgColor} p-5`}
      >
        {/* Headline */}
        <div className="flex items-start gap-3 mb-3">
          <div className={`p-2 rounded-lg ${severityConfig.iconBg}`}>
            <severityConfig.Icon className={`w-5 h-5 ${severityConfig.iconColor}`} />
          </div>
          <div className="flex-1">
            <h3 className={`font-display font-semibold text-lg ${severityConfig.textColor}`}>
              {explanation.headline.emoji} {explanation.headline.text}
            </h3>
          </div>
        </div>

        {/* Summary */}
        <p className="text-sentinel-text mb-4 leading-relaxed">
          {explanation.summary}
        </p>

        {/* Confidence Indicator */}
        <div className="flex items-center gap-2 mb-4">
          <div className="text-xs text-sentinel-muted">Confidence:</div>
          <ConfidenceBadge 
            confidence={explanation.confidence} 
            score={explanation.confidenceScore} 
          />
        </div>

        {/* Toggle Sections */}
        <div className="space-y-2">
          {/* Positive Signals (What triggered the flag) */}
          {explanation.positiveSignals.length > 0 && (
            <ToggleSection
              title={explanation.toggleTitle}
              icon={<Eye className="w-4 h-4" />}
              isExpanded={isPositiveExpanded}
              onToggle={() => setIsPositiveExpanded(!isPositiveExpanded)}
              variant="warning"
            >
              <ul className="space-y-2">
                {explanation.positiveSignals.map((signal, index) => (
                  <PositiveSignalItem key={index} signal={signal} />
                ))}
              </ul>
            </ToggleSection>
          )}

          {/* Negative Signals (What was NOT detected) */}
          {explanation.negativeSignals.length > 0 && (
            <ToggleSection
              title={explanation.negativeToggleTitle}
              icon={<EyeOff className="w-4 h-4" />}
              isExpanded={isNegativeExpanded}
              onToggle={() => setIsNegativeExpanded(!isNegativeExpanded)}
              variant="safe"
            >
              <ul className="space-y-2">
                {explanation.negativeSignals.map((signal, index) => (
                  <NegativeSignalItem key={index} signal={signal} />
                ))}
              </ul>
            </ToggleSection>
          )}
        </div>
      </motion.div>

      {/* Guidance Section */}
      {showGuidance && explanation.guidance && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass-card rounded-xl p-4 border border-sentinel-border"
        >
          <div className="flex items-start gap-3">
            <Info className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div>
              <h4 className="font-semibold text-sm text-sentinel-text mb-1">Guidance</h4>
              <p className="text-sm text-sentinel-muted">{explanation.guidance}</p>
              
              {explanation.recommendedActions && explanation.recommendedActions.length > 0 && (
                <ul className="mt-3 space-y-1">
                  {explanation.recommendedActions.map((action, index) => (
                    <li key={index} className="flex items-center gap-2 text-sm text-sentinel-muted">
                      <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                      {action}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

// ============================================
// TOGGLE SECTION COMPONENT
// ============================================

interface ToggleSectionProps {
  title: string;
  icon: React.ReactNode;
  isExpanded: boolean;
  onToggle: () => void;
  variant: 'warning' | 'safe';
  children: React.ReactNode;
}

function ToggleSection({ 
  title, 
  icon, 
  isExpanded, 
  onToggle, 
  variant,
  children 
}: ToggleSectionProps) {
  const variantStyles = {
    warning: {
      bg: 'bg-amber-500/5',
      border: 'border-amber-500/20',
      hoverBorder: 'hover:border-amber-500/40',
      text: 'text-amber-400',
    },
    safe: {
      bg: 'bg-green-500/5',
      border: 'border-green-500/20',
      hoverBorder: 'hover:border-green-500/40',
      text: 'text-green-400',
    },
  };

  const styles = variantStyles[variant];

  return (
    <div className={`rounded-lg border ${styles.border} ${styles.hoverBorder} transition-colors`}>
      <button
        onClick={onToggle}
        className={`w-full flex items-center justify-between p-3 ${styles.bg} rounded-lg`}
      >
        <div className="flex items-center gap-2">
          <span className={styles.text}>{icon}</span>
          <span className="text-sm font-medium text-sentinel-text">{title}</span>
        </div>
        {isExpanded ? (
          <ChevronUp className="w-4 h-4 text-sentinel-muted" />
        ) : (
          <ChevronDown className="w-4 h-4 text-sentinel-muted" />
        )}
      </button>
      
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="p-3 pt-0">
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ============================================
// SIGNAL ITEM COMPONENTS
// ============================================

interface PositiveSignalItemProps {
  signal: SecurityExplanationType['positiveSignals'][0];
}

function PositiveSignalItem({ signal }: PositiveSignalItemProps) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
      <div className="flex-1">
        <span className="text-sentinel-text">{signal.description}</span>
        {signal.reference && (
          <a
            href={signal.reference.explorerUrl || '#'}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-2 inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
          >
            <span className="font-mono">
              {signal.reference.value.slice(0, 8)}...{signal.reference.value.slice(-6)}
            </span>
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
        <div className="mt-1 text-xs text-sentinel-muted">
          Confidence: {signal.confidence}%
        </div>
      </div>
    </li>
  );
}

interface NegativeSignalItemProps {
  signal: SecurityExplanationType['negativeSignals'][0];
}

function NegativeSignalItem({ signal }: NegativeSignalItemProps) {
  const importanceColors = {
    HIGH: 'text-green-400',
    MEDIUM: 'text-blue-400',
    LOW: 'text-sentinel-muted',
  };

  return (
    <li className="flex items-start gap-2 text-sm">
      <CheckCircle className={`w-4 h-4 ${importanceColors[signal.importance]} mt-0.5 flex-shrink-0`} />
      <div className="flex-1">
        <span className="text-sentinel-text">{signal.description}</span>
        <div className="mt-0.5 text-xs text-sentinel-muted">
          Importance: {signal.importance.toLowerCase()}
        </div>
      </div>
    </li>
  );
}

// ============================================
// CONFIDENCE BADGE
// ============================================

interface ConfidenceBadgeProps {
  confidence: SecurityExplanationType['confidence'];
  score: number;
}

function ConfidenceBadge({ confidence, score }: ConfidenceBadgeProps) {
  const config = {
    CONFIRMED: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Confirmed' },
    LIKELY: { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'Likely' },
    SUSPICIOUS: { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'Suspicious' },
    UNCERTAIN: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Uncertain' },
    UNLIKELY: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Unlikely' },
  };

  const { bg, text, label } = config[confidence];

  return (
    <div className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full ${bg}`}>
      <span className={`text-xs font-medium ${text}`}>{label}</span>
      <span className="text-xs text-sentinel-muted">({score}%)</span>
    </div>
  );
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function getSeverityConfig(severity: SecurityExplanationType['headline']['severity']) {
  const configs = {
    CRITICAL: {
      Icon: AlertCircle,
      borderColor: 'border-l-red-500',
      bgColor: 'bg-red-500/5',
      iconBg: 'bg-red-500/10',
      iconColor: 'text-red-400',
      textColor: 'text-red-400',
    },
    WARNING: {
      Icon: AlertTriangle,
      borderColor: 'border-l-orange-500',
      bgColor: 'bg-orange-500/5',
      iconBg: 'bg-orange-500/10',
      iconColor: 'text-orange-400',
      textColor: 'text-orange-400',
    },
    CAUTION: {
      Icon: Info,
      borderColor: 'border-l-yellow-500',
      bgColor: 'bg-yellow-500/5',
      iconBg: 'bg-yellow-500/10',
      iconColor: 'text-yellow-400',
      textColor: 'text-yellow-400',
    },
    INFORMATIONAL: {
      Icon: Info,
      borderColor: 'border-l-blue-500',
      bgColor: 'bg-blue-500/5',
      iconBg: 'bg-blue-500/10',
      iconColor: 'text-blue-400',
      textColor: 'text-blue-400',
    },
    SAFE: {
      Icon: Shield,
      borderColor: 'border-l-green-500',
      bgColor: 'bg-green-500/5',
      iconBg: 'bg-green-500/10',
      iconColor: 'text-green-400',
      textColor: 'text-green-400',
    },
  };

  return configs[severity];
}

// ============================================
// COMPACT VARIANT
// ============================================

interface CompactExplanationProps {
  explanation: SecurityExplanationType;
}

export function CompactExplanation({ explanation }: CompactExplanationProps) {
  const severityConfig = getSeverityConfig(explanation.headline.severity);

  return (
    <div className={`flex items-center gap-3 p-3 rounded-lg ${severityConfig.bgColor} border border-sentinel-border`}>
      <severityConfig.Icon className={`w-5 h-5 ${severityConfig.iconColor}`} />
      <div className="flex-1 min-w-0">
        <div className={`font-medium text-sm ${severityConfig.textColor} truncate`}>
          {explanation.headline.emoji} {explanation.headline.text}
        </div>
        <div className="text-xs text-sentinel-muted truncate">
          {explanation.positiveSignals.length} concern{explanation.positiveSignals.length !== 1 ? 's' : ''} • 
          {' '}{explanation.negativeSignals.filter(s => s.importance === 'HIGH').length} safety indicators
        </div>
      </div>
      <ConfidenceBadge confidence={explanation.confidence} score={explanation.confidenceScore} />
    </div>
  );
}

// ============================================
// INLINE BADGE VARIANT
// ============================================

interface ExplanationBadgeProps {
  explanation: SecurityExplanationType;
  size?: 'sm' | 'md';
}

export function ExplanationBadge({ explanation, size = 'md' }: ExplanationBadgeProps) {
  const severityConfig = getSeverityConfig(explanation.headline.severity);
  const sizeClasses = size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-1.5 text-sm';

  return (
    <div className={`inline-flex items-center gap-1.5 rounded-full ${severityConfig.bgColor} ${sizeClasses}`}>
      <span>{explanation.headline.emoji}</span>
      <span className={`font-medium ${severityConfig.textColor}`}>
        {explanation.confidence === 'CONFIRMED' ? 'Confirmed' : 
         explanation.confidence === 'SUSPICIOUS' ? 'Suspicious' : 
         explanation.confidence === 'UNCERTAIN' ? 'Uncertain' : 
         'Safe'}
      </span>
    </div>
  );
}

export default SecurityExplanation;
