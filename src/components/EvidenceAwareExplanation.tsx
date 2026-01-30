'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronDown,
  ChevronUp,
  AlertOctagon,
  AlertTriangle,
  Info,
  CheckCircle,
  Shield,
  ShieldCheck,
  ExternalLink,
  Eye,
  EyeOff,
  HelpCircle,
  Lightbulb,
} from 'lucide-react';
import {
  UncertaintyAwareExplanation,
  TriggerSignal,
  AbsenceSignal,
  InferenceState,
} from '@/lib/explanation/uncertainty-messaging';

// ============================================
// EVIDENCE-AWARE EXPLANATION COMPONENT
// ============================================
//
// This component displays probabilistic, evidence-aware messaging
// that explains uncertainty HONESTLY.
//
// CORE UX RULES:
// 1. NEVER claim attacker control unless direct evidence exists
// 2. Separate "suspicious activity" from "confirmed compromise"
// 3. Always explain WHY something was flagged
// 4. Always explain WHAT WAS NOT observed
// 5. Default to calm, non-alarmist language
//
// OUTPUT FORMAT:
// [Status Headline]
// [1-sentence reassurance]
// [Toggle: Why Securnex flagged this]
// [Toggle: What Securnex did NOT detect]
// [Optional Guidance]

interface EvidenceAwareExplanationProps {
  explanation: UncertaintyAwareExplanation;
  showGuidance?: boolean;
  defaultExpanded?: boolean;
  compact?: boolean;
}

export function EvidenceAwareExplanation({
  explanation,
  showGuidance = true,
  defaultExpanded = false,
  compact = false,
}: EvidenceAwareExplanationProps) {
  const [triggersExpanded, setTriggersExpanded] = useState(defaultExpanded);
  const [absencesExpanded, setAbsencesExpanded] = useState(defaultExpanded);
  const [uncertaintiesExpanded, setUncertaintiesExpanded] = useState(false);

  const stateConfig = getStateConfig(explanation.inference.state);

  return (
    <div className="space-y-4">
      {/* ===== MAIN STATUS CARD ===== */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className={`
          rounded-xl border-l-4 ${stateConfig.borderColor} 
          ${stateConfig.bgColor} p-5
        `}
      >
        {/* Status Headline */}
        <div className="flex items-start gap-3 mb-4">
          <div className={`p-2.5 rounded-lg ${stateConfig.iconBg}`}>
            <stateConfig.Icon className={`w-5 h-5 ${stateConfig.iconColor}`} />
          </div>
          <div className="flex-1">
            <h3 className={`font-display font-semibold text-lg leading-tight ${stateConfig.textColor}`}>
              {explanation.headline.emoji} {explanation.headline.text}
            </h3>
            
            {/* Confidence Indicator (subtle) */}
            <div className="flex items-center gap-2 mt-1.5">
              <ConfidenceIndicator 
                state={explanation.inference.state}
                confidence={explanation.inference.confidence}
              />
            </div>
          </div>
        </div>

        {/* One-sentence Summary (Reassurance) */}
        <p className="text-sentinel-text leading-relaxed mb-5">
          {explanation.summary}
        </p>

        {/* ===== TOGGLE SECTIONS ===== */}
        <div className="space-y-3">
          {/* Toggle: Why Securnex flagged this */}
          {explanation.triggerSignals.length > 0 && (
            <ToggleSection
              title={explanation.triggerToggleTitle}
              subtitle={`${explanation.triggerSignals.length} indicator${explanation.triggerSignals.length !== 1 ? 's' : ''}`}
              icon={<Eye className="w-4 h-4" />}
              isExpanded={triggersExpanded}
              onToggle={() => setTriggersExpanded(!triggersExpanded)}
              variant="warning"
            >
              <div className="space-y-3">
                {explanation.triggerSignals.map((signal) => (
                  <TriggerSignalItem key={signal.id} signal={signal} />
                ))}
              </div>
            </ToggleSection>
          )}

          {/* Toggle: What Securnex did NOT detect */}
          {explanation.absenceSignals.length > 0 && (
            <ToggleSection
              title={explanation.absenceToggleTitle}
              subtitle={`${explanation.absenceSignals.filter(s => s.importance === 'CRITICAL' || s.importance === 'HIGH').length} key safety indicators`}
              icon={<EyeOff className="w-4 h-4" />}
              isExpanded={absencesExpanded}
              onToggle={() => setAbsencesExpanded(!absencesExpanded)}
              variant="safe"
            >
              <div className="space-y-2.5">
                {explanation.absenceSignals.map((signal) => (
                  <AbsenceSignalItem key={signal.id} signal={signal} />
                ))}
              </div>
            </ToggleSection>
          )}

          {/* Toggle: What we're uncertain about (only for non-confirmed states) */}
          {explanation.inference.state !== 'CONFIRMED_COMPROMISE' && 
           explanation.inference.state !== 'NO_ISSUES_DETECTED' &&
           explanation.inference.uncertainties.length > 0 && (
            <ToggleSection
              title="What we're uncertain about"
              subtitle="Transparency"
              icon={<HelpCircle className="w-4 h-4" />}
              isExpanded={uncertaintiesExpanded}
              onToggle={() => setUncertaintiesExpanded(!uncertaintiesExpanded)}
              variant="neutral"
            >
              <div className="space-y-2">
                {explanation.inference.uncertainties.map((uncertainty, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-sm">
                    <span className="text-gray-500 mt-0.5">•</span>
                    <span className="text-sentinel-muted">{uncertainty}</span>
                  </div>
                ))}
              </div>
            </ToggleSection>
          )}
        </div>

        {/* Attacker Control Disclaimer (for non-confirmed states) */}
        {!explanation.inference.canClaimAttackerControl && 
         explanation.triggerSignals.length > 0 && (
          <div className="mt-4 p-3 rounded-lg bg-blue-500/5 border border-blue-500/20">
            <div className="flex items-start gap-2">
              <Info className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-blue-300/80 leading-relaxed">
                <strong>Important:</strong> While suspicious activity was detected, 
                Securnex has <em>not</em> found direct evidence of attacker control 
                over this wallet. The activity may be user-initiated or circumstantial.
              </p>
            </div>
          </div>
        )}
      </motion.div>

      {/* ===== GUIDANCE SECTION ===== */}
      {showGuidance && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className={`
            glass-card rounded-xl p-4 border
            ${stateConfig.guidanceBorder}
          `}
        >
          <div className="flex items-start gap-3">
            <div className={`p-2 rounded-lg ${stateConfig.guidanceIconBg}`}>
              <Lightbulb className={`w-4 h-4 ${stateConfig.guidanceIconColor}`} />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <h4 className="font-semibold text-sm text-sentinel-text">Guidance</h4>
                <UrgencyBadge urgency={explanation.guidance.urgency} />
              </div>
              <p className="text-sm text-sentinel-muted mb-3">
                {explanation.guidance.mainGuidance}
              </p>
              
              {explanation.guidance.recommendedActions.length > 0 && (
                <ul className="space-y-1.5">
                  {explanation.guidance.recommendedActions.map((action, index) => (
                    <li key={index} className="flex items-center gap-2 text-sm text-sentinel-muted">
                      <div className={`w-1.5 h-1.5 rounded-full ${stateConfig.bulletColor}`} />
                      {action}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </motion.div>
      )}

      {/* ===== CERTAINTIES SECTION (for confirmed states) ===== */}
      {explanation.inference.canClaimAttackerControl && 
       explanation.inference.attackerControlEvidence && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="glass-card rounded-xl p-4 border border-red-500/30 bg-red-500/5"
        >
          <div className="flex items-start gap-3">
            <AlertOctagon className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
            <div>
              <h4 className="font-semibold text-sm text-red-400 mb-2">
                Why we are certain of compromise
              </h4>
              <ul className="space-y-1.5">
                {explanation.inference.attackerControlEvidence.map((evidence, index) => (
                  <li key={index} className="flex items-center gap-2 text-sm text-red-300/80">
                    <div className="w-1.5 h-1.5 rounded-full bg-red-400" />
                    {evidence}
                  </li>
                ))}
              </ul>
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
  subtitle?: string;
  icon: React.ReactNode;
  isExpanded: boolean;
  onToggle: () => void;
  variant: 'warning' | 'safe' | 'neutral';
  children: React.ReactNode;
}

function ToggleSection({
  title,
  subtitle,
  icon,
  isExpanded,
  onToggle,
  variant,
  children,
}: ToggleSectionProps) {
  const variantStyles = {
    warning: {
      bg: 'bg-amber-500/5',
      border: 'border-amber-500/20',
      hoverBorder: 'hover:border-amber-500/40',
      iconColor: 'text-amber-400',
      headerBg: 'bg-amber-500/10',
    },
    safe: {
      bg: 'bg-emerald-500/5',
      border: 'border-emerald-500/20',
      hoverBorder: 'hover:border-emerald-500/40',
      iconColor: 'text-emerald-400',
      headerBg: 'bg-emerald-500/10',
    },
    neutral: {
      bg: 'bg-gray-500/5',
      border: 'border-gray-500/20',
      hoverBorder: 'hover:border-gray-500/40',
      iconColor: 'text-gray-400',
      headerBg: 'bg-gray-500/10',
    },
  };

  const styles = variantStyles[variant];

  return (
    <div className={`rounded-lg border ${styles.border} ${styles.hoverBorder} transition-colors overflow-hidden`}>
      <button
        onClick={onToggle}
        className={`w-full flex items-center justify-between p-3 ${styles.headerBg}`}
      >
        <div className="flex items-center gap-2.5">
          <span className={styles.iconColor}>{icon}</span>
          <span className="text-sm font-medium text-sentinel-text">{title}</span>
          {subtitle && (
            <span className="text-xs text-sentinel-muted px-2 py-0.5 rounded-full bg-white/5">
              {subtitle}
            </span>
          )}
        </div>
        <motion.div
          animate={{ rotate: isExpanded ? 180 : 0 }}
          transition={{ duration: 0.2 }}
        >
          <ChevronDown className="w-4 h-4 text-sentinel-muted" />
        </motion.div>
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
            <div className={`p-4 ${styles.bg}`}>
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

function TriggerSignalItem({ signal }: { signal: TriggerSignal }) {
  const severityConfig = {
    CRITICAL: { color: 'text-red-400', bg: 'bg-red-500/10', icon: AlertOctagon },
    HIGH: { color: 'text-orange-400', bg: 'bg-orange-500/10', icon: AlertTriangle },
    MEDIUM: { color: 'text-amber-400', bg: 'bg-amber-500/10', icon: AlertTriangle },
    LOW: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', icon: Info },
  };

  const config = severityConfig[signal.severity];
  const IconComponent = config.icon;

  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-black/20">
      <div className={`p-1.5 rounded ${config.bg}`}>
        <IconComponent className={`w-3.5 h-3.5 ${config.color}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-sentinel-text leading-snug">
          {signal.description}
        </p>
        
        <div className="flex items-center gap-3 mt-2 text-xs">
          <span className={`${config.color}`}>
            {signal.severity.toLowerCase()} severity
          </span>
          <span className="text-sentinel-muted">
            {signal.confidence}% confidence
          </span>
          {signal.isDirectEvidence && (
            <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 text-[10px]">
              direct evidence
            </span>
          )}
        </div>

        {signal.reference && (
          <a
            href={signal.reference.explorerUrl || '#'}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 mt-2 text-xs text-blue-400 hover:text-blue-300"
          >
            <span className="font-mono">
              {signal.reference.value.slice(0, 10)}...{signal.reference.value.slice(-6)}
            </span>
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>
    </div>
  );
}

function AbsenceSignalItem({ signal }: { signal: AbsenceSignal }) {
  const importanceConfig = {
    CRITICAL: { color: 'text-emerald-400', checkColor: 'text-emerald-400' },
    HIGH: { color: 'text-green-400', checkColor: 'text-green-400' },
    MEDIUM: { color: 'text-teal-400', checkColor: 'text-teal-400' },
  };

  const config = importanceConfig[signal.importance];

  return (
    <div className="flex items-start gap-2.5">
      <CheckCircle className={`w-4 h-4 ${config.checkColor} mt-0.5 flex-shrink-0`} />
      <div className="flex-1">
        <p className="text-sm text-sentinel-text leading-snug">
          {signal.description}
        </p>
        <p className="text-xs text-sentinel-muted mt-0.5">
          {signal.importance.toLowerCase()} importance
        </p>
      </div>
    </div>
  );
}

// ============================================
// CONFIDENCE INDICATOR
// ============================================

function ConfidenceIndicator({ 
  state, 
  confidence 
}: { 
  state: InferenceState; 
  confidence: number;
}) {
  const stateLabels: Record<InferenceState, { label: string; color: string }> = {
    CONFIRMED_COMPROMISE: { label: 'Confirmed', color: 'text-red-400 bg-red-500/20' },
    SUSPICIOUS_UNCONFIRMED: { label: 'Suspicious', color: 'text-amber-400 bg-amber-500/20' },
    MONITORING_RECOMMENDED: { label: 'Uncertain', color: 'text-yellow-400 bg-yellow-500/20' },
    INFORMATIONAL_ONLY: { label: 'Historical', color: 'text-blue-400 bg-blue-500/20' },
    NO_ISSUES_DETECTED: { label: 'Clear', color: 'text-emerald-400 bg-emerald-500/20' },
  };

  const { label, color } = stateLabels[state];

  return (
    <div className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs ${color}`}>
      <span className="font-medium">{label}</span>
      <span className="opacity-60">({confidence}%)</span>
    </div>
  );
}

// ============================================
// URGENCY BADGE
// ============================================

function UrgencyBadge({ urgency }: { urgency: 'immediate' | 'soon' | 'when-convenient' | 'optional' }) {
  const config = {
    immediate: { text: 'Immediate', color: 'bg-red-500/20 text-red-400' },
    soon: { text: 'Soon', color: 'bg-orange-500/20 text-orange-400' },
    'when-convenient': { text: 'When convenient', color: 'bg-blue-500/20 text-blue-400' },
    optional: { text: 'Optional', color: 'bg-gray-500/20 text-gray-400' },
  };

  const { text, color } = config[urgency];

  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded ${color}`}>
      {text}
    </span>
  );
}

// ============================================
// STATE CONFIGURATION
// ============================================

function getStateConfig(state: InferenceState) {
  const configs = {
    CONFIRMED_COMPROMISE: {
      Icon: AlertOctagon,
      borderColor: 'border-l-red-500',
      bgColor: 'bg-red-500/5',
      iconBg: 'bg-red-500/10',
      iconColor: 'text-red-400',
      textColor: 'text-red-400',
      bulletColor: 'bg-red-400',
      guidanceBorder: 'border-red-500/30',
      guidanceIconBg: 'bg-red-500/10',
      guidanceIconColor: 'text-red-400',
    },
    SUSPICIOUS_UNCONFIRMED: {
      Icon: AlertTriangle,
      borderColor: 'border-l-orange-500',
      bgColor: 'bg-orange-500/5',
      iconBg: 'bg-orange-500/10',
      iconColor: 'text-orange-400',
      textColor: 'text-orange-400',
      bulletColor: 'bg-orange-400',
      guidanceBorder: 'border-orange-500/30',
      guidanceIconBg: 'bg-orange-500/10',
      guidanceIconColor: 'text-orange-400',
    },
    MONITORING_RECOMMENDED: {
      Icon: Info,
      borderColor: 'border-l-yellow-500',
      bgColor: 'bg-yellow-500/5',
      iconBg: 'bg-yellow-500/10',
      iconColor: 'text-yellow-400',
      textColor: 'text-yellow-400',
      bulletColor: 'bg-yellow-400',
      guidanceBorder: 'border-yellow-500/30',
      guidanceIconBg: 'bg-yellow-500/10',
      guidanceIconColor: 'text-yellow-400',
    },
    INFORMATIONAL_ONLY: {
      Icon: Info,
      borderColor: 'border-l-blue-500',
      bgColor: 'bg-blue-500/5',
      iconBg: 'bg-blue-500/10',
      iconColor: 'text-blue-400',
      textColor: 'text-blue-400',
      bulletColor: 'bg-blue-400',
      guidanceBorder: 'border-blue-500/30',
      guidanceIconBg: 'bg-blue-500/10',
      guidanceIconColor: 'text-blue-400',
    },
    NO_ISSUES_DETECTED: {
      Icon: ShieldCheck,
      borderColor: 'border-l-emerald-500',
      bgColor: 'bg-emerald-500/5',
      iconBg: 'bg-emerald-500/10',
      iconColor: 'text-emerald-400',
      textColor: 'text-emerald-400',
      bulletColor: 'bg-emerald-400',
      guidanceBorder: 'border-emerald-500/30',
      guidanceIconBg: 'bg-emerald-500/10',
      guidanceIconColor: 'text-emerald-400',
    },
  };

  return configs[state];
}

// ============================================
// COMPACT VARIANT
// ============================================

export function CompactEvidenceExplanation({ 
  explanation 
}: { 
  explanation: UncertaintyAwareExplanation;
}) {
  const stateConfig = getStateConfig(explanation.inference.state);
  const triggerCount = explanation.triggerSignals.length;
  const absenceCount = explanation.absenceSignals.filter(
    s => s.importance === 'CRITICAL' || s.importance === 'HIGH'
  ).length;

  return (
    <div className={`
      flex items-center gap-3 p-3.5 rounded-lg 
      ${stateConfig.bgColor} border border-sentinel-border
    `}>
      <stateConfig.Icon className={`w-5 h-5 ${stateConfig.iconColor}`} />
      <div className="flex-1 min-w-0">
        <div className={`font-medium text-sm ${stateConfig.textColor} truncate`}>
          {explanation.headline.emoji} {explanation.headline.text}
        </div>
        <div className="text-xs text-sentinel-muted mt-0.5">
          {triggerCount} concern{triggerCount !== 1 ? 's' : ''} • {absenceCount} safety indicators
        </div>
      </div>
      <ConfidenceIndicator 
        state={explanation.inference.state} 
        confidence={explanation.inference.confidence} 
      />
    </div>
  );
}

// ============================================
// INLINE BADGE VARIANT
// ============================================

export function EvidenceExplanationBadge({ 
  explanation,
  size = 'md',
}: { 
  explanation: UncertaintyAwareExplanation;
  size?: 'sm' | 'md';
}) {
  const stateConfig = getStateConfig(explanation.inference.state);
  const sizeClasses = size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-1.5 text-sm';

  const stateLabel: Record<InferenceState, string> = {
    CONFIRMED_COMPROMISE: 'Compromised',
    SUSPICIOUS_UNCONFIRMED: 'Suspicious',
    MONITORING_RECOMMENDED: 'Monitor',
    INFORMATIONAL_ONLY: 'Info',
    NO_ISSUES_DETECTED: 'Safe',
  };

  return (
    <div className={`
      inline-flex items-center gap-1.5 rounded-full 
      ${stateConfig.bgColor} ${sizeClasses}
    `}>
      <span>{explanation.headline.emoji}</span>
      <span className={`font-medium ${stateConfig.textColor}`}>
        {stateLabel[explanation.inference.state]}
      </span>
    </div>
  );
}

export default EvidenceAwareExplanation;
