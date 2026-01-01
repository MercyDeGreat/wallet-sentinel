'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowRight,
  ExternalLink,
  Copy,
  AlertCircle,
  Info,
  Zap,
  Lock,
  Wallet,
  RefreshCw,
} from 'lucide-react';
import { RecoveryPlan as RecoveryPlanType, RecoveryStep, SecurityRecommendation, RiskLevel } from '@/types';

interface RecoveryPlanProps {
  plan?: RecoveryPlanType;
  recommendations: SecurityRecommendation[];
}

export function RecoveryPlan({ plan, recommendations }: RecoveryPlanProps) {
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());

  const toggleStep = (order: number) => {
    const newCompleted = new Set(completedSteps);
    if (newCompleted.has(order)) {
      newCompleted.delete(order);
    } else {
      newCompleted.add(order);
    }
    setCompletedSteps(newCompleted);
  };

  if (!plan && recommendations.length === 0) {
    return (
      <div className="glass-card rounded-xl p-12 text-center">
        <CheckCircle className="w-16 h-16 text-status-safe mx-auto mb-4" />
        <h3 className="font-display font-semibold text-xl mb-2">No Recovery Needed</h3>
        <p className="text-sentinel-muted max-w-md mx-auto">
          Your wallet appears to be secure. No immediate recovery actions are required.
          Continue practicing good security hygiene.
        </p>
      </div>
    );
  }

  const immediateRecs = recommendations.filter((r) => r.category === 'IMMEDIATE');
  const shortTermRecs = recommendations.filter((r) => r.category === 'SHORT_TERM');
  const longTermRecs = recommendations.filter((r) => r.category === 'LONG_TERM');

  return (
    <div className="space-y-6">
      {/* Urgency Banner */}
      {plan && (
        <UrgencyBanner urgency={plan.urgencyLevel} estimatedTime={plan.estimatedTimeMinutes} />
      )}

      {/* Warnings */}
      {plan && plan.warnings.length > 0 && (
        <div className="glass-card rounded-xl p-4 border-l-4 border-l-status-warning">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-status-warning flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="font-medium text-status-warning mb-2">Important Warnings</h4>
              <ul className="space-y-2">
                {plan.warnings.map((warning, index) => (
                  <li key={index} className="text-sm text-sentinel-muted flex items-start gap-2">
                    <span className="text-status-warning">•</span>
                    {warning}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Recovery Steps */}
      {plan && plan.steps.length > 0 && (
        <div className="glass-card rounded-xl p-6">
          <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
            <Zap className="w-5 h-5 text-blue-400" />
            Recovery Steps
          </h3>

          <div className="space-y-4">
            {plan.steps.map((step, index) => (
              <RecoveryStepCard
                key={step.order}
                step={step}
                isCompleted={completedSteps.has(step.order)}
                onToggle={() => toggleStep(step.order)}
                isFirst={index === 0}
                isLast={index === plan.steps.length - 1}
              />
            ))}
          </div>

          {/* Progress */}
          <div className="mt-6 pt-4 border-t border-sentinel-border">
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-sentinel-muted">Progress</span>
              <span className="text-sentinel-text">
                {completedSteps.size} / {plan.steps.length} completed
              </span>
            </div>
            <div className="h-2 bg-sentinel-surface rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-blue-500 to-cyan-500"
                initial={{ width: 0 }}
                animate={{ width: `${(completedSteps.size / plan.steps.length) * 100}%` }}
                transition={{ duration: 0.5 }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Fresh Wallet Notice */}
      {plan?.safeWalletRequired && (
        <div className="glass-card rounded-xl p-6 border-l-4 border-l-blue-500">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-xl bg-blue-500/20">
              <Wallet className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h4 className="font-display font-semibold mb-2">Fresh Wallet Required</h4>
              <p className="text-sm text-sentinel-muted mb-4">
                You will need a new, secure wallet to transfer your assets to. This wallet should:
              </p>
              <ul className="space-y-2 text-sm">
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-status-safe" />
                  <span>Use a completely new seed phrase</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-status-safe" />
                  <span>Be generated on a secure, clean device</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-status-safe" />
                  <span>Never have been used before</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-status-safe" />
                  <span>Ideally use a hardware wallet</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Recommendations by Category */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {immediateRecs.length > 0 && (
          <RecommendationSection
            title="Immediate Actions"
            icon={<AlertCircle className="w-5 h-5 text-status-danger" />}
            recommendations={immediateRecs}
            color="danger"
          />
        )}
        {shortTermRecs.length > 0 && (
          <RecommendationSection
            title="Short-Term"
            icon={<Clock className="w-5 h-5 text-status-warning" />}
            recommendations={shortTermRecs}
            color="warning"
          />
        )}
        {longTermRecs.length > 0 && (
          <RecommendationSection
            title="Long-Term"
            icon={<Shield className="w-5 h-5 text-blue-400" />}
            recommendations={longTermRecs}
            color="info"
          />
        )}
      </div>

      {/* Transaction Simulation Notice */}
      <div className="glass-card rounded-xl p-4 border-l-4 border-l-cyan-500">
        <div className="flex items-start gap-3">
          <RefreshCw className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-medium text-cyan-400 mb-1">Transaction Simulation</h4>
            <p className="text-sm text-sentinel-muted">
              Before executing any recovery transactions, we recommend using transaction simulation
              to verify the outcome. This helps detect if a drainer contract might intercept your
              recovery attempt.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function UrgencyBanner({ urgency, estimatedTime }: { urgency: RiskLevel; estimatedTime: number }) {
  const config = {
    CRITICAL: {
      bg: 'bg-status-danger-bg',
      border: 'border-status-danger',
      text: 'text-status-danger',
      label: 'CRITICAL - Act Immediately',
      icon: AlertCircle,
    },
    HIGH: {
      bg: 'bg-orange-500/10',
      border: 'border-orange-500',
      text: 'text-orange-400',
      label: 'HIGH PRIORITY',
      icon: AlertTriangle,
    },
    MEDIUM: {
      bg: 'bg-status-warning-bg',
      border: 'border-status-warning',
      text: 'text-status-warning',
      label: 'MEDIUM PRIORITY',
      icon: Info,
    },
    LOW: {
      bg: 'bg-blue-500/10',
      border: 'border-blue-500',
      text: 'text-blue-400',
      label: 'LOW PRIORITY',
      icon: Info,
    },
  };

  const { bg, border, text, label, icon: Icon } = config[urgency];

  return (
    <div className={`${bg} border ${border} rounded-xl p-4`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Icon className={`w-6 h-6 ${text}`} />
          <div>
            <div className={`font-display font-bold ${text}`}>{label}</div>
            <div className="text-sm text-sentinel-muted">Recovery plan ready</div>
          </div>
        </div>
        <div className="text-right">
          <div className="flex items-center gap-2 text-sentinel-muted">
            <Clock className="w-4 h-4" />
            <span className="text-sm">Est. {estimatedTime} min</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function RecoveryStepCard({
  step,
  isCompleted,
  onToggle,
  isFirst,
  isLast,
}: {
  step: RecoveryStep;
  isCompleted: boolean;
  onToggle: () => void;
  isFirst: boolean;
  isLast: boolean;
}) {
  const priorityConfig = {
    IMMEDIATE: { bg: 'bg-status-danger-bg', text: 'text-status-danger', label: 'Immediate' },
    HIGH: { bg: 'bg-orange-500/10', text: 'text-orange-400', label: 'High' },
    MEDIUM: { bg: 'bg-status-warning-bg', text: 'text-status-warning', label: 'Medium' },
    LOW: { bg: 'bg-blue-500/10', text: 'text-blue-400', label: 'Low' },
  };

  const priority = priorityConfig[step.priority];

  const actionIcons = {
    REVOKE_APPROVAL: Lock,
    TRANSFER_ASSETS: ArrowRight,
    CLOSE_ACCOUNT: AlertCircle,
    DELEGATE_REVOKE: Lock,
    MANUAL: Info,
  };

  const ActionIcon = actionIcons[step.action.type] || Info;

  return (
    <div className="relative">
      {/* Connection Line */}
      {!isLast && (
        <div className="absolute left-[22px] top-[52px] bottom-0 w-0.5 bg-sentinel-border" />
      )}

      <div
        className={`relative flex items-start gap-4 p-4 rounded-xl transition-all ${
          isCompleted ? 'bg-status-safe-bg/50' : 'bg-sentinel-surface hover:bg-sentinel-elevated'
        }`}
      >
        {/* Step Number / Checkbox */}
        <button
          onClick={onToggle}
          className={`w-11 h-11 rounded-full flex items-center justify-center flex-shrink-0 transition-all ${
            isCompleted
              ? 'bg-status-safe text-white'
              : 'bg-sentinel-elevated border-2 border-sentinel-border'
          }`}
        >
          {isCompleted ? (
            <CheckCircle className="w-5 h-5" />
          ) : (
            <span className="font-bold">{step.order}</span>
          )}
        </button>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className={`font-medium ${isCompleted ? 'line-through text-sentinel-muted' : ''}`}>
              {step.title}
            </h4>
            <span className={`px-2 py-0.5 text-xs rounded ${priority.bg} ${priority.text}`}>
              {priority.label}
            </span>
          </div>
          <p className="text-sm text-sentinel-muted">{step.description}</p>

          {/* Action Button */}
          {!isCompleted && step.action.type !== 'MANUAL' && (
            <button className="mt-3 flex items-center gap-2 px-4 py-2 bg-sentinel-primary text-white text-sm rounded-lg hover:bg-blue-500 transition-colors">
              <ActionIcon className="w-4 h-4" />
              Execute Step
            </button>
          )}

          {/* Gas Estimate */}
          {step.estimatedGasCost && (
            <div className="mt-2 text-xs text-sentinel-muted">
              Estimated gas: {step.estimatedGasCost}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function RecommendationSection({
  title,
  icon,
  recommendations,
  color,
}: {
  title: string;
  icon: React.ReactNode;
  recommendations: SecurityRecommendation[];
  color: 'danger' | 'warning' | 'info';
}) {
  const borderColors = {
    danger: 'border-t-status-danger',
    warning: 'border-t-status-warning',
    info: 'border-t-blue-500',
  };

  return (
    <div className={`glass-card rounded-xl overflow-hidden border-t-4 ${borderColors[color]}`}>
      <div className="p-4 border-b border-sentinel-border">
        <h4 className="font-display font-semibold flex items-center gap-2">
          {icon}
          {title}
        </h4>
      </div>
      <div className="p-4 space-y-3">
        {recommendations.map((rec) => (
          <div key={rec.id} className="p-3 bg-sentinel-surface rounded-lg">
            <h5 className="font-medium text-sm mb-1">{rec.title}</h5>
            <p className="text-xs text-sentinel-muted">{rec.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}


