'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  CheckCircle,
  ExternalLink,
  Copy,
  ChevronRight,
  Clock,
  TrendingUp,
  Layers,
  Info,
} from 'lucide-react';
import { WalletAnalysisResult, SecurityStatus, RiskLevel } from '@/types';
import { ThreatCard } from './ThreatCard';
import { ApprovalsDashboard } from './ApprovalsDashboard';
import { RecoveryPlan } from './RecoveryPlan';
import { EducationalPanel } from './EducationalPanel';

interface SecurityDashboardProps {
  result: WalletAnalysisResult;
}

type Tab = 'overview' | 'threats' | 'approvals' | 'recovery' | 'education';

export function SecurityDashboard({ result }: SecurityDashboardProps) {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [copied, setCopied] = useState(false);

  // Safe array guards - ensure arrays are always defined
  const safeThreats = Array.isArray(result?.detectedThreats) ? result.detectedThreats : [];
  const safeApprovals = Array.isArray(result?.approvals) ? result.approvals : [];
  const safeRecommendations = Array.isArray(result?.recommendations) ? result.recommendations : [];

  const copyAddress = () => {
    navigator.clipboard.writeText(result?.address || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'threats', label: 'Threats', count: result.detectedThreats.length },
    { id: 'approvals', label: 'Approvals', count: result.approvals.length },
    { id: 'recovery', label: 'Recovery' },
    { id: 'education', label: 'Learn' },
  ];

  return (
    <div className="space-y-6">
      {/* Status Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`glass-card rounded-2xl p-6 ${getStatusBorderClass(result.securityStatus)}`}
      >
        <div className="flex flex-col md:flex-row md:items-center gap-4">
          {/* Status Badge */}
          <StatusBadge 
            status={result.securityStatus} 
            chain={result.chain}
            chainAwareStatus={result.chainAwareStatus}
          />

          {/* Wallet Info */}
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-sm text-sentinel-muted truncate max-w-[300px]">
                {result.address}
              </span>
              <button
                onClick={copyAddress}
                className="p-1 hover:bg-sentinel-surface rounded transition-colors"
                title={copied ? 'Copied!' : 'Copy address'}
              >
                {copied ? (
                  <CheckCircle className="w-4 h-4 text-status-safe" />
                ) : (
                  <Copy className="w-4 h-4 text-sentinel-muted" />
                )}
              </button>
              <a
                href={getExplorerUrl(result.chain, result.address)}
                target="_blank"
                rel="noopener noreferrer"
                className="p-1 hover:bg-sentinel-surface rounded transition-colors"
                title="View on explorer"
              >
                <ExternalLink className="w-4 h-4 text-sentinel-muted" />
              </a>
            </div>
            <p className="text-sentinel-text">{result.summary}</p>
          </div>

          {/* Risk Score */}
          <div className="flex flex-col items-end">
            <div className="text-sm text-sentinel-muted mb-1">Risk Score</div>
            <div className="flex items-center gap-2">
              <RiskMeter score={result.riskScore} />
              <span className={`text-2xl font-bold ${getRiskScoreColor(result.riskScore)}`}>
                {result.riskScore}
              </span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Solana Disclaimer - CRITICAL for user awareness */}
      {result.chain === 'solana' && result.chainDisclaimer && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="glass-card rounded-xl p-4 border-l-4 border-l-blue-500 bg-blue-500/5"
        >
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div>
              <h4 className="font-semibold text-sm text-blue-400 mb-1">
                Solana Analysis Limitations
              </h4>
              <p className="text-sm text-sentinel-muted">
                {result.chainDisclaimer}
              </p>
              {result.analysisMetadata?.limitations && result.analysisMetadata.limitations.length > 0 && (
                <ul className="mt-2 text-xs text-sentinel-muted space-y-1">
                  {result.analysisMetadata.limitations.slice(0, 3).map((limitation, index) => (
                    <li key={index} className="flex items-center gap-1.5">
                      <span className="w-1 h-1 bg-blue-400/50 rounded-full" />
                      {limitation}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </motion.div>
      )}

      {/* Secondary Tags - Additional context that does NOT affect risk score */}
      {result.chainAwareStatus?.secondaryTags && result.chainAwareStatus.secondaryTags.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.07 }}
          className="flex flex-wrap gap-2"
        >
          {result.chainAwareStatus.secondaryTags.map((tagInfo, index) => (
            <div
              key={index}
              className={`
                inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium
                ${tagInfo.severity === 'WARNING' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                  tagInfo.severity === 'CAUTION' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                  'bg-blue-500/10 text-blue-400 border border-blue-500/20'}
              `}
              title={tagInfo.description}
            >
              <Info className="w-3.5 h-3.5" />
              <span>{tagInfo.displayText}</span>
              <span className="text-[10px] opacity-60 ml-1">(Does not affect risk score)</span>
            </div>
          ))}
        </motion.div>
      )}

      {/* Quick Stats */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4"
      >
        <StatCard
          icon={<AlertTriangle className="w-5 h-5" />}
          label="Active Threats"
          value={safeThreats.filter((t) => t?.ongoingRisk).length}
          color={safeThreats.filter((t) => t?.ongoingRisk).length > 0 ? 'danger' : 'safe'}
        />
        <StatCard
          icon={<Layers className="w-5 h-5" />}
          label="Token Approvals"
          value={safeApprovals.length}
          color={safeApprovals.filter((a) => a?.riskLevel === 'HIGH' || a?.riskLevel === 'CRITICAL').length > 0 ? 'warning' : 'info'}
        />
        <StatCard
          icon={<AlertCircle className="w-5 h-5" />}
          label="High Risk Approvals"
          value={safeApprovals.filter((a) => a?.riskLevel === 'HIGH' || a?.riskLevel === 'CRITICAL').length}
          color={safeApprovals.filter((a) => a?.riskLevel === 'HIGH' || a?.riskLevel === 'CRITICAL').length > 0 ? 'danger' : 'safe'}
        />
        <StatCard
          icon={<Clock className="w-5 h-5" />}
          label="Analysis Time"
          value={new Date(result.timestamp).toLocaleTimeString()}
          color="info"
          isText
        />
      </motion.div>

      {/* Navigation Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="flex gap-2 overflow-x-auto pb-2"
      >
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg whitespace-nowrap transition-all ${
              activeTab === tab.id
                ? 'bg-sentinel-primary text-white'
                : 'bg-sentinel-surface hover:bg-sentinel-elevated text-sentinel-text'
            }`}
          >
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className={`px-2 py-0.5 rounded-full text-xs ${
                activeTab === tab.id
                  ? 'bg-white/20'
                  : 'bg-sentinel-border'
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </motion.div>

      {/* Tab Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {activeTab === 'overview' && (
          <OverviewTab result={result} onNavigate={setActiveTab} />
        )}
        {activeTab === 'threats' && (
          <div className="space-y-4">
            {safeThreats.length === 0 ? (
              result.chain === 'solana' ? (
                <EmptyState
                  icon={<Shield className="w-12 h-12 text-blue-400" />}
                  title="No On-Chain Threats Detected"
                  description="No detectable on-chain security threats were found. Note: Solana compromises often occur off-chain and may not leave visible traces."
                />
              ) : (
                <EmptyState
                  icon={<Shield className="w-12 h-12 text-status-safe" />}
                  title="No Threats Detected"
                  description="No known security threats were found for this wallet."
                />
              )
            ) : (
              safeThreats.map((threat) => (
                <ThreatCard key={threat?.id} threat={threat} chain={result?.chain || 'ethereum'} />
              ))
            )}
          </div>
        )}
        {activeTab === 'approvals' && (
          <ApprovalsDashboard approvals={safeApprovals} chain={result?.chain || 'ethereum'} />
        )}
        {activeTab === 'recovery' && (
          <RecoveryPlan plan={result?.recoveryPlan} recommendations={safeRecommendations} />
        )}
        {activeTab === 'education' && (
          <EducationalPanel content={result?.educationalContent} chain={result?.chain || 'ethereum'} />
        )}
      </motion.div>
    </div>
  );
}

function OverviewTab({
  result,
  onNavigate,
}: {
  result: WalletAnalysisResult;
  onNavigate: (tab: Tab) => void;
}) {
  // Safe array guards for nested component
  const safeThreats = Array.isArray(result?.detectedThreats) ? result.detectedThreats.filter(t => t != null) : [];
  const safeApprovals = Array.isArray(result?.approvals) ? result.approvals.filter(a => a != null) : [];
  const safeRecommendations = Array.isArray(result?.recommendations) ? result.recommendations.filter(r => r != null) : [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* PREVIOUSLY_COMPROMISED Banner - Historical compromise, no active threat */}
      {result?.securityStatus === 'PREVIOUSLY_COMPROMISED' && (
        <div className="lg:col-span-2">
          <div className="glass-card rounded-xl p-6 border-l-4 border-amber-500 bg-amber-500/5">
            <h3 className="font-display font-semibold text-lg mb-3 flex items-center gap-2 text-amber-400">
              <Clock className="w-5 h-5" />
              Previously Compromised - No Active Threat
            </h3>
            <p className="text-sentinel-muted mb-4">
              This wallet experienced a security incident in the past, but all malicious access has been revoked.
              The wallet is currently safe to use with normal caution.
            </p>
            <div className="bg-sentinel-surface rounded-lg p-4 space-y-2">
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle className="w-4 h-4 text-status-safe" />
                <span className="text-sentinel-muted">All malicious approvals revoked</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle className="w-4 h-4 text-status-safe" />
                <span className="text-sentinel-muted">No active drainer access</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle className="w-4 h-4 text-status-safe" />
                <span className="text-sentinel-muted">No ongoing drain activity</span>
              </div>
            </div>
            <p className="text-xs text-sentinel-muted mt-3">
              💡 Tip: Continue to monitor your approvals regularly and revoke any suspicious permissions.
            </p>
          </div>
        </div>
      )}
      
      {/* ACTIVELY_COMPROMISED Banner - Urgent action required */}
      {result?.securityStatus === 'ACTIVELY_COMPROMISED' && (
        <div className="lg:col-span-2">
          <div className="glass-card rounded-xl p-6 border-l-4 border-status-danger bg-status-danger/10">
            <h3 className="font-display font-semibold text-lg mb-3 flex items-center gap-2 text-status-danger">
              <AlertCircle className="w-5 h-5" />
              🚨 ACTIVELY COMPROMISED - Immediate Action Required
            </h3>
            <p className="text-sentinel-text mb-4">
              This wallet has active malicious access. Attackers can still drain your assets.
              Take action IMMEDIATELY to secure your funds.
            </p>
            <div className="bg-sentinel-surface rounded-lg p-4 space-y-2">
              <div className="flex items-center gap-2 text-sm text-status-danger">
                <AlertTriangle className="w-4 h-4" />
                <span>Malicious approvals are still active</span>
              </div>
            </div>
            <button
              onClick={() => onNavigate('recovery')}
              className="mt-4 px-4 py-2 bg-status-danger text-white rounded-lg hover:bg-red-600 transition-colors font-semibold"
            >
              View Recovery Plan →
            </button>
          </div>
        </div>
      )}
      
      {/* Critical Actions - For other non-safe statuses */}
      {result?.securityStatus !== 'SAFE' && 
       result?.securityStatus !== 'PREVIOUSLY_COMPROMISED' && 
       result?.securityStatus !== 'ACTIVELY_COMPROMISED' && (
        <div className="lg:col-span-2">
          <div className="glass-card rounded-xl p-6 border-l-4 border-status-danger">
            <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-status-danger" />
              Recommended Actions
            </h3>
            <div className="space-y-3">
              {safeRecommendations
                .filter((r) => r?.category === 'IMMEDIATE')
                .slice(0, 3)
                .map((rec) => (
                  <div
                    key={rec.id}
                    className="flex items-center gap-3 p-3 bg-sentinel-surface rounded-lg"
                  >
                    <div className={`w-2 h-2 rounded-full ${getPriorityColor(rec.priority)}`} />
                    <div className="flex-1">
                      <div className="font-medium text-sm">{rec.title}</div>
                      <div className="text-xs text-sentinel-muted">{rec.description}</div>
                    </div>
                    {rec.actionable && (
                      <button
                        onClick={() => onNavigate('recovery')}
                        className="px-3 py-1 text-xs bg-sentinel-primary text-white rounded hover:bg-blue-500 transition-colors"
                      >
                        Take Action
                      </button>
                    )}
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* Threats Summary */}
      <div className="glass-card rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-semibold">Detected Threats</h3>
          {result.detectedThreats.length > 0 && (
            <button
              onClick={() => onNavigate('threats')}
              className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
            >
              View All <ChevronRight className="w-4 h-4" />
            </button>
          )}
        </div>
        {safeThreats.length === 0 ? (
          <div className="text-center py-8">
            {result.chain === 'solana' ? (
              <>
                <Shield className="w-12 h-12 text-blue-400 mx-auto mb-3" />
                <p className="text-sentinel-muted">No on-chain threats detected</p>
                <p className="text-xs text-sentinel-muted mt-1">
                  Off-chain attacks may not be visible
                </p>
              </>
            ) : (
              <>
                <CheckCircle className="w-12 h-12 text-status-safe mx-auto mb-3" />
                <p className="text-sentinel-muted">No threats detected</p>
              </>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {safeThreats.slice(0, 3).map((threat) => (
              <div
                key={threat.id}
                className="flex items-center gap-3 p-3 bg-sentinel-surface rounded-lg"
              >
                <div className={`w-2 h-2 rounded-full ${getSeverityDotColor(threat.severity)}`} />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-sm truncate">{threat.title}</div>
                  <div className="text-xs text-sentinel-muted">{threat.type.replace(/_/g, ' ')}</div>
                </div>
                {threat.ongoingRisk && (
                  <span className="px-2 py-1 text-xs bg-status-danger-bg text-status-danger rounded">
                    Active
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Approvals Summary */}
      <div className="glass-card rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-semibold">Token Approvals</h3>
          {safeApprovals.length > 0 && (
            <button
              onClick={() => onNavigate('approvals')}
              className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
            >
              Manage <ChevronRight className="w-4 h-4" />
            </button>
          )}
        </div>
        {safeApprovals.length === 0 ? (
          <div className="text-center py-8">
            <Shield className="w-12 h-12 text-status-safe mx-auto mb-3" />
            <p className="text-sentinel-muted">No active approvals</p>
          </div>
        ) : (
          <div className="space-y-2">
            {safeApprovals.slice(0, 4).map((approval) => (
              <div
                key={approval.id}
                className="flex items-center gap-3 p-3 bg-sentinel-surface rounded-lg"
              >
                <div className={`w-2 h-2 rounded-full ${getSeverityDotColor(approval.riskLevel)}`} />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-sm truncate">{approval.token.symbol}</div>
                  <div className="text-xs text-sentinel-muted font-mono truncate">
                    {approval.spender.slice(0, 10)}...{approval.spender.slice(-8)}
                  </div>
                </div>
                {approval.isUnlimited && (
                  <span className="px-2 py-1 text-xs bg-status-warning-bg text-status-warning rounded">
                    Unlimited
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatusBadge({ 
  status, 
  chain,
  chainAwareStatus 
}: { 
  status: SecurityStatus;
  chain?: string;
  chainAwareStatus?: import('@/types').ChainAwareSecurityLabel;
}) {
  // For Solana, use chain-aware labels to avoid false "SAFE" claims
  const isSolana = chain === 'solana';
  
  const config: Record<SecurityStatus, {
    icon: typeof CheckCircle;
    label: string;
    bg: string;
    border: string;
    text: string;
    dot: string;
  }> = {
    SAFE: {
      icon: isSolana ? Shield : CheckCircle, // Different icon for Solana
      label: isSolana 
        ? (chainAwareStatus?.shortLabel || 'NO RISK DETECTED')
        : 'SAFE',
      bg: isSolana ? 'bg-blue-500/10' : 'bg-status-safe-bg', // Different color for Solana
      border: isSolana ? 'border-blue-500/30' : 'border-status-safe/30',
      text: isSolana ? 'text-blue-400' : 'text-status-safe',
      dot: isSolana ? 'status-dot-info' : 'status-dot-safe',
    },
    PREVIOUSLY_COMPROMISED: {
      icon: Shield, // Shield with history indicator
      label: 'PREVIOUSLY COMPROMISED',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/30',
      text: 'text-amber-400',
      dot: 'status-dot-historical',
    },
    POTENTIALLY_COMPROMISED: {
      icon: AlertTriangle,
      label: 'POTENTIALLY COMPROMISED',
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/30',
      text: 'text-orange-400',
      dot: 'status-dot-warning',
    },
    AT_RISK: {
      icon: AlertTriangle,
      label: 'AT RISK',
      bg: 'bg-status-warning-bg',
      border: 'border-status-warning/30',
      text: 'text-status-warning',
      dot: 'status-dot-warning',
    },
    ACTIVELY_COMPROMISED: {
      icon: AlertCircle,
      label: 'ACTIVELY COMPROMISED',
      bg: 'bg-status-danger-bg',
      border: 'border-status-danger/30',
      text: 'text-status-danger',
      dot: 'status-dot-danger',
    },
    COMPROMISED: {
      icon: AlertCircle,
      label: 'COMPROMISED',
      bg: 'bg-status-danger-bg',
      border: 'border-status-danger/30',
      text: 'text-status-danger',
      dot: 'status-dot-danger',
    },
    INCOMPLETE_DATA: {
      icon: AlertCircle,
      label: 'INCOMPLETE SCAN',
      bg: 'bg-gray-500/10',
      border: 'border-gray-500/30',
      text: 'text-gray-400',
      dot: 'status-dot-neutral',
    },
  };

  const statusConfig = config[status] || config.SAFE; // Default to SAFE if unknown status (not AT_RISK to prevent false alarms)
  const { icon: Icon, label, bg, border, text, dot } = statusConfig;

  return (
    <div className={`flex items-center gap-3 px-4 py-3 rounded-xl ${bg} border ${border}`}>
      <div className={`status-dot ${dot}`} />
      <Icon className={`w-6 h-6 ${text}`} />
      <span className={`font-display font-bold text-lg ${text}`}>{label}</span>
    </div>
  );
}

function RiskMeter({ score }: { score: number }) {
  const getColor = () => {
    if (score >= 70) return 'bg-status-danger';
    if (score >= 30) return 'bg-status-warning';
    return 'bg-status-safe';
  };

  return (
    <div className="w-24 risk-meter">
      <motion.div
        className={`risk-meter-fill ${getColor()}`}
        initial={{ width: 0 }}
        animate={{ width: `${score}%` }}
        transition={{ duration: 1, ease: 'easeOut' }}
      />
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  color,
  isText,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  color: 'safe' | 'warning' | 'danger' | 'info';
  isText?: boolean;
}) {
  const colorClasses = {
    safe: 'text-status-safe',
    warning: 'text-status-warning',
    danger: 'text-status-danger',
    info: 'text-blue-400',
  };

  return (
    <div className="glass-card rounded-xl p-4">
      <div className="flex items-center gap-2 text-sentinel-muted mb-2">
        {icon}
        <span className="text-xs">{label}</span>
      </div>
      <div className={`${isText ? 'text-sm' : 'text-2xl'} font-bold ${colorClasses[color]}`}>
        {value}
      </div>
    </div>
  );
}

function EmptyState({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="glass-card rounded-xl p-12 text-center">
      <div className="flex justify-center mb-4">{icon}</div>
      <h3 className="font-display font-semibold text-lg mb-2">{title}</h3>
      <p className="text-sentinel-muted">{description}</p>
    </div>
  );
}

// Utility functions
function getStatusBorderClass(status: SecurityStatus): string {
  switch (status) {
    case 'SAFE':
      return 'border-l-4 border-l-status-safe';
    case 'POTENTIALLY_COMPROMISED':
      return 'border-l-4 border-l-orange-500';
    case 'AT_RISK':
      return 'border-l-4 border-l-status-warning';
    case 'COMPROMISED':
      return 'border-l-4 border-l-status-danger';
    default:
      return 'border-l-4 border-l-status-warning';
  }
}

function getRiskScoreColor(score: number): string {
  if (score >= 70) return 'text-status-danger';
  if (score >= 30) return 'text-status-warning';
  return 'text-status-safe';
}

function getPriorityColor(priority: RiskLevel): string {
  switch (priority) {
    case 'CRITICAL':
      return 'bg-status-danger';
    case 'HIGH':
      return 'bg-orange-500';
    case 'MEDIUM':
      return 'bg-status-warning';
    case 'LOW':
      return 'bg-blue-500';
  }
}

function getSeverityDotColor(severity: RiskLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-status-danger';
    case 'HIGH':
      return 'bg-orange-500';
    case 'MEDIUM':
      return 'bg-status-warning';
    case 'LOW':
      return 'bg-status-safe';
  }
}

function getExplorerUrl(chain: string, address: string): string {
  const explorers: Record<string, string> = {
    ethereum: 'https://etherscan.io/address/',
    base: 'https://basescan.org/address/',
    bnb: 'https://bscscan.com/address/',
    solana: 'https://solscan.io/account/',
  };
  return `${explorers[chain] || explorers.ethereum}${address}`;
}


