'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  CheckCircle,
  Shield,
  ExternalLink,
  Copy,
  Info,
  ChevronDown,
  AlertCircle as AlertIcon,
} from 'lucide-react';
import { TokenApproval, Chain, RiskLevel } from '@/types';

interface ApprovalsDashboardProps {
  approvals: TokenApproval[];
  chain: Chain;
}

export function ApprovalsDashboard({ approvals, chain }: ApprovalsDashboardProps) {
  const [filter, setFilter] = useState<'all' | 'high' | 'malicious'>('all');
  const [selectedApprovals, setSelectedApprovals] = useState<Set<string>>(new Set());

  const filteredApprovals = approvals.filter((approval) => {
    if (filter === 'high') {
      return approval.riskLevel === 'HIGH' || approval.riskLevel === 'CRITICAL';
    }
    if (filter === 'malicious') {
      return approval.isMalicious;
    }
    return true;
  });

  const toggleSelection = (id: string) => {
    const newSelection = new Set(selectedApprovals);
    if (newSelection.has(id)) {
      newSelection.delete(id);
    } else {
      newSelection.add(id);
    }
    setSelectedApprovals(newSelection);
  };

  const selectAllHighRisk = () => {
    const highRiskIds = approvals
      .filter((a) => a.riskLevel === 'HIGH' || a.riskLevel === 'CRITICAL' || a.isMalicious)
      .map((a) => a.id);
    setSelectedApprovals(new Set(highRiskIds));
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

  if (approvals.length === 0) {
    return (
      <div className="glass-card rounded-xl p-12 text-center">
        <Shield className="w-16 h-16 text-status-safe mx-auto mb-4" />
        <h3 className="font-display font-semibold text-xl mb-2">No Active Approvals</h3>
        <p className="text-sentinel-muted max-w-md mx-auto">
          This wallet has no active token approvals. This means no external contracts can spend tokens on your behalf.
        </p>
      </div>
    );
  }

  const highRiskCount = approvals.filter(
    (a) => a.riskLevel === 'HIGH' || a.riskLevel === 'CRITICAL'
  ).length;
  const maliciousCount = approvals.filter((a) => a.isMalicious).length;

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card rounded-xl p-4">
          <div className="text-sentinel-muted text-sm mb-1">Total Approvals</div>
          <div className="text-2xl font-bold">{approvals.length}</div>
        </div>
        <div className="glass-card rounded-xl p-4">
          <div className="text-sentinel-muted text-sm mb-1 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-status-warning" />
            High Risk
          </div>
          <div className="text-2xl font-bold text-status-warning">{highRiskCount}</div>
        </div>
        <div className="glass-card rounded-xl p-4">
          <div className="text-sentinel-muted text-sm mb-1 flex items-center gap-2">
            <AlertIcon className="w-4 h-4 text-status-danger" />
            Malicious
          </div>
          <div className="text-2xl font-bold text-status-danger">{maliciousCount}</div>
        </div>
      </div>

      {/* Warning Banner */}
      {(highRiskCount > 0 || maliciousCount > 0) && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 bg-status-warning-bg border border-status-warning/30 rounded-xl"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-status-warning flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="font-medium text-status-warning mb-1">Action Recommended</h4>
              <p className="text-sm text-sentinel-muted">
                {maliciousCount > 0
                  ? `You have ${maliciousCount} approval${maliciousCount > 1 ? 's' : ''} to known malicious contracts. Revoke these immediately.`
                  : `You have ${highRiskCount} high-risk approval${highRiskCount > 1 ? 's' : ''} including unlimited token approvals.`}
              </p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Toolbar */}
      <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
        {/* Filters */}
        <div className="flex gap-2">
          <FilterButton
            active={filter === 'all'}
            onClick={() => setFilter('all')}
            label="All"
            count={approvals.length}
          />
          <FilterButton
            active={filter === 'high'}
            onClick={() => setFilter('high')}
            label="High Risk"
            count={highRiskCount}
            color="warning"
          />
          <FilterButton
            active={filter === 'malicious'}
            onClick={() => setFilter('malicious')}
            label="Malicious"
            count={maliciousCount}
            color="danger"
          />
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          {highRiskCount > 0 && (
            <button
              onClick={selectAllHighRisk}
              className="px-3 py-2 text-sm bg-sentinel-surface border border-sentinel-border rounded-lg hover:border-status-warning transition-colors"
            >
              Select All High Risk
            </button>
          )}
          {selectedApprovals.size > 0 && (
            <button className="btn-danger text-sm py-2">
              Revoke {selectedApprovals.size} Selected
            </button>
          )}
        </div>
      </div>

      {/* Approval List */}
      <div className="space-y-3">
        {filteredApprovals.map((approval, index) => (
          <motion.div
            key={approval.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.05 }}
          >
            <ApprovalCard
              approval={approval}
              chain={chain}
              isSelected={selectedApprovals.has(approval.id)}
              onSelect={() => toggleSelection(approval.id)}
              getExplorerUrl={getExplorerUrl}
            />
          </motion.div>
        ))}
      </div>

      {/* Revocation Info */}
      <div className="glass-card rounded-xl p-4 border-l-4 border-l-blue-500">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-medium text-blue-400 mb-1">How Revocation Works</h4>
            <p className="text-sm text-sentinel-muted">
              Revoking an approval sets the allowance to zero, preventing the spender from transferring your tokens.
              This requires a small gas fee. You will need to sign the transaction with your wallet.
              This action is irreversible but you can always grant new approvals later.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function FilterButton({
  active,
  onClick,
  label,
  count,
  color,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
  color?: 'warning' | 'danger';
}) {
  const colorClasses = {
    warning: 'text-status-warning',
    danger: 'text-status-danger',
  };

  return (
    <button
      onClick={onClick}
      className={`px-3 py-2 rounded-lg text-sm font-medium transition-all ${
        active
          ? 'bg-sentinel-primary text-white'
          : 'bg-sentinel-surface hover:bg-sentinel-elevated'
      }`}
    >
      {label}
      <span className={`ml-2 ${color && !active ? colorClasses[color] : ''}`}>({count})</span>
    </button>
  );
}

function ApprovalCard({
  approval,
  chain,
  isSelected,
  onSelect,
  getExplorerUrl,
}: {
  approval: TokenApproval;
  chain: Chain;
  isSelected: boolean;
  onSelect: () => void;
  getExplorerUrl: (address: string) => string;
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyAddress = (address: string) => {
    navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`glass-card rounded-xl overflow-hidden transition-all ${
        isSelected ? 'ring-2 ring-sentinel-primary' : ''
      } ${approval.isMalicious ? 'border-l-4 border-l-status-danger' : ''}`}
    >
      {/* Main Row */}
      <div className="p-4 flex items-center gap-4">
        {/* Checkbox */}
        <button
          onClick={onSelect}
          className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${
            isSelected
              ? 'bg-sentinel-primary border-sentinel-primary'
              : 'border-sentinel-border hover:border-sentinel-primary'
          }`}
        >
          {isSelected && <CheckCircle className="w-3 h-3 text-white" />}
        </button>

        {/* Token Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold">{approval.token.symbol}</span>
            <span className="text-xs text-sentinel-muted">{approval.token.name}</span>
            {approval.isMalicious && (
              <span className="px-2 py-0.5 text-xs bg-status-danger-bg text-status-danger rounded-full">
                Malicious
              </span>
            )}
            {approval.isUnlimited && !approval.isMalicious && (
              <span className="px-2 py-0.5 text-xs bg-status-warning-bg text-status-warning rounded-full">
                Unlimited
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 text-xs text-sentinel-muted">
            <span>Spender:</span>
            <span className="font-mono truncate max-w-[200px]">
              {approval.spenderLabel || approval.spender}
            </span>
          </div>
        </div>

        {/* Risk Badge */}
        <RiskBadge level={approval.riskLevel} />

        {/* Expand Button */}
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="p-2 hover:bg-sentinel-surface rounded-lg transition-colors"
        >
          <ChevronDown
            className={`w-5 h-5 text-sentinel-muted transition-transform ${
              isExpanded ? 'rotate-180' : ''
            }`}
          />
        </button>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: 'auto', opacity: 1 }}
          className="px-4 pb-4 space-y-4"
        >
          {/* Details Grid */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <div className="text-sentinel-muted mb-1">Token Address</div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs truncate">{approval.token.address}</span>
                <button onClick={() => copyAddress(approval.token.address)}>
                  <Copy className={`w-4 h-4 ${copied ? 'text-status-safe' : 'text-sentinel-muted'}`} />
                </button>
                <a
                  href={getExplorerUrl(approval.token.address)}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <ExternalLink className="w-4 h-4 text-sentinel-muted" />
                </a>
              </div>
            </div>
            <div>
              <div className="text-sentinel-muted mb-1">Spender Address</div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs truncate">{approval.spender}</span>
                <button onClick={() => copyAddress(approval.spender)}>
                  <Copy className={`w-4 h-4 ${copied ? 'text-status-safe' : 'text-sentinel-muted'}`} />
                </button>
                <a
                  href={getExplorerUrl(approval.spender)}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <ExternalLink className="w-4 h-4 text-sentinel-muted" />
                </a>
              </div>
            </div>
            <div>
              <div className="text-sentinel-muted mb-1">Approval Amount</div>
              <div className="font-mono text-xs">
                {approval.isUnlimited ? 'Unlimited ∞' : approval.amount}
              </div>
            </div>
            <div>
              <div className="text-sentinel-muted mb-1">Granted</div>
              <div className="text-xs">{new Date(approval.grantedAt).toLocaleDateString()}</div>
            </div>
          </div>

          {/* Risk Reason */}
          {approval.riskReason && (
            <div className="p-3 bg-sentinel-surface rounded-lg">
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-status-warning flex-shrink-0 mt-0.5" />
                <p className="text-sm text-sentinel-muted">{approval.riskReason}</p>
              </div>
            </div>
          )}

          {/* Revoke Button */}
          <button className="w-full btn-danger text-sm py-2">
            Revoke This Approval
          </button>
        </motion.div>
      )}
    </div>
  );
}

function RiskBadge({ level }: { level: RiskLevel }) {
  const config = {
    CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Critical' },
    HIGH: { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'High' },
    MEDIUM: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Medium' },
    LOW: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Low' },
  };

  const { bg, text, label } = config[level];

  return (
    <span className={`px-3 py-1 rounded-full text-xs font-medium ${bg} ${text}`}>
      {label} Risk
    </span>
  );
}


