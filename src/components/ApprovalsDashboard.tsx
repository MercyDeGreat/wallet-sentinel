'use client';

import { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  CheckCircle,
  Shield,
  ExternalLink,
  Copy,
  Info,
  ChevronDown,
  AlertCircle as AlertIcon,
  Loader2,
  Wallet,
  X,
  DollarSign,
} from 'lucide-react';
import { TokenApproval, Chain, RiskLevel } from '@/types';
import { useAccount, useConnect, useDisconnect, useWriteContract, useWaitForTransactionReceipt, useSwitchChain, useSendTransaction } from 'wagmi';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { parseEther } from 'viem';
import { ERC20_ABI, CHAIN_IDS } from '@/lib/web3-config';

// Service fee configuration
const SERVICE_FEE_RECIPIENT = '0x3eE604833B5572422dBF7eB7e2d342daf4188aE2' as `0x${string}`;
const SERVICE_FEE_USD = 1; // $1 USD

// Approximate ETH prices for fee calculation (updates needed for production)
const NATIVE_TOKEN_PRICES: Record<string, number> = {
  ethereum: 3500, // ETH price in USD
  base: 3500,     // ETH price in USD  
  bnb: 600,       // BNB price in USD
};

interface ApprovalsDashboardProps {
  approvals: TokenApproval[];
  chain: Chain;
}

interface RevocationState {
  approvalId: string;
  status: 'pending' | 'paying_fee' | 'fee_confirming' | 'signing' | 'confirming' | 'success' | 'error';
  txHash?: string;
  feeTxHash?: string;
  error?: string;
}

export function ApprovalsDashboard({ approvals, chain }: ApprovalsDashboardProps) {
  const [filter, setFilter] = useState<'all' | 'high' | 'malicious'>('all');
  const [selectedApprovals, setSelectedApprovals] = useState<Set<string>>(new Set());
  const [revocationStates, setRevocationStates] = useState<Record<string, RevocationState>>({});
  const [showConnectModal, setShowConnectModal] = useState(false);

  const { address, isConnected, chainId } = useAccount();
  const { disconnect } = useDisconnect();
  const { switchChain } = useSwitchChain();

  const targetChainId = CHAIN_IDS[chain];
  const isCorrectChain = chainId === targetChainId;

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

  const getTxExplorerUrl = (txHash: string) => {
    const explorers: Record<string, string> = {
      ethereum: 'https://etherscan.io/tx/',
      base: 'https://basescan.org/tx/',
      bnb: 'https://bscscan.com/tx/',
      solana: 'https://solscan.io/tx/',
    };
    return `${explorers[chain] || explorers.ethereum}${txHash}`;
  };

  const updateRevocationState = useCallback((approvalId: string, state: Partial<RevocationState>) => {
    setRevocationStates(prev => ({
      ...prev,
      [approvalId]: { ...prev[approvalId], approvalId, ...state } as RevocationState,
    }));
  }, []);

  const handleSwitchChain = async () => {
    if (switchChain && targetChainId) {
      try {
        await switchChain({ chainId: targetChainId });
      } catch (err) {
        console.error('Failed to switch chain:', err);
      }
    }
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

  // Count successful revocations
  const revokedCount = Object.values(revocationStates).filter(s => s.status === 'success').length;

  return (
    <div className="space-y-6">
      {/* Wallet Connection Section */}
      <div className="glass-card rounded-xl p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Wallet className="w-5 h-5 text-sentinel-primary" />
            <div>
              <div className="font-medium">Wallet Connection</div>
              <div className="text-sm text-sentinel-muted">
                {isConnected 
                  ? `Connected: ${address?.slice(0, 6)}...${address?.slice(-4)}`
                  : 'Connect your wallet to revoke approvals'}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isConnected && !isCorrectChain && (
              <button 
                onClick={handleSwitchChain}
                className="px-3 py-2 text-sm bg-status-warning text-black rounded-lg font-medium hover:opacity-90 transition-opacity"
              >
                Switch to {chain.charAt(0).toUpperCase() + chain.slice(1)}
              </button>
            )}
            <ConnectButton 
              showBalance={false}
              chainStatus="icon"
              accountStatus="address"
            />
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
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
        <div className="glass-card rounded-xl p-4">
          <div className="text-sentinel-muted text-sm mb-1 flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-status-safe" />
            Revoked
          </div>
          <div className="text-2xl font-bold text-status-safe">{revokedCount}</div>
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
              getTxExplorerUrl={getTxExplorerUrl}
              isConnected={isConnected}
              isCorrectChain={isCorrectChain}
              revocationState={revocationStates[approval.id]}
              updateRevocationState={updateRevocationState}
            />
          </motion.div>
        ))}
      </div>

      {/* Service Fee Notice */}
      <div className="glass-card rounded-xl p-4 border-l-4 border-l-cyan-500 bg-cyan-950/20">
        <div className="flex items-start gap-3">
          <DollarSign className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-medium text-cyan-400 mb-1">Service Fee: $1 + Gas</h4>
            <p className="text-sm text-sentinel-muted">
              Each revocation includes a <strong className="text-cyan-400">$1 service fee</strong> to support Securnex development, 
              plus network gas fees. You will sign two transactions: one for the service fee and one for the revocation.
            </p>
          </div>
        </div>
      </div>

      {/* Revocation Info */}
      <div className="glass-card rounded-xl p-4 border-l-4 border-l-blue-500">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-medium text-blue-400 mb-1">How Revocation Works</h4>
            <p className="text-sm text-sentinel-muted">
              Revoking an approval sets the allowance to zero, preventing the spender from transferring your tokens.
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
  getTxExplorerUrl,
  isConnected,
  isCorrectChain,
  revocationState,
  updateRevocationState,
}: {
  approval: TokenApproval;
  chain: Chain;
  isSelected: boolean;
  onSelect: () => void;
  getExplorerUrl: (address: string) => string;
  getTxExplorerUrl: (txHash: string) => string;
  isConnected: boolean;
  isCorrectChain: boolean;
  revocationState?: RevocationState;
  updateRevocationState: (approvalId: string, state: Partial<RevocationState>) => void;
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [feePaid, setFeePaid] = useState(false);

  // Calculate service fee in native token
  const nativePrice = NATIVE_TOKEN_PRICES[chain] || 3500;
  const feeInNative = SERVICE_FEE_USD / nativePrice;
  const feeWei = parseEther(feeInNative.toFixed(18));

  // Wagmi hooks for fee payment
  const { 
    sendTransaction, 
    data: feeHash, 
    isPending: isFeePending, 
    error: feeError,
    reset: resetFee 
  } = useSendTransaction();
  
  const { isLoading: isFeeConfirming, isSuccess: isFeeSuccess } = useWaitForTransactionReceipt({ hash: feeHash });

  // Wagmi hooks for revocation
  const { writeContract, data: hash, isPending: isWritePending, error: writeError } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash });

  // Update state when fee transaction progresses
  if (isFeePending && revocationState?.status !== 'paying_fee') {
    updateRevocationState(approval.id, { status: 'paying_fee' });
  }
  if (feeHash && isFeeConfirming && revocationState?.status !== 'fee_confirming') {
    updateRevocationState(approval.id, { status: 'fee_confirming', feeTxHash: feeHash });
  }
  if (isFeeSuccess && !feePaid) {
    setFeePaid(true);
    // Now proceed with revocation
    updateRevocationState(approval.id, { status: 'signing', feeTxHash: feeHash });
    writeContract({
      address: approval.token.address as `0x${string}`,
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [approval.spender as `0x${string}`, BigInt(0)],
    });
  }

  // Update state when revocation transaction progresses
  if (isWritePending && feePaid && revocationState?.status !== 'signing') {
    updateRevocationState(approval.id, { status: 'signing' });
  }
  if (hash && isConfirming && revocationState?.status !== 'confirming') {
    updateRevocationState(approval.id, { status: 'confirming', txHash: hash });
  }
  if (isSuccess && revocationState?.status !== 'success') {
    updateRevocationState(approval.id, { status: 'success', txHash: hash });
  }
  if ((writeError || feeError) && revocationState?.status !== 'error') {
    const errorMsg = writeError?.message || feeError?.message || 'Transaction failed';
    updateRevocationState(approval.id, { status: 'error', error: errorMsg });
  }

  const copyAddress = (address: string) => {
    navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRevoke = async () => {
    if (!isConnected || !isCorrectChain) return;
    
    updateRevocationState(approval.id, { status: 'pending' });
    setFeePaid(false);

    try {
      // Step 1: Send service fee
      sendTransaction({
        to: SERVICE_FEE_RECIPIENT,
        value: feeWei,
      });
    } catch (err: any) {
      updateRevocationState(approval.id, { status: 'error', error: err?.message || 'Failed to revoke' });
    }
  };

  const isRevoking = revocationState?.status === 'pending' || 
                     revocationState?.status === 'paying_fee' ||
                     revocationState?.status === 'fee_confirming' ||
                     revocationState?.status === 'signing' || 
                     revocationState?.status === 'confirming';
  const isRevoked = revocationState?.status === 'success';
  const hasError = revocationState?.status === 'error';

  // Get status text for button
  const getStatusText = () => {
    switch (revocationState?.status) {
      case 'pending': return 'Preparing...';
      case 'paying_fee': return 'Pay $1 Fee...';
      case 'fee_confirming': return 'Fee Confirming...';
      case 'signing': return 'Sign Revoke...';
      case 'confirming': return 'Confirming...';
      default: return 'Revoke ($1 + gas)';
    }
  };

  return (
    <div
      className={`glass-card rounded-xl overflow-hidden transition-all ${
        isSelected ? 'ring-2 ring-sentinel-primary' : ''
      } ${approval.isMalicious ? 'border-l-4 border-l-status-danger' : ''} ${
        isRevoked ? 'opacity-60' : ''
      }`}
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
            {isRevoked && (
              <span className="px-2 py-0.5 text-xs bg-status-safe/20 text-status-safe rounded-full flex items-center gap-1">
                <CheckCircle className="w-3 h-3" />
                Revoked
              </span>
            )}
            {approval.isMalicious && !isRevoked && (
              <span className="px-2 py-0.5 text-xs bg-status-danger-bg text-status-danger rounded-full">
                Malicious
              </span>
            )}
            {approval.isUnlimited && !approval.isMalicious && !isRevoked && (
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

        {/* Quick Revoke Button */}
        {!isRevoked && (
          <button
            onClick={handleRevoke}
            disabled={!isConnected || !isCorrectChain || isRevoking}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
              !isConnected || !isCorrectChain
                ? 'bg-sentinel-surface text-sentinel-muted cursor-not-allowed'
                : isRevoking
                ? 'bg-status-warning/20 text-status-warning cursor-wait'
                : 'bg-status-danger text-white hover:bg-red-600'
            }`}
          >
            {isRevoking ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                {getStatusText()}
              </>
            ) : (
              <>
                <DollarSign className="w-4 h-4" />
                Revoke ($1 + gas)
              </>
            )}
          </button>
        )}

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

      {/* Success/Error Messages */}
      <AnimatePresence>
        {(isRevoked || hasError) && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className={`px-4 py-2 ${isRevoked ? 'bg-status-safe/10' : 'bg-status-danger/10'}`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {isRevoked ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-status-safe" />
                    <span className="text-sm text-status-safe">Successfully revoked!</span>
                  </>
                ) : (
                  <>
                    <X className="w-4 h-4 text-status-danger" />
                    <span className="text-sm text-status-danger">
                      {revocationState?.error?.slice(0, 50) || 'Failed to revoke'}
                    </span>
                  </>
                )}
              </div>
              {revocationState?.txHash && (
                <a
                  href={getTxExplorerUrl(revocationState.txHash)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-400 hover:underline flex items-center gap-1"
                >
                  View Transaction <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Expanded Details */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
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

            {/* Not Connected Warning */}
            {!isConnected && (
              <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                <div className="flex items-start gap-2">
                  <Wallet className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-blue-400">
                    Connect your wallet above to revoke this approval.
                  </p>
                </div>
              </div>
            )}

            {isConnected && !isCorrectChain && (
              <div className="p-3 bg-status-warning/10 border border-status-warning/30 rounded-lg">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-status-warning flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-status-warning">
                    Please switch to {chain.charAt(0).toUpperCase() + chain.slice(1)} network to revoke this approval.
                  </p>
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
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
