'use client';

import { motion } from 'framer-motion';
import {
  ShieldCheck,
  Info,
  AlertTriangle,
  AlertCircle,
} from 'lucide-react';
import { CompromiseResolutionInfo, CompromiseSubStatus } from '@/types';

interface CompromiseStatusBadgeProps {
  resolution: CompromiseResolutionInfo;
  size?: 'sm' | 'md' | 'lg';
  showTooltip?: boolean;
}

/**
 * CompromiseStatusBadge
 * 
 * Displays the sub-status for previously compromised wallets:
 * - "Previously Compromised (Resolved)" - Blue/informational, historical with all remediated
 * - "Previously Compromised (No Active Risk)" - Blue/informational, historical but should monitor
 * - "Active Threat" - Red/danger, currently compromised
 * - "Clean" - Gray/neutral, no history of compromise
 * 
 * IMPORTANT: These badges are INFORMATIONAL, not punitive.
 * They do NOT increase risk score.
 */
export function CompromiseStatusBadge({ 
  resolution, 
  size = 'md',
  showTooltip = true 
}: CompromiseStatusBadgeProps) {
  const { displayBadge, tooltipText, subStatus } = resolution;
  
  // Size configurations
  const sizeConfig = {
    sm: {
      iconSize: 14,
      padding: 'px-2 py-0.5',
      text: 'text-xs',
      gap: 'gap-1',
    },
    md: {
      iconSize: 16,
      padding: 'px-3 py-1',
      text: 'text-sm',
      gap: 'gap-1.5',
    },
    lg: {
      iconSize: 18,
      padding: 'px-4 py-1.5',
      text: 'text-base',
      gap: 'gap-2',
    },
  };
  
  const config = sizeConfig[size];
  
  // Color scheme based on sub-status
  const colorSchemes: Record<CompromiseSubStatus, {
    bg: string;
    text: string;
    border: string;
    icon: string;
  }> = {
    RESOLVED: {
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      border: 'border-blue-500/30',
      icon: 'text-blue-400',
    },
    NO_ACTIVE_RISK: {
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      border: 'border-blue-500/30',
      icon: 'text-blue-400',
    },
    ACTIVE_THREAT: {
      bg: 'bg-red-500/10',
      text: 'text-red-400',
      border: 'border-red-500/30',
      icon: 'text-red-400',
    },
    ACTIVE_DRAINER_DETECTED: {
      bg: 'bg-red-600/20',
      text: 'text-red-400',
      border: 'border-red-500/50',
      icon: 'text-red-400',
    },
    NONE: {
      bg: 'bg-gray-500/10',
      text: 'text-gray-400',
      border: 'border-gray-500/30',
      icon: 'text-gray-400',
    },
  };
  
  const colors = colorSchemes[subStatus];
  
  // Icon based on display badge
  const IconComponent = {
    'shield-check': ShieldCheck,
    'info': Info,
    'alert-triangle': AlertTriangle,
    'alert-circle': AlertCircle,
  }[displayBadge.icon] || Info;
  
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="relative group inline-block"
    >
      <div
        className={`
          inline-flex items-center ${config.gap} ${config.padding}
          rounded-full border ${colors.bg} ${colors.border}
          font-medium ${config.text} ${colors.text}
          transition-all duration-200
        `}
      >
        <IconComponent size={config.iconSize} className={colors.icon} />
        <span>{displayBadge.text}</span>
      </div>
      
      {/* Tooltip */}
      {showTooltip && (
        <div
          className={`
            absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2
            px-3 py-2 rounded-lg bg-gray-900 border border-gray-700
            text-sm text-gray-200 max-w-xs text-center
            opacity-0 group-hover:opacity-100 pointer-events-none
            transition-opacity duration-200 shadow-xl
          `}
        >
          {tooltipText}
          {/* Arrow */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-px">
            <div className="border-8 border-transparent border-t-gray-700" />
          </div>
        </div>
      )}
    </motion.div>
  );
}

/**
 * Inline variant for use in text
 */
export function CompromiseStatusInline({ resolution }: { resolution: CompromiseResolutionInfo }) {
  const { subStatus, explanation } = resolution;
  
  // Don't show anything for clean wallets
  if (subStatus === 'NONE') {
    return null;
  }
  
  const colorClasses: Record<CompromiseSubStatus, string> = {
    RESOLVED: 'text-blue-400',
    NO_ACTIVE_RISK: 'text-blue-400',
    ACTIVE_THREAT: 'text-red-400',
    ACTIVE_DRAINER_DETECTED: 'text-red-400',
    NONE: 'text-gray-400',
  };
  
  return (
    <span className={`${colorClasses[subStatus]} text-sm`}>
      {explanation}
    </span>
  );
}

/**
 * Card variant for detailed display
 */
export function CompromiseStatusCard({ resolution }: { resolution: CompromiseResolutionInfo }) {
  const { displayBadge, tooltipText, explanation, subStatus, resolution: resolutionDetails } = resolution;
  
  // Don't show anything for clean wallets
  if (subStatus === 'NONE') {
    return null;
  }
  
  // Don't show for active threats (handled by ThreatCard)
  if (subStatus === 'ACTIVE_THREAT') {
    return null;
  }
  
  const IconComponent = {
    'shield-check': ShieldCheck,
    'info': Info,
    'alert-triangle': AlertTriangle,
    'alert-circle': AlertCircle,
  }[displayBadge.icon] || Info;
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4"
    >
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg bg-blue-500/10">
          <IconComponent className="w-5 h-5 text-blue-400" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="font-semibold text-blue-400">{displayBadge.text}</h3>
          </div>
          <p className="text-sm text-gray-300 mb-3">{explanation}</p>
          
          {/* Resolution details */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${resolutionDetails.allApprovalsRevoked ? 'bg-green-500' : 'bg-yellow-500'}`} />
              <span className="text-gray-400">
                {resolutionDetails.allApprovalsRevoked ? 'All approvals revoked' : 'Some approvals remain'}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${resolutionDetails.noActiveMaliciousContracts ? 'bg-green-500' : 'bg-yellow-500'}`} />
              <span className="text-gray-400">
                {resolutionDetails.noActiveMaliciousContracts ? 'No active threats' : 'Active threats present'}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${resolutionDetails.noRecentSweeperActivity ? 'bg-green-500' : 'bg-yellow-500'}`} />
              <span className="text-gray-400">
                {resolutionDetails.noRecentSweeperActivity ? 'No recent sweeper activity' : 'Recent sweeper activity'}
              </span>
            </div>
            {resolutionDetails.daysSinceLastMaliciousActivity !== undefined && (
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full bg-blue-500" />
                <span className="text-gray-400">
                  {resolutionDetails.daysSinceLastMaliciousActivity} days since last incident
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* Info footer */}
      <div className="mt-3 pt-3 border-t border-blue-500/10 text-xs text-gray-500">
        ℹ️ {tooltipText}
      </div>
    </motion.div>
  );
}

export default CompromiseStatusBadge;

