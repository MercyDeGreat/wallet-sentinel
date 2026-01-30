'use client';

import { motion } from 'framer-motion';
import {
  ShieldCheck,
  Info,
  AlertTriangle,
  AlertCircle,
  AlertOctagon,
} from 'lucide-react';
import { CompromiseResolutionInfo, CompromiseSubStatus, SecurityStatus } from '@/types';

interface CompromiseStatusBadgeProps {
  resolution: CompromiseResolutionInfo;
  size?: 'sm' | 'md' | 'lg';
  showTooltip?: boolean;
}

// ============================================
// THREE-STATE CLASSIFICATION UI (2026-01 REDESIGN)
// ============================================
// 
// 1. ACTIVELY_COMPROMISED (CRITICAL - RED)
//    - Show panic-level warning ONLY for confirmed active threats
//    - Requires ≥80% confidence
//
// 2. HISTORICALLY_COMPROMISED (WARNING - ORANGE)  
//    - Show calm, explanatory message
//    - "Previous compromise detected — no active attacker control"
//
// 3. RISK_EXPOSURE (INFO - YELLOW)
//    - Show informational message
//    - NOT called "compromised"
//    - "Risk exposure noted — not a compromise"

/**
 * CompromiseStatusBadge
 * 
 * Displays the three-state classification for wallet security:
 * - ACTIVE (Red): Under active attacker control
 * - HISTORICAL (Orange): Past compromise, attack stopped
 * - EXPOSURE (Yellow): Risk exposure, not compromised
 * - SAFE (Green/Gray): No issues
 * 
 * IMPORTANT: Historical indicators NEVER show red/panic styling
 */
export function CompromiseStatusBadge({ 
  resolution, 
  size = 'md',
  showTooltip = true 
}: CompromiseStatusBadgeProps) {
  const { displayBadge, tooltipText, subStatus, explanation } = resolution;
  
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
  
  // ============================================
  // COLOR SCHEME - THREE STATE CLASSIFICATION
  // ============================================
  // CRITICAL: Only ACTIVE states get red styling
  // Historical states get orange (warning, not panic)
  // Exposure states get yellow (informational)
  
  const colorSchemes: Record<CompromiseSubStatus, {
    bg: string;
    text: string;
    border: string;
    icon: string;
  }> = {
    // ACTIVE COMPROMISE states - RED (CRITICAL)
    ACTIVE_SWEEP_IN_PROGRESS: {
      bg: 'bg-red-600/20',
      text: 'text-red-400',
      border: 'border-red-500/50',
      icon: 'text-red-400',
    },
    ACTIVE_DRAINER_DETECTED: {
      bg: 'bg-red-600/20',
      text: 'text-red-400',
      border: 'border-red-500/50',
      icon: 'text-red-400',
    },
    LIVE_ATTACKER_ACCESS: {
      bg: 'bg-red-600/20',
      text: 'text-red-400',
      border: 'border-red-500/50',
      icon: 'text-red-400',
    },
    ACTIVE_THREAT: {
      bg: 'bg-red-500/10',
      text: 'text-red-400',
      border: 'border-red-500/30',
      icon: 'text-red-400',
    },
    
    // HISTORICAL COMPROMISE states - ORANGE (WARNING)
    RESOLVED: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      icon: 'text-orange-400',
    },
    NO_ACTIVE_RISK: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      icon: 'text-orange-400',
    },
    PREVIOUS_ATTACK: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      icon: 'text-orange-400',
    },
    
    // RISK EXPOSURE states - YELLOW (INFO)
    USER_SENT_TO_DRAINER: {
      bg: 'bg-yellow-500/10',
      text: 'text-yellow-400',
      border: 'border-yellow-500/30',
      icon: 'text-yellow-400',
    },
    PHISHING_INTERACTION: {
      bg: 'bg-yellow-500/10',
      text: 'text-yellow-400',
      border: 'border-yellow-500/30',
      icon: 'text-yellow-400',
    },
    INDIRECT_EXPOSURE: {
      bg: 'bg-yellow-500/10',
      text: 'text-yellow-400',
      border: 'border-yellow-500/30',
      icon: 'text-yellow-400',
    },
    
    // SAFE - GRAY/GREEN
    NONE: {
      bg: 'bg-gray-500/10',
      text: 'text-gray-400',
      border: 'border-gray-500/30',
      icon: 'text-gray-400',
    },
  };
  
  const colors = colorSchemes[subStatus] || colorSchemes.NONE;
  
  // Icon based on classification state
  const getIcon = () => {
    // Active states get octagon (most severe)
    if (['ACTIVE_SWEEP_IN_PROGRESS', 'ACTIVE_DRAINER_DETECTED', 'LIVE_ATTACKER_ACCESS', 'ACTIVE_THREAT'].includes(subStatus)) {
      return AlertOctagon;
    }
    // Historical states get triangle (warning)
    if (['RESOLVED', 'NO_ACTIVE_RISK', 'PREVIOUS_ATTACK'].includes(subStatus)) {
      return AlertTriangle;
    }
    // Exposure states get info circle
    if (['USER_SENT_TO_DRAINER', 'PHISHING_INTERACTION', 'INDIRECT_EXPOSURE'].includes(subStatus)) {
      return Info;
    }
    // Default to shield check
    return ShieldCheck;
  };
  
  const IconComponent = getIcon();
  
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
      
      {/* Tooltip with explanation */}
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
 * Inline variant for use in text - shows explanation
 */
export function CompromiseStatusInline({ resolution }: { resolution: CompromiseResolutionInfo }) {
  const { subStatus, explanation } = resolution;
  
  // Don't show anything for clean wallets
  if (subStatus === 'NONE') {
    return null;
  }
  
  const colorClasses: Record<string, string> = {
    // Active states
    ACTIVE_SWEEP_IN_PROGRESS: 'text-red-400',
    ACTIVE_DRAINER_DETECTED: 'text-red-400',
    LIVE_ATTACKER_ACCESS: 'text-red-400',
    ACTIVE_THREAT: 'text-red-400',
    // Historical states
    RESOLVED: 'text-orange-400',
    NO_ACTIVE_RISK: 'text-orange-400',
    PREVIOUS_ATTACK: 'text-orange-400',
    // Exposure states
    USER_SENT_TO_DRAINER: 'text-yellow-400',
    PHISHING_INTERACTION: 'text-yellow-400',
    INDIRECT_EXPOSURE: 'text-yellow-400',
    // Safe
    NONE: 'text-gray-400',
  };
  
  return (
    <span className={`${colorClasses[subStatus] || 'text-gray-400'} text-sm`}>
      {explanation}
    </span>
  );
}

/**
 * Card variant for detailed display with inline reasoning
 */
export function CompromiseStatusCard({ 
  resolution,
  confidence,
}: { 
  resolution: CompromiseResolutionInfo;
  confidence?: number;
}) {
  const { 
    displayBadge, 
    tooltipText, 
    explanation, 
    subStatus, 
    resolution: resolutionDetails 
  } = resolution;
  
  // Don't show anything for clean wallets
  if (subStatus === 'NONE') {
    return null;
  }
  
  // Determine card styling based on state category
  const isActiveState = ['ACTIVE_SWEEP_IN_PROGRESS', 'ACTIVE_DRAINER_DETECTED', 'LIVE_ATTACKER_ACCESS', 'ACTIVE_THREAT'].includes(subStatus);
  const isHistoricalState = ['RESOLVED', 'NO_ACTIVE_RISK', 'PREVIOUS_ATTACK'].includes(subStatus);
  const isExposureState = ['USER_SENT_TO_DRAINER', 'PHISHING_INTERACTION', 'INDIRECT_EXPOSURE'].includes(subStatus);
  
  // Card colors based on state
  const cardColors = isActiveState 
    ? 'bg-red-500/5 border-red-500/20'
    : isHistoricalState 
      ? 'bg-orange-500/5 border-orange-500/20'
      : 'bg-yellow-500/5 border-yellow-500/20';
  
  const iconColors = isActiveState
    ? 'bg-red-500/10 text-red-400'
    : isHistoricalState
      ? 'bg-orange-500/10 text-orange-400'
      : 'bg-yellow-500/10 text-yellow-400';
  
  const textColor = isActiveState
    ? 'text-red-400'
    : isHistoricalState
      ? 'text-orange-400'
      : 'text-yellow-400';
  
  // Get appropriate icon
  const IconComponent = isActiveState 
    ? AlertOctagon 
    : isHistoricalState 
      ? AlertTriangle 
      : Info;
  
  // Generate title based on state
  const getTitle = () => {
    if (isActiveState) return 'Actively Compromised';
    if (isHistoricalState) return 'Previous Compromise Detected';
    return 'Risk Exposure Noted';
  };
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`${cardColors} border rounded-xl p-4`}
    >
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-lg ${iconColors}`}>
          <IconComponent className="w-5 h-5" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <h3 className={`font-semibold ${textColor}`}>{getTitle()}</h3>
            {confidence !== undefined && (
              <span className="text-xs text-gray-500">
                ({confidence}% confidence)
              </span>
            )}
          </div>
          
          {/* Main explanation */}
          <p className="text-sm text-gray-300 mb-3">{explanation}</p>
          
          {/* Inline reasoning - WHY this status was assigned */}
          <div className={`text-xs ${textColor} mb-3 p-2 rounded bg-black/20`}>
            <strong>Why this status:</strong>{' '}
            {isActiveState && 'Live threat indicators detected within the monitoring window. Ongoing attacker activity confirmed.'}
            {isHistoricalState && subStatus === 'RESOLVED' && 'Historical compromise detected, but all malicious access has been revoked. No activity in 30+ days.'}
            {isHistoricalState && subStatus === 'NO_ACTIVE_RISK' && 'Past security incident identified. Attack appears to have stopped. Continue monitoring.'}
            {isHistoricalState && subStatus === 'PREVIOUS_ATTACK' && 'Wallet interacted with known drainer in the past. No ongoing attacker control observed.'}
            {isExposureState && 'Interaction with flagged addresses detected, but wallet behavior matches normal user activity. Not classified as compromise.'}
          </div>
          
          {/* Resolution details for historical states */}
          {(isHistoricalState || isExposureState) && (
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-1.5">
                <div className={`w-2 h-2 rounded-full ${resolutionDetails.allApprovalsRevoked ? 'bg-green-500' : 'bg-yellow-500'}`} />
                <span className="text-gray-400">
                  {resolutionDetails.allApprovalsRevoked ? 'Approvals revoked' : 'Check approvals'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className={`w-2 h-2 rounded-full ${resolutionDetails.noActiveMaliciousContracts ? 'bg-green-500' : 'bg-yellow-500'}`} />
                <span className="text-gray-400">
                  {resolutionDetails.noActiveMaliciousContracts ? 'No active threats' : 'Review contracts'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className={`w-2 h-2 rounded-full ${resolutionDetails.noRecentSweeperActivity ? 'bg-green-500' : 'bg-yellow-500'}`} />
                <span className="text-gray-400">
                  {resolutionDetails.noRecentSweeperActivity ? 'No recent sweeper' : 'Recent activity'}
                </span>
              </div>
              {resolutionDetails.daysSinceLastMaliciousActivity !== undefined && (
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-blue-500" />
                  <span className="text-gray-400">
                    {resolutionDetails.daysSinceLastMaliciousActivity} days since incident
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      {/* Footer with tooltip text */}
      <div className="mt-3 pt-3 border-t border-white/5 text-xs text-gray-500">
        {isActiveState ? '🚨' : isHistoricalState ? '⚠️' : 'ℹ️'} {tooltipText}
      </div>
    </motion.div>
  );
}

/**
 * Minimal badge for list views
 */
export function CompromiseStatusMiniBadge({ subStatus }: { subStatus: CompromiseSubStatus }) {
  // Mapping for minimal display
  const badgeConfig: Record<string, { text: string; color: string }> = {
    // Active
    ACTIVE_SWEEP_IN_PROGRESS: { text: 'ACTIVE', color: 'bg-red-500 text-white' },
    ACTIVE_DRAINER_DETECTED: { text: 'ACTIVE', color: 'bg-red-500 text-white' },
    LIVE_ATTACKER_ACCESS: { text: 'ACTIVE', color: 'bg-red-500 text-white' },
    ACTIVE_THREAT: { text: 'ACTIVE', color: 'bg-red-500 text-white' },
    // Historical
    RESOLVED: { text: 'HISTORICAL', color: 'bg-orange-500/80 text-white' },
    NO_ACTIVE_RISK: { text: 'HISTORICAL', color: 'bg-orange-500/80 text-white' },
    PREVIOUS_ATTACK: { text: 'HISTORICAL', color: 'bg-orange-500/80 text-white' },
    // Exposure
    USER_SENT_TO_DRAINER: { text: 'EXPOSURE', color: 'bg-yellow-500/80 text-black' },
    PHISHING_INTERACTION: { text: 'EXPOSURE', color: 'bg-yellow-500/80 text-black' },
    INDIRECT_EXPOSURE: { text: 'EXPOSURE', color: 'bg-yellow-500/80 text-black' },
    // Safe
    NONE: { text: 'SAFE', color: 'bg-green-500/80 text-white' },
  };
  
  const config = badgeConfig[subStatus] || badgeConfig.NONE;
  
  return (
    <span className={`${config.color} px-2 py-0.5 rounded text-xs font-bold uppercase`}>
      {config.text}
    </span>
  );
}

export default CompromiseStatusBadge;
