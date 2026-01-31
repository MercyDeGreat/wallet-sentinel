'use client';

// ============================================
// ADDRESS POISONING ATTACK - UI COMPONENT
// ============================================
//
// DEVELOPER NOTES (INTERNAL ONLY):
//
// WHY ADDRESS POISONING ≠ WALLET COMPROMISE:
// Address poisoning is a SOCIAL ENGINEERING attack. The attacker
// never gains control of the victim's wallet, private key, or approvals.
// The victim is tricked into manually sending funds to a spoofed address.
// This is fundamentally different from:
// - Sweeper bots (which have automated control)
// - Approval drainers (which exploit token approvals)
// - Private key leaks (which give full wallet control)
//
// WHY NO AUTOMATED DRAIN LANGUAGE:
// Address poisoning does NOT involve automated drainage. The victim
// manually initiates the transfer. Using language like "funds drained"
// or "sweeper bot" would be technically incorrect and unnecessarily
// alarming. The damage is already done — no "emergency action" can reverse it.
//
// WHY RECOMMENDATIONS FOCUS ON USER HYGIENE, NOT RECOVERY:
// Since no compromise occurred (no keys leaked, no approvals abused),
// there is nothing to "revoke" or "recover". The correct response is
// to educate the user on prevention for future transactions:
// - Verify full addresses before sending
// - Use address book / ENS names
// - Be cautious of transaction history clutter
//
// ============================================

import { motion } from 'framer-motion';
import { 
  AlertTriangle, 
  Shield,
  CheckCircle,
  Clock,
  Eye,
  BookOpen,
  History,
} from 'lucide-react';
import type { AttackClassification } from '@/lib/classification/types';

// ============================================
// COMPONENT PROPS
// ============================================

export interface AddressPoisoningCardProps {
  /**
   * The attack classification result from the engine.
   * MUST have classification.type === "ADDRESS_POISONING"
   */
  classification: AttackClassification;
  
  /**
   * Optional: First dust transaction timestamp for dynamic indicator
   */
  firstDustTimestamp?: number;
  
  /**
   * Optional: Similarity score for dynamic indicator (0-100)
   */
  similarityScore?: number;
  
  /**
   * Optional: Whether the outbound transfer was user-signed (not transferFrom)
   */
  wasUserSignedTransfer?: boolean;
  
  /**
   * Optional: Number of dust transfers received
   */
  dustTransferCount?: number;
  
  /**
   * Show/hide the recommendation section
   */
  showRecommendations?: boolean;
  
  /**
   * Compact mode for mobile/embedded views
   */
  compact?: boolean;
}

// ============================================
// MAIN COMPONENT
// ============================================

/**
 * AddressPoisoningCard
 * 
 * Displays a clear, non-alarmist explanation when an address poisoning
 * attack is detected. This component renders ONLY when:
 * 
 *   classification.type === "ADDRESS_POISONING"
 * 
 * UX SAFETY RULES (NEVER VIOLATE):
 * - NEVER show "ACTIVELY COMPROMISED"
 * - NEVER show "Sweeper bot detected"
 * - NEVER show "Private key leaked"
 * - NEVER recommend revoking approvals
 * - NEVER use emergency language
 * 
 * This output MUST reassure without minimizing risk.
 */
export function AddressPoisoningCard({
  classification,
  firstDustTimestamp,
  similarityScore,
  wasUserSignedTransfer = true,
  dustTransferCount,
  showRecommendations = true,
  compact = false,
}: AddressPoisoningCardProps) {
  // ============================================
  // SAFETY CHECK: Only render for ADDRESS_POISONING
  // ============================================
  if (classification.type !== 'ADDRESS_POISONING') {
    console.warn('[AddressPoisoningCard] Incorrect classification type:', classification.type);
    return null;
  }

  // ============================================
  // DYNAMIC INDICATOR GENERATION
  // ============================================
  
  // Calculate duration text from first dust timestamp
  const getDurationText = (): string => {
    if (!firstDustTimestamp) {
      return 'Repeated over time';
    }
    
    const now = Math.floor(Date.now() / 1000);
    const durationSeconds = now - firstDustTimestamp;
    const durationDays = Math.floor(durationSeconds / 86400);
    
    if (durationDays >= 60) {
      const months = Math.floor(durationDays / 30);
      return `Repeated over ${months}+ months`;
    } else if (durationDays >= 30) {
      return 'Repeated over 1+ month';
    } else if (durationDays >= 14) {
      return `Repeated over ${Math.floor(durationDays / 7)} weeks`;
    } else if (durationDays >= 1) {
      return `Repeated over ${durationDays} day${durationDays > 1 ? 's' : ''}`;
    } else {
      return 'Recent dusting activity';
    }
  };

  // Build dynamic indicators
  const indicators: { text: string; available: boolean }[] = [
    {
      // "Visually similar address" → require similarity score above threshold
      text: similarityScore !== undefined && similarityScore >= 60
        ? `Dusting from visually similar address (${similarityScore}% match)`
        : 'Dusting from a visually similar address',
      available: true, // Always show this indicator (core to attack)
    },
    {
      // "Repeated over 2+ months" → derive from first dust tx timestamp
      text: getDurationText(),
      available: true, // Fallback gracefully with generic text
    },
    {
      // "Manual outbound transfer" → ensure user-signed tx, not transferFrom
      text: wasUserSignedTransfer
        ? 'Manual outbound transfer to spoofed address'
        : 'Outbound transfer to spoofed address',
      available: true, // Always show if attack confirmed
    },
  ];

  // Add dust count if available
  if (dustTransferCount !== undefined && dustTransferCount > 1) {
    indicators.unshift({
      text: `${dustTransferCount} dust transfers received`,
      available: true,
    });
  }

  // ============================================
  // RENDER
  // ============================================
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`
        rounded-xl border-l-4 border-l-amber-500
        bg-amber-500/5 
        ${compact ? 'p-4' : 'p-5'}
      `}
      // IMPORTANT: Use warning colors (amber), NOT critical colors (red)
      // Address poisoning is a concern, but NOT an active compromise
    >
      {/* ============================================ */}
      {/* HEADER - Exact copy as specified */}
      {/* ============================================ */}
      <div className="flex items-start gap-3 mb-4">
        <div className="p-2 rounded-lg bg-amber-500/10">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
        </div>
        <div className="flex-1">
          {/* EXACT TEXT: "⚠️ Address Poisoning Attack" */}
          <h3 className="font-display font-semibold text-lg text-amber-400">
            ⚠️ Address Poisoning Attack
          </h3>
          {/* EXACT TEXT: "No wallet compromise detected." */}
          <p className="text-sentinel-text mt-1">
            No wallet compromise detected.
          </p>
        </div>
      </div>

      {/* ============================================ */}
      {/* SUMMARY - Exact copy as specified */}
      {/* ============================================ */}
      {/* EXACT TEXT: "Funds were sent to a look-alike address..." */}
      <p className="text-sentinel-muted mb-4 leading-relaxed">
        Funds were sent to a look-alike address that previously dusted this wallet.
      </p>

      {/* ============================================ */}
      {/* SAFETY REASSURANCE BOX */}
      {/* Shows what DID NOT happen - critical for accurate messaging */}
      {/* ============================================ */}
      <div className="bg-green-500/5 border border-green-500/20 rounded-lg p-3 mb-4">
        <div className="flex items-center gap-2 mb-2">
          <Shield className="w-4 h-4 text-green-400" />
          <span className="text-sm font-medium text-green-400">What did NOT happen</span>
        </div>
        <ul className="space-y-1 text-sm text-sentinel-muted">
          <li className="flex items-center gap-2">
            <CheckCircle className="w-3 h-3 text-green-400 flex-shrink-0" />
            No private key compromise
          </li>
          <li className="flex items-center gap-2">
            <CheckCircle className="w-3 h-3 text-green-400 flex-shrink-0" />
            No approval abuse
          </li>
          <li className="flex items-center gap-2">
            <CheckCircle className="w-3 h-3 text-green-400 flex-shrink-0" />
            No automated draining
          </li>
        </ul>
      </div>

      {/* ============================================ */}
      {/* INDICATORS - Dynamic with fallback */}
      {/* ============================================ */}
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-2">
          <Eye className="w-4 h-4 text-amber-400" />
          <span className="text-sm font-medium text-sentinel-text">Indicators:</span>
        </div>
        <ul className="space-y-1.5">
          {indicators.filter(i => i.available).map((indicator, index) => (
            <li key={index} className="flex items-start gap-2 text-sm text-sentinel-muted">
              <span className="text-amber-400 mt-1">•</span>
              <span>{indicator.text}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* ============================================ */}
      {/* RECOMMENDATIONS - Exact copy as specified */}
      {/* Focus on USER HYGIENE, not recovery (there's nothing to recover) */}
      {/* ============================================ */}
      {showRecommendations && (
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-2">
            <BookOpen className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-medium text-blue-400">Recommendation:</span>
          </div>
          <ul className="space-y-1.5">
            {/* EXACT TEXT as specified */}
            <li className="flex items-start gap-2 text-sm text-sentinel-muted">
              <span className="text-blue-400 mt-1">•</span>
              <span>Always verify full address</span>
            </li>
            <li className="flex items-start gap-2 text-sm text-sentinel-muted">
              <span className="text-blue-400 mt-1">•</span>
              <span>Use address book / ENS</span>
            </li>
            <li className="flex items-start gap-2 text-sm text-sentinel-muted">
              <span className="text-blue-400 mt-1">•</span>
              <span>Clear transaction history clutter</span>
            </li>
          </ul>
        </div>
      )}

      {/* ============================================ */}
      {/* CONFIDENCE FOOTER */}
      {/* ============================================ */}
      <div className="flex items-center justify-between mt-4 pt-3 border-t border-sentinel-border">
        <div className="flex items-center gap-2 text-xs text-sentinel-muted">
          <Clock className="w-3 h-3" />
          <span>Analyzed {new Date(classification.classifiedAt).toLocaleDateString()}</span>
        </div>
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-amber-500/20">
          <span className="text-xs font-medium text-amber-400">
            Confidence: {classification.confidence}%
          </span>
        </div>
      </div>
    </motion.div>
  );
}

// ============================================
// COMPACT VARIANT
// ============================================

export interface AddressPoisoningBadgeProps {
  classification: AttackClassification;
}

/**
 * Compact badge variant for inline display
 */
export function AddressPoisoningBadge({ classification }: AddressPoisoningBadgeProps) {
  if (classification.type !== 'ADDRESS_POISONING') {
    return null;
  }

  return (
    <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/20">
      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
      <span className="text-sm font-medium text-amber-400">Address Poisoning</span>
      <span className="text-xs text-sentinel-muted">• No Compromise</span>
    </div>
  );
}

// ============================================
// TIMELINE ENTRY VARIANT
// ============================================

export interface AddressPoisoningTimelineEntryProps {
  classification: AttackClassification;
  timestamp?: string;
}

/**
 * Timeline entry variant for wallet history view
 */
export function AddressPoisoningTimelineEntry({ 
  classification,
  timestamp 
}: AddressPoisoningTimelineEntryProps) {
  if (classification.type !== 'ADDRESS_POISONING') {
    return null;
  }

  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
      <div className="p-1.5 rounded-full bg-amber-500/20">
        <AlertTriangle className="w-4 h-4 text-amber-400" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-sm text-amber-400">Address Poisoning</span>
          <span className="text-xs px-1.5 py-0.5 rounded bg-green-500/10 text-green-400">
            No Compromise
          </span>
        </div>
        <p className="text-sm text-sentinel-muted mt-1">
          Funds sent to look-alike address via social engineering
        </p>
        {timestamp && (
          <div className="flex items-center gap-1 mt-2 text-xs text-sentinel-muted">
            <History className="w-3 h-3" />
            <span>{timestamp}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================
// EXPORTS
// ============================================

export default AddressPoisoningCard;
