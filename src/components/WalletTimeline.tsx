'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  AlertCircle,
  AlertTriangle,
  Info,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Clock,
  Activity,
} from 'lucide-react';
import {
  WalletTimeline as WalletTimelineType,
  TimelineEvent,
  TimelineEventSeverity,
  TimelineEventReference,
  TIMELINE_SEVERITY_COLORS,
} from '@/types';

interface WalletTimelineProps {
  timeline: WalletTimelineType;
  maxVisibleEvents?: number;
  showCurrentStatus?: boolean;
}

/**
 * WalletTimeline Component
 * 
 * Displays a chronological, human-readable timeline that explains:
 * - WHAT happened
 * - WHEN it happened
 * - WHAT changed
 * - CURRENT wallet state
 * 
 * CRITICAL: Past compromise ≠ Active compromise
 */
export function WalletTimeline({ 
  timeline, 
  maxVisibleEvents = 10,
  showCurrentStatus = true 
}: WalletTimelineProps) {
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [showAllEvents, setShowAllEvents] = useState(false);
  
  const visibleEvents = showAllEvents 
    ? timeline.events 
    : timeline.events.slice(-maxVisibleEvents);
  
  const hasMoreEvents = timeline.events.length > maxVisibleEvents;
  
  const toggleExpand = (eventId: string) => {
    setExpandedEventId(prev => prev === eventId ? null : eventId);
  };

  return (
    <div className="space-y-4">
      {/* Timeline Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-sentinel-muted" />
          <h3 className="font-display font-semibold text-lg">Security Timeline</h3>
        </div>
        <div className="text-xs text-sentinel-muted">
          {timeline.metadata.totalEvents} event{timeline.metadata.totalEvents !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Current Status Summary */}
      {showCurrentStatus && (
        <CurrentStatusBanner 
          status={timeline.currentStatus} 
          metadata={timeline.metadata}
        />
      )}

      {/* Show More Button (at top if collapsed) */}
      {hasMoreEvents && !showAllEvents && (
        <button
          onClick={() => setShowAllEvents(true)}
          className="w-full py-2 text-sm text-blue-400 hover:text-blue-300 
                     bg-sentinel-surface/50 rounded-lg border border-sentinel-border 
                     hover:border-blue-500/30 transition-colors flex items-center justify-center gap-2"
        >
          <ChevronUp className="w-4 h-4" />
          Show {timeline.events.length - maxVisibleEvents} earlier events
        </button>
      )}

      {/* Timeline Events */}
      <div className="relative">
        {/* Vertical timeline line */}
        <div className="absolute left-[19px] top-0 bottom-0 w-0.5 bg-sentinel-border" />
        
        <div className="space-y-1">
          <AnimatePresence mode="popLayout">
            {visibleEvents.map((event, index) => (
              <TimelineEventCard
                key={event.id}
                event={event}
                isExpanded={expandedEventId === event.id}
                onToggleExpand={() => toggleExpand(event.id)}
                isLast={index === visibleEvents.length - 1}
                chain={timeline.chain}
              />
            ))}
          </AnimatePresence>
        </div>
      </div>

      {/* Show Less Button (at bottom if expanded) */}
      {hasMoreEvents && showAllEvents && (
        <button
          onClick={() => setShowAllEvents(false)}
          className="w-full py-2 text-sm text-sentinel-muted hover:text-sentinel-text 
                     transition-colors flex items-center justify-center gap-2"
        >
          <ChevronDown className="w-4 h-4" />
          Show fewer events
        </button>
      )}

      {/* Timeline Legend */}
      <TimelineLegend />
    </div>
  );
}

// ============================================
// CURRENT STATUS BANNER
// ============================================

interface CurrentStatusBannerProps {
  status: WalletTimelineType['currentStatus'];
  metadata: WalletTimelineType['metadata'];
}

function CurrentStatusBanner({ status, metadata }: CurrentStatusBannerProps) {
  const getStatusConfig = () => {
    if (metadata.hasActiveThreats) {
      return {
        icon: AlertCircle,
        bg: 'bg-red-500/10',
        border: 'border-red-500/30',
        text: 'text-red-400',
        label: 'Active Threat',
      };
    }
    if (metadata.isFullyRecovered) {
      return {
        icon: CheckCircle,
        bg: 'bg-green-500/10',
        border: 'border-green-500/30',
        text: 'text-green-400',
        label: 'Recovered',
      };
    }
    if (metadata.hasHistoricalCompromise) {
      return {
        icon: Shield,
        bg: 'bg-orange-500/10',
        border: 'border-orange-500/30',
        text: 'text-orange-400',
        label: 'Historical Incident',
      };
    }
    return {
      icon: CheckCircle,
      bg: 'bg-green-500/10',
      border: 'border-green-500/30',
      text: 'text-green-400',
      label: 'Safe',
    };
  };

  const config = getStatusConfig();
  const Icon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-lg p-4 border ${config.bg} ${config.border}`}
    >
      <div className="flex items-start gap-3">
        <Icon className={`w-5 h-5 ${config.text} mt-0.5`} />
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className={`font-semibold ${config.text}`}>{config.label}</span>
            <span className="text-xs text-sentinel-muted">
              • Updated {formatRelativeTime(status.lastUpdated)}
            </span>
          </div>
          <p className="text-sm text-sentinel-text">{status.summary}</p>
        </div>
      </div>
    </motion.div>
  );
}

// ============================================
// TIMELINE EVENT CARD
// ============================================

interface TimelineEventCardProps {
  event: TimelineEvent;
  isExpanded: boolean;
  onToggleExpand: () => void;
  isLast: boolean;
  chain: string;
}

function TimelineEventCard({ 
  event, 
  isExpanded, 
  onToggleExpand, 
  isLast,
  chain 
}: TimelineEventCardProps) {
  const colors = TIMELINE_SEVERITY_COLORS[event.severityAtTime];
  const Icon = getEventIcon(event.severityAtTime);
  
  const isCurrent = event.eventType === 'SAFE_STATE_CONFIRMED' || 
                    event.eventType === 'RECOVERY_COMPLETE';

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      transition={{ duration: 0.2 }}
      className="relative pl-10"
    >
      {/* Timeline dot */}
      <div 
        className={`absolute left-2 top-3 w-5 h-5 rounded-full flex items-center justify-center
                    ${colors.bg} border-2 ${colors.border} z-10 bg-sentinel-bg`}
      >
        <span className="text-xs">{colors.emoji}</span>
      </div>

      {/* Event card */}
      <div 
        className={`rounded-lg border transition-all duration-200
                    ${isExpanded ? `${colors.bg} ${colors.border}` : 'bg-sentinel-surface border-sentinel-border hover:border-sentinel-elevated'}
                    ${event.isExpandable ? 'cursor-pointer' : ''}`}
        onClick={() => event.isExpandable && onToggleExpand()}
      >
        <div className="p-3">
          {/* Header row */}
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              {/* Date and title */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-sentinel-muted font-mono">
                  {isCurrent ? 'Current' : formatEventDate(event.timestamp)}
                </span>
                <span className="text-sentinel-muted">—</span>
                <span className={`font-semibold text-sm ${colors.text}`}>
                  {event.title}
                </span>
              </div>
              
              {/* Description */}
              <p className="text-sm text-sentinel-text mt-1">
                "{event.description}"
              </p>
            </div>

            {/* Expand button */}
            {event.isExpandable && (
              <button 
                className="p-1 hover:bg-sentinel-elevated rounded transition-colors"
                onClick={(e) => {
                  e.stopPropagation();
                  onToggleExpand();
                }}
              >
                {isExpanded ? (
                  <ChevronUp className="w-4 h-4 text-sentinel-muted" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-sentinel-muted" />
                )}
              </button>
            )}
          </div>

          {/* Expanded details */}
          <AnimatePresence>
            {isExpanded && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="mt-3 pt-3 border-t border-sentinel-border space-y-3">
                  {/* Technical details */}
                  {event.technicalDetails && (
                    <div className="text-xs text-sentinel-muted bg-sentinel-bg rounded p-2 font-mono">
                      {event.technicalDetails}
                    </div>
                  )}

                  {/* References */}
                  {event.references.length > 0 && (
                    <div className="space-y-1">
                      {event.references.map((ref, idx) => (
                        <ReferenceLink key={idx} reference={ref} />
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
}

// ============================================
// REFERENCE LINK
// ============================================

interface ReferenceLinkProps {
  reference: TimelineEventReference;
}

function ReferenceLink({ reference }: ReferenceLinkProps) {
  const getIcon = () => {
    switch (reference.type) {
      case 'transaction': return '📝';
      case 'contract': return '📄';
      case 'address': return '👤';
      case 'approval': return '✅';
      case 'block': return '🧱';
      default: return '🔗';
    }
  };

  const truncateValue = (value: string) => {
    if (value.length <= 20) return value;
    return `${value.slice(0, 10)}...${value.slice(-8)}`;
  };

  return (
    <a
      href={reference.explorerUrl || '#'}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      className="flex items-center gap-2 text-xs text-blue-400 hover:text-blue-300 
                 transition-colors group"
    >
      <span>{getIcon()}</span>
      <span className="font-mono">{truncateValue(reference.value)}</span>
      {reference.label && (
        <span className="text-sentinel-muted">({reference.label})</span>
      )}
      <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
    </a>
  );
}

// ============================================
// TIMELINE LEGEND
// ============================================

function TimelineLegend() {
  const items = [
    { color: TIMELINE_SEVERITY_COLORS.CRITICAL, label: 'Critical Threat' },
    { color: TIMELINE_SEVERITY_COLORS.HIGH, label: 'Threat Stopped' },
    { color: TIMELINE_SEVERITY_COLORS.MEDIUM, label: 'Recovery Action' },
    { color: TIMELINE_SEVERITY_COLORS.SAFE, label: 'Safe State' },
  ];

  return (
    <div className="flex flex-wrap gap-3 pt-3 border-t border-sentinel-border">
      {items.map((item, idx) => (
        <div key={idx} className="flex items-center gap-1.5 text-xs text-sentinel-muted">
          <span>{item.color.emoji}</span>
          <span>{item.label}</span>
        </div>
      ))}
    </div>
  );
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function getEventIcon(severity: TimelineEventSeverity) {
  switch (severity) {
    case 'CRITICAL': return AlertCircle;
    case 'HIGH': return AlertTriangle;
    case 'MEDIUM': return Info;
    case 'LOW': return Info;
    case 'SAFE': return CheckCircle;
    default: return Info;
  }
}

function formatEventDate(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function formatRelativeTime(timestamp: string): string {
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  const diffMs = now - then;
  
  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return 'just now';
}

// ============================================
// COMPACT TIMELINE VARIANT
// ============================================

interface CompactTimelineProps {
  timeline: WalletTimelineType;
  maxEvents?: number;
}

export function CompactTimeline({ timeline, maxEvents = 5 }: CompactTimelineProps) {
  const recentEvents = timeline.events.slice(-maxEvents);
  
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-sm text-sentinel-muted">
        <Clock className="w-4 h-4" />
        <span>Recent Activity</span>
      </div>
      
      <div className="space-y-1">
        {recentEvents.map((event) => {
          const colors = TIMELINE_SEVERITY_COLORS[event.severityAtTime];
          const isCurrent = event.eventType === 'SAFE_STATE_CONFIRMED' || 
                            event.eventType === 'RECOVERY_COMPLETE';
          
          return (
            <div 
              key={event.id}
              className="flex items-center gap-2 text-xs"
            >
              <span>{colors.emoji}</span>
              <span className="text-sentinel-muted font-mono">
                {isCurrent ? 'Now' : new Date(event.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
              </span>
              <span className={`truncate ${colors.text}`}>
                {event.description}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default WalletTimeline;
