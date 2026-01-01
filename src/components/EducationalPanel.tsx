'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  BookOpen,
  Shield,
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ExternalLink,
  Lightbulb,
  Target,
  Lock,
  Eye,
  Zap,
  Users,
} from 'lucide-react';
import { EducationalContent, Chain, RiskLevel, ChecklistItem } from '@/types';

interface EducationalPanelProps {
  content?: EducationalContent;
  chain: Chain;
}

export function EducationalPanel({ content, chain }: EducationalPanelProps) {
  const [activeSection, setActiveSection] = useState<string>('attack');
  const [checklist, setChecklist] = useState<Record<string, boolean>>({});

  const toggleChecklistItem = (id: string) => {
    setChecklist((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const sections = [
    { id: 'attack', label: 'Attack Analysis', icon: Target },
    { id: 'prevention', label: 'Prevention Tips', icon: Shield },
    { id: 'checklist', label: 'Security Checklist', icon: CheckCircle },
    { id: 'resources', label: 'Resources', icon: BookOpen },
  ];

  return (
    <div className="space-y-6">
      {/* Section Tabs */}
      <div className="flex gap-2 overflow-x-auto pb-2">
        {sections.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveSection(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg whitespace-nowrap transition-all ${
              activeSection === id
                ? 'bg-sentinel-primary text-white'
                : 'bg-sentinel-surface hover:bg-sentinel-elevated text-sentinel-text'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Attack Analysis */}
      {activeSection === 'attack' && content?.attackExplanation && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <AttackExplanationCard
            title="What Happened?"
            content={content.attackExplanation.whatHappened}
            icon={<AlertTriangle className="w-5 h-5 text-status-warning" />}
            color="warning"
          />
          <AttackExplanationCard
            title="How It Works"
            content={content.attackExplanation.howItWorks}
            icon={<Zap className="w-5 h-5 text-blue-400" />}
            color="info"
          />
          <AttackExplanationCard
            title="Ongoing Damage"
            content={content.attackExplanation.ongoingDamage}
            icon={<AlertTriangle className="w-5 h-5 text-status-danger" />}
            color="danger"
          />
          <AttackExplanationCard
            title="What Can Be Recovered"
            content={content.attackExplanation.recoverableInfo}
            icon={<Shield className="w-5 h-5 text-status-safe" />}
            color="safe"
          />
        </motion.div>
      )}

      {/* Prevention Tips */}
      {activeSection === 'prevention' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-4"
        >
          {content?.preventionTips.map((tip, index) => (
            <PreventionTipCard key={index} tip={tip} index={index} />
          ))}

          {/* General Best Practices */}
          <div className="glass-card rounded-xl p-6">
            <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
              <Lightbulb className="w-5 h-5 text-yellow-400" />
              General Best Practices
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <BestPracticeItem
                icon={<Lock className="w-4 h-4" />}
                title="Use Hardware Wallets"
                description="Keep significant holdings in cold storage"
              />
              <BestPracticeItem
                icon={<Eye className="w-4 h-4" />}
                title="Verify Before Signing"
                description="Always read transaction details carefully"
              />
              <BestPracticeItem
                icon={<Shield className="w-4 h-4" />}
                title="Limit Approvals"
                description="Only approve exact amounts needed"
              />
              <BestPracticeItem
                icon={<Users className="w-4 h-4" />}
                title="Use Separate Wallets"
                description="Different wallets for different purposes"
              />
            </div>
          </div>

          {/* Chain-Specific Tips */}
          <ChainSpecificTips chain={chain} />
        </motion.div>
      )}

      {/* Security Checklist */}
      {activeSection === 'checklist' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <div className="glass-card rounded-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-display font-semibold text-lg flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-status-safe" />
                Wallet Security Checklist
              </h3>
              <div className="text-sm text-sentinel-muted">
                {Object.values(checklist).filter(Boolean).length} / {content?.securityChecklist.length || 0} completed
              </div>
            </div>

            {/* Progress Bar */}
            <div className="h-2 bg-sentinel-surface rounded-full overflow-hidden mb-6">
              <motion.div
                className="h-full bg-gradient-to-r from-status-safe to-cyan-500"
                initial={{ width: 0 }}
                animate={{
                  width: `${
                    (Object.values(checklist).filter(Boolean).length /
                      (content?.securityChecklist.length || 1)) *
                    100
                  }%`,
                }}
                transition={{ duration: 0.5 }}
              />
            </div>

            {/* Grouped Checklist */}
            {content?.securityChecklist && (
              <ChecklistGroups
                items={content.securityChecklist}
                checklist={checklist}
                onToggle={toggleChecklistItem}
                chain={chain}
              />
            )}
          </div>
        </motion.div>
      )}

      {/* Resources */}
      {activeSection === 'resources' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <div className="glass-card rounded-xl p-6">
            <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-blue-400" />
              Security Resources
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ResourceLink
                title="Revoke.cash"
                description="Check and revoke token approvals"
                url="https://revoke.cash"
              />
              <ResourceLink
                title="Etherscan Token Approvals"
                description="View ERC-20 token approvals"
                url="https://etherscan.io/tokenapprovalchecker"
              />
              <ResourceLink
                title="ScamSniffer"
                description="Real-time scam detection"
                url="https://scamsniffer.io"
              />
              <ResourceLink
                title="ChainAbuse"
                description="Report and lookup malicious addresses"
                url="https://www.chainabuse.com"
              />
              <ResourceLink
                title="Forta Network"
                description="Real-time threat detection"
                url="https://forta.org"
              />
              <ResourceLink
                title="Wallet Guard"
                description="Transaction security extension"
                url="https://walletguard.app"
              />
            </div>
          </div>

          {/* Disclaimer */}
          <div className="glass-card rounded-xl p-6 border-l-4 border-l-status-warning">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-status-warning flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium text-status-warning mb-2">Important Disclaimer</h4>
                <p className="text-sm text-sentinel-muted">
                  The information provided here is for educational purposes only and should not be
                  considered financial or security advice. Always do your own research and consult
                  with security professionals when dealing with compromised wallets. We are not
                  responsible for any losses incurred.
                </p>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

function AttackExplanationCard({
  title,
  content,
  icon,
  color,
}: {
  title: string;
  content: string;
  icon: React.ReactNode;
  color: 'warning' | 'info' | 'danger' | 'safe';
}) {
  const [isExpanded, setIsExpanded] = useState(true);

  const borderColors = {
    warning: 'border-l-status-warning',
    info: 'border-l-blue-500',
    danger: 'border-l-status-danger',
    safe: 'border-l-status-safe',
  };

  return (
    <div className={`glass-card rounded-xl overflow-hidden border-l-4 ${borderColors[color]}`}>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-center justify-between hover:bg-sentinel-surface/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          {icon}
          <h4 className="font-display font-semibold">{title}</h4>
        </div>
        <ChevronDown
          className={`w-5 h-5 text-sentinel-muted transition-transform ${
            isExpanded ? 'rotate-180' : ''
          }`}
        />
      </button>
      {isExpanded && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: 'auto', opacity: 1 }}
          className="px-4 pb-4"
        >
          <p className="text-sentinel-muted leading-relaxed">{content}</p>
        </motion.div>
      )}
    </div>
  );
}

function PreventionTipCard({
  tip,
  index,
}: {
  tip: { title: string; description: string; importance: RiskLevel };
  index: number;
}) {
  const importanceColors = {
    CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
    HIGH: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
    MEDIUM: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
    LOW: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30' },
  };

  const colors = importanceColors[tip.importance];

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      className={`glass-card rounded-xl p-4 border ${colors.border}`}
    >
      <div className="flex items-start gap-4">
        <div className={`p-2 rounded-lg ${colors.bg}`}>
          <Shield className={`w-5 h-5 ${colors.text}`} />
        </div>
        <div>
          <h4 className="font-medium mb-1">{tip.title}</h4>
          <p className="text-sm text-sentinel-muted">{tip.description}</p>
        </div>
        <span className={`px-2 py-1 text-xs rounded ${colors.bg} ${colors.text}`}>
          {tip.importance}
        </span>
      </div>
    </motion.div>
  );
}

function BestPracticeItem({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="p-4 bg-sentinel-surface rounded-lg">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-blue-400">{icon}</span>
        <h5 className="font-medium text-sm">{title}</h5>
      </div>
      <p className="text-xs text-sentinel-muted">{description}</p>
    </div>
  );
}

function ChainSpecificTips({ chain }: { chain: Chain }) {
  const tips: Record<Chain, { title: string; tips: string[] }> = {
    ethereum: {
      title: 'Ethereum Security Tips',
      tips: [
        'Use EIP-712 typed signatures when possible for better readability',
        'Be cautious of gasless transactions (permit signatures)',
        'Check contract verification on Etherscan before interacting',
        'Consider using Flashbots Protect to prevent MEV attacks',
      ],
    },
    base: {
      title: 'Base Security Tips',
      tips: [
        'Base is an L2 - verify you are on the correct network',
        'Bridge assets carefully - use official bridges only',
        'Lower gas costs may enable more frequent approval audits',
        'Check if protocols are verified on both L1 and L2',
      ],
    },
    bnb: {
      title: 'BNB Chain Security Tips',
      tips: [
        'Be extra cautious of cloned/forked protocols',
        'Verify contract addresses match official sources',
        'Many scams originate on BSC - verify everything twice',
        'Use BscScan to check contract verification',
      ],
    },
    solana: {
      title: 'Solana Security Tips',
      tips: [
        'Verify program IDs match official documentation',
        'Be cautious of token account delegations',
        'Close unused token accounts to reclaim rent',
        'Check program upgrade authority status',
      ],
    },
  };

  const chainTips = tips[chain];

  return (
    <div className="glass-card rounded-xl p-6 border-l-4 border-l-cyan-500">
      <h4 className="font-display font-semibold mb-4 flex items-center gap-2">
        <Zap className="w-5 h-5 text-cyan-400" />
        {chainTips.title}
      </h4>
      <ul className="space-y-3">
        {chainTips.tips.map((tip, index) => (
          <li key={index} className="flex items-start gap-2 text-sm">
            <CheckCircle className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <span className="text-sentinel-muted">{tip}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ChecklistGroups({
  items,
  checklist,
  onToggle,
  chain,
}: {
  items: ChecklistItem[];
  checklist: Record<string, boolean>;
  onToggle: (id: string) => void;
  chain: Chain;
}) {
  // Group items by category
  const groups = items.reduce((acc, item) => {
    // Filter chain-specific items
    if (item.chainSpecific && !item.chainSpecific.includes(chain)) {
      return acc;
    }

    if (!acc[item.category]) {
      acc[item.category] = [];
    }
    acc[item.category].push(item);
    return acc;
  }, {} as Record<string, ChecklistItem[]>);

  return (
    <div className="space-y-6">
      {Object.entries(groups).map(([category, items]) => (
        <div key={category}>
          <h4 className="text-sm font-medium text-sentinel-muted mb-3">{category}</h4>
          <div className="space-y-2">
            {items.map((item) => (
              <button
                key={item.id}
                onClick={() => onToggle(item.id)}
                className={`w-full flex items-center gap-3 p-3 rounded-lg transition-all ${
                  checklist[item.id]
                    ? 'bg-status-safe-bg/50'
                    : 'bg-sentinel-surface hover:bg-sentinel-elevated'
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full border-2 flex items-center justify-center transition-colors ${
                    checklist[item.id]
                      ? 'bg-status-safe border-status-safe'
                      : 'border-sentinel-border'
                  }`}
                >
                  {checklist[item.id] && <CheckCircle className="w-3 h-3 text-white" />}
                </div>
                <span
                  className={`text-sm text-left ${
                    checklist[item.id] ? 'line-through text-sentinel-muted' : ''
                  }`}
                >
                  {item.item}
                </span>
                {item.chainSpecific && (
                  <span className="ml-auto px-2 py-0.5 text-xs bg-sentinel-surface rounded">
                    {chain.toUpperCase()}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ResourceLink({
  title,
  description,
  url,
}: {
  title: string;
  description: string;
  url: string;
}) {
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="p-4 bg-sentinel-surface rounded-lg hover:bg-sentinel-elevated transition-colors group"
    >
      <div className="flex items-center justify-between mb-1">
        <h5 className="font-medium text-blue-400 group-hover:text-blue-300">{title}</h5>
        <ExternalLink className="w-4 h-4 text-sentinel-muted" />
      </div>
      <p className="text-xs text-sentinel-muted">{description}</p>
    </a>
  );
}

