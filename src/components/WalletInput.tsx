'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, ChevronDown, RotateCcw, Loader2 } from 'lucide-react';
import { Chain } from '@/types';

interface WalletInputProps {
  onAnalyze: (address: string, chain: Chain) => void;
  onReset: () => void;
  isLoading: boolean;
  hasResult: boolean;
}

const CHAINS: { id: Chain; name: string; icon: string }[] = [
  { id: 'ethereum', name: 'Ethereum', icon: '⟠' },
  { id: 'base', name: 'Base', icon: '🔵' },
  { id: 'bnb', name: 'BNB Chain', icon: '🟡' },
  { id: 'solana', name: 'Solana', icon: '◎' },
];

export function WalletInput({ onAnalyze, onReset, isLoading, hasResult }: WalletInputProps) {
  const [address, setAddress] = useState('');
  const [chain, setChain] = useState<Chain>('ethereum');
  const [isChainDropdownOpen, setIsChainDropdownOpen] = useState(false);

  const selectedChain = CHAINS.find((c) => c.id === chain) || CHAINS[0];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (address.trim() && !isLoading) {
      onAnalyze(address.trim(), chain);
    }
  };

  const handleReset = () => {
    setAddress('');
    onReset();
  };

  const getPlaceholder = () => {
    if (chain === 'solana') {
      return 'Enter Solana wallet address...';
    }
    return 'Enter wallet address (0x...)';
  };

  return (
    <motion.div
      layout
      className={`max-w-3xl mx-auto ${hasResult ? 'sticky top-20 z-30' : ''}`}
    >
      <form onSubmit={handleSubmit}>
        <div className={`glass-card rounded-2xl p-2 ${hasResult ? 'shadow-xl' : ''}`}>
          <div className="flex flex-col md:flex-row gap-2">
            {/* Chain Selector */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setIsChainDropdownOpen(!isChainDropdownOpen)}
                className="flex items-center gap-2 px-4 py-3 bg-sentinel-surface rounded-xl border border-sentinel-border hover:border-sentinel-primary transition-colors min-w-[160px]"
              >
                <span className="text-lg">{selectedChain.icon}</span>
                <span className="text-sm font-medium">{selectedChain.name}</span>
                <ChevronDown className={`w-4 h-4 ml-auto transition-transform ${isChainDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {isChainDropdownOpen && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="absolute top-full left-0 mt-2 w-full bg-sentinel-elevated border border-sentinel-border rounded-xl shadow-xl z-50 overflow-hidden"
                >
                  {CHAINS.map((c) => (
                    <button
                      key={c.id}
                      type="button"
                      onClick={() => {
                        setChain(c.id);
                        setIsChainDropdownOpen(false);
                      }}
                      className={`flex items-center gap-2 w-full px-4 py-3 hover:bg-sentinel-surface transition-colors ${
                        c.id === chain ? 'bg-sentinel-surface text-blue-400' : ''
                      }`}
                    >
                      <span className="text-lg">{c.icon}</span>
                      <span className="text-sm">{c.name}</span>
                    </button>
                  ))}
                </motion.div>
              )}
            </div>

            {/* Address Input */}
            <div className="flex-1 relative">
              <input
                type="text"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder={getPlaceholder()}
                className="w-full bg-sentinel-surface border border-sentinel-border rounded-xl px-4 py-3 pr-12 text-sentinel-text placeholder-sentinel-muted focus:outline-none focus:border-sentinel-primary focus:ring-1 focus:ring-sentinel-primary transition-all font-mono text-sm"
                disabled={isLoading}
              />
              <Search className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-sentinel-muted" />
            </div>

            {/* Action Buttons */}
            <div className="flex gap-2">
              {hasResult && (
                <button
                  type="button"
                  onClick={handleReset}
                  className="px-4 py-3 bg-sentinel-surface border border-sentinel-border rounded-xl hover:border-sentinel-primary transition-colors"
                  title="New Analysis"
                >
                  <RotateCcw className="w-5 h-5" />
                </button>
              )}

              <button
                type="submit"
                disabled={!address.trim() || isLoading}
                className="btn-primary flex items-center gap-2 rounded-xl min-w-[120px] justify-center"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Analyzing</span>
                  </>
                ) : (
                  <span>Analyze</span>
                )}
              </button>
            </div>
          </div>
        </div>
      </form>

      {/* Security Notice */}
      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
        className="text-center text-xs text-sentinel-muted mt-3"
      >
        🔒 Read-only analysis • No wallet connection required • Your address is not stored
      </motion.p>
    </motion.div>
  );
}


