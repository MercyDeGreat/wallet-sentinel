'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { WalletAnalysisResult, Chain, SecurityStatus } from '@/types';
import { WalletInput } from '@/components/WalletInput';
import { SecurityDashboard } from '@/components/SecurityDashboard';
import { LoadingState } from '@/components/LoadingState';
import { Header } from '@/components/Header';
import { Shield, Lock, Eye, AlertTriangle } from 'lucide-react';

export default function HomePage() {
  const [analysisResult, setAnalysisResult] = useState<WalletAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (address: string, chain: Chain) => {
    setIsLoading(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address, chain }),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error?.message || 'Analysis failed');
      }

      setAnalysisResult(data.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setAnalysisResult(null);
    setError(null);
  };

  return (
    <main className="min-h-screen pb-6">
      <Header />

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Hero Section - Only show when no results */}
        <AnimatePresence mode="wait">
          {!analysisResult && !isLoading && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
              className="text-center mb-12"
            >
              <motion.div
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: 0.2, duration: 0.5 }}
                className="inline-flex items-center justify-center w-24 h-24 mb-6"
              >
                <img 
                  src="/logo.png" 
                  alt="Securnex" 
                  className="w-full h-full drop-shadow-[0_0_20px_rgba(0,212,255,0.5)]"
                />
              </motion.div>

              <h1 className="text-4xl md:text-5xl font-bold mb-4 tracking-wide">
                <span className="text-white">SECURNE</span>
                <span className="text-cyan-400">X</span>
              </h1>

              <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-8">
                Comprehensive security analysis for your blockchain wallets. 
                Detect threats, protect assets, recover safely.
              </p>

              {/* Feature highlights */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto mb-12">
                <FeatureCard
                  icon={<Eye className="w-5 h-5" />}
                  title="Threat Detection"
                  description="Identify drainers, approval abuse, and malicious contracts"
                  delay={0.3}
                />
                <FeatureCard
                  icon={<Lock className="w-5 h-5" />}
                  title="Recovery Tools"
                  description="Safely revoke approvals and protect remaining assets"
                  delay={0.4}
                />
                <FeatureCard
                  icon={<AlertTriangle className="w-5 h-5" />}
                  title="Live Monitoring"
                  description="Real-time alerts for ongoing threats and risks"
                  delay={0.5}
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Wallet Input Section */}
        <motion.div
          layout
          className={`${analysisResult ? 'mb-6' : 'mb-12'}`}
        >
          <WalletInput
            onAnalyze={handleAnalyze}
            onReset={handleReset}
            isLoading={isLoading}
            hasResult={!!analysisResult}
          />

          {error && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4 p-4 bg-status-danger-bg border border-status-danger/30 rounded-lg text-center"
            >
              <p className="text-status-danger">{error}</p>
            </motion.div>
          )}
        </motion.div>

        {/* Loading State */}
        <AnimatePresence>
          {isLoading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <LoadingState />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Analysis Results */}
        <AnimatePresence>
          {analysisResult && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
            >
              <SecurityDashboard result={analysisResult} />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Supported Chains - Only show when no results */}
        {!analysisResult && !isLoading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6 }}
            className="text-center"
          >
            <p className="text-sentinel-muted text-sm mb-4">Supported Chains</p>
            <div className="flex justify-center gap-6 flex-wrap">
              <ChainBadge name="Ethereum" color="blue" />
              <ChainBadge name="Base" color="blue" />
              <ChainBadge name="BNB Chain" color="yellow" />
              <ChainBadge name="Solana" color="purple" />
            </div>
          </motion.div>
        )}
      </div>
    </main>
  );
}

function FeatureCard({
  icon,
  title,
  description,
  delay,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="p-4 bg-sentinel-surface/50 border border-sentinel-border rounded-xl card-hover"
    >
      <div className="flex items-center gap-3 mb-2">
        <div className="text-blue-400">{icon}</div>
        <h3 className="font-display font-semibold text-sentinel-text">{title}</h3>
      </div>
      <p className="text-sm text-sentinel-muted">{description}</p>
    </motion.div>
  );
}

function ChainBadge({ name, color }: { name: string; color: 'blue' | 'yellow' | 'purple' }) {
  const colorClasses = {
    blue: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
    yellow: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
    purple: 'bg-purple-500/10 border-purple-500/30 text-purple-400',
  };

  return (
    <span className={`px-4 py-2 rounded-full border text-sm ${colorClasses[color]}`}>
      {name}
    </span>
  );
}


