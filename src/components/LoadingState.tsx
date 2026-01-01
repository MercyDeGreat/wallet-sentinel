'use client';

import { motion } from 'framer-motion';
import { Shield, Search, Database, FileSearch, CheckCircle } from 'lucide-react';

const steps = [
  { icon: Search, label: 'Fetching transaction history...' },
  { icon: Database, label: 'Checking malicious contract database...' },
  { icon: FileSearch, label: 'Analyzing approval patterns...' },
  { icon: Shield, label: 'Calculating risk score...' },
  { icon: CheckCircle, label: 'Generating security report...' },
];

export function LoadingState() {
  return (
    <div className="max-w-2xl mx-auto">
      <motion.div
        className="glass-card rounded-2xl p-8"
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
      >
        {/* Animated Shield */}
        <div className="flex justify-center mb-8">
          <motion.div
            className="relative"
            animate={{
              scale: [1, 1.05, 1],
            }}
            transition={{
              duration: 2,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          >
            <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-blue-600/20 to-cyan-600/20 border border-blue-500/30 flex items-center justify-center">
              <Shield className="w-12 h-12 text-blue-400" />
            </div>

            {/* Scanning effect */}
            <motion.div
              className="absolute inset-0 rounded-2xl overflow-hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              <motion.div
                className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-blue-400 to-transparent"
                animate={{
                  top: ['0%', '100%'],
                }}
                transition={{
                  duration: 1.5,
                  repeat: Infinity,
                  ease: 'linear',
                }}
              />
            </motion.div>
          </motion.div>
        </div>

        <h2 className="text-xl font-display font-semibold text-center mb-2">
          Analyzing Wallet Security
        </h2>
        <p className="text-sentinel-muted text-center text-sm mb-8">
          This may take a few moments...
        </p>

        {/* Progress Steps */}
        <div className="space-y-3">
          {steps.map((step, index) => {
            const Icon = step.icon;
            return (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.5 }}
                className="flex items-center gap-3 p-3 rounded-lg bg-sentinel-surface/50"
              >
                <motion.div
                  animate={{
                    opacity: [0.5, 1, 0.5],
                  }}
                  transition={{
                    duration: 1.5,
                    repeat: Infinity,
                    delay: index * 0.2,
                  }}
                >
                  <Icon className="w-5 h-5 text-blue-400" />
                </motion.div>
                <span className="text-sm text-sentinel-text">{step.label}</span>
                <motion.div
                  className="ml-auto w-4 h-4 rounded-full border-2 border-blue-400 border-t-transparent"
                  animate={{ rotate: 360 }}
                  transition={{
                    duration: 1,
                    repeat: Infinity,
                    ease: 'linear',
                  }}
                />
              </motion.div>
            );
          })}
        </div>

        {/* Terminal-style output */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
          className="mt-6 terminal"
        >
          <div className="terminal-header">
            <div className="terminal-dot bg-red-500" />
            <div className="terminal-dot bg-yellow-500" />
            <div className="terminal-dot bg-green-500" />
          </div>
          <div className="terminal-content text-xs">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1.5 }}
            >
              <span className="text-green-400">$</span>
              <span className="text-sentinel-muted"> sentinel analyze --chain ethereum</span>
            </motion.div>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 2 }}
              className="text-blue-400"
            >
              → Connecting to blockchain RPC...
            </motion.div>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 2.5 }}
              className="text-cyan-400"
            >
              → Scanning for known threat patterns...
            </motion.div>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: [0, 1, 0, 1] }}
              transition={{ delay: 3, duration: 0.5 }}
              className="text-sentinel-muted"
            >
              █
            </motion.div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
}

