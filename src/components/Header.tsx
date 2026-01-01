'use client';

import { Shield, Github, ExternalLink } from 'lucide-react';
import { motion } from 'framer-motion';

export function Header() {
  return (
    <header className="border-b border-sentinel-border bg-sentinel-bg/80 backdrop-blur-sm sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-3"
        >
          <div className="p-2 rounded-lg bg-gradient-to-br from-blue-600/20 to-cyan-600/20 border border-blue-500/30">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="font-display font-bold text-lg gradient-text">Wallet Sentinel</h1>
            <p className="text-xs text-sentinel-muted">Security Analysis Platform</p>
          </div>
        </motion.div>

        <motion.nav
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-4"
        >
          <a
            href="#about"
            className="text-sm text-sentinel-muted hover:text-sentinel-text transition-colors"
          >
            About
          </a>
          <a
            href="#faq"
            className="text-sm text-sentinel-muted hover:text-sentinel-text transition-colors"
          >
            FAQ
          </a>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-sentinel-surface border border-sentinel-border hover:border-sentinel-primary transition-colors"
          >
            <Github className="w-4 h-4" />
            <span className="text-sm">GitHub</span>
          </a>
        </motion.nav>
      </div>
    </header>
  );
}


