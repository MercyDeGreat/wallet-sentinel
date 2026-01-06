'use client';

import Image from 'next/image';
import { motion } from 'framer-motion';

// X (Twitter) Icon Component
function XIcon({ className }: { className?: string }) {
  return (
    <svg 
      viewBox="0 0 24 24" 
      className={className}
      fill="currentColor"
    >
      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
    </svg>
  );
}

export function Header() {
  return (
    <header className="border-b border-cyan-900/30 bg-black/90 backdrop-blur-sm sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-3"
        >
          {/* Logo */}
          <div className="relative w-10 h-10">
            <Image
              src="/logo.png"
              alt="Securnex Logo"
              width={40}
              height={40}
              className="drop-shadow-[0_0_10px_rgba(0,212,255,0.5)]"
            />
          </div>
          <div>
            <h1 className="font-bold text-xl tracking-wide">
              <span className="text-white">SECURNE</span>
              <span className="text-cyan-400">X</span>
            </h1>
            <p className="text-[10px] text-cyan-500/70 tracking-widest uppercase">Security Analysis Platform</p>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-3"
        >
          <span className="text-sm text-gray-500 hidden sm:inline">
            Built by <span className="text-cyan-400 font-medium">MercyDeGreat</span>
          </span>
          <a
            href="https://x.com/mercydegreat"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-black border border-cyan-800/50 hover:border-cyan-500/70 hover:shadow-[0_0_15px_rgba(0,212,255,0.3)] transition-all group"
          >
            <XIcon className="w-4 h-4 text-white" />
            <span className="text-sm text-white font-medium">Follow</span>
          </a>
        </motion.div>
      </div>
    </header>
  );
}
