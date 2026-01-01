import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Security-focused dark theme
        sentinel: {
          bg: '#0a0b0d',
          surface: '#12141a',
          elevated: '#1a1d24',
          border: '#2a2f3a',
          muted: '#6b7280',
          text: '#e5e7eb',
          primary: '#3b82f6',
          accent: '#06b6d4',
        },
        status: {
          safe: '#10b981',
          'safe-bg': 'rgba(16, 185, 129, 0.1)',
          warning: '#f59e0b',
          'warning-bg': 'rgba(245, 158, 11, 0.1)',
          danger: '#ef4444',
          'danger-bg': 'rgba(239, 68, 68, 0.1)',
          info: '#3b82f6',
          'info-bg': 'rgba(59, 130, 246, 0.1)',
        },
      },
      fontFamily: {
        sans: ['JetBrains Mono', 'Fira Code', 'monospace'],
        display: ['Space Grotesk', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanLine 2s linear infinite',
        'fade-in': 'fadeIn 0.5s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.8)' },
        },
      },
      backgroundImage: {
        'grid-pattern': 'linear-gradient(to right, #1a1d24 1px, transparent 1px), linear-gradient(to bottom, #1a1d24 1px, transparent 1px)',
        'gradient-radial': 'radial-gradient(ellipse at center, var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
};

export default config;


