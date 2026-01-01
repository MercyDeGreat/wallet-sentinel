import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Wallet Sentinel | Blockchain Security Analysis',
  description: 'Comprehensive wallet security analysis for Ethereum, Base, BNB Chain, and Solana. Detect wallet drainers, approval hijacks, and more.',
  keywords: ['crypto security', 'wallet security', 'blockchain analysis', 'drainer detection', 'web3 security'],
  authors: [{ name: 'Wallet Sentinel' }],
  openGraph: {
    title: 'Wallet Sentinel | Blockchain Security Analysis',
    description: 'Protect your crypto assets with comprehensive security analysis',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-sentinel-bg antialiased">
        {/* Background effects */}
        <div className="fixed inset-0 grid-pattern opacity-30 pointer-events-none" />
        <div className="fixed inset-0 bg-gradient-radial from-blue-900/10 via-transparent to-transparent pointer-events-none" />
        
        {/* Main content */}
        <div className="relative z-10">
          {children}
        </div>

        {/* Footer disclaimer */}
        <footer className="fixed bottom-0 left-0 right-0 bg-sentinel-bg/80 backdrop-blur-sm border-t border-sentinel-border py-3 px-4 z-50">
          <p className="text-center text-xs text-sentinel-muted max-w-4xl mx-auto">
            <strong className="text-status-warning">⚠️ Disclaimer:</strong> Wallet Sentinel provides security analysis for educational purposes only. 
            No wallet custody, no guarantees, no offensive actions. All analysis is read-only. 
            Always verify independently before taking action.
          </p>
        </footer>
      </body>
    </html>
  );
}

