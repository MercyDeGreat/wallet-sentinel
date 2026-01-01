import type { Metadata } from 'next';
import './globals.css';
import { Web3Provider } from '@/components/Web3Provider';

export const metadata: Metadata = {
  title: 'Securnex | Blockchain Security Analysis',
  description: 'Comprehensive wallet security analysis for Ethereum, Base, BNB Chain, and Solana. Detect wallet drainers, approval hijacks, and more.',
  keywords: ['crypto security', 'wallet security', 'blockchain analysis', 'drainer detection', 'web3 security', 'securnex'],
  authors: [{ name: 'MercyDeGreat' }],
  openGraph: {
    title: 'Securnex | Blockchain Security Analysis',
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
      <body className="min-h-screen bg-black antialiased">
        {/* Background effects - subtle grid */}
        <div className="fixed inset-0 grid-pattern opacity-20 pointer-events-none" />
        <div className="fixed inset-0 bg-gradient-radial from-cyan-950/20 via-transparent to-transparent pointer-events-none" />
        
        {/* Main content with Web3 Provider */}
        <Web3Provider>
          <div className="relative z-10">
            {children}
          </div>
        </Web3Provider>

        {/* Footer disclaimer */}
        <footer className="fixed bottom-0 left-0 right-0 bg-black/90 backdrop-blur-sm border-t border-cyan-900/30 py-3 px-4 z-50">
          <p className="text-center text-xs text-gray-500 max-w-4xl mx-auto">
            <strong className="text-cyan-500">⚠️ Disclaimer:</strong> Securnex provides security analysis for educational purposes only. 
            No wallet custody, no guarantees, no offensive actions. All analysis is read-only. 
            Always verify independently before taking action.
          </p>
        </footer>
      </body>
    </html>
  );
}
