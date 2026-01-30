import type { Metadata, Viewport } from 'next';
import './globals.css';
import { Web3Provider } from '@/components/Web3Provider';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  userScalable: true,
  themeColor: '#000000',
};

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
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'Securnex',
  },
  formatDetection: {
    telephone: false,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <head>
        {/* iOS Safari specific meta tags */}
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="mobile-web-app-capable" content="yes" />
      </head>
      <body className="min-h-screen min-h-[100dvh] bg-black antialiased overscroll-none">
        {/* Background effects - subtle grid */}
        <div className="fixed inset-0 grid-pattern opacity-20 pointer-events-none" />
        <div className="fixed inset-0 bg-gradient-radial from-cyan-950/20 via-transparent to-transparent pointer-events-none" />
        
        {/* Main content with Web3 Provider */}
        <Web3Provider>
          {/* Use CSS Grid for proper footer placement - works better than flexbox on iOS */}
          <div className="relative z-10 grid min-h-screen min-h-[100dvh]" style={{ gridTemplateRows: '1fr auto' }}>
            <main className="overflow-x-hidden">
              {children}
            </main>
            
            {/* Footer disclaimer - stays at bottom of content, never fixed */}
            <footer 
              className="bg-black/95 border-t border-cyan-900/30 py-3 px-4"
              style={{ 
                paddingBottom: 'calc(0.75rem + env(safe-area-inset-bottom, 0px))',
                position: 'relative',  /* Explicitly not fixed */
                width: '100%'
              }}
            >
              <p className="text-center text-[10px] sm:text-xs text-gray-500 max-w-4xl mx-auto leading-relaxed">
                <strong className="text-cyan-500">⚠️ Disclaimer:</strong> Securnex provides security analysis for educational purposes only. 
                No wallet custody, no guarantees, no offensive actions. All analysis is read-only. 
                Always verify independently before taking action.
              </p>
            </footer>
          </div>
        </Web3Provider>
      </body>
    </html>
  );
}
