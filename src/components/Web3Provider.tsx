'use client';

import { useState, useEffect, type ReactNode } from 'react';
import { WagmiProvider, http } from 'wagmi';
import { mainnet, base, bsc } from 'wagmi/chains';
import { RainbowKitProvider, darkTheme, getDefaultConfig } from '@rainbow-me/rainbowkit';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@rainbow-me/rainbowkit/styles.css';

// Create query client with error handling
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30000,
    },
  },
});

// Create config outside component to avoid recreation
const wagmiConfig = getDefaultConfig({
  appName: 'Securnex',
  projectId: process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || '0a0c3e4e9d6d4a8b9f0c3e4e9d6d4a8b',
  chains: [mainnet, base, bsc],
  transports: {
    [mainnet.id]: http('https://eth.llamarpc.com'),
    [base.id]: http('https://base.llamarpc.com'),
    [bsc.id]: http('https://bsc-dataseed.binance.org'),
  },
  ssr: true,
});

export function Web3Provider({ children }: { children: ReactNode }) {
  const [mounted, setMounted] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    try {
      setMounted(true);
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to initialize Web3'));
    }
  }, []);

  // Avoid hydration mismatch - render children without providers on server
  if (!mounted) {
    return <>{children}</>;
  }

  // If there's an error with Web3, still render the app (analysis works without wallet)
  if (error) {
    console.warn('Web3Provider initialization error:', error.message);
    return <>{children}</>;
  }

  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider
          theme={darkTheme({
            accentColor: '#06b6d4',
            accentColorForeground: 'white',
            borderRadius: 'medium',
            fontStack: 'system',
            overlayBlur: 'small',
          })}
          modalSize="compact"
          coolMode
        >
          {children}
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}
