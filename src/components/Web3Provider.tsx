'use client';

import { useState, useEffect, type ReactNode } from 'react';
import { WagmiProvider, createConfig, http } from 'wagmi';
import { mainnet, base, bsc } from 'wagmi/chains';
import { RainbowKitProvider, darkTheme, getDefaultConfig } from '@rainbow-me/rainbowkit';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@rainbow-me/rainbowkit/styles.css';

const queryClient = new QueryClient();

// Create config outside component to avoid recreation
const wagmiConfig = getDefaultConfig({
  appName: 'Wallet Sentinel',
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

  useEffect(() => {
    setMounted(true);
  }, []);

  // Avoid hydration mismatch
  if (!mounted) {
    return <>{children}</>;
  }

  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider
          theme={darkTheme({
            accentColor: '#10b981',
            accentColorForeground: 'white',
            borderRadius: 'medium',
            fontStack: 'system',
            overlayBlur: 'small',
          })}
          modalSize="compact"
        >
          {children}
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}
