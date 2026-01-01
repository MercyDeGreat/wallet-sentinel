/** @type {import('next').NextConfig} */

const nextConfig = {
  reactStrictMode: true,
  
  // Disable source maps in production to prevent code inspection
  productionBrowserSourceMaps: false,
  
  // Minification provides basic code protection
  swcMinify: true,
  
  images: {
    domains: ['raw.githubusercontent.com', 'assets.coingecko.com'],
    // Use unoptimized images for Cloudflare Pages
    unoptimized: true,
  },
  
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,POST,OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type' },
        ],
      },
    ];
  },
  
  webpack: (config, { isServer }) => {
    // Handle missing modules for WalletConnect/MetaMask SDK
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        'pino-pretty': false,
        'lokijs': false,
      };
      
      // Properly ignore react-native-async-storage
      config.resolve.alias = {
        ...config.resolve.alias,
        '@react-native-async-storage/async-storage': false,
      };
    }
    
    return config;
  },
  
  // Enable experimental optimizations
  experimental: {
    optimizePackageImports: ['lucide-react', 'framer-motion'],
  },
};

module.exports = nextConfig;
