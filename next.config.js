/** @type {import('next').NextConfig} */

const nextConfig = {
  reactStrictMode: true,
  
  // ============================================
  // CODE PROTECTION SETTINGS
  // ============================================
  
  // Disable source maps in production - prevents reverse engineering
  productionBrowserSourceMaps: false,
  
  // Enable SWC minification - obfuscates variable names
  swcMinify: true,
  
  // For Cloudflare Pages - no standalone output needed
  // output: 'standalone', // Uncomment for SmarterASP.NET
  
  // Compress output
  compress: true,
  
  // Disable x-powered-by header
  poweredByHeader: false,
  
  images: {
    domains: ['raw.githubusercontent.com', 'assets.coingecko.com'],
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
          // Security headers
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
        ],
      },
      {
        source: '/:path*',
        headers: [
          // Prevent caching of HTML to ensure users get latest version
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-XSS-Protection', value: '1; mode=block' },
        ],
      },
    ];
  },
  
  webpack: (config, { isServer, dev }) => {
    // Handle missing modules for WalletConnect/MetaMask SDK
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        'pino-pretty': false,
        'lokijs': false,
      };
      
      config.resolve.alias = {
        ...config.resolve.alias,
        '@react-native-async-storage/async-storage': false,
      };
    }
    
    // Production optimizations
    if (!dev) {
      // Minimize chunk names for obfuscation
      config.optimization = {
        ...config.optimization,
        moduleIds: 'deterministic',
        chunkIds: 'deterministic',
      };
    }
    
    return config;
  },
  
  experimental: {
    optimizePackageImports: ['lucide-react', 'framer-motion'],
  },
};

module.exports = nextConfig;
