// ============================================
// DATABASE CONNECTION FOR VERCEL + NEON
// ============================================
// Neon serverless PostgreSQL driver

import { neon, NeonQueryFunction } from '@neondatabase/serverless';

// Type for SQL query function
export type NeonClient = NeonQueryFunction<false, false>;

// Cached client instance
let cachedClient: NeonClient | null = null;

// Get database client
export function getDb(): NeonClient | null {
  if (cachedClient) return cachedClient;
  
  const connectionString = process.env.DATABASE_URL;
  
  if (!connectionString) {
    console.warn('[METRICS] DATABASE_URL not configured - metrics disabled');
    return null;
  }
  
  cachedClient = neon(connectionString);
  return cachedClient;
}
