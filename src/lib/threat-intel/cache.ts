// ============================================
// THREAT INTELLIGENCE CACHE
// ============================================
// Caching layer for threat intelligence results.
// Supports both in-memory and Redis backends.
//
// CACHING STRATEGY:
// - Cache by (address + chain) composite key
// - Shorter TTL for threat results (may change)
// - Longer TTL for clean results (stable)
// - Automatic expiration handling
// - Optional Redis for distributed deployments

import { ThreatReport, CacheConfig } from './types';

// ============================================
// CACHE INTERFACE
// ============================================

export interface CacheEntry<T> {
  data: T;
  createdAt: number;
  expiresAt: number;
  key: string;
}

export interface ThreatIntelCache {
  get(key: string): Promise<ThreatReport | null>;
  set(key: string, report: ThreatReport, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
  has(key: string): Promise<boolean>;
  getStats(): CacheStats;
}

export interface CacheStats {
  size: number;
  hits: number;
  misses: number;
  hitRate: number;
  oldestEntry?: number;
  newestEntry?: number;
}

// ============================================
// MEMORY CACHE IMPLEMENTATION
// ============================================

/**
 * In-memory cache implementation using LRU eviction.
 * Suitable for single-server deployments.
 */
export class MemoryThreatCache implements ThreatIntelCache {
  private cache: Map<string, CacheEntry<ThreatReport>> = new Map();
  private maxSize: number;
  private defaultTTL: number;
  private cleanTTL: number;
  private threatTTL: number;
  private hits: number = 0;
  private misses: number = 0;

  constructor(config: CacheConfig) {
    this.maxSize = config.maxSize || 10000;
    this.defaultTTL = config.defaultTTLSeconds;
    this.cleanTTL = config.cleanTTLSeconds;
    this.threatTTL = config.threatTTLSeconds;
  }

  async get(key: string): Promise<ThreatReport | null> {
    const normalizedKey = this.normalizeKey(key);
    const entry = this.cache.get(normalizedKey);

    if (!entry) {
      this.misses++;
      return null;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(normalizedKey);
      this.misses++;
      return null;
    }

    this.hits++;
    
    // Move to end for LRU (most recently used)
    this.cache.delete(normalizedKey);
    this.cache.set(normalizedKey, entry);
    
    return entry.data;
  }

  async set(key: string, report: ThreatReport, ttlSeconds?: number): Promise<void> {
    const normalizedKey = this.normalizeKey(key);
    
    // Determine TTL based on whether threat was detected
    let ttl = ttlSeconds;
    if (ttl === undefined) {
      ttl = report.threatDetected ? this.threatTTL : this.cleanTTL;
    }

    const now = Date.now();
    const entry: CacheEntry<ThreatReport> = {
      data: report,
      createdAt: now,
      expiresAt: now + (ttl * 1000),
      key: normalizedKey,
    };

    // Enforce max size with LRU eviction
    if (this.cache.size >= this.maxSize) {
      this.evictOldest();
    }

    this.cache.set(normalizedKey, entry);
  }

  async delete(key: string): Promise<boolean> {
    const normalizedKey = this.normalizeKey(key);
    return this.cache.delete(normalizedKey);
  }

  async clear(): Promise<void> {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  async has(key: string): Promise<boolean> {
    const normalizedKey = this.normalizeKey(key);
    const entry = this.cache.get(normalizedKey);
    
    if (!entry) return false;
    
    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(normalizedKey);
      return false;
    }
    
    return true;
  }

  getStats(): CacheStats {
    const entries = Array.from(this.cache.values());
    const total = this.hits + this.misses;
    
    return {
      size: this.cache.size,
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? this.hits / total : 0,
      oldestEntry: entries.length > 0 
        ? Math.min(...entries.map(e => e.createdAt)) 
        : undefined,
      newestEntry: entries.length > 0 
        ? Math.max(...entries.map(e => e.createdAt)) 
        : undefined,
    };
  }

  /**
   * Evict the oldest (least recently used) entries.
   */
  private evictOldest(): void {
    // Get first key (oldest in insertion order after LRU reordering)
    const firstKey = this.cache.keys().next().value;
    if (firstKey) {
      this.cache.delete(firstKey);
    }
  }

  /**
   * Remove all expired entries.
   */
  async cleanup(): Promise<number> {
    const now = Date.now();
    let removed = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Normalize cache key.
   */
  private normalizeKey(key: string): string {
    return key.toLowerCase().trim();
  }
}

// ============================================
// REDIS CACHE IMPLEMENTATION
// ============================================

/**
 * Redis cache implementation for distributed deployments.
 * Requires ioredis or similar Redis client.
 */
export class RedisThreatCache implements ThreatIntelCache {
  private redis: RedisClient | null = null;
  private prefix: string = 'securnex:threat:';
  private defaultTTL: number;
  private cleanTTL: number;
  private threatTTL: number;
  private hits: number = 0;
  private misses: number = 0;
  private connected: boolean = false;

  constructor(config: CacheConfig) {
    this.defaultTTL = config.defaultTTLSeconds;
    this.cleanTTL = config.cleanTTLSeconds;
    this.threatTTL = config.threatTTLSeconds;

    if (config.redisUrl) {
      this.initializeRedis(config.redisUrl);
    }
  }

  /**
   * Initialize Redis connection.
   */
  private async initializeRedis(url: string): Promise<void> {
    try {
      // Dynamic import to avoid requiring Redis in all environments
      // Using eval to bypass TypeScript module resolution
      // eslint-disable-next-line @typescript-eslint/no-implied-eval
      const dynamicImport = new Function('modulePath', 'return import(modulePath)');
      const ioredis = await dynamicImport('ioredis').catch(() => null) as { Redis: new (url: string, options: Record<string, unknown>) => RedisClient } | null;
      
      if (!ioredis) {
        console.warn('[ThreatCache] ioredis not available, Redis caching disabled');
        this.connected = false;
        return;
      }
      
      const { Redis } = ioredis;
      this.redis = new Redis(url, {
        maxRetriesPerRequest: 3,
        retryStrategy: (times: number) => {
          if (times > 3) return null;
          return Math.min(times * 200, 2000);
        },
        enableReadyCheck: true,
        lazyConnect: true,
      });

      await this.redis.connect();
      this.connected = true;
      console.log('[ThreatCache] Redis connected');
    } catch (error) {
      console.error('[ThreatCache] Redis connection failed:', error);
      this.redis = null;
      this.connected = false;
    }
  }

  async get(key: string): Promise<ThreatReport | null> {
    if (!this.redis || !this.connected) {
      this.misses++;
      return null;
    }

    try {
      const data = await this.redis.get(this.prefix + key.toLowerCase());
      
      if (!data) {
        this.misses++;
        return null;
      }

      this.hits++;
      return JSON.parse(data) as ThreatReport;
    } catch (error) {
      console.error('[ThreatCache] Redis get error:', error);
      this.misses++;
      return null;
    }
  }

  async set(key: string, report: ThreatReport, ttlSeconds?: number): Promise<void> {
    if (!this.redis || !this.connected) {
      return;
    }

    try {
      const ttl = ttlSeconds ?? (report.threatDetected ? this.threatTTL : this.cleanTTL);
      
      await this.redis.setex(
        this.prefix + key.toLowerCase(),
        ttl,
        JSON.stringify(report)
      );
    } catch (error) {
      console.error('[ThreatCache] Redis set error:', error);
    }
  }

  async delete(key: string): Promise<boolean> {
    if (!this.redis || !this.connected) {
      return false;
    }

    try {
      const result = await this.redis.del(this.prefix + key.toLowerCase());
      return result > 0;
    } catch (error) {
      console.error('[ThreatCache] Redis delete error:', error);
      return false;
    }
  }

  async clear(): Promise<void> {
    if (!this.redis || !this.connected) {
      return;
    }

    try {
      const keys = await this.redis.keys(this.prefix + '*');
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
      this.hits = 0;
      this.misses = 0;
    } catch (error) {
      console.error('[ThreatCache] Redis clear error:', error);
    }
  }

  async has(key: string): Promise<boolean> {
    if (!this.redis || !this.connected) {
      return false;
    }

    try {
      const exists = await this.redis.exists(this.prefix + key.toLowerCase());
      return exists > 0;
    } catch (error) {
      console.error('[ThreatCache] Redis has error:', error);
      return false;
    }
  }

  getStats(): CacheStats {
    const total = this.hits + this.misses;
    return {
      size: -1, // Cannot get size without scanning
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? this.hits / total : 0,
    };
  }

  /**
   * Check if Redis is connected.
   */
  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Disconnect from Redis.
   */
  async disconnect(): Promise<void> {
    if (this.redis) {
      await this.redis.disconnect();
      this.connected = false;
    }
  }
}

// Type for Redis client (minimal interface)
interface RedisClient {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  get(key: string): Promise<string | null>;
  setex(key: string, seconds: number, value: string): Promise<string>;
  del(...keys: string[]): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  exists(key: string): Promise<number>;
}

// ============================================
// CACHE FACTORY
// ============================================

/**
 * Create a cache instance based on configuration.
 */
export function createCache(config: CacheConfig): ThreatIntelCache {
  if (!config.enabled) {
    // Return a no-op cache
    return new NoOpCache();
  }

  if (config.backend === 'redis' && config.redisUrl) {
    return new RedisThreatCache(config);
  }

  return new MemoryThreatCache(config);
}

/**
 * No-op cache implementation for when caching is disabled.
 */
class NoOpCache implements ThreatIntelCache {
  async get(): Promise<null> {
    return null;
  }

  async set(): Promise<void> {
    // No-op
  }

  async delete(): Promise<boolean> {
    return false;
  }

  async clear(): Promise<void> {
    // No-op
  }

  async has(): Promise<boolean> {
    return false;
  }

  getStats(): CacheStats {
    return {
      size: 0,
      hits: 0,
      misses: 0,
      hitRate: 0,
    };
  }
}

// ============================================
// CACHE KEY UTILITIES
// ============================================

/**
 * Generate a cache key from input parameters.
 */
export function generateCacheKey(
  value: string,
  type: 'wallet' | 'contract' | 'domain' | 'url',
  chain?: string
): string {
  const normalizedValue = value.toLowerCase().trim();
  const normalizedChain = chain?.toLowerCase() || 'any';
  
  return `${type}:${normalizedChain}:${normalizedValue}`;
}

/**
 * Parse a cache key back into components.
 */
export function parseCacheKey(key: string): {
  type: string;
  chain: string;
  value: string;
} | null {
  const parts = key.split(':');
  if (parts.length !== 3) return null;
  
  return {
    type: parts[0],
    chain: parts[1],
    value: parts[2],
  };
}
