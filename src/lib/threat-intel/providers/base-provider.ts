// ============================================
// BASE THREAT PROVIDER
// ============================================
// Abstract base class for all threat intelligence providers.
// Handles common functionality: retries, rate limiting, error handling.
//
// PRODUCTION REQUIREMENTS:
// - Graceful failure handling (never block the pipeline)
// - Retry logic with exponential backoff
// - Rate limit tracking
// - Request/response logging (without exposing secrets)

import {
  ThreatProvider,
  ThreatProviderConfig,
  ThreatFinding,
  ThreatIntelInput,
  ProviderHealth,
  ProviderRateLimit,
  ThreatCategory,
  ThreatSeverity,
} from '../types';

/**
 * Abstract base class for threat intelligence providers.
 * Extend this to create new provider integrations.
 */
export abstract class BaseThreatProvider implements ThreatProvider {
  abstract readonly name: string;
  abstract readonly id: string;
  
  protected _config: ThreatProviderConfig;
  protected _health: ProviderHealth;
  protected _rateLimit: ProviderRateLimit | null = null;
  protected _requestCount: number = 0;
  protected _lastRequestAt: number = 0;

  constructor(config: Partial<ThreatProviderConfig>) {
    this._config = {
      id: '',
      name: '',
      endpoint: '',
      apiKeyEnvVar: '',
      timeoutMs: 5000,
      maxRetries: 2,
      retryDelayMs: 1000,
      confidenceWeight: 1.0,
      enabled: true,
      ...config,
    };

    this._health = {
      isHealthy: true,
      lastCheckAt: new Date().toISOString(),
      consecutiveFailures: 0,
    };
  }

  get enabled(): boolean {
    return this._config.enabled;
  }

  get config(): ThreatProviderConfig {
    return { ...this._config };
  }

  /**
   * Update provider configuration.
   */
  updateConfig(config: Partial<ThreatProviderConfig>): void {
    this._config = { ...this._config, ...config };
  }

  /**
   * Get current rate limit status.
   */
  getRateLimitStatus(): ProviderRateLimit | null {
    return this._rateLimit ? { ...this._rateLimit } : null;
  }

  /**
   * Main method to check an address for threats.
   * Handles retries, rate limiting, and error handling.
   */
  async checkAddress(input: ThreatIntelInput): Promise<ThreatFinding[]> {
    if (!this._config.enabled) {
      this.log('info', `Provider ${this.name} is disabled, skipping`);
      return [];
    }

    // Check rate limits
    if (this.isRateLimited()) {
      this.log('warn', `Provider ${this.name} is rate limited`);
      return [];
    }

    // Execute with retries
    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= this._config.maxRetries; attempt++) {
      try {
        if (attempt > 0) {
          const delay = this._config.retryDelayMs * Math.pow(2, attempt - 1);
          await this.sleep(delay);
          this.log('info', `Retry attempt ${attempt} for ${this.name}`);
        }

        const findings = await this.executeQuery(input);
        
        // Success - update health
        this._health.isHealthy = true;
        this._health.consecutiveFailures = 0;
        this._health.lastCheckAt = new Date().toISOString();
        
        return findings;
      } catch (error) {
        lastError = error as Error;
        this._health.consecutiveFailures++;
        this.log('error', `Query failed for ${this.name}: ${this.sanitizeError(lastError)}`);
      }
    }

    // All retries failed
    this._health.isHealthy = false;
    this._health.errorMessage = lastError?.message || 'Unknown error';
    
    // Return empty array - don't block the pipeline
    return [];
  }

  /**
   * Abstract method - implement in subclass.
   * Performs the actual API call to the provider.
   */
  protected abstract executeQuery(input: ThreatIntelInput): Promise<ThreatFinding[]>;

  /**
   * Perform health check on the provider.
   */
  async healthCheck(): Promise<ProviderHealth> {
    const startTime = Date.now();
    
    try {
      // Simple connectivity check - override in subclass for API-specific check
      const testInput: ThreatIntelInput = {
        value: '0x0000000000000000000000000000000000000000',
        type: 'wallet',
      };
      
      await this.executeQuery(testInput);
      
      this._health = {
        isHealthy: true,
        lastCheckAt: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        consecutiveFailures: 0,
      };
    } catch (error) {
      this._health = {
        isHealthy: false,
        lastCheckAt: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        errorMessage: this.sanitizeError(error as Error),
        consecutiveFailures: this._health.consecutiveFailures + 1,
      };
    }
    
    return { ...this._health };
  }

  /**
   * Check if we're currently rate limited.
   */
  protected isRateLimited(): boolean {
    if (!this._rateLimit) return false;
    if (!this._rateLimit.isLimited) return false;
    
    const resetTime = new Date(this._rateLimit.resetAt).getTime();
    return Date.now() < resetTime;
  }

  /**
   * Update rate limit tracking from API response headers.
   */
  protected updateRateLimit(headers: Headers): void {
    const remaining = headers.get('x-ratelimit-remaining');
    const limit = headers.get('x-ratelimit-limit');
    const reset = headers.get('x-ratelimit-reset');

    if (remaining !== null && limit !== null) {
      this._rateLimit = {
        requestsRemaining: parseInt(remaining, 10),
        requestsLimit: parseInt(limit, 10),
        resetAt: reset ? new Date(parseInt(reset, 10) * 1000).toISOString() : new Date(Date.now() + 60000).toISOString(),
        isLimited: parseInt(remaining, 10) <= 0,
      };
    }
  }

  /**
   * Get API key from environment variable.
   * Never logs or exposes the actual key.
   */
  protected getApiKey(): string | null {
    const key = process.env[this._config.apiKeyEnvVar];
    if (!key) {
      this.log('warn', `API key not found for ${this.name} (env: ${this._config.apiKeyEnvVar})`);
    }
    return key || null;
  }

  /**
   * Make an HTTP request with timeout.
   */
  protected async makeRequest(
    url: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this._config.timeoutMs);

    try {
      this._requestCount++;
      this._lastRequestAt = Date.now();

      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });

      // Update rate limit from response headers
      this.updateRateLimit(response.headers);

      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Create a ThreatFinding with provider attribution.
   */
  protected createFinding(params: {
    category: ThreatCategory;
    severity: ThreatSeverity;
    confidence: number;
    description: string;
    firstReportedAt?: string;
    lastSeenAt?: string;
    referenceUrl?: string;
    metadata?: Record<string, unknown>;
    tags?: string[];
    raw?: unknown;
  }): ThreatFinding {
    // Apply confidence weight
    const adjustedConfidence = Math.min(100, Math.round(params.confidence * this._config.confidenceWeight));

    return {
      provider: this.name,
      category: params.category,
      severity: params.severity,
      confidence: adjustedConfidence,
      description: params.description,
      firstReportedAt: params.firstReportedAt,
      lastSeenAt: params.lastSeenAt,
      referenceUrl: params.referenceUrl,
      metadata: params.metadata,
      tags: params.tags,
      raw: params.raw,
    };
  }

  /**
   * Normalize address to lowercase.
   */
  protected normalizeAddress(address: string): string {
    return address.toLowerCase().trim();
  }

  /**
   * Validate Ethereum address format.
   */
  protected isValidEthAddress(address: string): boolean {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
  }

  /**
   * Sanitize error messages (remove sensitive data).
   */
  protected sanitizeError(error: Error): string {
    let message = error.message || 'Unknown error';
    
    // Remove API keys, tokens, etc.
    message = message.replace(/[a-f0-9]{32,}/gi, '[REDACTED]');
    message = message.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
    message = message.replace(/api[_-]?key[=:]\s*\S+/gi, 'api_key=[REDACTED]');
    
    return message;
  }

  /**
   * Log message (respects verbose setting).
   */
  protected log(level: 'info' | 'warn' | 'error', message: string): void {
    const prefix = `[ThreatIntel:${this.name}]`;
    
    switch (level) {
      case 'error':
        console.error(`${prefix} ${message}`);
        break;
      case 'warn':
        console.warn(`${prefix} ${message}`);
        break;
      case 'info':
        if (process.env.THREAT_INTEL_VERBOSE === 'true') {
          console.log(`${prefix} ${message}`);
        }
        break;
    }
  }

  /**
   * Sleep for specified milliseconds.
   */
  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Map external severity to internal severity.
   * Override in subclass for provider-specific mapping.
   */
  protected mapSeverity(externalSeverity: string): ThreatSeverity {
    const mapping: Record<string, ThreatSeverity> = {
      // Common variations
      'low': 'low',
      'medium': 'medium',
      'high': 'high',
      'critical': 'critical',
      'severe': 'critical',
      'moderate': 'medium',
      'minor': 'low',
      'info': 'low',
      'warning': 'medium',
      'danger': 'high',
      'extreme': 'critical',
      // Numeric levels
      '1': 'low',
      '2': 'medium',
      '3': 'high',
      '4': 'critical',
      '5': 'critical',
    };

    return mapping[externalSeverity.toLowerCase()] || 'medium';
  }

  /**
   * Map external category to internal category.
   * Override in subclass for provider-specific mapping.
   */
  protected mapCategory(externalCategory: string): ThreatCategory {
    const mapping: Record<string, ThreatCategory> = {
      // Common variations
      'phishing': 'phishing',
      'phish': 'phishing',
      'scam': 'scam',
      'fraud': 'scam',
      'drainer': 'drainer',
      'drain': 'drainer',
      'wallet_drainer': 'drainer',
      'malware': 'malware',
      'exploit': 'exploit',
      'hack': 'exploit',
      'vulnerability': 'exploit',
      'impersonation': 'impersonation',
      'impersonate': 'impersonation',
      'fake': 'impersonation',
      'honeypot': 'honeypot',
      'rug': 'rug_pull',
      'rug_pull': 'rug_pull',
      'rugpull': 'rug_pull',
    };

    const normalized = externalCategory.toLowerCase().replace(/[_\s-]+/g, '_');
    return mapping[normalized] || 'unknown';
  }
}

/**
 * Helper to create standardized provider config.
 */
export function createProviderConfig(
  id: string,
  name: string,
  defaults: Partial<ThreatProviderConfig> = {}
): ThreatProviderConfig {
  return {
    id,
    name,
    endpoint: '',
    apiKeyEnvVar: `${id.toUpperCase()}_API_KEY`,
    timeoutMs: 5000,
    maxRetries: 2,
    retryDelayMs: 1000,
    confidenceWeight: 1.0,
    enabled: true,
    ...defaults,
  };
}
