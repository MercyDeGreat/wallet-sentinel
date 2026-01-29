// ============================================
// WALLET ANALYSIS API ENDPOINT
// ============================================
// POST /api/analyze
// Analyzes a wallet address for security threats.
// All operations are READ-ONLY and defensive.

import { NextRequest, NextResponse } from 'next/server';
import { EVMAnalyzer } from '@/lib/analyzers/evm-analyzer';
import { SolanaAnalyzer } from '@/lib/analyzers/solana-analyzer';
import { Chain, WalletAnalysisRequest, ApiResponse, WalletAnalysisResult, SecurityStatus } from '@/types';
import { getMetricsTracker, SecurityVerdict } from '@/lib/metrics';

// Map SecurityStatus to SecurityVerdict for metrics
function mapStatusToVerdict(status: SecurityStatus): SecurityVerdict {
  switch (status) {
    case 'SAFE': return 'SAFE';
    case 'AT_RISK': return 'AT_RISK';
    case 'COMPROMISED': return 'COMPROMISED';
    default: return 'AT_RISK';
  }
}

// Validate chain parameter
function isValidChain(chain: string): chain is Chain {
  return ['ethereum', 'base', 'bnb', 'solana'].includes(chain);
}

// Validate EVM address format
function isValidEvmAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

// Validate Solana address format
function isValidSolanaAddress(address: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
}

// Validate address format based on chain
function isValidAddress(address: string, chain: Chain): boolean {
  if (chain === 'solana') {
    return isValidSolanaAddress(address);
  }
  return isValidEvmAddress(address);
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Get client IP for metrics
    const ip = request.headers.get('x-forwarded-for') || 
               request.headers.get('x-real-ip') || 
               'unknown';

    // Parse request body
    let body: WalletAnalysisRequest;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json<ApiResponse<null>>(
        {
          success: false,
          error: {
            code: 'INVALID_JSON',
            message: 'Invalid request body',
          },
          timestamp: new Date().toISOString(),
        },
        { status: 400 }
      );
    }

    const { address, chain } = body;

    // Validate inputs
    if (!address || typeof address !== 'string') {
      return NextResponse.json<ApiResponse<null>>(
        {
          success: false,
          error: {
            code: 'INVALID_ADDRESS',
            message: 'Wallet address is required',
          },
          timestamp: new Date().toISOString(),
        },
        { status: 400 }
      );
    }

    if (!chain || !isValidChain(chain)) {
      return NextResponse.json<ApiResponse<null>>(
        {
          success: false,
          error: {
            code: 'INVALID_CHAIN',
            message: 'Valid chain is required (ethereum, base, bnb, solana)',
          },
          timestamp: new Date().toISOString(),
        },
        { status: 400 }
      );
    }

    const trimmedAddress = address.trim();
    
    if (!isValidAddress(trimmedAddress, chain)) {
      return NextResponse.json<ApiResponse<null>>(
        {
          success: false,
          error: {
            code: 'INVALID_ADDRESS_FORMAT',
            message: `Invalid ${chain} address format. ${chain === 'solana' ? 'Solana addresses are base58 encoded.' : 'EVM addresses start with 0x followed by 40 hex characters.'}`,
          },
          timestamp: new Date().toISOString(),
        },
        { status: 400 }
      );
    }

    console.log(`[ANALYZE] Starting analysis for ${trimmedAddress} on ${chain}`);

    // Perform analysis
    let result: WalletAnalysisResult;

    try {
      if (chain === 'solana') {
        const analyzer = new SolanaAnalyzer();
        result = await analyzer.analyzeWallet(trimmedAddress);
      } else {
        const analyzer = new EVMAnalyzer(chain);
        result = await analyzer.analyzeWallet(trimmedAddress);
      }
    } catch (analysisError) {
      console.error(`[ANALYZE_ERROR] Failed to analyze ${trimmedAddress}:`, analysisError);
      
      const errorMessage = analysisError instanceof Error ? analysisError.message : 'Unknown error';
      
      if (errorMessage.includes('timeout') || errorMessage.includes('TIMEOUT')) {
        return NextResponse.json<ApiResponse<null>>(
          {
            success: false,
            error: {
              code: 'NETWORK_TIMEOUT',
              message: 'Network timeout while fetching blockchain data. Please try again.',
              details: 'The blockchain API is slow to respond. This is usually temporary.',
            },
            timestamp: new Date().toISOString(),
          },
          { status: 503 }
        );
      }

      if (errorMessage.includes('RPC') || errorMessage.includes('network')) {
        return NextResponse.json<ApiResponse<null>>(
          {
            success: false,
            error: {
              code: 'RPC_ERROR',
              message: 'Unable to connect to blockchain. Please try again.',
              details: errorMessage,
            },
            timestamp: new Date().toISOString(),
          },
          { status: 503 }
        );
      }

      throw analysisError;
    }

    const duration = Date.now() - startTime;
    console.log(`[ANALYZE] Completed in ${duration}ms. Status: ${result.securityStatus}, Score: ${result.riskScore}, Threats: ${result.detectedThreats.length}`);

    // Record metrics (non-blocking)
    const userAgent = request.headers.get('user-agent') || 'unknown';
    const tracker = getMetricsTracker();
    
    tracker.recordScan({
      walletAddress: trimmedAddress,
      chain,
      verdict: mapStatusToVerdict(result.securityStatus),
      riskScore: result.riskScore,
      threatsCount: result.detectedThreats.length,
      durationMs: duration,
      ip,
      userAgent,
      source: 'web',
    }).catch(err => console.error('[METRICS] Failed to record:', err));

    return NextResponse.json<ApiResponse<WalletAnalysisResult>>(
      {
        success: true,
        data: result,
        timestamp: new Date().toISOString(),
      },
      { status: 200 }
    );
  } catch (error) {
    const duration = Date.now() - startTime;
    console.error(`[ANALYZE_FATAL] Error after ${duration}ms:`, error);

    return NextResponse.json<ApiResponse<null>>(
      {
        success: false,
        error: {
          code: 'ANALYSIS_ERROR',
          message: 'An unexpected error occurred during analysis. Please try again.',
          details: error instanceof Error ? error.message : 'Unknown error',
        },
        timestamp: new Date().toISOString(),
      },
      { status: 500 }
    );
  }
}

// Health check endpoint
export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    service: 'securnex',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    supportedChains: ['ethereum', 'base', 'bnb', 'solana'],
    disclaimer: 'This service provides security analysis for educational purposes. No wallet custody, no guarantees, no offensive actions. All operations are read-only.',
  });
}
