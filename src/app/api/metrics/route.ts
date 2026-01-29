// ============================================
// SECURNEX METRICS API ENDPOINT (Vercel + Neon)
// ============================================
// GET /api/metrics - Returns usage metrics
// GET /api/metrics?public=true - Returns public-safe metrics only

import { NextRequest, NextResponse } from 'next/server';
import { computeUsageMetrics, getPublicMetrics, detectAnomalies } from '@/lib/metrics';

export async function GET(request: NextRequest) {
  try {
    // Check if database is configured
    if (!process.env.DATABASE_URL) {
      return NextResponse.json({
        success: false,
        error: {
          code: 'NO_DATABASE',
          message: 'Metrics database not configured',
          details: 'Set DATABASE_URL environment variable in Vercel',
        },
        data: {
          message: 'Metrics tracking not yet enabled',
          setup_instructions: [
            '1. Create a Neon database at https://neon.tech',
            '2. Copy the connection string',
            '3. Add DATABASE_URL to Vercel Environment Variables',
            '4. Run the schema.sql in Neon SQL Editor',
            '5. Redeploy'
          ],
          placeholder_metrics: {
            total_scans: 0,
            unique_wallets: 0,
            unique_users: 0,
            launch_date: 'Not yet launched',
          }
        },
        timestamp: new Date().toISOString(),
      }, { status: 503 });
    }

    const url = new URL(request.url);
    const isPublic = url.searchParams.get('public') === 'true';
    const includeAnomalies = url.searchParams.get('anomalies') === 'true';

    if (isPublic) {
      const publicMetrics = await getPublicMetrics();
      
      if (!publicMetrics) {
        return NextResponse.json({
          success: false,
          error: { code: 'QUERY_ERROR', message: 'Failed to fetch metrics' },
          timestamp: new Date().toISOString(),
        }, { status: 500 });
      }
      
      return NextResponse.json({
        success: true,
        data: publicMetrics,
        timestamp: new Date().toISOString(),
      });
    }

    // Full metrics
    const metrics = await computeUsageMetrics({
      cooldown_hours: 24,
      exclude_rescans: true,
    });

    if (!metrics) {
      return NextResponse.json({
        success: false,
        error: { code: 'QUERY_ERROR', message: 'Failed to compute metrics' },
        timestamp: new Date().toISOString(),
      }, { status: 500 });
    }

    // Optionally include anomaly detection
    let anomalies = null;
    if (includeAnomalies) {
      anomalies = await detectAnomalies();
    }

    return NextResponse.json({
      success: true,
      data: {
        metrics,
        anomalies,
      },
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    console.error('[METRICS_ERROR]', error);
    
    return NextResponse.json({
      success: false,
      error: {
        code: 'METRICS_ERROR',
        message: 'Failed to compute metrics',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      timestamp: new Date().toISOString(),
    }, { status: 500 });
  }
}
