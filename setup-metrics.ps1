# ============================================
# SECURNEX METRICS SETUP SCRIPT (PowerShell)
# ============================================
# Run this script to set up the metrics database
# 
# Usage: .\setup-metrics.ps1

Write-Host "`n🛡️  SECURNEX METRICS SETUP" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

# Step 1: Check authentication
Write-Host "`n[1/4] Checking Cloudflare authentication..." -ForegroundColor Yellow
$whoami = npx wrangler whoami 2>&1

if ($whoami -match "not authenticated") {
    Write-Host "Not logged in. Opening browser for authentication..." -ForegroundColor Red
    npx wrangler login
    
    # Verify login
    $whoami = npx wrangler whoami 2>&1
    if ($whoami -match "not authenticated") {
        Write-Host "❌ Authentication failed. Please try again." -ForegroundColor Red
        exit 1
    }
}
Write-Host "✅ Authenticated with Cloudflare" -ForegroundColor Green

# Step 2: Create D1 database
Write-Host "`n[2/4] Creating D1 database 'securnex-metrics'..." -ForegroundColor Yellow
$createOutput = npx wrangler d1 create securnex-metrics 2>&1

if ($createOutput -match "already exists") {
    Write-Host "⚠️  Database already exists" -ForegroundColor Yellow
} elseif ($createOutput -match "database_id") {
    Write-Host "✅ Database created!" -ForegroundColor Green
    
    # Extract database_id
    $match = [regex]::Match($createOutput, 'database_id\s*=\s*"([^"]+)"')
    if ($match.Success) {
        $dbId = $match.Groups[1].Value
        Write-Host "   Database ID: $dbId" -ForegroundColor Cyan
        
        # Update wrangler.toml
        Write-Host "`n[3/4] Updating wrangler.toml with database binding..." -ForegroundColor Yellow
        $wranglerContent = Get-Content wrangler.toml -Raw
        
        # Check if already configured
        if ($wranglerContent -match "database_id = `"$dbId`"") {
            Write-Host "⚠️  wrangler.toml already configured" -ForegroundColor Yellow
        } else {
            # Append D1 binding
            $d1Config = @"

[[d1_databases]]
binding = "METRICS_DB"
database_name = "securnex-metrics"
database_id = "$dbId"
"@
            Add-Content -Path wrangler.toml -Value $d1Config
            Write-Host "✅ wrangler.toml updated" -ForegroundColor Green
        }
    }
} else {
    Write-Host $createOutput
}

# Step 4: Apply schema
Write-Host "`n[4/4] Applying database schema..." -ForegroundColor Yellow
npx wrangler d1 execute securnex-metrics --file=./schema.sql

Write-Host "`n✅ SETUP COMPLETE!" -ForegroundColor Green
Write-Host @"

Next steps:
1. Build: npm run pages:build
2. Deploy: npx wrangler pages deploy .vercel/output/static

Or to test locally:
   npm run pages:dev

Your metrics will be available at:
   https://your-site.pages.dev/api/metrics?public=true

"@ -ForegroundColor Cyan
