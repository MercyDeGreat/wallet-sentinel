#!/bin/bash
# ============================================
# SECURNEX METRICS SETUP SCRIPT (Bash)
# ============================================
# Run this script to set up the metrics database
# 
# Usage: chmod +x setup-metrics.sh && ./setup-metrics.sh

set -e

echo ""
echo "🛡️  SECURNEX METRICS SETUP"
echo "========================="

# Step 1: Check authentication
echo ""
echo "[1/4] Checking Cloudflare authentication..."
if npx wrangler whoami 2>&1 | grep -q "not authenticated"; then
    echo "Not logged in. Opening browser for authentication..."
    npx wrangler login
fi
echo "✅ Authenticated with Cloudflare"

# Step 2: Create D1 database
echo ""
echo "[2/4] Creating D1 database 'securnex-metrics'..."
CREATE_OUTPUT=$(npx wrangler d1 create securnex-metrics 2>&1) || true

if echo "$CREATE_OUTPUT" | grep -q "already exists"; then
    echo "⚠️  Database already exists"
    # Get existing database info
    DB_ID=$(npx wrangler d1 list 2>&1 | grep securnex-metrics | awk '{print $1}')
else
    echo "✅ Database created!"
    # Extract database_id from output
    DB_ID=$(echo "$CREATE_OUTPUT" | grep -oP 'database_id = "\K[^"]+')
fi

echo "   Database ID: $DB_ID"

# Step 3: Update wrangler.toml
echo ""
echo "[3/4] Updating wrangler.toml with database binding..."

if grep -q "database_id = \"$DB_ID\"" wrangler.toml 2>/dev/null; then
    echo "⚠️  wrangler.toml already configured"
else
    cat >> wrangler.toml << EOF

[[d1_databases]]
binding = "METRICS_DB"
database_name = "securnex-metrics"
database_id = "$DB_ID"
EOF
    echo "✅ wrangler.toml updated"
fi

# Step 4: Apply schema
echo ""
echo "[4/4] Applying database schema..."
npx wrangler d1 execute securnex-metrics --file=./schema.sql

echo ""
echo "✅ SETUP COMPLETE!"
echo ""
echo "Next steps:"
echo "1. Build: npm run pages:build"
echo "2. Deploy: npx wrangler pages deploy .vercel/output/static"
echo ""
echo "Or to test locally:"
echo "   npm run pages:dev"
echo ""
echo "Your metrics will be available at:"
echo "   https://your-site.pages.dev/api/metrics?public=true"
