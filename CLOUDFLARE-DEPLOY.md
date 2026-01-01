# Securnex - Cloudflare Pages Deployment Guide

## ✅ Why Cloudflare Pages?
- **Free tier** with generous limits
- **Global CDN** - Fast worldwide
- **Automatic HTTPS**
- **Easy custom domains**
- **Works perfectly with Next.js**

---

## Method 1: Deploy via GitHub (Recommended)

### Step 1: Push to GitHub

```bash
cd C:\Users\mercy\TOOL\wallet-sentinel
git init
git add .
git commit -m "Securnex initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/securnex.git
git push -u origin main
```

### Step 2: Connect to Cloudflare Pages

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click **Pages** in the sidebar
3. Click **Create a project** → **Connect to Git**
4. Select your GitHub account and `securnex` repository
5. Click **Begin setup**

### Step 3: Configure Build Settings

| Setting | Value |
|---------|-------|
| **Project name** | securnex |
| **Production branch** | main |
| **Framework preset** | Next.js |
| **Build command** | `npx @cloudflare/next-on-pages` |
| **Build output directory** | `.vercel/output/static` |

### Step 4: Set Environment Variables

Click **Environment variables** and add:

| Variable | Value |
|----------|-------|
| `NODE_VERSION` | `18` |
| `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` | Your WalletConnect Project ID |

### Step 5: Deploy!

Click **Save and Deploy** - Your site will be live in ~2 minutes at:
```
https://securnex.pages.dev
```

---

## Method 2: Deploy via CLI (Direct Upload)

### Step 1: Build for Cloudflare

```bash
cd C:\Users\mercy\TOOL\wallet-sentinel
npm run build
npm run build:cloudflare
```

### Step 2: Login to Cloudflare

```bash
npx wrangler login
```

### Step 3: Deploy

```bash
npm run deploy:cloudflare
```

---

## Add Custom Domain

1. In Cloudflare Pages dashboard, select your project
2. Go to **Custom domains**
3. Click **Set up a custom domain**
4. Enter your domain (e.g., `securnex.com`)
5. Follow DNS instructions

---

## Environment Variables (Production)

Set these in Cloudflare Pages dashboard under **Settings** → **Environment variables**:

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` | Yes | Get from cloud.walletconnect.com |
| `NODE_VERSION` | Yes | Set to `18` |

---

## Troubleshooting

### Build Fails
- Ensure Node version is set to 18
- Check build logs for specific errors

### API Routes Not Working
- Cloudflare Pages supports API routes via Edge Functions
- They work automatically with @cloudflare/next-on-pages

### Wallet Connection Issues
- Make sure WalletConnect Project ID is set
- Check browser console for errors

---

## Your Live URLs

After deployment, your site will be available at:
- **Default**: `https://securnex.pages.dev`
- **Custom**: `https://your-domain.com` (after DNS setup)

---

## Pricing

Cloudflare Pages **Free Tier** includes:
- 500 builds per month
- Unlimited bandwidth
- Unlimited requests
- Free SSL

More than enough for your project!

---

Built by MercyDeGreat | Service fee: $1 per revocation

