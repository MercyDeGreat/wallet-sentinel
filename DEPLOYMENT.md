# Securnex Deployment Guide

## 🔐 Build Status
Your production build is ready and encrypted in the `.next` folder.

## Deployment Options

### Option 1: Vercel (Recommended - Free)
1. Go to [vercel.com](https://vercel.com)
2. Click "Add New Project"
3. Import your GitHub repository (or upload folder)
4. Set environment variables:
   - `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` = Get from [cloud.walletconnect.com](https://cloud.walletconnect.com)
5. Deploy!

### Option 2: Netlify
1. Go to [netlify.com](https://netlify.com)
2. Drag and drop the `.next` folder
3. Or connect your GitHub repository

### Option 3: Railway
1. Go to [railway.app](https://railway.app)
2. Connect GitHub repository
3. Auto-deploys on push

### Option 4: Self-Hosted (VPS)
```bash
# On your server
git clone <your-repo>
cd wallet-sentinel
npm install
npm run build
npm run start
```

## Environment Variables Needed

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` | Yes | WalletConnect Cloud Project ID |

## Get WalletConnect Project ID
1. Go to https://cloud.walletconnect.com
2. Create account / Sign in
3. Create new project
4. Copy the Project ID

## Protection Applied
✅ Code minification  
✅ JavaScript obfuscation  
✅ String encryption  
✅ Control flow flattening  
✅ No source maps  
✅ Variable name mangling  

## Service Fee Configuration
Fee recipient wallet: `0x3eE604833B5572422dBF7eB7e2d342daf4188aE2`  
Fee amount: $1 USD per revocation  

## Run Production Locally (Test)
```bash
npm run start
```
Opens on http://localhost:3000

## Custom Domain
After deploying to Vercel/Netlify, you can add your custom domain in their dashboard.


