# Securnex - SmarterASP.NET Deployment Guide

## Prerequisites
- SmarterASP.NET hosting account with **Node.js support enabled**
- FTP client (FileZilla, WinSCP, etc.)

## Step 1: Build the Deployment Package

Run this command in your project folder:

```bash
npm run deploy:prepare
```

This creates a `/deploy` folder with everything needed for hosting.

## Step 2: Enable Node.js on SmarterASP.NET

1. Log in to your **SmarterASP.NET Control Panel**
2. Go to **Websites** → **Your Website** → **Node.js**
3. **Enable Node.js** and set:
   - Node.js Version: **18.x** or higher
   - Application Mode: **Production**
4. Click **Save**

## Step 3: Upload Files

Using FTP, upload the **contents** of the `/deploy` folder to your website's root:

```
deploy/
├── .next/           → Upload to /wwwroot/.next/
├── node_modules/    → Upload to /wwwroot/node_modules/
├── public/          → Upload to /wwwroot/public/
├── server.js        → Upload to /wwwroot/server.js
├── package.json     → Upload to /wwwroot/package.json
└── web.config       → Upload to /wwwroot/web.config
```

**Your wwwroot should look like:**
```
wwwroot/
├── .next/
├── node_modules/
├── public/
├── server.js
├── package.json
└── web.config
```

## Step 4: Verify Deployment

1. Visit your website URL
2. The site should load with the Securnex interface
3. Test wallet analysis functionality

## Troubleshooting

### Site shows 500 Error
- Check **iisnode/** folder for error logs
- Ensure Node.js is enabled in control panel
- Verify all files uploaded correctly

### API routes not working
- Check that `server.js` is in the root
- Verify `web.config` URL rewrite rules

### Site loads but wallet analysis fails
- Check browser console for errors
- Verify your RPC endpoints are accessible

## Code Protection Features

Your deployed code includes:
- ✅ **Minified JavaScript** - Variable names obfuscated
- ✅ **No source maps** - Can't reverse-engineer in browser DevTools
- ✅ **Standalone build** - Only production code included
- ✅ **Security headers** - XSS protection, clickjacking prevention

## Updating the Site

1. Make changes locally
2. Run `npm run deploy:prepare`
3. Upload changed files via FTP

---

**Built by MercyDeGreat** | [Twitter](https://x.com/mercydegreat)









