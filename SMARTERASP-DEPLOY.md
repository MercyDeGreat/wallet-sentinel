# Securnex - SmarterASP.NET Deployment Guide

## Prerequisites
- SmarterASP.NET account with Node.js support
- FTP client (FileZilla recommended)

---

## Step 1: Create Hosting Account

1. Go to [SmarterASP.NET](https://www.smarterasp.net)
2. Sign up for a hosting plan with **Node.js support**
3. Create a new website in your control panel
4. Note your FTP credentials:
   - FTP Host
   - FTP Username  
   - FTP Password

---

## Step 2: Prepare Files for Upload

Your deployment folder is: `C:\Users\mercy\TOOL\wallet-sentinel\.next\standalone`

Files to upload:
```
.next/standalone/
├── .next/           (the build output)
├── node_modules/    (required dependencies)
├── server.js        (entry point)
├── package.json
└── public/          (static files - copy from root)
```

**Important:** Copy the `public` folder into the standalone folder:
```powershell
Copy-Item -Recurse C:\Users\mercy\TOOL\wallet-sentinel\public C:\Users\mercy\TOOL\wallet-sentinel\.next\standalone\public
```

Also copy the static folder:
```powershell
Copy-Item -Recurse C:\Users\mercy\TOOL\wallet-sentinel\.next\static C:\Users\mercy\TOOL\wallet-sentinel\.next\standalone\.next\static
```

---

## Step 3: Upload via FTP

1. Open FileZilla
2. Connect to your SmarterASP.NET FTP:
   - Host: `ftp.your-site.smarterasp.net`
   - Username: Your FTP username
   - Password: Your FTP password
   - Port: 21

3. Navigate to your website root folder (usually `/site/wwwroot/`)

4. Upload these files from `.next/standalone/`:
   - `.next/` folder
   - `node_modules/` folder
   - `public/` folder
   - `server.js`
   - `package.json`
   - `web.config` (from project root)

---

## Step 4: Configure Node.js in Control Panel

1. Log into SmarterASP.NET Control Panel
2. Go to **Web Sites** → Select your site
3. Go to **Node.js** section
4. Set:
   - **Node.js Version**: 18.x or 20.x
   - **Startup File**: `server.js`
   - **Port**: Leave default or set to assigned port

5. Click **Save** and **Restart**

---

## Step 5: Set Environment Variables

In Control Panel → **Application Settings** or **Environment Variables**:

| Variable | Value |
|----------|-------|
| `NODE_ENV` | `production` |
| `PORT` | (use assigned port, usually 3000 or auto) |
| `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` | Your WalletConnect Project ID |

---

## Step 6: Verify Deployment

1. Visit your site URL: `https://your-site.smarterasp.net`
2. Test wallet analysis functionality
3. Test revocation (should show $1 fee)

---

## Troubleshooting

### Site Not Loading
- Check Node.js is enabled in control panel
- Verify `server.js` is in the root folder
- Check error logs in control panel

### 500 Internal Server Error
- Check if all files uploaded correctly
- Verify `web.config` is present
- Check Node.js version compatibility

### API Errors
- Ensure environment variables are set
- Check if outbound connections are allowed

---

## Alternative: Use Vercel (Easier)

If SmarterASP.NET is difficult, Vercel is much easier for Next.js:

1. Push code to GitHub
2. Go to [vercel.com](https://vercel.com)
3. Import repository
4. Auto-deploys in 2 minutes!

---

## Files Included
- `web.config` - IIS configuration
- `server.js` - Node.js entry point
- `.next/standalone/` - Production build

## Support
Built by MercyDeGreat

