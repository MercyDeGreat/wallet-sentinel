// ============================================
// SECURNEX - Production Server for IISNode
// ============================================
// This server runs Next.js in standalone mode on SmarterASP.NET

const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');
const path = require('path');

// Production mode
const dev = false;
const hostname = process.env.HOST || '127.0.0.1';
const port = parseInt(process.env.PORT || process.env.IISNODE_PORT || '3000', 10);

// Initialize Next.js
const app = next({ 
  dev, 
  hostname, 
  port,
  dir: __dirname,
});
const handle = app.getRequestHandler();

app.prepare().then(() => {
  createServer(async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true);
      await handle(req, res, parsedUrl);
    } catch (err) {
      console.error('Error handling request:', err);
      res.statusCode = 500;
      res.end('Internal Server Error');
    }
  })
  .once('error', (err) => {
    console.error('Server error:', err);
    process.exit(1);
  })
  .listen(port, () => {
    console.log(`> Securnex ready on http://${hostname}:${port}`);
  });
});
