// Securnex Production Server for IIS/IISNode
const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');
const path = require('path');

const dev = false;
const hostname = process.env.HOST || '127.0.0.1';
const port = process.env.PORT || 3000;

// Initialize Next.js
const app = next({ 
  dev, 
  hostname, 
  port,
  dir: __dirname 
});

const handle = app.getRequestHandler();

app.prepare().then(() => {
  createServer(async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true);
      await handle(req, res, parsedUrl);
    } catch (err) {
      console.error('Error occurred handling', req.url, err);
      res.statusCode = 500;
      res.end('Internal Server Error');
    }
  }).listen(port, (err) => {
    if (err) throw err;
    console.log(`> Securnex ready on http://${hostname}:${port}`);
  });
});

