'use strict';
/**
 * Example "customer application" integrating Signer (no dependencies, Node 18+).
 *
 * It shows the only server-side piece an application such as e-Office needs: an endpoint that
 * exchanges the application's secret API key for a short-lived, single-use transaction token.
 *
 *   SIGNER_URL=http://localhost:8080 SIGNER_API_KEY=sk_... APP_ORIGIN=http://localhost:3000 node server.js
 *   open http://localhost:3000
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { SignerServerClient } = require('../../sdk/node/signer-server-client');

const PORT = Number(process.env.PORT || 3000);
const APP_ORIGIN = process.env.APP_ORIGIN || `http://localhost:${PORT}`;
const signer = new SignerServerClient({ serverUrl: process.env.SIGNER_URL || 'http://localhost:8080', apiKey: process.env.SIGNER_API_KEY });

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/esign/token') {
      // In a real application: check the user's session and that they may sign this file.
      let body = '';
      for await (const chunk of req) { body += chunk; }
      const { fileNo } = body ? JSON.parse(body) : {};
      const t = await signer.issueToken({ origin: APP_ORIGIN, reference: fileNo || undefined, maxDocuments: 1 });
      return json(res, 200, { token: t.token, txn: t.txn });
    }
    if (req.method === 'GET' && req.url === '/config.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      return res.end(`window.SIGNER_URL = ${JSON.stringify(signer.serverUrl)};`);
    }
    const file = req.url === '/' ? 'index.html' : req.url.replace(/^\/+/, '');
    const full = path.join(__dirname, 'public', path.normalize(file));
    if (!full.startsWith(path.join(__dirname, 'public')) || !fs.existsSync(full)) {
      return json(res, 404, { error: 'not found' });
    }
    res.writeHead(200, { 'Content-Type': full.endsWith('.html') ? 'text/html' : 'application/javascript' });
    fs.createReadStream(full).pipe(res);
  } catch (e) {
    json(res, e.status || 500, { error: { code: e.code || 'ERROR', message: e.message } });
  }
});

server.listen(PORT, () => console.log(`Example application on ${APP_ORIGIN} (Signer: ${signer.serverUrl})`));
