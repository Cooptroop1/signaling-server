const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const { v4: uuidv4 } = require('uuid');

function handleRequest(req, res) {
  const proto = req.headers['x-forwarded-proto'];
  if (proto && proto !== 'https') {
    res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
    res.end();
    return;
  }
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  const fullUrl = new URL(req.url, `http://${req.headers.host}`);
  let filePath = path.join(__dirname, fullUrl.pathname === '/' ? 'index.html' : fullUrl.pathname);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    let contentType = 'text/plain';
    if (filePath.endsWith('.html')) {
      contentType = 'text/html';
      const nonce = crypto.randomBytes(16).toString('base64');
      let updatedCSP = "default-src 'self'; " +
        `script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net 'nonce-${nonce}'; ` +
        `style-src 'self' https://cdn.jsdelivr.net 'nonce-${nonce}' 'unsafe-hashes' 'sha256-biLFinpqYMtWHmXfkA1BPeCY0/fNt46SAZ+BBk5YUog=' 'sha256-E2oZTbkSZFNAieIligzDv/TFgADSZyPbO9tODj4+k/I='; ` +
        "img-src 'self' data: blob: https://raw.githubusercontent.com https://cdnjs.cloudflare.com; " +
        "media-src 'self' blob: data:; " +
        "connect-src 'self' wss://signaling-server-zc6m.onrender.com https://api.x.ai/v1/chat/completions; " +
        "object-src 'none'; base-uri 'self';";
      let htmlString = data.toString();
      htmlString = htmlString.replace(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/i, `<meta http-equiv="Content-Security-Policy" content="${updatedCSP}">`);
      htmlString = htmlString.replace(/<script/g, `<script nonce="${nonce}"`);
      htmlString = htmlString.replace(/<style/g, `<style nonce="${nonce}"`);
      data = Buffer.from(htmlString);

      // Cookie handling for clientId
      const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
      }, {}) : {};
      let clientIdFromCookie = cookies['clientId'];
      if (!clientIdFromCookie) {
        clientIdFromCookie = uuidv4();
        res.setHeader('Set-Cookie', `clientId=${clientIdFromCookie}; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000; Path=/`);
      }
    } else if (filePath.endsWith('.js')) {
      contentType = 'application/javascript';
    }

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

module.exports = { handleRequest };
