// server.js
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const otplib = require('otplib');

const CERT_KEY_PATH = 'path/to/your/private-key.pem';
const CERT_PATH = 'path/to/your/fullchain.pem';
let server;
if (process.env.NODE_ENV === 'production' || !fs.existsSync(CERT_KEY_PATH) || !fs.existsSync(CERT_PATH)) {
  server = http.createServer();
  console.log('Using HTTP server (production or missing certificates)');
} else {
  server = https.createServer({
    key: fs.readFileSync(CERT_KEY_PATH),
    cert: fs.readFileSync(CERT_PATH)
  });
  console.log('Using HTTPS server for local development');
}

server.on('request', (req, res) => {
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
        `style-src 'self' https://cdn.jsdelivr.net 'nonce-${nonce}' 'unsafe-hashes' 'sha256-biLFinpqYMtWHmXfkA1BPeCY0/fNt46SAZ+BBk5YUog='; ` +
        "img-src 'self' data: blob: https://raw.githubusercontent.com https://cdnjs.cloudflare.com; " +
        "media-src 'self' blob: data:; " +
        "connect-src 'self' wss://signaling-server-zc6m.onrender.com https://api.x.ai/v1/chat/completions; " +
        "object-src 'none'; base-uri 'self';";
      data = data.toString().replace(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/,
        `<meta http-equiv="Content-Security-Policy" content="${updatedCSP}">`);
      data = data.toString().replace(/<script(?! src)/g, `<script nonce="${nonce}"`);
      data = data.toString().replace(/<style/g, `<style nonce="${nonce}"`);
      let clientIdFromCookie;
      const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
      }, {}) : {};
      clientIdFromCookie = cookies['clientId'];
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
});

const wss = new WebSocket.Server({ server });
const rooms = new Map();
const dailyUsers = new Map();
const dailyConnections = new Map();
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const FEATURES_FILE = path.join('/data', 'features.json');
const STATS_FILE = path.join('/data', 'stats.json');
const UPDATE_INTERVAL = 30000;
const randomCodes = new Set();
const rateLimits = new Map();
const allTimeUsers = new Set();
const ipRateLimits = new Map();
const ipDailyLimits = new Map();
const ipFailureCounts = new Map();
const ipBans = new Map();
const revokedTokens = new Map();
const clientTokens = new Map();
const totpSecrets = new Map();
const processedMessageIds = new Map();
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  throw new Error('ADMIN_SECRET environment variable is not set. Please configure it for security.');
}
const ALLOWED_ORIGINS = ['https://anonomoose.com', 'https://www.anonomoose.com', 'http://localhost:3000', 'https://signaling-server-zc6m.onrender.com'];
const secretFile = path.join('/data', 'jwt_secret.txt');
const previousSecretFile = path.join('/data', 'previous_jwt_secret.txt');
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (fs.existsSync(secretFile)) {
    JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
  } else {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, JWT_SECRET);
    console.log('Generated new JWT secret and saved to disk.');
  }
}
if (fs.existsSync(secretFile)) {
  const stats = fs.statSync(secretFile);
  const mtime = stats.mtime.getTime();
  const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
  if (mtime < thirtyDaysAgo) {
    const previousSecret = JWT_SECRET;
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, JWT_SECRET);
    fs.writeFileSync(previousSecretFile, previousSecret);
    console.log('Rotated JWT secret. New secret saved, previous retained for grace period.');
  }
}
const TURN_USERNAME = process.env.TURN_USERNAME;
if (!TURN_USERNAME) {
  throw new Error('TURN_USERNAME environment variable is not set. Please configure it.');
}
const TURN_CREDENTIAL = process.env.TURN_CREDENTIAL;
if (!TURN_CREDENTIAL) {
  throw new Error('TURN_CREDENTIAL environment variable is not set. Please configure it.');
}
const IP_SALT = process.env.IP_SALT || 'your-random-salt-here';
let features = {
  enableService: true,
  enableImages: true,
  enableVoice: true,
  enableVoiceCalls: true,
  enableAudioToggle: true,
  enableGrokBot: true,
  enableP2P: true,
  enableRelay: true
};

if (fs.existsSync(FEATURES_FILE)) {
  try {
    features = JSON.parse(fs.readFileSync(FEATURES_FILE, 'utf8'));
    console.log('Loaded features:', features);
  } catch (err) {
    console.error('Error loading features file:', err);
  }
} else {
  fs.writeFileSync(FEATURES_FILE, JSON.stringify(features));
}

let aggregatedStats = fs.existsSync(STATS_FILE) ? JSON.parse(fs.readFileSync(STATS_FILE, 'utf8')) : { daily: {} };

function saveFeatures() {
  fs.writeFileSync(FEATURES_FILE, JSON.stringify(features));
  console.log('Saved features:', features);
}

function saveAggregatedStats() {
  fs.writeFileSync(STATS_FILE, JSON.stringify(aggregatedStats));
  console.log('Saved aggregated stats to disk');
}

function isValidBase32(str) {
  return /^[A-Z2-7]+=*$/i.test(str) && str.length >= 16;
}

function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  let sanitized = str.replace(/[^A-Za-z0-9+/=]/g, '');
  const padding = (4 - sanitized.length % 4) % 4;
  sanitized += '='.repeat(padding);
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  const isValid = base64Regex.test(sanitized);
  if (!isValid) console.warn('Invalid base64 detected:', str);
  return isValid;
}

function validateMessage(data) {
  if (typeof data !== 'object' || data === null || !data.type) {
    return { valid: false, error: 'Invalid message: must be an object with "type" field' };
  }
  if (data.token && typeof data.token !== 'string') {
    return { valid: false, error: 'Invalid token: must be a string' };
  }
  if (data.clientId && typeof data.clientId !== 'string') {
    return { valid: false, error: 'Invalid clientId: must be a string' };
  }
  if (data.code && !validateCode(data.code)) {
    return { valid: false, error: 'Invalid code format' };
  }
  if (data.username && !validateUsername(data.username)) {
    return { valid: false, error: 'Invalid username: 1-16 alphanumeric characters' };
  }
  switch (data.type) {
    case 'connect':
      if (!data.clientId || typeof data.clientId !== 'string') {
        return { valid: false, error: 'connect: clientId required as string' };
      }
      break;
    case 'refresh-token':
      if (!data.refreshToken || typeof data.refreshToken !== 'string') {
        return { valid: false, error: 'refresh-token: refreshToken required as string' };
      }
      break;
    case 'public-key':
      if (!data.publicKey || !isValidBase64(data.publicKey) || data.publicKey.length < 128 || data.publicKey.length > 132) {
        return { valid: false, error: 'public-key: invalid publicKey format or length' };
      }
      if (!data.code) {
        return { valid: false, error: 'public-key: code required' };
      }
      break;
    case 'encrypted-room-key':
      if (!data.encryptedKey || !isValidBase64(data.encryptedKey)) {
        return { valid: false, error: 'encrypted-room-key: invalid encryptedKey format' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'encrypted-room-key: invalid iv' };
      }
      if (!data.publicKey || !isValidBase64(data.publicKey) || data.publicKey.length < 128 || data.publicKey.length > 132) {
        return { valid: false, error: 'encrypted-room-key: invalid publicKey format or length' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'encrypted-room-key: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'encrypted-room-key: code required' };
      }
      break;
    case 'new-room-key':
      if (!data.encrypted || !isValidBase64(data.encrypted)) {
        return { valid: false, error: 'new-room-key: invalid encrypted' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'new-room-key: invalid iv' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'new-room-key: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'new-room-key: code required' };
      }
      break;
    case 'join':
      if (!data.code) {
        return { valid: false, error: 'join: code required' };
      }
      if (!data.username) {
        return { valid: false, error: 'join: username required' };
      }
      if (data.totpCode && typeof data.totpCode !== 'string') {
        return { valid: false, error: 'join: totpCode must be a string if provided' };
      }
      break;
    case 'check-totp':
      if (!data.code) {
        return { valid: false, error: 'check-totp: code required' };
      }
      break;
    case 'set-max-clients':
      if (!data.maxClients || typeof data.maxClients !== 'number' || data.maxClients < 2 || data.maxClients > 10) {
        return { valid: false, error: 'set-max-clients: maxClients must be number between 2 and 10' };
      }
      if (!data.code) {
        return { valid: false, error: 'set-max-clients: code required' };
      }
      break;
    case 'offer':
    case 'answer':
      if (!data.offer && !data.answer) {
        return { valid: false, error: `${data.type}: offer or answer required` };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: `${data.type}: targetId required as string` };
      }
      if (!data.code) {
        return { valid: false, error: `${data.type}: code required` };
      }
      break;
    case 'candidate':
      if (!data.candidate) {
        return { valid: false, error: 'candidate: candidate required' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'candidate: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'candidate: code required' };
      }
      break;
    case 'submit-random':
      if (!data.code) {
        return { valid: false, error: 'submit-random: code required' };
      }
      break;
    case 'get-random-codes':
      break;
    case 'relay-message':
      if (!data.content || typeof data.content !== 'string') {
        return { valid: false, error: 'relay-message: content required as string' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'relay-message: messageId required as string' };
      }
      if (!data.timestamp || typeof data.timestamp !== 'number') {
        return { valid: false, error: 'relay-message: timestamp required as number' };
      }
      if (!data.code) {
        return { valid: false, error: 'relay-message: code required' };
      }
      break;
    case 'relay-image':
    case 'relay-voice':
    case 'relay-file':
      if (!data.data || !isValidBase64(data.data)) {
        return { valid: false, error: `${data.type}: invalid data (base64)` };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: `${data.type}: messageId required as string` };
      }
      if (!data.timestamp || typeof data.timestamp !== 'number') {
        return { valid: false, error: `${data.type}: timestamp required as number' };
      }
      if (data.type === 'relay-file' && (!data.filename || typeof data.filename !== 'string')) {
        return { valid: false, error: 'relay-file: filename required as string' };
      }
      if (!data.code) {
        return { valid: false, error: `${data.type}: code required` };
      }
      break;
    case 'get-stats':
    case 'get-features':
    case 'toggle-feature':
      if (!data.secret || typeof data.secret !== 'string') {
        return { valid: false, error: `${data.type}: secret required as string` };
      }
      if (data.type === 'toggle-feature' && (!data.feature || typeof data.feature !== 'string')) {
        return { valid: false, error: 'toggle-feature: feature required as string' };
      }
      break;
    case 'ping':
    case 'pong':
      break;
    case 'set-totp':
      if (!data.code) {
        return { valid: false, error: 'set-totp: code required' };
      }
      if (!data.secret || typeof data.secret !== 'string' || !isValidBase32(data.secret)) {
        return { valid: false, error: 'set-totp: valid base32 secret required' };
      }
      break;
    default:
      return { valid: false, error: 'Unknown message type' };
  }
  return { valid: true };
}

if (fs.existsSync(LOG_FILE)) {
  const logContent = fs.readFileSync(LOG_FILE, 'utf8');
  const lines = logContent.split('\n');
  lines.forEach(line => {
    const match = line.match(/Client: (\w+)/);
    if (match) allTimeUsers.add(match[1]);
  });
  console.log(`Loaded ${allTimeUsers.size} all-time unique users from log.`);
}

setInterval(() => {
  randomCodes.forEach(code => {
    if (!rooms.has(code) || rooms.get(code).clients.size === 0) {
      randomCodes.delete(code);
    }
  });
  broadcastRandomCodes();
  console.log('Auto-cleaned random codes.');
}, 3600000);

const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 50000);

setInterval(() => {
  const now = Date.now();
  revokedTokens.forEach((expiry, token) => {
    if (expiry < now) {
      revokedTokens.delete(token);
    }
  });
  processedMessageIds.forEach((messageSet, code) => {
    const now = Date.now();
    messageSet.forEach((timestamp, messageId) => {
      if (now - timestamp > 300000) {
        messageSet.delete(messageId);
      }
    });
    if (messageSet.size === 0) {
      processedMessageIds.delete(code);
    }
  });
  console.log(`Cleaned up expired revoked tokens and message IDs. Tokens: ${revokedTokens.size}, Messages: ${processedMessageIds.size}`);
}, 3600000);

wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    console.warn(`Rejected connection from invalid origin: ${origin}`);
    ws.close(1008, 'Invalid origin');
    return;
  }
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress;
  const hashedIp = hashIp(clientIp);
  if (ipBans.has(hashedIp) && ipBans.get(hashedIp).expiry > Date.now()) {
    ws.send(JSON.stringify({ type: 'error', message: 'IP temporarily banned due to excessive failures. Try again later.' }));
    return;
  }
  let clientId, code, username;
  let isAdmin = false;
  ws.on('message', async (message) => {
    if (!restrictRate(ws)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }
    try {
      const data = JSON.parse(message);
      const loggedData = { ...data };
      if (loggedData.secret) {
        loggedData.secret = '[REDACTED]';
      }
      console.log('Received:', loggedData);
      const validation = validateMessage(data);
      if (!validation.valid) {
        ws.send(JSON.stringify({ type: 'error', message: validation.error }));
        incrementFailure(clientIp);
        return;
      }
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string' && !(data.type === 'public-key' && key === 'publicKey') && !(data.type === 'encrypted-room-key' && key === 'publicKey')) {
          data[key] = validator.escape(validator.trim(data[key]));
        }
      });
      if ((data.type === 'public-key' || data.type === 'encrypted-room-key') && data.publicKey) {
        if (!isValidBase64(data.publicKey) || data.publicKey.length < 128 || data.publicKey.length > 132) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format or length' }));
          incrementFailure(clientIp);
          return;
        }
      }
      if (data.type === 'get-stats' || data.type === 'get-features' || data.type === 'toggle-feature') {
        if (data.secret === ADMIN_SECRET) {
          isAdmin = true;
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
          return;
        }
      }
      if (!features.enableService && !isAdmin && data.type !== 'connect') {
        ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
        ws.close();
        return;
      }
      if (data.type !== 'connect' && data.type !== 'refresh-token') {
        if (!data.token) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing authentication token' }));
          return;
        }
        try {
          let decoded = jwt.verify(data.token, JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
            return;
          }
          if (revokedTokens.has(data.token)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
            return;
          }
        } catch (err) {
          if (fs.existsSync(previousSecretFile)) {
            const previousSecret = fs.readFileSync(previousSecretFile, 'utf8').trim();
            try {
              let decoded = jwt.verify(data.token, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
                return;
              }
              if (revokedTokens.has(data.token)) {
                ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
                return;
              }
            } catch (previousErr) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
              return;
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
            return;
          }
        }
      }
      if (data.type === 'connect') {
        clientId = data.clientId || uuidv4();
        ws.clientId = clientId;
        logStats({ clientId, event: 'connect' });
        const accessToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '10m' });
        const refreshToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '1h' });
        clientTokens.set(clientId, { accessToken, refreshToken });
        ws.send(JSON.stringify({ type: 'connected', clientId, accessToken, refreshToken }));
        return;
      }
      if (data.type === 'refresh-token') {
        if (!data.refreshToken) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing refresh token' }));
          return;
        }
        try {
          const decoded = jwt.verify(data.refreshToken, JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
            return;
          }
          if (revokedTokens.has(data.refreshToken)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
            return;
          }
          const oldRefreshExpiry = decoded.exp * 1000;
          revokedTokens.set(data.refreshToken, oldRefreshExpiry);
          const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '10m' });
          const newRefreshToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '1h' });
          clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
          ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
        } catch (err) {
          if (fs.existsSync(previousSecretFile)) {
            const previousSecret = fs.readFileSync(previousSecretFile, 'utf8').trim();
            try {
              const decoded = jwt.verify(data.refreshToken, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
                return;
              }
              if (revokedTokens.has(data.refreshToken)) {
                ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
                return;
              }
              const oldRefreshExpiry = decoded.exp * 1000;
              revokedTokens.set(data.refreshToken, oldRefreshExpiry);
              const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '10m' });
              const newRefreshToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '1h' });
              clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
              ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
            } catch (previousErr) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
              return;
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
            return;
          }
        }
        return;
      }
      if (data.type === 'public-key') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const initiatorWs = room.clients.get(room.initiator)?.ws;
          if (initiatorWs && initiatorWs.readyState === WebSocket.OPEN) {
            initiatorWs.send(JSON.stringify({ type: 'public-key', publicKey: data.publicKey, clientId: data.clientId, code: data.code }));
            console.log(`Forwarded public-key from ${data.clientId} to initiator ${room.initiator} for code: ${data.code}`);
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Initiator offline, cannot exchange keys', code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'encrypted-room-key') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const targetWs = room.clients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, publicKey: data.publicKey, clientId: data.clientId, code: data.code }));
            console.log(`Forwarded encrypted-room-key from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Target client not found or offline', code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'new-room-key') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const targetWs = room.clients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'new-room-key', encrypted: data.encrypted, iv: data.iv, targetId: data.targetId, clientId: data.clientId, code: data.code }));
            console.log(`Forwarded new-room-key from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Target client not found or offline', code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'join') {
        if (!features.enableService) {
          ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.', code: data.code }));
          return;
        }
        if (!restrictIpRate(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        if (!restrictIpDaily(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        if (!validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        if (!validateCode(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format: xxxx-xxxx-xxxx-xxxx.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        const roomTotpSecret = totpSecrets.get(code);
        if (roomTotpSecret && !data.totpCode) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          return;
        }
        if (roomTotpSecret && data.totpCode) {
          const isValid = otplib.authenticator.check(data.totpCode, roomTotpSecret);
          if (!isValid) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid TOTP code.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
        }
        if (!rooms.has(code)) {
          rooms.set(code, { initiator: clientId, clients: new Map(), maxClients: 2 });
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
          logStats({ clientId, username, code, event: 'init', totalClients: 1 });
        } else {
          const room = rooms.get(code);
          if (room.clients.size >= room.maxClients) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room is full.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (room.clients.has(clientId)) {
            if (room.clients.get(clientId).username === username) {
              const oldWs = room.clients.get(clientId).ws;
              setTimeout(() => {
                oldWs.close();
              }, 1000);
              room.clients.delete(clientId);
              broadcast(code, {
                type: 'client-disconnected',
                clientId,
                totalClients: room.clients.size,
                isInitiator: clientId === room.initiator
              });
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId.', code: data.code }));
              incrementFailure(clientIp);
              return;
            }
          } else if (Array.from(room.clients.values()).some(c => c.username === username)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
          logStats({ clientId, username, code, event: 'join', totalClients: room.clients.size + 1 });
          if (room.clients.size > 0) {
            room.clients.forEach((_, existingClientId) => {
              if (existingClientId !== clientId) {
                logStats({
                  clientId,
                  targetId: existingClientId,
                  code,
                  event: 'webrtc-connection',
                  totalClients: room.clients.size + 1
                });
              }
            });
          }
        }
        const room = rooms.get(code);
        room.clients.set(clientId, { ws, username });
        ws.code = code;
        ws.username = username;
        broadcast(code, { type: 'join-notify', clientId, username, code, totalClients: room.clients.size });
        return;
      }
      if (data.type === 'check-totp') {
        if (totpSecrets.has(data.code)) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
        } else {
          ws.send(JSON.stringify({ type: 'totp-not-required', code: data.code }));
        }
        return;
      }
      if (data.type === 'set-max-clients') {
        if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
          const room = rooms.get(data.code);
          room.maxClients = Math.min(data.maxClients, 10);
          broadcast(data.code, { type: 'max-clients', maxClients: room.maxClients, totalClients: room.clients.size });
          logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients: room.clients.size });
        }
        return;
      }
      if (data.type === 'set-totp') {
        if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
          totpSecrets.set(data.code, data.secret);
          broadcast(data.code, { type: 'totp-enabled', code: data.code });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
        }
        return;
      }
      if (data.type === 'offer' || data.type === 'answer' || data.type === 'candidate') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const target = room.clients.get(data.targetId);
          if (target && target.ws.readyState === WebSocket.OPEN) {
            console.log(`Forwarding ${data.type} from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
            target.ws.send(JSON.stringify({ ...data, clientId }));
          } else {
            console.warn(`Target ${data.targetId} not found or not open in room ${data.code}`);
            ws.send(JSON.stringify({ type: 'error', message: `Target ${data.targetId} not found or offline`, code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'submit-random') {
        if (!restrictIpRate(clientIp, 'submit-random')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        if (data.code && !rooms.get(data.code)?.clients.size) {
          ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        if (rooms.get(data.code)?.initiator === data.clientId) {
          randomCodes.add(data.code);
          broadcastRandomCodes();
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
          incrementFailure(clientIp);
        }
        return;
      }
      if (data.type === 'get-random-codes') {
        ws.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
        return;
      }
      if (data.type === 'remove-random-code') {
        if (randomCodes.has(data.code)) {
          randomCodes.delete(data.code);
          broadcastRandomCodes();
          console.log(`Removed code ${data.code} from randomCodes`);
        }
        return;
      }
      if (data.type === 'relay-message' || data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') {
        if (data.type === 'relay-image' && !features.enableImages) {
          ws.send(JSON.stringify({ type: 'error', message: 'Image messages are disabled.', code: data.code }));
          return;
        }
        if (data.type === 'relay-voice' && !features.enableVoice) {
          ws.send(JSON.stringify({ type: 'error', message: 'Voice messages are disabled.', code: data.code }));
          return;
        }
        const payload = data.type === 'relay-message' ? data.content : data.data;
        if (payload && (typeof payload !== 'string' || (data.type !== 'relay-message' && !isValidBase64(payload)))) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid payload format.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        if (payload && payload.length > 9333333) {
          ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 5MB).', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        const room = rooms.get(data.code);
        const senderId = data.clientId;
        if (!room.clients.has(senderId)) {
          ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
          incrementFailure(clientIp);
          return;
        }
        if (!processedMessageIds.has(data.code)) {
          processedMessageIds.set(data.code, new Map());
        }
        const messageSet = processedMessageIds.get(data.code);
        if (messageSet.has(data.messageId)) {
          console.warn(`Duplicate messageId ${data.messageId} in room ${data.code}, ignoring`);
          return;
        }
        messageSet.set(data.messageId, Date.now());
        room.clients.forEach((client, clientId) => {
          if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
              type: data.type.replace('relay-', ''),
              messageId: data.messageId,
              username: data.username,
              content: data.type === 'relay-message' ? data.content : undefined,
              data: data.type !== 'relay-message' ? data.data : undefined,
              filename: data.filename,
              timestamp: data.timestamp
            }));
            console.log(`Relayed ${data.type} from ${senderId} to ${clientId} in code ${data.code}`);
          }
        });
        console.log(`Relayed ${data.type} from ${senderId} in code ${data.code} to ${room.clients.size - 1} clients`);
        return;
      }
      if (data.type === 'get-stats') {
        if (data.secret === ADMIN_SECRET) {
          const now = new Date();
          const day = now.toISOString().slice(0, 10);
          let totalClients = 0;
          rooms.forEach(room => {
            totalClients += room.clients.size;
          });
          const weekly = computeAggregate(7);
          const monthly = computeAggregate(30);
          const yearly = computeAggregate(365);
          ws.send(JSON.stringify({
            type: 'stats',
            dailyUsers: dailyUsers.get(day)?.size || 0,
            dailyConnections: dailyConnections.get(day)?.size || 0,
            weeklyUsers: weekly.users,
            weeklyConnections: weekly.connections,
            monthlyUsers: monthly.users,
            monthlyConnections: monthly.connections,
            yearlyUsers: yearly.users,
            yearlyConnections: yearly.connections,
            allTimeUsers: allTimeUsers.size,
            activeRooms: rooms.size,
            totalClients: totalClients
          }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'get-features') {
        if (data.secret === ADMIN_SECRET) {
          ws.send(JSON.stringify({ type: 'features', ...features }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'toggle-feature') {
        if (data.secret === ADMIN_SECRET) {
          const featureKey = `enable${data.feature.charAt(0).toUpperCase() + data.feature.slice(1)}`;
          if (features.hasOwnProperty(featureKey)) {
            features[featureKey] = !features[featureKey];
            saveFeatures();
            const timestamp = new Date().toISOString();
            fs.appendFileSync(LOG_FILE, `${timestamp} - Admin toggled ${featureKey} to ${features[featureKey]} by client ${hashIp(clientIp)}\n`);
            ws.send(JSON.stringify({ type: 'feature-toggled', feature: data.feature, enabled: features[featureKey] }));
            wss.clients.forEach(client => {
              if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ type: 'features-update', ...features }));
                if (data.feature === 'service' && !features.enableService && !client.isAdmin) {
                  client.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
                  client.close();
                }
              }
            });
            if (data.feature === 'service' && !features.enableService) {
              rooms.clear();
              randomCodes.clear();
              totpSecrets.clear();
              processedMessageIds.clear();
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid feature' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      if (data.type === 'pong') {
        console.log('Received pong from client');
        return;
      }
    } catch (error) {
      console.error('Error processing message:', error);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.', code: data.code }));
      incrementFailure(clientIp);
    }
  });
  ws.on('close', () => {
    if (ws.clientId) {
      const tokens = clientTokens.get(ws.clientId);
      if (tokens) {
        try {
          const decodedAccess = jwt.verify(tokens.accessToken, JWT_SECRET, { ignoreExpiration: true });
          revokedTokens.set(tokens.accessToken, decodedAccess.exp * 1000);
          if (tokens.refreshToken) {
            const decodedRefresh = jwt.verify(tokens.refreshToken, JWT_SECRET, { ignoreExpiration: true });
            revokedTokens.set(tokens.refreshToken, decodedRefresh.exp * 1000);
          }
          clientTokens.delete(ws.clientId);
          console.log(`Revoked tokens for client ${ws.clientId} on disconnect`);
        } catch (err) {
          console.warn(`Failed to revoke tokens for client ${ws.clientId}: ${err.message}`);
        }
      }
    }
    if (ws.code && rooms.has(ws.code)) {
      const room = rooms.get(ws.code);
      const isInitiator = ws.clientId === room.initiator;
      room.clients.delete(ws.clientId);
      rateLimits.delete(ws.clientId);
      logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients: room.clients.size, isInitiator });
      if (room.clients.size === 0 || isInitiator) {
        rooms.delete(ws.code);
        randomCodes.delete(ws.code);
        totpSecrets.delete(ws.code);
        processedMessageIds.delete(ws.code);
        broadcast(ws.code, {
          type: 'client-disconnected',
          clientId: ws.clientId,
          totalClients: 0,
          isInitiator
        });
      } else {
        if (isInitiator) {
          const newInitiator = room.clients.keys().next().value;
          if (newInitiator) {
            room.initiator = newInitiator;
            broadcast(ws.code, {
              type: 'initiator-changed',
              newInitiator,
              totalClients: room.clients.size
            });
          }
        }
        broadcast(ws.code, {
          type: 'client-disconnected',
          clientId: ws.clientId,
          totalClients: room.clients.size,
          isInitiator
        });
      }
    }
  });
});

function restrictRate(ws) {
  if (ws.isAdmin) return true;
  if (!ws.clientId) return true;
  const now = Date.now();
  const rateLimit = rateLimits.get(ws.clientId) || { count: 0, startTime: now };
  if (now - rateLimit.startTime >= 60000) {
    rateLimit.count = 0;
    rateLimit.startTime = now;
  }
  rateLimit.count += 1;
  rateLimits.set(ws.clientId, rateLimit);
  if (rateLimit.count > 50) {
    console.warn(`Rate limit exceeded for client ${ws.clientId}: ${rateLimit.count} messages in 60s`);
    fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - Rate limit exceeded for client ${ws.clientId}: ${rateLimit.count} messages\n`);
    return false;
  }
  return true;
}

function restrictIpRate(ip, action) {
  const hashedIp = hashIp(ip);
  const now = Date.now();
  const key = `${hashedIp}:${action}`;
  const rateLimit = ipRateLimits.get(key) || { count: 0, startTime: now };
  if (now - rateLimit.startTime >= 60000) {
    rateLimit.count = 0;
    rateLimit.startTime = now;
  }
  rateLimit.count += 1;
  ipRateLimits.set(key, rateLimit);
  if (rateLimit.count > 5) {
    console.warn(`IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${rateLimit.count} in 60s`);
    fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${rateLimit.count}\n`);
    return false;
  }
  return true;
}

function restrictIpDaily(ip, action) {
  const hashedIp = hashIp(ip);
  const day = new Date().toISOString().slice(0, 10);
  const key = `${hashedIp}:${action}:${day}`;
  const dailyLimit = ipDailyLimits.get(key) || { count: 0 };
  dailyLimit.count += 1;
  ipDailyLimits.set(key, dailyLimit);
  if (dailyLimit.count > 100) {
    console.warn(`Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${dailyLimit.count} in day ${day}`);
    fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${dailyLimit.count}\n`);
    return false;
  }
  return true;
}

function incrementFailure(ip) {
  const hashedIp = hashIp(ip);
  const failure = ipFailureCounts.get(hashedIp) || { count: 0, banLevel: 0 };
  failure.count += 1;
  ipFailureCounts.set(hashedIp, failure);
  if (failure.count % 5 === 0) {
    console.warn(`High failure rate for hashed IP ${hashedIp}: ${failure.count} failures`);
  }
  if (failure.count >= 10) {
    const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];
    failure.banLevel = Math.min(failure.banLevel + 1, 2);
    const duration = banDurations[failure.banLevel];
    const expiry = Date.now() + duration;
    ipBans.set(hashedIp, { expiry, banLevel: failure.banLevel });
    const timestamp = new Date().toISOString();
    const banLogEntry = `${timestamp} - Hashed IP Banned: ${hashedIp}, Duration: ${duration / 60000} minutes, Ban Level: ${failure.banLevel}\n`;
    fs.appendFileSync(LOG_FILE, banLogEntry, (err) => {
      if (err) {
        console.error('Error appending ban log:', err);
      } else {
        console.warn(`Hashed IP ${hashedIp} banned until ${new Date(expiry).toISOString()} at ban level ${failure.banLevel} (${duration / 60000} minutes)`);
      }
    });
    ipFailureCounts.delete(hashedIp);
  }
}

function validateUsername(username) {
  const regex = /^[a-zA-Z0-9]{1,16}$/;
  return username && regex.test(username);
}

function validateCode(code) {
  const regex = /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/;
  return code && regex.test(code);
}

function logStats(data) {
  const timestamp = new Date().toISOString();
  const day = timestamp.slice(0, 10);
  const stats = {
    clientId: data.clientId,
    username: data.username ? crypto.createHmac('sha256', IP_SALT).update(data.username).digest('hex') : '',
    targetId: data.targetId || '',
    code: data.code || '',
    event: data.event || '',
    totalClients: data.totalClients || 0,
    isInitiator: data.isInitiator || false,
    timestamp,
    day
  };
  if (data.event === 'connect' || data.event === 'join' || data.event === 'webrtc-connection') {
    if (!dailyUsers.has(day)) {
      dailyUsers.set(day, new Set());
    }
    if (!dailyConnections.has(day)) {
      dailyConnections.set(day, new Set());
    }
    dailyUsers.get(day).add(data.clientId);
    allTimeUsers.add(data.clientId);
    if (data.event === 'webrtc-connection' && data.targetId) {
      dailyUsers.get(day).add(data.targetId);
      allTimeUsers.add(data.targetId);
      const connectionKey = `${data.clientId}-${data.targetId}-${data.code}`;
      dailyConnections.get(day).add(connectionKey);
    }
  }
  const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}\n`;
  fs.appendFileSync(LOG_FILE, logEntry, (err) => {
    if (err) {
      console.error('Error appending to log file:', err);
    }
  });
}

function updateLogFile() {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  const userCount = dailyUsers.get(day)?.size || 0;
  const connectionCount = dailyConnections.get(day)?.size || 0;
  const allTimeUserCount = allTimeUsers.size;
  const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}, All-Time Unique Users: ${allTimeUserCount}\n`;
  fs.appendFileSync(LOG_FILE, logEntry, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    } else {
      console.log(`Updated ${LOG_FILE} with ${userCount} unique users, ${connectionCount} WebRTC connections, and ${allTimeUserCount} all-time unique users for ${day}`);
    }
  });
  if (!aggregatedStats.daily) aggregatedStats.daily = {};
  aggregatedStats.daily[day] = { users: userCount, connections: connectionCount };
  saveAggregatedStats();
}

fs.writeFileSync(LOG_FILE, '', (err) => {
  if (err) console.error('Error creating log file:', err);
  else {
    updateLogFile();
    setInterval(updateLogFile, UPDATE_INTERVAL);
  }
});

function computeAggregate(days) {
  const now = new Date();
  let users = 0, connections = 0;
  for (let i = 0; i < days; i++) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const key = date.toISOString().slice(0, 10);
    if (aggregatedStats.daily[key]) {
      users += aggregatedStats.daily[key].users;
      connections += aggregatedStats.daily[key].connections;
    }
  }
  return { users, connections };
}

function broadcast(code, message) {
  const room = rooms.get(code);
  if (room) {
    room.clients.forEach(client => {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(JSON.stringify(message));
      }
    });
    console.log(`Broadcasted ${message.type} to ${room.clients.size} clients in code ${code}`);
  } else {
    console.warn(`Cannot broadcast: Room ${code} not found`);
  }
}

function broadcastRandomCodes() {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
    }
  });
  console.log(`Broadcasted random codes to all clients: ${Array.from(randomCodes)}`);
}

function hashIp(ip) {
  return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
}

server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
