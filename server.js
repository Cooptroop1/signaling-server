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
const UAParser = require('ua-parser-js');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

// Hash password
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

// Validate password
async function validatePassword(input, hash) {
  return bcrypt.compare(input, hash);
}

const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // For Render Postgres
});

// Test DB connection on startup
dbPool.connect((err) => {
  if (err) {
    console.error('DB connection error:', err.message, err.stack);
  } else {
    console.log('Connected to DB successfully');
  }
});

// Clean up old offline messages (TTL: 24 hours)
setInterval(async () => {
  try {
    await dbPool.query('DELETE FROM offline_messages WHERE created_at < NOW() - INTERVAL \'24 hours\'');
    console.log('Cleaned up expired offline messages');
  } catch (err) {
    console.error('Error cleaning up offline messages:', err.message, err.stack);
  }
}, 24 * 60 * 60 * 1000); // Run daily

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
        `style-src 'self' https://cdn.jsdelivr.net 'nonce-${nonce}'; ` +
        "img-src 'self' data: blob: https://raw.githubusercontent.com https://cdnjs.cloudflare.com; " +
        "media-src 'self' blob: data:; " +
        "connect-src 'self' wss://signaling-server-zc6m.onrender.com https://api.x.ai/v1/chat/completions; " +
        "object-src 'none'; base-uri 'self';";
      data = data.toString().replace(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/,
        `<meta http-equiv="Content-Security-Policy" content="${updatedCSP}">`);
      data = data.toString().replace(/<script(?! src)/g,
        `<script nonce="${nonce}"`);
      data = data.toString().replace(/<style/g,
        `<style nonce="${nonce}"`);
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
const AUDIT_FILE_BASE = path.join(__dirname, 'audit');
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
const clientSizeLimits = new Map();
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
        return { valid: false, error: data.type + ': offer or answer required' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: data.type + ': targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: data.type + ': code required' };
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
    case 'kick':
    case 'ban':
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: `${data.type}: targetId required as string` };
      }
      if (!data.signature || !isValidBase64(data.signature)) {
        return { valid: false, error: `${data.type}: valid signature required` };
      }
      if (!data.code) {
        return { valid: false, error: `${data.type}: code required` };
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
      if ((!data.content && !data.encryptedContent && !data.data && !data.encryptedData) || typeof (data.content || data.encryptedContent || data.data || data.encryptedData) !== 'string') {
        return { valid: false, error: 'relay-message: content, encryptedContent, data, or encryptedData required as string' };
      }
      if ((data.encryptedContent || data.encryptedData) && !data.iv) {
        return { valid: false, error: 'relay-message: iv required for encryptedContent or encryptedData' };
      }
      if ((data.encryptedContent || data.encryptedData) && !data.signature) {
        return { valid: false, error: 'relay-message: signature required for encryptedContent or encryptedData' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'relay-message: messageId required as string' };
      }
      if (!data.timestamp || typeof data.timestamp !== 'number') {
        return { valid: false, error: 'relay-message: timestamp required as number' };
      }
      if (!data.nonce || typeof data.nonce !== 'string') {
        return { valid: false, error: 'relay-message: nonce required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'relay-message: code required' };
      }
      break;
    case 'relay-image':
    case 'relay-voice':
    case 'relay-file':
      if ((!data.data && !data.encryptedData) || !isValidBase64(data.data || data.encryptedData)) {
        return { valid: false, error: data.type + ': invalid data or encryptedData (base64)' };
      }
      if (data.encryptedData && !data.iv) {
        return { valid: false, error: data.type + ': iv required for encryptedData' };
      }
      if (data.encryptedData && !data.signature) {
        return { valid: false, error: data.type + ': signature required for encryptedData' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: data.type + ': messageId required as string' };
      }
      if (!data.timestamp || typeof data.timestamp !== 'number') {
        return { valid: false, error: data.type + ': timestamp required as number' };
      }
      if (!data.nonce || typeof data.nonce !== 'string') {
        return { valid: false, error: data.type + ': nonce required as string' };
      }
      if (data.type === 'relay-file' && (!data.filename || typeof data.filename !== 'string')) {
        return { valid: false, error: 'relay-file: filename required as string' };
      }
      if (!data.code) {
        return { valid: false, error: data.type + ': code required' };
      }
      break;
    case 'get-stats':
    case 'get-features':
    case 'toggle-feature':
      if (!data.secret || typeof data.secret !== 'string') {
        return { valid: false, error: data.type + ': secret required as string' };
      }
      if (data.type === 'toggle-feature' && (!data.feature || typeof data.feature !== 'string')) {
        return { valid: false, error: 'toggle-feature: feature required as string' };
      }
      break;
    case 'export-stats-csv':
    case 'export-logs-csv':
      if (!data.secret || typeof data.secret !== 'string') {
        return { valid: false, error: data.type + ': secret required as string' };
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
    case 'register-username':
      if (!data.username) {
        return { valid: false, error: 'register-username: username required' };
      }
      if (!data.password || typeof data.password !== 'string' || data.password.length < 8) {
        return { valid: false, error: 'register-username: password required as string (min 8 chars)' };
      }
      if (data.public_key && !isValidBase64(data.public_key)) {
        return { valid: false, error: 'register-username: invalid public_key (base64)' };
      }
      break;
    case 'login-username':
      if (!data.username) {
        return { valid: false, error: 'login-username: username required' };
      }
      if (!data.password || typeof data.password !== 'string' || data.password.length < 8) {
        return { valid: false, error: 'login-username: password required as string (min 8 chars)' };
      }
      break;
    case 'find-user':
      if (!data.username) {
        return { valid: false, error: 'find-user: username required' };
      }
      break;
    case 'send-offline-message':
      if (!data.to_username) {
        return { valid: false, error: 'send-offline-message: to_username required' };
      }
      if (!data.encrypted || !isValidBase64(data.encrypted)) {
        return { valid: false, error: 'send-offline-message: invalid encrypted (base64)' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'send-offline-message: invalid iv (base64)' };
      }
      if (!data.ephemeral_public || !isValidBase64(data.ephemeral_public)) {
        return { valid: false, error: 'send-offline-message: invalid ephemeral_public (base64)' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'send-offline-message: messageId required as string' };
      }
      break;
    case 'confirm-offline-message':
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'confirm-offline-message: messageId required as string' };
      }
      break;
    case 'logout':
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
    messageSet.forEach((timestamp, nonce) => {
      if (now - timestamp > 300000) {
        messageSet.delete(nonce);
      }
    });
    if (messageSet.size === 0) {
      processedMessageIds.delete(code);
    }
  });
  console.log(`Cleaned up expired revoked tokens and message IDs. Tokens: ${revokedTokens.size}, Messages: ${processedMessageIds.size}`);
}, 600000);

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
  const userAgent = req.headers['user-agent'] || 'unknown';
  ws.userAgent = userAgent;
  const hashedIp = hashIp(clientIp);
  const hashedUa = hashUa(userAgent);
  const compositeKey = hashedIp + ':' + hashedUa;
  if (ipBans.has(compositeKey) && ipBans.get(compositeKey).expiry > Date.now()) {
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
        incrementFailure(clientIp, ws.userAgent);
        return;
      }
      // Skip escaping for specific fields that should remain untouched
      const skipEscapeFields = [
        data.type === 'public-key' && 'publicKey',
        data.type === 'encrypted-room-key' && 'publicKey',
        data.type === 'encrypted-room-key' && 'encryptedKey',
        data.type === 'encrypted-room-key' && 'iv',
        data.type === 'new-room-key' && 'encrypted',
        data.type === 'new-room-key' && 'iv',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'content',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'data',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'encryptedContent',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'encryptedData',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'iv',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'signature',
        data.type === 'send-offline-message' && 'encrypted',
        data.type === 'send-offline-message' && 'iv',
        data.type === 'send-offline-message' && 'ephemeral_public'
      ];
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string' && !skipEscapeFields.includes(key)) {
          data[key] = validator.escape(validator.trim(data[key]));
        }
      });
      if ((data.type === 'public-key' || data.type === 'encrypted-room-key') && data.publicKey) {
        if (!isValidBase64(data.publicKey) || data.publicKey.length < 128 || data.publicKey.length > 132) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format or length' }));
          incrementFailure(clientIp, ws.userAgent);
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
        await dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [clientId]);
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
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!restrictIpDaily(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        if (!validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!validateCode(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format: xxxx-xxxx-xxxx-xxxx.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
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
            incrementFailure(clientIp, ws.userAgent);
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
            incrementFailure(clientIp, ws.userAgent);
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
              incrementFailure(clientIp, ws.userAgent);
              return;
            }
          } else if (Array.from(room.clients.values()).some(c => c.username === username)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
            incrementFailure(clientIp, ws.userAgent);
            return;
          }
          if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
            incrementFailure(clientIp, ws.userAgent);
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
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (data.code && !rooms.get(data.code)?.clients.size) {
          ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (rooms.get(data.code)?.initiator === data.clientId) {
          randomCodes.add(data.code);
          broadcastRandomCodes();
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
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
        const payloadKey = data.content || data.encryptedContent || data.data || data.encryptedData;
        if (payloadKey && (typeof payloadKey !== 'string' || (data.encryptedContent || data.encryptedData || data.type !== 'relay-message') && !isValidBase64(payloadKey))) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid payload format.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const payloadSize = payloadKey ? (payloadKey.length * 3 / 4) : 0;
        if (!restrictClientSize(data.clientId, payloadSize)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Message size limit exceeded (1MB/min total).', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (payloadKey && payloadKey.length > 9333333) {
          ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 5MB).', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const room = rooms.get(data.code);
        const senderId = data.clientId;
        if (!room.clients.has(senderId)) {
          ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!processedMessageIds.has(data.code)) {
          processedMessageIds.set(data.code, new Map());
        }
        const messageSet = processedMessageIds.get(data.code);
        if (messageSet.has(data.nonce)) {
          console.warn(`Duplicate nonce ${data.nonce} in room ${data.code}, ignoring`);
          return;
        }
        const now = Date.now();
        if (Math.abs(now - data.timestamp) > 300000) {
          console.warn(`Invalid timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp} (now: ${now})`);
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid message timestamp.', code: data.code }));
          return;
        }
        if (data.timestamp > now) {
          console.warn(`Future timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Message timestamp in future.', code: data.code }));
          return;
        }
        messageSet.set(data.nonce, data.timestamp);
        room.clients.forEach((client, clientId) => {
          if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
              type: data.type.replace('relay-', ''),
              messageId: data.messageId,
              username: data.username,
              content: data.content,
              encryptedContent: data.encryptedContent,
              data: data.data,
              encryptedData: data.encryptedData,
              filename: data.filename,
              timestamp: data.timestamp,
              iv: data.iv,
              signature: data.signature,
              nonce: data.nonce
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
          let weekly = computeAggregate(7);
          let monthly = computeAggregate(30);
          let yearly = computeAggregate(365);
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
              clientTokens.forEach((tokens, clientId) => {
                revokedTokens.set(tokens.accessToken, Date.now() + 1000);
                if (tokens.refreshToken) {
                  revokedTokens.set(tokens.refreshToken, Date.now() + 1000);
                }
              });
              clientTokens.clear();
              console.log('All tokens invalidated due to service disable');
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
      if (data.type === 'export-stats-csv') {
        if (data.secret === ADMIN_SECRET) {
          const csv = generateStatsCSV();
          ws.send(JSON.stringify({ type: 'export-stats-csv', csv }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'export-logs-csv') {
        if (data.secret === ADMIN_SECRET) {
          const csv = generateLogsCSV();
          ws.send(JSON.stringify({ type: 'export-logs-csv', csv }));
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
      if (data.type === 'set-totp') {
        if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
          totpSecrets.set(data.code, data.secret);
          broadcast(data.code, { type: 'totp-enabled', code: data.code });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
        }
        return;
      }
      if (data.type === 'register-username') {
        const { username, password, public_key } = data;
        if (validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          try {
            const checkRes = await dbPool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (checkRes.rows.length > 0) {
              ws.send(JSON.stringify({ type: 'error', message: 'Username taken.' }));
              return;
            }
            const passwordHash = await hashPassword(password);
            await dbPool.query(
              'INSERT INTO users (username, password_hash, client_id, public_key) VALUES ($1, $2, $3, $4)',
              [username, passwordHash, data.clientId, public_key || null]
            );
            ws.send(JSON.stringify({ type: 'username-registered', username }));
            console.log(`Registered username ${username} for clientId ${data.clientId}`);
          } catch (err) {
            console.error('DB error registering username:', err.message, err.stack);
            ws.send(JSON.stringify({ type: 'error', message: 'Failed to register username. Check server logs for details.' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'login-username') {
        const { username, password } = data;
        if (validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          try {
            const res = await dbPool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (res.rows.length === 0) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid login credentials.' }));
              return;
            }
            const user = res.rows[0];
            const valid = await validatePassword(password, user.password_hash);
            if (!valid) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid login credentials.' }));
              return;
            }
            await dbPool.query('UPDATE users SET client_id = $1, last_active = CURRENT_TIMESTAMP WHERE id = $2', [data.clientId, user.id]);
            const msgRes = await dbPool.query(`
              SELECT om.id, om.message, u.username AS from_username
              FROM offline_messages om
              JOIN users u ON om.from_user_id = u.id
              WHERE om.to_user_id = $1
            `, [user.id]);
            const offlineMessages = msgRes.rows.map(msg => {
              try {
                const parsedMessage = JSON.parse(msg.message);
                return {
                  id: msg.id, // Include message ID for confirmation
                  from: msg.from_username,
                  code: parsedMessage.code || null,
                  type: parsedMessage.type || 'connection-request',
                  encrypted: parsedMessage.encrypted || null,
                  iv: parsedMessage.iv || null,
                  ephemeral_public: parsedMessage.ephemeral_public || null
                };
              } catch (err) {
                console.error(`Failed to parse offline message for user ${user.id}:`, err.message);
                return null;
              }
            }).filter(msg => msg !== null);
            console.log(`Fetched ${offlineMessages.length} offline messages for user ${username} (id: ${user.id})`);
            ws.send(JSON.stringify({ type: 'login-success', username, offlineMessages }));
            console.log(`User ${username} logged in with clientId ${data.clientId}`);
          } catch (err) {
            console.error('DB error during login:', err.message, err.stack);
            ws.send(JSON.stringify({ type: 'error', message: 'Failed to login. Check server logs.' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'find-user') {
        const { username, from_username } = data;
        try {
          const from_res = await dbPool.query('SELECT id, username FROM users WHERE client_id = $1', [data.clientId]);
          if (from_res.rows.length === 0) {
            console.warn(`Find-user failed: No user found for clientId ${data.clientId}`);
            ws.send(JSON.stringify({ type: 'error', message: 'Must be logged in to search users.' }));
            return;
          }
          const from_user_id = from_res.rows[0].id;
          const from_username = from_res.rows[0].username;
          const res = await dbPool.query('SELECT * FROM users WHERE username = $1', [username]);
          if (res.rows.length === 0) {
            ws.send(JSON.stringify({ type: 'user-not-found' }));
            return;
          }
          const user = res.rows[0];
          const dynamicCode = uuidv4().replace(/-/g, '').substring(0, 16).match(/.{1,4}/g).join('-');
          const ownerWs = [...wss.clients].find(client => client.clientId === user.client_id);
          if (ownerWs) {
            ownerWs.send(JSON.stringify({ type: 'incoming-connection', from: from_username, code: dynamicCode }));
          } else {
            await dbPool.query(
              'INSERT INTO offline_messages (from_user_id, to_user_id, message) VALUES ($1, $2, $3)',
              [from_user_id, user.id, JSON.stringify({ type: 'connection-request', code: dynamicCode })]
            );
          }
          const lastActive = user.last_active ? new Date(user.last_active).getTime() : 0;
          const isOnline = ownerWs || (Date.now() - lastActive < 5 * 60 * 1000);
          ws.send(JSON.stringify({ type: 'user-found', status: isOnline ? 'online' : 'offline', code: dynamicCode, public_key: user.public_key }));
          console.log(`User ${username} found for clientId ${data.clientId}, status: ${isOnline ? 'online' : 'offline'}, code: ${dynamicCode}`);
        } catch (err) {
          console.error('DB error finding user:', err.message, err.stack);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to find user. Check server logs for details.' }));
        }
        return;
      }
      if (data.type === 'send-offline-message') {
        const { to_username, encrypted, iv, ephemeral_public, messageId } = data;
        try {
          const res = await dbPool.query('SELECT id FROM users WHERE username = $1', [to_username]);
          if (res.rows.length === 0) {
            ws.send(JSON.stringify({ type: 'error', message: 'Recipient not found.' }));
            return;
          }
          const to_user_id = res.rows[0].id;
          const from_res = await dbPool.query('SELECT id FROM users WHERE client_id = $1', [data.clientId]);
          if (from_res.rows.length === 0) {
            console.warn(`Send-offline-message failed: No user found for clientId ${data.clientId}`);
            ws.send(JSON.stringify({ type: 'error', message: 'Sender not logged in with a username.' }));
            return;
          }
          const from_user_id = from_res.rows[0].id;
          await dbPool.query(
            'INSERT INTO offline_messages (from_user_id, to_user_id, message) VALUES ($1, $2, $3)',
            [from_user_id, to_user_id, JSON.stringify({ type: 'message', encrypted, iv, ephemeral_public, messageId })]
          );
          ws.send(JSON.stringify({ type: 'offline-message-sent', messageId }));
          console.log(`Offline message ${messageId} sent from clientId ${data.clientId} (user_id: ${from_user_id}) to ${to_username} (user_id: ${to_user_id})`);
        } catch (err) {
          console.error('DB error sending offline message:', err.message, err.stack);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to send offline message.' }));
        }
        return;
      }
      if (data.type === 'confirm-offline-message') {
        try {
          await dbPool.query('DELETE FROM offline_messages WHERE id = $1', [data.messageId]);
          console.log(`Confirmed and deleted offline message ${data.messageId} for clientId ${data.clientId}`);
          ws.send(JSON.stringify({ type: 'confirm-offline-message-ack', messageId: data.messageId }));
        } catch (err) {
          console.error('DB error confirming offline message:', err.message, err.stack);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to confirm offline message.' }));
        }
        return;
      }
      if (data.type === 'logout') {
        if (clientTokens.has(data.clientId)) {
          const tokens = clientTokens.get(data.clientId);
          revokedTokens.set(tokens.accessToken, Date.now() + 1000);
          if (tokens.refreshToken) {
            revokedTokens.set(tokens.refreshToken, Date.now() + 1000);
          }
          clientTokens.delete(data.clientId);
          console.log(`Client ${data.clientId} logged out, tokens revoked`);
        }
        if (ws.code && rooms.has(ws.code)) {
          const room = rooms.get(ws.code);
          const isInitiator = ws.clientId === room.initiator;
          room.clients.delete(ws.clientId);
          logStats({ clientId: ws.clientId, code: ws.code, event: 'logout', totalClients: room.clients.size, isInitiator });
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
        ws.send(JSON.stringify({ type: 'logout-success' }));
        return;
      }
    } catch (error) {
      console.error('Error processing message:', error.message, error.stack);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again. Check server logs.' }));
      incrementFailure(clientIp, ws.userAgent);
    }
  });
  ws.on('close', async () => {
    if (ws.clientId) {
      const tokens = clientTokens.get(ws.clientId);
      if (tokens) {
        try {
          const decoded = jwt.verify(tokens.accessToken, JWT_SECRET, { ignoreExpiration: true });
          revokedTokens.set(tokens.accessToken, decoded.exp * 1000);
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
    await dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [ws.clientId]);
  });
});

function restrictRate(ws) {
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

function restrictClientSize(clientId, size) {
  const now = Date.now();
  const sizeLimit = clientSizeLimits.get(clientId) || { totalSize: 0, startTime: now };
  if (now - sizeLimit.startTime >= 60000) {
    sizeLimit.totalSize = 0;
    sizeLimit.startTime = now;
  }
  sizeLimit.totalSize += size;
  clientSizeLimits.set(clientId, sizeLimit);
  if (sizeLimit.totalSize > 1048576) {
    console.warn(`Size limit exceeded for client ${clientId}: ${sizeLimit.totalSize} bytes in 60s`);
    fs.appendFileSync(AUDIT_FILE_BASE + '.log', `${new Date().toISOString()} - Size limit anomaly for client ${clientId}: ${sizeLimit.totalSize} bytes\n`);
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

function incrementFailure(ip, ua) {
  const hashedIp = hashIp(ip);
  const hashedUa = hashUa(ua);
  const key = hashedIp + ':' + hashedUa;
  const failure = ipFailureCounts.get(key) || { count: 0, banLevel: 0 };
  failure.count += 1;
  ipFailureCounts.set(key, failure);
  if (failure.count % 5 === 0) {
    console.warn(`High failure rate for key ${key}: ${failure.count} failures`);
    fs.appendFileSync(AUDIT_FILE_BASE + '.log', `${new Date().toISOString()} - High failure anomaly for key ${key}: ${failure.count} failures\n`);
  }
  if (failure.count >= 10) {
    const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];
    failure.banLevel = Math.min(failure.banLevel + 1, 2);
    const duration = banDurations[failure.banLevel];
    const expiry = Date.now() + duration;
    ipBans.set(key, { expiry, banLevel: failure.banLevel });
    const timestamp = new Date().toISOString();
    const banLogEntry = `${timestamp} - Key Banned: ${key}, Duration: ${duration / 60000} minutes, Ban Level: ${failure.banLevel}\n`;
    fs.appendFileSync(LOG_FILE, banLogEntry, (err) => {
      if (err) {
        console.error('Error appending ban log:', err);
      } else {
        console.warn(`Key ${key} banned until ${new Date(expiry).toISOString()} at ban level ${failure.banLevel} (${duration / 60000} minutes)`);
      }
    });
    ipFailureCounts.delete(key);
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
    clientId: validator.escape(data.clientId || ''),
    username: data.username ? validator.escape(crypto.createHmac('sha256', IP_SALT).update(data.username).digest('hex')) : '',
    targetId: validator.escape(data.targetId || ''),
    code: validator.escape(data.code || ''),
    event: validator.escape(data.event || ''),
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
    dailyUsers.get(day).add(stats.clientId);
    allTimeUsers.add(stats.clientId);
    if (data.event === 'webrtc-connection' && data.targetId) {
      dailyUsers.get(day).add(stats.targetId);
      allTimeUsers.add(stats.targetId);
      const connectionKey = `${stats.clientId}-${stats.targetId}-${stats.code}`;
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

function rotateAuditLog() {
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const currentFile = `${AUDIT_FILE_BASE}.log`;
  const rotatedFile = `${AUDIT_FILE_BASE}-${today}.log`;
  if (fs.existsSync(currentFile)) {
    fs.renameSync(currentFile, rotatedFile);
    console.log(`Rotated audit log to ${rotatedFile}`);
  }
  const files = fs.readdirSync(__dirname).filter(f => f.startsWith('audit-') && f.endsWith('.log'));
  files.forEach(file => {
    const fileDate = file.match(/audit-(\d{4}-\d{2}-\d{2})\.log/)[1];
    const fileTime = new Date(fileDate).getTime();
    if (now.getTime() - fileTime > 7 * 24 * 60 * 60 * 1000) {
      fs.unlinkSync(path.join(__dirname, file));
      console.log(`Deleted old audit log: ${file}`);
    }
  });
  fs.writeFileSync(currentFile, '');
}

rotateAuditLog();
setInterval(rotateAuditLog, 24 * 60 * 60 * 1000);

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
// New: Generate CSV for stats
function generateStatsCSV() {
  let csv = 'Period,Users,Connections\n';
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  csv += `Daily,${dailyUsers.get(day)?.size || 0},${dailyConnections.get(day)?.size || 0}\n`;
  const weekly = computeAggregate(7);
  csv += `Weekly,${weekly.users},${weekly.connections}\n`;
  const monthly = computeAggregate(30);
  csv += `Monthly,${monthly.users},${monthly.connections}\n`;
  const yearly = computeAggregate(365);
  csv += `Yearly,${yearly.users},${yearly.connections}\n`;
  csv += `All-Time,${allTimeUsers.size},N/A\n`;
  return csv;
}
// New: Generate CSV for logs (combine LOG_FILE and AUDIT_FILE)
function generateLogsCSV() {
  let csv = 'Timestamp,Event\n';
  const logContent = fs.readFileSync(LOG_FILE, 'utf8');
  logContent.split('\n').forEach(line => {
    if (line.trim()) csv += `${line}\n`;
  });
  const auditContent = fs.readFileSync(`${AUDIT_FILE_BASE}.log`, 'utf8');
  auditContent.split('\n').forEach(line => {
    if (line.trim()) csv += `${line}\n`;
  });
  return csv;
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
function hashUa(ua) {
  if (!ua) return crypto.createHmac('sha256', IP_SALT).update('unknown').digest('hex');
  const parser = new UAParser(ua);
  const result = parser.getResult();
  const normalized = `${result.browser.name || 'unknown'} ${result.browser.major || ''} ${result.os.name || 'unknown'} ${result.os.version ? result.os.version.split('.')[0] : ''}`.trim();
  return crypto.createHmac('sha256', IP_SALT).update(normalized || 'unknown').digest('hex');
}
server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});

// server.js
module.exports = {
  validateMessage,
  validateUsername,
  validateCode,
  isValidBase32,
  isValidBase64,
  hashPassword,
  validatePassword,
  logStats,
  restrictRate,
  restrictClientSize,
  restrictIpRate,
  restrictIpDaily,
  incrementFailure,
  broadcast,
  broadcastRandomCodes,
  hashIp,
  hashUa,
};
