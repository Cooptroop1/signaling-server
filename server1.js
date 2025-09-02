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
const shared = {
  rooms,
  dailyUsers,
  dailyConnections,
  LOG_FILE,
  AUDIT_FILE_BASE,
  FEATURES_FILE,
  STATS_FILE,
  UPDATE_INTERVAL,
  randomCodes,
  rateLimits,
  allTimeUsers,
  ipRateLimits,
  ipDailyLimits,
  ipFailureCounts,
  ipBans,
  revokedTokens,
  clientTokens,
  totpSecrets,
  processedMessageIds,
  clientSizeLimits,
  ADMIN_SECRET,
  ALLOWED_ORIGINS,
  JWT_SECRET,
  TURN_USERNAME,
  TURN_CREDENTIAL,
  IP_SALT,
  features,
  aggregatedStats,
  saveFeatures,
  saveAggregatedStats,
  isValidBase32,
  isValidBase64,
  validateMessage,
  hashIp,
  hashUa,
  broadcast,
  broadcastRandomCodes,
  generateLogsCSV,
  generateStatsCSV,
  computeAggregate,
  updateLogFile,
  rotateAuditLog,
  logStats,
  validateCode,
  validateUsername,
  incrementFailure,
  restrictIpDaily,
  restrictIpRate,
  restrictClientSize,
  restrictRate,
  wss,
  dbPool
};

module.exports.shared = shared;
if (fs.existsSync(shared.LOG_FILE)) {
  const logContent = fs.readFileSync(shared.LOG_FILE, 'utf8');
  const lines = logContent.split('\n');
  lines.forEach(line => {
    const match = line.match(/Client: (\w+)/);
    if (match) shared.allTimeUsers.add(match[1]);
  });
  console.log(`Loaded ${shared.allTimeUsers.size} all-time unique users from log.`);
}
setInterval(() => {
  shared.randomCodes.forEach(code => {
    if (!shared.rooms.has(code) || shared.rooms.get(code).clients.size === 0) {
      shared.randomCodes.delete(code);
    }
  });
  shared.broadcastRandomCodes();
  console.log('Auto-cleaned random codes.');
}, 3600000);
const pingInterval = setInterval(() => {
  shared.wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 50000);
setInterval(() => {
  const now = Date.now();
  shared.revokedTokens.forEach((expiry, token) => {
    if (expiry < now) {
      shared.revokedTokens.delete(token);
    }
  });
  shared.processedMessageIds.forEach((messageSet, code) => {
    const now = Date.now();
    messageSet.forEach((timestamp, nonce) => {
      if (now - timestamp > 300000) {
        messageSet.delete(nonce);
      }
    });
    if (messageSet.size === 0) {
      shared.processedMessageIds.delete(code);
    }
  });
  console.log(`Cleaned up expired revoked tokens and message IDs. Tokens: ${shared.revokedTokens.size}, Messages: ${shared.processedMessageIds.size}`);
}, 600000);
const { connectionHandler } = require('./server2');
wss.on('connection', connectionHandler);
server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
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
function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return Array.from(crypto.randomBytes(16)).map(b => chars[b % chars.length]).join('').match(/.{1,4}/g).join('-');
}
