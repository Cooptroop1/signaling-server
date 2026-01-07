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
const redis = require('redis');
const winston = require('winston');
// Hash password
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}
// Validate password
async function validatePassword(input, hash) {
  return bcrypt.compare(input, hash);
}
// Main logger for general operations
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ filename: path.join(__dirname, 'combined.log') }),
    new winston.transports.File({ filename: path.join(__dirname, 'error.log'), level: 'error' })
  ]
});
// User stats logger (appends to user_counts.log without rotation)
const userLogger = winston.createLogger({
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({ filename: path.join(__dirname, 'user_counts.log') })
  ]
});
// Audit logger without rotation
const auditLogger = winston.createLogger({
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, 'audit.log')
    })
  ]
});
const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // For Render Postgres
});
// Test DB connection on startup
dbPool.connect(async (err) => {
  if (err) {
    logger.error('DB connection error: %s %s', err.message, err.stack);
  } else {
    logger.info('Connected to DB successfully');
    await loadFeatures();
    await loadAggregatedStats();
  }
});
// Clean up old offline messages (TTL: 24 hours)
setInterval(async () => {
  try {
    await dbPool.query('DELETE FROM offline_messages WHERE created_at < NOW() - INTERVAL \'24 hours\'');
    logger.info('Cleaned up expired offline messages');
  } catch (err) {
    logger.error('Error cleaning up offline messages: %s %s', err.message, err.stack);
  }
}, 24 * 60 * 60 * 1000); // Run daily
// Added: Redis setup
const redisClient = redis.createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379' // Use env var from Render
});
redisClient.on('error', err => logger.error('Redis Client Error %o', err));
const pubClient = redisClient;
const subClient = redisClient.duplicate();
const subscribed = new Set(); // Track subscribed rooms
// Added: Redis message handler for pub/sub
const messageHandler = async (msg, channel) => {
  const code = channel.slice(5); // 'room:' prefix
  const room = rooms.get(code);
  if (!room) {
    logger.warn(`No room found for channel ${channel}`);
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(msg);
  } catch (err) {
    logger.error('Invalid pub/sub message: %o', err);
    return;
  }
  if (parsed.type === 'relay') {
    const { clientMessage, senderId } = parsed;
    room.clients.forEach((client, clientId) => {
      if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(clientMessage);
      }
    });
    logger.info(`Relayed via pub/sub ${parsed.messageType} from ${senderId} in code ${code} to ${room.clients.size - 1} clients`);
  } else if (parsed.type === 'unicast') {
    const { clientMessage, targetId, senderId } = parsed;
    room.clients.forEach((client, clientId) => {
      if (clientId === targetId && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(clientMessage);
        logger.info(`Relayed unicast ${JSON.parse(clientMessage).type} from ${senderId} to ${clientId} in ${code}`);
      }
    });
  } else if (parsed.type === 'broadcast') {
    const broadcastMsg = JSON.parse(parsed.clientMessage);
    room.clients.forEach(client => {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(JSON.stringify(broadcastMsg));
      }
    });
  } else if (parsed.type === 'kick' || parsed.type === 'ban') {
    const { targetId } = parsed;
    if (room.clients.has(targetId)) {
      const client = room.clients.get(targetId);
      client.ws.send(JSON.stringify({ type: parsed.type, message: `You have been ${parsed.type}ed from the room.` }));
      client.ws.close();
      // Close handler will handle removal and broadcast
    }
  }
};
// Connect to Redis asynchronously
(async () => {
  await redisClient.connect();
  await subClient.connect();
  logger.info('Connected to Redis');
  // Added: Load initial randomCodes from Redis
  const randomCodesFromRedis = await redisClient.sMembers('randomCodes');
  randomCodesFromRedis.forEach(code => randomCodes.add(code));
  logger.info(`Loaded ${randomCodes.size} random codes from Redis`);
  // New: Subscribe to global features channel
  await subClient.subscribe('global:features', (msg) => {
    try {
      features = JSON.parse(msg);
      logger.info('Received global features update via Redis: %o', features);
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'features-update', ...features }));
          if (!features.enableService && !client.isAdmin) {
            client.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
            client.close();
          }
        }
      });
    } catch (err) {
      logger.error('Invalid global features message: %o', err);
    }
  });
  logger.info('Subscribed to global:features channel');
})();
const CERT_KEY_PATH = 'path/to/your/private-key.pem';
const CERT_PATH = 'path/to/your/fullchain.pem';
let server;
if (process.env.NODE_ENV === 'production' || !fs.existsSync(CERT_KEY_PATH) || !fs.existsSync(CERT_PATH)) {
  server = http.createServer();
  logger.info('Using HTTP server (production or missing certificates)');
} else {
  server = https.createServer({
    key: fs.readFileSync(CERT_KEY_PATH),
    cert: fs.readFileSync(CERT_PATH)
  });
  logger.info('Using HTTPS server for local development');
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
        "connect-src 'self' wss://signaling-server-zc6m.onrender.com wss://signaling-server.onrender.com wss://signaling-server-1.onrender.com https://api.x.ai/v1/chat/completions https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; " + // Updated with all servers
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
const clientSizeLimits = new Map();
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  throw new Error('ADMIN_SECRET environment variable is not set. Please configure it for security.');
}
const ALLOWED_ORIGINS = ['https://anonomoose.com', 'https://www.anonomoose.com', 'http://localhost:3000', 'https://signaling-server-zc6m.onrender.com'];
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  logger.info('Generated new JWT secret (in-memory).');
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
  enableVoice: false,
  enableVoiceCalls: false,
  enableAudioToggle: false,
  enableGrokBot: false,
  enableP2P: true,
  enableRelay: true
};
let aggregatedStats = { daily: {} };
async function loadFeatures() {
  try {
    const res = await dbPool.query('SELECT * FROM features LIMIT 1');
    if (res.rows.length > 0) {
      features = res.rows[0];
      features.enableService = features.enableservice !== undefined ? features.enableservice : features.enableService;
      features.enableImages = features.enableimages !== undefined ? features.enableimages : features.enableImages;
      features.enableVoice = features.enablevoice !== undefined ? features.enablevoice : features.enableVoice;
      features.enableVoiceCalls = features.enablevoicecalls !== undefined ? features.enablevoicecalls : features.enableVoiceCalls;
      features.enableAudioToggle = features.enableaudiotoggle !== undefined ? features.enableaudiotoggle : features.enableAudioToggle;
      features.enableGrokBot = features.enablegrokbot !== undefined ? features.enablegrokbot : features.enableGrokBot;
      features.enableP2P = features.enablep2p !== undefined ? features.enablep2p : features.enableP2P;
      features.enableRelay = features.enablerelay !== undefined ? features.enablerelay : features.enableRelay;
    } else {
      await dbPool.query(
        'INSERT INTO features ("enableService", "enableImages", "enableVoice", "enableVoiceCalls", "enableAudioToggle", "enableGrokBot", "enableP2P", "enableRelay") VALUES (true, true, true, true, true, true, true, true)'
      );
      features = {
        enableService: true,
        enableImages: true,
        enableVoice: true,
        enableVoiceCalls: true,
        enableAudioToggle: true,
        enableGrokBot: true,
        enableP2P: true,
        enableRelay: true
      };
    }
    logger.info('Loaded features from DB: %o', features);
    // New: Publish initial features to Redis for sync
    pubClient.publish('global:features', JSON.stringify(features));
  } catch (err) {
    logger.error('Error loading features from DB: %s %s', err.message, err.stack);
  }
}
async function saveFeatures() {
  try {
    await dbPool.query(
      'UPDATE features SET "enableService"=$1, "enableImages"=$2, "enableVoice"=$3, "enableVoiceCalls"=$4, "enableAudioToggle"=$5, "enableGrokBot"=$6, "enableP2P"=$7, "enableRelay"=$8',
      [
        features.enableService,
        features.enableImages,
        features.enableVoice,
        features.enableVoiceCalls,
        features.enableAudioToggle,
        features.enableGrokBot,
        features.enableP2P,
        features.enableRelay
      ]
    );
    logger.info('Saved features to DB');
  } catch (err) {
    logger.error('Error saving features to DB: %s %s', err.message, err.stack);
  }
}
async function loadAggregatedStats() {
  try {
    const res = await dbPool.query('SELECT data FROM aggregated_stats LIMIT 1');
    if (res.rows.length > 0) {
      aggregatedStats = res.rows[0].data;
    } else {
      await dbPool.query('INSERT INTO aggregated_stats (data) VALUES ($1)', [JSON.stringify({ daily: {} })]);
      aggregatedStats = { daily: {} };
    }
    logger.info('Loaded aggregatedStats from DB');
  } catch (err) {
    logger.error('Error loading aggregatedStats from DB: %s %s', err.message, err.stack);
  }
}
async function saveAggregatedStats() {
  try {
    await dbPool.query('UPDATE aggregated_stats SET data = $1', [JSON.stringify(aggregatedStats)]);
    logger.info('Saved aggregatedStats to DB');
  } catch (err) {
    logger.error('Error saving aggregatedStats to DB: %s %s', err.message, err.stack);
  }
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
  if (!isValid) logger.warn('Invalid base64 detected: %s', str);
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
      if (data.mime && typeof data.mime !== 'string') {
        return { valid: false, error: data.type + ': mime must be string if provided' };
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
    case 'clear-random-codes':
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
      // Updated: Allow public_key in login for key update
      if (data.public_key && !isValidBase64(data.public_key)) {
        return { valid: false, error: 'login-username: invalid public_key (base64)' };
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
  logger.info(`Loaded ${allTimeUsers.size} all-time unique users from log.`);
}
setInterval(async () => {
  for (const code of [...randomCodes]) {
    const clientsKey = `room:${code}:clients`;
    const size = await redisClient.sCard(clientsKey);
    if (size === 0) {
      randomCodes.delete(code);
      await redisClient.sRem('randomCodes', code);
    }
  }
  broadcastRandomCodes();
  logger.info('Auto-cleaned random codes.');
}, 3600000);
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 50000);
setInterval(async () => {
  const now = Date.now();
  revokedTokens.forEach((expiry, token) => {
    if (expiry < now) {
      revokedTokens.delete(token);
    }
  });
  // Clean old nonces
  const nonceKeys = await redisClient.keys('room:*:nonces');
  for (const key of nonceKeys) {
    const nonces = await redisClient.hGetAll(key);
    for (const [nonce, ts] of Object.entries(nonces)) {
      if (now - parseInt(ts) > 300000) {
        await redisClient.hDel(key, nonce);
      }
    }
  }
  logger.info(`Cleaned up expired revoked tokens and message nonces. Tokens: ${revokedTokens.size}`);
}, 600000);
function checkAdminSecret(data, ws) {
  if (data.secret === ADMIN_SECRET) {
    return true;
  } else {
    ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
    return false;
  }
}
function revokeTokens(clientId) {
  const tokens = clientTokens.get(clientId);
  if (tokens) {
    try {
      const decoded = jwt.verify(tokens.accessToken, JWT_SECRET, { ignoreExpiration: true });
      revokedTokens.set(tokens.accessToken, decoded.exp * 1000);
      if (tokens.refreshToken) {
        const decodedRefresh = jwt.verify(tokens.refreshToken, JWT_SECRET, { ignoreExpiration: true });
        revokedTokens.set(tokens.refreshToken, decodedRefresh.exp * 1000);
      }
      clientTokens.delete(clientId);
      logger.info(`Revoked tokens for client ${clientId}`);
    } catch (err) {
      logger.warn(`Failed to revoke tokens for client ${clientId}: ${err.message}`);
    }
  }
}
async function safeQuery(query, params, ws, errorMsg) {
  try {
    return await dbPool.query(query, params);
  } catch (err) {
    logger.error('DB error: %s %s', err.message, err.stack);
    if (ws) ws.send(JSON.stringify({ type: 'error', message: errorMsg || 'Database error occurred.' }));
    throw err;
  }
}
async function forwardUnicast(code, targetId, message, fromId) {
  const clientMessage = JSON.stringify(message);
  pubClient.publish(`room:${code}`, JSON.stringify({
    type: 'unicast',
    clientMessage,
    targetId,
    senderId: fromId
  }));
  logger.info(`Published unicast ${message.type} from ${fromId} to ${targetId} for code: ${code}`);
}
function restrictLimit(map, key, increment, threshold, windowMs = 60000, logMsgPrefix) {
  const now = Date.now();
  const limit = map.get(key) || { value: 0, startTime: now };
  if (now - limit.startTime >= windowMs) {
    limit.value = 0;
    limit.startTime = now;
  }
  limit.value += increment;
  map.set(key, limit);
  if (limit.value > threshold) {
    logger.warn(`${logMsgPrefix} exceeded for ${key}: ${limit.value} in ${windowMs / 1000}s`);
    userLogger.info(`${new Date().toISOString()} - ${logMsgPrefix} exceeded for ${key}: ${limit.value}`);
    return false;
  }
  return true;
}
wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    logger.warn(`Rejected connection from invalid origin: ${origin}`);
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
  ws.on('message', async (message) => {
    if (!restrictLimit(rateLimits, ws.clientId, 1, 50, 60000, 'Rate limit')) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }
    try {
      const data = JSON.parse(message);
      const loggedData = { ...data };
      if (loggedData.secret) {
        loggedData.secret = '[REDACTED]';
      }
      logger.info('Received: %o', loggedData);
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
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') && 'mime',
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
      if (!features.enableService && data.type !== 'connect') {
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
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
          return;
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
        dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [clientId]).catch(err => {
          logger.error('DB error on connect: %s %s', err.message, err.stack);
        });
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
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
          return;
        }
        return;
      }
      if (data.type === 'public-key') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const targetId = rooms.get(data.code).initiator;
        const fwdMsg = { type: 'public-key', publicKey: data.publicKey, clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'encrypted-room-key') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, publicKey: data.publicKey, clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'new-room-key') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: 'new-room-key', encrypted: data.encrypted, iv: data.iv, targetId: data.targetId, clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'join') {
        if (!features.enableService) {
          ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.', code: data.code }));
          return;
        }
        if (!restrictLimit(ipRateLimits, `${hashedIp}:join`, 1, 5, 60000, 'IP rate limit')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!restrictLimit(ipDailyLimits, `${hashedIp}:join:${new Date().toISOString().slice(0, 10)}`, 1, 100, 86400000, 'Daily IP limit')) {
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
        const roomKey = `room:${code}`;
        const exists = await redisClient.exists(roomKey);
        let roomState;
        if (!exists) {
          roomState = { initiator: clientId, maxClients: 2 };
          await redisClient.set(roomKey, JSON.stringify(roomState), { EX: 86400 });
        } else {
          roomState = JSON.parse(await redisClient.get(roomKey));
        }
        const totpKey = `room:${code}:totp`;
        const roomTotpSecret = await redisClient.get(totpKey);
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
        // Check username unique globally
        let isReconnect = false;
        const clientKey = `room:${code}:client:${clientId}`;
        const existingUsername = await redisClient.get(clientKey);
        if (existingUsername) {
          if (existingUsername === username) {
            isReconnect = true;
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId.', code: data.code }));
            incrementFailure(clientIp, ws.userAgent);
            return;
          }
        } else {
          const allClientKeys = await redisClient.keys(`room:${code}:client:*`);
          if (allClientKeys.length > 0) {
            const allUsernamesMap = await redisClient.mGet(allClientKeys);
            const usernames = Object.values(allUsernamesMap);
            if (usernames.includes(username)) {
              ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
              incrementFailure(clientIp, ws.userAgent);
              return;
            }
          }
        }
        // Check if room full
        const clientsKey = `room:${code}:clients`;
        const multi = redisClient.multi();
        multi.sAdd(clientsKey, clientId);
        multi.sCard(clientsKey);
        const [added, currentSize] = await multi.exec();
        await redisClient.expire(clientsKey, 86400);
        if (currentSize > roomState.maxClients) {
          await redisClient.sRem(clientsKey, clientId);
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room is full.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        // Set username
        await redisClient.set(clientKey, username, { EX: 86400 });
        // Subscribe if not subscribed
        if (!subscribed.has(code)) {
          await subClient.subscribe(`room:${code}`, messageHandler);
          subscribed.add(code);
          logger.info(`Subscribed to Redis channel room:${code}`);
        }
        // Create or get local room
        if (!rooms.has(code)) {
          rooms.set(code, { initiator: roomState.initiator, clients: new Map(), maxClients: roomState.maxClients });
        }
        const room = rooms.get(code);
        room.clients.set(clientId, { ws, username });
        ws.code = code;
        ws.username = username;
        // Check if initiator online
        const isInitiatorLocal = clientId === roomState.initiator;
        const initiatorOnline = await redisClient.sIsMember(clientsKey, roomState.initiator);
        if (!initiatorOnline && !isInitiatorLocal) {
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          // Cleanup
          room.clients.delete(clientId);
          await redisClient.sRem(clientsKey, clientId);
          await redisClient.del(clientKey);
          return;
        }
        ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: isInitiatorLocal, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
        logStats({ clientId, username, code, event: 'join', totalClients: currentSize });
        if (room.clients.size > 0) {
          room.clients.forEach((_, existingClientId) => {
            if (existingClientId !== clientId) {
              logStats({
                clientId,
                targetId: existingClientId,
                code,
                event: 'webrtc-connection',
                totalClients: currentSize
              });
            }
          });
        }
        // Broadcast join-notify
        const totalClients = currentSize;
        const notifyMsg = { type: 'join-notify', clientId, username, code, totalClients };
        pubClient.publish(`room:${code}`, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(notifyMsg) }));
        // New: Remove from randomCodes if this is a non-initiator joining a random code (one-time use)
        if (randomCodes.has(code) && clientId !== roomState.initiator) {
          randomCodes.delete(code);
          await redisClient.sRem('randomCodes', code);
          broadcastRandomCodes();
          logger.info(`Removed one-time random code ${code} after join by ${clientId}`);
        }
        return;
      }
      if (data.type === 'check-totp') {
        const totpSecret = await redisClient.get(`room:${data.code}:totp`);
        if (totpSecret) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
        } else {
          ws.send(JSON.stringify({ type: 'totp-not-required', code: data.code }));
        }
        return;
      }
      if (data.type === 'set-max-clients') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        if (data.clientId === rooms.get(data.code).initiator) {
          const room = rooms.get(data.code);
          room.maxClients = Math.min(data.maxClients, 10);
          await redisClient.set(`room:${data.code}`, JSON.stringify({ initiator: room.initiator, maxClients: room.maxClients }), { EX: 86400 });
          const totalClients = await redisClient.sCard(`room:${data.code}:clients`);
          const msg = { type: 'max-clients', maxClients: room.maxClients, totalClients };
          pubClient.publish(`room:${data.code}`, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(msg) }));
          logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set max clients.', code: data.code }));
        }
        return;
      }
      if (data.type === 'set-totp') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        if (data.clientId === rooms.get(data.code).initiator) {
          await redisClient.set(`room:${data.code}:totp`, data.secret, { EX: 86400 });
          const msg = { type: 'totp-enabled', code: data.code };
          pubClient.publish(`room:${data.code}`, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(msg) }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
        }
        return;
      }
      if (data.type === 'offer' || data.type === 'answer') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: data.type, ...(data.offer ? { offer: data.offer } : { answer: data.answer }), clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'candidate') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: 'candidate', candidate: data.candidate, clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'kick' || data.type === 'ban') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        if (data.clientId === rooms.get(data.code).initiator) {
          pubClient.publish(`room:${data.code}`, JSON.stringify({ type: data.type, targetId: data.targetId, senderId: data.clientId }));
          logStats({ clientId: data.targetId, code: data.code, event: data.type });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can kick/ban.', code: data.code }));
        }
        return;
      }
      if (data.type === 'submit-random') {
        if (!restrictLimit(ipRateLimits, `${hashedIp}:submit-random`, 1, 5, 60000, 'Submit rate limit')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const size = await redisClient.sCard(`room:${data.code}:clients`);
        if (size === 0) {
          ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (rooms.get(data.code)?.initiator === data.clientId) {
          const added = await redisClient.sAdd('randomCodes', data.code);
          if (added) {
            randomCodes.add(data.code);
            broadcastRandomCodes();
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
        }
        return;
      }
      if (data.type === 'get-random-codes') {
        // Updated: Fetch from Redis for global sync
        const codes = await redisClient.sMembers('randomCodes');
        ws.send(JSON.stringify({ type: 'random-codes', codes }));
        return;
      }
      if (data.type === 'remove-random-code') {
        if (randomCodes.has(data.code)) {
          // Added: Remove from Redis and local Set
          await redisClient.sRem('randomCodes', data.code);
          randomCodes.delete(data.code);
          broadcastRandomCodes();
          logger.info(`Removed code ${data.code} from randomCodes`);
        }
        return;
      }
      // New: Handle clear-random-codes (admin only)
      if (data.type === 'clear-random-codes') {
        if (!checkAdminSecret(data, ws)) return;
        await redisClient.del('randomCodes');
        randomCodes.clear();
        broadcastRandomCodes();
        logger.info('Random codes cleared by admin');
        const timestamp = new Date().toISOString();
        userLogger.info(`${timestamp} - Admin cleared random codes`);
        ws.send(JSON.stringify({ type: 'random-codes-cleared' }));
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
        if (!restrictLimit(clientSizeLimits, data.clientId, payloadSize, 1048576, 60000, 'Size limit')) {
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
        // Check duplicate nonce globally
        const noncesKey = `room:${data.code}:nonces`;
        const existingTs = await redisClient.hGet(noncesKey, data.nonce);
        if (existingTs) {
          logger.warn(`Duplicate nonce ${data.nonce} in room ${data.code}, ignoring`);
          return;
        }
        const now = Date.now();
        if (Math.abs(now - data.timestamp) > 300000) {
          logger.warn(`Invalid timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp} (now: ${now})`);
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid message timestamp.', code: data.code }));
          return;
        }
        // Updated: Allow small future tolerance to handle clock skew (e.g., 30 seconds)
        if (data.timestamp > now + 30000) {
          logger.warn(`Future timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp} (now: ${now})`);
          ws.send(JSON.stringify({ type: 'error', message: 'Message timestamp in future.', code: data.code }));
          return;
        }
        await redisClient.hSet(noncesKey, data.nonce, data.timestamp);
        await redisClient.expire(noncesKey, 86400);
        const mime = data.mime ? validator.escape(validator.trim(data.mime)) : undefined;
        // Prepare client message object
        const clientMessageObj = {
          type: data.type.replace('relay-', ''),
          messageId: data.messageId,
          username: room.clients.get(senderId).username,
          content: data.content,
          encryptedContent: data.encryptedContent,
          data: data.data,
          encryptedData: data.encryptedData,
          filename: data.filename,
          timestamp: data.timestamp,
          iv: data.iv,
          signature: data.signature,
          nonce: data.nonce,
          mime: mime
        };
        const clientJson = JSON.stringify(clientMessageObj);
        // Publish to Redis
        const pubObj = {
          type: 'relay',
          messageType: data.type, // For logging
          clientMessage: clientJson,
          senderId: senderId
        };
        const pubJson = JSON.stringify(pubObj);
        pubClient.publish(`room:${data.code}`, pubJson).then(() => {
          logger.info(`Published ${data.type} from ${senderId} to Redis channel room:${data.code}`);
        }).catch(err => {
          logger.error('Redis publish error: %o', err);
        });
        return;
      }
      if (data.type === 'get-stats') {
        if (!checkAdminSecret(data, ws)) return;
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
        return;
      }
      if (data.type === 'get-features') {
        if (!checkAdminSecret(data, ws)) return;
        ws.send(JSON.stringify({ type: 'features', ...features }));
        return;
      }
      if (data.type === 'toggle-feature') {
        if (!checkAdminSecret(data, ws)) return;
        const featureKey = `enable${data.feature.charAt(0).toUpperCase() + data.feature.slice(1)}`;
        if (features.hasOwnProperty(featureKey)) {
          features[featureKey] = !features[featureKey];
          await saveFeatures();
          const timestamp = new Date().toISOString();
          userLogger.info(`${timestamp} - Admin toggled ${featureKey} to ${features[featureKey]} by client ${hashIp(clientIp)}`);
          ws.send(JSON.stringify({ type: 'feature-toggled', feature: data.feature, enabled: features[featureKey] }));
          // New: Publish updated features to Redis instead of local broadcast
          pubClient.publish('global:features', JSON.stringify(features));
          if (data.feature === 'service' && !features.enableService) {
            clientTokens.forEach((tokens, clientId) => {
              revokedTokens.set(tokens.accessToken, Date.now() + 1000);
              if (tokens.refreshToken) {
                revokedTokens.set(tokens.refreshToken, Date.now() + 1000);
              }
            });
            clientTokens.clear();
            logger.info('All tokens invalidated due to service disable');
            rooms.clear();
            randomCodes.clear();
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid feature' }));
        }
        return;
      }
      if (data.type === 'export-stats-csv') {
        if (!checkAdminSecret(data, ws)) return;
        const csv = generateStatsCSV();
        ws.send(JSON.stringify({ type: 'export-stats-csv', csv }));
        return;
      }
      if (data.type === 'export-logs-csv') {
        if (!checkAdminSecret(data, ws)) return;
        const csv = generateLogsCSV();
        ws.send(JSON.stringify({ type: 'export-logs-csv', csv }));
        return;
      }
      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      if (data.type === 'pong') {
        logger.info('Received pong from client');
        return;
      }
      if (data.type === 'register-username') {
        const { username, password, public_key } = data;
        if (validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          const checkRes = await safeQuery('SELECT * FROM users WHERE username = $1', [username], ws, 'Failed to register username.');
          if (checkRes.rows.length > 0) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username taken.' }));
            return;
          }
          const passwordHash = await hashPassword(password);
          await safeQuery(
            'INSERT INTO users (username, password_hash, client_id, public_key) VALUES ($1, $2, $3, $4)',
            [username, passwordHash, data.clientId, public_key || null],
            ws,
            'Failed to register username.'
          );
          ws.send(JSON.stringify({ type: 'username-registered', username }));
          logger.info(`Registered username ${username} for clientId ${data.clientId}`);
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'login-username') {
        const { username, password, public_key } = data; // Updated: Allow public_key
        if (validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          const res = await safeQuery('SELECT * FROM users WHERE username = $1', [username], ws, 'Failed to login.');
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
          // Updated: Update public_key if provided
          const updateParams = [data.clientId, new Date(), user.id];
          let updateQuery = 'UPDATE users SET client_id = $1, last_active = $2 WHERE id = $3';
          if (public_key && isValidBase64(public_key)) {
            updateQuery = 'UPDATE users SET client_id = $1, last_active = $2, public_key = $4 WHERE id = $5';
            updateParams.push(public_key, user.id);
          } else {
            updateParams.push(user.id);
          }
          await safeQuery(updateQuery, updateParams, ws, 'Failed to update user on login.');
          const msgRes = await safeQuery(`
            SELECT om.id, om.message, u.username AS from_username
            FROM offline_messages om
            JOIN users u ON om.from_user_id = u.id
            WHERE om.to_user_id = $1
          `, [user.id], ws, 'Failed to fetch offline messages.');
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
              logger.error(`Failed to parse offline message for user ${user.id}: %s`, err.message);
              return null;
            }
          }).filter(msg => msg !== null);
          logger.info(`Fetched ${offlineMessages.length} offline messages for user ${username} (id: ${user.id})`);
          ws.send(JSON.stringify({ type: 'login-success', username, offlineMessages }));
          logger.info(`User ${username} logged in with clientId ${data.clientId}`);
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'find-user') {
        const { username } = data;
        const from_res = await safeQuery('SELECT id, username FROM users WHERE client_id = $1', [data.clientId], ws, 'Must be logged in to search users.');
        if (from_res.rows.length === 0) {
          logger.warn(`Find-user failed: No user found for clientId ${data.clientId}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Must be logged in to search users.' }));
          return;
        }
        const from_user_id = from_res.rows[0].id;
        const from_username_actual = from_res.rows[0].username;
        const res = await safeQuery('SELECT * FROM users WHERE username = $1', [username], ws, 'Failed to find user.');
        if (res.rows.length === 0) {
          ws.send(JSON.stringify({ type: 'user-not-found' }));
          return;
        }
        const user = res.rows[0];
        const dynamicCode = uuidv4().replace(/-/g, '').substring(0, 16).match(/.{1,4}/g).join('-');
        const ownerWs = [...wss.clients].find(client => client.clientId === user.client_id);
        if (ownerWs) {
          ownerWs.send(JSON.stringify({ type: 'incoming-connection', from: from_username_actual, code: dynamicCode }));
        } else {
          await safeQuery(
            'INSERT INTO offline_messages (from_user_id, to_user_id, message) VALUES ($1, $2, $3)',
            [from_user_id, user.id, JSON.stringify({ type: 'connection-request', code: dynamicCode })],
            ws,
            'Failed to send offline message.'
          );
        }
        const lastActive = user.last_active ? new Date(user.last_active).getTime() : 0;
        const isOnline = ownerWs || (Date.now() - lastActive < 5 * 60 * 1000);
        ws.send(JSON.stringify({ type: 'user-found', status: isOnline ? 'online' : 'offline', code: dynamicCode, public_key: user.public_key }));
        logger.info(`User ${username} found for clientId ${data.clientId}, status: ${isOnline ? 'online' : 'offline'}, code: ${dynamicCode}`);
        return;
      }
      if (data.type === 'send-offline-message') {
        const { to_username, encrypted, iv, ephemeral_public, messageId } = data;
        const res = await safeQuery('SELECT id FROM users WHERE username = $1', [to_username], ws, 'Recipient not found.');
        if (res.rows.length === 0) {
          ws.send(JSON.stringify({ type: 'error', message: 'Recipient not found.' }));
          return;
        }
        const to_user_id = res.rows[0].id;
        const from_res = await safeQuery('SELECT id FROM users WHERE client_id = $1', [data.clientId], ws, 'Sender not logged in with a username.');
        if (from_res.rows.length === 0) {
          logger.warn(`Send-offline-message failed: No user found for clientId ${data.clientId}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Sender not logged in with a username.' }));
          return;
        }
        const from_user_id = from_res.rows[0].id;
        await safeQuery(
          'INSERT INTO offline_messages (from_user_id, to_user_id, message) VALUES ($1, $2, $3)',
          [from_user_id, to_user_id, JSON.stringify({ type: 'message', encrypted, iv, ephemeral_public, messageId })],
          ws,
          'Failed to send offline message.'
        );
        ws.send(JSON.stringify({ type: 'offline-message-sent', messageId }));
        logger.info(`Offline message ${messageId} sent from clientId ${data.clientId} (user_id: ${from_user_id}) to ${to_username} (user_id: ${to_user_id})`);
        return;
      }
      if (data.type === 'confirm-offline-message') {
        await safeQuery('DELETE FROM offline_messages WHERE id = $1', [data.messageId], ws, 'Failed to confirm offline message.');
        logger.info(`Confirmed and deleted offline message ${data.messageId} for clientId ${data.clientId}`);
        ws.send(JSON.stringify({ type: 'confirm-offline-message-ack', messageId: data.messageId }));
        return;
      }
      if (data.type === 'logout') {
        revokeTokens(data.clientId);
        if (ws.code && rooms.has(ws.code)) {
          // Logout triggers close handler
          ws.close();
        }
        ws.send(JSON.stringify({ type: 'logout-success' }));
        return;
      }
    } catch (error) {
      logger.error('Error processing message: %s %s', error.message, error.stack);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again. Check server logs.' }));
      incrementFailure(clientIp, ws.userAgent);
    }
  });
  ws.on('close', async () => {
    revokeTokens(ws.clientId);
    if (ws.code && rooms.has(ws.code)) {
      const code = ws.code;
      const roomKey = `room:${code}`;
      const clientsKey = `${roomKey}:clients`;
      await redisClient.sRem(clientsKey, ws.clientId);
      const clientKey = `${roomKey}:client:${ws.clientId}`;
      await redisClient.del(clientKey);
      rooms.get(code).clients.delete(ws.clientId);
      rateLimits.delete(ws.clientId);
      const isInitiator = ws.clientId === rooms.get(code).initiator;
      const totalClients = await redisClient.sCard(clientsKey);
      logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients, isInitiator });
      const disconnectedMsg = {
        type: 'client-disconnected',
        clientId: ws.clientId,
        totalClients,
        isInitiator
      };
      pubClient.publish(roomKey, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(disconnectedMsg) }));
      if (totalClients === 0) {
        rooms.delete(code);
        await redisClient.del(roomKey);
        await redisClient.del(`${roomKey}:totp`);
        await redisClient.del(`${roomKey}:nonces`);
        if (subscribed.has(code)) {
          await subClient.unsubscribe(`room:${code}`);
          subscribed.delete(code);
          logger.info(`Unsubscribed from Redis channel room:${code}`);
        }
      } else if (isInitiator) {
        const newInitiator = await redisClient.sRandMember(clientsKey);
        if (newInitiator) {
          rooms.get(code).initiator = newInitiator;
          await redisClient.set(roomKey, JSON.stringify({ initiator: newInitiator, maxClients: rooms.get(code).maxClients }), { EX: 86400 });
          const initiatorChangedMsg = {
            type: 'initiator-changed',
            newInitiator,
            totalClients
          };
          pubClient.publish(roomKey, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(initiatorChangedMsg) }));
        }
      }
    }
    if (ws.clientId) {
      dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [ws.clientId]).catch(err => {
        logger.error('DB error on close: %s %s', err.message, err.stack);
      });
    }
  });
});
function incrementFailure(ip, ua) {
  const hashedIp = hashIp(ip);
  const hashedUa = hashUa(ua);
  const key = hashedIp + ':' + hashedUa;
  const failure = ipFailureCounts.get(key) || { count: 0, banLevel: 0 };
  failure.count += 1;
  ipFailureCounts.set(key, failure);
  if (failure.count % 5 === 0) {
    logger.warn(`High failure rate for key ${key}: ${failure.count} failures`);
    auditLogger.info(`${new Date().toISOString()} - High failure anomaly for key ${key}: ${failure.count} failures`);
  }
  if (failure.count >= 10) {
    const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];
    failure.banLevel = Math.min(failure.banLevel + 1, 2);
    const duration = banDurations[failure.banLevel];
    const expiry = Date.now() + duration;
    ipBans.set(key, { expiry, banLevel: failure.banLevel });
    const timestamp = new Date().toISOString();
    const banLogEntry = `${timestamp} - Key Banned: ${key}, Duration: ${duration / 60000} minutes, Ban Level: ${failure.banLevel}`;
    userLogger.info(banLogEntry);
    logger.warn(`Key ${key} banned until ${new Date(expiry).toISOString()} at ban level ${failure.banLevel} (${duration / 60000} minutes)`);
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
  const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}`;
  userLogger.info(logEntry);
}
function updateLogFile() {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  const userCount = dailyUsers.get(day)?.size || 0;
  const connectionCount = dailyConnections.get(day)?.size || 0;
  const allTimeUserCount = allTimeUsers.size;
  const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}, All-Time Unique Users: ${allTimeUserCount}`;
  userLogger.info(logEntry);
  logger.info(`Updated ${LOG_FILE} with ${userCount} unique users, ${connectionCount} WebRTC connections, and ${allTimeUserCount} all-time unique users for ${day}`);
  if (!aggregatedStats.daily) aggregatedStats.daily = {};
  aggregatedStats.daily[day] = { users: userCount, connections: connectionCount };
  saveAggregatedStats();
}
userLogger.info('');
updateLogFile();
setInterval(updateLogFile, UPDATE_INTERVAL);
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
async function broadcastRandomCodes() {
  const codes = await redisClient.sMembers('randomCodes');
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'random-codes', codes }));
    }
  });
  logger.info(`Broadcasted random codes to all clients: ${codes}`);
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
  logger.info(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
