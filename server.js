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
const Redis = require('ioredis');

// Global error handlers to prevent crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

// Check for certificate files for local HTTPS
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

// Add HTTP request handler to serve static files with nonce injection
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
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const FEATURES_FILE = path.join('/data', 'features.json');
const STATS_FILE = path.join('/data', 'stats.json');
const UPDATE_INTERVAL = 30000;
const rateLimits = new Map();
const allTimeUsers = new Set();
const ipRateLimits = new Map();
const ipDailyLimits = new Map();
const ipFailureCounts = new Map();
const ipBans = new Map();
const revokedTokens = new Map();
const clientTokens = new Map();
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
  enableGrokBot: true
};

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const redisOptions = {
  retryStrategy(times) {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  reconnectOnError(err) {
    const targetError = 'READONLY';
    if (err.message.includes(targetError)) {
      return true;
    }
  }
};
const redis = new Redis(REDIS_URL, redisOptions);
const pub = new Redis(REDIS_URL, redisOptions);
const sub = new Redis(REDIS_URL, redisOptions);
const instanceId = uuidv4();

[redis, pub, sub].forEach(client => {
  client.on('error', (err) => {
    console.error('Redis Client Error:', err);
  });
  client.on('reconnecting', () => {
    console.log('Redis client reconnecting...');
  });
  client.on('ready', () => {
    console.log('Redis client ready');
  });
});

sub.subscribe('signaling', `signal:${instanceId}`);

const localClients = new Map(); 
const localRooms = new Map(); 

(async () => {
  try {
    let featuresStr = await redis.get('features');
    if (featuresStr) {
      const parsed = JSON.parse(featuresStr);
      features = {
        enableService: parsed.enableService || true,
        enableImages: parsed.enableImages || true,
        enableVoice: parsed.enableVoice || true,
        enableVoiceCalls: parsed.enableVoiceCalls || true,
        enableAudioToggle: parsed.enableAudioToggle || true,
        enableGrokBot: parsed.enableGrokBot || true
      };
    } else {
      await redis.set('features', JSON.stringify(features));
    }
    console.log('Loaded features:', features);
  } catch (err) {
    console.error('Error loading features from Redis:', err);
  }
})();

function saveFeatures() {
  const cleanFeatures = {
    enableService: features.enableService,
    enableImages: features.enableImages,
    enableVoice: features.enableVoice,
    enableVoiceCalls: features.enableVoiceCalls,
    enableAudioToggle: features.enableAudioToggle,
    enableGrokBot: features.enableGrokBot
  };
  fs.writeFileSync(FEATURES_FILE, JSON.stringify(cleanFeatures));
  console.log('Saved features to disk:', cleanFeatures);
}

let aggregatedStats = fs.existsSync(STATS_FILE) ? JSON.parse(fs.readFileSync(STATS_FILE, 'utf8')) : { daily: {} };
function saveAggregatedStats() {
  fs.writeFileSync(STATS_FILE, JSON.stringify(aggregatedStats));
  console.log('Saved aggregated stats to disk');
}

function isValidBase32(str) {
  return /^[A-Z2-7]+=*$/i.test(str) && str.length >= 16;
}

function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(str) && str.length % 4 === 0;
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
      if (!data.publicKey || !isValidBase64(data.publicKey)) {
        return { valid: false, error: 'public-key: invalid publicKey format' };
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
      if (data.publicKey && !isValidBase64(data.publicKey)) {
        return { valid: false, error: 'join: invalid publicKey format' };
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
    case 'relay-image':
    case 'relay-voice':
    case 'relay-file':
      const payloadField = data.type === 'relay-message' ? 'encryptedContent' : 'encryptedData';
      if (!data[payloadField] || !isValidBase64(data[payloadField])) {
        return { valid: false, error: `${data.type}: invalid ${payloadField}` };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: `${data.type}: invalid iv` };
      }
      if (!data.salt || !isValidBase64(data.salt)) {
        return { valid: false, error: `${data.type}: invalid salt` };
      }
      if (!data.signature || !isValidBase64(data.signature)) {
        return { valid: false, error: `${data.type}: invalid signature` };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: `${data.type}: messageId required as string` };
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

setInterval(async () => {
  try {
    const codes = await redis.smembers('randomCodes');
    for (const code of codes) {
      if (!await redis.exists(`room:${code}`) || await redis.scard(`room_clients:${code}`) === 0) {
        await redis.srem('randomCodes', code);
      }
    }
    console.log('Auto-cleaned random codes.');
  } catch (err) {
    console.error('Error in random codes cleanup:', err);
  }
}, 3600000);

const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 50000);

setInterval(async () => {
  try {
    const now = Date.now();
    const revokedKeys = await redis.keys('revoked:*');
    for (const key of revokedKeys) {
      const expiry = await redis.get(key);
      if (expiry && parseInt(expiry) < now) {
        await redis.del(key);
      }
    }
    console.log(`Cleaned up expired revoked tokens. Remaining: ${revokedKeys.length}`);
  } catch (err) {
    console.error('Error cleaning revoked tokens:', err);
  }
}, 3600000);

sub.on('message', (channel, event) => {
  try {
    const data = JSON.parse(event);
    if (channel === 'signaling') {
      if (data.type === 'join') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).totalClients = data.totalClients;
          localBroadcast(data.code, { type: 'join-notify', clientId: data.clientId, username: data.username, code: data.code, totalClients: data.totalClients, publicKey: data.publicKey });
        }
      } else if (data.type === 'disconnect') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).totalClients = data.totalClients;
          localBroadcast(data.code, { type: 'client-disconnected', clientId: data.clientId, totalClients: data.totalClients, isInitiator: data.isInitiator });
          if (data.totalClients <= 1) {
            // Clients handle UI
          }
        }
      } else if (data.type === 'max-clients') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).maxClients = data.maxClients;
          localBroadcast(data.code, { type: 'max-clients', maxClients: data.maxClients, totalClients: data.totalClients });
        }
      } else if (data.type === 'totp-enabled') {
        if (localRooms.has(data.code)) {
          localBroadcast(data.code, { type: 'totp-enabled', code: data.code });
        }
      } else if (data.type === 'initiator-changed') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).initiator = data.newInitiator;
          localBroadcast(data.code, { type: 'initiator-changed', newInitiator: data.newInitiator, totalClients: data.totalClients });
        }
      } else if (data.type === 'features-update') {
        features = {
          enableService: data.enableService,
          enableImages: data.enableImages,
          enableVoice: data.enableVoice,
          enableVoiceCalls: data.enableVoiceCalls,
          enableAudioToggle: data.enableAudioToggle,
          enableGrokBot: data.enableGrokBot
        };
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'features-update', ...features }));
          }
        });
        if (!features.enableService) {
          localRooms.clear();
          localClients.clear();
          wss.clients.forEach(ws => ws.close());
        }
      } else if (data.type === 'relay-message' || data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') {
        if (localRooms.has(data.code)) {
          localBroadcast(data.code, { type: data.type.replace('relay-', ''), messageId: data.messageId, username: data.username, encryptedContent: data.encryptedContent, encryptedData: data.encryptedData, iv: data.iv, salt: data.salt, signature: data.signature }, data.clientId);
        }
      }
    } else if (channel === `signal:${instanceId}`) {
      const targetWs = localClients.get(data.targetId)?.ws;
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({ ...data, clientId: data.clientId }));
      }
    }
  } catch (error) {
    console.error('Error handling pub/sub event:', error);
  }
});

function localBroadcast(code, msg, excludeClientId = null) {
  const room = localRooms.get(code);
  if (room) {
    room.myClients.forEach(clientId => {
      if (clientId !== excludeClientId) {
        const ws = localClients.get(clientId)?.ws;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify(msg));
        }
      }
    });
  }
}

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
  (async () => {
    try {
      const banTime = await redis.get(`ban:${hashedIp}`);
      if (banTime && parseInt(banTime) > Date.now()) {
        ws.send(JSON.stringify({ type: 'error', message: 'IP temporarily banned due to excessive failures. Try again later.' }));
        ws.close();
        return;
      }
    } catch (err) {
      console.error('Error checking ban:', err);
    }
  })();
  let clientId, code, username;
  let isAdmin = false;
  ws.on('message', async (message) => {
    if (!restrictRate(ws)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }
    let data;
    try {
      data = JSON.parse(message);
    } catch (err) {
      console.error('Invalid JSON in message:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format.' }));
      await incrementFailure(clientIp);
      return;
    }
    try {
      const validation = validateMessage(data);
      if (!validation.valid) {
        ws.send(JSON.stringify({ type: 'error', message: validation.error }));
        await incrementFailure(clientIp);
        return;
      }
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string' && !(data.type === 'public-key' && key === 'publicKey')) {
          data[key] = validator.escape(validator.trim(data[key]));
        }
      });
      if (data.type === 'public-key' && data.publicKey) {
        if (!isValidBase64(data.publicKey)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format' }));
          await incrementFailure(clientIp);
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
        let decoded;
        try {
          decoded = jwt.verify(data.token, JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
            return;
          }
          const revoked = await redis.get(`revoked:${data.token}`);
          if (revoked) {
            ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
            return;
          }
        } catch (err) {
          if (fs.existsSync(previousSecretFile)) {
            const previousSecret = fs.readFileSync(previousSecretFile, 'utf8').trim();
            try {
              decoded = jwt.verify(data.token, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
                return;
              }
              const revoked = await redis.get(`revoked:${data.token}`);
              if (revoked) {
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
        localClients.set(clientId, { ws, username: '', code: '' });
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
        let decoded;
        try {
          decoded = jwt.verify(data.refreshToken, JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
            return;
          }
          const revoked = await redis.get(`revoked:${data.refreshToken}`);
          if (revoked) {
            ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
            return;
          }
          const oldRefreshExpiry = decoded.exp * 1000 - Date.now();
          await redis.set(`revoked:${data.refreshToken}`, 1, 'PX', oldRefreshExpiry);
          const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '10m' });
          const newRefreshToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '1h' });
          clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
          ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
        } catch (err) {
          if (fs.existsSync(previousSecretFile)) {
            const previousSecret = fs.readFileSync(previousSecretFile, 'utf8').trim();
            try {
              decoded = jwt.verify(data.refreshToken, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
                return;
              }
              const revoked = await redis.get(`revoked:${data.refreshToken}`);
              if (revoked) {
                ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
                return;
              }
              const oldRefreshExpiry = decoded.exp * 1000 - Date.now();
              await redis.set(`revoked:${data.refreshToken}`, 1, 'PX', oldRefreshExpiry);
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
        const targetInstance = await redis.hget(`client:${data.clientId}`, 'instance');
        if (targetInstance === instanceId) {
          // Forward local if needed
        } else {
          pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
        }
        return;
      }
      if (data.type === 'encrypted-room-key') {
        const targetInstance = await redis.hget(`client:${data.targetId}`, 'instance');
        if (targetInstance === instanceId) {
          const targetWs = localClients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, clientId: data.clientId, code: data.code }));
          }
        } else {
          pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
        }
        return;
      }
      if (data.type === 'new-room-key') {
        const targetInstance = await redis.hget(`client:${data.targetId}`, 'instance');
        if (targetInstance === instanceId) {
          const targetWs = localClients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'new-room-key', encrypted: data.encrypted, iv: data.iv, targetId: data.targetId, clientId: data.clientId, code: data.code }));
          }
        } else {
          pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
        }
        return;
      }
      if (data.type === 'join') {
        if (!features.enableService) {
          ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.', code: data.code }));
          return;
        }
        if (!await restrictIpRate(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.', code: data.code }));
          await incrementFailure(clientIp);
          return;
        }
        if (!await restrictIpDaily(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.', code: data.code }));
          await incrementFailure(clientIp);
          return;
        }
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        if (!validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters.', code: data.code }));
          await incrementFailure(clientIp);
          return;
        }
        if (!validateCode(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format: xxxx-xxxx-xxxx-xxxx.', code: data.code }));
          await incrementFailure(clientIp);
          return;
        }
        const totpKey = `totp:${code}`;
        const roomTotpSecret = await redis.get(totpKey);
        if (roomTotpSecret && !data.totpCode) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          return;
        }
        if (roomTotpSecret && data.totpCode) {
          const isValid = otplib.authenticator.check(data.totpCode, roomTotpSecret);
          if (!isValid) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid TOTP code.', code: data.code }));
            await incrementFailure(clientIp);
            return;
          }
        }
        const roomKey = `room:${code}`;
        let roomStr = await redis.get(roomKey);
        let isNewRoom = false;
        if (!roomStr) {
          isNewRoom = true;
          room = { initiator: clientId, maxClients: 2 };
          await redis.set(roomKey, JSON.stringify(room));
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
          logStats({ clientId, username, code, event: 'init', totalClients: 1 });
        } else {
          room = JSON.parse(roomStr);
          const clientsKey = `room_clients:${code}`;
          const currentCount = await redis.scard(clientsKey);
          if (currentCount >= room.maxClients) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room is full.', code: data.code }));
            await incrementFailure(clientIp);
            return;
          }
          const members = await redis.smembers(clientsKey);
          const clientData = await redis.hgetall(`client:${clientId}`);
          if (members.includes(clientId)) {
            if (clientData.username === username) {
              // Reconnect
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId.', code: data.code }));
              await incrementFailure(clientIp);
              return;
            }
          } else {
            let usernameTaken = false;
            for (const id of members) {
              const memberUsername = await redis.hget(`client:${id}`, 'username');
              if (memberUsername === username) {
                usernameTaken = true;
                break;
              }
            }
            if (usernameTaken) {
              ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
              await incrementFailure(clientIp);
              return;
            }
          }
          const initiatorInstance = await redis.hget(`client:${room.initiator}`, 'instance');
          if (!initiatorInstance && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
            await incrementFailure(clientIp);
            return;
          }
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
          logStats({ clientId, username, code, event: 'join', totalClients: currentCount + 1 });
          if (currentCount > 0) {
            for (const existing of members) {
              if (existing !== clientId) {
                logStats({
                  clientId,
                  targetId: existing,
                  code,
                  event: 'webrtc-connection',
                  totalClients: currentCount + 1
                });
              }
            }
          }
        }
        const clientsKey = `room_clients:${code}`;
        await redis.sadd(clientsKey, clientId);
        await redis.hset(`client:${clientId}`, 'instance', instanceId, 'username', username);
        localClients.get(clientId).username = username;
        localClients.get(clientId).code = code;
        if (!localRooms.has(code)) {
          localRooms.set(code, { totalClients: 0, maxClients: room.maxClients, myClients: new Set(), initiator: room.initiator });
        }
        localRooms.get(code).myClients.add(clientId);
        const total = await redis.scard(clientsKey);
        localRooms.get(code).totalClients = total;
        pub.publish('signaling', JSON.stringify({ type: 'join', code, clientId, username, totalClients: total, publicKey: data.publicKey }));
        if (total > 1 && await redis.sismember('randomCodes', code)) {
          await redis.srem('randomCodes', code);
        }
      }
      if (data.type === 'check-totp') {
        const totpKey = `totp:${data.code}`;
        try {
          if (await redis.exists(totpKey)) {
            ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          } else {
            ws.send(JSON.stringify({ type: 'totp-not-required', code: data.code }));
          }
        } catch (err) {
          console.error('Error in check-totp:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error in TOTP check.' }));
        }
        return;
      }
      if (data.type === 'set-max-clients') {
        const roomKey = `room:${data.code}`;
        try {
          const roomStr = await redis.get(roomKey);
          if (roomStr) {
            const room = JSON.parse(roomStr);
            if (data.clientId === room.initiator) {
              room.maxClients = Math.min(data.maxClients, 10);
              await redis.set(roomKey, JSON.stringify(room));
              const total = await redis.scard(`room_clients:${data.code}`);
              pub.publish('signaling', JSON.stringify({ type: 'max-clients', code: data.code, maxClients: room.maxClients, totalClients: total }));
              logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients: total });
            }
          }
        } catch (err) {
          console.error('Error in set-max-clients:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error setting max clients.' }));
        }
      }
      if (data.type === 'set-totp') {
        const roomKey = `room:${data.code}`;
        try {
          const roomStr = await redis.get(roomKey);
          if (roomStr) {
            const room = JSON.parse(roomStr);
            if (data.clientId === room.initiator) {
              await redis.set(`totp:${data.code}`, data.secret);
              pub.publish('signaling', JSON.stringify({ type: 'totp-enabled', code: data.code }));
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
            }
          }
        } catch (err) {
          console.error('Error in set-totp:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error setting TOTP.' }));
        }
      }
      if (data.type === 'offer' || data.type === 'answer' || data.type === 'candidate') {
        try {
          const targetInstance = await redis.hget(`client:${data.targetId}`, 'instance');
          if (targetInstance) {
            if (targetInstance === instanceId) {
              const target = localClients.get(data.targetId);
              if (target && target.ws.readyState === WebSocket.OPEN) {
                console.log(`Forwarding ${data.type} from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
                target.ws.send(JSON.stringify({ ...data, clientId: data.clientId }));
              } else {
                console.warn(`Target ${data.targetId} not found or not open in room ${data.code}`);
              }
            } else {
              pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
            }
          }
        } catch (err) {
          console.error(`Error forwarding ${data.type}:`, err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error in signaling.' }));
        }
      }
      if (data.type === 'submit-random') {
        if (!await restrictIpRate(clientIp, 'submit-random')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.', code: data.code }));
          await incrementFailure(clientIp);
          return;
        }
        const roomKey = `room:${data.code}`;
        try {
          const roomStr = await redis.get(roomKey);
          if (roomStr) {
            const room = JSON.parse(roomStr);
            if (room.initiator === data.clientId) {
              await redis.sadd('randomCodes', data.code);
              ws.send(JSON.stringify({ type: 'random-submitted', code: data.code }));
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
              await incrementFailure(clientIp);
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
            await incrementFailure(clientIp);
          }
        } catch (err) {
          console.error('Error in submit-random:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error submitting to random board.' }));
        }
      }
      if (data.type === 'get-random-codes') {
        try {
          const codes = await redis.smembers('randomCodes');
          ws.send(JSON.stringify({ type: 'random-codes', codes }));
        } catch (err) {
          console.error('Error getting random codes:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error fetching random codes.' }));
        }
      }
      if (data.type === 'remove-random-code') {
        try {
          await redis.srem('randomCodes', data.code);
          console.log(`Removed code ${data.code} from randomCodes`);
        } catch (err) {
          console.error('Error removing random code:', err);
        }
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
        const payload = data.type === 'relay-message' ? data.encryptedContent : data.encryptedData;
        if (payload && payload.length > 9333333) {
          ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 5MB).', code: data.code }));
          await incrementFailure(clientIp);
          return;
        }
        if (payload && !isValidBase64(payload)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid base64 format in payload.', code: data.code }));
          await incrementFailure(clientIp);
          return;
        }
        const roomKey = `room:${data.code}`;
        try {
          if (!await redis.exists(roomKey)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
            await incrementFailure(clientIp);
            return;
          }
        } catch (err) {
          console.error('Error checking room existence:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error checking room.' }));
          return;
        }
        const senderId = data.clientId;
        const clientsKey = `room_clients:${data.code}`;
        try {
          if (!await redis.sismember(clientsKey, senderId)) {
            ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
            await incrementFailure(clientIp);
            return;
          }
        } catch (err) {
          console.error('Error checking membership:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error checking membership.' }));
          return;
        }
        pub.publish('signaling', JSON.stringify(data));
        console.log(`Relayed ${data.type} from ${senderId} in code ${data.code} (content not logged for privacy)`);
      }
      if (data.type === 'get-stats') {
        if (data.secret === ADMIN_SECRET) {
          const now = new Date();
          const day = now.toISOString().slice(0, 10);
          try {
            const roomKeys = await redis.keys('room:*');
            let activeRooms = roomKeys.length;
            let totalClients = 0;
            for (const key of roomKeys) {
              totalClients += await redis.scard(key.replace('room', 'room_clients'));
            }
            const weekly = await computeAggregate(7);
            const monthly = await computeAggregate(30);
            const yearly = await computeAggregate(365);
            const allTimeUsersCount = await redis.pfcount('allTimeUsers');
            ws.send(JSON.stringify({
              type: 'stats',
              dailyUsers: await redis.scard(`dailyUsers:${day}`) || 0,
              dailyConnections: await redis.scard(`dailyConnections:${day}`) || 0,
              weeklyUsers: weekly.users,
              weeklyConnections: weekly.connections,
              monthlyUsers: monthly.users,
              monthlyConnections: monthly.connections,
              yearlyUsers: yearly.users,
              yearlyConnections: yearly.connections,
              allTimeUsers: allTimeUsersCount,
              activeRooms,
              totalClients
            }));
          } catch (err) {
            console.error('Error fetching stats:', err);
            ws.send(JSON.stringify({ type: 'error', message: 'Server error fetching stats.' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
      }
      if (data.type === 'get-features') {
        if (data.secret === ADMIN_SECRET) {
          ws.send(JSON.stringify({ type: 'features', ...features }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
      }
      if (data.type === 'toggle-feature') {
        if (data.secret === ADMIN_SECRET) {
          const featureKey = `enable${data.feature.charAt(0).toUpperCase() + data.feature.slice(1)}`;
          if (features.hasOwnProperty(featureKey)) {
            features[featureKey] = !features[featureKey];
            try {
              await redis.set('features', JSON.stringify(features));
              saveFeatures();
              const timestamp = new Date().toISOString();
              fs.appendFileSync(LOG_FILE, `${timestamp} - Admin toggled ${featureKey} to ${features[featureKey]} by client ${hashIp(clientIp)}\n`);
              ws.send(JSON.stringify({ type: 'feature-toggled', feature: data.feature, enabled: features[featureKey] }));
              pub.publish('signaling', JSON.stringify({ type: 'features-update', enableService: features.enableService, enableImages: features.enableImages, enableVoice: features.enableVoice, enableVoiceCalls: features.enableVoiceCalls, enableAudioToggle: features.enableAudioToggle, enableGrokBot: features.enableGrokBot }));
              if (data.feature === 'service' && !features.enableService) {
                const roomKeys = await redis.keys('room:*');
                for (const key of roomKeys) {
                  await redis.del(key);
                  await redis.del(key.replace('room', 'room_clients'));
                  await redis.del(key.replace('room', 'totp'));
                }
                const clientKeys = await redis.keys('client:*');
                for (const key of clientKeys) {
                  await redis.del(key);
                }
                await redis.del('randomCodes');
              }
            } catch (err) {
              console.error('Error toggling feature:', err);
              ws.send(JSON.stringify({ type: 'error', message: 'Server error toggling feature.' }));
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid feature' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
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
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.', code: data ? data.code : 'unknown' }));
      await incrementFailure(clientIp);
    }
  });
  ws.on('close', async () => {
    try {
      if (ws.clientId) {
        const tokens = clientTokens.get(ws.clientId);
        if (tokens) {
          try {
            const decodedAccess = jwt.verify(tokens.accessToken, JWT_SECRET, { ignoreExpiration: true });
            await redis.set(`revoked:${tokens.accessToken}`, 1, 'PX', decodedAccess.exp * 1000 - Date.now());
            if (tokens.refreshToken) {
              const decodedRefresh = jwt.verify(tokens.refreshToken, JWT_SECRET, { ignoreExpiration: true });
              await redis.set(`revoked:${tokens.refreshToken}`, 1, 'PX', decodedRefresh.exp * 1000 - Date.now());
            }
            clientTokens.delete(ws.clientId);
            console.log(`Revoked tokens for client ${ws.clientId} on disconnect`);
          } catch (err) {
            console.warn(`Failed to revoke tokens for client ${ws.clientId}: ${err.message}`);
          }
        }
      }
      const code = localClients.has(ws.clientId) ? localClients.get(ws.clientId).code : null;
      if (code) {
        const clientsKey = `room_clients:${code}`;
        await redis.srem(clientsKey, ws.clientId);
        await redis.del(`client:${ws.clientId}`);
        const remaining = await redis.scard(clientsKey);
        let isInitiatorDisconnect = false;
        const roomKey = `room:${code}`;
        const roomStr = await redis.get(roomKey);
        if (roomStr) {
          const room = JSON.parse(roomStr);
          if (room.initiator === ws.clientId) {
            isInitiatorDisconnect = true;
            const members = await redis.smembers(clientsKey);
            if (members.length > 0) {
              room.initiator = members[0];
              await redis.set(roomKey, JSON.stringify(room));
              pub.publish('signaling', JSON.stringify({ type: 'initiator-changed', code, newInitiator: room.initiator, totalClients: remaining }));
            } else {
              await redis.del(roomKey);
              await redis.del(`totp:${code}`);
              await redis.srem('randomCodes', code);
            }
          }
        }
        pub.publish('signaling', JSON.stringify({ type: 'disconnect', code, clientId: ws.clientId, totalClients: remaining, isInitiator: isInitiatorDisconnect }));
        if (localRooms.has(code)) {
          localRooms.get(code).myClients.delete(ws.clientId);
          localRooms.get(code).totalClients = remaining;
          if (localRooms.get(code).myClients.size === 0) {
            localRooms.delete(code);
          }
        }
      }
      if (ws.clientId) localClients.delete(ws.clientId);
    } catch (err) {
      console.error('Error in ws close handler:', err);
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
    fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - Rate limit exceeded for client ${ws.clientId}: ${rateLimit.count}\n`);
    return false;
  }
  return true;
}

async function restrictIpRate(ip, action) {
  const hashedIp = hashIp(ip);
  const key = `iprate:${hashedIp}:${action}`;
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, 60);
  }
  if (count > 5) {
    console.warn(`IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${count} in 60s`);
    fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${count}\n`);
    return false;
  }
  return true;
}

async function restrictIpDaily(ip, action) {
  const hashedIp = hashIp(ip);
  const day = new Date().toISOString().slice(0, 10);
  const key = `ipdaily:${hashedIp}:${action}:${day}`;
  const count = await redis.incr(key);
  if (count > 100) {
    console.warn(`Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${count} in day ${day}`);
    fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${count}\n`);
    return false;
  }
  return true;
}

async function incrementFailure(ip) {
  const hashedIp = hashIp(ip);
  const failureKey = `ipfailure:${hashedIp}`;
  const count = await redis.incr(failureKey);
  if (count === 1) {
    await redis.expire(failureKey, 300);
  }
  if (count % 5 === 0) {
    console.warn(`High failure rate for hashed IP ${hashedIp}: ${count} failures`);
  }
  if (count >= 10) {
    const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];
    let banLevel = await redis.get(`banlevel:${hashedIp}`) || 0;
    banLevel = Math.min(parseInt(banLevel) + 1, 2);
    await redis.set(`banlevel:${hashedIp}`, banLevel, 'EX', 3600);
    const duration = banDurations[banLevel];
    const expiry = Date.now() + duration;
    await redis.set(`ban:${hashedIp}`, expiry);
    const timestamp = new Date().toISOString();
    const banLogEntry = `${timestamp} - Hashed IP Banned: ${hashedIp}, Duration: ${duration / 60000} minutes, Ban Level: ${banLevel}\n`;
    fs.appendFileSync(LOG_FILE, banLogEntry);
    console.warn(`Hashed IP ${hashedIp} banned until ${new Date(expiry).toISOString()} at ban level ${banLevel} (${duration / 60000} minutes)`);
    await redis.del(failureKey);
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
    username: data.username || '',
    targetId: data.targetId || '',
    code: data.code || '',
    event: data.event || '',
    totalClients: data.totalClients || 0,
    isInitiator: data.isInitiator || false,
    timestamp,
    day
  };
  (async () => {
    try {
      if (data.event === 'connect' || data.event === 'join' || data.event === 'webrtc-connection') {
        await redis.sadd(`dailyUsers:${day}`, data.clientId);
        await redis.pfadd('allTimeUsers', data.clientId);
        if (data.event === 'webrtc-connection' && data.targetId) {
          await redis.sadd(`dailyUsers:${day}`, data.targetId);
          await redis.pfadd('allTimeUsers', data.targetId);
          const connectionKey = `${data.clientId}-${data.targetId}-${data.code}`;
          await redis.sadd(`dailyConnections:${day}`, connectionKey);
        }
      }
    } catch (err) {
      console.error('Error logging stats to Redis:', err);
    }
  })();
  const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}\n`;
  fs.appendFileSync(LOG_FILE, logEntry);
}

function updateLogFile() {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  (async () => {
    try {
      const userCount = await redis.scard(`dailyUsers:${day}`) || 0;
      const connectionCount = await redis.scard(`dailyConnections:${day}`) || 0;
      const allTimeUserCount = await redis.pfcount('allTimeUsers') || 0;
      const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}, All-Time Unique Users: ${allTimeUserCount}\n`;
      fs.appendFileSync(LOG_FILE, logEntry);
      console.log(`Updated ${LOG_FILE} with ${userCount} unique users, ${connectionCount} WebRTC connections, and ${allTimeUserCount} all-time unique users for ${day}`);
      if (!aggregatedStats.daily) aggregatedStats.daily = {};
      aggregatedStats.daily[day] = { users: userCount, connections: connectionCount };
      saveAggregatedStats();
    } catch (err) {
      console.error('Error updating log file:', err);
    }
  })();
}

fs.writeFileSync(LOG_FILE, '', (err) => {
  if (err) console.error('Error creating log file:', err);
  else {
    updateLogFile();
    setInterval(updateLogFile, UPDATE_INTERVAL);
  }
});

async function computeAggregate(days) {
  const now = new Date();
  let users = 0, connections = 0;
  for (let i = 0; i < days; i++) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const key = date.toISOString().slice(0, 10);
    try {
      users += await redis.scard(`dailyUsers:${key}`) || 0;
      connections += await redis.scard(`dailyConnections:${key}`) || 0;
    } catch (err) {
      console.error('Error computing aggregate:', err);
    }
  }
  return { users, connections };
}

function hashIp(ip) {
  return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
}

server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
