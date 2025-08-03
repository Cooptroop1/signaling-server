const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const axios = require('axios'); // New: For Metered API calls

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

const wss = new WebSocket.Server({ server });
const rooms = new Map();
const dailyUsers = new Map();
const dailyConnections = new Map();
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const FEATURES_FILE = path.join(__dirname, 'features.json');
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

const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  throw new Error('ADMIN_SECRET environment variable is not set. Please configure it for security.');
}

const ALLOWED_ORIGINS = ['https://anonomoose.com', 'http://localhost:3000'];
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-fallback';
const METERED_API_KEY = process.env.METERED_API_KEY; // New: Replace static TURN with API key
if (!METERED_API_KEY) {
  throw new Error('METERED_API_KEY environment variable is not set. Please configure it for dynamic TURN credentials.');
}
const IP_SALT = process.env.IP_SALT || 'your-random-salt-here'; // Set in .env for security

let features = {
  enableService: true,
  enableImages: true,
  enableVoice: true
};

// Load features from file if exists
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

// Function to save features to file
function saveFeatures() {
  fs.writeFileSync(FEATURES_FILE, JSON.stringify(features));
  console.log('Saved features:', features);
}

function hashIp(ip) {
  return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
}

// Validate base64 string
function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(str) && str.length % 4 === 0;
}

// New: Generate time-limited TURN credentials using Metered API
async function generateTurnCredentials() {
  try {
    const response = await axios.post('https://api.metered.ca/v1/turnservice/credential', {
      ttl: 3600, // 1 hour expiry
      uris: [
        "turn:global.turn.metered.ca:80",
        "turn:global.turn.metered.ca:443",
        "turn:global.turn.metered.ca:80?transport=tcp",
        "turns:global.turn.metered.ca:443?transport=tcp"
      ]
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${METERED_API_KEY}` // Use API key
      }
    });
    return {
      username: response.data.username,
      credential: response.data.credential
    };
  } catch (error) {
    console.error('Error generating TURN credentials:', error.response ? error.response.data : error.message);
    throw new Error('Failed to generate TURN credentials');
  }
}

// Load historical unique users from log on startup
if (fs.existsSync(LOG_FILE)) {
  const logContent = fs.readFileSync(LOG_FILE, 'utf8');
  const lines = logContent.split('\n');
  lines.forEach(line => {
    const match = line.match(/Client: (\w+)/);
    if (match) allTimeUsers.add(match[1]);
  });
  console.log(`Loaded ${allTimeUsers.size} all-time unique users from log.`);
}

// Auto-cleanup for random codes every hour
setInterval(() => {
  randomCodes.forEach(code => {
    if (!rooms.has(code) || rooms.get(code).clients.size === 0) {
      randomCodes.delete(code);
    }
  });
  broadcastRandomCodes();
  console.log('Auto-cleaned random codes.');
}, 3600000);

// Server-side ping to detect dead connections
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// Cleanup expired revoked tokens
setInterval(() => {
  const now = Date.now();
  revokedTokens.forEach((expiry, token) => {
    if (expiry < now) {
      revokedTokens.delete(token);
    }
  });
  console.log(`Cleaned up expired revoked tokens. Remaining: ${revokedTokens.size}`);
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

  const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress; // Handle proxies
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
      console.log('Received:', data);

      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string' && !(data.type === 'public-key' && key === 'publicKey')) {
          data[key] = validator.escape(validator.trim(data[key]));
        }
      });

      if (data.type === 'public-key' && data.publicKey) {
        if (!isValidBase64(data.publicKey)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format' }));
          incrementFailure(clientIp);
          return;
        }
      }

      if (data.type === 'get-stats' || data.type === 'get-features' || data.type === 'toggle-feature') {
        if (data.secret === ADMIN_SECRET) {
          isAdmin = true;
        }
      }

      if (!features.enableService && !isAdmin && data.type !== 'connect') {
        ws.send(JSON.stringify({ type: 'error', message: 'Service is currently disabled.' }));
        ws.close();
        return;
      }

      if (data.type !== 'connect') {
        if (!data.token) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing authentication token' }));
          return;
        }
        try {
          const decoded = jwt.verify(data.token, JWT_SECRET);
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
        const accessToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '24h' });
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
          const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '15m' });
          clientTokens.set(data.clientId, { ...clientTokens.get(data.clientId), accessToken: newAccessToken });
          ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken }));
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
          return;
        }
        return;
      }

      if (data.type === 'public-key') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const initiatorWs = room.clients.get(room.initiator)?.ws;
          if (initiatorWs && initiatorWs.readyState === WebSocket.OPEN) {
            initiatorWs.send(JSON.stringify({ type: 'public-key', publicKey: data.publicKey, clientId: data.clientId, code: data.code }));
          }
        }
        return;
      }

      if (data.type === 'encrypted-room-key') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const targetWs = room.clients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, clientId: data.clientId, code: data.code }));
          }
        }
        return;
      }

      if (data.type === 'join') {
        if (!features.enableService) {
          ws.send(JSON.stringify({ type: 'error', message: 'Service is currently disabled.' }));
          return;
        }
        if (!restrictIpRate(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.' }));
          incrementFailure(clientIp);
          return;
        }
        if (!restrictIpDaily(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.' }));
          incrementFailure(clientIp);
          return;
        }
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        if (!validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username' }));
          incrementFailure(clientIp);
          return;
        }
        if (!validateCode(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format' }));
          incrementFailure(clientIp);
          return;
        }
        let turnCreds;
        try {
          turnCreds = await generateTurnCredentials();
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to generate TURN credentials. Try again later.' }));
          return;
        }
        if (!rooms.has(code)) {
          rooms.set(code, { initiator: clientId, clients: new Map(), maxClients: 2 });
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: turnCreds.username, turnCredential: turnCreds.credential, features }));
          logStats({ clientId, username, code, event: 'init', totalClients: 1 });
        } else {
          const room = rooms.get(code);
          if (room.clients.size >= room.maxClients) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat is full' }));
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
              ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId' }));
              incrementFailure(clientIp);
              return;
            }
          } else if (Array.from(room.clients.values()).some(c => c.username === username)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
            incrementFailure(clientIp);
            return;
          }
          if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Initiator offline' }));
            incrementFailure(clientIp);
            return;
          }
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false, turnUsername: turnCreds.username, turnCredential: turnCreds.credential, features }));
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
      }

      // ... (rest of the message handlers remain the same, no changes needed beyond the TURN generation in 'init')
    } catch (error) {
      console.error('Error processing message:', error);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.' }));
      incrementFailure(clientIp);
    }
  });

  // ... (rest of the server.js remains the same, including functions like restrictRate, etc.)
});

server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
