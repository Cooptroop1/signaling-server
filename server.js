const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken'); // New: for JWT tokens
const validator = require('validator'); // New: for robust input sanitization

const http = require('http'); // Added for HTTP server to support WS upgrades

const server = http.createServer();
const wss = new WebSocket.Server({ server });

const rooms = new Map();
const dailyUsers = new Map(); // Track unique clientIds per day
const dailyConnections = new Map(); // Track WebRTC connections per day
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const UPDATE_INTERVAL = 30000; // 30 seconds in milliseconds for testing
const randomCodes = new Set(); // Store unique codes for random matching
const rateLimits = new Map(); // Track message rate limits per clientId
const allTimeUsers = new Set(); // Track all-time unique users persistently
const ipRateLimits = new Map(); // Track IP-based rate limits for joins and submits
const ipDailyLimits = new Map(); // New: Daily joins per IP
const ipFailureCounts = new Map(); // New: Track failed attempts per IP for temporary bans
const ipBans = new Map(); // New: Banned IPs with expiration
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  throw new Error('ADMIN_SECRET environment variable is not set. Please configure it for security.');
}

// New: JWT secret for tokens
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-fallback'; // Set in env for production

// TURN credentials from env vars (set in Render dashboard) - Removed fallbacks, made required
const TURN_USERNAME = process.env.TURN_USERNAME;
if (!TURN_USERNAME) {
  throw new Error('TURN_USERNAME environment variable is not set. Please configure it.');
}
const TURN_CREDENTIAL = process.env.TURN_CREDENTIAL;
if (!TURN_CREDENTIAL) {
  throw new Error('TURN_CREDENTIAL environment variable is not set. Please configure it.');
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
}, 3600000); // Every hour (3600000 ms)

// Server-side ping to detect dead connections
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const clientIp = ws._socket.remoteAddress; // Get client IP
  let clientId, code, username;

  ws.on('message', async (message) => {
    // Rate limiting: 50 messages per minute per client
    if (!restrictRate(ws)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }

    try {
      const data = JSON.parse(message);
      console.log('Received:', data);

      // New: Sanitize all JSON fields robustly
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string') {
          data[key] = validator.escape(validator.trim(data[key])); // Escape HTML, trim whitespace
        }
      });

      if (data.type === 'connect') {
        clientId = data.clientId || uuidv4();
        ws.clientId = clientId;
        logStats({ clientId, event: 'connect' });
        // New: Generate JWT token for the client
        const token = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '1h' });
        ws.send(JSON.stringify({ type: 'connected', clientId, token }));
        return;
      }

      // New: Verify token for protected actions
      const protectedTypes = ['join', 'leave', 'set-max-clients', 'offer', 'answer', 'candidate', 'relay-message', 'relay-image', 'submit-random', 'public-key']; // Added public-key
      if (protectedTypes.includes(data.type)) {
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
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
          return;
        }
      }

      // New: Check if IP is banned
      if (ipBans.has(clientIp) && ipBans.get(clientIp) > Date.now()) {
        ws.send(JSON.stringify({ type: 'error', message: 'IP temporarily banned due to excessive failures. Try again later.' }));
        return;
      }

      if (data.type === 'public-key') {
        // New: Handle public key from joiner, relay to initiator
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
        // New: Handle encrypted room key from initiator, relay to joiner
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
        // IP rate limiting for joins: max 5 per minute per IP
        if (!restrictIpRate(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.' }));
          incrementFailure(clientIp);
          return;
        }

        // New: Daily join limit: max 100 per day per IP
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

        if (!rooms.has(code)) {
          rooms.set(code, { initiator: clientId, clients: new Map(), maxClients: 2 });
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL }));
          logStats({ clientId, username, code, event: 'init', totalClients: 1 });
        } else {
          const room = rooms.get(code);
          if (room.clients.size >= room.maxClients) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat is full' }));
            incrementFailure(clientIp);
            return;
          }
          // Allow rejoin if clientId matches existing client with same username
          if (room.clients.has(clientId)) {
            if (room.clients.get(clientId).username === username) {
              // Clean up old connection with a short delay to avoid race conditions
              const oldWs = room.clients.get(clientId).ws;
              setTimeout(() => {
                oldWs.close();
              }, 1000); // 1-second delay for graceful close
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
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL }));
          logStats({ clientId, username, code, event: 'join', totalClients: room.clients.size + 1 });
          // Log WebRTC connections for new client with all existing clients
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

      if (data.type === 'leave') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const isInitiator = data.clientId === room.initiator;
          room.clients.delete(data.clientId);
          logStats({ clientId: data.clientId, code: data.code, event: 'leave', totalClients: room.clients.size, isInitiator });
          if (room.clients.size === 0 || isInitiator) {
            rooms.delete(data.code);
            randomCodes.delete(data.code); // Remove code from random list if room empties or initiator leaves
            broadcast(data.code, { 
              type: 'client-disconnected', 
              clientId: data.clientId, 
              totalClients: 0, 
              isInitiator 
            });
          } else {
            if (isInitiator) {
              const newInitiator = room.clients.keys().next().value;
              if (newInitiator) {
                room.initiator = newInitiator;
                broadcast(data.code, { 
                  type: 'initiator-changed', 
                  newInitiator, 
                  totalClients: room.clients.size 
                });
              }
            }
            broadcast(data.code, { 
              type: 'client-disconnected', 
              clientId: data.clientId, 
              totalClients: room.clients.size, 
              isInitiator 
            });
          }
        }
      }

      if (data.type === 'set-max-clients') {
        if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
          const room = rooms.get(data.code);
          room.maxClients = Math.min(data.maxClients, 10);
          broadcast(data.code, { type: 'max-clients', maxClients: room.maxClients, totalClients: room.clients.size });
          logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients: room.clients.size });
        }
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
          }
        }
      }

      if (data.type === 'submit-random') {
        if (!restrictIpRate(clientIp, 'submit-random')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.' }));
          incrementFailure(clientIp);
          return;
        }

        if (data.code && !rooms.get(data.code)?.clients.size) {
          ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code' }));
          incrementFailure(clientIp);
          return;
        }
        if (rooms.get(data.code)?.initiator === data.clientId) {
          randomCodes.add(data.code);
          broadcastRandomCodes();
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board' }));
          incrementFailure(clientIp);
        }
      }

      if (data.type === 'get-random-codes') {
        ws.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
      }

      if (data.type === 'remove-random-code') {
        if (randomCodes.has(data.code)) {
          randomCodes.delete(data.code);
          broadcastRandomCodes();
          console.log(`Removed code ${data.code} from randomCodes`);
        }
      }

      // Relay fallback handling from the new code
      if (data.type === 'relay-message' || data.type === 'relay-image') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Not in a chat' }));
          incrementFailure(clientIp);
          return;
        }
        const room = rooms.get(data.code);
        const senderId = data.clientId;
        if (!room.clients.has(senderId)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Not in chat' }));
          incrementFailure(clientIp);
          return;
        }
        // Broadcast to all other clients in the room (no logging of content for privacy)
        room.clients.forEach((client, clientId) => {
          if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
              type: data.type.replace('relay-', ''), // Strip 'relay-' for client
              messageId: data.messageId,
              username: data.username,
              encryptedContent: data.encryptedContent, // New: For encrypted text
              encryptedData: data.encryptedData, // New: For encrypted images (base64)
              iv: data.iv // New: Initialization vector for decryption
            }));
          }
        });
        // Log only the event, not the content
        console.log(`Relayed ${data.type} from ${senderId} in code ${data.code} (content not logged for privacy)`);
      }

      if (data.type === 'get-stats') {
        if (data.secret === ADMIN_SECRET) {
          const now = new Date();
          const day = now.toISOString().slice(0, 10);
          let totalClients = 0;
          rooms.forEach(room => {
            totalClients += room.clients.size;
          });
          ws.send(JSON.stringify({
            type: 'stats',
            dailyUsers: dailyUsers.get(day)?.size || 0,
            dailyConnections: dailyConnections.get(day)?.size || 0,
            allTimeUsers: allTimeUsers.size,
            activeRooms: rooms.size,
            totalClients: totalClients
          }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
      }

      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
      }
    } catch (error) {
      console.error('Error processing message:', error);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.' }));
      incrementFailure(clientIp);
    }
  });

  ws.on('close', () => {
    if (ws.code && rooms.has(ws.code)) {
      const room = rooms.get(ws.code);
      const isInitiator = ws.clientId === room.initiator;
      room.clients.delete(ws.clientId);
      rateLimits.delete(ws.clientId); // Clear rate limit on disconnect
      logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients: room.clients.size, isInitiator });
      if (room.clients.size === 0 || isInitiator) {
        rooms.delete(ws.code);
        randomCodes.delete(ws.code); // Clean up random code on room closure or initiator disconnect
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

// Rate limiting function: 50 messages per minute per client
function restrictRate(ws) {
  if (!ws.clientId) return true; // Allow initial connect message
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
    return false;
  }
  return true;
}

// IP rate limiting function: max 5 actions (join/submit) per minute per IP
function restrictIpRate(ip, action) {
  const now = Date.now();
  const key = `${ip}:${action}`;
  const rateLimit = ipRateLimits.get(key) || { count: 0, startTime: now };
  if (now - rateLimit.startTime >= 60000) {
    rateLimit.count = 0;
    rateLimit.startTime = now;
  }
  rateLimit.count += 1;
  ipRateLimits.set(key, rateLimit);
  if (rateLimit.count > 5) {
    console.warn(`IP rate limit exceeded for ${action} from ${ip}: ${rateLimit.count} in 60s`);
    return false;
  }
  return true;
}

// New: Daily IP limit for joins (100/day)
function restrictIpDaily(ip, action) {
  const day = new Date().toISOString().slice(0, 10);
  const key = `${ip}:${action}:${day}`;
  const dailyLimit = ipDailyLimits.get(key) || { count: 0 };
  dailyLimit.count += 1;
  ipDailyLimits.set(key, dailyLimit);
  if (dailyLimit.count > 100) {
    console.warn(`Daily IP limit exceeded for ${action} from ${ip}: ${dailyLimit.count} in day ${day}`);
    return false;
  }
  return true;
}

// New: Increment failure count and ban IP if threshold reached
function incrementFailure(ip) {
  const failure = ipFailureCounts.get(ip) || { count: 0 };
  failure.count += 1;
  ipFailureCounts.set(ip, failure);
  if (failure.count >= 10) {
    const banUntil = Date.now() + 300000; // Ban for 5 minutes
    ipBans.set(ip, banUntil);
    console.warn(`IP ${ip} banned until ${new Date(banUntil).toISOString()} due to excessive failures`);
    ipFailureCounts.delete(ip); // Reset after ban
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
    targetId: data.targetId || '', // For webrtc-connection events
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
    allTimeUsers.add(data.clientId); // Add to all-time unique users
    if (data.event === 'webrtc-connection' && data.targetId) {
      dailyUsers.get(day).add(data.targetId); // Add targetId to unique users
      allTimeUsers.add(data.targetId); // Add to all-time unique users
      // Log connection with unique key
      const connectionKey = `${data.clientId}-${data.targetId}-${data.code}`;
      dailyConnections.get(day).add(connectionKey);
    }
  }

  const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}\n`;
  fs.appendFile(LOG_FILE, logEntry, (err) => {
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
  
  fs.appendFile(LOG_FILE, logEntry, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    } else {
      console.log(`Updated ${LOG_FILE} with ${userCount} unique users, ${connectionCount} WebRTC connections, and ${allTimeUserCount} all-time unique users for ${day}`);
    }
  });
}

// Initial file creation and 30-second updates for testing
fs.writeFile(LOG_FILE, '', (err) => {
  if (err) console.error('Error creating log file:', err);
  else {
    updateLogFile(); // Initial write
    setInterval(updateLogFile, UPDATE_INTERVAL); // Update every 30 seconds
  }
});

function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.random() * chars.length);
    if (i % 4 === 3 && i < 15) result += '-';
  }
  return result;
}

function broadcast(code, message) {
  const room = rooms.get(code);
  if (room) {
    room.clients.forEach(client => {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(JSON.stringify(message));
      }
    });
  }
}

function broadcastRandomCodes() {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
    }
  });
}

// Start the HTTP server (for WS upgrades; Render handles TLS for WSS)
server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
