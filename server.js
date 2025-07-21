try {
  require.resolve('ws');
  require.resolve('express');
  require.resolve('cors');
} catch (e) {
  console.error('Required dependencies missing. Please run `npm install`.', e);
  process.exit(1);
}

const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const rooms = new Map();
const dailyUsers = new Map();
const dailyConnections = new Map();
const randomCodes = new Set();
const rateLimits = new Map();
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const EVENT_LOG_FILE = path.join(__dirname, 'event_logs.log');
const UPDATE_INTERVAL = 30000;
const PORT = process.env.PORT || 10000;

// Middleware
app.use(express.json());
app.use(cors({ origin: '*' })); // Allow all origins for testing; restrict in production
app.use((req, res, next) => {
  console.log(`Received ${req.method} request to ${req.url}`);
  next();
});

// Analytics endpoint
app.post('/api/log', (req, res) => {
  const { eventType, timestamp, clientId, details } = req.body;
  if (!eventType || !timestamp || !clientId) {
    console.error('Invalid analytics event:', req.body);
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const logEntry = `${timestamp} - Client: ${clientId}, Event: ${eventType}, Details: ${JSON.stringify(details)}\n`;
  fs.appendFile(EVENT_LOG_FILE, logEntry, (err) => {
    if (err) {
      console.error('Error appending to event log:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    console.log(`Logged event: ${eventType} for client ${clientId}`);
    res.status(200).json({ status: 'Event logged' });
  });
});

// WebSocket server logic (unchanged from your original)
wss.on('connection', (ws) => {
  let clientId, code, username;

  ws.on('message', async (message) => {
    if (!restrictRate(ws)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }

    try {
      const data = JSON.parse(message);
      console.log('Received:', data);

      if (data.type === 'connect') {
        clientId = data.clientId;
        if (!clientId) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid clientId' }));
          return;
        }
        ws.clientId = clientId;
        logStats({ clientId, event: 'connect' });
      }

      if (data.type === 'join') {
        code = data.code;
        clientId = data.clientId;
        username = data.username;

        if (!validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username' }));
          return;
        }

        if (!rooms.has(code)) {
          rooms.set(code, { initiator: clientId, clients: new Map(), maxClients: 2 });
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true }));
          logStats({ clientId, username, code, event: 'init', totalClients: 1 });
        } else {
          const room = rooms.get(code);
          if (room.clients.size >= room.maxClients) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat is full' }));
            return;
          }
          if (room.clients.has(clientId)) {
            if (room.clients.get(clientId).username === username) {
              room.clients.get(clientId).ws.close();
              room.clients.delete(clientId);
              broadcast(code, { 
                type: 'client-disconnected', 
                clientId, 
                totalClients: room.clients.size, 
                isInitiator: clientId === room.initiator 
              });
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId' }));
              return;
            }
          } else if (Array.from(room.clients.values()).some(c => c.username === username)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
            return;
          }
          if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Initiator offline' }));
            return;
          }
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false }));
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

      if (data.type === 'leave') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const isInitiator = data.clientId === room.initiator;
          room.clients.delete(data.clientId);
          logStats({ clientId: data.clientId, code: data.code, event: 'leave', totalClients: room.clients.size, isInitiator });
          if (room.clients.size === 0 || isInitiator) {
            rooms.delete(data.code);
            randomCodes.delete(data.code);
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
        if (data.code && !rooms.get(data.code)?.clients.size) {
          ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code' }));
          return;
        }
        if (rooms.get(data.code)?.initiator === data.clientId) {
          randomCodes.add(data.code);
          broadcastRandomCodes();
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board' }));
        }
      }

      if (data.type === 'get-random-codes') {
        ws.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
      }

      if (data.type === 'remove-random-code') {
        if (rooms.get(data.code)?.initiator === data.clientId) {
          randomCodes.delete(data.code);
          broadcastRandomCodes();
          console.log(`Removed code ${data.code} from randomCodes`);
        }
      }

      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
      }
    } catch (error) {
      console.error('Error processing message:', error);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.' }));
    }
  });

  ws.on('close', () => {
    if (ws.code && rooms.has(ws.code)) {
      const room = rooms.get(ws.code);
      const isInitiator = ws.clientId === room.initiator;
      room.clients.delete(ws.clientId);
      rateLimits.delete(ws.clientId);
      logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients: room.clients.size, isInitiator });
      if (room.clients.size === 0 || isInitiator) {
        rooms.delete(ws.code);
        randomCodes.delete(ws.code);
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

// Rate limiting function
function restrictRate(ws) {
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
    return false;
  }
  return true;
}

// Validate username
function validateUsername(username) {
  const regex = /^[a-zA-Z0-9]{1,16}$/;
  return username && regex.test(username);
}

// Log user statistics
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

  if (data.event === 'connect' || data.event === 'join' || data.event === 'webrtc-connection') {
    if (!dailyUsers.has(day)) {
      dailyUsers.set(day, new Set());
    }
    if (!dailyConnections.has(day)) {
      dailyConnections.set(day, new Set());
    }
    dailyUsers.get(day).add(data.clientId);
    if (data.event === 'webrtc-connection' && data.targetId) {
      dailyUsers.get(day).add(data.targetId);
      const connectionKey = `${data.clientId}-${data.targetId}-${data.code}`;
      dailyConnections.get(day).add(connectionKey);
    }
  }

  const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}\n`;
  fs.appendFile(LOG_FILE, logEntry, (err) => {
    if (err) {
      console.error('Error appending to user log file:', err);
    }
  });
}

// Update user_counts.log
function updateLogFile() {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  const userCount = dailyUsers.get(day)?.size || 0;
  const connectionCount = dailyConnections.get(day)?.size || 0;
  const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}\n`;
  
  fs.appendFile(LOG_FILE, logEntry, (err) => {
    if (err) {
      console.error('Error writing to user log file:', err);
    } else {
      console.log(`Updated ${LOG_FILE} with ${userCount} unique users and ${connectionCount} WebRTC connections for ${day}`);
    }
  });
}

// Generate random code
function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.random() * chars.length);
    if (i % 4 === 3 && i < 15) result += '-';
  }
  return result;
}

// Broadcast messages
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

// Broadcast random codes
function broadcastRandomCodes() {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
    }
  });
}

// Initialize log files
fs.writeFile(LOG_FILE, '', (err) => {
  if (err) console.error('Error creating user log file:', err);
});
fs.writeFile(EVENT_LOG_FILE, '', (err) => {
  if (err) console.error('Error creating event log file:', err);
});
updateLogFile();
setInterval(updateLogFile, UPDATE_INTERVAL);

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
