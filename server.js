const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const wss = new WebSocket.Server({ port: process.env.PORT || 10000 });
const rooms = new Map();
const dailyUsers = new Map(); // Track unique clientIds per day
const dailyConnections = new Map(); // Track WebRTC connections per day
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const UPDATE_INTERVAL = 30000; // 30 seconds in milliseconds for testing
const randomCodes = new Set(); // Store unique codes for random matching

wss.on('connection', (ws) => {
  let clientId, code, username;

  ws.on('message', async (message) => {
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
          if (Array.from(room.clients.values()).some(c => c.username === username)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
            return;
          }
          if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Initiator offline' }));
            return;
          }
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false }));
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
          room.clients.delete(data.clientId);
          logStats({ clientId: data.clientId, code: data.code, event: 'leave', totalClients: room.clients.size });
          if (room.clients.size === 0) {
            rooms.delete(data.code);
            randomCodes.delete(data.code); // Remove code from random list if room empties
          } else {
            if (data.clientId === room.initiator) {
              const newInitiator = room.clients.keys().next().value;
              if (newInitiator) {
                room.initiator = newInitiator;
                broadcast(data.code, { type: 'initiator-changed', newInitiator, totalClients: room.clients.size });
              }
            }
            broadcast(data.code, { type: 'client-disconnected', clientId: data.clientId, totalClients: room.clients.size });
          }
        }
      }

      if (data.type === 'set-max-clients') {
        if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
          const room = rooms.get(data.code);
          room.maxClients = data.maxClients;
          broadcast(data.code, { type: 'max-clients', maxClients: data.maxClients, totalClients: room.clients.size });
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
        randomCodes.add(data.code);
        broadcastRandomCodes();
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
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });

  ws.on('close', () => {
    if (ws.code && rooms.has(ws.code)) {
      const room = rooms.get(ws.code);
      room.clients.delete(ws.clientId);
      logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients: room.clients.size });
      if (room.clients.size === 0) {
        rooms.delete(ws.code);
        randomCodes.delete(ws.code); // Clean up random code on room closure
      } else {
        if (ws.clientId === room.initiator) {
          const newInitiator = room.clients.keys().next().value;
          if (newInitiator) {
            room.initiator = newInitiator;
            broadcast(ws.code, { type: 'initiator-changed', newInitiator, totalClients: room.clients.size });
          }
        }
        broadcast(ws.code, { type: 'client-disconnected', clientId: ws.clientId, totalClients: room.clients.size });
      }
    }
  });
});

function validateUsername(username) {
  const regex = /^[a-zA-Z0-9]{1,16}$/;
  return username && regex.test(username);
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
      dailyUsers.get(day).add(data.targetId); // Add targetId to unique users
      // Log connection with unique key
      const connectionKey = `${data.clientId}-${data.targetId}-${data.code}`;
      dailyConnections.get(day).add(connectionKey);
    }
  }
}

function updateLogFile() {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  const userCount = dailyUsers.get(day)?.size || 0;
  const connectionCount = dailyConnections.get(day)?.size || 0;
  const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}\n`;
  
  fs.appendFile(LOG_FILE, logEntry, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    } else {
      console.log(`Updated ${LOG_FILE} with ${userCount} unique users and ${connectionCount} WebRTC connections for ${day}`);
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

console.log(`Signaling server running on port ${process.env.PORT || 10000}`);
