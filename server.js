const WebSocket = require('ws');
const axios = require('axios');

const wss = new WebSocket.Server({ port: process.env.PORT || 10000 });
const rooms = new Map();
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const statsBuffer = [];
const STATS_FLUSH_INTERVAL = 60000; // Flush every 60s
const dailyUsers = new Map(); // Track unique clientIds per day

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

async function logStats(data) {
  const timestamp = new Date().toISOString();
  const day = timestamp.slice(0, 10);
  const stats = {
    clientId: data.clientId,
    username: data.username || '',
    code: data.code || '',
    event: data.event || '',
    totalClients: data.totalClients || 0,
    timestamp,
    day
  };
  statsBuffer.push(stats);

  if (data.event === 'connect' || data.event === 'join') {
    if (!dailyUsers.has(day)) {
      dailyUsers.set(day, new Set());
    }
    dailyUsers.get(day).add(data.clientId);
  }
}

async function flushStats() {
  if (statsBuffer.length === 0) return;

  let content = statsBuffer.map(s => JSON.stringify(s)).join('\n') + '\n';
  let sha;
  try {
    const response = await axios.get('https://api.github.com/repos/cooptroop1/anonmess-stats/contents/stats.jsonl', {
      headers: { Authorization: `token ${GITHUB_TOKEN}`, Accept: 'application/vnd.github.v3+json' }
    });
    sha = response.data.sha;
    const currentContent = Buffer.from(response.data.content, 'base64').toString('utf-8');
    content = currentContent + content;
  } catch (error) {
    if (error.response?.status === 404) {
      console.log('stats.jsonl not found, creating new file');
      sha = undefined; // New file, no sha
    } else {
      console.error('Error fetching stats file:', error.response?.data || error.message);
      return;
    }
  }

  try {
    await axios.put(
      'https://api.github.com/repos/cooptroop1/anonmess-stats/contents/stats.jsonl',
      {
        message: `Update stats for ${new Date().toISOString()}`,
        content: Buffer.from(content).toString('base64'),
        sha,
        branch: 'main'
      },
      {
        headers: { Authorization: `token ${GITHUB_TOKEN}`, Accept: 'application/vnd.github.v3+json' }
      }
    );
    console.log(`Pushed ${statsBuffer.length} stats to GitHub`);

    const day = new Date().toISOString().slice(0, 10);
    if (dailyUsers.has(day)) {
      const userCount = dailyUsers.get(day).size;
      console.log(`Daily unique users for ${day}: ${userCount}`);
      statsBuffer.push({
        event: 'daily-users',
        day,
        userCount,
        timestamp: new Date().toISOString()
      });
      dailyUsers.delete(day);
    }

    statsBuffer.length = 0;
  } catch (error) {
    console.error('Error pushing stats:', error.response?.data || error.message);
  }
}

setInterval(flushStats, STATS_FLUSH_INTERVAL);

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

console.log(`Signaling server running on port ${process.env.PORT || 10000}`);
