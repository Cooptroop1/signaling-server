const WebSocket = require('ws');
const axios = require('axios');

const wss = new WebSocket.Server({ port: process.env.PORT || 10000 });
const rooms = new Map();
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const statsBuffer = [];
const STATS_FLUSH_INTERVAL = 60000; // Flush every 60s

wss.on('connection', (ws) => {
  let clientId, code, username;

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received:', data);

      if (data.type === 'connect') {
        clientId = data.clientId;
        ws.clientId = clientId;
        logStats({ clientId, event: 'connect' });
      }

      if (data.type === 'start') {
        clientId = data.clientId;
        username = data.username;
        code = data.code || generateCode();
        if (!rooms.has(code)) {
          rooms.set(code, { clients: new Map(), maxClients: 2 });
        }
        const room = rooms.get(code);
        if (room.clients.size >= room.maxClients) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room is full' }));
          return;
        }
        if (Array.from(room.clients.values()).some(c => c.username === username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
          return;
        }
        room.clients.set(clientId, { ws, username });
        ws.code = code;
        ws.username = username;
        ws.send(JSON.stringify({ type: 'code', code }));
        broadcast(code, { type: 'join', clientId, username, totalClients: room.clients.size });
        logStats({ clientId, username, code, event: 'start', totalClients: room.clients.size });
      }

      if (data.type === 'join') {
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        if (!rooms.has(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found' }));
          return;
        }
        const room = rooms.get(code);
        if (room.clients.size >= room.maxClients) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room is full' }));
          return;
        }
        if (Array.from(room.clients.values()).some(c => c.username === username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
          return;
        }
        room.clients.set(clientId, { ws, username });
        ws.code = code;
        ws.username = username;
        broadcast(code, { type: 'join', clientId, username, totalClients: room.clients.size });
        logStats({ clientId, username, code, event: 'join', totalClients: room.clients.size });
      }

      if (data.type === 'leave') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          room.clients.delete(data.clientId);
          logStats({ clientId: data.clientId, code: data.code, event: 'leave', totalClients: room.clients.size });
          if (room.clients.size === 0) {
            rooms.delete(data.code);
          } else {
            broadcast(data.code, { type: 'leave', clientId: data.clientId, totalClients: room.clients.size });
          }
        }
      }

      if (data.type === 'set-max-clients') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          room.maxClients = data.maxClients;
          broadcast(code, { type: 'set-max-clients', maxClients: data.maxClients, totalClients: room.clients.size });
          logStats({ clientId, code, event: 'set-max-clients', totalClients: room.clients.size, maxClients: data.maxClients });
        }
      }

      if (data.type === 'offer' || data.type === 'answer' || data.type === 'candidate') {
        if (rooms.has(data.code)) {
          const room = rooms.get(data.code);
          const target = room.clients.get(data.targetId);
          if (target && target.ws.readyState === WebSocket.OPEN) {
            target.ws.send(JSON.stringify(data));
          }
        }
      }

      if (data.type === 'stats') {
        logStats({
          clientId: data.clientId,
          username: data.username,
          code: data.code,
          connections: data.connections.reduce((sum, c) => sum + c.activeDataChannels, 0),
          event: data.event,
          totalClients: rooms.has(data.code) ? rooms.get(data.code).clients.size : 0
        });
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
        broadcast(ws.code, { type: 'leave', clientId: ws.clientId, totalClients: room.clients.size });
      }
    }
  });
});

async function logStats(data) {
  const timestamp = new Date().toISOString();
  const stats = {
    "clientId": data.clientId,
    "username": data.username || '',
    "code": data.code || '',
    "connections": data.connections || 0,
    "totalClients": data.totalClients || 0,
    "event": data.event || '',
    "timestamp": timestamp,
    "hour": `hour:${timestamp.slice(0, 13)}`,
    "day": `day:${timestamp.slice(0, 10)}`,
    "week": `week:${getWeek(timestamp)}`,
    "month": `month:${timestamp.slice(0, 7)}`,
    "year": `year:${timestamp.slice(0, 4)}`
  };
  statsBuffer.push(stats);
}

async function flushStats() {
  if (statsBuffer.length === 0) return;
  const content = statsBuffer.map(s => JSON.stringify(s)).join('\n') + '\n';
  try {
    const response = await axios.get('https://api.github.com/repos/cooptroop1/anonmess-stats/contents/stats.jsonl', {
      headers: { Authorization: `token ${GITHUB_TOKEN}`, Accept: 'application/vnd.github.v3+json' }
    });
    const sha = response.data.sha;
    await axios.put(
      'https://api.github.com/repos/cooptroop1/anonmess-stats/contents/stats.jsonl',
      {
        message: `Update stats for ${new Date().toISOString()}`,
        content: Buffer.from(content).toString('base64'),
        sha: sha,
        branch: 'main'
      },
      {
        headers: { Authorization: `token ${GITHUB_TOKEN}`, Accept: 'application/vnd.github.v3+json' }
      }
    );
    console.log(`Pushed ${statsBuffer.length} stats to GitHub`);
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

function getWeek(date) {
  const d = new Date(date);
  const start = new Date(d.getFullYear(), 0, 1);
  const day = Math.round((d - start) / 86400000);
  return Math.ceil((day + ((start.getDay() + 1) % 7)) / 7);
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
