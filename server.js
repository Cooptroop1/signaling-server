```javascript
const express = require('express');
const fetch = require('node-fetch');
const WebSocket = require('ws');
const app = express();

app.get('/get-turn-credentials', async (req, res) => {
  try {
    const response = await fetch('https://anonmess.metered.live/api/v1/turn/credentials?apiKey=20409a1726332ccf335585493153f4e3eafb');
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const iceServers = await response.json();
    res.json(iceServers);
  } catch (error) {
    console.error('Error fetching TURN credentials:', error);
    res.status(500).json({ error: 'Failed to fetch TURN credentials' });
  }
});

const server = app.listen(process.env.PORT || 3000);
const wss = new WebSocket.Server({ server });

let rooms = new Map();

wss.on('connection', (ws) => {
  console.log('New WebSocket client connected');
  let clientId = Math.random().toString(36).substr(2, 9);
  let roomCode = null;
  let username = null;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received message:', data);

      if (data.type === 'join') {
        roomCode = data.code || generateCode();
        username = data.username;
        if (!rooms.has(roomCode)) {
          rooms.set(roomCode, { clients: new Map(), maxClients: 2, initiator: clientId });
        }
        const room = rooms.get(roomCode);
        if (room.clients.size >= room.maxClients) {
          ws.send(JSON.stringify({ type: 'error', message: 'Chat is full' }));
          ws.close();
          return;
        }
        if (username && Array.from(room.clients.values()).some(client => client.username === username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
          ws.close();
          return;
        }
        room.clients.set(clientId, { ws, username });
        ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: clientId === room.initiator }));
        room.clients.forEach((client, id) => {
          if (id !== clientId) {
            client.ws.send(JSON.stringify({ type: 'join-notify', code: roomCode, clientId, totalClients: room.clients.size, username }));
            ws.send(JSON.stringify({ type: 'join-notify', code: roomCode, clientId: id, totalClients: room.clients.size, username: client.username }));
          }
        });
      } else if (data.type === 'set-max-clients' && roomCode) {
        const room = rooms.get(roomCode);
        if (room && clientId === room.initiator) {
          room.maxClients = data.maxClients;
          room.clients.forEach(client => {
            client.ws.send(JSON.stringify({ type: 'max-clients', maxClients: room.maxClients }));
          });
        }
      } else if (data.type === 'offer' && roomCode) {
        const room = rooms.get(roomCode);
        if (room && room.clients.has(data.targetId)) {
          room.clients.get(data.targetId).ws.send(JSON.stringify({ type: 'offer', offer: data.offer, clientId }));
        }
      } else if (data.type === 'answer' && roomCode) {
        const room = rooms.get(roomCode);
        if (room && room.clients.has(data.targetId)) {
          room.clients.get(data.targetId).ws.send(JSON.stringify({ type: 'answer', answer: data.answer, clientId }));
        }
      } else if (data.type === 'candidate' && roomCode) {
        const room = rooms.get(roomCode);
        if (room && room.clients.has(data.targetId)) {
          room.clients.get(data.targetId).ws.send(JSON.stringify({ type: 'candidate', candidate: data.candidate, clientId }));
        }
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });

  ws.on('close', () => {
    console.log(`Client ${clientId} disconnected`);
    if (roomCode) {
      const room = rooms.get(roomCode);
      if (room) {
        room.clients.delete(clientId);
        if (room.clients.size === 0) {
          rooms.delete(roomCode);
        } else {
          if (clientId === room.initiator && room.clients.size > 0) {
            room.initiator = Array.from(room.clients.keys())[0];
            room.clients.forEach(client => {
              client.ws.send(JSON.stringify({ type: 'initiator-changed', newInitiator: room.initiator }));
            });
          }
          room.clients.forEach(client => {
            client.ws.send(JSON.stringify({ type: 'client-disconnected', clientId, totalClients: room.clients.size }));
          });
        }
      }
    }
  });
});

function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
    if (i % 4 === 3 && i < 15) result += '-';
  }
  return result;
}
```
