const WebSocket = require('ws');
const wss = new WebSocket.Server({ host: '0.0.0.0', port: process.env.PORT || 10000 });

const rooms = new Map(); // code -> { initiator: clientId, clients: Map(ws -> clientId), maxClients, usernames: Map() }
const clientIds = new Map(); // ws -> clientId
const codes = new Map(); // ws -> code

function generateClientId() {
  return Math.random().toString(36).slice(2);
}

function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
    if (i % 4 === 3 && i < 15) result += '-';
  }
  return result;
}

wss.on('connection', (ws) => {
  const clientId = generateClientId();
  ws.clientId = clientId;
  ws.isInitiator = false;

  console.log(`Client ${clientId} connected`);

  ws.on('message', (data) => {
    const message = data.toString('utf8').trim();
    console.log(`Received message from ${clientId}:`, message);

    try {
      const parsed = JSON.parse(message);

      if (parsed.type === 'join' && parsed.code) {
        let clientCode = parsed.code;
        let username = parsed.username?.trim();

        if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9]{1,16}$/.test(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters required.' }));
          return;
        }

        if (!rooms.has(clientCode)) {
          rooms.set(clientCode, { initiator: null, clients: new Map(), maxClients: 2, usernames: new Map() });
        }

        const room = rooms.get(clientCode);

        if (Array.from(room.usernames.values()).includes(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this chat.' }));
          return;
        }

        if (room.clients.size >= room.maxClients && !room.clients.has(ws)) {
          ws.send(JSON.stringify({ type: 'error', message: `Chat is full, max ${room.maxClients} users allowed.` }));
          ws.close();
          return;
        }

        if (!clientIds.has(ws)) {
          clientIds.set(ws, clientId);
          codes.set(ws, clientCode);
          room.clients.set(ws, clientId);
          room.usernames.set(clientId, username);
          console.log(`Client ${clientId} joined code: ${clientCode} with username: ${username}, total clients: ${room.clients.size}`);

          if (!room.initiator || !room.clients.has(Array.from(room.clients.entries()).find(([_, id]) => id === room.initiator)?.[0])) {
            room.initiator = clientId;
            ws.isInitiator = true;
            console.log(`Set initiator ${clientId} for code: ${clientCode}`);
            ws.send(JSON.stringify({
              type: 'initiate',
              maxClients: room.maxClients,
              isInitiator: true
            }));
          } else {
            ws.send(JSON.stringify({
              type: 'initiate',
              clientId,
              maxClients: room.maxClients,
              isInitiator: false
            }));
          }

          broadcast(clientCode, {
            type: 'join-notify',
            clientId,
            totalClients: room.clients.size,
            code: clientCode,
            username
          });
        }
      } else if (parsed.type === 'set-max-clients' && codes.get(ws)) {
        const clientCode = codes.get(ws);
        const room = rooms.get(clientCode);
        if (!room) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid room' }));
          return;
        }
        if (ws.isInitiator && ws.clientId === room.initiator) {
          const newMax = Math.max(2, Math.min(10, parseInt(parsed.maxClients)));
          room.maxClients = newMax;
          console.log(`Initiator ${ws.clientId} set maxClients to ${newMax} for code: ${clientCode}`);
          broadcast(clientCode, { type: 'max-clients', maxClients: newMax });
        } else {
          console.log(`Client ${ws.clientId} attempted to set maxClients but is not initiator: isInitiator=${ws.isInitiator}, room.initiator=${room.initiator}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set max clients' }));
        }
      } else if (['offer', 'answer', 'candidate'].includes(parsed.type)) {
        const clientCode = codes.get(ws);
        if (!clientCode || !rooms.has(clientCode)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code or no room' }));
          return;
        }
        const room = rooms.get(clientCode);
        if (parsed.targetId) {
          const targetWs = Array.from(room.clients.entries()).find(([client, id]) => id === parsed.targetId)?.[0];
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ ...parsed, clientId: ws.clientId }));
            console.log(`Forwarded ${parsed.type} from ${ws.clientId} to ${parsed.targetId} in code: ${clientCode}`);
          }
        } else {
          room.clients.forEach((_, client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ ...parsed, clientId: ws.clientId }));
              console.log(`Broadcasted ${parsed.type} from ${ws.clientId} to ${client.clientId} in code: ${clientCode}`);
            }
          });
        }
      }
    } catch (error) {
      console.error(`Error processing message from ${clientId}:`, error);
    }
  });

  ws.on('close', () => {
    const clientCode = codes.get(ws);
    if (clientCode && rooms.has(clientCode)) {
      const room = rooms.get(clientCode);
      room.clients.delete(ws);
      room.usernames.delete(clientId);
      console.log(`Client ${clientId} disconnected from code: ${clientCode}, remaining: ${room.clients.size}`);
      clientIds.delete(ws);
      codes.delete(ws);

      if (room.clients.size === 0) {
        rooms.delete(clientCode);
        console.log(`Cleared code: ${clientCode}`);
      } else {
        broadcast(clientCode, {
          type: 'client-disconnected',
          clientId,
          totalClients: room.clients.size
        });
        if (ws.isInitiator && clientId === room.initiator) {
          room.initiator = null;
          if (room.clients.size > 0) {
            const newInitiatorWs = Array.from(room.clients.entries())[0][0];
            const newInitiatorId = newInitiatorWs.clientId;
            newInitiatorWs.isInitiator = true;
            room.initiator = newInitiatorId;
            console.log(`Assigned new initiator ${newInitiatorId} for code: ${clientCode}`);
            newInitiatorWs.send(JSON.stringify({
              type: 'initiate',
              clientId: newInitiatorId,
              maxClients: room.maxClients,
              isInitiator: true
            }));
            room.clients.forEach((_, client) => {
              if (client !== newInitiatorWs && client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ type: 'initiator-changed', newInitiator: newInitiatorId }));
              }
            });
          }
        }
      }
    }
  });

  ws.on('error', (error) => {
    console.error(`WebSocket error for ${clientId}:`, error);
  });
});

function broadcast(code, data) {
  const room = rooms.get(code);
  if (room) {
    room.clients.forEach((_, client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  }
}

console.log(`Signaling server running on port ${process.env.PORT || 10000}`);
