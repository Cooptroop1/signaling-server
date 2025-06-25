const WebSocket = require('ws');
const wss = new WebSocket.Server({ host: '0.0.0.0', port: process.env.PORT || 10000 });

// Store rooms by code
const rooms = new Map();

wss.on('connection', (ws) => {
  let clientCode = null;
  let clientId = Math.random().toString(36).slice(2); // Unique client ID
  ws.clientId = clientId;

  ws.on('message', (data) => {
    const message = data.toString('utf8');
    console.log(`Received message from ${clientId}:`, message);

    try {
      const parsed = JSON.parse(message);
      if (parsed.type === 'join' && parsed.code) {
        clientCode = parsed.code;
        if (!rooms.has(clientCode)) {
          rooms.set(clientCode, {
            clients: new Set(),
            maxClients: 2, // Default 1-on-1
            initiator: null
          });
        }
        const room = rooms.get(clientCode);
        // Set initiator as first client
        if (!room.initiator) {
          room.initiator = clientId;
          ws.initiator = true;
          console.log(`Set initiator ${clientId} for code: ${clientCode}`);
        }
        // Check client limit
        if (room.clients.size >= room.maxClients) {
          console.log(`Code ${clientCode} is full (max ${room.maxClients}), rejecting join`);
          ws.send(JSON.stringify({ type: 'error', message: `Chat is full, max ${room.maxClients} users allowed` }));
          ws.close();
          return;
        }
        // Add client
        room.clients.add(ws);
        console.log(`Client ${clientId} joined code: ${clientCode}, total clients: ${room.clients.size}`);
        // Send client ID and maxClients to joining client
        ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients }));
        // Notify others
        if (room.clients.size === 2) {
          room.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ type: 'join-notify', code: clientCode }));
              console.log(`Sent join-notify for code: ${clientCode}`);
            }
          });
        }
        // Broadcast new client to others
        room.clients.forEach((client) => {
          if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'join-client', code: clientCode, clientId }));
            console.log(`Notified client of join ${clientId} for code: ${clientCode}`);
          }
        });
      } else if (parsed.type === 'set-max-clients' && clientCode) {
        const room = rooms.get(clientCode);
        if (!room) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid room' }));
          return;
        }
        // Only initiator can set max clients
        if (ws.initiator && ws.clientId === room.initiator) {
          const newMax = Math.max(2, Math.min(10, parseInt(parsed.maxClients)));
          room.maxClients = newMax;
          console.log(`Initiator set maxClients to ${newMax} for code: ${clientCode}`);
          // Notify all clients
          room.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ type: 'max-clients', maxClients: newMax }));
            }
          });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set max clients' }));
        }
      } else if (['offer', 'answer', 'candidate'].includes(parsed.type)) {
        if (!clientCode || !rooms.has(clientCode)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code or no room' }));
          return;
        }
        const room = rooms.get(clientCode);
        if (parsed.targetId) {
          room.clients.forEach((client) => {
            if (client.clientId === parsed.targetId && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ ...parsed, clientId: ws.clientId }));
              console.log(`Forwarded ${parsed.type} to ${parsed.targetId} in code: ${clientCode}`);
            }
          });
        } else {
          room.clients.forEach((client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ ...parsed, clientId: ws.clientId }));
              console.log(`Broadcasted ${parsed.type} from ${ws.clientId} in code: ${clientCode}`);
            }
          });
        }
      }
    } catch (error) {
      console.error(`Error processing message from ${clientId}:`, error);
    }
  });

  ws.on('close', () => {
    if (clientCode && rooms.has(clientCode)) {
      const room = rooms.get(clientCode);
      room.clients.delete(ws);
      console.log(`Client ${clientId} disconnected from code: ${clientCode}, remaining: ${room.clients.size}`);
      // Notify others
      room.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'client-disconnected', clientId }));
          console.log(`Notified client of disconnect ${clientId} in code: ${clientCode}`);
        }
      });
      // Clean up
      if (room.clients.size === 0) {
        rooms.delete(clientCode);
        console.log(`Cleared code: ${clientCode}`);
      } else if (ws.initiator) {
        room.initiator = null;
        room.maxClients = 2;
        room.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'max-clients', maxClients: 2 }));
            console.log(`Reset maxClients to 2 for code: ${clientCode}`);
          }
        });
      }
    }
  });

  ws.on('error', (error) => {
    console.error(`WebSocket error for ${clientId}:`, error);
  });
});

console.log(`Signaling server running on port ${process.env.PORT || 10000}`);
