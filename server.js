const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: process.env.PORT || 8080 });

const rooms = new Map(); // Map of room code to { clients: Map(clientId -> { ws, username }), maxClients, initiator }

wss.on('connection', ws => {
  console.log('New client connected');
  
  ws.on('message', message => {
    try {
      const data = JSON.parse(message);
      console.log('Received message:', data);

      if (data.type === 'join') {
        const code = data.code || generateCode();
        const username = data.username || 'anonymous';
        const clientId = generateClientId();

        if (!rooms.has(code)) {
          rooms.set(code, { clients: new Map(), maxClients: 2, initiator: clientId });
        }

        const room = rooms.get(code);
        if (room.clients.size >= room.maxClients) {
          console.log(`Room ${code} is full (max: ${room.maxClients})`);
          ws.send(JSON.stringify({ type: 'error', message: 'Chat is full' }));
          return;
        }

        for (const [existingId, { username: existingUsername }] of room.clients) {
          if (existingUsername === username && existingId !== clientId) {
            console.log(`Username ${username} already taken in room ${code}`);
            ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
            return;
          }
        }

        room.clients.set(clientId, { ws, username });
        console.log(`Client ${clientId} joined room ${code} with username: ${username}`);

        ws.send(JSON.stringify({
          type: 'init',
          clientId,
          maxClients: room.maxClients,
          isInitiator: room.initiator === clientId
        }));

        room.clients.forEach((client, id) => {
          if (client.ws.readyState === WebSocket.OPEN) {
            console.log(`Sending join-notify to client ${id} in room ${code}`);
            client.ws.send(JSON.stringify({
              type: 'join-notify',
              code,
              clientId,
              totalClients: room.clients.size,
              username
            }));
          }
        });
      }

      if (data.type === 'set-max-clients' && rooms.has(data.code)) {
        const room = rooms.get(data.code);
        if (room.initiator === data.clientId) {
          room.maxClients = parseInt(data.maxClients);
          console.log(`Room ${data.code} max clients set to ${room.maxClients}`);
          room.clients.forEach(client => {
            if (client.ws.readyState === WebSocket.OPEN) {
              client.ws.send(JSON.stringify({
                type: 'max-clients',
                maxClients: room.maxClients
              }));
            }
          });
        }
      }

      if (['offer', 'answer', 'candidate'].includes(data.type) && rooms.has(data.code)) {
        const room = rooms.get(data.code);
        const targetClient = room.clients.get(data.targetId);
        if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
          console.log(`Forwarding ${data.type} from ${data.clientId} to ${data.targetId} in room ${data.code}`);
          targetClient.ws.send(JSON.stringify({
            type: data.type,
            clientId: data.clientId,
            [data.type]: data[data.type],
            code: data.code
          }));
        } else {
          console.log(`Target client ${data.targetId} not found or not open in room ${data.code}`);
        }
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
    rooms.forEach((room, code) => {
      const clientEntry = [...room.clients].find(([id, client]) => client.ws === ws);
      if (clientEntry) {
        const [clientId, client] = clientEntry;
        room.clients.delete(clientId);
        console.log(`Client ${clientId} removed from room ${code}`);
        if (room.initiator === clientId && room.clients.size > 0) {
          const newInitiator = room.clients.keys().next().value;
          room.initiator = newInitiator;
          console.log(`New initiator for room ${code}: ${newInitiator}`);
          room.clients.forEach(client => {
            if (client.ws.readyState === WebSocket.OPEN) {
              client.ws.send(JSON.stringify({
                type: 'initiator-changed',
                newInitiator,
                code
              }));
            }
          });
        }
        room.clients.forEach(client => {
          if (client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
              type: 'client-disconnected',
              clientId,
              totalClients: room.clients.size,
              code
            }));
          }
        });
        if (room.clients.size === 0) {
          rooms.delete(code);
          console.log(`Room ${code} deleted (empty)`);
        }
      }
    });
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

function generateClientId() {
  return Math.random().toString(36).substr(2, 10);
}

console.log('WebSocket server running on port', process.env.PORT || 8080);
