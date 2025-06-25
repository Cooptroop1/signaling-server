const WebSocket = require('ws');
const wss = new WebSocket.Server({ host: '0.0.0.0', port: process.env.PORT || 10000 });

// Store clients by code
const clients = new Map();

wss.on('connection', (ws) => {
  let clientCode = null;

  ws.on('message', (data) => {
    // Convert Buffer to string
    const message = data.toString('utf8');
    console.log('Received message:', message);

    try {
      const parsed = JSON.parse(message);
      if (parsed.type === 'join' && parsed.code) {
        clientCode = parsed.code;
        if (!clients.has(clientCode)) {
          clients.set(clientCode, new Set());
        }
        clients.get(clientCode).add(ws);
        console.log(`Client joined code: ${clientCode}, total clients: ${clients.get(clientCode).size}`);
      } else {
        // Forward message to other clients with the same code
        if (clientCode && clients.has(clientCode)) {
          clients.get(clientCode).forEach((client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
              client.send(message);
              console.log(`Forwarded message to client in code: ${clientCode}`);
            }
          });
        }
      }
    } catch (error) {
      console.error('Error processing message:', error.message);
    }
  });

  ws.on('close', () => {
    if (clientCode && clients.has(clientCode)) {
      clients.get(clientCode).delete(ws);
      console.log(`Client disconnected from code: ${clientCode}, remaining: ${clients.get(clientCode).size}`);
      if (clients.get(clientCode).size === 0) {
        clients.delete(clientCode);
      }
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

console.log(`Signaling server running on port ${process.env.PORT || 10000}`);
