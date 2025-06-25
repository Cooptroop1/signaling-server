const WebSocket = require('ws');
const wss = new WebSocket.Server({ host: '0.0.0.0', port: process.env.PORT || 10000 });

wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    // Convert Buffer to string
    const message = data.toString('utf8');
    wss.clients.forEach((client) => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  });
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

console.log(`Signaling server running on port ${process.env.PORT || 10000}`);
