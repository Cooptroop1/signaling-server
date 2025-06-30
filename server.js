
const WebSocket = require('ws');
const axios = require('axios');

const wss = new WebSocket.Server({ port: process.env.PORT || 10000 });
const rooms = {};
const githubToken = process.env.GITHUB_TOKEN || 'your-github-token';
const githubRepo = 'cooptroop1/anonmess-stats';
const statsFilePath = 'stats.jsonl';

async function logStats(stats) {
    const now = new Date();
    const hourKey = `hour:${now.toISOString().slice(0, 13)}`;
    const dayKey = `day:${now.toISOString().slice(0, 10)}`;
    const weekKey = `week:${now.getFullYear()}-${Math.ceil((now.getDate() + (new Date(now.getFullYear(), now.getMonth(), 1).getDay() + 6) % 7) / 7)}`;
    const monthKey = `month:${now.toISOString().slice(0, 7)}`;
    const yearKey = `year:${now.getFullYear()}`;
    const totalConnections = stats.connections.reduce((sum, conn) => sum + conn.activeDataChannels, 0);

    const logEntry = JSON.stringify({
        clientId: stats.clientId,
        username: stats.username,
        code: stats.code,
        connections: totalConnections,
        timestamp: now.toISOString(),
        hour: hourKey,
        day: dayKey,
        week: weekKey,
        month: monthKey,
        year: yearKey
    }) + '\n';

    // Fetch current file content and SHA
    let sha;
    try {
        const response = await axios.get(`https://api.github.com/repos/${githubRepo}/contents/${statsFilePath}`, {
            headers: {
                Authorization: `Bearer ${githubToken}`,
                Accept: 'application/vnd.github.v3+json'
            }
        });
        sha = response.data.sha;
        const currentContent = Buffer.from(response.data.content, 'base64').toString('utf-8');
        logEntry = currentContent + logEntry;
    } catch (error) {
        if (error.response?.status !== 404) {
            console.error('GitHub API error fetching file:', error);
            return;
        }
    }

    // Update file via GitHub API
    try {
        await axios.put(`https://api.github.com/repos/${githubRepo}/contents/${statsFilePath}`, {
            message: `Update stats ${now.toISOString()}`,
            content: Buffer.from(logEntry).toString('base64'),
            sha: sha,
            branch: 'main'
        }, {
            headers: {
                Authorization: `Bearer ${githubToken}`,
                Accept: 'application/vnd.github.v3+json'
            }
        });
        console.log('Pushed stats to GitHub');
    } catch (error) {
        console.error('GitHub API error updating file:', error);
    }
}

function generateCode() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let code = '';
    for (let i = 0; i < 16; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
        if (i % 4 === 3 && i < 15) code += '-';
    }
    return code;
}

wss.on('connection', async (ws) => {
    let clientId = null;

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            console.log('Received:', message);

            if (message.type === 'connect') {
                clientId = message.clientId;
                await logStats({ clientId, username: '', code: '', connections: [] });
            } else if (message.type === 'start') {
                const code = generateCode();
                rooms[code] = rooms[code] || [];
                rooms[code].push({ ws, clientId: message.clientId, username: message.username });
                ws.send(JSON.stringify({ type: 'code', code }));
            } else if (message.type === 'join') {
                const { code, clientId, username } = message;
                if (rooms[code]) {
                    if (rooms[code].length >= 10) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Room is full (max 10 clients)' }));
                        return;
                    }
                    rooms[code].push({ ws, clientId, username });
                    rooms[code].forEach(client => {
                        if (client.clientId !== clientId) {
                            client.ws.send(JSON.stringify({
                                type: 'join',
                                clientId,
                                username
                            }));
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Room not found' }));
                }
            } else if (message.type === 'offer' || message.type === 'answer' || message.type === 'candidate') {
                const { to, code } = message;
                if (rooms[code]) {
                    const recipient = rooms[code].find(client => client.clientId === to);
                    if (recipient) {
                        recipient.ws.send(JSON.stringify(message));
                    }
                }
            } else if (message.type === 'leave') {
                const { code, clientId } = message;
                if (rooms[code]) {
                    rooms[code] = rooms[code].filter(client => client.clientId !== clientId);
                    rooms[code].forEach(client => {
                        client.ws.send(JSON.stringify({ type: 'leave', clientId }));
                    });
                    if (rooms[code].length === 0) delete rooms[code];
                }
                await logStats({ clientId, username: '', code, connections: [] });
            } else if (message.type === 'stats') {
                await logStats(message);
            }
        } catch (error) {
            console.error('Error processing message:', error);
        }
    });

    ws.on('close', async () => {
        for (const code in rooms) {
            rooms[code] = rooms[code].filter(client => client.ws !== ws);
            if (clientId) {
                rooms[code].forEach(client => {
                    client.ws.send(JSON.stringify({ type: 'leave', clientId }));
                });
                if (rooms[code].length === 0) delete rooms[code];
                await logStats({ clientId, username: '', code, connections: [] });
            }
        }
    });
});

console.log('Signaling server running on port', process.env.PORT || 10000);
