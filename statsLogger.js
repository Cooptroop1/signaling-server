const fs = require('fs');
const path = require('path');
const config = require('./config');

let aggregatedStats = fs.existsSync(config.STATS_FILE) ? JSON.parse(fs.readFileSync(config.STATS_FILE, 'utf8')) : { daily: {} };

function logStats(data, redis, LOG_FILE) {
  const timestamp = new Date().toISOString();
  const day = timestamp.slice(0, 10);
  const stats = {
    clientId: data.clientId,
    username: data.username || '',
    targetId: data.targetId || '',
    code: data.code || '',
    event: data.event || '',
    totalClients: data.totalClients || 0,
    isInitiator: data.isInitiator || false,
    timestamp,
    day
  };

  (async () => {
    try {
      if (data.event === 'connect' || data.event === 'join' || data.event === 'webrtc-connection') {
        await redis.sadd(`dailyUsers:${day}`, data.clientId);
        await redis.pfadd('allTimeUsers', data.clientId);
        if (data.event === 'webrtc-connection' && data.targetId) {
          await redis.sadd(`dailyUsers:${day}`, data.targetId);
          await redis.pfadd('allTimeUsers', data.targetId);
          const connectionKey = `${data.clientId}-${data.targetId}-${data.code}`;
          await redis.sadd(`dailyConnections:${day}`, connectionKey);
        }
      }
    } catch (err) {
      console.error('Error logging stats to Redis:', err);
    }
  })();

  const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}\n`;
  fs.appendFileSync(LOG_FILE, logEntry);
}

async function computeAggregate(days, redis) {
  const now = new Date();
  let users = 0, connections = 0;
  for (let i = 0; i < days; i++) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const key = date.toISOString().slice(0, 10);
    try {
      users += await redis.scard(`dailyUsers:${key}`) || 0;
      connections += await redis.scard(`dailyConnections:${key}`) || 0;
    } catch (err) {
      console.error('Error computing aggregate:', err);
    }
  }
  return { users, connections };
}

function updateLogFile(redis, LOG_FILE, aggregatedStats, STATS_FILE) {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  (async () => {
    try {
      const userCount = await redis.scard(`dailyUsers:${day}`) || 0;
      const connectionCount = await redis.scard(`dailyConnections:${day}`) || 0;
      const allTimeUserCount = await redis.pfcount('allTimeUsers') || 0;
      const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}, All-Time Unique Users: ${allTimeUserCount}\n`;
      fs.appendFileSync(LOG_FILE, logEntry);
      console.log(`Updated ${LOG_FILE} with ${userCount} unique users, ${connectionCount} WebRTC connections, and ${allTimeUserCount} all-time unique users for ${day}`);
      if (!aggregatedStats.daily) aggregatedStats.daily = {};
      aggregatedStats.daily[day] = { users: userCount, connections: connectionCount };
      fs.writeFileSync(STATS_FILE, JSON.stringify(aggregatedStats));
      console.log('Saved aggregated stats to disk');
    } catch (err) {
      console.error('Error updating log file:', err);
    }
  })();
}

function hashIp(ip, IP_SALT) {
  return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
}

module.exports = { logStats, computeAggregate, updateLogFile, hashIp };
