const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const CERT_KEY_PATH = 'path/to/your/private-key.pem';
const CERT_PATH = 'path/to/your/fullchain.pem';
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const FEATURES_FILE = path.join('/data', 'features.json');
const STATS_FILE = path.join('/data', 'stats.json');
const UPDATE_INTERVAL = 30000;

const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) throw new Error('ADMIN_SECRET environment variable is not set.');

const ALLOWED_ORIGINS = ['https://anonomoose.com', 'https://www.anonomoose.com', 'http://localhost:3000', 'https://signaling-server-zc6m.onrender.com'];

const secretFile = path.join('/data', 'jwt_secret.txt');
const previousSecretFile = path.join('/data', 'previous_jwt_secret.txt');
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (fs.existsSync(secretFile)) {
    JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
  } else {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, JWT_SECRET);
    console.log('Generated new JWT secret and saved to disk.');
  }
}
if (fs.existsSync(secretFile)) {
  const stats = fs.statSync(secretFile);
  const mtime = stats.mtime.getTime();
  const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
  if (mtime < thirtyDaysAgo) {
    const previousSecret = JWT_SECRET;
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, JWT_SECRET);
    fs.writeFileSync(previousSecretFile, previousSecret);
    console.log('Rotated JWT secret. New secret saved, previous retained for grace period.');
  }
}

const TURN_USERNAME = process.env.TURN_USERNAME;
if (!TURN_USERNAME) throw new Error('TURN_USERNAME environment variable is not set.');

const TURN_CREDENTIAL = process.env.TURN_CREDENTIAL;
if (!TURN_CREDENTIAL) throw new Error('TURN_CREDENTIAL environment variable is not set.');

const IP_SALT = process.env.IP_SALT || 'your-random-salt-here';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const redisOptions = {
  retryStrategy(times) {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  reconnectOnError(err) {
    const targetError = 'READONLY';
    if (err.message.includes(targetError)) return true;
  }
};

module.exports = {
  CERT_KEY_PATH,
  CERT_PATH,
  LOG_FILE,
  FEATURES_FILE,
  STATS_FILE,
  UPDATE_INTERVAL,
  ADMIN_SECRET,
  ALLOWED_ORIGINS,
  JWT_SECRET,
  previousSecretFile,
  TURN_USERNAME,
  TURN_CREDENTIAL,
  IP_SALT,
  REDIS_URL,
  redisOptions
};
