
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const otplib = require('otplib');
const UAParser = require('ua-parser-js');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const redis = require('redis');
const winston = require('winston');
// Hash password
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}
// Validate password
async function validatePassword(input, hash) {
  return bcrypt.compare(input, hash);
}
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://crgmcdpmmxtrcocfbsac.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNyZ21jZHBtbXh0cmNvY2Zic2FjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2NjI4NTksImV4cCI6MjA4OTIzODg1OX0.pgEIhCIRKEjmwgIQVeQtXdzIWZu2diPXr-gjpvV7pGs';
const claimedLoginCache = new Map();
const pingRate = new Map();
const checkoutRate = new Map();
const deskRate = new Map();
function rateOk(map, key, max, windowMs) {
  const now = Date.now();
  const rec = map.get(key) || { n: 0, t: now };
  if (now - rec.t > windowMs) { rec.n = 0; rec.t = now; }
  rec.n += 1;
  map.set(key, rec);
  return rec.n <= max;
}
function bearerFrom(req, body) {
  const h = String((req && req.headers && req.headers.authorization) || '');
  if (/^Bearer\s+\S+/i.test(h)) return h.replace(/^Bearer\s+/i, '').trim();
  if (body && typeof body.access === 'string') return String(body.access).trim();
  return '';
}
async function verifySbUser(sbAccess) {
  if (!sbAccess || typeof sbAccess !== 'string' || sbAccess.length < 40 || sbAccess.length > 8000) return null;
  const cacheKey = crypto.createHash('sha256').update(sbAccess).digest('hex').slice(0, 24);
  const hit = claimedLoginCache.get(cacheKey);
  if (hit && hit.exp > Date.now()) return hit.user || null;
  try {
    const r = await fetch(SUPABASE_URL + '/auth/v1/user', {
      headers: {
        Authorization: 'Bearer ' + sbAccess,
        apikey: SUPABASE_ANON_KEY
      }
    });
    if (!r.ok) {
      claimedLoginCache.set(cacheKey, { ok: false, user: null, exp: Date.now() + 30000 });
      return null;
    }
    const raw = await r.json();
    const user = raw && raw.id ? { id: raw.id, email: raw.email || '' } : null;
    claimedLoginCache.set(cacheKey, { ok: !!user, user, exp: Date.now() + 120000 });
    if (claimedLoginCache.size > 500) {
      const now = Date.now();
      for (const [k, v] of claimedLoginCache) {
        if (v.exp < now) claimedLoginCache.delete(k);
      }
    }
    return user;
  } catch (e) {
    return null;
  }
}
async function verifyClaimedLogin(sbAccess) {
  const user = await verifySbUser(sbAccess);
  return !!user;
}
async function userOwnsName(userId, name, userAccess) {
  const nm = String(name || '').toLowerCase();
  if (!userId || !nm) return false;
  const token = SUPABASE_SERVICE_ROLE_KEY || userAccess;
  const key = SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY;
  if (!token) return false;
  const headers = { apikey: key, Authorization: 'Bearer ' + token };
  try {
    const r = await fetch(SUPABASE_URL + '/rest/v1/owned_names?user_id=eq.' + encodeURIComponent(userId) + '&select=name', { headers });
    const rows = await r.json();
    if (Array.isArray(rows) && rows.some((x) => String(x.name || '').toLowerCase() === nm)) return true;
  } catch (e) {}
  try {
    const r = await fetch(SUPABASE_URL + '/rest/v1/profiles?id=eq.' + encodeURIComponent(userId) + '&select=display_name', { headers });
    const rows = await r.json();
    if (Array.isArray(rows) && rows[0] && String(rows[0].display_name || '').toLowerCase() === nm) return true;
  } catch (e) {}
  return false;
}
// Main logger for general operations
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ filename: path.join(__dirname, 'combined.log') }),
    new winston.transports.File({ filename: path.join(__dirname, 'error.log'), level: 'error' })
  ]
});
// User stats logger (appends to user_counts.log without rotation)
const userLogger = winston.createLogger({
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({ filename: path.join(__dirname, 'user_counts.log') })
  ]
});
// Audit logger without rotation
const auditLogger = winston.createLogger({
  format: winston.format.simple(),
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, 'audit.log')
    })
  ]
});
const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // For Render Postgres
});
// Test DB connection on startup
dbPool.connect(async (err) => {
  if (err) {
    logger.error('DB connection error: %s %s', err.message, err.stack);
  } else {
    logger.info('Connected to DB successfully');
    await dbPool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_public_key TEXT');
    try {
      await dbPool.query('ALTER TABLE offline_messages ALTER COLUMN from_user_id DROP NOT NULL');
    } catch (e) {
      logger.warn('Could not relax offline_messages.from_user_id: %s', e.message);
    }
    await loadFeatures();
    await loadAggregatedStats();
  }
});
// Clean up old offline messages (TTL: 24 hours)
setInterval(async () => {
  try {
    await dbPool.query('DELETE FROM offline_messages WHERE created_at < NOW() - INTERVAL \'24 hours\'');
    logger.info('Cleaned up expired offline messages');
  } catch (err) {
    logger.error('Error cleaning up offline messages: %s %s', err.message, err.stack);
  }
}, 24 * 60 * 60 * 1000); // Run daily
// Added: Redis setup
const redisClient = redis.createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379' // Use env var from Render
});
redisClient.on('error', err => logger.error('Redis Client Error %o', err));
const pubClient = redisClient;
const subClient = redisClient.duplicate();
let webpush = null;
try { webpush = require('web-push'); } catch (e) { logger.warn('web-push not installed'); }
const VAPID_PUBLIC = process.env.VAPID_PUBLIC || 'BNKkuUrHAmam_htLZqI0Nb-J9vw4bWipcd5t_U1KNPGIfM-IuqgVKOYDzgxaELSyFoD1k1VG23HFPwl3rg_2zyQ';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || '5-E26pjHBd9TwjyCFvuRQs-ShLurnt7z3F81h55tRFs';
if (webpush) {
  try { webpush.setVapidDetails('mailto:hello@anonomoose.com', VAPID_PUBLIC, VAPID_PRIVATE); } catch (e) { logger.warn('vapid setup %s', e.message); }
}
let stripe = null;
const stripeKey = String(process.env.STRIPE_SECRET_KEY || '').trim();
try {
  if (stripeKey) stripe = require('stripe')(stripeKey);
} catch (e) { logger.warn('stripe %s', e.message); }
if (stripe) logger.info('Stripe mode %s', stripeKey.startsWith('sk_live_') ? 'LIVE' : (stripeKey.startsWith('sk_test_') ? 'TEST (swap to sk_live_ on Render)' : 'set'));
const SUPABASE_SERVICE_ROLE_KEY = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim().replace(/^["']|["']$/g, '');
logger.info('Vanity service role %s', SUPABASE_SERVICE_ROLE_KEY ? 'present' : 'MISSING');

async function supabaseAs(path, method, payload, bearer) {
  const key = (bearer || SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!key) throw new Error('No key to write name');
  const r = await fetch(SUPABASE_URL + path, {
    method: method || 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY,
      Authorization: 'Bearer ' + key,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal'
    },
    body: payload ? JSON.stringify(payload) : undefined
  });
  const text = await r.text();
  if (r.ok || r.status === 409) return { ok: true, status: r.status };
  let msg = text;
  try { const j = JSON.parse(text); msg = j.message || j.error || j.hint || j.details || text; } catch (e) {}
  throw new Error(msg || ('Supabase ' + r.status));
}

async function attachPaidName(userId, name, sessionId, amount) {
  const nm = String(name || '').replace(/[^A-Za-z0-9]/g, '');
  if (!userId || !nm) throw new Error('Missing name');
  if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error('Could not save the name you paid for');
  const kind = /^\d+$/.test(nm) ? 'number' : 'letter';
  const headers = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: 'Bearer ' + SUPABASE_SERVICE_ROLE_KEY,
    'Content-Type': 'application/json',
    Prefer: 'return=representation'
  };
  try {
    await fetch(SUPABASE_URL + '/rest/v1/vanity_receipts', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        session_id: sessionId || ('sess-' + Date.now()),
        user_id: userId,
        name: nm,
        amount_cents: amount || 0
      })
    });
  } catch (e) {}
  const ownedRes = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?name=ilike.' + encodeURIComponent(nm) + '&select=name,user_id',
    { headers }
  );
  const ownedRows = await ownedRes.json();
  const owned = Array.isArray(ownedRows)
    ? ownedRows.find((x) => String(x.name || '').toLowerCase() === nm.toLowerCase())
    : null;
  if (owned && owned.user_id && owned.user_id !== userId) throw new Error('Already owned');
  if (!owned) {
    const ins = await fetch(SUPABASE_URL + '/rest/v1/owned_names', {
      method: 'POST',
      headers,
      body: JSON.stringify({ name: nm, user_id: userId, kind })
    });
    if (!ins.ok && ins.status !== 409) {
      const t = await ins.text();
      logger.warn('owned_names insert %s', t && t.slice(0, 180));
      throw new Error('Could not save the name you paid for');
    }
  }
  if (kind === 'number') {
    const num = parseInt(nm, 10);
    await fetch(SUPABASE_URL + '/rest/v1/vanity_numbers?n=eq.' + num, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ status: 'sold', owner_id: userId, updated_at: new Date().toISOString() })
    });
  } else {
    const lr = await fetch(SUPABASE_URL + '/rest/v1/vanity_letters?name=eq.' + encodeURIComponent(nm) + '&select=name', { headers });
    const lrows = await lr.json();
    if (Array.isArray(lrows) && lrows.length) {
      await fetch(SUPABASE_URL + '/rest/v1/vanity_letters?name=eq.' + encodeURIComponent(nm), {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ status: 'sold', owner_id: userId })
      });
    } else {
      await fetch(SUPABASE_URL + '/rest/v1/vanity_letters', {
        method: 'POST',
        headers,
        body: JSON.stringify({ name: nm, status: 'sold', owner_id: userId, price_cents: amount || 1000 })
      });
    }
  }
  const check = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?user_id=eq.' + encodeURIComponent(userId) + '&name=ilike.' + encodeURIComponent(nm) + '&select=name',
    { headers }
  );
  const rows = await check.json();
  if (Array.isArray(rows) && rows.length) return { ok: true, name: nm };
  throw new Error('Could not save the name you paid for');
}

async function lookupVanityAmount(kind, name) {
  const headers = { apikey: SUPABASE_ANON_KEY, Authorization: 'Bearer ' + SUPABASE_ANON_KEY };
  if (kind === 'number') {
    const n = parseInt(name, 10);
    if (!n || n < 1 || n > 999) return { error: 'That number is not for sale' };
    const vr = await fetch(SUPABASE_URL + '/rest/v1/vanity_numbers?n=eq.' + n + '&select=buy_now_cents,price_cents,held_forever,status', { headers });
    const rows = await vr.json();
    const row = Array.isArray(rows) ? rows[0] : null;
    if (row && (row.held_forever || row.status === 'sold')) return { error: 'That number is not for sale' };
    const amount = Math.max(Number(row && row.buy_now_cents) || 0, Number(row && row.price_cents) || 0) || (n <= 9 ? 1000000 : n <= 99 ? 50000 : 1000);
    return { amount: Math.max(100, amount), sold: !!(row && row.status === 'sold') };
  }
  const vr = await fetch(SUPABASE_URL + '/rest/v1/vanity_letters?name=eq.' + encodeURIComponent(name) + '&select=price_cents,status', { headers });
  const rows = await vr.json();
  const row = Array.isArray(rows) ? rows[0] : null;
  if (row && row.status === 'sold') return { error: 'Already sold' };
  return { amount: Math.max(100, Number(row && row.price_cents) || 10000) };
}

async function lookupResaleAmount(name) {
  const nm = String(name || '').replace(/[^A-Za-z0-9]/g, '');
  if (!nm) return { error: 'Not for sale' };
  if (!SUPABASE_SERVICE_ROLE_KEY) return { error: 'Used names are not available right now' };
  const r = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?name=ilike.' + encodeURIComponent(nm) + '&listed_for_sale=eq.true&select=name,kind,user_id,sale_price_cents',
    { headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: 'Bearer ' + SUPABASE_SERVICE_ROLE_KEY } }
  );
  const rows = await r.json();
  const row = Array.isArray(rows) ? rows[0] : null;
  const amount = Number(row && row.sale_price_cents) || 0;
  if (!row || amount < 200) return { error: 'Not listed' };
  if (String(row.kind) === 'signup') return { error: 'Not for sale' };
  return { amount, sellerId: row.user_id, name: row.name, kind: 'resale' };
}

function svcHeaders() {
  return {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: 'Bearer ' + SUPABASE_SERVICE_ROLE_KEY,
    'Content-Type': 'application/json',
    Prefer: 'return=representation'
  };
}
async function loadUsedNameRows() {
  if (!SUPABASE_SERVICE_ROLE_KEY) return [];
  const r = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?listed_for_sale=eq.true&select=name,kind,sale_price_cents&order=sale_price_cents.desc',
    { headers: svcHeaders() }
  );
  const rows = await r.json();
  if (!Array.isArray(rows)) return [];
  return rows.filter((row) => {
    const nm = String(row && row.name || '');
    const price = Number(row && row.sale_price_cents) || 0;
    if (price < 200) return false;
    if (String(row.kind) === 'signup') return false;
    return true;
  }).map((row) => ({
    name: row.name,
    kind: row.kind,
    price_cents: Number(row.sale_price_cents) || 0
  }));
}

async function saveSellerPayout(row) {
  if (!SUPABASE_SERVICE_ROLE_KEY || !row || !row.user_id) return;
  const headers = Object.assign({}, svcHeaders(), { Prefer: 'resolution=merge-duplicates,return=minimal' });
  const r = await fetch(SUPABASE_URL + '/rest/v1/seller_payouts?on_conflict=user_id', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      user_id: row.user_id,
      stripe_account_id: row.stripe_account_id || null,
      payouts_enabled: !!row.payouts_enabled,
      details_submitted: !!row.details_submitted,
      updated_at: new Date().toISOString()
    })
  });
  if (!r.ok) {
    const text = await r.text();
    logger.warn('seller_payouts save %s', text && text.slice(0, 180));
  }
}
async function loadSellerPayout(userId) {
  if (!SUPABASE_SERVICE_ROLE_KEY || !userId) return null;
  const r = await fetch(
    SUPABASE_URL + '/rest/v1/seller_payouts?user_id=eq.' + encodeURIComponent(userId) + '&select=user_id,stripe_account_id,payouts_enabled,details_submitted',
    { headers: svcHeaders() }
  );
  const rows = await r.json();
  return Array.isArray(rows) ? rows[0] : null;
}
async function loadSellerPayoutByAccount(accountId) {
  if (!SUPABASE_SERVICE_ROLE_KEY || !accountId) return null;
  const r = await fetch(
    SUPABASE_URL + '/rest/v1/seller_payouts?stripe_account_id=eq.' + encodeURIComponent(accountId) + '&select=user_id,stripe_account_id,payouts_enabled,details_submitted',
    { headers: svcHeaders() }
  );
  const rows = await r.json();
  return Array.isArray(rows) ? rows[0] : null;
}
const STRIPE_V2_VERSION = '2026-08-26.preview';
async function stripeV2(method, path, body) {
  const r = await fetch('https://api.stripe.com' + path, {
    method,
    headers: {
      Authorization: 'Bearer ' + stripeKey,
      'Stripe-Version': STRIPE_V2_VERSION,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
  if (!r.ok) {
    const msg = (data && data.error && (data.error.message || data.error.code)) || (data && data.message) || text.slice(0, 180);
    throw new Error(String(msg || 'Stripe v2 error'));
  }
  return data;
}
function connectPayoutsOn(account) {
  if (!account) return false;
  if (account.payouts_enabled) return true;
  try {
    const st = account.configuration.recipient.capabilities.stripe_balance.stripe_transfers.status;
    if (st === 'active') return true;
  } catch (e) {}
  return false;
}
function connectDetailsOn(account) {
  if (!account) return false;
  if (account.details_submitted) return true;
  const due = account.requirements && (account.requirements.currently_due || account.requirements.currentlyDue);
  if (Array.isArray(due) && due.length === 0) return true;
  return false;
}
async function retrieveConnectAccount(accountId) {
  try {
    return await stripeV2('GET', '/v2/core/accounts/' + encodeURIComponent(accountId) + '?include=configuration.recipient&include=identity&include=requirements');
  } catch (e) {
    if (stripe) return stripe.accounts.retrieve(accountId);
    throw e;
  }
}
async function createConnectAccount(shopUser) {
  return stripeV2('POST', '/v2/core/accounts', {
    contact_email: shopUser.email || 'seller@anonomoose.com',
    display_name: 'Anonomoose seller',
    dashboard: 'express',
    identity: { country: 'GB', entity_type: 'individual' },
    defaults: {
      responsibilities: {
        fees_collector: 'application',
        losses_collector: 'application'
      }
    },
    configuration: {
      recipient: {
        capabilities: {
          stripe_balance: {
            stripe_transfers: { requested: true }
          }
        }
      }
    },
    include: ['configuration.recipient', 'identity', 'requirements']
  });
}
async function createConnectLink(accountId) {
  try {
    const link = await stripeV2('POST', '/v2/core/account_links', {
      account: accountId,
      use_case: {
        type: 'account_onboarding',
        account_onboarding: {
          configurations: ['recipient'],
          refresh_url: 'https://www.anonomoose.com/?connect=refresh',
          return_url: 'https://www.anonomoose.com/?connect=ok'
        }
      }
    });
    const url = link && (link.url || (link.use_case && link.use_case.account_onboarding && link.use_case.account_onboarding.url));
    if (url) return url;
  } catch (e) {
    logger.warn('connect v2 link %s', e && e.message);
  }
  const link = await stripe.accountLinks.create({
    account: accountId,
    refresh_url: 'https://www.anonomoose.com/?connect=refresh',
    return_url: 'https://www.anonomoose.com/?connect=ok',
    type: 'account_onboarding'
  });
  return link && link.url;
}
async function syncConnectAccount(account, userIdHint) {
  if (!account || !account.id) return;
  const metaUser = (account.metadata && (account.metadata.userId || account.metadata.user_id)) || '';
  const existing = metaUser ? await loadSellerPayout(metaUser) : await loadSellerPayoutByAccount(account.id);
  const userId = userIdHint || metaUser || (existing && existing.user_id);
  if (!userId) return;
  await saveSellerPayout({
    user_id: userId,
    stripe_account_id: account.id,
    payouts_enabled: connectPayoutsOn(account),
    details_submitted: connectDetailsOn(account)
  });
}
async function ensureSellerPayouts(shopUser, opts) {
  opts = opts || {};
  if (!shopUser || !shopUser.id) return { ok: false, error: 'Log in first' };
  if (!stripeKey) return { ok: false, error: 'Payments are not available right now' };
  let row = await loadSellerPayout(shopUser.id);
  if (row && row.payouts_enabled && row.stripe_account_id) {
    return { ok: true, ready: true };
  }
  let accountId = row && row.stripe_account_id;
  let account = null;
  try {
    if (accountId) {
      account = await retrieveConnectAccount(accountId);
    } else {
      account = await createConnectAccount(shopUser);
      accountId = account.id;
    }
  } catch (e) {
    logger.warn('connect account %s', e && e.message);
    return { ok: false, error: 'Could not start bank setup. ' + String(e && e.message || '').slice(0, 160) };
  }
  await syncConnectAccount(account, shopUser.id);
  if (connectPayoutsOn(account) || (opts.forceLink === false && row && row.payouts_enabled)) {
    return { ok: true, ready: true };
  }
  try {
    const url = await createConnectLink(accountId);
    if (!url) throw new Error('No onboarding URL');
    return { ok: true, ready: false, onboard: true, url };
  } catch (e) {
    logger.warn('connect link %s', e && e.message);
    return { ok: false, error: 'Could not open Stripe bank form. ' + String(e && e.message || '').slice(0, 120) };
  }
}
async function markSalePaid(sessionId, transferId) {
  if (!SUPABASE_SERVICE_ROLE_KEY || !sessionId) return;
  await fetch(
    SUPABASE_URL + '/rest/v1/name_sales?stripe_session_id=eq.' + encodeURIComponent(sessionId),
    {
      method: 'PATCH',
      headers: svcHeaders(),
      body: JSON.stringify({
        status: 'paid',
        stripe_transfer_id: transferId || null
      })
    }
  );
}
async function paySellerConnect(sellerId, netCents, sessionId, name) {
  const net = Math.round(Number(netCents) || 0);
  if (!sellerId || net < 1 || !stripe) return;
  const row = await loadSellerPayout(sellerId);
  if (!row || !row.stripe_account_id || !row.payouts_enabled) {
    logger.info('connect hold %s net %s', sellerId, net);
    return;
  }
  const transfer = await stripe.transfers.create({
    amount: net,
    currency: 'gbp',
    destination: row.stripe_account_id,
    metadata: { sellerId: String(sellerId), sessionId: String(sessionId || ''), name: String(name || '') }
  });
  await markSalePaid(sessionId, transfer && transfer.id);
}

async function setNameListing(userId, name, priceCents) {
  const nm = String(name || '').replace(/[^A-Za-z0-9]/g, '');
  if (!userId || !nm) return { ok: false, error: 'Missing name' };
  if (!SUPABASE_SERVICE_ROLE_KEY) return { ok: false, error: 'Listing is not available right now' };
  const listed = priceCents != null;
  const price = listed ? Math.round(Number(priceCents) || 0) : 0;
  if (listed && (price < 200 || price > 2000000)) return { ok: false, error: 'Price must be £2 to £20,000' };
  const found = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?user_id=eq.' + encodeURIComponent(userId) + '&name=ilike.' + encodeURIComponent(nm) + '&select=name,kind',
    { headers: svcHeaders() }
  );
  const rows = await found.json();
  const row = Array.isArray(rows) ? rows[0] : null;
  if (!row) return { ok: false, error: 'You do not own that name' };
  if (String(row.kind) === 'signup') return { ok: false, error: 'Free signup names cannot be sold' };
  if (listed && /^\d+$/.test(nm)) {
    const vr = await fetch(SUPABASE_URL + '/rest/v1/vanity_numbers?n=eq.' + parseInt(nm, 10) + '&select=held_forever', { headers: svcHeaders() });
    const vrows = await vr.json();
    if (Array.isArray(vrows) && vrows[0] && vrows[0].held_forever && nm !== '1' && nm !== '2') {
      return { ok: false, error: 'That number is not for sale' };
    }
  }
  const patch = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?user_id=eq.' + encodeURIComponent(userId) + '&name=ilike.' + encodeURIComponent(nm),
    {
      method: 'PATCH',
      headers: svcHeaders(),
      body: JSON.stringify(listed
        ? { listed_for_sale: true, sale_price_cents: price }
        : { listed_for_sale: false, sale_price_cents: null })
    }
  );
  const text = await patch.text();
  if (!patch.ok) {
    return { ok: false, error: text && text.slice(0, 180) || 'Could not update listing' };
  }
  return { ok: true, name: row.name, price_cents: listed ? price : 0 };
}

async function stripeFeeFromSession(session) {
  const amount = Number(session && session.amount_total) || 0;
  const abroadGuess = Math.round(amount * 0.075) + 20;
  if (!stripe || !session || !session.id) return abroadGuess;
  try {
    const full = await stripe.checkout.sessions.retrieve(session.id, {
      expand: ['payment_intent.latest_charge.balance_transaction']
    });
    const pi = full && full.payment_intent;
    const charge = pi && pi.latest_charge;
    const bt = charge && charge.balance_transaction;
    if (bt && typeof bt.fee === 'number') return bt.fee;
  } catch (e) {}
  return abroadGuess;
}

async function attachResaleName(buyerId, sellerId, name, sessionId, amount, stripeFee) {
  const nm = String(name || '').replace(/[^A-Za-z0-9]/g, '');
  if (!buyerId || !nm) throw new Error('Missing name');
  if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error('Could not move used name');
  const headers = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: 'Bearer ' + SUPABASE_SERVICE_ROLE_KEY,
    'Content-Type': 'application/json',
    Prefer: 'return=representation'
  };
  const found = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?name=ilike.' + encodeURIComponent(nm) + '&select=name,user_id,kind,sale_price_cents,listed_for_sale',
    { headers }
  );
  const rows = await found.json();
  const row = Array.isArray(rows)
    ? rows.find((x) => String(x.name || '').toLowerCase() === nm.toLowerCase())
    : null;
  if (!row || !row.user_id) throw new Error('Name is not for resale');
  if (String(row.kind) === 'signup') throw new Error('Not for sale');
  if (row.user_id === buyerId) return { ok: true, name: nm, already: true, seller_net_cents: 0 };
  if (sellerId && row.user_id !== sellerId) throw new Error('Listing changed');
  const seller = row.user_id;
  const list = Math.max(0, Number(amount) || Number(row.sale_price_cents) || 0);
  const fee = Math.max(0, Number(stripeFee) || 0);
  const platform = Math.max(1, Math.round(list * 0.05));
  const net = Math.max(0, list - fee - platform);
  const moved = await fetch(
    SUPABASE_URL + '/rest/v1/owned_names?user_id=eq.' + encodeURIComponent(seller) + '&name=ilike.' + encodeURIComponent(nm),
    {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ user_id: buyerId, listed_for_sale: false, sale_price_cents: null })
    }
  );
  if (!moved.ok) {
    const t = await moved.text();
    logger.warn('resale move %s', t && t.slice(0, 180));
    throw new Error('Could not move used name');
  }
  if (/^\d+$/.test(nm)) {
    await fetch(SUPABASE_URL + '/rest/v1/vanity_numbers?n=eq.' + parseInt(nm, 10), {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ status: 'sold', owner_id: buyerId, updated_at: new Date().toISOString() })
    });
  } else {
    await fetch(SUPABASE_URL + '/rest/v1/vanity_letters?name=eq.' + encodeURIComponent(nm), {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ status: 'sold', owner_id: buyerId })
    });
  }
  try {
    const rest = await fetch(
      SUPABASE_URL + '/rest/v1/owned_names?user_id=eq.' + encodeURIComponent(seller) + '&select=name,kind,created_at&order=created_at.asc',
      { headers }
    );
    const leftover = await rest.json();
    const signup = Array.isArray(leftover) ? leftover.find((x) => x.kind === 'signup') : null;
    const fallback = (signup && signup.name) || (Array.isArray(leftover) && leftover[0] && leftover[0].name) || ('u' + String(seller).replace(/-/g, '').slice(0, 8));
    const prof = await fetch(
      SUPABASE_URL + '/rest/v1/profiles?id=eq.' + encodeURIComponent(seller) + '&select=display_name',
      { headers }
    );
    const profRows = await prof.json();
    const current = Array.isArray(profRows) && profRows[0] ? String(profRows[0].display_name || '') : '';
    if (current.toLowerCase() === nm.toLowerCase()) {
      await fetch(SUPABASE_URL + '/rest/v1/profiles?id=eq.' + encodeURIComponent(seller), {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ display_name: fallback, updated_at: new Date().toISOString() })
      });
    }
  } catch (e) {
    logger.warn('resale seller name %s', e && e.message);
  }
  try {
    await fetch(SUPABASE_URL + '/rest/v1/name_sales', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        name: nm,
        seller_id: seller,
        buyer_id: buyerId,
        list_cents: list,
        stripe_fee_cents: fee,
        platform_cents: platform,
        seller_net_cents: net,
        stripe_session_id: sessionId || null,
        status: 'pending_payout'
      })
    });
  } catch (e) {}
  return { ok: true, name: nm, seller_net_cents: net, platform_cents: platform, stripe_fee_cents: fee };
}

function cleanPayError(err) {
  const s = String(err || '');
  if (/42702|ambiguous/i.test(s)) return 'Could not save the name. Refresh in a minute.';
  if (s.trim().charAt(0) === '{') {
    try {
      const j = JSON.parse(s);
      return String(j.error || j.message || 'Could not save the name').slice(0, 160);
    } catch (e) {}
    return 'Could not save the name';
  }
  return s.slice(0, 160) || 'Could not save the name';
}

async function fulfillPaidSession(session, userAccess) {
  let paid = session && (session.payment_status === 'paid' || session.status === 'complete');
  if (!paid && session && session.id && stripe) {
    for (let i = 0; i < 6 && !paid; i++) {
      await new Promise((r) => setTimeout(r, 400));
      session = await stripe.checkout.sessions.retrieve(session.id);
      paid = session && (session.payment_status === 'paid' || session.status === 'complete');
    }
  }
  if (!paid) return { ok: false, error: 'Payment not complete yet' };
  let stored = {};
  try {
    const raw = await redisClient.get('vanity:sess:' + session.id);
    if (raw) stored = JSON.parse(raw);
  } catch (e) {}
  const name = (session.metadata && session.metadata.name) || stored.name;
  const userId = (session.metadata && session.metadata.userId) || stored.userId;
  const locked = parseInt((session.metadata && session.metadata.amount) || stored.amount, 10) || 0;
  const paidAmount = Number(session.amount_total) || Number(stored.amount) || 0;
  if (!name || !userId) return { ok: false, error: 'Missing payment details' };
  if (locked && paidAmount && paidAmount < locked) {
    return { ok: false, error: 'Paid amount does not match the shop price' };
  }
  const metaKind = (session.metadata && session.metadata.kind) || stored.kind;
  const sellerId = (session.metadata && session.metadata.sellerId) || stored.sellerId || '';
  const doneKey = 'vanity:done:' + session.id;
  try {
    if (metaKind === 'resale') {
      const fee = await stripeFeeFromSession(session);
      const moved = await attachResaleName(userId, sellerId, name, session.id, paidAmount || locked, fee);
      try {
        await paySellerConnect(sellerId, moved && moved.seller_net_cents, session.id, name);
      } catch (e) {
        logger.warn('connect transfer %s', e && e.message);
      }
    } else {
      await attachPaidName(userId, name, session.id, paidAmount || locked);
    }
    await redisClient.set(doneKey, name, { EX: 30 * 24 * 3600 });
    await redisClient.set('vanity:paid:' + userId, name, { EX: 7 * 24 * 3600 });
    return { ok: true, name, userId, applied: true };
  } catch (e) {
    logger.warn('vanity fulfill %s', e && e.message);
    return { ok: false, error: cleanPayError(e && e.message), name, userId, applied: false };
  }
}
function readRawBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > (limit || 8000)) {
        reject(new Error('too large'));
        req.destroy();
        return;
      }
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function readJsonBody(req, limit) {
  return readRawBody(req, limit).then((buf) => {
    const raw = buf.toString('utf8');
    return raw ? JSON.parse(raw) : {};
  });
}
function pingCors(res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://www.anonomoose.com');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
}
const PUBLIC_PATHS = new Set([
  '/', '/index.html', '/offline.html', '/cover.html', '/random.html', '/w.html',
  '/manifest.json', '/sw.js', '/oldsw.js',
  '/crypto.js', '/ratchet.js', '/utils.js', '/main.js', '/init.js', '/events.js',
  '/supabase-auth.js', '/account-ui.js', '/logged-features.js',
  '/192.png', '/256.png', '/512.png', '/apple-touch-icon.png'
]);
function sendNotFound(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain', 'X-Robots-Tag': 'noindex, nofollow' });
  res.end('Not Found');
}
function adminDeskToken() {
  const secret = process.env.ADMIN_SECRET || '';
  if (!secret) return '';
  return crypto.createHmac('sha256', secret).update('moose-desk').digest('hex').slice(0, 32);
}
function hasAdminDeskCookie(req) {
  const want = adminDeskToken();
  if (!want) return false;
  const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
    const [name, value] = cookie.trim().split('=');
    acc[name] = value;
    return acc;
  }, {}) : {};
  return cookies['moose_desk'] === want;
}
function deskUnlockOk(req, fullUrl) {
  const tok = adminDeskToken();
  if (!tok || !fullUrl) return false;
  if (String(fullUrl.searchParams.get('k') || '') === tok) return true;
  if (fullUrl.pathname === '/moose-desk/' + tok) return true;
  return false;
}
function isDeskPath(fullUrl) {
  const tok = adminDeskToken();
  return fullUrl.pathname === '/moose-desk' || !!(tok && fullUrl.pathname === '/moose-desk/' + tok);
}
function deskClientKey(req) {
  return String((req.headers['x-forwarded-for'] || '')).split(',')[0].trim() || 'desk';
}
function mooseDeskGateHtml() {
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Desk</title><style>body{font-family:sans-serif;background:#111;color:#eee;display:flex;min-height:100vh;align-items:center;justify-content:center}form{background:#1f2937;padding:1.25rem;border-radius:10px;width:min(320px,90vw)}input,button{width:100%;box-sizing:border-box;margin-top:.5rem;padding:.6rem;border-radius:6px;border:0}button{background:#2563eb;color:#fff;cursor:pointer}</style></head><body><form method="POST" action="/moose-desk"><input type="password" name="secret" placeholder="Password" autofocus><button type="submit">Open</button></form></body></html>';
}
const subscribed = new Set(); // Track subscribed rooms
// Added: Redis message handler for pub/sub
const messageHandler = async (msg, channel) => {
  const code = channel.slice(5); // 'room:' prefix
  const room = rooms.get(code);
  if (!room) {
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(msg);
  } catch (err) {
    logger.error('Invalid pub/sub message: %o', err);
    return;
  }
  if (parsed.type === 'relay') {
    const { clientMessage, senderId } = parsed;
    room.clients.forEach((client, clientId) => {
      if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(clientMessage);
      }
    });
    logger.info('relay ok');
  } else if (parsed.type === 'unicast') {
    const { clientMessage, targetId, senderId } = parsed;
    room.clients.forEach((client, clientId) => {
      if (clientId === targetId && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(clientMessage);
        logger.info('unicast ok');
      }
    });
  } else if (parsed.type === 'broadcast') {
    const broadcastMsg = JSON.parse(parsed.clientMessage);
    room.clients.forEach(client => {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(JSON.stringify(broadcastMsg));
      }
    });
  } else if (parsed.type === 'kick' || parsed.type === 'ban') {
    const { targetId } = parsed;
    if (room.clients.has(targetId)) {
      const client = room.clients.get(targetId);
      client.ws.send(JSON.stringify({ type: parsed.type, message: `You have been ${parsed.type}ed from the room.` }));
      client.ws.close();
      // Close handler will handle removal and broadcast
    }
  }
};
// Connect to Redis asynchronously
(async () => {
  await redisClient.connect();
  await subClient.connect();
  logger.info('Connected to Redis');
  // Added: Load initial randomCodes from Redis
  const randomCodesFromRedis = await redisClient.sMembers('randomCodes');
  randomCodesFromRedis.forEach(code => randomCodes.add(code));
  logger.info(`Loaded ${randomCodes.size} random codes from Redis`);
  // New: Subscribe to global features channel
  await subClient.subscribe('global:features', (msg) => {
    try {
      features = JSON.parse(msg);
      logger.info('Received global features update via Redis: %o', features);
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'features-update', ...features }));
          if (!features.enableService && !client.isAdmin) {
            client.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
            client.close();
          }
        }
      });
    } catch (err) {
      logger.error('Invalid global features message: %o', err);
    }
  });
  logger.info('Subscribed to global:features channel');
  await subClient.subscribe('inbox', (msg) => {
    try {
      const parsed = JSON.parse(msg);
      wss.clients.forEach(client => {
        if (client.clientId === parsed.targetClientId && client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(parsed.payload));
        }
      });
    } catch (err) {
      logger.error('Invalid inbox message: %o', err);
    }
  });
  logger.info('Subscribed to inbox channel');
})();
const CERT_KEY_PATH = 'path/to/your/private-key.pem';
const CERT_PATH = 'path/to/your/fullchain.pem';
let server;
if (process.env.NODE_ENV === 'production' || !fs.existsSync(CERT_KEY_PATH) || !fs.existsSync(CERT_PATH)) {
  server = http.createServer();
  logger.info('Using HTTP server (production or missing certificates)');
} else {
  server = https.createServer({
    key: fs.readFileSync(CERT_KEY_PATH),
    cert: fs.readFileSync(CERT_PATH)
  });
  logger.info('Using HTTPS server for local development');
}
server.on('request', (req, res) => {
  const proto = req.headers['x-forwarded-proto'];
  if (proto && proto !== 'https') {
    res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
    res.end();
    return;
  }
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store');
  const origin = req.headers.origin || '';
  const allowOrigin = (origin === 'https://www.anonomoose.com' || origin === 'https://anonomoose.com') ? origin : 'https://www.anonomoose.com';
  const fullUrl = new URL(req.url, `http://${req.headers.host}`);
  if (fullUrl.pathname === '/push-sub' || fullUrl.pathname === '/inbox-ping' || fullUrl.pathname === '/vanity-checkout' || fullUrl.pathname === '/vanity-claim' || fullUrl.pathname === '/vanity-list' || fullUrl.pathname === '/vanity-unlist' || fullUrl.pathname === '/vanity-used' || fullUrl.pathname === '/connect-onboard' || fullUrl.pathname === '/stripe-webhook') {
    const vanityCors = fullUrl.pathname !== '/stripe-webhook';
    if (vanityCors) {
      res.setHeader('Access-Control-Allow-Origin', allowOrigin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
    if (req.method === 'OPTIONS' && vanityCors) {
      res.writeHead(204);
      res.end();
      return;
    }
    if (fullUrl.pathname === '/vanity-used' && (req.method === 'GET' || req.method === 'HEAD')) {
      loadUsedNameRows().then((rows) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, rows: rows || [] }));
      }).catch(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, rows: [] }));
      });
      return;
    }
    if (req.method !== 'POST') {
      res.writeHead(405);
      res.end();
      return;
    }
    if (fullUrl.pathname === '/stripe-webhook') {
      readRawBody(req, 20000).then(async (raw) => {
        let session = null;
        const sig = req.headers['stripe-signature'];
        const whsec = String(process.env.STRIPE_WEBHOOK_SECRET || '').trim();
        let account = null;
        if (stripe && whsec) {
          try {
            const event = stripe.webhooks.constructEvent(raw, sig, whsec);
            if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
              session = event.data && event.data.object;
            }
            if (event.type === 'account.updated') {
              account = event.data && event.data.object;
            }
          } catch (e) {
            logger.warn('stripe webhook sig %s', e && e.message);
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid signature' }));
            return;
          }
        } else if (stripe) {
          let body = {};
          try { body = JSON.parse(raw.toString('utf8') || '{}'); } catch (e) {}
          const eventType = body.type || '';
          const eventId = (body.data && body.data.object && body.data.object.id) || '';
          if (eventId && (eventType === 'checkout.session.completed' || eventType === 'checkout.session.async_payment_succeeded' || !eventType)) {
            session = await stripe.checkout.sessions.retrieve(eventId);
          }
          if (eventType === 'account.updated' && body.data && body.data.object) account = body.data.object;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ received: true }));
        if (session) {
          try { await fulfillPaidSession(session); } catch (e) { logger.warn('stripe webhook fulfill %s', e && e.message); }
        }
        if (account) {
          try { await syncConnectAccount(account); } catch (e) { logger.warn('stripe account.updated %s', e && e.message); }
        }
      }).catch(() => { if (!res.headersSent) { res.writeHead(400); res.end(); } });
      return;
    }
    readJsonBody(req).then(async (body) => {
      if (fullUrl.pathname === '/vanity-checkout') {
        const shopUser = await verifySbUser(bearerFrom(req, body));
        if (!shopUser) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Log in first' }));
          return;
        }
        if (!rateOk(checkoutRate, shopUser.id, 8, 60000)) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Too many checkout attempts. Wait a minute.' }));
          return;
        }
        if (!stripe) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Payments are not available right now. Try again later.' }));
          return;
        }
        const isResale = body.kind === 'resale' || body.resale === true;
        const kind = isResale ? 'resale' : (body.kind === 'letter' ? 'letter' : 'number');
        const name = String(body.name || body.n || '').replace(/[^A-Za-z0-9]/g, '');
        const userId = shopUser.id;
        if (!name || !userId) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Missing name' }));
          return;
        }
        const priced = isResale ? await lookupResaleAmount(name) : await lookupVanityAmount(kind, name);
        if (priced.error) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: priced.error }));
          return;
        }
        if (isResale && priced.sellerId && priced.sellerId === userId) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'That is your listing' }));
          return;
        }
        const amount = priced.amount;
        const sellerId = priced.sellerId || '';
        try {
          const sessionOpts = {
            mode: 'payment',
            payment_method_types: ['card'],
            client_reference_id: userId,
            success_url: 'https://www.anonomoose.com/?vanity=ok&session_id={CHECKOUT_SESSION_ID}',
            cancel_url: 'https://www.anonomoose.com/?vanity=cancel',
            metadata: { kind, name, userId, amount: String(amount), sellerId: String(sellerId || '') },
            line_items: [{
              quantity: 1,
              price_data: {
                currency: 'gbp',
                unit_amount: amount,
                product_data: { name: (isResale ? 'Anonomoose used name ' : 'Anonomoose name ') + name }
              }
            }]
          };
          if (shopUser.email) sessionOpts.customer_email = shopUser.email;
          const session = await stripe.checkout.sessions.create(sessionOpts);
          try {
            await redisClient.set('vanity:sess:' + session.id, JSON.stringify({
              name, userId, amount, kind, sellerId
            }), { EX: 7 * 24 * 3600 });
          } catch (e) {}
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            ok: true,
            url: session.url
          }));
        } catch (e) {
          logger.warn('stripe checkout %s', e && e.message);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: (e && e.message) || 'Stripe checkout failed' }));
        }
        return;
      }
      if (fullUrl.pathname === '/vanity-claim') {
        const claimUser = await verifySbUser(bearerFrom(req, body));
        if (!claimUser) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Log in first' }));
          return;
        }
        const sessionId = String(body.sessionId || '');
        if (!stripe || !sessionId) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false }));
          return;
        }
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const result = await fulfillPaidSession(session);
        if (result.userId && claimUser.id !== result.userId) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'This payment belongs to another account' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      if (fullUrl.pathname === '/connect-onboard') {
        const shopUser = await verifySbUser(bearerFrom(req, body));
        if (!shopUser) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Log in first' }));
          return;
        }
        const result = await ensureSellerPayouts(shopUser, { forceLink: !body.check });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      if (fullUrl.pathname === '/vanity-list' || fullUrl.pathname === '/vanity-unlist') {
        const shopUser = await verifySbUser(bearerFrom(req, body));
        if (!shopUser) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Log in first' }));
          return;
        }
        const name = String(body.name || body.n || '').replace(/[^A-Za-z0-9]/g, '');
        const price = fullUrl.pathname === '/vanity-list' ? Math.round(Number(body.price_cents || body.price || 0)) : null;
        const result = await setNameListing(shopUser.id, name, price);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      if (fullUrl.pathname === '/vanity-used') {
        const rows = await loadUsedNameRows();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, rows }));
        return;
      }
      if (fullUrl.pathname === '/push-sub') {
        const pushUser = await verifySbUser(bearerFrom(req, body));
        if (!pushUser) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Log in first' }));
          return;
        }
        const name = String(body.to || body.username || '').trim().toLowerCase();
        const sub = body.subscription || body;
        if (!name || name.length > 16 || !sub || !sub.endpoint) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false }));
          return;
        }
        const owned = await userOwnsName(pushUser.id, name, bearerFrom(req, body));
        if (!owned) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'That name is not yours' }));
          return;
        }
        await redisClient.set('push:' + name, JSON.stringify({
          endpoint: sub.endpoint,
          keys: sub.keys || { p256dh: body.p256dh, auth: body.auth }
        }), { EX: 30 * 24 * 3600 });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      const pingUser = await verifySbUser(bearerFrom(req, body));
      if (!pingUser) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Log in first' }));
        return;
      }
      if (!rateOk(pingRate, pingUser.id, 12, 60000)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Too many pings' }));
        return;
      }
      const to = String(body.to || '').trim().toLowerCase();
      const kind = String(body.kind || 'note').slice(0, 16);
      if (!to || to.length > 16 || !/^[a-z0-9]+$/i.test(to)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      if (!webpush) return;
      try {
        const raw = await redisClient.get('push:' + to);
        if (!raw) return;
        const sub = JSON.parse(raw);
        const labels = {
          call: 'Incoming call',
          poke: 'moose poked you',
          invite: 'Room invite',
          photo: 'Sealed photo',
          voice: 'Sealed voice',
          note: 'Sealed note'
        };
        await webpush.sendNotification(sub, JSON.stringify({
          title: 'Anonomoose',
          body: labels[kind] || 'Sealed note',
          kind,
          tag: 'moose-' + kind
        }));
      } catch (e) {
        if (e.statusCode === 404 || e.statusCode === 410) {
          try { await redisClient.del('push:' + to); } catch (x) {}
        } else {
          logger.warn('push fail %s', e.message);
        }
      }
    }).catch(() => {
      if (!res.headersSent) {
        res.writeHead(400);
        res.end();
      }
    });
    return;
  }
  if (fullUrl.pathname === '/admin.html') {
    sendNotFound(res);
    return;
  }
  if (isDeskPath(fullUrl)) {
    const finishDesk = (secretOk) => {
      if (secretOk) {
        const tok = adminDeskToken();
        if (tok) {
          res.setHeader('Set-Cookie', 'moose_desk=' + tok + '; Secure; HttpOnly; SameSite=Strict; Max-Age=43200; Path=/moose-desk');
        }
        fs.readFile(path.join(__dirname, 'admin.html'), (err, data) => {
          if (err) { sendNotFound(res); return; }
          res.setHeader('X-Robots-Tag', 'noindex, nofollow');
          res.setHeader('Cache-Control', 'no-store');
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(data);
        });
        return;
      }
      if (!deskUnlockOk(req, fullUrl)) {
        sendNotFound(res);
        return;
      }
      res.setHeader('X-Robots-Tag', 'noindex, nofollow');
      res.setHeader('Cache-Control', 'no-store');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(mooseDeskGateHtml());
    };
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (hasAdminDeskCookie(req)) {
        finishDesk(true);
        return;
      }
      if (deskUnlockOk(req, fullUrl) && req.method === 'GET') {
        finishDesk(false);
        return;
      }
      sendNotFound(res);
      return;
    }
    if (req.method === 'POST') {
      if (!rateOk(deskRate, deskClientKey(req), 8, 15 * 60 * 1000)) {
        sendNotFound(res);
        return;
      }
      let raw = '';
      req.on('data', (c) => { raw += c; if (raw.length > 4000) req.destroy(); });
      req.on('end', () => {
        let secret = '';
        try {
          const ct = String(req.headers['content-type'] || '');
          if (ct.includes('application/json')) {
            const j = JSON.parse(raw || '{}');
            secret = String(j.secret || '');
          } else {
            secret = new URLSearchParams(raw).get('secret') || '';
          }
        } catch (e) { secret = ''; }
        const want = process.env.ADMIN_SECRET || '';
        const ok = !!(want && secret && secret === want);
        if (!ok) {
          sendNotFound(res);
          return;
        }
        finishDesk(true);
      });
      return;
    }
    sendNotFound(res);
    return;
  }
  if (!PUBLIC_PATHS.has(fullUrl.pathname)) {
    sendNotFound(res);
    return;
  }
  let filePath = path.join(__dirname, fullUrl.pathname === '/' ? 'index.html' : fullUrl.pathname);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    let contentType = 'text/plain';
    if (filePath.endsWith('.html')) {
      contentType = 'text/html';
      const nonce = crypto.randomBytes(16).toString('base64');
      let updatedCSP = "default-src 'self'; " +
        `script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://static.cloudflareinsights.com 'nonce-${nonce}'; ` +
        `style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ` +
        "img-src 'self' data: blob: https://raw.githubusercontent.com https://cdnjs.cloudflare.com; " +
        "media-src 'self' blob: data:; " +
        "connect-src 'self' wss://signal.anonomoose.com https://signal.anonomoose.com wss://signaling-server-zc6m.onrender.com https://signaling-server-zc6m.onrender.com wss://signaling-server-1.onrender.com https://api.x.ai https://api.x.ai/v1/chat/completions https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://crgmcdpmmxtrcocfbsac.supabase.co wss://crgmcdpmmxtrcocfbsac.supabase.co https://static.cloudflareinsights.com https://www.anonomoose.com; " +
        "object-src 'none'; base-uri 'self'; form-action 'self';";
      data = data.toString().replace(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/,
        `<meta http-equiv="Content-Security-Policy" content="${updatedCSP}">`);
      data = data.toString().replace(/<script(?! src)/g,
        `<script nonce="${nonce}"`);
      data = data.toString().replace(/<style/g,
        `<style nonce="${nonce}"`);
      let clientIdFromCookie;
      const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
      }, {}) : {};
      clientIdFromCookie = cookies['clientId'];
      if (!clientIdFromCookie) {
        clientIdFromCookie = uuidv4();
        res.setHeader('Set-Cookie', `clientId=${clientIdFromCookie}; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000; Path=/`);
      }
      data = data.toString().replace('</head>', `<script nonce="${nonce}">window.__CLIENT_ID__=${JSON.stringify(clientIdFromCookie)};</script></head>`);
      res.setHeader('Content-Security-Policy', updatedCSP);
    } else if (filePath.endsWith('.js')) {
      contentType = 'application/javascript';
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    } else if (filePath.endsWith('.png')) {
      contentType = 'image/png';
    } else if (filePath.endsWith('.jpg') || filePath.endsWith('.jpeg')) {
      contentType = 'image/jpeg';
    } else if (filePath.endsWith('.json')) {
      contentType = 'application/json';
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});
const wss = new WebSocket.Server({ server });
const rooms = new Map();
const watchBinds = new Map();
const dailyUsers = new Map();
const dailyConnections = new Map();
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const AUDIT_FILE_BASE = path.join(__dirname, 'audit');
const UPDATE_INTERVAL = 30000;
const randomCodes = new Set();
const rateLimits = new Map();
const allTimeUsers = new Set();
const ipRateLimits = new Map();
const ipDailyLimits = new Map();
const ipFailureCounts = new Map();
const ipBans = new Map();
const revokedTokens = new Map();
const clientTokens = new Map();
const clientSizeLimits = new Map();
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  throw new Error('ADMIN_SECRET environment variable is not set. Please configure it for security.');
}
logger.info('desk gate /moose-desk?k=%s', adminDeskToken());
const ALLOWED_ORIGINS = ['https://anonomoose.com', 'https://www.anonomoose.com', 'http://localhost:3000', 'https://signaling-server-zc6m.onrender.com', 'https://signaling-server-1.onrender.com', 'https://signal.anonomoose.com'];
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  logger.info('Generated new JWT secret (in-memory).');
}
const TURN_USERNAME = process.env.TURN_USERNAME;
if (!TURN_USERNAME) {
  throw new Error('TURN_USERNAME environment variable is not set. Please configure it.');
}
const TURN_CREDENTIAL = process.env.TURN_CREDENTIAL;
if (!TURN_CREDENTIAL) {
  throw new Error('TURN_CREDENTIAL environment variable is not set. Please configure it.');
}
function issueTurnCredentials(forClientId) {
  const ttl = 3600;
  const secret = process.env.TURN_SECRET;
  if (secret) {
    const username = `${Math.floor(Date.now() / 1000) + ttl}:${forClientId}`;
    const credential = crypto.createHmac('sha1', secret).update(username).digest('base64');
    return { turnUsername: username, turnCredential: credential, turnTtl: ttl };
  }
  return { turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, turnTtl: ttl };
}
async function markOnline(id) {
  if (!id) return;
  try { await redisClient.set('online:' + id, '1', { EX: 120 }); } catch (e) {}
}
async function markOffline(id) {
  if (!id) return;
  try { await redisClient.del('online:' + id); } catch (e) {}
}
async function destroyRoom(code) {
  if (!code) return;
  try { await redisClient.set(`burned:${code}`, '1', { EX: 86400 }); } catch (e) {}
  const room = rooms.get(code);
  if (room && room.clients) {
    room.clients.forEach((entry) => {
      try { entry.ws.send(JSON.stringify({ type: 'room-wipe', clientId: 'server' })); } catch (e) {}
      try { entry.ws.close(); } catch (e) {}
    });
    rooms.delete(code);
  }
  try {
    await redisClient.del(`room:${code}`);
    await redisClient.del(`room:${code}:clients`);
    await redisClient.del(`room:${code}:totp`);
    await redisClient.del(`room:${code}:nonces`);
  } catch (e) {}
  randomCodes.delete(code);
  try { await redisClient.sRem('randomCodes', code); } catch (e) {}
  try { broadcastRandomCodes(); } catch (e) {}
  logger.info('Destroyed burned room');
}
const IP_SALT = process.env.IP_SALT || 'your-random-salt-here';
let features = {
  enableService: true,
  enableImages: true,
  enableVoice: true,
  enableVoiceCalls: true,
  enableAudioToggle: true,
  enableGrokBot: false,
  enableP2P: true,
  enableRelay: true
};
let aggregatedStats = { daily: {} };
async function loadFeatures() {
  try {
    const res = await dbPool.query('SELECT * FROM features LIMIT 1');
    if (res.rows.length > 0) {
      features = res.rows[0];
      features.enableService = features.enableservice !== undefined ? features.enableservice : features.enableService;
      features.enableImages = features.enableimages !== undefined ? features.enableimages : features.enableImages;
      features.enableVoice = features.enablevoice !== undefined ? features.enablevoice : features.enableVoice;
      features.enableVoiceCalls = features.enablevoicecalls !== undefined ? features.enablevoicecalls : features.enableVoiceCalls;
      features.enableAudioToggle = features.enableaudiotoggle !== undefined ? features.enableaudiotoggle : features.enableAudioToggle;
      features.enableGrokBot = features.enablegrokbot !== undefined ? features.enablegrokbot : features.enableGrokBot;
      features.enableP2P = features.enablep2p !== undefined ? features.enablep2p : features.enableP2P;
      features.enableRelay = features.enablerelay !== undefined ? features.enablerelay : features.enableRelay;
    } else {
      await dbPool.query(
        'INSERT INTO features ("enableService", "enableImages", "enableVoice", "enableVoiceCalls", "enableAudioToggle", "enableGrokBot", "enableP2P", "enableRelay") VALUES (true, true, true, true, true, true, true, true)'
      );
      features = {
        enableService: true,
        enableImages: true,
        enableVoice: true,
        enableVoiceCalls: true,
        enableAudioToggle: true,
        enableGrokBot: true,
        enableP2P: true,
        enableRelay: true
      };
    }
    logger.info('Loaded features from DB: %o', features);
    if (!features.enableVoice || !features.enableVoiceCalls || !features.enableAudioToggle) {
      features.enableVoice = true;
      features.enableVoiceCalls = true;
      features.enableAudioToggle = true;
      await saveFeatures();
      logger.info('Enabled voice notes, calls and speaker');
    }
    // New: Publish initial features to Redis for sync
    pubClient.publish('global:features', JSON.stringify(features));
  } catch (err) {
    logger.error('Error loading features from DB: %s %s', err.message, err.stack);
  }
}
async function saveFeatures() {
  try {
    await dbPool.query(
      'UPDATE features SET "enableService"=$1, "enableImages"=$2, "enableVoice"=$3, "enableVoiceCalls"=$4, "enableAudioToggle"=$5, "enableGrokBot"=$6, "enableP2P"=$7, "enableRelay"=$8',
      [
        features.enableService,
        features.enableImages,
        features.enableVoice,
        features.enableVoiceCalls,
        features.enableAudioToggle,
        features.enableGrokBot,
        features.enableP2P,
        features.enableRelay
      ]
    );
    logger.info('Saved features to DB');
  } catch (err) {
    logger.error('Error saving features to DB: %s %s', err.message, err.stack);
  }
}
async function loadAggregatedStats() {
  try {
    const res = await dbPool.query('SELECT data FROM aggregated_stats LIMIT 1');
    if (res.rows.length > 0) {
      aggregatedStats = res.rows[0].data;
    } else {
      await dbPool.query('INSERT INTO aggregated_stats (data) VALUES ($1)', [JSON.stringify({ daily: {} })]);
      aggregatedStats = { daily: {} };
    }
    logger.info('Loaded aggregatedStats from DB');
  } catch (err) {
    logger.error('Error loading aggregatedStats from DB: %s %s', err.message, err.stack);
  }
}
async function saveAggregatedStats() {
  try {
    await dbPool.query('UPDATE aggregated_stats SET data = $1', [JSON.stringify(aggregatedStats)]);
    logger.info('Saved aggregatedStats to DB');
  } catch (err) {
    logger.error('Error saving aggregatedStats to DB: %s %s', err.message, err.stack);
  }
}
function isValidBase32(str) {
  return /^[A-Z2-7]+=*$/i.test(str) && str.length >= 16;
}
function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  let sanitized = str.replace(/[^A-Za-z0-9+/=]/g, '');
  const padding = (4 - sanitized.length % 4) % 4;
  sanitized += '='.repeat(padding);
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  const isValid = base64Regex.test(sanitized);
  if (!isValid) logger.warn('Invalid base64 detected: %s', str);
  return isValid;
}
function validateMessage(data) {
  if (typeof data !== 'object' || data === null || !data.type) {
    return { valid: false, error: 'Invalid message: must be an object with "type" field' };
  }
  if (data.token && typeof data.token !== 'string') {
    return { valid: false, error: 'Invalid token: must be a string' };
  }
  if (data.clientId && typeof data.clientId !== 'string') {
    return { valid: false, error: 'Invalid clientId: must be a string' };
  }
  if (data.code && !validateCode(data.code)) {
    return { valid: false, error: 'Invalid code format' };
  }
  if (data.username && !validateUsername(data.username)) {
    return { valid: false, error: 'Invalid username: 1-16 alphanumeric characters' };
  }
  switch (data.type) {
    case 'connect':
      if (!data.clientId || typeof data.clientId !== 'string') {
        return { valid: false, error: 'connect: clientId required as string' };
      }
      break;
    case 'refresh-token':
      if (!data.refreshToken || typeof data.refreshToken !== 'string') {
        return { valid: false, error: 'refresh-token: refreshToken required as string' };
      }
      break;
    case 'public-key':
      if (!data.publicKey || !isValidBase64(data.publicKey) || data.publicKey.length < 80 || data.publicKey.length > 400) {
        return { valid: false, error: 'public-key: invalid publicKey format or length' };
      }
      if (data.identityPublic && (!isValidBase64(data.identityPublic) || data.identityPublic.length < 80 || data.identityPublic.length > 400)) {
        return { valid: false, error: 'public-key: invalid identityPublic format or length' };
      }
      if (!data.code) {
        return { valid: false, error: 'public-key: code required' };
      }
      break;
    case 'encrypted-room-key':
      if (!data.encryptedKey || !isValidBase64(data.encryptedKey)) {
        return { valid: false, error: 'encrypted-room-key: invalid encryptedKey format' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'encrypted-room-key: invalid iv' };
      }
      if (!data.publicKey || !isValidBase64(data.publicKey) || data.publicKey.length < 80 || data.publicKey.length > 400) {
        return { valid: false, error: 'encrypted-room-key: invalid publicKey format or length' };
      }
      if (data.identityPublic && (!isValidBase64(data.identityPublic) || data.identityPublic.length < 80 || data.identityPublic.length > 400)) {
        return { valid: false, error: 'encrypted-room-key: invalid identityPublic format or length' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'encrypted-room-key: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'encrypted-room-key: code required' };
      }
      break;
    case 'new-room-key':
      if (!data.encrypted || !isValidBase64(data.encrypted)) {
        return { valid: false, error: 'new-room-key: invalid encrypted' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'new-room-key: invalid iv' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'new-room-key: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'new-room-key: code required' };
      }
      if (typeof data.version !== 'number' || !Number.isInteger(data.version) || data.version < 1) {
        return { valid: false, error: 'new-room-key: version required as positive integer' };
      }
      if (!data.publicKey || !isValidBase64(data.publicKey) || data.publicKey.length < 80 || data.publicKey.length > 400) {
        return { valid: false, error: 'new-room-key: invalid publicKey format or length' };
      }
      break;
    case 'join':
      if (!data.code) {
        return { valid: false, error: 'join: code required' };
      }
      if (!data.username) {
        return { valid: false, error: 'join: username required' };
      }
      if (data.totpCode && typeof data.totpCode !== 'string') {
        return { valid: false, error: 'join: totpCode must be a string if provided' };
      }
      if (data.totpSecret && (typeof data.totpSecret !== 'string' || data.totpSecret.length > 64)) {
        return { valid: false, error: 'join: invalid totpSecret' };
      }
      if (data.identityPublic && (!isValidBase64(data.identityPublic) || data.identityPublic.length < 80 || data.identityPublic.length > 400)) {
        return { valid: false, error: 'join: invalid identityPublic format or length' };
      }
      if (data.sbAccess && (typeof data.sbAccess !== 'string' || data.sbAccess.length > 8000)) {
        return { valid: false, error: 'join: invalid sbAccess' };
      }
      break;
    case 'check-totp':
      if (!data.code) {
        return { valid: false, error: 'check-totp: code required' };
      }
      break;
    case 'set-max-clients':
      const maxLimit = features.enableRelay || !features.enableP2P ? 50 : 4;
      if (!data.maxClients || typeof data.maxClients !== 'number' || data.maxClients < 1 || data.maxClients > maxLimit) {
        return { valid: false, error: `set-max-clients: maxClients must be number between 2 and ${maxLimit}` };
      }
      if (!data.code) {
        return { valid: false, error: 'set-max-clients: code required' };
      }
      break;
    case 'offer':
    case 'answer':
      if (!data.offer && !data.answer) {
        return { valid: false, error: data.type + ': offer or answer required' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: data.type + ': targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: data.type + ': code required' };
      }
      break;
    case 'candidate':
      if (!data.candidate) {
        return { valid: false, error: 'candidate: candidate required' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'candidate: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'candidate: code required' };
      }
      break;
    case 'kick':
    case 'ban':
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: `${data.type}: targetId required as string` };
      }
      if (!data.signature || !isValidBase64(data.signature)) {
        return { valid: false, error: `${data.type}: valid signature required` };
      }
      if (!data.code) {
        return { valid: false, error: `${data.type}: code required` };
      }
      break;
    case 'submit-random':
      if (!data.code) {
        return { valid: false, error: 'submit-random: code required' };
      }
      break;
    case 'get-random-codes':
      break;
    case 'relay-message':
      if ((!data.content && !data.encryptedContent && !data.data && !data.encryptedData) || typeof (data.content || data.encryptedContent || data.data || data.encryptedData) !== 'string') {
        return { valid: false, error: 'relay-message: content, encryptedContent, data, or encryptedData required as string' };
      }
      if ((data.encryptedContent || data.encryptedData) && !data.iv) {
        return { valid: false, error: 'relay-message: iv required for encryptedContent or encryptedData' };
      }
      if ((data.encryptedContent || data.encryptedData) && !data.signature && !data.sk) {
        return { valid: false, error: 'relay-message: signature required for encryptedContent or encryptedData' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'relay-message: messageId required as string' };
      }
      if (!data.timestamp || typeof data.timestamp !== 'number') {
        return { valid: false, error: 'relay-message: timestamp required as number' };
      }
      if (!data.nonce || typeof data.nonce !== 'string') {
        return { valid: false, error: 'relay-message: nonce required as string' };
      }
      if (!data.sk && (!data.identityPublic || !isValidBase64(data.identityPublic))) {
        return { valid: false, error: 'relay-message: identityPublic required' };
      }
      if (!data.sk && (!data.identitySig || !isValidBase64(data.identitySig))) {
        return { valid: false, error: 'relay-message: identitySig required' };
      }
      if (!data.code) {
        return { valid: false, error: 'relay-message: code required' };
      }
      break;
    case 'relay-image':
    case 'relay-voice':
    case 'relay-file':
      if ((!data.data && !data.encryptedData) || !isValidBase64(data.data || data.encryptedData)) {
        return { valid: false, error: data.type + ': invalid data or encryptedData (base64)' };
      }
      if (data.encryptedData && !data.iv) {
        return { valid: false, error: data.type + ': iv required for encryptedData' };
      }
      if (data.encryptedData && !data.signature) {
        return { valid: false, error: data.type + ': signature required for encryptedData' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: data.type + ': messageId required as string' };
      }
      if (!data.timestamp || typeof data.timestamp !== 'number') {
        return { valid: false, error: data.type + ': timestamp required as number' };
      }
      if (!data.nonce || typeof data.nonce !== 'string') {
        return { valid: false, error: data.type + ': nonce required as string' };
      }
      if (data.type === 'relay-file' && (!data.filename || typeof data.filename !== 'string')) {
        return { valid: false, error: 'relay-file: filename required as string' };
      }
      if (!data.code) {
        return { valid: false, error: data.type + ': code required' };
      }
      if (data.mime && typeof data.mime !== 'string') {
        return { valid: false, error: data.type + ': mime must be string if provided' };
      }
      break;
    case 'get-stats':
    case 'get-features':
    case 'toggle-feature':
      if (!data.secret || typeof data.secret !== 'string') {
        return { valid: false, error: data.type + ': secret required as string' };
      }
      if (data.type === 'toggle-feature' && (!data.feature || typeof data.feature !== 'string')) {
        return { valid: false, error: 'toggle-feature: feature required as string' };
      }
      break;
    case 'export-stats-csv':
    case 'export-logs-csv':
    case 'clear-random-codes':
      if (!data.secret || typeof data.secret !== 'string') {
        return { valid: false, error: data.type + ': secret required as string' };
      }
      break;
    case 'ping':
    case 'pong':
    case 'get-turn-credentials':
    case 'room-wipe':
    case 'leave':
    case 'remove-random-code':
      break;
    case 'watch-bind':
      if (!data.token || typeof data.token !== 'string' || data.token.length < 8) {
        return { valid: false, error: 'watch-bind: token required' };
      }
      if (!data.code) return { valid: false, error: 'watch-bind: code required' };
      break;
    case 'watch-burn':
      if (!data.token || typeof data.token !== 'string' || data.token.length < 8) {
        return { valid: false, error: 'watch-burn: token required' };
      }
      break;
    case 'set-totp':
      if (!data.code) {
        return { valid: false, error: 'set-totp: code required' };
      }
      if (!data.secret || typeof data.secret !== 'string' || !isValidBase32(data.secret)) {
        return { valid: false, error: 'set-totp: valid base32 secret required' };
      }
      break;
    case 'register-username':
      if (!data.username) {
        return { valid: false, error: 'register-username: username required' };
      }
      if (!data.password || typeof data.password !== 'string' || data.password.length < 8) {
        return { valid: false, error: 'register-username: password required as string (min 8 chars)' };
      }
      if (data.public_key && !isValidBase64(data.public_key)) {
        return { valid: false, error: 'register-username: invalid public_key (base64)' };
      }
      if (data.identity_public_key && !isValidBase64(data.identity_public_key)) {
        return { valid: false, error: 'register-username: invalid identity_public_key (base64)' };
      }
      break;
    case 'login-username':
      if (!data.username) {
        return { valid: false, error: 'login-username: username required' };
      }
      if (!data.password || typeof data.password !== 'string' || data.password.length < 8) {
        return { valid: false, error: 'login-username: password required as string (min 8 chars)' };
      }
      // Updated: Allow public_key in login for key update
      if (data.public_key && !isValidBase64(data.public_key)) {
        return { valid: false, error: 'login-username: invalid public_key (base64)' };
      }
      if (data.identity_public_key && !isValidBase64(data.identity_public_key)) {
        return { valid: false, error: 'login-username: invalid identity_public_key (base64)' };
      }
      break;
    case 'find-user':
      if (!data.username) {
        return { valid: false, error: 'find-user: username required' };
      }
      break;
    case 'send-offline-message':
      if (!data.to_username) {
        return { valid: false, error: 'send-offline-message: to_username required' };
      }
      if (!data.encrypted || !isValidBase64(data.encrypted)) {
        return { valid: false, error: 'send-offline-message: invalid encrypted (base64)' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'send-offline-message: invalid iv (base64)' };
      }
      if (!data.ephemeral_public || !isValidBase64(data.ephemeral_public)) {
        return { valid: false, error: 'send-offline-message: invalid ephemeral_public (base64)' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'send-offline-message: messageId required as string' };
      }
      if (data.identity_public && !isValidBase64(data.identity_public)) {
        return { valid: false, error: 'send-offline-message: invalid identity_public (base64)' };
      }
      break;
    case 'confirm-offline-message':
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'confirm-offline-message: messageId required as string' };
      }
      break;
    case 'logout':
      break;
    default:
      return { valid: false, error: 'Unknown message type' };
  }
  return { valid: true };
}
if (fs.existsSync(LOG_FILE)) {
  const logContent = fs.readFileSync(LOG_FILE, 'utf8');
  const lines = logContent.split('\n');
  lines.forEach(line => {
    const match = line.match(/Client: (\w+)/);
    if (match) allTimeUsers.add(match[1]);
  });
  logger.info(`Loaded ${allTimeUsers.size} all-time unique users from log.`);
}
setInterval(async () => {
  for (const code of [...randomCodes]) {
    const clientsKey = `room:${code}:clients`;
    const size = await redisClient.sCard(clientsKey);
    if (size === 0) {
      randomCodes.delete(code);
      await redisClient.sRem('randomCodes', code);
    }
  }
  broadcastRandomCodes();
  logger.info('Auto-cleaned random codes.');
}, 3600000);
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 50000);
setInterval(async () => {
  const now = Date.now();
  revokedTokens.forEach((expiry, token) => {
    if (expiry < now) {
      revokedTokens.delete(token);
    }
  });
  // Clean old nonces
  const nonceKeys = await redisClient.keys('room:*:nonces');
  for (const key of nonceKeys) {
    const nonces = await redisClient.hGetAll(key);
    for (const [nonce, ts] of Object.entries(nonces)) {
      if (now - parseInt(ts) > 300000) {
        await redisClient.hDel(key, nonce);
      }
    }
  }
  logger.info(`Cleaned up expired revoked tokens and message nonces. Tokens: ${revokedTokens.size}`);
}, 600000);
function checkAdminSecret(data, ws) {
  if (data.secret === ADMIN_SECRET) {
    return true;
  } else {
    ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
    return false;
  }
}
function revokeTokens(clientId) {
  const tokens = clientTokens.get(clientId);
  if (tokens) {
    try {
      const decoded = jwt.verify(tokens.accessToken, JWT_SECRET, { ignoreExpiration: true });
      revokedTokens.set(tokens.accessToken, decoded.exp * 1000);
      if (tokens.refreshToken) {
        const decodedRefresh = jwt.verify(tokens.refreshToken, JWT_SECRET, { ignoreExpiration: true });
        revokedTokens.set(tokens.refreshToken, decodedRefresh.exp * 1000);
      }
      clientTokens.delete(clientId);
      logger.info(`Revoked tokens for client ${clientId}`);
    } catch (err) {
      logger.warn(`Failed to revoke tokens for client ${clientId}: ${err.message}`);
    }
  }
}
async function safeQuery(query, params, ws, errorMsg) {
  try {
    return await dbPool.query(query, params);
  } catch (err) {
    logger.error('DB error: %s %s', err.message, err.stack);
    if (ws) ws.send(JSON.stringify({ type: 'error', message: errorMsg || 'Database error occurred.' }));
    throw err;
  }
}
async function forwardUnicast(code, targetId, message, fromId) {
  const clientMessage = JSON.stringify(message);
  pubClient.publish(`room:${code}`, JSON.stringify({
    type: 'unicast',
    clientMessage,
    targetId,
    senderId: fromId
  }));
  logger.info(`Published unicast ${message.type} from ${fromId} to ${targetId} for code: ${code}`);
}
function restrictLimit(map, key, increment, threshold, windowMs = 60000, logMsgPrefix) {
  const now = Date.now();
  const limit = map.get(key) || { value: 0, startTime: now };
  if (now - limit.startTime >= windowMs) {
    limit.value = 0;
    limit.startTime = now;
  }
  limit.value += increment;
  map.set(key, limit);
  if (limit.value > threshold) {
    logger.warn(`${logMsgPrefix} exceeded for ${key}: ${limit.value} in ${windowMs / 1000}s`);
    userLogger.info(`${new Date().toISOString()} - ${logMsgPrefix} exceeded for ${key}: ${limit.value}`);
    return false;
  }
  return true;
}
wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    logger.warn(`Rejected connection from invalid origin: ${origin}`);
    ws.close(1008, 'Invalid origin');
    return;
  }
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress;
  const userAgent = req.headers['user-agent'] || 'unknown';
  ws.userAgent = userAgent;
  const hashedIp = hashIp(clientIp);
  const hashedUa = hashUa(userAgent);
  const compositeKey = hashedIp + ':' + hashedUa;
  if (ipBans.has(compositeKey) && ipBans.get(compositeKey).expiry > Date.now()) {
    logger.warn(`IP had a ban flag but connect is still allowed: ${compositeKey}`);
    ipBans.delete(compositeKey);
    ipFailureCounts.delete(compositeKey);
  }
  let clientId, code, username;
  ws.on('message', async (message) => {
    if (!restrictLimit(rateLimits, ws.clientId, 1, 50, 60000, 'Rate limit')) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }
    try {
      const data = JSON.parse(message);
      const loggedData = { ...data };
      ['secret', 'password', 'token', 'refreshToken', 'encrypted', 'encryptedKey', 'encryptedContent', 'encryptedData', 'encryptedBlob', 'content', 'data', 'signature', 'identitySig', 'iv', 'publicKey', 'ephemeral_public', 'public_key', 'identityPublic', 'identity_public', 'identity_public_key'].forEach(k => {
        if (loggedData[k]) loggedData[k] = '[REDACTED]';
      });
      logger.info('Received: %s', loggedData.type || 'unknown');
      const validation = validateMessage(data);
      if (!validation.valid) {
        ws.send(JSON.stringify({ type: 'error', message: validation.error }));
        logger.warn('Message validation failed: %s', validation.error);
        return;
      }
      // Skip escaping for specific fields that should remain untouched
      const skipEscapeFields = [
        'token',
        'refreshToken',
        'clientId',
        'targetId',
        'nonce',
        'messageId',
        'code',
        data.type === 'public-key' && 'publicKey',
        data.type === 'public-key' && 'identityPublic',
        data.type === 'public-key' && 'identityEcdh',
        data.type === 'encrypted-room-key' && 'publicKey',
        data.type === 'encrypted-room-key' && 'identityPublic',
        data.type === 'encrypted-room-key' && 'identityEcdh',
        data.type === 'encrypted-room-key' && 'encryptedKey',
        data.type === 'encrypted-room-key' && 'iv',
        data.type === 'new-room-key' && 'encrypted',
        data.type === 'new-room-key' && 'iv',
        data.type === 'new-room-key' && 'publicKey',
        data.type === 'join' && 'identityPublic',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'identityPublic',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'identitySig',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'content',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'data',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'encryptedContent',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'encryptedData',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'iv',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'signature',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') && 'mime',
        data.type === 'send-offline-message' && 'encrypted',
        data.type === 'send-offline-message' && 'iv',
        data.type === 'send-offline-message' && 'ephemeral_public',
        data.type === 'send-offline-message' && 'identity_public',
        data.type === 'register-username' && 'public_key',
        data.type === 'register-username' && 'identity_public_key',
        data.type === 'login-username' && 'public_key',
        data.type === 'login-username' && 'identity_public_key'
      ];
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string' && !skipEscapeFields.includes(key)) {
          data[key] = validator.escape(validator.trim(data[key]));
        }
      });
      if ((data.type === 'public-key' || data.type === 'encrypted-room-key' || data.type === 'new-room-key') && data.publicKey) {
        if (!isValidBase64(data.publicKey) || data.publicKey.length < 80 || data.publicKey.length > 400) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format or length' }));
          logger.warn('Rejected public key length %s', data.publicKey && data.publicKey.length);
          return;
        }
      }
      if (!features.enableService && data.type !== 'connect') {
        ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
        ws.close();
        return;
      }
      if (data.type !== 'connect' && data.type !== 'refresh-token' && data.type !== 'watch-burn') {
        if (!data.token) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing authentication token' }));
          return;
        }
        try {
          let decoded = jwt.verify(data.token, JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
            return;
          }
          if (revokedTokens.has(data.token)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
            return;
          }
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
          return;
        }
      }
      if (data.type === 'connect') {
        clientId = data.clientId || uuidv4();
        ws.clientId = clientId;
        logStats({ clientId, event: 'connect' });
        const accessToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '10m' });
        const refreshToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '1h' });
        clientTokens.set(clientId, { accessToken, refreshToken });
        ws.accessToken = accessToken;
        const turn = issueTurnCredentials(clientId);
        ws.send(JSON.stringify({ type: 'connected', clientId, accessToken, refreshToken, ...turn }));
        ipFailureCounts.delete(compositeKey);
        ipBans.delete(compositeKey);
        markOnline(clientId);
        dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [clientId]).catch(err => {
          logger.error('DB error on connect: %s %s', err.message, err.stack);
        });
        return;
      }
      if (data.type === 'refresh-token') {
        if (!data.refreshToken) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing refresh token' }));
          return;
        }
        try {
          const decoded = jwt.verify(data.refreshToken, JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
            return;
          }
          if (revokedTokens.has(data.refreshToken)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
            return;
          }
          const oldRefreshExpiry = decoded.exp * 1000;
          revokedTokens.set(data.refreshToken, oldRefreshExpiry);
          const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '10m' });
          const newRefreshToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '1h' });
          clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
          ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
          return;
        }
        return;
      }
      if (data.type === 'public-key') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const targetId = rooms.get(data.code).initiator;
        const fwdMsg = { type: 'public-key', publicKey: data.publicKey, identityPublic: data.identityPublic, identityEcdh: data.identityEcdh, clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'encrypted-room-key') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, publicKey: data.publicKey, identityPublic: data.identityPublic, identityEcdh: data.identityEcdh, clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'new-room-key') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: 'new-room-key', encrypted: data.encrypted, iv: data.iv, targetId: data.targetId, clientId: data.clientId, code: data.code, version: data.version, publicKey: data.publicKey };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'join') {
        if (!features.enableService) {
          ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.', code: data.code }));
          return;
        }
        if (!restrictLimit(ipRateLimits, `${hashedIp}:join`, 1, 5, 60000, 'IP rate limit')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!restrictLimit(ipDailyLimits, `${hashedIp}:join:${new Date().toISOString().slice(0, 10)}`, 1, 100, 86400000, 'Daily IP limit')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        if (!validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!validateCode(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format: xxxx-xxxx-xxxx-xxxx.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const burned = await redisClient.get(`burned:${code}`);
        if (burned) {
          ws.send(JSON.stringify({ type: 'error', message: 'That room was burned. Start a new chat.', code: data.code }));
          return;
        }
        const roomKey = `room:${code}`;
        const exists = await redisClient.exists(roomKey);
        let roomState;
        if (!exists) {
          roomState = { initiator: clientId, maxClients: 2, forceRelay: false };
          await redisClient.set(roomKey, JSON.stringify(roomState), { EX: 86400 });
        } else {
          roomState = JSON.parse(await redisClient.get(roomKey));
        }
        const totpKey = `room:${code}:totp`;
        if (data.totpSecret && clientId === roomState.initiator) {
          await redisClient.set(totpKey, String(data.totpSecret).toUpperCase(), { EX: 86400 });
        }
        const roomTotpSecret = await redisClient.get(totpKey);
        if (roomTotpSecret && !data.totpCode && clientId !== roomState.initiator) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          return;
        }
        if (roomTotpSecret && data.totpCode) {
          const isValid = otplib.authenticator.check(data.totpCode, roomTotpSecret);
          if (!isValid) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid TOTP code.', code: data.code }));
            incrementFailure(clientIp, ws.userAgent);
            return;
          }
        }
        // Check username unique globally
        let isReconnect = false;
        const clientKey = `room:${code}:client:${clientId}`;
        const existingUsername = await redisClient.get(clientKey);
        if (existingUsername) {
          if (existingUsername === username) {
            isReconnect = true;
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId.', code: data.code }));
            incrementFailure(clientIp, ws.userAgent);
            return;
          }
        } else {
          const allClientKeys = await redisClient.keys(`room:${code}:client:*`);
          if (allClientKeys.length > 0) {
            const allUsernamesMap = await redisClient.mGet(allClientKeys);
            const usernames = Object.values(allUsernamesMap);
            if (usernames.includes(username)) {
              ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
              incrementFailure(clientIp, ws.userAgent);
              return;
            }
          }
        }
        // Check if room full
        const clientsKey = `room:${code}:clients`;
        const multi = redisClient.multi();
        multi.sAdd(clientsKey, clientId);
        multi.sCard(clientsKey);
        const [added, currentSize] = await multi.exec();
        await redisClient.expire(clientsKey, 86400);
        if (currentSize > roomState.maxClients) {
          await redisClient.sRem(clientsKey, clientId);
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room is full.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        // Set username
        await redisClient.set(clientKey, username, { EX: 86400 });
        const claimed = await verifyClaimedLogin(data.sbAccess);
        delete data.sbAccess;
        if (claimed) {
          await redisClient.set(`room:${code}:claimed:${clientId}`, '1', { EX: 86400 });
        } else {
          await redisClient.del(`room:${code}:claimed:${clientId}`);
        }
        // Subscribe if not subscribed
        if (!subscribed.has(code)) {
          await subClient.subscribe(`room:${code}`, messageHandler);
          subscribed.add(code);
          logger.info('room subscribed');
        }
        // Create or get local room
        if (!rooms.has(code)) {
          rooms.set(code, { initiator: roomState.initiator, clients: new Map(), maxClients: roomState.maxClients, forceRelay: !!roomState.forceRelay });
        }
        const room = rooms.get(code);
        room.clients.set(clientId, { ws, username, claimed });
        ws.code = code;
        ws.username = username;
        ws.claimed = claimed;
        // Check if initiator online
        const isInitiatorLocal = clientId === roomState.initiator;
        const initiatorOnline = await redisClient.sIsMember(clientsKey, roomState.initiator);
        if (!initiatorOnline && !isInitiatorLocal) {
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          // Cleanup
          room.clients.delete(clientId);
          await redisClient.sRem(clientsKey, clientId);
          await redisClient.del(clientKey);
          return;
        }
        const turn = issueTurnCredentials(clientId);
        let roster = [];
        try {
          const ids = await redisClient.sMembers(clientsKey);
          const rosterPipe = redisClient.multi();
          ids.forEach((id) => {
            rosterPipe.get(`room:${code}:client:${id}`);
            rosterPipe.get(`room:${code}:claimed:${id}`);
          });
          const rosterVals = await rosterPipe.exec();
          roster = ids.map((id, i) => ({
            clientId: id,
            username: rosterVals[i * 2] || '',
            claimed: rosterVals[i * 2 + 1] === '1'
          }));
        } catch (e) {
          roster = [{ clientId, username, claimed }];
        }
        ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: isInitiatorLocal, forceRelay: !!room.forceRelay || room.maxClients > 4, features, roster, ...turn }));
        logStats({ clientId, username, code, event: 'join', totalClients: currentSize });
        if (room.clients.size > 0) {
          room.clients.forEach((_, existingClientId) => {
            if (existingClientId !== clientId) {
              logStats({
                clientId,
                targetId: existingClientId,
                code,
                event: 'webrtc-connection',
                totalClients: currentSize
              });
            }
          });
        }
        // Broadcast join-notify
        const totalClients = currentSize;
        const notifyMsg = { type: 'join-notify', clientId, username, code, totalClients, identityPublic: data.identityPublic || null, claimed };
        pubClient.publish(`room:${code}`, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(notifyMsg) }));
        // New: Remove from randomCodes if this is a non-initiator joining a random code (one-time use)
        if (randomCodes.has(code) && clientId !== roomState.initiator) {
          randomCodes.delete(code);
          await redisClient.sRem('randomCodes', code);
          broadcastRandomCodes();
          logger.info('random join');
        }
        return;
      }
      if (data.type === 'check-totp') {
        const totpSecret = await redisClient.get(`room:${data.code}:totp`);
        if (totpSecret) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
        } else {
          ws.send(JSON.stringify({ type: 'totp-not-required', code: data.code }));
        }
        return;
      }
      if (data.type === 'set-max-clients') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        if (data.clientId === rooms.get(data.code).initiator) {
          const maxLimit = features.enableRelay || !features.enableP2P ? 50 : 4;
          const room = rooms.get(data.code);
          room.maxClients = Math.min(data.maxClients, maxLimit);
          if (room.maxClients > 4) room.forceRelay = true;
          await redisClient.set(`room:${data.code}`, JSON.stringify({ initiator: room.initiator, maxClients: room.maxClients, forceRelay: !!room.forceRelay }), { EX: 86400 });
          const totalClients = await redisClient.sCard(`room:${data.code}:clients`);
          const msg = { type: 'max-clients', maxClients: room.maxClients, totalClients, forceRelay: !!room.forceRelay };
          pubClient.publish(`room:${data.code}`, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(msg) }));
          logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set max clients.', code: data.code }));
        }
        return;
      }
      if (data.type === 'set-totp') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        if (data.clientId === rooms.get(data.code).initiator) {
          await redisClient.set(`room:${data.code}:totp`, data.secret, { EX: 86400 });
          const msg = { type: 'totp-enabled', code: data.code };
          pubClient.publish(`room:${data.code}`, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(msg) }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
        }
        return;
      }
      if (data.type === 'offer' || data.type === 'answer') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: data.type, ...(data.offer ? { offer: data.offer } : { answer: data.answer }), clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'candidate') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const fwdMsg = { type: 'candidate', candidate: data.candidate, clientId: data.clientId, code: data.code };
        await forwardUnicast(data.code, data.targetId, fwdMsg, data.clientId);
        return;
      }
      if (data.type === 'kick' || data.type === 'ban') {
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        if (data.clientId === rooms.get(data.code).initiator) {
          const room = rooms.get(data.code);
          room.maxClients = Math.max(1, (room.maxClients || 2) - 1);
          await redisClient.set(`room:${data.code}`, JSON.stringify({ initiator: room.initiator, maxClients: room.maxClients, forceRelay: !!room.forceRelay }), { EX: 86400 });
          const totalClients = await redisClient.sCard(`room:${data.code}:clients`);
          pubClient.publish(`room:${data.code}`, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify({ type: 'max-clients', maxClients: room.maxClients, totalClients, forceRelay: !!room.forceRelay }) }));
          pubClient.publish(`room:${data.code}`, JSON.stringify({ type: data.type, targetId: data.targetId, senderId: data.clientId }));
          logStats({ clientId: data.targetId, code: data.code, event: data.type });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can kick/ban.', code: data.code }));
        }
        return;
      }
      if (data.type === 'submit-random') {
        if (!restrictLimit(ipRateLimits, `${hashedIp}:submit-random`, 1, 5, 60000, 'Submit rate limit')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room not found', code: data.code }));
          return;
        }
        const size = await redisClient.sCard(`room:${data.code}:clients`);
        if (size === 0) {
          ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (rooms.get(data.code)?.initiator === data.clientId) {
          const added = await redisClient.sAdd('randomCodes', data.code);
          if (added) {
            randomCodes.add(data.code);
            broadcastRandomCodes();
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
        }
        return;
      }
      if (data.type === 'get-random-codes') {
        // Updated: Fetch from Redis for global sync
        const codes = await redisClient.sMembers('randomCodes');
        ws.send(JSON.stringify({ type: 'random-codes', codes }));
        return;
      }
      if (data.type === 'remove-random-code') {
        if (randomCodes.has(data.code)) {
          // Added: Remove from Redis and local Set
          await redisClient.sRem('randomCodes', data.code);
          randomCodes.delete(data.code);
          broadcastRandomCodes();
          logger.info('random code removed');
        }
        return;
      }
      // New: Handle clear-random-codes (admin only)
      if (data.type === 'clear-random-codes') {
        if (!checkAdminSecret(data, ws)) return;
        await redisClient.del('randomCodes');
        randomCodes.clear();
        broadcastRandomCodes();
        logger.info('Random codes cleared by admin');
        const timestamp = new Date().toISOString();
        userLogger.info(`${timestamp} - Admin cleared random codes`);
        ws.send(JSON.stringify({ type: 'random-codes-cleared' }));
        return;
      }
      if (data.type === 'relay-message' || data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') {
        if (data.type === 'relay-image' && !features.enableImages) {
          ws.send(JSON.stringify({ type: 'error', message: 'Image messages are disabled.', code: data.code }));
          return;
        }
        if (data.type === 'relay-voice' && !features.enableVoice) {
          ws.send(JSON.stringify({ type: 'error', message: 'Voice messages are disabled.', code: data.code }));
          return;
        }
        const payloadKey = data.content || data.encryptedContent || data.data || data.encryptedData;
        if (payloadKey && (typeof payloadKey !== 'string' || (data.encryptedContent || data.encryptedData || data.type !== 'relay-message') && !isValidBase64(payloadKey))) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid payload format.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const payloadSize = payloadKey ? (payloadKey.length * 3 / 4) : 0;
        if (!restrictLimit(clientSizeLimits, data.clientId, payloadSize, 1048576, 60000, 'Size limit')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Message size limit exceeded (1MB/min total).', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (payloadKey && payloadKey.length > 9333333) {
          ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 5MB).', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const room = rooms.get(data.code);
        const senderId = data.clientId;
        if (!room.clients.has(senderId)) {
          ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
          incrementFailure(clientIp, ws.userAgent);
          return;
        }
        // Check duplicate nonce globally
        const noncesKey = `room:${data.code}:nonces`;
        const existingTs = await redisClient.hGet(noncesKey, data.nonce);
        if (existingTs) {
          logger.warn(`Duplicate nonce ${data.nonce} in room ${data.code}, ignoring`);
          return;
        }
        const now = Date.now();
        if (Math.abs(now - data.timestamp) > 300000) {
          logger.warn(`Invalid timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp} (now: ${now})`);
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid message timestamp.', code: data.code }));
          return;
        }
        // Updated: Allow small future tolerance to handle clock skew (e.g., 30 seconds)
        if (data.timestamp > now + 30000) {
          logger.warn(`Future timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp} (now: ${now})`);
          ws.send(JSON.stringify({ type: 'error', message: 'Message timestamp in future.', code: data.code }));
          return;
        }
        await redisClient.hSet(noncesKey, data.nonce, data.timestamp);
        await redisClient.expire(noncesKey, 86400);
        const mime = data.mime ? validator.escape(validator.trim(data.mime)) : undefined;
        // Prepare client message object
        const clientMessageObj = {
          type: data.type.replace('relay-', ''),
          messageId: data.messageId,
          username: room.clients.get(senderId).username,
          content: data.content,
          encryptedContent: data.encryptedContent,
          data: data.data,
          encryptedData: data.encryptedData,
          filename: data.filename,
          timestamp: data.timestamp,
          iv: data.iv,
          signature: data.signature,
          nonce: data.nonce,
          mime: mime,
          senderId: senderId,
          identityPublic: data.identityPublic,
          identitySig: data.identitySig,
          sk: data.sk
        };
        const clientJson = JSON.stringify(clientMessageObj);
        // Publish to Redis
        const pubObj = {
          type: 'relay',
          messageType: data.type, // For logging
          clientMessage: clientJson,
          senderId: senderId
        };
        const pubJson = JSON.stringify(pubObj);
        pubClient.publish(`room:${data.code}`, pubJson).then(() => {
          logger.info('published %s', data.type);
        }).catch(err => {
          logger.error('Redis publish error: %o', err);
        });
        return;
      }
      if (data.type === 'get-stats') {
        if (!checkAdminSecret(data, ws)) return;
        const now = new Date();
        const day = now.toISOString().slice(0, 10);
        let totalClients = 0;
        rooms.forEach(room => {
          totalClients += room.clients.size;
        });
        let weekly = computeAggregate(7);
        let monthly = computeAggregate(30);
        let yearly = computeAggregate(365);
        ws.send(JSON.stringify({
          type: 'stats',
          dailyUsers: dailyUsers.get(day)?.size || 0,
          dailyConnections: dailyConnections.get(day)?.size || 0,
          weeklyUsers: weekly.users,
          weeklyConnections: weekly.connections,
          monthlyUsers: monthly.users,
          monthlyConnections: monthly.connections,
          yearlyUsers: yearly.users,
          yearlyConnections: yearly.connections,
          allTimeUsers: allTimeUsers.size,
          activeRooms: rooms.size,
          totalClients: totalClients
        }));
        return;
      }
      if (data.type === 'get-features') {
        if (!checkAdminSecret(data, ws)) return;
        ws.send(JSON.stringify({ type: 'features', ...features }));
        return;
      }
      if (data.type === 'toggle-feature') {
        if (!checkAdminSecret(data, ws)) return;
        const featureKey = `enable${data.feature.charAt(0).toUpperCase() + data.feature.slice(1)}`;
        if (features.hasOwnProperty(featureKey)) {
          features[featureKey] = !features[featureKey];
          await saveFeatures();
          const timestamp = new Date().toISOString();
          userLogger.info(`${timestamp} - Admin toggled ${featureKey} to ${features[featureKey]} by client ${hashIp(clientIp)}`);
          ws.send(JSON.stringify({ type: 'feature-toggled', feature: data.feature, enabled: features[featureKey] }));
          // New: Publish updated features to Redis instead of local broadcast
          pubClient.publish('global:features', JSON.stringify(features));
          if (data.feature === 'service' && !features.enableService) {
            clientTokens.forEach((tokens, clientId) => {
              revokedTokens.set(tokens.accessToken, Date.now() + 1000);
              if (tokens.refreshToken) {
                revokedTokens.set(tokens.refreshToken, Date.now() + 1000);
              }
            });
            clientTokens.clear();
            logger.info('All tokens invalidated due to service disable');
            rooms.clear();
            randomCodes.clear();
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid feature' }));
        }
        return;
      }
      if (data.type === 'export-stats-csv') {
        if (!checkAdminSecret(data, ws)) return;
        const csv = generateStatsCSV();
        ws.send(JSON.stringify({ type: 'export-stats-csv', csv }));
        return;
      }
      if (data.type === 'export-logs-csv') {
        if (!checkAdminSecret(data, ws)) return;
        const csv = generateLogsCSV();
        ws.send(JSON.stringify({ type: 'export-logs-csv', csv }));
        return;
      }
      if (data.type === 'get-turn-credentials') {
        const turn = issueTurnCredentials(data.clientId || ws.clientId);
        ws.send(JSON.stringify({ type: 'turn-credentials', ...turn }));
        return;
      }
      if (data.type === 'leave') {
        if (ws.code && rooms.has(ws.code)) {
          const leftCode = ws.code;
          const roomKey = `room:${leftCode}`;
          const clientsKey = `${roomKey}:clients`;
          await redisClient.sRem(clientsKey, ws.clientId);
          await redisClient.del(`${roomKey}:client:${ws.clientId}`);
          rooms.get(leftCode).clients.delete(ws.clientId);
          const totalClients = await redisClient.sCard(clientsKey);
          pubClient.publish(roomKey, JSON.stringify({
            type: 'broadcast',
            clientMessage: JSON.stringify({
              type: 'client-disconnected',
              clientId: ws.clientId,
              totalClients,
              isInitiator: ws.clientId === rooms.get(leftCode).initiator
            })
          }));
          if (totalClients === 0) {
            rooms.delete(leftCode);
            await redisClient.del(roomKey);
            await redisClient.del(`${roomKey}:totp`);
            await redisClient.del(`${roomKey}:nonces`);
            await redisClient.sRem('randomCodes', leftCode);
            randomCodes.delete(leftCode);
            if (typeof broadcastRandomCodes === 'function') broadcastRandomCodes();
          }
          ws.code = null;
        }
        return;
      }
      if (data.type === 'room-wipe') {
        if (!ws.code || ws.code !== data.code) {
          ws.send(JSON.stringify({ type: 'error', message: 'Not in that room.' }));
          return;
        }
        pubClient.publish(`room:${data.code}`, JSON.stringify({
          type: 'broadcast',
          clientMessage: JSON.stringify({ type: 'room-wipe', clientId: data.clientId })
        }));
        setTimeout(() => { destroyRoom(data.code).catch(() => {}); }, 400);
        return;
      }
      if (data.type === 'watch-bind') {
        watchBinds.set(data.token, { code: data.code, at: Date.now() });
        ws.send(JSON.stringify({ type: 'watch-bound', ok: true }));
        return;
      }
      if (data.type === 'watch-burn') {
        const bound = watchBinds.get(data.token);
        if (!bound || Date.now() - bound.at > 6 * 60 * 60 * 1000) {
          ws.send(JSON.stringify({ type: 'error', message: 'No room on this link.' }));
          return;
        }
        pubClient.publish(`room:${bound.code}`, JSON.stringify({
          type: 'broadcast',
          clientMessage: JSON.stringify({ type: 'room-wipe', clientId: 'watch' })
        }));
        setTimeout(() => { destroyRoom(bound.code).catch(() => {}); }, 400);
        watchBinds.delete(data.token);
        ws.send(JSON.stringify({ ok: true, type: 'watch-burned' }));
        return;
      }
      if (data.type === 'ping') {
        markOnline(data.clientId || ws.clientId);
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      if (data.type === 'pong') {
        logger.info('Received pong from client');
        return;
      }
      if (data.type === 'register-username') {
        const { username, password, public_key, identity_public_key } = data;
        if (validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          const checkRes = await safeQuery('SELECT * FROM users WHERE username = $1', [username], ws, 'Failed to register username.');
          if (checkRes.rows.length > 0) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username taken.' }));
            return;
          }
          const passwordHash = await hashPassword(password);
          await safeQuery(
            'INSERT INTO users (username, password_hash, client_id, public_key, identity_public_key) VALUES ($1, $2, $3, $4, $5)',
            [username, passwordHash, data.clientId, public_key || null, identity_public_key || null],
            ws,
            'Failed to register username.'
          );
          ws.send(JSON.stringify({ type: 'username-registered', username }));
          logger.info('username registered');
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'login-username') {
        const { username, password, public_key, identity_public_key } = data; // Updated: Allow public_key
        if (validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          const res = await safeQuery('SELECT * FROM users WHERE username = $1', [username], ws, 'Failed to login.');
          if (res.rows.length === 0) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid login credentials.' }));
            return;
          }
          const user = res.rows[0];
          const valid = await validatePassword(password, user.password_hash);
          if (!valid) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid login credentials.' }));
            return;
          }
          // Updated: Update public_key if provided
          const updateParams = [data.clientId, new Date()];
          let updateQuery = 'UPDATE users SET client_id = $1, last_active = $2 WHERE id = $3';
          if (public_key && isValidBase64(public_key) && identity_public_key && isValidBase64(identity_public_key)) {
            updateQuery = 'UPDATE users SET client_id = $1, last_active = $2, public_key = $3, identity_public_key = $4 WHERE id = $5';
            updateParams.push(public_key, identity_public_key, user.id);
          } else if (public_key && isValidBase64(public_key)) {
            updateQuery = 'UPDATE users SET client_id = $1, last_active = $2, public_key = $3 WHERE id = $4';
            updateParams.push(public_key, user.id);
          } else {
            updateParams.push(user.id);
          }
          await safeQuery(updateQuery, updateParams, ws, 'Failed to update user on login.');
          const msgRes = await safeQuery(`
            SELECT om.id, om.message
            FROM offline_messages om
            WHERE om.to_user_id = $1
          `, [user.id], ws, 'Failed to fetch offline messages.');
          const offlineMessages = msgRes.rows.map(msg => {
            try {
              const parsedMessage = JSON.parse(msg.message);
              return {
                id: msg.id,
                from: null,
                code: null,
                type: parsedMessage.type || 'message',
                encrypted: parsedMessage.encrypted || null,
                iv: parsedMessage.iv || null,
                ephemeral_public: parsedMessage.ephemeral_public || null,
                messageId: parsedMessage.messageId || null
              };
            } catch (err) {
              logger.error(`Failed to parse offline message for user ${user.id}: %s`, err.message);
              return null;
            }
          }).filter(msg => msg !== null);
          logger.info('offline fetch');
          ws.send(JSON.stringify({ type: 'login-success', username, offlineMessages }));
          logger.info('user login');
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'find-user') {
        const { username } = data;
        const from_res = await safeQuery('SELECT id, username FROM users WHERE client_id = $1', [data.clientId], ws, 'Must be logged in to search users.');
        if (from_res.rows.length === 0) {
          logger.warn(`Find-user failed: No user found for clientId ${data.clientId}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Must be logged in to search users.' }));
          return;
        }
        const res = await safeQuery('SELECT id, client_id, public_key, identity_public_key, last_active FROM users WHERE username = $1', [username], ws, 'Failed to find user.');
        if (res.rows.length === 0) {
          ws.send(JSON.stringify({ type: 'user-not-found' }));
          return;
        }
        const user = res.rows[0];
        let isOnline = false;
        try {
          isOnline = !!(await redisClient.get('online:' + user.client_id));
        } catch (e) {}
        if (!isOnline) {
          const lastActive = user.last_active ? new Date(user.last_active).getTime() : 0;
          isOnline = Date.now() - lastActive < 2 * 60 * 1000;
        }
        ws.send(JSON.stringify({
          type: 'user-found',
          status: isOnline ? 'online' : 'offline',
          public_key: user.public_key,
          identity_public_key: user.identity_public_key
        }));
        logger.info('user lookup');
        return;
      }
      if (data.type === 'send-offline-message') {
        const { to_username, encrypted, iv, ephemeral_public, messageId } = data;
        const res = await safeQuery('SELECT id, client_id FROM users WHERE username = $1', [to_username], ws, 'Recipient not found.');
        if (res.rows.length === 0) {
          ws.send(JSON.stringify({ type: 'error', message: 'Recipient not found.' }));
          return;
        }
        const to_user_id = res.rows[0].id;
        const to_client_id = res.rows[0].client_id;
        const from_res = await safeQuery('SELECT id FROM users WHERE client_id = $1', [data.clientId], ws, 'Sender not logged in with a username.');
        if (from_res.rows.length === 0) {
          logger.warn(`Send-offline-message failed: No user found for clientId ${data.clientId}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Sender not logged in with a username.' }));
          return;
        }
        const sealed = JSON.stringify({ type: 'message', encrypted, iv, ephemeral_public, messageId });
        const inserted = await safeQuery(
          'INSERT INTO offline_messages (from_user_id, to_user_id, message) VALUES ($1, $2, $3) RETURNING id',
          [null, to_user_id, sealed],
          ws,
          'Failed to send offline message.'
        );
        const rowId = inserted && inserted.rows && inserted.rows[0] ? inserted.rows[0].id : null;
        const payload = {
          type: 'inbox-message',
          id: rowId,
          encrypted,
          iv,
          ephemeral_public,
          messageId
        };
        try {
          await pubClient.publish('inbox', JSON.stringify({ targetClientId: to_client_id, payload }));
        } catch (e) {}
        ws.send(JSON.stringify({ type: 'offline-message-sent', messageId }));
        logger.info('offline stored');
        return;
      }
      if (data.type === 'confirm-offline-message') {
        const owner = await safeQuery('SELECT id FROM users WHERE client_id = $1', [data.clientId], ws, 'Not logged in.');
        if (owner.rows.length === 0) {
          ws.send(JSON.stringify({ type: 'error', message: 'Not logged in.' }));
          return;
        }
        const del = await safeQuery(
          'DELETE FROM offline_messages WHERE id = $1 AND to_user_id = $2',
          [data.messageId, owner.rows[0].id],
          ws,
          'Failed to confirm offline message.'
        );
        logger.info(`Confirmed offline message ${data.messageId} for owner ${owner.rows[0].id}`);
        ws.send(JSON.stringify({ type: 'confirm-offline-message-ack', messageId: data.messageId }));
        return;
      }
      if (data.type === 'logout') {
        revokeTokens(data.clientId);
        if (ws.code && rooms.has(ws.code)) {
          // Logout triggers close handler
          ws.close();
        }
        ws.send(JSON.stringify({ type: 'logout-success' }));
        return;
      }
    } catch (error) {
      logger.error('Error processing message: %s %s', error.message, error.stack);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again. Check server logs.' }));
      incrementFailure(clientIp, ws.userAgent);
    }
  });
  ws.on('close', async () => {
    const currentTokens = clientTokens.get(ws.clientId);
    if (currentTokens && ws.accessToken && currentTokens.accessToken === ws.accessToken) {
      revokeTokens(ws.clientId);
    }
    let stillConnected = false;
    wss.clients.forEach(c => {
      if (c !== ws && c.clientId === ws.clientId && c.readyState === WebSocket.OPEN) stillConnected = true;
    });
    if (!stillConnected) markOffline(ws.clientId);
    if (ws.code && rooms.has(ws.code) && !stillConnected) {
      const code = ws.code;
      const roomKey = `room:${code}`;
      const clientsKey = `${roomKey}:clients`;
      await redisClient.sRem(clientsKey, ws.clientId);
      const clientKey = `${roomKey}:client:${ws.clientId}`;
      await redisClient.del(clientKey);
      rooms.get(code).clients.delete(ws.clientId);
      rateLimits.delete(ws.clientId);
      const isInitiator = ws.clientId === rooms.get(code).initiator;
      const totalClients = await redisClient.sCard(clientsKey);
      logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients, isInitiator });
      const disconnectedMsg = {
        type: 'client-disconnected',
        clientId: ws.clientId,
        totalClients,
        isInitiator
      };
      pubClient.publish(roomKey, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(disconnectedMsg) }));
      if (totalClients === 0) {
        rooms.delete(code);
        await redisClient.del(roomKey);
        await redisClient.del(`${roomKey}:totp`);
        await redisClient.del(`${roomKey}:nonces`);
        await redisClient.sRem('randomCodes', code);
        randomCodes.delete(code);
        broadcastRandomCodes();
        if (subscribed.has(code)) {
          await subClient.unsubscribe(`room:${code}`);
          subscribed.delete(code);
          logger.info('room unsubscribed');
        }
      } else if (isInitiator) {
        const newInitiator = await redisClient.sRandMember(clientsKey);
        if (newInitiator) {
          rooms.get(code).initiator = newInitiator;
          await redisClient.set(roomKey, JSON.stringify({ initiator: newInitiator, maxClients: rooms.get(code).maxClients }), { EX: 86400 });
          const initiatorChangedMsg = {
            type: 'initiator-changed',
            newInitiator,
            totalClients
          };
          pubClient.publish(roomKey, JSON.stringify({ type: 'broadcast', clientMessage: JSON.stringify(initiatorChangedMsg) }));
        }
      }
    }
    if (ws.clientId) {
      dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [ws.clientId]).catch(err => {
        logger.error('DB error on close: %s %s', err.message, err.stack);
      });
    }
  });
});
function incrementFailure(ip, ua) {
  const hashedIp = hashIp(ip);
  const hashedUa = hashUa(ua);
  const key = hashedIp + ':' + hashedUa;
  const failure = ipFailureCounts.get(key) || { count: 0, banLevel: 0 };
  failure.count += 1;
  ipFailureCounts.set(key, failure);
  if (failure.count % 5 === 0) {
    logger.warn(`High failure rate for key ${key}: ${failure.count} failures`);
    auditLogger.info(`${new Date().toISOString()} - High failure anomaly for key ${key}: ${failure.count} failures`);
  }
  if (failure.count >= 40) {
    const banDurations = [2 * 60 * 1000, 10 * 60 * 1000, 30 * 60 * 1000];
    failure.banLevel = Math.min((failure.banLevel || 0) + 1, 2);
    const duration = banDurations[failure.banLevel];
    const expiry = Date.now() + duration;
    ipBans.set(key, { expiry, banLevel: failure.banLevel });
    const timestamp = new Date().toISOString();
    const banLogEntry = `${timestamp} - Key Banned: ${key}, Duration: ${duration / 60000} minutes, Ban Level: ${failure.banLevel}`;
    userLogger.info(banLogEntry);
    logger.warn(`Key ${key} banned until ${new Date(expiry).toISOString()} at ban level ${failure.banLevel} (${duration / 60000} minutes)`);
    ipFailureCounts.delete(key);
  }
}
function validateUsername(username) {
  const regex = /^[a-zA-Z0-9]{1,16}$/;
  return username && regex.test(username);
}
function validateCode(code) {
  const regex = /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/;
  return code && regex.test(code);
}
function logStats(data) {
  const timestamp = new Date().toISOString();
  const day = timestamp.slice(0, 10);
  const stats = {
    clientId: validator.escape(data.clientId || ''),
    username: data.username ? validator.escape(crypto.createHmac('sha256', IP_SALT).update(data.username).digest('hex')) : '',
    targetId: validator.escape(data.targetId || ''),
    code: validator.escape(data.code || ''),
    event: validator.escape(data.event || ''),
    totalClients: data.totalClients || 0,
    isInitiator: data.isInitiator || false,
    timestamp,
    day
  };
  if (data.event === 'connect' || data.event === 'join' || data.event === 'webrtc-connection') {
    if (!dailyUsers.has(day)) {
      dailyUsers.set(day, new Set());
    }
    if (!dailyConnections.has(day)) {
      dailyConnections.set(day, new Set());
    }
    dailyUsers.get(day).add(stats.clientId);
    allTimeUsers.add(stats.clientId);
    if (data.event === 'webrtc-connection' && data.targetId) {
      dailyUsers.get(day).add(stats.targetId);
      allTimeUsers.add(stats.targetId);
      const connectionKey = `${stats.clientId}-${stats.targetId}-${stats.code}`;
      dailyConnections.get(day).add(connectionKey);
    }
  }
  const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}`;
  userLogger.info(logEntry);
}
function updateLogFile() {
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  const userCount = dailyUsers.get(day)?.size || 0;
  const connectionCount = dailyConnections.get(day)?.size || 0;
  const allTimeUserCount = allTimeUsers.size;
  const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}, All-Time Unique Users: ${allTimeUserCount}`;
  userLogger.info(logEntry);
  logger.info(`Updated ${LOG_FILE} with ${userCount} unique users, ${connectionCount} WebRTC connections, and ${allTimeUserCount} all-time unique users for ${day}`);
  if (!aggregatedStats.daily) aggregatedStats.daily = {};
  aggregatedStats.daily[day] = { users: userCount, connections: connectionCount };
  saveAggregatedStats();
}
userLogger.info('');
updateLogFile();
setInterval(updateLogFile, UPDATE_INTERVAL);
function computeAggregate(days) {
  const now = new Date();
  let users = 0, connections = 0;
  for (let i = 0; i < days; i++) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const key = date.toISOString().slice(0, 10);
    if (aggregatedStats.daily[key]) {
      users += aggregatedStats.daily[key].users;
      connections += aggregatedStats.daily[key].connections;
    }
  }
  return { users, connections };
}
// New: Generate CSV for stats
function generateStatsCSV() {
  let csv = 'Period,Users,Connections\n';
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  csv += `Daily,${dailyUsers.get(day)?.size || 0},${dailyConnections.get(day)?.size || 0}\n`;
  const weekly = computeAggregate(7);
  csv += `Weekly,${weekly.users},${weekly.connections}\n`;
  const monthly = computeAggregate(30);
  csv += `Monthly,${monthly.users},${monthly.connections}\n`;
  const yearly = computeAggregate(365);
  csv += `Yearly,${yearly.users},${yearly.connections}\n`;
  csv += `All-Time,${allTimeUsers.size},N/A\n`;
  return csv;
}
// New: Generate CSV for logs (combine LOG_FILE and AUDIT_FILE)
function generateLogsCSV() {
  let csv = 'Timestamp,Event\n';
  const logContent = fs.readFileSync(LOG_FILE, 'utf8');
  logContent.split('\n').forEach(line => {
    if (line.trim()) csv += `${line}\n`;
  });
  const auditContent = fs.readFileSync(`${AUDIT_FILE_BASE}.log`, 'utf8');
  auditContent.split('\n').forEach(line => {
    if (line.trim()) csv += `${line}\n`;
  });
  return csv;
}
async function broadcastRandomCodes() {
  const codes = await redisClient.sMembers('randomCodes');
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'random-codes', codes }));
    }
  });
  logger.info('broadcast random codes');
}
function hashIp(ip) {
  return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
}
function hashUa(ua) {
  if (!ua) return crypto.createHmac('sha256', IP_SALT).update('unknown').digest('hex');
  const parser = new UAParser(ua);
  const result = parser.getResult();
  const normalized = `${result.browser.name || 'unknown'} ${result.browser.major || ''} ${result.os.name || 'unknown'} ${result.os.version ? result.os.version.split('.')[0] : ''}`.trim();
  return crypto.createHmac('sha256', IP_SALT).update(normalized || 'unknown').digest('hex');
}
server.listen(process.env.PORT || 10000, () => {
  logger.info(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
