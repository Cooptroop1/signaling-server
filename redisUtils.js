async function cleanupRandomCodes(redis) {
  try {
    const codes = await redis.smembers('randomCodes');
    for (const code of codes) {
      if (!await redis.exists(`room:${code}`) || await redis.scard(`room_clients:${code}`) === 0) {
        await redis.srem('randomCodes', code);
      }
    }
    console.log('Auto-cleaned random codes.');
  } catch (err) {
    console.error('Error in random codes cleanup:', err);
  }
}

async function cleanupRevokedTokens(redis) {
  try {
    const now = Date.now();
    const revokedKeys = await redis.keys('revoked:*');
    for (const key of revokedKeys) {
      const expiry = await redis.get(key);
      if (expiry && parseInt(expiry) < now) {
        await redis.del(key);
      }
    }
    console.log(`Cleaned up expired revoked tokens. Remaining: ${revokedKeys.length}`);
  } catch (err) {
    console.error('Error cleaning revoked tokens:', err);
  }
}

module.exports = { cleanupRandomCodes, cleanupRevokedTokens };
