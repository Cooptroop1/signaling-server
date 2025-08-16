const fs = require('fs');
const config = require('./config');

async function loadFeatures(redis) {
  try {
    let featuresStr = await redis.get('features');
    if (featuresStr) {
      const parsed = JSON.parse(featuresStr);
      return {
        enableService: parsed.enableService || true,
        enableImages: parsed.enableImages || true,
        enableVoice: parsed.enableVoice || true,
        enableVoiceCalls: parsed.enableVoiceCalls || true,
        enableAudioToggle: parsed.enableAudioToggle || true,
        enableGrokBot: parsed.enableGrokBot || true
      };
    } else {
      const defaultFeatures = {
        enableService: true,
        enableImages: true,
        enableVoice: true,
        enableVoiceCalls: true,
        enableAudioToggle: true,
        enableGrokBot: true
      };
      await redis.set('features', JSON.stringify(defaultFeatures));
      return defaultFeatures;
    }
  } catch (err) {
    console.error('Error loading features from Redis:', err);
    return {
      enableService: true,
      enableImages: true,
      enableVoice: true,
      enableVoiceCalls: true,
      enableAudioToggle: true,
      enableGrokBot: true
    };
  }
}

function saveFeatures(features, FEATURES_FILE) {
  const cleanFeatures = {
    enableService: features.enableService,
    enableImages: features.enableImages,
    enableVoice: features.enableVoice,
    enableVoiceCalls: features.enableVoiceCalls,
    enableAudioToggle: features.enableAudioToggle,
    enableGrokBot: features.enableGrokBot
  };
  fs.writeFileSync(FEATURES_FILE, JSON.stringify(cleanFeatures));
  console.log('Saved features to disk:', cleanFeatures);
}

module.exports = { loadFeatures, saveFeatures };
