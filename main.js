let initiatorPublic;
let userPrivateKey = localStorage.getItem('userPrivateKey'); // Loads saved key
let userPublicKey; // Optional

let turnUsername = '';
let turnCredential = '';
let localStream = null;
let voiceCallActive = false;
let grokBotActive = false;
let grokApiKey = localStorage.getItem('grokApiKey') || '';
let renegotiating = new Map();
let audioOutputMode = 'earpiece';
let totpEnabled = false;
let totpSecret = '';
let pendingTotpSecret = null;
let mediaRecorder = null;
let voiceChunks = [];
let voiceTimerInterval = null;
let messageCount = 0;

const CHUNK_SIZE = 16384; // 16KB safe for data channels
const chunkBuffers = new Map(); // {chunkId: {chunks: [], received: 0}}
const negotiationQueues = new Map();
let globalSendRate = { count: 0, startTime: performance.now() };
const renegotiationCounts = new Map();
const maxRenegotiations = 5;
let keyVersion = 0;
let globalSizeRate = { totalSize: 0, startTime: performance.now() };
let processedNonces = new Map();

// Full working updateFeaturesUI
function updateFeaturesUI() {
  console.log('updateFeaturesUI called');
  const privacyStatus = document.getElementById('privacyStatus');
  if (privacyStatus) {
    privacyStatus.textContent = useRelay ? 'Relay Mode (E2EE)' : 'E2E Encrypted (P2P)';
    privacyStatus.classList.remove('hidden');
  }

  const imageButton = document.getElementById('imageButton');
  const voiceButton = document.getElementById('voiceButton');
  const voiceCallButton = document.getElementById('voiceCallButton');
  const audioOutputButton = document.getElementById('audioOutputButton');
  const grokButton = document.getElementById('grokButton');

  if (imageButton) imageButton.classList.toggle('hidden', !features.enableImages);
  if (voiceButton) voiceButton.classList.toggle('hidden', !features.enableVoice);
  if (voiceCallButton) voiceCallButton.classList.toggle('hidden', !features.enableVoiceCalls);
  if (audioOutputButton) {
    const shouldHide = !features.enableAudioToggle || !voiceCallActive;
    audioOutputButton.classList.toggle('hidden', shouldHide);
  }
  if (grokButton) grokButton.classList.toggle('hidden', !features.enableGrokBot);
}

// Lazy observer — define it here so it's available when sending images
let lazyObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const elem = entry.target;
      if (elem.dataset.src) {
        elem.src = elem.dataset.src;
        delete elem.dataset.src;
        lazyObserver.unobserve(elem);
      }
      if (elem.dataset.fullSrc) {
        elem.src = elem.dataset.fullSrc;
        delete elem.dataset.fullSrc;
        lazyObserver.unobserve(elem);
      }
    }
  });
}, { rootMargin: '100px' });
