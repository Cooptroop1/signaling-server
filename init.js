// init.js
// Export UI elements as a module for use in other scripts
export const UI = {
  socket: new WebSocket('wss://signaling-server-zc6m.onrender.com'),
  statusElement: document.getElementById('status'),
  codeDisplayElement: document.getElementById('codeDisplay'),
  copyCodeButton: document.getElementById('copyCodeButton'),
  initialContainer: document.getElementById('initialContainer'),
  usernameContainer: document.getElementById('usernameContainer'),
  connectContainer: document.getElementById('connectContainer'),
  chatContainer: document.getElementById('chatContainer'),
  newSessionButton: document.getElementById('newSessionButton'),
  maxClientsContainer: document.getElementById('maxClientsContainer'),
  inputContainer: document.querySelector('.input-container'),
  messages: document.getElementById('messages'),
  cornerLogo: document.getElementById('cornerLogo'),
  button2: document.getElementById('button2'),
  helpText: document.getElementById('helpText'),
  helpModal: document.getElementById('helpModal'),
  addUserText: document.getElementById('addUserText'),
  addUserModal: document.getElementById('addUserModal'),
  addUserRadios: document.getElementById('addUserRadios'),
  privacyStatus: document.getElementById('privacyStatus'),
  userDots: document.getElementById('userDots'),
  toggleRecent: document.getElementById('toggleRecent'),
  recentCodesList: document.getElementById('recentCodesList'),
  messageInput: document.getElementById('messageInput'),
  sendButton: document.getElementById('sendButton'),
  imageButton: document.getElementById('imageButton'),
  imageInput: document.getElementById('imageInput'),
  voiceButton: document.getElementById('voiceButton'),
  voiceCallButton: document.getElementById('voiceCallButton'),
  audioOutputButton: document.getElementById('audioOutputButton'),
  grokButton: document.getElementById('grokButton'),
  grokKeyContainer: document.getElementById('grokKeyContainer'),
  grokApiKey: document.getElementById('grokApiKey'),
  saveGrokKey: document.getElementById('saveGrokKey'),
  remoteAudioContainer: document.getElementById('remoteAudioContainer'),
  button1: document.getElementById('button1'),
  startChatToggleButton: document.getElementById('startChatToggleButton'),
  start2FAChatButton: document.getElementById('start2FAChatButton'),
  connectToggleButton: document.getElementById('connectToggleButton'),
  connect2FAChatButton: document.getElementById('connect2FAChatButton'),
  recentChats: document.getElementById('recentChats'),
  usernameInput: document.getElementById('usernameInput'),
  joinWithUsernameButton: document.getElementById('joinWithUsernameButton'),
  backButton: document.getElementById('backButton'),
  usernameConnectInput: document.getElementById('usernameConnectInput'),
  codeInput: document.getElementById('codeInput'),
  connectButton: document.getElementById('connectButton'),
  backButtonConnect: document.getElementById('backButtonConnect'),
  claimUsernameButton: document.getElementById('claimUsernameButton'),
  loginButton: document.getElementById('loginButton'),
  searchUserButton: document.getElementById('searchUserButton'),
  logoutButton: document.getElementById('logoutButton'),
  totpOptionsModal: document.getElementById('totpOptionsModal'),
  totpUsernameInput: document.getElementById('totpUsernameInput'),
  totpTypeOptions: document.getElementById('totpTypeOptions'),
  customTotpSecretContainer: document.getElementById('customTotpSecretContainer'),
  customTotpSecret: document.getElementById('customTotpSecret'),
  createTotpRoomButton: document.getElementById('createTotpRoomButton'),
  cancelTotpButton: document.getElementById('cancelTotpButton'),
  totpInputModal: document.getElementById('totpInputModal'),
  totpCodeInput: document.getElementById('totpCodeInput'),
  submitTotpCodeButton: document.getElementById('submitTotpCodeButton'),
  cancelTotpInputButton: document.getElementById('cancelTotpInputButton'),
  totpSecretModal: document.getElementById('totpSecretModal'),
  totpSecretDisplay: document.getElementById('totpSecretDisplay'),
  qrCodeCanvas: document.getElementById('qrCodeCanvas'),
  closeTotpSecretButton: document.getElementById('closeTotpSecretButton'),
  claimUsernameModal: document.getElementById('claimUsernameModal'),
  claimUsernameInput: document.getElementById('claimUsernameInput'),
  claimPasswordInput: document.getElementById('claimPasswordInput'),
  claimError: document.getElementById('claimError'),
  claimSuccess: document.getElementById('claimSuccess'),
  claimSubmitButton: document.getElementById('claimSubmitButton'),
  claimCancelButton: document.getElementById('claimCancelButton'),
  loginModal: document.getElementById('loginModal'),
  loginUsernameInput: document.getElementById('loginUsernameInput'),
  loginPasswordInput: document.getElementById('loginPasswordInput'),
  loginError: document.getElementById('loginError'),
  loginSuccess: document.getElementById('loginSuccess'),
  loginSubmitButton: document.getElementById('loginSubmitButton'),
  loginCancelButton: document.getElementById('loginCancelButton'),
  searchUserModal: document.getElementById('searchUserModal'),
  searchUsernameInput: document.getElementById('searchUsernameInput'),
  searchError: document.getElementById('searchError'),
  searchResult: document.getElementById('searchResult'),
  searchSubmitButton: document.getElementById('searchSubmitButton'),
  searchCancelButton: document.getElementById('searchCancelButton'),
  incomingConnectionModal: document.getElementById('incomingConnectionModal'),
  incomingMessage: document.getElementById('incomingMessage'),
  acceptButton: document.getElementById('acceptButton'),
  denyButton: document.getElementById('denyButton'),
  voiceTimer: document.getElementById('voiceTimer'),
};

// Initialize UI on DOM load
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, initializing maxClients UI');
  if (!UI.statusElement) {
    console.error('Critical UI element missing');
    return;
  }

  // Set initial UI state
  UI.statusElement.textContent = 'Start a new chat or connect to an existing one';
  UI.codeDisplayElement.classList.add('hidden');
  UI.copyCodeButton.classList.add('hidden');
  UI.initialContainer.classList.remove('hidden');
  UI.usernameContainer.classList.add('hidden');
  UI.connectContainer.classList.add('hidden');
  UI.chatContainer.classList.add('hidden');
  UI.newSessionButton.classList.add('hidden');
  UI.maxClientsContainer.classList.add('hidden');
  UI.inputContainer.classList.add('hidden');
  UI.messages.classList.remove('waiting');
  UI.privacyStatus.classList.add('hidden');
  UI.grokKeyContainer.classList.add('hidden');
  UI.remoteAudioContainer.classList.add('hidden');
  UI.audioOutputButton.classList.add('hidden');
  UI.audioOutputButton.classList.add('hidden');
  UI.loginModal.classList.add('hidden');
  UI.searchUserModal.classList.add('hidden');
  UI.claimUsernameModal.classList.add('hidden');
  UI.incomingConnectionModal.classList.add('hidden');
  UI.totpOptionsModal.classList.remove('active');
  UI.customTotpSecretContainer.classList.add('hidden');
  UI.recentCodesList.classList.add('hidden');

  initializeMaxClientsUI();
  setupLazyObserver();
  loadRecentCodes();

  // Corner logo animation
  let cycleTimeout;
  function triggerCycle() {
    if (cycleTimeout) clearTimeout(cycleTimeout);
    UI.cornerLogo.classList.add('wink');
    cycleTimeout = setTimeout(() => {
      UI.cornerLogo.classList.remove('wink');
    }, 500);
    setTimeout(triggerCycle, 60000);
  }
  setTimeout(triggerCycle, 60000);

  // Focus on initial button
  UI.startChatToggleButton?.focus();
});
