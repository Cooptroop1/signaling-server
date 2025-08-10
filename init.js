
// Initialize UI components on DOM load
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, initializing maxClients UI');
  initializeMaxClientsUI();

  // UI element references
  const statusElement = document.getElementById('status');
  const codeDisplayElement = document.getElementById('codeDisplay');
  const copyCodeButton = document.getElementById('copyCodeButton');
  const initialContainer = document.getElementById('initialContainer');
  const usernameContainer = document.getElementById('usernameContainer');
  const connectContainer = document.getElementById('connectContainer');
  const chatContainer = document.getElementById('chatContainer');
  const newSessionButton = document.getElementById('newSessionButton');
  const maxClientsContainer = document.getElementById('maxClientsContainer');
  const inputContainer = document.querySelector('.input-container');
  const messages = document.getElementById('messages');
  const cornerLogo = document.getElementById('cornerLogo');
  const button2 = document.getElementById('button2');
  const helpText = document.getElementById('helpText');
  const helpModal = document.getElementById('helpModal');

  // Set initial UI state
  if (statusElement) {
    statusElement.textContent = 'Start a new chat or connect to an existing one';
  }
  if (codeDisplayElement) {
    codeDisplayElement.classList.add('hidden');
  }
  if (copyCodeButton) {
    copyCodeButton.classList.add('hidden');
  }
  if (initialContainer) {
    initialContainer.classList.remove('hidden');
  }
  if (usernameContainer) {
    usernameContainer.classList.add('hidden');
  }
  if (connectContainer) {
    connectContainer.classList.add('hidden');
  }
  if (chatContainer) {
    chatContainer.classList.add('hidden');
  }
  if (newSessionButton) {
    newSessionButton.classList.add('hidden');
  }
  if (maxClientsContainer) {
    maxClientsContainer.classList.add('hidden');
  }
  if (inputContainer) {
    inputContainer.classList.add('hidden');
  }
  if (messages) {
    messages.classList.remove('waiting');
  }

  // Corner logo animation
  let cycleTimeout;
  function triggerCycle() {
    if (cycleTimeout) clearTimeout(cycleTimeout);
    if (cornerLogo) {
      cornerLogo.classList.add('wink');
      cycleTimeout = setTimeout(() => {
        cornerLogo.classList.remove('wink');
      }, 500);
      setTimeout(triggerCycle, 60000);
    }
  }
  setTimeout(triggerCycle, 60000);

  // Focus on initial button
  document.getElementById('startChatToggleButton')?.focus();
});
