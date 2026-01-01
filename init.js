// Initialize UI components on DOM load
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, initializing maxClients UI');
  initializeMaxClientsUI();

  // UI element references and initial states
  const uiElements = {
    status: { id: 'status', text: 'Start a new chat or connect to an existing one' },
    codeDisplay: { id: 'codeDisplay', classAction: 'add', className: 'hidden' },
    copyCode: { id: 'copyCodeButton', classAction: 'add', className: 'hidden' },
    initial: { id: 'initialContainer', classAction: 'remove', className: 'hidden' },
    username: { id: 'usernameContainer', classAction: 'add', className: 'hidden' },
    connect: { id: 'connectContainer', classAction: 'add', className: 'hidden' },
    chat: { id: 'chatContainer', classAction: 'add', className: 'hidden' },
    newSession: { id: 'newSessionButton', classAction: 'add', className: 'hidden' },
    maxClients: { id: 'maxClientsContainer', classAction: 'add', className: 'hidden' },
    input: { id: 'inputContainer', selector: '.input-container', classAction: 'add', className: 'hidden' },
    messages: { id: 'messages', classAction: 'remove', className: 'waiting' },
    cornerLogo: { id: 'cornerLogo' },
    button2: { id: 'button2' },
    helpText: { id: 'helpText' },
    helpModal: { id: 'helpModal' }
  };

  // Apply initial states
  Object.values(uiElements).forEach(config => {
    const element = config.selector 
      ? document.querySelector(config.selector) 
      : document.getElementById(config.id);
    if (element) {
      if (config.text) {
        element.textContent = config.text;
      }
      if (config.classAction && config.className) {
        element.classList[config.classAction](config.className);
      }
    }
  });

  // Corner logo animation
  const cornerLogo = document.getElementById('cornerLogo');
  let cycleTimeout;
  function triggerCycle() {
    if (cycleTimeout) clearTimeout(cycleTimeout);
    if (cornerLogo) {
      cornerLogo.classList.add('wink');
      cycleTimeout = setTimeout(() => {
        cornerLogo.classList.remove('wink');
        setTimeout(triggerCycle, 60000); // Recursive call after wink removal
      }, 500);
    }
  }
  setTimeout(triggerCycle, 60000);

  // Focus on initial button
  document.getElementById('startChatToggleButton')?.focus();
});
