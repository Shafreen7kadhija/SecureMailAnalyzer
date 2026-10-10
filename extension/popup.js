document.addEventListener('DOMContentLoaded', () => {
  const backendEl = document.getElementById('backend-status');
  const openDashBtn = document.getElementById('open-dashboard');

  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (res) => {
    if (res && res.status === 'ONLINE') {
      backendEl.textContent = 'ONLINE (127.0.0.1:5000)';
      backendEl.className = 'status-val val-online';
    } else {
      backendEl.textContent = 'OFFLINE';
      backendEl.className = 'status-val val-offline';
    }
  });

  openDashBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://127.0.0.1:5000/?tab=gmail-shield' });
  });
});
