/**
 * SecureMailAnalyzer — Chrome Extension Service Worker (Manifest V3)
 * Enforces pre-download security policy, communicates with local backend,
 * caches verdicts in chrome.storage.session (surviving worker recycles),
 * and provides defense-in-depth download cancellation.
 */

const DEFAULT_BACKEND_URL = 'http://127.0.0.1:5000';

// Fast in-memory policy cache synchronized with chrome.storage.session
const inMemoryCache = new Map();

// Helper to access session-persistent verdicts across service worker lifecycles
async function getSessionVerdicts() {
  if (chrome.storage && chrome.storage.session) {
    try {
      const data = await chrome.storage.session.get('sma_verdicts');
      return data.sma_verdicts || {};
    } catch (e) {
      console.warn('[SecureMailAnalyzer] storage.session read error:', e);
    }
  }
  // Fallback to in-memory cache representation
  const obj = {};
  for (const [k, v] of inMemoryCache.entries()) {
    obj[k] = v;
  }
  return obj;
}

async function saveSessionVerdict(key, decision) {
  inMemoryCache.set(key, decision);
  if (chrome.storage && chrome.storage.session) {
    try {
      const current = await getSessionVerdicts();
      current[key] = decision;
      await chrome.storage.session.set({ sma_verdicts: current });
    } catch (e) {
      console.warn('[SecureMailAnalyzer] storage.session write error:', e);
    }
  }
}

async function clearSessionVerdicts() {
  inMemoryCache.clear();
  if (chrome.storage && chrome.storage.session) {
    try {
      await chrome.storage.session.remove('sma_verdicts');
    } catch (e) {
      console.warn('[SecureMailAnalyzer] storage.session clear error:', e);
    }
  }
}

// Helper to get backend base URL from storage
async function getBackendUrl() {
  try {
    const data = await chrome.storage.local.get(['backendUrl']);
    return data.backendUrl || DEFAULT_BACKEND_URL;
  } catch (e) {
    return DEFAULT_BACKEND_URL;
  }
}

// Check backend status
async function checkBackendStatus() {
  const backend = await getBackendUrl();
  try {
    const res = await fetch(`${backend}/api/extension/status`, { method: 'GET' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return {
      status: 'OFFLINE',
      error: err.message,
      policy: { mode: 'FAIL_CLOSED', blocking_threshold: 50 },
    };
  }
}

// Query backend policy for a specific attachment
async function queryAttachmentPolicy(payload) {
  const backend = await getBackendUrl();
  const cacheKey = [
    payload.gmail_message_id || '',
    payload.gmail_part_id || '',
    payload.filename || '',
  ].join('::');

  try {
    const res = await fetch(`${backend}/api/extension/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      // Fail closed on HTTP error: Never treat backend error as safe!
      const failClosedDecision = {
        status: 'ANALYSIS_FAILED',
        enforcement_decision: 'BLOCKED',
        is_blocked: true,
        reason: `SecureMailAnalyzer backend returned HTTP error ${res.status}. Enforcing fail-closed policy.`,
        filename: payload.filename,
        gmail_message_id: payload.gmail_message_id,
        gmail_part_id: payload.gmail_part_id,
      };
      await saveSessionVerdict(cacheKey, failClosedDecision);
      return failClosedDecision;
    }

    const decision = await res.json();
    decision.gmail_message_id = payload.gmail_message_id;
    decision.gmail_part_id = payload.gmail_part_id;
    await saveSessionVerdict(cacheKey, decision);
    return decision;
  } catch (networkErr) {
    // Fail closed if backend is offline or unreachable
    const failClosedDecision = {
      status: 'BACKEND_UNAVAILABLE',
      enforcement_decision: 'BLOCKED',
      is_blocked: true,
      reason: 'SecureMailAnalyzer local service (127.0.0.1:5000) is unreachable. Pre-download protection fails closed to prevent unverified downloads.',
      filename: payload.filename,
      gmail_message_id: payload.gmail_message_id,
      gmail_part_id: payload.gmail_part_id,
    };
    await saveSessionVerdict(cacheKey, failClosedDecision);
    return failClosedDecision;
  }
}

// Execute authorized release
async function requestAuthorizedRelease(payload) {
  const backend = await getBackendUrl();
  try {
    const res = await fetch(`${backend}/api/extension/release`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Failed to authorize release');
    }

    // Invalidate session cache upon release so next query reflects updated policy
    await clearSessionVerdicts();
    return data;
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// Message listener from content script or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_POLICY') {
    queryAttachmentPolicy(message.payload).then(sendResponse);
    return true; // Keep message channel open for async response
  }

  if (message.type === 'EXECUTE_RELEASE') {
    requestAuthorizedRelease(message.payload).then(sendResponse);
    return true;
  }

  if (message.type === 'GET_STATUS') {
    checkBackendStatus().then(sendResponse);
    return true;
  }
});

/**
 * Secondary defense-in-depth: chrome.downloads interception.
 * Note: The PRIMARY pre-download prevention is the DOM capture-phase interception in content.js.
 * chrome.downloads.onCreated is an asynchronous post-creation event in Chromium; it cannot guarantee
 * zero bytes touched temporary storage if the network stream is already active, but it cancels
 * any matching download before completion.
 */
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const url = downloadItem.url || '';
  const finalUrl = downloadItem.finalUrl || '';
  const referrer = downloadItem.referrer || '';
  const isGmailDownload =
    url.includes('mail.google.com') ||
    finalUrl.includes('mail.google.com') ||
    referrer.includes('mail.google.com');

  if (!isGmailDownload) return;

  // Extract URL parameters if present
  let urlMessageId = '';
  let urlPartId = '';
  try {
    const targetUrl = new URL(url || finalUrl);
    urlMessageId = targetUrl.searchParams.get('th') || '';
    urlPartId = targetUrl.searchParams.get('attid') || '';
  } catch (e) {
    // URL parsing failed; proceed with filename
  }

  const rawFilename = downloadItem.filename ? downloadItem.filename.split(/[\\/]/).pop().trim() : '';

  const storedVerdicts = await getSessionVerdicts();

  for (const [key, decision] of Object.entries(storedVerdicts)) {
    if (!decision || !decision.is_blocked) continue;

    let isMatch = false;

    // Match 1: Message ID + Part ID from download URL match stored verdict (strongest compound match)
    if (urlMessageId && urlPartId && decision.gmail_message_id && decision.gmail_part_id) {
      if (decision.gmail_message_id === urlMessageId && decision.gmail_part_id === urlPartId) {
        isMatch = true;
      }
    }

    // Match 2: Message ID match + exact filename match (requires verified message ID anchor, length >= 2)
    // Never matches on filename alone; must have urlMessageId proving it belongs to the same message
    if (!isMatch && urlMessageId && decision.gmail_message_id && decision.gmail_message_id === urlMessageId && rawFilename.length >= 2) {
      if (decision.filename && rawFilename.toLowerCase() === decision.filename.toLowerCase()) {
        isMatch = true;
      }
    }

    // Do NOT fall back to matching on filename alone (Match 3 removed).
    // An unanchored filename alone cannot be trusted as attachment identity.
    // If reliable identity (message ID or message ID + part ID) is unavailable or mismatched,
    // the download is not cancelled by filename alone to avoid false positives or cross-message collision.

    if (isMatch) {
      console.warn(
        `[SecureMailAnalyzer] Defense-in-depth: Cancelling blocked Gmail download (ID: ${downloadItem.id}, File: ${rawFilename || decision.filename})`
      );
      chrome.downloads.cancel(downloadItem.id, () => {
        if (chrome.runtime.lastError) {
          console.warn('[SecureMailAnalyzer] Download cancel notification:', chrome.runtime.lastError.message);
        }
      });
      break;
    }
  }
});
