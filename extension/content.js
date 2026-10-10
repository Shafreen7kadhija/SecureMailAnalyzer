/**
 * SecureMailAnalyzer — Gmail In-Page Content Script
 * Captures download clicks, prevents unauthorized downloads pre-download,
 * displays in-page SOC threat analysis modals, and enforces single-use release workflows.
 */

(function () {
  'use strict';

  console.log('[SecureMailAnalyzer] Gmail Shield content script active.');

  // Temporary flag to permit one-tick re-dispatch of an authorized download
  const bypassingElements = new WeakSet();

  // Active single-use release tokens keyed by attachment identity
  const activeReleaseTokens = new Map();

  // Helper to extract reliable metadata and identity from Gmail attachment elements
  function extractAttachmentMetadata(target) {
    let current = target;
    let filename = '';
    let messageId = '';
    let partId = '';
    let downloadUrl = '';
    let cardElement = null;

    // 1. Check current element and ancestors up to 10 levels
    for (let i = 0; i < 10 && current && current !== document.body; i++) {
      const aria = current.getAttribute('aria-label') || '';
      const tooltip = current.getAttribute('data-tooltip') || '';
      const href = current.getAttribute('href') || '';
      const dlUrl = current.getAttribute('download_url') || '';

      // Check download URL
      if (!downloadUrl) {
        if (href.includes('view=att') || href.includes('attid=') || dlUrl.includes('view=att')) {
          downloadUrl = href || dlUrl;
        }
      }

      // Extract message ID (th= parameter) from URLs
      if (!messageId) {
        const matchTh = (href + ' ' + dlUrl).match(/[?&]th=([a-f0-9]+)/i);
        if (matchTh && matchTh[1]) {
          messageId = matchTh[1];
        }
      }

      // Extract part ID (attid= parameter) from URLs
      if (!partId) {
        const matchAttId = (href + ' ' + dlUrl).match(/[?&]attid=([0-9.]+)/i);
        if (matchAttId && matchAttId[1]) {
          partId = matchAttId[1];
        }
      }

      // Check filename patterns
      if (!filename) {
        const dlMatch = (aria || tooltip).match(/Download\s+(?:attachment\s+)?(.+)/i);
        if (dlMatch && dlMatch[1]) {
          filename = dlMatch[1].trim();
        }
      }

      // Check Gmail's attachment title classes
      if (!filename && current.querySelector) {
        const titleEl = current.querySelector('.aV3, [role="link"], span[dir="ltr"]');
        if (titleEl && titleEl.textContent && titleEl.textContent.includes('.')) {
          filename = titleEl.textContent.trim();
        }
      }

      // Identify attachment card container
      if (
        current.classList?.contains('aQH') ||
        current.classList?.contains('aQy') ||
        current.getAttribute('role') === 'listitem' ||
        current.hasAttribute('download_url')
      ) {
        cardElement = current;
        if (!filename && current.innerText) {
          const lines = current.innerText.split('\n').map((s) => s.trim()).filter(Boolean);
          const candidate = lines.find((l) => l.includes('.') && l.length > 3 && l.length < 120);
          if (candidate) filename = candidate;
        }
      }

      current = current.parentElement;
    }

    // 2. Fallback for messageId from Gmail's message wrapper elements
    if (!messageId && target.closest) {
      const msgWrapper = target.closest('[data-legacy-message-id], [data-message-id]');
      if (msgWrapper) {
        messageId = msgWrapper.getAttribute('data-legacy-message-id') || msgWrapper.getAttribute('data-message-id') || '';
      }
    }

    // 3. Fallback for messageId from URL hash
    if (!messageId && window.location.hash) {
      const hashMatch = window.location.hash.match(/(?:#inbox|#all|#sent|#starred|#search\/[^\/]+|#label\/[^\/]+)\/([a-f0-9]{16,})/i);
      if (hashMatch && hashMatch[1]) {
        messageId = hashMatch[1];
      }
    }

    // Clean up filename (remove trailing size like "(15 KB)")
    if (filename) {
      filename = filename.replace(/\s*\([0-9.]+\s*[KMGT]?B\)\s*$/i, '').trim();
    }

    return {
      filename: filename || 'attachment.bin',
      gmail_message_id: messageId || null,
      gmail_part_id: partId || null,
      download_url: downloadUrl || null,
      cardElement,
    };
  }

  // Determine if clicked element is an attachment download trigger
  function isDownloadTrigger(target) {
    if (!target) return false;
    let el = target;
    for (let i = 0; i < 6 && el && el !== document.body; i++) {
      const aria = (el.getAttribute('aria-label') || '').toLowerCase();
      const tooltip = (el.getAttribute('data-tooltip') || '').toLowerCase();
      const href = (el.getAttribute('href') || '').toLowerCase();

      if (
        aria.includes('download') ||
        tooltip.includes('download') ||
        href.includes('attid=') ||
        href.includes('&disp=attd') ||
        (el.tagName === 'A' && el.hasAttribute('download')) ||
        el.classList?.contains('aQy')
      ) {
        return true;
      }

      // Check SVG download icons
      if (el.tagName === 'path' || el.tagName === 'svg') {
        const parentBtn = el.closest('button, [role="button"], a');
        if (parentBtn) {
          const btnAria = (parentBtn.getAttribute('aria-label') || '').toLowerCase();
          const btnTooltip = (parentBtn.getAttribute('data-tooltip') || '').toLowerCase();
          if (btnAria.includes('download') || btnTooltip.includes('download')) {
            return true;
          }
        }
      }

      el = el.parentElement;
    }
    return false;
  }

  // Helper to build a unique key for the attachment
  function getAttachmentIdentityKey(meta) {
    if (meta.gmail_message_id) {
      return `${meta.gmail_message_id}_${meta.gmail_part_id || meta.filename || 'unknown'}`;
    }
    // Fail closed against token collision: unanchored attachments get a distinct nonce key
    return `unanchored_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  // In-page SOC Threat Alert Modal
  function showThreatModal(decision, meta, onReleaseApproved) {
    const existing = document.getElementById('sma-threat-modal-root');
    if (existing) existing.remove();

    const root = document.createElement('div');
    root.id = 'sma-threat-modal-root';

    const isBlocked = decision.is_blocked;
    const score = decision.risk_score !== undefined && decision.risk_score !== null ? `${decision.risk_score}/100` : 'PENDING';
    const severity = decision.severity || 'HIGH';

    root.innerHTML = `
      <div class="sma-modal-backdrop">
        <div class="sma-modal-card ${isBlocked ? 'sma-border-danger' : 'sma-border-warning'}">
          <div class="sma-modal-header">
            <div class="sma-header-icon ${isBlocked ? 'sma-icon-danger' : 'sma-icon-warning'}">
              🛡️
            </div>
            <div>
              <div class="sma-badge-row">
                <span class="sma-badge ${isBlocked ? 'sma-badge-danger' : 'sma-badge-warning'}">
                  ${isBlocked ? 'PRE-DOWNLOAD ACTION BLOCKED' : 'VERIFICATION REQUIRED'}
                </span>
                <span class="sma-score-badge">RISK SCORE: ${score} (${severity})</span>
              </div>
              <h2 class="sma-modal-title">SecureMailAnalyzer Pre-Download Protection</h2>
            </div>
            <button class="sma-close-btn" id="sma-close-modal">&times;</button>
          </div>

          <div class="sma-modal-body">
            <div class="sma-file-box">
              <span class="sma-file-label">TARGET ATTACHMENT:</span>
              <span class="sma-file-name">${decision.filename || meta.filename}</span>
              ${meta.gmail_message_id ? `<span class="sma-file-sub">Message ID: ${meta.gmail_message_id}</span>` : ''}
            </div>

            <p class="sma-reason-text">
              ${decision.reason}
            </p>

            <div class="sma-notice-banner">
              ⚠️ <strong>Strict Prevention Policy:</strong> This download action was halted at the browser event layer before the file reached your computer. Repeating the click will not bypass this block.
            </div>

            <div id="sma-release-form-container" class="sma-release-container" style="display:none;">
              <h4 class="sma-release-title">Authorized Emergency Release Override</h4>
              <p class="sma-release-sub">Requires documented analyst identity and business rationale. Generates an auditable single-use release token (15-minute expiry).</p>
              <input type="text" id="sma-analyst-name" placeholder="Analyst Name / ID (e.g. Jane Doe - SOC Lead)" class="sma-input" />
              <textarea id="sma-release-reason" rows="2" placeholder="Documented business justification (minimum 8 characters)..." class="sma-textarea"></textarea>
              <div class="sma-release-actions">
                <button id="sma-submit-release" class="sma-btn sma-btn-danger">Confirm & Authorize Release</button>
                <button id="sma-cancel-release" class="sma-btn sma-btn-secondary">Cancel</button>
              </div>
            </div>
          </div>

          <div class="sma-modal-footer">
            <a href="http://127.0.0.1:5000/?tab=threat-story${decision.investigation_id ? '&id=' + decision.investigation_id : ''}" target="_blank" class="sma-btn sma-btn-primary">
              Inspect Threat Story in SOC Console &rarr;
            </a>
            ${
              isBlocked && decision.can_release && decision.investigation_id
                ? `<button id="sma-trigger-release" class="sma-btn sma-btn-outline">Authorize Single-Use Release</button>`
                : ''
            }
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(root);

    // Event listeners
    document.getElementById('sma-close-modal')?.addEventListener('click', () => root.remove());

    const triggerReleaseBtn = document.getElementById('sma-trigger-release');
    const releaseForm = document.getElementById('sma-release-form-container');
    if (triggerReleaseBtn && releaseForm) {
      triggerReleaseBtn.addEventListener('click', () => {
        releaseForm.style.display = 'block';
        triggerReleaseBtn.style.display = 'none';
      });
    }

    document.getElementById('sma-cancel-release')?.addEventListener('click', () => {
      if (releaseForm) releaseForm.style.display = 'none';
      if (triggerReleaseBtn) triggerReleaseBtn.style.display = 'inline-block';
    });

    document.getElementById('sma-submit-release')?.addEventListener('click', () => {
      const analyst = document.getElementById('sma-analyst-name')?.value || '';
      const reason = document.getElementById('sma-release-reason')?.value || '';

      if (analyst.trim().length < 2) {
        alert('Please specify your Analyst Name or ID (minimum 2 characters).');
        return;
      }
      if (reason.trim().length < 8) {
        alert('Please provide a documented justification of at least 8 characters.');
        return;
      }

      chrome.runtime.sendMessage(
        {
          type: 'EXECUTE_RELEASE',
          payload: {
            investigation_id: decision.investigation_id,
            authorized_by: analyst.trim(),
            reason: reason.trim(),
          },
        },
        (res) => {
          if (res && res.success && res.auth_token) {
            alert(`Authorized release issued (${res.auth_token}). Permitting download.`);
            const tokenKey = getAttachmentIdentityKey(meta);
            activeReleaseTokens.set(tokenKey, res.auth_token);
            root.remove();
            if (onReleaseApproved) onReleaseApproved(res.auth_token);
          } else {
            alert('Release failed: ' + (res?.error || 'Unknown server authorization error'));
          }
        }
      );
    });
  }

  // Toast notification
  function showToast(message, isSafe = true) {
    const toast = document.createElement('div');
    toast.className = `sma-toast ${isSafe ? 'sma-toast-safe' : 'sma-toast-warn'}`;
    toast.innerHTML = `<span>🛡️ <strong>SecureMailAnalyzer:</strong> ${message}</span>`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }

  // Core capture click handler
  function handlePotentialDownload(event) {
    // Check if target is download trigger
    if (!isDownloadTrigger(event.target)) return;

    // Check if element is undergoing authorized re-dispatch
    if (bypassingElements.has(event.target)) {
      bypassingElements.delete(event.target);
      return; // Allow native download to execute
    }

    // MANDATORY PRE-DOWNLOAD ENFORCEMENT: Immediately halt native download execution!
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    try {
      const meta = extractAttachmentMetadata(event.target);
      const tokenKey = getAttachmentIdentityKey(meta);
      const pendingReleaseToken = activeReleaseTokens.get(tokenKey) || null;

      console.log('[SecureMailAnalyzer] Intercepted download interaction for:', meta.filename, 'Message ID:', meta.gmail_message_id);

      // Query backend enforcement engine
      chrome.runtime.sendMessage(
        {
          type: 'CHECK_POLICY',
          payload: {
            filename: meta.filename,
            gmail_message_id: meta.gmail_message_id,
            gmail_part_id: meta.gmail_part_id,
            download_url: meta.download_url,
            release_token: pendingReleaseToken,
          },
        },
        (decision) => {
          if (!decision) {
            showThreatModal(
              {
                is_blocked: true,
                severity: 'HIGH',
                filename: meta.filename,
                reason: 'SecureMailAnalyzer local service (127.0.0.1:5000) is unreachable. Pre-download protection fails closed to prevent unverified downloads.',
                can_release: false,
              },
              meta
            );
            return;
          }

          if (decision.status === 'RELEASED' || decision.enforcement_decision === 'RELEASED') {
            // Authorized single-use release redeemed successfully
            activeReleaseTokens.delete(tokenKey);
            showToast(`Single-use release authorized: ${meta.filename}. Initiating download...`, true);
            bypassingElements.add(event.target);
            event.target.click();
          } else if (decision.is_blocked) {
            showThreatModal(decision, meta, (approvedToken) => {
              // On release approval, re-trigger download with new token
              console.log('[SecureMailAnalyzer] Re-triggering download with verified release token.');
              activeReleaseTokens.set(tokenKey, approvedToken);
              bypassingElements.add(event.target);
              event.target.click();
            });
          } else if (decision.status === 'PENDING_ANALYSIS') {
            showThreatModal(decision, meta);
          } else {
            // Clean file permitted under policy
            showToast(`Verified clean under policy (${decision.risk_score}/100 - ${decision.severity}). Permitting download.`, true);
            bypassingElements.add(event.target);
            event.target.click();
          }
        }
      );
    } catch (parseErr) {
      console.error('[SecureMailAnalyzer] Error parsing attachment metadata:', parseErr);
      // Fail closed on parsing exception
      showThreatModal(
        {
          is_blocked: true,
          severity: 'HIGH',
          filename: 'attachment',
          reason: 'Internal extension parsing error while inspecting attachment. Failing closed to protect host.',
          can_release: false,
        },
        { filename: 'attachment' }
      );
    }
  }

  // Inject permanent SOC badge in Gmail top bar
  function injectStatusPill() {
    if (document.getElementById('sma-gmail-status-pill')) return;
    const pill = document.createElement('div');
    pill.id = 'sma-gmail-status-pill';
    pill.innerHTML = `
      <a href="http://127.0.0.1:5000/?tab=gmail-shield" target="_blank" title="SecureMailAnalyzer: Pre-Download Protection Active">
        <span class="sma-pill-dot"></span>
        <span>SecureMailAnalyzer Active</span>
      </a>
    `;
    document.body.appendChild(pill);
  }

  // Register capture-phase click and auxclick (middle-click) listeners
  window.addEventListener('click', handlePotentialDownload, true);
  window.addEventListener('auxclick', handlePotentialDownload, true);

  // Periodic injection of status pill when Gmail DOM loads
  setInterval(injectStatusPill, 3000);
})();
