/* ═══════════════════════════════════════════════════════
   KAVACH — EmailJS Emergency Alert Module
   Shared across dashboard.html + fraud.html
   ═══════════════════════════════════════════════════════ */

// ── EmailJS Config ───────────────────────────────────────
const EMAILJS_CONFIG = {
  PUBLIC_KEY:  'cudlMrVPY16x3lJ5p',       // Your EmailJS public key
  SERVICE_ID:  'service_ezrenq8',          // Restored 'service_' prefix
  TEMPLATE_ID: 'template_hqptc4i',         // ✅ Real EmailJS template ID
};

// ── Alert Recipients ─────────────────────────────────────
const ALERT_RECIPIENTS = [
  'dibyabhusal82@gmail.com',   // Primary (your account email)
  'manash110145@gmail.com',           // Placeholder — update as needed
  'sonyaah860@gmail.com',        // Placeholder
  'akshyatarai07@gmail.com',        // Placeholder
];

// ── Validate config on load ──────────────────────────────
(function validateConfig() {
  const missing = [];
  if (!EMAILJS_CONFIG.PUBLIC_KEY) missing.push('PUBLIC_KEY');
  if (!EMAILJS_CONFIG.SERVICE_ID) missing.push('SERVICE_ID');
  if (!EMAILJS_CONFIG.TEMPLATE_ID) missing.push('TEMPLATE_ID');
  if (missing.length) {
    console.warn('[KAVACH EmailJS] Missing config:', missing.join(', '));
  } else {
    emailjs.init(EMAILJS_CONFIG.PUBLIC_KEY);
    console.log('[KAVACH EmailJS] Initialized ✓');
  }
})();

// ── Auto-send guard ──────────────────────────────────────
const _autoSentAlerts = new Set(); // tracks alert IDs already sent

// ── Core send function ────────────────────────────────────
/**
 * Sends alert email to all ALERT_RECIPIENTS.
 * @param {number} score       - Fraud score (0-100)
 * @param {string} risk        - Risk level: LOW/MEDIUM/HIGH/CRITICAL
 * @param {string} message     - Alert message / description
 * @param {string} [alertId]   - Optional ID to prevent duplicate auto-sends
 */
function sendAlertToAll(score, risk, message, alertId) {
  if (!EMAILJS_CONFIG.PUBLIC_KEY || !EMAILJS_CONFIG.SERVICE_ID || !EMAILJS_CONFIG.TEMPLATE_ID) {
    showAlertToast('❌ EmailJS not configured. Check console.', 'error');
    console.error('[KAVACH EmailJS] Cannot send — missing config.');
    return;
  }

  const payload = {
    score: score,
    risk: risk,
    message: message || 'High-risk event detected by KAVACH ATM-Sentinel.',
    time: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
    system: 'KAVACH ATM-Sentinel v2.0',
  };

  let successCount = 0;
  let failCount = 0;
  const total = ALERT_RECIPIENTS.length;

  ALERT_RECIPIENTS.forEach((email) => {
    emailjs.send(
      EMAILJS_CONFIG.SERVICE_ID,
      EMAILJS_CONFIG.TEMPLATE_ID,
      { ...payload, to_email: email }
    )
      .then(() => {
        successCount++;
        console.log('[KAVACH EmailJS] ✓ Sent to', email);
        if (successCount + failCount === total) {
          const msg = failCount === 0
            ? `✅ Alert sent to ${successCount} recipients`
            : `⚠ Sent to ${successCount}, failed for ${failCount}`;
          showAlertToast(msg, failCount === 0 ? 'success' : 'warning');
        }
      })
      .catch((err) => {
        failCount++;
        // Logs specific reason (e.g., 'The service ID is invalid')
        console.error('[KAVACH EmailJS] ✗ Failed for', email, err.text || err);
        if (successCount + failCount === total) {
          const detail = err.text ? `: ${err.text}` : '';
          showAlertToast(`❌ Email failed${detail}`, 'error');
        }
      });
  });
}

// ── Auto-trigger (call from fraud monitor polling) ───────
/**
 * Call this on every fraud score poll. Sends once per unique alertId.
 * @param {number} score
 * @param {string} risk
 * @param {string} message
 * @param {string} alertId  - Unique ID (e.g. transaction_id)
 */
function autoTriggerAlert(score, risk, message, alertId) {
  if (score >= 80 && alertId && !_autoSentAlerts.has(alertId)) {
    _autoSentAlerts.add(alertId);
    console.log('[KAVACH EmailJS] Auto-trigger fired for score:', score, 'id:', alertId);
    sendAlertToAll(score, risk, message, alertId);
    showAlertToast(`🚨 Auto-alert sent! Score: ${score} (${risk})`, 'critical');
  }
}

// ── Toast notification ────────────────────────────────────
function showAlertToast(message, type = 'success') {
  const existing = document.getElementById('kavach-alert-toast');
  if (existing) existing.remove();

  const colors = {
    success: { bg: 'rgba(0,230,118,0.12)', border: '#00E676', text: '#00E676' },
    warning: { bg: 'rgba(255,176,32,0.12)', border: '#FFB020', text: '#FFB020' },
    error: { bg: 'rgba(255,51,102,0.12)', border: '#FF3366', text: '#FF3366' },
    critical: { bg: 'rgba(255,51,102,0.18)', border: '#FF3366', text: '#fff' },
  };
  const c = colors[type] || colors.success;

  const toast = document.createElement('div');
  toast.id = 'kavach-alert-toast';
  toast.style.cssText = `
    position:fixed; bottom:28px; right:28px; z-index:99999;
    padding:14px 20px; border-radius:10px; max-width:360px;
    background:${c.bg}; border:1px solid ${c.border};
    color:${c.text}; font-family:monospace; font-size:13px;
    box-shadow:0 8px 32px rgba(0,0,0,0.4);
    animation:toastIn .3s ease; pointer-events:none;
  `;
  toast.innerHTML = message;

  // Inject animation if not present
  if (!document.getElementById('kavach-toast-style')) {
    const s = document.createElement('style');
    s.id = 'kavach-toast-style';
    s.textContent = '@keyframes toastIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}';
    document.head.appendChild(s);
  }

  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4500);
}
