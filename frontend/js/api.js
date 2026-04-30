/* ═══════════════════════════════════════════════════════
   KAVACH api.js — All fetch() wrappers
═══════════════════════════════════════════════════════ */

// Config is now managed in app.js

function authHeaders() {
  const token = sessionStorage.getItem('kavach_token');
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

async function apiPost(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function apiPostForm(url, formData) {
  const res = await fetch(url, {
    method: 'POST',
    headers: authHeaders(),
    body: formData
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

async function apiGet(url) {
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

// ── Auth ─────────────────────────────────────────────────
async function login(badge_number, password) {
  // Hardcoded credentials: username=admin, password=admin
  if (badge_number === 'admin' && password === 'admin') {
    const officer = {
      name: 'ADMIN OFFICER',
      role: 'ADMINISTRATOR',
      badge: 'ADMIN'
    };
    sessionStorage.setItem('kavach_token', 'kavach_admin_token');
    sessionStorage.setItem('kavach_officer', JSON.stringify(officer));
    return { success: true };
  }
  throw new Error('Invalid credentials — access denied');
}

// ── Deep Trace ───────────────────────────────────────────
async function analyzeVideo(file) {
  const fd = new FormData();
  fd.append('file', file);
  return apiPostForm(KAVACH.DEEPTRACE + '/analyze/video', fd);
}

async function analyzeImage(file) {
  const fd = new FormData();
  fd.append('file', file);
  return apiPostForm(KAVACH.DEEPTRACE + '/analyze/image', fd);
}

// ── Doc Guard ────────────────────────────────────────────
async function analyzeDocument(file) {
  const fd = new FormData();
  fd.append('file', file);
  const docId = file.name.replace(/\.[^/.]+$/, '').replace(/\s+/g, '_') || 'doc_' + Date.now();
  fd.append('doc_id', docId);
  return apiPostForm(KAVACH.DOCGUARD + '/verify', fd);
}

async function uploadDocumentBaseline(file, docId) {
  const fd = new FormData();
  fd.append('file', file);
  fd.append('doc_id', docId || file.name.replace(/\.[^/.]+$/, ''));
  return apiPostForm(KAVACH.DOCGUARD + '/register', fd);
}

// ── FIR Warden ───────────────────────────────────────────
async function registerFIR(firData) {
  return apiPost(KAVACH.FIRWARDEN + '/report', firData);
}

async function listFIRs() {
  return apiGet(KAVACH.FIRWARDEN);
}

async function getFIRAnomalies() {
  // FIR anomalies are returned as part of the FIR object now
  return [];
}

// ── Sentinel ─────────────────────────────────────────────
function sentinelStreamURL(src) {
  return KAVACH.SENTINEL + '/stream?src=' + encodeURIComponent(src);
}

async function getSentinelRisk() {
  return apiGet(KAVACH.SENTINEL + '/risk');
}

async function getSentinelDetections() {
  return apiGet(KAVACH.SENTINEL + '/detections');
}

async function captureSentinelFrame() {
  return apiPost(KAVACH.SENTINEL + '/capture', {});
}

// ── Net Watch ───────────────────────────────────────────
async function getNetWatchStats() {
  return apiGet(KAVACH.NETWATCH + '/stats');
}

async function getNetWatchAccessLog() {
  return apiGet(KAVACH.NETWATCH + '/access-log');
}

async function checkIPIntelligence(ip) {
  return apiPost(KAVACH.NETWATCH + '/check', { ip });
}

async function captureAccess() {
  return apiGet(KAVACH.NETWATCH + '/capture');
}

// ── Fraud / Transaction / Fusion ──────────────────────────
async function getFusionScore() {
  return apiGet(KAVACH.MAIN + '/fraud/fusion-score');
}

async function submitTransaction(txnData) {
  return apiPost(KAVACH.MAIN + '/fraud/transaction', txnData);
}

async function getTransactions(params = {}) {
  const qs = new URLSearchParams();
  if (params.flagged)     qs.set('flagged', 'true');
  if (params.account_id)  qs.set('account_id', params.account_id);
  if (params.limit)       qs.set('limit', params.limit);
  return apiGet(KAVACH.MAIN + '/fraud/transactions?' + qs.toString());
}

async function getFraudAlerts(limit = 10) {
  return apiGet(KAVACH.MAIN + '/fraud/alerts?limit=' + limit);
}

// ── Blockchain ────────────────────────────────────────────
async function getChainStatus() {
  return apiGet(KAVACH.MAIN + '/chain/status');
}

async function getBlockchainLedger() {
  return apiGet(KAVACH.MAIN + '/blockchain');
}

// ── Stats / Health ────────────────────────────────────────
async function getDashboardSummary() {
  return apiGet(KAVACH.STATS + '/dashboard/summary');
}

async function getDashboardChart() {
  return apiGet(KAVACH.STATS + '/dashboard/chart24h');
}

async function checkHealth(service) {
  const urls = {
    sentinel:  KAVACH.SENTINEL  + '/health',
    deeptrace: KAVACH.DEEPTRACE + '/health',
    docguard:  KAVACH.DOCGUARD  + '/health',
    kavach:    KAVACH.MAIN      + '/health',
  };
  return apiGet(urls[service] || (KAVACH.MAIN + '/health'));
}
