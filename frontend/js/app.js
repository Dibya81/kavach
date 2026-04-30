/* ═══════════════════════════════════════════════════════
   KAVACH app.js — Shared across all pages
   Handles: auth guard, sidebar nav active state,
            WebSocket connection, clock, alerts badge
═══════════════════════════════════════════════════════ */

// ── Config ───────────────────────────────────────────────
// SENTINEL + DEEPTRACE run on their own ports (separate modules)
// DOCGUARD + FIRWARDEN + NETWATCH run unified on port 8000
const KAVACH = {
  // Use dynamic origin if running on the same domain as backend, 
  // otherwise fallback to hardcoded HF Space URL.
  get BASE() {
    return (window.location.hostname === 'localhost' || window.location.hostname.includes('hf.space'))
      ? window.location.origin
      : 'https://dibya14-kavach-api.hf.space';
  },

  get MAIN()      { return this.BASE + '/api'; },
  get SENTINEL()  { return this.BASE + '/api/proxy/sentinel'; },
  get DEEPTRACE() { return this.BASE + '/api/proxy/deeptrace'; },
  get NETWATCH()  { return this.BASE + '/api/net-watch'; },
  get FRAUD()     { return this.BASE + '/api/fraud'; },
  get FIRWARDEN() { return this.BASE + '/api/fir'; },
  get DOCGUARD()  { return this.BASE + '/api/doc-guard'; },
  get POLICE()    { return this.BASE + '/api/police'; },
  get STATS()     { return this.BASE + '/api'; },
  
  get WS_URL() {
    const wsProto = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    if (window.location.hostname.includes('hf.space')) {
      return wsProto + window.location.host + '/api/ws/alerts';
    }
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      // run.py starts on 7860; use browser port if explicitly set (e.g. dev server on 5500)
      const port = window.location.port || '7860';
      return wsProto + 'localhost:' + port + '/api/ws/alerts';
    }
    return wsProto + 'dibya14-kavach-api.hf.space/api/ws/alerts';
  }
};

// ── Auth guard ──────────────────────────────────────────
function requireAuth() {
  const token = sessionStorage.getItem('kavach_token');
  const page  = (window.location.pathname.split('/').pop() || 'index.html');
  const PUBLIC_PAGES = ['index.html', 'login.html', ''];
  const isPublic = PUBLIC_PAGES.includes(page);

  if (!token && !isPublic) {
    window.location.replace('index.html');
    return null;
  }
  return token;
}

// Run immediately — blocks page render before any content shows
requireAuth();

function getOfficer() {
  try {
    return JSON.parse(sessionStorage.getItem('kavach_officer') || '{}');
  } catch { return {}; }
}

function logout() {
  sessionStorage.clear();
  window.location.href = 'index.html';
}

// ── Sidebar active state ────────────────────────────────
function initNav() {
  const current = window.location.pathname.split('/').pop();
  document.querySelectorAll('.nav-item').forEach(link => {
    const href = link.getAttribute('href');
    if (href === current) link.classList.add('active');
  });

  const officer = getOfficer();
  const nameEl = document.getElementById('officer-name');
  const roleEl = document.getElementById('officer-role');
  const avatarEl = document.getElementById('officer-avatar');
  if (nameEl)   nameEl.textContent   = officer.name   || 'OFFICER';
  if (roleEl)   roleEl.textContent   = officer.role   || 'CONSTABLE';
  if (avatarEl) avatarEl.textContent = (officer.name || 'O')[0].toUpperCase();
}

// ── Clock ───────────────────────────────────────────────
function initClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const tick = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-IN', { hour12: false }) +
                     ' IST';
  };
  tick();
  setInterval(tick, 1000);
}

// ── WebSocket (global alert stream) ────────────────────
let ws = null;
let wsAlertCount = 0;
const wsHandlers = [];  // other pages can register handlers

function initWS() {
  const dotEl    = document.getElementById('ws-dot');
  const statusEl = document.getElementById('ws-status-text');
  const badgeEl  = document.getElementById('nav-alert-badge');

  function setStatus(state, label) {
    if (dotEl) {
      dotEl.className = 'ws-dot ' + state;
    }
    if (statusEl) statusEl.textContent = label;
  }

  function connect() {
    setStatus('reconnecting', 'connecting...');
    ws = new WebSocket(KAVACH.WS_URL);

    ws.onopen = () => {
      setStatus('connected', 'live');
    };

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'ping') return;
        wsAlertCount++;
        if (badgeEl) badgeEl.textContent = wsAlertCount;
        wsHandlers.forEach(fn => { try { fn(data); } catch(e) {} });
      } catch(e) {}
    };

    ws.onclose = () => {
      setStatus('reconnecting', 'reconnecting...');
      setTimeout(connect, 3000);
    };

    ws.onerror = () => setStatus('error', 'error');
  }

  connect();
}

function onAlert(fn) {
  wsHandlers.push(fn);
}

// ── Sidebar nav HTML (injected into each page) ───────
// Each page calls renderShell() to get the full layout
function renderShell(pageTitle, pageSubtitle, contentHtml) {
  const shell = document.getElementById('shell');
  if (!shell) return;
  
  // Ensure shell has the correct class for layout
  shell.className = 'shell';
  
  shell.innerHTML = `
    <div class="topbar">
      <a href="dashboard.html" class="topbar-logo">KAVACH</a>
      <div class="topbar-sep"></div>
      <span style="font-size:11px;color:var(--text3);letter-spacing:1px">
        NATIONAL INTELLIGENCE PLATFORM
      </span>
      <div class="topbar-right">
        <div class="ws-pill">
          <div class="ws-dot" id="ws-dot"></div>
          <span id="ws-status-text">connecting</span>
        </div>
        <div class="clock" id="clock"></div>
        <button class="btn-logout" onclick="logout()">LOGOUT</button>
      </div>
    </div>

    <div class="shell-body">
      <nav class="sidebar">
        <div class="sidebar-logo"><i class="fas fa-shield-halved"></i><span>KAVACH</span></div>
        
        <div class="nav-group">
          <div class="nav-label">Core</div>
          <a href="dashboard.html" class="nav-item ${window.location.pathname.includes('dashboard.html') ? 'active' : ''}">
            <i class="fas fa-chart-line"></i><span>Dashboard</span>
            <span class="nav-badge hidden" id="nav-alert-badge">0</span>
          </a>
          <a href="fraud.html" class="nav-item ${window.location.pathname.includes('fraud.html') ? 'active' : ''}">
            <i class="fas fa-user-secret"></i><span>Fraud Monitor</span>
          </a>
          <a href="fir.html" class="nav-item ${window.location.pathname.includes('fir.html') ? 'active' : ''}">
            <i class="fas fa-file-invoice"></i><span>FIR Warden</span>
          </a>
        </div>

        <div class="nav-group">
          <div class="nav-label">Surveillance</div>
          <a href="sentinel.html" class="nav-item ${window.location.pathname.includes('sentinel.html') ? 'active' : ''}">
            <i class="fas fa-video"></i><span>Sentinel</span>
          </a>
          <a href="police_dashboard.html" class="nav-item ${window.location.pathname.includes('police_dashboard.html') ? 'active' : ''}" style="color: var(--critical-red);">
            <i class="fas fa-building-shield"></i><span>Police HQ</span>
          </a>
          <a href="deeptrace.html" class="nav-item ${window.location.pathname.includes('deeptrace.html') ? 'active' : ''}">
            <i class="fas fa-fingerprint"></i><span>DeepTrace</span>
          </a>
          <a href="netwatch.html" class="nav-item ${window.location.pathname.includes('netwatch.html') ? 'active' : ''}">
            <i class="fas fa-network-wired"></i><span>NetWatch</span>
          </a>
        </div>

        <div class="nav-group">
          <div class="nav-label">Integrity</div>
          <a href="blockchain.html" class="nav-item ${window.location.pathname.includes('blockchain.html') ? 'active' : ''}">
            <i class="fas fa-link"></i><span>Chain Audit</span>
          </a>
          <a href="docguard.html" class="nav-item ${window.location.pathname.includes('docguard.html') ? 'active' : ''}">
            <i class="fas fa-id-card"></i><span>DocGuard</span>
          </a>
        </div>

        <div class="sidebar-footer" style="margin-top:auto; padding:20px; border-top:1px solid rgba(255,255,255,0.05);">
          <div class="officer-card" style="display:flex; align-items:center; gap:12px;">
            <div class="officer-avatar" id="officer-avatar" style="width:32px; height:32px; background:var(--cyber-blue); color:var(--bg-obsidian); border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px;">O</div>
            <div class="officer-info">
              <div class="officer-name" id="officer-name" style="font-size:12px; font-weight:700;">OFFICER</div>
              <div class="officer-role" id="officer-role" style="font-size:10px; color:var(--text-muted);">CONSTABLE</div>
            </div>
          </div>
        </div>
      </nav>

      <main class="main-content">
        <header class="page-header" style="margin-bottom:32px;">
          <h1 style="font-size:24px; font-weight:700; letter-spacing:-0.5px;">${pageTitle}</h1>
          <p class="muted" style="font-size:14px;">${pageSubtitle}</p>
        </header>
        <div class="page-body">
          ${contentHtml}
        </div>
      </main>
    </div>
  `;

  initNav();
  initClock();
  initWS();
}

// ── Utility: render alert card HTML ─────────────────────
const SEV_ICON = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🟢' };
const SEV_CLASS = { CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low' };

function alertCardHTML(alert) {
  const sev = alert.severity || 'LOW';
  const ts  = alert.timestamp
    ? new Date(alert.timestamp).toLocaleTimeString('en-IN', { hour12: false })
    : new Date().toLocaleTimeString('en-IN', { hour12: false });
  return `
    <div class="alert-card ${SEV_CLASS[sev] || 'low'}">
      <div class="alert-top">
        <span>${SEV_ICON[sev] || '⚪'}</span>
        <span class="alert-type">${alert.type || 'ALERT'}</span>
        <span class="alert-time">${ts}</span>
        <span class="badge badge-${sev.toLowerCase()}">${sev}</span>
      </div>
      <div class="alert-msg">${alert.message || ''}</div>
      ${alert.track_id != null ? `<div class="alert-meta">Track ID: ${alert.track_id}</div>` : ''}
      <div class="alert-meta">Module: ${alert.source || alert.module || '—'}</div>
    </div>
  `;
}

// ── Utility: progress bar color by score ────────────────
function scoreColor(score) {
  if (score > 0.70) return 'red';
  if (score > 0.45) return 'orange';
  return 'green';
}

// ── Utility: score → bar HTML ────────────────────────────
function scoreBar(score, label, detail) {
  const pct   = Math.round(score * 100);
  const color = scoreColor(score);
  const passed = score <= 0.50;
  return `
    <div class="signal-row">
      <div class="signal-name">${label}</div>
      <div class="signal-bar">
        <div class="progress-bar">
          <div class="progress-fill ${color}" style="width:${pct}%"></div>
        </div>
        <div class="text-xs text-muted mt-2">${detail || ''}</div>
      </div>
      <div class="signal-score">${pct}%</div>
      <div class="signal-status">
        <span class="badge ${passed ? 'badge-low' : 'badge-critical'}">
          ${passed ? '✓ PASS' : '✗ FAIL'}
        </span>
      </div>
    </div>
  `;
}

// Boot on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  // requireAuth already called immediately above, but re-check after DOM loads
  // so pages that render content first also get blocked
  requireAuth();
  if (document.getElementById('shell')) {
    // shell pages auto-init nav + clock + WS via renderShell()
  }
});
