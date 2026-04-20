const API = window.location.origin;
let allAlerts = [];
let stats = {};
let statsRefreshTimer = null;
let savedRules = [];
let tracking = {
  enabled: false,
  query: '',
  matches: 0,
  lastAlert: null,
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));
}

// ── Severity badge ──────────────────────────────────────────────────────────
function sevBadge(sev) {
  return `<span class="sev-badge sev-${escapeHtml(sev)}">${escapeHtml(sev)}</span>`;
}

function catBadge(cat) {
  return `<span class="cat-badge">${escapeHtml(cat)}</span>`;
}

function protoPill(proto) {
  return `<span class="proto-pill">${escapeHtml(proto)}</span>`;
}

// ── Render alert row ─────────────────────────────────────────────────────────
function alertRow(a) {
  const time = escapeHtml((a.timestamp || '').split('.')[0]);
  const src = escapeHtml(a.sport ? `${a.src}:${a.sport}` : a.src);
  const dst = escapeHtml(a.dport ? `${a.dst}:${a.dport}` : a.dst);
  const msg = escapeHtml(a.msg || '');
  return `<div class="alert-row">
    <span class="alert-time">${time}</span>
    <span>${protoPill(a.proto)}</span>
    <span class="alert-msg" title="${msg}">${msg}</span>
    <span>${sevBadge(a.severity)} ${catBadge(a.category)}</span>
    <span class="alert-ip alert-ip-dst" style="font-size:10px;">${src}<br><span style="color:var(--text3)">→ ${dst}</span></span>
  </div>`;
}

function matchesTracking(alert) {
  if (!tracking.enabled || !tracking.query) return true;
  const haystack = [
    alert.msg || '',
    alert.src || '',
    alert.dst || '',
    alert.proto || '',
    alert.sid || '',
    alert.category || '',
  ].join(' ').toLowerCase();
  return haystack.includes(tracking.query);
}

function updateTrackingUi() {
  const stateLabel = document.getElementById('trackingState');
  const chip = document.getElementById('trackingChip');
  const toggle = document.getElementById('trackingToggle');
  const matchesEl = document.getElementById('trackingMatches');
  const lastTimeEl = document.getElementById('trackingLastTime');
  const lastMsgEl = document.getElementById('trackingLastMsg');

  if (tracking.enabled && tracking.query) {
    stateLabel.textContent = 'Active';
    chip.textContent = `Tracking target: ${tracking.query}`;
    toggle.textContent = 'Stop Tracking';
    toggle.classList.add('active');
  } else {
    stateLabel.textContent = 'Idle';
    chip.textContent = 'Tracking target: none';
    toggle.textContent = 'Start Tracking';
    toggle.classList.remove('active');
  }

  matchesEl.textContent = tracking.matches.toLocaleString();
  lastTimeEl.textContent = tracking.lastAlert ? tracking.lastAlert.timestamp.split('.')[0] : '—';
  lastMsgEl.textContent = tracking.lastAlert ? tracking.lastAlert.msg : 'No tracked event yet';
}

// ── Apply filters ────────────────────────────────────────────────────────────
function applyFilters() {
  const sev = document.getElementById('filterSev').value;
  const cat = document.getElementById('filterCat').value;
  const search = document.getElementById('filterSearch').value.toLowerCase();

  const filtered = allAlerts.filter(a => {
    if (sev && a.severity !== sev) return false;
    if (cat && a.category !== cat) return false;
    if (search && !a.msg.toLowerCase().includes(search) && !a.src.includes(search) && !a.dst.includes(search)) return false;
    if (!matchesTracking(a)) return false;
    return true;
  });

  const feed = document.getElementById('alertFeed');
  document.getElementById('feedCount').textContent = `${filtered.length} alerts`;

  if (filtered.length === 0) {
    feed.innerHTML = `<div class="empty"><div class="empty-icon">🔍</div>No alerts match filters</div>`;
    return;
  }

  feed.innerHTML = filtered.slice(0, 100).map(alertRow).join('');
}

function clearFilters() {
  document.getElementById('filterSev').value = '';
  document.getElementById('filterCat').value = '';
  document.getElementById('filterSearch').value = '';
  applyFilters();
}

function toggleTracking() {
  const input = document.getElementById('trackingInput');
  const query = input.value.trim().toLowerCase();

  if (!tracking.enabled) {
    if (!query) {
      document.getElementById('trackingState').textContent = 'Enter a target';
      return;
    }
    tracking.enabled = true;
    tracking.query = query;
    tracking.matches = allAlerts.filter(matchesTracking).length;
    tracking.lastAlert = allAlerts.find(matchesTracking) || null;
  } else {
    tracking.enabled = false;
    tracking.query = '';
    tracking.matches = 0;
    tracking.lastAlert = null;
  }

  updateTrackingUi();
  applyFilters();
}

function renderRulesList() {
  const listEl = document.getElementById('rulesList');
  const countEl = document.getElementById('rulesCount');
  countEl.textContent = `${savedRules.length} rule${savedRules.length === 1 ? '' : 's'}`;

  if (!savedRules.length) {
    listEl.innerHTML = `<div class="empty"><div class="empty-icon">#</div>No saved rules found</div>`;
    return;
  }

  listEl.innerHTML = savedRules.map((rule) => `
    <div class="rule-item">
      <div class="rule-copy">
        <div class="rule-title">${escapeHtml(rule.msg || `SID ${rule.sid}`)}</div>
        <div class="rule-meta">SID ${escapeHtml(rule.sid)} · line ${escapeHtml(rule.line_number)}</div>
        <div class="rule-line" title="${escapeHtml(rule.line)}">${escapeHtml(rule.line)}</div>
      </div>
      <button class="delete-btn" onclick="deleteRule('${escapeHtml(rule.sid)}')">Delete</button>
    </div>
  `).join('');
}

async function loadRules() {
  try {
    const response = await fetch(`${API}/api/rules`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    savedRules = data.rules || [];
    renderRulesList();
  } catch (error) {
    document.getElementById('ruleStatus').textContent = `Unable to load rules: ${error.message}`;
    document.getElementById('ruleStatus').className = 'status-text error';
  }
}

async function submitRule() {
  const statusEl = document.getElementById('ruleStatus');
  statusEl.textContent = 'Saving rule...';
  statusEl.className = 'status-text';

  const payload = {
    action: 'alert',
    proto: document.getElementById('ruleProto').value,
    src_net: document.getElementById('ruleSrcNet').value,
    src_port: document.getElementById('ruleSrcPort').value,
    dst_net: document.getElementById('ruleDstNet').value,
    dst_port: document.getElementById('ruleDstPort').value || 'any',
    msg: document.getElementById('ruleMsg').value,
    sid: document.getElementById('ruleSid').value,
    rev: 1,
    priority: document.getElementById('rulePriority').value,
    content: document.getElementById('ruleContent').value,
  };

  try {
    const response = await fetch(`${API}/api/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }
    statusEl.textContent = data.message;
    statusEl.className = 'status-text success';
    document.getElementById('ruleMsg').value = '';
    document.getElementById('ruleContent').value = '';
    document.getElementById('ruleSid').value = String(Number(document.getElementById('ruleSid').value || 1001001) + 1);
    await loadRules();
  } catch (error) {
    statusEl.textContent = error.message;
    statusEl.className = 'status-text error';
  }
}

async function deleteRule(sid) {
  const statusEl = document.getElementById('ruleStatus');
  if (!window.confirm(`Delete rule with SID ${sid}?`)) {
    return;
  }

  statusEl.textContent = `Deleting rule ${sid}...`;
  statusEl.className = 'status-text';

  try {
    const response = await fetch(`${API}/api/rules/${encodeURIComponent(sid)}`, {
      method: 'DELETE',
    });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }
    statusEl.textContent = data.message;
    statusEl.className = 'status-text success';
    await loadRules();
  } catch (error) {
    statusEl.textContent = error.message;
    statusEl.className = 'status-text error';
  }
}

// ── Update category filter dropdown ─────────────────────────────────────────
function updateCatFilter(categories) {
  const sel = document.getElementById('filterCat');
  const current = sel.value;
  const cats = new Set(categories.map(c => c.name));
  sel.innerHTML = '<option value="">All</option>' +
    [...cats].map(c => {
      const safe = escapeHtml(c);
      return `<option value="${safe}"${c===current?' selected':''}>${safe}</option>`;
    }).join('');
}

// ── Bar list renderer ────────────────────────────────────────────────────────
function renderBars(containerId, items, colorClass, labelKey = 'ip') {
  const el = document.getElementById(containerId);
  if (!items || items.length === 0) {
    el.innerHTML = `<div style="color:var(--text3);font-size:12px;padding:12px 0;">No data yet</div>`;
    return;
  }
  const max = items[0].count;
  el.innerHTML = items.slice(0, 8).map(item => {
    const label = escapeHtml(item[labelKey] || item.name || item.ip);
    const pct = Math.round((item.count / max) * 100);
    return `<div class="bar-item">
      <div class="bar-label">
        <span class="bar-label-text">${label}</span>
        <span class="bar-label-count">${item.count}</span>
      </div>
      <div class="bar-track"><div class="bar-fill ${colorClass}" style="width:${pct}%"></div></div>
    </div>`;
  }).join('');
}

// ── Sparkline canvas ─────────────────────────────────────────────────────────
function drawSparkline(data) {
  const canvas = document.getElementById('sparkCanvas');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.offsetWidth;
  const h = canvas.offsetHeight || 80;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  if (!data || data.length < 2) {
    ctx.fillStyle = '#8b949e';
    ctx.font = '12px sans-serif';
    ctx.fillText('Not enough data yet', 8, h / 2 + 4);
    return;
  }

  const counts = data.map(d => d.count);
  const max = Math.max(...counts, 1);
  const pad = { left: 8, right: 8, top: 8, bottom: 20 };
  const cw = w - pad.left - pad.right;
  const ch = h - pad.top - pad.bottom;

  const xStep = cw / (data.length - 1);
  const points = data.map((d, i) => ({
    x: pad.left + i * xStep,
    y: pad.top + ch - (d.count / max) * ch,
  }));

  // Fill
  ctx.beginPath();
  ctx.moveTo(points[0].x, points[0].y);
  points.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.lineTo(points[points.length - 1].x, pad.top + ch);
  ctx.lineTo(points[0].x, pad.top + ch);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + ch);
  grad.addColorStop(0, 'rgba(88,166,255,0.3)');
  grad.addColorStop(1, 'rgba(88,166,255,0)');
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.moveTo(points[0].x, points[0].y);
  points.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.strokeStyle = '#58a6ff';
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // X labels
  ctx.fillStyle = '#6e7681';
  ctx.font = '10px monospace';
  ctx.textAlign = 'center';
  const step = Math.max(1, Math.floor(data.length / 5));
  data.forEach((d, i) => {
    if (i % step === 0) ctx.fillText(d.time, points[i].x, h - 4);
  });
}

// ── Update stats panel ───────────────────────────────────────────────────────
function updateStats(s) {
  stats = s;
  document.getElementById('statTotal').textContent = s.total.toLocaleString();

  const critHigh = (s.severity.critical || 0) + (s.severity.high || 0);
  document.getElementById('statCritical').textContent = critHigh.toLocaleString();
  document.getElementById('statIPs').textContent = (s.unique_src || 0).toLocaleString();

  const iface = s.meta?.interface || 'eth0';
  document.getElementById('ifaceBadge').textContent = iface;
  document.getElementById('headerSub').textContent = `${iface} · Real-time intrusion detection`;
  document.getElementById('rulesPathLabel').textContent = (s.meta?.rules_file || 'local.rules').split('/').pop();

  renderBars('topIPs', s.top_src, 'ip', 'ip');
  renderBars('catBars', s.categories, 'cat', 'name');
  renderBars('protoBars', s.protocols, 'proto', 'name');
  updateCatFilter(s.categories);
  drawSparkline(s.alerts_per_minute);
}

// ── Load initial alerts ──────────────────────────────────────────────────────
async function loadAlerts() {
  try {
    const r = await fetch(`${API}/api/alerts`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    allAlerts = data;
    if (allAlerts.length > 0) {
      const last = allAlerts[0];
      document.getElementById('statLast').textContent = last.timestamp.split('.')[0];
      document.getElementById('statLastMsg').textContent = last.msg.slice(0, 40) + (last.msg.length > 40 ? '…' : '');
    }
    if (tracking.enabled && tracking.query) {
      tracking.matches = allAlerts.filter(matchesTracking).length;
      tracking.lastAlert = allAlerts.find(matchesTracking) || null;
      updateTrackingUi();
    }
    applyFilters();
    document.getElementById('connError').style.display = 'none';
  } catch (e) {
    document.getElementById('connError').style.display = 'block';
  }
}

async function loadStats() {
  try {
    const r = await fetch(`${API}/api/stats`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    updateStats(data);
  } catch (e) {}
}

// ── SSE live stream ──────────────────────────────────────────────────────────
function connectSSE() {
  const es = new EventSource(`${API}/api/stream`);

  es.onopen = () => {
    document.getElementById('statusDot').classList.remove('offline');
    document.getElementById('liveBadge').textContent = 'LIVE';
    document.getElementById('connError').style.display = 'none';
  };

  es.onmessage = (e) => {
    try {
      const alert = JSON.parse(e.data);
      allAlerts.unshift(alert);
      if (allAlerts.length > 500) allAlerts = allAlerts.slice(0, 500);

      document.getElementById('statLast').textContent = alert.timestamp.split('.')[0];
      document.getElementById('statLastMsg').textContent = alert.msg.slice(0, 40) + (alert.msg.length > 40 ? '…' : '');

      if (tracking.enabled && matchesTracking(alert)) {
        tracking.matches += 1;
        tracking.lastAlert = alert;
        updateTrackingUi();
      }

      applyFilters();
      loadStats();
    } catch (e) {}
  };

  es.onerror = () => {
    document.getElementById('statusDot').classList.add('offline');
    document.getElementById('liveBadge').textContent = 'RECONNECTING';
    setTimeout(connectSSE, 3000);
    es.close();
  };
}

// ── Init ─────────────────────────────────────────────────────────────────────
(async () => {
  await loadAlerts();
  await loadStats();
  await loadRules();
  updateTrackingUi();
  connectSSE();
  statsRefreshTimer = setInterval(loadStats, 5000);
})();

window.addEventListener('resize', () => drawSparkline(stats.alerts_per_minute || []));
