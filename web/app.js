let latestReport = null;
let latestEntries = [];
let samplePaths = { v1: './sample-data/snapshot_v1', v2: './sample-data/snapshot_v2' };
let activeSession = null;

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

function setMessage(text, isError = false) {
  const msgEl = $('#message');
  if (msgEl) msgEl.textContent = text;
  const alertBox = $('#alertBox');
  if (alertBox) {
    if (isError && text) {
      alertBox.hidden = false;
      alertBox.textContent = text;
    } else {
      alertBox.hidden = true;
      alertBox.textContent = '';
    }
  }
}

function setProgress(active, label = 'Processing…') {
  const wrap = $('#progressWrap');
  const text = $('#progressText');
  if (!wrap) return;
  wrap.hidden = !active;
  if (text) text.textContent = label;
}

// 12-Tab Navigation
$$('.nav-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('.nav-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.getAttribute('data-tab');
    $$('.tab-view').forEach((sec) => {
      sec.hidden = sec.id !== `tab-${target}`;
      sec.classList.toggle('active', sec.id === `tab-${target}`);
    });
  });
});

// Dark / Light Theme Toggle
$('#themeToggle').addEventListener('click', () => {
  const html = document.documentElement;
  const next = html.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  html.setAttribute('data-theme', next);
});

async function initStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    if (d.sample_snapshot_v1) samplePaths.v1 = d.sample_snapshot_v1;
    if (d.sample_snapshot_v2) samplePaths.v2 = d.sample_snapshot_v2;
    if (!$('#source').value) $('#source').value = samplePaths.v2;
    renderAdbStatus(d.adb);
    renderSecurityStatus(d.security);
    await loadSnapshots();
    await refreshAuditLog();
  } catch (err) {
    setMessage('Unable to reach local API: ' + err.message, true);
  }
}

$('#loadSampleV2').addEventListener('click', () => {
  $('#source').value = samplePaths.v2;
  $('#scanForm').requestSubmit();
});

$('#loadSampleV1').addEventListener('click', () => {
  $('#source').value = samplePaths.v1;
  $('#scanForm').requestSubmit();
});

$('#scanForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const sourcePath = $('#source').value.trim();
  if (!sourcePath) return;
  const enableAi = $('#enableAiToggle') ? $('#enableAiToggle').checked : true;
  setProgress(true, 'Scanning accessible files and computing SHA-256 & SHA-512…');
  setMessage('Scanning accessible files…');

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (activeSession) {
      headers['X-WRE-Token'] = activeSession.token;
      headers['X-CSRF-Token'] = activeSession.csrf_token;
    }
    const r = await fetch('/api/scan', {
      method: 'POST',
      headers,
      body: JSON.stringify({ source: sourcePath, enable_ai: enableAi }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Scan failed');

    latestReport = d;
    latestEntries = d.entries || [];

    $('#files').textContent = d.files_scanned || 0;
    $('#media').textContent = d.media_count || 0;
    $('#backups').textContent = d.backup_candidates || 0;
    $('#dupes').textContent = (d.duplicates || []).length;

    const cats = d.category_counts || {};
    ['photos', 'videos', 'voice_notes', 'audio', 'documents', 'stickers', 'gifs', 'thumbnails'].forEach((c) => {
      const el = $(`#cat-${c}`);
      if (el) el.textContent = cats[c] || 0;
    });

    renderCategoryBarChart(cats);
    renderEstimator(d.recovery_estimate);
    renderHistory(d.history || []);
    renderWorkspaceAi(d.forensic_ai);
    renderChatTab(d);
    renderBackupTab(d);
    renderEntries();
    renderTimelineTab(d);
    renderEvidenceTab(d.evidence_summary);
    renderDuplicatesTab(d.duplicate_analysis);
    await loadSnapshots();
    await refreshAuditLog();

    setMessage(`Scan complete: ${d.files_scanned} files analyzed (${(d.errors || []).length} warnings).`);
  } catch (err) {
    setMessage(err.message, true);
  } finally {
    setProgress(false);
  }
});

function renderCategoryBarChart(cats) {
  const box = $('#categoryChart');
  if (!box) return;
  const entries = Object.entries(cats || {});
  const maxVal = Math.max(1, ...entries.map(([, v]) => v));
  const bars = entries.map(([k, v], i) => {
    const w = Math.max(6, Math.round((v / maxVal) * 220));
    const y = 16 + i * 22;
    return `<text x="6" y="${y + 11}" fill="#9fb3cd" font-size="11">${k}</text>` +
           `<rect x="95" y="${y}" width="${w}" height="14" rx="4" fill="#3be2b0"/>` +
           `<text x="${102 + w}" y="${y + 11}" fill="#eef5ff" font-size="11" font-weight="bold">${v}</text>`;
  }).join('');
  box.innerHTML = `<svg width="100%" height="195" viewBox="0 0 360 195">${bars}</svg>`;
}

function renderEstimator(est) {
  if (!est) return;
  const badge = $('#readinessBadge');
  const level = est.readiness || 'Low';
  badge.textContent = `Readiness: ${level}`;
  badge.className = `readiness-badge readiness-${level.toLowerCase()}`;

  const fillList = (sel, items, fallback) => {
    const ul = $(sel);
    if (!ul) return;
    ul.replaceChildren();
    (items && items.length ? items : [fallback]).forEach((txt) => {
      const li = document.createElement('li');
      li.textContent = txt;
      ul.append(li);
    });
  };
  fillList('#estEvidence', est.evidence, 'No supporting evidence found.');
  fillList('#estMissing', est.missing_requirements, 'No missing requirements flagged.');
  fillList('#estSteps', est.recommended_next_steps, 'Proceed to inspect or export files.');
}

function renderWorkspaceAi(ai) {
  if (!ai) return;
  const vList = $('#aiVerifiedList');
  const iList = $('#aiInferredList');
  if (vList) {
    vList.replaceChildren();
    (ai.verified_findings || []).forEach((f) => {
      const li = document.createElement('li');
      li.textContent = `[VERIFIED] ${f.statement}`;
      vList.append(li);
    });
  }
  if (iList) {
    iList.replaceChildren();
    const obs = [...(ai.inferred_observations || []).map((o) => `[INFERRED] ${o.statement}`), ...(ai.recommendations || []).map((r) => `[RECOMMENDED] ${r}`)];
    (obs.length ? obs : ['No additional inferred anomalies detected.']).forEach((txt) => {
      const li = document.createElement('li');
      li.textContent = txt;
      iList.append(li);
    });
  }
}

$('#runAiAnalysisBtn').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/ai/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: $('#enableAiToggle').checked }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'AI analysis failed');
    renderWorkspaceAi(d.forensic_findings);
  } catch (err) {
    setMessage(err.message, true);
  }
});

$('#previewExportBtn').addEventListener('click', async () => {
  const paths = $$('.pick:checked').map((x) => x.value);
  const dest = $('#destination').value.trim() || '/tmp/whatsapp-verified-export';
  const box = $('#exportPreviewOutput');
  if (!paths.length) {
    box.textContent = 'Select at least one media item in the Media Recovery tab first.';
    return;
  }
  try {
    const r = await fetch('/api/export/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths, destination: dest }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Preview failed');
    box.textContent = `Preview Ready: ${d.ready_count} of ${d.total_requested} file(s) eligible (${d.total_bytes_to_copy} bytes total) -> Destination: ${d.destination}`;
  } catch (err) {
    box.textContent = err.message;
  }
});

function renderHistory(historyList) {
  const body = $('#historyBody');
  body.replaceChildren();
  if (!historyList.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No scans recorded yet.</td></tr>';
    return;
  }
  historyList.forEach((h) => {
    const tr = document.createElement('tr');
    [h.timestamp, h.source, h.files_scanned, h.media_count, h.readiness].forEach((val) => {
      const td = document.createElement('td');
      td.textContent = val;
      tr.append(td);
    });
    body.append(tr);
  });
}

function renderChatTab(report) {
  const wrap = $('#chatDbList');
  wrap.replaceChildren();
  const dbs = report.chat_databases || [];
  if (!dbs.length) {
    wrap.innerHTML = '<p class="empty">No unencrypted SQLite databases found in this scan.</p>';
  } else {
    dbs.forEach((db) => {
      const card = document.createElement('div');
      card.className = 'subcard';
      card.style.marginBottom = '10px';
      const title = document.createElement('h3');
      title.textContent = `${db.name} (${db.format_type}) — Integrity: ${db.integrity.toUpperCase()}`;
      const meta = document.createElement('p');
      const walFrames = (db.wal_diagnostics && db.wal_diagnostics.uncheckpointed_frames) || 0;
      meta.textContent = `Tables: ${(db.tables || []).join(', ')} | Messages: ${db.message_count || 0} | Uncheckpointed WAL Frames: ${walFrames} | Range: ${db.earliest_timestamp || 'N/A'} to ${db.latest_timestamp || 'N/A'}`;
      card.append(title, meta);
      wrap.append(card);
    });
  }

  if (!$('#oldDbPath').value && samplePaths.v1) $('#oldDbPath').value = `${samplePaths.v1}/Databases/msgstore.db`;
  if (!$('#newDbPath').value && samplePaths.v2) $('#newDbPath').value = `${samplePaths.v2}/Databases/msgstore.db`;
  if (!$('#chatContactFile').value && samplePaths.v2) $('#chatContactFile').value = `${samplePaths.v2}/Exports/contacts.vcf`;

  const allMsgs = [];
  dbs.forEach((db) => (db.sample_messages || []).forEach((m) => allMsgs.push({ ...m, source: db.name })));
  (report.chat_exports || []).forEach((exp) => (exp.messages || []).forEach((m) => allMsgs.push({ ...m, source: exp.name })));
  renderChatMessagesTable(allMsgs);
}

function renderChatMessagesTable(messages) {
  const body = $('#chatMessagesBody');
  body.replaceChildren();
  if (!messages.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No accessible chat messages matched.</td></tr>';
    return;
  }
  messages.slice(0, 200).forEach((m) => {
    const tr = document.createElement('tr');
    const senderLabel = m.contact_name && m.contact_name !== m.sender ? `${m.contact_name} (${m.sender})` : (m.sender || 'Participant');
    [m.id || '-', m.timestamp || '-', senderLabel, m.text || '', m.sha256 || ''].forEach((v, i) => {
      const td = document.createElement('td');
      td.textContent = v;
      if (i === 4) td.className = 'hash';
      tr.append(td);
    });
    body.append(tr);
  });
}

$('#chatSearchBtn').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/chat/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: $('#chatSearchQuery').value,
        sender: $('#chatSearchSender').value,
        contact_file: $('#chatContactFile').value,
      }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Chat search failed');
    renderChatMessagesTable(d.results || []);
  } catch (err) {
    setMessage(err.message, true);
  }
});

$$('.chat-exp-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const fmt = btn.getAttribute('data-fmt');
    try {
      const r = await fetch('/api/chat/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          format: fmt,
          query: $('#chatSearchQuery').value,
          sender: $('#chatSearchSender').value,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || 'Chat export failed');
      window.open(d.download_url, '_blank');
    } catch (err) {
      setMessage(err.message, true);
    }
  });
});

$('#compareDbBtn').addEventListener('click', async () => {
  const out = $('#dbCompareOutput');
  out.textContent = 'Comparing SQLite databases…';
  try {
    const r = await fetch('/api/chat/compare-db', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_db: $('#oldDbPath').value, new_db: $('#newDbPath').value }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Database comparison failed');
    out.replaceChildren();
    const stats = document.createElement('div');
    stats.className = 'comparison-stats';
    Object.entries(d.summary || {}).forEach(([k, v]) => {
      const s = document.createElement('span');
      s.textContent = `${k}: ${v}`;
      stats.append(s);
    });
    out.append(stats);

    if ((d.missing_in_new || []).length) {
      const h = document.createElement('h3');
      h.textContent = 'Historical Messages Present in Older DB (Absent in Newer DB):';
      out.append(h);
      const ul = document.createElement('ul');
      ul.className = 'clean-list';
      d.missing_in_new.forEach((m) => {
        const li = document.createElement('li');
        li.textContent = `[ID ${m.id} • ${m.timestamp}] ${m.sender}: ${m.text}`;
        ul.append(li);
      });
      out.append(ul);
    }
  } catch (err) {
    out.textContent = err.message;
  }
});

function renderBackupTab(report) {
  const bh = report.backup_health || {};
  $('#backupHealthBadge').textContent = `Status: ${bh.health_status || 'Unknown'}`;
  const warnBox = $('#backupWarningsBox');
  warnBox.replaceChildren();
  (bh.warnings || []).forEach((w) => {
    const p = document.createElement('div');
    p.className = 'notice';
    p.textContent = w;
    warnBox.append(p);
  });

  const body = $('#backupTableBody');
  body.replaceChildren();
  const backups = bh.backups || [];
  if (!backups.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No backup candidates found.</td></tr>';
    return;
  }
  backups.forEach((b) => {
    const tr = document.createElement('tr');
    const specName = b.format_specification ? `${b.encryption_format.toUpperCase()} (${b.format_specification.header_type})` : (b.encrypted ? `Encrypted (${b.encryption_format})` : (b.sqlite && b.sqlite.supported ? `SQLite (${b.sqlite.format_type})` : 'File'));
    [b.name, specName, `${b.size} bytes`, b.modified_iso || '-', b.status || 'ok', b.sha256].forEach((val, idx) => {
      const td = document.createElement('td');
      td.textContent = val;
      if (idx === 5) td.className = 'hash';
      tr.append(td);
    });
    body.append(tr);
  });
}

function renderEntries() {
  const q = ($('#filter').value || '').toLowerCase();
  const cat = $('#mediaCategoryFilter').value;
  const minS = $('#minSizeFilter').value ? parseInt($('#minSizeFilter').value, 10) : null;
  const maxS = $('#maxSizeFilter').value ? parseInt($('#maxSizeFilter').value, 10) : null;
  const onlyCorrupt = $('#onlyCorruptFilter').checked;
  const onlyOrphaned = $('#onlyOrphanedFilter') ? $('#onlyOrphanedFilter').checked : false;

  const body = $('#entries');
  body.replaceChildren();

  const filtered = latestEntries.filter((x) => {
    if (x.kind !== 'media') return false;
    if (cat !== 'all' && x.category !== cat) return false;
    if (q && !x.name.toLowerCase().includes(q)) return false;
    if (minS !== null && x.size < minS) return false;
    if (maxS !== null && x.size > maxS) return false;
    if (onlyCorrupt && !x.corrupt) return false;
    if (onlyOrphaned && !x.orphaned) return false;
    return true;
  });

  if (!filtered.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No matching media files found.</td></tr>';
    return;
  }

  filtered.forEach((item) => {
    const tr = document.createElement('tr');
    const check = document.createElement('input');
    check.type = 'checkbox';
    check.className = 'pick';
    check.value = item.path;
    check.setAttribute('aria-label', 'Select ' + item.name);
    const td0 = document.createElement('td');
    td0.append(check);
    tr.append(td0);

    const recDate = (item.timestamp_meta && item.timestamp_meta.reconstructed_date) || '';
    const sigLabel = item.corrupt ? `CORRUPT (${item.corruption_reason || 'invalid'})` : `Intact (${item.signature || 'ok'}${recDate ? ' • ' + recDate : ''})`;
    [item.category || item.mime || 'media', item.name, `${item.size} bytes`, sigLabel, item.sha256].forEach((v, i) => {
      const td = document.createElement('td');
      td.textContent = v;
      if (i === 4) td.className = 'hash';
      tr.append(td);
    });

    const tdPrev = document.createElement('td');
    if (item.mime) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'secondary-btn';
      b.textContent = 'Preview';
      b.addEventListener('click', () => showPreview(item));
      tdPrev.append(b);
    } else {
      tdPrev.textContent = 'Not previewable';
    }
    tr.append(tdPrev);
    body.append(tr);
  });
}

['#filter', '#mediaCategoryFilter', '#minSizeFilter', '#maxSizeFilter', '#onlyCorruptFilter', '#onlyOrphanedFilter'].forEach((sel) => {
  const el = $(sel);
  if (el) {
    el.addEventListener('input', renderEntries);
    el.addEventListener('change', renderEntries);
  }
});

$('#selectAllMediaBtn').addEventListener('click', () => { $$('.pick').forEach((c) => { c.checked = true; }); });
$('#clearMediaSelectionBtn').addEventListener('click', () => { $$('.pick').forEach((c) => { c.checked = false; }); });

async function showPreview(item) {
  const box = $('#preview');
  const body = $('#previewBody');
  body.replaceChildren();
  box.hidden = false;
  const url = '/api/preview?path=' + encodeURIComponent(item.path);
  let el;
  if (item.mime.startsWith('image/')) {
    el = document.createElement('img');
    el.alt = item.name;
    el.className = 'media-preview';
    el.src = url;
  } else if (item.mime.startsWith('video/')) {
    el = document.createElement('video');
    el.controls = true;
    el.className = 'media-preview';
    el.src = url;
  } else if (item.mime.startsWith('audio/')) {
    el = document.createElement('audio');
    el.controls = true;
    el.src = url;
  } else {
    el = document.createElement('a');
    el.href = url;
    el.target = '_blank';
    el.className = 'btn-link';
    el.textContent = `Open ${item.name}`;
  }
  const p = document.createElement('p');
  p.textContent = `${item.name} (${item.category || item.mime}, ${item.size} bytes, SHA-256: ${item.sha256})`;
  body.append(el, p);
  box.scrollIntoView({ behavior: 'smooth' });
}

$('#closePreview').addEventListener('click', () => {
  $('#preview').hidden = true;
  $('#previewBody').replaceChildren();
});

function renderTimelineTab(report) {
  const chartBox = $('#timelineChartBox');
  const gapsBox = $('#timelineGapsBox');
  if (!chartBox || !gapsBox) return;

  const dbs = report.chat_databases || [];
  const tAnalysis = (dbs[0] && dbs[0].timeline_analysis) || {};
  const daily = tAnalysis.daily_activity || [];
  if (!daily.length) {
    chartBox.innerHTML = '<p class="empty">No timestamped chat records available for timeline chart.</p>';
  } else {
    const maxC = Math.max(1, ...daily.map((d) => d.count));
    const bars = daily.map((d, idx) => {
      const w = Math.max(12, Math.round((d.count / maxC) * 240));
      const y = 14 + idx * 26;
      return `<text x="8" y="${y + 13}" fill="#9fb3cd" font-size="11">${d.date}</text>` +
             `<rect x="105" y="${y}" width="${w}" height="16" rx="4" fill="#6fb3ff"/>` +
             `<text x="${112 + w}" y="${y + 13}" fill="#eef5ff" font-size="11">${d.count} msg(s)</text>`;
    }).join('');
    chartBox.innerHTML = `<svg width="100%" height="${Math.max(80, daily.length * 30)}" viewBox="0 0 420 ${Math.max(80, daily.length * 30)}">${bars}</svg>`;
  }

  gapsBox.replaceChildren();
  const gaps = tAnalysis.gaps || [];
  if (!gaps.length) {
    gapsBox.innerHTML = '<p class="empty">No anomalous conversation gaps detected.</p>';
  } else {
    const ul = document.createElement('ul');
    ul.className = 'clean-list';
    gaps.forEach((g) => {
      const li = document.createElement('li');
      li.textContent = `Gap of ${g.duration_hours} hours (${g.duration_seconds}s) between message #${g.from_message_id} (${g.gap_start}) and message #${g.to_message_id} (${g.gap_end}).`;
      ul.append(li);
    });
    gapsBox.append(ul);
  }
}

function renderEvidenceTab(evSummary) {
  const tbody = $('#evidenceTableBody');
  if (!tbody || !evSummary) return;
  tbody.replaceChildren();
  const items = evSummary.evidence_items || [];
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No evidence items registered yet.</td></tr>';
    return;
  }
  items.forEach((item) => {
    const tr = document.createElement('tr');
    [item.evidence_id, item.name, item.category, item.acquired_at, item.sha256, (item.sha512 || '').slice(0, 24) + '…'].forEach((v, idx) => {
      const td = document.createElement('td');
      td.textContent = v;
      if (idx === 4 || idx === 5) td.className = 'hash';
      tr.append(td);
    });
    tbody.append(tr);
  });
}

$('#generateManifestBtn').addEventListener('click', async () => {
  const key = $('#manifestSigningKey').value.trim() || null;
  const box = $('#manifestOutputBox');
  try {
    const r = await fetch('/api/evidence/manifest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signing_key: key }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Manifest generation failed');
    box.hidden = false;
    box.textContent = `Manifest ${d.manifest_id} (${d.verification_mode}) — SHA-256: ${d.manifest_sha256}${d.signature ? ' | HMAC Signature: ' + d.signature : ''}`;
  } catch (err) {
    box.hidden = false;
    box.textContent = err.message;
  }
});

function renderDuplicatesTab(dupAnalysis) {
  const container = $('#duplicateGroupsContainer');
  container.replaceChildren();
  if (!dupAnalysis || !dupAnalysis.groups || !dupAnalysis.groups.length) {
    $('#wastedBytesBadge').textContent = 'Reclaimable: 0 B';
    container.innerHTML = '<p class="empty">No duplicate files detected.</p>';
    return;
  }
  $('#wastedBytesBadge').textContent = `Reclaimable: ${dupAnalysis.wasted_bytes} bytes (${dupAnalysis.duplicate_file_count} extra files)`;
  dupAnalysis.groups.forEach((g) => {
    const card = document.createElement('div');
    card.className = 'subcard';
    card.style.marginBottom = '10px';
    const h = document.createElement('h3');
    h.textContent = `SHA-256: ${g.sha256.slice(0, 24)}… (${g.count} identical copies • ${g.size} bytes each)`;
    const ul = document.createElement('ul');
    ul.className = 'clean-list';
    g.paths.forEach((p) => {
      const li = document.createElement('li');
      li.textContent = p;
      ul.append(li);
    });
    card.append(h, ul);
    container.append(card);
  });
}

async function loadSnapshots() {
  const d = await fetch('/api/snapshots').then((r) => r.json());
  for (const id of ['old', 'new']) {
    const sel = $('#' + id);
    sel.replaceChildren();
    (d.snapshots || []).forEach((s) => {
      const o = document.createElement('option');
      o.value = s.path;
      o.textContent = s.name;
      sel.append(o);
    });
  }
  if ((d.snapshots || []).length > 1) $('#new').selectedIndex = d.snapshots.length - 1;
}

$('#compare').addEventListener('click', async () => {
  const out = $('#comparison');
  out.textContent = 'Comparing snapshots…';
  try {
    const r = await fetch('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old: $('#old').value, new: $('#new').value }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Comparison failed');
    out.replaceChildren();
    const wrap = document.createElement('div');
    wrap.className = 'comparison-stats';
    Object.entries(d.summary || {}).forEach(([k, v]) => {
      const s = document.createElement('span');
      s.textContent = `${k}: ${v}`;
      wrap.append(s);
    });
    out.append(wrap);
  } catch (e) {
    out.textContent = e.message;
  }
});

$('#export').addEventListener('click', async () => {
  const paths = $$('.pick:checked').map((x) => x.value);
  if (!paths.length) {
    $('#exportmsg').textContent = 'Select at least one media file in the Media Recovery tab.';
    return;
  }
  const dest = $('#destination').value.trim();
  if (!dest) {
    $('#exportmsg').textContent = 'Enter a safe destination folder outside the scanned directory.';
    return;
  }
  setProgress(true, 'Copying files and verifying dual SHA-256 & SHA-512 checksums…');
  $('#exportmsg').textContent = 'Copying and verifying SHA-256/SHA-512…';
  try {
    const r = await fetch('/api/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths, destination: dest }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Export failed');
    $('#exportmsg').textContent = `Verified ${d.verified_count} of ${d.results.length} selected files. Certificate ID: ${d.certificate_id}`;

    const certBox = $('#verificationCertBox');
    certBox.hidden = false;
    $('#certMeta').textContent = `Certificate ID: ${d.certificate_id} | Mode: ${d.verification_mode} | Manifest SHA-256: ${d.manifest_sha256}`;

    const tbody = $('#verificationTableBody');
    tbody.replaceChildren();
    (d.results || []).forEach((item) => {
      const tr = document.createElement('tr');
      [
        item.name || item.source,
        item.source_sha256 || '-',
        item.destination_sha256 || '-',
        item.verified ? 'VERIFIED OK (SHA-256 + SHA-512)' : `FAILED (${item.error || 'Mismatch'})`,
      ].forEach((val, idx) => {
        const td = document.createElement('td');
        td.textContent = val;
        if (idx === 1 || idx === 2) td.className = 'hash';
        tr.append(td);
      });
      tbody.append(tr);
    });
  } catch (e) {
    $('#exportmsg').textContent = e.message;
  } finally {
    setProgress(false);
  }
});

function renderAdbStatus(adb) {
  const box = $('#adbStatusBox');
  if (!box || !adb) return;
  box.replaceChildren();
  const p1 = document.createElement('p');
  p1.innerHTML = `<strong>ADB Available:</strong> ${adb.available ? 'Yes' : 'No'} | <strong>Platform:</strong> ${adb.platform || 'Unknown'} | <strong>Termux:</strong> ${adb.is_termux ? 'Yes' : 'No'}`;
  const p2 = document.createElement('p');
  p2.textContent = adb.message || '';
  box.append(p1, p2);

  const fillPaths = (sel, items) => {
    const ul = $(sel);
    if (!ul) return;
    ul.replaceChildren();
    (items || []).forEach((p) => {
      const li = document.createElement('li');
      li.textContent = p;
      ul.append(li);
    });
  };
  fillPaths('#adbWaPaths', adb.known_whatsapp_paths);
  fillPaths('#adbW4bPaths', adb.known_whatsapp_business_paths);
}

function renderSecurityStatus(sec) {
  const box = $('#securityAuditBox');
  if (!box || !sec) return;
  box.replaceChildren();
  const ul = document.createElement('ul');
  ul.className = 'clean-list';
  [
    `Local-Only Processing: ${sec.local_only_processing}`,
    `Loopback Default: ${sec.loopback_only_default}`,
    `Telemetry Enabled: ${sec.telemetry_enabled}`,
    `Read-Only Source Scanning: ${sec.read_only_source_scanning}`,
    `Encrypted Temp Storage: ${sec.encrypted_temp_storage_enabled}`,
    `Secret-Free Audit Logging: ${sec.secret_free_audit_logging}`,
    `Dependencies Pinned & Audited: ${sec.dependencies_checked}`,
  ].forEach((item) => {
    const li = document.createElement('li');
    li.textContent = item;
    ul.append(li);
  });
  box.append(ul);
}

async function refreshAuditLog() {
  const tbody = $('#auditLogBody');
  if (!tbody) return;
  const r = await fetch('/api/audit-log');
  const d = await r.json();
  tbody.replaceChildren();
  (d.events || []).slice(0, 20).forEach((ev) => {
    const tr = document.createElement('tr');
    [ev.timestamp, ev.action, ev.status].forEach((val) => {
      const td = document.createElement('td');
      td.textContent = val;
      tr.append(td);
    });
    tbody.append(tr);
  });
}

$('#issueSessionBtn').addEventListener('click', async () => {
  const r = await fetch('/api/auth/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label: 'dashboard-operator' }) });
  activeSession = await r.json();
  setMessage(`Session token issued (expires at ${activeSession.expires_at}). CSRF protection active.`);
  await refreshAuditLog();
});

$('#refreshAdbBtn').addEventListener('click', initStatus);

$('#lang').addEventListener('change', async (e) => {
  const t = await fetch('/api/i18n/' + e.target.value).then((r) => r.json());
  document.documentElement.setAttribute('dir', t.dir || 'ltr');
  $('#title').textContent = t.title;
  $('#subtitle').textContent = t.subtitle;
  $('#scanBtn').textContent = t.scan;
  $('#privacyNote').textContent = t.privacy;
  $('#disclaimerBanner').textContent = t.disclaimer;
  $('#readinessTitle').textContent = t.readiness_title;
  $('#lbl-files').textContent = t.kpi_files;
  $('#lbl-media').textContent = t.kpi_media;
  $('#lbl-backups').textContent = t.kpi_backups;
  $('#lbl-dupes').textContent = t.kpi_dupes;
  setMessage(t.privacy);
});

initStatus();
