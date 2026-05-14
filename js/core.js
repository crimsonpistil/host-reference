// ── HUNT REFERENCE — core.js ──
// Shared UI logic for all tactic pages.
// DATA must be loaded before this file via a tactic-specific data/*.js script tag.

// ── CMS TEMPLATES ──
const CMS_TEMPLATES = {
  // ── Execution (TA0002) ──
  'T1059.001': { title:'T1059.001 — PowerShell', body:`## TAG - EXECUTION\n### Technique: PowerShell, T1059.001\n- Time:\n- Host:\n- User Account:\n- Parent Process:\n- Process Command Line:\n- Encoded Payload (decoded):\n- ScriptBlock Content (Event 4104):\n- AMSI Result:\n- Outbound Network Connections:\n- Tool Inferred: (Empire / Cobalt Strike / Nishang / manual)\n\nNotes:` },
  'T1059.003': { title:'T1059.003 — Windows Command Shell', body:`## TAG - EXECUTION\n### Technique: Windows Command Shell, T1059.003\n- Time:\n- Host:\n- User Account:\n- Parent Process:\n- Command Line:\n- Discovery Commands Observed:\n- Obfuscation Pattern: (caret / quote / hex / none)\n- Subsequent Process Spawned:\n\nNotes:` },
  'T1059.005': { title:'T1059.005 — Visual Basic', body:`## TAG - EXECUTION\n### Technique: Visual Basic, T1059.005\n- Time:\n- Host:\n- User Account:\n- Parent Process: (Office app?)\n- Script Path:\n- Script Content (sanitized):\n- Network Activity:\n\nNotes:` },
  'T1059.007': { title:'T1059.007 — JavaScript', body:`## TAG - EXECUTION\n### Technique: JavaScript, T1059.007\n- Time:\n- Host:\n- User Account:\n- Engine: (wscript / cscript / mshta)\n- Script Path:\n- Script Content (sanitized):\n\nNotes:` },
  T1047: { title:'T1047 — Windows Management Instrumentation', body:`## TAG - EXECUTION\n### Technique: WMI, T1047\n- Time:\n- Host:\n- User Account:\n- Process: (wmic.exe / Win32_Process)\n- Command Line:\n- Target Host (if remote):\n- WMI Subscription Created (Y/N):\n\nNotes:` },
  'T1053.005': { title:'T1053.005 — Scheduled Task', body:`## TAG - EXECUTION\n### Technique: Scheduled Task, T1053.005\n- Time:\n- Host:\n- User Account:\n- Task Name:\n- Task Action / Binary:\n- Task Trigger:\n- Run-As Account: (SYSTEM elevation?)\n- Created Locally or Remotely:\n\nNotes:` },
  'T1569.002': { title:'T1569.002 — Service Execution', body:`## TAG - EXECUTION\n### Technique: Service Execution, T1569.002\n- Time:\n- Host:\n- User Account:\n- Service Name:\n- binPath:\n- Service Type / Start Type:\n- Tool Inferred: (sc.exe / PsExec / Impacket)\n\nNotes:` },
  'T1218.005': { title:'T1218.005 — Mshta', body:`## TAG - EXECUTION\n### Technique: Mshta, T1218.005\n- Time:\n- Host:\n- User Account:\n- mshta.exe Command Line:\n- HTA Source: (URL / inline VBS / inline JS)\n- Subsequent Process Spawned:\n- Outbound Network:\n\nNotes:` },
  'T1218.011': { title:'T1218.011 — Rundll32', body:`## TAG - EXECUTION\n### Technique: Rundll32, T1218.011\n- Time:\n- Host:\n- User Account:\n- rundll32.exe Command Line:\n- DLL Path:\n- Export Function:\n- DLL Signed (Y/N):\n\nNotes:` },
  'T1218.010': { title:'T1218.010 — Regsvr32', body:`## TAG - EXECUTION\n### Technique: Regsvr32, T1218.010\n- Time:\n- Host:\n- User Account:\n- regsvr32.exe Command Line:\n- /i: URL or Path:\n- Scriptlet Content (.sct):\n- Squiblydoo Pattern (Y/N):\n\nNotes:` },
  T1106: { title:'T1106 — Native API', body:`## TAG - EXECUTION\n### Technique: Native API, T1106\n- Time:\n- Host:\n- User Account:\n- Process Created Without CLI Trace:\n- Module Load Pattern:\n- CreateRemoteThread Observed (EID 8):\n- Memory Region Analysis:\n\nNotes:` },
  T1129: { title:'T1129 — Shared Modules', body:`## TAG - EXECUTION\n### Technique: Shared Modules / DLL Side-Loading, T1129\n- Time:\n- Host:\n- User Account:\n- Loading Process:\n- DLL Path:\n- DLL Signed (Y/N):\n- Search Order Hijack (Y/N):\n\nNotes:` },
  'T1204.002': { title:'T1204.002 — User Execution: Malicious File', body:`## TAG - EXECUTION\n### Technique: User Execution: Malicious File, T1204.002\n- Time:\n- Host:\n- User Account:\n- File Path:\n- File Type: (.exe / .lnk / .iso / .img / .one)\n- Source: (email attachment / browser download / removable media)\n- MOTW Present (Y/N):\n- Subsequent Activity:\n\nNotes:` },
};

// ── STATE ──
let activeTech = 'all';
let activeApt  = null;
let huntOpen   = false;
let totalRows  = 0;
let selectedRows = new Set();
let huntItems  = {};     // rowId -> { indicator, techId, severity, addedAt, row }
let rowRegistry = {};    // rowId -> { row, techId }

// ── PERSISTENCE ──
// Hunt items survive across tabs and browser sessions via localStorage.
// Schema versioning lets us migrate or discard incompatible saved data.
const HUNT_STORAGE_KEY = 'hunt_reference_hunts_v1';
const HUNT_SCHEMA_VERSION = 1;

function loadHunts() {
  try {
    const raw = localStorage.getItem(HUNT_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed._v !== HUNT_SCHEMA_VERSION) {
      console.warn('Hunt storage schema mismatch; discarding old data.');
      localStorage.removeItem(HUNT_STORAGE_KEY);
      return;
    }
    huntItems = parsed.items || {};
  } catch (e) {
    console.error('Failed to load hunts from localStorage:', e);
    huntItems = {};
  }
}

function saveHunts() {
  try {
    const payload = { _v: HUNT_SCHEMA_VERSION, items: huntItems };
    localStorage.setItem(HUNT_STORAGE_KEY, JSON.stringify(payload));
  } catch (e) {
    // QuotaExceededError is the realistic failure mode.
    console.error('Failed to save hunts to localStorage:', e);
  }
}

// Cross-tab sync: when another tab modifies the hunt list, refresh ours.
window.addEventListener('storage', e => {
  if (e.key !== HUNT_STORAGE_KEY) return;
  loadHunts();
  renderHunt();
  // Refresh star button states for indicators on the current page.
  document.querySelectorAll('.ind-row').forEach(rowEl => {
    const rowId = rowEl.dataset.rowId;
    const star = rowEl.querySelector('.star-btn');
    if (!star) return;
    if (huntItems[rowId]) {
      star.innerHTML = '&#9733;';
      star.classList.add('starred');
    } else {
      star.innerHTML = '&#9734;';
      star.classList.remove('starred');
    }
  });
});

// ── HELPERS ──
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function aptOrigins(apt) {
  return apt.map(a => {
    if (a.cls === 'apt-cn') return 'CN';
    if (a.cls === 'apt-ru') return 'RU';
    if (a.cls === 'apt-ir') return 'IR';
    if (a.cls === 'apt-kp') return 'KP';
    return '';
  }).join(' ');
}

function copyText(text, btn, label) {
  navigator.clipboard.writeText(text.trim()).then(() => {
    const orig = btn.textContent;
    btn.textContent = label || 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1400);
  });
}

// ── BUILD ROW ──
function buildRow(row, techId, rowId) {
  const aptBadges = row.apt.map(a =>
    `<span class="apt-badge ${a.cls}">${a.name}</span>`
  ).join('');

  const searchText = [
    row.indicator, row.notes, row.sysmon, row.kibana, row.powershell,
    row.registry || '', row.tools || '', row.ossdetect || '',
    row.apt.map(a => a.name + ' ' + (a.note||'')).join(' '),
    row.cite || '', techId
  ].join(' ').toLowerCase();

  const el = document.createElement('div');
  el.className = 'ind-row';
  el.dataset.tech = techId;
  el.dataset.apt  = aptOrigins(row.apt);
  el.dataset.text = searchText;
  el.dataset.rowId = rowId;
  el.dataset.techId = techId;

  // ── collapsed bar ──
  const bar = document.createElement('div');
  bar.className = 'ind-collapsed';
  const isStarred = !!huntItems[rowId];
  bar.innerHTML = `
    <input type="checkbox" class="row-check" title="Select for export">
    <button class="star-btn${isStarred ? ' starred' : ''}" title="Add to hunt">${isStarred ? '&#9733;' : '&#9734;'}</button>
    <span class="ind-name">${esc(row.indicator)}</span>
    <div class="apt-badges">${aptBadges}</div>
    <div class="quick-tools">
      <button class="qtool qt-y" title="Copy Sysmon">SYS</button>
      <button class="qtool qt-k" title="Copy Kibana">KQL</button>
      <button class="qtool qt-p" title="Copy PowerShell">PS</button>
    </div>
    <span class="expand-icon">&#9662;</span>`;

  bar.querySelector('.row-check').addEventListener('click', e => {
    e.stopPropagation();
    toggleSelect(rowId, e.target);
  });
  bar.querySelector('.star-btn').addEventListener('click', e => {
    e.stopPropagation();
    toggleHuntItem(rowId, e.target);
  });
  bar.querySelector('.qt-y').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.sysmon, e.target);
  });
  bar.querySelector('.qt-k').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.kibana, e.target);
  });
  bar.querySelector('.qt-p').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.powershell, e.target);
  });
  bar.addEventListener('click', () => el.classList.toggle('open'));

  // ── detail panel ──
  const detail = document.createElement('div');
  detail.className = 'ind-detail';

  // tab bar
  const tabs = [
    ['t-sys', 'Sysmon'],
    ['t-kib', 'Kibana'],
    ['t-ps', 'PowerShell'],
    ['t-reg', 'Registry/Artifacts'],
    ['t-tool', 'Tools'],
    ['t-oss', 'OSS Detections'],
    ['t-not', 'Notes'],
    ['t-apt', 'APT'],
    ['t-cms', 'CMS Template'],
  ];
  const tabBar = document.createElement('div');
  tabBar.className = 'tab-bar';
  tabs.forEach(([cls, label], i) => {
    const btn = document.createElement('button');
    btn.className = 'dtab ' + cls + (i === 0 ? ' active' : '');
    btn.textContent = label;
    btn.addEventListener('click', () => switchTab(detail, btn, cls));
    tabBar.appendChild(btn);
  });
  detail.appendChild(tabBar);

  // code panels
  function codePanel(langCls, langLabel, content) {
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => copyText(content, copyBtn));
    wrap.innerHTML = `<div class="code-hdr"><span class="code-lang ${langCls}">${langLabel}</span></div>`;
    wrap.querySelector('.code-hdr').appendChild(copyBtn);
    const pre = document.createElement('pre');
    pre.className = 'code-body';
    pre.textContent = content;
    wrap.appendChild(pre);
    return wrap;
  }

  // panels
  const panels = {
    'ark': codePanel('l-sys', 'Sysmon Event',  row.sysmon),
    'kib': codePanel('l-kib', 'Kibana KQL',     row.kibana),
    'sur': codePanel('l-ps',  'PowerShell Hunt', row.powershell),
    'reg': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.registry || '(no registry/file artifacts documented)'; return d; })(),
    'tool': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.tools || '(no adversary tools documented)'; return d; })(),
    'oss': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.ossdetect || '(no open-source detections documented)'; return d; })(),
    'not': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.notes; return d; })(),
    'apt': (() => {
      const d = document.createElement('div');
      row.apt.forEach(a => {
        const item = document.createElement('div');
        item.className = 'apt-item';
        item.innerHTML = `<span class="apt-badge ${a.cls}" style="font-size:11px">${esc(a.name)}</span>`;
        if (a.note) {
          const note = document.createElement('div');
          note.className = 'apt-item-note';
          note.textContent = a.note;
          item.appendChild(note);
        }
        d.appendChild(item);
      });
      if (row.cite) {
        const cite = document.createElement('div');
        cite.className = 'apt-cite';
        cite.textContent = row.cite;
        d.appendChild(cite);
      }
      return d;
    })(),
    'cms': (() => {
      const d = document.createElement('div');
      const tpl = CMS_TEMPLATES[techId];
      if (tpl) {
        const hdr = document.createElement('div');
        hdr.className = 'cms-hdr';
        const title = document.createElement('span');
        title.className = 'cms-title';
        title.textContent = tpl.title;
        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.style.borderColor = 'var(--teal)';
        copyBtn.textContent = 'Copy Template';
        copyBtn.addEventListener('click', () => copyText(tpl.body, copyBtn, 'Copied!'));
        hdr.appendChild(title);
        hdr.appendChild(copyBtn);
        const pre = document.createElement('pre');
        pre.className = 'cms-body-pre';
        pre.textContent = tpl.body;
        d.appendChild(hdr);
        d.appendChild(pre);
      } else {
        d.innerHTML = '<span style="color:var(--text3);font-size:12px">No CMS template for this technique yet.</span>';
      }
      return d;
    })(),
  };

  const panelKeys = ['ark','kib','sur','reg','tool','oss','not','apt','cms'];
  panelKeys.forEach((key, i) => {
    const wrap = document.createElement('div');
    wrap.className = 'tab-panel' + (i === 0 ? ' active' : '');
    wrap.appendChild(panels[key]);
    detail.appendChild(wrap);
  });

  el.appendChild(bar);
  el.appendChild(detail);
  rowRegistry[rowId] = { row, techId };
  return el;
}

function switchTab(detail, activeBtn, activeCls) {
  detail.querySelectorAll('.dtab').forEach(b => b.classList.remove('active'));
  detail.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  activeBtn.classList.add('active');
  // Tab class -> panel index mapping (must match panelKeys order)
  const tabToIdx = {
    't-sys': 0, 't-kib': 1, 't-ps': 2,
    't-reg': 3, 't-tool': 4, 't-oss': 5,
    't-not': 6, 't-apt': 7, 't-cms': 8
  };
  const idx = tabToIdx[activeCls];
  const panels = detail.querySelectorAll('.tab-panel');
  if (panels[idx]) panels[idx].classList.add('active');
}

// ── RENDER ──
function render() {
  const content = document.getElementById('content');
  const toc     = document.getElementById('toc');
  const sidebarStats = document.getElementById('sidebar-stats');
  if (!content) return;

  DATA.forEach(tech => {
    // TOC
    const tocItem = document.createElement('div');
    tocItem.className = 'toc-item';
    tocItem.dataset.tech = tech.id;
    tocItem.innerHTML = `<span class="toc-id">${tech.id}</span><span class="toc-count">${tech.rows.length}</span>`;
    tocItem.addEventListener('click', () => {
      document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
      const btn = document.querySelector(`.fbtn[data-tech="${tech.id}"]`);
      if (btn) { btn.classList.add('active'); activeTech = tech.id; applyFilters(); }
      document.getElementById('tech-' + tech.id)?.scrollIntoView({ behavior:'smooth', block:'start' });
    });
    if (toc) toc.appendChild(tocItem);

    // Section
    const section = document.createElement('div');
    section.className = 'technique-section';
    section.id = 'tech-' + tech.id;
    section.dataset.tech = tech.id;

    const hdr = document.createElement('div');
    hdr.className = 'tech-header';
    hdr.innerHTML = `<span class="tech-id">${tech.id}</span><span class="tech-name">${tech.name}</span><span class="tech-count">${tech.rows.length}</span><span class="tech-desc">${tech.desc || ''}</span><span class="tech-toggle">&#9662;</span>`;
    hdr.addEventListener('click', () => section.classList.toggle('collapsed'));
    section.appendChild(hdr);

    const wrap = document.createElement('div');
    wrap.className = 'rows-wrap';

    let lastSub = '';
    tech.rows.forEach((row, i) => {
      if (row.sub && row.sub !== lastSub) {
        const div = document.createElement('div');
        div.className = 'sub-divider';
        div.textContent = row.sub;
        wrap.appendChild(div);
        lastSub = row.sub;
      }
      const rowId = tech.id + '_' + i;
      wrap.appendChild(buildRow(row, tech.id, rowId));
      totalRows++;
    });

    section.appendChild(wrap);
    content.appendChild(section);
  });

  if (sidebarStats) {
    sidebarStats.innerHTML = DATA.map(t =>
      `<div><span style="color:var(--accent);font-family:var(--mono)">${t.id}</span> — ${t.rows.length}</div>`
    ).join('') + `<div style="margin-top:6px;color:var(--text2)">Total: <strong>${totalRows}</strong></div>`;
  }

  updateStats(totalRows, totalRows);
}

// ── SELECT / EXPORT SELECTED ──
function toggleSelect(rowId, cb) {
  if (cb.checked) selectedRows.add(rowId);
  else selectedRows.delete(rowId);
  const btn = document.getElementById('export-selected-btn');
  if (btn) btn.style.display = selectedRows.size > 0 ? 'flex' : 'none';
}

function exportSelected() {
  if (!selectedRows.size) return;
  let out = `Hunt Reference — Selected Indicators\nExported: ${new Date().toLocaleString()}\n${'='.repeat(60)}\n\n`;
  selectedRows.forEach(rowId => {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    const { row, techId } = entry;
    out += `[${techId}] ${row.indicator}\n${'-'.repeat(50)}\nSYSMON:\n${row.sysmon}\n\nKIBANA:\n${row.kibana}\n\nPOWERSHELL:\n${row.powershell}\n\nREGISTRY/ARTIFACTS:\n${row.registry || '(none)'}\n\nTOOLS:\n${row.tools || '(none)'}\n\nOSS DETECTIONS:\n${row.ossdetect || '(none)'}\n\nNOTES:\n${row.notes}\n\n${'='.repeat(60)}\n\n`;
  });
  download(out, 'selected_indicators.txt', 'text/plain');
}

// ── HUNT ──
function toggleHunt() {
  huntOpen = !huntOpen;
  document.getElementById('hunt-panel').classList.toggle('open', huntOpen);
}

function toggleHuntItem(rowId, starBtn) {
  if (huntItems[rowId]) {
    delete huntItems[rowId];
    starBtn.innerHTML = '&#9734;';
    starBtn.classList.remove('starred');
  } else {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    huntItems[rowId] = {
      indicator: entry.row.indicator,
      techId: entry.techId,
      severity: 'high',
      addedAt: Date.now(),
      row: entry.row  // full row data — enables cross-tactic export from any page
    };
    starBtn.innerHTML = '&#9733;';
    starBtn.classList.add('starred');
    if (!huntOpen) { huntOpen = true; document.getElementById('hunt-panel').classList.add('open'); }
  }
  saveHunts();
  renderHunt();
}

function renderHunt() {
  const list = document.getElementById('hunt-list');
  const countEl = document.getElementById('hunt-count');
  const keys = Object.keys(huntItems);

  if (!keys.length) {
    list.innerHTML = '<div class="hunt-empty">No indicators added. Click &#9734; on any row.</div>';
    if (countEl) countEl.style.display = 'none';
    return;
  }

  if (countEl) { countEl.textContent = keys.length; countEl.style.display = 'inline'; }

  // Sort by addedAt ascending — oldest first, building a hunt timeline.
  // Items added before persistence existed have no addedAt and sort as 0 (top).
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Group consecutive items by techId and insert a small header before each new group.
  let html = '';
  let lastTech = null;
  sortedKeys.forEach(rowId => {
    const item = huntItems[rowId];
    if (item.techId !== lastTech) {
      html += `<div class="hunt-group-header">${item.techId}</div>`;
      lastTech = item.techId;
    }
    const ts = item.addedAt
      ? new Date(item.addedAt).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' })
      : '';
    html += `<div class="hunt-item">
      <span class="hunt-item-tech">${item.techId}</span>
      <span class="hunt-item-name">${esc(item.indicator)}</span>
      ${ts ? `<span class="hunt-item-ts" title="Added">${ts}</span>` : ''}
      <select class="sev-sel sev-${item.severity}" onchange="setSev('${rowId}',this)">
        <option value="critical" ${item.severity==='critical'?'selected':''}>CRITICAL</option>
        <option value="high"     ${item.severity==='high'    ?'selected':''}>HIGH</option>
        <option value="medium"   ${item.severity==='medium'  ?'selected':''}>MEDIUM</option>
        <option value="low"      ${item.severity==='low'     ?'selected':''}>LOW</option>
      </select>
      <button class="hunt-remove" onclick="removeHunt('${rowId}')">&#10005;</button>
    </div>`;
  });
  list.innerHTML = html;
}

function setSev(rowId, sel) {
  if (huntItems[rowId]) {
    huntItems[rowId].severity = sel.value;
    sel.className = 'sev-sel sev-' + sel.value;
    saveHunts();
  }
}

function removeHunt(rowId) {
  delete huntItems[rowId];
  const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
  if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  saveHunts();
  renderHunt();
}

function clearHunt() {
  Object.keys(huntItems).forEach(rowId => {
    const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
    if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  });
  huntItems = {};
  saveHunts();
  renderHunt();
}

function exportHunt(fmt) {
  const keys = Object.keys(huntItems);
  if (!keys.length) return;

  // Sort by addedAt to preserve hunt timeline order in exports.
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Use stored row data first; fall back to rowRegistry for items added before
  // persistence existed, or that for some reason lack the .row field.
  const getRow = rowId => huntItems[rowId].row || (rowRegistry[rowId] && rowRegistry[rowId].row);

  if (fmt === 'csv') {
    const q = s => '"' + String(s||'').replace(/"/g,'""').replace(/\n/g,' ') + '"';
    let csv = 'Order,Added,Severity,Technique,Indicator,Sysmon,Kibana,PowerShell,Registry,Tools,OSSDetections,Notes\n';
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toISOString() : '';
      csv += [i+1, ts, item.severity.toUpperCase(), item.techId, r.indicator, r.sysmon, r.kibana, r.powershell, r.registry||'', r.tools||'', r.ossdetect||'', r.notes].map(q).join(',') + '\n';
    });
    download(csv, 'hunt_package.csv', 'text/csv');
  } else {
    let out = `Hunt Package\nExported: ${new Date().toLocaleString()}\nIndicators: ${sortedKeys.length}\n${'='.repeat(60)}\n\n`;
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toLocaleString() : 'unknown';
      out += `[${i+1}] [${item.severity.toUpperCase()}] ${item.techId} — ${r.indicator}\nAdded: ${ts}\n${'-'.repeat(50)}\nSYSMON:\n${r.sysmon}\n\nKIBANA:\n${r.kibana}\n\nPOWERSHELL:\n${r.powershell}\n\nREGISTRY/ARTIFACTS:\n${r.registry || '(none)'}\n\nTOOLS:\n${r.tools || '(none)'}\n\nOSS DETECTIONS:\n${r.ossdetect || '(none)'}\n\nNOTES:\n${r.notes}\n\n${'='.repeat(60)}\n\n`;
    });
    download(out, 'hunt_package.txt', 'text/plain');
  }
}

function download(content, filename, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── SEARCH + FILTER ──
function highlight(text, terms) {
  let result = esc(text);
  terms.forEach(t => {
    if (!t) return;
    const re = new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + ')', 'gi');
    result = result.replace(re, '<mark>$1</mark>');
  });
  return result;
}

function applyFilters() {
  const q   = (document.getElementById('search')?.value || '').toLowerCase().trim();
  const aq  = (document.getElementById('apt-search')?.value || '').toLowerCase().trim();
  const terms = q ? q.split(/\s+/).filter(Boolean) : [];
  let visible = 0;

  document.querySelectorAll('.ind-row').forEach(row => {
    const techMatch = activeTech === 'all' || row.dataset.tech === activeTech;
    const aptMatch  = !activeApt  || row.dataset.apt.includes(activeApt);
    const textMatch = !terms.length || terms.every(t => row.dataset.text.includes(t));
    const aptTxt    = !aq || row.dataset.text.includes(aq);

    if (techMatch && aptMatch && textMatch && aptTxt) {
      row.classList.remove('hidden');
      visible++;
      const nameEl = row.querySelector('.ind-name');
      if (nameEl) {
        const orig = row.querySelector('[data-row-id]')?.dataset.rowId
          ? rowRegistry[row.dataset.rowId]?.row.indicator
          : nameEl.textContent;
        if (orig) nameEl.innerHTML = highlight(orig, [...terms, aq].filter(Boolean));
      }
    } else {
      row.classList.add('hidden');
    }
  });

  document.querySelectorAll('.technique-section').forEach(sec => {
    sec.style.display = sec.querySelectorAll('.ind-row:not(.hidden)').length ? '' : 'none';
    const tocItem = document.querySelector(`.toc-item[data-tech="${sec.dataset.tech}"]`);
    if (tocItem) tocItem.classList.toggle('active', sec.dataset.tech === activeTech);
  });

  document.getElementById('no-results').style.display = visible ? 'none' : 'block';
  updateStats(visible, totalRows);
}

function updateStats(visible, total) {
  const el = document.getElementById('stats');
  if (el) el.textContent = `${visible} / ${total} indicators`;
}

// ── EVENT LISTENERS ──
document.getElementById('search')?.addEventListener('input', applyFilters);
document.getElementById('apt-search')?.addEventListener('input', applyFilters);

document.querySelectorAll('.fbtn[data-tech]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeTech = btn.dataset.tech;
    applyFilters();
  });
});

document.querySelectorAll('.fbtn[data-apt]').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.apt;
    if (activeApt === key) {
      activeApt = null;
      btn.className = 'fbtn';
    } else {
      document.querySelectorAll('.fbtn[data-apt]').forEach(b => b.className = 'fbtn');
      activeApt = key;
      btn.classList.add('apt-' + key.toLowerCase());
    }
    applyFilters();
  });
});

// ── INIT ──
loadHunts();
render();
applyFilters();
renderHunt();
