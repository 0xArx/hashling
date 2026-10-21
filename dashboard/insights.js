// Hashling insights: the views built on Hashling's correlation engines (dossiers, storylines,
// what changed, traffic history, process history, downloads, secrets, storage).
// Loaded by app.js, which shares its helpers on window.W. Charts are plain SVG, no library.
const W = window.W;
const { $, esc, attr, icon, P, views, state, api, ago, day, rate, bytes, plural, home, toast, askBtn, askIcons, quickChips, drawer, findingItem, statusBar, propose, askAI } = W;

Object.assign(P, {
  gauge: '<path d="M4.5 17a8.5 8.5 0 1 1 15 0"/><path d="m12 13 4-5"/><circle cx="12" cy="13" r="1.3"/>',
  download: '<path d="M12 4v11"/><path d="m7 10 5 5 5-5"/><path d="M5 20h14"/>',
  upload: '<path d="M12 16V5"/><path d="m7 10 5-5 5 5"/><path d="M5 20h14"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3"/>',
  chain: '<path d="M9.5 14.5 14.5 9.5"/><path d="M11 7l1.6-1.6a3.5 3.5 0 0 1 5 5L16 12"/><path d="M13 17l-1.6 1.6a3.5 3.5 0 0 1-5-5L8 12"/>',
  play: '<path d="M8 5.5v13l10-6.5z"/>',
  pin: '<path d="M12 21s6.5-5.6 6.5-11a6.5 6.5 0 0 0-13 0c0 5.4 6.5 11 6.5 11z"/><circle cx="12" cy="10" r="2.3"/>',
  phone: '<path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2"/>',
  bolt: '<path d="M13 3 5 13.5h6L10 21l8-10.5h-6z"/>',
  scope: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/><path d="M11 8v6M8 11h6"/>',
});

// ---------- navigation ----------
const monitor = W.NAV.find(([g]) => g === 'Monitor')[1];
const after = (id, item) => monitor.splice(monitor.findIndex(([x]) => x === id) + 1, 0, item);
after('agents', ['processes', 'Processes', 'terminal', 'processes']);
after('scans', ['downloads', 'Downloads & apps', 'download', 'downloads']);
after('downloads', ['uploads', 'Uploads', 'upload']);
after('permissions', ['secrets', 'Keys & secrets', 'lock', 'secrets']);
W.NAV.splice(W.NAV.findIndex(([g]) => g === 'Activity'), 0, ['Optimize', [['optimize', 'Storage & speed', 'gauge', 'optimize']]]);
Object.assign(W.TITLES, {
  processes: ['Processes', 'Every program that ran, who started it, and anything that looked like a malware technique'],
  downloads: ['Downloads & apps', 'Where your files and apps came from, and whether Apple and malware databases trust them'],
  uploads: ['Uploads', 'What left this Mac in the last 7 days, where it went, and which files were involved'],
  secrets: ['Keys & secrets', 'Passwords and API keys left in plain text where malware looks first'],
  optimize: ['Storage & speed', 'What fills your disk, what can go safely, and what slows your Mac at startup'],
});
Object.assign(W.AREA_META, { processes: ['Processes', 'terminal'], downloads: ['Downloads & apps', 'download'], secrets: ['Keys & secrets', 'lock'], optimize: ['Storage & speed', 'gauge'] });
Object.assign(W.CAT, { webvisits: 'Websites you visited', pups: 'Junk apps', sensors: 'Camera and microphone', ransomware: 'Ransomware', webnotify: 'Website notifications', browser: 'Browser settings', behavior: 'Network behaviour', processes: 'Processes', downloads: 'Downloads', netsafety: 'Wi-Fi and router', secrets: 'Keys & secrets', notarization: 'App checks', storage: 'Storage', updates: 'Updates', incidents: 'Linked warning signs' });
Object.assign(W.LIVE, { uploads: [], processes: [], downloads: ['downloads', 'notarization', 'outdated'], secrets: ['secrets'], optimize: ['storage'] });

// ---------- charts ----------
// Categorical slots validated for CVD and normal-vision separation (dataviz reference palette).
// Theme variables, so light and dark each use their own validated steps.
const SERIES = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)', 'var(--s8)'];
const OTHER = 'var(--other)';
const GRID = 'var(--grid)';
// Colour follows the app, not its rank, so changing the range never repaints a survivor.
state.appColor ??= {};
function colorOf(name) {
  if (name === 'Other') return OTHER;
  if (!state.appColor[name]) {
    const used = new Set(Object.values(state.appColor));
    state.appColor[name] = SERIES.find((c) => !used.has(c)) ?? OTHER;
  }
  return state.appColor[name];
}

const charts = new Map();
let seq = 0;
const chart = (kind, data, h, label) => {
  const id = `c${++seq}`;
  charts.set(id, { kind, data, h });
  return `<div class="viz" data-chart="${id}" style="height:${h}px" role="img" aria-label="${esc(label)}"></div>`;
};
const ro = new ResizeObserver((entries) => { for (const e of entries) draw(e.target); });
W.hydrate = (root) => {
  for (const el of root.querySelectorAll('[data-chart]')) ro.observe(el);
  if (charts.size > 120) for (const id of charts.keys()) if (!document.querySelector(`[data-chart="${id}"]`)) charts.delete(id);
};
function draw(el) {
  const c = charts.get(el.dataset.chart);
  const w = Math.floor(el.clientWidth);
  if (!c || !w || el._w === w) return;
  el._w = w;
  DRAW[c.kind](el, c.data, w, c.h);
}

/** Tooltip built with textContent: names come from the system and are untrusted. */
function tip(el) {
  let t = el.querySelector('.viz-tip');
  if (!t) { t = document.createElement('div'); t.className = 'viz-tip'; t.setAttribute('role', 'tooltip'); el.append(t); }
  return {
    show(x, y, head, rows) {
      t.replaceChildren();
      if (head) { const h = document.createElement('div'); h.className = 'viz-tip-head'; h.textContent = head; t.append(h); }
      for (const r of rows) {
        const row = document.createElement('div'); row.className = 'viz-tip-row';
        if (r.color) { const k = document.createElement('i'); k.style.background = r.color; row.append(k); }
        const v = document.createElement('b'); v.textContent = r.value; row.append(v);
        const n = document.createElement('span'); n.textContent = r.name; row.append(n);
        t.append(row);
      }
      t.classList.add('on');
      const box = el.getBoundingClientRect();
      const tw = t.offsetWidth, th = t.offsetHeight;
      t.style.transform = `translate(${Math.round(x + 14 + tw > box.width ? x - tw - 14 : x + 14)}px, ${Math.round(Math.max(0, Math.min(y - th / 2, box.height - th)))}px)`;
    },
    hide() { t.classList.remove('on'); },
  };
}

/** Round axis maximum; byte axes snap to whole units (KB, MB, GB, as Finder counts them) so ticks read cleanly. */
const niceBytes = (v) => { if (v <= 0) return 1000; const u = 1000 ** Math.max(0, Math.floor(Math.log10(v) / 3)); return niceMax(v / u) * u; };
const niceMax = (v) => { if (v <= 0) return 1; const p = 10 ** Math.floor(Math.log10(v)); const n = v / p; return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p; };
const timeLabel = (t, spanMs) => new Date(t).toLocaleString([], spanMs > 2 * 86_400_000 ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' });

const DRAW = {
  /** Time series: stacked areas (several apps) or a single line. Crosshair snaps to the nearest point. */
  series(el, d, w, h) {
    const L = 54, R = 12, T = 10, B = 24;
    const iw = w - L - R, ih = h - T - B;
    const n = d.t.length;
    const x = (i) => L + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
    const tops = d.t.map((_, i) => d.stacked ? d.series.reduce((s, sr) => s + sr.values[i], 0) : Math.max(...d.series.map((sr) => sr.values[i])));
    const max = d.yMax ?? (d.fmt === bytes ? niceBytes : niceMax)(Math.max(...tops, 0) * 1.05);
    const y = (v) => T + ih - (v / max) * ih;
    const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
    let svg = `<svg width="${w}" height="${h}" aria-hidden="true">`;
    for (const v of ticks) svg += `<line x1="${L}" x2="${w - R}" y1="${y(v)}" y2="${y(v)}" stroke="${GRID}"/><text x="${L - 8}" y="${y(v) + 4}" text-anchor="end" class="viz-ax">${esc(d.fmt(v).replace(/\.0+ /, ' '))}</text>`;
    const span = d.t[n - 1] - d.t[0];
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 90))));
    for (let i = 0; i < n; i += every) svg += `<text x="${x(i)}" y="${h - 6}" text-anchor="middle" class="viz-ax">${esc(timeLabel(d.t[i], span))}</text>`;
    if (d.stacked) {
      const base = new Array(n).fill(0);
      for (const sr of d.series) {
        const lo = base.slice();
        const hi = lo.map((b, i) => b + sr.values[i]);
        const top = hi.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' L');
        const bot = lo.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).reverse().join(' L');
        svg += `<path d="M${top} L${bot} Z" fill="${sr.color}" fill-opacity="0.78"/><path d="M${top}" fill="none" stroke="var(--panel)" stroke-width="1.5"/>`;
        hi.forEach((v, i) => { base[i] = v; });
      }
    } else {
      for (const sr of d.series) {
        const pts = sr.values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' L');
        svg += `<path d="M${x(0)},${y(0)} L${pts} L${x(n - 1)},${y(0)} Z" fill="${sr.color}" fill-opacity="0.08"/><path d="M${pts}" fill="none" stroke="${sr.color}" stroke-width="2" stroke-linejoin="round"/>`;
        if (n <= 40) sr.values.forEach((v, i) => { svg += `<circle cx="${x(i)}" cy="${y(v)}" r="2.5" fill="${sr.color}" stroke="var(--panel)" stroke-width="1.5"/>`; });
      }
    }
    svg += `<line class="viz-cross" x1="0" x2="0" y1="${T}" y2="${T + ih}" stroke="var(--faint)" stroke-width="1" opacity="0"/><rect x="${L}" y="${T}" width="${iw}" height="${ih}" fill="transparent" class="viz-hit"/></svg>`;
    el.innerHTML = svg;
    const tt = tip(el);
    const cross = el.querySelector('.viz-cross');
    const hit = el.querySelector('.viz-hit');
    const show = (i) => {
      cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('opacity', '1');
      const rows = d.series.map((sr) => ({ color: sr.color, value: d.fmt(sr.values[i]), name: sr.name, v: sr.values[i] })).filter((r) => r.v > 0 || d.series.length === 1);
      if (d.stacked && rows.length > 1) rows.unshift({ value: d.fmt(tops[i]), name: 'Total' });
      tt.show(x(i), T + ih / 3, new Date(d.t[i]).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }), rows.length ? rows : [{ value: d.fmt(0), name: 'No traffic' }]);
    };
    hit.addEventListener('pointermove', (e) => { const r = el.getBoundingClientRect(); show(Math.max(0, Math.min(n - 1, Math.round(((e.clientX - r.left - L) / iw) * (n - 1))))); });
    hit.addEventListener('pointerleave', () => { cross.setAttribute('opacity', '0'); tt.hide(); });
  },

  /** App -> company flow (Sankey). Band width = number of live connections. */
  flow(el, d, w, h) {
    const LW = Math.min(150, w * 0.28), RW = Math.min(190, w * 0.34), NW = 10, GAP = 8, T = 6;
    const ax = LW, bx = w - RW - NW;
    const sum = (m) => [...m.values()].reduce((a, b) => a + b, 0);
    const aTot = new Map(), bTot = new Map();
    for (const l of d.links) { aTot.set(l.a, (aTot.get(l.a) ?? 0) + l.v); bTot.set(l.b, (bTot.get(l.b) ?? 0) + l.v); }
    const total = sum(aTot);
    // Space left for the bands after every node has room for its label; values can be bytes, so scale, never floor.
    const k = Math.max(40, h - T * 2 - (GAP + 16) * Math.max(aTot.size, bTot.size)) / total;
    // Every node takes at least a label's height so names never overlap.
    const place = (m) => { let yy = T; const pos = new Map(); for (const [name, v] of m) { pos.set(name, { y: yy, h: Math.max(2, v * k), off: 0 }); yy += Math.max(16, v * k) + GAP; } return pos; };
    const A = place(aTot), B = place(bTot);
    let svg = `<svg width="${w}" height="${h}" aria-hidden="true">`;
    d.links.forEach((l, i) => {
      const a = A.get(l.a), b = B.get(l.b), t = Math.max(1.5, l.v * k);
      const y0 = a.y + a.off, y1 = b.y + b.off; a.off += t; b.off += t;
      const x0 = ax + NW, x1 = bx, xm = (x0 + x1) / 2;
      svg += `<path class="viz-link" data-i="${i}" d="M${x0},${y0} C${xm},${y0} ${xm},${y1} ${x1},${y1} L${x1},${y1 + t} C${xm},${y1 + t} ${xm},${y0 + t} ${x0},${y0 + t} Z" fill="${colorOf(l.a)}" fill-opacity="0.32"/>`;
    });
    for (const [name, p] of A) svg += `<rect x="${ax}" y="${p.y}" width="${NW}" height="${p.h}" rx="3" fill="${colorOf(name)}"/><text x="${ax - 8}" y="${p.y + p.h / 2 + 4}" text-anchor="end" class="viz-lbl">${esc(clip(name, 20))}</text>`;
    for (const [name, p] of B) svg += `<rect x="${bx}" y="${p.y}" width="${NW}" height="${p.h}" rx="3" fill="var(--node)"/><text x="${bx + NW + 8}" y="${p.y + p.h / 2 + 4}" class="viz-lbl">${esc(clip(name, 26))}</text>`;
    el.innerHTML = svg + '</svg>';
    const tt = tip(el);
    for (const p of el.querySelectorAll('.viz-link')) {
      const l = d.links[Number(p.dataset.i)];
      p.addEventListener('pointermove', (e) => { const r = el.getBoundingClientRect(); tt.show(e.clientX - r.left, e.clientY - r.top, `${l.a} → ${l.b}`, [d.fmt ? { color: colorOf(l.a), value: d.fmt(l.v), name: d.unit ?? '' } : { color: colorOf(l.a), value: plural(l.v, 'connection'), name: 'open now' }]); });
      p.addEventListener('pointerleave', () => tt.hide());
    }
  },
};
/** Plain text with `command` spans shown as code. */
const ticks = (t) => esc(t).replace(/`([^`]+)`/g, '<code>$1</code>');
const clip = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));

/** Horizontal bars in HTML: label, bar, value. Values are direct labels, so no hover is needed to read them. */
function bars(rows, { fmt = bytes, color = SERIES[0], max } = {}) {
  const m = max ?? Math.max(...rows.map((r) => r.v), 1);
  return `<div class="bars">${rows.map((r) => `<div class="bar-row" title="${esc(`${r.label}: ${fmt(r.v)}`)}"><span class="bar-label">${esc(r.label)}</span><span class="bar-track"><span class="bar-fill" style="width:${Math.max(0.6, (r.v / m) * 100).toFixed(2)}%;background:${r.color ?? color}"></span></span><span class="bar-val">${esc(fmt(r.v))}</span></div>`).join('')}</div>`;
}

/** One segmented bar (parts of a whole) with a legend that carries the numbers. */
function partsBar(parts, fmt = (v) => String(v)) {
  const total = parts.reduce((n, p) => n + p.v, 0) || 1;
  return `<div class="parts" role="img" aria-label="${esc(parts.map((p) => `${p.label} ${fmt(p.v)}`).join(', '))}">${parts.filter((p) => p.v > 0).map((p) => `<span style="flex:${p.v / total};background:${p.color}" title="${esc(`${p.label}: ${fmt(p.v)}`)}"></span>`).join('')}</div>
  <div class="legend">${parts.filter((p) => p.v > 0).map((p) => `<span><i style="background:${p.color}"></i>${esc(p.label)} <b>${esc(fmt(p.v))}</b></span>`).join('')}</div>`;
}

// ---------- storylines (kill chain) ----------
const STAGES = [['arrived', 'Arrived', 'download'], ['ran', 'Ran', 'play'], ['stayed', 'Stays at startup', 'power'], ['called-home', 'Called home', 'globe'], ['misbehaved', 'Malware technique', 'alert']];
function killChain(stages, steps = []) {
  const first = (s) => steps.find((x) => x.stage === s)?.ts;
  return `<ol class="chain">${STAGES.map(([id, label, ic]) => {
    const on = stages.includes(id);
    return `<li class="${on ? 'on' : ''}"><span class="node">${icon(ic)}</span><b>${label}</b><span class="when">${on && first(id) ? esc(ago(first(id))) : on ? 'yes' : 'not seen'}</span></li>`;
  }).join('')}</ol>`;
}
function openStory(i) {
  const s = state.incidents?.[i];
  if (!s) return;
  const ctx = { kind: 'incident', program: s.name, path: s.root, severity: s.severity, stages: s.stages, steps: s.steps.map((x) => `${new Date(x.ts).toISOString()} ${x.stage}: ${x.text}`) };
  drawer(`<div class="drawer-head"><span class="sev ${esc(s.severity)}">${esc(s.severity)}</span><span class="title">Linked warning signs</span><button class="btn ghost icon-btn" data-close aria-label="Close">${icon('x')}</button></div>
  <div class="drawer-body">
    <div><h2 id="drawer-title">${esc(s.name)}</h2><p class="muted mono small wrap" style="margin:6px 0 0">${esc(home(s.root))}</p></div>
    <div class="explain"><p class="label">Why I linked these</p><p>Each signal alone could be harmless. Together they follow the pattern of an infection: software arrives, runs, makes itself start automatically and contacts a server. They all involve the same program.</p></div>
    ${killChain(s.stages, s.steps)}
    <div><p class="label">Timeline</p><div class="story-steps">${s.steps.map((x) => `<div class="story-step"><time>${esc(day(x.ts))}</time><span class="dot ${x.weight >= 3 ? 'high' : x.weight >= 2 ? 'medium' : 'low'}"></span><span><b>${esc(STAGES.find(([id]) => id === x.stage)?.[1] ?? x.stage)}</b> · ${esc(x.text)}</span></div>`).join('')}</div></div>
    <div><p class="label">Ask Hashling about it</p>${quickChips(ctx)}</div>
    <div class="row"><button class="btn" data-act="dossier" data-q="${esc(s.root)}">${icon('scope')}Investigate ${esc(clip(s.name, 24))}</button><button class="btn danger" data-act="propose" data-a="${attr({ type: 'quarantine_file', target: { path: s.root }, reason: `Quarantine ${s.name}: ${s.stages.length} linked warning signs` })}">Quarantine…</button></div>
  </div>`);
}

// ---------- app dossier ----------
const LEVEL = { high: ['bad', 'High risk'], medium: ['flag', 'Some risk'], low: ['ok', 'Low risk'], minimal: ['ok', 'Very low risk'] };
const VERDICT = { notarized: ['ok', 'Notarized by Apple'], 'app-store': ['ok', 'Mac App Store'], apple: ['ok', 'Part of macOS'], 'developer-id': ['', 'Identified developer, not notarized'], rejected: ['bad', 'Not checked by Apple'], unknown: ['', 'Not assessed'] };

function factorBars(factors) {
  const m = Math.max(10, ...factors.map((f) => Math.abs(f.points)));
  return `<div class="factors">${factors.map((f) => {
    const pct = (Math.abs(f.points) / m) * 50;
    const good = f.points < 0;
    return `<div class="factor"><div class="factor-label"><span>${esc(f.label)}</span>${f.detail ? `<span class="faint small wrap">${esc(f.detail)}</span>` : ''}</div>
      <div class="factor-track"><span class="axis"></span>${f.points ? `<span class="factor-fill ${good ? 'good' : 'bad'}" style="${good ? `right:50%` : `left:50%`};width:${pct.toFixed(1)}%"></span>` : '<span class="factor-zero"></span>'}</div>
      <span class="factor-val ${good ? 'good' : f.points ? 'bad' : ''}">${f.points > 0 ? '+' : ''}${f.points}</span></div>`;
  }).join('')}<div class="factor-key"><span>${icon('check')}Lowers risk</span><span>Raises risk${icon('alert')}</span></div></div>`;
}

/** Everything an app set up, as one approval: quit it, turn off its startup items, take back permissions, lock it away. */
function removeAllBlock(d, root) {
  // Only offered when something about the app is off; a well-known, checked app does not need a scary button.
  if (/^\/(System|usr|bin|sbin)\//.test(root) || /Apple/.test(d.identity.signer ?? '') || ['low', 'minimal'].includes(d.risk.level)) return '';
  // Quitting the main program closes its helpers too.
  const main = d.running.filter((p) => p.name === d.name).slice(0, 2);
  const steps = [
    ...(main.length ? main : d.running.slice(0, 1)).map((p) => ({ type: 'kill_process', target: { pid: p.pid, name: p.name } })),
    ...d.persistence.filter((p) => p.plist).map((p) => ({ type: 'disable_persistence', target: { plist: p.plist, label: p.label } })),
    ...d.permissions.filter((g) => g.service && /^[A-Za-z0-9.-]+$/.test(g.client)).map((g) => ({ type: 'revoke_permission', target: { service: g.service, bundleId: g.client } })),
    { type: 'quarantine_file', target: { path: root } },
  ];
  const parts = [d.running.length && 'quit it', d.persistence.length && `turn off ${plural(d.persistence.length, 'startup item')}`, d.permissions.length && `take back ${plural(d.permissions.length, 'permission')}`, 'lock the app away in Quarantine'].filter(Boolean);
  return `<div class="fix-panel"><div><b>Don’t trust ${esc(d.name)}?</b><span class="sub">Remove all of it in one go: ${esc(parts.join(', '))}. One Touch ID. Anything locked away can be restored later.</span></div><button class="btn" data-act="propose" data-a="${attr({ type: 'remove_all', target: { name: d.name, steps }, reason: `Remove ${d.name}: ${parts.join(', ')}.` })}">Remove all of it…</button></div>`;
}

async function openDossier(q) {
  drawer(`<div class="drawer-head"><span class="title">About this app</span><button class="btn ghost icon-btn" data-close aria-label="Close">${icon('x')}</button></div><div class="drawer-body"><div class="step"><span class="spin"></span>Collecting everything I know about ${esc(clip(home(q), 60))}…</div></div>`);
  const d = await api(`/api/dossier?q=${encodeURIComponent(q)}`);
  if ($('#drawer').hidden) return;
  if (d.error) { drawer(`<div class="drawer-head"><span class="title">About this app</span><button class="btn ghost icon-btn" data-close aria-label="Close">${icon('x')}</button></div><div class="drawer-body"><div class="empty">${esc(d.error)} It may have quit or been removed.</div></div>`); return; }
  const [tone, levelText] = LEVEL[d.risk.level] ?? LEVEL.low;
  const v = VERDICT[d.identity.notarized] ?? null;
  const root = d.bundle ?? d.path;
  const ctx = { kind: 'app-dossier', name: d.name, path: root, risk: d.risk, signer: d.identity.signer, notarized: d.identity.notarized, reputation: d.identity.reputation?.verdict, downloadedFrom: d.identity.downloadedFrom, startedBy: d.viaAgent, destinations7d: d.network.destinations7d.slice(0, 12).map((x) => x.dest ?? x.org ?? x.host), startupItems: d.persistence.map((p) => p.label), permissions: d.permissions.map((p) => p.label), ruleHits: d.ruleHits.map((r) => r.rule) };
  const ident = {
    'Signed by': d.identity.signer,
    'Apple check': v?.[1],
    'Malware databases': d.identity.reputation ? ({ malicious: `Matches known malware${d.identity.reputation.avDetectionPct ? ` (${d.identity.reputation.avDetectionPct}% of engines)` : ''}`, 'known-good': 'Known legitimate file (CIRCL / NSRL)', unknown: 'Not in any database (normal for most apps)' })[d.identity.reputation.verdict] : 'Not checked',
    'Downloaded from': d.identity.downloadedFrom ? safeHost(d.identity.downloadedFrom) : d.identity.quarantineAgent ? `via ${d.identity.quarantineAgent}` : null,
    'First seen running': d.identity.firstSeenRunning ? day(d.identity.firstSeenRunning) : null,
    Version: d.version, 'App ID': d.bundleId,
  };
  const n = d.network;
  drawer(`<div class="drawer-head"><span class="title">About this app</span><span class="right"></span><button class="btn ghost icon-btn" data-close aria-label="Close">${icon('x')}</button></div>
  <div class="drawer-body">
    <div><h2 id="drawer-title">${esc(d.name)}</h2><p class="muted mono small wrap" style="margin:6px 0 0">${esc(home(root))}</p>${d.note ? `<p class="muted" style="margin:8px 0 0">${esc(d.note)}</p>` : ''}</div>
    <div class="risk ${tone}"><div class="risk-num"><b>${d.risk.score}</b><span>/ 100</span></div><div class="risk-body"><b>${levelText}</b><div class="risk-meter"><span style="width:${d.risk.score}%"></span></div><span class="sub">Based on ${plural(d.risk.factors.length, 'thing')} I checked about this app</span></div></div>
    ${d.risk.factors.length ? `<div><p class="label">Why this score</p>${factorBars(d.risk.factors)}</div>` : ''}
    <div><p class="label">Ask Hashling about it</p>${quickChips(ctx)}</div>
    <dl class="kv">${Object.entries(ident).filter(([, x]) => x).map(([k, x]) => `<dt>${esc(k)}</dt><dd>${esc(x)}</dd>`).join('')}
      <dt>Started by</dt><dd>${d.startedBy.length ? d.startedBy.map((p) => `${esc(p.name)}${p.agent ? ` <span class="chip agent">${esc(p.agent)}</span>` : ''}`).join(' ← ') : d.running.length ? 'You or macOS (not another app)' : 'Not running now'}</dd></dl>
    <div><p class="label">Network</p>
      <div class="mini-stats"><div><b>${bytes(n.last24h.bytesOut)}</b><span>sent in 24 h</span></div><div><b>${bytes(n.last24h.bytesIn)}</b><span>received in 24 h</span></div><div><b>${n.destinations7d.length}</b><span>places in 7 days</span></div></div>
      ${n.now.some((c) => c.intel) ? `<div class="status bad" style="margin:10px 0 0"><div class="ico">${icon('alert', 'lg')}</div><div><b>Talking to a known-malicious server</b><span class="sub">${esc(n.now.filter((c) => c.intel).map((c) => `${c.ip} (${c.intel.label})`).join(', '))}</span></div></div>` : ''}
      ${n.beacons.length ? `<div class="small" style="margin-top:10px">${n.beacons.map((b) => `<span class="chip ${b.suspicious ? 'warn' : ''}">checks in with ${esc(b.dest)} every ${esc(b.intervalSec)}s</span>`).join(' ')}</div>` : ''}
      ${n.destinations7d.length ? `<details class="fold" style="margin-top:10px"><summary>Everywhere it connected in the last 7 days (${n.destinations7d.length})</summary><div class="fold-body"><div class="dest-list">${n.destinations7d.map((x) => `<div><span>${esc(x.dest ?? x.org ?? x.host ?? x.ip)}</span><span class="faint small">${esc(x.country ?? '')} ${esc(ago(x.lastSeen))}</span></div>`).join('')}</div></div></details>` : '<p class="small muted" style="margin:10px 0 0">No internet connections recorded.</p>'}
      ${n.exposedPorts.length ? `<p class="small" style="margin:10px 0 0">Other devices on your network can connect to it (${plural(n.exposedPorts.length, 'port')}).</p>` : ''}
    </div>
    ${d.persistence.length ? `<div><p class="label">Starts automatically</p><div class="list">${d.persistence.map((p) => `<div class="item"><div class="body"><div class="t">${esc(p.label)}</div><div class="s mono">${esc(home(p.plist ?? p.program ?? ''))}</div></div>${p.isNew ? '<span class="chip warn">new</span>' : ''}</div>`).join('')}</div></div>` : ''}
    ${d.permissions.length ? `<div><p class="label">Privacy permissions</p><div class="row" style="gap:6px">${d.permissions.map((p) => `<span class="chip ${p.risk === 'high' ? 'warn' : ''}">${esc(p.label)}</span>`).join('')}</div></div>` : ''}
    ${d.ruleHits.length ? `<div><p class="label">Malware techniques seen</p><div class="list">${d.ruleHits.map((r) => `<div class="item"><span class="dot high"></span><div class="body"><div class="t">${esc(String(r.rule).replace(/-/g, ' '))}</div><div class="s mono wrap">${esc(clip(r.args ?? r.name, 160))}</div><div class="tiny faint">${esc(day(r.ts))}</div></div></div>`).join('')}</div></div>` : ''}
    ${d.childProcesses7d.length ? `<div><p class="label">Programs it started (7 days)</p><div class="row" style="gap:6px">${d.childProcesses7d.map((c) => `<span class="chip">${esc(c.name)} <span class="faint">×${c.n}</span></span>`).join('')}</div></div>` : ''}
    ${d.findings.length ? `<div><p class="label">Related findings</p><div class="list">${d.findings.map((f) => `<div class="item click" data-act="finding" data-id="${esc(f.id)}" tabindex="0" role="button"><span class="dot ${f.tier === 'suspicious' ? 'high' : f.tier === 'risk' ? 'medium' : 'low'}"></span><div class="body"><div class="t">${esc(f.title)}</div></div>${icon('chev', 'chev')}</div>`).join('')}</div></div>` : ''}
    ${removeAllBlock(d, root)}
    <div class="row"><button class="btn" data-act="scan-quick" data-v="${esc(root)}">${icon('bug')}Scan for malware</button>${d.running[0] ? `<button class="btn" data-act="process" data-pid="${d.running[0].pid}">Inspect process</button>` : ''}${root.startsWith('/System') ? '' : `<button class="btn danger" data-act="propose" data-a="${attr({ type: 'quarantine_file', target: { path: root }, reason: `Quarantine ${d.name} (risk ${d.risk.score}/100)` })}">Quarantine…</button>`}</div>
  </div>`);
}
const safeHost = (u) => { try { return new URL(u).hostname; } catch { return u; } };
const investigate = (q, label = 'Investigate') => `<button type="button" class="ask" data-act="dossier" data-q="${esc(q)}" title="Everything I know about this app">${icon('scope')}${esc(label)}</button>`;
W.investigate = investigate;

// ---------- Overview: storylines, what changed, score trend ----------
const baseOverview = views.overview;
views.overview = async () => {
  const [html, inc, ch, hist] = await Promise.all([baseOverview(), api('/api/incidents').catch(() => null), api('/api/changes?hours=24').catch(() => null), api('/api/score-history?days=30').catch(() => [])]);
  state.incidents = inc?.incidents ?? [];
  return html.replace('<div class="home mt">', `${storylines(state.incidents)}<div class="home mt">`).replace('<!--rail-extra-->', briefing(ch) + scoreCard(hist));
};

function storylines(list) {
  if (!list.length) return '';
  return `<div class="mt"><div class="section-head"><p class="h2">${icon('chain')}Linked warning signs</p></div>
    <div class="stack" style="gap:10px">${list.slice(0, 4).map((s, i) => `<div class="card story"><div class="row between" style="flex-wrap:nowrap;gap:12px"><div style="min-width:0"><div class="row" style="gap:8px"><b class="wrap">${esc(s.name)}</b><span class="sev ${esc(s.severity)}">${esc(s.severity)}</span></div><p class="small muted" style="margin:4px 0 0">${plural(s.stages.length, 'step')} that malware usually takes, all by the same program. It can be harmless, for example an app you are building or just installed. If you do not recognise it, open the storyline.</p></div>
      <button class="btn sm" data-act="story" data-i="${i}">See the storyline</button></div>${killChain(s.stages, s.steps)}</div>`).join('')}</div></div>`;
}

const CHANGE_ROWS = [
  ['newApps', 'new app', 'new apps', 'download', (x) => x.name ?? home(x.key)],
  ['newStartupItems', 'new startup item', 'new startup items', 'power', (x) => x.label ?? home(x.key)],
  ['newPermissions', 'new permission', 'new permissions', 'key', (x) => `${x.client ?? x.app ?? ''} · ${x.label ?? x.service ?? ''}`],
  ['newPrograms', 'program ran for the first time', 'programs ran for the first time', 'play', (x) => `${x.name}${x.agent ? ` (started by ${x.agent})` : ''}`],
  ['newListeningPorts', 'new open port', 'new open ports', 'wifi', (x) => x.key],
  ['newDestinations', 'new place an app talked to', 'new places apps talked to', 'globe', (x) => `${x.app} → ${x.dest}`],
  ['downloads', 'download', 'downloads', 'download', (x) => `${x.name}${x.from_url ? ` from ${safeHost(x.from_url)}` : ''}`],
];
function briefing(ch) {
  if (!ch) return '<section><div class="section-head"><p class="h2">Since yesterday</p></div><div class="card pad"><p class="muted small" style="margin:0">Not available yet.</p></div></section>';
  // Simple mode skips the noisy rows (programs and destinations change all day on a normal Mac).
  const quiet = state.mode === 'simple' ? new Set(['newPrograms', 'newDestinations', 'newListeningPorts']) : new Set();
  const rows = CHANGE_ROWS.filter(([k]) => !quiet.has(k)).map(([k, one, many, ic, fmt]) => [ch[k] ?? [], one, many, ic, fmt]).filter(([list]) => list.length);
  const score = ch.score && ch.score.from !== ch.score.to ? `<span class="chip ${ch.score.to > ch.score.from ? 'ok' : 'warn'}">score ${ch.score.from} → ${ch.score.to}</span>` : '';
  return `<section class="adv"><div class="section-head"><p class="h2">Since yesterday</p>${score}</div><div class="card pad brief">
    <p class="small muted" style="margin:0 0 12px">Compared with what I learned is normal for this Mac.</p>
    ${Date.now() - (ch.learningSince ?? 0) < 86_400_000 && !rows.length ? `<div class="empty" style="padding:18px">I’m still learning what is normal for this Mac. From ${esc(new Date((ch.learningSince ?? Date.now()) + 86_400_000).toLocaleString([], { weekday: 'long', hour: '2-digit', minute: '2-digit' }))}, this shows anything new.</div>` : rows.length ? `<div class="brief-list">${rows.map(([list, one, many, ic, fmt]) => `<details class="brief-row"><summary>${icon(ic)}<b>${list.length >= 50 ? '50+' : list.length}</b><span>${esc(list.length === 1 ? one : many)}</span>${icon('chev', 'chev')}</summary><ul>${list.slice(0, 12).map((x) => `<li class="wrap">${esc(fmt(x))}<span class="faint"> · ${esc(ago(x.firstSeen ?? x.ts))}</span></li>`).join('')}${list.length > 12 ? `<li class="faint">and ${list.length - 12} more</li>` : ''}</ul></details>`).join('')}</div>` : '<div class="empty" style="padding:18px">Nothing new since yesterday.</div>'}
    <div class="row" style="margin-top:12px;gap:8px">${askBtn({ kind: 'what-changed', hours: 24, counts: Object.fromEntries(rows.map(([l, , many]) => [many, l.length])) }, 'Brief me', 'Give me my daily briefing: call what_changed for 24 hours and storylines, tell me in a few bullets what is new and whether any of it matters.')}<span class="tiny faint">${state.incidents.length ? '' : 'No linked warning signs. I check every minute whether separate signals point to the same program.'}</span></div></div></section>`;
}
function scoreCard(hist) {
  const pts = hist ?? [];
  // Say how far back the line really goes: a new install has hours of data, not 30 days.
  const first = pts[0]?.ts;
  const span = !first || Date.now() - first > 29 * 86_400_000 ? 'last 30 days'
    : `since ${new Date(first).toLocaleString([], Date.now() - first < 86_400_000 ? { hour: 'numeric', minute: '2-digit' } : { weekday: 'long', hour: 'numeric' })}`;
  return `<section><div class="section-head"><p class="h2">Security score</p><span class="small faint">${esc(span)}</span></div><div class="card pad">
    ${pts.length >= 2 ? '<p class="small muted" style="margin:0 0 8px">Higher is safer. A dip means I found something; the line climbs back once it is dealt with.</p>' : ''}
    ${pts.length >= 2 ? chart('series', { t: pts.map((p) => p.ts), series: [{ name: 'Score', color: SERIES[0], values: pts.map((p) => p.score) }], fmt: (v) => String(Math.round(v)), yMax: 100 }, 180, `Security score over time, now ${pts[pts.length - 1].score}`)
      : `<div class="empty" style="padding:28px 12px">I record your score every hour.<br>The trend appears after the next reading.</div>`}</div></section>`;
}

// ---------- Network: traffic history, who apps talk to, beacons, network safety, threat intel ----------
const baseNetwork = views.network;
state.trafficHours ??= 6;
views.network = async () => {
  const [html, tr, beh, ns, intel, net] = await Promise.all([baseNetwork(), api(`/api/traffic?hours=${state.trafficHours}&top=5`), api('/api/behavior'), api('/api/netsafety'), api('/api/intel'), api('/api/network')]);
  const extra = `${netSafety(ns, intel)}${trafficCard(tr)}${flowCard(net)}${behaviorCard(beh)}`;
  const marker = '<div class="toolbar mt">';
  return html.replace(marker, `${extra}${marker}`);
};

function netSafety(ns, intel) {
  const feeds = intel?.feeds ?? [];
  const entries = feeds.reduce((n, f) => n + (f.entries ?? 0), 0);
  const wifi = ns?.wifi;
  const lvl = wifi?.securityLevel === 'ok' ? 'ok' : wifi?.connected ? 'bad' : '';
  return `<div class="grid g2 mt">
    <div class="card pad"><p class="h3" style="margin:0 0 10px">This network</p>
      <div class="checks-mini">
        <div>${icon(lvl === 'ok' ? 'check' : 'alert')}<span><b>${esc(ns?.label ?? 'Unknown')}</b><span class="sub">${lvl === 'ok' ? 'Encrypted Wi-Fi.' : wifi?.connected ? 'Others nearby may be able to read unencrypted traffic.' : 'Not on Wi-Fi.'}</span></span></div>
        <div>${icon(ns?.gatewayStable === false ? 'alert' : 'check')}<span><b>${ns?.gatewayStable === false ? 'Router identity changed' : 'Router identity unchanged'}</b><span class="sub">${ns?.gatewayStable === false ? 'A different device is answering as your router. This is how man-in-the-middle attacks start.' : ns?.gatewayKnown ? 'Same router hardware as before on this network.' : 'First time I’ve seen this network; I remember its router now.'}</span></span></div>
        <div>${icon('check')}<span><b>DNS: ${esc((ns?.dns ?? []).map((d) => d.owner ?? d.ip).join(', ') || 'unknown')}</b><span class="sub">The service that turns names into addresses. I’ll alert you if it changes.</span></span></div>
      </div></div>
    <div class="card pad"><p class="h3" style="margin:0 0 6px">Known bad servers</p>
      <p class="small muted" style="margin:0 0 10px">Every connection is checked against ${entries.toLocaleString()} servers that security researchers have caught spreading malware or running scams. The list updated ${esc(ago(feeds.reduce((m, f) => Math.max(m, f.updated ?? 0), 0)))}. You will be warned the moment any app talks to one.</p>
      <details class="fold"><summary>Where the list comes from</summary><div class="fold-body"><div class="dest-list">${feeds.map((f) => `<div><span><b>${esc(f.name)}</b><span class="faint small"> · ${esc(f.about)}</span></span><span class="faint small">${(f.entries ?? 0).toLocaleString()}</span></div>`).join('')}</div></div></details></div>
  </div>`;
}

function trafficCard(tr) {
  const apps = tr.apps ?? [];
  const series = apps.map((a) => ({ name: a, color: colorOf(a), values: tr.points.map((p) => (p.apps[a]?.in ?? 0) + (p.apps[a]?.out ?? 0)) }));
  const per = tr.bucketMs >= 3_600_000 ? 'per hour' : `per ${Math.round(tr.bucketMs / 60_000)} min`;
  const totals = new Map(tr.totals.map((t) => [t.app, t]));
  const has = series.some((s) => s.values.some((v) => v > 0));
  return `<div class="card pad mt"><div class="row between" style="gap:10px"><div><p class="h3" style="margin:0">Traffic over time</p><p class="small muted" style="margin:2px 0 0">Data sent and received by the busiest apps, ${per}</p></div>
    <div class="seg" role="group" aria-label="Time range">${[[1, '1 h'], [6, '6 h'], [24, '24 h'], [168, '7 days']].map(([h, l]) => `<button class="${state.trafficHours === h ? 'on' : ''}" data-act="traffic-range" data-v="${h}">${l}</button>`).join('')}</div></div>
    ${has ? `<div class="legend" style="margin:12px 0 4px">${series.map((s) => { const t = totals.get(s.name); return `<span><i style="background:${s.color}"></i>${esc(s.name)}${t ? ` <b>${bytes(t.bytesIn + t.bytesOut)}</b>` : ''}</span>`; }).join('')}</div>
      ${chart('series', { t: tr.points.map((p) => p.t), series, stacked: true, fmt: bytes }, 220, `Network traffic by app over the last ${state.trafficHours} hours`)}
      <details class="fold" style="margin-top:8px"><summary>Show as a table</summary><div class="fold-body"><div class="tablewrap flat"><table class="table"><thead><tr><th>App</th><th class="num">Received</th><th class="num">Sent</th></tr></thead><tbody>${tr.totals.map((t) => `<tr><td>${esc(t.app)}</td><td class="num">${bytes(t.bytesIn)}</td><td class="num">${bytes(t.bytesOut)}</td></tr>`).join('')}</tbody></table></div></div></details>`
      : '<div class="empty" style="padding:28px">I’m recording traffic. The chart fills in over the next minutes.</div>'}</div>`;
}

function flowCard(net) {
  const counts = new Map();
  for (const p of net.processes ?? []) for (const c of p.connections) if (c.external) { const k = `${p.app}\u0000${c.org ?? c.host ?? 'Not identified yet'}`; counts.set(k, (counts.get(k) ?? 0) + 1); }
  const byApp = new Map();
  for (const [k, v] of counts) { const [a] = k.split('\u0000'); byApp.set(a, (byApp.get(a) ?? 0) + v); }
  const topApps = [...byApp].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([a]) => a);
  const byOrg = new Map();
  for (const [k, v] of counts) { const [a, b] = k.split('\u0000'); if (topApps.includes(a)) byOrg.set(b, (byOrg.get(b) ?? 0) + v); }
  const topOrgs = new Set([...byOrg].sort((a, b) => b[1] - a[1]).slice(0, 9).map(([b]) => b));
  const merged = new Map();
  for (const [k, v] of counts) {
    const [a, b0] = k.split('\u0000');
    if (!topApps.includes(a)) continue;
    const key = `${a}\u0000${topOrgs.has(b0) ? b0 : 'Everyone else'}`;
    merged.set(key, (merged.get(key) ?? 0) + v);
  }
  const links = [...merged].map(([k, v]) => { const [a, b] = k.split('\u0000'); return { a, b, v }; })
    .sort((x, y) => topApps.indexOf(x.a) - topApps.indexOf(y.a) || (x.b === 'Everyone else') - (y.b === 'Everyone else') || y.v - x.v);
  if (!links.length) return '';
  const nodes = Math.max(topApps.length, new Set(links.map((l) => l.b)).size);
  return `<div class="card pad mt"><p class="h3" style="margin:0">Who your apps are talking to</p><p class="small muted" style="margin:2px 0 12px">Live internet connections from the busiest apps to the companies that own the other end. Hover a band for the count.</p>
    ${chart('flow', { links }, Math.max(200, nodes * 34), 'Apps and the companies they connect to')}</div>`;
}

function behaviorCard(beh) {
  const beacons = beh?.beacons ?? [];
  const spikes = (beh?.uploads ?? []).filter((u) => u.ratio && u.ratio >= 10 && u.out > 100 * 1024 * 1024); // same bar as the alert
  return `<div class="grid g2 mt">
    <div class="card pad"><p class="h3" style="margin:0 0 4px">Regular check-ins</p><p class="small muted" style="margin:0 0 10px">Malware often contacts its server on a fixed clock (“beaconing”). I time every app’s new connections, the way the open-source RITA tool does.</p>
      ${beacons.length ? `<div class="list">${beacons.slice(0, 8).map((b) => `<div class="item"><span class="dot ${b.suspicious ? 'high' : 'low'}"></span><div class="body"><div class="t">${esc(b.app)} → ${esc(b.dest)}</div><div class="s">every ${esc(b.intervalSec)}s · ${b.count ?? ''} times${b.suspicious ? ' · unusual for this app' : ' · normal for this kind of app'}</div><div class="row-actions">${investigate(b.path ?? b.app)}</div></div></div>`).join('')}</div>` : `<div class="empty-inline">${icon('check')}No app is checking in on a suspicious schedule.</div>`}</div>
    <div class="card pad"><div class="row between" style="gap:8px"><p class="h3" style="margin:0 0 4px">Unusual uploads</p><a class="small" href="#/uploads" style="color:var(--accent-2)">Everything sent this week</a></div><p class="small muted" style="margin:0 0 10px">An app sending far more than it normally does in ${esc(beh?.windowMinutes ?? 15)} minutes can mean your files are being copied out.</p>
      ${spikes.length ? `<div class="list">${spikes.map((u) => `<div class="item"><span class="dot high"></span><div class="body"><div class="t">${esc(u.app)} sent ${bytes(u.out)}</div><div class="s">${Math.round(u.ratio)}× more than usual</div><div class="row-actions">${investigate(u.app)}</div></div></div>`).join('')}</div>` : `<div class="empty-inline">${icon('check')}No upload spikes. I’m still learning each app’s normal for the first week.</div>`}</div>
  </div>`;
}

// ---------- Processes ----------
state.procAgent ??= false;
state.procQ ??= '';
views.processes = async () => {
  const q = new URLSearchParams({ hours: '24', ...(state.procAgent ? { agent: '1' } : {}), ...(state.procQ ? { q: state.procQ } : {}) });
  const [d, ag] = await Promise.all([api(`/api/processes?${q}`), api('/api/processes?hours=24&agent=1')]);
  // Processes that exited before ps could read them show as "(name)" or "<defunct>".
  const items = d.items.filter((i) => !/^[(<]/.test(i.path) && !/^[(<]/.test(i.name));
  const hits = items.filter((i) => i.rule);
  const rules = d.rules?.rules ?? [];
  return `${statusBar('processes')}
  ${agentActivity(ag)}
  ${hits.length ? `<div class="mt"><div class="section-head"><p class="h2">Malware techniques seen</p></div><div class="list">${hits.slice(0, 20).map((i) => `<div class="item"><span class="dot high"></span><div class="body"><div class="t">${esc(rules.find((r) => r.id === i.rule)?.title ?? i.rule)}</div><div class="s mono wrap">${esc(clip(i.args, 220))}</div><div class="row-actions">${investigate(i.path)}${askBtn({ kind: 'process-rule-hit', rule: i.rule, program: i.name, path: i.path, command: i.args, parent: i.parent, agent: i.agent }, 'Explain')}<span class="tag">${esc(day(i.ts))}</span></div></div></div>`).join('')}</div></div>` : ''}
  <div class="toolbar mt">
    <label class="search">${icon('search')}<input class="input" id="proc-filter" placeholder="Filter by program or command" value="${esc(state.procQ)}" aria-label="Filter programs"></label>
    <div class="seg" role="group"><button class="${state.procAgent ? '' : 'on'}" data-act="proc-agent" data-v="0">Everything</button><button class="${state.procAgent ? 'on' : ''}" data-act="proc-agent" data-v="1">Started by AI agents</button></div>
    <span class="tiny faint right">Sampled every 2 seconds · last 24 hours</span>
  </div>
  <div class="tablewrap"><table class="table"><thead><tr><th>When</th><th>Program</th><th>Started by</th><th>Command</th><th class="num"><span class="sr">Actions</span></th></tr></thead><tbody>
    ${items.slice(0, 200).map((i) => `<tr><td class="small faint" style="white-space:nowrap">${esc(W.clock(i.ts))}</td><td><b>${esc(i.name)}</b>${i.rule ? ' <span class="chip bad">technique</span>' : ''}</td><td class="small">${esc(i.parent ?? '')}${i.agent ? ` <span class="chip agent">${esc(i.agent)}</span>` : ''}</td><td class="mono tiny muted cmd" title="${esc(i.args)}">${esc(clip(i.args, 140))}</td><td class="num">${investigate(i.path, '')}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">Nothing matches.</td></tr>'}
  </tbody></table></div>
  <details class="card fold mt"><summary>What I watch for (${rules.length} techniques used by Mac malware)</summary><div class="fold-body"><div class="list">${rules.map((r) => `<div class="item"><span class="dot ${r.tier === 'suspicious' ? 'high' : 'medium'}"></span><div class="body"><div class="t">${esc(r.title)}</div><div class="s">${esc(r.why)}</div></div></div>`).join('')}</div></div></details>`;
};

function agentActivity(d) {
  const agents = d.agents ?? [];
  if (!agents.length) return `<div class="card pad mt"><p class="h3" style="margin:0">What your AI agents ran</p><div class="empty-inline">${icon('check')}No AI agent started any program in the last 24 hours.</div></div>`;
  return `<div class="mt"><div class="section-head"><p class="h2">What your AI agents ran</p><span class="small faint">last 24 hours</span></div><div class="stack" style="gap:10px">${agents.map((a) => {
    const mine = d.items.filter((i) => i.agent === a.agent && !/^[(<]/.test(i.path) && !/^[(<]/.test(i.name));
    const tree = new Map();
    for (const i of mine) { const p = tree.get(i.parent ?? '?') ?? new Map(); p.set(i.name, (p.get(i.name) ?? 0) + 1); tree.set(i.parent ?? '?', p); }
    const parents = [...tree].sort((x, y) => sumMap(y[1]) - sumMap(x[1])).slice(0, 8);
    return `<div class="card pad"><div class="row between" style="gap:10px"><div><b>${esc(a.agent)}</b> <span class="muted">ran ${plural(a.n, 'program')} (${a.kinds} different) · last ${esc(ago(a.last))}</span></div>${askBtn({ kind: 'agent-activity', agent: a.agent, programs: [...new Set(mine.map((i) => i.name))].slice(0, 40) }, 'Audit with AI', `Audit what ${a.agent} ran on my Mac in the last 24 hours using process_history with agent_only. Is anything risky or unexpected?`)}</div>
      <div class="ptree"><div class="ptree-root">${icon('bot')}${esc(a.agent)}</div>${parents.map(([parent, kids]) => `<div class="ptree-branch"><div class="ptree-parent">${esc(parent)} <span class="faint">${sumMap(kids)}</span></div><div class="ptree-kids">${[...kids].sort((x, y) => y[1] - x[1]).slice(0, 14).map(([k, n]) => `<span class="chip">${esc(k)} <span class="faint">×${n}</span></span>`).join('')}${kids.size > 14 ? `<span class="faint small">+${kids.size - 14} more</span>` : ''}</div></div>`).join('')}</div></div>`;
  }).join('')}</div></div>`;
}
const sumMap = (m) => [...m.values()].reduce((a, b) => a + b, 0);

// ---------- Downloads & apps ----------
const NOTE = { notarized: ['#0ca30c', 'Notarized by Apple'], 'app-store': ['var(--s1)', 'Mac App Store'], apple: ['var(--s7)', 'Part of macOS'], 'developer-id': ['var(--node)', 'Identified developer only'], unknown: ['var(--other)', 'Could not check'], rejected: ['#d03b3b', 'Would be blocked'] };
views.downloads = async () => {
  const [dl, nz, od] = await Promise.all([api('/api/downloads'), api('/api/notarization'), api('/api/outdated')]);
  const counts = nz.counts ?? {};
  // Same as the warnings: browser web-app shortcuts, Hashling itself and uninstallers are not a concern.
  const rejected = (nz.apps ?? []).filter((a) => a.verdict === 'rejected' && !/\/(Chrome|Edge|Brave|Arc|Vivaldi|Chromium) Apps\.localized\//.test(a.path) && !/\/Hashling\.app$/.test(a.path) && !/^(Remove|Uninstall) /i.test(a.name));
  const apps = (od.apps ?? []);
  // Simple mode skips apps that are already gone, and the source column when macOS recorded none.
  const items = state.mode === 'simple' ? dl.items.filter((i) => i.exists !== false) : dl.items;
  const gone = dl.items.length - items.length;
  const showFrom = items.some((i) => i.from_url);
  return `${statusBar('downloads')}
  <div class="mt"><div class="section-head"><p class="h2">Recent arrivals</p><span class="small faint"><span title="${esc((dl.watch?.watching ?? []).map(home).join(', '))}">Watching your Downloads and Applications folders, and the places apps use to start automatically</span></span></div>
  <div class="tablewrap"><table class="table"><thead><tr><th>File</th>${showFrom ? '<th>Came from</th>' : ''}<th>Developer</th><th>Apple check</th><th>Malware</th><th class="num"><span class="sr">Actions</span></th></tr></thead><tbody>
    ${items.map((i) => { const rep = parse(i.rep); const intel = parse(i.intel); return `<tr><td><b class="wrap">${esc(i.name)}</b>${i.exists === false ? ' <span class="chip">removed</span>' : ''}<div class="sub">${esc(i.kind)} · ${esc(ago(i.ts))}${i.size ? ` · ${bytes(i.size)}` : ''}${i.times > 1 ? ` · updated ${i.times} times` : ''}</div></td>
      ${showFrom ? `<td class="small">${i.from_url ? esc(safeHost(i.from_url)) : '<span class="faint" title="macOS only records where a file came from when a browser or app tags it">Unknown</span>'}${intel ? ' <span class="chip bad">known malware host</span>' : ''}</td>` : ''}
      <td class="small">${['developer-id', 'apple', 'app-store'].includes(i.signer_kind) ? `<span class="muted">${esc(String(i.signer).replace(/\s*\([A-Z0-9]{10}\)$/, ''))}</span>` : `<span class="chip warn">${esc(i.signer ?? 'No developer signature')}</span>`}</td>
      <td class="small">${i.self ? '<span class="chip ok" title="Hashling’s own app, built on this Mac">This is Hashling</span>' : i.notarized ? `<span class="chip ${i.notarized === 'notarized' ? 'ok' : i.notarized === 'rejected' ? 'warn' : ''}">${esc(VERDICT[i.notarized]?.[1] ?? i.notarized)}</span>` : '<span class="faint">·</span>'}</td>
      <td class="small">${rep?.verdict === 'malicious' ? '<span class="chip bad">Known malware</span>' : i.scan?.detections?.length ? '<span class="chip bad">Malware found</span>' : i.scan?.status === 'done' ? '<span class="chip ok">Clean</span>' : i.scan?.status === 'running' || i.scan?.status === 'queued' ? '<span class="chip">Scanning…</span>' : i.scan ? '<span class="chip">Not finished</span>' : '<span class="faint">·</span>'}</td>
      <td class="num">${investigate(i.path, '')}</td></tr>`; }).join('') || '<tr><td colspan="${showFrom ? 6 : 5}" class="empty">Nothing new has arrived since I started watching. New downloads and apps show up here within seconds.</td></tr>'}
  </tbody></table></div>${gone ? `<p class="tiny faint" style="margin:6px 2px 0">${plural(gone, 'item')} that ${gone === 1 ? 'is' : 'are'} no longer on this Mac ${gone === 1 ? 'is' : 'are'} not shown.</p>` : ''}</div>
  <div class="card pad mt"><div class="row between" style="gap:10px"><div><p class="h3" style="margin:0">Apple’s verdict on your apps</p><p class="small muted" style="margin:2px 0 12px">I check every app the same way macOS does before it opens one. Apps that fail are often pirated, tampered with, or ones you built yourself.</p></div><span class="small faint">${plural((nz.apps ?? []).length, 'app')} · ${esc(ago(nz.at))}</span></div>
    ${partsBar(Object.entries(NOTE).map(([k, [color, label]]) => ({ label, color, v: counts[k] ?? 0 })))}
    ${rejected.length ? `<details class="fold" style="margin-top:12px"><summary>Apps Apple has not checked (${rejected.length})</summary><div class="fold-body"><div class="list">${rejected.map((a) => `<div class="item"><div class="body"><div class="t">${esc(a.name)}</div><div class="s mono">${esc(home(a.path))}</div><div class="row-actions">${investigate(a.path)}${askIcons({ kind: 'gatekeeper-rejected', app: a.name, path: a.path }, 'Why would Gatekeeper block this app, and should I keep it?')}</div></div></div>`).join('')}</div></div></details>` : ''}</div>
  <div class="card pad mt"><div class="row between" style="gap:10px"><div><p class="h3" style="margin:0">Outdated software</p><p class="small muted" style="margin:2px 0 0">Old versions with known security holes are the most common way in. ${apps.length ? `${plural(apps.length, 'program')} ${apps.length === 1 ? 'has an update' : 'have updates'}.` : ''}</p></div>${apps.length ? askBtn({ kind: 'outdated', items: apps.slice(0, 60).map((a) => `${a.name} ${a.installed} → ${a.latest}`) }, 'Which matter?', 'Which of these outdated apps and packages matter most for security, and how do I update them?') : ''}</div>
    ${!od.brew ? '<p class="small muted">Homebrew is not installed, so I check only App Store updates in System Settings.</p>' : apps.length ? `${state.mode === 'simple' ? `<details class="mt"><summary class="small">Show the list</summary>` : ''}<div class="outdated">${apps.slice(0, 40).map((a) => `<div title="${esc(`${a.name} ${a.installed} → ${a.latest}`)}"><span>${esc(a.name)}</span><span class="mono tiny faint">${esc(clip(String(a.installed).split(',')[0], 14))} → ${esc(clip(String(a.latest).split(',')[0], 14))}</span></div>`).join('')}</div>${apps.length > 40 ? `<p class="small faint" style="margin:8px 0 0">and ${apps.length - 40} more</p>` : ''}${state.mode === 'simple' ? '</details>' : ''}<p class="small muted" style="margin:10px 0 0">Update everything from Homebrew with <code>brew upgrade --greedy</code> in Terminal.</p>` : `<div class="empty-inline">${icon('check')}Everything installed with Homebrew is up to date.</div>`}</div>`;
};
const parse = (s) => { if (!s || typeof s !== 'string') return s ?? null; try { return JSON.parse(s); } catch { return null; } };

// ---------- Uploads ----------
state.upHours ??= 168;
/** App -> destination links for the flow chart: top apps, top destinations, the rest folded. */
function flowLinks(rows, aKey, bKey, vKey, maxA = 6, maxB = 9) {
  const sumBy = (k) => { const m = new Map(); for (const r of rows) m.set(r[k], (m.get(r[k]) ?? 0) + r[vKey]); return [...m].sort((x, y) => y[1] - x[1]); };
  const apps = sumBy(aKey).slice(0, maxA).map(([a]) => a);
  const inApps = rows.filter((r) => apps.includes(r[aKey]));
  const dests = new Set((() => { const m = new Map(); for (const r of inApps) m.set(r[bKey], (m.get(r[bKey]) ?? 0) + r[vKey]); return [...m].sort((x, y) => y[1] - x[1]).slice(0, maxB).map(([b]) => b); })());
  const merged = new Map();
  for (const r of inApps) { const k = `${r[aKey]}\u0000${dests.has(r[bKey]) ? r[bKey] : 'Everyone else'}`; merged.set(k, (merged.get(k) ?? 0) + r[vKey]); }
  return [...merged].map(([k, v]) => { const [a, b] = k.split('\u0000'); return { a, b, v }; })
    .sort((x, y) => apps.indexOf(x.a) - apps.indexOf(y.a) || (x.b === 'Everyone else') - (y.b === 'Everyone else') || y.v - x.v);
}

views.uploads = async () => {
  let u = await api(`/api/uploads?hours=${state.upHours}`);
  // With under a day of history, a 7-day chart is one sliver: start on 24 hours until the user picks.
  if (!state.upPicked && state.upHours !== 24 && u.historyStart && Date.now() - u.historyStart < 86_400_000) { state.upHours = 24; u = await api('/api/uploads?hours=24'); }
  const partial = u.historyStart && u.historyStart > u.since;
  const series = u.apps.map((a) => ({ name: a, color: colorOf(a), values: u.points.map((p) => p.apps[a] ?? 0) }));
  const has = series.some((x) => x.values.some((v) => v > 0));
  const per = u.bucketMs >= 6 * 3600_000 ? 'per 6 hours' : u.bucketMs >= 3 * 3600_000 ? 'per 3 hours' : 'per hour';
  // Servers whose owner is not known yet are grouped instead of listed as raw addresses.
  const links = flowLinks(u.dests.filter((d) => d.bytes >= 50 * 1024).map((d) => (/^[\d.]+$|^[0-9a-f:]+$/i.test(d.dest) && /[.:]/.test(d.dest) ? { ...d, dest: 'Not identified yet' } : d)), 'app', 'dest', 'bytes', 6, 7);
  const nodes = Math.max(new Set(links.map((l) => l.a)).size, new Set(links.map((l) => l.b)).size);
  const filesByApp = new Map();
  for (const f of u.files) filesByApp.set(f.app, [...(filesByApp.get(f.app) ?? []), f]);
  const range = u.hours >= 168 ? 'the last 7 days' : u.hours >= 72 ? 'the last 3 days' : 'the last 24 hours';
  const ctx = { kind: 'uploads', range, totalSent: bytes(u.total), topApps: u.byApp.slice(0, 8).map((a) => `${a.app} ${bytes(a.bytes)}`), topDestinations: u.dests.slice(0, 10).map((d) => `${d.app} → ${d.dest} ${bytes(d.bytes)}`), commands: u.commands.slice(0, 10).map((c) => `${c.tool} ${c.files.join(' ')} → ${c.dest ?? '?'}${c.agent ? ` (by ${c.agent})` : ''}`), filesOpenWhileSending: u.files.slice(0, 15).map((f) => `${f.app}: ${home(f.file)}`) };
  return `<div class="explain"><p class="label">What I can see</p><p>${esc(u.limitation)}${partial ? ` I started recording ${esc(ago(u.historyStart))}, so earlier uploads are not included.` : ''}</p></div>
  <div class="figures mt">
    <div class="metric"><b>${bytes(u.total)}</b><span>sent in ${range}</span></div>
    <div class="metric"><b>${u.byApp.length}</b><span>apps sent data</span></div>
    <div class="metric"><b>${new Set(u.dests.map((d) => d.dest)).size}</b><span>places it went</span></div>
    <div class="metric"><b>${u.commands.length}</b><span>upload commands</span></div>
  </div>
  <div class="card pad mt"><div class="row between" style="gap:10px"><div><p class="h3" style="margin:0">Sent over time</p><p class="small muted" style="margin:2px 0 0">Data each app sent, ${per}</p></div>
    <div class="row" style="gap:8px">${askBtn(ctx, 'What did I upload?', `Using uploads_report for ${range}, tell me in plain English what left my Mac: which apps sent the most, to whom, which files were involved, and whether anything looks unusual or unexpected.`)}
    <div class="seg" role="group" aria-label="Time range">${[[24, '24 h'], [72, '3 days'], [168, '7 days']].map(([h, l]) => `<button class="${state.upHours === h ? 'on' : ''}" data-act="up-range" data-v="${h}">${l}</button>`).join('')}</div></div></div>
    ${has ? `<div class="legend" style="margin:12px 0 4px">${series.map((x) => { const t = u.byApp.find((a) => a.app === x.name); return `<span><i style="background:${x.color}"></i>${esc(x.name)}${t ? ` <b>${bytes(t.bytes)}</b>` : ''}</span>`; }).join('')}</div>
      ${chart('series', { t: u.points.map((p) => p.t), series, stacked: true, fmt: bytes }, 220, `Data sent by app over ${range}`)}
      <details class="fold" style="margin-top:8px"><summary>Every app (${u.byApp.length})</summary><div class="fold-body">${bars(u.byApp.map((a) => ({ label: a.app, v: a.bytes, color: colorOf(a.app) === OTHER ? 'var(--node)' : colorOf(a.app) })))}</div></details>`
      : '<div class="empty" style="padding:28px">Nothing sent yet in this range.</div>'}</div>
  ${links.length ? `<div class="card pad mt"><p class="h3" style="margin:0">Where it went</p><p class="small muted" style="margin:2px 0 12px">How much each app sent to each company’s servers. Hover a band for the amount.</p>
    ${chart('flow', { links, fmt: bytes, unit: 'sent' }, Math.max(200, nodes * 34), `Data sent from apps to destinations over ${range}`)}
    <details class="fold" style="margin-top:10px"><summary>All destinations (${u.dests.length})</summary><div class="fold-body"><div class="tablewrap flat"><table class="table"><thead><tr><th>App</th><th>Sent to</th><th class="num">Amount</th><th>Last</th></tr></thead><tbody>${u.dests.map((d) => `<tr><td>${esc(d.app)}</td><td>${esc(d.dest)}${d.host && d.host !== d.dest ? `<div class="sub">${esc(d.host)}</div>` : ''}${d.country ? ` <span class="faint small">${esc(d.country)}</span>` : ''}</td><td class="num">${bytes(d.bytes)}</td><td class="small faint">${esc(ago(d.last))}</td></tr>`).join('')}</tbody></table></div></div></details></div>` : ''}
  <div class="grid g2 mt" style="align-items:start">
    <div class="card pad"><p class="h3" style="margin:0 0 4px">Files sent by commands</p><p class="small muted" style="margin:0 0 10px">Uploads run with curl, scp, rsync, cloud tools or git name their files, so these are certain. Includes commands your AI agents ran.</p>
      ${u.commands.length ? `<div class="list">${groupCommands(u.commands).map(({ c, n, first }) => `<div class="item"><span class="dot ${c.agent ? 'medium' : 'low'}"></span><div class="body"><div class="t">${esc(c.tool)} → ${esc(c.dest ?? 'unknown')}${c.agent ? ` <span class="chip agent">${esc(c.agent)}</span>` : ''}</div><div class="s">${c.files.length ? `<span class="mono wrap">${c.files.map((f) => esc(home(f))).join('<br>')}</span>` : 'Code changes from the project it was run in'}</div><div class="row-actions">${askBtn({ kind: 'upload-command', tool: c.tool, files: c.files, dest: c.dest, agent: c.agent, startedBy: c.parent, command: c.args, times: n }, 'Explain', 'What did this command upload, where to, and is that expected?')}<span class="tag">${n > 1 ? `${n} times · ${esc(day(first))} to ${esc(day(c.ts))}` : esc(day(c.ts))}</span></div></div></div>`).join('')}</div>` : `<div class="empty-inline">${icon('check')}No upload commands seen in ${range}.</div>`}</div>
    <div class="card pad"><p class="h3" style="margin:0 0 4px">Files open while sending</p><p class="small muted" style="margin:0 0 10px">When an app sends more than ${bytes(256 * 1024)} a second, I note which of your files it has open. Likely what it uploaded, not certain.</p>
      ${filesByApp.size ? [...filesByApp].map(([app, fs]) => `<div class="upf"><div class="row between" style="gap:8px"><b>${esc(app)}</b><span class="small faint">${plural(fs.length, 'file')}</span></div><div class="dest-list">${fs.slice(0, 12).map((f) => `<div><span class="mono small">${esc(home(f.file))}</span><span class="faint small">${f.size ? `${bytes(f.size)} · ` : ''}${esc(ago(f.last))}</span></div>`).join('')}</div>${fs.length > 12 ? `<p class="small faint" style="margin:6px 0 0">and ${fs.length - 12} more</p>` : ''}</div>`).join('') : `<div class="empty-inline">${icon('check')}No app had your files open during a big upload in ${range}.</div>`}</div>
  </div>`;
};

/** Same command, same place, same files: one row with a count instead of a wall of repeats. */
function groupCommands(list) {
  const groups = new Map();
  for (const c of list) {
    const k = [c.tool, c.dest, c.agent, ...c.files].join('\u0000');
    const g = groups.get(k);
    if (g) { g.n++; g.first = Math.min(g.first, c.ts); if (c.ts > g.c.ts) g.c = c; } else groups.set(k, { c, n: 1, first: c.ts });
  }
  return [...groups.values()].sort((a, b) => b.c.ts - a.c.ts);
}

// ---------- Keys & secrets ----------
views.secrets = async () => {
  const s = await api('/api/secrets');
  const files = s.files ?? [];
  return `${statusBar('secrets')}
  <div class="explain mt"><p class="label">How this works</p><p>Info-stealers grab saved keys first: shell history, config files, cloud logins. I look for the patterns open-source scanners like gitleaks use, in the places stealers read. It only counts what it finds and never copies a value.</p></div>
  <div class="mt"><div class="section-head"><p class="h2">Credential files on this Mac</p></div>
  <div class="tablewrap"><table class="table"><thead><tr><th>File</th><th>What is in it</th><th>Who can read it</th><th class="num"><span class="sr">Actions</span></th></tr></thead><tbody>
    ${files.map((f) => `<tr><td><b>${esc(f.label)}</b><div class="sub mono">${esc(f.path)}</div></td><td class="small">${Object.keys(f.kinds ?? {}).length ? Object.entries(f.kinds).map(([k, n]) => `<span class="chip">${esc(k)} ×${n}</span>`).join(' ') : f.expected ? '<span class="muted">Logins kept by the tool that owns it</span>' : '<span class="faint">·</span>'}</td>
      <td class="small">${f.worldReadable ? '<span class="chip warn">Every user and app</span>' : '<span class="muted">Only you</span>'}</td>
      <td class="num">${askIcons({ kind: 'credential-file', file: f.path, label: f.label, kinds: f.kinds, worldReadable: f.worldReadable }, 'Is this file a risk, and how do I protect it?')}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">No credential files found.</td></tr>'}
  </tbody></table></div></div>`;
};

// ---------- Storage & speed ----------
const GB = 1024 ** 3;
views.optimize = async () => {
  const s = await api('/api/storage');
  // While a measurement runs, show which step it is on and check back every few seconds.
  clearTimeout(state.storageTimer);
  if (s.progress) state.storageTimer = setTimeout(() => { if (state.view === 'optimize') W.render(); }, 4000);
  const progressCard = s.progress ? `<section class="card pad measuring" aria-live="polite"><div class="row between" style="gap:10px"><b>Measuring your disk: step ${s.progress.step} of ${s.progress.total}</b><span class="small faint">started ${esc(ago(s.progress.startedAt))}</span></div>
    <div class="measure-bar" role="progressbar" aria-valuemin="0" aria-valuemax="${s.progress.total}" aria-valuenow="${s.progress.step}"><span style="width:${Math.round(((s.progress.step - 0.5) / s.progress.total) * 100)}%"></span></div>
    <p class="small muted" style="margin:8px 0 0">${esc(s.progress.label)}… This usually takes a few minutes on a full disk. You can leave this page; it keeps going.</p></section>` : '';
  if (s.pending && progressCard) return progressCard;
  if (s.pending) return `<div class="card empty-state">${icon('gauge', 'lg')}<p class="h2">Measuring your disk</p><p class="muted">I measure storage a few minutes after I start, then every 6 hours. It takes a minute or two.</p><button class="btn" data-act="run" data-v="storage">Measure now</button></div>`;
  state.storage = s;
  const { disk } = s;
  // Older measurements used the bare folder name.
  const known = s.folders.filter((f) => f.size).map((f) => (f.label === 'Library' ? { ...f, label: 'App data (Library folder)' } : f)).sort((a, b) => b.size - a.size);
  const knownSum = known.reduce((n, f) => n + f.size, 0);
  const cleanupCtx = { kind: 'storage', free: bytes(disk.free), total: bytes(disk.total), reclaimable: bytes(s.reclaimable), junk: s.junk.map((j) => `${j.label} ${bytes(j.size)}`), unusedApps: s.unused.slice(0, 15).map((a) => `${a.name} ${bytes(a.size)} idle ${a.idleDays}d`), duplicates: s.duplicates.length, leftovers: s.leftovers.length };
  const cachesTotal = s.caches.reduce((n, c) => n + c.size, 0);
  const unusedTotal = s.unused.reduce((n, a) => n + a.size, 0);
  const leftTotal = s.leftovers.reduce((n, l) => n + l.size, 0);
  const dupTotal = s.duplicates.reduce((n, d) => n + d.size * (d.files.length - 1), 0);
  return `${statusBar('optimize')}${progressCard ? `<div style="margin-bottom:16px">${progressCard}</div>` : ''}
  <section class="card pad opt-hero">
    <div><p class="label" style="margin:0">Disk</p><p class="opt-big"><b>${bytes(disk.free)}</b> free of ${bytes(disk.total)}</p>
      ${partsBar([...known.slice(0, 6).map((f, i) => ({ label: f.label, v: f.size, color: SERIES[i] })), { label: 'System & other', v: Math.max(0, disk.used - knownSum), color: 'var(--node)' }, { label: 'Free', v: disk.free, color: 'var(--line-2)' }], bytes)}</div>
    <div class="opt-side"><div class="metric" style="padding:0"><b>${bytes(s.reclaimable)}</b><span>can be cleared safely</span></div>
      <button class="btn blue" data-act="ask" data-ctx="${attr(cleanupCtx)}" data-prompt="Make me a cleanup plan for this Mac. Use storage_report, rank by space saved, start with what is safest, never include documents or photos, and propose each step as an action I can approve with Touch ID.">${icon('spark')}AI cleanup plan</button>
      <span class="tiny faint">Measured ${esc(ago(s.at))}, took ${s.tookMs < 90_000 ? `${Math.max(1, Math.round(s.tookMs / 1000))} seconds` : `about ${Math.round(s.tookMs / 60_000)} minutes`} · <button class="linkish" data-act="run" data-v="storage">measure again</button></span></div>
  </section>

  <div class="grid g2 mt" style="align-items:stretch">
    <div class="card pad"><p class="h3" style="margin:0 0 12px">Where your space went</p>${bars(known.map((f) => ({ label: f.label, v: f.size })))}</div>
    <div class="card pad adv"><p class="h3" style="margin:0 0 4px">Using the most memory now</p><p class="small muted" style="margin:0 0 10px">Each app counted as a whole, including its helper parts.</p>${bars(s.heavy.slice(0, 10).map((h) => ({ label: h.name, v: h.mem })), { color: SERIES[6] })}</div>
  </div>

  <div class="card pad mt"><p class="h3" style="margin:0 0 4px">Safe to clear</p><p class="small muted" style="margin:0 0 10px">Caches and build files that rebuild themselves when needed.</p>
      ${s.junk.length ? `<div class="list cols2">${s.junk.map((j) => `<div class="item"><div class="body"><div class="t">${esc(j.label)} <span class="faint">${bytes(j.size)}</span></div><div class="s">${ticks(j.why)}</div></div><button class="btn sm" data-act="propose" data-a="${attr(j.how === 'trash' ? { type: 'trash_paths', target: { paths: [j.path], bytes: j.size, label: j.label }, reason: `Free ${bytes(j.size)}: ${j.label}. ${j.why}` } : { type: 'run_cleanup', target: { id: j.how }, reason: `Free up to ${bytes(j.size)}: ${j.label}. ${j.why}` })}">Clear…</button></div>`).join('')}</div>` : `<div class="empty-inline">${icon('check')}No developer caches worth clearing.</div>`}
      ${s.caches.length ? `<details class="fold" style="margin-top:10px"><summary>App caches · ${bytes(cachesTotal)}</summary><div class="fold-body">${bars(s.caches.slice(0, 12).map((c) => ({ label: c.app, v: c.size })), { color: SERIES[2] })}<div class="row" style="margin-top:10px"><button class="btn sm" data-act="propose" data-a="${attr({ type: 'trash_paths', target: { paths: s.caches.map((c) => c.path), bytes: cachesTotal, label: 'app caches' }, reason: `Free ${bytes(cachesTotal)} of app caches. Apps rebuild what they need.` })}">Clear all app caches…</button></div></div></details>` : ''}</div>


  <div class="mt"><div class="section-head"><p class="h2">Apps you don’t use</p><span class="small faint">${s.unused.length ? `${plural(s.unused.length, 'app')} · ${bytes(unusedTotal)}` : ''}</span></div>
    ${s.unused.length ? `<div class="tablewrap"><table class="table"><thead><tr><th>App</th><th>Last opened</th><th class="num">Size</th><th class="num"><span class="sr">Actions</span></th></tr></thead><tbody>${s.unused.map((a) => `<tr><td><b>${esc(a.name)}</b>${a.extraCopy ? ' <span class="chip warn">extra copy</span>' : ''}<div class="sub mono">${esc(home(a.path))}</div></td><td class="small">${a.neverOpened ? `<span class="chip warn">Never opened</span> <span class="faint">installed ${a.idleDays} days ago</span>` : `${a.idleDays} days ago`}</td><td class="num">${bytes(a.size)}</td><td class="num"><div class="row" style="gap:6px;justify-content:flex-end;flex-wrap:nowrap">${investigate(a.path, '')}${a.uninstaller ? `<button class="btn xs" data-act="open-uninstaller" data-v="${esc(a.path)}" title="${esc(a.name)} comes with its own uninstaller, which also removes its plug-ins and helpers">Uninstall… ${icon('ext')}</button>` : `<button class="btn xs" data-act="propose" data-a="${attr({ type: 'trash_paths', target: { paths: [a.path], bytes: a.size, label: a.name }, reason: `Move ${a.extraCopy ? `this extra copy of ${a.name}` : a.name} to the Trash: ${a.neverOpened ? 'never opened' : `not opened in ${a.idleDays} days`}, ${bytes(a.size)}.` })}">Trash…</button>`}</div></td></tr>`).join('')}</tbody></table></div>
      <p class="small muted" style="margin:8px 0 0">Going by when macOS last saw each app opened. Moving to the Trash keeps “Put Back” working. Some apps leave support files behind; they will show up under leftovers after the next measurement.</p>` : `<div class="empty-inline">${icon('check')}Every app over 50 MB was opened in the last 3 months.</div>`}</div>

  <div class="grid g2 mt" style="align-items:start">
    <div class="card pad"><div class="row between"><p class="h3" style="margin:0">Duplicate files</p><span class="small faint">${dupTotal ? `${bytes(dupTotal)} extra` : ''}</span></div><p class="small muted" style="margin:2px 0 10px">Exact copies (5 MB+) in Downloads, Desktop, Documents, Movies and Music, confirmed byte for byte.</p>
      ${s.duplicates.length ? `<div class="list">${s.duplicates.slice(0, 12).map((g) => { const keep = [...g.files].sort((a, b) => (a.includes('/Downloads/') - b.includes('/Downloads/')) || a.length - b.length)[0]; const extra = g.files.filter((f) => f !== keep); return `<div class="item"><div class="body"><div class="t wrap">${esc(g.files[0].split('/').pop())} <span class="faint">${g.files.length} copies · ${bytes(g.size)} each</span></div><div class="s mono wrap">${g.files.map((f) => `${f === keep ? '✓ keep ' : ''}${esc(home(f))}`).join('<br>')}</div></div><button class="btn xs" data-act="propose" data-a="${attr({ type: 'trash_paths', target: { paths: extra, bytes: g.size * extra.length, label: `copies of ${g.files[0].split('/').pop()}` }, reason: `Remove ${plural(extra.length, 'duplicate')} of ${g.files[0].split('/').pop()} (${bytes(g.size * extra.length)}). Keeping ${home(keep)}.` })}">Trash ${extra.length}…</button></div>`; }).join('')}</div>` : `<div class="empty-inline">${icon('check')}No duplicate files found.</div>`}</div>
    <div class="card pad"><div class="row between"><p class="h3" style="margin:0">Leftovers from deleted apps</p><span class="small faint">${leftTotal ? bytes(leftTotal) : ''}</span></div><p class="small muted" style="margin:2px 0 10px">Support folders named after apps that are no longer installed, matched by the app’s ID, the way the open-source Pearcleaner does.</p>
      ${s.leftovers.length ? `${bars(s.leftovers.slice(0, 10).map((l) => ({ label: `${l.id} (${l.where})`, v: l.size })), { color: SERIES[1] })}<div class="row" style="margin-top:10px"><button class="btn sm" data-act="propose" data-a="${attr({ type: 'trash_paths', target: { paths: s.leftovers.map((l) => l.path), bytes: leftTotal, label: 'leftovers from deleted apps' }, reason: `Remove ${plural(s.leftovers.length, 'leftover folder')} from apps that are no longer installed (${bytes(leftTotal)}).` })}">Trash all leftovers…</button></div>` : `<div class="empty-inline">${icon('check')}No leftovers found.</div>`}</div>

  <div class="card pad mt adv"><p class="h3" style="margin:0 0 4px">What starts with your Mac</p><p class="small muted" style="margin:0 0 10px">Background helpers that launch at login, with what they use right now.</p>
      ${s.startup.length ? `<div class="tablewrap flat"><table class="table"><thead><tr><th>Item</th><th class="num">Memory</th><th class="num">CPU</th><th class="num"><span class="sr">Actions</span></th></tr></thead><tbody>${s.startup.slice(0, 15).map((i) => `<tr><td><b class="wrap">${esc(W.friendlyName?.(i) ?? i.label)}</b><div class="sub">${i.running ? 'Running' : 'Not running now'} · ${esc(String(i.signer ?? '').replace(/^Ad-hoc signed \(no developer identity\)$/, 'No verified developer'))}</div></td><td class="num">${i.mem ? bytes(i.mem) : '·'}</td><td class="num">${i.cpu ? `${i.cpu.toFixed(1)}%` : '·'}</td><td class="num">${i.plist && !i.plist.startsWith('/System') ? `<button class="btn xs" data-act="propose" data-a="${attr({ type: 'disable_persistence', target: { plist: i.plist, label: i.label }, reason: `Stop ${i.label} from starting with your Mac${i.mem ? ` (uses ${bytes(i.mem)} of memory)` : ''}.` })}">Disable…</button>` : ''}</td></tr>`).join('')}</tbody></table></div>` : `<div class="empty-inline">${icon('check')}Nothing extra starts with your Mac.</div>`}</div>

  ${s.largeFiles.length ? `<details class="card fold mt"><summary>Files over 1 GB (${s.largeFiles.length})</summary><div class="fold-body"><div class="list">${s.largeFiles.map((f) => `<div class="item"><div class="body"><div class="t mono small wrap">${esc(home(f.path))}</div><div class="s">${bytes(f.size)} · changed ${esc(ago(f.modified))}</div></div><button class="btn xs" data-act="propose" data-a="${attr({ type: 'trash_paths', target: { paths: [f.path], bytes: f.size, label: f.path.split('/').pop() }, reason: `Move ${home(f.path)} (${bytes(f.size)}) to the Trash.` })}">Trash…</button></div>`).join('')}</div></div></details>` : ''}

  <details class="card fold mt adv"><summary>How I decide what is safe to remove</summary><div class="fold-body small">
    <p>I follow the rules of well-known open-source cleaners instead of guessing:</p>
    <ul><li><b>Caches</b> come from a fixed list of folders that rebuild themselves (the approach of Mole). Tools with their own cleanup command, like <code>brew cleanup</code> and <code>npm cache clean</code>, are run instead of deleting files.</li>
    <li><b>Leftovers</b> are found by the app’s ID: a support folder only counts if no installed app has that ID (the approach of Pearcleaner). Apple’s own folders are never touched.</li>
    <li><b>Duplicates</b> are matched in stages, size, then the first megabyte, then the whole file (the approach of czkawka), so only true copies count.</li>
    <li>Nothing is deleted. Files go to the Trash with “Put Back”, and every step waits for your Touch ID in Approvals.</li></ul></div></details>`;
};

// ---------- events ----------
document.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  try {
    if (act === 'dossier') { ev.stopPropagation(); await openDossier(el.dataset.q); }
    else if (act === 'story') openStory(Number(el.dataset.i));
    else if (act === 'traffic-range') { state.trafficHours = Number(el.dataset.v); W.render(); }
    else if (act === 'proc-agent') { state.procAgent = el.dataset.v === '1'; W.render(); }
    else if (act === 'up-range') { state.upHours = Number(el.dataset.v); state.upPicked = true; W.render(); }
  } catch (e) { if (e.message !== 'unauthorized') toast(e.message); }
}, true);
document.addEventListener('input', (e) => {
  if (e.target.id === 'proc-filter') { state.procQ = e.target.value; clearTimeout(state.pt); state.pt = setTimeout(() => W.render(true), 300); }
});

// ---------- Privacy: websites that can send you notifications ----------
const basePermissions = views.permissions;
views.permissions = async () => {
  const [html, wn] = await Promise.all([basePermissions(), api('/api/webnotify').catch(() => null)]);
  const sites = wn?.sites ?? [];
  const byBrowser = Object.entries(sites.reduce((m, s) => ((m[s.browser] ??= []).push(s), m), {}));
  return `${html}
  <div class="mt"><div class="section-head"><p class="h2">Websites that can send you notifications</p><span class="small faint">${sites.length ? plural(sites.length, 'website') : ''}</span></div>
    ${sites.length ? `<div class="grid ${byBrowser.length > 1 ? 'g2' : ''}" style="align-items:start">${byBrowser.map(([b, list]) => `<div class="card"><div class="pad-sm row between" style="border-bottom:1px solid var(--line)"><p class="h3">${esc(b)}</p>${b === 'Safari' ? '<span class="small faint">Safari &gt; Settings &gt; Websites &gt; Notifications</span>' : `<button class="btn xs" data-act="browser-notif" data-v="${esc(b)}">Remove in ${esc(b)} ${icon('ext')}</button>`}</div>
      <div class="list ${byBrowser.length === 1 && list.length > 4 ? 'cols2' : ''}">${list.sort((x, y) => Number(y.spammy) - Number(x.spammy)).map((s) => `<div class="item"><span class="dot ${s.spammy ? 'high' : ''}" style="margin-top:7px"></span><div class="body"><div class="t">${esc(s.site)}</div><div class="s">${s.spammy ? 'Looks like a notification-spam site. Remove it.' : 'Can pop up alerts on your screen.'}</div></div></div>`).join('')}</div></div>`).join('')}</div>`
      : `<div class="empty-inline">${icon('check')}${wn ? 'No website can send you notifications.' : 'Not checked yet.'}</div>`}
    <p class="small muted" style="margin:10px 0 0">A real virus warning never comes from a website notification. If one says your Mac is infected, it is a scam.</p></div>`;
};
document.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-act="browser-notif"]');
  if (!el) return;
  await api(`/api/open-browser-notifications/${encodeURIComponent(el.dataset.v)}`, { method: 'POST' }).catch((e) => W.toast(e.message));
  W.toast(`Opened ${el.dataset.v}’s notification settings. Remove sites you do not want.`);
});

// ---------- Privacy: who used your camera, microphone and screen ----------
const SENSOR = { cam: ['Camera', 'bad'], mic: ['Microphone', 'warn'], scr: ['Screen recording', 'warn'], aud: ['System audio', ''], loc: ['Location', ''] };
const withSensors = views.permissions;
views.permissions = async () => {
  const [html, s] = await Promise.all([withSensors(), api('/api/sensors').catch(() => null)]);
  const list = (s?.sessions ?? []).filter((x) => x.kind !== 'loc').slice(0, 40);
  const mins = (x) => x.end ? Math.max(1, Math.round((x.end - x.start) / 60_000)) : null;
  const when = (t) => new Date(t).toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' });
  return `${html}
  <div class="mt"><div class="section-head"><p class="h2">Who used your camera, microphone and screen</p><span class="small faint">last 7 days</span></div>
    ${list.length ? `<div class="card"><div class="list ${list.length > 6 ? 'cols2' : ''}">${list.map((x) => `<div class="item"><span class="dot ${x.end ? '' : 'on'}" style="margin-top:7px" title="${x.end ? 'Finished' : 'In use now'}"></span><div class="body"><div class="t row" style="gap:8px"><span>${esc(x.name)}</span><span class="chip ${SENSOR[x.kind]?.[1] ?? ''}">${esc(SENSOR[x.kind]?.[0] ?? x.kind)}</span></div><div class="s">${esc(when(x.start))}${x.end ? `, for ${mins(x)} min` : ', in use now'}</div></div></div>`).join('')}</div></div>`
      : `<div class="empty-inline">${icon('check')}${s ? 'Nothing used your camera, microphone or screen recording in the last 7 days.' : 'Not checked yet.'}</div>`}
    <p class="small muted" style="margin:10px 0 0">This is the same information as the orange and green dots at the top of your screen, kept for a week. If you see an app you do not recognise, take its permission away above.</p></div>`;
};

/** Insert extra cards right under a page's own status bar (the first status block), not above it. */
function afterStatus(html, extra) {
  const start = html.indexOf('<div class="status');
  if (start < 0) return extra + html;
  let depth = 0, i = start;
  const re = /<\/?div\b/g;
  re.lastIndex = start;
  for (let m; (m = re.exec(html)); ) { depth += m[0] === '<div' ? 1 : -1; if (depth === 0) { i = html.indexOf('>', m.index) + 1; break; } }
  return html.slice(0, i) + extra + html.slice(i);
}

// ---------- Safe browsing (filtering DNS) on the Internet page ----------
const withSafeDns = views.network;
views.network = async () => {
  const [html, d, v] = await Promise.all([withSafeDns(), api('/api/safe-dns').catch(() => null), api('/api/visits').catch(() => null)]);
  if (!d) return html;
  const checkedSites = Object.values(v?.checked ?? {}).reduce((n, x) => n + x, 0);
  const visitsLine = checkedSites ? `<p class="small muted" style="margin:10px 2px 0">${icon('check')} I checked the ${checkedSites.toLocaleString()} websites you visited this week against lists of known scam and malware sites${v.visits?.length ? `: ${v.visits.length} matched, see the warnings above.` : '. None matched.'}</p>` : '';
  const custom = d.services.flatMap((s) => s.servers).filter((x) => !['9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'].includes(x));
  const card = d.on
    ? `<div class="status mt"><div class="ico">${icon('shieldok', 'lg')}</div><div><b>Safe browsing is on</b><span class="sub">Known scam, phishing and malware websites will not open, in any browser or app. Provided free by Quad9, a non-profit.</span></div><div class="actions"><button class="btn sm ghost" data-act="propose" data-a="${attr({ type: 'safe_dns', target: { on: false }, reason: 'Turn off safe browsing and go back to your network’s normal settings' })}">Turn off</button></div></div>`
    : `<div class="status calm mt"><div class="ico">${icon('shield', 'lg')}</div><div><b>Turn on safe browsing</b><span class="sub">Blocks known scam, phishing and malware websites before they open, in every browser and app. Free, from Quad9, a non-profit that does not keep your personal data.${custom.length ? ` This replaces your current setting (${esc(custom.join(', '))}); turning it off puts it back.` : ''}</span></div><div class="actions"><button class="btn primary sm" data-act="propose" data-a="${attr({ type: 'safe_dns', target: { on: true }, reason: 'Turn on safe browsing: block known scam and malware websites on this Mac' })}">Turn on</button></div></div>`;
  return afterStatus(html, card + visitsLine);
};

// ---------- Malware: weekly full scan ----------
const withFullScan = views.scans;
views.scans = async () => {
  const [html, f, prefs] = await Promise.all([withFullScan(), api('/api/snapshot-full-scan').catch(() => null), api('/api/prefs').catch(() => ({}))]);
  const last = f?.at;
  const auto = Boolean(prefs.autoQuarantine);
  const autoCard = `<div class="status ${auto ? '' : 'calm'}" style="margin:0"><div class="ico">${icon(auto ? 'shieldok' : 'shield', 'lg')}</div><div><b>Lock away malware automatically: ${auto ? 'on' : 'off'}</b><span class="sub">${auto ? 'When a scan finds a file that matches known malware, I move it to Quarantine straight away. You can restore it from Approvals if it was a mistake.' : 'Like antivirus apps, I can move files that match known malware to Quarantine straight away, without waiting for you. Off by default, so nothing happens without you.'}</span></div><div class="actions"><button class="btn sm ${auto ? 'ghost' : 'primary'}" data-act="auto-quarantine" data-v="${auto ? '0' : '1'}">${auto ? 'Turn off' : 'Turn on'}</button></div></div>`;
  const card = `<div class="status calm" style="margin:0"><div class="ico">${icon('shield', 'lg')}</div><div><b>Full scan</b><span class="sub">Checks your apps, their support files, startup folders and your Desktop, Documents and Downloads. I run it once a week on my own, only while the Mac is plugged in and you are away. ${last ? `Last run ${esc(ago(last))}.` : 'Not run yet.'}</span></div><div class="actions"><button class="btn sm" data-act="full-scan">Run a full scan now</button></div></div>`;
  return afterStatus(html, `<div class="grid g2 mt" style="align-items:stretch">${card}${autoCard}</div>`);
};
document.addEventListener('click', async (ev) => {
  const t = ev.target.closest('[data-act="auto-quarantine"]');
  if (!t) return;
  await api('/api/prefs', { method: 'POST', body: { autoQuarantine: t.dataset.v === '1' } });
  toast(t.dataset.v === '1' ? 'On. Malware I find will be locked away straight away.' : 'Off. I’ll ask you first.');
  W.render();
});
document.addEventListener('click', async (ev) => {
  if (!ev.target.closest('[data-act="full-scan"]')) return;
  try { await api('/api/scans/full', { method: 'POST' }); toast('Full scan started. It can take an hour; you can keep using your Mac.'); W.render(); } catch (e) { toast(e.message); }
});
