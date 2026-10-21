// Hashling dashboard. Vanilla JS, no build step. Everything comes from the local Hashling API.
const $ = (s, el = document) => el.querySelector(s);
const page = $('#main');
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const attr = (o) => esc(JSON.stringify(o));
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CAT = { network: 'Network', posture: 'System', persistence: 'Startup items', permissions: 'Permissions', location: 'Location', trackers: 'Tracking', malware: 'Malware', 'malware-artifacts': 'Malware', agents: 'AI agents' };

// ---------- icons ----------
const P = {
  home: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V20h14V9.5"/><path d="M10 20v-6h4v6"/>',
  spark: '<path d="M12 3l1.8 4.7L18.5 9.5l-4.7 1.8L12 16l-1.8-4.7L5.5 9.5l4.7-1.8z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>',
  bot: '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 8V4"/><circle cx="12" cy="3.5" r="1"/><path d="M9 13v1.5M15 13v1.5"/><path d="M2 13v3M22 13v3"/>',
  bug: '<path d="M8 8a4 4 0 0 1 8 0v1H8z"/><rect x="6" y="9" width="12" height="11" rx="6"/><path d="M12 13v7"/><path d="M3 13h3M18 13h3M4 7l3 2M20 7l-3 2M4 19l3-2M20 19l-3-2"/>',
  power: '<path d="M12 3v8"/><path d="M6.3 6.3a8 8 0 1 0 11.4 0"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9"/><path d="m17 6 3 3"/><path d="m15 8 2 2"/>',
  radar: '<path d="M12 12 19 5"/><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  sliders: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  alert: '<path d="M12 3 2 20h20L12 3z"/><path d="M12 10v4M12 17h.01"/>',
  check: '<path d="m5 12 4.5 4.5L19 7"/>',
  shield: '<path d="M12 2.8 4.5 5.8v5.6c0 4.7 3.2 8.2 7.5 9.8 4.3-1.6 7.5-5.1 7.5-9.8V5.8L12 2.8Z"/>',
  hash: '<path d="M5 9h14M4 15h14M10 3 8 21M16 3l-2 18"/>',
  shieldok: '<path d="M12 2.8 4.5 5.8v5.6c0 4.7 3.2 8.2 7.5 9.8 4.3-1.6 7.5-5.1 7.5-9.8V5.8L12 2.8Z"/><path d="m8.8 12 2.2 2.2 4.2-4.4"/>',
  inbox: '<path d="M3 13h5l1.5 3h5L16 13h5"/><path d="M5 5h14l2 8v6H3v-6z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  expand: '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>',
  chev: '<path d="m9 6 6 6-6 6"/>',
  send: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  ext: '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  eyeoff: '<path d="M3 3l18 18"/><path d="M10.6 5.1A10 10 0 0 1 12 5c5 0 9 4.5 10 7-.4 1-1.2 2.4-2.4 3.6M6.6 6.6C4.6 8 3.3 10 2 12c1 2.5 5 7 10 7 1.8 0 3.4-.5 4.8-1.3"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  undo: '<path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/>',
  wifi: '<path d="M2 9a15 15 0 0 1 20 0"/><path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 16a5 5 0 0 1 7 0"/><path d="M12 19.5h.01"/>',
};
const icon = (n, cls = '') => `<svg class="i ${cls}" viewBox="0 0 24 24" aria-hidden="true">${P[n] ?? ''}</svg>`;

// ---------- navigation ----------
const NAV = [
  [null, [['overview', 'Overview', 'home'], ['assistant', 'Assistant', 'spark'], ['scamcheck', 'Scam check', 'shield'], ['approvals', 'Approvals', 'inbox']]],
  ['Monitor', [['network', 'Network', 'globe', 'network'], ['agents', 'AI agents', 'bot', 'agents'], ['scans', 'Malware', 'bug', 'scans'], ['startup', 'Startup items', 'power', 'startup'], ['permissions', 'Permissions', 'key', 'permissions'], ['tracking', 'Tracking', 'radar', 'tracking'], ['system', 'System settings', 'sliders', 'system']]],
  ['Activity', [['findings', 'Findings', 'alert'], ['ignored', 'Ignored', 'eyeoff'], ['timeline', 'Timeline', 'clock']]],
  [null, [['accounts', 'Account safety', 'key'], ['hacked', 'I think I’ve been hacked', 'alert'], ['settings', 'Settings', 'gear']]],
];
const TITLES = {
  overview: ['Overview', 'Everything I’m watching on this Mac'],
  ignored: ['Ignored', 'Warnings you chose to ignore or snooze. Bring any of them back here.'],
  assistant: ['Assistant', 'Ask me anything about your security. I check your Mac, then answer with the AI you connected.'],
  network: ['Network', 'Every app talking over the network, and who is on the other end'],
  agents: ['AI agents', 'What each AI agent on this Mac is able to do'],
  scans: ['Malware', 'Checks your files for known viruses and Mac malware, with three open-source scanners'],
  startup: ['Startup items', 'Things set to start by themselves, where malware likes to hide'],
  permissions: ['Permissions', 'Which apps can use your camera, microphone, screen, keys and files'],
  tracking: ['Tracking', 'Trackers near you and apps that can see your location'],
  system: ['System settings', 'The macOS settings that keep this Mac safe'],
  findings: ['Findings', 'Everything I think you should know about'],
  approvals: ['Approvals', 'Nothing changes on your Mac until you approve it here with Touch ID'],
  timeline: ['Timeline', 'What I noticed, newest first'],
  query: ['SQL console', 'Advanced: read-only osquery SQL. Easier: ask the Assistant in plain English.'],
  settings: ['Settings', 'Your AI connection and what I can access'],
};

const state = { view: 'overview', sus: {}, expanded: new Set(), netFilter: '', netAll: false, fStatus: 'open', fCat: '', fMin: 'low', busy: new Set(), sql: "SELECT name, port, address, pid FROM listening_ports WHERE address NOT IN ('127.0.0.1','::1') LIMIT 50;", sqlResult: null, agentOpen: null, ai: null };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Reads retry for ~9 s while Hashling restarts; writes never retry so an action can't run twice. */
async function api(path, opts = {}) {
  const read = !opts.method || opts.method === 'GET';
  let res;
  for (let attempt = 0, wait = 300; ; attempt++, wait *= 2) {
    try {
      res = await fetch(path, { credentials: 'same-origin', headers: { 'content-type': 'application/json' }, ...opts, body: opts.body ? JSON.stringify(opts.body) : undefined });
      break;
    } catch {
      if (!read || attempt >= 5) throw new Error('offline');
      await sleep(wait);
    }
  }
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { location.replace('/' + location.hash); throw new Error('unauthorized'); }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ---------- formatting ----------
const ago = (t) => {
  if (!t) return 'not yet';
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 30) return 'just now';
  if (s < 90) return '1 min ago';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
};
const clock = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const day = (t) => new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
// Sizes use Finder's units (1 KB = 1000 bytes), so numbers match what people see elsewhere on the Mac.
const rate = (b) => (b < 1 ? '0 B/s' : b < 1e3 ? `${Math.round(b)} B/s` : b < 1e6 ? `${(b / 1e3).toFixed(b < 1e4 ? 1 : 0)} KB/s` : `${(b / 1e6).toFixed(1)} MB/s`);
const bytes = (b) => (b < 1e3 ? `${b} B` : b < 1e6 ? `${(b / 1e3).toFixed(0)} KB` : b < 1e9 ? `${(b / 1e6).toFixed(b < 1e8 ? 1 : 0)} MB` : `${(b / 1e9).toFixed(b < 1e11 ? 1 : 0)} GB`);
/** AI app risk in words a beginner can act on. */
const riskBadge = (r) => `<span class="sev plain ${esc(r)}">${({ critical: 'High risk', high: 'High risk', medium: 'Some risk', low: 'Low risk', info: 'Low risk' })[r] ?? esc(r)}</span>`;
const sev = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : /(s|x|ch|sh)$/.test(w) ? 'es' : 's'}`;
const home = (p) => String(p ?? '').replace(/^\/Users\/[^/]+/, '~');

function toast(msg, action) {
  const t = $('#toast');
  t.innerHTML = `<span>${esc(msg)}</span>${action ? `<button type="button" class="toast-btn">${esc(action.label)}</button>` : ''}`;
  t.classList.toggle('has-action', Boolean(action));
  if (action) t.querySelector('.toast-btn').onclick = () => { t.classList.remove('show'); action.fn(); };
  // A new message replacing one already on screen: a soft blur-swap, so the change is noticed.
  if (t.classList.contains('show') && !calm()) t.animate([{ filter: 'blur(3px)', opacity: 0.6 }, { filter: 'blur(0)', opacity: 1 }], { duration: 200, easing: 'ease-out' });
  t.classList.add('show');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove('show'), action ? 7000 : 4200);
}

/** Ignore a finding (or snooze it for some days), with Undo. */
async function ignoreFinding(id, days) {
  await api(`/api/findings/${encodeURIComponent(id)}/ignore`, { method: 'POST', body: days ? { days } : {} });
  closeDrawer();
  render();
  toast(days ? `Snoozed for ${days} days. It comes back after that.` : 'Ignored. I won\u2019t warn you about it again.', { label: 'Undo', fn: () => unignoreFinding(id, true) });
}
async function unignoreFinding(id, quiet) {
  await api(`/api/findings/${encodeURIComponent(id)}/reopen`, { method: 'POST' });
  closeDrawer();
  render();
  if (!quiet) toast('Got it. I’ll warn you about it again.');
}
const ignoreBtn = (f) => (f.status === 'acknowledged'
  ? `<button class="btn xs ghost" type="button" data-act="unignore" data-id="${esc(f.id)}" title="Start warning about this again">${icon('undo')}Unignore</button>`
  : `<button class="btn xs ghost ignore-btn" type="button" data-act="ignore" data-id="${esc(f.id)}" title="Stop warning me about this">${icon('eyeoff')}Ignore</button>`);

/** Icon-only Explain / Claude pair for dense table rows. */
const askIcons = (ctx, prompt) => {
  const data = `data-ctx="${attr(ctx)}"${prompt ? ` data-prompt="${esc(prompt)}"` : ''}`;
  return `<span class="ask-pair icons"><button class="ask" type="button" data-act="ask" ${data} title="Ask me to explain" aria-label="Explain">${icon('spark')}</button><button class="ask ask-claude" type="button" data-act="handoff" ${data} title="Ask in Claude" aria-label="Ask in Claude">${icon('ext')}</button></span>`;
};

/** A small "Explain" button that asks the AI about any item. */
const askBtn = (ctx, label = 'Explain', prompt) => {
  const data = `data-ctx="${attr(ctx)}"${prompt ? ` data-prompt="${esc(prompt)}"` : ''}`;
  return `<span class="ask-pair"><button class="ask" type="button" data-act="ask" ${data}>${icon('spark')}${esc(label)}</button><button class="ask ask-claude" type="button" data-act="handoff" ${data} title="Ask in Claude (opens your Claude app with this question filled in)" aria-label="Ask in Claude">${icon('ext')}Claude</button></span>`;
};

/** The "anything suspicious here?" bar at the top of each monitor view. */
const TIER = {
  suspicious: { label: 'Suspicious', hint: 'Signs something bad may be happening' },
  risk: { label: 'Worth fixing', hint: 'Not suspicious, but these weaken your security' },
  hardening: { label: 'Optional', hint: 'Nice to have. Nothing is wrong.' },
};
const tierDot = (f) => (f.tier === 'suspicious' ? (f.severity === 'critical' ? 'critical' : 'high') : f.tier === 'risk' ? 'medium' : 'low');

/** Risks and optional suggestions shown under an area's status bar, calm and clearly separate from "suspicious". */
function tierBlocks(s) {
  const risks = s.risks ?? [];
  const tips = s.suggestions ?? [];
  return `${risks.length ? `<section class="tier-block"><div class="tier-head"><span class="dot medium"></span><b>Worth fixing</b><span class="tier-count">${risks.length}</span><span class="tier-hint">${TIER.risk.hint}</span></div><div class="list">${risks.map((f) => findingItem(f, false)).join('')}</div></section>` : ''}
  ${tips.length ? `<details class="tier-block optional"><summary class="tier-head"><span class="dot low"></span><b>Optional: strengthen your security</b><span class="tier-count">${tips.length}</span><span class="tier-hint">${TIER.hardening.hint}</span></summary><div class="list">${tips.map((f) => findingItem(f, false)).join('')}</div></details>` : ''}`;
}

function statusBar(area, extra = '') {
  const s = state.sus[area];
  if (!s) return '';
  const checked = (s.checkedAt ? `Checked ${ago(s.checkedAt)}` : 'First check running') + (s.ignored ? ` · <a href="#/ignored" class="ignored-link">${s.ignored} ignored</a>` : '');
  const ctx = { kind: 'area', area, label: s.label, flagged: s.items };
  if (!s.count && s.blocked) {
    return `<div class="tier-stack"><div class="status flag"><div class="ico">${icon('lock', 'lg')}</div><div><b>Not checked yet</b><span class="sub">I need your permission to look here, so I can’t say it’s safe yet. See how to allow it below.</span></div></div>${tierBlocks(s)}</div>`;
  }
  if (!s.count) {
    return `<div class="tier-stack"><div class="status"><div class="ico">${icon('shieldok', 'lg')}</div><div><b>${esc(s.clean)}</b><span class="sub">${checked}${extra ? ` · ${esc(extra)}` : ''}</span></div>
      <div class="actions">${askBtn(ctx, 'Double-check with AI', `Double-check my ${s.label} with your tools. Is anything suspicious or worth fixing? Be brief.`)}</div></div>
      ${tierBlocks(s)}</div>`;
  }
  const tone = RANK[s.worst] >= RANK.high ? 'bad' : 'flag';
  return `<div class="tier-stack"><div class="status-wrap"><div class="status ${tone}"><div class="ico">${icon('alert', 'lg')}</div><div><b>${s.count === 1 ? '1 suspicious thing found' : `${s.count} suspicious things found`}</b><span class="sub">${esc(TIER.suspicious.hint)} · ${checked}</span></div>
    <div class="actions">${askBtn(ctx, 'Explain all with AI', `Look at the suspicious ${s.label} you found, explain each one simply, tell me which matter most on my Mac, and what to do.`)}</div></div>
    <div class="status-list">${s.items.map((f) => findingItem(f, false)).join('')}</div></div>
    ${tierBlocks(s)}</div>`;
}

function findingItem(f, showCat = true) {
  const ignored = f.status === 'acknowledged';
  return `<div class="item click ${ignored ? 'is-ignored' : ''}" data-act="finding" data-id="${esc(f.id)}" tabindex="0" role="button">
    <span class="dot ${ignored ? '' : tierDot(f)}"></span>
    <div class="body"><div class="t">${esc(f.title)}${ignored ? ` <span class="chip">${f.ignored_until ? `Snoozed until ${esc(new Date(f.ignored_until).toLocaleDateString([], { month: 'short', day: 'numeric' }))}` : 'Ignored'}</span>` : ''}</div><div class="s">${esc(f.summary)}</div>
      <div class="row-actions">${f.status !== 'resolved' && !ignored ? fixBtn({ kind: 'finding', id: f.id, title: f.title, severity: f.severity, summary: f.summary }) : ''}${askBtn({ kind: 'finding', id: f.id, title: f.title, severity: f.severity, summary: f.summary })}${f.status !== 'resolved' ? ignoreBtn(f) : ''}${showCat && f.tier ? `<span class="tier-tag ${esc(f.tier)}">${esc(TIER[f.tier].label)}</span>` : ''}${showCat && f.category ? `<span class="tag">${esc(CAT[f.category] ?? f.category)}</span>` : ''}</div></div>
    ${icon('chev', 'chev')}
  </div>`;
}

const eventRow = (e) => `<div class="event"><time>${clock(e.ts)}</time><span class="dot ${esc(e.severity)}"></span><span class="wrap">${esc(e.title)}${e.times > 1 ? ` <span class="times">${e.times} times</span>` : ''}</span></div>`;

/** Plain wording for my own housekeeping events, so the timeline reads like a diary, not a log file. */
function plainEvent(e) {
  let t = e.title.replace(/\(\((.*?)\)\)/g, '($1)').replace(/^(\w[\w ]*) \((\w[\w-]*)\)(?= )/, (m, a, n) => (a.toLowerCase() === n.toLowerCase() ? a : m));
  const clean = t.match(/^Scan finished clean \((\d+) files?\)$/);
  if (clean) t = `Malware scan: nothing found (${Number(clean[1]).toLocaleString()} ${clean[1] === '1' ? 'file' : 'files'} checked)`;
  if (/^Hashling [\d.]+ started$/.test(t)) t = 'I started up';
  t = t.replace(/^Hashling assistant proposed: /, 'I suggested: ')
    // Claude Code's program file is named after its version, e.g. "2.1.285".
    .replace(/^\d+\.\d+\.\d+(?= (connected|contacted) )/, 'Claude Code');
  return { ...e, title: plainIds(t) };
}
/**
 * Tidy a list of events: drop scan bookkeeping outside Expert mode and merge repeats of the same
 * line on the same day into one row ("12 times"), keeping the newest time.
 */
function tidyEvents(events) {
  const out = [];
  const byKey = new Map();
  for (const raw of events) {
    if (state.mode !== 'expert' && /^Scan queued by /.test(raw.title)) continue;
    const e = plainEvent(raw);
    const key = `${new Date(e.ts).toDateString()}|${e.title}`;
    const hit = byKey.get(key);
    if (hit) { hit.times++; continue; }
    const row = { ...e, times: 1 };
    byKey.set(key, row);
    out.push(row);
  }
  return out;
}

function ring(score, size = 118, stroke = 10) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = score >= 80 ? 'var(--ok)' : score >= 55 ? 'var(--warn)' : 'var(--high)';
  return `<svg viewBox="0 0 ${size} ${size}"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--track)" stroke-width="${stroke}"/><circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${color}" stroke-width="${stroke}" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - score / 100)}"/></svg>`;
}

// ---------- views ----------
const views = {};

const AREA_META = { network: ['Network', 'globe'], agents: ['AI agents', 'bot'], scans: ['Malware', 'bug'], startup: ['Startup items', 'power'], permissions: ['Permissions', 'key'], tracking: ['Tracking', 'radar'], system: ['System settings', 'sliders'] };

/** Plain explanation of the score: where it starts, what takes points off, and the biggest gain. */
function scoreExplain(o) {
  const b = o.scoreBreakdown;
  if (!b) return '';
  const words = { suspicious: ['suspicious thing', 'suspicious things'], risk: ['thing worth fixing', 'things worth fixing'], hardening: ['optional tip', 'optional tips'] };
  const parts = Object.keys(words).filter((t) => b.byTier[t] > 0).map((t) => `<li>Minus ${b.byTier[t]} for ${o.tiers[t]} ${words[t][o.tiers[t] === 1 ? 0 : 1]}</li>`).join('');
  const gain = b.topGains[0];
  return `<details class="score-why"><summary>How is this score worked out?</summary>
    <ul><li>Starts at <b>${b.settings}</b>, from how well your macOS security settings are set (FileVault, firewall, updates and more).</li>${parts}<li>Ignored warnings do not count.</li></ul>
    ${gain ? `<p>Biggest gain: <a href="#/findings?id=${encodeURIComponent(gain.id)}">${esc(gain.title)}</a> (about +${Math.max(1, Math.round(gain.points))}).</p>` : ''}</details>`;
}

views.overview = async () => {
  const o = await api('/api/overview');
  const c = o.openFindings;
  const net = o.network ?? {};
  const t = o.tiers;
  const mac = o.os ? ` (macOS ${esc(o.os)})` : '';
  const optional = t.hardening ? ` There ${t.hardening === 1 ? 'is also 1 optional way' : `are also ${t.hardening} optional ways`} to strengthen it.` : '';
  const summary = t.suspicious
    ? `I found ${plural(t.suspicious, 'suspicious thing')} on this Mac${mac}${t.risk ? ` and ${t.risk} more worth fixing` : ''}. Start with the suspicious ones; click any for a plain-English explanation.`
    : t.risk
      ? `Nothing suspicious on this Mac${mac}. ${t.risk === 1 ? 'One thing is' : `${t.risk} things are`} worth fixing to keep it safe.${optional}`
      : `Nothing suspicious and nothing to fix on this Mac${mac}.${optional || ' I’ll keep watching in the background.'}`;
  return `
  <section class="card hero">
    <div class="ring" aria-label="Security score ${o.score} of 100">${ring(o.score)}<div class="num"><div><b>${o.score}</b><span>out of 100</span></div></div></div>
    <div>
      <p class="verdict">${esc(o.verdict)}</p>
      <p class="muted" style="margin:0;max-width:560px">${summary}</p>
      <div class="counts">${[['suspicious', 'suspicious', 'high'], ['risk', 'worth fixing', 'medium'], ['hardening', 'optional', 'low']].map(([t, l, cls]) => `<a class="sev ${cls} ${o.tiers[t] ? '' : 'zero'}" href="#/findings" data-tier="${t}">${o.tiers[t]} ${l}</a>`).join('')}${o.ignoredFindings ? `<a class="sev info" href="#/ignored">${o.ignoredFindings} ignored</a>` : ''}</div>
      ${scoreExplain(o)}
    </div>
    <div class="stack" style="gap:8px">
      <button class="btn blue" data-act="ask" data-ctx="${attr({ kind: 'overview', score: o.score, top: o.topFindings })}" data-prompt="Give me a security check-up of this Mac. Start with what matters most, explain it simply, and propose fixes I can approve.">${icon('spark')}Run an AI check-up</button>
      <a class="btn" href="#/findings">See everything I found</a>
    </div>
  </section>

  ${o.limitations?.length ? `<div class="status flag mt"><div class="ico">${icon('alert', 'lg')}</div><div><b>I can\u2019t see everything yet</b><ul class="limits">${o.limitations.map((l) => `<li>${esc(l)}</li>`).join('')}</ul></div><div class="actions"><a class="btn sm" href="#/settings">Fix in Settings</a></div></div>` : ''}

  <div class="home mt">
    <div class="home-main">
      <div class="section-head"><p class="h2">Needs your attention</p><a href="#/findings">See all</a></div>
      <div class="list">${o.topFindings.length ? o.topFindings.map((f) => findingItem(f)).join('') : '<div class="empty">Nothing suspicious and nothing to fix right now.</div>'}</div>
      ${o.suggestions.length ? `<details class="tier-block optional adv"><summary class="tier-head"><span class="dot low"></span><b>Optional: strengthen your security</b><span class="tier-count">${o.suggestions.length}</span><span class="tier-hint">${TIER.hardening.hint}</span></summary><div class="list">${o.suggestions.map((f) => findingItem(f, false)).join('')}</div></details>` : ''}
      <div class="grid g2 mt home-pair"><!--rail-extra--></div>
      <section class="adv mt"><div class="section-head"><p class="h2">Just now</p><a href="#/timeline">Timeline</a></div>
        <div class="list">${tidyEvents(o.recentEvents).slice(0, 8).map(eventRow).join('') || '<div class="empty">Quiet so far.</div>'}</div></section>
    </div>
    <aside class="home-rail">
      <section><div class="section-head"><p class="h2">What I’m watching</p></div>
        <div class="card watch">${Object.entries(AREA_META).map(([k, [name, ic]]) => {
    const s = state.sus[k] ?? {};
    const risks = s.risks?.length ?? 0;
    const tone = s.count ? 'bad' : risks || s.blocked ? 'flag' : 'ok';
    const text = s.count ? `${s.count} suspicious` : risks ? `${risks} worth fixing` : s.blocked ? 'Not checked yet' : 'All clear';
    return `<a class="area" href="#/${k}"><span class="ic">${icon(ic)}</span><span class="name">${esc(name)}</span><span class="state ${tone}">${tone === 'ok' ? '' : icon('alert')}${text}</span></a>`;
  }).join('')}</div></section>
      <section><div class="section-head"><p class="h2">Right now</p><a href="#/network">${esc(TITLES.network[0])}</a></div>
        <dl class="card now">
          <a href="#/network"><dt>Apps using the internet</dt><dd>${net.processesOnline ?? '…'}</dd></a>
          <a href="#/network"><dt>Downloading</dt><dd>${rate(net.rateIn ?? 0)}</dd></a>
          <a href="#/uploads"><dt>Uploading</dt><dd>${rate(net.rateOut ?? 0)}</dd></a>
          <a href="#/approvals" class="${o.pendingActions ? 'wait' : ''}"><dt>Waiting for your approval</dt><dd>${o.pendingActions}</dd></a>
        </dl></section>
      <section><div class="section-head"><p class="h2">${esc(TITLES.agents[0])}</p><a href="#/agents">Details</a></div>
        <div class="list">${o.agents.map((a) => `<a class="item click" href="#/agents" data-agent="${esc(a.name)}"><span class="dot ${a.running ? 'on' : ''}" style="margin-top:7px" title="${a.running ? 'Running' : 'Not running'}"></span><div class="body"><div class="t row between" style="gap:8px;flex-wrap:nowrap"><span>${esc(a.name)}</span>${riskBadge(a.risk)}</div><div class="s">${a.reasons.length ? esc(a.reasons.slice(0, 3).join(' · ')) : 'No risky abilities found'}</div></div></a>`).join('') || '<div class="empty">No AI agents found.</div>'}</div></section>
    </aside>
  </div>`;
};

// --- Agents ---
const has = (a, id) => a.capabilities.some((c) => c.id === id);
const cap = (a, id) => a.capabilities.find((c) => c.id === id);
const mcpOf = (a, tag) => a.mcpServers.filter((s) => s.enabled && s.tags.includes(tag));
const mcp = (a, tag) => (mcpOf(a, tag).length ? (['runs shell commands', 'controls your desktop', 'signs in for you', 'payments'].includes(tag) ? 'high' : 'medium') : null);
const mcpNames = (a, tag) => mcpOf(a, tag).map((s) => `MCP: ${s.name}`).join(', ');
const MATRIX = [
  ['Runs tools without asking', 'It acts without your confirmation, so a tricked agent acts immediately.', (a) => (a.mode.risk === 'high' || has(a, 'never-ask') ? 'high' : null), (a) => a.mode.detail],
  ['Runs programs or shell commands', 'It can run any program on your Mac, with your user rights.', (a) => (has(a, 'broad-exec') ? 'high' : mcp(a, 'runs shell commands')), (a) => cap(a, 'broad-exec')?.detail ?? mcpNames(a, 'runs shell commands')],
  ['Reads and writes your files', 'It can open, change or delete files.', (a) => mcp(a, 'reads and writes files') ?? (has(a, 'file-ops') ? 'medium' : null), (a) => mcpNames(a, 'reads and writes files') || cap(a, 'file-ops')?.detail],
  ['Controls a web browser', 'It can browse, click and read pages as you, including logged-in sites.', (a) => mcp(a, 'controls a browser') ?? (a.plugins.some((p) => /chrome|browser/i.test(p)) ? 'high' : null), (a) => mcpNames(a, 'controls a browser') || a.plugins.filter((p) => /chrome|browser/i.test(p)).join(', ')],
  ['Controls your desktop', 'It can see the screen and click and type in any app.', (a) => mcp(a, 'controls your desktop') ?? (a.plugins.some((p) => /computer-use/i.test(p)) ? 'high' : null), (a) => mcpNames(a, 'controls your desktop') || a.plugins.filter((p) => /computer-use/i.test(p)).join(', ')],
  ['Signs in for you', 'It can log in to accounts on your behalf.', (a) => mcp(a, 'signs in for you'), (a) => mcpNames(a, 'signs in for you')],
  ['Email and messages', 'It can read or send mail and chat messages.', (a) => mcp(a, 'email and messages'), (a) => mcpNames(a, 'email and messages')],
  ['Pushes code to GitHub', 'It can publish code changes under your account.', (a) => (has(a, 'push') ? 'medium' : mcp(a, 'code hosting')), (a) => cap(a, 'push')?.detail ?? mcpNames(a, 'code hosting')],
  ['Cloud and deploys', 'It can change cloud services and live websites.', (a) => mcp(a, 'cloud and deploys'), (a) => mcpNames(a, 'cloud and deploys')],
  ['Payments', 'It can touch payment or billing systems.', (a) => mcp(a, 'payments'), (a) => mcpNames(a, 'payments')],
  ['Can read all your files', 'macOS gave it Full Disk Access: every file, including other apps’ private data.', (a) => (a.permissions.some((p) => p.label === 'Full Disk Access') ? 'high' : null), (a) => a.permissions.filter((p) => p.label === 'Full Disk Access').map((p) => p.via).join(', ')],
  ['Sees your screen or controls other apps', 'macOS lets it watch the screen or keyboard, or click and type in other apps.', (a) => (a.permissions.some((p) => /Accessibility|Screen|Input/.test(p.label)) ? 'high' : null), (a) => a.permissions.filter((p) => /Accessibility|Screen|Input/.test(p.label)).map((p) => `${p.label} via ${p.via}`).join(', ')],
  ['Has passwords or keys in its settings', 'Passwords or API keys are saved in files it reads, so a tricked AI could leak them.', (a) => (a.secrets.length ? 'high' : null), (a) => a.secrets.map((s) => `${s.total} in ${s.file}`).join(', ')],
  ['Adds tools from any project without asking', 'Opening a project folder can switch on new tools by itself.', (a) => (has(a, 'project-mcp') ? 'high' : null), () => 'Any project folder can add a tool (an MCP server) that starts automatically'],
  ['Runs its own automatic commands', 'Commands set to run by themselves when the AI starts, stops or uses a tool.', (a) => (a.hooks.length ? 'medium' : null), (a) => a.hooks.map((h) => `${h.event}: ${h.command}`).join('\n')],
  ['Online right now', 'It currently has internet connections.', (a) => (a.network.connections ? 'info' : null), (a) => a.network.destinations.join(', ')],
];

views.agents = async () => {
  const d = await api('/api/agents');
  const agents = (d.agents ?? []).sort((x, y) => RANK[y.risk] - RANK[x.risk]);
  if (!agents.length) return statusBar('agents') + '<div class="empty">No AI agents found on this Mac.</div>';
  const sel = agents.find((a) => a.id === state.agentOpen) ?? agents[0];
  return `${statusBar('agents', `${plural(agents.length, 'agent')} found`)}
  <div class="tablewrap"><table class="matrix">
    <thead><tr><th>What it can do</th>${agents.map((a) => `<th><button class="agent-col ${a.id === sel.id ? 'on' : ''}" data-act="agent" data-id="${esc(a.id)}"><span class="row" style="gap:6px"><span class="dot ${a.running ? 'on' : ''}"></span>${esc(a.name)}</span>${riskBadge(a.risk)}</button></th>`).join('')}</tr></thead>
    <tbody>${MATRIX.map(([label, why, fn, detail]) => `<tr><td><span title="${esc(why)}">${esc(label)}</span></td>${agents.map((a) => {
      const r = fn(a);
      if (!r) return '<td><span class="no">·</span></td>';
      const ctx = { kind: 'agent-ability', agent: a.name, ability: label, meaning: why, detail: detail(a) || '', mode: a.mode.label };
      return `<td><button class="cell ${r}" data-act="ask" data-ctx="${attr(ctx)}" title="${esc(`${label}: ${detail(a) || why}. Click to ask me.`)}">${r === 'info' ? '<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3" fill="currentColor"/></svg>' : icon('check')}</button></td>`;
    }).join('')}</tr>`).join('')}</tbody>
  </table></div>
  <p class="tiny faint" style="margin:8px 2px 0">Orange means real damage is possible if the agent is tricked, for example by a prompt injection hidden in a web page, email or file it reads. Click any square to ask why.</p>
  <div class="mt">${agentCard(sel)}</div>`;
};

function agentCard(a) {
  // Simple mode lists only abilities that matter, without the raw settings behind them.
  const simple = state.mode === 'simple';
  const caps = [...a.capabilities].filter((c) => !simple || c.risk !== 'info').sort((x, y) => RANK[y.risk] - RANK[x.risk]);
  const ctx = { kind: 'agent', name: a.name, risk: a.risk, mode: a.mode, reasons: a.riskReasons, mcpServers: a.mcpServers.map((s) => ({ name: s.name, tags: s.tags, command: s.command ?? s.url })), secrets: a.secrets.map((s) => ({ file: s.file, kinds: s.kinds })) };
  return `<article class="card">
    <div class="pad"><div class="agent-head">
      <div class="avatar">${esc(a.name[0])}</div>
      <div style="flex:1;min-width:0"><p class="h2">${esc(a.name)}</p><div class="small muted">${a.running ? `Running${state.mode === 'simple' ? '' : ` (${plural(a.pids.length, 'process')})`}` : 'Not running'} · ${esc(a.mode.label)}</div></div>
      ${riskBadge(a.risk)}
      ${askBtn(ctx, 'Is this agent safe?', `Is ${a.name} set up safely on my Mac? Explain its riskiest abilities simply and tell me exactly how to tighten it without breaking my workflow.`)}
    </div>
    ${a.riskReasons.length ? `<p class="muted" style="margin:14px 0 0">Why it is ${esc(({ critical: 'high', high: 'high', medium: 'some', low: 'low', info: 'low' })[a.risk] ?? a.risk)} risk: ${esc(a.riskReasons.join(', '))}.</p>` : ''}</div>
    <hr class="sep">
    <div class="grid g2" style="gap:0">
      <div class="pad"><p class="label">What it can do</p><div class="caps">${caps.length ? caps.map((c) => `<div class="cap"><span class="dot ${c.risk}" style="margin-top:7px"></span><div class="body">${esc(c.label)}${c.detail && !simple ? `<span class="d">${esc(c.detail)}</span>` : ''}</div>${askBtn({ kind: 'agent-ability', agent: a.name, ability: c.label, detail: c.detail, risk: c.risk }, 'Explain')}</div>`).join('') : '<span class="muted">No notable abilities found.</span>'}</div></div>
      <div class="pad adv" style="border-left:1px solid var(--line)"><p class="label">Details</p>
        <dl class="kv">
          <dt>Permission mode</dt><dd>${esc(a.mode.label)}<div class="small muted">${esc(a.mode.detail)}</div></dd>
          <dt>Config files</dt><dd class="mono small">${a.configFiles.map(esc).join('<br>') || '·'}</dd>
          <dt>macOS permissions</dt><dd>${[...new Map(a.permissions.map((p) => [p.label, p])).values()].map((p) => `<span class="chip ${p.risk === 'high' ? 'bad' : ''}">${esc(p.label)}</span>`).join(' ') || `<span class="muted">${state.sus?.permissions?.blocked ? 'Not checked yet (I need Full Disk Access to see them)' : 'None'}</span>`}</dd>
          <dt>Credentials</dt><dd>${a.secrets.length ? a.secrets.map((s) => `<div><span class="chip bad">${s.total} in ${esc(s.file)}</span><div class="small muted" style="margin-top:4px">${esc(Object.entries(s.kinds).map(([k, n]) => `${n} × ${k}`).join(', '))}</div></div>`).join('') : '<span class="muted">None found in its config</span>'}</dd>
          <dt>Network now</dt><dd>${a.network.connections ? `${plural(a.network.connections, 'connection')} · ↓ ${rate(a.network.rateIn)} ↑ ${rate(a.network.rateOut)}<div class="small muted">${esc(a.network.destinations.join(', '))}</div>` : '<span class="muted">Offline</span>'}</dd>
        </dl></div>
    </div>
    <details class="fold adv" ${a.mcpServers.length ? 'open' : ''}><summary>Connected tools (MCP servers) <span class="chip">${a.mcpServers.length}</span></summary><div class="fold-body">
      ${a.mcpServers.length ? `<div class="tablewrap" style="box-shadow:none"><table class="table"><thead><tr><th>Server</th><th>Runs</th><th>Can</th><th></th></tr></thead><tbody>${a.mcpServers.map((s) => `<tr>
        <td><b>${esc(s.name)}</b><div class="sub">${esc(s.source)}</div></td>
        <td class="mono small wrap" style="max-width:280px">${esc(s.url ?? s.command ?? '')}</td>
        <td>${s.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join(' ') || '<span class="muted small">unknown</span>'} ${s.enabled ? '' : '<span class="chip">disabled</span>'} ${s.unpinned ? '<span class="chip warn" title="Started with npx/uvx and no version, so it auto-updates">auto-updates</span>' : ''}</td>
        <td class="num">${askBtn({ kind: 'mcp-server', agent: a.name, server: s }, 'Explain')}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted small" style="margin:0">None configured.</p>'}
    </div></details>
    ${a.rules ? `<details class="fold adv"><summary>Permission rules <span class="chip">${a.rules.allow.length} allow · ${a.rules.ask.length} ask · ${a.rules.deny.length} deny</span></summary><div class="fold-body"><div class="grid g3">${['allow', 'ask', 'deny'].map((k) => `<div><p class="label">${k}</p><div class="mono small">${a.rules[k].map(esc).join('<br>') || '<span class="muted">none</span>'}</div></div>`).join('')}</div></div></details>` : ''}
    ${a.hooks.length ? `<details class="fold adv"><summary>Hooks <span class="chip">${a.hooks.length}</span></summary><div class="fold-body mono small">${a.hooks.map((h) => `<div style="padding:3px 0"><b>${esc(h.event)}</b> ${esc(h.command)}</div>`).join('')}</div></details>` : ''}
    ${a.skills.length || a.plugins.length ? `<details class="fold adv"><summary>Skills and plugins <span class="chip">${a.skills.length + a.plugins.length}</span></summary><div class="fold-body row">${[...a.plugins, ...a.skills].map((s) => `<span class="chip">${esc(s)}</span>`).join('')}</div></details>` : ''}
  </article>`;
}

// --- Network ---
views.network = async () => {
  const [d, fresh] = await Promise.all([api('/api/network'), api('/api/network/new?hours=24')]);
  const s = d.summary ?? {};
  let ps = d.processes ?? [];
  if (!state.netAll) ps = ps.filter((p) => p.connections.some((c) => c.external) || p.rateIn + p.rateOut > 0);
  if (state.netFilter) { const f = state.netFilter.toLowerCase(); ps = ps.filter((p) => `${p.app} ${p.name} ${p.path} ${p.connections.map((c) => `${c.org} ${c.host} ${c.remote}`).join(' ')}`.toLowerCase().includes(f)); }
  // Simple mode hides macOS's own background services (unless one matches a known bad server).
  const system = state.mode === 'simple' && !state.netSystem ? ps.filter((p) => p.signerKind === 'apple' && !p.connections.some((c) => c.intel)) : [];
  if (system.length) ps = ps.filter((p) => !system.includes(p));
  return `${statusBar('network', `${s.processesOnline ?? 0} apps online`)}
  <div class="figures">
    <div class="metric"><b>${s.processesOnline ?? 0}</b><span>apps on the internet</span></div>
    <div class="metric adv"><b>${s.externalConnections ?? 0}</b><span>internet connections</span></div>
    <div class="metric"><b>↓ ${rate(s.rateIn ?? 0)}</b><span>↑ ${rate(s.rateOut ?? 0)} uploading</span></div>
    <div class="metric adv"><b>${s.listeningExposed ?? 0}</b><span>open ports other devices on your network can reach</span></div>
  </div>
  <div class="toolbar mt">
    <label class="search">${icon('search')}<input class="input" id="net-filter" placeholder="Filter by app, company or IP" value="${esc(state.netFilter)}" aria-label="Filter network"></label>
    <div class="seg" role="group"><button class="${state.netAll ? '' : 'on'}" data-act="net-all" data-v="0">Internet only</button><button class="${state.netAll ? 'on' : ''}" data-act="net-all" data-v="1">Everything</button></div>
    <span class="tiny faint right">Updates every 10 seconds · ${ago(d.updated_at)}</span>
  </div>
  <div class="tablewrap"><table class="table">
    <thead><tr><th>App</th><th>Made by</th><th class="num">Traffic now</th><th>Talking to</th><th class="num"><span class="sr">Actions</span></th></tr></thead>
    <tbody>${ps.map(netRow).join('') || '<tr><td colspan="5" class="empty">No matching activity.</td></tr>'}${system.length ? `<tr><td colspan="5" class="small muted">${plural(system.length, 'macOS system service')} hidden. They are part of your Mac and signed by Apple. <button class="linkish" data-act="net-system">Show macOS system services</button></td></tr>` : ''}</tbody>
  </table></div>
  <div class="mt"><div class="section-head"><p class="h2">First contact in the last 24 hours</p></div>
    <p class="small muted" style="margin:-4px 0 10px">Places an app talked to for the first time since I started watching. New destinations for AI agents are worth a glance.</p>
    <div class="tablewrap"><table class="table"><thead><tr><th>When</th><th>App</th><th>Destination</th><th>Address</th><th></th></tr></thead><tbody>
      ${fresh.slice(0, 60).map((r) => `<tr><td class="small faint">${day(r.first_seen)}</td><td>${esc(r.data.app)} ${r.data.agent ? `<span class="chip agent">${esc(r.data.agent)}</span>` : ''}</td><td>${esc(r.data.dest)}${r.data.host && r.data.host !== r.data.dest ? `<div class="sub">${esc(r.data.host)}</div>` : ''}</td><td class="mono small">${esc(r.data.ip)}:${esc(r.data.port)}</td><td class="num">${askIcons({ kind: 'new-destination', ...r.data, firstSeen: r.first_seen }, 'Who is this destination, and is it normal for this app to contact it?')}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">Nothing new yet. I learn what is normal first.</td></tr>'}
    </tbody></table></div></div>`;
};

function netRow(p) {
  const ext = p.connections.filter((c) => c.external);
  const orgs = [...new Set(ext.map((c) => c.org ?? c.host ?? c.remote))];
  const key = `net:${p.pid}`;
  const open = state.expanded.has(key);
  const trusted = ['Signed by Apple', 'Mac App Store'].includes(p.signer) || p.signerKind === 'developer-id';
  const ctx = { kind: 'network-app', app: p.app, process: p.name, pid: p.pid, path: p.path, signer: p.signer, agent: p.agent ?? p.parentAgent, download: rate(p.rateIn), upload: rate(p.rateOut), totals: `${bytes(p.bytesIn)} in / ${bytes(p.bytesOut)} out`, destinations: orgs.slice(0, 10), listening: p.listening };
  return `<tr class="click" data-act="expand" data-key="${esc(key)}">
    <td><b>${esc(p.app)}</b>${p.app !== p.name ? `<div class="sub">${esc(p.name)}</div>` : ''}${p.agent || p.parentAgent ? ` <span class="chip agent" style="margin-top:4px">${esc(p.agent ?? `started by ${p.parentAgent}`)}</span>` : ''}</td>
    <td class="small signer" title="${esc(p.signer)}">${trusted ? `<span class="muted">${esc(p.signer)}</span>` : `<span class="chip ${p.signerKind === 'invalid' ? 'bad' : 'warn'}">${esc(p.signer)}</span>`}</td>
    <td class="num"><div class="traffic"><span title="Download">↓ ${rate(p.rateIn)}</span><span title="Upload">↑ ${rate(p.rateOut)}</span></div></td>
    <td class="small" style="max-width:260px">${esc(orgs.slice(0, 3).join(', '))}${orgs.length > 3 ? ` <span class="faint">+${orgs.length - 3}</span>` : ''}${!ext.length && p.listening.length ? '<span class="muted">Waiting for connections</span>' : ''}</td>
    <td class="num">${askIcons(ctx)}</td>
  </tr>${open ? `<tr class="subrow"><td colspan="5">
    ${p.note ? `<p style="margin:0 0 10px">${esc(p.note)}</p>` : ''}
    <div class="mono tiny faint wrap" style="margin-bottom:8px">${esc(p.path)} · pid ${p.pid} · ${esc(p.user)} · ${bytes(p.bytesIn)} in / ${bytes(p.bytesOut)} out since it started</div>
    ${p.connections.map((cn) => `<div class="conn"><span>${esc(cn.org ?? (cn.external ? cn.remote : 'Your local network'))}${cn.country ? ` <span class="faint">${esc(cn.country)}</span>` : ''}</span><span class="mono faint wrap">${esc(cn.host ?? '')}</span><span class="mono">${esc(cn.remote)}:${cn.remotePort}</span><span class="faint">${esc(cn.proto)} ${esc(cn.state)}</span>${cn.external ? askBtn({ kind: 'connection', app: p.app, process: p.name, remote: cn.remote, port: cn.remotePort, host: cn.host, owner: cn.org, country: cn.country }, 'Who is this?') : '<span></span>'}</div>`).join('')}
    ${p.listening.length ? `<div class="small" style="margin-top:10px">Accepting connections on ${p.listening.map((l) => `<span class="chip ${l.exposed ? 'warn' : ''}" title="${l.exposed ? 'Reachable by other devices on your network' : 'Only this Mac can reach it'}">${esc(l.address)}:${l.port}</span>`).join(' ')}</div>` : ''}
    <div class="row" style="margin-top:12px">
      <button class="btn sm" data-act="dossier" data-q="${esc(p.path)}">Investigate app</button>
      <button class="btn sm" data-act="process" data-pid="${p.pid}">Inspect process</button>
      <button class="btn sm danger" data-act="propose" data-a="${attr({ type: 'kill_process', target: { pid: p.pid, name: p.name }, reason: `Quit ${p.name} from the Network view` })}">Quit app…</button>
    </div>
  </td></tr>` : ''}`;
}

// --- Ignored ---
const AREA_OF = { network: 'Network', agents: 'AI agents', malware: 'Malware', 'malware-artifacts': 'Malware', persistence: 'Startup items', permissions: 'Permissions', trackers: 'Tracking', location: 'Tracking', posture: 'System settings' };
views.ignored = async () => {
  const list = await api('/api/findings?status=acknowledged&min=info');
  if (!list.length) {
    return `<div class="card empty-state"><span class="ico">${icon('eyeoff', 'lg')}</span><p class="h2">Nothing is ignored</p><p class="muted">When you ignore or snooze a warning, it shows up here so you can bring it back any time.</p><a class="btn" href="#/findings">See everything I found</a></div>`;
  }
  const snoozed = list.filter((f) => f.ignored_until).length;
  const groups = {};
  for (const f of list) (groups[AREA_OF[f.category] ?? CAT[f.category] ?? 'Other'] ??= []).push(f);
  return `<div class="status"><div class="ico">${icon('eyeoff', 'lg')}</div><div><b>${plural(list.length, 'warning')} ignored</b><span class="sub">${snoozed ? `${snoozed} snoozed (they come back on their own) · ` : ''}I still keep an eye on these, but I won’t warn you about them.</span></div>
    <div class="actions"><button class="btn sm" data-act="unignore-all">${icon('undo')}Unignore all</button></div></div>
  ${Object.entries(groups).map(([area, items]) => `<div class="section-group"><div class="section-head"><p class="h2">${esc(area)} <span class="faint" style="font-weight:500">${items.length}</span></p></div>
    <div class="list">${items.map((f) => findingItem(f, false)).join('')}</div></div>`).join('')}`;
};

// --- Findings ---
views.findings = async () => {
  const q = new URLSearchParams({ status: state.fStatus, min: 'info', ...(state.fCat ? { category: state.fCat } : {}) });
  const list = await api(`/api/findings?${q}`);
  const cats = ['', 'incidents', 'network', 'behavior', 'netsafety', 'agents', 'processes', 'malware', 'malware-artifacts', 'downloads', 'notarization', 'persistence', 'permissions', 'secrets', 'posture', 'updates', 'trackers', 'location', 'storage'];
  return `<div class="toolbar">
    <div class="seg">${[['open', 'Needs attention'], ['acknowledged', 'Ignored'], ['resolved', 'Resolved'], ['all', 'All']].map(([v, l]) => `<button class="${state.fStatus === v ? 'on' : ''}" data-act="fstatus" data-v="${v}">${l}</button>`).join('')}</div>
    <select class="input" id="f-cat" aria-label="Category">${cats.map((c) => `<option value="${c}" ${state.fCat === c ? 'selected' : ''}>${c ? esc(CAT[c] ?? c) + (c === 'malware-artifacts' ? ' (threat hunting)' : '') : 'All areas'}</option>`).join('')}</select>
    <div class="seg">${[['', 'All levels'], ['suspicious', 'Suspicious'], ['risk', 'Worth fixing'], ['hardening', 'Optional']].map(([v, l]) => `<button class="${(state.fTier ?? '') === v ? 'on' : ''}" data-act="ftier" data-v="${v}">${l}</button>`).join('')}</div>
  </div>
  ${(() => {
    const shown = list.filter((f) => !state.fTier || f.tier === state.fTier);
    if (!shown.length) return '<div class="card empty-state"><span class="ico">' + icon('shieldok', 'lg') + '</span><p class="h2">Nothing here</p><p class="muted">No findings match these filters.</p></div>';
    return ['suspicious', 'risk', 'hardening'].map((t) => { const g = shown.filter((f) => f.tier === t); return g.length ? `<section class="tier-group"><div class="tier-head"><span class="dot ${t === 'suspicious' ? 'high' : t === 'risk' ? 'medium' : 'low'}"></span><b>${esc(TIER[t].label)}</b><span class="tier-count">${g.length}</span><span class="tier-hint">${esc(TIER[t].hint)}</span></div><div class="list">${g.map((f) => findingItem(f)).join('')}</div></section>` : ''; }).join('');
  })()}`;
};

const QUICK = [
  ['Is this dangerous?', 'Is this actually dangerous on my Mac? Check with your tools and give me a clear yes, no or maybe, with the reason.'],
  ['Explain it simply', 'Explain this to me like I am not technical. What is it and why do you care about it?'],
  ['What should I do?', 'What exactly should I do about this? Give me the simplest safe steps.'],
  ['Fix it for me', 'Fix this for me. Before anything changes, tell me exactly what you will do, what will change on my Mac, and whether I can undo it. Then propose it so I can approve it with Touch ID. If you cannot change it, give me the exact steps instead.'],
];
/** What a Fix button asks your AI: explain the exact change first, then propose it for Touch ID. */
/** How each kind of change can be undone, shown on every proposal. */
const UNDO = {
  quarantine_file: 'You can undo this: restore the file from Quarantine on the approvals page.',
  restore_file: 'Puts the file back where it was.',
  kill_process: 'The app can simply be opened again.',
  disable_persistence: 'You can undo this: the startup file is kept in Quarantine and can be restored.',
  revoke_permission: 'You can undo this: grant the permission again in System Settings.',
  block_domain: 'You can undo this: unblock the website on the approvals page.',
  unblock_domain: 'You can block it again any time.',
  trash_paths: 'You can undo this: open the Trash and choose Put Back.',
  run_cleanup: 'Only removes caches that rebuild themselves. Nothing personal is deleted.',
  safe_dns: 'You can undo this: turn safe browsing off again at any time, which puts your old settings back.',
  remove_all: 'You can undo most of it: the app and its startup items are kept in Quarantine and can be restored from Approvals.',
};
const FIX_PROMPT = 'Fix this for me. Before anything changes, tell me exactly what you will do, what will change on my Mac, and whether I can undo it. Then propose it so I can approve it with Touch ID. If you cannot change it, give me the exact steps instead.';
const fixBtn = (ctx) => `<button type="button" class="btn xs fix-btn" data-act="ask" data-ctx="${attr(ctx)}" data-prompt="${esc(FIX_PROMPT)}">${icon('spark')}Fix</button>`;
const quickChips = (ctx) => `<div class="quick">${QUICK.map(([l, p]) => `<button type="button" data-act="ask" data-ctx="${attr(ctx)}" data-prompt="${esc(p)}">${esc(l)}</button>`).join('')}<button type="button" class="claude-chip" data-act="handoff" data-ctx="${attr(ctx)}">${icon('ext')}Ask in Claude</button></div>`;

async function openFinding(id) {
  const f = await api(`/api/findings/${encodeURIComponent(id)}`);
  const ctx = { kind: 'finding', id: f.id, title: f.title, severity: f.severity, category: f.category, summary: f.summary };
  drawer(`<div class="drawer-head">${sev(f.severity)}<span class="chip">${esc(CAT[f.category] ?? f.category)}</span>${f.status !== 'open' ? `<span class="chip">${esc(f.status)}</span>` : ''}<span class="right"></span><button class="btn ghost icon-btn" data-close aria-label="Close">${icon('x')}</button></div>
  <div class="drawer-body">
    <div><h2 id="drawer-title">${esc(f.title)}</h2><p class="muted wrap" style="margin:6px 0 0">${esc(f.summary)}</p></div>
    <div class="explain"><p class="label">What this means</p><p>${esc(f.explanation)}</p>${f.recommendation ? `<p class="label" style="margin-top:12px">What to do</p><p>${esc(f.recommendation)}</p>` : ''}</div>
    ${f.status !== 'resolved' ? `<div class="fix-panel"><div><b>Let me fix this</b><span class="sub">I check the problem, tell you exactly what I’ll change and whether you can undo it, then wait. Nothing changes until you approve with Touch ID.</span></div><button class="btn primary" data-act="ask" data-ctx="${attr(ctx)}" data-prompt="${esc(FIX_PROMPT)}">${icon('spark')}Fix with AI</button></div>` : ''}
    <div><p class="label">Ask Hashling about it</p>${quickChips(ctx)}</div>
    ${f.key?.startsWith('tcc-leftover:') ? (() => {
      const items = f.evidence.items ?? [{ name: f.evidence.name, label: f.evidence.label, service: f.evidence.service }];
      const byService = [...new Map(items.map((i) => [i.service, i])).values()];
      return `<div><p class="label">Do it in System Settings</p><div class="row" style="gap:8px">${byService.map((i) => `<button class="btn" data-act="settings-pane" data-v="tcc-${esc(i.service)}">Open ${esc(i.label)} ${icon('ext')}</button>`).join('')}</div><p class="tiny faint" style="margin:8px 0 0">In each list, select ${esc([...new Set(items.map((i) => i.name))].join(' and '))} and click the minus (−) button. I’ll check again in a few minutes and this note goes away by itself.</p></div>`;
    })() : ''}
    ${f.actions.length ? `<div><p class="label">I can do this for you</p><div class="row">${f.actions.map((a) => `<button class="btn primary" data-act="propose" data-a="${attr({ ...a, reason: f.title, finding_id: f.id })}">${esc(a.label)}</button>`).join('')}</div><p class="tiny faint" style="margin:8px 0 0">You confirm with Touch ID in Approvals before anything happens.</p></div>` : ''}
    ${f.status === 'open' ? `<div><p class="label">Don\u2019t need this warning?</p><div class="row"><button class="btn" data-act="ignore" data-id="${esc(f.id)}">${icon('eyeoff')}Ignore</button><button class="btn" data-act="snooze" data-id="${esc(f.id)}" data-days="7">${icon('clock')}Snooze 7 days</button><button class="btn ghost" data-act="snooze" data-id="${esc(f.id)}" data-days="30">30 days</button></div><p class="tiny faint" style="margin:8px 0 0">Ignored warnings stop showing in status bars and counts. You can bring them back from Findings, Ignored.</p></div>`
      : f.status === 'acknowledged' ? `<div class="status flag" style="margin:0"><div class="ico">${icon('eyeoff', 'lg')}</div><div><b>${f.ignored_until ? `Snoozed until ${esc(day(f.ignored_until))}` : 'You are ignoring this'}</b><span class="sub">I still keep an eye on it, but I won\u2019t warn you.</span></div><div class="actions"><button class="btn sm" data-act="unignore" data-id="${esc(f.id)}">${icon('undo')}Stop ignoring</button></div></div>` : ''}
    <details class="fold" style="border:1px solid var(--line);border-radius:12px"><summary>Technical evidence</summary><div class="fold-body"><pre>${esc(JSON.stringify(f.evidence, null, 2))}</pre></div></details>
    <p class="tiny faint">First seen ${day(f.first_seen)} · last seen ${ago(f.last_seen)} · id ${esc(f.id)}</p>
  </div>`);
}

/** Generic detail drawer for any item (startup item, permission, check, tracker...). */
function openItem(ctx) {
  const facts = Object.entries(ctx.facts ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== '');
  drawer(`<div class="drawer-head"><span class="title">${esc(ctx.kindLabel ?? 'Details')}</span><button class="btn ghost icon-btn" data-close aria-label="Close">${icon('x')}</button></div>
  <div class="drawer-body">
    <div><h2 id="drawer-title">${esc(ctx.title)}</h2>${ctx.subtitle ? `<p class="muted wrap" style="margin:6px 0 0">${esc(ctx.subtitle)}</p>` : ''}</div>
    ${ctx.explain ? `<div class="explain"><p class="label">What this means</p><p>${esc(ctx.explain)}</p>${ctx.todo ? `<p class="label" style="margin-top:12px">What to do</p><p>${esc(ctx.todo)}</p>` : ''}</div>` : ''}
    <div><p class="label">Ask Hashling about it</p>${quickChips(ctx.ai ?? ctx)}</div>
    ${ctx.buttons ?? ''}
    ${facts.length ? `<dl class="kv">${facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="${String(v).startsWith('/') || String(v).startsWith('~') ? 'mono small' : ''}">${esc(Array.isArray(v) ? v.join(', ') : v)}</dd>`).join('')}</dl>` : ''}
  </div>`);
}

function drawer(html) {
  $('#drawer-panel').innerHTML = html;
  $('#drawer').hidden = false;
  $('#drawer').dataset.mode = 'detail';
  requestAnimationFrame(() => $('#drawer-panel [data-close]')?.focus());
}
function closeDrawer() { $('#drawer').hidden = true; }

// --- Approvals ---
// "com.loom.desktop" -> "Loom": a bundle identifier means nothing to most people.
const GENERIC_ID = new Set(['desktop', 'mac', 'macos', 'app', 'client', 'agent', 'helper', 'osx']);
const appFromId = (id) => { const p = id.split('.'); const name = p.length > 2 && GENERIC_ID.has(p[p.length - 1].toLowerCase()) ? p[p.length - 2] : p[p.length - 1]; return name.charAt(0).toUpperCase() + name.slice(1); };
const plainIds = (t) => String(t ?? '').replace(/\b(?:com|org|net|io|dev|us|co)\.[a-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g, appFromId);
/** Plain words for the errors macOS hands back when a fix could not be done. */
function plainResult(a) {
  const r = String(a.result ?? '');
  if (a.status !== 'failed') return plainIds(r);
  if (/No such bundle identifier/i.test(r)) return 'That app is no longer on this Mac, so there was nothing to take away.';
  if (/don.t have permission|not permitted|Operation not permitted|EPERM|EACCES/i.test(r)) return 'macOS would not let me touch it. It may be owned by the system or another user. Drag it to the Trash yourself if you still want it gone.';
  if (/No such process|already exited/i.test(r)) return 'It had already stopped.';
  if (/No such file|ENOENT/i.test(r)) return 'It was already gone.';
  return plainIds(r).replace(/\s*\(OSStatus error -?\d+\.?\)/g, '');
}
const CLEANUP = new Set(['trash_paths', 'run_cleanup']);
/** "(4.5 GB)", "about 0.87 GB", "up to 2.4 GB" -> bytes, for adding up what a batch of cleanups frees. */
const sizeOf = (a) => { const m = `${a.summary} ${a.reason}`.match(/(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB)\b/i); return m ? Number(m[1]) * 1024 ** ({ KB: 1, MB: 2, GB: 3, TB: 4 }[m[2].toUpperCase()]) : 0; };
const bytesText = (b) => b >= 1024 ** 3 ? `${(b / 1024 ** 3).toFixed(b >= 10 * 1024 ** 3 ? 0 : 1)} GB` : `${Math.max(1, Math.round(b / 1024 ** 2))} MB`;
const pendingItem = (a) => `
    <div class="item"><span class="dot ${CLEANUP.has(a.type) ? 'low' : 'medium'}" style="margin-top:7px"></span><div class="body"><div class="t">${esc(plainIds(a.summary))}</div><div class="s">${esc(plainIds(a.reason))}</div><div class="tiny faint" style="margin-top:4px">Suggested by ${esc(a.requested_by === 'Hashling assistant' ? 'me' : a.requested_by)} · ${ago(a.created_at)}${a.crucial ? ' · <span class="crucial-tag">Important, stays here until you decide</span>' : ''}</div></div>
      <div class="side-r">${askBtn({ kind: 'pending-action', id: a.id, summary: a.summary, reason: a.reason, by: a.requested_by }, 'Should I?', 'Should I approve this action? Explain what it will do, whether it can be undone, and any risk.')}<button class="btn primary sm" data-act="approve" data-id="${esc(a.id)}" ${state.busy.has(a.id) ? 'disabled' : ''}>${state.busy.has(a.id) ? 'Waiting for Touch ID…' : 'Approve'}</button><button class="btn sm" data-act="reject" data-id="${esc(a.id)}">Reject</button></div></div>`;

views.approvals = async () => {
  const [pending, all, q, archived] = await Promise.all([api('/api/actions?status=pending'), api('/api/actions'), api('/api/quarantine'), api('/api/actions?status=archived')]);
  const done = all.filter((a) => a.status !== 'pending' && a.status !== 'archived').slice(0, 30);
  const fixes = pending.filter((a) => !CLEANUP.has(a.type));
  const cleanups = pending.filter((a) => CLEANUP.has(a.type));
  const freed = cleanups.reduce((n, a) => n + sizeOf(a), 0);
  return `${pending.length ? `<div class="status flag"><div class="ico">${icon('inbox', 'lg')}</div><div><b>${!fixes.length && freed ? `${plural(pending.length, 'cleanup')} ready to free about ${bytesText(freed)}` : `${plural(pending.length, 'change')} waiting for your OK`}</b><span class="sub">Approving asks for Touch ID (or your password) on this Mac.</span></div>${pending.length > 1 ? `<div class="actions"><button class="btn primary sm" data-act="approve-all" ${state.busyAll ? 'disabled' : ''}>${state.busyAll ? 'Waiting for Touch ID…' : `Approve all ${pending.length}`}</button><button class="btn sm" data-act="reject-all">Reject all</button></div>` : ''}</div>` : `<div class="status"><div class="ico">${icon('shieldok', 'lg')}</div><div><b>Nothing is waiting for your approval</b><span class="sub">Your AI can only suggest fixes. You decide.</span></div></div>`}
  ${fixes.length ? `${cleanups.length ? `<div class="section-head mt"><p class="h2">Security fixes</p><span class="small faint">${plural(fixes.length, 'change')}</span></div>` : ''}<div class="list">${fixes.map(pendingItem).join('')}</div>` : ''}
  ${cleanups.length ? `<div class="section-head mt"><p class="h2">Free up space</p><span class="small faint">${plural(cleanups.length, 'cleanup')}${freed ? ` · about ${bytesText(freed)}` : ''} · everything goes to the Trash</span></div><div class="list">${cleanups.map(pendingItem).join('')}</div>` : ''}
  ${archived.length ? `<details class="card fold mt archive"${state.archiveOpen ? ' open' : ''}><summary>${icon('inbox')}Archived suggestions <span class="tier-count">${archived.length}</span><span class="tier-hint">Waited more than a day without a decision. Nothing was changed.</span></summary>
    <div class="list">${archived.map((a) => `<div class="item"><span class="dot low" style="margin-top:7px;opacity:.55"></span><div class="body"><div class="t">${esc(plainIds(a.summary))}</div><div class="s">${esc(plainIds(a.reason))}</div><div class="tiny faint" style="margin-top:4px">Archived ${ago(a.decided_at ?? a.created_at)}</div></div>
      <div class="side-r"><button class="btn sm" data-act="restore-action" data-id="${esc(a.id)}">${icon('undo')}Bring back</button><button class="btn sm ghost" data-act="dismiss-action" data-id="${esc(a.id)}">Dismiss</button></div></div>`).join('')}</div></details>` : ''}
  <div class="grid g2 mt" style="align-items:start">
    <div><div class="section-head"><p class="h2">Quarantine</p></div><div class="list">${q.items.map((i) => `<div class="item"><div class="body"><div class="t mono small">${esc(home(i.original))}</div><div class="s">${i.restored ? 'Restored' : 'Locked away'} ${ago(i.at)}${i.sha256 ? ` · sha256 ${esc(i.sha256.slice(0, 12))}…` : ''}</div></div>${i.restored ? '' : `<button class="btn sm" data-act="propose" data-a="${attr({ type: 'restore_file', target: { id: i.id }, reason: `Restore ${home(i.original)}` })}">Restore…</button>`}</div>`).join('') || '<div class="empty">Nothing in quarantine.</div>'}</div></div>
    <div class="adv"><div class="section-head"><p class="h2">Blocked domains</p></div><div class="list">${q.blockedDomains.map((d) => `<div class="item"><div class="body t mono">${esc(d)}</div><button class="btn sm" data-act="propose" data-a="${attr({ type: 'unblock_domain', target: { domain: d }, reason: `Unblock ${d}` })}">Unblock…</button></div>`).join('') || '<div class="empty">No domains blocked.</div>'}</div>
      <div class="row" style="margin-top:10px"><input class="input" id="block-domain" placeholder="tracker.example.com" style="flex:1"><button class="btn" data-act="block">Block domain…</button></div></div>
  </div>
  <div class="mt"><div class="section-head"><p class="h2">History</p></div><div class="tablewrap"><table class="table stack-sm"><thead><tr><th>Action</th><th>By</th><th>Status</th><th>Result</th><th>When</th></tr></thead><tbody>
    ${done.map((a) => `<tr><td class="cell-title">${esc(plainIds(a.summary))}</td><td class="small muted" data-label="By">${esc(a.requested_by === 'Hashling assistant' ? 'Me' : a.requested_by)}</td><td><span class="chip ${a.status === 'failed' ? 'bad' : a.status === 'executed' ? 'ok' : ''}">${esc({ executed: 'Done', failed: 'Didn’t work', rejected: 'Rejected', approved: 'Approved' }[a.status] ?? a.status)}</span></td><td class="small muted wrap">${esc(plainResult(a))}</td><td class="small faint">${ago(a.decided_at ?? a.created_at)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No history yet.</td></tr>'}
  </tbody></table></div></div>`;
};

// --- Malware ---
views.scans = async () => {
  const [scans, st, packs] = await Promise.all([api('/api/scans'), api('/api/status'), api('/api/attack-packs')]);
  const e = st.engines;
  const eng = [
    ['ClamAV', e.clamav && e.clamavDb, e.clamav ? (e.clamavDb ? 'Cisco Talos signatures' : 'Signatures downloading') : 'Not installed', 'An open-source antivirus engine maintained by Cisco Talos. It compares files against millions of known malware signatures.'],
    ['YARA-X with Apple XProtect rules', e.yara && e.xprotectRules, 'The same rules macOS uses', 'YARA-X matches files against pattern rules. I run Apple’s own XProtect rules, so I see what macOS knows about.'],
    ['osquery threat hunting', Boolean(packs.ran), packs.ran ? `${packs.ran} checks for known Mac malware` : 'Waiting', 'osquery looks for the files, startup entries and extensions that specific Mac malware families are known to leave behind.'],
    ['Your own YARA rules', e.customRules > 0, e.customRules ? plural(e.customRules, 'rule file') : 'Add .yar files to ~/.hashling/rules', 'Drop your own rule files in ~/.hashling/rules to scan with them too.'],
  ];
  return `${statusBar('scans', packs.ran ? `${packs.ran} threat-hunting checks` : '')}
  <div class="card pad"><p class="h3" style="margin-bottom:10px">Scan a file or folder</p>
    <div class="row"><input class="input" id="scan-path" placeholder="~/Downloads" style="flex:1;min-width:220px"><button class="btn primary" data-act="scan">Scan now</button><button class="btn" data-act="scan-quick" data-v="~/Downloads">Scan Downloads</button></div>
    <p class="tiny faint" style="margin:10px 0 0">I also scan Downloads, shared and temporary folders every day. Your AI agent can ask me to scan too.</p></div>
  <div class="grid g4 mt">${eng.map(([n, ok, d, why]) => `<div class="card pad-sm"><div class="row" style="gap:8px"><span class="dot ${ok ? 'ok' : ''}"></span><b class="small">${esc(n)}</b></div><p class="tiny muted" style="margin:6px 0 8px">${esc(d)}</p>${askBtn({ kind: 'engine', name: n, about: why }, 'What is this?')}</div>`).join('')}</div>
  <div class="mt"><div class="section-head"><p class="h2">Recent scans</p></div><div class="tablewrap"><table class="table"><thead><tr><th>Scanned</th><th>Started by</th><th>Status</th><th class="num">Files</th><th>Found</th><th>When</th></tr></thead><tbody>
    ${scans.map((s) => `<tr><td class="mono small wrap">${s.paths.map((p) => esc(home(p))).join('<br>')}</td><td class="small muted">${esc(s.requested_by)}</td><td><span class="chip ${s.status === 'failed' ? 'bad' : s.status === 'done' ? 'ok' : ''}">${esc(({ done: 'Finished', failed: 'Did not finish', running: 'Scanning…', queued: 'Waiting to start' })[s.status] ?? s.status)}</span>${s.error ? `<div class="sub">${esc(s.error)}</div>` : ''}</td><td class="num">${s.files_scanned}</td>
      <td>${s.detections.length ? s.detections.map((d) => `<div class="row small" style="gap:6px"><span class="sev high">${esc(d.signature)}</span><span class="mono wrap">${esc(home(d.path))}</span>${askBtn({ kind: 'detection', ...d }, 'Explain')}</div>`).join('') : `<span class="muted small">${s.status === 'done' ? 'Clean' : ''}</span>`}</td><td class="small faint">${ago(s.started_at)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No scans yet.</td></tr>'}
  </tbody></table></div></div>`;
};

// --- Startup items ---
const KINDS = { 'launch-agent': ['Launch agents', 'Programs that start when you log in.'], 'launch-daemon': ['Launch daemons', 'Background services that run as administrator (root), even before you log in.'], 'system-extension': ['System extensions', 'Low-level add-ons such as network filters and drivers.'], 'browser-extension': ['Browser extensions', 'Add-ons that can read and change websites you visit.'], cron: ['Scheduled jobs', 'Commands that run on a timer.'], 'startup-item': ['Legacy startup items', 'An old way of starting programs at boot.'] };
const FLAG = { 'script-download': ['downloads and runs code', 'bad'], 'risky-location': ['unusual folder', 'bad'], 'invalid-signature': ['broken signature', 'bad'], unsigned: ['no developer identity', 'warn'], 'missing-program': ['leftover', 'warn'] };
/** A readable name for a startup item: the app it belongs to, or its label without the reverse-domain prefix. */
function friendlyName(i) {
  const app = (i.program ?? '').match(/([^/]+)\.app\//)?.[1];
  if (app) return app === 'Hashling' ? 'Hashling' : app;
  const parts = String(i.label ?? '').split('.');
  if (parts.length < 3 || !/^(com|org|net|io|app|dev|co|me|us|de|uk|ai|tv)$/.test(parts[0])) return i.label;
  const words = parts.slice(1).join(' ').replace(/[-_]/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

views.startup = async () => {
  const d = await api('/api/persistence');
  const items = (d.items ?? []).sort((a, b) => b.flags.length - a.flags.length || Number(b.isNew) - Number(a.isNew));
  state.startupItems = items;
  return `${statusBar('startup', `${plural(items.length, 'item')} checked`)}
  ${(d.notes ?? []).length ? `<p class="small muted" style="margin:0 0 16px">${d.notes.map(esc).join(' ')}</p>` : ''}
  ${Object.entries(KINDS).map(([k, [title, sub]]) => { const list = items.filter((i) => i.kind === k); return list.length ? `
    <div class="mt" style="margin-top:0;margin-bottom:22px"><div class="section-head"><p class="h2">${esc(title)} <span class="faint" style="font-weight:500">${list.length}</span></p></div><p class="small muted" style="margin:-6px 0 10px">${esc(sub)}</p>
    ${(() => { const row = (i) => {
      const idx = items.indexOf(i);
      return `<div class="item click" data-act="startup" data-i="${idx}"><span class="dot ${i.flags.some((f) => FLAG[f]?.[1] === 'bad') ? 'high' : i.flags.some((f) => FLAG[f]) || i.isNew ? 'medium' : 'ok'}" style="margin-top:7px"></span>
        <div class="body"><div class="t">${esc(friendlyName(i))} ${i.isNew ? '<span class="chip warn">new</span>' : ''} ${i.flags.filter((f) => FLAG[f]).map((f) => `<span class="chip ${FLAG[f][1]}">${esc(FLAG[f][0])}</span>`).join(' ')}</div><div class="s mono tiny">${friendlyName(i) !== i.label ? `${esc(i.label)} · ` : ''}${esc(home(i.program ?? i.details?.bundleId ?? i.details?.id ?? ''))}</div>
          <div class="row-actions">${askBtn({ kind: 'startup-item', label: i.label, type: i.kind, program: i.program, signer: i.signer, flags: i.flags, isNew: i.isNew, details: i.details })}${i.signer ? `<span class="tag">${esc(i.signer)}</span>` : ''}</div></div>
        ${icon('chev', 'chev')}</div>`;
    };
    // Long lists (dozens of browser extensions) show what needs a look first and fold the rest.
    const quiet = list.length > 12 ? list.filter((i) => !i.isNew && !i.flags.some((f) => FLAG[f])) : [];
    const loud = list.filter((i) => !quiet.includes(i));
    return `${loud.length ? `<div class="list">${loud.map(row).join('')}</div>` : ''}${quiet.length ? `<details class="card fold" style="margin-top:${loud.length ? 10 : 0}px"><summary>${plural(quiet.length, k === 'browser-extension' ? 'extension' : 'item')} with nothing unusual${k === 'browser-extension' ? ', all from official stores' : ''}</summary><div class="fold-body"><div class="list">${quiet.map(row).join('')}</div></div></details>` : ''}`;
    })()}</div>` : ''; }).join('')}`;
};

// --- Permissions ---
views.permissions = async () => {
  const d = await api('/api/permissions');
  const grants = d.grants ?? [];
  const groups = {};
  for (const g of grants) (groups[g.label] ??= { risk: g.risk, items: [] }).items.push(g);
  // Simple mode skips groups only security and developer tools use.
  const order = Object.entries(groups).filter(([label]) => state.mode !== 'simple' || !/^(Endpoint security|Developer tool)/.test(label)).sort((a, b) => RANK[b[1].risk] - RANK[a[1].risk]);
  return `${statusBar('permissions', grants.length ? `${plural(grants.length, 'permission')} checked` : '')}
  ${d.limitation ? `<div class="status flag"><div class="ico">${icon('key', 'lg')}</div><div><b>Give me Full Disk Access so I can see permissions</b><span class="sub">${esc(d.limitation)}</span></div><div class="actions"><button class="btn sm" data-act="settings-pane" data-v="fda">Open Full Disk Access</button></div></div>` : ''}
  <div class="grid g2" style="align-items:start">${order.map(([label, g]) => `<div class="card"><div class="pad-sm row between" style="border-bottom:1px solid var(--line)"><p class="h3">${esc(label)}</p><span class="row" style="gap:8px">${riskBadge(g.risk)}${askBtn({ kind: 'permission-type', permission: label, apps: g.items.map((x) => x.client) }, 'Explain')}</span></div>
    ${g.items.map((x) => `<div class="item"><div class="body"><div class="t">${esc(x.name ?? x.client.split('/').pop())}${x.target ? ` <span class="faint">→ ${esc(x.target)}</span>` : ''}</div><div class="s tiny">${esc(x.signerKind === 'missing' ? 'App no longer installed. Only you can remove this entry, in System Settings.' : x.signer ?? 'Developer unknown')}</div>${x.name && x.name !== x.client ? `<div class="s mono tiny faint">${esc(x.client)}</div>` : ''}</div><div class="side-r">${x.signerKind === 'missing' ? '' : askBtn({ kind: 'permission', app: x.name ?? x.client, bundleId: x.client, permission: label, signer: x.signer, target: x.target }, 'Should it?', `Should ${x.name ?? x.client} have ${label}? Explain what it lets the app do and whether I should keep it.`)}${x.signerKind === 'missing' ? `<button class="btn xs" data-act="settings-pane" data-v="tcc-${esc(x.service)}" title="Select ${esc(x.name ?? x.client)} and click the minus (−) button">Remove in Settings ${icon('ext')}</button>` : x.clientType === 'bundle' ? `<button class="btn xs" data-act="propose" data-a="${attr({ type: 'revoke_permission', target: { service: x.service, bundleId: x.client }, reason: `Remove ${label} access from ${x.name ?? x.client}` })}">Remove access…</button>` : ''}</div></div>`).join('')}</div>`).join('') || (d.limitation ? '' : '<div class="empty">No permissions granted.</div>')}</div>`;
};

// --- Tracking ---
views.tracking = async () => {
  const [t, l] = await Promise.all([api('/api/trackers'), api('/api/location')]);
  const trackers = t.trackers ?? [];
  return `${statusBar('tracking', t.scanning ? `${t.devicesHeard ?? 0} Bluetooth devices heard` : '')}
  ${t.limitation ? `<div class="status flag"><div class="ico">${icon('radar', 'lg')}</div><div><b>Bluetooth tracker scanning is limited</b><span class="sub">${esc(t.limitation)}</span></div><div class="actions"><button class="btn sm" data-act="settings-pane" data-v="bluetooth">Open Bluetooth privacy</button></div></div>` : ''}
  <div class="section-head"><p class="h2">Trackers near you</p>${askBtn({ kind: 'trackers', trackers }, 'How does this work?', 'How do you detect AirTags and other trackers, what do the results mean for me right now, and what should I do if one is following me?')}</div>
  ${(() => {
    const item = (x) => `<div class="item click" data-act="item" data-ctx="${attr({ kindLabel: 'Bluetooth tracker', title: x.label, subtitle: x.distance, explain: x.kind === 'findmy-nearby-owner' ? 'This is a Find My device (an iPhone, AirPods, AirTag or Mac) that is close to its owner. Usually that owner is you or someone near you. Not a concern on its own.' : x.kind === 'findmy-separated' ? 'This Find My device is away from its owner. If it keeps appearing wherever you go, someone may have hidden it in your belongings.' : 'A third-party Bluetooth tracker. They broadcast all the time, so seeing one nearby is normal. It matters only if it follows you around.', facts: { 'Signal strength': `${x.rssi} dBm`, 'First heard': day(x.firstSeen), 'Times heard': x.sightings, 'Following you': x.suspicious ? 'Possibly' : 'No' }, ai: { kind: 'tracker', ...x } })}">
    ${x.suspicious ? `<span class="dot high" style="margin-top:7px"></span>` : '<span class="dot ok" style="margin-top:7px"></span>'}<div class="body"><div class="t">${esc(x.label)}</div><div class="s">${esc(x.distance)} · heard ${plural(x.sightings, 'time')} since ${clock(x.firstSeen)}</div></div><div class="side-r">${x.suspicious ? sev('high') : '<span class="chip ok">Not following you</span>'}${icon('chev', 'chev')}</div></div>`;
    const watch = trackers.filter((x) => x.suspicious);
    const normal = trackers.filter((x) => !watch.includes(x));
    if (!trackers.length) return `<div class="list">${`<div class="empty">${t.scanning ? `No trackers heard (${t.devicesHeard ?? 0} Bluetooth devices nearby). Checked ${ago(t.updated_at)}.` : 'Not scanning yet.'}</div>`}</div>`;
    return `${watch.length ? `<div class="list">${watch.map(item).join('')}</div>` : `<div class="status" style="margin:0"><div class="ico">${icon('shieldok', 'lg')}</div><div><b>No tracker is following you</b><span class="sub">I check again every few minutes, wherever you take this Mac.</span></div></div>`}
      ${normal.length ? `<details class="card fold mt"><summary>${plural(normal.length, 'tracker')} heard nearby, none following you. That is normal around other people.</summary><div class="fold-body"><div class="list">${normal.sort((a, b) => (b.kind === 'findmy-separated') - (a.kind === 'findmy-separated')).map(item).join('')}</div></div></details>` : ''}`;
  })()}
  <p class="tiny faint" style="margin:8px 2px 0">A Find My item that is away from its owner and keeps showing up for 30+ minutes is flagged. If you have moved and it stayed with you, check your bag, coat and car.</p>
  <div class="mt"><div class="section-head"><p class="h2">Apps that can see your location</p><button class="btn sm" data-act="settings-pane" data-v="location">Location Services ${icon('ext')}</button></div>
  ${l.limitation ? `<p class="small muted" style="margin:-4px 0 10px">${esc(l.limitation)}</p>` : ''}
  <div class="list">${(l.clients ?? []).map((cl) => `<div class="item"><div class="body"><div class="t">${esc(cl.name)}</div><div class="s tiny">${cl.authorized === null ? esc(cl.purpose ?? '') : esc(cl.bundleId ?? '')}</div></div><div class="side-r">${cl.authorized === null ? '<span class="chip outline">Can ask</span>' : cl.authorized ? '<span class="chip warn">Allowed</span>' : '<span class="chip">Denied</span>'}${askBtn({ kind: 'location-app', app: cl.name, bundleId: cl.bundleId, purpose: cl.purpose, allowed: cl.authorized }, 'Why?', `Why would ${cl.name} want my location, and should I allow it?`)}</div></div>`).join('') || '<div class="empty">None found.</div>'}</div></div>`;
};

// --- System ---
/** Everyday names for the security checks, shown in Simple mode (the technical name is one hover away in the glossary). */
const SIMPLE_CHECK = {
  sip: 'Core macOS protection', gatekeeper: 'Only open apps Apple has checked', filevault: 'Disk encryption', firewall: 'Firewall (blocks uninvited connections)',
  stealth: 'Hide this Mac from network scans', xprotect: 'Apple’s built-in malware protection', 'security-updates': 'Install security fixes automatically',
  'os-updates': 'Install macOS updates automatically', 'pending-updates': 'Updates waiting to install', 'auto-login': 'Automatic login (no password at startup)',
  guest: 'Guest account (anyone can use the Mac)', 'screen-lock': 'Ask for a password after sleep', proxy: 'Web traffic sent through another server',
  'custom-roots': 'Extra certificates your Mac trusts', mdm: 'Managed by a company or school', profiles: 'Settings profiles installed', 'remote-apps': 'Remote-control apps installed',
};
const PANE_FOR = { firewall: 'firewall', stealth: 'firewall', filevault: 'filevault', 'security-updates': 'updates', 'os-updates': 'updates', 'pending-updates': 'updates', 'auto-login': 'users', guest: 'users', 'screen-lock': 'lock', proxy: 'network', profiles: 'profiles', mdm: 'profiles', 'remote-apps': 'loginitems' };
views.system = async () => {
  const [p, st, pf] = await Promise.all([api('/api/posture'), api('/api/status'), api('/api/findings?status=active&category=posture&min=info')]);
  const byCheck = Object.fromEntries(pf.map((f) => [f.key.replace(/^posture:/, ''), f]));
  const order = { fail: 0, warn: 1, unknown: 2, pass: 3 };
  const checks = (p.checks ?? []).sort((a, b) => order[a.status] - order[b.status]);
  const failing = checks.filter((c) => c.status !== 'pass').length;
  return `${statusBar('system', `${checks.length - failing} of ${checks.length} checks passing`)}
  <div class="list">${checks.map((c) => { const f = byCheck[c.id]; const ign = f?.status === 'acknowledged'; return `<div class="check ${ign ? 'is-ignored' : ''}"><span class="badge-ico ${c.status === 'pass' ? 'ok' : ign ? '' : f?.tier === 'hardening' ? 'opt' : c.status === 'fail' ? 'fail' : 'warn'}">${icon(c.status === 'pass' ? 'check' : ign ? 'eyeoff' : f?.tier === 'hardening' ? 'plus' : 'alert')}</span>
    <div style="flex:1;min-width:0"><b>${esc(state.mode === 'simple' ? SIMPLE_CHECK[c.id] ?? c.label : c.label)}</b> <span class="muted">· ${esc(c.detail)}</span>${c.status !== 'pass' && f?.tier === 'hardening' && !ign ? ' <span class="tier-tag hardening">Optional</span>' : ''}${ign ? ' <span class="chip">Ignored</span>' : ''}<div class="why">${esc(c.why)}</div>${c.status !== 'pass' && c.fix ? `<div class="fix"><b>${f?.tier === 'hardening' ? 'To strengthen:' : 'How to fix:'}</b> ${esc(c.fix)}</div>` : ''}
    <div class="row-actions">${askBtn({ kind: 'system-check', check: c.label, status: c.status, detail: c.detail, why: c.why, fix: c.fix }, c.status === 'pass' ? 'Explain' : 'Help me fix', c.status === 'pass' ? undefined : `Help me fix "${c.label}" on my Mac. Explain why it matters for me and walk me through it step by step.`)}${c.status !== 'pass' && !ign && PANE_FOR[c.id] ? `<button class="btn xs" data-act="settings-pane" data-v="${PANE_FOR[c.id]}">Open setting ${icon('ext')}</button>` : ''}${f ? ignoreBtn(f) : ''}</div></div></div>`; }).join('')}</div>
  <div class="mt"><div class="section-head"><p class="h2">My background checks</p></div><div class="tablewrap"><table class="table"><thead><tr><th>Watcher</th><th>Runs every</th><th>Last run</th><th>Status</th><th></th></tr></thead><tbody>
    ${Object.entries(st.collectors).map(([k, s]) => `<tr><td>${esc(k)}</td><td class="small muted">${s.every < 60 ? s.every + ' s' : s.every < 3600 ? s.every / 60 + ' min' : s.every / 3600 + ' h'}</td><td class="small">${s.running ? 'running…' : ago(s.lastRun)}${s.durationMs ? ` <span class="faint">(${(s.durationMs / 1000).toFixed(1)} s)</span>` : ''}</td><td>${s.ok === false ? `<span class="chip bad" title="${esc(s.error)}">error</span>` : s.ok ? '<span class="chip ok">ok</span>' : '<span class="faint small">waiting</span>'}</td><td class="num"><button class="btn xs ghost" data-act="run" data-v="${esc(k)}">Run now</button></td></tr>`).join('')}
  </tbody></table></div></div>`;
};

// --- Timeline ---
views.timeline = async () => {
  const ev = tidyEvents(await api('/api/events?limit=600'));
  let last = '';
  // Runs of "X contacted a new destination: Y" become one line per app, so the timeline stays readable.
  const rows = [];
  for (const e of ev) {
    if (/<->/.test(e.title)) continue; // a bare socket logged by older versions, not an app
    const prev = rows[rows.length - 1];
    // A batch of suggestions made in the same minute: one line that opens to the list.
    const sug = e.title.match(/^(I suggested|You proposed|AI agent proposed|.+ proposed): (.*)$/);
    if (sug) {
      if (prev?.batch && prev.who === sug[1] && Math.abs(prev.ts - e.ts) < 120_000) { prev.items.push(sug[2]); continue; }
      rows.push({ batch: true, who: sug[1], items: [sug[2]], ts: e.ts, severity: e.severity, title: e.title });
      continue;
    }
    const m = e.title.match(/^(.*) contacted a new destination: (.*)$/);
    if (m && prev?.group && prev.actor === m[1] && new Date(prev.ts).toDateString() === new Date(e.ts).toDateString()) { prev.dests.push(m[2]); continue; }
    rows.push(m ? { group: true, actor: m[1], dests: [m[2]], ts: e.ts, severity: e.severity } : e);
  }
  const isAddr = (d) => /^[\d.]+$|^[0-9a-f:]+$/i.test(d) && /[.:]/.test(d);
  const groupRow = (g) => {
    const all = [...new Set(g.dests)];
    const named = all.filter((d) => !isAddr(d));
    const unnamed = all.length - named.length;
    const what = [named.slice(0, 3).join(', ') + (named.length > 3 ? ` and ${named.length - 3} more` : ''), unnamed === 1 ? `${named.length ? 'one' : 'a'} server with no known owner` : unnamed ? `${unnamed} servers with no known owner` : ''].filter(Boolean).join(', plus ');
    const title = `${g.actor} connected to ${all.length === 1 ? 'a new place' : `${all.length} new places`}: ${what}`;
    return all.length === 1 ? eventRow({ ts: g.ts, severity: g.severity, title })
      : `<details class="event-group"><summary class="event"><time>${clock(g.ts)}</time><span class="dot ${esc(g.severity)}"></span><span class="wrap">${esc(title)}</span></summary><ul>${all.map((d) => `<li class="${isAddr(d) ? 'mono tiny' : ''}">${esc(d)}</li>`).join('')}</ul></details>`;
  };
  const batchRow = (b) => b.items.length === 1 ? eventRow(b)
    : `<details class="event-group"><summary class="event"><time>${clock(b.ts)}</time><span class="dot ${esc(b.severity)}"></span><span class="wrap">${esc(`${b.who} ${b.items.length} changes`)}</span></summary><ul>${b.items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></details>`;
  return `<div class="list">${rows.map((e) => { const d = new Date(e.ts).toDateString(); const head = d !== last ? `<div class="day-head">${esc(d)}</div>` : ''; last = d; return head + (e.group ? groupRow(e) : e.batch ? batchRow(e) : eventRow(e)); }).join('') || '<div class="empty">Nothing yet.</div>'}</div>`;
};

// --- Query ---
views.query = async () => {
  const r = state.sqlResult;
  const cols = r?.rows?.length ? Object.keys(r.rows[0]) : [];
  const ex = [['Open ports', "SELECT name, port, address, pid FROM listening_ports WHERE address NOT IN ('127.0.0.1','::1') LIMIT 50;"], ['Recent apps', 'SELECT name, bundle_identifier, path FROM apps ORDER BY last_opened_time DESC LIMIT 20;'], ['Live sockets', 'SELECT p.name, s.remote_address, s.remote_port FROM process_open_sockets s JOIN processes p USING (pid) WHERE s.remote_port > 0 LIMIT 50;'], ['USB devices', 'SELECT vendor, model, serial FROM usb_devices;']];
  return `<div class="status"><div class="ico">${icon('spark', 'lg')}</div><div><b>No SQL needed</b><span class="sub">Ask the Assistant in plain English, for example \u201cwhat USB devices are plugged in?\u201d. It writes and runs the query for you.</span></div><div class="actions"><button class="btn ai sm" data-act="assistant">${icon('spark')}Ask in plain English</button></div></div>
  <div class="card pad"><textarea id="sql" spellcheck="false" rows="4" aria-label="SQL" class="mono">${esc(state.sql)}</textarea>
  <div class="row" style="margin-top:10px"><button class="btn primary" data-act="sql">Run query</button>${ex.map(([l, q]) => `<button class="btn sm ghost" data-act="sql-ex" data-v="${esc(q)}">${esc(l)}</button>`).join('')}
  <span class="right">${askBtn({ kind: 'osquery' }, 'Write a query for me', 'Help me write an osquery query. Ask me what I want to find out first if it is not clear.')}</span></div></div>
  ${r ? `<div class="mt">${r.error ? `<div class="status bad"><div class="ico">${icon('alert', 'lg')}</div><div><b>Query error</b><span class="sub">${esc(r.error)}</span></div></div>` : ''}${cols.length ? `<div class="tablewrap"><table class="table"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${r.rows.map((row) => `<tr>${cols.map((c) => `<td class="small wrap">${esc(row[c])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : r.error ? '' : '<div class="empty">No rows.</div>'}</div>` : ''}`;
};

// --- Settings ---
views.settings = async () => {
  const [cfg, st, o] = await Promise.all([api('/api/ai/config'), api('/api/ai/status'), api('/api/overview')]);
  state.ai = st;
  const lim = (o.limitations ?? []).join(' ');
  const fda = !/Full Disk Access/.test(lim);
  const bt = !/Bluetooth/.test(lim);
  return `<div class="grid g2" style="align-items:start">
  <section class="card">
    <div class="pad"><p class="h2">Your AI connection</p><p class="small muted" style="margin:4px 0 6px">Every warning already explains itself. With your Claude account connected, I can also answer your own questions.</p>
      <ul class="small muted" style="margin:0;padding-left:18px;line-height:1.7"><li>I can look things up, scan files and suggest fixes.</li><li>I can’t change anything by myself: every fix needs your Touch ID.</li><li>Prefer another AI? Cursor, Codex and other AI apps can work with me too (through MCP). I come with a guide they read to set themselves up.</li></ul></div>
    <hr class="sep">
    <div class="pad stack" style="gap:14px">
      <div class="status ${st.ready ? '' : 'flag'}" style="margin:0"><div class="ico">${icon(st.ready ? 'shieldok' : 'alert', 'lg')}</div><div><b>${st.ready ? 'Connected' : 'Not connected yet'}</b><span class="sub">${esc(st.detail)}${st.account ? ` (${esc(st.account)})` : ''}</span></div></div>
      <div><p class="label">Connect with</p><div class="seg" role="radiogroup">${[['claude-code', 'Claude Code sign-in'], ['anthropic-key', 'Anthropic API key'], ['off', 'Off']].map(([v, l]) => `<button class="${cfg.provider === v ? 'on' : ''}" data-act="ai-provider" data-v="${v}">${l}</button>`).join('')}</div></div>
      ${cfg.provider === 'claude-code' ? `<div class="row"><button class="btn ${st.ready ? '' : 'primary'}" data-act="ai-connect">${icon('ext')}${st.ready ? 'Sign in with another account' : 'Sign in to Claude'}</button><span class="tiny muted">Opens Terminal and your browser. Sign in once, then come back.</span></div>` : ''}
      ${cfg.provider === 'anthropic-key' ? `<div class="stack" style="gap:8px"><input class="input" id="ai-key" type="password" autocomplete="off" placeholder="${cfg.hasKey ? 'Key saved. Paste a new one to replace it.' : 'sk-ant-…'}"><input class="input" id="ai-headers" placeholder="Extra headers (optional), e.g. anthropic-workspace-id: wrkspc_…" value="${esc(cfg.extraHeaders)}"><div class="row"><button class="btn primary" data-act="ai-save-key">Save key</button>${cfg.hasKey ? '<button class="btn ghost" data-act="ai-clear-key">Remove key</button>' : ''}<span class="tiny muted">Stored only on this Mac in ~/.hashling/config.json. Uses your API credit.</span></div></div>` : ''}
      <div class="adv"><p class="label">Model</p><div class="seg">${Object.entries(cfg.models).map(([k, m]) => `<button class="${cfg.model === k ? 'on' : ''}" data-act="ai-model" data-v="${k}">${esc(m.label)}</button>`).join('')}</div></div>
      <hr class="sep adv">
      <div class="adv"><p class="label">Ask in Claude opens</p><div class="seg">${cfg.handoffTargets.map((t) => `<button class="${cfg.handoff === t.id ? 'on' : ''}" data-act="ai-handoff" data-v="${t.id}" ${t.available ? '' : 'disabled title="Not installed on this Mac"'}>${esc(t.label)}</button>`).join('')}</div>
        <p class="tiny muted" style="margin:8px 0 0">${esc(cfg.handoffTargets.find((t) => t.id === cfg.handoff)?.detail ?? '')} The question is filled in for you to review; nothing is sent until you press send. If my tools are missing in a Claude Desktop chat, quit and reopen Claude once.</p></div>
      <div class="row"><button class="btn" data-act="assistant">${icon('spark')}Ask Hashling</button><button class="btn" data-act="handoff">${icon('ext')}Ask in Claude</button></div>
    </div>
  </section>
  <section class="card">
    <div class="pad"><p class="h2">What I can see</p><p class="small muted" style="margin:4px 0 0">Some macOS data is protected. Grant these once so I can see the full picture. Only you can grant them.</p></div>
    <div class="list" style="border:0;border-top:1px solid var(--line);border-radius:0;box-shadow:none">
      <div class="item"><span class="dot ${fda ? 'ok' : 'medium'}" style="margin-top:7px"></span><div class="body"><div class="t">Full Disk Access</div><div class="s">${fda ? 'On. I can read app permissions and browser extensions.' : 'Lets me read app permissions and browser extensions. Turn on Hashling in the list. If it is missing, click + and choose Hashling from the Applications folder in your home folder.'}</div></div><button class="btn sm" data-act="settings-pane" data-v="fda">${fda ? 'Granted' : 'Grant'} ${icon('ext')}</button></div>
      <div class="item"><span class="dot ${bt ? 'ok' : 'medium'}" style="margin-top:7px"></span><div class="body"><div class="t">Bluetooth</div><div class="s">Lets me listen for AirTags and other trackers. I never connect to them.</div></div><button class="btn sm" data-act="settings-pane" data-v="bluetooth">${bt ? 'Granted' : 'Grant'} ${icon('ext')}</button></div>
      <div class="item"><span class="dot info" style="margin-top:7px"></span><div class="body"><div class="t">Apps that can see your location</div><div class="s">macOS keeps the exact list private, even from me, so I show the apps that are able to ask for your location instead.</div></div></div>
    </div>
    <div class="pad adv" style="border-bottom:1px solid var(--line)"><p class="label">Advanced</p><p class="small muted" style="margin:0 0 10px">You never need SQL: ask the Assistant in plain English and it looks things up on your Mac for you. If you know osquery SQL, you can run read-only queries yourself.</p><a class="btn sm" href="#/query">${icon('terminal')}Open SQL console</a></div>
    <details class="fold remove-hashling"><summary>Remove Hashling</summary><div class="fold-body small">
      <ol class="howto">
        <li>If you blocked any websites with Hashling, unblock them first in <a href="#/approvals">Approvals</a>. Otherwise they stay blocked.</li>
        <li>If you want any quarantined files back, restore them there too.</li>
        <li>Open Terminal and run <code>hashling uninstall --all</code>. I stop, no longer start at login, and my app is removed.</li>
        <li>Optional: delete the <code>.hashling</code> folder in your home folder to remove its history. The uninstall command lists anything else that is left.</li>
      </ol></div></details>
    <div class="pad"><p class="label">Privacy</p><p class="small muted" style="margin:0">I run on this Mac, with no account and no cloud. I go online only to look up who owns an internet address, download malware signatures and lists of known bad servers, check new downloads’ fingerprints (never the files), and check for updates. When you ask me or your own AI agent something, your question and what I look up on your Mac go to that AI’s company (Anthropic when you ask me here). Use whichever AI you trust; nothing is sent unless you ask.</p></div>
  </section></div>`;
};

// ---------- assistant ----------
const chat = { threadId: null, messages: [], busy: false, ctx: null, ctxLabel: '', abort: null };

function ctxLabel(ctx) {
  if (!ctx) return '';
  return ctx.title ?? ctx.ability ?? ctx.check ?? ctx.label ?? ctx.app ?? ctx.permission ?? ctx.name ?? ctx.agent ?? ctx.server?.name ?? ctx.summary ?? (ctx.kind ? ctx.kind.replace(/-/g, ' ') : '');
}

const DEFAULT_PROMPT = {
  finding: 'Explain this finding simply: what is it, is it dangerous on my Mac, and what should I do?',
  'network-app': 'What is this app doing on the network? Who is it talking to, is that normal, and is anything suspicious?',
  connection: 'Who is on the other end of this connection, and is it normal for this app to talk to them?',
  'new-destination': 'Who is this new destination and is it normal for this app to contact it?',
  'agent-ability': 'Explain this ability: what can the agent do with it, what could go wrong, and how do I limit it safely?',
  'mcp-server': 'What does this MCP server let the agent do, and is it safe to keep?',
  'startup-item': 'What is this startup item, who made it, and is it safe to keep?',
  permission: 'Should this app have this permission? What does it let the app do?',
  'permission-type': 'What does this permission allow, and do these apps need it?',
  'system-check': 'Explain this setting and whether I should change it.',
  detection: 'What is this detection, how dangerous is it, and what should I do?',
  engine: 'Explain this scanning engine and what it protects me from.',
  tracker: 'What is this tracker and should I be worried?',
};

function md(src) {
  const blocks = [];
  let s = String(src ?? '').replace(/```([\s\S]*?)```/g, (_, code) => { blocks.push(code.replace(/^\w*\n/, '')); return `\u0000${blocks.length - 1}\u0000`; });
  s = esc(s);
  const inline = (t) => t
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  const out = [];
  let list = null;
  const flush = () => { if (list) { out.push(`<${list.t}>${list.items.map((i) => `<li>${inline(i)}</li>`).join('')}</${list.t}>`); list = null; } };
  let para = [];
  const flushP = () => { if (para.length) { out.push(`<p>${inline(para.join('<br>'))}</p>`); para = []; } };
  for (const line of s.split('\n')) {
    const ul = line.match(/^\s*[-*•]\s+(.*)$/);
    const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
    const h = line.match(/^#{1,4}\s+(.*)$/);
    const code = line.match(/^\u0000(\d+)\u0000$/);
    if (ul || ol) { flushP(); const t = ul ? 'ul' : 'ol'; if (!list || list.t !== t) { flush(); list = { t, items: [] }; } list.items.push((ul ?? ol)[1]); continue; }
    flush();
    if (h) { flushP(); out.push(`<h4>${inline(h[1])}</h4>`); continue; }
    if (code) { flushP(); out.push(`<pre><code>${esc(blocks[Number(code[1])])}</code></pre>`); continue; }
    if (!line.trim()) { flushP(); continue; }
    para.push(line.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${esc(blocks[Number(i)])}</code>`));
  }
  flushP(); flush();
  return out.join('');
}

/** Suggested questions: a short title to read, a hint, and the full question that gets sent. */
const SUGGEST = [
  ['shieldok', 'Am I safe right now?', 'A quick check-up of this Mac', 'Am I safe right now? Give me a quick check-up.'],
  ['globe', 'Anything sending data somewhere odd?', 'Apps talking to unusual places', 'Is anything on my Mac sending data somewhere unusual?'],
  ['bot', 'What can my AI apps do?', 'And how to make them safer', 'What can my AI apps do, and how do I make them safer?'],
  ['radar', 'Is anyone tracking me?', 'AirTags and location access', 'Is anyone tracking me?'],
  ['upload', 'What did my Mac upload?', 'This week, and where it went', 'What did my Mac upload this week, and to whom?'],
  ['gauge', 'Why is my Mac slow?', 'And how to free up space safely', 'Why is my Mac slow, and how can I free up space?'],
  ['clock', 'What’s new since yesterday?', 'Changes worth knowing about', 'Is anything new on my Mac since yesterday that I should know about?'],
  ['spark', 'Fix the most important problem', 'I explain first, you approve', 'Fix the most important problem for me.'],
];

function chatHtml(mode) {
  const ai = state.ai;
  // The side panel is narrow, so it shows the first four suggestions; the full page shows all of them.
  const inDock = !$('#dock').hidden;
  const welcome = !chat.messages.length ? `<div class="welcome">
      <div class="welcome-mascot">${hashlingSvg()}</div>
      <h2 class="welcome-title">Hi, I’m Hashling.</h2>
      <p class="welcome-sub">Ask me anything about this Mac. I check it first, explain in plain words, and every fix waits for your Touch ID.</p>
      ${ai && !ai.ready ? `<div class="ai-off"><b>The built-in assistant isn\u2019t connected yet</b><p class="small muted" style="margin:4px 0 10px">${esc(ai.detail)} Until then, your questions open in your Claude app with my tools, ready to send.</p><div class="row"><button class="btn primary sm" data-act="handoff">${icon('ext')}Ask in Claude</button><button class="btn sm" data-act="ai-connect">Sign in to Claude</button></div></div>` : ''}
      <div class="suggest">${(inDock ? SUGGEST.slice(0, 4) : SUGGEST).map(([ic, title, hint, q]) => `<button type="button" data-act="ask" data-prompt="${esc(q)}"><span class="sg-ico">${icon(ic)}</span><span class="sg-text"><b>${esc(title)}</b><small>${esc(hint)}</small></span></button>`).join('')}</div></div>` : '';
  return `${welcome}${chat.messages.map((m) => m.role === 'user'
    ? `${m.ctxLabel ? `<div class="msg-ctx">${icon('spark')}About: ${esc(m.ctxLabel)}</div>` : ''}<div class="msg-user">${esc(m.text)}</div>`
    : `<div class="msg-ai"><div class="av av-hashling">${hashlingSvg()}</div><div class="content">
        ${m.steps?.length ? `<div class="steps">${m.steps.map((s) => `<div class="step">${s.done ? `<span class="ok">${icon('check')}</span>` : '<span class="spin"></span>'}${esc(s.label)}</div>`).join('')}</div>` : ''}
        ${m.text ? `<div class="md">${md(m.text)}</div>` : m.error ? '' : '<div class="step"><span class="spin"></span>Thinking…</div>'}
        ${m.error ? `<div class="ai-off" style="margin-top:6px"><b>Couldn’t answer</b><p class="small muted" style="margin:4px 0 10px">${esc(m.error)}</p>${/sign in|signed in|API key/i.test(m.error) ? `<div class="row"><button class="btn primary sm" data-act="handoff" data-prompt="${esc(m.question ?? '')}" data-ctx="${attr(m.ctx ?? null)}">${icon('ext')}Ask in Claude instead</button><button class="btn sm" data-act="ai-connect">Sign in to Claude</button></div>` : ''}</div>` : ''}
        ${(m.actions ?? []).map((a) => `<div class="action-card"><span class="dot medium"></span><div class="body"><div class="t">${esc(a.summary)}</div>${a.reason ? `<div class="s">${esc(a.reason)}</div>` : ''}${UNDO[a.type] ? `<div class="s undo">${icon('undo')}${esc(UNDO[a.type])}</div>` : ''}<div class="s">${a.status === 'pending' ? 'Nothing has changed yet. Approve to do it, with Touch ID.' : esc(({ executed: 'Done.', rejected: 'You said no. Nothing changed.', failed: 'It did not work. Nothing else was changed.', archived: 'Archived after a day. Bring it back from Approvals any time.' })[a.status] ?? a.status)}</div></div>${a.status === 'pending' ? `<button class="btn primary sm" data-act="approve" data-id="${esc(a.id)}">Approve</button><button class="btn sm" data-act="reject" data-id="${esc(a.id)}">Reject</button>` : ''}</div>`).join('')}
      </div></div>`).join('')}`;
}

function composerHtml() {
  return `<div class="composer">${chat.ctx ? `<div class="ctx-chip">${icon('spark')}<span>About: ${esc(chat.ctxLabel)}</span><button type="button" data-act="ctx-clear" aria-label="Remove context">${icon('x')}</button></div>` : ''}
    <form id="ask-form"><textarea id="ask-input" rows="1" placeholder="${chat.messages.length ? 'Ask a follow-up…' : 'Ask about your Mac’s security…'}" aria-label="Message"></textarea>
    ${chat.busy ? `<button class="btn icon-btn" type="button" data-act="stop" aria-label="Stop">${icon('stop')}</button>` : `<button class="btn blue icon-btn" type="submit" aria-label="Send">${icon('send')}</button>`}</form>
    <div class="hint"><span>Enter to send, Shift+Enter for a new line</span><span class="right">${chat.messages.length ? `<button class="btn xs ghost" type="button" data-act="new-chat">${icon('plus')}New chat</button>` : ''}</span></div></div>`;
}

function renderChat() {
  const target = !$('#dock').hidden ? $('#dock-chat') : state.view === 'assistant' ? $('#chat-area') : null;
  if (!target) return;
  const scroll = target.querySelector('.chat-scroll');
  const atBottom = !scroll || scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 80;
  const draft = target.querySelector('#ask-input')?.value ?? '';
  target.innerHTML = `<div class="chat-scroll">${chatHtml()}</div>${composerHtml()}`;
  const input = target.querySelector('#ask-input');
  if (input) { input.value = draft; autosize(input); }
  const sc = target.querySelector('.chat-scroll');
  if (atBottom) sc.scrollTop = sc.scrollHeight;
}

/**
 * The assistant docks on the right like a side panel: the page narrows to make room,
 * it stays open across pages, and its width and open state are remembered per browser.
 */
const DOCK_KEY = 'hashling.dock';
const dockPrefs = (() => { try { return JSON.parse(localStorage.getItem(DOCK_KEY)) ?? {}; } catch { return {}; } })();
const saveDock = () => { try { localStorage.setItem(DOCK_KEY, JSON.stringify(dockPrefs)); } catch { /* private window */ } };
// The page keeps at least 820px beside the sidebar; below that the panel slides over instead (see styles.css).
const clampDock = (w) => Math.round(Math.max(340, Math.min(w, 760, innerWidth - 248 - 820)));
function setDock(open) {
  $('#dock').hidden = !open;
  $('.shell').classList.toggle('docked', open);
  $('.shell').style.setProperty('--dock-w', `${clampDock(dockPrefs.w ?? 420)}px`);
  dockPrefs.open = open;
  saveDock();
  if (!open) $('#dock-inner').innerHTML = '';
  requestAnimationFrame(() => balance(page));
}
function closeDock() { setDock(false); $('[data-act="assistant"]')?.focus(); }
{
  const handle = $('#dock-resize');
  let dragging = false;
  handle.addEventListener('pointerdown', (e) => { dragging = true; handle.setPointerCapture(e.pointerId); $('#dock').classList.add('resizing'); e.preventDefault(); });
  handle.addEventListener('pointermove', (e) => { if (dragging) $('.shell').style.setProperty('--dock-w', `${clampDock(innerWidth - e.clientX)}px`); });
  handle.addEventListener('pointerup', () => {
    if (!dragging) return;
    dragging = false;
    $('#dock').classList.remove('resizing');
    dockPrefs.w = parseInt(getComputedStyle($('.shell')).getPropertyValue('--dock-w'), 10);
    saveDock();
    balance(page);
  });
  // Keyboard: arrow keys resize too.
  handle.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    dockPrefs.w = clampDock((dockPrefs.w ?? 420) + (e.key === 'ArrowLeft' ? 24 : -24));
    $('.shell').style.setProperty('--dock-w', `${dockPrefs.w}px`);
    saveDock();
  });
}

function autosize(t) { t.style.height = 'auto'; t.style.height = Math.min(160, t.scrollHeight) + 'px'; }

async function openAssistant() {
  if (state.view === 'assistant') { renderChat(); $('#ask-input')?.focus(); return; }
  closeDrawer();
  if ($('#dock').hidden) {
    $('#dock-inner').innerHTML = `<div class="drawer-head dock-head"><span class="av av-hashling">${hashlingSvg()}</span><span class="title">Ask Hashling</span><button class="btn ghost sm" data-act="handoff-chat" title="Continue this question in your Claude app">${icon('ext')}Claude</button><a class="btn ghost icon-btn" href="#/assistant" title="Open full page" aria-label="Open full page">${icon('expand')}</a><button class="btn ghost icon-btn" data-act="dock-close" aria-label="Close the assistant">${icon('x')}</button></div><div class="chat" id="dock-chat"></div>`;
    setDock(true);
  }
  if (!state.ai) { try { state.ai = await api('/api/ai/status'); } catch { /* ignore */ } }
  renderChat();
  $('#ask-input')?.focus();
}

/** Open the question in the user's own Claude app, pre-filled. */
async function handoff(prompt, ctx, reason = '') {
  const question = (prompt || (ctx ? DEFAULT_PROMPT[ctx.kind] ?? 'Explain this to me simply and tell me what to do.' : 'Give me a quick security check-up of this Mac.')).trim();
  const r = await api('/api/ai/handoff', { method: 'POST', body: { question, context: ctx ?? undefined } });
  if (r.ok) toast(`${reason}Opened in ${r.label}. Check the question, then press send.`);
  else toast(r.error);
  return r.ok;
}

/** Re-check whenever we last saw "not connected", so signing in takes effect on the very next click. */
async function aiReady() {
  if (!state.ai?.ready) { try { state.ai = await api('/api/ai/status'); } catch { return false; } }
  return state.ai.ready;
}

async function askAI(prompt, ctx) {
  if (chat.busy) { toast('I’m still answering. Stop me or wait a moment.'); return; }
  // Fallback: when the built-in assistant is not connected, hand the question to the user's Claude app.
  if (!(await aiReady())) { await handoff(prompt, ctx ?? chat.ctx, 'Built-in assistant not connected. '); return; }
  if (ctx) { chat.ctx = ctx; chat.ctxLabel = ctxLabel(ctx); }
  const text = (prompt || (chat.ctx ? DEFAULT_PROMPT[chat.ctx.kind] ?? 'Explain this to me simply and tell me what to do.' : '')).trim();
  if (!text) return;
  if (state.view !== 'assistant' && $('#dock').hidden) await openAssistant();
  const userMsg = { role: 'user', text, ctxLabel: chat.ctx ? chat.ctxLabel : '' };
  const aiMsg = { role: 'assistant', text: '', steps: [], actions: [], question: text, ctx: chat.ctx };
  chat.messages.push(userMsg, aiMsg);
  const context = chat.ctx;
  chat.ctx = null;
  chat.busy = true;
  renderChat();
  const ac = new AbortController();
  chat.abort = ac;
  let frame = null;
  const paint = () => { if (!frame) frame = requestAnimationFrame(() => { frame = null; renderChat(); }); };
  try {
    const res = await fetch('/api/ai/ask', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ threadId: chat.threadId, message: text, context }), signal: ac.signal });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        const e = JSON.parse(line);
        if (e.type === 'start') chat.threadId = e.threadId;
        else if (e.type === 'text') aiMsg.text += e.text;
        else if (e.type === 'tool') aiMsg.steps.push({ name: e.name, label: e.text, done: false });
        else if (e.type === 'tool_done') { const s = [...aiMsg.steps].reverse().find((x) => x.name === e.name && !x.done); if (s) s.done = true; }
        else if (e.type === 'action') { aiMsg.actions.push(e.action); updateBadges(); }
        else if (e.type === 'error') aiMsg.error = e.message;
        paint();
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') aiMsg.error = e.message; else aiMsg.error = aiMsg.text ? '' : 'Stopped.';
  } finally {
    for (const s of aiMsg.steps) s.done = true;
    chat.busy = false;
    chat.abort = null;
    renderChat();
    if (/sign in|API key/i.test(aiMsg.error ?? '')) state.ai = null;
  }
}

views.assistant = async () => {
  const [threads, st] = await Promise.all([api('/api/ai/threads').catch(() => []), api('/api/ai/status').catch(() => null)]);
  state.ai = st;
  // Group chats like a messages app: Today, Yesterday, This week, Earlier.
  const startOfDay = new Date(); startOfDay.setHours(0, 0, 0, 0);
  const groupOf = (t) => (t >= startOfDay.getTime() ? 'Today' : t >= startOfDay.getTime() - 86_400_000 ? 'Yesterday' : t >= startOfDay.getTime() - 6 * 86_400_000 ? 'This week' : 'Earlier');
  const groups = new Map();
  for (const t of threads) { const g = groupOf(t.updated_at); (groups.get(g) ?? groups.set(g, []).get(g)).push(t); }
  const list = [...groups].map(([g, ts]) => `<p class="thread-group">${g}</p>${ts.map((t) => `<button class="thread ${t.id === chat.threadId ? 'on' : ''}" data-act="thread" data-id="${esc(t.id)}" title="${esc(t.title)}"><span>${esc(t.title)}</span></button>`).join('')}`).join('');
  return `<div class="assistant-page">
    <aside class="threads" aria-label="Your chats">
      <div class="threads-head"><b>Chats</b><button class="btn sm" data-act="new-chat" aria-label="New chat">${icon('plus')}New</button></div>
      <div class="threads-list">${list || '<p class="threads-empty">Your chats with me appear here.</p>'}</div>
    </aside>
    <div class="chat-card"><div class="chat" id="chat-area"></div></div>
  </div>`;
};

async function loadThread(id) {
  const t = await api(`/api/ai/threads/${encodeURIComponent(id)}`);
  chat.threadId = t.id;
  chat.messages = t.messages.map((m) => (m.role === 'user' ? { role: 'user', text: m.text, ctxLabel: ctxLabel(m.context) } : { role: 'assistant', text: m.text, steps: (m.tools ?? []).map((n) => ({ name: n, label: n.replace(/_/g, ' '), done: true })), actions: m.actions ?? [] }));
  renderChat();
}

// ---------- interactions ----------
/** Words for the confirm button, per kind of change. */
const VERB = { trash_paths: 'Move to Trash', quarantine_file: 'Quarantine it', restore_file: 'Restore it', kill_process: 'Quit it', disable_persistence: 'Turn it off', revoke_permission: 'Take it away', block_domain: 'Block it', unblock_domain: 'Unblock it', run_cleanup: 'Clean up', safe_dns: 'Turn it on', remove_all: 'Remove all of it', bulk: 'Approve all' };

/** Ask before a change the user started themselves. Resolves true when they confirm. */
function confirmAction(a) {
  return new Promise((resolve) => {
    const d = document.createElement('dialog');
    d.className = 'confirm';
    d.setAttribute('aria-labelledby', 'confirm-title');
    d.innerHTML = `<h2 id="confirm-title">${esc(a.reason)}</h2>
      ${a.items?.length ? `<ul class="confirm-list">${a.items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
      ${UNDO[a.type] ? `<p class="undo">${icon('undo')}${esc(UNDO[a.type])}</p>` : ''}
      <p class="muted small">Touch ID (or your password) confirms it. Nothing happens if you cancel.</p>
      <div class="row"><button class="btn primary" value="ok">${esc(a.type === 'safe_dns' && a.target?.on === false ? 'Turn it off' : VERB[a.type] ?? 'Do it')}</button><button class="btn ghost" value="cancel">Cancel</button></div>`;
    document.body.append(d);
    const done = (ok) => { d.close(); d.remove(); resolve(ok); };
    d.addEventListener('click', (e) => { const b = e.target.closest('button[value]'); if (b) done(b.value === 'ok'); else if (e.target === d) done(false); });
    d.addEventListener('cancel', (e) => { e.preventDefault(); done(false); });
    d.showModal();
    d.querySelector('button[value="ok"]').focus();
  });
}

/** A change you started from a button: confirm, then do it now. Approvals is only for what an AI suggests. */
async function propose(a) {
  if (!(await confirmAction(a))) return;
  let created;
  try { created = await api('/api/actions', { method: 'POST', body: a }); } catch (e) { toast(e.message); return; }
  closeDrawer();
  toast('Confirm with Touch ID on your Mac…');
  try {
    const r = await api(`/api/actions/${created.id}/approve`, { method: 'POST' });
    toast(r.status === 'executed' ? `Done. ${r.result}` : `It did not work. ${r.result}`, r.status === 'executed' ? undefined : { label: 'Ask AI', fn: () => askAI('That change did not work. Explain why in plain words and tell me what I can do instead.', { kind: 'failed-action', summary: created.summary, error: r.result }) });
  } catch (e) {
    // Touch ID cancelled: drop it rather than leave it waiting in Approvals.
    await api(`/api/actions/${created.id}/reject`, { method: 'POST' }).catch(() => {});
    toast(/cancel|not approved/i.test(e.message) ? 'Cancelled. Nothing changed.' : e.message);
  }
  render();
}

/** Approve (one Touch ID) or reject everything that is waiting. */
async function bulk(approveThem) {
  const pending = await api('/api/actions?status=pending');
  if (!pending.length) return;
  const ids = pending.map((a) => a.id);
  if (!approveThem) { await api('/api/actions/reject-all', { method: 'POST', body: { ids } }); toast(`Rejected ${plural(ids.length, 'action')}. Nothing changed.`); render(); return; }
  const ok = await confirmAction({ type: 'bulk', reason: `Approve all ${ids.length} waiting changes?`, items: pending.map((a) => a.summary), target: {} });
  if (!ok) return;
  state.busyAll = true; render();
  toast('Confirm with Touch ID on your Mac…');
  try {
    const r = await api('/api/actions/approve-all', { method: 'POST', body: { ids } });
    toast(r.failed.length ? `Done ${r.done}. ${plural(r.failed.length, 'item')} did not work: ${r.failed[0].summary}.` : `Done. All ${plural(r.done, 'change')} made.`);
  } catch (e) { toast(/not approved|cancel/i.test(e.message) ? 'Cancelled. Nothing changed.' : e.message); }
  finally { state.busyAll = false; render(); }
}

async function approve(id) {
  state.busy.add(id);
  if (state.view === 'approvals') render();
  toast('Confirm with Touch ID on your Mac…');
  try {
    const r = await api(`/api/actions/${id}/approve`, { method: 'POST' });
    toast(r.status === 'executed' ? `Done. ${r.result}` : `Failed: ${r.result}`);
    if (r.status === 'executed') await leaveRow(rowFor(id), 'ok');
    for (const m of chat.messages) for (const a of m.actions ?? []) if (a.id === id) a.status = r.status;
  } catch (e) { toast(e.message); }
  finally { state.busy.delete(id); render(); renderChat(); }
}

document.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-act], [data-close], a[data-min], a[data-tier]');
  if (!el) return;
  if (el.matches('[data-close]')) return closeDrawer();
  if (el.dataset.act === 'dock-close') return closeDock();
  if (el.matches('a[data-min]')) { state.fMin = el.dataset.min; state.fStatus = 'open'; return; }
  if (el.matches('a[data-tier]')) { state.fTier = el.dataset.tier; state.fStatus = 'open'; return; }
  const act = el.dataset.act;
  if (act === 'ask') ev.stopPropagation();
  try {
    if (act === 'ask') await askAI(el.dataset.prompt, el.dataset.ctx ? JSON.parse(el.dataset.ctx) : null);
    else if (act === 'assistant') await openAssistant();
    else if (act === 'retry') render();
    else if (act === 'handoff') await handoff(el.dataset.prompt, el.dataset.ctx ? JSON.parse(el.dataset.ctx) : null);
    else if (act === 'handoff-chat') { const last = [...chat.messages].reverse().find((m) => m.role === 'user'); const lastAi = [...chat.messages].reverse().find((m) => m.role === 'assistant'); await handoff(last?.text, lastAi?.ctx ?? chat.ctx); }
    else if (act === 'ai-handoff') { await api('/api/ai/config', { method: 'POST', body: { handoff: el.dataset.v } }); toast('Saved.'); render(); }
    else if (act === 'finding') await openFinding(el.dataset.id);
    else if (act === 'item') openItem(JSON.parse(el.dataset.ctx));
    else if (act === 'startup') {
      const i = state.startupItems?.[Number(el.dataset.i)];
      if (!i) return;
      const reason = i.flags.map((f) => FLAG[f]?.[0]).filter(Boolean).join(', ');
      openItem({ kindLabel: KINDS[i.kind]?.[0] ?? 'Startup item', title: i.label, subtitle: reason ? `Flagged: ${reason}` : i.isNew ? 'New since I started watching' : 'Nothing unusual found',
        explain: `${KINDS[i.kind]?.[1] ?? ''} ${i.flags.includes('unsigned') ? 'This one has no verified developer identity, which is normal for tools you built or installed with Homebrew and unusual for downloaded apps.' : ''} ${i.flags.includes('missing-program') ? 'The program it points to no longer exists, so it is a harmless leftover.' : ''} ${i.flags.includes('script-download') ? 'It downloads or decodes something and runs it at startup, a classic malware pattern.' : ''}`.trim(),
        facts: { Program: home(i.program), 'Signed by': i.signer, Plist: home(i.plist), 'Runs at login': i.runAtLoad ? 'Yes' : undefined, 'Kept alive': i.keepAlive ? 'Yes' : undefined, 'First seen': day(i.firstSeen), Permissions: i.details?.permissions },
        buttons: i.plist && !i.plist.startsWith('/System') ? `<div class="row">${i.program ? `<button class="btn" data-act="dossier" data-q="${esc(i.program)}">Investigate program</button>` : ''}<button class="btn danger" data-act="propose" data-a="${attr({ type: 'disable_persistence', target: { plist: i.plist, label: i.label }, reason: `Disable startup item ${i.label}` })}">Disable and quarantine…</button></div>` : '',
        ai: { kind: 'startup-item', label: i.label, type: i.kind, program: i.program, signer: i.signer, flags: i.flags, isNew: i.isNew, details: i.details } });
    }
    else if (act === 'expand') { const k = el.dataset.key; state.expanded.has(k) ? state.expanded.delete(k) : state.expanded.add(k); render(); }
    else if (act === 'propose') await propose(JSON.parse(el.dataset.a));
    else if (act === 'open-uninstaller') { const r = await api('/api/open-uninstaller', { method: 'POST', body: { app: el.dataset.v } }); toast(`Opened ${r.name}. Follow its steps to remove the app.`); }
    else if (act === 'ignore') await ignoreFinding(el.dataset.id);
    else if (act === 'snooze') await ignoreFinding(el.dataset.id, Number(el.dataset.days) || 7);
    else if (act === 'unignore') await unignoreFinding(el.dataset.id);
    else if (act === 'unignore-all') {
      const list = await api('/api/findings?status=acknowledged&min=info');
      el.disabled = true;
      await Promise.all(list.map((f) => api(`/api/findings/${encodeURIComponent(f.id)}/reopen`, { method: 'POST' })));
      render();
      toast(`Brought back ${plural(list.length, 'warning')}. I’ll warn you about them again.`);
    }
    else if (act === 'approve') await approve(el.dataset.id);
    else if (act === 'approve-all' || act === 'reject-all') await bulk(act === 'approve-all');
    else if (act === 'restore-action') {
      const r = await api(`/api/actions/${el.dataset.id}/restore`, { method: 'POST' });
      await leaveRow(el.closest('#main .item'), 'no');
      state.archiveOpen = true;
      toast(`Back on your list: ${plainIds(r.summary)}`); render();
    }
    else if (act === 'dismiss-action') {
      await api(`/api/actions/${el.dataset.id}/reject`, { method: 'POST' });
      await leaveRow(el.closest('#main .item'), 'no');
      state.archiveOpen = true;
      toast('Dismissed. Nothing was changed.'); render();
    }
    else if (act === 'reject') { await api(`/api/actions/${el.dataset.id}/reject`, { method: 'POST' }); toast('Rejected.'); await leaveRow(el.closest("#main .item"), 'no'); for (const m of chat.messages) for (const a of m.actions ?? []) if (a.id === el.dataset.id) a.status = 'rejected'; render(); renderChat(); }
    else if (act === 'agent') { state.agentOpen = el.dataset.id; render(); }
    else if (act === 'net-all') { state.netAll = el.dataset.v === '1'; render(); }
    else if (act === 'net-system') { state.netSystem = true; render(); }
    else if (act === 'fstatus') { state.fStatus = el.dataset.v; render(); }
    else if (act === 'ftier') { state.fTier = el.dataset.v; render(); }
    else if (act === 'process') await openProcess(Number(el.dataset.pid));
    else if (act === 'scan' || act === 'scan-quick') { const p = act === 'scan-quick' ? el.dataset.v : $('#scan-path').value.trim(); if (!p) return; await api('/api/scans', { method: 'POST', body: { paths: [p] } }); toast('Scan started.'); render(); }
    else if (act === 'block') { const d = $('#block-domain').value.trim(); if (d) await propose({ type: 'block_domain', target: { domain: d }, reason: `Block ${d} (requested from the dashboard)` }); }
    else if (act === 'run') { await api(`/api/run/${el.dataset.v}`, { method: 'POST' }); toast(`Running ${el.dataset.v}…`); }
    else if (act === 'sql-ex') { state.sql = el.dataset.v; $('#sql').value = state.sql; }
    else if (act === 'sql') { state.sql = $('#sql').value; el.disabled = true; try { state.sqlResult = await api('/api/osquery', { method: 'POST', body: { sql: state.sql } }); } catch (e) { state.sqlResult = { rows: [], error: e.message }; } render(); }
    else if (act === 'settings-pane') { await api(`/api/open-settings/${el.dataset.v}`, { method: 'POST' }); toast('Opened System Settings.'); }
    else if (act === 'ai-connect') { const r = await api('/api/ai/connect', { method: 'POST' }); toast(r.ok ? 'Terminal opened. Finish signing in, then ask again.' : r.error); state.ai = null; setTimeout(() => { if (state.view === 'settings') render(); }, 15000); }
    else if (act === 'ai-provider') { const r = await api('/api/ai/config', { method: 'POST', body: { provider: el.dataset.v } }); state.ai = r.status; render(); }
    else if (act === 'ai-model') { await api('/api/ai/config', { method: 'POST', body: { model: el.dataset.v } }); toast('Model updated.'); render(); }
    else if (act === 'ai-save-key') { const key = $('#ai-key').value.trim(); const r = await api('/api/ai/config', { method: 'POST', body: { ...(key ? { apiKey: key } : {}), extraHeaders: $('#ai-headers').value } }); state.ai = r.status; toast(r.status.ready ? 'Saved. The assistant is ready.' : r.status.detail); render(); }
    else if (act === 'ai-clear-key') { await api('/api/ai/config', { method: 'POST', body: { apiKey: '' } }); render(); }
    else if (act === 'ctx-clear') { chat.ctx = null; renderChat(); }
    else if (act === 'stop') chat.abort?.abort();
    else if (act === 'new-chat') { chat.threadId = null; chat.messages = []; chat.ctx = null; if (state.view === 'assistant') render(); else renderChat(); }
    else if (act === 'thread') { await loadThread(el.dataset.id); document.querySelectorAll('.thread').forEach((t) => t.classList.toggle('on', t.dataset.id === el.dataset.id)); }
  } catch (e) { if (e.message !== 'unauthorized') toast(e.message); }
});

document.addEventListener('submit', (e) => {
  if (e.target.id !== 'ask-form') return;
  e.preventDefault();
  const input = $('#ask-input', e.target);
  const v = input.value.trim();
  if (!v || chat.busy) return;
  input.value = '';
  askAI(v, null);
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('#drawer').hidden) closeDrawer();
  else if (e.key === 'Escape' && !$('#dock').hidden && $('#dock').contains(document.activeElement)) closeDock();
  if (e.target.id === 'ask-input' && e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); e.target.form.requestSubmit(); }
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.item[data-act]')) { e.preventDefault(); e.target.click(); }
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openAssistant(); }
});
document.addEventListener('input', (e) => {
  if (e.target.id === 'ask-input') autosize(e.target);
  if (e.target.id === 'net-filter') { state.netFilter = e.target.value; clearTimeout(state.ft); state.ft = setTimeout(() => render(true), 250); }
});
document.addEventListener('change', (e) => {
  if (e.target.id === 'f-cat') { state.fCat = e.target.value; render(); }
  if (e.target.id === 'f-min') { state.fMin = e.target.value; render(); }
});
window.addEventListener('scroll', () => $('#topbar').classList.toggle('scrolled', window.scrollY > 4), { passive: true });

async function openProcess(pid) {
  const p = await api(`/api/process/${pid}`);
  if (p.error) return toast(p.error);
  const ctx = { kind: 'process', name: p.name, pid: p.pid, path: p.path, signer: p.signer, startedBy: p.parents.map((x) => x.name), agent: p.agent, unusualLocation: p.unusualLocation };
  drawer(`<div class="drawer-head"><span class="chip">${esc(p.signer)}</span><span class="right"></span><button class="btn ghost icon-btn" data-close aria-label="Close">${icon('x')}</button></div>
  <div class="drawer-body">
    <div><h2 id="drawer-title">${esc(p.name)} <span class="faint" style="font-weight:500">pid ${p.pid}</span></h2>${p.note ? `<p class="muted" style="margin:6px 0 0">${esc(p.note)}</p>` : ''}</div>
    ${p.unusualLocation ? `<div class="status flag" style="margin:0"><div class="ico">${icon('alert', 'lg')}</div><div><b>Runs from ${esc(p.unusualLocation)}</b><span class="sub">Legitimate apps rarely do.</span></div></div>` : ''}
    <div><p class="label">Ask Hashling about it</p>${quickChips(ctx)}</div>
    <dl class="kv"><dt>Runs as</dt><dd>${String(p.user) === '0' || p.user === 'root' ? 'The system (administrator)' : String(p.user) === '501' || p.user === 'you' ? 'You' : `Another user (${esc(p.user)})`}</dd><dt>Started</dt><dd>${esc(p.started ? (Number.isNaN(Date.parse(p.started)) ? p.started : new Date(p.started).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })) : '')}</dd><dt>Processor / memory</dt><dd>${p.cpu ?? '?'}% / ${p.mem ?? '?'}%</dd>
    <dt>Started by</dt><dd>${p.parents.map((x) => `${esc(x.name)}${x.agent ? ` <span class="chip agent">${esc(x.agent)}</span>` : ''}`).join(' ← ') || 'macOS'}</dd><dt>Programs it started</dt><dd>${p.children.filter((c) => !/^[(<]/.test(c.name)).map((c) => esc(c.name)).join(', ') || 'None'}</dd></dl>
    <details class="fold" style="border:1px solid var(--line);border-radius:12px"><summary>Technical details</summary><div class="fold-body"><dl class="kv"><dt>Path</dt><dd class="mono small wrap">${esc(p.path)}</dd><dt>Command</dt><dd class="mono small wrap">${esc(p.commandLine)}</dd><dt>Open files</dt><dd><pre>${esc(p.openFiles.join('\n') || 'None visible')}</pre></dd></dl></div></details>
    <div class="row"><button class="btn" data-act="dossier" data-q="${esc(p.path)}">Investigate app</button><button class="btn danger" data-act="propose" data-a="${attr({ type: 'kill_process', target: { pid: p.pid, name: p.name }, reason: `Quit ${p.name}` })}">Quit process…</button>${p.path.startsWith('/') && !p.path.startsWith('/System') ? `<button class="btn" data-act="propose" data-a="${attr({ type: 'quarantine_file', target: { path: p.path }, reason: `Quarantine ${p.name}` })}">Quarantine file…</button>` : ''}</div>
  </div>`);
}

// ---------- routing & live updates ----------
function renderNav() {
  $('#nav').innerHTML = NAV.map(([group, items]) => `${group ? `<div class="nav-group">${group}</div>` : '<div style="height:6px"></div>'}${items.map(([id, label, ic, area]) => {
    const s = area ? state.sus[area] : null;
    const flag = s?.count ? `<span class="dotflag" style="background:var(--high)" title="${plural(s.count, 'suspicious thing')}"></span>` : s?.risks?.length ? `<span class="dotflag" style="background:var(--warn)" title="${plural(s.risks.length, 'thing')} worth fixing"></span>` : '';
    const badge = id === 'approvals' ? '<span class="badge hot" id="n-approvals"></span>' : id === 'findings' ? '<span class="badge" id="n-findings"></span>' : id === 'ignored' ? '<span class="badge" id="n-ignored"></span>' : '';
    return `<a href="#/${id}" data-v="${id}" class="${state.view === id ? 'active' : ''}">${icon(ic)}${label}${flag}${badge}</a>`;
  }).join('')}`).join('');
  placePill($('#nav'), state.pillView !== undefined && state.pillView !== state.view);
  state.pillView = state.view;
}

let rendering = false, again = false;

// ---------- Motion ----------
function calm() { return matchMedia("(prefers-reduced-motion: reduce)").matches; }

/** Page arrival: number the sections and the first rows of each list so CSS can cascade them in. */
function enterView(root) {
  [...root.children].forEach((el, i) => el.style.setProperty('--i', i));
  for (const list of root.querySelectorAll('.list, .suggest, tbody')) {
    [...list.children].slice(0, 8).forEach((el, j) => { el.classList.add('stagger'); el.style.setProperty('--j', j); });
  }
  root.classList.add('view-enter');
}

/**
 * The one authored moment: the score ring draws itself in on arrival, and when the score
 * changes while you watch, it slides from the old value to the new one and the number counts.
 */
let scoreRun = null;
function animateScore(root) {
  const wrap = root.querySelector('.ring[aria-label^="Security score"]');
  if (!wrap) return;
  const to = Number(wrap.getAttribute('aria-label').match(/\d+/)?.[0] ?? 0);
  const arc = wrap.querySelector('svg circle:last-of-type');
  if (!arc || calm()) { state.shownScore = to; return; }
  const now = performance.now();
  // A live refresh rebuilt the ring mid-count: carry on from where it was.
  if (scoreRun && scoreRun.to === to && now < scoreRun.t0 + scoreRun.dur) return drawScore(arc, now - scoreRun.t0);
  const from = state.shownScore ?? 0;
  state.shownScore = to;
  if (from === to) return;
  scoreRun = { from, to, t0: now, dur: from === 0 ? 900 : 650, c: Number(arc.getAttribute('stroke-dasharray')) };
  drawScore(arc, 0);
  const ease = (x) => 1 - (1 - x) ** 4;
  const run = scoreRun;
  const tick = (t) => {
    if (run !== scoreRun) return;
    const k = Math.min(1, (t - run.t0) / run.dur);
    const num = document.querySelector('#main .ring .num b');
    if (num) num.textContent = Math.round(run.from + (run.to - run.from) * ease(k));
    if (k < 1) requestAnimationFrame(tick);
    else if (num) { num.classList.remove('settle'); void num.offsetWidth; num.classList.add('settle'); }
  };
  requestAnimationFrame(tick);
}
function drawScore(arc, elapsed) {
  const r = scoreRun;
  const a = arc.animate([{ strokeDashoffset: r.c * (1 - r.from / 100) }, { strokeDashoffset: r.c * (1 - r.to / 100) }], { duration: r.dur, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' });
  a.currentTime = elapsed;
  if (elapsed) { const num = arc.closest('.ring').querySelector('.num b'); if (num) num.textContent = Math.round(r.from + (r.to - r.from) * (1 - (1 - elapsed / r.dur) ** 4)); }
}

/** A decided row leaves: approve shows a tick, then the row folds shut; reject just slides off. */
async function leaveRow(row, kind) {
  if (!row || !row.isConnected) return;
  row.classList.add('leaving', kind);
  if (calm()) { await row.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 200, fill: 'forwards' }).finished; return; }
  if (kind === 'ok') {
    row.insertAdjacentHTML('beforeend', '<span class="done-tick" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></span>');
    await new Promise((r) => setTimeout(r, 520));
  }
  const h = row.offsetHeight;
  await row.animate([
    { opacity: 1, transform: 'translateX(0)', height: `${h}px` },
    { opacity: 0, transform: `translateX(${kind === 'ok' ? 0 : 16}px)`, height: `${h}px`, offset: 0.45 },
    { opacity: 0, transform: `translateX(${kind === 'ok' ? 0 : 16}px)`, height: '0px', paddingTop: '0px', paddingBottom: '0px', borderTopWidth: '0px' },
  ], { duration: kind === 'ok' ? 340 : 280, easing: 'cubic-bezier(0.77, 0, 0.175, 1)', fill: 'forwards' }).finished;
}
const rowFor = (id) => document.querySelector(`#main [data-act="approve"][data-id="${CSS.escape(id)}"]`)?.closest('.item');

/** The sidebar highlight: one pill that glides from the old page to the new one. */
function placePill(nav, animate) {
  const active = nav.querySelector('a.active');
  let pill = nav.querySelector('.nav-pill');
  if (!active) { pill?.remove(); nav.classList.remove('has-pill'); return; }
  if (!pill) { pill = document.createElement('span'); pill.className = 'nav-pill'; nav.prepend(pill); }
  nav.classList.add('has-pill');
  const from = state.pillBox;
  const box = { x: active.offsetLeft, y: active.offsetTop, w: active.offsetWidth, h: active.offsetHeight };
  const set = (b) => { pill.style.transform = `translate(${b.x}px, ${b.y}px)`; pill.style.width = `${b.w}px`; pill.style.height = `${b.h}px`; };
  if (animate && from && !calm()) {
    pill.classList.add('instant'); set(from); void pill.offsetWidth; pill.classList.remove('instant');
  } else pill.classList.add('instant');
  requestAnimationFrame(() => { set(box); if (!animate) requestAnimationFrame(() => pill.classList.remove('instant')); });
  state.pillBox = box;
  // Phones show the sections as a sideways strip: keep the current one in view.
  if (animate && innerWidth <= 760) active.scrollIntoView({ inline: 'nearest', block: 'nearest', behavior: calm() ? 'auto' : 'smooth' });
}

/** Badges pop when their number changes. */
function setBadge(el, value) {
  if (!el) return;
  const next = String(value || '');
  if (el.textContent !== next && next && el.dataset.seen && !calm()) { el.classList.remove('pop'); void el.offsetWidth; el.classList.add('pop'); }
  el.textContent = next;
  el.dataset.seen = '1';
}

// Opening a fold plays its reveal once; live refreshes rebuild open folds without replaying it.
document.addEventListener('toggle', (e) => {
  const d = e.target;
  if (!(d instanceof HTMLDetailsElement)) return;
  if (d.classList.contains('archive')) state.archiveOpen = d.open;
  if (!d.open) return;
  d.classList.add('just-opened');
  setTimeout(() => d.classList.remove('just-opened'), 320);
}, true);

/**
 * Side-by-side columns: when one runs much longer than its neighbour, shorten its longest
 * list to match and add "Show N more". Inner grids first, so outer ones measure final heights.
 */
const expandedCols = new Set();
function balance(root) {
  for (const b of root.querySelectorAll('.more-btn[data-balance]')) b.remove();
  for (const el of root.querySelectorAll('.clamped')) el.classList.remove('clamped');
  const grids = [...root.querySelectorAll('.g2, .g3, .split, .home')];
  grids.slice().reverse().forEach((grid) => {
    const cols = [...grid.children].filter((c) => c.offsetParent && c.offsetHeight);
    if (cols.length < 2 || new Set(cols.map((c) => c.offsetTop)).size !== 1) return; // stacked on small screens
    const hs = cols.map((c) => c.offsetHeight);
    const tall = hs.indexOf(Math.max(...hs));
    const target = Math.max(...hs.filter((_, i) => i !== tall));
    const key = `${state.view}:${grids.indexOf(grid)}:${tall}`;
    if (hs[tall] - target < 160) return;
    // Shorten the longest lists first, one at a time, until the column fits (each keeps at least 4 rows).
    const lists = [...cols[tall].querySelectorAll('.list, .dest-list, tbody')].filter((l) => l.offsetHeight && !l.closest('details:not([open])') && l.children.length > 5).sort((x, y) => y.offsetHeight - x.offsetHeight);
    let excess = hs[tall] - target;
    lists.forEach((list, n) => {
      if (excess <= 0) return;
      const items = [...list.children];
      let hidden = 0;
      excess += 44; // the button takes some room back
      for (let i = items.length - 1; i >= 4 && excess > 0; i--) { excess -= items[i].offsetHeight; items[i].classList.add('clamped'); hidden++; }
      if (hidden < 2) { items.forEach((it) => it.classList.remove('clamped')); excess -= 44; return; }
      const k = `${key}:${n}`;
      if (expandedCols.has(k)) { items.forEach((it) => it.classList.remove('clamped')); return; }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn sm more-btn';
      btn.dataset.balance = k;
      btn.textContent = `Show ${hidden} more`;
      btn.addEventListener('click', () => { expandedCols.add(k); items.forEach((it) => it.classList.remove('clamped')); btn.remove(); });
      (list.tagName === 'TBODY' ? list.closest('table') ?? list : list).after(btn);
    });
  });
}
let balanceTimer;
addEventListener('resize', () => { clearTimeout(balanceTimer); balanceTimer = setTimeout(() => { if (!$('#dock').hidden) $('.shell').style.setProperty('--dock-w', `${clampDock(dockPrefs.w ?? 420)}px`); balance(page); }, 150); });

async function render(keepFocus = false) {
  if (rendering) { again = true; return; }
  rendering = true;
  const focusId = keepFocus ? document.activeElement?.id : null;
  const caret = focusId ? document.activeElement.selectionStart : null;
  try {
    state.sus = await api('/api/suspicious').catch(() => state.sus);
    const html = await views[state.view]();
    const y = window.scrollY;
    if (state.view === 'assistant' && $('#chat-area')) {
      // keep the live chat; only refresh the thread list
      const tmp = document.createElement('div'); tmp.innerHTML = html;
      $('.threads')?.replaceWith(tmp.querySelector('.threads'));
    } else {
      page.classList.remove('view-enter');
      page.innerHTML = html;
      window.W?.hydrate?.(page);
      balance(page);
      if (state.entering) { state.entering = false; enterView(page); }
      animateScore(page);
      if (state.view === 'assistant') renderChat();
    }
    window.scrollTo(0, y);
    if (focusId) { const el = document.getElementById(focusId); el?.focus(); if (caret != null) el?.setSelectionRange?.(caret, caret); }
  } catch (e) {
    if (e.message === 'offline') {
      state.offline = true;
      page.innerHTML = `<div class="card empty-state"><div class="step"><span class="spin"></span>Reconnecting\u2026</div><p class="muted small">I’m restarting or busy for a moment. This page refreshes by itself as soon as I’m back.</p></div>`;
    } else if (e.message !== 'unauthorized') {
      page.innerHTML = `<div class="card empty-state"><span class="ico">${icon('alert', 'lg')}</span><p class="h2">Couldn\u2019t load this page</p><p class="muted">${esc(e.message)}</p><button class="btn" data-act="retry">Try again</button></div>`;
    }
  } finally {
    rendering = false;
    renderNav();
    updateBadges();
    if (again) { again = false; render(keepFocus); }
  }
}

async function updateBadges() {
  try {
    const o = await api('/api/overview');
    const n = (o.openFindings.critical ?? 0) + (o.openFindings.high ?? 0) + (o.openFindings.medium ?? 0);
    // renderNav rebuilds the badges, so remember the last numbers to know when one changed.
    for (const [id, v] of [['n-approvals', o.pendingActions], ['n-findings', n], ['n-ignored', o.ignoredFindings]]) {
      const el = $(`#${id}`); if (!el) continue;
      const before = state.badges?.[id];
      el.textContent = before ? String(before) : ''; if (before !== undefined) el.dataset.seen = '1';
      setBadge(el, v);
      (state.badges ??= {})[id] = v || '';
    }
    $('#side-score').innerHTML = `<span class="mini-ring">${ring(o.score, 38, 5)}</span><div><b>${o.score} / 100</b><span>${esc(o.verdict)}</span></div>`;
  } catch { /* ignore */ }
}

function route() {
  const [v, query = ''] = (location.hash.replace(/^#\//, '') || 'overview').split('?');
  const deepId = new URLSearchParams(query).get('id');
  const prev = state.view;
  state.view = views[v] ? v : 'overview';
  document.body.dataset.view = state.view;
  const [t, s] = TITLES[state.view];
  $('#title').textContent = t;
  $('#subtitle').textContent = s;
  document.title = `${t} · Hashling`;
  closeDrawer();
  if (state.view === 'assistant' && !$('#dock').hidden) setDock(false);
  if (prev !== state.view) { page.classList.remove('view-enter'); page.innerHTML = '<div class="loading">Loading…</div>'; state.entering = true; if (state.view !== 'overview') state.shownScore = undefined; }
  render();
  window.scrollTo(0, 0);
  // Notifications deep-link to #/findings?id=<finding id>.
  if (deepId && state.view === 'findings') openFinding(deepId).catch((e) => toast(e.message));
}
window.addEventListener('hashchange', route);
// Reopen the assistant if it was open last time.
if (dockPrefs.open) setTimeout(() => { if (state.view !== 'assistant') openAssistant(); }, 0);

const LIVE = { ignored: ['findings', 'posture', 'network', 'agents', 'persistence', 'permissions', 'trackers', 'location', 'malware'], network: ['network'], overview: null, agents: ['agents', 'network'], approvals: ['action', 'scan'], scans: ['scan', 'malware', 'attackPacks'], findings: ['findings'], timeline: ['event'], startup: ['persistence'], permissions: ['permissions'], tracking: ['trackers', 'location'], system: ['posture', 'status'] };
/** After Hashling comes back: reload if the dashboard was updated, otherwise just refresh the view. */
async function onReconnect() {
  try {
    const h = await (await fetch('/api/health', { credentials: 'same-origin' })).json();
    if (state.ui && h.ui && h.ui !== state.ui) { location.reload(); return; }
    state.ui = h.ui;
  } catch { /* the stream will retry */ }
  if (state.offline) { state.offline = false; render(); }
}

function connect() {
  const es = new EventSource('/api/stream');
  es.onopen = () => { $('#live').classList.add('on'); onReconnect(); };
  es.onerror = () => $('#live').classList.remove('on');
  es.addEventListener('change', (e) => {
    const changed = JSON.parse(e.data);
    window.W?.buddyOnChange?.();
    const want = LIVE[state.view];
    const typing = ['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement?.tagName);
    if (!$('#drawer').hidden || want === undefined || (typing && state.view !== 'network')) { updateBadges(); return; }
    if (want === null || changed.some((c) => want.includes(c))) render(typing); else updateBadges();
  });
}

/** The mascot artwork. Four bars, so each one can move on its own. */
function hashlingSvg(cls = '') {
  return `<svg class="hashling ${cls}" viewBox="0 0 120 120" aria-hidden="true">
    <ellipse class="hl-shadow" cx="60" cy="112" rx="30" ry="5"/>
    <g class="hl-body">
      <rect class="hl-bar" x="38" y="10" width="15" height="98" rx="7.5" transform="skewX(-10)" transform-origin="45.5 59" fill="url(#hl-g)"/>
      <rect class="hl-bar" x="67" y="10" width="15" height="98" rx="7.5" transform="skewX(-10)" transform-origin="74.5 59" fill="url(#hl-g)"/>
      <g class="hl-arm"><rect x="16" y="36" width="90" height="15" rx="7.5" fill="url(#hl-g)"/><rect x="24" y="39" width="34" height="4" rx="2" fill="#fff" opacity=".4"/></g>
      <g class="hl-low"><rect x="13" y="68" width="90" height="15" rx="7.5" fill="url(#hl-g)"/><rect x="21" y="71" width="34" height="4" rx="2" fill="#fff" opacity=".4"/></g>
    </g>
  </svg>`;
}
// One shared gradient for every Hashling on the page (a copy inside a hidden one would not paint).
document.body.insertAdjacentHTML('afterbegin', '<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs><linearGradient id="hl-g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8B7DFB"/><stop offset="1" stop-color="#5F4FE0"/></linearGradient></defs></svg>');

// Deeper views (dossiers, storylines, traffic, processes, downloads, storage) live in insights.js.
window.W = { friendlyName, $, page, esc, attr, icon, P, NAV, TITLES, AREA_META, LIVE, CAT, views, state, api, ago, clock, day, rate, bytes, sev, plural, home, toast, askBtn, askIcons, quickChips, drawer, closeDrawer, findingItem, statusBar, propose, askAI, render, ring, leaveRow };
window.W.openAssistant = openAssistant;
window.W.hashlingSvg = hashlingSvg;
try { await import('./insights.js'); } catch (e) { console.error('Hashling insights did not load', e); }
try { await import('./protect.js'); } catch (e) { console.error('Hashling protection pages did not load', e); }
try { await import('./guide.js'); } catch (e) { console.error('Hashling guide did not load', e); }
try { await import('./buddy.js'); } catch (e) { console.error('Hashling helper did not load', e); }

renderNav();
route();
connect();
