/**
 * Hashling on your phone. Every request is sealed with the key from the QR code (see seal.js)
 * and sent to /p/<phone id>; the Mac opens it, does the work, and seals the answer back.
 */
import { seal, open, b64u } from '/seal.js';

const $ = (s, el = document) => el.querySelector(s);
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const te = new TextEncoder();
const td = new TextDecoder();
const calm = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const view = $('#view');

// ---------- Pairing and the sealed channel ----------
const CRED = 'hashling.phone';
let cred = (() => { try { return JSON.parse(localStorage.getItem(CRED)); } catch { return null; } })();
if (location.hash.length > 20) {
  const [id, key] = location.hash.slice(1).split('.');
  if (id && key) { cred = { id, key }; try { localStorage.setItem(CRED, JSON.stringify(cred)); } catch { /* private tab */ } }
  // The key never needs to be seen again: take it out of the address bar and history.
  history.replaceState(null, '', location.pathname);
}
const forget = () => { cred = null; try { localStorage.removeItem(CRED); } catch { /* private tab */ } };

const deviceName = () => (/iPhone/.test(navigator.userAgent) ? 'iPhone' : /iPad/.test(navigator.userAgent) ? 'iPad' : /Android/.test(navigator.userAgent) ? 'Android phone' : 'phone');

class Gone extends Error {}
async function call(method, path, body, bin) {
  if (!cred) throw new Gone('none');
  const key = b64u.dec(cred.key);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const msg = { t: Date.now(), r: b64u.enc(crypto.getRandomValues(new Uint8Array(12))), device: deviceName(), method, path, body, bin };
  const sealed = seal(key, nonce, te.encode(JSON.stringify(msg)), te.encode(`hashling-phone:${cred.id}:req`));
  let res;
  try {
    res = await fetch(`/p/${encodeURIComponent(cred.id)}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ n: b64u.enc(nonce), c: b64u.enc(sealed) }) });
  } catch { throw new Error('offline'); }
  if (res.status === 404 || res.status === 401) { forget(); throw new Gone('forgotten'); }
  if (res.status === 410) { forget(); throw new Gone('expired'); }
  if (res.status === 429) throw new Error('Too many tries. Wait a minute.');
  const j = await res.json();
  const out = JSON.parse(td.decode(open(key, b64u.dec(j.n), b64u.dec(j.c), te.encode(`hashling-phone:${cred.id}:res`))));
  if (out.status >= 400) throw new Error(out.body?.error || 'Something went wrong.');
  return out.body;
}
const get = (path) => call('GET', path);
const post = (path, body, bin) => call('POST', path, body, bin);

// ---------- Small pieces ----------
function hashlingSvg(cls = '') {
  return `<svg class="hashling ${cls}" viewBox="0 0 120 120" aria-hidden="true">
    <ellipse class="hl-shadow" cx="60" cy="112" rx="30" ry="5"/>
    <g class="hl-body">
      <rect x="38" y="10" width="15" height="98" rx="7.5" transform="skewX(-10)" transform-origin="45.5 59" fill="url(#hl-g)"/>
      <rect x="67" y="10" width="15" height="98" rx="7.5" transform="skewX(-10)" transform-origin="74.5 59" fill="url(#hl-g)"/>
      <rect x="16" y="36" width="90" height="15" rx="7.5" fill="url(#hl-g)"/><rect x="24" y="39" width="34" height="4" rx="2" fill="#fff" opacity=".4"/>
      <rect x="13" y="68" width="90" height="15" rx="7.5" fill="url(#hl-g)"/><rect x="21" y="71" width="34" height="4" rx="2" fill="#fff" opacity=".4"/>
    </g>
  </svg>`;
}
document.body.insertAdjacentHTML('afterbegin', '<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs><linearGradient id="hl-g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8B7DFB"/><stop offset="1" stop-color="#5F4FE0"/></linearGradient></defs></svg>');
$('#mark').innerHTML = hashlingSvg();

const ICON = {
  chev: '<svg viewBox="0 0 24 24" class="i"><path d="m9 6 6 6-6 6"/></svg>',
  alert: '<svg viewBox="0 0 24 24" class="i"><path d="M12 4 2.8 19.5h18.4z"/><path d="M12 10v4.5M12 17.2v.1"/></svg>',
  check: '<svg viewBox="0 0 24 24" class="i"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>',
  wifi: '<svg viewBox="0 0 24 24" class="i"><path d="M3 9.5a13.5 13.5 0 0 1 18 0M6 13a8.5 8.5 0 0 1 12 0M9 16.4a3.6 3.6 0 0 1 6 0"/><path d="M12 19.6v.1"/></svg>',
  image: '<svg viewBox="0 0 24 24" class="i"><rect x="3.5" y="5" width="17" height="14" rx="2.5"/><circle cx="9" cy="10" r="1.6"/><path d="m4 17 5-4.5 4 3.5 2.5-2 4.5 3.5"/></svg>',
  send: '<svg viewBox="0 0 24 24" class="i"><path d="M12 19V5M6 11l6-6 6 6"/></svg>',
  mac: '<svg viewBox="0 0 24 24" class="i"><rect x="3.5" y="5" width="17" height="11" rx="1.6"/><path d="M2 19h20"/></svg>',
  undo: '<svg viewBox="0 0 24 24" class="i"><path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/></svg>',
};

function ring(score, size = 132, stroke = 11) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = score >= 80 ? 'var(--ok)' : score >= 55 ? 'var(--warn)' : 'var(--high)';
  return `<svg viewBox="0 0 ${size} ${size}"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--track)" stroke-width="${stroke}"/><circle class="arc" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${color}" stroke-width="${stroke}" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - score / 100)}"/></svg>`;
}

const ago = (t) => { const s = Math.round((Date.now() - t) / 1000); return s < 60 ? 'just now' : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`; };
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const SEV = { critical: 'bad', high: 'bad', medium: 'warn', low: 'low', info: 'low' };

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3800);
}

// ---------- Screens ----------
const state = { tab: 'home', chat: [], threadId: null, asking: false, shownScore: null, scam: null };

function paint(html, enter = true) {
  view.innerHTML = html;
  if (enter && !calm()) { view.classList.remove('enter'); void view.offsetWidth; view.classList.add('enter'); }
}

function setupScreen(reason) {
  $('#tabs').hidden = true;
  $('#live').hidden = true;
  const lead = {
    none: ['Connect to your Mac', 'Use Hashling from your phone over your Wi-Fi. It takes a few seconds.'],
    forgotten: ['This phone was disconnected', 'It was disconnected from Hashling on your Mac. Connect it again with a new code.'],
    expired: ['That code has expired', 'Codes work once, for 10 minutes. Make a new one on your Mac.'],
  }[reason] ?? ['Connect to your Mac', ''];
  paint(`<div class="setup">
    <div class="setup-mascot">${hashlingSvg('big')}</div>
    <h1>${esc(lead[0])}</h1>
    <p class="lead">${esc(lead[1])}</p>
    <ol class="steps">
      <li><span><b>On your Mac,</b> open Hashling and go to <b>Settings</b>, then <b>Your phone</b>.</span></li>
      <li><span>Switch on <b>phone mode</b> and confirm with Touch ID.</span></li>
      <li><span>Point this phone’s camera at the code on the screen and open the link.</span></li>
    </ol>
    <p class="fine">${ICON.wifi} Your phone and Mac need to be on the same Wi-Fi. Everything between them is encrypted with a key only they share.</p>
  </div>`);
}

function offlineScreen() {
  $('#live').hidden = true;
  paint(`<div class="setup">
    <div class="setup-mascot rest">${hashlingSvg('big')}</div>
    <h1>I can’t reach your Mac</h1>
    <p class="lead">Check that your phone is on the same Wi-Fi as your Mac, and that the Mac is awake.</p>
    <button class="btn primary wide" data-act="retry">Try again</button>
  </div>`);
}

async function show(tab, { quiet = false } = {}) {
  state.tab = tab;
  for (const b of document.querySelectorAll('.tabs button')) b.classList.toggle('on', b.dataset.tab === tab);
  try {
    const html = await SCREENS[tab]();
    if (state.tab !== tab) return;
    $('#tabs').hidden = false;
    $('#live').hidden = false;
    paint(html, !quiet);
    AFTER[tab]?.();
  } catch (e) {
    if (e instanceof Gone) return setupScreen(e.message);
    if (e.message === 'offline') return offlineScreen();
    paint(`<div class="card pad"><p class="h2">Couldn’t load this</p><p class="muted">${esc(e.message)}</p><button class="btn" data-act="retry">Try again</button></div>`);
  }
}

const SCREENS = {
  async home() {
    const o = await get('/api/overview');
    setBadge(o.pendingActions);
    state.homeFindings = o.topFindings;
    const tone = o.score >= 80 ? 'ok' : o.score >= 55 ? 'warn' : 'bad';
    return `<section class="hero ${tone}">
      <div class="ring" data-score="${o.score}">${ring(o.score)}<div class="num"><b>${o.score}</b><span>out of 100</span></div></div>
      <h1>${esc(o.verdict)}</h1>
      <p class="muted">${o.tiers.suspicious ? `${plural(o.tiers.suspicious, 'suspicious thing')} to look at first.` : o.tiers.risk ? `${plural(o.tiers.risk, 'thing')} worth fixing.` : 'Nothing needs you right now.'}</p>
    </section>
    ${o.pendingActions ? `<button class="card row-card attention" data-go="approve"><span class="ico">${ICON.check}</span><div><b>${plural(o.pendingActions, 'change')} waiting for you</b><span>Approve on your Mac with Touch ID, or say no here.</span></div>${ICON.chev}</button>` : ''}
    <h2 class="h2">Needs your attention</h2>
    <div class="list">${o.topFindings.length ? o.topFindings.map((f, i) => `<button class="item" data-finding="${i}"><span class="dot ${SEV[f.severity] ?? 'low'}"></span><div><b>${esc(f.title)}</b><span>${esc(f.summary)}</span></div>${ICON.chev}</button>`).join('') : `<div class="empty">${ICON.check}Nothing suspicious and nothing to fix.</div>`}</div>
    <div class="quick">
      <button class="card" data-go="scam"><b>Is this a scam?</b><span>Paste a text, email or link, or add a screenshot.</span></button>
      <button class="card" data-go="ask"><b>Ask Hashling</b><span>Anything about your Mac, in plain words.</span></button>
    </div>
    <p class="fine center">Checked ${ago(o.at)} · ${esc(cred && state.mac ? state.mac : 'your Mac')}</p>`;
  },

  async scam() {
    const r = state.scam;
    return `<h1 class="title">Is this a scam?</h1>
    <p class="muted">Paste a text message, email or link. Or add a screenshot. I check it on your Mac.</p>
    <div class="card pad">
      <textarea id="scam-text" rows="5" placeholder="Paste the message here">${esc(state.scamText ?? '')}</textarea>
      <div class="row">
        <button class="btn primary" data-act="scam-check">Check it</button>
        <label class="btn">${ICON.image}Screenshot<input type="file" id="scam-image" accept="image/*" hidden></label>
      </div>
    </div>
    ${r ? scamResult(r) : ''}`;
  },

  async ask() {
    const st = await get('/api/ai/status').catch(() => ({ ready: false }));
    const msgs = state.chat.map((m) => m.role === 'user'
      ? `<div class="msg me">${esc(m.text)}</div>`
      : `<div class="msg ai"><span class="av">${hashlingSvg()}</span><div class="bubble">${m.pending ? '<span class="dots"><i></i><i></i><i></i></span>' : format(m.text)}${(m.actions ?? []).length ? `<button class="btn sm" data-go="approve">${plural(m.actions.length, 'suggested change')} in Approvals ${ICON.chev}</button>` : ''}</div></div>`).join('');
    return `<div class="chat">
      ${state.chat.length ? msgs : `<div class="welcome">${hashlingSvg('big')}<h1>Ask me anything</h1><p class="muted">I check your Mac first, then answer in plain words.</p>
        <div class="chips">${['Am I safe right now?', 'Is anyone tracking me?', 'What did my Mac upload this week?', 'Why is my Mac slow?'].map((q) => `<button class="chip" data-q="${esc(q)}">${esc(q)}</button>`).join('')}</div>
        ${st.ready ? '' : `<p class="note">${ICON.mac}The assistant is not set up on your Mac yet. Set it up there first, in Settings.</p>`}</div>`}
    </div>
    <form class="composer" id="composer"><textarea id="ask-input" rows="1" placeholder="Ask Hashling…" ${state.asking ? 'disabled' : ''}></textarea><button class="send" aria-label="Send" ${state.asking ? 'disabled' : ''}>${ICON.send}</button></form>`;
  },

  async approve() {
    const [pending, archived] = await Promise.all([get('/api/actions?status=pending'), get('/api/actions?status=archived')]);
    setBadge(pending.length);
    return `<h1 class="title">Approvals</h1>
    <p class="muted">Nothing changes until you approve it. Approving asks for Touch ID on your Mac.</p>
    <div class="list">${pending.length ? pending.map((a) => `<div class="item act" data-id="${esc(a.id)}"><span class="dot ${a.crucial ? 'bad' : 'low'}"></span><div><b>${esc(a.summary)}</b><span>${esc(a.reason)}</span>${a.crucial ? '<em class="crucial">Important, stays until you decide</em>' : ''}
      <div class="row"><button class="btn primary sm" data-act="approve" data-id="${esc(a.id)}">Approve</button><button class="btn sm" data-act="reject" data-id="${esc(a.id)}">Reject</button></div></div></div>`).join('') : `<div class="empty">${ICON.check}Nothing is waiting for you.</div>`}</div>
    ${archived.length ? `<details class="archive"><summary>Archived suggestions <em>${archived.length}</em></summary><p class="fine">Waited more than a day without a decision. Nothing was changed.</p><div class="list">${archived.map((a) => `<div class="item act"><span class="dot faint"></span><div><b>${esc(a.summary)}</b><div class="row"><button class="btn sm" data-act="restore" data-id="${esc(a.id)}">${ICON.undo}Bring back</button></div></div></div>`).join('')}</div></details>` : ''}`;
  },
};

const AFTER = {
  home() { animateScore(); },
  ask() {
    const sc = document.scrollingElement; sc.scrollTop = sc.scrollHeight;
    const input = $('#ask-input');
    input?.addEventListener('input', () => { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 140)}px`; });
  },
  scam() {
    $('#scam-image')?.addEventListener('change', (e) => { const f = e.target.files?.[0]; if (f) void checkScreenshot(f); });
  },
};

function setBadge(n) { const b = $('#badge'); b.hidden = !n; if (b.textContent !== String(n || '') && n && !calm()) { b.classList.remove('pop'); void b.offsetWidth; b.classList.add('pop'); } b.textContent = n || ''; }

/** The score ring draws in the first time, then slides when the number changes. */
function animateScore() {
  const wrap = $('.ring[data-score]');
  if (!wrap) return;
  const to = Number(wrap.dataset.score);
  const from = state.shownScore ?? 0;
  state.shownScore = to;
  if (from === to || calm()) return;
  const arc = $('.arc', wrap);
  const c = Number(arc.getAttribute('stroke-dasharray'));
  const dur = from === 0 ? 900 : 600;
  arc.animate([{ strokeDashoffset: c * (1 - from / 100) }, { strokeDashoffset: c * (1 - to / 100) }], { duration: dur, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' });
  const num = $('.num b', wrap);
  const t0 = performance.now();
  const tick = (t) => { const k = Math.min(1, (t - t0) / dur); num.textContent = Math.round(from + (to - from) * (1 - (1 - k) ** 4)); if (k < 1) requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
}

/** Light formatting for the assistant's answers: paragraphs, **bold**, and lists. */
function format(text) {
  return esc(text).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').split(/\n{2,}/).map((p) => /^\s*[-*] /m.test(p)
    ? `<ul>${p.split('\n').filter((l) => l.trim()).map((l) => `<li>${l.replace(/^\s*[-*] /, '')}</li>`).join('')}</ul>`
    : `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');
}

function scamResult(r) {
  const bad = r.flags.length;
  return `<div class="card pad verdict ${bad ? (r.listed?.length || bad >= 3 ? 'bad' : 'warn') : 'ok'}">
    <p class="h2">${bad ? (r.listed?.length ? 'This is a scam' : bad >= 3 ? 'This looks like a scam' : 'Be careful with this') : 'No warning signs found'}</p>
    ${bad ? `<ul class="flags">${r.flags.map((f) => `<li><b>${esc(f.label)}</b><span>${esc(f.why)}</span></li>`).join('')}</ul><p class="fine">Don’t tap links or reply. If it claims to be a company you use, open their app or website yourself.</p>` : '<p class="muted">Nothing I check for turned up. Scams change fast, so if something feels off, trust that feeling.</p>'}
    <button class="btn sm" data-act="ask-about">Ask Hashling about it</button>
  </div>`;
}

async function checkScam(text) {
  state.scamText = text;
  if (!text.trim()) return toast('Paste a message first.');
  const btn = $('[data-act="scam-check"]'); if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
  try { state.scam = await post('/api/scam-flags', { text }); } catch (e) { toast(e.message); }
  await show('scam', { quiet: true });
  $('.verdict')?.scrollIntoView({ behavior: calm() ? 'auto' : 'smooth', block: 'start' });
}

/** Screenshots are shrunk on the phone first, then read on the Mac (text and QR codes) and deleted there. */
async function checkScreenshot(file) {
  toast('Reading your screenshot on your Mac…');
  try {
    const bmp = await createImageBitmap(file);
    const scale = Math.min(1, 1800 / Math.max(bmp.width, bmp.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(bmp.width * scale); canvas.height = Math.round(bmp.height * scale);
    canvas.getContext('2d').drawImage(bmp, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((r) => canvas.toBlob(r, 'image/jpeg', 0.85));
    const bin = b64u.enc(new Uint8Array(await blob.arrayBuffer()));
    const out = await post('/api/read-image', null, bin);
    const text = [out.text, ...(out.codes ?? []).map((c) => `QR code: ${c}`)].filter(Boolean).join('\n');
    if (!text.trim()) return toast('I couldn’t find any words in that picture.');
    await checkScam(text);
  } catch (e) { toast(e.message || 'I couldn’t read that picture.'); }
}

async function ask(q) {
  q = q.trim();
  if (!q || state.asking) return;
  state.asking = true;
  state.chat.push({ role: 'user', text: q }, { role: 'ai', pending: true });
  await show('ask', { quiet: true });
  const slot = state.chat[state.chat.length - 1];
  try {
    const r = await post('/api/ai/ask', { message: q, threadId: state.threadId, context: { from: 'phone' } });
    state.threadId = r.threadId ?? state.threadId;
    Object.assign(slot, { pending: false, text: r.error ? `Sorry, ${r.error}` : r.text || 'I didn’t get an answer. Try again.', actions: r.actions });
  } catch (e) { Object.assign(slot, { pending: false, text: e.message === 'offline' ? 'I lost the connection to your Mac. Try again.' : e.message }); }
  state.asking = false;
  if (state.tab === 'ask') await show('ask', { quiet: true });
  else toast('Hashling answered your question.');
}

function openFinding(f) {
  $('#sheet').innerHTML = `<div class="grab"></div>
    <span class="tag ${SEV[f.severity] ?? 'low'}">${esc(f.tier === 'suspicious' ? 'Suspicious' : f.tier === 'risk' ? 'Worth fixing' : 'Optional')}</span>
    <h2>${esc(f.title)}</h2>
    <p>${esc(f.summary)}</p>
    ${f.explanation ? `<h3>Why it matters</h3><p>${esc(f.explanation)}</p>` : ''}
    ${f.recommendation ? `<h3>What to do</h3><p>${esc(f.recommendation)}</p>` : ''}
    <div class="row"><button class="btn primary" data-act="ask-finding">Ask about it</button><button class="btn" data-act="ignore" data-id="${esc(f.id)}">Ignore</button><button class="btn ghost" data-act="close">Close</button></div>`;
  state.sheetFinding = f;
  $('#sheet').hidden = false; $('#sheet-bg').hidden = false;
  requestAnimationFrame(() => document.body.classList.add('sheet-open'));
}
function closeSheet() {
  document.body.classList.remove('sheet-open');
  setTimeout(() => { $('#sheet').hidden = true; $('#sheet-bg').hidden = true; }, calm() ? 0 : 220);
}

// ---------- Events ----------
document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-tab], [data-go], [data-act], [data-finding], [data-q]');
  if (!el) return;
  if (el.dataset.tab || el.dataset.go) return show(el.dataset.tab || el.dataset.go);
  if (el.dataset.q) return ask(el.dataset.q);
  if (el.dataset.finding) {
    const f = state.homeFindings?.[Number(el.dataset.finding)];
    if (f) openFinding(await get(`/api/findings/${encodeURIComponent(f.id)}`).catch(() => f));
    return;
  }
  const act = el.dataset.act;
  try {
    if (act === 'retry') return start();
    if (act === 'close') return closeSheet();
    if (act === 'scam-check') return checkScam($('#scam-text').value);
    if (act === 'ask-about') { closeSheet(); await show('ask'); return ask(`Is this a scam? Here is the message:\n\n${state.scamText}`); }
    if (act === 'ask-finding') { const f = state.sheetFinding; closeSheet(); await show('ask'); return ask(`Explain this warning from my Mac and what I should do: “${f.title}”`); }
    if (act === 'ignore') { await post(`/api/findings/${encodeURIComponent(el.dataset.id)}/ignore`, {}); closeSheet(); toast('Ignored. I won’t warn you about it again.'); return show('home', { quiet: true }); }
    if (act === 'approve') {
      el.disabled = true; el.textContent = 'Confirm on your Mac…';
      toast('Confirm with Touch ID on your Mac.');
      const r = await post(`/api/actions/${encodeURIComponent(el.dataset.id)}/approve`, {});
      toast(r.status === 'executed' ? `Done. ${r.result ?? ''}` : `It didn’t work: ${r.result ?? ''}`);
      await leave(el.closest('.item'), 'ok');
      return show('approve', { quiet: true });
    }
    if (act === 'reject') { await post(`/api/actions/${encodeURIComponent(el.dataset.id)}/reject`, {}); await leave(el.closest('.item'), 'no'); toast('Rejected. Nothing was changed.'); return show('approve', { quiet: true }); }
    if (act === 'restore') { await post(`/api/actions/${encodeURIComponent(el.dataset.id)}/restore`, {}); toast('Back on your list.'); return show('approve', { quiet: true }); }
  } catch (err) {
    if (err instanceof Gone) return setupScreen(err.message);
    toast(err.message === 'offline' ? 'I can’t reach your Mac right now.' : err.message);
    if (act === 'approve') show('approve', { quiet: true });
  }
});
$('#sheet-bg').addEventListener('click', closeSheet);
document.addEventListener('submit', (e) => { if (e.target.id === 'composer') { e.preventDefault(); const v = $('#ask-input').value; void ask(v); } });
document.addEventListener('keydown', (e) => { if (e.target.id === 'ask-input' && e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void ask(e.target.value); } });

/** A decided row: approved rows show a tick, then fold away; rejected ones slide off. */
async function leave(row, kind) {
  if (!row || calm()) return;
  row.classList.add('leaving', kind);
  if (kind === 'ok') await new Promise((r) => setTimeout(r, 450));
  const h = row.offsetHeight;
  await row.animate([{ opacity: 1, height: `${h}px` }, { opacity: 0, transform: `translateX(${kind === 'ok' ? 0 : 18}px)`, height: `${h}px`, offset: 0.45 }, { opacity: 0, height: '0px', paddingTop: '0px', paddingBottom: '0px' }], { duration: 300, easing: 'cubic-bezier(0.77, 0, 0.175, 1)', fill: 'forwards' }).finished;
}

// Keep Home and Approvals fresh while the app is open.
setInterval(() => { if (document.visibilityState === 'visible' && cred && (state.tab === 'home' || state.tab === 'approve') && !document.body.classList.contains('sheet-open')) void show(state.tab, { quiet: true }); }, 15_000);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && cred) void show(state.tab, { quiet: true }); });

async function start() {
  if (!cred) return setupScreen('none');
  try {
    const hello = await post('/hello', {});
    state.mac = hello.mac;
    $('#mac').textContent = `Watching ${hello.mac}`;
    await show('home');
  } catch (e) {
    if (e instanceof Gone) return setupScreen(e.message);
    offlineScreen();
  }
}
void start();
