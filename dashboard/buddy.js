// Hashling, the little # that keeps you company: a Clippy-style helper in the corner.
// It has no face, so it shows how it feels with its body (bob, hop, tilt, shiver, lean).
// It speaks rarely: one short tip per page a day, and when something new needs a look.
// Loaded by app.js after guide.js; shares helpers through window.W.
const W = window.W;
const { $, esc, state, api, views } = W;

const { hashlingSvg } = W;

// ---------- preferences ----------
const KEY = 'hashling.buddy';
const SEEN_KEY = 'hashling.tips';
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private window */ } },
};
/** On by default for beginners (Simple mode); anyone can switch it in Settings. */
const enabled = () => { const v = store.get(KEY); return v ? v === 'on' : state.mode === 'simple'; };
const today = () => new Date().toDateString();
function seenToday(id) {
  try { const s = JSON.parse(store.get(SEEN_KEY) || '{}'); return s[id] === today(); } catch { return false; }
}
function markSeen(id) {
  let s = {}; try { s = JSON.parse(store.get(SEEN_KEY) || '{}'); } catch { /* reset */ }
  s[id] = today(); store.set(SEEN_KEY, JSON.stringify(s));
}

// ---------- the element ----------
const root = document.createElement('div');
root.className = 'buddy';
root.innerHTML = `<div class="buddy-bubble" id="buddy-bubble" role="status" aria-live="polite" hidden></div>
  <button class="buddy-me" type="button" aria-label="Ask Hashling. Opens the side panel. You can also drag me somewhere else." aria-haspopup="true">${hashlingSvg()}</button>`;
document.body.append(root);
const me = root.querySelector('.buddy-me');
const bubble = root.querySelector('#buddy-bubble');

let mood = 'idle';
let moodTimer = 0;
/** idle, wave, hop, think, worry, point, happy, rest. Short moods fall back to the resting one. */
let reacting = false;
function setMood(m, ms = 0) {
  if (ms) {
    // A short reaction (bounce, wave…) always plays to the end, then I go back to my resting mood.
    clearTimeout(moodTimer);
    reacting = true;
    root.dataset.mood = m;
    moodTimer = setTimeout(() => { reacting = false; root.dataset.mood = mood; }, ms);
    return;
  }
  mood = m;
  if (!reacting) root.dataset.mood = m;
}

// ---------- talking ----------
let lastUnasked = 0;
let hideTimer = 0;
/**
 * Show a speech bubble. actions: [{label, go?: '#/route', run?: fn, primary?: bool}].
 * Unasked tips are rate-limited so Hashling never nags.
 */
function say(text, { actions = [], mood: m, asked = false, stay = false, extra = '' } = {}) {
  if (!enabled() && !asked) return false;
  if (!asked && Date.now() - lastUnasked < 90_000) return false;
  if (!asked) lastUnasked = Date.now();
  if (m) setMood(m, 2600);
  bubble.innerHTML = `<button class="buddy-x" type="button" data-buddy="close" aria-label="Close">×</button>
    <p>${text}</p>${extra}
    ${actions.length ? `<div class="buddy-acts">${actions.map((a, i) => `<button type="button" class="btn sm ${a.primary ? 'primary' : ''}" data-buddy="act" data-i="${i}">${esc(a.label)}</button>`).join('')}</div>` : ''}`;
  bubble._actions = actions;
  bubble.hidden = false;
  root.classList.add('talking');
  clearTimeout(hideTimer);
  if (!stay) hideTimer = setTimeout(hush, 14_000);
  return true;
}
function hush() { bubble.hidden = true; root.classList.remove('talking'); }
bubble.addEventListener('mouseenter', () => clearTimeout(hideTimer));
bubble.addEventListener('mouseleave', () => { if (!bubble.hidden) hideTimer = setTimeout(hush, 6_000); });
bubble.addEventListener('click', (e) => {
  const b = e.target.closest('[data-buddy]'); if (!b) return;
  if (b.dataset.buddy === 'close') return hush();
  if (b.dataset.buddy !== 'act') return; // typing in the ask box is not an action
  const a = bubble._actions?.[Number(b.dataset.i)]; hush();
  if (a?.go) location.hash = a.go;
  a?.run?.();
});

// ---------- pressing Hashling ----------
// Press: it squishes. Release: it hops and opens the side panel. Drag: it follows and stays where you drop it.
// Pressing opens the side panel.
const POS_KEY = 'hashling.pos';
function place(pos) {
  root.style.left = root.style.top = root.style.right = root.style.bottom = '';
  if (!pos) { root.dataset.side = 'right'; root.dataset.vert = 'above'; return; }
  const w = me.offsetWidth || 72, h = me.offsetHeight || 72;
  const x = Math.min(Math.max(8, pos.x * innerWidth), innerWidth - w - 8);
  const y = Math.min(Math.max(8, pos.y * innerHeight), innerHeight - h - 8);
  // Anchor from the nearest edges, so Hashling stays put and the bubble grows away from it.
  const left = x + w / 2 < innerWidth / 2;
  const below = y < 300;
  root.dataset.side = left ? 'left' : 'right';
  root.dataset.vert = below ? 'below' : 'above';
  // Set all four sides: the stylesheet's default corner would otherwise still apply.
  Object.assign(root.style, left ? { left: `${x}px`, right: 'auto' } : { left: 'auto', right: `${innerWidth - x - w}px` });
  Object.assign(root.style, below ? { top: `${y}px`, bottom: 'auto' } : { top: 'auto', bottom: `${innerHeight - y - h}px` });
}
let savedPos = null;
try { savedPos = JSON.parse(store.get(POS_KEY) || 'null'); } catch { /* ignore */ }
place(savedPos);
window.addEventListener('resize', () => place(savedPos));

let press = null;
me.addEventListener('pointerdown', (e) => {
  if (e.button !== 0) return;
  const r = me.getBoundingClientRect();
  press = { x: e.clientX, y: e.clientY, dx: e.clientX - r.left, dy: e.clientY - r.top, dragging: false };
  me.setPointerCapture(e.pointerId);
  root.classList.add('pressed');
});
me.addEventListener('pointermove', (e) => {
  if (!press) return;
  if (!press.dragging && Math.hypot(e.clientX - press.x, e.clientY - press.y) < 6) return;
  if (!press.dragging) { press.dragging = true; hush(); root.classList.add('dragging'); root.classList.remove('pressed'); }
  const x = e.clientX - press.dx, y = e.clientY - press.dy;
  Object.assign(root.style, { left: `${x}px`, top: `${y}px`, right: 'auto', bottom: 'auto' });
  // lean the way it is being carried
  root.style.setProperty('--carry', `${Math.max(-18, Math.min(18, (e.movementX || 0) * 1.5))}deg`);
});
function release(e) {
  if (!press) return;
  const was = press; press = null;
  root.classList.remove('pressed', 'dragging');
  if (was.dragging) {
    const r = me.getBoundingClientRect();
    savedPos = { x: r.left / innerWidth, y: r.top / innerHeight };
    store.set(POS_KEY, JSON.stringify(savedPos));
    place(savedPos);
    setMood('land', 500);
    return;
  }
  if (e.type === 'pointerup') poke();
}
me.addEventListener('pointerup', release);
me.addEventListener('pointercancel', release);
// Keyboard (Enter or Space) clicks have no pointer: open the menu straight away.
me.addEventListener('click', (e) => { if (e.detail === 0) openMenu(); });
// Double-click puts Hashling back in its corner.
me.addEventListener('dblclick', () => { savedPos = null; store.set(POS_KEY, 'null'); place(null); setMood('hop', 900); });

// Pressing me opens the side panel, where you can ask me anything.
function poke() {
  hush();
  // Bounce first, so you see me react, then open the panel.
  setMood('bounce', 950);
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  setTimeout(() => (W.openAssistant ? W.openAssistant() : (location.hash = '#/assistant')), reduced ? 0 : 560);
}
function openMenu() { poke(); }
// Escape closes my bubble.
root.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !bubble.hidden) { hush(); me.focus(); } });
function hide() {
  store.set(KEY, 'off'); apply();
  W.toast?.('Okay, I’ll stay out of the way. Bring me back any time in Settings.');
}

// ---------- what it says on each page ----------
// Short and friendly. The "About this page" card has the full explanation.
const TIPS = {
  scamcheck: { text: 'Got a strange text, email or link? Paste it here and I’ll point out the warning signs.', mood: 'point' },
  network: { text: 'These are the apps using the internet right now. If the bar at the top is green, there’s nothing to do.', mood: 'think' },
  agents: { text: 'AI apps can do a lot on your Mac. Orange ticks are the powerful abilities worth a look.', mood: 'think' },
  downloads: { text: 'I check every new app and download. If something says “would be blocked” and you don’t know it, remove it.', mood: 'think' },
  permissions: { text: 'Apps you don’t use shouldn’t keep camera, microphone or screen access. Remove it with one click.', mood: 'point' },
  tracking: { text: 'If an AirTag or other tracker keeps following you around, I’ll warn you here.', mood: 'think' },
  optimize: { text: 'Need space? Everything here goes to the Trash, so you can always put it back.', mood: 'happy' },
  accounts: { text: 'Start with two-step sign-in on your email and Apple Account. It stops most account break-ins.', mood: 'point' },
  hacked: { text: 'Take a breath. Go down the list in order. I’m right here with you.', mood: 'rest' },
  approvals: { text: 'These are fixes waiting for your OK. Read one, then Approve or Reject. Nothing changes without you.', mood: 'point' },
};

let overview = null;
async function freshOverview() {
  try { overview = await api('/api/overview'); } catch { /* keep the last one */ }
  return overview;
}
/** The resting mood follows how the Mac is doing. */
function baseMood(o) {
  if (!o) return 'idle';
  return o.openFindings?.critical || o.openFindings?.high ? 'worry' : 'idle';
}

async function onView() {
  if (!enabled()) return;
  const v = state.view;
  const o = await freshOverview();
  setMood(baseMood(o));
  if (v === 'assistant' || v === 'settings') return;
  if (!seenToday('hello')) {
    markSeen('hello');
    setMood('wave', 2600);
    say('Hi, I’m Hashling, your personal AI security agent! I keep watch over your Mac and explain things in plain words. Click me any time you have a question.', { actions: [{ label: 'Got it', primary: true }] });
    return;
  }
  if (v === 'overview' && o) {
    const bad = (o.openFindings?.critical ?? 0) + (o.openFindings?.high ?? 0);
    const id = `home:${bad ? 'bad' : 'ok'}`;
    if (seenToday(id)) return;
    if (bad) { if (say(bad === 1 ? 'One thing looks suspicious. Want me to show you?' : `${bad} things look suspicious. Want me to show you?`, { mood: 'point', actions: [{ label: 'Show me', primary: true, run: () => document.querySelector('.home .item, .finding, [data-act="finding"]')?.scrollIntoView({ behavior: 'smooth', block: 'center' }) }, { label: 'Later' }] })) markSeen(id); }
    else if (say('All clear right now. I’ll keep watching.', { mood: 'happy' })) markSeen(id);
    return;
  }
  if (v === 'approvals' && !(o?.pendingActions)) return;
  const tip = TIPS[v];
  if (tip && !seenToday(`tip:${v}`) && say(tip.text, { mood: tip.mood })) markSeen(`tip:${v}`);
}

// Something new arrived: hop and say so, once.
let lastBad = null;
W.buddyOnChange = async () => {
  if (!enabled()) return;
  const o = await freshOverview(); if (!o) return;
  const bad = (o.openFindings?.critical ?? 0) + (o.openFindings?.high ?? 0);
  if (lastBad !== null && bad > lastBad) {
    setMood('hop', 1100);
    say('Something new needs a look.', { mood: 'point', asked: true, actions: [{ label: 'Show me', primary: true, go: '#/overview' }, { label: 'Later' }] });
  }
  lastBad = bad;
  setMood(baseMood(o));
};

// Idle for a while: Hashling rests too. Any movement wakes it up.
let idleTimer = 0;
function awake() {
  if (root.dataset.mood === 'rest' && mood === 'rest') setMood(baseMood(overview));
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => setMood('rest'), 180_000);
}
['pointermove', 'keydown', 'scroll'].forEach((e) => window.addEventListener(e, awake, { passive: true }));

function apply() {
  root.hidden = !enabled();
  if (root.hidden) hush();
}
window.addEventListener('hashchange', () => { hush(); apply(); setTimeout(onView, 700); });
apply();
awake();
setTimeout(onView, 1200);

// ---------- Settings: switch Hashling on or off ----------
const baseSettings = views.settings;
views.settings = async () => {
  const html = await baseSettings();
  const on = enabled();
  return `${html}<section class="card pad mt buddy-setting"><div class="row between" style="gap:16px;align-items:center">
    <div class="row" style="gap:14px;align-items:center">${hashlingSvg('sm')}<div><p class="h2" style="margin:0">Me, in the corner</p><p class="small muted" style="margin:4px 0 0">That little # is me. Press me to open the side panel and ask me anything, drag me anywhere you like, and double-click to send me back to my corner.</p></div></div>
    <button class="btn ${on ? '' : 'primary'}" type="button" data-buddy-toggle>${on ? 'Hide Hashling' : 'Show Hashling'}</button></div></section>`;
};
document.addEventListener('click', (e) => {
  if (!e.target.closest('[data-buddy-toggle]')) return;
  store.set(KEY, enabled() ? 'off' : 'on');
  apply();
  if (enabled()) { setMood('wave', 2600); say('I’m back! Click me any time.', { asked: true }); }
  W.render?.();
});
