// Hashling guide: the beginner layer. Detail modes (simple / standard / expert), friendly page
// names, an "About this page" card on every view, and the first-run setup. Loaded by app.js
// after insights.js; shares helpers through window.W.
const W = window.W;
const { $, esc, icon, views, state, api, toast } = W;

// ---------- modes ----------
const MODES = {
  simple: {
    label: 'Simple', badge: 'Recommended for most people',
    blurb: 'Tells you if something is wrong, in plain words, and what to do about it. Only the pages most people need.',
    shows: ['Is anything wrong right now', 'What your apps connect to', 'Who can use your camera, mic and location', 'Space you can free up'],
  },
  standard: {
    label: 'Standard', badge: 'Comfortable with computers',
    blurb: 'Everything I check, each explained. Adds malware scans, startup items, uploads, saved keys and the full history.',
    shows: ['Everything in Simple', 'Malware scans and startup items', 'What was uploaded this week', 'Full list of findings and timeline'],
  },
  expert: {
    label: 'Expert', badge: 'Developers and security people',
    blurb: 'All the raw detail: every process and command, file paths, signatures and a read-only SQL console.',
    shows: ['Everything in Standard', 'Every program that ran and who started it', 'File paths, signers and technical evidence', 'osquery SQL console'],
  },
};

/** Sidebar per mode. Simple mode uses friendlier names and fewer pages. */
const SIMPLE_NAV = [
  [null, [['overview', 'Home', 'home'], ['assistant', 'Ask Hashling', 'spark'], ['scamcheck', 'Scam check', 'shield'], ['approvals', 'Approvals', 'inbox']]],
  ['Check my Mac', [['network', 'Internet', 'globe', 'network'], ['agents', 'AI apps', 'bot', 'agents'], ['downloads', 'Apps & downloads', 'download', 'downloads'], ['permissions', 'Privacy', 'key', 'permissions'], ['tracking', 'Trackers & location', 'radar', 'tracking'], ['optimize', 'Storage & speed', 'gauge', 'optimize']]],
  [null, [['accounts', 'Account safety', 'key'], ['hacked', 'I think I’ve been hacked', 'alert'], ['phonecheck', 'Check my phone', 'mobile', 'phonecheck'], ['settings', 'Settings', 'gear']]],
];
const SIMPLE_TITLES = {
  overview: ['Home', 'Is your Mac safe right now? Start here.'],
  network: ['Internet', 'Which apps are online, and who they talk to'],
  agents: ['AI apps', 'The AI apps on this Mac, and what each one is allowed to do'],
  downloads: ['Apps & downloads', 'Is everything you downloaded and installed safe?'],
  permissions: ['Privacy', 'Which apps can use your camera, microphone, screen and files'],
  tracking: ['Trackers & location', 'Hidden trackers near you, and apps that can see where you are'],
  approvals: ['Approvals', 'Fixes I suggested. Nothing happens until you say yes.'],
  assistant: ['Ask Hashling', 'Ask me anything about your Mac’s safety, in your own words.'],
  // Pages outside the Simple sidebar can still be reached from a warning or a Home tile.
  processes: ['Running programs', 'Programs that ran on this Mac, and any that behaved like malware'],
  startup: ['Starts by itself', 'Things set to start when your Mac starts, where malware likes to hide'],
  system: ['Mac settings', 'The macOS settings that keep this Mac safe'],
  secrets: ['Saved passwords & keys', 'Passwords and keys left in files, where malware looks first'],
  phonecheck: ['Check my phone', 'Plug your phone in with a cable and I’ll check it for spy apps and missing updates'],
};
// Simple mode names for warning labels and Home tiles.
const SIMPLE_CAT = { agents: 'AI apps', processes: 'Running programs', network: 'Internet', behavior: 'Internet', netsafety: 'Wi-Fi and router', permissions: 'Privacy', trackers: 'Trackers', location: 'Location', persistence: 'Starts by itself', posture: 'Mac settings', notarization: 'Apps & downloads', downloads: 'Apps & downloads', secrets: 'Saved passwords & keys', storage: 'Storage', phone: 'Your phone' };
const FULL_CAT = { ...W.CAT };
const FULL_NAV = W.NAV.map(([g, items]) => [g, items.slice()]);
const FULL_TITLES = { ...W.TITLES };

function applyMode(mode) {
  state.mode = MODES[mode] ? mode : 'simple';
  document.body.dataset.mode = state.mode;
  const nav = state.mode === 'simple' ? SIMPLE_NAV
    : FULL_NAV.map(([g, items]) => [g, items.filter(([id]) => state.mode === 'expert' || id !== 'processes')]);
  W.NAV.splice(0, W.NAV.length, ...nav.map(([g, items]) => [g, items.slice()]));
  Object.assign(W.TITLES, FULL_TITLES, state.mode === 'simple' ? SIMPLE_TITLES : {});
  Object.assign(W.CAT, FULL_CAT, state.mode === 'simple' ? SIMPLE_CAT : {});
}
W.applyMode = applyMode;

async function setMode(mode) {
  await api('/api/prefs', { method: 'POST', body: { mode } });
  applyMode(mode);
  const [t, s] = W.TITLES[state.view] ?? ['', ''];
  $('#title').textContent = t;
  $('#subtitle').textContent = s;
}

// ---------- "About this page" ----------
// Three short answers per page: what am I looking at, why does it matter, what should I do.
const HELP = {
  accounts: ['A short checklist for your email, Apple Account and bank.', 'Most money and data is lost through accounts, not the Mac itself.', 'Tick each step when it is done. I can walk you through any of them.'],
  scamcheck: ['A quick check for messages, links and phone numbers you are unsure about, and for passwords that have leaked.', 'Scam messages and reused leaked passwords are the most common ways people lose money and accounts.', 'Paste the message and press Check it. If anything looks off, do not click, call or pay.'],
  hacked: ['A calm, step-by-step plan for when you think someone got into your Mac or accounts.', 'Acting in the right order (email first, then bank) stops most of the damage.', 'Tick off each step as you go. I’ll walk you through it.'],
  overview: ['A summary of everything I check on this Mac, with a score out of 100.', 'Red means something looks suspicious. Orange is worth fixing. Blue is optional.', 'Start with anything red. Click it for a plain explanation and a suggested fix.'],
  assistant: ['A chat with me, your AI security agent. I check this Mac before I answer, using the AI account you connected.', 'You can ask anything, like "is this app safe?" or "what did I upload today?"', 'Type a question. It can suggest fixes, but you approve each one with Touch ID.'],
  network: ['Every app that is using the internet right now, and the company on the other end.', 'Malware has to talk to its owner. Unknown programs talking to unknown servers are the warning sign.', 'Nothing to do if the top bar is green. Click any app to see who it talks to.'],
  agents: ['The AI apps on this Mac (like Claude, ChatGPT or Cursor) and what each is allowed to do.', 'An AI that can run commands or read your files can be tricked by a hidden instruction on a web page.', 'Check the red and orange abilities. Turn off ones you do not use in that app’s settings.'],
  processes: ['Every program that ran in the last 24 hours, who started it, and the exact command.', 'Mac malware gives itself away with tricks like fake password prompts or reading browser cookies.', 'Look at “What your AI agents ran” and anything marked as a technique.'],
  scans: ['Malware scans with three engines, including the rules Apple uses in macOS.', 'Downloads are the most common way malware gets onto a Mac.', 'Scan your Downloads folder now and then, or any file you are unsure about.'],
  downloads: ['Files and apps that arrived on this Mac, where they came from, and whether Apple checked them.', 'Pirated or fake apps are the most common way Macs get infected.', 'If something says “would be blocked” and you do not recognise it, remove it.'],
  uploads: ['What left this Mac: how much each app sent, to whom, and which files were involved when I could tell.', 'Info-stealing malware and over-eager apps send your files somewhere. This is how you would notice.', 'Look for apps or places you do not recognise. Ask me if something looks odd.'],
  startup: ['Programs set to start by themselves when your Mac starts or you log in.', 'Malware adds itself here so it comes back after a restart.', 'Anything marked new or unsigned that you do not recognise is worth a look.'],
  permissions: ['Which apps can use your camera, microphone, screen, keyboard and files.', 'Screen recording and keyboard access let an app see everything you type and do.', 'Remove access from apps you do not use or do not recognise.'],
  secrets: ['Passwords and API keys saved in plain text in files on this Mac.', 'They are the first thing info-stealing malware copies.', 'Move keys into a password manager or your Keychain, and rotate any that leaked.'],
  tracking: ['Bluetooth trackers like AirTags near you, and apps that can see your location.', 'A tracker that keeps following you is a stalking warning sign.', 'If one follows you, find it using the guidance shown. Turn off location for apps that do not need it.'],
  system: ['The macOS settings that matter most for safety, like FileVault and the firewall.', 'These are your Mac’s seat belts: they stop most attacks before they start.', 'Turn on anything marked red or orange. Each item says exactly where the switch is.'],
  optimize: ['What fills your disk, what can be removed safely, and what slows your Mac down at startup.', 'Caches and old apps quietly eat space. Nothing is deleted: items go to the Trash.', 'Try “AI cleanup plan”, or clear the safe items one by one.'],
  findings: ['Every issue I found, from most to least worrying.', 'One list for everything, so nothing slips through.', 'Work from the top. Ignore anything you have checked and are happy with.'],
  ignored: ['Warnings you chose to ignore or snooze.', 'You can always change your mind.', 'Bring back anything you want me to warn you about again.'],
  approvals: ['Fixes that are waiting for your OK, and the history of ones you approved.', 'Nothing on your Mac changes without your Touch ID. Not even I can skip this.', 'Read each one. Approve, or reject if you are unsure.'],
  timeline: ['Everything I noticed, newest first.', 'Useful to answer “what happened while I was away?”', 'Click anything for details.'],
  query: ['A read-only console for osquery SQL, for people who know it.', 'It can answer almost any question about this Mac, but you never need it.', 'Easier: ask the Assistant in plain English and it writes the query for you.'],
  phonecheck: ['A check-up of a phone you plug into this Mac with a cable: spy apps, hidden profiles, apps from outside the store and missing updates.', 'Stalkerware is usually installed by someone who had your phone in their hands. It hides well, but it leaves signs I can read over the cable.', 'Plug your phone in, say yes on the phone, then press Check my phone. I never change anything on it.'],
  settings: ['Your AI connection, how much detail I show, and what I can access.', 'I see more, and explain better, with the right access.', 'Grant Full Disk Access once, and pick the detail level you like.'],
};

state.helpHidden = (() => { try { return new Set(JSON.parse(localStorage.getItem('hashling.help.hidden') ?? '[]')); } catch { return new Set(); } })();
const saveHidden = () => { try { localStorage.setItem('hashling.help.hidden', JSON.stringify([...state.helpHidden])); } catch { /* private window */ } };

function helpCard(view) {
  const h = HELP[view];
  if (!h) return '';
  // Experts start with help folded away; everyone can fold or reopen it.
  const folded = state.helpHidden.has(view) || (state.mode === 'expert' && !state.helpHidden.has(`open:${view}`));
  if (folded) return `<div class="help-mini"><button class="linkish" data-act="help-open" data-v="${view}">${icon('spark')}About this page</button></div>`;
  return `<section class="help" aria-label="About this page">
    <div class="help-row"><span class="help-k">What this is</span><p>${esc(h[0])}</p></div>
    <div class="help-row"><span class="help-k">Why it matters</span><p>${esc(h[1])}</p></div>
    <div class="help-row"><span class="help-k">What to do</span><p>${esc(h[2])}</p></div>
    <button class="btn ghost icon-btn help-x" data-act="help-close" data-v="${view}" aria-label="Hide this explanation">${icon('x')}</button>
  </section>`;
}
for (const view of Object.keys(HELP)) {
  const base = views[view];
  if (base) views[view] = async () => helpCard(view) + await base();
}

// Simple mode: the overview tiles show only the beginner areas, plus any other area with a problem.
const SIMPLE_AREAS = new Set(SIMPLE_NAV.flatMap(([, items]) => items.map(([id]) => id)));
const helpOverview = views.overview;
views.overview = async () => {
  const html = await helpOverview();
  if (state.mode !== 'simple') return html;
  return html.replace(/<a class="area" href="#\/(\w+)">[\s\S]*?<\/a>/g, (tile, id) => (SIMPLE_AREAS.has(id) || !/state ok/.test(tile) ? tile.replace(/(<span class="name">)([^<]*)/, (m, open, name) => `${open}${esc(SIMPLE_NAV.flatMap(([, i]) => i).find(([x]) => x === id)?.[1] ?? SIMPLE_TITLES[id]?.[0] ?? name)}`) : ''));
};

// ---------- glossary ----------
// Jargon in explanations gets a dotted underline; hover or focus shows a one-line plain definition.
const TERMS = {
  'prompt injection': 'Hidden instructions in a web page, email or file that trick an AI into doing something you did not ask for.',
  'malware': 'Software made to harm you or steal from you, like viruses, spyware and password stealers.',
  'info-stealer': 'Malware that copies your passwords, browser logins, crypto wallets and saved keys.',
  'MCP': 'Model Context Protocol: the plug-in system that gives AI apps extra tools, like reading files or browsing.',
  'Full Disk Access': 'A macOS permission that lets an app read protected data such as other apps’ settings.',
  'FileVault': 'macOS disk encryption. If your Mac is stolen, nobody can read your files without your password.',
  'firewall': 'A filter that blocks other devices from connecting to apps on your Mac.',
  'Gatekeeper': 'The macOS check that only lets apps from identified developers open by default.',
  'notarized': 'Scanned by Apple for malware before release. A good sign an app is genuine.',
  'notarization': 'Apple’s malware check that developers submit their apps to before release.',
  'quarantine': 'Moving a file somewhere safe where it cannot run. You can restore it later.',
  'beaconing': 'A program contacting a server on a fixed clock, which is how malware checks in for orders.',
  'exfiltration': 'Copying data off a computer without permission.',
  'DNS': 'The service that turns names like apple.com into the numeric addresses computers use.',
  'router': 'The box that connects your Wi-Fi to the internet.',
  'port': 'A numbered door an app opens so other devices can connect to it.',
  'launch agent': 'A small file telling macOS to start a program automatically when you log in.',
  'startup item': 'Something set to start by itself when your Mac starts or you log in.',
  'API key': 'A password that lets a program use an online service in your name.',
  'token': 'A password-like code that keeps you signed in to a service.',
  'hash': 'A short fingerprint of a file. The same file always has the same fingerprint.',
  'SIP': 'System Integrity Protection: stops anything, even admin software, from changing core macOS files.',
  'XProtect': 'Apple’s built-in malware scanner that updates itself in the background.',
  'ad-hoc': 'Signed without a verified developer identity. Normal for tools you build yourself.',
  'proxy': 'A middleman that your internet traffic passes through.',
  'root certificate': 'A certificate your Mac trusts completely. A rogue one lets someone read your secure traffic.',
  'MDM': 'Mobile Device Management: lets an organisation control a Mac remotely, usually your employer or school.',
  'encrypted': 'Scrambled so only the intended recipient can read it.',
  'phishing': 'A fake message or website that tricks you into giving away a password or payment details.',
  'Bluetooth': 'Short-range wireless used by headphones, keyboards and trackers like AirTags.',
};
const TERM_RE = new RegExp(`\\b(${Object.keys(TERMS).sort((a, b) => b.length - a.length).map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\b`, 'i');
const TERM_SCOPE = '.explain p, .help p, .item .s, .check .why, .check .fix, .setup-lead, .status .sub';
function glossify(root) {
  for (const box of root.querySelectorAll(TERM_SCOPE)) {
    if (box.dataset.gloss) continue;
    box.dataset.gloss = '1';
    const used = new Set();
    const walker = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (let node of nodes) {
      if (node.parentElement?.closest('.term, code, a, button')) continue;
      let m;
      while (node && (m = node.nodeValue.match(TERM_RE))) {
        const key = Object.keys(TERMS).find((t) => t.toLowerCase() === m[1].toLowerCase());
        if (used.has(key)) break;
        used.add(key);
        const hit = node.splitText(m.index);
        const rest = hit.splitText(m[1].length);
        const span = document.createElement('span');
        span.className = 'term';
        span.tabIndex = 0;
        span.dataset.def = TERMS[key];
        span.setAttribute('aria-label', `${m[1]}: ${TERMS[key]}`);
        span.textContent = hit.nodeValue;
        hit.replaceWith(span);
        node = rest;
      }
    }
  }
}
new MutationObserver(() => glossify(document.body)).observe(document.body, { childList: true, subtree: true });
// Open the definition leftward when there is no room on the right.
const placeTerm = (e) => { const t = e.target.closest?.('.term'); if (t) t.classList.toggle('flip', t.getBoundingClientRect().left + 290 > document.documentElement.clientWidth); };
document.addEventListener('pointerover', placeTerm);
document.addEventListener('focusin', placeTerm);

// ---------- text size ----------
// A per-viewer convenience, so it lives in this browser only.
const readSize = () => { try { return localStorage.getItem('hashling.textSize') === 'large' ? 'large' : 'normal'; } catch { return 'normal'; } };
function applyTextSize(size) { document.documentElement.dataset.text = size; try { localStorage.setItem('hashling.textSize', size); } catch { /* private window */ } }
applyTextSize(readSize());

// Appearance: Hashling is light unless the viewer picks Dark or Match my Mac in Settings. Per viewer.
// Only an explicit choice is saved, so everyone else gets the light look.
const THEME_KEY = 'hashling.appearance';
const readTheme = () => { try { const t = localStorage.getItem(THEME_KEY); return ['auto', 'dark', 'light'].includes(t) ? t : 'light'; } catch { return 'light'; } };
function applyTheme(t, chosen = false) {
  if (t === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  if (chosen) { try { localStorage.setItem(THEME_KEY, t); } catch { /* private window */ } }
}
applyTheme(readTheme());

// ---------- Settings: detail level ----------
const baseSettings = views.settings;
views.settings = async () => {
  const html = await baseSettings();
  const card = `<section class="card pad mode-card"><div class="row between" style="gap:10px"><div><p class="h2" style="margin:0">How much detail</p><p class="small muted" style="margin:4px 0 0">Change this any time. It only changes what you see, not how carefully I check.</p></div><button class="btn sm" data-act="setup-open">Run setup again</button></div>
    <div class="mode-pick" role="radiogroup" aria-label="Detail level">${Object.entries(MODES).map(([k, m]) => `<button type="button" role="radio" aria-checked="${state.mode === k}" class="mode-opt ${state.mode === k ? 'on' : ''}" data-act="mode" data-v="${k}"><b>${m.label}</b><span>${esc(m.blurb)}</span></button>`).join('')}</div>
    <div class="row" style="gap:12px;margin-top:16px"><span class="small"><b>Text size</b></span><div class="seg" role="radiogroup" aria-label="Text size">${[['normal', 'Normal'], ['large', 'Larger']].map(([v, l]) => `<button type="button" role="radio" aria-checked="${readSize() === v}" class="${readSize() === v ? 'on' : ''}" data-act="text-size" data-v="${v}">${l}</button>`).join('')}</div></div>
    <div class="row" style="gap:12px;margin-top:10px"><span class="small"><b>Appearance</b></span><div class="seg" role="radiogroup" aria-label="Appearance">${[['auto', 'Match my Mac'], ['light', 'Light'], ['dark', 'Dark']].map(([v, l]) => `<button type="button" role="radio" aria-checked="${readTheme() === v}" class="${readTheme() === v ? 'on' : ''}" data-act="theme" data-v="${v}">${l}</button>`).join('')}</div><span class="tiny muted">Text size and appearance only change this browser.</span></div></section>`;
  // The help card stays first; the mode picker sits right under it.
  return html.replace(/(<\/section>\s*)?(<div class="grid g2")/, (m, help = '', grid) => `${help}${card}<div class="mt"></div>${grid}`);
};

// ---------- first-run setup ----------
const setup = { step: 0, mode: 'simple', fda: null, fdaRetry: false, ai: null, dns: null, auto: false };
const STEPS = ['Welcome', 'Detail', 'Access', 'AI helper', 'Protection', 'Done'];

function setupHtml() {
  const dots = `<ol class="setup-steps" aria-label="Setup progress">${STEPS.map((s, i) => `<li class="${i < setup.step ? 'done' : i === setup.step ? 'on' : ''}"><span>${i + 1}</span>${s}</li>`).join('')}</ol>`;
  let body = '';
  if (setup.step === 0) {
    body = `<div class="setup-hero setup-mascot">${W.hashlingSvg()}</div><h2 id="setup-title">Hi, I’m Hashling.</h2>
      <p class="setup-lead">I’m your personal AI cybersecurity agent. I watch over this Mac for you, explain what I see in plain English, and fix things when you say yes.</p>
      <ul class="setup-points">
        <li>${icon('globe')}<span><b>I keep an eye on things.</b> What your apps connect to, what you download, who can see your camera or location, and what your AI apps can do.</span></li>
        <li>${icon('spark')}<span><b>I explain, you decide.</b> Every warning comes with what it means and what to do. No jargon. For extra help, use any AI you trust.</span></li>
        <li>${icon('shield')}<span><b>Nothing changes without you.</b> Every fix waits for your Touch ID. I run on this Mac, with no account and no cloud.</span></li>
      </ul>
      <div class="setup-actions"><button class="btn primary lg" data-act="setup-next">Set up in 2 minutes</button><button class="btn ghost" data-act="setup-skip">Skip, show me the dashboard</button></div>`;
  } else if (setup.step === 1) {
    body = `<h2 id="setup-title">How much detail do you want?</h2><p class="setup-lead">This only changes what you see. I check just as carefully in every mode, and you can switch any time in Settings.</p>
      <div class="mode-pick big" role="radiogroup" aria-label="Detail level">${Object.entries(MODES).map(([k, m]) => `<button type="button" role="radio" aria-checked="${setup.mode === k}" class="mode-opt ${setup.mode === k ? 'on' : ''}" data-act="setup-mode" data-v="${k}"><span class="mode-badge">${esc(m.badge)}</span><b>${m.label}</b><span>${esc(m.blurb)}</span><ul>${m.shows.map((x) => `<li>${icon('check')}${esc(x)}</li>`).join('')}</ul></button>`).join('')}</div>
      <div class="setup-actions"><button class="btn primary lg" data-act="setup-next">Continue with ${MODES[setup.mode].label}</button><button class="btn ghost" data-act="setup-back">Back</button></div>`;
  } else if (setup.step === 2) {
    const ok = setup.fda === true;
    body = `<h2 id="setup-title">Let me see the whole picture</h2><p class="setup-lead">macOS keeps some information private, like which apps can use your camera. Giving me <b>Full Disk Access</b> lets me check those for you. I only look. I change something only when you approve a fix with Touch ID.</p>
      ${ok ? `<div class="status" style="margin:0"><div class="ico">${icon('shieldok', 'lg')}</div><div><b>Full Disk Access is on</b><span class="sub">I can see everything I need.</span></div></div>`
        : `<ol class="howto"><li>Click <b>Open System Settings</b> below.</li><li>Find <b>Hashling</b> in the list and turn it on. If it is not there, click <b>+</b>, open your home folder, then <b>Applications</b>, and choose <b>Hashling</b>.</li><li>macOS may ask for your password. Then come back here and click <b>Check again</b>.</li></ol>
        <div class="row" style="gap:8px"><button class="btn" data-act="settings-pane" data-v="fda">${icon('ext')}Open System Settings</button><button class="btn ghost" data-act="setup-fda-check">Check again</button></div>
        ${setup.fdaRetry ? `<p class="small" style="margin:12px 0 6px">Still off. If you just switched me on, macOS needs me to restart once to notice.</p><button class="btn sm" data-act="setup-restart">Restart Hashling</button>` : ''}`}
      ${ok ? '' : '<p class="small muted" style="margin:14px 0 0">Optional. Without it I still check your network, downloads, startup items, storage and more.</p>'}
      <div class="setup-actions"><button class="btn primary lg" data-act="setup-next">${ok ? 'Continue' : 'Continue without it'}</button><button class="btn ghost" data-act="setup-back">Back</button></div>`;
  } else if (setup.step === 3) {
    const ai = setup.ai;
    body = `<h2 id="setup-title">Connect your AI (optional)</h2><p class="setup-lead">Every warning already comes with a plain explanation. Connect your Claude account and I can also answer your own questions, like “is this app safe?” or “why is my Mac slow?”. Prefer another AI? Any agent that supports MCP (Claude Code, Claude Desktop, Cursor, Codex and others) can work with me too.</p>
      ${ai?.ready ? `<div class="status" style="margin:0"><div class="ico">${icon('shieldok', 'lg')}</div><div><b>Connected${ai.account ? ` as ${esc(ai.account)}` : ''}</b><span class="sub">Ask me anything from the button at the top of every page.</span></div></div>
        <p class="small muted" style="margin:12px 0 0">When you ask me something, your question and what I look up on your Mac go to Claude. Nothing is sent unless you ask, and I only suggest fixes: you make them happen with Touch ID.</p>`
        : `<div class="explain"><p>I can only <b>look</b> and <b>suggest</b>. I cannot change anything on your Mac by myself: every fix I suggest waits for your Touch ID.</p><p style="margin-top:8px">When you ask me something, your question and what I look up on your Mac are sent to that AI’s company and handled under their privacy terms. Nothing is sent unless you ask.</p></div>
        <div class="row" style="gap:8px;margin-top:12px"><button class="btn" data-act="ai-connect">${icon('ext')}Connect Claude</button><button class="btn ghost" data-act="setup-check">Check again</button></div>
        <p class="small muted" style="margin:10px 0 0">Opens Terminal and your browser so you can sign in once. No Claude account? Skip this, everything else works without it.</p>`}
      <div class="setup-actions"><button class="btn primary lg" data-act="setup-next">${ai?.ready ? 'Continue' : 'Skip for now'}</button><button class="btn ghost" data-act="setup-back">Back</button></div>`;
  } else if (setup.step === 4) {
    const row = (on, title, text, button) => `<li class="prot ${on ? 'on' : ''}">${icon(on ? 'check' : 'shield')}<div><b>${title}</b><span>${text}</span></div>${on ? '<span class="chip ok">On</span>' : button}</li>`;
    body = `<h2 id="setup-title">Recommended protection</h2><p class="setup-lead">Two switches most people should turn on. Each takes one click, and you can turn them off any time on the Internet and Malware pages.</p>
      <ul class="prot-list">
        ${row(setup.dns, 'Safe browsing', 'Blocks known scam, phishing and malware websites before they open, in every browser and app. Free, from Quad9, a non-profit.', `<button class="btn sm" data-act="setup-dns">Turn on</button>`)}
        ${row(setup.auto, 'Lock away malware automatically', 'If a scan finds a file that matches known malware, I move it to Quarantine straight away. You can restore it later.', `<button class="btn sm" data-act="setup-auto">Turn on</button>`)}
        ${row(true, 'Warn before risky pastes', 'Already on. I warn you if a website copies a command for Terminal, a common way to install malware.', '')}
      </ul>
      <div class="setup-actions"><button class="btn primary lg" data-act="setup-next">Continue</button><button class="btn ghost" data-act="setup-back">Back</button></div>`;
  } else {
    body = `<div class="setup-hero ok">${icon('check')}</div><h2 id="setup-title">You’re all set</h2><p class="setup-lead">I’m now keeping watch in the background, even when this page is closed.</p>
      <ul class="setup-points">
        <li>${icon('hash')}<span><b>Look for the # in your menu bar</b> at the top of the screen. It shows your score and opens this dashboard.</span></li>
        <li>${icon('alert')}<span><b>I’ll only notify you</b> when something needs you. No noise.</span></li>
        <li>${icon('spark')}<span><b>Click Fix on any warning.</b> I explain exactly what will change and whether you can undo it, then the fix waits in “Approvals” for your Touch ID.</span></li>
      </ul>
      <div class="setup-actions"><button class="btn primary lg" data-act="setup-finish">Show me my Mac’s check-up</button></div>`;
  }
  return `<div class="setup-card" role="dialog" aria-modal="true" aria-labelledby="setup-title">${dots}<div class="setup-body">${body}</div></div>`;
}

function renderSetup() {
  let el = $('#setup');
  if (!el) { el = document.createElement('div'); el.id = 'setup'; el.className = 'setup'; document.body.append(el); }
  el.innerHTML = setupHtml();
  el.hidden = false;
  requestAnimationFrame(() => el.querySelector('.setup-actions .btn.primary')?.focus());
}
async function refreshSetupStatus() {
  const [o, ai, dns, prefs] = await Promise.all([api('/api/overview').catch(() => null), api('/api/ai/status').catch(() => null), api('/api/safe-dns').catch(() => null), api('/api/prefs').catch(() => null)]);
  setup.dns = Boolean(dns?.on);
  setup.auto = Boolean(prefs?.autoQuarantine);
  setup.fda = o ? !(o.limitations ?? []).some((l) => /Full Disk Access/.test(l)) : null;
  setup.ai = ai;
}
async function openSetup() {
  setup.step = 0;
  setup.mode = state.mode ?? 'simple';
  await refreshSetupStatus();
  renderSetup();
}
async function closeSetup(done) {
  if (done) await api('/api/prefs', { method: 'POST', body: { setupDone: true } });
  const el = $('#setup');
  if (el) el.hidden = true;
}

document.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  try {
    if (act === 'help-close') { state.helpHidden.add(el.dataset.v); state.helpHidden.delete(`open:${el.dataset.v}`); saveHidden(); W.render(); }
    else if (act === 'help-open') { state.helpHidden.delete(el.dataset.v); state.helpHidden.add(`open:${el.dataset.v}`); saveHidden(); W.render(); }
    else if (act === 'mode') { await setMode(el.dataset.v); toast(`${MODES[el.dataset.v].label} mode. ${el.dataset.v === 'simple' ? 'Only the pages most people need.' : el.dataset.v === 'expert' ? 'All the technical detail is on.' : 'Every check, explained.'}`); W.render(); }
    else if (act === 'text-size') { applyTextSize(el.dataset.v); W.render(); }
    else if (act === 'theme') { applyTheme(el.dataset.v, true); W.render(); }
    else if (act === 'setup-open') await openSetup();
    else if (act === 'setup-skip') { await closeSetup(true); }
    else if (act === 'setup-mode') { setup.mode = el.dataset.v; renderSetup(); }
    else if (act === 'setup-back') { setup.step = Math.max(0, setup.step - 1); renderSetup(); }
    else if (act === 'setup-next') {
      if (setup.step === 1) { await setMode(setup.mode); W.render(); }
      setup.step = Math.min(STEPS.length - 1, setup.step + 1);
      if (setup.step >= 2) await refreshSetupStatus();
      renderSetup();
    }
    else if (act === 'setup-fda-check') {
      el.disabled = true; el.textContent = 'Checking…';
      const r = await api('/api/recheck-access', { method: 'POST', body: {} }).catch(() => null);
      setup.fda = Boolean(r?.on); setup.fdaRetry = !setup.fda; renderSetup();
    } else if (act === 'setup-restart') {
      el.disabled = true; el.textContent = 'Restarting… (about 15 seconds)';
      const r = await api('/api/recheck-access', { method: 'POST', body: { restart: true } }).catch(() => null);
      if (r?.restarting) {
        // Wait for the new Hashling to answer, then look again.
        await new Promise((ok) => setTimeout(ok, 3000));
        for (let i = 0; i < 30; i++) { if (await fetch('/api/health').then((x) => x.ok).catch(() => false)) break; await new Promise((ok) => setTimeout(ok, 1000)); }
      }
      const again = r?.on ? r : await api('/api/recheck-access', { method: 'POST', body: {} }).catch(() => null);
      setup.fda = Boolean(again?.on); setup.fdaRetry = !setup.fda; renderSetup();
      if (!setup.fda) toast('Still off. Check that the switch next to Hashling is on in Full Disk Access.');
    } else if (act === 'setup-check') { el.disabled = true; await refreshSetupStatus(); renderSetup(); }
    else if (act === 'setup-auto') { await api('/api/prefs', { method: 'POST', body: { autoQuarantine: true } }); await refreshSetupStatus(); renderSetup(); }
    else if (act === 'setup-dns') {
      // Changing network settings needs the Mac password; Hashling creates the change and approves it in one go.
      el.disabled = true; el.textContent = 'Waiting for your password…';
      try {
        const a = await api('/api/actions', { method: 'POST', body: { type: 'safe_dns', target: { on: true }, reason: 'Turn on safe browsing during setup' } });
        await api(`/api/actions/${a.id}/approve`, { method: 'POST' });
      } catch (e) { toast(/cancel|not approved/i.test(e.message) ? 'Not turned on. You can do it later on the Internet page.' : e.message); }
      await refreshSetupStatus(); renderSetup();
    }
    else if (act === 'setup-finish') { await closeSetup(true); location.hash = '#/overview'; W.render(); }
  } catch (e) { if (e.message !== 'unauthorized') toast(e.message); }
});
document.addEventListener('keydown', (e) => {
  const el = $('#setup');
  if (!el || el.hidden) return;
  if (e.key === 'Escape' && setup.step === 0) { closeSetup(true); return; }
  // A dialog keeps keyboard focus inside it: Tab wraps around instead of reaching the page behind.
  if (e.key !== 'Tab') return;
  const focusable = [...el.querySelectorAll('button:not([disabled]), a[href], input, [tabindex]:not([tabindex="-1"])')].filter((x) => x.getClientRects().length);
  if (!focusable.length) return;
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (e.shiftKey && (document.activeElement === first || !el.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && (document.activeElement === last || !el.contains(document.activeElement))) { e.preventDefault(); first.focus(); }
});

// Load preferences before the first render, and greet new users with setup.
const prefs = await api('/api/prefs').catch(() => ({ mode: 'simple', setupDone: true }));
applyMode(prefs.mode);
if (!prefs.setupDone) openSetup();
