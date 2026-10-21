/**
 * Hover explanations. Point at almost any label (a menu item, a heading, a button, a tag like
 * "Quarantine" or "High risk") and a small bubble says what it means in plain words. Keyboard
 * users get the same bubble on focus. The first bubble waits a moment so it never pops up by
 * accident; after that, moving along shows the next one straight away.
 */
const W = window.W;

/** Plain words for the labels people meet in Hashling, keyed by the label in lowercase. */
const HINTS = {
  // Pages
  'overview': 'Your home page: how safe this Mac is right now and what needs you first.',
  'assistant': 'Chat with me. Ask anything about this Mac and I check it before I answer.',
  'scam check': 'Paste a text, email or link, or add a screenshot, and I tell you if it looks like a scam.',
  'approvals': 'Fixes waiting for your yes. Nothing on your Mac changes until you approve with Touch ID.',
  'network': 'Which apps are using the internet, how much they send, and who they talk to.',
  'internet': 'Which apps are using the internet, how much they send, and who they talk to.',
  'ai agents': 'AI tools on this Mac, like Claude or Cursor, and what each one is allowed to do.',
  'ai apps': 'AI tools on this Mac, like Claude or Cursor, and what each one is allowed to do.',
  'processes': 'Every program that runs on this Mac, and who started it. Malware has to run to do harm.',
  'malware': 'Software made to harm you or steal from you. I scan for it with several free engines.',
  'downloads & apps': 'Where new files and apps came from, and whether their maker is verified by Apple.',
  'apps & downloads': 'Where new files and apps came from, and whether their maker is verified by Apple.',
  'uploads': 'How much each app sent off this Mac this week, and where it went.',
  'startup items': 'Programs set to start by themselves when you log in. Malware likes to hide here.',
  'permissions': 'Which apps can use your camera, microphone, screen, files or location.',
  'privacy': 'Which apps can use your camera, microphone, screen, files or location.',
  'keys & secrets': 'Passwords and keys left in plain files, where a bad program or tricked AI could read them.',
  'tracking': 'Hidden trackers like AirTags that follow you, and apps that know your location.',
  'trackers & location': 'Hidden trackers like AirTags that follow you, and apps that know your location.',
  'system settings': 'The Mac settings that matter most for safety, like encryption and the firewall.',
  'storage & speed': 'What fills your disk and what slows your Mac, with safe ways to free space.',
  'findings': 'Everything I have noticed, from most to least important.',
  'ignored': 'Warnings you told me to stop showing. You can bring any of them back.',
  'timeline': 'A diary of what happened on this Mac and when.',
  'account safety': 'The few settings that keep your email, Apple Account and bank safe.',
  'i think i’ve been hacked': 'Calm, step-by-step help for when something feels wrong.',
  'settings': 'How Hashling works for you: detail level, AI helper, phone and protection switches.',
  'phone check-up': 'Plug in a phone with a cable and I check it for spyware signs. I only read, never change it.',
  'activity': 'Your score and what happened recently.',
  'monitor': 'The areas I keep an eye on all the time.',
  'optimize': 'Ways to free up space and speed your Mac up.',
  // Overview
  'needs your attention': 'The things I found that matter most. Click one for a plain explanation and a fix.',
  'what i’m watching': 'Every area I check. Coloured tiles have something to look at; the rest are all clear.',
  'right now': 'A live look at this Mac in this moment.',
  'since yesterday': 'What is new compared with what I learned is normal for this Mac.',
  'security score': 'A number out of 100 for how safe this Mac is. Higher is safer.',
  'just now': 'The latest things that happened on this Mac.',
  'your to-do list': 'A few simple things to do now. Each has one button.',
  'linked warning signs': 'Several odd things done by the same program, which together look like malware.',
  'apps online': 'How many apps are using the internet right now.',
  'waiting for you': 'Fixes waiting for your yes in Approvals.',
  'coming in': 'How fast data is arriving on this Mac right now.',
  'going out': 'How fast data is leaving this Mac right now.',
  'out of': 'Your security score. Higher is safer.',
  // Tiers and tags
  'suspicious': 'Looks like something harmful. Look at these first.',
  'worth fixing': 'Not harmful by itself, but a weak spot someone could use.',
  'optional': 'Nice-to-have extra protection. Nothing is wrong.',
  'all clear': 'I checked this area and found nothing to worry about.',
  'not checked yet': 'I can’t look here yet, usually because a permission is missing.',
  'high risk': 'This tool can do a lot on your Mac, like run programs, without asking you first.',
  'medium risk': 'This tool can do some risky things. Worth a look at what it is allowed to do.',
  'some risk': 'This tool can do some risky things. Worth a look at what it is allowed to do.',
  'low risk': 'This tool can’t do much harm with its current settings.',
  'live': 'I’m connected and these numbers update by themselves.',
  'new': 'First time I have seen this on your Mac.',
  'technique': 'This program did something malware is known for.',
  'done': 'This fix was carried out.',
  'didn’t work': 'This fix could not be carried out. Nothing else was changed.',
  'rejected': 'You said no, so nothing changed.',
  'archived': 'Nobody decided within a day, so I put it aside. Nothing changed.',
  'important, stays here until you decide': 'A serious fix. It waits until you decide instead of being archived.',
  // Approvals and safety words
  'quarantine': 'A locked box for dangerous files. A file in quarantine can’t run, and you can put it back later.',
  'blocked domains': 'Websites I stop every app on this Mac from reaching. You can unblock them any time.',
  'history': 'Every fix that was suggested, and what happened to it.',
  'security fixes': 'Changes that close a security problem. Each needs your Touch ID.',
  'free up space': 'Clean-ups that free disk space. Everything goes to the Trash, so you can get it back.',
  'archived suggestions': 'Suggestions nobody decided on within a day. Nothing changed. Bring any back if you want it.',
  'breach watch': 'I check whether your email turned up in a company’s data leak, and tell you about new ones.',
  'extra protection': 'Extra shields you can switch on. Both stay off until you do.',
  'ransomware brake': 'If something starts scrambling your files, I pause it straight away so it can’t do more damage.',
  'text message scam watch': 'I read new texts on this Mac and warn you about scams. Nothing leaves your Mac.',
  'your phone': 'Use Hashling from your phone over your own Wi-Fi, or check your phone for spyware with a cable.',
  // Buttons
  'run an ai check-up': 'Your AI looks over everything I found and explains what to do first, in plain words.',
  'see everything i found': 'The full list of what I noticed, most important first.',
  'ask hashling': 'Open the side panel and ask me anything about this Mac.',
  'explain': 'Get a plain-words explanation of this from your AI.',
  'fix': 'Let your AI suggest a fix. Nothing changes until you approve it.',
  'ignore': 'Stop showing this warning. You can bring it back from the Ignored page.',
  'approve': 'Do it now. macOS asks for Touch ID or your password first.',
  'approve all': 'Do all of these. macOS asks for Touch ID once.',
  'reject': 'Say no. Nothing changes.',
  'reject all': 'Say no to all of these. Nothing changes.',
  'should i?': 'Ask your AI whether this is a good idea before you decide.',
  'claude': 'Open this in the Claude app to talk it through there.',
  'bring back': 'Put this suggestion back on your list so you can decide on it.',
  'dismiss': 'Close this suggestion for good. Nothing changes.',
  'block domain…': 'Stop every app on this Mac from reaching that website.',
  'restore…': 'Put this file back where it was. Only do it if you are sure it is safe.',
  'look at it': 'Open this warning for a plain explanation and what to do.',
  'review': 'Go to Approvals to say yes or no.',
  'brief me': 'Your AI sums up what is new since yesterday and whether it matters.',
  'check it': 'Check this message for scam warning signs.',
  'see all': 'Show the full list.',
};

const norm = (s) => s.replace(/[\d,]+(\.\d+)?\s*(kb\/s|mb\/s|b\/s)?/gi, ' ').replace(/[“”"]/g, '').replace(/'/g, '’').replace(/\s+/g, ' ').trim().toLowerCase();
const SELECTOR = '.nav a, .nav-group, .h2, .h3, .area .name, .area .state, .sev, .tier-tag, .chip, .badge-risk, .risk, .btn, .ask, .live, .ov-now span, .section-head a, th, .crucial-tag, summary b, .tier-head b, .protect-row b, .ov-limits b, [data-tip]';

function hintFor(el) {
  if (el.dataset.tip) return el.dataset.tip;
  if (el.closest('.term')) return null; // the glossary already explains these words
  const key = norm(el.textContent ?? '');
  if (!key || key.length > 48) return null;
  return HINTS[key] ?? HINTS[key.replace(/^(\d+\s*)/, '')] ?? null;
}

// One bubble for the whole page.
const tip = document.createElement('div');
tip.className = 'hint-bubble';
tip.id = 'hint-bubble';
tip.setAttribute('role', 'tooltip');
tip.hidden = true;
document.body.appendChild(tip);

let showTimer = 0, hideTimer = 0, warm = 0, current = null;
function place(el) {
  // Aim at the words themselves: a heading's box can be much wider than its text.
  const range = document.createRange();
  range.selectNodeContents(el);
  const tr = range.getBoundingClientRect();
  const r = tr.width ? tr : el.getBoundingClientRect();
  const b = tip.getBoundingClientRect();
  const below = r.top < b.height + 16;
  const x = Math.max(10, Math.min(innerWidth - b.width - 10, r.left + r.width / 2 - b.width / 2));
  tip.style.left = `${x}px`;
  tip.style.top = `${below ? r.bottom + 8 : r.top - b.height - 8}px`;
  tip.dataset.side = below ? 'below' : 'above';
  tip.style.setProperty('--tx', `${Math.max(14, Math.min(b.width - 14, r.left + r.width / 2 - x))}px`);
}
function show(el, text) {
  current = el;
  tip.textContent = text;
  tip.hidden = false;
  tip.classList.remove('in');
  place(el);
  el.setAttribute('aria-describedby', 'hint-bubble');
  requestAnimationFrame(() => tip.classList.add('in'));
  warm = Date.now();
}
function hide() {
  clearTimeout(showTimer);
  if (current) current.removeAttribute('aria-describedby');
  current = null;
  tip.classList.remove('in');
  tip.hidden = true;
}
function arm(el, delay) {
  const text = hintFor(el);
  if (!text) return;
  clearTimeout(showTimer);
  clearTimeout(hideTimer);
  // Already reading bubbles: skip the wait, so moving along the menu feels instant.
  const instant = Date.now() - warm < 700;
  showTimer = setTimeout(() => show(el, text), instant ? 0 : delay);
}

const finePointer = matchMedia('(hover: hover) and (pointer: fine)');
document.addEventListener('pointerover', (e) => {
  if (!finePointer.matches) return;
  const el = e.target.closest?.(SELECTOR);
  if (!el || el === current) return;
  arm(el, 550);
});
document.addEventListener('pointerout', (e) => {
  const el = e.target.closest?.(SELECTOR);
  if (!el || (e.relatedTarget && el.contains(e.relatedTarget))) return;
  clearTimeout(showTimer);
  if (current) { warm = Date.now(); hideTimer = setTimeout(hide, 60); }
});
document.addEventListener('focusin', (e) => { const el = e.target.closest?.(SELECTOR); if (el && e.target.matches(':focus-visible')) arm(el, 250); });
document.addEventListener('focusout', hide);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });
addEventListener('scroll', hide, { passive: true, capture: true });
document.addEventListener('pointerdown', hide);

// Headings that have an explanation get a faint dotted underline, so people learn they can point at them.
function markHeadings(root) {
  for (const el of root.querySelectorAll('.h2, .h3, .section-head p')) if (hintFor(el)) el.classList.add('has-hint');
}
const baseHydrate = W.hydrate;
W.hydrate = (root) => { baseHydrate?.(root); markHeadings(root); };
markHeadings(document);
W.HINTS = HINTS;
