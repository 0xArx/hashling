/**
 * Extra protection: breach watch (Accounts), the ransomware brake and text message scam watch
 * (Settings, plus an alert card on the Overview), and "Was this made by AI?" (Scam check).
 */
const W = window.W;
const { views, api, esc, toast, ago, icon, attr, plural } = W;

const state = { media: null, breachBusy: false };

// ---------- Accounts: breach watch ----------
function breachCard(list) {
  const rows = list.map((w) => {
    const n = w.breaches.length;
    const status = w.error && !w.lastCheck ? `<span class="chip warn">Not checked yet</span>` : n ? `<span class="chip bad">In ${plural(n, 'breach', 'breaches')}</span>` : `<span class="chip ok">Not in any known breach</span>`;
    return `<details class="breach-row"${n ? '' : ' data-empty'}><summary><span class="breach-mail">${esc(w.masked)}</span>${status}<span class="small faint breach-when">${w.lastCheck ? `checked ${ago(w.lastCheck)}` : 'checking…'}</span><button class="btn xs ghost" data-act="breach-remove" data-v="${esc(w.email)}">Stop watching</button></summary>
      ${n ? `<ul class="breach-list">${w.breaches.slice(0, 8).map((b) => `<li><div><b>${esc(b.name)}</b>${b.year ? ` <span class="faint">${esc(b.year)}</span>` : ''}${b.domain ? ` <span class="small muted">${esc(b.domain)}</span>` : ''}</div><div class="small muted">Leaked: ${esc(b.data.slice(0, 8).join(', ') || 'account details')}</div></li>`).join('')}${n > 8 ? `<li class="small muted">and ${n - 8} older ${n - 8 === 1 ? 'breach' : 'breaches'}</li>` : ''}</ul>
        <p class="small breach-todo"><b>What to do:</b> change the password on these sites and anywhere you reused it, turn on two-step sign-in for your email, and expect scam emails that mention them.</p>` : ''}
      ${w.error ? `<p class="tiny faint" style="margin:6px 0 0">${esc(w.error)}</p>` : ''}
    </details>`;
  }).join('');
  return `<section class="card pad mt breach-card">
    <div class="row between" style="gap:14px;align-items:flex-start">
      <div><p class="h2" style="margin:0">Breach watch</p>
        <p class="small muted" style="margin:4px 0 0;max-width:64ch">When a company is hacked, its customers’ details often end up for sale online. Add an email you use and I’ll tell you if it shows up in a known breach, and again whenever a new one appears.</p></div>
      ${list.length ? `<button class="btn sm" data-act="breach-check" ${state.breachBusy ? 'disabled' : ''}>${state.breachBusy ? 'Checking…' : 'Check now'}</button>` : ''}
    </div>
    ${rows ? `<div class="breach-rows mt">${rows}</div>` : ''}
    ${list.length < 5 ? `<form class="row breach-add mt" data-form="breach"><input class="input" id="breach-email" type="email" autocomplete="email" placeholder="you@example.com" aria-label="Email address to watch" required><button class="btn primary" ${state.breachBusy ? 'disabled' : ''}>${state.breachBusy ? 'Checking…' : 'Watch this address'}</button></form>` : ''}
    <p class="tiny faint" style="margin:10px 0 0">To look an address up, I send it to <a href="https://xposedornot.com" target="_blank" rel="noopener">XposedOrNot</a>, a free breach database, once a day. Nothing else is sent, and your passwords never leave this Mac.</p>
  </section>`;
}
const baseAccounts = views.accounts;
views.accounts = async () => {
  const [html, list] = await Promise.all([baseAccounts(), api('/api/breaches').catch(() => [])]);
  return breachCard(list) + html;
};

// ---------- Settings: extra protection ----------
const toggle = (on, act, label) => `<button class="switch ${on ? 'on' : ''}" role="switch" aria-checked="${on}" aria-label="${esc(label)}" data-act="${act}" data-v="${on ? '0' : '1'}"><i></i></button>`;
function protectCard(prefs, mw) {
  return `<section class="card pad mt protect-card">
    <p class="h2" style="margin:0 0 4px">Extra protection</p>
    <p class="small muted" style="margin:0 0 14px">Both are off until you switch them on.</p>
    <div class="protect-row"><div><b>Ransomware brake</b><span class="small muted">If something starts scrambling your files, I pause it straight away, before you even see the warning. Pausing loses nothing. You then quit it, or let it carry on if it is yours, with Touch ID.</span></div>${toggle(prefs.ransomBrake, 'pref-brake', 'Ransomware brake')}</div>
    <div class="protect-row"><div><b>Text message scam watch</b><span class="small muted">I read new texts and iMessages on this Mac and warn you about scams, like fake delivery fees and unpaid tolls. Only texts from people you have never written to. Everything stays on this Mac.</span>
      ${prefs.messageWatch ? `<span class="tiny ${mw?.error ? 'warn-text' : 'faint'}" style="display:block;margin-top:6px">${mw?.error ? esc(mw.error) : mw?.at ? `Checked ${plural(mw.scanned, 'text')} so far. ${mw.flagged.length ? `${plural(mw.flagged.length, 'scam')} flagged in the last month.` : 'No scams.'}` : 'Starting…'}</span>` : ''}</div>${toggle(prefs.messageWatch, 'pref-messages', 'Text message scam watch')}</div>
  </section>`;
}
const baseSettings = views.settings;
views.settings = async () => {
  const [html, prefs, mw] = await Promise.all([baseSettings(), api('/api/prefs'), api('/api/message-watch').catch(() => null)]);
  const card = protectCard(prefs, mw);
  return html.startsWith('<section class="help') ? html.replace('</section>', `</section>${card}`) : card + html;
};

// ---------- Overview: something was paused ----------
const baseOverview = views.overview;
views.overview = async () => {
  const [html, paused] = await Promise.all([baseOverview(), api('/api/ransomware/paused').catch(() => [])]);
  if (!paused.length) return html;
  const card = `<section class="status bad paused-card"><div class="ico">${icon('alert', 'lg')}</div><div>
    <b>I paused ${paused.length === 1 ? esc(paused[0].name) : `${paused.length} programs`} because ${paused.length === 1 ? 'it was' : 'they were'} scrambling your files</b>
    <span class="sub">Nothing is lost while ${paused.length === 1 ? 'it is' : 'they are'} paused. If you don’t know ${paused.length === 1 ? 'it' : 'them'}, quit now, turn off Wi-Fi and unplug any backup disk.</span>
    <div class="paused-list">${paused.map((p) => `<div class="paused-item"><span class="mono small">${esc(p.name)}</span><span class="tiny faint">${esc(p.path)} · paused ${ago(p.at)}</span>
      <div class="row" style="gap:6px"><button class="btn sm danger" data-act="propose" data-a="${attr({ type: 'kill_process', target: { pid: p.pid, name: p.name }, reason: `Quit ${p.name}: it was renaming your files like ransomware, so I paused it` })}">Quit it</button><button class="btn sm ghost" data-act="brake-resume" data-v="${p.pid}">It’s mine, let it continue</button></div></div>`).join('')}</div>
  </div></section>`;
  return card + html;
};

// ---------- Scam check: was this made by AI? ----------
function mediaCard() {
  const r = state.media;
  const tone = r?.verdict === 'ai' ? 'bad' : r?.verdict === 'edited' ? 'flag' : '';
  return `<section class="card pad mt media-card">
    <p class="h2" style="margin:0 0 4px">Was this picture or video made by AI?</p>
    <p class="small muted" style="margin:0 0 12px">Many AI tools label what they make. I look for those labels in the file, right here on your Mac.</p>
    <label class="dropzone" data-drop="media">${icon('upload')}<span>${r?.reading ? 'Checking…' : 'Choose a picture or video, or drop it here'}</span><input type="file" id="media-file" accept="image/*,video/*" hidden></label>
    ${r && !r.reading ? `<div class="status ${tone} mt" style="margin-bottom:0"><div class="ico">${icon(r.verdict === 'none' ? 'search' : 'alert', 'lg')}</div><div>
      <b>${r.verdict === 'ai' ? 'Made with AI' : r.verdict === 'edited' ? 'Partly made or changed with AI' : 'No AI label found'}${r.name ? ` <span class="faint small">${esc(r.name)}</span>` : ''}</b>
      <span class="sub">${esc(r.note)}</span>
      ${r.signs.length ? `<ul class="small media-signs">${r.signs.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>` : ''}</div></div>` : ''}
    <details class="fold-lite mt"><summary>Deepfake calls and videos: how to stay safe</summary>
      <ul class="small deepfake-tips">
        <li><b>Agree a family code word.</b> AI can copy a voice from a few seconds of video. If “your son” calls in trouble, ask for the word.</li>
        <li><b>Hang up and call back</b> on the number you already have, not the one that called you.</li>
        <li><b>Money plus pressure means stop.</b> Real banks, police and bosses never need you to pay right now, in gift cards or crypto.</li>
        <li><b>On video, ask them to turn their head</b> or wave a hand in front of their face. Fakes often blur or glitch.</li>
        <li><b>Celebrity investment videos are almost always fake.</b> Famous people do not sell crypto in adverts.</li>
      </ul>
      <button class="btn xs ai" data-act="ask" data-prompt="${esc('I think I might have had a deepfake call or video. Explain in simple words how to tell, and what I should do now.')}">${icon('spark')}Ask Hashling</button>
    </details>
  </section>`;
}
const baseScam = views.scamcheck;
views.scamcheck = async () => (await baseScam()) + mediaCard();

async function checkMediaFile(file) {
  if (!file) return;
  state.media = { reading: true };
  W.render();
  try {
    const r = await (await fetch('/api/ai-media', { method: 'POST', body: file, credentials: 'same-origin' })).json();
    if (r.error) throw new Error(r.error);
    state.media = { ...r, name: file.name };
  } catch (e) { state.media = null; toast(e.message); }
  W.render();
}
document.addEventListener('change', (e) => { if (e.target.id === 'media-file') void checkMediaFile(e.target.files?.[0]); });
document.addEventListener('dragover', (e) => { if (e.target.closest?.('[data-drop="media"]')) { e.preventDefault(); e.target.closest('[data-drop]').classList.add('over'); } });
document.addEventListener('dragleave', (e) => e.target.closest?.('[data-drop="media"]')?.classList.remove('over'));
document.addEventListener('drop', (e) => { const z = e.target.closest?.('[data-drop="media"]'); if (!z) return; e.preventDefault(); z.classList.remove('over'); void checkMediaFile(e.dataTransfer.files?.[0]); });

// ---------- Actions ----------
document.addEventListener('submit', async (e) => {
  if (e.target.dataset.form !== 'breach') return;
  e.preventDefault();
  const email = document.getElementById('breach-email').value;
  state.breachBusy = true; W.render();
  try { await api('/api/breaches', { method: 'POST', body: { email } }); toast('Watching it. I’ll check again every day.'); }
  catch (err) { toast(err.message); }
  state.breachBusy = false; W.render();
});
document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act^="breach-"], [data-act^="pref-"], [data-act="brake-resume"]');
  if (!el) return;
  const act = el.dataset.act;
  e.preventDefault();
  try {
    if (act === 'breach-check') { state.breachBusy = true; W.render(); await api('/api/breaches/check', { method: 'POST' }); toast('Checked every address just now.'); }
    else if (act === 'breach-remove') { await api(`/api/breaches/${encodeURIComponent(el.dataset.v)}`, { method: 'DELETE' }); toast('I’ve stopped watching that address and forgotten what I found.'); }
    else if (act === 'pref-brake') { await api('/api/prefs', { method: 'POST', body: { ransomBrake: el.dataset.v === '1' } }); toast(el.dataset.v === '1' ? 'Ransomware brake is on.' : 'Ransomware brake is off. I’ll still warn you.'); }
    else if (act === 'pref-messages') { await api('/api/prefs', { method: 'POST', body: { messageWatch: el.dataset.v === '1' } }); toast(el.dataset.v === '1' ? 'Text watch is on. Checking your last week of texts now.' : 'Text watch is off, and I’ve forgotten what it found.'); }
    else if (act === 'brake-resume') { toast('Confirm with Touch ID…'); await api(`/api/ransomware/resume/${encodeURIComponent(el.dataset.v)}`, { method: 'POST' }); toast('It can carry on now.'); }
  } catch (err) { toast(err.message); }
  state.breachBusy = false;
  W.render();
});
