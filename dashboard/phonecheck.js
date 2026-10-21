// Phone check-up: plug a phone into this Mac with a cable and I look inside it, read-only.
// Loaded by app.js before guide.js, so the page gets the beginner layer ("About this page", Simple names).
const W = window.W;
const { views, api, esc, icon, toast, ago, bytes, askBtn, state } = W;

W.P.mobile = '<rect x="6.5" y="2.5" width="11" height="19" rx="2.6"/><path d="M10.5 18.5h3"/>';
W.P.cable = '<path d="M12 2v5"/><path d="M9 7h6v4a3 3 0 0 1-6 0z"/><path d="M12 14v3a4 4 0 0 0 4 4h2"/>';
const last = W.NAV[W.NAV.length - 1][1];
last.splice(last.findIndex(([id]) => id === 'settings'), 0, ['phonecheck', 'Phone check-up', 'mobile', 'phonecheck']);
Object.assign(W.TITLES, { phonecheck: ['Phone check-up', 'Plug your phone into this Mac with a cable and I’ll check it for stalkerware, spy profiles and missing updates'] });
Object.assign(W.CAT, { phone: 'Phone check-up' });
Object.assign(W.LIVE, { phonecheck: ['phonecheck', 'phoneReports', 'phone'] });

/** “Abdul’s iPhone” stays as is; a plain “iPhone” becomes “your iPhone”. */
const yours = (name) => (/['’]s\b/.test(name) ? name : `your ${name}`);
const Yours = (name) => { const y = yours(name); return y[0].toUpperCase() + y.slice(1); };

const ui = { password: '', open: new Set(), deepOk: new Set(), dismissed: 0 };
const STATE_CHIP = {
  ready: ['ok', 'Ready'], 'needs-trust': ['warn', 'Needs your OK'], 'trust-pending': ['warn', 'Waiting for you'], locked: ['warn', 'Locked'], denied: ['bad', 'Not trusted'],
  'needs-tools': ['', 'Needs tools'], 'needs-debugging': ['warn', 'USB debugging off'], 'needs-allow': ['warn', 'Waiting for you'], offline: ['bad', 'Not answering'],
};
const STATUS_ICO = { ok: ['ok', 'check'], warn: ['warn', 'alert'], bad: ['fail', 'alert'], info: ['opt', 'plus'] };

const ANDROID_STEPS = `<ol class="small phone-steps">
  <li>Open <b>Settings</b> &gt; <b>About phone</b> and tap <b>Build number</b> seven times. (On Samsung: About phone &gt; Software information.) It says you are now a developer.</li>
  <li>Go back to Settings, open <b>Developer options</b> (often under System) and turn on <b>USB debugging</b>.</li>
  <li>Plug the phone in. When it asks <b>Allow USB debugging?</b>, tap <b>Allow</b>.</li>
  <li>When we’re done, turn USB debugging off again.</li></ol>`;

function busyCard(job) {
  const pct = job.pct ?? Math.round(((job.step - 0.5) / Math.max(1, job.total)) * 100);
  const what = { install: 'Getting the tools', check: 'Checking your phone', deep: 'Deep spyware check' }[job.kind];
  return `<section class="card pad measuring pc-busy" aria-live="polite"><div class="row between" style="gap:10px"><b>${what}: step ${job.step || 1} of ${job.total}</b><span class="small faint">started ${esc(ago(job.startedAt))}</span></div>
    <div class="measure-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><span style="width:${Math.max(4, Math.min(100, pct))}%"></span></div>
    <p class="small muted" style="margin:8px 0 0">${esc(job.label)}${job.pct != null ? ` (${job.pct}%)` : ''}…${job.kind === 'deep' ? ' This can take a long time with lots of photos. You can leave this page.' : ''}</p></section>`;
}

function toolsBlock(platform, t) {
  if (platform === 'ios') return `<div class="pc-tools"><p class="small" style="margin:0 0 8px">To read an iPhone I use two free, open-source tools: <b>libimobiledevice</b> and <b>pymobiledevice3</b>. About 200 MB, no password needed. They only ask the phone questions.</p>
    <button class="btn primary" data-act="pc-tools" data-v="ios"${t.brew ? '' : ' disabled'}>${icon('plus')}Get the tools</button></div>`;
  return `<div class="pc-tools"><p class="small" style="margin:0 0 8px">To read an Android phone I use <b>adb</b>, Google’s free tool for talking to Android over a cable. About 15 MB, no password needed.</p>
    <button class="btn primary" data-act="pc-tools" data-v="android"${t.brew ? '' : ' disabled'}>${icon('plus')}Get the tools</button></div>`;
}

function deviceCard(d, st, report) {
  const [tone, label] = STATE_CHIP[d.state] ?? ['', d.state];
  const busy = Boolean(st.job);
  const mine = st.job?.deviceId === d.id;
  let action = '';
  if (d.state === 'ready') action = `<button class="btn primary" data-act="pc-check" data-id="${esc(d.id)}"${busy ? ' disabled' : ''}>${icon('shield')}${mine && st.job.kind === 'check' ? 'Checking…' : report ? 'Check again' : 'Check my phone'}</button>`;
  else if (d.state === 'needs-trust' || d.state === 'denied') action = `<button class="btn primary" data-act="pc-trust" data-id="${esc(d.id)}">Ask my phone to trust this Mac</button>`;
  else if (d.state === 'trust-pending' || d.state === 'needs-allow') action = `<span class="step small"><span class="spin"></span>Waiting for you to tap ${d.platform === 'ios' ? 'Trust' : 'Allow'} on the phone</span>`;
  const extra = d.state === 'needs-tools' ? toolsBlock(d.platform, st.tools) : d.state === 'needs-debugging' ? `<div class="pc-tools">${ANDROID_STEPS}</div>` : '';
  return `<div class="item pc-device"><span class="ph-ico">${icon('mobile')}</span>
    <div class="body"><div class="t">${esc(d.name)} <span class="chip ${tone}">${esc(label)}</span></div>
      <div class="s">${esc([d.model !== d.name ? d.model : '', d.os].filter(Boolean).join(' · ') || (d.platform === 'ios' ? 'iPhone or iPad' : 'Android phone'))}</div>
      <div class="s">${esc(d.hint)}</div>${extra}</div>
    <div class="side-r">${action}</div></div>`;
}

function emptyCard(st) {
  return `<section class="card pad pc-empty">
    <div class="pc-plug" aria-hidden="true">${icon('mobile')}<span class="pc-wire"></span>${icon('cable')}</div>
    <p class="h2" style="margin:0">Plug your phone into this Mac with a cable</p>
    <p class="muted" style="margin:6px auto 0;max-width:56ch">I notice it by myself and offer a check. I only read: I never change anything on your phone, and nothing I read leaves this Mac.</p>
    <div class="g2 pc-how mt">
      <div><p class="h3">iPhone or iPad</p><ol class="small phone-steps"><li>Plug it in and unlock it.</li><li>Tap <b>Trust</b> when it asks <b>Trust This Computer?</b>, then enter your passcode.</li><li>Press <b>Check my phone</b> here.</li></ol></div>
      <div><p class="h3">Android</p>${ANDROID_STEPS}</div>
    </div>
    ${st.tools.ios ? '' : `<p class="tiny faint" style="margin:14px 0 0">The first time, I’ll ask to get a couple of free, open-source tools. No password needed.</p>`}
  </section>`;
}

const WHAT_I_CHECK = `<section class="mt"><p class="h3" style="margin:0 0 10px">What I check</p><ul class="rules">
  <li>${icon('check')}<span><b>Stalkerware:</b> apps that secretly send your messages, location and photos to someone else, matched against the open list kept by Echap, a member of the Coalition Against Stalkerware.</span></li>
  <li>${icon('check')}<span><b>Apps from outside the App Store or Play Store,</b> and apps that can read your screen, your notifications or make themselves hard to remove.</span></li>
  <li>${icon('check')}<span><b>Hidden settings:</b> configuration profiles, certificates and remote management that hand control of the phone to someone else.</span></li>
  <li>${icon('check')}<span><b>Quiet watchers:</b> location-sharing and “family safety” apps, keyboards that could read what you type, apps that can follow you in the background, and on Android, apps that took over texting, can see which apps you use, or can draw fake screens.</span></li>
  <li>${icon('check')}<span><b>How locked down it is:</b> latest security fixes, passcode, Developer Mode and wireless debugging, an unlocked bootloader, and when it was last backed up.</span></li>
  <li>${icon('check')}<span><b>Deep check (iPhone, optional):</b> Amnesty International’s Mobile Verification Toolkit looks for traces of spyware like Pegasus in a backup.</span></li>
</ul></section>`;

function itemRow(r, i) {
  const [cls, ic] = STATUS_ICO[i.status];
  const key = `${r.id}:${i.id}`;
  const list = i.list?.length ? `<details class="pc-list"${ui.open.has(key) ? ' open' : ''} data-key="${esc(key)}"><summary class="small">${i.list.length === 1 ? 'Show it' : `Show all ${i.list.length}`}</summary>
    <ul>${i.list.map((x) => `<li class="${x.flag ?? ''}"><b>${esc(x.name)}</b><span>${esc(x.note)}</span></li>`).join('')}</ul></details>` : '';
  const ask = i.status === 'warn' || i.status === 'bad'
    ? `<div class="row-actions">${askBtn({ kind: 'phone-check', phone: r.name, platform: r.platform, os: r.os, check: i.title, detail: i.detail, fix: i.fix, items: i.list?.slice(0, 25) }, 'Help me with this', `My ${r.platform === 'ios' ? 'iPhone' : 'Android phone'} check-up says: "${i.title}". Explain what it means for me in plain words, how worried I should be, and walk me through fixing it on the phone. If it could be stalkerware, tell me how to stay safe first.`)}</div>` : '';
  return `<div class="check"><span class="badge-ico ${cls}">${icon(ic)}</span><div><b>${esc(i.title)}</b><div class="why">${esc(i.detail)}</div>${i.fix && i.status !== 'ok' ? `<div class="fix"><b>What to do:</b> ${esc(i.fix)}</div>` : ''}${list}${ask}</div></div>`;
}

function deepCard(r, st) {
  if (r.platform !== 'ios') return '';
  const sp = st.space[r.id] ?? { need: 0, free: 0, enough: false };
  const plugged = st.devices.find((d) => d.id === r.id && d.state === 'ready');
  const res = r.deep?.result;
  const GB = (b) => `${Math.max(1, Math.round(b / 1e9))} GB`;
  const head = `<p class="h2" style="margin:0">Deep spyware check <span class="tier-tag hardening">Optional</span></p>
    <p class="small muted" style="margin:6px 0 0;max-width:70ch">For when you have a real reason to worry, like a journalist, activist, or someone being stalked. I make a backup of the phone on this Mac and Amnesty International’s free <b>Mobile Verification Toolkit</b> looks in it for traces of known spyware. Then I delete the backup.</p>`;
  if (st.job?.kind === 'deep' && st.job.deviceId === r.id) return `<section class="card pad mt pc-deep">${head}</section>`;
  const last = res ? `<p class="small" style="margin:10px 0 0">${res.error ? `Last try didn’t finish: ${esc(res.error)}` : res.detections ? `<b class="crucial-tag">Last deep check (${esc(ago(res.at))}) found ${res.detections} sign${res.detections === 1 ? '' : 's'} of known spyware.</b>` : `Last deep check ${esc(ago(res.at))}: no known spyware.`}</p>` : '';
  let body;
  if (!st.tools.mvt) body = `<div class="row mt" style="gap:10px"><button class="btn" data-act="pc-tools" data-v="mvt"${st.job ? ' disabled' : ''}>${icon('plus')}Get MVT (about 75 MB)</button><span class="small faint">Free and open source, from Amnesty International.</span></div>`;
  else if (!plugged) body = `<p class="small faint" style="margin:10px 0 0">Plug this phone in and unlock it to run the deep check.</p>`;
  else {
    const needPw = r.deep?.encrypted;
    body = `<div class="pc-space mt"><div><b>${GB(sp.need)}</b><span>free space I need, at most</span></div><div><b>${GB(sp.free)}</b><span>free on this Mac now</span></div><div><b>${r.deep?.encrypted === true ? 'Encrypted' : r.deep?.encrypted === false ? 'Not encrypted' : 'Not sure'}</b><span>your phone’s backups</span></div></div>
      ${sp.enough ? '' : `<div class="status flag mt"><div class="ico">${icon('alert', 'lg')}</div><div><b>Not enough free space</b><span class="sub">The backup could need up to ${GB(sp.need)}. Free up space first in <a href="#/optimize">Storage &amp; speed</a>.</span></div></div>`}
      ${needPw ? `<label class="label mt" for="pc-pw" style="display:block">Backup password</label><input id="pc-pw" class="input" type="password" autocomplete="off" placeholder="The one you chose for “Encrypt local backup”" style="width:min(360px,100%)"><p class="tiny faint" style="margin:6px 0 0">Not your phone passcode. I only use it to open the backup on this Mac and never save it.</p>`
        : `<p class="tiny faint" style="margin:10px 0 0">${r.deep?.encrypted == null ? 'Your phone didn’t say whether its backups are encrypted. If they are, the deep check stops and tells you. ' : ''}Tip: an encrypted backup lets MVT see more. If you want that, turn on <b>Encrypt local backup</b> in Finder (click your phone in the sidebar) and run this again. I won’t change that setting for you.</p>`}
      <label class="pc-ok mt"><input type="checkbox" data-act="pc-deep-ok" data-id="${esc(r.id)}"${ui.deepOk.has(r.id) ? ' checked' : ''}> I understand: you’ll make a temporary backup of my phone here (up to ${GB(sp.need)}), check it, then delete it. My phone may ask for its passcode.</label>
      <div class="row mt" style="gap:10px"><button class="btn primary" data-act="pc-deep" data-id="${esc(r.id)}"${sp.enough && ui.deepOk.has(r.id) && !st.job ? '' : ' disabled'}>${icon('search')}Start the deep check</button><span class="small faint">Keep the phone plugged in and unlocked.</span></div>`;
  }
  return `<section class="card pad mt pc-deep">${head}${last}${body}</section>`;
}

const ONLY_YOU = {
  ios: ['<b>Safety Check:</b> Settings &gt; Privacy &amp; Security &gt; Safety Check shows who you share your location and data with, and can stop it all at once.', '<b>Your Apple Account devices:</b> Settings &gt; your name, scroll down. Remove any device you don’t own.', '<b>Find My sharing:</b> Find My app &gt; People. Stop sharing with anyone you didn’t choose.'],
  android: ['<b>Your Google account devices:</b> Settings &gt; Google &gt; Manage your Google Account &gt; Security &gt; Your devices.', '<b>Location sharing:</b> Google Maps &gt; your picture &gt; Location sharing.', '<b>Play Protect scan:</b> Play Store &gt; your picture &gt; Play Protect &gt; Scan.'],
};

/** A few plain numbers about the phone, above the checks. */
function glance(r) {
  const f = r.facts ?? {};
  const cells = [
    [r.os, r.model],
    f.apps != null ? [String(f.apps), 'apps installed'] : null,
    f.storageUsed && f.storageTotal ? [bytes(f.storageUsed), `used of ${bytes(f.storageTotal)}`] : null,
    f.backupOn === false ? ['Off', 'iCloud Backup'] : f.lastBackup ? [ago(f.lastBackup), 'last iCloud backup'] : null,
  ].filter(Boolean);
  return cells.length > 1 ? `<div class="pc-glance">${cells.map(([b, s]) => `<div><b>${esc(b)}</b><span>${esc(s)}</span></div>`).join('')}</div>` : '';
}

function reportCard(r, st) {
  const tone = r.verdict === 'worry' ? 'bad' : r.verdict === 'look' ? 'flag' : '';
  const order = { bad: 0, warn: 1, ok: 2, info: 3 };
  const items = [...r.items].sort((a, b) => order[a.status] - order[b.status]);
  return `<section class="mt pc-report">
    <div class="section-head"><p class="h2">${esc(r.name)}</p><span class="small faint">${esc([r.model !== r.name ? r.model : '', r.os].filter(Boolean).join(' · '))} · checked ${esc(ago(r.checkedAt))}</span></div>
    <div class="status ${tone}"><div class="ico">${icon(r.verdict === 'clear' ? 'shieldok' : 'alert', 'lg')}</div><div><b>${esc(r.headline)}</b><span class="sub">${r.verdict === 'worry' ? 'Read the red items first. Nothing on your phone has been changed.' : r.verdict === 'look' ? 'Nothing looks like spyware. A few things are worth a minute.' : 'Your phone looks clean from here.'}<span class="adv"> · ${W.plural(r.counts.apps ?? 0, 'app')}, ${r.counts.outsideStore ?? 0} from outside a store${r.counts.profiles != null ? `, ${W.plural(r.counts.profiles, 'profile')}` : ''}</span></span></div>
      <div class="actions">${askBtn({ kind: 'phone-report', phone: r.name, platform: r.platform, os: r.os, headline: r.headline, items: r.items.filter((i) => i.status !== 'ok').map((i) => ({ status: i.status, title: i.title, detail: i.detail, items: i.list?.slice(0, 15) })) }, 'Explain with AI', 'Use phone_checkup to read my phone check-up. Tell me in plain words what matters most, what to do first on the phone, and what I can ignore. If anything could be stalkerware, tell me how to stay safe before removing it.')}</div></div>
    ${r.notes.length ? `<p class="small muted" style="margin:-8px 0 12px">${r.notes.map(esc).join(' ')}</p>` : ''}
    ${glance(r)}
    <div class="list">${items.map((i) => itemRow(r, i)).join('')}</div>
    ${deepCard(r, st)}
    <section class="mt"><p class="h3" style="margin:0 0 10px">Things only you can check on the phone</p><ul class="rules">${ONLY_YOU[r.platform].map((t) => `<li>${icon('check')}<span>${t}</span></li>`).join('')}</ul></section>
    <div class="row mt" style="justify-content:flex-end"><button class="btn sm ghost" data-act="pc-forget" data-id="${esc(r.id)}">${icon('trash')}Forget this report</button></div>
  </section>`;
}

views.phonecheck = async () => {
  const st = await api('/api/phonecheck');
  state.phonecheck = st;
  const byId = Object.fromEntries(st.reports.map((r) => [r.id, r]));
  const err = st.lastError && st.lastError.at !== ui.dismissed && Date.now() - st.lastError.at < 10 * 60_000
    ? `<div class="status bad"><div class="ico">${icon('alert', 'lg')}</div><div><b>That didn’t work</b><span class="sub">${esc(st.lastError.message)}</span></div><div class="actions"><button class="btn sm" data-act="pc-dismiss">OK</button></div></div>` : '';
  const devices = st.devices.length
    ? `<section class="card pc-devices"><div class="list" style="border:0;box-shadow:none">${st.devices.map((d) => deviceCard(d, st, byId[d.id])).join('')}</div></section>`
    : emptyCard(st);
  const reports = st.reports.map((r) => reportCard(r, st)).join('');
  return `${st.job ? busyCard(st.job) : ''}${err && !st.job ? err : ''}${devices}${reports}${st.reports.length ? '' : WHAT_I_CHECK}`;
};

// The Home page offers the check as soon as a phone is plugged in.
const baseOverview = views.overview;
views.overview = async () => {
  const [html, st] = await Promise.all([baseOverview(), api('/api/phonecheck').catch(() => null)]);
  const fresh = (st?.devices ?? []).filter((d) => !st.reports.some((r) => r.id === d.id && Date.now() - r.checkedAt < 3600_000));
  if (!fresh.length) return html;
  const d = fresh[0];
  const banner = `<a class="pc-banner" href="#/phonecheck"><span class="ph-ico">${icon('mobile')}</span><span><b>${esc(Yours(d.name))} is plugged in</b><span class="small muted">Want me to check it for stalkerware, spy profiles and missing updates? Nothing on the phone changes.</span></span><span class="btn sm primary">Check it</span></a>`;
  return banner + html;
};

// Keep a typed backup password (and open lists) across live refreshes.
const baseHydrate = W.hydrate;
W.hydrate = (root) => {
  baseHydrate?.(root);
  const pw = root.querySelector('#pc-pw');
  if (pw) pw.value = ui.password;
};
document.addEventListener('input', (e) => { if (e.target.id === 'pc-pw') ui.password = e.target.value; });
document.addEventListener('toggle', (e) => {
  const el = e.target;
  if (!el.classList?.contains('pc-list')) return;
  el.open ? ui.open.add(el.dataset.key) : ui.open.delete(el.dataset.key);
}, true);

document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act^="pc-"]');
  if (!el) return;
  const act = el.dataset.act;
  const id = el.dataset.id;
  try {
    if (act === 'pc-deep-ok') {
      el.checked ? ui.deepOk.add(id) : ui.deepOk.delete(id);
      const btn = document.querySelector(`[data-act="pc-deep"][data-id="${CSS.escape(id)}"]`);
      const sp = state.phonecheck?.space?.[id];
      if (btn) btn.disabled = !(el.checked && sp?.enough && !state.phonecheck?.job);
      return;
    }
    if (act === 'pc-tools') { el.disabled = true; await api(`/api/phonecheck/tools/${encodeURIComponent(el.dataset.v)}`, { method: 'POST' }); toast('Getting the tools. This takes a minute or two.'); }
    else if (act === 'pc-trust') { const r = await api(`/api/phonecheck/trust/${encodeURIComponent(id)}`, { method: 'POST' }); toast(r.message); }
    else if (act === 'pc-check') { el.disabled = true; await api(`/api/phonecheck/check/${encodeURIComponent(id)}`, { method: 'POST' }); }
    else if (act === 'pc-deep') {
      el.disabled = true;
      await api(`/api/phonecheck/deep/${encodeURIComponent(id)}`, { method: 'POST', body: { password: ui.password || undefined } });
      ui.password = ''; ui.deepOk.delete(id);
      toast('Started. I’ll delete the backup as soon as the check is done.');
    } else if (act === 'pc-forget') { await api(`/api/phonecheck/reports/${encodeURIComponent(id)}`, { method: 'DELETE' }); toast('Forgotten. Its warnings are gone from Findings too.'); }
    else if (act === 'pc-dismiss') { ui.dismissed = state.phonecheck?.lastError?.at ?? 0; el.closest('.status')?.remove(); return; }
  } catch (err) { toast(err.message); }
  W.render();
});
