/**
 * Two things that live alongside every page:
 * - Updates: an "Update now" bar when a newer Hashling release exists, and an Updates card in Settings.
 * - Fully local AI: the panel under "Your AI connection" that picks, downloads and runs a model on this Mac.
 */
const W = window.W;
const { views, api, esc, toast, ago, icon, state } = W;

// ---------- updates ----------

let upd = null;

function bar() {
  const el = document.getElementById('update-bar');
  if (!el) return;
  const u = upd;
  if (!u?.available || sessionStorage.getItem('hashling.updateLater') === u.latest.version) { el.hidden = true; return; }
  const busy = ['downloading', 'verifying', 'installing'].includes(u.phase);
  el.hidden = false;
  el.innerHTML = `<div class="update-inner">${W.hashlingSvg('xs')}
    <div class="update-text"><b>${busy ? `Updating to Hashling ${esc(u.latest.version)}…` : `Hashling ${esc(u.latest.version)} is ready`}</b>
      <span>${busy ? 'I’ll restart by myself in a minute, and this page will reload.' : u.canInstall ? `You have ${esc(u.current)}. Updating takes about a minute and keeps your settings and history.` : 'You run Hashling from its source code, so update it with git pull.'}</span></div>
    <div class="update-actions">
      ${u.latest.url ? `<a class="btn ghost sm" href="${esc(u.latest.url)}" target="_blank" rel="noopener">What’s new</a>` : ''}
      ${busy ? '' : `<button class="btn ghost sm" data-act="upd-later">Later</button>`}
      ${u.canInstall && !busy ? `<button class="btn primary sm" data-act="upd-install">Update now</button>` : ''}
    </div></div>
    ${u.phase === 'error' && u.error ? `<p class="update-err">${esc(u.error)}</p>` : ''}`;
}

async function refreshUpdate() {
  upd = await api('/api/update').catch(() => upd);
  bar();
}

function updatesCard() {
  const u = upd;
  if (!u) return '';
  const line = u.available
    ? `Hashling ${esc(u.latest.version)} is available. You have ${esc(u.current)}.`
    : `You have the latest version, Hashling ${esc(u.current)}.`;
  return `<section class="card pad mt updates-card">
    <div class="row between" style="gap:16px;align-items:flex-start">
      <div><p class="h2" style="margin:0">Updates</p>
        <p class="small muted" style="margin:4px 0 0;max-width:60ch">${line} I check for new versions by myself every few hours${u.checkedAt ? `, last ${ago(u.checkedAt)}` : ''}. Updating asks for your Touch ID, checks the download against its published checksum, and keeps your settings and history.</p>
        ${u.devCheckout ? '<p class="tiny faint" style="margin:8px 0 0">This copy runs from its source code (a git checkout), so update it with <code>git pull</code> instead.</p>' : ''}
        ${u.phase === 'error' && u.error ? `<p class="tiny" style="margin:8px 0 0;color:var(--bad)">${esc(u.error)}</p>` : ''}</div>
      <div class="row" style="gap:8px;flex:none">
        <button class="btn" data-act="upd-check" ${u.phase === 'checking' ? 'disabled' : ''}>${u.phase === 'checking' ? 'Checking…' : 'Check now'}</button>
        ${u.canInstall ? '<button class="btn primary" data-act="upd-install">Update now</button>' : ''}
      </div>
    </div>
  </section>`;
}

// ---------- fully local AI ----------

let local = null;
let poll = null;
const GB = (n) => `${n < 10 ? n.toFixed(1) : Math.round(n)} GB`;

function progressLine(l) {
  const busy = ['installing-engine', 'downloading', 'verifying'].includes(l.phase);
  if (!busy && l.phase !== 'error') return '';
  if (l.phase === 'error') return `<div class="status bad" style="margin:0"><div class="ico">${icon('alert', 'lg')}</div><div><b>Local AI isn’t ready</b><span class="sub">${esc(l.error)}</span></div><div class="actions"><button class="btn sm" data-act="local-retry">Try again</button></div></div>`;
  const pct = l.progress ? Math.floor((l.progress.done / l.progress.total) * 100) : 0;
  const what = l.phase === 'installing-engine' ? 'Installing the llama.cpp engine (a few minutes, once)'
    : l.phase === 'verifying' ? `Checking the ${esc(l.label ?? 'model')} download`
    : `Downloading ${esc(l.label ?? 'the model')}: ${GB(l.progress.done / 1e9)} of ${GB(l.progress.total / 1e9)}`;
  return `<div class="local-progress"><div class="row between"><span class="small">${what}…</span>${l.phase === 'downloading' ? `<span class="tiny muted">${pct}%</span>` : ''}</div>
    <div class="local-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><span style="width:${l.phase === 'downloading' ? pct : 100}%" class="${l.phase === 'downloading' ? '' : 'pulse'}"></span></div>
    <p class="tiny faint" style="margin:6px 0 0">You can keep using Hashling. If your Mac restarts, I pick up where I left off.</p></div>`;
}

function localPanel(l) {
  const c = l.config;
  const rec = l.models.find((m) => m.id === l.recommended);
  const opt = (v, title, sub, extra = '') => `<label class="local-opt ${c.choice === v ? 'on' : ''}"><input type="radio" name="local-choice" value="${v}" ${c.choice === v ? 'checked' : ''}><span><b>${title}</b><span class="tiny muted">${sub}</span>${extra}</span></label>`;
  return `<div class="local-panel stack" style="gap:12px">
    ${progressLine(l)}
    <p class="small muted" style="margin:0">Your Mac: ${esc(l.specs.chip)} with ${l.specs.ramGB} GB of memory. Everything runs on it with the free llama.cpp engine, so your questions and my answers never leave it. The model starts when you ask something and stops after 10 quiet minutes, so it only uses memory while it works.</p>
    <div class="local-opts" role="radiogroup" aria-label="Which model">
      ${opt('auto', `Automatic: ${esc(rec.label)}`, `Picked for ${l.specs.ramGB} GB of memory. ${GB(rec.sizeGB)} download.`)}
      ${l.models.map((m) => opt(m.id, esc(m.label), `${esc(m.note)} ${GB(m.sizeGB)}${m.downloaded ? ', downloaded' : ''}.${m.fits ? '' : ' May be slow or not fit on this Mac.'}`)).join('')}
      ${opt('custom', 'A model I choose', 'Any single-file GGUF model from Hugging Face, or a .gguf file on this Mac.', `<input class="input" id="local-custom" placeholder="Qwen/Qwen3-8B-GGUF:Q4_K_M  or  ~/Models/my-model.gguf" value="${esc(c.custom ?? '')}">`)}
      ${opt('server', 'My own model server', 'Ollama, LM Studio or llama.cpp already running on this Mac.', `<div class="row" style="gap:8px"><input class="input" id="local-url" placeholder="http://127.0.0.1:11434" value="${esc(c.serverUrl ?? '')}"><input class="input" id="local-model" placeholder="Model name, e.g. qwen3:8b" value="${esc(c.serverModel ?? '')}"></div>`)}
    </div>
    <div class="row" style="gap:10px"><button class="btn primary" data-act="local-save">Use this model</button><span class="tiny muted">${l.freeGB} GB free on this Mac.</span></div>
    ${l.downloaded.length ? `<div><p class="label">Downloaded models</p><div class="list">${l.downloaded.map((d) => `<div class="item"><div class="body"><div class="t">${esc(d.file.replace(/\.gguf$/, ''))}</div><div class="s">${GB(d.sizeGB)}</div></div><button class="btn sm ghost" data-act="local-delete" data-file="${esc(d.file)}">Delete</button></div>`).join('')}</div></div>` : ''}
  </div>`;
}

async function refreshLocal() {
  local = await api('/api/ai/local').catch(() => null);
  const busy = local && ['installing-engine', 'downloading', 'verifying'].includes(local.phase);
  clearInterval(poll);
  if (busy) poll = setInterval(async () => {
    if (state.view !== 'settings') return clearInterval(poll);
    const prev = local?.phase;
    local = await api('/api/ai/local').catch(() => local);
    const slot = document.querySelector('.local-panel');
    if (prev !== local?.phase) { W.render(); return; }
    const p = slot?.querySelector('.local-progress');
    if (p) p.outerHTML = progressLine(local);
  }, 1500);
}

// ---------- settings page ----------

const base = views.settings;
views.settings = async () => {
  const [html, cfg] = await Promise.all([base(), api('/api/ai/config').catch(() => null), refreshUpdate()]);
  state.localOnly = cfg?.provider === 'local';
  let out = html;
  if (out.includes('<!--local-ai-->')) {
    await refreshLocal();
    out = out.replace('<!--local-ai-->', local ? localPanel(local) : '');
  }
  return out + updatesCard();
};

document.addEventListener('change', (e) => {
  if (e.target.name !== 'local-choice') return;
  document.querySelectorAll('.local-opt').forEach((o) => o.classList.toggle('on', o.querySelector('input').checked));
});

document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act^="upd-"], [data-act^="local-"]');
  if (!el) return;
  const act = el.dataset.act;
  try {
    if (act === 'upd-check') {
      el.disabled = true; el.textContent = 'Checking…';
      upd = await api('/api/update/check', { method: 'POST' });
      toast(upd.available ? `Hashling ${upd.latest.version} is available.` : upd.error ? upd.error : 'You have the latest version.');
      bar(); W.render();
    } else if (act === 'upd-install') {
      el.disabled = true; el.textContent = 'Confirm with Touch ID…';
      await api('/api/update/install', { method: 'POST' });
      toast('Updating. I’ll restart by myself in a minute.');
      await refreshUpdate();
    } else if (act === 'upd-later') {
      sessionStorage.setItem('hashling.updateLater', upd.latest.version);
      bar();
    } else if (act === 'local-save') {
      const choice = document.querySelector('input[name="local-choice"]:checked')?.value ?? 'auto';
      const body = { choice };
      if (choice === 'custom') body.custom = document.getElementById('local-custom')?.value ?? '';
      if (choice === 'server') { body.serverUrl = document.getElementById('local-url')?.value ?? ''; body.serverModel = document.getElementById('local-model')?.value ?? ''; }
      local = await api('/api/ai/local', { method: 'POST', body });
      toast(local.phase === 'ready' ? 'Saved. Local AI is ready.' : 'Saved. I’m setting it up now.');
      W.render();
    } else if (act === 'local-retry') {
      await api('/api/ai/local/setup', { method: 'POST' });
      W.render();
    } else if (act === 'local-delete') {
      local = await api(`/api/ai/local/models/${encodeURIComponent(el.dataset.file)}`, { method: 'DELETE' });
      toast('Deleted. The space is free again.');
      W.render();
    }
  } catch (err) {
    toast(err.message);
    if (act === 'upd-install') { el.disabled = false; el.textContent = 'Update now'; }
  }
});

// The bar shows on every page; check what the server knows now, then every 10 minutes.
api('/api/ai/config').then((c) => { state.localOnly = c.provider === 'local'; if (state.localOnly) W.render(); }).catch(() => {});
refreshUpdate();
setInterval(refreshUpdate, 10 * 60_000);
// While an update installs, Hashling restarts; the page reloads once it answers again on the new version.
setInterval(async () => {
  if (!upd || upd.phase !== 'installing') return;
  const h = await fetch('/api/health').then((r) => r.json()).catch(() => null);
  if (h?.ok) { const u = await api('/api/update').catch(() => null); if (u && u.current !== upd.current) location.reload(); }
}, 4000);
