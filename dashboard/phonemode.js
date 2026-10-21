/**
 * Settings: "Your phone". Switch phone mode on (Touch ID), pair a phone with a one-time QR code,
 * and see or disconnect the phones that can reach Hashling.
 */
const W = window.W;
const { views, api, esc, toast, ago, icon } = W;

const PHONE = '<svg viewBox="0 0 24 24" class="i" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6.5" y="2.5" width="11" height="19" rx="2.6"/><path d="M10.5 18.5h3"/></svg>';
const pair = { id: null, svg: '', expiresAt: 0, timer: null, done: null };

async function qrSvg(text) {
  const { default: qrcode } = await import('/vendor/qrcode.js');
  const q = qrcode(0, 'M');
  q.addData(text);
  q.make();
  return q.createSvgTag({ cellSize: 6, margin: 3, scalable: true });
}

function phoneCard(st) {
  const devices = st.devices.length
    ? `<div class="list mt phone-devices">${st.devices.map((d) => `<div class="item"><span class="ph-ico">${PHONE}</span><div class="body"><div class="t">${esc(d.name)}</div><div class="s">Connected ${ago(d.paired_at)}${d.last_seen ? ` · last used ${ago(d.last_seen)}` : ''}</div></div><button class="btn sm ghost" data-act="phone-forget" data-id="${esc(d.id)}">Disconnect</button></div>`).join('')}</div>`
    : '';
  const qr = pair.id && !pair.done
    ? `<div class="phone-pair">
        <div class="qr" aria-label="QR code to connect your phone">${pair.svg}</div>
        <div><p class="h3" style="margin:0 0 6px">Scan this with your phone’s camera</p>
          <ol class="small muted phone-steps"><li>Open the Camera app and point it at the code.</li><li>Tap the link that appears.</li><li>Tap Share, then <b>Add to Home Screen</b> to keep me one tap away.</li></ol>
          <p class="tiny faint" id="pair-left">Works once, for 10 minutes.</p>
          <button class="btn sm ghost" data-act="phone-pair-cancel">Cancel</button></div>
      </div>`
    : pair.done
      ? `<div class="phone-done">${W.hashlingSvg('sm')}<div><b>Your ${esc(pair.done)} is connected.</b><span class="small muted">Open Hashling from your phone any time you’re on this Wi-Fi.</span></div></div>`
      : '';
  return `<section class="card pad mt phone-card">
    <div class="row between" style="gap:16px;align-items:flex-start">
      <div class="row" style="gap:14px;align-items:flex-start"><span class="ph-badge ${st.on ? 'on' : ''}">${PHONE}</span>
        <div><p class="h2" style="margin:0">Your phone</p>
        <p class="small muted" style="margin:4px 0 0;max-width:60ch">${st.on
          ? `Phone mode is on. Phones you connect can see your score and warnings, check scam texts and ask me anything over your Wi-Fi. Approving a fix still needs Touch ID on this Mac.`
          : `Use Hashling from your phone over your Wi-Fi: see your score and warnings, check a scam text or screenshot, and ask me anything. Approving a fix still needs Touch ID on this Mac.`}</p></div></div>
      ${st.on ? `<div class="row" style="gap:8px">${pair.id && !pair.done ? '' : `<button class="btn primary" data-act="phone-pair">${icon('plus')}Connect a phone</button>`}<button class="btn" data-act="phone-off">Switch off</button></div>`
        : `<button class="btn primary" data-act="phone-on">Switch on phone mode</button>`}
    </div>
    ${st.on && !st.wifi ? `<div class="status flag mt"><div class="ico">${icon('alert', 'lg')}</div><div><b>This Mac isn’t on Wi-Fi</b><span class="sub">Connect it to the same Wi-Fi as your phone.</span></div></div>` : ''}
    ${qr}${devices}
    <p class="tiny faint" style="margin:14px 0 0">Only phones you connect with a code can reach me, and everything between us is encrypted with a key that never leaves the two devices. If macOS asks whether to accept incoming connections, choose Allow.</p>
  </section>`;
}

const base = views.settings;
views.settings = async () => {
  const [html, st] = await Promise.all([base(), api('/api/phone').catch(() => null)]);
  if (!st) return html;
  const card = phoneCard(st);
  // Right under the page's explanation card, so it is easy to find from the phone's own instructions.
  return html.startsWith('<section class="help') ? html.replace('</section>', `</section>${card}`) : card + html;
};

function tickPair() {
  clearInterval(pair.timer);
  pair.timer = setInterval(async () => {
    if (!pair.id) return clearInterval(pair.timer);
    const left = pair.expiresAt - Date.now();
    const el = document.getElementById('pair-left');
    if (el) el.textContent = left > 0 ? `Works once. ${Math.ceil(left / 60000)} min left.` : 'This code expired. Make a new one.';
    const r = await api(`/api/phone/pair/${encodeURIComponent(pair.id)}`).catch(() => null);
    if (r?.paired) {
      clearInterval(pair.timer);
      pair.done = r.name;
      toast(`Your ${r.name} is connected.`);
      W.render();
      setTimeout(() => { pair.id = null; pair.done = null; if (W.state.view === 'settings') W.render(); }, 9000);
    } else if (r?.expired || left <= 0) {
      clearInterval(pair.timer);
      pair.id = null;
      if (W.state.view === 'settings') W.render();
    }
  }, 2000);
}

document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act^="phone-"]');
  if (!el) return;
  const act = el.dataset.act;
  try {
    if (act === 'phone-on') {
      el.disabled = true; el.textContent = 'Confirm with Touch ID…';
      await api('/api/phone/on', { method: 'POST' });
      toast('Phone mode is on. Now connect a phone.');
    } else if (act === 'phone-off') {
      await api('/api/phone/off', { method: 'POST' });
      pair.id = null; pair.done = null;
      toast('Phone mode is off. Phones can’t reach me until you switch it on again.');
    } else if (act === 'phone-pair') {
      const r = await api('/api/phone/pair', { method: 'POST' });
      Object.assign(pair, { id: r.id, expiresAt: r.expiresAt, done: null, svg: await qrSvg(r.url) });
      tickPair();
    } else if (act === 'phone-pair-cancel') {
      pair.id = null; clearInterval(pair.timer);
    } else if (act === 'phone-forget') {
      await api(`/api/phone/devices/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' });
      toast('Disconnected. That phone can’t reach me any more.');
    }
  } catch (err) { toast(err.message); }
  W.render();
});
