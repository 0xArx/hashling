// Unlock screen: asks the Hashling service to confirm with Touch ID, then loads the dashboard.
const btn = document.getElementById('unlock');
const status = document.getElementById('status');
const label = btn.textContent;

function setStatus(text, tone = '') {
  status.textContent = text;
  status.className = `status-line ${tone}`;
}

async function unlock() {
  btn.disabled = true;
  btn.innerHTML = '<span class="spin" aria-hidden="true"></span>Confirm on your Mac…';
  setStatus('I’ve asked your Mac for Touch ID. Look for the prompt.');
  // The prompt can open behind other windows or on another screen. Say so, instead of looking stuck.
  const hint = setTimeout(() => setStatus('I’m still waiting. The Touch ID window may be behind other windows or on another screen: press Command + Tab or look at your other displays. You can also click the # in your menu bar and choose Open dashboard.'), 15000);
  try {
    const res = await fetch('/api/unlock', { method: 'POST', credentials: 'same-origin' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Could not unlock.');
    setStatus('Thanks, it’s you. Opening your dashboard…', 'ok');
    location.replace('/' + location.hash);
    return;
  } catch (e) {
    setStatus(e.message, 'error');
  } finally {
    clearTimeout(hint);
  }
  btn.disabled = false;
  btn.textContent = label;
}

btn.addEventListener('click', unlock);
