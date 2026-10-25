import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync, existsSync, writeFileSync, readdirSync, statSync, mkdirSync, rmSync, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { randomUUID } from 'node:crypto';
import { join, extname, normalize, basename } from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { HOST, PORT, ROOT, TOKEN_PATH, BIN, DATA_DIR, LOCAL_NAME, DASHBOARD_URL } from './config.ts';
import { bus } from './bus.ts';
import { listFindings, getFinding, setFindingStatus, getSnapshot, putSnapshot, listEvents, recentSeen, logEvent } from './db.ts';
import { redact } from './lib/redact.ts';
import { overview } from './overview.ts';
import { runCollector, collectorNames, status } from './scheduler.ts';
import { requestScan, getScan, listScans, engines, refreshScanFindings, requestFullScan } from './scanner.ts';
import { proposeAction, listActions, getAction, approveAction, approveMany, rejectAction, restoreAction, listQuarantine, blockedDomains, ACTION_TYPES } from './actions.ts';
import { osquery, validateSql } from './lib/osquery.ts';
import { processInfo } from './process.ts';
import { ask, aiStatus, publicConfig, saveConfig, listThreads, getThread, deleteThread, openClaudeLogin, handoff, MODELS } from './ai.ts';
import { run } from './lib/exec.ts';
import { suspicious } from './overview.ts';
import { matchIp, matchHost } from './intel/feeds.ts';
import { reputation } from './intel/reputation.ts';
import { dossier } from './intel/dossier.ts';
import { whatChanged } from './intel/changes.ts';
import { trafficSeries, scoreHistory } from './history.ts';
import { listDownloads, checkFile } from './collectors/downloads.ts';
import { processHistory, agentActivity } from './collectors/processes.ts';
import { CLEANUPS, safeDnsStatus } from './actions.ts';
import { uploadsReport } from './intel/uploads.ts';
import { storageProgress } from './collectors/storage.ts';
import { loadPrefs, savePrefs } from './prefs.ts';
import { SETTINGS_ANCHOR } from './collectors/permissions.ts';
import { clearRansomwareAlerts, pausedPrograms, resumeProgram } from './intel/ransomware.ts';
import { loadHelper, saveHelper, weeklySummary } from './summary.ts';
import { redFlags } from './lib/scamflags.ts';
import { findUninstaller } from './lib/uninstaller.ts';
import { PHONE_SECRET, phoneMayCall, phoneState, phoneOn, phoneOff, newPairing, forgetPhone, pairingDone } from './phone.ts';
import { userPresence } from './actions.ts';
import { updateState, checkForUpdate, installUpdate } from './updates.ts';
import { localStatus, saveLocalConfig, setupLocal, deleteModel } from './localai.ts';
import { listWatched, watchEmail, unwatchEmail, checkBreaches } from './intel/breaches.ts';
import { messageWatchState, resetMessageWatch } from './collectors/messages.ts';
import { checkMedia } from './lib/aimedia.ts';
import { phoneCheckState, askToTrust, startCheck, startDeepCheck, installPhoneTools, forgetReport } from './phonecheck.ts';

export function loadToken(): string {
  if (existsSync(TOKEN_PATH)) return readFileSync(TOKEN_PATH, 'utf8').trim();
  const t = randomBytes(24).toString('hex');
  writeFileSync(TOKEN_PATH, t, { mode: 0o600 });
  return t;
}

const TOKEN = loadToken();

/** Changes whenever the dashboard files change, so open tabs know to reload after an update. */
/** A fingerprint of the dashboard files, read fresh each time, so open tabs can tell when they are out of date. */
const uiBuild = () => {
  try {
    const dir = join(ROOT, 'dashboard');
    return readdirSync(dir).map((f) => statSync(join(dir, f)).mtimeMs).reduce((a, b) => Math.max(a, b), 0).toString(36);
  } catch { return '0'; }
};
const COOKIE = 'hashling_session';
const DASH = join(ROOT, 'dashboard');
const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };

// One-time sign-in codes: `hashling open` and the menu bar ask for one, so the
// long-lived token never appears in a URL or in browser history.
const signInCodes = new Map<string, number>();

function issueSignInCode(): string {
  const now = Date.now();
  for (const [c, exp] of signInCodes) if (exp <= now) signInCodes.delete(c);
  const code = randomBytes(24).toString('hex');
  signInCodes.set(code, now + 60_000);
  return code;
}

function redeemSignInCode(code: string): boolean {
  const exp = signInCodes.get(code);
  signInCodes.delete(code);
  return exp !== undefined && exp > Date.now();
}

/** Browsers mark every request with where it came from; only Hashling's own pages (or a typed URL) get in. */
function crossSite(req: IncomingMessage): boolean {
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return true;
  return Boolean(req.headers.origin) && !originOk(req);
}

/** Shown when a link on another website points at Hashling. Static, no data, cannot be framed. */
function arrivedFromElsewhere(res: ServerResponse): void {
  res.writeHead(403, {
    'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'",
  });
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Open Hashling</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f6f8;color:#0f1729;font:15px/1.55 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;padding:20px}
main{max-width:440px;background:#fff;border:1px solid #e9ebef;border-radius:18px;padding:28px;box-shadow:0 18px 48px -12px rgba(15,23,41,.18)}
h1{font-size:21px;margin:0 0 8px}p{margin:0 0 14px;color:#364152}a{display:inline-block;background:#111827;color:#fff;text-decoration:none;padding:10px 18px;border-radius:10px;font-weight:600}
small{display:block;margin-top:16px;color:#566073}
@media (prefers-color-scheme:dark){body{background:#0f1115;color:#e9ecf2}main{background:#171a21;border-color:#262b35}p{color:#c6ccd7}a{background:#e9ecf2;color:#11141a}small{color:#a1a9b7}}</style></head><body><main>
<h1>Open Hashling from your Mac</h1>
<p>You followed a link to Hashling from another website. To keep your dashboard safe, Hashling only opens from your own Mac.</p>
<a href="/">Open Hashling</a>
<small>Next time, click the # in your menu bar, or type <b>hashling open</b> in Terminal.</small>
</main></body></html>`);
}

/** The only page a signed-out browser can load: self-contained, so no other file is reachable without signing in. */
function unlockPage(res: ServerResponse): void {
  const nonce = randomBytes(16).toString('base64');
  const html = readFileSync(join(DASH, 'unlock.html'), 'utf8')
    .replace('__UNLOCK_JS__', readFileSync(join(DASH, 'unlock.js'), 'utf8'))
    .replaceAll('__NONCE__', nonce);
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
  });
  res.end(html);
}

const sessionCookie = () => `${COOKIE}=${TOKEN}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000`;

// Unlocking a browser needs the person at this Mac (Touch ID or login password).
let unlocking = false;
const unlockAttempts: number[] = [];

async function unlock(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const origin = req.headers.origin;
  if (!origin || !originOk(req)) return send(res, 403, { error: `Open me at ${DASHBOARD_URL} to unlock.` });
  if (who(req)) return send(res, 200, { ok: true });
  const t = Date.now();
  while (unlockAttempts.length && t - unlockAttempts[0] > 60_000) unlockAttempts.shift();
  if (unlocking) return send(res, 409, { error: 'A confirmation is already waiting on your Mac.' });
  if (unlockAttempts.length >= 5) return send(res, 429, { error: 'Too many attempts. Wait a minute and try again.' });
  if (!existsSync(BIN.auth)) return send(res, 503, { error: 'I’m missing the part that asks for Touch ID. Open the dashboard from the # in your menu bar instead, or reinstall Hashling.' });
  unlocking = true;
  unlockAttempts.push(t);
  try {
    const r = await run(BIN.auth, ['open the Hashling dashboard in this browser'], { timeout: 120_000 });
    if (!r.ok) return send(res, 403, { error: /cancel/i.test(r.stdout) ? 'Cancelled. Try again when you are ready.' : (r.stdout.trim() || 'Not confirmed.') });
    send(res, 200, { ok: true }, { 'set-cookie': sessionCookie() });
  } finally {
    unlocking = false;
  }
}

const safeEq = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

type Who = { kind: 'dashboard' | 'agent' | 'phone'; name: string } | null;

function who(req: IncomingMessage): Who {
  const auth = req.headers.authorization?.replace(/^Bearer\s+/i, '') ?? '';
  const phone = String(req.headers['x-hashling-phone'] ?? '');
  // Phone mode relays a paired phone's opened requests from this same Mac with a per-run secret.
  if (auth && phone && safeEq(auth, TOKEN) && safeEq(phone, PHONE_SECRET) && (req.socket.remoteAddress === '127.0.0.1' || req.socket.remoteAddress === '::ffff:127.0.0.1')) return { kind: 'phone', name: String(req.headers['x-hashling-client'] ?? 'Your phone').slice(0, 60) };
  if (auth && safeEq(auth, TOKEN)) return { kind: 'agent', name: String(req.headers['x-hashling-client'] ?? 'AI agent').slice(0, 60) };
  const cookie = (req.headers.cookie ?? '').split(/;\s*/).find((c) => c.startsWith(COOKIE + '='))?.split('=')[1] ?? '';
  if (cookie && safeEq(cookie, TOKEN)) return { kind: 'dashboard', name: 'You' };
  return null;
}

/** Only answer to this Mac's own names so a web page cannot reach the API through DNS rebinding. */
const HOSTS = new Set([`${HOST}:${PORT}`, `localhost:${PORT}`, `[::1]:${PORT}`, `${LOCAL_NAME}:${PORT}`]);
function hostOk(req: IncomingMessage): boolean {
  return HOSTS.has((req.headers.host ?? '').toLowerCase());
}

function originOk(req: IncomingMessage): boolean {
  const o = req.headers.origin;
  return !o || o === DASHBOARD_URL || o === `http://${HOST}:${PORT}` || o === `http://localhost:${PORT}`;
}

function send(res: ServerResponse, code: number, body: unknown, headers: Record<string, string> = {}): void {
  const json = JSON.stringify(body);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(json);
}

async function body(req: IncomingMessage): Promise<Record<string, any>> {
  let data = '';
  for await (const chunk of req) { data += chunk; if (data.length > 256_000) throw new Error('Body too large'); }
  if (!data) return {};
  return JSON.parse(data);
}

function staticFile(res: ServerResponse, path: string): void {
  const rel = normalize(path === '/' ? '/index.html' : path).replace(/^(\.\.[/\\])+/, '');
  const file = join(DASH, rel);
  if (!file.startsWith(DASH) || !existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
  res.writeHead(200, {
    'content-type': MIME[extname(file)] ?? 'application/octet-stream',
    'cache-control': 'no-cache',
    'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
  });
  res.end(readFileSync(file));
}

type Handler = (req: IncomingMessage, res: ServerResponse, params: string[], w: NonNullable<Who>, url: URL) => Promise<void> | void;
const routes: { method: string; re: RegExp; dashboardOnly?: boolean; h: Handler }[] = [];
const route = (method: string, path: string, h: Handler, dashboardOnly = false) => routes.push({ method, re: new RegExp('^' + path.replace(/:(\w+)/g, '([^/]+)') + '$'), h, dashboardOnly });
const snap = (name: string) => (_q: IncomingMessage, res: ServerResponse) => { const s = getSnapshot(name); send(res, 200, s ? { ...s.data as object, updated_at: s.updated_at, limitation: s.error } : { pending: true, limitation: 'Not collected yet.' }); };

route('GET', '/api/overview', (_q, res) => send(res, 200, overview()));
route('POST', '/api/session-code', (_q, res) => { const code = issueSignInCode(); send(res, 200, { code, url: `${DASHBOARD_URL}/?c=${code}`, expiresIn: 60 }); });
route('GET', '/api/findings', (_q, res, _p, _w, url) => send(res, 200, listFindings({ status: url.searchParams.get('status') ?? 'active', category: url.searchParams.get('category') ?? undefined, minSeverity: url.searchParams.get('min') ?? undefined, limit: Number(url.searchParams.get('limit') ?? 300) })));
route('GET', '/api/findings/:id', (_q, res, [id]) => { const f = getFinding(id); f ? send(res, 200, f) : send(res, 404, { error: 'No such finding' }); });
route('POST', '/api/findings/:id/ignore', async (req, res, [id]) => { const b = await body(req); send(res, 200, { ok: setFindingStatus(id, 'acknowledged', Number(b.days) || undefined) }); }, true);
route('POST', '/api/findings/:id/ack', (_q, res, [id]) => send(res, 200, { ok: setFindingStatus(id, 'acknowledged') }), true);
route('POST', '/api/findings/:id/reopen', (_q, res, [id]) => send(res, 200, { ok: setFindingStatus(id, 'open') }), true);
route('GET', '/api/network', snap('network'));
route('GET', '/api/network/new', (_q, res, _p, _w, url) => send(res, 200, recentSeen('net', Date.now() - Number(url.searchParams.get('hours') ?? 24) * 3600_000, 300)));
route('GET', '/api/posture', snap('posture'));
route('GET', '/api/persistence', snap('persistence'));
route('GET', '/api/permissions', snap('permissions'));
route('GET', '/api/location', snap('location'));
route('GET', '/api/trackers', snap('trackers'));
route('GET', '/api/agents', snap('agents'));
route('GET', '/api/attack-packs', snap('attackPacks'));
route('GET', '/api/events', (_q, res, _p, _w, url) => send(res, 200, listEvents(Number(url.searchParams.get('limit') ?? 100), Number(url.searchParams.get('since') ?? 0))));
route('GET', '/api/status', (_q, res) => send(res, 200, { collectors: status, engines: engines() }));
route('GET', '/api/process/:pid', async (_q, res, [pid]) => send(res, 200, await processInfo(Number(pid))));
route('POST', '/api/osquery', async (req, res) => {
  const { sql } = await body(req);
  const bad = validateSql(String(sql ?? ''));
  if (bad) return send(res, 400, { error: bad });
  const r = await osquery(String(sql), 30_000);
  send(res, r.error && !r.rows.length ? 400 : 200, { rows: r.rows.slice(0, 500), truncated: r.rows.length > 500, error: r.error });
});
route('GET', '/api/scans', (_q, res) => send(res, 200, listScans(30)));
route('GET', '/api/scans/:id', (_q, res, [id]) => { const s = getScan(id); s ? send(res, 200, s) : send(res, 404, { error: 'No such scan' }); });
route('POST', '/api/scans/full', (_q, res) => { const r = requestFullScan('You (full scan)'); send(res, 'error' in r ? 400 : 202, r); }, true);
route('POST', '/api/scans', async (req, res, _p, w) => {
  const { paths } = await body(req);
  const r = requestScan(Array.isArray(paths) ? paths.map(String) : [String(paths ?? '')], w.name);
  send(res, 'error' in r ? 400 : 202, r);
});
route('GET', '/api/actions', (_q, res, _p, _w, url) => send(res, 200, listActions(url.searchParams.get('status') ?? undefined)));
route('GET', '/api/actions/:id', (_q, res, [id]) => { const a = getAction(id); a ? send(res, 200, a) : send(res, 404, { error: 'No such action' }); });
route('POST', '/api/actions', async (req, res, _p, w) => {
  const b = await body(req);
  const r = proposeAction(String(b.type ?? ''), b.target ?? {}, String(b.reason ?? (w.kind === 'dashboard' ? 'Requested from the dashboard' : '')), w.name, b.finding_id);
  send(res, 'error' in r ? 400 : 201, 'error' in r ? { ...r, types: ACTION_TYPES } : { ...r, note: 'Waiting for the user to approve this in the Hashling dashboard (Touch ID). It will not run until then.' });
});
route('POST', '/api/actions/approve-all', async (req, res) => { const b = await body(req); const r = await approveMany(Array.isArray(b.ids) ? b.ids.map(String) : []); send(res, 'error' in r ? 400 : 200, r); }, true);
route('POST', '/api/actions/reject-all', async (req, res) => { const b = await body(req); let n = 0; for (const id of Array.isArray(b.ids) ? b.ids.map(String) : []) if (!('error' in rejectAction(id))) n++; send(res, 200, { rejected: n }); }, true);
route('POST', '/api/actions/:id/approve', async (_q, res, [id]) => { const r = await approveAction(id); send(res, 'error' in r ? 400 : 200, r); }, true);
route('POST', '/api/actions/:id/reject', (_q, res, [id]) => { const r = rejectAction(id); send(res, 'error' in r ? 400 : 200, r); }, true);
route('POST', '/api/actions/:id/restore', (_q, res, [id]) => { const r = restoreAction(id); send(res, 'error' in r ? 400 : 200, r); }, true);
route('GET', '/api/suspicious', (_q, res) => send(res, 200, suspicious()));
// --- engines added in v0.2 ---
route('GET', '/api/intel', snap('intel'));
route('POST', '/api/intel/check', async (req, res) => {
  const b = await body(req);
  const out: Record<string, unknown> = {};
  if (b.ip) out.ip = matchIp(String(b.ip), b.port ? Number(b.port) : undefined);
  if (b.host) out.host = matchHost(String(b.host));
  if (b.path) out.file = await reputation(String(b.path).replace(/^~/, process.env.HOME ?? '')).catch((e) => ({ error: String(e.message) }));
  send(res, 200, out);
});
route('GET', '/api/behavior', snap('behavior'));
route('GET', '/api/traffic', (_q, res, _p, _w, url) => send(res, 200, trafficSeries(Math.min(168, Number(url.searchParams.get('hours') ?? 6)), Number(url.searchParams.get('top') ?? 5))));
route('GET', '/api/score-history', (_q, res, _p, _w, url) => send(res, 200, scoreHistory(Number(url.searchParams.get('days') ?? 30))));
route('GET', '/api/downloads', (_q, res) => send(res, 200, { items: listDownloads(150), watch: getSnapshot('downloadWatch')?.data ?? null }));
route('GET', '/api/processes', (_q, res, _p, _w, url) => send(res, 200, {
  items: processHistory({ agentOnly: url.searchParams.get('agent') === '1', hours: Number(url.searchParams.get('hours') ?? 24), query: url.searchParams.get('q') ?? undefined, limit: 400 }),
  agents: agentActivity(Number(url.searchParams.get('hours') ?? 24)),
  rules: getSnapshot('processes')?.data ?? null,
}));
route('GET', '/api/netsafety', snap('netsafety'));
route('GET', '/api/secrets', snap('secrets'));
route('GET', '/api/webnotify', snap('webnotify'));
route('GET', '/api/sensors', snap('sensors'));
route('GET', '/api/visits', snap('visits'));
route('GET', '/api/snapshot-full-scan', snap('fullScan'));
route('GET', '/api/safe-dns', async (_q, res) => send(res, 200, await safeDnsStatus()));
route('GET', '/api/notarization', snap('notarization'));
route('GET', '/api/outdated', snap('outdated'));
route('GET', '/api/storage', (_q, res) => { const s = getSnapshot('storage'); send(res, 200, { ...(s ? { ...(s.data as object), updated_at: s.updated_at } : { pending: true, limitation: 'Not collected yet.' }), progress: storageProgress() }); });
route('GET', '/api/incidents', snap('incidents'));
route('GET', '/api/dossier', async (_q, res, _p, _w, url) => send(res, 200, await dossier(url.searchParams.get('q') ?? '')));
route('GET', '/api/changes', (_q, res, _p, _w, url) => send(res, 200, whatChanged(Number(url.searchParams.get('hours') ?? 24))));
route('GET', '/api/cleanups', (_q, res) => send(res, 200, CLEANUPS));
route('GET', '/api/uploads', (_q, res, _p, _w, url) => send(res, 200, uploadsReport(Math.min(168, Math.max(1, Number(url.searchParams.get('hours') ?? 168))))));
route('GET', '/api/prefs', (_q, res) => send(res, 200, loadPrefs()));
route('POST', '/api/prefs', async (req, res) => {
  const b = await body(req);
  const before = loadPrefs();
  const after = savePrefs(b);
  if (before.messageWatch && !after.messageWatch) resetMessageWatch();
  if (!before.messageWatch && after.messageWatch) void runCollector('messages');
  send(res, 200, after);
}, true);
route('GET', '/api/message-watch', (_q, res) => send(res, 200, messageWatchState()), true);
// Setup's "Check again" for Full Disk Access: look right now instead of waiting for the next scheduled check.
// macOS sometimes applies a new grant only after the app restarts, so {restart: true} exits and launchd
// (KeepAlive) starts Hashling again a few seconds later.
route('POST', '/api/recheck-access', async (req, res) => {
  const b = (await body(req)) as { restart?: boolean } | null;
  await runCollector('permissions');
  const on = Boolean(getSnapshot<{ fullDiskAccess: boolean }>('permissions')?.data?.fullDiskAccess);
  if (!on && b?.restart) { send(res, 200, { on, restarting: true }); setTimeout(() => process.exit(0), 300); return; }
  send(res, 200, { on });
}, true);
// Updates. Anyone connected may see whether one exists; installing changes the Mac, so it needs Touch ID.
route('GET', '/api/update', (_q, res) => send(res, 200, updateState()));
route('POST', '/api/update/check', async (_q, res) => send(res, 200, await checkForUpdate()), true);
route('POST', '/api/update/install', async (_q, res) => {
  const s = updateState();
  if (!s.canInstall) return send(res, 409, { error: s.devCheckout ? 'This copy of Hashling runs from its source code. Update it with git pull.' : 'There is no newer version to install.' });
  const p = await userPresence(`update Hashling to version ${s.latest?.version}`);
  if (!p.ok) return send(res, 403, { error: `Not updated: ${p.message}.` });
  const r = await installUpdate();
  send(res, 'error' in r ? 500 : 202, r);
}, true);
route('GET', '/api/ai/status', async (_q, res) => send(res, 200, await aiStatus()), true);
route('GET', '/api/ai/config', (_q, res) => send(res, 200, publicConfig()), true);
route('POST', '/api/ai/config', async (req, res) => {
  const b = await body(req);
  const patch: Record<string, unknown> = {};
  if (['claude-code', 'anthropic-key', 'local', 'off'].includes(b.provider)) patch.provider = b.provider;
  if (b.model in MODELS) patch.model = b.model;
  if (typeof b.apiKey === 'string') patch.apiKey = b.apiKey.trim();
  if (typeof b.extraHeaders === 'string') patch.extraHeaders = b.extraHeaders.trim().slice(0, 500);
  if (['desktop-code', 'desktop-chat', 'cli'].includes(b.handoff)) patch.handoff = b.handoff;
  saveConfig(patch);
  if (patch.provider === 'local') void setupLocal();
  send(res, 200, { ...publicConfig(), status: await aiStatus() });
}, true);
// Fully local AI: what this Mac can run, the chosen model, and setup progress.
route('GET', '/api/ai/local', (_q, res) => send(res, 200, localStatus()), true);
route('POST', '/api/ai/local', async (req, res) => {
  const b = await body(req);
  const r = saveLocalConfig({ choice: String(b.choice ?? 'auto'), custom: b.custom == null ? undefined : String(b.custom), serverUrl: b.serverUrl == null ? undefined : String(b.serverUrl), serverModel: b.serverModel == null ? undefined : String(b.serverModel) });
  if ('error' in r) return send(res, 400, r);
  saveConfig({ provider: 'local' });
  void setupLocal();
  send(res, 200, localStatus());
}, true);
route('POST', '/api/ai/local/setup', (_q, res) => { void setupLocal(); send(res, 202, localStatus()); }, true);
route('DELETE', '/api/ai/local/models/:file', (_q, res, [file]) => send(res, deleteModel(decodeURIComponent(file)) ? 200 : 404, localStatus()), true);
route('POST', '/api/ai/handoff', async (req, res) => {
  const b = await body(req);
  send(res, 200, await handoff({ question: String(b.question ?? ''), context: b.context, target: b.target }));
}, true);
route('POST', '/api/ai/connect', async (_q, res) => send(res, 200, await openClaudeLogin()), true);
const PANES: Record<string, string> = {
  fda: 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles',
  bluetooth: 'x-apple.systempreferences:com.apple.preference.security?Privacy_Bluetooth',
  location: 'x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices',
  privacy: 'x-apple.systempreferences:com.apple.preference.security',
  firewall: 'x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall',
  filevault: 'x-apple.systempreferences:com.apple.preference.security?FileVault',
  sharing: 'x-apple.systempreferences:com.apple.Sharing-Settings.extension',
  updates: 'x-apple.systempreferences:com.apple.Software-Update-Settings.extension',
  users: 'x-apple.systempreferences:com.apple.Users-Groups-Settings.extension',
  lock: 'x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension',
  loginitems: 'x-apple.systempreferences:com.apple.LoginItems-Settings.extension',
  network: 'x-apple.systempreferences:com.apple.Network-Settings.extension',
  profiles: 'x-apple.systempreferences:com.apple.Profiles-Settings.extension',
  notifications: 'x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=dev.hashling.app',
  appleid: 'x-apple.systempreferences:com.apple.systempreferences.AppleIDSettings',
  passwords: 'x-apple.systempreferences:com.apple.Passwords-Settings.extension',
};
// The menu bar's paste guard reports what it stopped, so it shows on the timeline and the AI can explain it.
route('POST', '/api/paste-guard', async (req, res) => {
  const b = await body(req);
  const source = String(b.source ?? 'An app').slice(0, 80);
  const cleared = Boolean(b.cleared);
  if (b.kind === 'address-swap') logEvent('process', 'high', `A copied crypto wallet address was swapped for a different one${cleared ? ' (I put yours back)' : ''}`, { kind: 'address-swap', cleared, addresses: String(b.command ?? '').slice(0, 80) });
  else logEvent('process', cleared ? 'medium' : 'high', cleared ? `Stopped a risky Terminal command copied from ${source}` : `You chose to keep a risky Terminal command copied from ${source}`, { source, cleared, command: redact(String(b.command ?? '')).slice(0, 400) });
  send(res, 200, { ok: true });
}, true);
const BROWSER_APPS: Record<string, [string, string]> = {
  Chrome: ['Google Chrome', 'chrome://settings/content/notifications'], Edge: ['Microsoft Edge', 'edge://settings/content/notifications'],
  Brave: ['Brave Browser', 'brave://settings/content/notifications'], Arc: ['Arc', 'arc://settings/content/notifications'], Vivaldi: ['Vivaldi', 'vivaldi://settings/content/notifications'],
};
route('POST', '/api/open-browser-notifications/:browser', async (_q, res, [browser]) => {
  const b = BROWSER_APPS[browser];
  if (!b) return send(res, 404, { error: 'Unknown browser' });
  const r = await run('/usr/bin/open', ['-a', b[0], b[1]]);
  send(res, r.ok ? 200 : 500, { ok: r.ok });
}, true);
// Leaked-password check (k-anonymity): the dashboard sends only the first 5 characters of the password's SHA-1;
// it compares the returned suffixes itself, so neither Hashling nor the service ever sees the password.
route('GET', '/api/pwned-range/:prefix', async (_q, res, [prefix]) => {
  if (!/^[0-9A-F]{5}$/i.test(prefix)) return send(res, 400, { error: 'Bad prefix' });
  try {
    const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix.toUpperCase()}`, { headers: { 'Add-Padding': 'true', 'User-Agent': 'Hashling-Mac-security' }, signal: AbortSignal.timeout(10_000) });
    if (!r.ok) return send(res, 502, { error: 'The leak database did not answer. Try again in a minute.' });
    send(res, 200, { body: await r.text() });
  } catch { send(res, 502, { error: 'Could not reach the leak database. Check your internet connection.' }); }
}, true);
// Check before you open: the dashboard sends a copy of the file you picked; it is checked, then deleted.
// Scam check from a screenshot: read its text and QR codes on this Mac (Apple Vision), then delete it.
route('POST', '/api/read-image', async (req, res) => {
  const size = Number(req.headers['content-length'] ?? 0);
  if (!size || size > 30 * 1024 ** 2) return send(res, 400, { error: size ? 'That image is over 30 MB.' : 'Empty image.' });
  const dir = join(DATA_DIR, 'inbox', randomUUID());
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'image');
  try {
    await pipeline(req, createWriteStream(file, { mode: 0o600 }));
    const r = await run(BIN.ocr, [file], { timeout: 60_000 });
    const out = JSON.parse(r.stdout || '{}');
    send(res, out.error ? 400 : 200, out.error ? { error: 'I couldn’t read that picture.' } : { text: String(out.text ?? ''), codes: out.codes ?? [] });
  } catch { send(res, 500, { error: 'I couldn’t read that picture.' }); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}, true);
// "Was this made by AI?": the dashboard sends a copy of the picture or video; it is checked, then deleted.
route('POST', '/api/ai-media', async (req, res) => {
  const size = Number(req.headers['content-length'] ?? 0);
  if (!size || size > 500 * 1024 ** 2) return send(res, 400, { error: size ? 'That file is over 500 MB.' : 'Empty file.' });
  const dir = join(DATA_DIR, 'inbox', randomUUID());
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'media');
  try {
    await pipeline(req, createWriteStream(file, { mode: 0o600 }));
    send(res, 200, checkMedia(file));
  } catch { send(res, 500, { error: 'I couldn’t read that file.' }); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}, true);
route('POST', '/api/check-file', async (req, res, _p, _w, url) => {
  const name = basename(String(url.searchParams.get('name') ?? 'file')).replace(/[^\w.\- ()]/g, '_').slice(0, 120) || 'file';
  const size = Number(req.headers['content-length'] ?? 0);
  if (!size || size > 3 * 1024 ** 3) return send(res, 400, { error: size ? 'That file is over 3 GB. Scan it from the Malware page instead.' : 'Empty file.' });
  const dir = join(DATA_DIR, 'inbox', randomUUID());
  mkdirSync(dir, { recursive: true });
  const file = join(dir, name);
  try {
    await pipeline(req, createWriteStream(file, { mode: 0o600 }));
    send(res, 200, { name, ...(await checkFile(file)) });
  } catch (e) { send(res, 500, { error: `Could not check it: ${(e as Error).message}` }); }
  finally { rmSync(dir, { recursive: true, force: true }); refreshScanFindings(); }
}, true);
// The trusted helper's details and the summary are for the person at the Mac only (agents cannot read them).
route('GET', '/api/helper', (_q, res) => send(res, 200, { helper: loadHelper() }), true);
route('POST', '/api/helper', async (req, res) => { try { send(res, 200, { helper: saveHelper(await body(req)) }); } catch (e) { send(res, 400, { error: (e as Error).message }); } }, true);
route('GET', '/api/weekly-summary', (_q, res) => send(res, 200, weeklySummary()), true);
route('POST', '/api/ransomware/clear', (_q, res) => { clearRansomwareAlerts(); send(res, 200, { ok: true }); }, true);
// What the menu bar app knows that the daemon cannot: whether macOS lets Hashling show notifications.
// Remembered across restarts, so the health panel never says "not checked yet" after an update.
let clientStatus: { notifications?: string; at?: number } = getSnapshot<{ notifications?: string; at?: number }>('clientStatus')?.data ?? {};
route('POST', '/api/client-status', async (req, res) => {
  const b = await body(req);
  if (['on', 'off', 'undecided'].includes(b.notifications)) { clientStatus = { notifications: b.notifications, at: Date.now() }; putSnapshot('clientStatus', clientStatus); }
  send(res, 200, { ok: true });
}, true);
// "Is Hashling working properly?": every moving part, in plain words, with what to do if one is not.
const PART_NAMES: Record<string, string> = { network: 'Internet watch', processes: 'Program watch', persistence: 'Startup items', permissions: 'Privacy permissions', posture: 'System settings', trackers: 'Tracker scan', agents: 'AI apps', secrets: 'Exposed keys', storage: 'Storage', notarization: 'App checks', visits: 'Visited websites', sensors: 'Camera and microphone history', intel: 'Threat lists', signatures: 'Malware signatures' };
route('GET', '/api/health-report', async (_q, res) => {
  const { status } = await import('./scheduler.ts');
  const DAY = 86_400_000;
  const items: { name: string; ok: boolean; detail: string; fix?: string; pane?: string }[] = [];
  const failing = Object.entries(status).filter(([, s]) => s.error);
  const stale = Object.entries(status).filter(([, s]) => s.lastRun && Date.now() - s.lastRun > Math.max(3 * s.every * 1000, 3 * 3600_000) && s.every < 86_400);
  items.push(failing.length || stale.length
    ? { name: 'Background checks', ok: false, detail: `${[...failing, ...stale].map(([k]) => PART_NAMES[k] ?? k).join(', ')} ${failing.length ? 'had a problem' : 'has not run for a while'}.`, fix: 'Restart me: click the # in the menu bar, choose Quit Hashling, then open Hashling again from the Applications folder in your home folder.' }
    : { name: 'Background checks', ok: true, detail: `All ${Object.keys(status).length} checks are running on schedule.` });
  const e = engines();
  const sig = getSnapshot<{ at: number; ok: boolean }>('signatures');
  const sigAge = sig ? (Date.now() - sig.data.at) / DAY : Infinity;
  items.push(e.clamav && e.clamavDb && sigAge < 3
    ? { name: 'Malware scanner', ok: true, detail: `Three scanning engines ready. Virus signatures updated ${sigAge < 1 ? 'today' : `${Math.round(sigAge)} days ago`}${e.customRules ? `, plus ${e.customRules} sets of extra Mac malware rules` : ''}.` }
    : { name: 'Malware scanner', ok: false, detail: !e.clamav ? 'The ClamAV scanner is not installed.' : !e.clamavDb ? 'Virus signatures are not downloaded yet.' : `Virus signatures are ${Math.round(sigAge)} days old.`, fix: 'Check that the Mac is online. I update signatures twice a day by myself; if this stays, reinstall Hashling with its installer.' });
  const intel = getSnapshot<{ feeds: { entries: number; updated: number | null; error?: string }[] }>('intel')?.data?.feeds ?? [];
  const entries = intel.reduce((n, f) => n + (f.entries ?? 0), 0);
  const oldest = Math.max(...intel.map((f) => (f.updated ? Date.now() - f.updated : Infinity)), 0) / DAY;
  items.push(intel.length && oldest < 2
    ? { name: 'Scam and malware lists', ok: true, detail: `${entries.toLocaleString('en')} known bad websites and servers, updated ${oldest < 1 ? 'today' : 'yesterday'}.` }
    : { name: 'Scam and malware lists', ok: false, detail: intel.length ? `Some lists are ${Math.round(oldest)} days old.` : 'Not downloaded yet.', fix: 'Check that the Mac is online. I refresh them every few hours by myself.' });
  const perms = getSnapshot<{ fullDiskAccess: boolean }>('permissions')?.data;
  items.push(perms?.fullDiskAccess
    ? { name: 'Full Disk Access', ok: true, detail: 'On. I can see app permissions, browser extensions and history checks.' }
    : { name: 'Full Disk Access', ok: false, detail: 'Off. I can’t see which apps can use your camera or screen, or check your browsers.', fix: 'Turn on Hashling in System Settings, Privacy & Security, Full Disk Access.', pane: 'fda' });
  items.push(clientStatus.notifications === 'off'
    ? { name: 'Notifications', ok: false, detail: 'Off. I can only warn you when this page is open (the most serious alerts still pop up).', fix: 'Turn on “Allow notifications” for Hashling.', pane: 'notifications' }
    : { name: 'Notifications', ok: true, detail: clientStatus.notifications === 'on' ? 'On. I can warn you even when this page is closed.' : 'Not checked yet.' });
  send(res, 200, { at: Date.now(), ok: items.every((i) => i.ok), items });
});
// Scam check: red flags plus any link in the text that is on a phishing or malware list. Local only.
route('POST', '/api/scam-flags', async (req, res) => {
  const text = String((await body(req)).text ?? '').slice(0, 20_000);
  const flags = redFlags(text);
  const hosts = [...new Set([...text.matchAll(/\b(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/gi)].map((m) => m[1].toLowerCase()))];
  const listed = hosts.map((h) => ({ host: h, hit: matchHost(h) })).filter((x) => x.hit);
  for (const l of listed) flags.unshift({ label: `Known ${/phishing/.test(l.hit!.label) ? 'phishing' : 'malware'} site: ${l.host}`, why: `${l.hit!.feed} lists it as a ${l.hit!.label}. Do not open it.` });
  send(res, 200, { flags, listed: listed.map((l) => ({ host: l.host, label: l.hit!.label, feed: l.hit!.feed })) });
});
route('GET', '/api/client-status', (_q, res) => send(res, 200, clientStatus));
route('POST', '/api/sensor-alert', async (req, res) => {
  const b = await body(req);
  const kind = ['camera', 'screen'].includes(b.kind) ? b.kind : 'microphone';
  logEvent('permission', 'medium', `${String(b.app ?? 'An app').slice(0, 60)} ${kind === 'screen' ? 'recorded your screen' : `used your ${kind}`} for the first time`, { app: String(b.app ?? '').slice(0, 60), kind });
  send(res, 200, { ok: true });
}, true);
route('POST', '/api/open-uninstaller', async (req, res) => {
  const { app } = await body(req);
  const u = typeof app === 'string' ? findUninstaller(app) : null;
  if (!u) return send(res, 404, { error: 'No uninstaller found next to this app.' });
  const r = await run('/usr/bin/open', [u]);
  send(res, r.ok ? 200 : 500, r.ok ? { ok: true, name: basename(u) } : { error: 'Could not open the uninstaller.' });
}, true);
route('POST', '/api/open-settings/:pane', async (_q, res, [pane]) => {
  const anchor = pane.startsWith('tcc-') ? SETTINGS_ANCHOR[pane.slice(4)] : undefined;
  const url = anchor ? `x-apple.systempreferences:com.apple.preference.security?${anchor}` : PANES[pane];
  if (!url) return send(res, 404, { error: 'Unknown settings pane' });
  const r = await run('/usr/bin/open', [url]);
  send(res, r.ok ? 200 : 500, { ok: r.ok });
}, true);
route('GET', '/api/ai/threads', (_q, res) => send(res, 200, listThreads()), true);
route('GET', '/api/ai/threads/:id', (_q, res, [id]) => { const t = getThread(id); t ? send(res, 200, t) : send(res, 404, { error: 'No such conversation' }); }, true);
route('DELETE', '/api/ai/threads/:id', (_q, res, [id]) => { deleteThread(id); send(res, 200, { ok: true }); }, true);
route('POST', '/api/ai/ask', async (req, res) => {
  const b = await body(req);
  const message = String(b.message ?? '').trim();
  if (!message) return send(res, 400, { error: 'Ask something.' });
  res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store', 'x-accel-buffering': 'no' });
  const ac = new AbortController();
  res.on('close', () => { if (!res.writableEnded) ac.abort(); });
  await ask({ threadId: b.threadId, message, context: b.context }, (e) => { if (!res.writableEnded) res.write(JSON.stringify(e) + '\n'); }, ac.signal);
  res.end();
}, true);
// Phone mode. Switching it on opens a door on the Wi-Fi, so it asks for Touch ID first.
route('GET', '/api/phone', (_q, res) => send(res, 200, phoneState()), true);
route('POST', '/api/phone/on', async (_q, res) => {
  const p = await userPresence('let your phone connect to Hashling over your Wi-Fi');
  if (!p.ok) return send(res, 403, { error: `Not switched on: ${p.message}.` });
  try { send(res, 200, await phoneOn()); } catch (e) { send(res, 500, { error: `I couldn’t open phone mode: ${(e as Error).message}` }); }
}, true);
route('POST', '/api/phone/off', (_q, res) => send(res, 200, phoneOff()), true);
route('POST', '/api/phone/pair', (_q, res) => { const r = newPairing(); send(res, 'error' in r ? 400 : 200, r); }, true);
route('GET', '/api/phone/pair/:id', (_q, res, [id]) => send(res, 200, pairingDone(id)), true);
route('DELETE', '/api/phone/devices/:id', (_q, res, [id]) => send(res, forgetPhone(id) ? 200 : 404, { ok: true }), true);
// Phone check-up over a USB cable. Agents can read the reports; only the person at the Mac can start a check.
route('GET', '/api/phonecheck', (_q, res) => send(res, 200, phoneCheckState()));
route('POST', '/api/phonecheck/tools/:kind', (_q, res, [kind]) => {
  if (!['ios', 'android', 'mvt'].includes(kind)) return send(res, 400, { error: 'Unknown tool' });
  const r = installPhoneTools(kind as 'ios' | 'android' | 'mvt'); send(res, 'error' in r ? 409 : 202, r);
}, true);
route('POST', '/api/phonecheck/trust/:id', async (_q, res, [id]) => send(res, 200, await askToTrust(id)), true);
route('POST', '/api/phonecheck/check/:id', (_q, res, [id]) => { const r = startCheck(id); send(res, 'error' in r ? 409 : 202, r); }, true);
route('POST', '/api/phonecheck/deep/:id', async (req, res, [id]) => { const b = await body(req); const r = startDeepCheck(id, typeof b.password === 'string' && b.password ? b.password : undefined); send(res, 'error' in r ? 409 : 202, r); }, true);
route('DELETE', '/api/phonecheck/reports/:id', (_q, res, [id]) => send(res, forgetReport(id) ? 200 : 404, { ok: true }), true);
// Breach watch. The addresses are personal, so only the dashboard can see or change the list.
// Ransomware brake: programs paused because they were scrambling files. Letting one carry on needs Touch ID.
route('GET', '/api/ransomware/paused', (_q, res) => send(res, 200, pausedPrograms()));
route('POST', '/api/ransomware/resume/:pid', async (_q, res, [pid]) => {
  const p = pausedPrograms().find((x) => x.pid === Number(pid));
  if (!p) return send(res, 404, { error: 'That program is not paused.' });
  const ok = await userPresence(`let ${p.name} carry on changing your files`);
  if (!ok.ok) return send(res, 403, { error: `Still paused: ${ok.message}.` });
  send(res, 200, { ok: resumeProgram(p.pid) });
}, true);
route('GET', '/api/breaches', (_q, res) => send(res, 200, listWatched()), true);
route('POST', '/api/breaches', async (req, res) => { const r = await watchEmail(String((await body(req)).email ?? '')); send(res, 'error' in r ? 400 : 200, r); }, true);
route('POST', '/api/breaches/check', async (_q, res) => { await checkBreaches(true); send(res, 200, listWatched()); }, true);
route('DELETE', '/api/breaches/:email', (_q, res, [email]) => send(res, unwatchEmail(email) ? 200 : 404, { ok: true }), true);
route('GET', '/api/quarantine', (_q, res) => send(res, 200, { items: listQuarantine(), blockedDomains: blockedDomains() }));
route('POST', '/api/run/:name', async (_q, res, [name]) => {
  if (!collectorNames.includes(name)) return send(res, 404, { error: 'Unknown collector' });
  void runCollector(name);
  send(res, 202, { ok: true });
}, true);

function sse(req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
  res.write('retry: 3000\n\n');
  let pending = new Set<string>();
  let timer: NodeJS.Timeout | null = null;
  const onChange = (e: { type: string; name?: string; category?: string }) => {
    pending.add(e.name ?? e.category ?? e.type);
    if (!timer) timer = setTimeout(() => { res.write(`event: change\ndata: ${JSON.stringify([...pending])}\n\n`); pending = new Set(); timer = null; }, 400);
  };
  bus.on('change', onChange);
  const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
  req.on('close', () => { bus.off('change', onChange); clearInterval(ping); if (timer) clearTimeout(timer); });
}

export function startServer(): void {
  const server = createServer(async (req, res) => {
    try {
      if (!hostOk(req)) { res.writeHead(421); res.end('Misdirected request'); return; }
      // Pages live at hashling.localhost. Old addresses still work for the CLI and agents (the API),
      // but a browser visiting one is sent to the friendly name, keeping the path and sign-in code.
      if (req.method === 'GET' && !req.url?.startsWith('/api/') && (req.headers.host ?? '').toLowerCase() !== `${LOCAL_NAME}:${PORT}`) {
        res.writeHead(302, { location: DASHBOARD_URL + (req.url ?? '/'), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
        res.end();
        return;
      }
      if (crossSite(req)) {
        // Someone followed a link to Hashling from another site. Data and actions stay refused; a plain
        // page visit gets a friendly stop page whose button makes a same-site visit the user chose.
        if (req.method === 'GET' && req.headers['sec-fetch-mode'] === 'navigate' && req.headers['sec-fetch-dest'] === 'document') return arrivedFromElsewhere(res);
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }); res.end('I only accept requests from my own pages.'); return;
      }
      const url = new URL(req.url ?? '/', `http://${HOST}:${PORT}`);
      if (url.pathname === '/api/health') return send(res, 200, { ok: true, name: 'hashling', ui: uiBuild() });
      if (url.pathname === '/api/unlock' && req.method === 'POST') return await unlock(req, res);

      if (!url.pathname.startsWith('/api/')) {
        const code = url.searchParams.get('c');
        if (code) {
          // Clean URL either way; a used or expired code simply lands on the unlock screen.
          const ok = redeemSignInCode(code);
          res.writeHead(302, { location: '/', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', ...(ok ? { 'set-cookie': sessionCookie() } : {}) });
          res.end();
          return;
        }
        if (!who(req)) {
          if (url.pathname === '/' || url.pathname === '/index.html') return unlockPage(res);
          res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('Sign in to Hashling first.');
          return;
        }
        if (url.pathname === '/unlock.html' || url.pathname === '/unlock.js') { res.writeHead(302, { location: '/' }); res.end(); return; }
        return staticFile(res, url.pathname);
      }

      const w = who(req);
      if (!w) return send(res, 401, { error: 'Missing or wrong token' });
      if (url.pathname === '/api/stream') return sse(req, res);
      if (req.method !== 'GET' && !originOk(req)) return send(res, 403, { error: 'Bad origin' });
      for (const r of routes) {
        const m = r.method === req.method && url.pathname.match(r.re);
        if (!m) continue;
        if (w.kind === 'phone' && !phoneMayCall(req.method ?? 'GET', url.pathname + url.search)) return send(res, 403, { error: 'That can only be done on the Mac.' });
        if (r.dashboardOnly && w.kind !== 'dashboard' && w.kind !== 'phone') return send(res, 403, { error: 'Only the person using this Mac can do that, from the Hashling dashboard. Agents can propose actions with POST /api/actions.' });
        return await r.h(req, res, m.slice(1).map(decodeURIComponent), w, url);
      }
      send(res, 404, { error: 'Not found' });
    } catch (e) {
      send(res, 500, { error: String((e as Error).message) });
    }
  });
  // On restart the previous instance can hold the port for a moment; wait for it instead of crashing.
  let tries = 0;
  server.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code === 'EADDRINUSE' && tries++ < 60) { setTimeout(() => server.listen(PORT, HOST), 250); return; }
    console.error('Hashling could not start its dashboard:', e.message);
    process.exit(1);
  });
  server.listen(PORT, HOST, () => {
    console.log(`Hashling dashboard on ${DASHBOARD_URL}${tries ? ` (after waiting ${(tries * 0.25).toFixed(1)}s for the port)` : ''}`);
    // macOS answers hashling.localhost with ::1 first; listening there too saves the browser a fallback.
    const v6 = createServer(server.listeners('request')[0] as Parameters<typeof createServer>[1]);
    v6.on('error', () => { /* IPv6 loopback unavailable: browsers fall back to 127.0.0.1 */ });
    v6.listen(PORT, '::1');
  });
}
