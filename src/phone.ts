/**
 * Phone mode: use Hashling from your phone over your Wi-Fi.
 *
 * Off until the user switches it on (with Touch ID). Then a second, small server listens on the
 * Wi-Fi for this Mac's paired phones only. A phone pairs by scanning a QR code on the Mac screen:
 * the code carries a random key in the URL fragment, which browsers never send over the network.
 * Every request and answer after that is sealed with ChaCha20-Poly1305 under that key, because a
 * plain http:// page on the Wi-Fi cannot use the browser's own crypto. Nothing readable crosses
 * the air, and a message that was changed, replayed or sealed with another key is refused.
 *
 * The phone can look, check scams, ask, reject and ignore. Approving a fix still needs Touch ID
 * on this Mac, exactly as from the dashboard.
 */
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { networkInterfaces } from 'node:os';
import { readFileSync, existsSync } from 'node:fs';
import { join, extname, normalize } from 'node:path';
import { PORT, PHONE_PORT, ROOT, TOKEN_PATH } from './config.ts';
import { db, now, logEvent, putSnapshot, getSnapshot } from './db.ts';
import { bus } from './bus.ts';
import { run } from './lib/exec.ts';

db.exec(`CREATE TABLE IF NOT EXISTS phone_devices (
  id TEXT PRIMARY KEY,
  name TEXT,
  key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  paired_at INTEGER,
  last_seen INTEGER,
  address TEXT
)`);

/** The API trusts this per-run header (with the token) as "your paired phone". It never leaves this Mac. */
export const PHONE_SECRET = randomBytes(24).toString('hex');

const PAIR_WINDOW = 10 * 60_000;
const CLOCK_SKEW = 5 * 60_000;
const DIR = join(ROOT, 'dashboard', 'phone');

/** What a phone may ask for. Everything else is refused before it reaches the API. */
const ALLOWED: [string, RegExp][] = [
  ['GET', /^\/api\/(overview|suspicious|events|ai\/status|ai\/threads)(\?.*)?$/],
  ['GET', /^\/api\/findings(\/[\w-]+)?(\?.*)?$/],
  ['GET', /^\/api\/actions(\?status=(pending|archived))?$/],
  ['POST', /^\/api\/(scam-flags|read-image|ai\/ask)$/],
  ['POST', /^\/api\/actions\/[\w-]+\/(approve|reject|restore)$/],
  ['POST', /^\/api\/findings\/[\w-]+\/ignore$/],
];
export const phoneMayCall = (method: string, path: string) => ALLOWED.some(([m, re]) => m === method && re.test(path));

let server: Server | null = null;
let macName = 'your Mac';
void run('/usr/sbin/scutil', ['--get', 'ComputerName']).then((r) => { if (r.ok && r.stdout.trim()) macName = r.stdout.trim(); });

/** This Mac's Wi-Fi / Ethernet addresses a phone can reach. */
function lanAddresses(): string[] {
  const out: string[] = [];
  for (const [name, list] of Object.entries(networkInterfaces())) {
    if (!/^(en|bridge)\d/.test(name)) continue;
    for (const a of list ?? []) if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')) out.push(a.address);
  }
  return out;
}

type Device = { id: string; name: string | null; key: string; created_at: number; paired_at: number | null; last_seen: number | null; address: string | null };
const devices = () => db.prepare('SELECT * FROM phone_devices WHERE paired_at IS NOT NULL ORDER BY paired_at DESC').all() as Device[];

export function phoneState() {
  const on = Boolean(server?.listening);
  const addrs = lanAddresses();
  return {
    on,
    port: PHONE_PORT,
    addresses: addrs,
    wifi: addrs.length > 0,
    macName,
    devices: devices().map((d) => ({ id: d.id, name: d.name ?? 'Phone', paired_at: d.paired_at, last_seen: d.last_seen })),
  };
}

/** Switch phone mode on. The caller has already confirmed with Touch ID. */
export async function phoneOn(): Promise<ReturnType<typeof phoneState>> {
  putSnapshot('phoneMode', { on: true });
  await listen();
  logEvent('system', 'info', 'Phone mode switched on');
  bus.emit('change', { type: 'phone' });
  return phoneState();
}

export function phoneOff(): ReturnType<typeof phoneState> {
  putSnapshot('phoneMode', { on: false });
  server?.close();
  server = null;
  db.prepare('DELETE FROM phone_devices WHERE paired_at IS NULL').run();
  logEvent('system', 'info', 'Phone mode switched off');
  bus.emit('change', { type: 'phone' });
  return phoneState();
}

/** On start-up, reopen phone mode if the user left it on. */
export function startPhoneIfOn(): void {
  if (getSnapshot<{ on: boolean }>('phoneMode')?.data.on) void listen().catch((e) => console.error('[phone]', e.message));
}

/** A fresh pairing: a QR code that works once, for 10 minutes. */
export function newPairing(): { id: string; url: string; expiresAt: number } | { error: string } {
  if (!server?.listening) return { error: 'Switch phone mode on first.' };
  const addr = lanAddresses()[0];
  if (!addr) return { error: 'This Mac is not on Wi-Fi, so a phone cannot reach it.' };
  db.prepare('DELETE FROM phone_devices WHERE paired_at IS NULL AND created_at < ?').run(now() - PAIR_WINDOW);
  const id = randomBytes(9).toString('base64url');
  const key = randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO phone_devices (id, key, created_at) VALUES (?, ?, ?)').run(id, key, now());
  return { id, url: `http://${addr}:${PHONE_PORT}/#${id}.${key}`, expiresAt: now() + PAIR_WINDOW };
}

export function forgetPhone(id: string): boolean {
  const d = db.prepare('SELECT name FROM phone_devices WHERE id = ?').get(id) as { name: string | null } | undefined;
  if (!d) return false;
  db.prepare('DELETE FROM phone_devices WHERE id = ?').run(id);
  logEvent('system', 'info', `Disconnected ${d.name ?? 'a phone'}`);
  bus.emit('change', { type: 'phone' });
  return true;
}

/** Was this pairing scanned yet? The Settings card waits on it. */
export function pairingDone(id: string): { paired: boolean; name?: string; expired?: boolean } {
  const d = db.prepare('SELECT * FROM phone_devices WHERE id = ?').get(id) as Device | undefined;
  if (!d) return { paired: false, expired: true };
  if (d.paired_at) return { paired: true, name: d.name ?? 'Phone' };
  return { paired: false, expired: now() - d.created_at > PAIR_WINDOW };
}

function listen(): Promise<void> {
  if (server?.listening) return Promise.resolve();
  server = createServer((req, res) => { void handle(req, res).catch(() => reply(res, 500, { error: 'Something went wrong.' })); });
  server.requestTimeout = 180_000;
  return new Promise((resolve, reject) => {
    server!.once('error', reject);
    server!.listen(PHONE_PORT, '0.0.0.0', () => { server!.off('error', reject); resolve(); });
  });
}

const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };

function reply(res: ServerResponse, code: number, body: unknown): void {
  if (res.headersSent) return;
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

/** The phone app itself: plain files with no data in them. */
function staticFile(res: ServerResponse, path: string): void {
  const rel = normalize(path === '/' ? '/index.html' : path).replace(/^(\.\.[/\\])+/, '');
  const file = rel === '/favicon.svg' ? join(ROOT, 'dashboard', 'favicon.svg') : join(DIR, rel);
  if ((!file.startsWith(DIR) && !file.endsWith('favicon.svg')) || !existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
  res.writeHead(200, {
    'content-type': MIME[extname(file)] ?? 'application/octet-stream',
    'cache-control': 'no-cache',
    'content-security-policy': "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
  });
  res.end(readFileSync(file));
}

const seen = new Map<string, number>();
const failures = new Map<string, number[]>();
const tooManyFailures = (ip: string) => (failures.get(ip) ?? []).filter((t) => now() - t < 60_000).length >= 20;
const fail = (ip: string) => failures.set(ip, [...(failures.get(ip) ?? []).filter((t) => now() - t < 60_000), now()]);

function sealFor(key: Buffer, id: string, payload: unknown): { n: string; c: string } {
  const nonce = randomBytes(12);
  const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  const pt = Buffer.from(JSON.stringify(payload));
  c.setAAD(Buffer.from(`hashling-phone:${id}:res`), { plaintextLength: pt.length });
  return { n: nonce.toString('base64url'), c: Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]).toString('base64url') };
}

function openFrom(key: Buffer, id: string, n: string, c: string): Record<string, any> {
  const nonce = Buffer.from(n, 'base64url');
  const sealed = Buffer.from(c, 'base64url');
  if (nonce.length !== 12 || sealed.length < 16) throw new Error('bad message');
  const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAAD(Buffer.from(`hashling-phone:${id}:req`), { plaintextLength: sealed.length - 16 });
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  return JSON.parse(Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]).toString('utf8'));
}

async function readBody(req: IncomingMessage, limit: number): Promise<string> {
  let data = '';
  for await (const chunk of req) { data += chunk; if (data.length > limit) throw new Error('too large'); }
  return data;
}

let TOKEN = '';
const token = () => (TOKEN ||= readFileSync(TOKEN_PATH, 'utf8').trim());

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://phone');
  const ip = req.socket.remoteAddress ?? '?';
  if (req.method === 'GET') return staticFile(res, url.pathname);
  const m = req.method === 'POST' && url.pathname.match(/^\/p\/([\w-]{6,40})$/);
  if (!m) return reply(res, 404, { error: 'Not found' });
  if (tooManyFailures(ip)) return reply(res, 429, { error: 'Too many tries. Wait a minute.' });

  const id = m[1];
  const dev = db.prepare('SELECT * FROM phone_devices WHERE id = ?').get(id) as Device | undefined;
  if (!dev) { fail(ip); return reply(res, 404, { error: 'forgotten' }); }
  if (!dev.paired_at && now() - dev.created_at > PAIR_WINDOW) { db.prepare('DELETE FROM phone_devices WHERE id = ?').run(id); return reply(res, 410, { error: 'expired' }); }

  const key = Buffer.from(dev.key, 'base64url');
  let msg: Record<string, any>;
  try {
    const raw = JSON.parse(await readBody(req, 16 * 1024 ** 2));
    msg = openFrom(key, id, String(raw.n), String(raw.c));
  } catch { fail(ip); return reply(res, 401, { error: 'sealed' }); }
  // Fresh and never seen before, so a recorded message cannot be played again.
  for (const [k, t] of seen) if (now() - t > 2 * CLOCK_SKEW) seen.delete(k);
  const nonceKey = `${id}:${msg.r}`;
  if (typeof msg.t !== 'number' || Math.abs(now() - msg.t) > CLOCK_SKEW || !msg.r || seen.has(nonceKey)) return reply(res, 200, sealFor(key, id, { status: 409, body: { error: 'Your phone’s clock looks off, or this was sent twice. Try again.' } }));
  seen.set(nonceKey, now());

  if (!dev.paired_at) {
    const name = String(msg.device ?? 'Phone').replace(/[^\p{L}\p{N} .,'’()-]/gu, '').slice(0, 40) || 'Phone';
    db.prepare('UPDATE phone_devices SET paired_at = ?, name = ?, address = ?, last_seen = ? WHERE id = ?').run(now(), name, ip, now(), id);
    // The same phone scanning a new code replaces its old connection instead of listing it twice.
    db.prepare('DELETE FROM phone_devices WHERE id != ? AND name = ? AND address = ? AND paired_at IS NOT NULL').run(id, name, ip);
    logEvent('system', 'info', `Your ${name} is connected to Hashling`);
    bus.emit('change', { type: 'phone' });
  }
  else if (!dev.last_seen || now() - dev.last_seen > 30_000) db.prepare('UPDATE phone_devices SET last_seen = ?, address = ? WHERE id = ?').run(now(), ip, id);

  const method = String(msg.method ?? 'GET').toUpperCase();
  const path = String(msg.path ?? '');
  if (path === '/hello') return reply(res, 200, sealFor(key, id, { status: 200, body: { ok: true, mac: macName } }));
  if (!phoneMayCall(method, path)) return reply(res, 200, sealFor(key, id, { status: 403, body: { error: 'That can only be done on the Mac.' } }));

  const bin = typeof msg.bin === 'string' ? Buffer.from(msg.bin, 'base64') : null;
  const r = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method,
    headers: { authorization: `Bearer ${token()}`, 'x-hashling-phone': PHONE_SECRET, 'x-hashling-client': `Your ${dev.name ?? 'phone'}`, 'content-type': bin ? 'application/octet-stream' : 'application/json' },
    body: method === 'GET' ? undefined : bin ?? JSON.stringify(msg.body ?? {}),
    signal: AbortSignal.timeout(170_000),
  });
  const text = await r.text();
  let body: unknown;
  if (path === '/api/ai/ask') {
    // The assistant streams its answer; the phone gets it whole.
    const out: { text: string; actions: unknown[]; threadId?: string; error?: string } = { text: '', actions: [] };
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line);
        if (e.type === 'text') out.text += e.text;
        else if (e.type === 'action') out.actions.push(e.action);
        else if (e.type === 'start' || e.type === 'done') out.threadId = e.threadId ?? out.threadId;
        else if (e.type === 'error') out.error = e.message;
      } catch { /* partial line */ }
    }
    body = out;
  } else {
    try { body = JSON.parse(text); } catch { body = { error: text.slice(0, 200) }; }
  }
  reply(res, 200, sealFor(key, id, { status: r.status, body }));
}
