/**
 * Live watch on the places new software arrives (Downloads, Applications) and
 * where it installs itself to run at login (LaunchAgents/Daemons), using macOS
 * FSEvents through fs.watch. Each new download gets: where it came from (the
 * download URL macOS records), the threat-feed check on that host, who signed
 * it, Apple's notarization verdict, and a ClamAV + YARA-X scan.
 */
import { watch, existsSync, statSync, mkdirSync, writeFileSync, unlinkSync, type FSWatcher } from 'node:fs';
import { join, basename, extname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { APP_PATH, DATA_DIR, HOME } from '../config.ts';
import { run } from '../lib/exec.ts';
import { signInfo, describeSigner } from '../lib/codesign.ts';
import { matchHost } from '../intel/feeds.ts';
import { reputation } from '../intel/reputation.ts';
import { requestScan, getScan } from '../scanner.ts';
import { db, now, toJson, parseJson, logEvent, syncFindings, putSnapshot, type FindingInput } from '../db.ts';
import { bus } from '../bus.ts';

db.exec(`CREATE TABLE IF NOT EXISTS downloads (
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  size INTEGER NOT NULL,
  kind TEXT NOT NULL,
  from_url TEXT,
  referrer TEXT,
  agent TEXT,
  signer TEXT,
  signer_kind TEXT,
  notarized TEXT,
  intel TEXT,
  scan_id TEXT
)`);
try { db.exec('ALTER TABLE downloads ADD COLUMN rep TEXT'); } catch { /* exists */ }
try { db.exec('ALTER TABLE downloads ADD COLUMN version TEXT'); } catch { /* exists */ }

const WATCH = {
  downloads: join(HOME, 'Downloads'),
  apps: '/Applications',
  userApps: join(HOME, 'Applications'),
};
const PERSIST_DIRS = [join(HOME, 'Library/LaunchAgents'), '/Library/LaunchAgents', '/Library/LaunchDaemons'];
const PARTIAL = /\.(crdownload|download|part|partial|tmp|opdownload)$|^\.|^~\$/i;
const EXEC_EXT = new Set(['.app', '.pkg', '.mpkg', '.dmg', '.zip', '.command', '.sh', '.tool', '.terminal', '.workflow', '.scpt', '.jar', '.iso', '.tar', '.gz', '.tgz', '.7z', '.rar', '.xz', '.bz2']);

const watchers: FSWatcher[] = [];
const pending = new Map<string, NodeJS.Timeout>();
let status: { watching: string[]; blocked: string[] } = { watching: [], blocked: [] };

function kindOf(path: string): string {
  const ext = extname(path).toLowerCase();
  if (ext === '.app') return 'app';
  if (ext === '.pkg' || ext === '.mpkg') return 'installer';
  if (ext === '.dmg' || ext === '.iso') return 'disk image';
  if (['.zip', '.tar', '.gz', '.tgz', '.7z', '.rar', '.xz', '.bz2'].includes(ext)) return 'archive';
  if (['.command', '.sh', '.tool', '.terminal', '.workflow', '.scpt', '.jar'].includes(ext)) return 'script';
  if (['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.pages', '.numbers', '.key'].includes(ext)) return 'document';
  if (['.jpg', '.jpeg', '.png', '.gif', '.heic', '.webp', '.mp4', '.mov', '.mp3', '.wav', '.m4a'].includes(ext)) return 'media';
  return ext ? ext.slice(1) : 'file';
}

/** Where macOS says a download came from: URL + referrer, plus the app that downloaded it. */
async function provenance(path: string): Promise<{ url?: string; referrer?: string; agent?: string }> {
  const out: { url?: string; referrer?: string; agent?: string } = {};
  const q = await run('/usr/bin/xattr', ['-p', 'com.apple.quarantine', path], { timeout: 5000 });
  if (q.ok) out.agent = q.stdout.trim().split(';')[2] || undefined;
  const w = await run('/usr/bin/xattr', ['-px', 'com.apple.metadata:kMDItemWhereFroms', path], { timeout: 5000 });
  if (w.ok && w.stdout.trim()) {
    const tmpDir = join(DATA_DIR, 'tmp');
    mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
    const tmp = join(tmpDir, `wf-${randomUUID()}.plist`);
    writeFileSync(tmp, Buffer.from(w.stdout.replace(/\s+/g, ''), 'hex'));
    const j = await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', tmp], { timeout: 5000 });
    try { unlinkSync(tmp); } catch { /* already gone */ }
    try { const arr = JSON.parse(j.stdout) as string[]; out.url = arr[0]; out.referrer = arr[1]; } catch { /* ignore */ }
  }
  return out;
}

/** Apple's verdict: is this notarized? */
async function notarization(path: string, kind: string): Promise<string> {
  const type = kind === 'installer' ? 'install' : kind === 'disk image' ? 'open' : 'exec';
  const args = ['-a', '-vv', '-t', type, ...(type === 'open' ? ['--context', 'context:primary-signature'] : []), path];
  const r = await run('/usr/sbin/spctl', args, { timeout: 20_000 });
  const text = `${r.stdout}\n${r.stderr}`;
  if (/source=Notarized/i.test(text)) return 'notarized';
  if (/source=(Apple System|Mac App Store)/i.test(text)) return 'apple';
  if (/accepted/.test(text)) return 'accepted';
  if (/rejected|no usable signature/i.test(text)) return 'rejected';
  return 'unknown';
}

/** An app's version from its Info.plist, e.g. "156.0.8078.47". */
async function appVersion(path: string): Promise<string | null> {
  const plist = join(path, 'Contents/Info.plist');
  for (const key of ['CFBundleShortVersionString', 'CFBundleVersion']) {
    const r = await run('/usr/bin/plutil', ['-extract', key, 'raw', '-o', '-', plist], { timeout: 5000 });
    if (r.ok && r.stdout.trim()) return r.stdout.trim();
  }
  return null;
}

async function analyze(path: string): Promise<void> {
  if (!existsSync(path)) return;
  let st = statSync(path);
  if (st.isDirectory() && !path.endsWith('.app')) return;
  // Wait until the file stops growing (browsers write in chunks).
  for (let i = 0; i < 20 && st.isFile(); i++) {
    await new Promise((r) => setTimeout(r, 1500));
    if (!existsSync(path)) return;
    const next = statSync(path);
    if (next.size === st.size) break;
    st = next;
  }
  const kind = kindOf(path);
  const name = basename(path);
  // Apps are folders that change inside every time they run or update themselves, so an app
  // counts as new only the first time, and again only when its version changes.
  const version = kind === 'app' ? await appVersion(path) : null;
  const known = kind === 'app'
    ? db.prepare('SELECT version FROM downloads WHERE path = ? ORDER BY ts DESC LIMIT 1').get(path) as { version: string | null } | undefined
    : undefined;
  if (kind === 'app' && known && (known.version ?? null) === version) return;
  if (kind !== 'app' && db.prepare('SELECT 1 FROM downloads WHERE path = ? AND size = ? AND ts > ?').get(path, st.size, now() - 3600_000)) return;

  const prov = await provenance(path);
  const host = prov.url ? (() => { try { return new URL(prov.url!).hostname; } catch { return undefined; } })() : undefined;
  const intel = host ? matchHost(host) : null;
  const executable = EXEC_EXT.has(extname(path).toLowerCase()) || kind === 'app';
  const sign = executable ? await signInfo(path) : null;
  const notarized = executable && ['app', 'installer', 'disk image'].includes(kind) ? await notarization(path, kind) : null;
  const scan = executable || kind === 'document' || kind === 'archive' || st.size < 50 * 1048576 ? requestScan([path], 'Hashling (download watch)') : null;
  const scanId = scan && 'id' in scan ? scan.id : null;
  const rep = executable || kind === 'archive' ? await reputation(path).catch(() => null) : null;

  const id = randomUUID().slice(0, 10);
  db.prepare(`INSERT INTO downloads (id, ts, path, name, size, kind, from_url, referrer, agent, signer, signer_kind, notarized, intel, scan_id, rep, version)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, now(), path, name, st.isDirectory() ? 0 : st.size, kind, prov.url ?? null, prov.referrer ?? null, prov.agent ?? null,
      sign ? describeSigner(sign) : null, sign?.kind ?? null, notarized, intel ? toJson(intel) : null, scanId, rep ? toJson(rep) : null, version);
  const title = known ? `${name.replace(/\.app$/, '')} updated${version ? ` to ${version}` : ''}` : `New ${kind}: ${name}${host ? ` from ${host}` : ''}`;
  logEvent('download', intel ? 'high' : 'info', title, { id, path });
  bus.emit('change', { type: 'downloads' });
  refreshDownloadFindings();
}

export function listDownloads(limit = 100) {
  // One row per file: auto-updaters (Chrome, Xcode) rewrite their app bundle several times in a row.
  return (db.prepare(`SELECT d.*, (SELECT COUNT(*) FROM downloads x WHERE x.path = d.path) AS times FROM downloads d
    WHERE d.ts = (SELECT MAX(ts) FROM downloads y WHERE y.path = d.path) ORDER BY d.ts DESC LIMIT ?`).all(limit) as Record<string, unknown>[]).map((r) => {
    const scan = r.scan_id ? getScan(String(r.scan_id)) : null;
    return { ...r, self: r.path === APP_PATH, intel: parseJson(r.intel, null), rep: parseJson(r.rep, null), exists: existsSync(String(r.path)), scan: scan ? { status: scan.status, detections: scan.detections, engines: scan.engines } : null };
  });
}

/** "ChromeUpdate_v2" -> "Chrome Update v2", so word matching works on squashed file names. */
const words = (name: string) => name.replace(/\.[a-z0-9]+$/i, '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_\-.+]+/g, ' ');
/** invoice.pdf.app, photo.jpg.command: a program dressed up as a document. */
const DISGUISED = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|heic|mp4|mov|mp3|txt|rtf|zip)\.(app|command|pkg|scpt|terminal|tool|workflow)$/i;
const FAKE_UPDATE = /\b(chrome|google|safari|firefox|edge|flash ?player|adobe|java|zoom|teams|microsoft|apple|mac ?os|macos|security|video ?player|media ?player|codec|player|update|updater|installer|crack|cracked|keygen|activator|patch|free ?download)\b/i;
export function refreshDownloadFindings(): void {
  const findings: FindingInput[] = [];
  for (const d of listDownloads(200) as Record<string, any>[]) {
    if (!d.exists) continue;
    const host = d.from_url ? (() => { try { return new URL(d.from_url).hostname; } catch { return ''; } })() : '';
    if (d.intel) {
      findings.push({
        key: `download-intel:${d.path}`, category: 'downloads', severity: 'high',
        title: `${d.name} came from a known malware host`,
        summary: `Downloaded from ${host}, listed by ${d.intel.feed} as ${d.intel.label}.`,
        explanation: 'abuse.ch and similar projects track websites that are actively spreading malware. This file was downloaded from one of them, so treat it as dangerous even if the scanners did not recognise it yet.',
        recommendation: 'Do not open it. Quarantine it.',
        evidence: d, actions: [{ type: 'quarantine_file', target: { path: d.path }, label: 'Quarantine file' }],
      });
    }
    if (d.rep?.verdict === 'malicious') {
      findings.push({
        key: `download-rep:${d.path}`, category: 'downloads', severity: 'critical',
        title: `${d.name} matches known malware`,
        summary: d.rep.avDetectionPct ? `${d.rep.avDetectionPct}% of antivirus engines flag this exact file (Team Cymru Malware Hash Registry).` : `Listed as malicious by ${d.rep.knownMalicious} (CIRCL hashlookup).`,
        explanation: 'I fingerprinted this file and looked the fingerprint up in free malware databases. An exact match means this very file has been seen spreading malware.',
        recommendation: 'Do not open it. Quarantine it now.',
        evidence: d, actions: [{ type: 'quarantine_file', target: { path: d.path }, label: 'Quarantine file' }],
      });
    }
    // "Update your browser / player" pages are the most common way Mac stealers arrive: an unchecked
    // installer named after a well-known product or a codec, update or crack.
    const untrusted = ['app', 'installer', 'disk image', 'archive', 'script'].includes(d.kind) && (d.notarized === 'rejected' || ['unsigned', 'adhoc', 'invalid'].includes(d.signer_kind) || d.kind === 'script');
    const disguised = DISGUISED.test(d.name);
    if (d.path !== APP_PATH && (disguised || (untrusted && FAKE_UPDATE.test(words(d.name))))) {
      findings.push({
        key: `download-fake:${d.path}`, category: 'downloads', severity: 'high',
        title: disguised ? `${d.name} is a program pretending to be a document` : `${d.name} looks like a fake update`,
        summary: disguised ? `The name ends in .${d.name.split('.').pop()}, so opening it runs a program, not a document.${host ? ` It came from ${host}.` : ''}` : `It is named like ${FAKE_UPDATE.exec(words(d.name))?.[0] ?? 'an update'} but is not from the real developer${host ? `, and came from ${host}` : ''}.`,
        explanation: 'Pop-ups saying your browser, Flash, a video player or macOS needs an update are a favourite trick: the "update" is malware that steals passwords, cookies and crypto wallets. Real updates come from the app itself, System Settings or the App Store, never from a random website.',
        recommendation: 'Do not open it. Quarantine it. If you already opened it and typed your Mac password, change your important passwords from another device.',
        evidence: d, actions: [{ type: 'quarantine_file', target: { path: d.path }, label: 'Quarantine file' }],
      });
      continue;
    }
    // Hashling's own launcher is Developer ID signed but built locally, so it is never notarized.
    if (d.path !== APP_PATH && ['app', 'installer', 'disk image'].includes(d.kind) && (d.notarized === 'rejected' || ['unsigned', 'adhoc', 'invalid'].includes(d.signer_kind))) {
      findings.push({
        key: `download-unsigned:${d.path}`, category: 'downloads', severity: 'medium',
        title: `${d.name} is not checked by Apple`,
        summary: `${d.signer ? `Made by ${String(d.signer).replace(/\s*\([A-Z0-9]{10}\)$/, '')}` : 'No developer signature'}.${d.notarized === 'rejected' ? ' Apple has not checked it for malware.' : ''}${host ? ` Downloaded from ${host}.` : ''}`,
        explanation: 'Apps from identified developers are signed and notarized (scanned by Apple) before they can open normally. Unsigned or rejected apps skip that check. Fake installers, cracked apps and "update your player" pop-ups are the main way Mac malware spreads, and they look exactly like this.',
        recommendation: 'Only open it if you trust exactly where it came from. Otherwise quarantine it and get the app from the developer\'s official site or the App Store.',
        evidence: d, actions: [{ type: 'quarantine_file', target: { path: d.path }, label: 'Quarantine file' }],
      });
    }
  }
  syncFindings('downloads', findings);
}

function schedule(path: string, fn: () => void, ms = 2500): void {
  clearTimeout(pending.get(path));
  pending.set(path, setTimeout(() => { pending.delete(path); fn(); }, ms));
}

/** Start the watchers. Folders macOS blocks (privacy) are reported, not retried in a loop. */
export function startDownloadWatch(): void {
  const watching: string[] = [];
  const blocked: string[] = [];
  const add = (dir: string, onFile: (path: string) => void, recursive = false) => {
    if (!existsSync(dir)) return;
    try {
      const w = watch(dir, { recursive }, (_ev, file) => {
        if (!file) return;
        const name = String(file);
        const top = name.split('/')[0];
        if (PARTIAL.test(basename(name)) || PARTIAL.test(top)) return;
        onFile(join(dir, top.endsWith('.app') ? top : name));
      });
      w.on('error', () => { /* folder went away or access revoked */ });
      watchers.push(w);
      watching.push(dir);
    } catch {
      blocked.push(dir);
    }
  };
  add(WATCH.downloads, (p) => schedule(p, () => void analyze(p).catch((e) => console.error('[downloads]', e))));
  for (const dir of [WATCH.apps, WATCH.userApps]) add(dir, (p) => { if (p.endsWith('.app')) schedule(p, () => void analyze(p).catch(() => undefined), 8000); });
  for (const dir of PERSIST_DIRS) add(dir, (p) => schedule(dir, () => { logEvent('persistence', 'low', `Startup folder changed: ${basename(p)}`, { path: p }); bus.emit('trigger', 'persistence'); }, 1500));
  status = { watching, blocked };
  putSnapshot('downloadWatch', { at: Date.now(), ...status });
  void backfillVersions();
}

/** Apps recorded before versions were tracked: note the version they have now, so they don't show up as updated. */
async function backfillVersions(): Promise<void> {
  const rows = db.prepare(`SELECT id, path FROM downloads d WHERE kind = 'app' AND version IS NULL
    AND ts = (SELECT MAX(ts) FROM downloads y WHERE y.path = d.path)`).all() as { id: string; path: string }[];
  for (const r of rows) if (existsSync(r.path)) db.prepare('UPDATE downloads SET version = ? WHERE id = ?').run(await appVersion(r.path), r.id);
}

export function stopDownloadWatch(): void { for (const w of watchers.splice(0)) w.close(); }

/**
 * "Check before you open": everything Hashling knows about one file, waited for, in plain terms.
 * Used for a copy the user picks in the dashboard; nothing is recorded as a download.
 */
export async function checkFile(path: string): Promise<{ kind: string; verdict: 'danger' | 'caution' | 'ok'; reasons: string[]; signer: string | null; apple: string | null; detections: string[] }> {
  const kind = kindOf(path);
  const executable = EXEC_EXT.has(extname(path).toLowerCase()) || kind === 'app';
  const [sign, apple, rep] = await Promise.all([
    executable ? signInfo(path) : Promise.resolve(null),
    executable && ['installer', 'disk image'].includes(kind) ? notarization(path, kind) : Promise.resolve(null),
    reputation(path).catch(() => null),
  ]);
  const scan = requestScan([path], 'You (check before opening)');
  let detections: string[] = [];
  if ('id' in scan) {
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      const s = getScan(scan.id);
      if (s && (s.status === 'done' || s.status === 'failed')) { detections = (s.detections ?? []).map((d) => d.signature); break; }
    }
  }
  const reasons: string[] = [];
  let verdict: 'danger' | 'caution' | 'ok' = 'ok';
  if (detections.length) { verdict = 'danger'; reasons.push(`Matches known malware: ${detections.slice(0, 3).join(', ')}.`); }
  if (rep?.knownMalicious) { verdict = 'danger'; reasons.push(`Listed as malware by ${rep.knownMalicious}.`); }
  if (rep?.avDetectionPct && rep.avDetectionPct >= 10) { verdict = 'danger'; reasons.push(`${Math.round(rep.avDetectionPct)}% of antivirus engines flag it.`); }
  if (apple === 'rejected') { if (verdict === 'ok') verdict = 'caution'; reasons.push('Apple has not checked it (not notarized). macOS would warn you before opening it.'); }
  if (sign && ['unsigned', 'adhoc', 'invalid'].includes(sign.kind)) { if (verdict === 'ok') verdict = 'caution'; reasons.push(sign.kind === 'invalid' ? 'Its developer signature is broken, which can mean it was tampered with.' : 'It has no verified developer.'); }
  if (kind === 'script') { if (verdict === 'ok') verdict = 'caution'; reasons.push('It is a script: opening it runs commands on your Mac. Only open scripts from people you trust.'); }
  if (rep?.knownGood) reasons.push(`Recognised as a genuine file${rep.knownName ? ` (${rep.knownName})` : ''}.`);
  if (!reasons.length) reasons.push('No malware found, and nothing about it looks unusual.');
  if (apple === 'notarized' || apple === 'apple') reasons.push('Apple checked it for malware (notarized).');
  return { kind, verdict, reasons, signer: sign ? describeSigner(sign) : null, apple, detections };
}
