import { plural } from './lib/text.ts';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { BIN, CLAMAV_DB, FRESHCLAM_CONF, RULES_DIR, DATA_DIR, XPROTECT_YARA, HOME } from './config.ts';
import { run, runLines } from './lib/exec.ts';
import { db, now, toJson, parseJson, logEvent, syncFindings, putSnapshot, getSnapshot, type FindingInput } from './db.ts';
import { loadPrefs } from './prefs.ts';
import { autoQuarantine } from './actions.ts';
import { bus } from './bus.ts';

export interface Detection { path: string; engine: 'clamav' | 'yara-x'; signature: string; ruleset?: string }
export interface Scan {
  id: string;
  paths: string[];
  requested_by: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  started_at: number;
  finished_at: number | null;
  files_scanned: number;
  detections: Detection[];
  engines: string[];
  error: string | null;
}

const COMPILED = join(DATA_DIR, 'xprotect.yarc');
const queue: string[] = [];
let busy = false;

/** Folders nobody should be able to make Hashling read for an agent. */
const BLOCKED = [/^\/(System|private\/var\/db|dev)(\/|$)/, /\/Library\/Keychains(\/|$)/, /\/\.ssh(\/|$)/];

export function engines(): { clamav: boolean; clamavDb: boolean; yara: boolean; xprotectRules: boolean; customRules: number } {
  let custom = 0;
  try { custom = readdirSync(RULES_DIR).filter((f) => /\.(yar|yara)$/.test(f)).length; } catch { /* none */ }
  let dbOk = false;
  try { dbOk = readdirSync(CLAMAV_DB).some((f) => /\.(cvd|cld)$/.test(f)); } catch { /* none */ }
  return { clamav: existsSync(BIN.clamscan), clamavDb: dbOk, yara: existsSync(BIN.yr), xprotectRules: existsSync(XPROTECT_YARA), customRules: custom };
}

// Scans that were running when Hashling last stopped will never finish; say so instead of showing "running" forever.
db.prepare(`UPDATE scans SET status = 'failed', finished_at = ?, error = 'Interrupted because I restarted' WHERE status IN ('running', 'queued')`).run(now());

export function requestScan(paths: string[], requestedBy: string): Scan | { error: string } {
  const clean: string[] = [];
  for (const p of paths) {
    const abs = resolve(p.replace(/^~(?=\/|$)/, HOME));
    if (!existsSync(abs)) return { error: `Path does not exist: ${abs}` };
    if (BLOCKED.some((re) => re.test(abs))) return { error: `Scanning ${abs} is not allowed.` };
    clean.push(abs);
  }
  if (!clean.length) return { error: 'No paths given.' };
  if (queue.length >= 5) return { error: 'Too many scans queued. Try again when the current ones finish.' };
  const id = randomUUID().slice(0, 8);
  db.prepare(`INSERT INTO scans (id, paths, requested_by, status, started_at) VALUES (?, ?, ?, 'queued', ?)`).run(id, toJson(clean), requestedBy, now());
  queue.push(id);
  logEvent('scan', 'info', `Scan queued by ${requestedBy}: ${clean.join(', ')}`, { id });
  void pump();
  return getScan(id)!;
}

export function getScan(id: string): Scan | null {
  const r = db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  return r ? toScan(r) : null;
}

export function listScans(limit = 20): Scan[] {
  return (db.prepare('SELECT * FROM scans ORDER BY started_at DESC LIMIT ?').all(limit) as Record<string, unknown>[]).map(toScan);
}

function toScan(r: Record<string, unknown>): Scan {
  return { ...(r as unknown as Scan), paths: parseJson(r.paths, []), detections: parseJson(r.detections, []), engines: parseJson(r.engines, []) };
}

async function pump(): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    while (queue.length) await execute(queue.shift()!);
  } finally {
    busy = false;
  }
}

const CUSTOM_COMPILED = join(DATA_DIR, 'custom.yarc');

/** Community + your own rules in ~/.hashling/rules, compiled once and reused until a file changes. */
async function compiledCustomRules(): Promise<string | null> {
  if (!existsSync(BIN.yr)) return null;
  let newest = 0;
  try { for (const f of readdirSync(RULES_DIR)) if (/\.(yar|yara)$/.test(f)) newest = Math.max(newest, statSync(join(RULES_DIR, f)).mtimeMs); } catch { return null; }
  if (!newest) return null;
  if (existsSync(CUSTOM_COMPILED) && statSync(CUSTOM_COMPILED).mtimeMs > newest) return CUSTOM_COMPILED;
  const r = await run(BIN.yr, ['compile', '--ignore-invalid-rules', '--disable-warnings', '-o', CUSTOM_COMPILED, `custom:${RULES_DIR}`], { timeout: 300_000 });
  return r.ok || existsSync(CUSTOM_COMPILED) ? CUSTOM_COMPILED : null;
}

async function compiledRules(): Promise<string | null> {
  if (!existsSync(BIN.yr) || !existsSync(XPROTECT_YARA)) return null;
  const src = statSync(XPROTECT_YARA).mtimeMs;
  if (existsSync(COMPILED) && statSync(COMPILED).mtimeMs > src) return COMPILED;
  const r = await run(BIN.yr, ['compile', '--ignore-invalid-rules', '--disable-warnings', '-o', COMPILED, `xprotect:${XPROTECT_YARA}`], { timeout: 120_000 });
  return r.ok || existsSync(COMPILED) ? COMPILED : null;
}

async function execute(id: string): Promise<void> {
  const scan = getScan(id);
  if (!scan) return;
  const update = (fields: Partial<Scan>) => {
    const s = { ...getScan(id)!, ...fields };
    db.prepare('UPDATE scans SET status = ?, finished_at = ?, files_scanned = ?, detections = ?, engines = ?, error = ? WHERE id = ?')
      .run(s.status, s.finished_at, s.files_scanned, toJson(s.detections), toJson(s.engines), s.error, id);
    bus.emit('change', { type: 'scan', id });
  };
  update({ status: 'running' });
  const detections: Detection[] = [];
  const used: string[] = [];
  let files = 0;
  const errors: string[] = [];

  try {
    const e = engines();
    if (e.clamav && e.clamavDb) {
      used.push('ClamAV');
      const r = await runLines(BIN.clamscan, ['-r', '--no-summary', '--stdout', `--database=${CLAMAV_DB}`, '--max-filesize=200M', '--max-scansize=400M', '--cross-fs=no', '--exclude-dir=/(node_modules|\\.git|DerivedData|\\.Trash)$', ...scan.paths], (line) => {
        const m = line.match(/^(.*): (.+) FOUND$/);
        if (m) { files++; detections.push({ path: m[1], engine: 'clamav', signature: m[2] }); }
        else if (/: OK$/.test(line)) { files++; if (files % 200 === 0) update({ files_scanned: files, detections }); }
      }, 3 * 3600_000);
      if (r.code !== 0 && r.code !== 1) errors.push(`ClamAV: ${r.stderr.split('\n').find((l) => l.trim()) ?? 'failed'}`);
    } else if (e.clamav) {
      errors.push('ClamAV signatures are not downloaded yet.');
    }

    const yarc = await compiledRules();
    if (yarc) { used.push('YARA-X (Apple XProtect rules)'); }
    const custom = engines().customRules;
    const customYarc = custom ? await compiledCustomRules() : null;
    for (const target of scan.paths) {
      if (yarc) {
        // yr needs every option before the rules and target, or it rejects the target.
        await runLines(BIN.yr, ['scan', '--output-format', 'ndjson', '--recursive', '--skip-larger', String(200 * 1024 * 1024), '--disable-warnings', '-C', yarc, target], (line) => collectYara(line, 'xprotect', detections), 3600_000);
      }
      if (custom) {
        if (customYarc) await runLines(BIN.yr, ['scan', '--output-format', 'ndjson', '--recursive', '--skip-larger', String(200 * 1024 * 1024), '--disable-warnings', '-C', customYarc, target], (line) => collectYara(line, 'custom', detections), 3600_000);
      }
    }
    if (customYarc) used.push(custom === 1 && existsSync(join(RULES_DIR, 'yara-forge-core.yar')) ? 'YARA-X (YARA-Forge community rules)' : `YARA-X (${custom} community/custom rule files)`);
    if (!used.length) throw new Error('No scanning engine is installed.');

    update({ status: 'done', finished_at: now(), files_scanned: files, detections, engines: used, error: errors.join(' ') || null });
    if (detections.length) logEvent('scan', 'high', `Scan found ${plural(detections.length, 'detection')}`, { id, detections: detections.slice(0, 10) });
    else logEvent('scan', 'info', `Scan finished clean (${files} files)`, { id });
    if (detections.length && loadPrefs().autoQuarantine) {
      const inbox = join(DATA_DIR, 'inbox');
      for (const path of new Set(detections.map((d) => d.path))) {
        if (path.startsWith(inbox) || !existsSync(path)) continue;
        await autoQuarantine(path, detections.find((d) => d.path === path)!.signature).catch((e) => console.error('[auto-quarantine]', e));
      }
    }
    refreshScanFindings();
  } catch (err) {
    update({ status: 'failed', finished_at: now(), files_scanned: files, detections, engines: used, error: String((err as Error).message) });
  }
}

function collectYara(line: string, ruleset: string, out: Detection[]): void {
  if (!line.trim()) return;
  try {
    const o = JSON.parse(line) as { path?: string; file?: string; rules?: { identifier?: string; namespace?: string }[]; rule?: string };
    const path = o.path ?? o.file;
    const rules = o.rules ?? (o.rule ? [{ identifier: o.rule }] : []);
    for (const r of rules) if (path && r.identifier) out.push({ path, engine: 'yara-x', signature: r.identifier, ruleset });
  } catch {
    const m = line.match(/^(\S+)\s+(\/.+)$/);
    if (m) out.push({ path: m[2], engine: 'yara-x', signature: m[1], ruleset });
  }
}

/** Every detected file that still exists stays an open malware finding. */
export function refreshScanFindings(): void {
  const rows = db.prepare(`SELECT id, detections FROM scans WHERE status = 'done' AND detections != '[]' ORDER BY started_at DESC LIMIT 50`).all() as { id: string; detections: string }[];
  const byPath = new Map<string, Detection[]>();
  for (const r of rows) for (const d of parseJson<Detection[]>(r.detections, [])) {
    // Copies checked from the dashboard are deleted right after; they are a check, not an infection.
    if (!existsSync(d.path) || d.path.startsWith(join(DATA_DIR, 'inbox'))) continue;
    const list = byPath.get(d.path) ?? [];
    if (!list.some((x) => x.signature === d.signature)) list.push(d);
    byPath.set(d.path, list);
  }
  const findings: FindingInput[] = [...byPath].map(([path, ds]) => ({
    key: `scan:${path}`, category: 'malware', severity: ds.some((d) => /eicar/i.test(d.signature)) ? 'medium' : 'high',
    title: `Malware signature match: ${path.split('/').pop()}`,
    summary: `${ds.map((d) => `${d.signature} (${d.engine === 'clamav' ? 'ClamAV' : 'YARA-X ' + (d.ruleset === 'xprotect' ? 'XProtect rules' : 'custom rules')})`).join(', ')}`,
    explanation: ds.some((d) => /eicar/i.test(d.signature))
      ? 'EICAR is a harmless industry test file used to check that antivirus works. Seeing it means scanning works.'
      : 'This file matches a signature for known malware. ClamAV signatures come from Cisco Talos; XProtect rules are the ones Apple uses in macOS itself. False positives happen but are rare for these rule sets.',
    recommendation: 'Quarantine the file. I keep it in a locked folder so it can be restored if it turns out to be safe.',
    evidence: { path, detections: ds },
    actions: [{ type: 'quarantine_file', target: { path }, label: 'Quarantine file' }],
  }));
  syncFindings('malware', findings);
}

/** Everywhere Mac malware and adware actually live: apps, their support files, startup folders and your files. */
export function fullScanPaths(): string[] {
  return ['/Applications', join(HOME, 'Applications'), join(HOME, 'Library/Application Support'), join(HOME, 'Library/LaunchAgents'),
    '/Library/LaunchAgents', '/Library/LaunchDaemons', '/Library/Application Support', join(HOME, 'Downloads'), join(HOME, 'Desktop'),
    join(HOME, 'Documents'), '/Users/Shared', '/private/tmp', '/private/var/tmp'].filter((p) => existsSync(p));
}
export function requestFullScan(by: string) {
  const r = requestScan(fullScanPaths(), by);
  if ('id' in r) putSnapshot('fullScan', { at: Date.now(), id: r.id });
  return r;
}
/** Once a week, only while the Mac is plugged in and nobody is using it, so it never slows you down. */
export async function weeklyFullScan(): Promise<void> {
  const last = getSnapshot<{ at: number }>('fullScan')?.data.at ?? 0;
  if (Date.now() - last < 7 * 86_400_000) return;
  const power = await run('/usr/bin/pmset', ['-g', 'ps']);
  if (!/AC Power/.test(power.stdout)) return;
  const idle = await run('/usr/sbin/ioreg', ['-c', 'IOHIDSystem', '-d', '4']);
  const ns = Number(idle.stdout.match(/"HIDIdleTime" = (\d+)/)?.[1] ?? 0);
  if (ns / 1e9 < 10 * 60) return;
  requestFullScan('Hashling (weekly full scan)');
}

/** Daily scan of the places downloads and droppers land. */
export function routineScan(): void {
  const targets = [join(HOME, 'Downloads'), '/Users/Shared', join(HOME, 'Library/LaunchAgents'), '/tmp'].filter((p) => existsSync(p));
  if (targets.length) requestScan(targets, 'Hashling (routine)');
}

export async function updateSignatures(): Promise<void> {
  if (!existsSync(BIN.freshclam)) return;
  mkdirSync(CLAMAV_DB, { recursive: true });
  // Older installs wrote "NotifyClamd no", which freshclam rejects (it expects a clamd.conf path).
  try { const conf = readFileSync(FRESHCLAM_CONF, 'utf8'); if (/^NotifyClamd no$/m.test(conf)) writeFileSync(FRESHCLAM_CONF, conf.replace(/^NotifyClamd no\n?/m, '')); } catch { /* no config yet */ }
  // ClamAV 1.5 verifies signed databases against its root certificate, which Homebrew keeps in etc/.
  const certs = join(dirname(dirname(BIN.freshclam)), 'etc/clamav/certs');
  const r = await run(BIN.freshclam, [`--config-file=${FRESHCLAM_CONF}`, '--quiet', ...(existsSync(certs) ? [`--cvdcertsdir=${certs}`] : [])], { timeout: 600_000 });
  putSnapshot('signatures', { at: now(), ok: r.ok, files: readdirSync(CLAMAV_DB) }, r.ok ? null : r.stderr.slice(0, 300));
}
