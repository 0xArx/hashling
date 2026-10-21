import { readdirSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';
import { HOME, APP_PATH } from '../config.ts';
import { run, readPlist } from '../lib/exec.ts';
import { signInfo, describeSigner, riskyLocation } from '../lib/codesign.ts';
import { bundleOf } from '../lib/procs.ts';
import { osquery } from '../lib/osquery.ts';
import { db, putSnapshot, syncFindings, markSeen, baselineStart, type FindingInput, type Severity } from '../db.ts';

export interface PersistItem {
  kind: 'launch-agent' | 'launch-daemon' | 'system-extension' | 'cron' | 'browser-extension' | 'startup-item';
  scope: 'user' | 'system';
  label: string;
  plist?: string;
  program?: string;
  args?: string[];
  runAtLoad?: boolean;
  keepAlive?: boolean;
  disabled?: boolean;
  signer?: string;
  signerKind?: string;
  team?: string;
  firstSeen: number;
  isNew: boolean;
  flags: string[];
  details?: Record<string, unknown>;
}

const LAUNCH_DIRS: { dir: string; kind: PersistItem['kind']; scope: PersistItem['scope'] }[] = [
  { dir: join(HOME, 'Library/LaunchAgents'), kind: 'launch-agent', scope: 'user' },
  { dir: '/Library/LaunchAgents', kind: 'launch-agent', scope: 'system' },
  { dir: '/Library/LaunchDaemons', kind: 'launch-daemon', scope: 'system' },
  { dir: '/Library/StartupItems', kind: 'startup-item', scope: 'system' },
];

const SHELLS = /^\/(bin|usr\/bin)\/(sh|bash|zsh|dash|python3?|perl|ruby|osascript|env)$/;
const DEV_LOCATIONS = /^(\/opt\/homebrew|\/usr\/local|\/Users\/[^/]+\/(Developer|\.nvm|\.volta|\.bun|\.cargo|\.local))\b/;
const NEW_WINDOW = 7 * 86_400_000;

/**
 * Whether a Chromium extension came from an official store. osquery reports from_webstore as
 * "true"/"false" (older builds "1"/"0"), and newer Chrome may leave it empty, so the store update
 * URL in the extension's manifest counts too. Unknown is treated as from the store: only clear
 * evidence of a sideload is flagged.
 */
const STORE_UPDATE = /^https:\/\/(clients2\.google\.com\/service\/update2\/crx|edge\.microsoft\.com\/extensionwebstorebase\/)/;
function storeExtension(e: { from_webstore: string; update_url?: string }): boolean {
  if (/^(true|1)$/i.test(e.from_webstore ?? '') || STORE_UPDATE.test(e.update_url ?? '')) return true;
  return !/^(false|0)$/i.test(e.from_webstore ?? '');
}

export async function collectPersistence(): Promise<void> {
  const items: PersistItem[] = [];
  const findings: FindingInput[] = [];
  const since = baselineStart('persist');
  const baselined = since !== null;
  baseline = since;
  const notes: string[] = [];
  const t = Date.now();

  for (const { dir, kind, scope } of LAUNCH_DIRS) {
    let files: string[] = [];
    try { files = readdirSync(dir).filter((f) => f.endsWith('.plist')); } catch { continue; }
    for (const f of files) {
      const path = join(dir, f);
      const pl = await readPlist<Record<string, unknown>>(path);
      if (!pl) { notes.push(`Could not read ${path}`); continue; }
      const args = Array.isArray(pl.ProgramArguments) ? (pl.ProgramArguments as unknown[]).map(String) : [];
      const program = typeof pl.Program === 'string' ? pl.Program : args[0];
      const label = typeof pl.Label === 'string' ? pl.Label : basename(f, '.plist');
      items.push(await inspect({ kind, scope, label, plist: path, program, args, runAtLoad: Boolean(pl.RunAtLoad), keepAlive: Boolean(pl.KeepAlive), disabled: Boolean(pl.Disabled) }));
    }
  }

  // System extensions (network filters, drivers, endpoint security clients).
  const se = await run('/usr/bin/systemextensionsctl', ['list'], { timeout: 10_000 });
  for (const line of se.stdout.split('\n')) {
    const m = line.match(/^\s*\*?\s*\*?\s*([A-Z0-9]{10})\s+(\S+)\s+\(([^)]*)\)\s+(.+?)\s+\[(.+)\]$/);
    if (m) items.push(await inspect({ kind: 'system-extension', scope: 'system', label: m[4], program: undefined, details: { team: m[1], bundleId: m[2], version: m[3], state: m[5] } }));
  }

  // Cron jobs.
  const cron = await run('/usr/bin/crontab', ['-l'], { timeout: 5000 });
  for (const line of cron.stdout.split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    items.push(await inspect({ kind: 'cron', scope: 'user', label: line.trim().slice(0, 120), program: line.trim().split(/\s+/)[5], details: { line } }));
  }

  // Browser extensions (needs Full Disk Access for Chrome-family profiles).
  const uid = process.getuid?.() ?? 501;
  const ext = await osquery<{ browser_type: string; name: string; identifier: string; from_webstore: string; update_url: string; permissions: string; path: string; version: string }>(
    `SELECT c.browser_type, c.name, c.identifier, c.from_webstore, c.update_url, c.permissions, c.path, c.version FROM users u JOIN chrome_extensions c USING (uid) WHERE u.uid = ${uid}`);
  const ff = await osquery<{ name: string; identifier: string; path: string; version: string; visible: string; active: string }>(
    `SELECT f.name, f.identifier, f.path, f.version, f.visible, f.active FROM users u JOIN firefox_addons f USING (uid) WHERE u.uid = ${uid}`);
  const browserCount = ext.rows.length + ff.rows.length;
  for (const e of ext.rows) {
    const perms = (e.permissions ?? '').split(/,\s*/).filter(Boolean);
    items.push(await inspect({ kind: 'browser-extension', scope: 'user', label: `${e.name} (${e.browser_type})`, program: undefined,
      details: { browser: e.browser_type, id: e.identifier, version: e.version, fromStore: storeExtension(e), permissions: perms, path: e.path } }));
  }
  for (const e of ff.rows) {
    items.push(await inspect({ kind: 'browser-extension', scope: 'user', label: `${e.name} (firefox)`, program: undefined, details: { browser: 'firefox', id: e.identifier, version: e.version, active: e.active === '1', path: e.path } }));
  }
  if (!browserCount) notes.push('Browser extensions are hidden from me until I have Full Disk Access.');
  notes.push('macOS keeps Login Items private, so they are not listed here yet. See them in System Settings > General > Login Items.');

  // Findings.
  for (const it of items) {
    // Hashling's own login item: an update briefly replaces the app, which would look like a broken signature.
    if (it.program?.startsWith(`${APP_PATH}/`)) continue;
    const name = it.label;
    const base = { category: 'persistence', evidence: it as unknown as Record<string, unknown> };
    const disableAction = it.plist ? [{ type: 'disable_persistence', target: { plist: it.plist, label: it.label, scope: it.scope }, label: 'Disable and quarantine' }] : [];
    const push = (key: string, severity: Severity, title: string, summary: string, explanation: string, recommendation: string, extra: Partial<FindingInput> = {}) =>
      findings.push({ ...base, key, severity, title, summary, explanation, recommendation, actions: disableAction, ...extra });

    if (it.flags.includes('script-download')) {
      push(`persist:dl:${it.plist ?? name}`, 'high', `Startup item downloads and runs code: ${name}`,
        `Runs: ${(it.args ?? []).join(' ').slice(0, 200)}`,
        'This item runs a shell command at startup that downloads or decodes something and executes it. That is the classic way Mac malware keeps itself alive and pulls new payloads.',
        'Unless you set this up yourself, disable it and quarantine anything it points to.');
    }
    if (it.flags.includes('risky-location')) {
      push(`persist:loc:${it.plist ?? name}`, 'high', `Startup item runs a program from an unusual folder: ${name}`,
        `${it.program}`, 'Legitimate software runs from /Applications, /Library or system folders. Startup items that launch programs from hidden, temporary or Downloads folders are a common malware pattern.',
        'Check what the program is. If you do not recognise it, disable it.');
    }
    if (it.flags.includes('invalid-signature')) {
      push(`persist:sig:${it.plist ?? name}`, 'high', `Startup program has a broken signature: ${name}`,
        `${it.program}`, 'The program was modified after its developer signed it. That can mean tampering.', 'Reinstall it from the developer or disable it.');
    } else if (it.flags.includes('unsigned')) {
      push(`persist:unsigned:${it.plist ?? name}`, it.flags.includes('dev-location') ? 'low' : 'medium', `Startup program has no developer identity: ${name}`,
        `${it.program} (${it.signer})`, 'Signed programs can be traced to a developer Apple has verified. Unsigned startup programs are normal for tools you install with Homebrew or build yourself, and suspicious otherwise.',
        'If you recognise it, acknowledge this. Otherwise disable it.');
    }
    if (it.flags.includes('missing-program')) {
      push(`persist:orphan:${it.plist ?? name}`, 'low', `Leftover startup item: ${name}`,
        `Points to ${it.program}, which no longer exists.`, 'The app this belonged to was probably deleted but left its startup entry behind. Harmless, but it is clutter macOS tries to launch.',
        'Disable it to clean up.');
    }
    if (it.isNew && baselined && it.kind !== 'browser-extension' && it.signerKind !== 'apple') {
      push(`persist:new:${it.plist ?? it.kind + ':' + name}`, 'medium', `New startup item installed: ${name}`,
        `${it.kind.replace('-', ' ')} added ${new Date(it.firstSeen).toLocaleString()}. ${it.signer ?? ''}`,
        'Something new registered itself to run automatically. Installers do this for updaters and helpers; malware does it to survive restarts.',
        'Make sure it matches something you installed recently.');
    }
    if (it.kind === 'browser-extension') {
      const perms = (it.details?.permissions as string[] | undefined) ?? [];
      if (it.details?.fromStore === false) {
        push(`persist:ext-sideload:${it.details?.id}`, 'medium', `Browser extension not from the store: ${name}`,
          `Permissions: ${perms.join(', ') || 'none'}`, 'Extensions installed outside the official store skip its review. Adware and data-stealing extensions are often sideloaded by other installers.',
          'Remove it from the browser\'s extensions page unless you installed it on purpose (for example while developing).', { actions: [] });
      }
      // Store extensions with broad access are the norm (ad blockers, password managers, Acrobat), so they are not
      // a warning; the extensions list still shows their permissions for anyone who wants to look.
    }
  }

  putSnapshot('persistence', { at: t, items, notes, counts: countBy(items) });
  syncFindings('persistence', findings);
}

let baseline: number | null = null;

async function inspect(it: Omit<PersistItem, 'firstSeen' | 'isNew' | 'flags'>): Promise<PersistItem> {
  const flags: string[] = [];
  let signer: string | undefined, signerKind: string | undefined, team: string | undefined;
  const program = it.program;
  if (program && program.startsWith('/')) {
    const isShell = SHELLS.test(program);
    const target = isShell ? (it.args ?? []).slice(1).find((a) => a.startsWith('/') && !a.startsWith('-')) : program;
    const cmdline = (it.args ?? []).join(' ');
    if (isShell && /(curl|wget|base64\s+(-d|--decode)|\|\s*(sh|bash|zsh|python)|osascript\s+-e|eval\b)/.test(cmdline)) flags.push('script-download');
    if (target) {
      let exists = true;
      try { statSync(target); } catch { exists = false; }
      if (!exists) flags.push('missing-program');
      else {
        const s = await signInfo(bundleOf(target) ?? target);
        signer = describeSigner(s); signerKind = s.kind; team = s.team;
        if (s.kind === 'invalid') flags.push('invalid-signature');
        else if (s.kind === 'unsigned' || s.kind === 'adhoc') flags.push('unsigned');
        if (riskyLocation(target)) flags.push('risky-location');
        if (DEV_LOCATIONS.test(target)) flags.push('dev-location');
      }
    }
  } else if (it.kind === 'system-extension') {
    signer = `Team ${it.details?.team}`;
    signerKind = 'developer-id';
  }
  const key = it.plist ?? `${it.kind}:${it.label}`;
  const seen = markSeen('persist', key, { label: it.label, kind: it.kind });
  // Each kind has its own starting point: browser extensions only become visible once Hashling has
  // Full Disk Access, and the first time it sees them they are not "new", just newly visible.
  const kindStart = (db.prepare("SELECT MIN(first_seen) AS t FROM seen WHERE kind = 'persist' AND json_extract(data, '$.kind') = ?").get(it.kind) as { t: number | null }).t;
  const start = Math.max(baseline ?? Infinity, kindStart ?? Infinity);
  const isNew = baseline !== null && Number.isFinite(start) && seen.first_seen > start + 120_000 && Date.now() - seen.first_seen < NEW_WINDOW;
  return { ...it, signer, signerKind, team, flags, firstSeen: seen.first_seen, isNew };
}

function countBy(items: PersistItem[]): Record<string, number> {
  const c: Record<string, number> = {};
  for (const i of items) c[i.kind] = (c[i.kind] ?? 0) + 1;
  return c;
}
