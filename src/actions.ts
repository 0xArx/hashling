import { existsSync, mkdirSync, renameSync, writeFileSync, readFileSync, chmodSync, statSync, readdirSync, copyFileSync, unlinkSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { basename, join, isAbsolute, dirname } from 'node:path';
import { BIN, QUARANTINE_DIR, NAME, DATA_DIR } from './config.ts';
import { run } from './lib/exec.ts';
import { db, now, toJson, parseJson, logEvent, getFinding, getSnapshot } from './db.ts';
import { bus } from './bus.ts';
import { SERVICES, removeSteps } from './collectors/permissions.ts';
import { findUninstaller } from './lib/uninstaller.ts';
import { plural } from './lib/text.ts';

export const ACTION_TYPES = ['quarantine_file', 'restore_file', 'kill_process', 'disable_persistence', 'revoke_permission', 'block_domain', 'unblock_domain', 'trash_paths', 'run_cleanup', 'safe_dns', 'remove_all'] as const;

/** Fixed, well-known cleanup commands. Each only removes data its own tool can re-create. */
export const CLEANUPS: Record<string, { label: string; cmd: string; args: string[] }> = {
  'brew-cleanup': { label: 'Homebrew: remove old downloads and versions (brew cleanup)', cmd: '/opt/homebrew/bin/brew', args: ['cleanup', '--prune=all'] },
  'npm-cache': { label: 'npm: clear the download cache (npm cache clean)', cmd: '/opt/homebrew/bin/npm', args: ['cache', 'clean', '--force'] },
  'pnpm-prune': { label: 'pnpm: remove packages no project uses (pnpm store prune)', cmd: '/opt/homebrew/bin/pnpm', args: ['store', 'prune'] },
  'simctl-unavailable': { label: 'Xcode: delete simulators for iOS versions you no longer have', cmd: '/usr/bin/xcrun', args: ['simctl', 'delete', 'unavailable'] },
};

/** Never move these, whatever an agent proposes. */
const PROTECTED = [/^\/System(\/|$)/, /^\/usr(\/|$)/, /^\/bin(\/|$)/, /^\/sbin(\/|$)/, /^\/Library\/(Apple|Keychains)(\/|$)/, /\/Library\/Keychains(\/|$)/, /\/\.ssh(\/|$)/, /\/\.hashling(\/|$)/, /\/\.Trash(\/|$)/, /^\/Applications\/(Safari|Hashling)\.app$/];
export type ActionType = typeof ACTION_TYPES[number];
export type ActionStatus = 'pending' | 'rejected' | 'executed' | 'failed' | 'expired';

export interface Action {
  id: string;
  type: ActionType;
  target: Record<string, unknown>;
  reason: string;
  finding_id: string | null;
  requested_by: string;
  status: ActionStatus;
  created_at: number;
  decided_at: number | null;
  result: string | null;
  summary: string;
}

const HOSTS_TAG = '# added by Hashling';

/** The app name people see, not its bundle id (com.loom.desktop -> Loom Desktop). */
function appName(bundleId: string): string {
  const grants = getSnapshot<{ grants?: { client: string; name?: string }[] }>('permissions')?.data.grants ?? [];
  return grants.find((g) => g.client === bundleId)?.name ?? bundleId;
}

export function describe(type: ActionType, t: Record<string, unknown>): string {
  switch (type) {
    case 'quarantine_file': return `Quarantine ${t.path}`;
    case 'restore_file': return `Restore ${t.original ?? t.id} from quarantine`;
    case 'kill_process': return `Quit ${t.name ?? 'this program'}`;
    case 'disable_persistence': return `Disable startup item ${t.label ?? t.plist}`;
    case 'revoke_permission': return `Take away ${SERVICES[String(t.service)]?.label ?? t.service} from ${appName(String(t.bundleId))}`;
    case 'block_domain': return `Block ${t.domain} for every app`;
    case 'unblock_domain': return `Unblock ${t.domain}`;
    case 'trash_paths': {
      const n = (t.paths as string[]).length;
      const size = t.bytes ? fmtSize(Number(t.bytes)) : '';
      const what = t.label ? String(t.label) : `${n} item${n === 1 ? '' : 's'}`;
      const extra = [t.label && n > 1 ? `${n} items` : '', size].filter(Boolean).join(', ');
      return `Move ${what} to the Trash${extra ? ` (${extra})` : ''}`;
    }
    case 'run_cleanup': return CLEANUPS[String(t.tool)]?.label ?? `Run ${t.tool}`;
    case 'remove_all': return `Remove ${t.name} and everything it set up (${plural((t.steps as unknown[]).length, 'step')})`;
    case 'safe_dns': return t.on ? 'Turn on safe browsing (Quad9 blocks known scam and malware sites)' : 'Turn off safe browsing';
  }
}

/** Validate an action proposal. Returns a clean target or an error. */
export function validate(type: string, target: Record<string, unknown>): { ok: true; target: Record<string, unknown> } | { ok: false; error: string } {
  if (!(ACTION_TYPES as readonly string[]).includes(type)) return { ok: false, error: `Unknown action type. Use one of: ${ACTION_TYPES.join(', ')}` };
  const str = (k: string) => (typeof target[k] === 'string' ? (target[k] as string).trim() : '');
  switch (type as ActionType) {
    case 'quarantine_file': {
      const path = str('path');
      if (!isAbsolute(path) || !existsSync(path)) return { ok: false, error: 'target.path must be an absolute path that exists.' };
      if (/^\/(System|usr|bin|sbin)\//.test(path) || path.startsWith(QUARANTINE_DIR)) return { ok: false, error: 'That location cannot be quarantined.' };
      return { ok: true, target: { path } };
    }
    case 'restore_file': {
      const id = str('id');
      const manifest = join(QUARANTINE_DIR, id, 'manifest.json');
      if (!/^[a-f0-9-]{8,}$/.test(id) || !existsSync(manifest)) return { ok: false, error: 'target.id must be a quarantine id.' };
      const m = JSON.parse(readFileSync(manifest, 'utf8'));
      return { ok: true, target: { id, original: m.original } };
    }
    case 'kill_process': {
      const pid = Number(target.pid);
      if (!Number.isInteger(pid) || pid <= 1) return { ok: false, error: 'target.pid must be a process id.' };
      return { ok: true, target: { pid, name: str('name') || undefined } };
    }
    case 'disable_persistence': {
      const plist = str('plist');
      if (!plist.endsWith('.plist') || !existsSync(plist) || !/\/Library\/(LaunchAgents|LaunchDaemons|StartupItems)\//.test(plist) || plist.startsWith('/System/')) {
        return { ok: false, error: 'target.plist must be a LaunchAgent/LaunchDaemon plist outside /System.' };
      }
      return { ok: true, target: { plist, label: str('label') || basename(plist, '.plist'), scope: plist.startsWith('/Library/') ? 'system' : 'user' } };
    }
    case 'revoke_permission': {
      const service = str('service');
      const bundleId = str('bundleId');
      if (!SERVICES[service]) return { ok: false, error: 'target.service must be a TCC service such as kTCCServiceCamera.' };
      if (!/^[A-Za-z0-9.-]+$/.test(bundleId)) return { ok: false, error: 'target.bundleId must be an app bundle identifier.' };
      const grant = (getSnapshot<{ grants?: { client: string; service: string; name?: string; signerKind?: string }[] }>('permissions')?.data.grants ?? []).find((g) => g.client === bundleId && g.service === service);
      if (grant?.signerKind === 'missing') return { ok: false, error: `${grant.name ?? bundleId} is no longer installed, so macOS will not let me remove its entry. Tell the user to do it by hand: ${removeSteps(SERVICES[service].label, grant.name ?? bundleId)}` };
      return { ok: true, target: { service, bundleId } };
    }
    case 'block_domain':
    case 'unblock_domain': {
      const domain = str('domain').toLowerCase();
      if (!/^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/.test(domain)) return { ok: false, error: 'target.domain must be a domain name like example.com.' };
      if (/(^|\.)(apple\.com|icloud\.com|localhost)$/.test(domain) && type === 'block_domain') return { ok: false, error: 'Refusing to block Apple system domains.' };
      return { ok: true, target: { domain } };
    }
    case 'trash_paths': {
      const raw = Array.isArray(target.paths) ? (target.paths as unknown[]).map(String) : [];
      if (!raw.length || raw.length > 300) return { ok: false, error: 'target.paths must list 1 to 300 absolute paths.' };
      const home = process.env.HOME ?? '';
      let bytes = 0;
      let hasFolder = false;
      for (const p of raw) {
        if (!isAbsolute(p) || !existsSync(p)) return { ok: false, error: `Not found: ${p}` };
        if (p === home || PROTECTED.some((re) => re.test(p))) return { ok: false, error: `That location is protected: ${p}` };
        if (!p.startsWith(home + '/') && !p.startsWith('/Applications/')) return { ok: false, error: `Only items in your home folder or /Applications can be moved: ${p}` };
        const uninstaller = findUninstaller(p);
        if (uninstaller) return { ok: false, error: `${basename(p, '.app')} comes with its own uninstaller ("${basename(uninstaller)}" in ${dirname(uninstaller)}). Use that instead: it also removes the plug-ins and helper files that moving the app to the Trash would leave behind. The Storage page has an Uninstall button for it.` };
        if ([home + '/Documents', home + '/Desktop', home + '/Downloads', home + '/Library', home + '/Pictures', home + '/Movies', home + '/Music'].includes(p)) return { ok: false, error: `Refusing to trash a whole top-level folder: ${p}` };
        try { const st = statSync(p); if (st.isDirectory()) hasFolder = true; else bytes += st.size; } catch { /* unreadable */ }
      }
      // A folder's own stat size is not its contents; trust only the measured size the caller sends.
      return { ok: true, target: { paths: raw, bytes: Number(target.bytes) || (hasFolder ? undefined : bytes || undefined), label: str('label') || undefined } };
    }
    case 'safe_dns': return { ok: true, target: { on: target.on !== false } };
    case 'remove_all': {
      // A bundle of ordinary actions under one Touch ID; each part is checked exactly as if proposed alone.
      const raw = Array.isArray(target.steps) ? target.steps as { type: string; target: Record<string, unknown> }[] : [];
      if (!raw.length || raw.length > 30) return { ok: false, error: 'target.steps must list 1 to 30 actions.' };
      const steps: { type: string; target: Record<string, unknown> }[] = [];
      for (const s of raw) {
        if (!REMOVE_PARTS.includes(s?.type as ActionType)) return { ok: false, error: `remove_all can only contain ${REMOVE_PARTS.join(', ')}.` };
        const v = validate(s.type, s.target ?? {});
        if (!v.ok) return { ok: false, error: `${s.type}: ${v.error}` };
        steps.push({ type: s.type, target: v.target });
      }
      steps.sort((a, b) => REMOVE_PARTS.indexOf(a.type as ActionType) - REMOVE_PARTS.indexOf(b.type as ActionType));
      return { ok: true, target: { name: str('name') || 'this app', steps } };
    }
    case 'run_cleanup': {
      const tool = str('tool') || str('id'); // the dashboard and MCP send {id}
      if (!CLEANUPS[tool]) return { ok: false, error: `target.tool must be one of: ${Object.keys(CLEANUPS).join(', ')}` };
      if (!existsSync(CLEANUPS[tool].cmd)) return { ok: false, error: `${CLEANUPS[tool].cmd} is not installed.` };
      return { ok: true, target: { tool } };
    }
  }
}

/** Sizes in the units Finder uses (1 GB = 1,000,000,000 bytes), so they match what people see. */
function fmtSize(b: number): string { return b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : `${Math.max(1, Math.round(b / 1e6))} MB`; }

export function proposeAction(type: string, target: Record<string, unknown>, reason: string, requestedBy: string, findingId?: string): Action | { error: string } {
  const v = validate(type, target ?? {});
  if (!v.ok) return { error: v.error };
  if (!reason?.trim()) return { error: 'Give a short reason the user will see.' };
  if (findingId && !getFinding(findingId)) findingId = undefined;
  const dup = db.prepare(`SELECT id FROM actions WHERE status = 'pending' AND type = ? AND target = ?`).get(type, toJson(v.target)) as { id: string } | undefined;
  if (dup) return getAction(dup.id)!;
  const pending = (db.prepare(`SELECT COUNT(*) AS n FROM actions WHERE status = 'pending'`).get() as { n: number }).n;
  if (pending >= 25) return { error: 'Too many actions are waiting for the user. Ask them to review the dashboard first.' };
  const id = randomUUID().slice(0, 8);
  db.prepare(`INSERT INTO actions (id, type, target, reason, finding_id, requested_by, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`)
    .run(id, type, toJson(v.target), reason.trim().slice(0, 600), findingId ?? null, requestedBy.slice(0, 80), now());
  logEvent('action', 'low', `${requestedBy} proposed: ${describe(type as ActionType, v.target)}`, { id });
  bus.emit('change', { type: 'action', id });
  return getAction(id)!;
}

function toAction(r: Record<string, unknown>): Action {
  const target = parseJson<Record<string, unknown>>(r.target, {});
  return { ...(r as unknown as Action), target, summary: describe(r.type as ActionType, target) };
}

export function getAction(id: string): Action | null {
  const r = db.prepare('SELECT * FROM actions WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  return r ? toAction(r) : null;
}

export function listActions(status?: string, limit = 50): Action[] {
  expireOld();
  const rows = status
    ? db.prepare('SELECT * FROM actions WHERE status = ? ORDER BY created_at DESC LIMIT ?').all(status, limit)
    : db.prepare('SELECT * FROM actions ORDER BY created_at DESC LIMIT ?').all(limit);
  return (rows as Record<string, unknown>[]).map(toAction);
}

function expireOld(): void {
  db.prepare(`UPDATE actions SET status = 'expired', decided_at = ? WHERE status = 'pending' AND created_at < ?`).run(now(), now() - 24 * 3600_000);
}

function finish(id: string, status: ActionStatus, result: string): Action {
  db.prepare('UPDATE actions SET status = ?, decided_at = ?, result = ? WHERE id = ?').run(status, now(), result, id);
  bus.emit('change', { type: 'action', id });
  return getAction(id)!;
}

export function rejectAction(id: string): Action | { error: string } {
  const a = getAction(id);
  if (!a) return { error: 'No such action.' };
  if (a.status !== 'pending') return { error: `Action is already ${a.status}.` };
  logEvent('action', 'info', `You rejected: ${a.summary}`, { id });
  return finish(id, 'rejected', 'Rejected by you.');
}

/** Ask the person at the keyboard (Touch ID or login password) to confirm. */
async function userPresence(reason: string): Promise<{ ok: boolean; message: string }> {
  if (!existsSync(BIN.auth)) return { ok: false, message: 'I’m missing the part that asks for Touch ID. Reinstalling Hashling fixes this.' };
  const r = await run(BIN.auth, [reason], { timeout: 120_000 });
  const raw = (r.stdout || r.stderr).trim();
  if (r.ok) return { ok: true, message: raw || 'Confirmed' };
  // The macOS dialog was closed or timed out: say plainly that nothing happened.
  return { ok: false, message: /cancel|denied|not interactive|timed? ?out/i.test(raw) || r.timedOut ? 'you cancelled, so nothing was changed' : raw || 'it was not confirmed, so nothing was changed' };
}

export async function approveAction(id: string): Promise<Action | { error: string }> {
  const a = getAction(id);
  if (!a) return { error: 'No such action.' };
  if (a.status !== 'pending') return { error: `Action is already ${a.status}.` };
  // macOS shows this as "Hashling is trying to make this change on your Mac: …".
  const presence = await userPresence(`make this change on your Mac: ${a.summary}`);
  if (!presence.ok) return { error: `Not approved: ${presence.message}` };
  try {
    const result = await execute(a);
    logEvent('action', 'info', `Done: ${a.summary}`, { id, result });
    return finish(id, 'executed', result);
  } catch (e) {
    const msg = String((e as Error).message);
    logEvent('action', 'medium', `Failed: ${a.summary}`, { id, error: msg });
    return finish(id, 'failed', msg);
  }
}

/** Several pending actions under one Touch ID, run one after another. */
export async function approveMany(ids: string[]): Promise<{ done: number; failed: { summary: string; error: string }[] } | { error: string }> {
  const list = ids.map(getAction).filter((a): a is Action => Boolean(a) && a!.status === 'pending');
  if (!list.length) return { error: 'Nothing to approve.' };
  const presence = await userPresence(`make ${list.length === 1 ? 'this change' : `these ${list.length} changes`} on your Mac: ${list.map((a) => a.summary).join('; ').slice(0, 300)}`);
  if (!presence.ok) return { error: `Not approved: ${presence.message}` };
  let done = 0;
  const failed: { summary: string; error: string }[] = [];
  for (const a of list) {
    try { const result = await execute(a); logEvent('action', 'info', `Done: ${a.summary}`, { id: a.id, result }); finish(a.id, 'executed', result); done++; }
    catch (e) { const msg = String((e as Error).message); logEvent('action', 'medium', `Failed: ${a.summary}`, { id: a.id, error: msg }); finish(a.id, 'failed', msg); failed.push({ summary: a.summary, error: msg }); }
  }
  return { done, failed };
}

// ---------- executors ----------

const sq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** Run a shell snippet as root via the standard macOS administrator prompt. */
async function asAdmin(script: string, prompt: string): Promise<string> {
  const as = `do shell script "${script.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" with prompt "${(NAME + ': ' + prompt).replace(/"/g, '\\"')}" with administrator privileges`;
  const r = await run('/usr/bin/osascript', ['-e', as], { timeout: 180_000 });
  if (!r.ok) throw new Error(/User canceled|-128/.test(r.stderr) ? 'Administrator prompt was cancelled.' : r.stderr.trim());
  return r.stdout.trim();
}

function sha256(path: string): string | null {
  try { return createHash('sha256').update(readFileSync(path)).digest('hex'); } catch { return null; }
}

async function quarantine(path: string, extra: Record<string, unknown> = {}): Promise<string> {
  const id = randomUUID();
  const dir = join(QUARANTINE_DIR, id);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const dest = join(dir, basename(path) + '.quarantined');
  const isDir = statSync(path).isDirectory();
  const hash = isDir ? null : sha256(path);
  let mode = 0;
  try { mode = statSync(path).mode & 0o7777; } catch { /* ignore */ }
  try {
    renameSync(path, dest);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'EXDEV') { if (isDir) throw new Error('Cannot quarantine a folder across disks.'); copyFileSync(path, dest); unlinkSync(path); }
    else if (code === 'EACCES' || code === 'EPERM') await asAdmin(`mv ${sq(path)} ${sq(dest)} && chown -R $(stat -f %u ${sq(dir)}) ${sq(dest)}`, `quarantine ${basename(path)}`);
    else throw e;
  }
  if (!isDir) { try { chmodSync(dest, 0o400); } catch { /* ignore */ } }
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ original: path, sha256: hash, mode, at: now(), isDir, ...extra }, null, 2));
  return id;
}

async function execute(a: Action): Promise<string> {
  const t = a.target;
  switch (a.type) {
    case 'remove_all': {
      const done: string[] = [];
      const failed: string[] = [];
      for (const s of t.steps as { type: ActionType; target: Record<string, unknown> }[]) {
        const what = describe(s.type, s.target);
        try { await execute({ ...a, type: s.type, target: s.target }); done.push(what); } catch (e) { failed.push(`${what} (${(e as Error).message})`); }
      }
      if (!done.length) throw new Error(`Nothing could be removed. ${failed.join('; ')}`);
      return `Done: ${done.join('; ')}.${failed.length ? ` Could not: ${failed.join('; ')}.` : ''} Anything quarantined can be restored from Approvals.`;
    }
    case 'quarantine_file': {
      const id = await quarantine(String(t.path));
      return `Moved to quarantine (${id.slice(0, 8)}). It can no longer run, and you can restore it from the dashboard.`;
    }
    case 'restore_file': {
      const dir = join(QUARANTINE_DIR, String(t.id));
      const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
      const file = readdirSync(dir).find((f) => f.endsWith('.quarantined'));
      if (!file) throw new Error('Quarantined file is missing.');
      if (existsSync(m.original)) throw new Error(`Something already exists at ${m.original}.`);
      mkdirSync(dirname(m.original), { recursive: true });
      try { renameSync(join(dir, file), m.original); }
      catch { await asAdmin(`mv ${sq(join(dir, file))} ${sq(m.original)}`, `restore ${basename(m.original)}`); }
      try { if (m.mode) chmodSync(m.original, m.mode); } catch { /* ignore */ }
      if (m.label && m.original.endsWith('.plist')) {
        const domain = m.scope === 'system' ? 'system' : `gui/${process.getuid?.()}`;
        if (m.scope === 'system') await asAdmin(`launchctl bootstrap system ${sq(m.original)}`, `re-enable ${m.label}`).catch(() => undefined);
        else await run('/bin/launchctl', ['bootstrap', domain, m.original]);
      }
      writeFileSync(join(dir, 'restored'), String(now()));
      return `Restored to ${m.original}.`;
    }
    case 'kill_process': {
      const pid = Number(t.pid);
      const ps = await run('/bin/ps', ['-p', String(pid), '-o', 'comm=']);
      if (!ps.stdout.trim()) return 'The process had already exited.';
      if (t.name && !ps.stdout.includes(String(t.name))) throw new Error(`pid ${pid} is now a different program (${ps.stdout.trim()}); not killing it.`);
      try {
        process.kill(pid, 'SIGTERM');
        await new Promise((r) => setTimeout(r, 2000));
        try { process.kill(pid, 0); process.kill(pid, 'SIGKILL'); } catch { /* exited */ }
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'EPERM') await asAdmin(`kill -9 ${pid}`, `quit ${t.name ?? pid}`);
        else throw e;
      }
      return `Quit ${t.name ?? 'process'} (pid ${pid}).`;
    }
    case 'disable_persistence': {
      const plist = String(t.plist);
      if (t.scope === 'system') {
        const id = randomUUID();
        const dir = join(QUARANTINE_DIR, id);
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const dest = join(dir, basename(plist) + '.quarantined');
        await asAdmin(`launchctl bootout system ${sq(plist)} 2>/dev/null; mv ${sq(plist)} ${sq(dest)} && chown $(stat -f %u ${sq(dir)}) ${sq(dest)}`, `disable ${t.label}`);
        writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ original: plist, at: now(), label: t.label, scope: 'system' }, null, 2));
        return `Unloaded and quarantined ${t.label}. It will not start again.`;
      }
      await run('/bin/launchctl', ['bootout', `gui/${process.getuid?.()}`, plist]);
      const id = await quarantine(plist, { label: t.label, scope: 'user' });
      return `Unloaded and quarantined ${t.label} (${id.slice(0, 8)}). It will not start again.`;
    }
    case 'revoke_permission': {
      const svc = String(t.service).replace(/^kTCCService/, '');
      const r = await run('/usr/bin/tccutil', ['reset', svc, String(t.bundleId)]);
      const label = SERVICES[String(t.service)]?.label ?? svc;
      const name = appName(String(t.bundleId));
      if (!r.ok) {
        if (/-10814|No such bundle identifier/.test(r.stderr)) throw new Error(`macOS could not find ${name}, which usually means it is uninstalled, so it would not remove the entry. Nothing was changed. ${removeSteps(label, name)}`);
        throw new Error(`macOS would not take away the permission. Nothing was changed. (${r.stderr.trim() || 'no details'})`);
      }
      return `Done. ${name} will have to ask again before it can use ${label}.`;
    }
    case 'safe_dns': {
      const services = await dnsServices();
      if (!services.length) throw new Error('No active network found. Nothing was changed.');
      const saved = join(DATA_DIR, 'dns-before.json');
      if (t.on) {
        // Keep what each network used before, so turning it off puts it back exactly.
        const before: Record<string, string[]> = {};
        for (const s of services) before[s] = await currentDns(s);
        if (!existsSync(saved)) writeFileSync(saved, JSON.stringify(before), { mode: 0o600 });
        await asAdmin(services.map((s) => `/usr/sbin/networksetup -setdnsservers ${sq(s)} ${QUAD9.join(' ')}`).join(' && '), 'turn on safe browsing (filtering DNS)');
        return 'Safe browsing is on. Known scam, phishing and malware websites will not open, in any browser or app.';
      }
      const before = existsSync(saved) ? JSON.parse(readFileSync(saved, 'utf8')) as Record<string, string[]> : {};
      await asAdmin(services.map((s) => `/usr/sbin/networksetup -setdnsservers ${sq(s)} ${(before[s]?.length ? before[s] : ['Empty']).map(sq).join(' ')}`).join(' && '), 'turn off safe browsing');
      try { unlinkSync(saved); } catch { /* none */ }
      return 'Safe browsing is off. Your Mac uses your network’s normal settings again.';
    }
    case 'block_domain': {
      const d = String(t.domain);
      const hosts = readFileSync('/etc/hosts', 'utf8');
      if (hosts.includes(`0.0.0.0 ${d} `)) return `${d} is already blocked.`;
      await asAdmin(`printf '%s\\n' ${sq(`0.0.0.0 ${d} ${HOSTS_TAG}`)} ${sq(`:: ${d} ${HOSTS_TAG}`)} >> /etc/hosts && dscacheutil -flushcache && killall -HUP mDNSResponder`, `block ${d}`);
      return `${d} now resolves to nowhere for every app on this Mac.`;
    }
    case 'unblock_domain': {
      const d = String(t.domain);
      await asAdmin(`sed -i '' ${sq(`/ ${d.replace(/\./g, '\\.')} ${HOSTS_TAG}$/d`)} /etc/hosts && dscacheutil -flushcache && killall -HUP mDNSResponder`, `unblock ${d}`);
      return `${d} is reachable again.`;
    }
    case 'trash_paths': {
      const paths = t.paths as string[];
      const r = await run(BIN.trash, paths, { timeout: 300_000 });
      const results = r.stdout.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l) as { path: string; ok: boolean; error?: string }; } catch { return null; } }).filter(Boolean) as { path: string; ok: boolean; error?: string }[];
      let moved = results.filter((x) => x.ok).length;
      let failed = results.filter((x) => !x.ok);
      // Items an installer put there as the administrator (root) need your password, the same as in Finder.
      const denied = failed.filter((x) => /permission|not permitted/i.test(x.error ?? ''));
      let adminNote = '';
      if (denied.length) {
        const trash = join(process.env.HOME ?? '', '.Trash');
        const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
        const cmd = denied.map((x) => `/bin/mv -n ${sq(x.path)} ${sq(join(trash, `${basename(x.path)} ${stamp}`))}`).join(' && ');
        try {
          await asAdmin(cmd, `move ${denied.length === 1 ? basename(denied[0].path) : `${denied.length} items`} to the Trash. It was installed with administrator rights, so macOS needs your password, just like Finder would.`);
          moved += denied.length;
          failed = failed.filter((x) => !denied.includes(x));
          adminNote = ' Some items needed your password because they were installed with administrator rights. Emptying the Trash may ask for it again, and those items cannot use Put Back.';
        } catch (e) {
          const msg = (e as Error).message;
          if (!moved) throw new Error(/cancel/i.test(msg) ? 'You cancelled the password prompt. Nothing was moved.'
            : /not permitted/i.test(msg) ? 'macOS blocked it: apps are protected from being changed by other apps. Drag it to the Trash in Finder instead, or allow Hashling in System Settings, Privacy & Security, App Management.'
            : `macOS would not move it. Nothing was changed. (${msg})`);
        }
      }
      if (!moved) throw new Error(failed[0]?.error ?? 'Nothing could be moved to the Trash.');
      return `${paths.length === 1 ? 'Moved it to the Trash. You can put it back' : moved === paths.length ? `Moved all ${moved} items to the Trash. You can put them back` : `Moved ${moved} of ${paths.length} items to the Trash. You can put them back`} from the Trash, or empty it to free the space.${adminNote}${failed.length ? ` ${failed.length} could not be moved (${failed[0].error}).` : ''}`;
    }
    case 'run_cleanup': {
      const c = CLEANUPS[String(t.tool)];
      const r = await run(c.cmd, c.args, { timeout: 600_000 });
      if (!r.ok) throw new Error((r.stderr || r.stdout).trim().split('\n').slice(-2).join(' ') || 'The cleanup failed.');
      const tail = (r.stdout || r.stderr).trim().split('\n').filter(Boolean).slice(-1)[0] ?? '';
      return `Done. ${tail}`.trim();
    }
  }
}

// ---------- Safe browsing (Quad9: free, non-profit, blocks known malicious domains, no personal logs) ----------
/** What a "remove all of it" bundle may contain, in the order it runs: stop it, unhook it, then lock it away. */
const REMOVE_PARTS: ActionType[] = ['kill_process', 'disable_persistence', 'revoke_permission', 'quarantine_file', 'trash_paths'];

export const QUAD9 = ['9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'];
async function dnsServices(): Promise<string[]> {
  const r = await run('/usr/sbin/networksetup', ['-listallnetworkservices']);
  return r.stdout.split('\n').slice(1).map((l) => l.trim()).filter((l) => l && !l.startsWith('*') && !/bridge|usb|bluetooth/i.test(l));
}
async function currentDns(service: string): Promise<string[]> {
  const r = await run('/usr/sbin/networksetup', ['-getdnsservers', service]);
  return /There aren't any/.test(r.stdout) ? [] : r.stdout.split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f:.]+$/i.test(l));
}
export async function safeDnsStatus(): Promise<{ on: boolean; services: { name: string; servers: string[] }[] }> {
  const services = await Promise.all((await dnsServices()).map(async (name) => ({ name, servers: await currentDns(name) })));
  return { on: services.length > 0 && services.every((s) => s.servers.includes(QUAD9[0])), services };
}

/**
 * Opt-in automatic quarantine: a file that matches known malware is locked away at once, without
 * waiting for Touch ID, because the user switched this on. It can be restored like any quarantine.
 */
export async function autoQuarantine(path: string, signature: string): Promise<string | null> {
  const v = validate('quarantine_file', { path });
  if (!v.ok) return null;
  const id = await quarantine(path, { auto: true, signature });
  logEvent('action', 'high', `I locked away ${basename(path)} automatically (matched ${signature})`, { id, path, signature });
  return id;
}

export function listQuarantine(): { id: string; original: string; at: number; sha256: string | null; restored: boolean }[] {
  let ids: string[] = [];
  try { ids = readdirSync(QUARANTINE_DIR); } catch { return []; }
  return ids.flatMap((id) => {
    try {
      const m = JSON.parse(readFileSync(join(QUARANTINE_DIR, id, 'manifest.json'), 'utf8'));
      return [{ id, original: m.original, at: m.at, sha256: m.sha256 ?? null, restored: existsSync(join(QUARANTINE_DIR, id, 'restored')) }];
    } catch { return []; }
  }).sort((a, b) => b.at - a.at);
}

export function blockedDomains(): string[] {
  try {
    return readFileSync('/etc/hosts', 'utf8').split('\n').filter((l) => l.endsWith(HOSTS_TAG) && l.startsWith('0.0.0.0')).map((l) => l.split(/\s+/)[1]);
  } catch { return []; }
}
