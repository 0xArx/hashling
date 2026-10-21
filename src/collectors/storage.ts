/**
 * Optimize: where the disk went and what can safely go, using techniques from
 * open-source Mac cleaners:
 * - safe cache & developer-junk locations (the categories Mole cleans)
 * - app leftovers: support folders whose app (bundle ID) is no longer installed
 *   (Pearcleaner's approach)
 * - duplicates: same size -> same first 1 MB -> same full SHA-256 (czkawka's staged hashing)
 * - unused apps from Spotlight's last-opened date, and what slows startup.
 * Nothing is deleted here. Cleanups are proposed as actions that move items to
 * the Trash after Touch ID, so they can be put back.
 */
import { bus } from '../bus.ts';
import { existsSync, readdirSync, statSync, lstatSync, createReadStream, openSync, readSync, closeSync } from 'node:fs';
import { join, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { HOME } from '../config.ts';
import { run, readPlist } from '../lib/exec.ts';
import { getSnapshot, putSnapshot, syncFindings, type FindingInput } from '../db.ts';
import { findUninstaller } from '../lib/uninstaller.ts';

const H = (p: string) => join(HOME, p);
const GB = 1024 ** 3;

async function duBytes(path: string, timeout = 120_000): Promise<number | null> {
  if (!existsSync(path)) return null;
  const r = await run('/usr/bin/du', ['-sk', path], { timeout });
  const kb = Number(r.stdout.split('\t')[0]);
  return Number.isFinite(kb) && kb > 0 ? kb * 1024 : r.ok ? 0 : null;
}

/** Safe-to-clear locations. Each regenerates on its own when needed. */
const JUNK: { id: string; label: string; path: string; why: string; how: 'trash' | string }[] = [
  { id: 'npm', label: 'npm download cache', path: H('.npm/_cacache'), why: 'Copies of every package npm ever downloaded. npm re-downloads what it needs.', how: 'npm-cache' },
  { id: 'pnpm', label: 'pnpm store', path: H('Library/pnpm/store'), why: 'Shared package store for pnpm. `pnpm store prune` removes packages no project uses.', how: 'pnpm-prune' },
  { id: 'yarn', label: 'Yarn cache', path: H('Library/Caches/Yarn'), why: 'Downloaded Yarn packages, re-fetched when needed.', how: 'trash' },
  { id: 'pip', label: 'pip cache', path: H('Library/Caches/pip'), why: 'Downloaded Python packages, re-fetched when needed.', how: 'trash' },
  { id: 'homebrew', label: 'Homebrew downloads', path: H('Library/Caches/Homebrew'), why: 'Old installers and bottles. `brew cleanup` removes them safely.', how: 'brew-cleanup' },
  { id: 'deriveddata', label: 'Xcode build data (DerivedData)', path: H('Library/Developer/Xcode/DerivedData'), why: 'Build products Xcode regenerates on the next build.', how: 'trash' },
  { id: 'xcode-archives', label: 'Xcode archives', path: H('Library/Developer/Xcode/Archives'), why: 'Old app builds you exported. Keep any you still need to read old crash reports.', how: 'trash' },
  { id: 'device-support', label: 'iOS device support files', path: H('Library/Developer/Xcode/iOS DeviceSupport'), why: 'Debug symbols for iOS versions of devices you once connected. Re-created when you connect a device.', how: 'trash' },
  { id: 'simulators', label: 'Unavailable simulators', path: H('Library/Developer/CoreSimulator/Devices'), why: 'Simulators for iOS versions no longer installed. `simctl delete unavailable` removes only those.', how: 'simctl-unavailable' },
  { id: 'logs', label: 'App logs', path: H('Library/Logs'), why: 'Old diagnostic logs from apps.', how: 'trash' },
  { id: 'gradle', label: 'Gradle cache', path: H('.gradle/caches'), why: 'Android / Java build cache, re-downloaded when needed.', how: 'trash' },
  { id: 'cocoapods', label: 'CocoaPods cache', path: H('Library/Caches/CocoaPods'), why: 'Downloaded pods, re-fetched when needed.', how: 'trash' },
  { id: 'go-build', label: 'Go build cache', path: H('Library/Caches/go-build'), why: 'Compiled Go packages; `go clean -cache` equivalent.', how: 'trash' },
];

const LIBRARY_LEFTOVER_DIRS = ['Application Support', 'Caches', 'Containers', 'Group Containers', 'Saved Application State', 'Logs', 'HTTPStorages', 'WebKit'];
const BUNDLE_LIKE = /^(com|org|net|io|app|dev|co|me|us|de|uk|ai|tv|jp|fr)\.[A-Za-z0-9-]+\.[A-Za-z0-9.-]+$/;

async function installedBundleIds(): Promise<{ ids: Set<string>; apps: { name: string; path: string; id?: string }[] }> {
  const ids = new Set<string>();
  const apps: { name: string; path: string; id?: string }[] = [];
  const dirs = ['/Applications', H('Applications'), '/System/Applications', '/System/Applications/Utilities', '/Applications/Utilities'];
  for (const dir of dirs) {
    let entries: string[] = [];
    try { entries = readdirSync(dir); } catch { continue; }
    for (const f of entries) {
      const paths = f.endsWith('.app') ? [join(dir, f)] : (() => { try { return readdirSync(join(dir, f)).filter((g) => g.endsWith('.app')).map((g) => join(dir, f, g)); } catch { return []; } })();
      for (const p of paths) {
        const info = await readPlist<Record<string, unknown>>(join(p, 'Contents/Info.plist'));
        const id = info?.CFBundleIdentifier as string | undefined;
        if (id) ids.add(id.toLowerCase());
        if (!dir.startsWith('/System')) apps.push({ name: basename(p, '.app'), path: p, id });
      }
    }
  }
  return { ids, apps };
}

/** Only simulators for runtimes that are no longer installed: what `simctl delete unavailable` removes. */
async function unavailableSimulatorBytes(): Promise<number> {
  const r = await run('/usr/bin/xcrun', ['simctl', 'list', 'devices', 'unavailable', '-j'], { timeout: 30_000 });
  if (!r.ok) return 0;
  let total = 0;
  try {
    const d = JSON.parse(r.stdout) as { devices: Record<string, { udid: string }[]> };
    for (const dev of Object.values(d.devices).flat()) total += (await duBytes(H(`Library/Developer/CoreSimulator/Devices/${dev.udid}`), 60_000)) ?? 0;
  } catch { /* unexpected output */ }
  return total;
}

/** Spotlight's record of when an app was last opened, plus its size on disk. */
async function appUsage(apps: { name: string; path: string; id?: string }[]) {
  const out: { name: string; path: string; id?: string; size: number; lastUsed: number | null; added: number | null }[] = [];
  for (let i = 0; i < apps.length; i += 25) {
    const batch = apps.slice(i, i + 25);
    const r = await run('/usr/bin/mdls', ['-name', 'kMDItemLastUsedDate', '-name', 'kMDItemPhysicalSize', '-name', 'kMDItemDateAdded', ...batch.map((a) => a.path)], { timeout: 30_000 });
    const blocks = r.stdout.split(/\n(?=kMDItemDateAdded)/);
    batch.forEach((a, j) => {
      const b = blocks[j] ?? '';
      const date = (k: string) => { const m = b.match(new RegExp(`${k}\\s*=\\s*(\\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d [+-]\\d{4})`)); return m ? Date.parse(m[1].replace(' ', 'T').replace(' ', '')) : null; };
      const size = Number(b.match(/kMDItemPhysicalSize\s*=\s*(\d+)/)?.[1] ?? 0);
      out.push({ ...a, size, lastUsed: date('kMDItemLastUsedDate'), added: date('kMDItemDateAdded') });
    });
  }
  return out;
}

/** App libraries and bundles: their files belong to the app, and removing one breaks the library. */
const PACKAGE = /\.(app|photoslibrary|imovielibrary|fcpbundle|logicx|band|musiclibrary|tvlibrary|aplibrary|lrdata|xcarchive|bundle|framework|pkg)$/i;

/** czkawka-style staged duplicate search in the user's own folders. */
async function findDuplicates(): Promise<{ size: number; files: string[] }[]> {
  const roots = ['Downloads', 'Desktop', 'Documents', 'Movies', 'Music'].map(H).filter(existsSync);
  const bySize = new Map<number, string[]>();
  let count = 0;
  // Each physical file counts once: two paths to the same inode (a symlinked folder, a hard link)
  // are one file, and "trashing the extra copy" would delete the only one.
  const inodes = new Set<string>();
  const walk = (dir: string, depth: number) => {
    if (depth > 6 || count > 40_000) return;
    let entries: string[] = [];
    try { entries = readdirSync(dir); } catch { return; }
    // Code projects keep copies on purpose (fixtures, model weights, build output).
    if (depth > 0 && entries.includes('.git')) return;
    for (const name of entries) {
      if (name.startsWith('.') || name === 'node_modules' || PACKAGE.test(name) || name === 'Library') continue;
      const p = join(dir, name);
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(p, depth + 1);
      else if (st.isFile() && st.size >= 5 * 1024 * 1024) {
        const ino = `${st.dev}:${st.ino}`;
        if (inodes.has(ino)) continue;
        inodes.add(ino);
        count++; const list = bySize.get(st.size) ?? []; list.push(p); bySize.set(st.size, list);
      }
    }
  };
  for (const r of roots) walk(r, 0);
  const head = (p: string) => { const fd = openSync(p, 'r'); const buf = Buffer.alloc(1024 * 1024); const n = readSync(fd, buf, 0, buf.length, 0); closeSync(fd); return createHash('sha256').update(buf.subarray(0, n)).digest('hex'); };
  const full = (p: string) => new Promise<string>((res, rej) => { const h = createHash('sha256'); createReadStream(p).on('data', (c) => h.update(c)).on('end', () => res(h.digest('hex'))).on('error', rej); });
  const groups: { size: number; files: string[] }[] = [];
  let hashedBytes = 0;
  for (const [size, files] of [...bySize].filter(([, f]) => f.length > 1).sort((a, b) => b[0] - a[0])) {
    if (hashedBytes > 20 * GB) break;
    const byHead = new Map<string, string[]>();
    for (const f of files) { try { const k = head(f); byHead.set(k, [...(byHead.get(k) ?? []), f]); } catch { /* unreadable */ } }
    for (const cands of byHead.values()) {
      if (cands.length < 2) continue;
      const byFull = new Map<string, string[]>();
      for (const f of cands) { try { const k = await full(f); hashedBytes += size; byFull.set(k, [...(byFull.get(k) ?? []), f]); } catch { /* unreadable */ } }
      for (const same of byFull.values()) if (same.length > 1) groups.push({ size, files: same });
    }
  }
  return groups.sort((a, b) => b.size * (b.files.length - 1) - a.size * (a.files.length - 1)).slice(0, 60);
}

/** Which step a running measurement is on, so the dashboard can show progress instead of silence. */
let progress: { step: number; total: number; label: string; startedAt: number } | null = null;
export const storageProgress = () => progress;
const STEPS = ['Measuring your folders', 'Checking caches', 'Finding apps you do not use', 'Finding leftovers from deleted apps', 'Finding very large files', 'Looking for duplicate files', 'Checking what starts with your Mac'];
function stepTo(i: number, startedAt: number): void {
  progress = { step: i + 1, total: STEPS.length, label: STEPS[i], startedAt };
  bus.emit('change', { type: 'snapshot', name: 'storage' });
}

export async function collectStorage(): Promise<void> {
  const started = Date.now();
  try { await measure(started); } finally { progress = null; }
}

async function measure(started: number): Promise<void> {
  stepTo(0, started);
  const df = await run('/bin/df', ['-k', '/'], { timeout: 5000 });
  const parts = df.stdout.trim().split('\n').pop()!.split(/\s+/);
  const disk = { total: Number(parts[1]) * 1024, used: Number(parts[2]) * 1024, free: Number(parts[3]) * 1024 };

  const folders: { label: string; path: string; size: number | null }[] = [];
  for (const [label, p] of [['Applications', '/Applications'], ['Documents', H('Documents')], ['Downloads', H('Downloads')], ['Desktop', H('Desktop')], ['Movies', H('Movies')], ['Music', H('Music')], ['Pictures', H('Pictures')], ['Developer', H('Developer')], ['App data (Library folder)', H('Library')]] as const) {
    folders.push({ label, path: p, size: await duBytes(p, 240_000) });
  }

  stepTo(1, started);
  const junk: { id: string; label: string; path: string; why: string; how: string; size: number }[] = [];
  for (const j of JUNK) {
    const size = j.id === 'simulators' ? await unavailableSimulatorBytes() : await duBytes(j.path);
    if (size && size > 50 * 1024 * 1024) junk.push({ ...j, size });
  }
  // Per-app caches (biggest first): safe to clear, apps rebuild them.
  const caches: { app: string; path: string; size: number }[] = [];
  try {
    for (const name of readdirSync(H('Library/Caches'))) {
      if (['Homebrew', 'pip', 'Yarn', 'CocoaPods', 'go-build', 'com.apple.bird', 'CloudKit'].includes(name)) continue;
      const size = await duBytes(join(H('Library/Caches'), name), 30_000);
      if (size && size > 100 * 1024 * 1024) caches.push({ app: name, path: join(H('Library/Caches'), name), size });
    }
  } catch { /* protected */ }
  caches.sort((a, b) => b.size - a.size);

  stepTo(2, started);
  const { ids, apps } = await installedBundleIds();
  const usage = await appUsage(apps);
  const DAY = 86_400_000;
  const unused = usage
    .map((a) => ({ ...a, idleDays: a.lastUsed ? Math.floor((Date.now() - a.lastUsed) / DAY) : a.added ? Math.floor((Date.now() - a.added) / DAY) : null, neverOpened: !a.lastUsed }))
    .filter((a) => a.size > 50 * 1024 * 1024 && a.idleDays !== null && a.idleDays >= 90)
    .sort((a, b) => b.size - a.size)
    // Two installs of the same app (e.g. a stray /Applications/Applications copy): flag the extra one.
    .map((a, i, all) => ({ ...a, extraCopy: Boolean(a.id) && all.findIndex((b) => b.id === a.id) < i, uninstaller: findUninstaller(a.path) }));

  // Leftovers of apps that are gone.
  stepTo(3, started);
  const leftovers: { id: string; path: string; where: string; size: number }[] = [];
  for (const dir of LIBRARY_LEFTOVER_DIRS) {
    let entries: string[] = [];
    try { entries = readdirSync(H(`Library/${dir}`)); } catch { continue; }
    for (const name of entries) {
      const id = name.replace(/\.savedState$/, '').toLowerCase();
      if (!BUNDLE_LIKE.test(id) || id.startsWith('com.apple.') || ids.has(id) || [...ids].some((x) => id.startsWith(`${x}.`) || x.startsWith(`${id}.`))) continue;
      const p = H(`Library/${dir}/${name}`);
      const size = await duBytes(p, 30_000);
      if (size && size > 20 * 1024 * 1024) leftovers.push({ id: name, path: p, where: dir, size });
    }
  }
  leftovers.sort((a, b) => b.size - a.size);

  stepTo(4, started);
  const big = await run('/usr/bin/mdfind', ['-onlyin', HOME, 'kMDItemFSSize > 1000000000'], { timeout: 30_000 });
  const largeFiles = big.stdout.split('\n').filter(Boolean).filter((p) => !p.includes('/Library/Containers/com.docker') && !p.includes('.app/')).slice(0, 40)
    .map((p) => { try { const st = statSync(p); return { path: p, size: st.size, modified: st.mtimeMs, isDir: st.isDirectory() }; } catch { return null; } })
    .filter(Boolean) as { path: string; size: number; modified: number; isDir: boolean }[];
  largeFiles.sort((a, b) => b.size - a.size);

  stepTo(5, started);
  const duplicates = await findDuplicates();

  // What runs at login, and what it costs right now.
  stepTo(6, started);
  const persist = getSnapshot<{ items: { kind: string; label: string; program?: string; plist?: string; signer?: string }[] }>('persistence')?.data?.items ?? [];
  const ps = await run('/bin/ps', ['-axo', 'pid=,%cpu=,rss=,comm='], { timeout: 8000 });
  const usageByPath = new Map<string, { cpu: number; mem: number }>();
  for (const line of ps.stdout.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+([\d.]+)\s+(\d+)\s+(.+)$/);
    if (!m) continue;
    const u = usageByPath.get(m[4]) ?? { cpu: 0, mem: 0 };
    u.cpu += Number(m[2]); u.mem += Number(m[3]) * 1024;
    usageByPath.set(m[4], u);
  }
  const startup = persist.filter((i) => ['launch-agent', 'launch-daemon'].includes(i.kind) && i.program && !i.program.startsWith('/System'))
    .map((i) => ({ label: i.label, program: i.program!, plist: i.plist, signer: i.signer, running: usageByPath.has(i.program!), cpu: usageByPath.get(i.program!)?.cpu ?? 0, mem: usageByPath.get(i.program!)?.mem ?? 0 }))
    .sort((a, b) => b.mem - a.mem);
  const heavy = [...usageByPath].map(([path, u]) => ({ path, name: basename(path), ...u })).sort((a, b) => b.mem - a.mem).slice(0, 12);

  const reclaimable = junk.reduce((n, j) => n + j.size, 0) + caches.reduce((n, c) => n + c.size, 0)
    + leftovers.reduce((n, l) => n + l.size, 0) + duplicates.reduce((n, d) => n + d.size * (d.files.length - 1), 0);

  const findings: FindingInput[] = [];
  if (disk.free / disk.total < 0.1) {
    findings.push({ key: 'storage:low-disk', category: 'storage', severity: 'medium', title: `Only ${Math.round(disk.free / 1e9)} GB free on your disk`,
      summary: `${Math.round((disk.free / disk.total) * 100)}% of the disk is free.`,
      explanation: 'macOS needs free space for updates, virtual memory and backups. Below about 10% free, updates can fail and the Mac slows down.',
      recommendation: 'Open Optimize to see what can be cleared safely.' });
  }
  putSnapshot('storage', { at: Date.now(), tookMs: Date.now() - started, disk, folders, junk, caches: caches.slice(0, 30), unused, leftovers: leftovers.slice(0, 40), largeFiles, duplicates, startup, heavy, reclaimable });
  syncFindings('storage', findings);
}
