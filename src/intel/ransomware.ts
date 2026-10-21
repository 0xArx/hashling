/**
 * Ransomware tripwire. Ransomware scrambles your files and usually renames them with a new
 * ending (holiday.jpg -> holiday.jpg.locked), then drops a note telling you how to pay.
 * Hashling watches the folders people keep their files in for exactly those two signs.
 * Builds, downloads and syncing change many files too, but they do not add one new ending to
 * dozens of existing files in a minute, or leave a payment note.
 */
import { watch, existsSync, statSync, readFileSync, type FSWatcher } from 'node:fs';
import { join, extname, basename } from 'node:path';
import { HOME } from '../config.ts';
import { logEvent, syncFindings, putSnapshot } from '../db.ts';
import { run } from '../lib/exec.ts';
import { loadPrefs } from '../prefs.ts';
import { bus } from '../bus.ts';

const FOLDERS = ['Documents', 'Desktop', 'Pictures', 'Movies', 'Music'].map((d) => join(HOME, d));
const NOISY = /(^|\/)(node_modules|\.git|\.next|dist|build|\.cache|DerivedData|\.Trash|Library)(\/|$)|\.(tmp|crdownload|part|download|swp|sb-[a-z0-9]+)$/i;
/** Endings real files have; anything else stacked on top of one of these is suspicious. */
const REAL_EXT = /^\.(jpe?g|png|heic|gif|tiff?|raw|cr2|nef|mov|mp4|m4v|avi|mp3|m4a|wav|aiff?|pdf|docx?|xlsx?|pptx?|pages|numbers|key|txt|rtf|md|csv|zip|psd|ai|sketch|fig|json|sqlite|db)$/i;
const NOTE_NAME = /(decrypt|restore|recover|ransom|how[_ -]?to|readme|read[_ -]?me|instruction|your[_ -]?files|files[_ -]?encrypted)[^/]*\.(txt|html?|hta|rtf)$/i;
const NOTE_TEXT = /(decrypt|encrypted|bitcoin|btc|monero|\.onion|tor browser|private key|ransom)/i;

const WINDOW = 60_000;
const THRESHOLD = 25;
let recent: { ext: string; at: number; file: string }[] = [];
const alerts = new Map<string, { at: number; title: string; summary: string; evidence: Record<string, unknown> }>();
const watchers: FSWatcher[] = [];

function raise(key: string, title: string, summary: string, evidence: Record<string, unknown>, files: string[] = []) {
  if (alerts.has(key)) return;
  alerts.set(key, { at: Date.now(), title, summary, evidence });
  logEvent('finding', 'critical', title, evidence);
  publish();
  if (loadPrefs().ransomBrake) void brake(files).catch((e) => console.error('[ransomware brake]', e));
}

// ---------- The brake ----------
// Ransomware has to open each file to scramble it. When the tripwire fires, ask macOS which
// programs have those files (or their folder) open and pause them on the spot. A paused program
// keeps everything it had and can carry on later, so a wrong guess costs nothing; you then quit
// it or let it continue, both with Touch ID.
/** Programs that touch lots of files for good reasons: indexing, syncing, backups, previews. */
const TRUSTED = /^(Finder|mds|mds_stores|mdworker|mdworker_shared|mdsync|fileproviderd|bird|cloudd|backupd|QuickLookUIService|com\.apple\..*|photolibraryd|photoanalysisd|Dropbox|Google Drive|OneDrive|Box|revisiond|fseventsd)$/i;
export interface Paused { pid: number; name: string; path: string; at: number; resumed?: boolean }
let paused: Paused[] = [];

async function holders(paths: string[], dirs: string[]): Promise<Map<number, { name: string; path: string }>> {
  const found = new Map<number, { name: string; path: string }>();
  const parse = (out: string) => {
    let pid = 0, name = '';
    for (const line of out.split('\n')) {
      if (line[0] === 'p') pid = Number(line.slice(1));
      else if (line[0] === 'c') name = line.slice(1);
      if (pid && name && !found.has(pid)) found.set(pid, { name, path: '' });
    }
  };
  if (paths.length) parse((await run('/usr/sbin/lsof', ['-nP', '-Fpc', '--', ...paths], { timeout: 4000 })).stdout);
  for (const d of dirs) parse((await run('/usr/sbin/lsof', ['-nP', '-Fpc', '+d', d], { timeout: 4000 })).stdout);
  for (const [pid, v] of found) {
    const r = await run('/bin/ps', ['-o', 'comm=', '-p', String(pid)], { timeout: 2000 });
    v.path = r.stdout.trim();
  }
  return found;
}

async function brake(files: string[]): Promise<void> {
  const dirs = [...new Set(files.map((f) => f.slice(0, f.lastIndexOf('/'))))].slice(0, 4);
  const found = await holders(files.slice(-12), dirs);
  const stopped: Paused[] = [];
  for (const [pid, p] of found) {
    if (pid === process.pid || pid <= 1 || TRUSTED.test(p.name) || p.path.startsWith('/System/') || p.path.startsWith('/usr/libexec/')) continue;
    try { process.kill(pid, 'SIGSTOP'); stopped.push({ pid, name: p.name, path: p.path, at: Date.now() }); } catch { /* owned by another user or already gone */ }
  }
  if (!stopped.length) {
    logEvent('finding', 'high', 'I couldn’t tell which program is renaming your files, so nothing was paused', { dirs: dirs.map((d) => d.replace(HOME, '~')) });
    return;
  }
  paused.push(...stopped);
  for (const p of stopped) logEvent('action', 'critical', `I paused ${p.name} because it was scrambling your files`, { pid: p.pid, path: p.path });
  publish();
  bus.emit('change', { type: 'ransomware' });
}

export function pausedPrograms(): Paused[] { return paused.filter((p) => !p.resumed); }

/** Let a paused program carry on (the user confirmed with Touch ID that it is theirs). */
export function resumeProgram(pid: number): boolean {
  const p = paused.find((x) => x.pid === pid && !x.resumed);
  if (!p) return false;
  try { process.kill(pid, 'SIGCONT'); } catch { /* already gone */ }
  p.resumed = true;
  logEvent('action', 'info', `You let ${p.name} continue`, { pid });
  publish();
  return true;
}

function publish() {
  putSnapshot('ransomware', { at: Date.now(), watching: watchers.length, alerts: [...alerts.values()], paused: pausedPrograms() });
  syncFindings('ransomware', [...alerts].map(([key, a]) => ({
    key: `ransomware:${key}`, category: 'ransomware', severity: 'critical', title: a.title, summary: a.summary,
    explanation: 'Ransomware scrambles your files so you cannot open them, renames them, and leaves a note asking for payment. The faster it is stopped, the fewer files it reaches.',
    recommendation: pausedPrograms().length
      ? `I paused ${pausedPrograms().map((p) => p.name).join(', ')}, so it can’t scramble more files right now. If you don’t know it, quit it (Approve below) and then: 1) turn off Wi-Fi, 2) unplug any backup disk, 3) don’t pay, and get help. If it is yours (a photo app renaming files, for example), let it continue on the Ransomware brake card.`
      : 'Act now: 1) Turn off Wi-Fi. 2) Unplug any backup disk so it cannot be scrambled too. 3) Shut the Mac down by holding the power button. 4) Do not pay. Then get help, and restore your files from a backup on a clean Mac.',
    evidence: { ...a.evidence, paused: pausedPrograms() },
    actions: pausedPrograms().map((p) => ({ type: 'kill_process', target: { pid: p.pid, name: p.name }, label: `Quit ${p.name}` })),
  })));
}

function onChange(dir: string, name: string) {
  if (NOISY.test(name)) return;
  const file = join(dir, name);
  const ext = extname(name).toLowerCase();
  const inner = extname(basename(name, ext));
  // holiday.jpg.locked: a real ending with an unknown one stacked on top.
  if (ext && !REAL_EXT.test(ext) && inner && REAL_EXT.test(inner) && existsSync(file)) {
    const now = Date.now();
    recent = recent.filter((r) => now - r.at < WINDOW);
    recent.push({ ext, at: now, file });
    const same = recent.filter((r) => r.ext === ext);
    if (same.length >= THRESHOLD) {
      raise(`ext${ext}`, `Your files are being renamed to “${ext}”: possible ransomware`,
        `${same.length} files in a minute, for example ${basename(same[0].file)} and ${basename(same[same.length - 1].file)}.`,
        { ext, count: same.length, examples: same.slice(-5).map((r) => r.file.replace(HOME, '~')) }, same.map((r) => r.file));
    }
  }
  if (NOTE_NAME.test(name) && existsSync(file)) {
    try {
      const st = statSync(file);
      if (st.size < 200_000 && Date.now() - st.birthtimeMs < 120_000 && NOTE_TEXT.test(readFileSync(file, 'utf8').slice(0, 20_000))) {
        raise(`note:${file}`, 'A ransom note appeared in your files', `${file.replace(HOME, '~')} asks for payment to unlock files.`, { file: file.replace(HOME, '~') }, [file]);
      }
    } catch { /* gone or unreadable */ }
  }
}

export function startRansomwareWatch(): void {
  for (const dir of FOLDERS) {
    if (!existsSync(dir)) continue;
    try {
      const w = watch(dir, { recursive: true }, (_ev, f) => { if (f) onChange(dir, String(f)); });
      w.on('error', () => { /* folder went away or access revoked */ });
      watchers.push(w);
    } catch { /* not allowed */ }
  }
  // Only the snapshot: an alert from before a restart stays until you clear it.
  putSnapshot('ransomware', { at: Date.now(), watching: watchers.length, alerts: [] });
}

/** The user said it was them (or it is over): clear the alerts. */
export function clearRansomwareAlerts(): void { alerts.clear(); recent = []; paused = paused.filter((p) => !p.resumed); publish(); }
