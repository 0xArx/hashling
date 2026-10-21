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

function raise(key: string, title: string, summary: string, evidence: Record<string, unknown>) {
  if (alerts.has(key)) return;
  alerts.set(key, { at: Date.now(), title, summary, evidence });
  logEvent('finding', 'critical', title, evidence);
  publish();
}

function publish() {
  putSnapshot('ransomware', { at: Date.now(), watching: watchers.length, alerts: [...alerts.values()] });
  syncFindings('ransomware', [...alerts].map(([key, a]) => ({
    key: `ransomware:${key}`, category: 'ransomware', severity: 'critical', title: a.title, summary: a.summary,
    explanation: 'Ransomware scrambles your files so you cannot open them, renames them, and leaves a note asking for payment. The faster it is stopped, the fewer files it reaches.',
    recommendation: 'Act now: 1) Turn off Wi-Fi. 2) Unplug any backup disk so it cannot be scrambled too. 3) Shut the Mac down by holding the power button. 4) Do not pay. Then get help, and restore your files from a backup on a clean Mac.',
    evidence: a.evidence,
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
        { ext, count: same.length, examples: same.slice(-5).map((r) => r.file.replace(HOME, '~')) });
    }
  }
  if (NOTE_NAME.test(name) && existsSync(file)) {
    try {
      const st = statSync(file);
      if (st.size < 200_000 && Date.now() - st.birthtimeMs < 120_000 && NOTE_TEXT.test(readFileSync(file, 'utf8').slice(0, 20_000))) {
        raise(`note:${file}`, 'A ransom note appeared in your files', `${file.replace(HOME, '~')} asks for payment to unlock files.`, { file: file.replace(HOME, '~') });
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
export function clearRansomwareAlerts(): void { alerts.clear(); recent = []; publish(); }
