/**
 * Uploads: what left this Mac, from which app, to whom, and which files were involved.
 *
 * Hashling cannot read inside uploads (almost all traffic is encrypted, and breaking HTTPS
 * to look would make the Mac less safe). It builds the picture from three things it can see:
 *   1. bytes sent per connection, so every upload has an app, a destination and a time;
 *   2. the files an app has open while it is sending a lot ("likely" the files being uploaded);
 *   3. upload commands (curl -F @file, scp, rsync, cloud CLIs, git push), which name the files.
 * Everything is kept for 7 days.
 */
import { basename } from 'node:path';
import { db, now } from '../db.ts';
import { HOME } from '../config.ts';
import { run } from '../lib/exec.ts';
import { redact } from '../lib/redact.ts';

db.exec(`
CREATE TABLE IF NOT EXISTS upload_dest (
  minute INTEGER NOT NULL,
  app TEXT NOT NULL,
  dest TEXT NOT NULL,
  host TEXT,
  country TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (minute, app, dest)
);
CREATE INDEX IF NOT EXISTS upload_dest_minute ON upload_dest(minute);
CREATE TABLE IF NOT EXISTS upload_files (
  ts INTEGER NOT NULL,
  app TEXT NOT NULL,
  file TEXT NOT NULL,
  size INTEGER,
  rate INTEGER,
  dests TEXT
);
CREATE INDEX IF NOT EXISTS upload_files_ts ON upload_files(ts);
CREATE TABLE IF NOT EXISTS upload_cmds (
  ts INTEGER NOT NULL,
  pid INTEGER NOT NULL,
  tool TEXT NOT NULL,
  files TEXT NOT NULL,
  dest TEXT,
  agent TEXT,
  parent TEXT,
  args TEXT,
  PRIMARY KEY (pid, ts)
);
`);

const MIN = 60_000;

export function recordUploadDests(rows: { app: string; dest: string; host?: string; country?: string; bytes: number }[], at = now()): void {
  if (!rows.length) return;
  const minute = Math.floor(at / MIN) * MIN;
  const up = db.prepare(`INSERT INTO upload_dest (minute, app, dest, host, country, bytes) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(minute, app, dest) DO UPDATE SET bytes = bytes + excluded.bytes, host = COALESCE(excluded.host, host)`);
  db.exec('BEGIN');
  try {
    for (const r of rows) if (r.bytes > 0) up.run(minute, r.app, r.dest, r.host ?? null, r.country ?? null, Math.round(r.bytes));
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

// ---------- files open while an app is sending ----------
/** Sending faster than this for one sample counts as "uploading". */
export const UPLOAD_RATE = 256 * 1024;
const lastLook = new Map<string, number>();
const SKIP_FILE = /\/\.hashling\/|\/Library\/(HTTPStorages|Preferences|Saved Application State|Cookies|WebKit|Caches|Logs|Containers\/[^/]+\/Data\/Library\/Caches|Application Support\/[^/]+\/(Cache|Code Cache|GPUCache|Service Worker|IndexedDB|Local Storage|Session Storage|blob_storage|Crashpad))|\.app\/|\/node_modules\/|\/\.git\/|\/Library\/.*\.(sqlite3?|db)$|\.(dylib|so|db-wal|db-shm|sqlite-wal|sqlite-shm|lock|log)$|\/(Cookies|History|Favicons|Top Sites|Web Data|Login Data|Network Persistent State|TransportSecurity|Preferences|Local State)(-journal)?$|\/\.DS_Store$/;

/**
 * While an app sends a lot, note which of your files it has open for reading. Throttled to
 * once per 30 s per app; runs in the background so it never delays the network collector.
 */
export function noteFilesWhileUploading(app: string, pids: number[], rate: number, dests: string[]): void {
  const t = now();
  if (t - (lastLook.get(app) ?? 0) < 30_000) return;
  lastLook.set(app, t);
  void (async () => {
    const r = await run('/usr/sbin/lsof', ['-n', '-P', '-w', '-a', '-p', pids.slice(0, 20).join(','), '-d', '^txt,^mem', '-Fatns'], { timeout: 8000 });
    if (!r.stdout) return;
    const files = new Map<string, number | null>();
    let mode = '', type = '', size: number | null = null;
    for (const line of r.stdout.split('\n')) {
      const k = line[0], v = line.slice(1);
      if (k === 'f') { mode = ''; type = ''; size = null; }
      else if (k === 'a') mode = v;
      else if (k === 't') type = v;
      else if (k === 's') size = Number(v);
      else if (k === 'n' && type === 'REG' && mode !== 'w' && (v.startsWith(`${HOME}/`) || v.startsWith('/Volumes/')) && !SKIP_FILE.test(v)) files.set(v, size);
    }
    if (!files.size) return;
    const ins = db.prepare('INSERT INTO upload_files (ts, app, file, size, rate, dests) VALUES (?, ?, ?, ?, ?, ?)');
    for (const [file, sz] of [...files].slice(0, 40)) ins.run(t, app, file, sz, Math.round(rate), JSON.stringify(dests.slice(0, 5)));
  })().catch(() => { /* lsof can fail for short-lived processes */ });
}

// ---------- upload commands ----------
export interface UploadCmd { tool: string; files: string[]; dest: string | null }
const hostOf = (u: string) => { try { return new URL(u).hostname; } catch { return u.match(/^(?:[^@\s]+@)?([^:\s/]+):/)?.[1] ?? null; } };
/** Split a command line on whitespace, honouring simple quotes (ps prints argv joined by spaces). */
const words = (a: string) => (a.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map((w) => w.replace(/^["']|["']$/g, ''));
const isRemote = (w: string) => /^[^/\s]*@?[\w.-]+:(?!\/\/)/.test(w) && !/^[A-Za-z]:\\/.test(w);

/** Recognise a command that sends local files somewhere. Judged on the real program, never a shell's script text. */
export function parseUploadCommand(path: string, args: string): UploadCmd | null {
  const tool = basename(path);
  const w = words(args).slice(1);
  const plain = w.filter((x) => !x.startsWith('-'));
  switch (tool) {
    case 'curl': {
      const files: string[] = [];
      for (let i = 0; i < w.length; i++) {
        const x = w[i], next = w[i + 1] ?? '';
        if (x === '-T' || x === '--upload-file') files.push(next);
        else if (/^(-F|--form)$/.test(x) && /=[@<]/.test(next)) files.push(next.replace(/^[^=]*=[@<]/, '').split(';')[0]);
        else if (/^(-d|--data|--data-binary|--data-raw|--data-urlencode|--json)$/.test(x) && next.startsWith('@') && next !== '@-') files.push(next.slice(1));
      }
      if (!files.length) return null;
      const url = w.find((x) => /^https?:\/\//.test(x));
      return { tool, files, dest: url ? hostOf(url) : null };
    }
    case 'scp': case 'rsync': {
      const target = [...plain].reverse().find(isRemote);
      if (!target || !plain.length || isRemote(plain[0])) return null; // a download (remote -> local)
      return { tool, files: plain.slice(0, -1).filter((x) => !isRemote(x)), dest: hostOf(target) };
    }
    case 'rclone': {
      if (!['copy', 'sync', 'move', 'copyto', 'moveto'].includes(plain[0] ?? '')) return null;
      const [, src, dst] = plain;
      return src && dst && !isRemote(src) && isRemote(dst) ? { tool, files: [src], dest: dst.split(':')[0] } : null;
    }
    case 'aws': {
      if (plain[0] !== 's3' || !['cp', 'sync', 'mv'].includes(plain[1] ?? '')) return null;
      const [src, dst] = plain.slice(2);
      return src && dst?.startsWith('s3://') && !src.startsWith('s3://') ? { tool: 'aws s3', files: [src], dest: dst.split('/')[2] } : null;
    }
    case 'gsutil': case 'gcloud': {
      const i = plain.findIndex((x) => x === 'cp' || x === 'rsync');
      const dst = plain[plain.length - 1];
      return i >= 0 && dst?.startsWith('gs://') ? { tool, files: plain.slice(i + 1, -1).filter((x) => !x.startsWith('gs://')), dest: dst.split('/')[2] } : null;
    }
    case 'gh': {
      if (plain[0] === 'release' && plain[1] === 'upload') return { tool: 'gh release upload', files: plain.slice(3), dest: 'github.com' };
      if (plain[0] === 'gist' && plain[1] === 'create') return { tool: 'gh gist create', files: plain.slice(2), dest: 'gist.github.com' };
      return null;
    }
    case 'git': {
      if (plain[0] !== 'push') return null;
      return { tool: 'git push', files: [], dest: plain[1] ?? 'origin' };
    }
    case 'croc': case 'wormhole': case 'magic-wormhole': {
      return plain[0] === 'send' ? { tool, files: plain.slice(1), dest: `${tool} relay` } : null;
    }
    case 'nc': case 'ncat': case 'netcat': case 'sftp': case 'ftp':
      return null; // the file arrives on stdin, which ps cannot show
    default: return null;
  }
}

/** Destinations can carry credentials (https://x-access-token:ghp_…@github.com/…): keep only what is safe to show. */
export function safeDest(dest: string | null): string | null {
  if (!dest) return dest;
  const noLogin = dest.replace(/^([a-z][\w+.-]*:\/\/)[^/@\s]*@/i, '$1');
  return redact(noLogin);
}

export function recordUploadCommand(ts: number, pid: number, cmd: UploadCmd, agent: string | null, parent: string | null, args: string): void {
  db.prepare('INSERT OR IGNORE INTO upload_cmds (ts, pid, tool, files, dest, agent, parent, args) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(ts, pid, cmd.tool, JSON.stringify(cmd.files.slice(0, 30).map(redact)), safeDest(cmd.dest), agent, parent, redact(safeDest(args) ?? '').slice(0, 600));
}

// ---------- report ----------
export function uploadsReport(hours = 168) {
  const since = now() - hours * 3600_000;
  const bucket = hours <= 24 ? 3600_000 : hours <= 72 ? 3 * 3600_000 : 6 * 3600_000;
  // Only what left the Mac: upload_dest counts internet destinations, never local or loopback traffic.
  const byApp = db.prepare('SELECT app, SUM(bytes) AS bytes FROM upload_dest WHERE minute >= ? GROUP BY app HAVING bytes > 0 ORDER BY bytes DESC LIMIT 40').all(since) as { app: string; bytes: number }[];
  const top = byApp.slice(0, 5).map((a) => a.app);
  const rows = db.prepare('SELECT minute, app, SUM(bytes) AS bytes_out FROM upload_dest WHERE minute >= ? GROUP BY minute, app').all(since) as { minute: number; app: string; bytes_out: number }[];
  const series = new Map<number, Record<string, number>>();
  for (const r of rows) {
    const b = Math.floor(r.minute / bucket) * bucket;
    const name = top.includes(r.app) ? r.app : 'Other';
    const slot = series.get(b) ?? {};
    slot[name] = (slot[name] ?? 0) + r.bytes_out;
    series.set(b, slot);
  }
  const points: { t: number; apps: Record<string, number> }[] = [];
  for (let t = Math.floor(since / bucket) * bucket; t <= now(); t += bucket) points.push({ t, apps: series.get(t) ?? {} });
  const dests = db.prepare(`SELECT app, dest, MAX(host) AS host, MAX(country) AS country, SUM(bytes) AS bytes, MIN(minute) AS first, MAX(minute) AS last
    FROM upload_dest WHERE minute >= ? GROUP BY app, dest ORDER BY bytes DESC LIMIT 80`).all(since) as { app: string; dest: string; host: string | null; country: string | null; bytes: number; first: number; last: number }[];
  const files = db.prepare(`SELECT app, file, MAX(size) AS size, COUNT(*) AS seen, MIN(ts) AS first, MAX(ts) AS last, MAX(rate) AS rate, MAX(dests) AS dests
    FROM upload_files WHERE ts >= ? GROUP BY app, file ORDER BY last DESC LIMIT 150`).all(since) as { app: string; file: string; size: number | null; seen: number; first: number; last: number; rate: number; dests: string }[];
  const commands = (db.prepare('SELECT ts, tool, files, dest, agent, parent, args FROM upload_cmds WHERE ts >= ? ORDER BY ts DESC LIMIT 100').all(since) as { ts: number; tool: string; files: string; dest: string | null; agent: string | null; parent: string | null; args: string }[])
    .map((c) => ({ ...c, files: JSON.parse(c.files) as string[] }));
  const historyStart = (db.prepare('SELECT MIN(minute) AS t FROM upload_dest').get() as { t: number | null }).t;
  const total = byApp.reduce((n, a) => n + a.bytes, 0);
  return {
    hours, since, bucketMs: bucket, historyStart, total,
    apps: [...top, ...(byApp.length > top.length ? ['Other'] : [])], byApp, points,
    dests, files: files.map((f) => ({ ...f, dests: JSON.parse(f.dests ?? '[]') as string[] })), commands,
    limitation: 'Upload contents are encrypted, so I see how much went where, not what was inside. Files are named when the upload command lists them, or noted as "open while sending" when an app sent a lot.',
  };
}

export function pruneUploads(): void {
  const week = now() - 7 * 86_400_000;
  db.prepare('DELETE FROM upload_dest WHERE minute < ?').run(week);
  db.prepare('DELETE FROM upload_files WHERE ts < ?').run(week);
  db.prepare('DELETE FROM upload_cmds WHERE ts < ?').run(week);
}
