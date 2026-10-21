/**
 * Time series Hashling keeps so it can see behaviour over time (something an
 * on-demand agent cannot): traffic per app per minute, every new outgoing
 * connection, and the security score. Kept for 7 days (score: 90 days).
 */
import { db, now } from './db.ts';
import { pruneUploads } from './intel/uploads.ts';

db.exec(`
CREATE TABLE IF NOT EXISTS traffic (
  minute INTEGER NOT NULL,
  app TEXT NOT NULL,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (minute, app)
);
CREATE TABLE IF NOT EXISTS conn_opens (
  ts INTEGER NOT NULL,
  app TEXT NOT NULL,
  path TEXT,
  signer TEXT,
  agent TEXT,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  dest TEXT
);
CREATE INDEX IF NOT EXISTS conn_opens_key ON conn_opens(app, ip, port, ts);
CREATE INDEX IF NOT EXISTS conn_opens_ts ON conn_opens(ts);
CREATE TABLE IF NOT EXISTS score_history (
  ts INTEGER PRIMARY KEY,
  score INTEGER NOT NULL,
  suspicious INTEGER NOT NULL,
  risk INTEGER NOT NULL,
  hardening INTEGER NOT NULL
);
`);

const MIN = 60_000;

export function recordTraffic(rows: { app: string; bytesIn: number; bytesOut: number }[], at = now()): void {
  const minute = Math.floor(at / MIN) * MIN;
  const up = db.prepare(`INSERT INTO traffic (minute, app, bytes_in, bytes_out) VALUES (?, ?, ?, ?)
    ON CONFLICT(minute, app) DO UPDATE SET bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out`);
  db.exec('BEGIN');
  try {
    for (const r of rows) if (r.bytesIn > 0 || r.bytesOut > 0) up.run(minute, r.app, Math.round(r.bytesIn), Math.round(r.bytesOut));
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

export function recordConnOpens(rows: { app: string; path: string; signer: string; agent: string | null; ip: string; port: number; dest: string }[], at = now()): void {
  if (!rows.length) return;
  const ins = db.prepare('INSERT INTO conn_opens (ts, app, path, signer, agent, ip, port, dest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  db.exec('BEGIN');
  try {
    for (const r of rows) ins.run(at, r.app, r.path, r.signer, r.agent, r.ip, r.port, r.dest);
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

export function recordScore(score: number, tiers: { suspicious: number; risk: number; hardening: number }): void {
  const hour = Math.floor(now() / 3600_000) * 3600_000;
  db.prepare(`INSERT INTO score_history (ts, score, suspicious, risk, hardening) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(ts) DO UPDATE SET score = excluded.score, suspicious = excluded.suspicious, risk = excluded.risk, hardening = excluded.hardening`)
    .run(hour, score, tiers.suspicious, tiers.risk, tiers.hardening);
}

export function scoreHistory(days = 30) {
  return db.prepare('SELECT ts, score, suspicious, risk, hardening FROM score_history WHERE ts >= ? ORDER BY ts').all(now() - days * 86_400_000);
}

/** Traffic per app bucketed for charts: the top N apps by volume plus "Other". */
export function trafficSeries(hours: number, top = 5) {
  const since = now() - hours * 3600_000;
  const bucket = hours <= 1 ? MIN : hours <= 6 ? 5 * MIN : hours <= 24 ? 15 * MIN : 60 * MIN;
  const totals = db.prepare('SELECT app, SUM(bytes_in) AS i, SUM(bytes_out) AS o FROM traffic WHERE minute >= ? GROUP BY app ORDER BY (i + o) DESC').all(since) as { app: string; i: number; o: number }[];
  const keep = new Set(totals.slice(0, top).map((t) => t.app));
  const rows = db.prepare('SELECT minute, app, bytes_in, bytes_out FROM traffic WHERE minute >= ?').all(since) as { minute: number; app: string; bytes_in: number; bytes_out: number }[];
  const series = new Map<number, Record<string, { in: number; out: number }>>();
  for (const r of rows) {
    const b = Math.floor(r.minute / bucket) * bucket;
    const name = keep.has(r.app) ? r.app : 'Other';
    const slot = series.get(b) ?? {};
    const v = slot[name] ?? { in: 0, out: 0 };
    v.in += r.bytes_in; v.out += r.bytes_out;
    slot[name] = v;
    series.set(b, slot);
  }
  const apps = [...keep, ...(totals.length > top ? ['Other'] : [])];
  const points: { t: number; apps: Record<string, { in: number; out: number }> }[] = [];
  for (let t = Math.floor(since / bucket) * bucket; t <= now(); t += bucket) points.push({ t, apps: series.get(t) ?? {} });
  return { bucketMs: bucket, apps, totals: totals.slice(0, 12).map((t) => ({ app: t.app, bytesIn: t.i, bytesOut: t.o })), points };
}

/** Upload volume per app in a window, and that app's typical (p95) volume per window over the past week. */
export function uploadStats(windowMs: number) {
  const nowMs = now();
  const recent = db.prepare('SELECT app, SUM(bytes_out) AS out FROM traffic WHERE minute >= ? GROUP BY app').all(nowMs - windowMs) as { app: string; out: number }[];
  return recent.map((r) => {
    const hist = db.prepare(`SELECT (minute / ?) AS w, SUM(bytes_out) AS out FROM traffic WHERE app = ? AND minute < ? AND minute >= ? GROUP BY w`)
      .all(windowMs, r.app, nowMs - windowMs, nowMs - 7 * 86_400_000) as { out: number }[];
    const sorted = hist.map((h) => h.out).sort((a, b) => a - b);
    const p95 = sorted.length ? sorted[Math.floor(sorted.length * 0.95)] ?? sorted[sorted.length - 1] : 0;
    return { app: r.app, out: r.out, p95, samples: sorted.length };
  });
}

/** New-connection timestamps per (app, ip, port) in a window, for beacon analysis. */
export function connOpenGroups(sinceMs: number) {
  const rows = db.prepare('SELECT app, path, signer, agent, ip, port, dest, ts FROM conn_opens WHERE ts >= ? ORDER BY ts').all(sinceMs) as { app: string; path: string; signer: string; agent: string | null; ip: string; port: number; dest: string; ts: number }[];
  const groups = new Map<string, { app: string; path: string; signer: string; agent: string | null; ip: string; port: number; dest: string; times: number[] }>();
  for (const r of rows) {
    const k = `${r.app}|${r.dest}|${r.port}`;
    const g = groups.get(k) ?? { app: r.app, path: r.path, signer: r.signer, agent: r.agent, ip: r.ip, port: r.port, dest: r.dest, times: [] };
    g.times.push(r.ts);
    groups.set(k, g);
  }
  return [...groups.values()];
}

export function pruneHistory(): void {
  const week = now() - 7 * 86_400_000;
  db.prepare('DELETE FROM traffic WHERE minute < ?').run(week);
  db.prepare('DELETE FROM conn_opens WHERE ts < ?').run(week);
  pruneUploads();
  db.prepare('DELETE FROM score_history WHERE ts < ?').run(now() - 90 * 86_400_000);
}
