import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { DATA_DIR, DB_PATH } from './config.ts';
import { bus } from './bus.ts';

mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

export const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 3000;
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  key TEXT UNIQUE NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  explanation TEXT NOT NULL DEFAULT '',
  recommendation TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '{}',
  actions TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open',
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS snapshots (
  name TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  error TEXT
);
CREATE TABLE IF NOT EXISTS seen (
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  data TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (kind, key)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  finding_id TEXT,
  requested_by TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  decided_at INTEGER,
  result TEXT
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  paths TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  files_scanned INTEGER NOT NULL DEFAULT 0,
  detections TEXT NOT NULL DEFAULT '[]',
  engines TEXT NOT NULL DEFAULT '[]',
  error TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status, category);
`);

// Added after v0.1: snooze support for ignored findings (NULL = ignored until you undo it).
try { db.exec('ALTER TABLE findings ADD COLUMN ignored_until INTEGER'); } catch { /* already there */ }

export const now = () => Date.now();
export const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * How worried to be, separate from raw severity:
 * - suspicious: signs something bad may be happening (malware, a tracker following you, tampering)
 * - risk: a real weakness worth fixing (firewall off, plaintext keys, agents that run code unasked)
 * - hardening: optional ways to strengthen security (guest account, stealth mode, leftovers)
 */
export type Tier = 'suspicious' | 'risk' | 'hardening';

const SUSPICIOUS_KEYS = /^(scan:|attack:|tracker:|intel:|beacon:|download-intel:|incident:|netsafe:gateway-changed:|net:risky-loc:|net:port:|persist:(dl|loc|sig|new|ext-sideload):|phone:[^:]+:sus:|proc:(fake-password-prompt|dscl-authonly|keychain-dump|encoded-exec|reverse-shell|cookie-theft|security-off|unsigned-from-temp):)/;
const HARDENING_KEYS = /^(tcc-leftover:|phone:[^:]+:tip:|posture:(guest|stealth|os-updates|screen-lock|xprotect|mdm|profiles|remote-apps)$|persist:(orphan|ext-perm):|agent:mcp-unpinned:|tcc:input-monitoring-summary|location:|notarize:|secrets-perms:|storage:|outdated:)/;

export function tierOf(f: { key: string; severity: string; category: string }): Tier {
  if (SUSPICIOUS_KEYS.test(f.key)) return 'suspicious';
  if (f.key.startsWith('net:unsigned:')) return f.severity === 'high' ? 'suspicious' : 'risk';
  if (HARDENING_KEYS.test(f.key)) return 'hardening';
  if ((f.key.startsWith('persist:unsigned:') || f.key.startsWith('tcc:')) && SEVERITY_RANK[f.severity] <= SEVERITY_RANK.low) return 'hardening';
  if (f.severity === 'info') return 'hardening';
  return 'risk';
}

export const TIER_RANK: Record<Tier, number> = { hardening: 0, risk: 1, suspicious: 2 };

export interface SuggestedAction { type: string; target: Record<string, unknown>; label: string }

export interface FindingInput {
  key: string;
  category: string;
  severity: Severity;
  title: string;
  summary: string;
  explanation?: string;
  recommendation?: string;
  evidence?: unknown;
  actions?: SuggestedAction[];
}

export interface Finding extends Required<Omit<FindingInput, 'evidence' | 'actions'>> {
  id: string;
  tier: Tier;
  evidence: Record<string, unknown>;
  actions: SuggestedAction[];
  status: 'open' | 'acknowledged' | 'resolved';
  ignored_until: number | null;
  first_seen: number;
  last_seen: number;
  resolved_at: number | null;
}

const j = (v: unknown) => JSON.stringify(v ?? null);
const parse = <T>(s: unknown, fallback: T): T => { try { return s == null ? fallback : JSON.parse(String(s)) as T; } catch { return fallback; } };

function rowToFinding(r: Record<string, unknown>): Finding {
  const f = { ...(r as unknown as Finding), evidence: parse(r.evidence, {}), actions: parse(r.actions, []) };
  f.tier = tierOf(f);
  return f;
}

/**
 * Replace the open findings of one category with the current set.
 * New findings are inserted, existing ones refreshed, and ones no longer
 * observed are marked resolved. Acknowledged findings stay acknowledged.
 */
export function syncFindings(category: string, inputs: FindingInput[], keyPrefix = ''): void {
  db.exec('BEGIN');
  try { syncFindingsTx(category, inputs, keyPrefix); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; }
}

/** keyPrefix limits what gets resolved to one part of a category (one phone among several). */
function syncFindingsTx(category: string, inputs: FindingInput[], keyPrefix: string): void {
  const t = now();
  const keys = new Set(inputs.map((f) => f.key));
  const getByKey = db.prepare('SELECT * FROM findings WHERE key = ?');
  const insert = db.prepare(`INSERT INTO findings (id, key, category, severity, title, summary, explanation, recommendation, evidence, actions, status, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`);
  const update = db.prepare(`UPDATE findings SET severity = ?, title = ?, summary = ?, explanation = ?, recommendation = ?, evidence = ?, actions = ?, last_seen = ?,
    status = CASE WHEN status = 'resolved' THEN 'open' ELSE status END, resolved_at = NULL WHERE key = ?`);
  for (const f of inputs) {
    const existing = getByKey.get(f.key) as Record<string, unknown> | undefined;
    if (!existing) {
      const id = randomUUID().slice(0, 8);
      insert.run(id, f.key, category, f.severity, f.title, f.summary, f.explanation ?? '', f.recommendation ?? '', j(f.evidence ?? {}), j(f.actions ?? []), t, t);
      if (SEVERITY_RANK[f.severity] >= SEVERITY_RANK.low) logEvent('finding', f.severity, f.title, { id, category });
    } else {
      if (existing.status === 'resolved') logEvent('finding', f.severity, `Back again: ${f.title}`, { id: existing.id, category });
      update.run(f.severity, f.title, f.summary, f.explanation ?? '', f.recommendation ?? '', j(f.evidence ?? {}), j(f.actions ?? []), t, f.key);
    }
  }
  const open = db.prepare(`SELECT key FROM findings WHERE category = ? AND status != 'resolved'`).all(category) as { key: string }[];
  // Ignored findings stay ignored even if they go away and come back later.
  const resolve = db.prepare(`UPDATE findings SET status = CASE WHEN status = 'acknowledged' THEN status ELSE 'resolved' END, resolved_at = ? WHERE key = ?`);
  for (const { key } of open) if (!keys.has(key) && key.startsWith(keyPrefix)) resolve.run(t, key);
  bus.emit('change', { type: 'findings', category });
}

/** Snoozed findings come back on their own once the snooze ends. */
function expireIgnores(): void {
  const r = db.prepare(`UPDATE findings SET status = 'open', ignored_until = NULL WHERE status = 'acknowledged' AND ignored_until IS NOT NULL AND ignored_until <= ?`).run(now());
  if (Number(r.changes) > 0) bus.emit('change', { type: 'findings' });
}

export function listFindings(opts: { status?: string; category?: string; minSeverity?: string; limit?: number } = {}): Finding[] {
  expireIgnores();
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (opts.status === 'active' || !opts.status) where.push(`status != 'resolved'`);
  else if (opts.status !== 'all') { where.push('status = ?'); args.push(opts.status); }
  if (opts.category) { where.push('category = ?'); args.push(opts.category); }
  const rows = db.prepare(`SELECT * FROM findings ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY last_seen DESC LIMIT ?`)
    .all(...args, opts.limit ?? 500) as Record<string, unknown>[];
  const min = SEVERITY_RANK[opts.minSeverity ?? 'info'] ?? 0;
  return rows.map(rowToFinding)
    .filter((f) => SEVERITY_RANK[f.severity] >= min)
    .sort((a, b) => TIER_RANK[b.tier] - TIER_RANK[a.tier] || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.last_seen - a.last_seen);
}

export function getFinding(id: string): Finding | null {
  const r = db.prepare('SELECT * FROM findings WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  return r ? rowToFinding(r) : null;
}

/** Ignore a finding (optionally only for a number of days) or bring it back. */
export function setFindingStatus(id: string, status: 'open' | 'acknowledged', days?: number): boolean {
  const until = status === 'acknowledged' && days && days > 0 ? now() + Math.min(days, 365) * 86_400_000 : null;
  const r = db.prepare('UPDATE findings SET status = ?, ignored_until = ? WHERE id = ? AND status != ?').run(status, until, id, 'resolved');
  const f = getFinding(id);
  if (f && Number(r.changes) > 0) {
    logEvent('finding', 'info', status === 'open' ? `You stopped ignoring: ${f.title}` : `You ignored${days ? ` for ${days} days` : ''}: ${f.title}`, { id });
  }
  bus.emit('change', { type: 'findings', category: f?.category });
  return Number(r.changes) > 0;
}

export function putSnapshot(name: string, data: unknown, error: string | null = null): void {
  db.prepare(`INSERT INTO snapshots (name, data, updated_at, error) VALUES (?, ?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at, error = excluded.error`)
    .run(name, j(data), now(), error);
  bus.emit('change', { type: 'snapshot', name });
}

export function getSnapshot<T = unknown>(name: string): { data: T; updated_at: number; error: string | null } | null {
  const r = db.prepare('SELECT * FROM snapshots WHERE name = ?').get(name) as Record<string, unknown> | undefined;
  return r ? { data: parse<T>(r.data, null as T), updated_at: Number(r.updated_at), error: (r.error as string) ?? null } : null;
}

/** Record that something was observed. Returns true the first time a (kind, key) is seen. */
export function markSeen(kind: string, key: string, data: unknown = {}): { isNew: boolean; first_seen: number } {
  const t = now();
  const existing = db.prepare('SELECT first_seen FROM seen WHERE kind = ? AND key = ?').get(kind, key) as { first_seen: number } | undefined;
  if (existing) {
    db.prepare('UPDATE seen SET last_seen = ?, count = count + 1, data = ? WHERE kind = ? AND key = ?').run(t, j(data), kind, key);
    return { isNew: false, first_seen: existing.first_seen };
  }
  db.prepare('INSERT INTO seen (kind, key, first_seen, last_seen, data) VALUES (?, ?, ?, ?, ?)').run(kind, key, t, t, j(data));
  return { isNew: true, first_seen: t };
}

/** When the first observation of this kind was recorded (null if never). */
export function baselineStart(kind: string): number | null {
  const r = db.prepare('SELECT MIN(first_seen) AS t FROM seen WHERE kind = ?').get(kind) as { t: number | null } | undefined;
  return r?.t ?? null;
}

export function hasBaseline(kind: string): boolean {
  return Boolean(db.prepare('SELECT 1 FROM seen WHERE kind = ? LIMIT 1').get(kind));
}

export function recentSeen(kind: string, sinceMs: number, limit = 200): { key: string; first_seen: number; last_seen: number; count: number; data: Record<string, unknown> }[] {
  return (db.prepare('SELECT * FROM seen WHERE kind = ? AND first_seen >= ? ORDER BY first_seen DESC LIMIT ?').all(kind, sinceMs, limit) as Record<string, unknown>[])
    .map((r) => ({ key: String(r.key), first_seen: Number(r.first_seen), last_seen: Number(r.last_seen), count: Number(r.count), data: parse(r.data, {}) }));
}

export function logEvent(kind: string, severity: Severity, title: string, detail: unknown = {}): void {
  db.prepare('INSERT INTO events (ts, kind, severity, title, detail) VALUES (?, ?, ?, ?, ?)').run(now(), kind, severity, title, j(detail));
  bus.emit('change', { type: 'event', kind, severity, title });
}

export function listEvents(limit = 100, sinceMs = 0): { id: number; ts: number; kind: string; severity: string; title: string; detail: unknown }[] {
  return (db.prepare('SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT ?').all(sinceMs, limit) as Record<string, unknown>[])
    .map((r) => ({ id: Number(r.id), ts: Number(r.ts), kind: String(r.kind), severity: String(r.severity), title: String(r.title), detail: parse(r.detail, {}) }));
}

export function pruneOld(): void {
  const month = now() - 30 * 86_400_000;
  db.prepare('DELETE FROM events WHERE ts < ?').run(month);
  db.prepare(`DELETE FROM findings WHERE status = 'resolved' AND resolved_at < ?`).run(month);
  db.prepare(`DELETE FROM seen WHERE kind = 'net' AND last_seen < ?`).run(now() - 90 * 86_400_000);
}

export { parse as parseJson, j as toJson };
