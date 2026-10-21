/**
 * "What changed": everything new on this Mac since a point in time, compared
 * against the baseline Hashling has learned. New things are where trouble starts.
 */
import { db, now, getSnapshot, listFindings, parseJson } from '../db.ts';
import { scoreHistory } from '../history.ts';

export function whatChanged(hours = 24) {
  const since = now() - hours * 3600_000;
  const seen = (kind: string, limit = 50) => (db.prepare('SELECT key, first_seen, data FROM seen WHERE kind = ? AND first_seen >= ? ORDER BY first_seen DESC LIMIT ?').all(kind, since, limit) as { key: string; first_seen: number; data: string }[])
    .map((r) => ({ key: r.key, firstSeen: r.first_seen, ...parseJson<Record<string, unknown>>(r.data, {}) }));
  // Ignore the first baseline sweep, which records everything at once.
  const baseline = (kind: string) => (db.prepare('SELECT MIN(first_seen) AS t FROM seen WHERE kind = ?').get(kind) as { t: number | null }).t ?? now();
  const real = <T extends { firstSeen: number }>(kind: string, rows: T[]) => rows.filter((r) => r.firstSeen > baseline(kind) + 120_000);

  const scores = scoreHistory(Math.max(1, Math.ceil(hours / 24))) as { ts: number; score: number }[];
  const findingsOpened = listFindings({ status: 'all' }).filter((f) => f.first_seen >= since);
  // When Hashling started learning this Mac: until a day has passed, there is no "normal" to compare with.
  const learningSince = (db.prepare('SELECT MIN(first_seen) AS t FROM seen').get() as { t: number | null }).t ?? now();
  return {
    since, hours, learningSince,
    score: scores.length ? { from: scores[0].score, to: scores[scores.length - 1].score } : null,
    newApps: real('app', seen('app')),
    // A kind of startup item that only just became visible (browser extensions arrive with Full Disk
    // Access) is not "new": count items only after Hashling could already see their kind.
    newStartupItems: real('persist', seen('persist')).filter((r) => {
      const kind = (r as { kind?: string }).kind;
      const start = kind ? (db.prepare("SELECT MIN(first_seen) AS t FROM seen WHERE kind = 'persist' AND json_extract(data, '$.kind') = ?").get(kind) as { t: number | null }).t : null;
      return !start || r.firstSeen > start + 120_000;
    }),
    newPermissions: real('tcc', seen('tcc')),
    newDestinations: real('net', seen('net', 80)),
    newListeningPorts: real('listen', seen('listen')),
    // Simulator runtimes mount Apple's own binaries under cryptexd; they are not new software.
    newPrograms: real('exe', seen('exe', 120)).filter((r) => !/^\/private\/var\/run\/com\.apple\.security\.cryptexd\/|\/CoreSimulator\//.test(r.key)).slice(0, 80),
    // One entry per file: auto-updaters rewrite the same app several times.
    downloads: db.prepare('SELECT name, kind, from_url, signer, notarized, MAX(ts) AS ts FROM downloads WHERE ts >= ? GROUP BY path ORDER BY ts DESC LIMIT 50').all(since),
    findingsOpened: findingsOpened.map((f) => ({ id: f.id, tier: f.tier, title: f.title, status: f.status, at: f.first_seen })),
    incidents: (getSnapshot<{ incidents: { name: string; severity: string; stages: string[] }[] }>('incidents')?.data?.incidents ?? []),
  };
}
