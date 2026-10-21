import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { BIN } from '../config.ts';
import { osquery, osqueryAvailable } from '../lib/osquery.ts';
import { putSnapshot, syncFindings, type FindingInput } from '../db.ts';

interface PackQuery { query: string; description?: string; value?: string; platform?: string }

/** The osquery project's own detection packs for known Mac malware and unwanted extensions. */
const PACKS = ['osx-attacks.conf', 'unwanted-chrome-extensions.conf'];

function loadPack(file: string): Record<string, PackQuery> {
  const path = join(BIN.osqueryPacks, file);
  if (!existsSync(path)) return {};
  const text = readFileSync(path, 'utf8').replace(/\\\r?\n/g, ' ');
  try {
    const pack = JSON.parse(text) as { platform?: string; queries: Record<string, PackQuery> };
    return pack.queries ?? {};
  } catch {
    return {};
  }
}

/** Run the query for the current user only; browser tables need a users join. */
function adapt(sql: string): string {
  const uid = process.getuid?.() ?? 501;
  return sql.replace(/\bfrom\s+(chrome_extensions|firefox_addons|safari_extensions)\b/gi,
    (_m, t) => `FROM (SELECT ${t}.* FROM users JOIN ${t} USING (uid) WHERE users.uid = ${uid}) AS ${t}`);
}

export async function collectAttackPacks(): Promise<void> {
  if (!osqueryAvailable()) {
    putSnapshot('attackPacks', { at: Date.now(), ran: 0, hits: [] }, 'osquery is not installed.');
    return;
  }
  const queries: { pack: string; name: string; q: PackQuery }[] = [];
  for (const p of PACKS) for (const [name, q] of Object.entries(loadPack(p))) if (!q.platform || /darwin|posix|all/.test(q.platform)) queries.push({ pack: p.replace('.conf', ''), name, q });

  const hits: { pack: string; name: string; description?: string; rows: Record<string, string>[] }[] = [];
  const errors: string[] = [];
  let i = 0;
  const worker = async () => {
    while (i < queries.length) {
      const { pack, name, q } = queries[i++];
      const sql = adapt(q.query.trim());
      const r = await osquery(sql, 20_000);
      if (r.error && !r.rows.length) errors.push(`${name}: ${r.error.slice(0, 120)}`);
      if (r.rows.length) hits.push({ pack, name, description: q.description, rows: r.rows.slice(0, 20) });
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);

  const findings: FindingInput[] = hits.map((h) => ({
    key: `attack:${h.pack}:${h.name}`, category: 'malware', severity: h.pack === 'osx-attacks' ? 'high' : 'medium',
    title: h.pack === 'osx-attacks' ? `Known Mac malware artifact found: ${h.name}` : `Known unwanted browser extension: ${h.name}`,
    summary: `${h.rows.length} match(es). ${h.description ?? ''}`.trim(),
    explanation: `This matched a detection from osquery's ${h.pack} pack, which looks for files, startup items and extensions that specific malware families are known to leave behind. A match means an artifact with that exact name or location exists; occasionally a legitimate file shares a name.`,
    recommendation: 'Look at the matched paths. If they are not something you installed on purpose, quarantine them and scan the folder.',
    evidence: { pack: h.pack, query: h.name, rows: h.rows, reference: h.description },
    actions: h.rows.flatMap((r) => (r.path && r.path.startsWith('/') ? [{ type: 'quarantine_file', target: { path: r.path }, label: `Quarantine ${r.path.split('/').pop()}` }] : [])).slice(0, 3),
  }));

  putSnapshot('attackPacks', { at: Date.now(), ran: queries.length, hits, errors: errors.slice(0, 20) });
  syncFindings('malware-artifacts', findings);
}
