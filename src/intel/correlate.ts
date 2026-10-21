/**
 * Storylines: individual signals are often weak on their own; together they
 * tell the story of an infection. Hashling links signals that share the same
 * program into one incident with a timeline, and escalates its severity as
 * more stages appear (the "kill chain"):
 *   arrived (download) -> ran (process) -> stayed (startup item)
 *   -> called home (new destinations, beacons, threat-feed hits) -> misbehaved (rule hits)
 * The same idea drives EDR "storylines" and correlation rules in open-source SIEMs like Wazuh.
 */
import { basename } from 'node:path';
import { db, getSnapshot, listFindings, now, parseJson, putSnapshot, syncFindings, type FindingInput, type Severity } from '../db.ts';
import { bundleOf } from '../lib/procs.ts';
import { APP_PATH } from '../config.ts';

type Stage = 'arrived' | 'ran' | 'stayed' | 'called-home' | 'misbehaved';
interface Step { ts: number; stage: Stage; text: string; weight: number }

const STAGE_LABEL: Record<Stage, string> = { arrived: 'Arrived', ran: 'Ran', stayed: 'Set itself to start automatically', 'called-home': 'Called home', misbehaved: 'Did something suspicious' };

export function correlate(): void {
  const since = now() - 3 * 86_400_000;
  const stories = new Map<string, { name: string; root: string; steps: Step[] }>();
  const add = (path: string | null | undefined, step: Step) => {
    if (!path || path.startsWith('/System/') || path.startsWith('/usr/') || path.startsWith('/bin/') || path.startsWith('/sbin/')) return;
    // Hashling itself: every update arrives, runs and starts at login, which is not an infection.
    if (path === APP_PATH || path.startsWith(`${APP_PATH}/`)) return;
    const root = bundleOf(path) ?? path;
    const s = stories.get(root) ?? { name: basename(root).replace(/\.app$/, ''), root, steps: [] };
    s.steps.push(step);
    stories.set(root, s);
  };

  // Arrived: downloads that are not plainly trustworthy.
  for (const d of db.prepare('SELECT * FROM downloads WHERE ts >= ?').all(since) as Record<string, any>[]) {
    const intel = parseJson<{ feed: string } | null>(d.intel, null);
    const rep = parseJson<{ verdict: string } | null>(d.rep, null);
    const untrusted = ['unsigned', 'adhoc', 'invalid'].includes(d.signer_kind) || d.notarized === 'rejected';
    if (!intel && rep?.verdict !== 'malicious' && !untrusted) continue;
    add(d.path, { ts: d.ts, stage: 'arrived', weight: intel || rep?.verdict === 'malicious' ? 3 : 1, text: `Downloaded ${d.name}${d.from_url ? ` from ${safeHost(d.from_url)}` : ''}${intel ? ' (known malware host)' : ''}${rep?.verdict === 'malicious' ? ' (matches known malware)' : untrusted ? ' (not checked by Apple)' : ''}` });
  }
  // Ran + misbehaved: process history.
  for (const r of db.prepare('SELECT path, MIN(ts) AS first, COUNT(*) AS n FROM proc_history WHERE ts >= ? GROUP BY path').all(since) as { path: string; first: number; n: number }[]) {
    if (stories.has(bundleOf(r.path) ?? r.path)) add(r.path, { ts: r.first, stage: 'ran', weight: 1, text: `Started running (${r.n} time${r.n > 1 ? 's' : ''})` });
  }
  for (const r of db.prepare('SELECT ts, path, name, rule, parent FROM proc_history WHERE rule IS NOT NULL AND ts >= ?').all(since) as Record<string, any>[]) {
    add(r.path, { ts: r.ts, stage: 'misbehaved', weight: 3, text: `${r.name}: ${String(r.rule).replace(/-/g, ' ')}` });
  }
  // Stayed: new startup items.
  for (const i of getSnapshot<{ items: { label: string; program?: string; isNew?: boolean; firstSeen: number; flags: string[] }[] }>('persistence')?.data?.items ?? []) {
    if (i.isNew || i.flags?.some((f) => ['script-download', 'risky-location', 'invalid-signature'].includes(f))) add(i.program, { ts: i.firstSeen, stage: 'stayed', weight: 2, text: `Added startup item ${i.label}` });
  }
  // Called home: threat-feed hits and beacons.
  for (const f of listFindings({ status: 'active', category: 'network' })) {
    const path = (f.evidence as { path?: string }).path;
    if (f.key.startsWith('intel:')) add(path, { ts: f.first_seen, stage: 'called-home', weight: 3, text: f.summary });
  }
  for (const b of getSnapshot<{ beacons: { path: string; dest: string; intervalSec: number; suspicious: boolean; lastSeen: number }[] }>('behavior')?.data?.beacons ?? []) {
    if (b.suspicious) add(b.path, { ts: b.lastSeen, stage: 'called-home', weight: 2, text: `Checks in with ${b.dest} every ${b.intervalSec}s` });
  }

  const incidents: { id: string; name: string; root: string; severity: Severity; stages: Stage[]; steps: Step[] }[] = [];
  const findings: FindingInput[] = [];
  for (const s of stories.values()) {
    const stages = [...new Set(s.steps.map((x) => x.stage))];
    // Count each stage once (an app that re-installs itself is not three warning signs), and require a
    // real red flag: arriving and running is just installing and opening an app.
    const weight = stages.reduce((n, st) => n + Math.max(...s.steps.filter((x) => x.stage === st).map((x) => x.weight)), 0);
    if (stages.length < 2 || weight < 3 || !stages.some((st) => st === 'stayed' || st === 'called-home' || st === 'misbehaved')) continue;
    const severity: Severity = stages.length >= 4 || weight >= 9 ? 'critical' : stages.length >= 3 || weight >= 6 ? 'high' : 'medium';
    const steps = s.steps.sort((a, b) => a.ts - b.ts);
    incidents.push({ id: s.root, name: s.name, root: s.root, severity, stages, steps });
    findings.push({
      key: `incident:${s.root}`, category: 'incidents', severity,
      title: `${s.name}: ${stages.length} warning signs that fit together`,
      summary: stages.map((x) => STAGE_LABEL[x]).join(' → '),
      explanation: 'Each of these signals could be harmless alone. Together they follow the pattern of an infection: software arrives, runs, makes itself start automatically and contacts a server. I linked them because they all involve the same program.',
      recommendation: `Open the storyline to see each step. If you do not recognise ${s.name}, quarantine it, disable its startup items, and run a full scan.`,
      evidence: { root: s.root, steps },
      actions: [{ type: 'quarantine_file', target: { path: s.root }, label: 'Quarantine it' }],
    });
  }
  incidents.sort((a, b) => b.steps.length - a.steps.length);
  putSnapshot('incidents', { at: now(), incidents });
  syncFindings('incidents', findings);
}

function safeHost(url: string): string { try { return new URL(url).hostname; } catch { return url; } }
