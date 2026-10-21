/**
 * App dossier: everything Hashling knows about one program, from every engine,
 * combined into a single risk score with the reasons behind it. This is the
 * "connect the dots" view an on-demand agent cannot build by itself, because it
 * draws on history Hashling has been collecting all along.
 */
import { existsSync } from 'node:fs';
import { basename } from 'node:path';
import { db, getSnapshot, listFindings, parseJson, now } from '../db.ts';
import { listProcs, bundleOf, appOf, ancestry } from '../lib/procs.ts';
import { signInfo, describeSigner, riskyLocation } from '../lib/codesign.ts';
import { agentName, processNote } from '../knowledge.ts';
import { reputation } from './reputation.ts';
import { readPlist, run } from '../lib/exec.ts';

export interface Factor { points: number; label: string; detail?: string; good?: boolean }

interface NetProcLite { pid: number; app: string; path: string; rateIn: number; rateOut: number; connections: { external: boolean; org?: string; host?: string; remote: string; remotePort: number; country?: string; intel?: { feed: string; label: string } }[]; listening: { port: number; exposed: boolean }[] }

/** Resolve "Slack", a pid, a path, or a bundle id to a program on disk. */
export async function resolveApp(query: string | number): Promise<{ name: string; path: string; bundle: string | null } | null> {
  const procs = await listProcs();
  if (typeof query === 'number' || /^\d+$/.test(String(query))) {
    const p = procs.get(Number(query));
    return p ? { name: p.app, path: p.path, bundle: bundleOf(p.path) } : null;
  }
  const q = String(query).trim();
  if (q.startsWith('/') || q.startsWith('~')) {
    const path = q.replace(/^~/, process.env.HOME ?? '');
    return existsSync(path) ? { name: appOf(path) ?? basename(path), path, bundle: bundleOf(path) ?? (path.endsWith('.app') ? path : null) } : null;
  }
  const lower = q.toLowerCase();
  for (const p of procs.values()) if (p.app.toLowerCase() === lower || p.name.toLowerCase() === lower) return { name: p.app, path: p.path, bundle: bundleOf(p.path) };
  const apps = getSnapshot<{ apps: { name: string; path: string }[] }>('notarization')?.data?.apps ?? [];
  const hit = apps.find((a) => a.name.toLowerCase() === lower) ?? apps.find((a) => a.name.toLowerCase().includes(lower));
  if (hit) return { name: hit.name, path: hit.path, bundle: hit.path };
  for (const p of procs.values()) if (p.app.toLowerCase().includes(lower)) return { name: p.app, path: p.path, bundle: bundleOf(p.path) };
  return null;
}

export async function dossier(query: string | number) {
  const target = await resolveApp(query);
  if (!target) return { error: `I couldn’t find a program matching "${query}".` };
  const root = target.bundle ?? target.path;
  const inApp = (p?: string | null) => Boolean(p) && (p === target.path || p!.startsWith(root + '/') || p === root);
  const factors: Factor[] = [];

  // Identity
  const sign = await signInfo(root);
  const info = target.bundle ? await readPlist<Record<string, unknown>>(`${target.bundle}/Contents/Info.plist`) : null;
  const bundleId = (info?.CFBundleIdentifier as string) ?? null;
  const version = (info?.CFBundleShortVersionString as string) ?? null;
  const notarized = (getSnapshot<{ apps: { path: string; verdict: string }[] }>('notarization')?.data?.apps ?? []).find((a) => a.path === target.bundle)?.verdict ?? null;
  const rep = await reputation(root).catch(() => null);
  const xattr = await run('/usr/bin/xattr', ['-p', 'com.apple.quarantine', root], { timeout: 4000 });
  const dl = db.prepare('SELECT * FROM downloads WHERE path = ? OR ? LIKE path || \'%\' ORDER BY ts DESC LIMIT 1').get(root, root) as Record<string, any> | undefined;
  const firstRun = db.prepare('SELECT MIN(ts) AS t FROM proc_history WHERE path = ? OR path LIKE ?').get(target.path, root + '/%') as { t: number | null };

  if (sign.kind === 'apple') factors.push({ points: -30, label: 'Signed by Apple', good: true });
  else if (sign.kind === 'app-store') factors.push({ points: -25, label: 'From the Mac App Store', good: true });
  else if (sign.kind === 'developer-id') factors.push({ points: -10, label: `Signed by ${describeSigner(sign)}`, good: true });
  else if (sign.kind === 'invalid') factors.push({ points: 40, label: 'Signature is broken (file was modified)' });
  else if (sign.kind === 'unsigned' || sign.kind === 'adhoc') factors.push({ points: /^\/(opt\/homebrew|usr\/local)/.test(root) ? 5 : 20, label: 'No developer identity', detail: describeSigner(sign) });
  if (notarized === 'notarized') factors.push({ points: -10, label: 'Notarized by Apple', good: true });
  if (notarized === 'rejected') factors.push({ points: 15, label: 'Not checked by Apple' });
  if (rep?.verdict === 'malicious') factors.push({ points: 80, label: 'Matches known malware', detail: rep.avDetectionPct ? `${rep.avDetectionPct}% of AV engines` : rep.knownMalicious });
  if (rep?.verdict === 'known-good') factors.push({ points: -10, label: 'Known legitimate file (CIRCL / NSRL)', good: true });
  const risky = riskyLocation(target.path);
  if (risky) factors.push({ points: 25, label: `Runs from ${risky}` });
  if (dl?.intel) factors.push({ points: 50, label: 'Downloaded from a known malware host', detail: dl.from_url });

  // Runtime
  const procs = await listProcs();
  const running = [...procs.values()].filter((p) => inApp(p.path));
  const startedBy = running[0] ? ancestry(running[0].pid, procs, 6).map((p) => ({ name: p.name, agent: agentName(p.path, p.name) })) : [];
  const viaAgent = startedBy.find((p) => p.agent && p.agent.toLowerCase() !== target.name.toLowerCase())?.agent ?? null;
  if (viaAgent) factors.push({ points: 0, label: `Started by ${viaAgent}` });

  // Network (now + history)
  const net = (getSnapshot<{ processes: NetProcLite[] }>('network')?.data?.processes ?? []).filter((p) => inApp(p.path));
  const conns = net.flatMap((p) => p.connections.filter((c) => c.external));
  const intelHits = conns.filter((c) => c.intel);
  if (intelHits.length) factors.push({ points: 60, label: 'Talking to known-malicious servers', detail: intelHits.map((c) => `${c.remote} (${c.intel!.label})`).join(', ') });
  const exposed = net.flatMap((p) => p.listening.filter((l) => l.exposed).map((l) => l.port));
  if (exposed.length) { const ports = [...new Set(exposed)]; factors.push({ points: 5, label: 'Other devices on your network can connect to it', detail: `port${ports.length > 1 ? 's' : ''} ${ports.slice(0, 3).join(', ')}${ports.length > 3 ? ` and ${ports.length - 3} more` : ''}` }); }
  const appName = net[0]?.app ?? target.name;
  const destinations = db.prepare(`SELECT data, first_seen, last_seen, count FROM seen WHERE kind = 'net' AND key LIKE ? ORDER BY last_seen DESC LIMIT 40`).all(`${appName}|%`) as { data: string; first_seen: number; last_seen: number; count: number }[];
  const traffic = db.prepare('SELECT SUM(bytes_in) AS i, SUM(bytes_out) AS o FROM traffic WHERE app = ? AND minute >= ?').get(appName, now() - 86_400_000) as { i: number | null; o: number | null };
  const beacons = (getSnapshot<{ beacons: { app: string; path: string; dest: string; intervalSec: number; suspicious: boolean }[] }>('behavior')?.data?.beacons ?? []).filter((b) => b.app === appName || inApp(b.path));
  if (beacons.some((b) => b.suspicious)) factors.push({ points: 30, label: 'Checks in with a server on a fixed schedule', detail: beacons.filter((b) => b.suspicious).map((b) => `${b.dest} every ${b.intervalSec}s`).join(', ') });

  // Persistence & permissions
  const persist = (getSnapshot<{ items: { kind: string; label: string; program?: string; plist?: string; isNew?: boolean }[] }>('persistence')?.data?.items ?? []).filter((i) => inApp(i.program));
  if (persist.length) factors.push({ points: persist.some((p) => p.isNew) ? 15 : 5, label: `Starts automatically (${persist.length} startup item${persist.length > 1 ? 's' : ''})`, detail: persist.map((p) => p.label).join(', ') });
  const grants = (getSnapshot<{ grants: { client: string; label: string; risk: string }[] }>('permissions')?.data?.grants ?? []).filter((g) => (bundleId && g.client === bundleId) || inApp(g.client));
  const powerful = grants.filter((g) => g.risk === 'high');
  if (powerful.length) factors.push({ points: 10, label: `Holds powerful permissions`, detail: powerful.map((g) => g.label).join(', ') });

  // Behaviour on this Mac
  const ruleHits = db.prepare('SELECT ts, name, args, rule, agent FROM proc_history WHERE rule IS NOT NULL AND (path = ? OR path LIKE ? OR parent = ?) ORDER BY ts DESC LIMIT 20').all(target.path, root + '/%', basename(target.path)) as Record<string, any>[];
  if (ruleHits.length) factors.push({ points: 35, label: 'Ran commands matching malware techniques', detail: [...new Set(ruleHits.map((r) => r.rule))].join(', ') });
  // Skip names ps could not read: processes that already exited show as "(name)" or "<defunct>".
  const children = db.prepare("SELECT name, COUNT(*) AS n, MAX(ts) AS last FROM proc_history WHERE parent = ? AND ts >= ? AND name NOT LIKE '(%' AND name NOT LIKE '<%' GROUP BY name ORDER BY n DESC LIMIT 15").all(basename(target.path), now() - 7 * 86_400_000);
  // "New" only means something once Hashling has watched for a while before it first ran.
  const historyStart = (db.prepare('SELECT MIN(ts) AS t FROM proc_history').get() as { t: number | null }).t ?? now();
  const isNew = firstRun.t && now() - firstRun.t < 86_400_000 && firstRun.t - historyStart > 2 * 86_400_000;
  if (isNew) factors.push({ points: 5, label: 'First seen running in the last 24 hours' });

  const findings = listFindings({ status: 'active' }).filter((f) => JSON.stringify(f.evidence).includes(root) || f.title.includes(target.name));
  const score = Math.max(0, Math.min(100, 20 + factors.reduce((n, f) => n + f.points, 0)));
  const level = score >= 70 ? 'high' : score >= 40 ? 'medium' : score >= 20 ? 'low' : 'minimal';

  return {
    name: target.name, path: target.path, bundle: target.bundle, bundleId, version, note: processNote(basename(target.path)),
    risk: { score, level, factors: factors.sort((a, b) => b.points - a.points) },
    identity: { signer: describeSigner(sign), signerKind: sign.kind, team: sign.team, notarized, reputation: rep && { verdict: rep.verdict, sha256: rep.sha256, avDetectionPct: rep.avDetectionPct, knownName: rep.knownName }, downloadedFrom: dl?.from_url ?? null, quarantineAgent: xattr.ok ? xattr.stdout.split(';')[2] : null, firstSeenRunning: firstRun.t },
    running: running.map((p) => ({ pid: p.pid, name: p.name })), startedBy, viaAgent,
    network: {
      now: conns.slice(0, 20).map((c) => ({ dest: c.org ?? c.host ?? c.remote, host: c.host, ip: c.remote, port: c.remotePort, country: c.country, intel: c.intel ?? null })),
      destinations7d: destinations.map((d) => ({ ...parseJson<Record<string, unknown>>(d.data, {}), firstSeen: d.first_seen, lastSeen: d.last_seen })),
      last24h: { bytesIn: traffic.i ?? 0, bytesOut: traffic.o ?? 0 },
      beacons, exposedPorts: [...new Set(exposed)],
    },
    persistence: persist, permissions: grants, ruleHits, childProcesses7d: children,
    findings: findings.map((f) => ({ id: f.id, tier: f.tier, title: f.title })),
  };
}
