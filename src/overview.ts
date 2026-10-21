import { NAME, VERSION } from './config.ts';
import { listFindings, getSnapshot, listEvents, SEVERITY_RANK } from './db.ts';
import { status } from './scheduler.ts';
import { engines, listScans } from './scanner.ts';
import { listActions } from './actions.ts';

/** Everything an agent (or the dashboard header) needs in one call. */
export function overview() {
  const findings = listFindings({ status: 'active' });
  const open = findings.filter((f) => f.status === 'open');
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of open) bySeverity[f.severity]++;
  const posture = getSnapshot<{ score: number; os: string; checks: { id: string; label: string; status: string; detail: string }[] }>('posture');
  const net = getSnapshot<{ summary: Record<string, unknown> }>('network');
  const trackers = getSnapshot<{ trackers: { suspicious: boolean }[] }>('trackers');
  const perms = getSnapshot<{ grants: unknown[] }>('permissions');
  const agents = getSnapshot<{ agents: { name: string; risk: string; running: boolean; riskReasons: string[] }[] }>('agents');

  // Optional hardening suggestions barely move the score; suspicious items weigh the most.
  const tierWeight = { suspicious: 1.5, risk: 1, hardening: 0.25 } as const;
  const cost = (f: (typeof open)[number]) => ({ critical: 25, high: 12, medium: 5, low: 1.5, info: 0 }[f.severity] ?? 0) * tierWeight[f.tier];
  const penalty = open.reduce((n, f) => n + cost(f), 0);
  const tiers = { suspicious: 0, risk: 0, hardening: 0 };
  for (const f of open) tiers[f.tier]++;
  const postureScore = posture?.data?.score ?? 70;
  const score = Math.max(0, Math.min(100, Math.round(postureScore - penalty)));
  // What the score is made of, so the dashboard can explain it and point at the biggest gain.
  const byTier = { suspicious: 0, risk: 0, hardening: 0 };
  for (const f of open) byTier[f.tier] += cost(f);
  const scoreBreakdown = {
    settings: postureScore,
    byTier: { suspicious: Math.round(byTier.suspicious), risk: Math.round(byTier.risk), hardening: Math.round(byTier.hardening) },
    topGains: [...open].sort((a, b) => cost(b) - cost(a)).slice(0, 3).map((f) => ({ id: f.id, title: f.title, points: Math.round(cost(f) * 10) / 10 })),
  };
  const verdict = tiers.suspicious ? 'Something looks suspicious'
    : tiers.risk ? (tiers.risk === 1 ? 'One risk worth fixing' : `${tiers.risk} risks worth fixing`)
      : tiers.hardening ? 'Looking good. A few optional improvements' : 'All clear';

  const access: string[] = [];
  if (getSnapshot('permissions')?.error) access.push(getSnapshot('permissions')!.error!);
  if (getSnapshot('trackers')?.error) access.push(getSnapshot('trackers')!.error!);
  // The location note is not something the user can fix, so it stays on the Tracking page only.

  return {
    product: `${NAME} ${VERSION}`,
    at: Date.now(),
    score,
    scoreBreakdown,
    verdict,
    os: posture?.data?.os,
    openFindings: bySeverity,
    tiers,
    topFindings: open.filter((f) => f.tier !== 'hardening').slice(0, 10).map((f) => ({ id: f.id, severity: f.severity, tier: f.tier, category: f.category, title: f.title, summary: f.summary, status: f.status })),
    suggestions: open.filter((f) => f.tier === 'hardening').slice(0, 10).map((f) => ({ id: f.id, severity: f.severity, tier: f.tier, category: f.category, title: f.title, summary: f.summary, status: f.status })),
    postureFailing: (posture?.data?.checks ?? []).filter((c) => c.status !== 'pass').map((c) => `${c.label}: ${c.detail}`),
    network: net?.data?.summary ?? null,
    agents: (agents?.data?.agents ?? []).map((a) => ({ name: a.name, risk: a.risk, running: a.running, reasons: a.riskReasons.slice(0, 4) })),
    trackers: { nearby: trackers?.data?.trackers?.length ?? 0, suspicious: trackers?.data?.trackers?.filter((t) => t.suspicious).length ?? 0 },
    permissionGrants: perms?.data?.grants?.length ?? null,
    pendingActions: listActions('pending').length,
    ignoredFindings: findings.filter((f) => f.status === 'acknowledged').length,
    lastScan: listScans(1)[0] ?? null,
    engines: engines(),
    limitations: access,
    collectors: status,
    recentEvents: listEvents(40).map((e) => ({ ts: e.ts, severity: e.severity, title: e.title })),
  };
}

/** Per-area "anything suspicious?" summary for the bar at the top of each dashboard view. */
export const AREAS: Record<string, { label: string; categories: string[]; collectors: string[]; clean: string }> = {
  network: { label: 'network activity', categories: ['network', 'behavior', 'netsafety', 'webvisits'], collectors: ['network', 'behavior', 'netsafety', 'visits'], clean: 'No suspicious network activity found' },
  processes: { label: 'processes', categories: ['processes'], collectors: ['processes'], clean: 'No suspicious commands seen' },
  downloads: { label: 'downloads', categories: ['downloads', 'notarization'], collectors: ['notarization'], clean: 'Nothing suspicious downloaded' },
  secrets: { label: 'exposed keys', categories: ['secrets'], collectors: ['secrets'], clean: 'No exposed keys found' },
  optimize: { label: 'storage', categories: ['storage'], collectors: ['storage'], clean: 'Plenty of space' },
  agents: { label: 'AI agent risks', categories: ['agents'], collectors: ['agents'], clean: 'Nothing suspicious in your AI apps' },
  scans: { label: 'malware', categories: ['malware', 'malware-artifacts', 'ransomware', 'pups'], collectors: ['attackPacks', 'routineScan'], clean: 'No malware found' },
  startup: { label: 'startup items', categories: ['persistence'], collectors: ['persistence'], clean: 'No suspicious startup items found' },
  permissions: { label: 'permissions', categories: ['permissions', 'webnotify', 'browser', 'sensors'], collectors: ['permissions', 'webnotify', 'browserhijack', 'sensors'], clean: 'No suspicious permissions found' },
  tracking: { label: 'tracking', categories: ['trackers', 'location'], collectors: ['trackers', 'location'], clean: 'No one appears to be tracking you' },
  system: { label: 'system settings', categories: ['posture', 'updates'], collectors: ['posture', 'outdated'], clean: 'All important security settings are on' },
};

export function suspicious() {
  const all = listFindings({ status: 'open' });
  const ignored = listFindings({ status: 'acknowledged' });
  const out: Record<string, unknown> = {};
  for (const [key, a] of Object.entries(AREAS)) {
    const items = all.filter((f) => a.categories.includes(f.category));
    const flagged = items.filter((f) => f.tier === 'suspicious');
    const pick = (f: typeof items[number]) => ({ id: f.id, severity: f.severity, tier: f.tier, title: f.title, summary: f.summary, status: f.status });
    // Slow collectors may not have run since a restart; their last saved result still counts.
    const runs = a.collectors.map((c) => status[c]?.lastRun || getSnapshot(c)?.updated_at || 0).filter(Boolean);
    out[key] = {
      label: a.label,
      clean: a.clean,
      count: flagged.length,
      worst: flagged[0]?.severity ?? null,
      risks: items.filter((f) => f.tier === 'risk').map(pick),
      suggestions: items.filter((f) => f.tier === 'hardening').map(pick),
      notes: 0,
      ignored: ignored.filter((f) => a.categories.includes(f.category)).length,
      checkedAt: runs.length ? Math.max(...runs) : null,
      // Missing access the user can grant: never show an all-clear for an area Hashling could not check.
      blocked: a.collectors.map((c) => getSnapshot(c)?.error).find((e) => e && /Full Disk Access|Bluetooth/.test(e)) ?? null,
      items: flagged.slice(0, 8).map(pick),
    };
  }
  return out;
}
