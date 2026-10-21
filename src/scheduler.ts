import { SCHEDULE, BIN } from './config.ts';
import { run } from './lib/exec.ts';
import { collectNetwork } from './collectors/network.ts';
import { collectPosture } from './collectors/posture.ts';
import { collectPersistence } from './collectors/persistence.ts';
import { collectPermissions } from './collectors/permissions.ts';
import { collectLocation } from './collectors/location.ts';
import { collectTrackers } from './collectors/trackers.ts';
import { collectAttackPacks } from './collectors/attackPacks.ts';
import { collectAgents } from './collectors/agents.ts';
import { collectProcesses, refreshProcessFindings, pruneProcesses, processSnapshot } from './collectors/processes.ts';
import { collectBehavior } from './collectors/behavior.ts';
import { collectNetSafety } from './collectors/netsafety.ts';
import { collectSecrets } from './collectors/secrets.ts';
import { collectWebNotifications, collectBrowserHijacks } from './collectors/webnotify.ts';
import { collectSensors } from './collectors/sensors.ts';
import { collectPups } from './collectors/pups.ts';
import { collectVisits } from './collectors/visits.ts';
import { collectNotarization } from './collectors/notarization.ts';
import { collectStorage } from './collectors/storage.ts';
import { startDownloadWatch, refreshDownloadFindings } from './collectors/downloads.ts';
import { updateFeeds, loadFeeds } from './intel/feeds.ts';
import { updateYaraForge, updateElasticMacRules, collectOutdated } from './intel/extras.ts';
import { correlate } from './intel/correlate.ts';
import { startRansomwareWatch } from './intel/ransomware.ts';
import { pruneHistory, recordScore } from './history.ts';
import { routineScan, updateSignatures, refreshScanFindings, weeklyFullScan } from './scanner.ts';
import { pruneOld } from './db.ts';
import { bus } from './bus.ts';

export interface CollectorStatus { lastRun: number | null; ok: boolean | null; error: string | null; durationMs: number | null; running: boolean; every: number }

const COLLECTORS: Record<string, { every: number; fn: () => Promise<void> | void }> = {
  network: { every: SCHEDULE.network, fn: collectNetwork },
  posture: { every: SCHEDULE.posture, fn: collectPosture },
  persistence: { every: SCHEDULE.persistence, fn: collectPersistence },
  permissions: { every: SCHEDULE.permissions, fn: collectPermissions },
  location: { every: SCHEDULE.location, fn: collectLocation },
  trackers: { every: SCHEDULE.trackers, fn: collectTrackers },
  attackPacks: { every: SCHEDULE.attackPacks, fn: collectAttackPacks },
  agents: { every: SCHEDULE.agents, fn: collectAgents },
  processes: { every: SCHEDULE.processes, fn: collectProcesses },
  behavior: { every: SCHEDULE.behavior, fn: collectBehavior },
  intel: { every: SCHEDULE.intel, fn: () => updateFeeds() },
  netsafety: { every: SCHEDULE.netsafety, fn: collectNetSafety },
  secrets: { every: SCHEDULE.secrets, fn: collectSecrets },
  webnotify: { every: 30 * 60, fn: collectWebNotifications },
  browserhijack: { every: 30 * 60, fn: collectBrowserHijacks },
  sensors: { every: 5 * 60, fn: collectSensors },
  pups: { every: 30 * 60, fn: collectPups },
  visits: { every: 2 * 60, fn: collectVisits },
  notarization: { every: SCHEDULE.notarization, fn: collectNotarization },
  storage: { every: SCHEDULE.storage, fn: collectStorage },
  yaraForge: { every: 7 * 86_400, fn: updateYaraForge },
  elasticRules: { every: 7 * 86_400, fn: updateElasticMacRules },
  correlate: { every: 60, fn: correlate },
  outdated: { every: 86_400, fn: collectOutdated },
  score: { every: SCHEDULE.score, fn: async () => { const { overview } = await import('./overview.ts'); const o = overview(); recordScore(o.score, o.tiers); } },
  signatures: { every: SCHEDULE.signatures, fn: updateSignatures },
  routineScan: { every: SCHEDULE.routineScan, fn: routineScan },
  fullScan: { every: 3600, fn: weeklyFullScan },
  housekeeping: { every: 3600, fn: () => { pruneOld(); pruneHistory(); pruneProcesses(); refreshScanFindings(); refreshProcessFindings(); refreshDownloadFindings(); } },
};

export const status: Record<string, CollectorStatus> = Object.fromEntries(
  Object.entries(COLLECTORS).map(([k, c]) => [k, { lastRun: null, ok: null, error: null, durationMs: null, running: false, every: c.every }]),
);

export const collectorNames = Object.keys(COLLECTORS);

export async function runCollector(name: string): Promise<CollectorStatus> {
  const c = COLLECTORS[name];
  const s = status[name];
  if (!c || !s) throw new Error(`Unknown collector ${name}`);
  if (s.running) return s;
  s.running = true;
  const t = Date.now();
  try {
    await c.fn();
    s.ok = true;
    s.error = null;
  } catch (e) {
    s.ok = false;
    s.error = String((e as Error).message ?? e).slice(0, 500);
    console.error(`[${name}]`, s.error);
  } finally {
    s.running = false;
    s.lastRun = Date.now();
    s.durationMs = s.lastRun - t;
    if (c.every >= 10) bus.emit('change', { type: 'status', name });
  }
  return s;
}

/** Start every collector, staggered so the first minute is not a CPU spike. */
export function startScheduler(opts: { skip?: string[] } = {}): void {
  loadFeeds();
  processSnapshot();
  // Real-time triggers (e.g. a startup folder changed) run a collector now instead of waiting.
  const pendingTriggers = new Map<string, NodeJS.Timeout>();
  bus.on('trigger', (name: string) => {
    if (!COLLECTORS[name]) return;
    clearTimeout(pendingTriggers.get(name));
    pendingTriggers.set(name, setTimeout(() => void runCollector(name), 1000));
  });
  // macOS checks a newly installed helper the first time it runs (it can take ~45 s); do that now, not when someone is waiting.
  void run(BIN.ocr, [], { timeout: 120_000 }).catch(() => undefined);
  if (!opts.skip?.includes('downloads')) startDownloadWatch();
  if (!opts.skip?.includes('ransomware')) startRansomwareWatch();
  const order = ['posture', 'network', 'processes', 'persistence', 'permissions', 'location', 'trackers', 'agents', 'netsafety', 'secrets', 'housekeeping', 'intel', 'behavior', 'correlate', 'attackPacks', 'score', 'signatures', 'yaraForge', 'outdated', 'notarization', 'storage', 'routineScan'];
  // Anything not listed above still runs, after the core collectors (so a new collector can never be forgotten).
  order.push(...Object.keys(COLLECTORS).filter((k) => !order.includes(k)));
  order.forEach((name, i) => {
    if (opts.skip?.includes(name)) return;
    const c = COLLECTORS[name];
    const delay = name === 'routineScan' ? 10 * 60_000 : name === 'signatures' ? 2 * 60_000 : name === 'notarization' ? 4 * 60_000 : name === 'yaraForge' ? 3 * 60_000 : name === 'outdated' ? 5 * 60_000 : name === 'storage' ? 6 * 60_000 : i * 1500;
    setTimeout(() => {
      void runCollector(name);
      setInterval(() => void runCollector(name), c.every * 1000).unref();
    }, delay).unref();
  });
}
