import { existsSync } from 'node:fs';
import { BIN } from '../config.ts';
import { run } from '../lib/exec.ts';
import { putSnapshot, syncFindings, logEvent, type FindingInput } from '../db.ts';

/** One BLE advertiser as reported by the hashling-ble helper. */
interface Adv {
  id: string;
  name?: string;
  rssi: number;
  mfg?: string;       // manufacturer data, hex, starting with company id (little endian)
  services?: string[];
  count: number;
}

export interface Tracker {
  id: string;
  kind: 'findmy-separated' | 'findmy-nearby-owner' | 'tile' | 'samsung-smarttag' | 'chipolo' | 'other';
  label: string;
  rssi: number;
  distance: string;
  firstSeen: number;
  lastSeen: number;
  sightings: number;
  suspicious: boolean;
}

const history = new Map<string, Tracker>();
const FOLLOW_MS = 30 * 60_000;

function classify(a: Adv): Tracker['kind'] | null {
  const mfg = (a.mfg ?? '').toLowerCase();
  if (mfg.startsWith('4c00')) {
    // Apple: type 0x12 = Find My (offline finding). Length 0x19 = separated from owner, 0x02 = near owner.
    const type = mfg.slice(4, 6), len = parseInt(mfg.slice(6, 8), 16);
    if (type === '12') return len >= 0x19 ? 'findmy-separated' : 'findmy-nearby-owner';
    if (type === '07' && len >= 0x19) return 'findmy-separated'; // AirTag sound/pairing state
    return null;
  }
  const svc = (a.services ?? []).map((s) => s.toUpperCase());
  if (svc.some((s) => s === 'FEED' || s === 'FEEC' || s === 'FD84')) return 'tile';
  if (svc.includes('FD5A')) return 'samsung-smarttag';
  if (svc.includes('FE33') || svc.includes('FE65')) return 'chipolo';
  return null;
}

const LABEL: Record<Tracker['kind'], string> = {
  'findmy-separated': 'Find My device away from its owner (AirTag or similar)',
  'findmy-nearby-owner': 'Find My device near its owner',
  tile: 'Tile tracker',
  'samsung-smarttag': 'Samsung SmartTag',
  chipolo: 'Chipolo tracker',
  other: 'Tracker',
};

function distance(rssi: number): string {
  if (rssi >= -55) return 'very close (within ~1 m)';
  if (rssi >= -70) return 'close (a few metres)';
  if (rssi >= -85) return 'in the room or next door';
  return 'far away';
}

export async function collectTrackers(): Promise<void> {
  if (!existsSync(BIN.ble)) {
    putSnapshot('trackers', { at: Date.now(), trackers: [], scanning: false }, 'The Bluetooth scanner helper is not built yet. Run `npm run helpers`.');
    return;
  }
  const r = await run(BIN.ble, ['--seconds', '12'], { timeout: 30_000 });
  let advs: Adv[] = [];
  let error: string | null = null;
  try {
    const parsed = JSON.parse(r.stdout || '{}') as { state?: string; devices?: Adv[]; error?: string };
    advs = parsed.devices ?? [];
    if (parsed.error) error = parsed.error;
    if (parsed.state && parsed.state !== 'poweredOn') error = parsed.state === 'unauthorized'
      ? 'I need Bluetooth permission to look for trackers. Allow it for Hashling in System Settings > Privacy & Security > Bluetooth.'
      : parsed.state === 'poweredOff' ? 'Bluetooth is off, so I can’t look for trackers.'
        : 'Bluetooth access has not been granted yet. I ask for it the first time I run as Hashling.app.';
  } catch {
    error = `Bluetooth scan failed: ${(r.stderr || r.stdout).slice(0, 200)}`;
  }

  const t = Date.now();
  for (const a of advs) {
    const kind = classify(a);
    if (!kind) continue;
    const prev = history.get(a.id);
    const tr: Tracker = prev
      ? { ...prev, rssi: a.rssi, lastSeen: t, sightings: prev.sightings + 1, distance: distance(a.rssi) }
      : { id: a.id, kind, label: LABEL[kind], rssi: a.rssi, distance: distance(a.rssi), firstSeen: t, lastSeen: t, sightings: 1, suspicious: false };
    tr.suspicious = kind === 'findmy-separated' && tr.sightings >= 3 && tr.lastSeen - tr.firstSeen >= FOLLOW_MS;
    if (tr.suspicious && !prev?.suspicious) logEvent('tracker', 'high', 'A Find My tracker away from its owner keeps showing up near you', { id: tr.id, rssi: tr.rssi });
    history.set(a.id, tr);
  }
  for (const [id, tr] of history) if (t - tr.lastSeen > 2 * 3600_000) history.delete(id);

  const current = [...history.values()].filter((x) => t - x.lastSeen < 10 * 60_000).sort((a, b) => Number(b.suspicious) - Number(a.suspicious) || b.rssi - a.rssi);
  const findings: FindingInput[] = current.filter((x) => x.suspicious).map((x) => ({
    key: `tracker:${x.id}`, category: 'trackers', severity: 'high',
    title: 'Unknown AirTag-style tracker has been near you for a while',
    summary: `Seen ${x.sightings} times over ${Math.round((x.lastSeen - x.firstSeen) / 60_000)} minutes, currently ${x.distance}.`,
    explanation: 'This device is part of Apple\'s Find My network and is in "separated from owner" mode, so its owner is not nearby, yet it has stayed close to this Mac. If you have moved around (different rooms, café, car) and it kept showing up, someone may be tracking your bag, car or belongings. A neighbour\'s lost item can also cause this when you have not moved.',
    recommendation: 'Check your bag, jacket, car and laptop sleeve. On an iPhone, open Find My > Items > Identify Found Item, or use "Unknown items" alerts. If you feel unsafe, contact local support services before removing it.',
    evidence: x as unknown as Record<string, unknown>,
  }));

  putSnapshot('trackers', { at: t, trackers: current, scanning: true, devicesHeard: advs.length }, error);
  syncFindings('trackers', findings);
}
