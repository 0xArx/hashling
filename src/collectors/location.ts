import { plural } from '../lib/text.ts';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { HOME } from '../config.ts';
import { readPlist } from '../lib/exec.ts';
import { putSnapshot, syncFindings, type FindingInput } from '../db.ts';

export interface LocationClient {
  name: string;
  bundleId?: string;
  path?: string;
  authorized: boolean | null;
  source: 'locationd' | 'declared';
  purpose?: string;
}

const CLIENTS_PLIST = '/var/db/locationd/clients.plist';
const APP_DIRS = ['/Applications', join(HOME, 'Applications'), '/System/Applications'];

/**
 * Which apps can know where you are. The authoritative list lives in a
 * root-only file; without root, Hashling lists apps that declare they will ask.
 */
export async function collectLocation(): Promise<void> {
  const findings: FindingInput[] = [];
  const clients: LocationClient[] = [];
  const raw = await readPlist<Record<string, Record<string, unknown>>>(CLIENTS_PLIST);
  let source: 'locationd' | 'declared' = 'declared';

  if (raw) {
    source = 'locationd';
    for (const [key, v] of Object.entries(raw)) {
      if (!v || typeof v !== 'object') continue;
      const authorized = v.Authorized === true || v.Authorized === 1 || Number(v.AuthorizationLevel ?? 0) >= 2;
      const bundleId = typeof v.BundleId === 'string' ? v.BundleId : undefined;
      const path = typeof v.Executable === 'string' ? v.Executable : typeof v.BundlePath === 'string' ? v.BundlePath : undefined;
      const name = (path ?? bundleId ?? key).split('/').pop()!.replace(/\.app$/, '');
      clients.push({ name, bundleId, path, authorized, source });
    }
  } else {
    for (const dir of APP_DIRS) {
      let apps: string[] = [];
      try { apps = readdirSync(dir).filter((a) => a.endsWith('.app')); } catch { continue; }
      for (const a of apps) {
        const info = await readPlist<Record<string, unknown>>(join(dir, a, 'Contents/Info.plist'));
        if (!info) continue;
        const purpose = (info.NSLocationUsageDescription ?? info.NSLocationWhenInUseUsageDescription ?? info.NSLocationAlwaysUsageDescription ?? info.NSLocationAlwaysAndWhenInUseUsageDescription) as string | undefined;
        if (purpose) clients.push({ name: a.replace(/\.app$/, ''), bundleId: info.CFBundleIdentifier as string, path: join(dir, a), authorized: null, source, purpose });
      }
    }
  }

  const authorized = clients.filter((c) => c.authorized);
  if (source === 'locationd' && authorized.length) {
    const nonApple = authorized.filter((c) => !c.bundleId?.startsWith('com.apple.') && !c.path?.startsWith('/System/'));
    if (nonApple.length) {
      findings.push({
        key: 'location:authorized', category: 'location', severity: 'info',
        title: `${plural(nonApple.length, 'non-Apple app')} can see your location`,
        summary: nonApple.map((c) => c.name).join(', '),
        explanation: 'These apps were allowed to use Location Services. Location reveals where you live, work and travel.',
        recommendation: 'Turn off apps that do not need it in System Settings > Privacy & Security > Location Services.',
        evidence: { clients: nonApple },
      });
    }
  }

  putSnapshot('location', { at: Date.now(), source, clients }, source === 'declared'
    ? 'macOS keeps the exact list private, even from me, so these are the apps able to ask for your location. Location Services shows which ones you allowed.' : null);
  syncFindings('location', findings);
}
