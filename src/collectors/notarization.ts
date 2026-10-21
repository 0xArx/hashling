/**
 * Gatekeeper's verdict on every installed app (`spctl --assess`): was it
 * notarized by Apple, signed by an identified developer, from the App Store,
 * or rejected? Runs daily; results feed the Downloads and Optimize views.
 */
import { readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { HOME, APP_PATH } from '../config.ts';
import { run } from '../lib/exec.ts';
import { putSnapshot, syncFindings, markSeen, type FindingInput } from '../db.ts';

export interface AppVerdict { name: string; path: string; verdict: 'notarized' | 'app-store' | 'apple' | 'developer-id' | 'rejected' | 'unknown'; origin?: string }

export async function collectNotarization(): Promise<void> {
  const apps: string[] = [];
  for (const dir of ['/Applications', join(HOME, 'Applications')]) {
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir)) {
      if (f.endsWith('.app')) apps.push(join(dir, f));
      else if (!f.startsWith('.')) { try { for (const g of readdirSync(join(dir, f))) if (g.endsWith('.app')) apps.push(join(dir, f, g)); } catch { /* not a folder */ } }
    }
  }
  const results: AppVerdict[] = [];
  let i = 0;
  const worker = async () => {
    while (i < apps.length) {
      const path = apps[i++];
      const r = await run('/usr/sbin/spctl', ['-a', '-vv', '-t', 'exec', path], { timeout: 30_000 });
      const text = `${r.stdout}\n${r.stderr}`;
      const origin = text.match(/origin=(.+)/)?.[1]?.trim();
      const verdict: AppVerdict['verdict'] = /source=Notarized/i.test(text) ? 'notarized' : /source=Mac App Store/i.test(text) ? 'app-store'
        : /source=Apple System/i.test(text) ? 'apple' : /accepted/.test(text) ? 'developer-id' : /rejected/.test(text) ? 'rejected' : 'unknown';
      results.push({ name: path.split('/').pop()!.replace(/\.app$/, ''), path, verdict, origin });
    }
  };
  await Promise.all([worker(), worker(), worker()]);
  results.sort((a, b) => a.name.localeCompare(b.name));
  for (const r of results) markSeen('app', r.path, { name: r.name, path: r.path, verdict: r.verdict });
  // Not worth a warning: web-app shortcuts the browser itself creates (never sent to Apple), and Hashling itself.
  const NOT_A_CONCERN = /\/(Chrome|Edge|Brave|Arc|Vivaldi|Chromium) Apps\.localized\//;
  // An app's own uninstaller ("Remove X", "Uninstall X") is covered by the app itself.
  const rejected = results.filter((r) => r.verdict === 'rejected' && !NOT_A_CONCERN.test(r.path) && r.path !== APP_PATH && !/^(Remove|Uninstall) /i.test(r.name));
  const findings: FindingInput[] = rejected.map((r) => ({
    key: `notarize:${r.path}`, category: 'notarization', severity: 'low',
    title: `${r.name} has not been checked by Apple`,
    summary: 'macOS would normally warn before opening it: it is not from an identified developer, or Apple has not scanned it for malware.',
    explanation: 'macOS normally refuses to open apps like this. It may have been allowed manually, built by you, or be pirated or tampered with. Pirated apps are a common way Mac malware spreads.',
    recommendation: 'Keep it only if you know exactly where it came from. Otherwise remove it and get the official version.',
    evidence: r as unknown as Record<string, unknown>,
  }));
  putSnapshot('notarization', { at: Date.now(), apps: results, counts: results.reduce((c, r) => ({ ...c, [r.verdict]: (c[r.verdict] ?? 0) + 1 }), {} as Record<string, number>) });
  syncFindings('notarization', findings);
}
