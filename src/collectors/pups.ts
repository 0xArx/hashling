/**
 * Junk apps (what antivirus calls PUPs, "potentially unwanted programs"): fake cleaners and
 * "speed boosters" that invent problems to sell a licence, and adware that hijacks your browser.
 * None is a virus, but none is worth keeping. Matched by app name and by startup item name.
 */
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { HOME } from '../config.ts';
import { getSnapshot, syncFindings, putSnapshot, type FindingInput } from '../db.ts';

/** [pattern, plain description]. Kept to names whose reputation is well documented. */
const JUNK: [RegExp, string][] = [
  [/^(MacKeeper|PCKeeper)/i, 'a “cleaner” that shows scary warnings to sell a subscription. Widely flagged as unwanted software.'],
  [/^(Advanced Mac Cleaner|Mac Auto Fixer|Mac Cleanup Pro|Mac Tonic|Mac Mechanic|Smart Mac Booster|Mac Speedup Pro|Mac Optimizer Pro|Disk Cleanup Pro|Mac Clean Pro|Mac Booster|MacBooster|Similar Photo Cleaner|Advanced Mac Tuneup|Mac Space Cleaner|Mac Life Cleaner)/i, 'a fake “speed up your Mac” app. It invents problems, then asks you to pay to fix them.'],
  [/^(Search Baron|Search Marquis|SearchMine|Search Quick|Safe Finder|SafeFinder|Chill Tab|WeKnow|Spigot|MyShopcoupon|Mac Search|ApplicationEnhancer|Genieo|Installmac|Advanced Search Pro|SearchPage|Search Pulse|Search Alpha)/i, 'adware that hijacks your browser’s search and start page to show ads and see what you search for.'],
  [/^(MaxOfferDeal|OfferDeal|ProgressSite|ElementaryType|SkilledObject|ActivityInput|ManagementControl|DataSearch|TrustedFinder|ProtocolLibrary|SearchRange|InitialProgram|AnalyzerSystem|GlobalTechSearch)/i, 'part of the Adload or Pirrit adware families. It changes browser settings, shows ads and can download more junk.'],
  [/^(Zipcloud|Simple Mac Cleaner|Mac Defender|MacGuard|MacProtector|MacSecurity|Mac Shield|MacSweeper|iAntiVirus)/i, 'fake antivirus software. It is a scam that pretends your Mac is infected.'],
];
/** Startup item labels that Adload, Pirrit and friends use. */
const JUNK_AGENTS: [RegExp, string][] = [
  [/^com\.(pcv|mykotlerino|apple\.Safari\.[a-z]{8,})\b/i, 'an adware startup item (Pirrit family).'],
  [/^com\.(ElementaryType|SkilledObject|ProgressSite|ActivityInput|ManagementControl|DataSearch|TrustedFinder|ProtocolLibrary|SearchRange|InitialProgram|AnalyzerSystem|MaxOfferDeal)/i, 'an adware startup item (Adload family).'],
  [/^com\.(mackeeper|zeobit|kromtech|iobit\.MacBooster|techyutils|pcvark)/i, 'the startup item of a junk “cleaner” app.'],
];

export async function collectPups(): Promise<void> {
  const hits: { name: string; where: string; why: string; path?: string }[] = [];
  for (const dir of ['/Applications', join(HOME, 'Applications')]) {
    let names: string[] = [];
    try { names = readdirSync(dir).filter((n) => n.endsWith('.app')); } catch { continue; }
    for (const n of names) {
      const name = n.replace(/\.app$/, '');
      const m = JUNK.find(([re]) => re.test(name));
      if (m) hits.push({ name, where: 'app', why: m[1], path: join(dir, n) });
    }
  }
  const items = getSnapshot<{ items: { label: string; plist?: string }[] }>('persistence')?.data.items ?? [];
  for (const it of items) {
    const m = JUNK_AGENTS.find(([re]) => re.test(it.label));
    if (m) hits.push({ name: it.label, where: 'startup', why: m[1], path: it.plist });
  }
  putSnapshot('pups', { at: Date.now(), hits });
  const findings: FindingInput[] = hits.map((h) => ({
    key: `pup:${h.where}:${h.name}`, category: 'pups', severity: 'medium',
    title: h.where === 'app' ? `${h.name} is a known junk app` : `A known adware startup item is installed: ${h.name}`,
    summary: `${h.name} is ${h.why}`,
    explanation: 'Antivirus companies call these “potentially unwanted programs”. They are not viruses, but they slow your Mac, show ads or scare you into paying, and often install more junk.',
    recommendation: h.where === 'app' ? `Remove ${h.name}. If it has its own uninstaller use that, otherwise move it to the Trash, then check Startup items for anything it left behind.` : 'Turn off this startup item, then look for the app it belongs to and remove it.',
    evidence: h as unknown as Record<string, unknown>,
    actions: h.path ? h.where === 'app'
      ? [{ type: 'trash_paths', target: { paths: [h.path], label: h.name }, label: 'Move to Trash' }]
      : [{ type: 'disable_persistence', target: { plist: h.path, label: h.name }, label: 'Turn it off' }] : [],
  }));
  syncFindings('pups', findings);
}
