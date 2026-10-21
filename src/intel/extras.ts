/**
 * - YARA-Forge core rules (github.com/YARAHQ/yara-forge): a curated, tested
 *   collection of public YARA rules, used alongside Apple's XProtect rules.
 * - Outdated software: Homebrew formulae and apps (casks) with newer versions.
 */
import { existsSync, mkdirSync, statSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { RULES_DIR, DATA_DIR } from '../config.ts';
import { run } from '../lib/exec.ts';
import { putSnapshot, syncFindings, type FindingInput } from '../db.ts';

const FORGE_URL = 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip';

export async function updateYaraForge(): Promise<void> {
  mkdirSync(RULES_DIR, { recursive: true, mode: 0o700 });
  const target = join(RULES_DIR, 'yara-forge-core.yar');
  if (existsSync(target) && Date.now() - statSync(target).mtimeMs < 6 * 86_400_000) return;
  const res = await fetch(FORGE_URL, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`YARA-Forge download failed: HTTP ${res.status}`);
  const zip = join(DATA_DIR, 'tmp-yara-forge.zip');
  mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(zip, Buffer.from(await res.arrayBuffer()));
  const list = await run('/usr/bin/unzip', ['-Z1', zip]);
  const entry = list.stdout.split('\n').find((l) => l.endsWith('.yar'));
  if (!entry) throw new Error('YARA-Forge archive had no .yar file');
  const out = await run('/usr/bin/unzip', ['-p', zip, entry], { maxBuffer: 128 * 1024 * 1024 });
  if (!out.ok || !out.stdout.includes('rule ')) throw new Error('Could not extract YARA-Forge rules');
  writeFileSync(target, out.stdout);
  try { unlinkSync(zip); } catch { /* gone */ }
}

/**
 * Elastic's open macOS malware rules (Elastic License 2.0): Atomic and other stealers, backdoors and the
 * big Mac adware families (Adload, Bundlore, Genieo, Pirrit, VSearch). Hacking-tool and exploit rules are
 * left out: on a personal Mac they flag security tools, not malware.
 */
export async function updateElasticMacRules(): Promise<void> {
  mkdirSync(RULES_DIR, { recursive: true, mode: 0o700 });
  const target = join(RULES_DIR, 'elastic-macos.yar');
  if (existsSync(target) && Date.now() - statSync(target).mtimeMs < 6 * 86_400_000) return;
  const tree = await fetch('https://api.github.com/repos/elastic/protections-artifacts/git/trees/main?recursive=1', { headers: { 'User-Agent': 'Hashling-Mac-security' }, signal: AbortSignal.timeout(30_000) });
  if (!tree.ok) throw new Error(`Elastic rules list failed: HTTP ${tree.status}`);
  const files = ((await tree.json()).tree as { path: string }[]).map((x) => x.path)
    .filter((p) => /^yara\/rules\/MacOS_.+\.yar$/.test(p) && !/MacOS_(Hacktool|Exploit)_/.test(p));
  const parts = [`// Elastic protections-artifacts macOS rules, Elastic License 2.0 (https://github.com/elastic/protections-artifacts). ${files.length} files.`];
  for (const f of files) {
    const r = await fetch(`https://raw.githubusercontent.com/elastic/protections-artifacts/main/${f}`, { signal: AbortSignal.timeout(30_000) });
    if (r.ok) parts.push(await r.text());
  }
  if (parts.length < 10) throw new Error('Too few Elastic rules downloaded');
  writeFileSync(target, parts.join('\n\n'));
}

export async function collectOutdated(): Promise<void> {
  const brew = ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'].find(existsSync);
  const findings: FindingInput[] = [];
  let apps: { name: string; installed: string; latest: string; kind: string }[] = [];
  if (brew) {
    const r = await run(brew, ['outdated', '--greedy', '--json=v2'], { timeout: 120_000 });
    try {
      const j = JSON.parse(r.stdout) as { formulae: { name: string; installed_versions: string[]; current_version: string }[]; casks: { name: string; installed_versions: string[] | string; current_version: string }[] };
      apps = [
        ...j.casks.map((c) => ({ name: c.name, installed: String(Array.isArray(c.installed_versions) ? c.installed_versions[0] : c.installed_versions), latest: c.current_version, kind: 'app' })),
        ...j.formulae.map((f) => ({ name: f.name, installed: f.installed_versions[0], latest: f.current_version, kind: 'tool' })),
      ];
    } catch { /* brew not usable */ }
  }
  const appsOnly = apps.filter((a) => a.kind === 'app');
  if (appsOnly.length) {
    findings.push({
      key: 'outdated:brew-casks', category: 'updates', severity: 'low',
      title: `${appsOnly.length} app${appsOnly.length === 1 ? ' has' : 's have'} a newer version`,
      summary: appsOnly.slice(0, 8).map((a) => `${a.name} ${a.installed} → ${a.latest}`).join(', '),
      explanation: 'Updates often fix security holes. Apps installed with Homebrew do not always update themselves.',
      recommendation: 'Run `brew upgrade --cask --greedy` in Terminal, or update each app from its own menu.',
      evidence: { apps: appsOnly },
    });
  }
  putSnapshot('outdated', { at: Date.now(), brew: Boolean(brew), apps });
  syncFindings('updates', findings);
}
