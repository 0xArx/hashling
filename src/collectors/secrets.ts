/**
 * Keys and passwords left in plain text where any program (or a hijacked AI
 * agent) can read them: shell history, shell startup files, and common
 * credential files. Only the kind and count are recorded, never the value.
 * Patterns follow the open-source gitleaks / detect-secrets rule ideas.
 */
import { existsSync, statSync, readdirSync, readFileSync, lstatSync } from 'node:fs';
import { join, extname, basename } from 'node:path';
import { HOME, ROOT } from '../config.ts';
import { scanSecrets } from './agents.ts';
import { putSnapshot, syncFindings, type FindingInput } from '../db.ts';

const H = (p: string) => join(HOME, p);

/** Files that should never hold secrets, and files that are meant to (but are worth knowing about). */
const SHOULD_NOT: { path: string; label: string; fix: string }[] = [
  { path: H('.zsh_history'), label: 'Terminal history (zsh)', fix: 'Remove the lines with keys (edit ~/.zsh_history), then rotate those keys. Start commands with a space and set `setopt HIST_IGNORE_SPACE` to keep secrets out of history.' },
  { path: H('.bash_history'), label: 'Terminal history (bash)', fix: 'Remove the lines with keys from ~/.bash_history and rotate those keys.' },
  { path: H('.python_history'), label: 'Python history', fix: 'Remove the lines with keys from ~/.python_history and rotate them.' },
  { path: H('.node_repl_history'), label: 'Node.js history', fix: 'Remove the lines with keys from ~/.node_repl_history and rotate them.' },
  { path: H('.zshrc'), label: 'Shell startup file (.zshrc)', fix: 'Move keys out of .zshrc into the macOS Keychain (`security add-generic-password`) or a password manager, and load them only where needed.' },
  { path: H('.zprofile'), label: 'Shell startup file (.zprofile)', fix: 'Move keys into the Keychain or a password manager.' },
  { path: H('.bash_profile'), label: 'Shell startup file (.bash_profile)', fix: 'Move keys into the Keychain or a password manager.' },
  { path: H('.bashrc'), label: 'Shell startup file (.bashrc)', fix: 'Move keys into the Keychain or a password manager.' },
  { path: H('.profile'), label: 'Shell startup file (.profile)', fix: 'Move keys into the Keychain or a password manager.' },
];
const CREDENTIAL_FILES: { path: string; label: string }[] = [
  { path: H('.aws/credentials'), label: 'AWS credentials' },
  { path: H('.npmrc'), label: 'npm config' },
  { path: H('.netrc'), label: '.netrc (logins for curl/git)' },
  { path: H('.git-credentials'), label: 'Git credentials (plain text)' },
  { path: H('.docker/config.json'), label: 'Docker registry logins' },
  { path: H('.pypirc'), label: 'PyPI upload token' },
  { path: H('.config/gh/hosts.yml'), label: 'GitHub CLI token' },
];

export async function collectSecrets(): Promise<void> {
  const findings: FindingInput[] = [];
  const files: { path: string; label: string; kinds: Record<string, number>; total: number; expected: boolean; worldReadable: boolean }[] = [];
  for (const f of SHOULD_NOT) {
    if (!existsSync(f.path)) continue;
    const hit = scanSecrets(f.path);
    if (!hit) continue;
    const worldReadable = (statSync(f.path).mode & 0o004) !== 0;
    files.push({ path: f.path.replace(HOME, '~'), label: f.label, kinds: hit.kinds, total: hit.total, expected: false, worldReadable });
    findings.push({
      key: `secrets:${f.path}`, category: 'secrets', severity: f.path.includes('history') ? 'high' : 'medium',
      title: `${hit.total} ${hit.total === 1 ? 'key or password' : 'keys or passwords'} in your ${f.label}`,
      summary: `${f.path.replace(HOME, '~')}: ${Object.entries(hit.kinds).map(([k, n]) => `${n} × ${k}`).join(', ')}`,
      explanation: `Any program running as you can read this file, including AI agents and anything they are tricked into doing. ${f.path.includes('history') ? 'Keys typed into a terminal stay in its history file for years.' : 'Startup files are copied into every terminal and often end up in screenshots, backups and dotfile repos.'} I counted them; I did not copy them.`,
      recommendation: f.fix,
      evidence: { file: f.path.replace(HOME, '~'), kinds: hit.kinds, worldReadable },
    });
  }
  for (const f of CREDENTIAL_FILES) {
    if (!existsSync(f.path)) continue;
    const hit = scanSecrets(f.path);
    const mode = statSync(f.path).mode;
    const worldReadable = (mode & 0o044) !== 0;
    files.push({ path: f.path.replace(HOME, '~'), label: f.label, kinds: hit?.kinds ?? {}, total: hit?.total ?? 0, expected: true, worldReadable });
    if (worldReadable && (hit?.total ?? 0) > 0) {
      findings.push({
        key: `secrets-perms:${f.path}`, category: 'secrets', severity: 'low',
        title: `${f.label} can be read by other users`,
        summary: `${f.path.replace(HOME, '~')} has permissions ${(mode & 0o777).toString(8)}.`,
        explanation: 'Credential files should only be readable by you (permission 600).',
        recommendation: `Run: chmod 600 ${f.path.replace(HOME, '~')}`,
      });
    }
  }
  const seeds = findRecoveryPhrases();
  for (const f of seeds) {
    findings.push({
      key: `secrets-seed:${f.path}`, category: 'secrets', severity: 'high',
      title: `A crypto wallet recovery phrase is saved in ${basename(f.path)}`,
      summary: `${f.path.replace(HOME, '~')} holds what looks like a ${f.words}-word recovery phrase.`,
      explanation: 'Anyone who reads a recovery phrase owns the wallet and can empty it, with no way to get the money back. Mac stealers search for exactly these files first. I spotted the word pattern but did not copy the words.',
      recommendation: 'Write the phrase on paper (or a metal backup) and keep it somewhere safe and offline. Then delete this file and empty the Trash. If the file was ever synced, shared or on a Mac that had malware, move the funds to a new wallet.',
      evidence: { file: f.path.replace(HOME, '~'), words: f.words },
    });
  }
  putSnapshot('secrets', { at: Date.now(), files, seeds: seeds.map((x) => ({ ...x, path: x.path.replace(HOME, '~') })) });
  syncFindings('secrets', findings);
}

// ---------- Crypto recovery phrases ----------

let bip39: Set<string> | null = null;
const words = () => (bip39 ??= new Set(readFileSync(join(ROOT, 'src/data/bip39-english.txt'), 'utf8').split('\n').map((w) => w.trim()).filter(Boolean)));
const TEXT_EXT = new Set(['.txt', '.md', '.rtf', '.csv', '.text', '.note', '']);
const SKIP_DIR = /^(node_modules|\.git|Library|\.Trash|\.cache|dist|build)$/;

/** The longest run of BIP-39 words in a row (numbering like "1." or "1)" between them is fine). */
export function longestSeedRun(text: string): number {
  const dict = words();
  let best = 0, run = 0;
  for (const t of text.toLowerCase().split(/[\s,;|]+/)) {
    if (!t || /^\d+[.):]?$/.test(t)) continue;
    const w = t.replace(/^\d+[.):-]/, '').replace(/[^a-z]/g, '');
    if (w && dict.has(w)) { run++; best = Math.max(best, run); } else run = 0;
  }
  return best;
}

/**
 * Plain-text files in the folders people save things to. Files that live only in iCloud
 * (offloaded) are skipped so the scan never downloads anything.
 */
export function findRecoveryPhrases(): { path: string; words: number }[] {
  const out: { path: string; words: number }[] = [];
  let budget = 4000;
  const walk = (dir: string, depth: number) => {
    let names: string[] = [];
    try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      if (budget-- <= 0) return;
      const p = join(dir, n);
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) { if (depth < 3 && !SKIP_DIR.test(n) && !n.endsWith('.app')) walk(p, depth + 1); continue; }
      if (!TEXT_EXT.has(extname(n).toLowerCase()) || st.size < 40 || st.size > 256 * 1024 || st.blocks === 0) continue;
      let text = '';
      try { text = readFileSync(p, 'utf8'); } catch { continue; }
      const run = longestSeedRun(text);
      if (run >= 12) out.push({ path: p, words: [24, 21, 18, 15, 12].find((n) => run >= n) ?? 12 });
    }
  };
  for (const d of ['Desktop', 'Documents', 'Downloads']) walk(join(HOME, d), 0);
  return out;
}
