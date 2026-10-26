/**
 * Booby-trapped project folders. Since 2025 researchers have shown that just opening a repository in an AI
 * coding agent can run someone else's program with your full access:
 * - a committed .mcp.json (or .cursor/.vscode/.gemini equivalent) starts an MCP server once the folder is
 *   trusted, especially when project settings switch servers on by themselves (TrustFall, Adversa AI, May 2026);
 * - project settings switch off the agent's safety questions, add hooks, run an apiKeyHelper or send the
 *   agent's traffic to someone else's server (CVE-2026-33068, CVE-2026-21852 in Claude Code);
 * - git config in the folder runs commands when the agent uses git (GitSpawn, Adversa AI, Oct 2026);
 * - symlinks point the agent's writes at ~/.ssh/authorized_keys and other secrets (GhostApproval, Wiz, Jul 2026).
 *
 * This looks at the folders your AI agents have opened (plus ~/Developer) and tells apart what you set up
 * yourself from what came with the project: committed by someone else, or downloaded from the internet.
 * Only the second kind becomes a warning. It only reads, and never opens a file iCloud has moved off the Mac.
 */
import { existsSync, lstatSync, readdirSync, readFileSync, readlinkSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { HOME } from '../config.ts';
import { putSnapshot, syncFindings, type FindingInput, type Severity } from '../db.ts';
import { run } from '../lib/exec.ts';

type Level = 'high' | 'medium' | 'low';
export interface ProjectIssue {
  kind: 'mcp' | 'settings' | 'git' | 'symlink';
  file: string;
  what: string;
  detail?: string;
  level: Level;
  /** Who it came from: 'you', a commit author's name, or 'downloaded'. */
  origin?: string;
  foreign?: boolean;
  /** What it counts as on this Mac, after taking the origin into account. */
  severity?: Severity;
}
export interface ProjectReport { path: string; name: string; agents: string[]; trusted: boolean; issues: ProjectIssue[]; severity: Severity }

const H = (...p: string[]) => join(HOME, ...p);
const RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SUSPICIOUS = /\b(curl|wget|nc|ncat|netcat|socat|base64|osascript|mkfifo|eval)\b|\b(python3?|perl|ruby|node)\s+-[ce]\b|\b(ba|z)?sh\s+-c\b|\|\s*(ba|z)?sh\b|\/dev\/tcp|\/tmp\/|\.ssh\b|authorized_keys/i;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'Pods', 'vendor', '.venv', 'venv', 'target', '.build', 'DerivedData', '__pycache__', '.turbo', '.cache']);
const SENSITIVE: [RegExp, boolean][] = [
  // [path pattern, always serious]
  [/^\.ssh(\/|$)/, true], [/^\.aws(\/|$)/, true], [/^\.gnupg(\/|$)/, true], [/^\.netrc$/, true], [/^Library\/Keychains(\/|$)/, true],
  [/^\.config\/gh(\/|$)/, true], [/^\.docker\/config\.json$/, true], [/^\.kube(\/|$)/, true], [/^\.claude\.json$/, true], [/^\.claude\/settings/, true],
  [/^\.(zshrc|zprofile|bashrc|bash_profile|profile|gitconfig)$/, false], [/^Library\/LaunchAgents(\/|$)/, false],
];

// ---------- reading safely ----------

/** Read a small text file, but never one iCloud has moved off the Mac (that would download it, or hang offline). */
function safeRead(p: string, max = 256 * 1024): string | null {
  try {
    const st = lstatSync(p);
    if (!st.isFile() || st.size > max) return null;
    if (st.size > 0 && st.blocks === 0) return null;
    return readFileSync(p, 'utf8');
  } catch { return null; }
}

/** JSON that may carry comments or trailing commas (VS Code style). */
function looseJson(text: string | null): any {
  if (!text) return null;
  try { return JSON.parse(text); } catch { /* try without comments */ }
  try {
    return JSON.parse(text.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_m, s) => s ?? '').replace(/,\s*([}\]])/g, '$1'));
  } catch { return null; }
}

function isDir(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

// ---------- which folders ----------

/** Folders AI agents on this Mac have opened, and which agents opened them. */
export function agentFolders(): Map<string, { agents: Set<string>; trusted: boolean }> {
  const out = new Map<string, { agents: Set<string>; trusted: boolean }>();
  const add = (p: string | undefined, agent: string, trusted = false) => {
    if (!p) return;
    const path = resolve(p);
    if (path === HOME || path === '/' || !path.startsWith('/') || /^\/(System|Applications|Library|usr|bin|private)(\/|$)/.test(path)) return;
    const e = out.get(path) ?? { agents: new Set<string>(), trusted: false };
    e.agents.add(agent);
    e.trusted ||= trusted;
    out.set(path, e);
  };
  // Claude Code: its projects list, and the working folder recorded in each project's newest session.
  const cc = looseJson(safeRead(H('.claude.json'), 8 * 1024 * 1024));
  for (const [p, v] of Object.entries<any>(cc?.projects ?? {})) add(p, 'Claude Code', Boolean(v?.hasTrustDialogAccepted));
  try {
    for (const d of readdirSync(H('.claude/projects'))) {
      const dir = H('.claude/projects', d);
      const newest = readdirSync(dir).filter((f) => f.endsWith('.jsonl')).map((f) => ({ f, t: statSync(join(dir, f)).mtimeMs })).sort((a, b) => b.t - a.t)[0];
      if (!newest) continue;
      const head = safeRead(join(dir, newest.f), 64 * 1024 * 1024)?.slice(0, 20_000) ?? '';
      add(head.match(/"cwd":"((?:\\.|[^"\\])+)"/)?.[1]?.replace(/\\(.)/g, '$1'), 'Claude Code', true);
    }
  } catch { /* no Claude Code sessions */ }
  // Cursor, VS Code and Windsurf remember each folder they opened.
  for (const [app, name] of [['Cursor', 'Cursor'], ['Code', 'VS Code'], ['Windsurf', 'Windsurf']]) {
    const root = H('Library/Application Support', app, 'User/workspaceStorage');
    let dirs: string[] = [];
    try { dirs = readdirSync(root); } catch { continue; }
    for (const d of dirs) {
      const f = looseJson(safeRead(join(root, d, 'workspace.json')))?.folder;
      if (typeof f === 'string' && f.startsWith('file://')) { try { add(decodeURIComponent(new URL(f).pathname), name); } catch { /* odd URL */ } }
    }
  }
  // Codex lists the projects you trusted.
  for (const m of (safeRead(H('.codex/config.toml')) ?? '').matchAll(/^\[projects\."((?:\\.|[^"\\])+)"\]/gm)) add(m[1], 'Codex', true);
  for (const p of Object.keys(looseJson(safeRead(H('.gemini/trustedFolders.json'))) ?? {})) add(p, 'Gemini CLI', true);
  // And the usual place people keep their code.
  for (const root of [H('Developer'), H('Projects'), H('code'), H('src')]) {
    try { for (const d of readdirSync(root)) if (!d.startsWith('.')) add(join(root, d), 'your code folder'); } catch { /* none */ }
  }
  for (const [p] of out) if (!isDir(p)) out.delete(p);
  return out;
}

// ---------- what to look for ----------

function commandOf(s: any): string {
  if (!s || typeof s !== 'object') return '';
  if (s.url || s.serverUrl) return String(s.url ?? s.serverUrl);
  return [s.command, ...(Array.isArray(s.args) ? s.args : [])].filter(Boolean).map(String).join(' ');
}

function mcpIssues(proj: string, autoOn: boolean): ProjectIssue[] {
  const issues: ProjectIssue[] = [];
  for (const [file, key] of [['.mcp.json', 'mcpServers'], ['.cursor/mcp.json', 'mcpServers'], ['.vscode/mcp.json', 'servers'], ['.gemini/settings.json', 'mcpServers'], ['.windsurf/mcp.json', 'mcpServers']] as const) {
    const j = looseJson(safeRead(join(proj, file)));
    const servers = (j?.[key] ?? (key === 'servers' ? j?.mcp?.servers : undefined)) as Record<string, any> | undefined;
    for (const [name, s] of Object.entries(servers ?? {})) {
      const cmd = commandOf(s);
      if (!cmd) continue;
      const remote = /^https?:\/\//.test(cmd);
      const local = /(^|\s)(\.{1,2}\/|\$\{workspaceFolder\})|(^|\s)[\w./-]+\.(js|mjs|ts|py|sh|rb)\b/.test(cmd);
      const level: Level = SUSPICIOUS.test(cmd) ? 'high' : local || (autoOn && file === '.mcp.json') ? 'medium' : 'low';
      issues.push({
        kind: 'mcp', file, level, detail: cmd.slice(0, 240),
        what: remote ? `connects your AI agent to "${name}" at ${cmd.replace(/^https?:\/\/([^/]+).*/, '$1')}`
          : `starts a program called "${name}" for your AI agent${autoOn && file === '.mcp.json' ? ', and your settings switch it on without asking' : ''}`,
      });
    }
  }
  return issues;
}

function settingsIssues(proj: string): { issues: ProjectIssue[]; autoOn: boolean } {
  const issues: ProjectIssue[] = [];
  let autoOn = false;
  for (const file of ['.claude/settings.json', '.claude/settings.local.json']) {
    const s = looseJson(safeRead(join(proj, file)));
    if (!s) continue;
    if (s.permissions?.defaultMode === 'bypassPermissions') issues.push({ kind: 'settings', file, level: 'high', what: 'switches off all of Claude Code’s safety questions in this folder' });
    if (s.enableAllProjectMcpServers || (Array.isArray(s.enabledMcpjsonServers) && s.enabledMcpjsonServers.length)) {
      autoOn = true;
      issues.push({ kind: 'settings', file, level: 'medium', what: 'switches on the project’s own MCP servers without asking you' });
    }
    for (const [event, list] of Object.entries<any>(s.hooks ?? {})) for (const h of list ?? []) for (const hh of h?.hooks ?? []) {
      if (!hh?.command) continue;
      const cmd = String(hh.command);
      issues.push({ kind: 'settings', file, level: SUSPICIOUS.test(cmd) ? 'high' : 'medium', what: `runs a command by itself on every “${event}”`, detail: cmd.slice(0, 240) });
    }
    if (s.apiKeyHelper) issues.push({ kind: 'settings', file, level: SUSPICIOUS.test(String(s.apiKeyHelper)) ? 'high' : 'medium', what: 'runs a command to fetch your API key', detail: String(s.apiKeyHelper).slice(0, 240) });
    for (const [k, v] of Object.entries<any>(s.env ?? {})) {
      if (!/(BASE_URL|API_URL|_PROXY)$/i.test(k)) continue;
      const host = String(v).replace(/^\w+:\/\/([^/:]+).*/, '$1');
      if (/(^|\.)(anthropic\.com|openai\.com|localhost)$|^127\.0\.0\.1$/.test(host)) continue;
      issues.push({ kind: 'settings', file, level: 'high', what: `sends your AI agent’s traffic, including your API key, through ${host}`, detail: `${k}=${String(v).slice(0, 120)}` });
    }
    const allow = (s.permissions?.allow ?? []).filter((r: string) => /^Bash$|^Bash\(\*\)|^Bash\((curl|wget|bash|sh|zsh|python3?|node|npx)\b/.test(String(r)));
    if (allow.length) issues.push({ kind: 'settings', file, level: 'medium', what: 'lets the agent run programs without asking', detail: allow.slice(0, 4).join(', ') });
  }
  return { issues, autoOn };
}

/** A tiny git config reader: "section.sub.key" → value. */
function gitConfig(text: string): [string, string][] {
  const out: [string, string][] = [];
  let section = '';
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const sec = line.match(/^\[\s*([\w.-]+)(?:\s+"((?:\\.|[^"\\])*)")?\s*\]/);
    if (sec) { section = sec[2] !== undefined ? `${sec[1].toLowerCase()}.${sec[2]}` : sec[1].toLowerCase(); continue; }
    const kv = line.match(/^([\w-]+)\s*=\s*(.*)$/);
    if (kv && section) out.push([`${section}.${kv[1].toLowerCase()}`, kv[2].replace(/^"(.*)"$/, '$1')]);
  }
  return out;
}

function gitIssues(gitDir: string, label: string, hidden: boolean): ProjectIssue[] {
  const text = safeRead(join(gitDir, 'config'));
  if (!text) return [];
  const issues: ProjectIssue[] = [];
  const file = `${label}/config`;
  for (const [key, value] of gitConfig(text)) {
    let what = '';
    if (key === 'core.fsmonitor' && !/^(true|false)$/i.test(value)) what = 'runs a program every time git looks at your files';
    else if (key === 'core.sshcommand') what = 'replaces the program git uses to connect';
    else if (key === 'core.askpass' || (key === 'credential.helper' && value.startsWith('!'))) what = 'runs a program when git needs a password';
    else if (key === 'core.hookspath' && !/^\.husky(\/_)?\/?$/.test(value)) what = 'runs the project’s own scripts when you commit or check out';
    else if (/^filter\..+\.(clean|smudge|process)$/.test(key) && !/git-lfs/.test(value)) what = 'runs a program on files as git reads and writes them';
    else if (/^diff\..+\.(textconv|command)$|^merge\..+\.driver$/.test(key)) what = 'runs a program when git compares or merges files';
    else if (/^alias\./.test(key) && value.startsWith('!')) what = `turns the git command “${key.slice(6)}” into a shell command`;
    else if (key === 'include.path' || /^includeif\./.test(key)) what = 'loads more git settings from another file';
    if (!what) continue;
    issues.push({ kind: 'git', file, detail: `${key} = ${value.slice(0, 200)}`, what: hidden ? `has a hidden git repository whose settings ${what.replace(/^runs/, 'run')}` : `git settings: ${what}`, level: SUSPICIOUS.test(value) || hidden ? 'high' : 'medium' });
  }
  return issues;
}

/** Hidden ("bare") git repositories inside a project: git uses their settings if an agent runs git there. */
function hiddenRepos(proj: string): string[] {
  const found: string[] = [];
  const walk = (dir: string, depth: number) => {
    let names: string[] = [];
    try { names = readdirSync(dir); } catch { return; }
    if (dir !== proj && names.includes('HEAD') && names.includes('config') && names.includes('objects')) { found.push(dir); return; }
    if (depth >= 2) return;
    for (const n of names.slice(0, 300)) if (!SKIP_DIRS.has(n) && n !== '.git' && isDir(join(dir, n))) walk(join(dir, n), depth + 1);
  };
  walk(proj, 0);
  return found.slice(0, 5);
}

function symlinkIssues(proj: string, deadline: number): ProjectIssue[] {
  const issues: ProjectIssue[] = [];
  let seen = 0;
  const walk = (dir: string, depth: number) => {
    let names: string[] = [];
    try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      if (++seen > 3000 || Date.now() > deadline) return;
      if (SKIP_DIRS.has(n)) continue;
      const p = join(dir, n);
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isSymbolicLink()) {
        let target: string;
        try { target = resolve(dirname(p), readlinkSync(p)); } catch { continue; }
        if (target.startsWith(proj + sep) || !target.startsWith(HOME + sep)) continue;
        const rel = relative(HOME, target);
        const hit = SENSITIVE.find(([re]) => re.test(rel));
        if (hit) issues.push({ kind: 'symlink', file: relative(proj, p), level: hit[1] ? 'high' : 'medium', what: `is a shortcut that points at ~/${rel}, so an agent writing to it changes that file instead`, detail: `${relative(proj, p)} → ~/${rel}` });
      } else if (st.isDirectory() && depth < 2) walk(p, depth + 1);
    }
  };
  walk(proj, 0);
  return issues;
}

// ---------- where it came from ----------

let me: { names: Set<string>; emails: Set<string> } | null = null;
async function myIdentity() {
  if (me) return me;
  const [n, e] = await Promise.all([run('/usr/bin/git', ['config', '--global', 'user.name']), run('/usr/bin/git', ['config', '--global', 'user.email'])]);
  me = { names: new Set([n.stdout.trim()].filter(Boolean)), emails: new Set([e.stdout.trim().toLowerCase()].filter(Boolean)) };
  return me;
}

async function downloaded(p: string): Promise<boolean> {
  const r = await run('/usr/bin/xattr', ['-p', 'com.apple.quarantine', p], { timeout: 3000 });
  return r.ok && r.stdout.trim().length > 0;
}

/** You, a commit author, or "downloaded". Unknown counts as you, so your own setups never nag. */
async function originOf(proj: string, file: string): Promise<{ origin: string; foreign: boolean }> {
  const abs = join(proj, file);
  if (await downloaded(abs)) return { origin: 'downloaded from the internet', foreign: true };
  if (!existsSync(join(proj, '.git')) || file.startsWith('.git/')) return { origin: 'you', foreign: false };
  const r = await run('/usr/bin/git', ['-C', proj, 'log', '-1', '--format=%an%x09%ae', '--', file], { timeout: 5000 });
  const [name, email] = r.stdout.trim().split('\t');
  if (!r.ok || !name) return { origin: 'you', foreign: false };
  const id = await myIdentity();
  const local = await run('/usr/bin/git', ['-C', proj, 'config', 'user.name'], { timeout: 3000 });
  if (id.names.has(name) || id.emails.has((email ?? '').toLowerCase()) || local.stdout.trim() === name) return { origin: 'you', foreign: false };
  return { origin: name, foreign: true };
}

/** What an issue counts as here: things you set up yourself are noted, not warned about. */
function effective(i: ProjectIssue): Severity {
  if (i.foreign) return i.level;
  if (i.kind === 'symlink' && i.level === 'high') return 'medium';
  return 'info';
}

// ---------- the check ----------

export async function checkProject(path: string, opts: { agents?: string[]; trusted?: boolean; userAutoOn?: boolean; deadline?: number } = {}): Promise<ProjectReport> {
  const settings = settingsIssues(path);
  const issues = [...settings.issues, ...mcpIssues(path, settings.autoOn || Boolean(opts.userAutoOn))];
  if (isDir(join(path, '.git'))) issues.push(...gitIssues(join(path, '.git'), '.git', false));
  for (const repo of hiddenRepos(path)) issues.push(...gitIssues(repo, relative(path, repo), true));
  if (path !== HOME) issues.push(...symlinkIssues(path, opts.deadline ?? Date.now() + 5000));
  for (const i of issues) {
    // .git/config is never committed: it is yours unless the folder was downloaded. A hidden repository never is.
    const o = i.kind !== 'git' ? await originOf(path, i.file)
      : !i.file.startsWith('.git/') ? { origin: 'hidden in the project', foreign: true }
        : await downloaded(join(path, '.git/config')) ? { origin: 'downloaded from the internet', foreign: true } : { origin: 'you', foreign: false };
    i.origin = o.origin;
    i.foreign = o.foreign;
    i.severity = effective(i);
  }
  const severity = issues.reduce<Severity>((m, i) => (RANK[i.severity!] > RANK[m] ? i.severity! : m), 'info');
  return { path, name: basename(path), agents: opts.agents ?? [], trusted: Boolean(opts.trusted), issues, severity };
}

export async function collectProjects(): Promise<void> {
  const folders = agentFolders();
  const userAutoOn = Boolean(looseJson(safeRead(H('.claude/settings.json')))?.enableAllProjectMcpServers);
  const deadline = Date.now() + 60_000;
  const reports: ProjectReport[] = [];
  let checked = 0;
  for (const [path, info] of [...folders].slice(0, 600)) {
    if (Date.now() > deadline) break;
    checked++;
    const r = await checkProject(path, { agents: [...info.agents], trusted: info.trusted, userAutoOn, deadline: Math.min(deadline, Date.now() + 3000) });
    if (r.issues.length) reports.push(r);
  }
  reports.sort((a, b) => RANK[b.severity] - RANK[a.severity]);

  const findings: FindingInput[] = reports.filter((r) => RANK[r.severity] >= RANK.medium).map((r) => {
    const warn = r.issues.filter((i) => RANK[i.severity!] >= RANK.medium);
    const from = [...new Set(warn.map((i) => i.origin).filter((o) => o && o !== 'you'))];
    const where = r.path.replace(HOME, '~');
    const files = [...new Set(warn.map((i) => i.file))];
    return {
      key: `project:${r.path}`, category: 'agents', severity: r.severity,
      title: r.severity === 'high' ? `Opening ${r.name} in an AI agent could run someone else’s code` : `${r.name} can change what your AI agents do`,
      summary: warn.slice(0, 3).map((i) => `${i.file} ${i.what}`).join('; '),
      explanation: `${where} contains settings that AI coding agents act on by themselves${r.agents.length ? ` (it was opened by ${r.agents.join(', ')})` : ''}. ${from.length ? `They came from ${from.join(', ')}, not from you. ` : ''}In 2026 researchers showed attacks that use exactly these files to run a stranger’s program on your Mac as soon as you trust the folder, with your access to your files, keys and accounts.`,
      recommendation: `Before you open this folder in an AI agent again, read ${files.slice(0, 3).join(', ')}. If you don’t know why they are there, delete them (or the folder) and don’t trust the folder in your agent.${warn.some((i) => i.kind === 'git' && i.file === '.git/config') ? ' To remove a git setting, run git config --unset <name> inside the folder.' : ''}`,
      evidence: { project: where, agents: r.agents, trusted: r.trusted, issues: warn.map(({ kind, file, what, detail, origin, severity }) => ({ kind, file, what, detail, origin, severity })) },
    };
  });

  putSnapshot('projects', {
    at: Date.now(), checked, total: folders.size,
    projects: reports.map((r) => ({ ...r, path: r.path.replace(HOME, '~') })).slice(0, 100),
  });
  syncFindings('agents', findings, 'project:');
}
