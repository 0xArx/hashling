import { plural } from '../lib/text.ts';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { HOME } from '../config.ts';
import { listProcs } from '../lib/procs.ts';
import { agentName } from '../knowledge.ts';
import { getSnapshot, putSnapshot, syncFindings, type FindingInput, type Severity } from '../db.ts';

export type Risk = 'high' | 'medium' | 'low' | 'info';

export interface Capability { id: string; label: string; risk: Risk; detail?: string }
export interface McpServer {
  name: string;
  transport: 'stdio' | 'http';
  command?: string;
  url?: string;
  source: string;
  enabled: boolean;
  tags: string[];
  envKeys: string[];
  unpinned: boolean;
}
export interface SecretHit { file: string; kinds: Record<string, number>; total: number }
export interface AgentProfile {
  id: string;
  name: string;
  installed: boolean;
  running: boolean;
  pids: number[];
  configFiles: string[];
  mode: { label: string; risk: Risk; detail: string };
  capabilities: Capability[];
  mcpServers: McpServer[];
  rules?: { allow: string[]; ask: string[]; deny: string[] };
  hooks: { event: string; command: string }[];
  skills: string[];
  plugins: string[];
  secrets: SecretHit[];
  permissions: { label: string; risk: string; via: string }[];
  network: { connections: number; destinations: string[]; rateIn: number; rateOut: number };
  risk: Risk;
  riskReasons: string[];
}

/** Patterns for credentials. Only the kind and count are ever reported, never the value. */
const SECRET_PATTERNS: [string, RegExp][] = [
  ['Anthropic API key', /sk-ant-[a-z0-9]{2,6}-[A-Za-z0-9_-]{20,}/g],
  ['OpenAI key', /sk-(proj|admin|svcacct)-[A-Za-z0-9_-]{20,}/g],
  ['GitHub token', /\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{30,}\b|github_pat_[A-Za-z0-9_]{40,}/g],
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/g],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
  ['Stripe key', /\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}/g],
  ['Groq key', /\bgsk_[A-Za-z0-9]{30,}/g],
  ['Resend key', /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}/g],
  ['Supabase secret', /\bsb_secret_[A-Za-z0-9_-]{20,}|\bsbp_[a-f0-9]{30,}/g],
  ['Vercel token', /\bvcp_[A-Za-z0-9]{30,}/g],
  ['ElevenLabs key', /\bsk_[a-f0-9]{40,}\b/g],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['JWT / service key', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g],
  ['Private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
  ['Cloudflare token', /\bcfat_[A-Za-z0-9]{30,}/g],
  ['Password in text', /\b(password|passwd|db pass(word)?)\b[^\n]{0,20}[:=]\s*`?[^\s`]{8,}/gi],
];

export function scanSecrets(file: string): SecretHit | null {
  let text: string;
  try {
    if (statSync(file).size > 5_000_000) return null;
    text = readFileSync(file, 'utf8');
  } catch { return null; }
  const kinds: Record<string, number> = {};
  let total = 0;
  for (const [kind, re] of SECRET_PATTERNS) {
    const n = text.match(re)?.length ?? 0;
    if (n) { kinds[kind] = n; total += n; }
  }
  return total ? { file, kinds, total } : null;
}

const readJson = (p: string): Record<string, any> | null => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; } };
const H = (p: string) => join(HOME, p);

/** Tiny TOML reader: enough for [section] tables and key = value lines. */
function readToml(p: string): Record<string, Record<string, unknown>> | null {
  let text: string;
  try { text = readFileSync(p, 'utf8'); } catch { return null; }
  const out: Record<string, Record<string, unknown>> = { '': {} };
  let cur = '';
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    const sec = line.match(/^\[+([^\]]+)\]+$/);
    if (sec) { cur = sec[1].trim(); out[cur] ??= {}; continue; }
    const kv = line.match(/^("?[^=]+?"?)\s*=\s*(.+)$/);
    if (!kv) continue;
    const key = kv[1].replace(/"/g, '').trim();
    let v: unknown = kv[2].trim();
    const s = v as string;
    if (/^".*"$/.test(s)) v = s.slice(1, -1);
    else if (s === 'true' || s === 'false') v = s === 'true';
    else if (/^\[.*\]$/.test(s)) { try { v = JSON.parse(s); } catch { /* keep string */ } }
    else if (/^\{.*\}$/.test(s)) v = s;
    else if (!Number.isNaN(Number(s))) v = Number(s);
    out[cur][key] = v;
  }
  return out;
}

/** What an MCP server can probably do, from its name and command line. */
function tagServer(name: string, cmd: string): string[] {
  const s = `${name} ${cmd}`.toLowerCase();
  const tags: string[] = [];
  const add = (t: string, re: RegExp) => { if (re.test(s)) tags.push(t); };
  add('runs shell commands', /shell|terminal|exec|bash|command|repl|desktop-commander|iterm/);
  add('reads and writes files', /filesystem|file|fs\b|desktop-commander|obsidian|notes/);
  add('controls a browser', /browser|playwright|puppeteer|chrome|beme-browser|stagehand/);
  add('controls your desktop', /computer|macos|automation|applescript|screen/);
  add('signs in for you', /auth|beme|password|1password|keychain/);
  add('email and messages', /mail|gmail|slack|discord|telegram|whatsapp|imessage|messages/);
  add('code hosting', /github|gitlab|bitbucket/);
  add('cloud and deploys', /vercel|aws|gcp|azure|cloudflare|supabase|netlify|kubernetes|docker/);
  add('payments', /stripe|paypal|payment|billing/);
  add('databases', /postgres|mysql|sqlite|mongo|redis|database|db\b/);
  return tags;
}

function serverRisk(srv: McpServer): Risk {
  if (srv.tags.some((t) => ['runs shell commands', 'controls your desktop', 'signs in for you', 'payments'].includes(t))) return 'high';
  if (srv.tags.length || srv.unpinned || srv.transport === 'http') return 'medium';
  return 'low';
}

function servers(map: Record<string, any> | undefined, source: string, disabled: string[] = []): McpServer[] {
  if (!map || typeof map !== 'object') return [];
  return Object.entries(map).map(([name, v]) => {
    const command = v?.command ? [v.command, ...(Array.isArray(v.args) ? v.args : [])].join(' ') : undefined;
    const url = v?.url ?? v?.serverUrl ?? v?.httpUrl;
    const unpinned = Boolean(command && /\b(npx|bunx|uvx|pnpm dlx)\b/.test(command) && !/@\d+\.\d+/.test(command));
    return {
      name, source, command, url,
      transport: url ? 'http' : 'stdio',
      enabled: !disabled.includes(name) && v?.disabled !== true && v?.enabled !== false,
      tags: tagServer(name, command ?? url ?? ''),
      envKeys: Object.keys(v?.env ?? v?.headers ?? {}),
      unpinned,
    } as McpServer;
  });
}

function listDir(p: string): string[] {
  try { return readdirSync(p).filter((f) => !f.startsWith('.')); } catch { return []; }
}

function claudeCode(): Partial<AgentProfile> & { id: string; name: string } {
  const cfg = readJson(H('.claude.json'));
  const files = [H('.claude.json'), H('.claude/settings.json'), H('.claude/settings.local.json'), H('.claude/CLAUDE.md')].filter(existsSync);
  const s = readJson(H('.claude/settings.json')) ?? {};
  const sl = readJson(H('.claude/settings.local.json')) ?? {};
  const allow = [...(s.permissions?.allow ?? []), ...(sl.permissions?.allow ?? [])];
  const ask = [...(s.permissions?.ask ?? []), ...(sl.permissions?.ask ?? [])];
  const deny = [...(s.permissions?.deny ?? []), ...(sl.permissions?.deny ?? [])];
  const defaultMode = sl.permissions?.defaultMode ?? s.permissions?.defaultMode ?? 'default';
  const mcp = servers(cfg?.mcpServers, '~/.claude.json');
  for (const [proj, p] of Object.entries<any>(cfg?.projects ?? {})) mcp.push(...servers(p?.mcpServers, `project ${proj.replace(HOME, '~')}`, p?.disabledMcpServers ?? []));
  const hooks: { event: string; command: string }[] = [];
  for (const src of [s, sl]) for (const [event, list] of Object.entries<any>(src.hooks ?? {})) {
    for (const h of list ?? []) for (const hh of h?.hooks ?? []) if (hh?.command) hooks.push({ event, command: String(hh.command).slice(0, 200) });
  }
  const plugins = Object.entries<any>(s.enabledPlugins ?? {}).filter(([, on]) => on).map(([k]) => k);
  const caps: Capability[] = [];
  const mode = defaultMode === 'bypassPermissions'
    ? { label: 'Bypass permissions', risk: 'high' as Risk, detail: 'Runs every tool without asking.' }
    : defaultMode === 'acceptEdits' ? { label: 'Auto-accept edits', risk: 'medium' as Risk, detail: 'Edits files without asking; still asks for commands.' }
      : defaultMode === 'plan' ? { label: 'Plan mode', risk: 'low' as Risk, detail: 'Read-only until you approve a plan.' }
        : { label: 'Asks before acting', risk: 'low' as Risk, detail: 'Asks before running commands that are not on the allow list.' };
  if (s.skipDangerousModePermissionPrompt) caps.push({ id: 'bypass-ok', label: 'Its “skip all safety questions” mode has been used before', risk: 'medium', detail: 'The "dangerous mode" warning was dismissed, so sessions can be started in bypass-permissions mode with no prompt.' });
  const broad = allow.filter((r: string) => /^Bash\((node|python3?|npx|bash|sh|zsh|deno|bun|ruby|perl|osascript|curl|\*)\b|^Bash$|^Bash\(\*\)/.test(r));
  if (broad.length) caps.push({ id: 'broad-exec', label: 'Can run code without asking', risk: 'high', detail: `It can run programs on your Mac without asking you first, because its settings allow commands like ${broad.slice(0, 4).join(', ')}.` });
  if (allow.some((r: string) => /^Bash\((rm|mv|cp)\b/.test(r))) caps.push({ id: 'file-ops', label: 'Can move and copy files without asking', risk: 'medium', detail: allow.filter((r: string) => /^Bash\((rm|mv|cp)\b/.test(r)).join(', ') });
  if (allow.some((r: string) => /git push|gh \*/.test(r))) caps.push({ id: 'push', label: 'Can push code and use GitHub without asking', risk: 'medium', detail: allow.filter((r: string) => /git push|gh /.test(r)).join(', ') });
  if (s.enableAllProjectMcpServers) caps.push({ id: 'project-mcp', label: 'Adds tools from any project without asking', risk: 'high', detail: 'Any project folder you open can add a plug-in (an MCP server, which is a program on your Mac), and it is switched on without asking you.' });
  if (hooks.length) caps.push({ id: 'hooks', label: `${plural(hooks.length, 'command')} set to run by ${hooks.length === 1 ? 'itself' : 'themselves'} (hooks)`, risk: 'medium', detail: 'Hooks run shell commands on every matching tool call.' });
  if (Object.keys(s.env ?? {}).length) caps.push({ id: 'env', label: `Changes ${plural(Object.keys(s.env).length, 'setting')} when it starts (environment variables)`, risk: 'info', detail: Object.keys(s.env).join(', ') });
  return {
    id: 'claude-code', name: 'Claude Code', installed: files.length > 0, configFiles: files, mode, capabilities: caps, mcpServers: mcp,
    rules: { allow, ask, deny }, hooks, skills: listDir(H('.claude/skills')), plugins,
  };
}

function claudeDesktop() {
  const p = H('Library/Application Support/Claude/claude_desktop_config.json');
  const cfg = readJson(p);
  const ext = listDir(H('Library/Application Support/Claude/Claude Extensions'));
  return {
    id: 'claude-desktop', name: 'Claude Desktop', installed: existsSync('/Applications/Claude.app') || Boolean(cfg), configFiles: cfg ? [p] : [],
    mode: { label: 'Asks per tool', risk: 'low' as Risk, detail: 'Claude Desktop asks before a tool is used unless you chose "Always allow".' },
    capabilities: ext.length ? [{ id: 'extensions', label: `${plural(ext.length, 'desktop extension')} installed`, risk: 'medium' as Risk, detail: ext.join(', ') }] : [],
    mcpServers: servers(cfg?.mcpServers, 'claude_desktop_config.json'),
    hooks: [], skills: [], plugins: ext,
  };
}

function codex() {
  const p = H('.codex/config.toml');
  const t = readToml(p);
  if (!t) return { id: 'codex', name: 'Codex', installed: existsSync('/Applications/Codex.app'), configFiles: [], mode: { label: 'Unknown', risk: 'info' as Risk, detail: '' }, capabilities: [], mcpServers: [], hooks: [], skills: [], plugins: [] };
  const top = t[''] ?? {};
  const approval = String(top.approval_policy ?? 'on-request');
  const sandbox = String(top.sandbox_mode ?? 'workspace-write');
  const mcp: McpServer[] = [];
  for (const [sec, v] of Object.entries(t)) {
    const m = sec.match(/^mcp_servers\.("?)([^".]+)\1$/);
    if (m) mcp.push(...servers({ [m[2]]: { command: v.command, args: v.args, url: v.url, env: {} } }, 'config.toml'));
  }
  const plugins = Object.keys(t).filter((k) => k.startsWith('plugins.')).map((k) => k.replace(/^plugins\."?|"$/g, ''));
  const caps: Capability[] = [];
  if (sandbox === 'danger-full-access') caps.push({ id: 'no-sandbox', label: 'No sandbox', risk: 'high', detail: 'Commands run with full access to your files and network.' });
  if (approval === 'never') caps.push({ id: 'never-ask', label: 'Never asks for approval', risk: 'high', detail: 'approval_policy = "never".' });
  if (plugins.some((p) => /computer-use|chrome|browser/.test(p))) caps.push({ id: 'computer', label: 'Has add-ons that control your screen or browser', risk: 'high', detail: plugins.filter((p) => /computer-use|chrome|browser/.test(p)).join(', ') });
  const trusted = Object.entries(t).filter(([k, v]) => k.startsWith('projects.') && v.trust_level === 'trusted').length;
  if (trusted) caps.push({ id: 'trusted', label: `Trusts ${plural(trusted, 'folder')} (fewer safety questions there)`, risk: 'info', detail: 'Trusted folders skip some prompts.' });
  return {
    id: 'codex', name: 'Codex', installed: true, configFiles: [p, H('.codex/AGENTS.md')].filter(existsSync),
    mode: { label: `${approval} / ${sandbox}`, risk: (approval === 'never' || sandbox === 'danger-full-access' ? 'high' : sandbox === 'workspace-write' ? 'low' : 'low') as Risk, detail: `Approval policy "${approval}", sandbox "${sandbox}".` },
    capabilities: caps, mcpServers: mcp, hooks: [], skills: listDir(H('.codex/skills')), plugins,
  };
}

function editorAgent(id: string, name: string, app: string, settingsPath: string, mcpPaths: string[], yoloKeys: RegExp) {
  const settings = readJson(settingsPath) ?? {};
  const mcp: McpServer[] = [];
  const files: string[] = [];
  if (existsSync(settingsPath)) files.push(settingsPath);
  for (const mp of mcpPaths) {
    const j = readJson(mp);
    if (!j) continue;
    files.push(mp);
    mcp.push(...servers(j.mcpServers ?? j.servers ?? j.mcp, mp.replace(HOME, '~')));
  }
  mcp.push(...servers(settings['mcp.servers'] ?? settings.mcp?.servers, 'settings.json'));
  const yolo = Object.entries(settings).filter(([k, v]) => yoloKeys.test(k) && (v === true || (typeof v === 'object' && v && Object.values(v).some((x) => x === true))));
  return {
    id, name, installed: existsSync(app) || files.length > 0, configFiles: files,
    mode: yolo.length ? { label: 'Auto-run on', risk: 'high' as Risk, detail: `Settings: ${yolo.map(([k]) => k).join(', ')}` } : { label: 'Asks before running tools', risk: 'low' as Risk, detail: 'No auto-approve setting found.' },
    capabilities: yolo.map(([k]) => ({ id: k, label: `Auto-approves: ${k}`, risk: 'high' as Risk })), mcpServers: mcp, hooks: [], skills: [], plugins: [],
  };
}

function simpleAgent(id: string, name: string, app: string, cfgPath: string, mcpKey: string, yolo?: (j: Record<string, any>) => boolean) {
  const j = readJson(cfgPath);
  return {
    id, name, installed: existsSync(app) || Boolean(j), configFiles: j ? [cfgPath] : [],
    mode: j && yolo?.(j) ? { label: 'Auto-approve on', risk: 'high' as Risk, detail: 'Tools run without confirmation.' } : { label: j ? 'Asks before acting' : 'Not configured', risk: 'low' as Risk, detail: '' },
    capabilities: [], mcpServers: servers(j?.[mcpKey], cfgPath.replace(HOME, '~')), hooks: [], skills: [], plugins: [],
  };
}

export async function collectAgents(): Promise<void> {
  type Partial2 = Partial<AgentProfile> & { id: string; name: string };
  const profiles: Partial2[] = [
    claudeCode(),
    claudeDesktop(),
    codex(),
    editorAgent('cursor', 'Cursor', '/Applications/Cursor.app', H('Library/Application Support/Cursor/User/settings.json'), [H('.cursor/mcp.json')], /yolo|autoRun|auto[-_]?run|autoApprove/i),
    editorAgent('vscode', 'VS Code (Copilot)', '/Applications/Visual Studio Code.app', H('Library/Application Support/Code/User/settings.json'), [H('Library/Application Support/Code/User/mcp.json')], /autoApprove|chat\.tools\.(global\.)?autoApprove|autoRun/i),
    editorAgent('windsurf', 'Windsurf', '/Applications/Windsurf.app', H('Library/Application Support/Windsurf/User/settings.json'), [H('.codeium/windsurf/mcp_config.json')], /autoExecut|turbo|autoRun/i),
    simpleAgent('gemini', 'Gemini CLI', '/opt/homebrew/bin/gemini', H('.gemini/settings.json'), 'mcpServers', (j) => j.autoAccept === true || j.yolo === true),
    simpleAgent('opencode', 'OpenCode', '/opt/homebrew/bin/opencode', H('.config/opencode/opencode.json'), 'mcp', (j) => JSON.stringify(j.permission ?? {}).includes('"allow"')),
  ];

  const procs = await listProcs();
  const net = getSnapshot<{ processes: { pid: number; agent: string | null; parentAgent: string | null; connections: { external: boolean; org?: string; host?: string; remote: string }[]; rateIn: number; rateOut: number }[] }>('network')?.data;
  const perms = getSnapshot<{ grants: { client: string; label: string; risk: string; path?: string }[] }>('permissions')?.data?.grants ?? [];
  const terminals = ['com.apple.Terminal', 'com.mitchellh.ghostty', 'com.googlecode.iterm2', 'dev.warp.Warp-Stable', 'com.microsoft.VSCode', 'com.todesktop.230313mzl4w4u92'];

  const findings: FindingInput[] = [];
  const result: AgentProfile[] = [];
  for (const p of profiles) {
    const display = p.name.split(' ')[0];
    const pids = [...procs.values()].filter((x) => agentName(x.path, x.name) === display || (p.id === 'claude-code' && /\/claude$/.test(x.path))).map((x) => x.pid);
    const mine = (net?.processes ?? []).filter((x) => x.agent === display || x.parentAgent === display);
    const ext = mine.flatMap((x) => x.connections.filter((c) => c.external));
    const secrets = (p.configFiles ?? []).map(scanSecrets).filter(Boolean) as SecretHit[];
    const grants = perms.filter((g) => (p.id === 'claude-desktop' && g.client === 'com.anthropic.claudefordesktop')
      || (p.id === 'cursor' && /cursor/i.test(g.client)) || (p.id === 'vscode' && g.client === 'com.microsoft.VSCode')
      || ((p.id === 'claude-code' || p.id === 'codex' || p.id === 'gemini' || p.id === 'opencode') && terminals.includes(g.client)))
      .map((g) => ({ label: g.label, risk: g.risk, via: terminals.includes(g.client) && !['claude-desktop', 'cursor', 'vscode'].includes(p.id) ? `${g.client} (the terminal it runs in)` : g.client }));

    const caps: Capability[] = [...(p.capabilities ?? [])];
    for (const s of p.mcpServers ?? []) if (s.enabled) for (const tag of s.tags) if (!caps.some((c) => c.id === `mcp:${tag}`)) caps.push({ id: `mcp:${tag}`, label: `${tag[0].toUpperCase()}${tag.slice(1)} (through an add-on)`, risk: serverRisk(s), detail: (p.mcpServers ?? []).filter((x) => x.tags.includes(tag)).map((x) => x.name).join(', ') });
    // Several terminals can hold the same permission: one row per permission, listing every app that has it.
    for (const g of grants) {
      if (g.risk !== 'high') continue;
      const had = caps.find((c) => c.id === `tcc:${g.label}`);
      if (had) had.detail = `${had.detail}, ${g.via}`;
      else caps.push({ id: `tcc:${g.label}`, label: g.label, risk: 'high', detail: `Granted to ${g.via}` });
    }
    if (secrets.length) caps.push({ id: 'secrets', label: `Has ${plural(secrets.reduce((n, s) => n + s.total, 0), 'password or key', 'passwords or keys')} saved in its settings`, risk: 'high', detail: secrets.map((s) => s.file.replace(HOME, '~')).join(', ') });

    const reasons: string[] = [];
    if (p.mode?.risk === 'high') reasons.push(p.mode.label);
    reasons.push(...caps.filter((c) => c.risk === 'high').map((c) => c.label));
    const risk: Risk = reasons.length >= 2 ? 'high' : reasons.length ? 'medium' : caps.some((c) => c.risk === 'medium') ? 'low' : 'info';

    const profile: AgentProfile = {
      id: p.id, name: p.name, installed: Boolean(p.installed), running: pids.length > 0, pids: pids.slice(0, 20), configFiles: (p.configFiles ?? []).map((f) => f.replace(HOME, '~')),
      mode: p.mode ?? { label: 'Unknown', risk: 'info', detail: '' }, capabilities: caps, mcpServers: p.mcpServers ?? [], rules: p.rules,
      hooks: p.hooks ?? [], skills: p.skills ?? [], plugins: p.plugins ?? [], secrets: secrets.map((s) => ({ ...s, file: s.file.replace(HOME, '~') })), permissions: grants,
      network: { connections: ext.length, destinations: [...new Set(ext.map((c) => c.org ?? c.host ?? c.remote))].slice(0, 15), rateIn: mine.reduce((n, x) => n + x.rateIn, 0), rateOut: mine.reduce((n, x) => n + x.rateOut, 0) },
      risk, riskReasons: reasons,
    };
    if (profile.installed) result.push(profile);

    for (const s of secrets) {
      findings.push({
        key: `agent:secrets:${s.file}`, category: 'agents', severity: 'high',
        title: `${plural(s.total, 'credential')} in plain text in ${s.file.replace(HOME, '~')}`,
        summary: Object.entries(s.kinds).map(([k, n]) => `${n} × ${k}`).join(', '),
        explanation: `${p.name} reads this file, so every agent session (and any prompt injection that reaches it) can see these keys. Anything else running as you can read it too. I only counted the keys; I did not copy them.`,
        recommendation: 'Move keys into the macOS Keychain or a password manager, reference them through environment variables, and rotate any key that has been exposed to an agent you do not fully control.',
        evidence: { agent: p.name, file: s.file.replace(HOME, '~'), kinds: s.kinds },
      });
    }
    const sev = (r: Risk): Severity => (r === 'high' ? 'medium' : r === 'medium' ? 'low' : 'info');
    for (const c of caps.filter((x) => x.risk === 'high' && ['broad-exec', 'project-mcp', 'no-sandbox', 'never-ask'].includes(x.id))) {
      findings.push({
        key: `agent:cap:${p.id}:${c.id}`, category: 'agents', severity: sev(c.risk),
        title: `${p.name}: ${c.label}`, summary: c.detail ?? '',
        explanation: 'An agent that can run programs without asking turns any successful prompt injection (from a web page, issue, email or file it reads) into code running on your Mac.',
        recommendation: 'Narrow the allow list to specific commands, or keep these tools on "ask".',
        evidence: { agent: p.name, capability: c },
      });
    }
    if (p.mode?.risk === 'high') {
      findings.push({ key: `agent:mode:${p.id}`, category: 'agents', severity: 'medium', title: `${p.name} runs tools without asking`, summary: p.mode.detail, explanation: 'Auto-approve modes skip the human check that stops a hijacked agent.', recommendation: 'Turn auto-approve off except in throwaway sandboxes.', evidence: { agent: p.name, mode: p.mode } });
    }
    for (const s of (p.mcpServers ?? []).filter((x) => x.enabled && x.unpinned && serverRisk(x) === 'high')) {
      findings.push({ key: `agent:mcp-unpinned:${p.id}:${s.name}`, category: 'agents', severity: 'low', title: `${p.name}: powerful MCP server "${s.name}" auto-updates`,
        summary: s.command ?? '', explanation: 'This server is started with npx/uvx without a pinned version, so a compromised release would run on your Mac the next time the agent starts.',
        recommendation: 'Pin an exact version (package@1.2.3).', evidence: { agent: p.name, server: s } });
    }
  }

  putSnapshot('agents', { at: Date.now(), agents: result });
  syncFindings('agents', findings);
}
