/**
 * Process history: every program that starts, who started it (including which
 * AI agent), and its command line (credentials redacted). New processes are
 * checked against detection rules modelled on real macOS malware techniques
 * (Atomic/AMOS, Cuckoo, Poseidon stealers and common post-exploitation),
 * in the spirit of the open-source Sigma rule set.
 *
 * Limitation: polling every 2 seconds can miss programs that start and exit
 * faster than that. Full coverage needs Apple's Endpoint Security (root).
 */
import { run } from '../lib/exec.ts';
import { listProcs, ancestry, type Proc } from '../lib/procs.ts';
import { agentName, REMOTE_CONTROL_HOSTS } from '../knowledge.ts';
import { statSync } from 'node:fs';
import { redact } from '../process.ts';
import { parseUploadCommand, recordUploadCommand } from '../intel/uploads.ts';
import { db, now, logEvent, syncFindings, putSnapshot, markSeen, type FindingInput, type Severity } from '../db.ts';

db.exec(`CREATE TABLE IF NOT EXISTS proc_history (
  ts INTEGER NOT NULL,
  pid INTEGER NOT NULL,
  ppid INTEGER NOT NULL,
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  args TEXT NOT NULL,
  uid INTEGER NOT NULL,
  agent TEXT,
  parent TEXT,
  rule TEXT
);
CREATE INDEX IF NOT EXISTS proc_history_ts ON proc_history(ts);
CREATE INDEX IF NOT EXISTS proc_history_agent ON proc_history(agent, ts);`);

export interface Rule { id: string; title: string; severity: Severity; tier: 'suspicious' | 'risk'; test: (args: string, p: Proc, parents: Proc[]) => boolean; why: string; todo: string }

const APPLE_PARENT = (ps: Proc[]) => ps.length > 0 && /^\/(System|usr|bin|sbin)\//.test(ps[0].path) && !/\/(sh|bash|zsh|osascript|python3?)$/.test(ps[0].path);
const TRUSTED_INSTALLERS = /(raw\.githubusercontent\.com\/Homebrew|brew\.sh|sh\.rustup\.rs|get\.pnpm\.io|bun\.sh|deno\.land|astral\.sh|nvm-sh|claude\.ai\/install|install\.python-poetry|get\.docker\.com|ollama\.com\/install)/i;

const SHELL = /\/(sh|bash|zsh|dash|fish)$/;
/** Rules about shell syntax itself. Everything else is judged on the real program when it runs. */
const SHELL_RULES = new Set(['pipe-to-shell', 'encoded-exec', 'reverse-shell']);
/**
 * The commands a shell `-c` script actually runs, minus text it only passes around: heredoc bodies
 * (file contents) and quoted strings (echo text, sed scripts). Agent wrappers like Claude Code's
 * `eval '<command>'` are unwrapped first. A command nested in quotes (`bash -c "curl … | sh"`) is
 * still caught, because the inner shell is its own process.
 */
function shellCode(a: string): string {
  const ev = a.match(/\beval '((?:[^']|'"'"')*)'/);
  const code = ev ? ev[1].replaceAll(`'"'"'`, `'`) : a;
  return code
    .replace(/<<-?\s*(['"]?)(\w+)\1[^\n]*\n[\s\S]*?\n\s*\2(?=\s|$)/g, ' ')
    .replace(/'[^']*'|"(?:[^"\\]|\\.)*"/g, ' ');
}

/** First rule this process matches. A shell's `-c` script only counts for shell-syntax rules, so text an agent writes into a file never triggers an alert. */
export function matchRule(a: string, p: Proc, parents: Proc[]): Rule | undefined {
  const shell = SHELL.test(p.path);
  const text = shell ? shellCode(a) : a;
  return RULES.find((r) => { if (shell && !SHELL_RULES.has(r.id)) return false; try { return r.test(text, p, parents); } catch { return false; } });
}

/** The main program of a remote-control app (not its helpers), so one launch is one alert. */
const remoteHost = (p: Proc) => {
  const parts = p.path.split('.app/');
  return parts.length === 2 && /^Contents\/MacOS\/[^/]+$/.test(parts[1]) && REMOTE_CONTROL_HOSTS.test(parts[0].split('/').pop() ?? '') ? `${parts[0]}.app` : null;
};
const installedHoursAgo = (bundle: string) => { try { return (Date.now() - statSync(bundle).birthtimeMs) / 3_600_000; } catch { return Infinity; } };
const REMOTE_WHY = 'Remote-control apps let another person see your screen and use your mouse and keyboard. Scammers who pretend to be your bank, Apple, Microsoft or "tech support" ask you to open one, then empty bank accounts while you watch.';
const REMOTE_TODO = 'If someone on the phone or in a pop-up asked you to open this, hang up and quit the app now. Banks and Apple never ask for this. Then change your bank and email passwords from another device. If you opened it yourself for someone you know, you can ignore this.';

export const RULES: Rule[] = [
  { id: 'remote-control-new', severity: 'high', tier: 'suspicious', title: 'A just-installed app can now control your Mac',
    test: (_a, p) => { const b = remoteHost(p); return Boolean(b) && installedHoursAgo(b!) < 24; },
    why: `${REMOTE_WHY} This one was installed in the last day, which is exactly how these scams start.`, todo: REMOTE_TODO },
  { id: 'remote-control', severity: 'medium', tier: 'risk', title: 'Someone may be able to control your Mac',
    // screensharingd only starts when another computer connects to macOS Screen Sharing.
    test: (_a, p) => Boolean(remoteHost(p)) || p.name === 'screensharingd',
    why: REMOTE_WHY, todo: REMOTE_TODO },
  { id: 'fake-password-prompt', severity: 'high', tier: 'suspicious', title: 'A script showed a password prompt',
    test: (a) => /osascript/.test(a) && /(display dialog|hidden answer|with title).*(password|passcode)|password.*(display dialog|hidden answer)/i.test(a),
    why: 'Mac stealers like Atomic (AMOS) and Cuckoo pop up a fake "system" dialog with AppleScript asking for your password, then use it to unlock your keychain. Real macOS password prompts never come from osascript.',
    todo: 'If you did not expect a password prompt, do not type your password. Quit the program that started it and run a full scan.' },
  { id: 'dscl-authonly', severity: 'high', tier: 'suspicious', title: 'A program tested your login password',
    test: (a) => /\bdscl\b.*-authonly/i.test(a),
    why: '`dscl . -authonly` checks whether a password is correct. Atomic Stealer uses it to confirm the password it tricked you into typing before stealing your keychain.',
    todo: 'Change your Mac login password, then check Startup items and run a malware scan.' },
  { id: 'keychain-dump', severity: 'high', tier: 'suspicious', title: 'Something read your keychain',
    test: (a, _p, ps) => /\bsecurity\s+(dump-keychain|find-generic-password\s+.*-w|find-internet-password\s+.*-w|export)/i.test(a) && !APPLE_PARENT(ps),
    why: 'The keychain holds your saved passwords and keys. Dumping it or printing passwords (-w) from a script is how stealers take them. Some developer tools read one specific item on purpose.',
    todo: 'Check which program did this. If it was not a tool you use, quit it and rotate passwords stored in your keychain.' },
  { id: 'encoded-exec', severity: 'high', tier: 'suspicious', title: 'A hidden (encoded) script ran',
    test: (a) => /base64\s+(-d|--decode|-D)[^|]*\|\s*(sh|bash|zsh|python3?|perl|osascript)\b|(python3?|perl)\s+-c\s+.*(b64decode|base64|exec\(|eval\()/i.test(a),
    why: 'Decoding text and piping it straight into a shell hides what is actually running. Malware droppers use it to avoid detection.',
    todo: 'Look at what started it. Quarantine anything you did not run yourself.' },
  { id: 'reverse-shell', severity: 'critical', tier: 'suspicious', title: 'A reverse shell was opened',
    test: (a) => /\/dev\/tcp\/|\bnc\b.*\s-e\s|\bncat\b.*--exec|bash\s+-i\s+>&|socat\s+.*exec:/i.test(a),
    why: 'A reverse shell hands control of this Mac to someone on another computer.',
    todo: 'Disconnect from the internet, quit the process, and get help. Treat this Mac as compromised.' },
  { id: 'cookie-theft', severity: 'high', tier: 'suspicious', title: 'Browser cookies or saved passwords were read',
    test: (a, p) => /(Cookies|Login Data|logins\.json|key4\.db|Web Data)\b/.test(a) && /\b(sqlite3|cp|ditto|zip|tar|curl|python3?)\b/.test(a) && !/Google Chrome|Safari|firefox|Brave|Arc|Edge/i.test(p.path),
    why: 'Copying a browser\'s cookie or password database lets someone log in to your accounts without your password. Infostealers do exactly this.',
    todo: 'Sign out of important sites (this invalidates stolen cookies), change passwords, and quarantine the program.' },
  { id: 'security-off', severity: 'high', tier: 'suspicious', title: 'A macOS security feature was switched off',
    test: (a) => /spctl\s+--(master|global)-disable|csrutil\s+disable|defaults\s+write\s+com\.apple\.LaunchServices\s+LSQuarantine\s+-bool\s+(no|false)|launchctl\s+(unload|bootout).*(XProtect|syspolicy|MRT)/i.test(a),
    why: 'Turning off Gatekeeper, quarantine or XProtect removes the protections that stop unknown software. Malware does this to keep running.',
    todo: 'Turn the feature back on (my Mac settings page shows which) and scan the Mac.' },
  { id: 'quarantine-strip', severity: 'medium', tier: 'risk', title: 'Gatekeeper\'s download check was removed from a file',
    test: (a) => /\bxattr\b.*(-d\s+com\.apple\.quarantine|-c\b|-cr\b|-rc\b|-r\s+-d\s+com\.apple\.quarantine)/i.test(a),
    why: 'macOS marks downloaded files so Gatekeeper checks them before they open. Removing that mark skips the check. Scam "install guides" for cracked apps tell people to run exactly this.',
    todo: 'Make sure you trust that file. Let me scan it before you open it.' },
  { id: 'pipe-to-shell', severity: 'medium', tier: 'risk', title: 'A script was downloaded and run in one step',
    // Downloaded text fed to a shell, or to Python as a script (`| python3` / `| python3 -`); `python3 -c '...'` only parses it.
    test: (a) => /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?((sh|bash|zsh)\b(?!\s+-c\b)|python3?(\s+-)?\s*($|[;&|)]))/i.test(a) && !TRUSTED_INSTALLERS.test(a),
    why: '`curl ... | sh` runs whatever a website sends, without you seeing it first. It is common for developer tools and also a favourite trick of malware "install" instructions.',
    todo: 'Check the address it downloaded from. If you do not recognise it, scan your Mac and check Startup items.' },
  { id: 'unsigned-from-temp', severity: 'high', tier: 'suspicious', title: 'A program ran from a temporary or hidden folder',
    test: (a, p) => /^\/(private\/)?tmp\/|^\/private\/var\/folders\/[^/]+\/[^/]+\/T\/(?!.*\.(app|xpc)\/)|^\/Users\/Shared\//.test(p.path) && !/\/(go-build|node-compile-cache|com\.apple|TemporaryItems|AppTranslocation)/.test(p.path),
    why: 'Real apps run from Applications or system folders. Droppers unpack themselves into temp folders and run from there.',
    todo: 'Check what this is. Quarantine it if you did not run it on purpose.' },
  { id: 'silent-screenshot', severity: 'medium', tier: 'risk', title: 'A silent screenshot was taken in the background',
    test: (a, _p, ps) => /\bscreencapture\b.*\s-x\b/.test(a) && !APPLE_PARENT(ps),
    why: '`screencapture -x` takes a screenshot without the shutter sound. Spyware uses it to watch what you do.',
    todo: 'Find out which program started it.' },
];

let known = new Map<number, string>();
const seenExe = new Set<string>();
let firstRun = true;

export async function collectProcesses(): Promise<void> {
  const [procs, argsOut] = await Promise.all([listProcs(), run('/bin/ps', ['-axww', '-o', 'pid=,args='], { timeout: 8000, maxBuffer: 16 * 1024 * 1024 })]);
  const args = new Map<number, string>();
  for (const line of argsOut.stdout.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (m) args.set(Number(m[1]), m[2]);
  }
  const t = now();
  const next = new Map<number, string>();
  const ins = db.prepare('INSERT INTO proc_history (ts, pid, ppid, name, path, args, uid, agent, parent, rule) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const hits: { rule: Rule; p: Proc; a: string; agent: string | null; parents: Proc[] }[] = [];
  const rows: unknown[][] = [];
  for (const p of procs.values()) {
    const key = p.path;
    next.set(p.pid, key);
    if (known.get(p.pid) === key) continue;
    if (p.ppid === process.pid) continue; // Hashling's own probes (ps, lsof, codesign) are not activity on this Mac
    if (firstRun) { if (!seenExe.has(p.path)) { seenExe.add(p.path); markSeen('exe', p.path, { name: p.name, path: p.path }); } continue; }
    const a = args.get(p.pid) ?? p.path;
    const parents = ancestry(p.pid, procs, 10);
    const agent = agentName(p.path, p.name) ?? parents.map((x) => agentName(x.path, x.name)).find(Boolean) ?? null;
    const rule = matchRule(a, p, parents);
    const up = parseUploadCommand(p.path, a);
    if (up) recordUploadCommand(t, p.pid, up, agent, parents[0]?.name ?? null, a);
    rows.push([t, p.pid, p.ppid, p.name, p.path, redact(a).slice(0, 600), p.uid, agent, parents[0]?.name ?? null, rule?.id ?? null]);
    if (!seenExe.has(p.path)) { seenExe.add(p.path); markSeen('exe', p.path, { name: p.name, path: p.path, agent, parent: parents[0]?.name ?? null }); }
    if (rule) hits.push({ rule, p, a, agent, parents });
  }
  if (rows.length) {
    db.exec('BEGIN');
    try { for (const r of rows) ins.run(...(r as [number])); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; }
  }
  known = next;
  firstRun = false;

  for (const h of hits) {
    if (!markSeen('proc-rule', `${h.rule.id}|${h.p.pid}`).isNew) continue;
    logEvent('process', h.rule.severity, `${h.rule.title}: ${h.p.name}${h.agent ? ` (started by ${h.agent})` : ''}`, { pid: h.p.pid, rule: h.rule.id });
  }
  if (hits.length) refreshProcessFindings();
}

/** Rule hits from the last 3 days stay visible as findings. */
export function refreshProcessFindings(): void {
  const rows = db.prepare('SELECT * FROM proc_history WHERE rule IS NOT NULL AND ts >= ? ORDER BY ts DESC LIMIT 200').all(now() - 3 * 86_400_000) as Record<string, any>[];
  const findings: FindingInput[] = [];
  const seen = new Set<string>();
  for (const r of rows) {
    const rule = RULES.find((x) => x.id === r.rule);
    if (!rule) continue;
    const key = `proc:${rule.id}:${r.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      key, category: 'processes', severity: rule.severity,
      title: `${rule.title}${r.agent ? ` (via ${r.agent})` : ''}`,
      // Plain words here; the exact command is in the evidence (Technical details) for those who want it.
      summary: `${r.name} ran at ${new Date(r.ts).toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' })}${r.agent ? `, started by ${r.agent}` : r.parent ? `, started by ${r.parent}` : ''}.`,
      explanation: rule.why, recommendation: rule.todo,
      evidence: { pid: r.pid, path: r.path, command: r.args, startedBy: r.parent, agent: r.agent, at: r.ts, rule: rule.id },
    });
  }
  syncFindings('processes', findings);
}

/** Recent processes, newest first; optionally only those an AI agent started. */
export function processHistory(opts: { agentOnly?: boolean; hours?: number; limit?: number; query?: string } = {}) {
  const since = now() - (opts.hours ?? 24) * 3600_000;
  const where = ['ts >= ?'];
  const params: (string | number)[] = [since];
  if (opts.agentOnly) where.push('agent IS NOT NULL');
  if (opts.query) { where.push('(name LIKE ? OR args LIKE ?)'); params.push(`%${opts.query}%`, `%${opts.query}%`); }
  return db.prepare(`SELECT * FROM proc_history WHERE ${where.join(' AND ')} ORDER BY ts DESC LIMIT ?`).all(...params, opts.limit ?? 300);
}

/** Per-agent summary for the Processes view. */
export function agentActivity(hours = 24) {
  const since = now() - hours * 3600_000;
  return db.prepare(`SELECT agent, COUNT(*) AS n, COUNT(DISTINCT name) AS kinds, MAX(ts) AS last FROM proc_history WHERE agent IS NOT NULL AND ts >= ? GROUP BY agent ORDER BY n DESC`).all(since);
}

export function pruneProcesses(): void {
  db.prepare('DELETE FROM proc_history WHERE ts < ? AND rule IS NULL').run(now() - 3 * 86_400_000);
  db.prepare('DELETE FROM proc_history WHERE ts < ?').run(now() - 30 * 86_400_000);
}

export function processSnapshot(): void {
  putSnapshot('processes', { at: now(), rules: RULES.map((r) => ({ id: r.id, title: r.title, tier: r.tier, why: r.why })) });
}
