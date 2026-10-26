import { plural } from './lib/text.ts';
import { existsSync, writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { APP_PATH, DATA_DIR, HOME, HOST, PORT, ROOT, TOKEN_PATH, VERSION, FRESHCLAM_CONF, CLAMAV_DB } from './config.ts';

const LABEL = process.env.HASHLING_LABEL ?? 'dev.hashling.agent'; // overridable so tests never touch the real service
const PLIST = join(HOME, 'Library/LaunchAgents', `${LABEL}.plist`);
const LOG = join(HOME, 'Library/Logs/hashling.log');
const uid = process.getuid?.() ?? 501;
const sh = (cmd: string, args: string[], quiet = false) => spawnSync(cmd, args, { stdio: quiet ? 'pipe' : 'inherit', encoding: 'utf8' });

const [cmd = 'help', ...rest] = process.argv.slice(2);

async function health(): Promise<boolean> {
  try { return (await fetch(`http://${HOST}:${PORT}/api/health`, { signal: AbortSignal.timeout(1500) })).ok; } catch { return false; }
}

async function api(path: string, init: RequestInit = {}) {
  const t = readFileSync(TOKEN_PATH, 'utf8').trim();
  const r = await fetch(`http://${HOST}:${PORT}${path}`, { ...init, headers: { authorization: `Bearer ${t}`, 'content-type': 'application/json', 'x-hashling-client': 'hashling CLI' } });
  return r.json() as Promise<any>;
}

function plist(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array><string>${APP_PATH}/Contents/MacOS/Hashling</string></array>
  <key>AssociatedBundleIdentifiers</key><string>dev.hashling.app</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>2</integer>
  <key>ProcessType</key><string>Standard</string>
  <key>Nice</key><integer>5</integer>
  <key>StandardOutPath</key><string>${LOG}</string>
  <key>StandardErrorPath</key><string>${LOG}</string>
</dict></plist>
`;
}

async function install() {
  mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  if (!existsSync(join(APP_PATH, 'Contents/MacOS/Hashling'))) {
    console.log('Building my app (Hashling.app)...');
    if (sh('/bin/sh', [join(ROOT, 'scripts/build-helpers.sh')]).status !== 0) process.exit(1);
  }
  if (!existsSync(FRESHCLAM_CONF)) {
    mkdirSync(CLAMAV_DB, { recursive: true });
    writeFileSync(FRESHCLAM_CONF, `DatabaseDirectory ${CLAMAV_DB}\nDatabaseMirror database.clamav.net\n`);
  }
  mkdirSync(join(HOME, 'Library/LaunchAgents'), { recursive: true });
  writeFileSync(PLIST, plist());
  sh('/bin/launchctl', ['bootout', `gui/${uid}/${LABEL}`], true);
  // launchd needs a moment to finish unloading before the same job can be loaded again.
  let loaded = false;
  for (let i = 0; i < 10 && !loaded; i++) {
    loaded = sh('/bin/launchctl', ['bootstrap', `gui/${uid}`, PLIST], true).status === 0;
    if (!loaded) await new Promise((res) => setTimeout(res, 500));
  }
  if (!loaded) { console.error('I couldn’t start my background service.'); process.exit(1); }
  for (let i = 0; i < 30 && !(await health()); i++) await new Promise((res) => setTimeout(res, 500));
  console.log(await health() ? `Hashling ${VERSION} here: I’m running, and I’ll start by myself every time you log in.` : `I’m installed but not answering yet. Details are in ${LOG}`);
  console.log('\nOpen my dashboard: click the # in the menu bar, or run  hashling open\n\nUsing an AI coding agent? Connect it to me:\n  Claude Code:  claude mcp add --scope user hashling -- hashling mcp\n  Others:       command "hashling", args ["mcp"]');
}

async function main() {
  switch (cmd) {
    case 'install': return install();
    case 'start': {
      if (!existsSync(PLIST)) return install();
      sh('/bin/launchctl', ['bootstrap', `gui/${uid}`, PLIST], true);
      sh('/bin/launchctl', ['kickstart', `gui/${uid}/${LABEL}`], true);
      return console.log('Started.');
    }
    case 'stop': sh('/bin/launchctl', ['bootout', `gui/${uid}/${LABEL}`], true); return console.log('Stopped. I’ll start again when you log in (run `hashling uninstall` to remove me).');
    case 'restart': sh('/bin/launchctl', ['kickstart', '-k', `gui/${uid}/${LABEL}`]); return console.log('Restarted. I’ll be back in a few seconds.');
    case 'uninstall': {
      sh('/bin/launchctl', ['bootout', `gui/${uid}/${LABEL}`], true);
      rmSync(PLIST, { force: true });
      const all = rest.includes('--all');
      if (all) rmSync(APP_PATH, { recursive: true, force: true });
      // Say exactly what is left behind, so nothing stays on the Mac by surprise.
      let blocked = 0;
      try { blocked = readFileSync(process.env.HASHLING_HOSTS ?? '/etc/hosts', 'utf8').split('\n').filter((l) => l.includes('# added by Hashling') && l.startsWith('0.0.0.0')).length; } catch { /* unreadable */ }
      console.log(`I’ve been removed: I no longer run or start when you log in.${all ? ' Hashling.app is gone too.' : ' Hashling.app is still in Applications (use --all to remove it).'}`);
      console.log('\nStill on this Mac, on purpose:');
      console.log(`  - Your history and any quarantined files, in ${DATA_DIR.replace(HOME, '~')}. Delete that folder if you do not need them.`);
      if (blocked) console.log(`  - ${blocked === 1 ? '1 website you blocked stays' : `${blocked} websites you blocked stay`} blocked. To unblock, remove the lines marked "# added by Hashling" from /etc/hosts.`);
      console.log('  - The hashling command and any AI agent connection. Remove them with:\n      rm "$(command -v hashling)"\n      claude mcp remove hashling');
      return;
    }
    case 'open': {
      if (!(await health())) { console.error('I’m not running. Start me with `hashling start`.'); process.exit(1); }
      // A one-time code (valid 60 s, single use) keeps the real key out of the URL and browser history.
      const { url } = await api('/api/session-code', { method: 'POST' });
      sh('/usr/bin/open', [url + (rest[0] ? `#/${rest[0]}` : '')]);
      return;
    }
    case 'status': {
      if (!(await health())) { console.log('I’m not running. Start me with `hashling start`.'); process.exit(1); }
      const o = await api('/api/overview');
      console.log(`Hashling here. Your Mac scores ${o.score}/100 (${o.grade}): ${o.verdict}.`);
      console.log(`What I found: ${Object.entries(o.openFindings).map(([k, v]) => `${v} ${k}`).join(', ')}`);
      for (const f of o.topFindings) console.log(`  [${f.severity}] ${f.title}`);
      if (o.pendingActions) console.log(`${plural(o.pendingActions, 'fix', 'fixes')} waiting for your OK in my dashboard.`);
      for (const l of o.limitations) console.log(`  note: ${l}`);
      return;
    }
    case 'scan': {
      const r = await api('/api/scans', { method: 'POST', body: JSON.stringify({ paths: rest.length ? rest : ['.'] }) });
      if (r.error) { console.error(r.error); process.exit(1); }
      process.stdout.write(`Scanning ${r.paths.join(', ')} `);
      let s = r;
      while (s.status === 'running' || s.status === 'queued') { await new Promise((res) => setTimeout(res, 1500)); process.stdout.write('.'); s = await api(`/api/scans/${r.id}`); }
      console.log(s.status === 'done' ? `\nDone. I scanned ${plural(s.files_scanned, 'file')} and found ${s.detections.length ? plural(s.detections.length, 'threat') : 'nothing harmful'} (${s.engines.join(', ')}).` : `\n${s.status}: ${s.files_scanned} files, ${plural(s.detections.length, 'detection')} [${s.engines.join(', ')}]`);
      for (const d of s.detections) console.log(`  ${d.signature}  ${d.path}`);
      return;
    }
    case 'mcp': {
      await import('./mcp.ts');
      return;
    }
    case 'run': return import('./daemon.ts');
    case 'logs': sh('/usr/bin/tail', ['-n', '80', '-f', LOG]); return;
    case 'version': case '--version': case '-v': return console.log(VERSION);
    default:
      console.log(`hashling ${VERSION}: your personal AI cybersecurity agent for Mac.

  hashling install     build Hashling.app, start it now and at login
  hashling open        open my dashboard
  hashling status      your score and what I found
  hashling scan PATH   scan files or folders for malware
  hashling mcp         run the MCP server (for AI agents)
  hashling start | stop | restart | logs
  hashling uninstall [--all]`);
  }
}

await main();
