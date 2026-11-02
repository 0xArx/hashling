// Checks that normal developer files and signed apps stop raising malware alarms while real threats still do,
// inside a throwaway home folder. Needs no scanning engine: the matches are written in as if a scan had found them.
//   node scripts/test-scan.mjs
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const home = mkdtempSync(join(tmpdir(), 'hashling-scan-'));
const file = (rel, text = 'x') => { const p = join(home, rel); mkdirSync(join(p, '..'), { recursive: true }); writeFileSync(p, text); return p; };

// The rules behind the real false alarms, and a real malware rule, exactly as the scanner records them.
const WASM = { engine: 'yara-x', ruleset: 'custom', signature: 'DELIVRTO_SUSP_HTML_WASM_Smuggling', score: 70, description: 'Presence of Base64 JavaScript blob loading WASM' };
const SMUGGLE = { engine: 'yara-x', ruleset: 'custom', signature: 'ELCEEF_HTML_Smuggling_A', score: 75, description: 'Generic detection for HTML smuggling (T1027.006)' };
const REAL = { engine: 'yara-x', ruleset: 'custom', signature: 'MacOS_Trojan_Generic_d1b2c3e4' }; // Elastic's real naming, the word Generic included
const GENERIC = { engine: 'yara-x', ruleset: 'custom', signature: 'SEKOIA_Generic_Tor_Hidden_Service_Leading_To_Winports', score: 75, description: 'Detects malicious TOR redirection' };
const REAL2 = { engine: 'yara-x', ruleset: 'custom', signature: 'SEKOIA_Win_Malware_Agnianestealer', score: 75, description: 'Detect the Agniane stealer using strings' };
const APPLE = { engine: 'yara-x', ruleset: 'xprotect', signature: 'XProtect_MACOS_SUSP_Thing' };
const PHISH = { engine: 'clamav', signature: 'Email.Phishing.Auction-297' };
const CLAM = { engine: 'clamav', signature: 'Osx.Trojan.Generic-1234' };
const EICAR = { engine: 'clamav', signature: 'Eicar-Test-Signature' };

const paths = {
  napi: file('Developer/app/node_modules/@napi-rs/wasm-runtime/dist/runtime.js'),
  pdf: file('Desktop/Projects/a/node_modules/pdf-parse/dist/cjs/index.cjs'),
  pyPkg: file('.venv/lib/python3.13/site-packages/x/y.js'),
  maildir: file('Desktop/ECE419/maildir/saibi-e/inbox/181.'),
  evilPkg: file('Developer/app/node_modules/evil-pkg/index.js'),
  evilPkg2: file('Developer/app/node_modules/other-evil/index.js'),
  evilPkg3: file('Developer/app/node_modules/third-evil/index.js'),
  stealer: file('Applications/Fake.app/Contents/MacOS/Fake'),
  unsignedApp: file('Applications/Homemade.app/Contents/Resources/a.js'),
  appleHit: file('Library/LaunchAgents/helper'),
  clamHit: file('Downloads/installer.dmg'),
  eicar: file('Downloads/eicar.com'),
  dlHtml: file('Downloads/invoice.html'),
  dlPkg: file('Downloads/shared/node_modules/p/i.js'),
  dlMail: file('Downloads/saved.eml'),
  localHtml: file('Documents/page.html'),
};
for (const p of [paths.dlHtml, paths.dlPkg, paths.dlMail]) spawnSync('/usr/bin/xattr', ['-w', 'com.apple.quarantine', '0081;00000000;Safari;', p]);
const signedFile = '/System/Applications/Calculator.app/Contents/Info.plist'; // a really signed app on every Mac

const hits = [
  [paths.napi, WASM], [paths.pdf, WASM], [paths.pyPkg, SMUGGLE], [signedFile, SMUGGLE], [paths.maildir, PHISH],
  [paths.evilPkg, REAL], [paths.evilPkg2, REAL2], [paths.evilPkg3, GENERIC], [paths.stealer, REAL], [paths.unsignedApp, SMUGGLE], [paths.appleHit, APPLE], [paths.clamHit, CLAM], [paths.eicar, EICAR],
  [paths.dlHtml, SMUGGLE], [paths.dlPkg, WASM], [paths.dlMail, PHISH], [paths.localHtml, WASM],
].map(([path, d]) => ({ path, ...d }));

const env = { ...process.env, HOME: home, HASHLING_HOME: join(home, '.hashling') };
const out = spawnSync(process.execPath, ['--no-warnings', '--input-type=module', '-e', `
  const here = ${JSON.stringify(root)};
  const { db } = await import(here + 'src/db.ts');
  const { refreshScanFindings, getScan, collectYara, isSignedApp, yaraArgs, compiledCustomRules } = await import(here + 'src/scanner.ts');
  const { listFindings } = await import(here + 'src/db.ts');
  const hits = ${JSON.stringify(hits)};
  db.prepare("INSERT INTO scans (id, paths, requested_by, status, started_at, detections) VALUES ('t1', '[]', 'test', 'done', 1, ?)").run(JSON.stringify(hits));
  refreshScanFindings();
  // Rules compiled by an older engine: newer than their source, but they no longer load, so they must be rebuilt.
  let rebuilt = null;
  if (${JSON.stringify(existsSync('/opt/homebrew/bin/yr') || existsSync('/usr/local/bin/yr'))}) {
    const { mkdirSync, writeFileSync, utimesSync } = await import('node:fs');
    const data = process.env.HASHLING_HOME;
    mkdirSync(data + '/rules', { recursive: true });
    writeFileSync(data + '/rules/t.yar', 'rule t { condition: true }');
    utimesSync(data + '/rules/t.yar', new Date(1000), new Date(1000));
    writeFileSync(data + '/custom.yarc', 'compiled by an older engine');
    rebuilt = { path: await compiledCustomRules() };
  }
  const parsed = [];
  collectYara(JSON.stringify({ path: '/x/a.js', rules: [{ identifier: 'R1', meta: [['description', 'Generic thing'], ['score', 70]] }] }), 'custom', parsed);
  console.log(JSON.stringify({
    findings: listFindings({ status: 'open' }).map((f) => ({ key: f.key, severity: f.severity, tier: f.tier, title: f.title })),
    verdicts: Object.fromEntries(getScan('t1').detections.map((d) => [d.path, d.verdict])),
    why: getScan('t1').detections.find((d) => d.path.endsWith('runtime.js')).why,
    parsed: parsed[0],
    rebuilt,
    fileArgs: yaraArgs('rules.yarc', ${JSON.stringify(paths.localHtml)}),
    folderArgs: yaraArgs('rules.yarc', ${JSON.stringify(join(home, 'Documents'))}),
    signed: isSignedApp('/System/Applications/Calculator.app'),
    unsigned: isSignedApp(${JSON.stringify(join(home, 'Applications/Homemade.app'))}),
  }));
  process.exit(0);`], { env, encoding: 'utf8' });

let failed = false;
const check = (ok, what) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failed = true; };
try {
  if (out.status !== 0) throw new Error(out.stderr || 'the check crashed');
  const r = JSON.parse(out.stdout.trim().split('\n').pop());
  const f = (p) => r.findings.find((x) => x.key.endsWith(':' + p));
  const name = (p) => p.replace(home, '~');
  for (const p of [paths.napi, paths.pdf, paths.pyPkg]) check(!f(p), `a general pattern in a developer package stays quiet: ${name(p)}`);
  check(!f(signedFile), 'a general pattern inside a signed, intact app stays quiet');
  check(!f(paths.maildir), 'a phishing email in an old mail folder stays quiet');
  check(r.verdicts[paths.napi] === 'quiet' && /developer package/.test(r.why), 'the match is still kept in the scan, with the reason it is harmless');
  for (const p of [paths.evilPkg, paths.evilPkg2, paths.evilPkg3]) check(f(p)?.severity === 'high' && f(p)?.tier === 'suspicious', `known malware inside node_modules is still a high warning: ${name(p)}`);
  check(f(paths.stealer)?.severity === 'high' && /^Malware signature/.test(f(paths.stealer)?.title), 'known malware in an app is still a high warning');
  check(f(paths.appleHit)?.severity === 'high', 'a match on Apple’s own rules is always a high warning, whatever its name');
  check(f(paths.clamHit)?.severity === 'high', 'a ClamAV malware signature is still a high warning');
  check(f(paths.eicar)?.severity === 'medium', 'the EICAR test file still shows, so people can check scanning works');
  check(f(paths.dlHtml)?.tier === 'suspicious' && /^Suspicious download/.test(f(paths.dlHtml)?.title), 'a downloaded file with a smuggling pattern is still a high warning');
  check(f(paths.dlPkg)?.tier === 'suspicious', 'node_modules from a download is not trusted');
  check(f(paths.unsignedApp)?.tier === 'risk' && f(paths.unsignedApp)?.severity === 'low', 'a pattern in an app with no real signature is worth a look');
  check(f(paths.localHtml)?.tier === 'risk' && /^Worth a look/.test(f(paths.localHtml)?.title), 'a pattern in some other file of yours is worth a look, not an alarm');
  check(!f(paths.dlMail), 'a phishing email saved from the internet stays quiet too: it is not an infection');
  check(r.signed === true && r.unsigned === false, 'a real Apple signature passes and a folder named .app does not');
  check(r.parsed?.score === 70 && r.parsed?.description === 'Generic thing', 'the scanner keeps each rule’s score and description');
  check(!r.fileArgs.includes('--recursive') && r.folderArgs.includes('--recursive'), 'a single file is scanned without --recursive, which the engine refuses');
  // The real engine, where it is installed: it must see the same file on its own and inside a folder.
  const yr = ['/opt/homebrew/bin/yr', '/usr/local/bin/yr'].find((b) => existsSync(b));
  if (yr) {
    const probe = file('Documents/probe/a.txt', 'hashling-probe-string');
    const rules = join(home, 'r.yarc');
    writeFileSync(join(home, 'r.yar'), 'rule probe { strings: $a = "hashling-probe-string" condition: $a }');
    spawnSync(yr, ['compile', '-o', rules, join(home, 'r.yar')]);
    const scan = (args, target) => spawnSync(yr, [...args.slice(0, -2), rules, target], { encoding: 'utf8' });
    const reloaded = spawnSync(yr, ['scan', '--disable-warnings', '-C', r.rebuilt.path, '/etc/hosts']);
    check(reloaded.status === 0, 'rules an engine update left unloadable are rebuilt, not silently skipped');
    check(scan(r.fileArgs, probe).stdout.includes('"probe"'), 'the real engine matches a single file');
    check(scan(r.folderArgs, join(home, 'Documents')).stdout.includes('"probe"'), 'the real engine matches inside a folder');
  }
  console.log(failed ? 'Scan judgement tests failed.' : 'Scan judgement tests passed: real threats still warn, normal developer files stay quiet.');
} catch (e) {
  console.error(`Scan judgement test crashed: ${e.stack}`);
  failed = true;
} finally {
  rmSync(home, { recursive: true, force: true });
}
process.exitCode = failed ? 1 : 0;
