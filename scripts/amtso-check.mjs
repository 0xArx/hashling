// Runs the AMTSO Security Features Check (desktop) and the EICAR test file against the Hashling
// running on this Mac, and prints the results as a Markdown table for docs/AMTSO-CHECK.md.
//   node scripts/amtso-check.mjs
// The test files are harmless by design: every antivirus agrees to flag them so people can check
// their protection works. They are never opened, and everything is deleted at the end.
import { mkdtempSync, writeFileSync, copyFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

const BASE = 'http://127.0.0.1:5750';
const TOKEN = readFileSync(join(homedir(), '.hashling/token'), 'utf8').trim();
const FILES = ['https://amtso.eicar.org', 'http://amtso.eicar.org'];
// EICAR's own copies, for when AMTSO's file server does not answer.
const FALLBACK = { 'eicar.com': 'https://secure.eicar.org/eicar.com', 'eicar.zip': 'https://secure.eicar.org/eicar_com.zip', 'eicar-nested.zip': 'https://secure.eicar.org/eicarcom2.zip' };
const PHISHING_PAGE = 'https://www.amtso.org/check-desktop-phishing-page/';
// The EICAR string, split so this script is not itself flagged.
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

const api = async (path, init = {}) => {
  const r = await fetch(BASE + path, { ...init, headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json', ...init.headers } });
  return r.json();
};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function scan(paths) {
  let s = await api('/api/scans', { method: 'POST', body: JSON.stringify({ paths }) });
  if (s.error) throw new Error(s.error);
  while (s.status === 'queued' || s.status === 'running') { await wait(1500); s = await api(`/api/scans/${s.id}`); }
  return s;
}

const dir = mkdtempSync(join(tmpdir(), 'hashling-amtso-'));
const dropped = join(homedir(), 'Downloads', 'hashling-eicar-test.com');
const rows = [];
const from = {};
const row = (test, file, result, pass) => rows.push({ test, file, result, pass });

try {
  writeFileSync(join(dir, 'eicar-made-here.com'), EICAR);
  const names = ['eicar.com', 'eicar.zip', 'eicar-nested.zip', 'eicar.7z', 'eicar.rar', 'eicar.tgz', 'eicar.cab', 'eicar.jar', 'eicar.lzh', 'eicar.ace', 'eicar.exe', 'PotentiallyUnwanted.exe', 'cloudcar.exe'];

  for (const n of names) {
    for (const url of [...FILES.map((f) => `${f}/${n}`), FALLBACK[n]].filter(Boolean)) {
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(10_000) });
        if (r.ok) { writeFileSync(join(dir, n), Buffer.from(await r.arrayBuffer())); from[n] = url; break; }
      } catch { /* try the next source */ }
    }
  }
  // Archives made on this Mac, so the compressed check runs even when no server answers.
  const mk = join(dir, 'made'); execFileSync('mkdir', [mk]); writeFileSync(join(mk, 'eicar.com'), EICAR);
  execFileSync('zip', ['-qj', join(dir, 'eicar-made-here.zip'), join(mk, 'eicar.com')]);
  execFileSync('tar', ['-czf', join(dir, 'eicar-made-here.tgz'), '-C', mk, 'eicar.com']);
  execFileSync('zip', ['-qj', join(mk, 'inner.zip'), join(dir, 'eicar-made-here.zip')]);
  execFileSync('cp', [join(mk, 'inner.zip'), join(dir, 'eicar-made-here-nested.zip')]);
  rmSync(mk, { recursive: true, force: true });

  // 1-3, 6: scan everything on demand.
  const s = await scan([dir]);
  const hit = (n) => s.detections.filter((d) => d.path.endsWith('/' + n)).map((d) => d.signature);
  const verdict = (n) => { const h = hit(n); return h.length ? `Detected: ${[...new Set(h)].join(', ')}` : (existsSync(join(dir, n)) ? 'Not detected' : 'Not downloaded'); };
  row('EICAR test file (made on this Mac)', 'eicar-made-here.com', verdict('eicar-made-here.com'), hit('eicar-made-here.com').length > 0);
  row('Manually downloaded malware', 'eicar.com', verdict('eicar.com'), hit('eicar.com').length > 0);
  for (const n of ['eicar.zip', 'eicar-nested.zip', 'eicar-made-here.zip', 'eicar-made-here-nested.zip', 'eicar-made-here.tgz', 'eicar.7z', 'eicar.rar', 'eicar.tgz', 'eicar.cab', 'eicar.jar', 'eicar.lzh', 'eicar.ace', 'eicar.exe'])
    if (existsSync(join(dir, n))) row('Compressed malware', n, verdict(n), hit(n).length > 0);
  if (existsSync(join(dir, 'PotentiallyUnwanted.exe'))) row('Potentially unwanted app (PUA)', 'PotentiallyUnwanted.exe', verdict('PotentiallyUnwanted.exe'), hit('PotentiallyUnwanted.exe').length > 0);
  else row('Potentially unwanted app (PUA)', 'PotentiallyUnwanted.exe', 'Could not run: AMTSO\'s file server did not answer', null);

  // 6: cloud lookup. Hashling's cloud check is a fingerprint lookup with Team Cymru and CIRCL.
  if (!existsSync(join(dir, 'cloudcar.exe'))) row('Cloud lookup (CloudCar)', 'cloudcar.exe', 'Could not run: AMTSO\'s file server did not answer', null);
  else {
  const cloudScan = verdict('cloudcar.exe');
  const rep = await api('/api/intel/check', { method: 'POST', body: JSON.stringify({ path: join(dir, 'cloudcar.exe') }) });
  const pct = rep.file?.avDetectionPct;
  const cloudHit = hit('cloudcar.exe').length > 0 || (typeof pct === 'number' && pct > 0);
  row('Cloud lookup (CloudCar)', 'cloudcar.exe', `${cloudScan}. Fingerprint lookup: ${typeof pct === 'number' ? `${pct}% of engines flag it` : rep.file?.error ?? 'not known'}`, cloudHit);
  }

  // 4: a file landing in Downloads, the way a drive-by download would.
  copyFileSync(join(dir, 'eicar-made-here.com'), dropped);
  let seen = null;
  for (let i = 0; i < 60 && !seen; i++) {
    await wait(2000);
    const d = await api('/api/downloads');
    seen = d.items?.find((x) => x.path === dropped && x.scan && (x.scan.status === 'done' || x.scan.detections?.length));
  }
  const dl = seen?.scan?.detections?.map((d) => d.signature) ?? [];
  row('Drive-by download (file lands in Downloads)', 'hashling-eicar-test.com', seen ? (dl.length ? `Detected within seconds of arriving: ${[...new Set(dl)].join(', ')}. Not blocked before it was saved.` : 'Seen, not detected') : 'Not seen within 2 minutes', dl.length > 0 ? 'partly' : false);

  // 5: phishing page.
  const flags = await api('/api/scam-flags', { method: 'POST', body: JSON.stringify({ text: PHISHING_PAGE }) });
  const listed = flags.listed?.length ? `Listed: ${flags.listed.map((l) => l.feed).join(', ')}` : 'Not on the public phishing lists Hashling uses';
  row('Phishing page', PHISHING_PAGE, `${listed}. Hashling does not block pages in the browser.`, Boolean(flags.listed?.length));
} finally {
  rmSync(dir, { recursive: true, force: true });
  rmSync(dropped, { force: true });
  // A scan of an empty folder refreshes findings, so the test files' findings close now they are gone.
  const empty = mkdtempSync(join(tmpdir(), 'hashling-amtso-'));
  await scan([empty]).catch(() => {});
  rmSync(empty, { recursive: true, force: true });
}

console.log(`Run on ${new Date().toISOString().slice(0, 10)}\n`);
console.log('| Check | File | Result | |\n|---|---|---|---|');
for (const r of rows) console.log(`| ${r.test} | \`${r.file}\` | ${r.result} | ${r.pass === null ? 'Not run' : r.pass === 'partly' ? 'Partly' : r.pass ? 'Pass' : 'Fail'} |`);
console.log(`\nDownloaded from: ${Object.entries(from).map(([n, u]) => `${n} (${new URL(u).host})`).join(', ') || 'nowhere (no server answered)'}`);
