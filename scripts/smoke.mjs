// Starts a throwaway Hashling (its own data folder and port, so it never touches an installed copy),
// checks that the server answers and that the dashboard API refuses strangers, then shuts it down.
//   node scripts/smoke.mjs
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = 5850;
const home = mkdtempSync(join(tmpdir(), 'hashling-smoke-'));
const root = new URL('..', import.meta.url).pathname;
const daemon = spawn(process.execPath, ['--no-warnings', 'src/daemon.ts'], {
  cwd: root,
  env: { ...process.env, HASHLING_HOME: home, HASHLING_PORT: String(PORT), HASHLING_ENRICH: '0' },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '';
daemon.stdout.on('data', (d) => { log += d; });
daemon.stderr.on('data', (d) => { log += d; });

const base = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fail = (msg) => { throw new Error(msg); };

async function waitForHealth() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) return r.json();
    } catch { /* not listening yet */ }
    if (daemon.exitCode !== null) fail(`Hashling exited early (code ${daemon.exitCode})`);
    await sleep(500);
  }
  fail('Hashling did not answer /api/health within 30 s');
}

try {
  const health = await waitForHealth();
  if (health.ok !== true || health.name !== 'hashling') fail(`unexpected health reply: ${JSON.stringify(health)}`);

  const stranger = await fetch(`${base}/api/overview`);
  if (stranger.status !== 401) fail(`/api/overview without a token answered ${stranger.status}, expected 401`);

  const tokenFile = join(home, 'token');
  if (!existsSync(tokenFile)) fail('no token file was created');
  const token = readFileSync(tokenFile, 'utf8').trim();
  const overview = await fetch(`${base}/api/overview`, { headers: { authorization: `Bearer ${token}` } });
  if (!overview.ok) fail(`/api/overview with the token answered ${overview.status}`);
  const body = await overview.json();
  if (typeof body.score !== 'number') fail('overview has no score');

  const crossSite = await fetch(`${base}/api/overview`, { headers: { authorization: `Bearer ${token}`, 'sec-fetch-site': 'cross-site' } });
  if (crossSite.status !== 403) fail(`a cross-site request answered ${crossSite.status}, expected 403`);

  console.log(`Smoke test passed: health ok, strangers refused, cross-site refused, overview score ${body.score}.`);
} catch (err) {
  console.error(`Smoke test failed: ${err.message}\n--- Hashling output ---\n${log.slice(-4000)}`);
  process.exitCode = 1;
} finally {
  daemon.kill('SIGTERM');
  await sleep(500);
  if (daemon.exitCode === null) daemon.kill('SIGKILL');
  rmSync(home, { recursive: true, force: true });
}
