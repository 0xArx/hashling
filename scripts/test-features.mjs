// Tests updates and fully local AI against stand-in servers, in a sandbox: no real release, no real model,
// no install and no Touch ID. Run with: node scripts/test-features.mjs
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), 'hashling-features-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const servers = [];
let daemon = null;
let failed = false;
const check = (ok, what) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failed = true; };

function serve(handler) {
  return new Promise((resolve) => {
    const s = createServer(handler);
    servers.push(s);
    s.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${s.address().port}`));
  });
}

/** Run a snippet against a module in a fresh Node process, so environment variables apply before it loads. */
function node(code, env) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, ['--no-warnings', '--input-type=module', '-e', code], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    p.on('close', () => resolve(out.trim()));
  });
}

try {
  // ---------- updates ----------
  const tgzName = 'hashling-9.9.9-source.tar.gz';
  const tgz = join(tmp, tgzName);
  execFileSync('git', ['archive', '--format=tar.gz', '--prefix=hashling-9.9.9/', '-o', tgz, 'HEAD'], { cwd: root });
  const sha = createHash('sha256').update(readFileSync(tgz)).digest('hex');
  const release = (base, sumsPath) => JSON.stringify({ tag_name: 'v9.9.9', html_url: 'https://example.invalid/v9.9.9', published_at: new Date().toISOString(), assets: [
    { name: tgzName, browser_download_url: `${base}/src` }, { name: 'SHA256SUMS.txt', browser_download_url: `${base}${sumsPath}` }] });
  const gh = await serve((req, res) => {
    const base = `http://${req.headers.host}`;
    if (req.url === '/latest') return res.end(release(base, '/sums'));
    if (req.url === '/latest-bad') return res.end(release(base, '/bad-sums'));
    if (req.url === '/src') return res.end(readFileSync(tgz));
    if (req.url === '/sums') return res.end(`${sha}  ${tgzName}\n`);
    if (req.url === '/bad-sums') return res.end(`${'0'.repeat(64)}  ${tgzName}\n`);
    res.statusCode = 404; res.end();
  });

  // An installed copy has no .git folder; a git checkout is told to use git pull instead.
  const app = join(tmp, 'app');
  cpSync(join(root, 'src'), join(app, 'src'), { recursive: true });
  cpSync(join(root, 'package.json'), join(app, 'package.json'));
  symlinkSync(join(root, 'node_modules'), join(app, 'node_modules'));
  const run = (url) => node(`
    const u = await import(${JSON.stringify(join(app, 'src/updates.ts'))});
    const s = await u.checkForUpdate();
    const r = await u.installUpdate();
    console.log(JSON.stringify({ s, r, newer: [u.newer('0.10.0', '0.9.9'), u.newer('0.1.0', '0.1.0'), u.newer('v1.2.0', '1.10.0')] }));
    process.exit(0);`, { HASHLING_HOME: join(tmp, 'home-upd'), HASHLING_UPDATE_URL: `${gh}${url}`, HASHLING_UPDATE_DRY_RUN: '1', HASHLING_NO_UPDATE_CHECK: '1' });
  const good = JSON.parse((await run('/latest')).split('\n').pop());
  check(good.s.available && good.s.canInstall && good.s.latest.version === '9.9.9', 'a newer release is found and can be installed');
  check(good.r.ok === true, 'the download matches its checksum and unpacks (test run, not installed)');
  check(JSON.stringify(good.newer) === '[true,false,false]', 'version comparison');
  const bad = JSON.parse((await run('/latest-bad')).split('\n').pop());
  check(Boolean(bad.r.error) && /checksum/.test(bad.r.error), 'a download that does not match its checksum is refused');
  const dev = JSON.parse((await node(`
    const u = await import(${JSON.stringify(join(root, 'src/updates.ts'))});
    await u.checkForUpdate(); console.log(JSON.stringify(u.updateState())); process.exit(0);`,
  { HASHLING_HOME: join(tmp, 'home-dev'), HASHLING_UPDATE_URL: `${gh}/latest`, HASHLING_NO_UPDATE_CHECK: '1' })).split('\n').pop());
  check(dev.available && !dev.canInstall && dev.devCheckout, 'a git checkout sees the update but is told to use git pull');

  // ---------- fully local AI ----------
  const seen = [];
  const sse = (res, chunks) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); for (const c of chunks) res.write(`data: ${JSON.stringify({ choices: [{ delta: c }] })}\n\n`); res.end('data: [DONE]\n\n'); };
  const model = await serve(async (req, res) => {
    if (req.url === '/v1/models') return res.end(JSON.stringify({ data: [{ id: 'stand-in' }] }));
    let body = '';
    for await (const c of req) body += c;
    const j = JSON.parse(body);
    seen.push(j);
    const toolResult = j.messages.find((m) => m.role === 'tool');
    if (!toolResult) return sse(res, [{ content: '<think>plan' }, { content: 'ning</think>Let me check. ' }, { tool_calls: [{ index: 0, id: 'c1', function: { name: 'security_overview', arguments: '{}' } }] }]);
    // Hashling caps tool results at 8,000 characters for models, so read the score without parsing the whole result.
    const score = Number(String(toolResult.content).match(/"score":\s*(\d+)/)?.[1]);
    sse(res, [{ content: `**Your Mac scores ${score}.** ` }, { content: 'Nothing else to do.' }]);
  });

  const home = join(tmp, 'home-ai');
  const port = 5860;
  daemon = spawn(process.execPath, ['--no-warnings', 'src/daemon.ts'], { cwd: root, stdio: 'ignore',
    env: { ...process.env, HASHLING_HOME: home, HASHLING_PORT: String(port), HASHLING_ENRICH: '0', HASHLING_NO_UPDATE_CHECK: '1', HASHLING_SKIP: 'network,processes,storage' } });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 60 && !(await fetch(`${base}/api/health`).then((r) => r.ok).catch(() => false)); i++) await sleep(500);
  const token = readFileSync(join(home, 'token'), 'utf8').trim();
  const dash = { cookie: `hashling_session=${token}`, 'content-type': 'application/json' };

  const local = await (await fetch(`${base}/api/ai/local`, { headers: dash })).json();
  check(local.recommended && local.models.length === 5 && local.specs.ramGB > 0, `a model is picked for this Mac (${local.recommended} for ${local.specs.ramGB} GB)`);
  const remote = await fetch(`${base}/api/ai/local`, { method: 'POST', headers: dash, body: JSON.stringify({ choice: 'server', serverUrl: 'https://example.com', serverModel: 'x' }) });
  check(remote.status === 400, 'a model server that is not on this Mac is refused');
  const set = await (await fetch(`${base}/api/ai/local`, { method: 'POST', headers: dash, body: JSON.stringify({ choice: 'server', serverUrl: model, serverModel: 'stand-in' }) })).json();
  check(set.config.choice === 'server', 'local mode switched on with a model server on this Mac');
  for (let i = 0; i < 20; i++) { const s = await (await fetch(`${base}/api/ai/status`, { headers: dash })).json(); if (s.ready) break; await sleep(250); }
  const status = await (await fetch(`${base}/api/ai/status`, { headers: dash })).json();
  check(status.ready && status.provider === 'local', 'the assistant reports fully local and ready');

  const ask = await fetch(`${base}/api/ai/ask`, { method: 'POST', headers: dash, body: JSON.stringify({ message: 'Is my Mac safe?' }) });
  const events = (await ask.text()).trim().split('\n').map((l) => JSON.parse(l));
  const text = events.filter((e) => e.type === 'text').map((e) => e.text).join('');
  check(events.some((e) => e.type === 'tool' && e.name === 'security_overview'), 'the local model called a Hashling tool');
  check(/Your Mac scores \d+/.test(text) && !/think|plan/.test(text), 'the answer uses the tool result and hides the model’s private reasoning');
  check(events.at(-1)?.type === 'done', 'the answer finished');
  check(seen[0]?.tools?.length > 5 && seen[0].tools.length < 20 && seen[0].tools.every((t) => t.type === 'function'), 'the model was offered a focused set of tools');

  const cfg = await (await fetch(`${base}/api/ai/config`, { headers: dash })).json();
  check(cfg.provider === 'local', 'the provider stays on fully local');
} catch (e) {
  console.error(`Test crashed: ${e.stack}`);
  failed = true;
} finally {
  daemon?.kill('SIGTERM');
  for (const s of servers) s.close();
  await sleep(300);
  rmSync(tmp, { recursive: true, force: true });
}
console.log(failed ? 'Feature tests failed.' : 'Feature tests passed: updates and fully local AI.');
process.exit(failed ? 1 : 0);
