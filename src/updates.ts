/**
 * Updates. Hashling checks GitHub for a newer release (never for every code change), shows an
 * "Update now" button, and on the user's Touch ID downloads that release's source, checks it against
 * the release's SHA-256 checksums and runs the same installer a first install uses. The installer
 * swaps ~/.hashling/app in one move and restarts Hashling, so open dashboards reload on the new version.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createWriteStream, existsSync, mkdirSync, openSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { DATA_DIR, ROOT, VERSION } from './config.ts';
import { bus } from './bus.ts';
import { logEvent } from './db.ts';
import { run } from './lib/exec.ts';

const RELEASES = process.env.HASHLING_UPDATE_URL ?? 'https://api.github.com/repos/0xArx/hashling/releases/latest';
const UPDATE_DIR = join(DATA_DIR, 'updates');
const LOG = join(UPDATE_DIR, 'update.log');
const CHECK_EVERY = 6 * 3600_000;

type Phase = 'idle' | 'checking' | 'downloading' | 'verifying' | 'installing' | 'error';
interface Release { version: string; url: string; publishedAt: string | null; source: string; sums: string; sourceName: string }

const state: { phase: Phase; latest: Release | null; checkedAt: number | null; error: string | null } = { phase: 'idle', latest: null, checkedAt: null, error: null };

/** Running from a git checkout means a developer copy: it updates with git, not with this button. */
const devCheckout = existsSync(join(ROOT, '.git'));

/** "0.10.1" > "0.9.3", ignoring a leading v and anything after a dash. */
export function newer(a: string, b: string): boolean {
  const p = (v: string) => v.replace(/^v/, '').split('-')[0].split('.').map((n) => Number(n) || 0);
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  return false;
}

export function updateState() {
  const available = Boolean(state.latest && newer(state.latest.version, VERSION));
  return {
    current: VERSION,
    latest: state.latest ? { version: state.latest.version, url: state.latest.url, publishedAt: state.latest.publishedAt } : null,
    available,
    canInstall: available && !devCheckout,
    devCheckout,
    phase: state.phase,
    error: state.error,
    checkedAt: state.checkedAt,
  };
}

function setPhase(phase: Phase, error: string | null = null): void {
  state.phase = phase;
  state.error = error;
  bus.emit('change', { type: 'update' });
}

export async function checkForUpdate(): Promise<ReturnType<typeof updateState>> {
  if (state.phase !== 'idle' && state.phase !== 'error') return updateState();
  setPhase('checking');
  try {
    const r = await fetch(RELEASES, { headers: { accept: 'application/vnd.github+json', 'user-agent': `hashling/${VERSION}` }, signal: AbortSignal.timeout(15_000) });
    if (!r.ok) throw new Error(r.status === 404 ? 'No release has been published yet.' : `GitHub answered ${r.status}.`);
    const j = await r.json() as { tag_name?: string; html_url?: string; published_at?: string; draft?: boolean; prerelease?: boolean; assets?: { name: string; browser_download_url: string }[] };
    const version = String(j.tag_name ?? '').replace(/^v/, '');
    const source = j.assets?.find((a) => /^hashling-.*-source\.tar\.gz$/.test(a.name));
    const sums = j.assets?.find((a) => a.name === 'SHA256SUMS.txt');
    state.latest = !j.draft && !j.prerelease && version && source && sums
      ? { version, url: j.html_url ?? '', publishedAt: j.published_at ?? null, source: source.browser_download_url, sums: sums.browser_download_url, sourceName: source.name }
      : null;
    state.checkedAt = Date.now();
    if (state.latest && newer(state.latest.version, VERSION)) logEvent('update', 'info', `Hashling ${state.latest.version} is available`, { version: state.latest.version });
    setPhase('idle');
  } catch (e) {
    state.checkedAt = Date.now();
    setPhase('error', `I couldn’t check for updates: ${(e as Error).message}`);
  }
  return updateState();
}

async function download(url: string, file: string): Promise<void> {
  const r = await fetch(url, { headers: { 'user-agent': `hashling/${VERSION}` }, signal: AbortSignal.timeout(10 * 60_000) });
  if (!r.ok || !r.body) throw new Error(`the download failed (${r.status})`);
  await pipeline(Readable.fromWeb(r.body as never), createWriteStream(file));
}

/** Download, verify and hand over to the installer. The caller has already asked for Touch ID. */
export async function installUpdate(): Promise<{ ok: true; version: string } | { error: string }> {
  const s = updateState();
  if (!s.available || !state.latest) return { error: 'There is no newer version to install.' };
  if (devCheckout) return { error: 'This copy of Hashling runs from its source code. Update it with git pull.' };
  if (state.phase !== 'idle' && state.phase !== 'error') return { error: 'An update is already in progress.' };
  const rel = state.latest;
  try {
    rmSync(UPDATE_DIR, { recursive: true, force: true });
    mkdirSync(UPDATE_DIR, { recursive: true, mode: 0o700 });
    setPhase('downloading');
    const tgz = join(UPDATE_DIR, rel.sourceName);
    const sumsFile = join(UPDATE_DIR, 'SHA256SUMS.txt');
    await download(rel.sums, sumsFile);
    await download(rel.source, tgz);

    setPhase('verifying');
    const want = readFileSync(sumsFile, 'utf8').split('\n').map((l) => l.trim().split(/\s+/)).find(([, name]) => name === rel.sourceName)?.[0];
    const got = createHash('sha256').update(readFileSync(tgz)).digest('hex');
    if (!want || want.toLowerCase() !== got) throw new Error('the download did not match its published checksum, so I did not install it');

    const src = join(UPDATE_DIR, 'src');
    mkdirSync(src);
    const x = await run('/usr/bin/tar', ['-xzf', tgz, '-C', src, '--strip-components', '1'], { timeout: 120_000 });
    if (!x.ok || !existsSync(join(src, 'scripts/install.sh'))) throw new Error('the download could not be unpacked');

    if (process.env.HASHLING_UPDATE_DRY_RUN) {
      logEvent('update', 'info', `Update to ${rel.version} downloaded and verified (test run, not installed)`, {});
      setPhase('idle');
      return { ok: true, version: rel.version };
    }

    setPhase('installing');
    logEvent('update', 'info', `Updating Hashling to ${rel.version}`, { from: VERSION });
    // The installer restarts Hashling, so it runs in its own process group and outlives this one.
    const out = openSync(LOG, 'a');
    const child = spawn('/bin/sh', [join(src, 'scripts/install.sh')], {
      cwd: UPDATE_DIR, detached: true, stdio: ['ignore', out, out],
      env: { ...process.env, HASHLING_SOURCE: tgz, HASHLING_ANSWER: 'n', HASHLING_SKIP_SIGNATURES: '1', HASHLING_NO_OPEN: '1' },
    });
    child.on('exit', (code) => { if (code) setPhase('error', `The update did not finish. Nothing was replaced. Details are in ${LOG}`); });
    child.unref();
    return { ok: true, version: rel.version };
  } catch (e) {
    setPhase('error', `I didn’t update: ${(e as Error).message}.`);
    return { error: state.error! };
  }
}

/** Check soon after starting, then every 6 hours. */
export function startUpdateChecks(): void {
  if (process.env.HASHLING_NO_UPDATE_CHECK) return;
  setTimeout(() => void checkForUpdate(), 60_000).unref();
  setInterval(() => void checkForUpdate(), CHECK_EVERY).unref();
}
