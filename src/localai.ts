/**
 * Fully local AI. Hashling runs an open model on this Mac with llama.cpp, so questions and answers
 * never leave it. It picks a model that fits the Mac's memory (or the one the user chose), installs the
 * llama.cpp engine with Homebrew, downloads the model once into ~/.hashling/models and checks it against
 * the SHA-256 Hugging Face publishes. The model server starts on the first question and stops after a few
 * idle minutes, so it only holds memory while it is in use. A model server the user already runs on this
 * Mac (Ollama, LM Studio, llama.cpp) can be used instead; it must be on this Mac.
 *
 * The chat loop gives the model the same Hashling tools Claude gets (read-only, plus propose_action,
 * which still waits for Touch ID).
 */
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, statfsSync, writeFileSync } from 'node:fs';
import { totalmem } from 'node:os';
import { basename, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { DATA_DIR, PORT, ROOT } from './config.ts';
import { bus } from './bus.ts';
import { logEvent } from './db.ts';
import { run } from './lib/exec.ts';

const CONFIG_PATH = join(DATA_DIR, 'config.json');
const MODELS_DIR = join(DATA_DIR, 'models');
const LOCAL_PORT = Number(process.env.HASHLING_LOCAL_AI_PORT ?? PORT + 20);
const IDLE_STOP = 10 * 60_000;
const GB = 1e9;

/** Open-weight models (Apache 2.0), smallest first. minRamGB is the Mac memory each one is comfortable with. */
export const LOCAL_MODELS = [
  { id: 'qwen3-1.7b', label: 'Qwen3 1.7B', repo: 'Qwen/Qwen3-1.7B-GGUF', file: 'Qwen3-1.7B-Q8_0.gguf', sizeGB: 1.8, minRamGB: 4, note: 'Tiny and quick. Good for scam checks, but it can get details about your Mac wrong.' },
  { id: 'qwen3-4b', label: 'Qwen3 4B', repo: 'unsloth/Qwen3-4B-Instruct-2507-GGUF', file: 'Qwen3-4B-Instruct-2507-Q4_K_M.gguf', sizeGB: 2.5, minRamGB: 8, note: 'A good everyday helper for most Macs.' },
  { id: 'qwen3-8b', label: 'Qwen3 8B', repo: 'Qwen/Qwen3-8B-GGUF', file: 'Qwen3-8B-Q4_K_M.gguf', sizeGB: 5.0, minRamGB: 24, note: 'Clearer answers, a little slower.' },
  { id: 'gpt-oss-20b', label: 'gpt-oss 20B', repo: 'ggml-org/gpt-oss-20b-GGUF', file: 'gpt-oss-20b-MXFP4.gguf', sizeGB: 12.1, minRamGB: 36, note: 'Strong at using my tools. Needs plenty of memory.' },
  { id: 'qwen3-30b', label: 'Qwen3 30B-A3B', repo: 'Qwen/Qwen3-30B-A3B-GGUF', file: 'Qwen3-30B-A3B-Q4_K_M.gguf', sizeGB: 18.6, minRamGB: 64, note: 'The most capable here, and still quick on big Macs.' },
] as const;

/**
 * Common questions whose data Hashling fetches before the model answers. Very small models sometimes
 * describe a tool instead of calling it, so these answers never depend on that.
 */
const PREFETCH: [RegExp, string][] = [
  [/\b(space|storage|disk|slow|clean ?up|free up|full)\b/i, 'storage_report'],
  [/\b(changed?|new since|since yesterday|what'?s new|anything new)\b/i, 'what_changed'],
  [/\b(upload|uploaded|sent out|left my mac)\b/i, 'uploads_report'],
  [/\b(ai apps?|agents?|claude code|cursor|codex)\b/i, 'agent_inventory'],
  [/\b(repo|repos|repository|project|projects|folder|clone[d]?)\b/i, 'risky_projects'],
];

/** The tools a local model gets: the ones that answer most questions, so a small model is not swamped. */
const LOCAL_TOOLS = new Set(['risky_projects', 'security_overview', 'list_findings', 'explain_finding', 'scam_check', 'investigate_app', 'what_changed', 'network_activity', 'agent_inventory', 'uploads_report', 'storage_report', 'system_posture', 'permissions', 'persistence_items', 'hashling_health', 'propose_action', 'list_actions']);

export interface LocalConfig {
  /** 'auto' picks by memory; a catalog id; 'custom' (a Hugging Face model or a .gguf file); 'server' (a model server already running on this Mac). */
  choice: string;
  custom?: string;
  serverUrl?: string;
  serverModel?: string;
}

type Phase = 'idle' | 'installing-engine' | 'downloading' | 'verifying' | 'ready' | 'error';
const st: { phase: Phase; done: number; total: number; error: string | null; label: string | null } = { phase: 'idle', done: 0, total: 0, error: null, label: null };
let setupRun: Promise<void> | null = null;
let server: ChildProcess | null = null;
let serverModelPath: string | null = null;
let idleTimer: NodeJS.Timeout | null = null;

// ---------- configuration ----------

function readAll(): Record<string, unknown> {
  try { return JSON.parse(readFileSync(CONFIG_PATH, 'utf8')); } catch { return {}; }
}

export function loadLocalConfig(): LocalConfig {
  const c = readAll().localAi as LocalConfig | undefined;
  return { choice: 'auto', ...(c ?? {}) };
}

/** A model server address must be on this Mac, or "fully local" would not be true. */
export function isLoopbackUrl(u: string): boolean {
  try {
    const url = new URL(u);
    return ['http:', 'https:'].includes(url.protocol) && ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(url.hostname);
  } catch { return false; }
}

export function saveLocalConfig(patch: Partial<LocalConfig>): LocalConfig | { error: string } {
  const next: LocalConfig = { ...loadLocalConfig(), ...patch };
  const ids = LOCAL_MODELS.map((m) => m.id) as string[];
  if (!['auto', 'custom', 'server', ...ids].includes(next.choice)) return { error: 'Unknown model choice.' };
  if (next.choice === 'custom' && !next.custom?.trim()) return { error: 'Type a Hugging Face model (like Qwen/Qwen3-8B-GGUF) or the path to a .gguf file on this Mac.' };
  if (next.choice === 'server') {
    if (!next.serverUrl || !isLoopbackUrl(next.serverUrl)) return { error: 'The model server must run on this Mac, for example http://127.0.0.1:11434 for Ollama.' };
    if (!next.serverModel?.trim()) return { error: 'Type the model name your server uses, for example qwen3:8b.' };
  }
  next.custom = next.custom?.trim().slice(0, 300);
  next.serverModel = next.serverModel?.trim().slice(0, 120);
  writeFileSync(CONFIG_PATH, JSON.stringify({ ...readAll(), localAi: next }, null, 2), { mode: 0o600 });
  stopServer();
  if (st.phase === 'ready' || st.phase === 'error') setPhase('idle');
  return next;
}

// ---------- this Mac ----------

let chip: string | null = null;
export function macSpecs(): { ramGB: number; chip: string } {
  if (chip === null) {
    try { chip = execFileSync('/usr/sbin/sysctl', ['-n', 'machdep.cpu.brand_string'], { encoding: 'utf8', timeout: 3000 }).trim(); } catch { chip = 'Mac'; }
  }
  return { ramGB: Math.round(totalmem() / 2 ** 30), chip };
}

export function recommendedModel(ramGB = macSpecs().ramGB) {
  // The tiny model is only ever a manual choice: automatic picks start at the 4B, which gets details right.
  return [...LOCAL_MODELS].reverse().find((m) => m.id !== 'qwen3-1.7b' && ramGB >= m.minRamGB) ?? LOCAL_MODELS[1];
}

function freeGB(): number {
  try { const s = statfsSync(DATA_DIR); return (s.bavail * s.bsize) / GB; } catch { return 0; }
}

function brewPrefix(): string {
  return existsSync('/opt/homebrew/bin/brew') ? '/opt/homebrew' : '/usr/local';
}

function enginePath(): string {
  return process.env.HASHLING_LLAMA_SERVER ?? join(brewPrefix(), 'bin/llama-server');
}

// ---------- what to run ----------

interface Target { kind: 'file'; label: string; path: string; download?: { url: string; sha256?: string; sizeGB: number } }
interface ServerTarget { kind: 'server'; label: string; url: string; model: string }

async function hfFiles(repo: string): Promise<{ path: string; size: number; sha256?: string }[]> {
  const r = await fetch(`https://huggingface.co/api/models/${repo}/tree/main`, { signal: AbortSignal.timeout(20_000) });
  if (r.status === 404 || r.status === 401) throw new Error(`I couldn’t find ${repo} on Hugging Face (it may be private or misspelled)`);
  if (!r.ok) throw new Error(`Hugging Face answered ${r.status}`);
  const items = await r.json() as { path: string; size: number; lfs?: { oid?: string } }[];
  return items.filter((x) => x.path.endsWith('.gguf')).map((x) => ({ path: x.path, size: x.size, sha256: x.lfs?.oid }));
}

/** Work out the model to run from the saved choice. Network is only used to look up a Hugging Face repo. */
async function resolveTarget(c = loadLocalConfig()): Promise<Target | ServerTarget> {
  if (c.choice === 'server') return { kind: 'server', label: `${c.serverModel} on your own model server`, url: c.serverUrl!.replace(/\/+$/, ''), model: c.serverModel! };
  if (c.choice === 'custom') {
    const v = c.custom!;
    if (v.startsWith('/') || v.startsWith('~')) {
      const path = v.replace(/^~/, process.env.HOME ?? '');
      if (!path.endsWith('.gguf') || !existsSync(path)) throw new Error(`there is no .gguf file at ${v}`);
      return { kind: 'file', label: basename(path), path };
    }
    const [repo, quant] = v.split(':');
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error('a Hugging Face model looks like owner/name, for example Qwen/Qwen3-8B-GGUF');
    const files = (await hfFiles(repo)).filter((f) => !/mmproj|-\d{5}-of-\d{5}/i.test(f.path));
    if (!files.length) throw new Error(`${repo} has no single-file .gguf model`);
    const want = (quant ?? 'Q4_K_M').toLowerCase();
    const pick = files.find((f) => f.path.toLowerCase().includes(want)) ?? files.sort((a, b) => a.size - b.size)[0];
    return { kind: 'file', label: pick.path.replace(/\.gguf$/, ''), path: join(MODELS_DIR, basename(pick.path)), download: { url: `https://huggingface.co/${repo}/resolve/main/${pick.path}`, sha256: pick.sha256, sizeGB: pick.size / GB } };
  }
  const m = c.choice === 'auto' ? recommendedModel() : LOCAL_MODELS.find((x) => x.id === c.choice) ?? recommendedModel();
  const path = join(MODELS_DIR, m.file);
  if (existsSync(path)) return { kind: 'file', label: m.label, path };
  const meta = (await hfFiles(m.repo)).find((f) => f.path === m.file);
  return { kind: 'file', label: m.label, path, download: { url: `https://huggingface.co/${m.repo}/resolve/main/${m.file}`, sha256: meta?.sha256, sizeGB: (meta?.size ?? m.sizeGB * GB) / GB } };
}

// ---------- setting up ----------

function setPhase(phase: Phase, error: string | null = null): void {
  st.phase = phase;
  st.error = error;
  bus.emit('change', { type: 'localai' });
}

async function sha256File(path: string): Promise<string> {
  const h = createHash('sha256');
  for await (const chunk of createReadStream(path)) h.update(chunk as Buffer);
  return h.digest('hex');
}

/**
 * Download with resume (a .part file), then check the SHA-256 Hugging Face publishes for it. A connection
 * that drops or stalls (no data for 45 s) is picked up again where it stopped, up to 5 times.
 */
async function download(t: Target): Promise<void> {
  const d = t.download!;
  mkdirSync(MODELS_DIR, { recursive: true, mode: 0o700 });
  const part = `${t.path}.part`;
  const size = () => (existsSync(part) ? statSync(part).size : 0);
  if (freeGB() < d.sizeGB - size() / GB + 2) throw new Error(`there isn’t enough free space: ${t.label} needs about ${Math.ceil(d.sizeGB)} GB plus 2 GB to spare`);
  setPhase('downloading');
  st.total = Math.round(d.sizeGB * GB);
  for (let attempt = 1; ; attempt++) {
    const have = size();
    st.done = have;
    const ac = new AbortController();
    let stall = setTimeout(() => ac.abort(), 45_000);
    try {
      const r = await fetch(d.url, { headers: have ? { range: `bytes=${have}-` } : {}, signal: ac.signal });
      if (r.status === 416) break; // already complete
      if (!r.ok || !r.body) throw new Error(`the model download failed (${r.status})`);
      const resumed = r.status === 206;
      if (!resumed) st.done = 0;
      const out = createWriteStream(part, { flags: resumed ? 'a' : 'w' });
      let lastEmit = 0;
      try {
        for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) {
          clearTimeout(stall);
          stall = setTimeout(() => ac.abort(), 45_000);
          if (!out.write(chunk)) await new Promise<void>((res) => out.once('drain', () => res()));
          st.done += chunk.length;
          if (Date.now() - lastEmit > 1000) { lastEmit = Date.now(); bus.emit('change', { type: 'localai' }); }
        }
      } finally {
        await new Promise<void>((res) => out.end(() => res()));
      }
      break;
    } catch (e) {
      if (/download failed \(4/.test((e as Error).message) || attempt >= 5) {
        throw new Error(/download failed/.test((e as Error).message) ? (e as Error).message : 'the download was interrupted. Press Try again to continue where it stopped');
      }
      await new Promise((res) => setTimeout(res, 3000 * attempt));
    } finally {
      clearTimeout(stall);
    }
  }
  setPhase('verifying');
  if (d.sha256 && (await sha256File(part)) !== d.sha256) {
    rmSync(part, { force: true });
    throw new Error('the downloaded model did not match its published checksum, so I deleted it. Try again');
  }
  renameSync(part, t.path);
}

async function installEngine(): Promise<void> {
  if (existsSync(enginePath())) return;
  const brew = join(brewPrefix(), 'bin/brew');
  if (!existsSync(brew)) throw new Error('Homebrew is missing, so I can’t install the llama.cpp engine. Running my installer again sets it up');
  setPhase('installing-engine');
  const r = await run(brew, ['install', 'llama.cpp'], { timeout: 30 * 60_000, env: { HOMEBREW_NO_AUTO_UPDATE: '1', HOMEBREW_NO_ENV_HINTS: '1' } });
  if (!r.ok || !existsSync(enginePath())) throw new Error(`Homebrew could not install llama.cpp: ${(r.stderr || r.stdout).trim().split('\n').pop()}`);
}

/** Install the engine and download the model, once. Safe to call repeatedly. */
export function setupLocal(): Promise<void> {
  if (setupRun) return setupRun;
  setupRun = (async () => {
    try {
      st.done = 0; st.total = 0;
      const t = await resolveTarget();
      st.label = t.label;
      if (t.kind === 'server') {
        const r = await fetch(`${t.url}/v1/models`, { signal: AbortSignal.timeout(5000) }).catch(() => null);
        if (!r?.ok) throw new Error(`your model server at ${t.url} is not answering. Start it, then press Try again`);
      } else {
        await installEngine();
        if (t.download && !existsSync(t.path)) await download(t);
      }
      setPhase('ready');
      logEvent('ai', 'info', `Fully local AI is ready: ${t.label}`, {});
    } catch (e) {
      setPhase('error', `I couldn’t set up local AI: ${(e as Error).message}.`);
    } finally {
      setupRun = null;
    }
  })();
  return setupRun;
}

// ---------- running ----------

function stopServer(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = null;
  server?.kill('SIGTERM');
  server = null;
  serverModelPath = null;
}

// The model server belongs to Hashling: when Hashling stops, so does it.
process.on('exit', () => { server?.kill('SIGTERM'); });

function touchIdle(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(stopServer, IDLE_STOP);
  idleTimer.unref();
}

/** Start llama-server for this model (or reuse the running one) and return its address. */
async function ensureServer(t: Target): Promise<string> {
  const base = `http://127.0.0.1:${LOCAL_PORT}`;
  if (server && serverModelPath === t.path && server.exitCode === null) { touchIdle(); return base; }
  stopServer();
  let log = '';
  server = spawn(enginePath(), ['-m', t.path, '--host', '127.0.0.1', '--port', String(LOCAL_PORT), '--jinja', '-c', '16384', '--no-webui'], { stdio: ['ignore', 'pipe', 'pipe'] });
  serverModelPath = t.path;
  server.stderr!.on('data', (d) => { if (log.length < 4000) log += d; });
  server.stdout!.on('data', () => { /* drain */ });
  server.on('exit', () => { server = null; serverModelPath = null; });
  for (let i = 0; i < 240; i++) {
    const ok = await fetch(`${base}/health`, { signal: AbortSignal.timeout(2000) }).then((r) => r.ok).catch(() => false);
    if (ok) { touchIdle(); return base; }
    if (!server) throw new Error(`the local model stopped while loading: ${log.trim().split('\n').pop() ?? 'no details'}`);
    await new Promise((r) => setTimeout(r, 500));
  }
  stopServer();
  throw new Error('the local model took too long to load');
}

export function localStatus() {
  const c = loadLocalConfig();
  const specs = macSpecs();
  const rec = recommendedModel(specs.ramGB);
  let downloaded: { file: string; sizeGB: number }[] = [];
  try { downloaded = readdirSync(MODELS_DIR).filter((f) => f.endsWith('.gguf')).map((f) => ({ file: f, sizeGB: Math.round(statSync(join(MODELS_DIR, f)).size / GB * 10) / 10 })); } catch { /* none yet */ }
  return {
    specs, recommended: rec.id, config: c,
    models: LOCAL_MODELS.map((m) => ({ ...m, fits: specs.ramGB >= m.minRamGB, downloaded: downloaded.some((d) => d.file === m.file) })),
    phase: st.phase, error: st.error, label: st.label,
    progress: st.total ? { done: st.done, total: st.total } : null,
    engineInstalled: existsSync(enginePath()), downloaded, freeGB: Math.round(freeGB()), running: Boolean(server),
  };
}

/** Is local AI usable right now? Never touches the network. */
export function localReady(): { ready: boolean; detail: string } {
  const c = loadLocalConfig();
  if (st.phase === 'installing-engine') return { ready: false, detail: 'Setting up: installing the llama.cpp engine.' };
  if (st.phase === 'downloading') return { ready: false, detail: `Setting up: downloading ${st.label} (${st.total ? Math.floor(st.done / st.total * 100) : 0}%).` };
  if (st.phase === 'verifying') return { ready: false, detail: `Setting up: checking the ${st.label} download.` };
  if (st.phase === 'error') return { ready: false, detail: st.error! };
  if (c.choice === 'server') return st.phase === 'ready' ? { ready: true, detail: `Fully local, using ${c.serverModel} on your own model server.` } : { ready: false, detail: 'Not set up yet. Press Set up in Settings.' };
  const m = c.choice === 'auto' ? recommendedModel() : LOCAL_MODELS.find((x) => x.id === c.choice);
  const file = c.choice === 'custom' ? null : m ? join(MODELS_DIR, m.file) : null;
  const have = existsSync(enginePath()) && (file ? existsSync(file) : st.phase === 'ready');
  return have ? { ready: true, detail: `Fully local, running ${c.choice === 'custom' ? st.label ?? 'your model' : m!.label} on this Mac. Nothing leaves it.` } : { ready: false, detail: 'Not set up yet. Press Set up in Settings.' };
}

export function deleteModel(file: string): boolean {
  if (!/^[\w.-]+\.gguf$/.test(file)) return false;
  const p = join(MODELS_DIR, file);
  if (!existsSync(p)) return false;
  if (serverModelPath === p) stopServer();
  rmSync(p, { force: true });
  bus.emit('change', { type: 'localai' });
  return true;
}

/** Pick up an interrupted setup after a restart. */
export function resumeLocalSetup(provider: string): void {
  if (provider === 'local' && !localReady().ready) void setupLocal();
}

// ---------- chatting ----------

export interface LocalEvent { type: 'text' | 'tool' | 'tool_done' | 'action'; text?: string; name?: string; input?: unknown; action?: unknown }
export interface ChatTurn { role: 'user' | 'assistant'; text: string }

/**
 * A short, factual summary of Hashling's overview. Small models answer from what is in front of them,
 * so they always get the real picture first instead of guessing.
 */
function overviewBrief(raw: string): string {
  let o: any;
  try { o = JSON.parse(raw); } catch { return raw.slice(0, 2500); }
  const counts = Object.entries(o.openFindings ?? {}).filter(([, n]) => Number(n) > 0).map(([k, n]) => `${n} ${k}`).join(', ') || 'none';
  const top = (o.topFindings ?? []).slice(0, 10).map((f: any) => `- [${f.severity}] ${f.title}${f.summary ? `: ${String(f.summary).slice(0, 160)}` : ''}`).join('\n') || '- nothing open';
  const blind = (o.limitations ?? []).slice(0, 3).map((l: string) => `- ${l}`).join('\n');
  const weak = (o.scoreBreakdown?.areas ?? []).filter((a: any) => a.score < 100).sort((x: any, y: any) => x.score - y.score).slice(0, 3).map((a: any) => `${a.label} ${a.score}`).join(', ');
  return [`Score: ${o.score}/100, ${o.grade ?? ''} (${o.verdict}).${weak ? ` Weakest parts: ${weak}.` : ''}`, `Open findings by severity: ${counts}.`, `The open issues that matter (do not mention any issue that is not in this list or in a tool result):\n${top}`,
    o.pendingActions ? `Fixes already waiting for the user's Touch ID: ${o.pendingActions}.` : 'No fixes are waiting for approval.',
    blind ? `What Hashling cannot see yet:\n${blind}` : ''].filter(Boolean).join('\n');
}

/** Remove a model's private reasoning (<think>…</think>) from streamed text, even when tags split across chunks. */
function thinkFilter() {
  let inside = false;
  let carry = '';
  return (chunk: string): string => {
    let s = carry + chunk;
    carry = '';
    let out = '';
    while (s) {
      const tag = inside ? '</think>' : '<think>';
      const i = s.indexOf(tag);
      if (i >= 0) { if (!inside) out += s.slice(0, i); s = s.slice(i + tag.length); inside = !inside; continue; }
      const keep = [...Array(tag.length).keys()].reverse().find((k) => k > 0 && s.endsWith(tag.slice(0, k))) ?? 0;
      if (!inside) out += s.slice(0, s.length - keep);
      carry = s.slice(s.length - keep);
      s = '';
    }
    return out;
  };
}

/**
 * Answer with the local model, letting it call Hashling's tools. Returns the answer text, the tools used
 * and any proposed actions. Throws a plain-word error.
 */
export async function localChat(system: string, history: ChatTurn[], message: string, onEvent: (e: LocalEvent) => void, signal: AbortSignal, toolLabel: (n: string) => string): Promise<{ answer: string; tools: string[]; actions: unknown[] }> {
  const t = await resolveTarget();
  const base = t.kind === 'server' ? t.url : await ensureServer(t);
  const model = t.kind === 'server' ? t.model : 'local';

  const mcp = new Client({ name: 'hashling-local-ai', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath, args: ['--no-warnings', join(ROOT, 'src/mcp.ts')], stderr: 'ignore',
    env: { ...process.env as Record<string, string>, HASHLING_HOME: DATA_DIR, HASHLING_CLIENT_NAME: 'Hashling assistant (local AI)' },
  });
  await mcp.connect(transport);
  try {
    const tools = (await mcp.listTools()).tools.filter((x) => LOCAL_TOOLS.has(x.name))
      .map((x) => ({ type: 'function', function: { name: x.name, description: (x.description ?? '').slice(0, 600), parameters: x.inputSchema } }));
    const prefetched: string[] = [];
    // Ground every answer in the real state of this Mac before the model says anything.
    onEvent({ type: 'tool', name: 'security_overview', text: toolLabel('security_overview'), input: {} });
    const ov = await mcp.callTool({ name: 'security_overview', arguments: {} }).catch(() => null);
    onEvent({ type: 'tool_done', name: 'security_overview' });
    const brief = ov ? overviewBrief(((ov.content as { text?: string }[]) ?? []).map((p) => p.text ?? '').join('\n')) : 'Hashling’s overview could not be read just now.';
    let extra = '';
    for (const [re, name] of PREFETCH) {
      if (!re.test(message)) continue;
      onEvent({ type: 'tool', name, text: toolLabel(name), input: {} });
      const r = await mcp.callTool({ name, arguments: {} }).catch(() => null);
      onEvent({ type: 'tool_done', name });
      const text = r ? ((r.content as { text?: string }[]) ?? []).map((p) => p.text ?? '').join('\n') : '';
      if (text) { extra += `\n\n${name.replace(/_/g, ' ')}, checked just now:\n${text.slice(0, 5000)}`; prefetched.push(name); }
    }
    const messages: Record<string, unknown>[] = [
      { role: 'system', content: extra
        ? `${system}\n\nThe facts for this question, checked just now. Answer from these first:${extra}\n\nThe overall summary of this Mac, for background only:\n${brief}`
        : `${system}\n\nHashling’s live summary of this Mac, checked just now (these are the facts; use them, never invent others):\n${brief}` },
      ...history.slice(-12).map((m) => ({ role: m.role, content: m.text.slice(0, 4000) })),
      { role: 'user', content: message },
    ];
    let answer = '';
    const used: string[] = ['security_overview', ...prefetched];
    const actions: unknown[] = [];

    for (let round = 0; round < 10; round++) {
      if (signal.aborted) break;
      const r = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST', signal,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model, messages, tools, tool_choice: 'auto', stream: true, temperature: 0.3, max_tokens: 1500, chat_template_kwargs: { enable_thinking: false } }),
      });
      if (!r.ok || !r.body) throw new Error(`the local model answered ${r.status}: ${(await r.text().catch(() => '')).slice(0, 200)}`);
      const calls: { id: string; name: string; args: string }[] = [];
      let text = '';
      const clean = thinkFilter();
      let buf = '';
      const dec = new TextDecoder();
      for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) {
        buf += dec.decode(chunk, { stream: true });
        let i: number;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).trim();
          buf = buf.slice(i + 1);
          if (!line.startsWith('data:')) continue;
          const data = line.slice(5).trim();
          if (data === '[DONE]') continue;
          let j: any;
          try { j = JSON.parse(data); } catch { continue; }
          const d = j.choices?.[0]?.delta ?? {};
          if (typeof d.content === 'string' && d.content) {
            const out = clean(d.content).replace(/\s*—\s*/g, ', ');
            if (out) { text += out; onEvent({ type: 'text', text: out }); }
          }
          for (const tc of d.tool_calls ?? []) {
            const k = tc.index ?? calls.length;
            calls[k] ??= { id: tc.id ?? `call_${round}_${k}`, name: '', args: '' };
            if (tc.id) calls[k].id = tc.id;
            if (tc.function?.name) calls[k].name += tc.function.name;
            if (tc.function?.arguments) calls[k].args += tc.function.arguments;
          }
        }
      }
      answer += text;
      if (!calls.length) break;
      if (text && !answer.endsWith('\n\n')) { answer += '\n\n'; onEvent({ type: 'text', text: '\n\n' }); }

      messages.push({ role: 'assistant', content: text || null, tool_calls: calls.map((c) => ({ id: c.id, type: 'function', function: { name: c.name, arguments: c.args || '{}' } })) });
      for (const c of calls) {
        let input: Record<string, unknown> = {};
        let result: string;
        try { input = c.args ? JSON.parse(c.args) : {}; } catch { /* reported below */ }
        if (!LOCAL_TOOLS.has(c.name)) result = `There is no tool named ${c.name}.`;
        else {
          used.push(c.name);
          onEvent({ type: 'tool', name: c.name, text: toolLabel(c.name), input });
          try {
            const res = await mcp.callTool({ name: c.name, arguments: input });
            result = ((res.content as { type: string; text?: string }[]) ?? []).map((p) => p.text ?? '').join('\n');
          } catch (e) { result = `The tool failed: ${(e as Error).message}`; }
          onEvent({ type: 'tool_done', name: c.name });
          if (c.name === 'propose_action') {
            try { const a = JSON.parse(result); if (a?.id && a?.status) { actions.push(a); onEvent({ type: 'action', action: a }); } } catch { /* error text */ }
          }
        }
        messages.push({ role: 'tool', tool_call_id: c.id, content: result.length > 8000 ? `${result.slice(0, 8000)}\n…(cut short)` : result });
      }
    }
    return { answer: answer.trim(), tools: used, actions };
  } finally {
    await mcp.close().catch(() => {});
    if (t.kind !== 'server') touchIdle();
  }
}
