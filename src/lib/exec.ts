import { execFile, spawn } from 'node:child_process';

export interface RunResult {
  ok: boolean;
  code: number | null;
  /** Killed for running past its timeout. */
  timedOut?: boolean;
  stdout: string;
  stderr: string;
}

/** Run a binary with arguments (never through a shell). */
export function run(cmd: string, args: string[] = [], opts: { timeout?: number; maxBuffer?: number; input?: string } = {}): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = execFile(
      cmd,
      args,
      { timeout: opts.timeout ?? 30_000, killSignal: 'SIGKILL', maxBuffer: opts.maxBuffer ?? 32 * 1024 * 1024, encoding: 'utf8' },
      (err, stdout, stderr) => {
        const raw = (err as { code?: unknown } | null)?.code;
        const code = err ? (typeof raw === 'number' ? raw : 1) : 0;
        const timedOut = Boolean((err as { killed?: boolean } | null)?.killed);
        resolve({ ok: !err, code, timedOut, stdout: stdout ?? '', stderr: stderr || (err ? String(err.message) : '') });
      },
    );
    if (opts.input !== undefined) {
      child.stdin?.end(opts.input);
    }
  });
}

/** Run and stream stdout line by line. */
export function runLines(cmd: string, args: string[], onLine: (line: string) => void, timeout = 600_000): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let buf = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      buf += chunk;
      let i: number;
      while ((i = buf.indexOf('\n')) >= 0) {
        onLine(buf.slice(0, i));
        buf = buf.slice(i + 1);
      }
    });
    child.stderr.on('data', (c) => { if (stderr.length < 64_000) stderr += c; });
    child.on('error', (e) => { clearTimeout(timer); resolve({ ok: false, code: null, stdout: '', stderr: String(e) }); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (buf) onLine(buf);
      resolve({ ok: code === 0, code, stdout: '', stderr });
    });
  });
}

/** Parse a plist file to JSON with plutil. Returns null when unreadable. */
export async function readPlist<T = Record<string, unknown>>(path: string): Promise<T | null> {
  const r = await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path], { timeout: 5000 });
  if (!r.ok) return null;
  try { return JSON.parse(r.stdout) as T; } catch { return null; }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
