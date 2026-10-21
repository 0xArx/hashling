import { basename } from 'node:path';
import { run } from './exec.ts';
import { redact } from './redact.ts';

export interface Proc {
  pid: number;
  ppid: number;
  uid: number;
  path: string;
  name: string;
  app: string;
}

/** The outermost .app bundle in a path, e.g. "Google Chrome" for its helper processes. */
export function appOf(path: string): string | null {
  const m = path.match(/^(.*?\/([^/]+)\.app)(\/|$)/);
  return m ? m[2] : null;
}

export function bundleOf(path: string): string | null {
  const m = path.match(/^(.*?\.app)(\/|$)/);
  return m ? m[1] : null;
}

/** Snapshot of every running process (pid, parent, owner, executable path). */
export async function listProcs(): Promise<Map<number, Proc>> {
  const r = await run('/bin/ps', ['-axo', 'pid=,ppid=,uid=,comm='], { timeout: 10_000 });
  const map = new Map<number, Proc>();
  for (const line of r.stdout.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/);
    if (!m) continue;
    // `comm` is usually the executable path, but a program can rename itself to its whole command
    // line (npm does: "npm exec vercel deploy --token …"). Never let that carry a secret, and name
    // such a process by its title without the flags.
    const raw = redact(m[4].trim());
    const path = raw;
    const name = raw.startsWith('/') ? basename(raw) : raw.split(/\s+-/)[0].slice(0, 60);
    map.set(Number(m[1]), { pid: Number(m[1]), ppid: Number(m[2]), uid: Number(m[3]), path, name, app: appOf(path) ?? name });
  }
  return map;
}

/** Walk up the parent chain (for "which agent started this curl?"). */
export function ancestry(pid: number, procs: Map<number, Proc>, depth = 8): Proc[] {
  const out: Proc[] = [];
  let cur = procs.get(pid);
  while (cur && out.length < depth && cur.ppid > 1) {
    const parent = procs.get(cur.ppid);
    if (!parent) break;
    out.push(parent);
    cur = parent;
  }
  return out;
}
