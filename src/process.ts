import { run } from './lib/exec.ts';
import { listProcs, ancestry, bundleOf } from './lib/procs.ts';
import { signInfo, describeSigner, riskyLocation } from './lib/codesign.ts';
import { agentName, processNote } from './knowledge.ts';
import { getSnapshot } from './db.ts';

/** Everything Hashling knows about one running process. */
export async function processInfo(pid: number) {
  const procs = await listProcs();
  const p = procs.get(pid);
  if (!p) return { error: `No running process with pid ${pid}` };
  const [ps, files] = await Promise.all([
    run('/bin/ps', ['-p', String(pid), '-o', 'lstart=,%cpu=,%mem=,args=']),
    run('/usr/sbin/lsof', ['-p', String(pid), '-Fn', '-n', '-P'], { timeout: 8000 }),
  ]);
  const sign = await signInfo(bundleOf(p.path) ?? p.path);
  const net = getSnapshot<{ processes: { pid: number; connections: unknown[]; listening: unknown[]; rateIn: number; rateOut: number }[] }>('network')?.data?.processes.find((x) => x.pid === pid);
  const openFiles = files.stdout.split('\n').filter((l) => l.startsWith('n/') && !/\.(dylib|so)$|^n\/(System|usr\/lib|dev)\//.test(l)).map((l) => l.slice(1));
  const m = ps.stdout.trim().match(/^(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})\s+([\d.]+)\s+([\d.]+)\s+(.*)$/);
  return {
    pid, name: p.name, app: p.app, path: p.path, user: p.uid === 0 ? 'root' : p.uid,
    started: m?.[1], cpu: m ? Number(m[2]) : undefined, mem: m ? Number(m[3]) : undefined,
    commandLine: redact(m?.[4] ?? ''),
    signer: describeSigner(sign), signature: sign,
    agent: agentName(p.path, p.name), note: processNote(p.name),
    unusualLocation: riskyLocation(p.path),
    parents: ancestry(pid, procs).map((a) => ({ pid: a.pid, name: a.name, path: a.path, agent: agentName(a.path, a.name) })),
    children: [...procs.values()].filter((c) => c.ppid === pid).slice(0, 30).map((c) => ({ pid: c.pid, name: c.name })),
    network: net ?? null,
    openFiles: [...new Set(openFiles)].slice(0, 60),
  };
}

import { redact } from './lib/redact.ts';
export { redact };
