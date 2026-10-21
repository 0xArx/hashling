import { plural } from '../lib/text.ts';
import { run } from '../lib/exec.ts';
import { listProcs, ancestry, bundleOf, type Proc } from '../lib/procs.ts';
import { ipInfo, isPrivate } from '../lib/ipinfo.ts';
import { signInfo, describeSigner, riskyLocation, type SignInfo } from '../lib/codesign.ts';
import { agentName, processNote, SUSPICIOUS_PORTS } from '../knowledge.ts';
import { matchIp, matchHost } from '../intel/feeds.ts';
import { recordTraffic, recordConnOpens } from '../history.ts';
import { recordUploadDests, noteFilesWhileUploading, UPLOAD_RATE } from '../intel/uploads.ts';
import { putSnapshot, syncFindings, markSeen, hasBaseline, logEvent, type FindingInput } from '../db.ts';

export interface Conn {
  proto: string;
  local: string;
  localPort: number;
  remote: string;
  remotePort: number;
  state: string;
  bytesIn: number;
  bytesOut: number;
  host?: string;
  org?: string;
  country?: string;
  external: boolean;
  intel?: { feed: string; label: string; matched: string };
}

export interface NetProc {
  pid: number;
  name: string;
  app: string;
  path: string;
  user: string;
  signer: string;
  signerKind: string;
  agent: string | null;
  parentAgent: string | null;
  note?: string;
  bytesIn: number;
  bytesOut: number;
  rateIn: number;
  rateOut: number;
  connections: Conn[];
  listening: { proto: string; address: string; port: number; exposed: boolean }[];
}

let lastTotals = new Map<number, { in: number; out: number; at: number }>();
let lastConnKeys = new Set<string>();
/** Bytes each connection had sent at the last sample, so uploads can be attributed to a destination. */
let lastConnOut = new Map<string, number>();
let connOutPrimed = false;

function splitAddr(s: string, v6: boolean): [string, number] {
  if (s === '*:*' || s === '*.*') return ['*', 0];
  const i = v6 ? s.lastIndexOf('.') : s.lastIndexOf(':');
  const host = s.slice(0, i);
  const port = s.slice(i + 1);
  return [host.replace(/%.*$/, ''), port === '*' ? 0 : Number(port)];
}

/** Parse `nettop -L 1 -n -x -J state,bytes_in,bytes_out`. */
function parseNettop(text: string): Map<number, { name: string; in: number; out: number; conns: Omit<Conn, 'external'>[] }> {
  const out = new Map<number, { name: string; in: number; out: number; conns: Omit<Conn, 'external'>[] }>();
  let cur: { name: string; in: number; out: number; conns: Omit<Conn, 'external'>[] } | null = null;
  for (const line of text.split('\n').slice(1)) {
    if (!line.trim()) continue;
    const m = line.match(/^(tcp|udp)([46]) (.+?)<->(.+?),([^,]*),([^,]*),([^,]*),?$/);
    if (m && cur) {
      const v6 = m[2] === '6';
      const [local, localPort] = splitAddr(m[3], v6);
      const [remote, remotePort] = splitAddr(m[4], v6);
      cur.conns.push({ proto: m[1] + m[2], local, localPort, remote, remotePort, state: m[5] || (m[1] === 'udp' ? 'UDP' : ''), bytesIn: Number(m[6] || 0), bytesOut: Number(m[7] || 0) });
      continue;
    }
    const p = line.match(/^(.*)\.(\d+),[^,]*,(\d*),(\d*),?$/);
    if (p) {
      cur = { name: p[1], in: Number(p[3] || 0), out: Number(p[4] || 0), conns: [] };
      out.set(Number(p[2]), cur);
    }
  }
  return out;
}

const LOCAL_LISTEN = /^(127\.|::1$|localhost)/;
const DEV_LOCATIONS = /^(\/opt\/homebrew|\/usr\/local|\/Users\/[^/]+\/(Developer|\.nvm|\.volta|\.bun|\.cargo|\.local|Library\/pnpm|\.npm|\.deno|\.orbstack|go\/bin))\b/;

export async function collectNetwork(): Promise<void> {
  const [nt, procs] = await Promise.all([
    run('/usr/bin/nettop', ['-L', '1', '-n', '-x', '-J', 'state,bytes_in,bytes_out'], { timeout: 15_000 }),
    listProcs(),
  ]);
  if (!nt.ok && !nt.stdout) throw new Error(`nettop failed: ${nt.stderr.slice(0, 200)}`);
  const parsed = parseNettop(nt.stdout);
  const at = Date.now();
  const baselined = hasBaseline('net');
  const findings: FindingInput[] = [];
  const trafficRows: { app: string; bytesIn: number; bytesOut: number }[] = [];
  const uploadRows: Parameters<typeof recordUploadDests>[0] = [];
  const connOut = new Map<string, number>();
  const opens: Parameters<typeof recordConnOpens>[0] = [];
  const connKeys = new Set<string>();
  const result: NetProc[] = [];
  const totals = new Map<number, { in: number; out: number; at: number }>();
  const meUid = process.getuid?.() ?? 501;

  for (const [pid, entry] of parsed) {
    // nettop sometimes reports a bare socket ("quic6 2001:…<->2600:…") instead of a process; it is not an app.
    if (!procs.get(pid) && /<->/.test(entry.name)) continue;
    const proc: Proc = procs.get(pid) ?? { pid, ppid: 0, uid: -1, path: entry.name, name: entry.name, app: entry.name };
    const conns: Conn[] = [];
    const listening: NetProc['listening'] = [];
    for (const c of entry.conns) {
      if (c.state === 'Listen' || (c.proto.startsWith('udp') && c.remote === '*' && c.localPort)) {
        if (c.localPort) listening.push({ proto: c.proto, address: c.local, port: c.localPort, exposed: !LOCAL_LISTEN.test(c.local) });
        continue;
      }
      if (c.remote === '*' || !c.remotePort) continue;
      const external = !isPrivate(c.remote);
      const info = external ? ipInfo(c.remote) : {};
      const intel = external ? (matchIp(c.remote, c.remotePort) ?? (info.host ? matchHost(info.host) : null)) : null;
      conns.push({ ...c, external, host: info.host, org: info.org, country: info.country, ...(intel ? { intel } : {}) });
    }
    if (!conns.length && !listening.length && !entry.in && !entry.out) continue;

    const prev = lastTotals.get(pid);
    totals.set(pid, { in: entry.in, out: entry.out, at });
    const dt = prev ? (at - prev.at) / 1000 : 0;
    const rateIn = prev && dt > 0 ? Math.max(0, (entry.in - prev.in) / dt) : 0;
    const rateOut = prev && dt > 0 ? Math.max(0, (entry.out - prev.out) / dt) : 0;
    if (prev) trafficRows.push({ app: proc.app, bytesIn: Math.max(0, entry.in - prev.in), bytesOut: Math.max(0, entry.out - prev.out) });
    for (const c of conns) {
      if (!c.external) continue;
      const k = `${pid}|${c.proto}|${c.local}:${c.localPort}|${c.remote}:${c.remotePort}`;
      const before = lastConnOut.get(k);
      connOut.set(k, c.bytesOut);
      // A connection that opened since the last sample sent everything it has sent so far.
      const sent = before === undefined ? (connOutPrimed ? c.bytesOut : 0) : c.bytesOut - before;
      if (sent > 0) uploadRows.push({ app: proc.app, dest: c.org ?? c.host ?? c.remote, host: c.host, country: c.country, bytes: sent });
    }
    if (rateOut >= UPLOAD_RATE) {
      const pids = [...procs.values()].filter((p) => p.app === proc.app).map((p) => p.pid);
      noteFilesWhileUploading(proc.app, pids.length ? pids : [pid], rateOut, [...new Set(conns.filter((c) => c.external).map((c) => c.org ?? c.host ?? c.remote))]);
    }

    const signTarget = bundleOf(proc.path) ?? proc.path;
    const sign: SignInfo = proc.path.startsWith('/') ? await signInfo(signTarget) : { kind: 'missing', trusted: false };
    const agent = agentName(proc.path, proc.name);
    const parentAgent = agent ? null : (ancestry(pid, procs).map((p) => agentName(p.path, p.name)).find(Boolean) ?? null);

    const np: NetProc = {
      pid, name: proc.name, app: proc.app, path: proc.path,
      user: proc.uid === 0 ? 'root' : proc.uid === meUid ? 'you' : String(proc.uid),
      signer: describeSigner(sign), signerKind: sign.kind, agent, parentAgent,
      note: processNote(proc.name) ?? processNote(proc.app),
      bytesIn: entry.in, bytesOut: entry.out, rateIn, rateOut, connections: conns, listening,
    };
    result.push(np);

    // Every newly opened outgoing connection, for beacon analysis later.
    for (const c of conns.filter((x) => x.external && x.proto.startsWith('tcp'))) {
      const key = `${pid}|${c.localPort}|${c.remote}|${c.remotePort}`;
      connKeys.add(key);
      if (!lastConnKeys.has(key) && lastConnKeys.size) opens.push({ app: proc.app, path: proc.path, signer: sign.kind, agent: agent ?? parentAgent, ip: c.remote, port: c.remotePort, dest: c.host ?? c.org ?? c.remote });
    }

    // Connections to known-bad infrastructure from open threat feeds.
    for (const c of conns.filter((x) => x.intel)) {
      findings.push({
        key: `intel:${proc.app}:${c.intel!.matched}`, category: 'network', severity: 'high',
        title: `${proc.name} is talking to a known-malicious server`,
        summary: `${c.org ?? c.host ?? c.remote}:${c.remotePort} is listed by ${c.intel!.feed} as ${c.intel!.label}.`,
        explanation: `I check every connection against free, open threat-intelligence feeds (abuse.ch, Spamhaus, Emerging Threats, FireHOL). This address is on ${c.intel!.feed}, which tracks ${c.intel!.label}. Legitimate apps almost never talk to these servers. Shared hosting can occasionally cause a false match, so check what ${proc.name} is.`,
        recommendation: 'If you do not recognise this app, quit it, quarantine its file, and run a malware scan of your Downloads folder.',
        evidence: { pid, path: proc.path, signer: sign, remote: c.remote, port: c.remotePort, host: c.host, org: c.org, intel: c.intel },
        actions: [
          { type: 'kill_process', target: { pid, name: proc.name }, label: 'Quit process' },
          ...(c.host ? [{ type: 'block_domain', target: { domain: c.host }, label: `Block ${c.host}` }] : []),
          ...(proc.path.startsWith('/') && !proc.path.startsWith('/System') ? [{ type: 'quarantine_file', target: { path: proc.path }, label: 'Quarantine file' }] : []),
        ],
      });
      logEvent('network', 'high', `${proc.name} connected to ${c.remote} (${c.intel!.label}, ${c.intel!.feed})`, { pid, ip: c.remote });
    }

    // First-seen destinations per app (baseline on first run is silent).
    for (const c of conns.filter((x) => x.external)) {
      const dest = c.org ?? c.host ?? c.remote;
      const seen = markSeen('net', `${proc.app}|${dest}`, { app: proc.app, dest, ip: c.remote, port: c.remotePort, host: c.host, org: c.org, agent: agent ?? parentAgent });
      // Only announce destinations with a known owner: a raw address means nothing to a reader, and the
      // same server is announced by name once its owner is looked up.
      if (seen.isNew && baselined && (c.org || c.host) && (agent || parentAgent || !sign.trusted)) {
        logEvent('network', 'info', `${agent ?? parentAgent ? `${agent ?? parentAgent} (${proc.name})` : proc.app} contacted a new destination: ${dest}`, { pid, ip: c.remote, port: c.remotePort, host: c.host });
      }
    }

    const external = conns.filter((c) => c.external);
    const risky = riskyLocation(proc.path);
    if (external.length && risky && sign.kind !== 'apple') {
      findings.push({
        key: `net:risky-loc:${proc.path}`, category: 'network', severity: sign.trusted ? 'medium' : 'high',
        title: `${proc.name} is online and running from ${risky}`,
        summary: `${proc.path} has ${plural(external.length, 'internet connection')}. ${describeSigner(sign)}.`,
        explanation: `Legitimate apps live in /Applications or system folders. Programs that run from ${risky} and talk to the internet are a common pattern for malware droppers and info-stealers. It can also be a harmless download or build artifact.`,
        recommendation: 'Check where this file came from. If you did not start it on purpose, quit it and quarantine the file.',
        evidence: { pid, path: proc.path, signer: sign, destinations: external.slice(0, 10).map((c) => `${c.org ?? c.host ?? c.remote}:${c.remotePort}`) },
        actions: [
          { type: 'kill_process', target: { pid, name: proc.name }, label: 'Quit process' },
          { type: 'quarantine_file', target: { path: proc.path }, label: 'Quarantine file' },
        ],
      });
    } else if (external.length && !sign.trusted && sign.kind !== 'missing' && sign.kind !== 'unreadable' && !DEV_LOCATIONS.test(proc.path)) {
      findings.push({
        key: `net:unsigned:${proc.path}`, category: 'network', severity: sign.kind === 'invalid' ? 'high' : 'low',
        title: `${proc.name} talks to the internet, but its developer is not verified`,
        summary: `${describeSigner(sign)}. ${plural(external.length, 'connection')}, e.g. ${external.slice(0, 3).map((c) => c.org ?? c.host ?? c.remote).join(', ')}.`,
        explanation: sign.kind === 'invalid'
          ? 'The code signature of this program no longer matches its contents, which means the file was modified after it was signed. Tampering is a strong warning sign.'
          : 'Programs from identified developers are signed so macOS can tell who made them. This one has no developer identity, which is normal for tools you built yourself or installed with a package manager, and unusual for apps you downloaded.',
        recommendation: 'If you recognise this tool, acknowledge the finding. Otherwise find out what installed it.',
        evidence: { pid, path: proc.path, signer: sign },
        actions: [{ type: 'kill_process', target: { pid, name: proc.name }, label: 'Quit process' }],
      });
    }

    for (const c of external) {
      const why = SUSPICIOUS_PORTS[c.remotePort];
      if (why) {
        findings.push({
          key: `net:port:${proc.app}:${c.remotePort}`, category: 'network', severity: 'medium',
          title: `${proc.name} connected to port ${c.remotePort}`,
          summary: `Remote ${c.org ?? c.host ?? c.remote}:${c.remotePort} (${why}).`,
          explanation: `Port ${c.remotePort} is associated with ${why}. Normal apps almost always use web ports (443/80).`,
          recommendation: 'Confirm you know why this program uses that port.',
          evidence: { pid, path: proc.path, remote: c.remote, port: c.remotePort, host: c.host, org: c.org },
          actions: [{ type: 'kill_process', target: { pid, name: proc.name }, label: 'Quit process' }],
        });
      }
    }

    for (const l of listening.filter((x) => x.exposed)) markSeen('listen', `${proc.app}|${l.port}`, { app: proc.app, port: l.port, address: l.address });
    const exposed = listening.filter((l) => l.exposed && l.proto.startsWith('tcp'));
    const remoteSvc = exposed.find((l) => [22, 5900, 3283, 3389].includes(l.port));
    if (remoteSvc) {
      findings.push({
        key: `net:remote-svc:${remoteSvc.port}`, category: 'network', severity: 'medium',
        title: remoteSvc.port === 22 ? 'Remote Login (SSH) is accepting connections' : 'Screen Sharing / remote control is accepting connections',
        summary: `${proc.name} is listening on port ${remoteSvc.port} on all network interfaces.`,
        explanation: 'Anyone on the same network can try to log in to this Mac. Only keep this on if you use it.',
        recommendation: 'Turn it off in System Settings > General > Sharing if you do not need it.',
        evidence: { pid, path: proc.path, port: remoteSvc.port },
      });
    } else if (exposed.length && sign.kind !== 'apple') {
      findings.push({
        key: `net:listen:${proc.path}`, category: 'network', severity: 'low',
        title: `${proc.name} accepts connections from other devices`,
        summary: `Other devices on your Wi-Fi can connect to it (port ${exposed.map((l) => l.port).slice(0, 6).join(', ')}).`,
        explanation: 'This server is reachable by anything on your network, not just this Mac. Dev servers often do this by default; on public Wi-Fi it exposes them to strangers.',
        recommendation: 'Bind local tools to 127.0.0.1 where possible, or quit them when not in use.',
        evidence: { pid, path: proc.path, ports: exposed.map((l) => `${l.address}:${l.port}`) },
      });
    }
  }

  lastTotals = totals;
  lastConnKeys = connKeys;
  recordTraffic(trafficRows, at);
  recordUploadDests(uploadRows, at);
  lastConnOut = connOut;
  connOutPrimed = true;
  recordConnOpens(opens, at);
  result.sort((a, b) => (b.rateIn + b.rateOut) - (a.rateIn + a.rateOut) || b.connections.length - a.connections.length);
  const ext = result.reduce((n, p) => n + p.connections.filter((c) => c.external).length, 0);
  putSnapshot('network', {
    at,
    processes: result,
    summary: {
      processesOnline: result.filter((p) => p.connections.some((c) => c.external)).length,
      externalConnections: ext,
      listeningExposed: result.reduce((n, p) => n + p.listening.filter((l) => l.exposed).length, 0),
      agentsOnline: [...new Set(result.filter((p) => (p.agent || p.parentAgent) && p.connections.some((c) => c.external)).map((p) => p.agent ?? p.parentAgent))],
      rateIn: result.reduce((n, p) => n + p.rateIn, 0),
      rateOut: result.reduce((n, p) => n + p.rateOut, 0),
    },
  });
  syncFindings('network', dedupe(findings));
}

function dedupe(f: FindingInput[]): FindingInput[] {
  const m = new Map<string, FindingInput>();
  for (const x of f) if (!m.has(x.key)) m.set(x.key, x);
  return [...m.values()];
}
