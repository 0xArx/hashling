/**
 * Behaviour over time, from the history Hashling keeps:
 * - Beaconing (the technique behind RITA, Active Countermeasures' open-source
 *   threat-hunting tool): malware "checks in" with its server at regular
 *   intervals. We look for connections opened on a near-constant schedule.
 * - Upload spikes: an app suddenly sending far more data than it normally does,
 *   a common sign of data theft (exfiltration).
 */
import { connOpenGroups, uploadStats } from '../history.ts';
import { matchIp } from '../intel/feeds.ts';
import { riskyLocation } from '../lib/codesign.ts';
import { putSnapshot, syncFindings, logEvent, markSeen, type FindingInput } from '../db.ts';

const RUNTIME = /^\/(opt\/homebrew|usr\/local|usr\/bin)\/.*\/(node|python3?(\.\d+)?|ruby|bun|deno|perl|php|java)$|^\/usr\/bin\/(python3|ruby|perl)$/;
const TRUSTED = new Set(['apple', 'app-store', 'developer-id']);
/** Apps whose job is to upload a lot (sync, backup, calls, browsers). Spikes are logged, not flagged. */
const HEAVY_UPLOADERS = /^(bird|cloudd|nsurlsessiond|Dropbox|Google Drive|OneDrive|Backblaze|bztransmit|backupd|Photos|photolibraryd|zoom\.us|FaceTime|avconferenced|Slack|Discord|Microsoft Teams|Google Chrome|Safari|com\.apple\.WebKit\.Networking|firefox|Brave Browser|Arc|Microsoft Edge|Music|AppleMusic|Spotify|Docker|com\.docker\.backend|Time Machine|Creative Cloud|Steam|Telegram|WhatsApp|Messages|Mail)$/i;

export interface Beacon {
  app: string; path: string; signer: string; agent: string | null; dest: string; ip: string; port: number;
  count: number; intervalSec: number; jitter: number; score: number; lastSeen: number; suspicious: boolean; reason: string;
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

export async function collectBehavior(): Promise<void> {
  const findings: FindingInput[] = [];
  const t = Date.now();

  // --- Beaconing over the last 6 hours ---
  const beacons: Beacon[] = [];
  for (const g of connOpenGroups(t - 6 * 3600_000)) {
    if (g.times.length < 6) continue;
    const gaps = g.times.slice(1).map((x, i) => (x - g.times[i]) / 1000).filter((d) => d >= 8);
    if (gaps.length < 5) continue;
    const med = median(gaps);
    if (med < 20 || med > 7200) continue;
    const mad = median(gaps.map((d) => Math.abs(d - med)));
    const jitter = mad / med;
    if (jitter > 0.2) continue;
    const intel = matchIp(g.ip, g.port);
    // A script runtime (Homebrew's node, python, ...) is ad-hoc signed, so its signature says nothing about
    // the script it runs. Those count only if the destination is on a feed or they run from a risky place.
    const runtime = RUNTIME.test(g.path);
    const risky = riskyLocation(g.path);
    const untrusted = runtime ? Boolean(risky) : !TRUSTED.has(g.signer);
    const score = Math.round((1 - jitter) * Math.min(1, gaps.length / 20) * 100) / 100;
    const b: Beacon = {
      app: g.app, path: g.path, signer: g.signer, agent: g.agent, dest: g.dest, ip: g.ip, port: g.port,
      count: g.times.length, intervalSec: Math.round(med), jitter: Math.round(jitter * 100) / 100, score, lastSeen: g.times[g.times.length - 1],
      suspicious: Boolean(intel) || untrusted,
      reason: intel ? `destination is on ${intel.feed} (${intel.label})` : untrusted ? (risky ? `it runs from ${risky}` : 'the program has no trusted developer signature')
        : runtime ? 'a script runtime installed with a package manager, polling on a timer (typical for your own tools and dev servers)' : 'signed app on a regular schedule (normal for updaters and sync)',
    };
    beacons.push(b);
    if (b.suspicious) {
      findings.push({
        key: `beacon:${g.app}:${g.dest}:${g.port}`, category: 'network', severity: intel ? 'high' : 'medium',
        title: `${g.app} checks in with ${g.dest} every ${fmtInterval(b.intervalSec)}`,
        summary: `${b.count} connections in 6 hours, almost perfectly regular (jitter ${Math.round(b.jitter * 100)}%). ${b.reason[0].toUpperCase() + b.reason.slice(1)}.`,
        explanation: 'Malware often "phones home" to its control server on a fixed timer to ask for instructions. This pattern, called beaconing, is one of the most reliable signs of an infected computer. Legitimate updaters do it too, which is why I only flag it for programs without a trusted signature or for known-bad destinations.',
        recommendation: `Find out what ${g.app} is. If you did not install it on purpose, quit it and quarantine its file.`,
        evidence: b as unknown as Record<string, unknown>,
        actions: g.path?.startsWith('/') && !g.path.startsWith('/System') ? [{ type: 'quarantine_file', target: { path: g.path }, label: 'Quarantine file' }] : [],
      });
    }
  }
  beacons.sort((a, b) => Number(b.suspicious) - Number(a.suspicious) || b.score - a.score);

  // --- Upload spikes in the last 15 minutes vs the app's own last week ---
  const window = 15 * 60_000;
  const uploads = uploadStats(window)
    .map((u) => ({ ...u, ratio: u.p95 ? Math.round((u.out / u.p95) * 10) / 10 : null }))
    .sort((a, b) => b.out - a.out);
  for (const u of uploads) {
    const big = u.out > 100 * 1024 * 1024;
    const unusual = u.samples >= 20 ? u.out > 10 * Math.max(u.p95, 5 * 1024 * 1024) : u.out > 500 * 1024 * 1024;
    if (!big || !unusual) continue;
    const mb = Math.round(u.out / 1e6);
    if (HEAVY_UPLOADERS.test(u.app)) {
      if (markSeen('upload-spike', `${u.app}|${Math.floor(t / 3600_000)}`).isNew) logEvent('network', 'info', `${u.app} uploaded ${mb} MB in 15 minutes (it normally sends far less)`, u);
      continue;
    }
    findings.push({
      key: `upload:${u.app}`, category: 'network', severity: 'medium',
      title: `${u.app} uploaded ${mb} MB in the last 15 minutes`,
      summary: u.ratio ? `That is ${u.ratio}x its usual peak for 15 minutes this week.` : 'I have little history for this app yet, and this is a lot of data.',
      explanation: 'Sending a large amount of data out suddenly can mean files are being copied off the Mac (exfiltration). It is also normal for backups, uploads you started, or video calls. Check whether you were doing something that explains it.',
      recommendation: `If you were not uploading anything with ${u.app}, quit it and ask me which servers it was talking to.`,
      evidence: u as unknown as Record<string, unknown>,
    });
  }

  putSnapshot('behavior', { at: t, beacons: beacons.slice(0, 40), uploads: uploads.slice(0, 15), windowMinutes: 15 });
  syncFindings('behavior', findings);
}

export function fmtInterval(sec: number): string {
  if (sec < 90) return `${sec} seconds`;
  if (sec < 5400) return `${Math.round(sec / 60)} minutes`;
  return `${Math.round(sec / 3600)} hours`;
}
