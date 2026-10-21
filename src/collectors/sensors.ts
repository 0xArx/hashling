/**
 * Camera, microphone, screen and location history: who used them and when.
 * macOS logs every change of the orange and green indicator dots (Control Center
 * "sensor-indicators"); Hashling turns those log lines into sessions.
 */
import { basename } from 'node:path';
import { run } from '../lib/exec.ts';
import { getSnapshot, putSnapshot, syncFindings, type FindingInput } from '../db.ts';
import { bundlePath } from './permissions.ts';

export const SENSOR_LABEL: Record<string, string> = { cam: 'Camera', mic: 'Microphone', scr: 'Screen recording', aud: 'System audio recording', loc: 'Location' };
export interface Session { kind: string; app: string; name: string; start: number; end: number | null }

const KEEP = 7 * 86_400_000;
/** macOS parts people would not recognise by their process name. */
const SYSTEM_NAMES: Record<string, string> = {
  'com.apple.systemuiserver': 'macOS screenshot tool', 'com.apple.screencaptureui': 'macOS screenshot tool',
  'com.apple.controlcenter': 'Control Center', 'com.apple.FaceTime': 'FaceTime', 'com.apple.siri': 'Siri', 'com.apple.corespeechd': 'Siri',
};
const names = new Map<string, string>(Object.entries(SYSTEM_NAMES));
async function nameOf(id: string): Promise<string> {
  if (!names.has(id)) { const p = await bundlePath(id).catch(() => null); names.set(id, p ? basename(p).replace(/\.app$/, '') : id.split('.').pop() ?? id); }
  return names.get(id)!;
}

export async function collectSensors(): Promise<void> {
  const prev = getSnapshot<{ sessions: Session[]; until: number }>('sensors')?.data;
  const sessions: Session[] = (prev?.sessions ?? []).filter((s) => (s.end ?? Date.now()) > Date.now() - KEEP);
  const since = Math.max(prev?.until ?? 0, Date.now() - 86_400_000);
  const r = await run('/usr/bin/log', ['show', '--start', new Date(since).toISOString().replace('T', ' ').slice(0, 19), '--style', 'ndjson',
    '--predicate', 'subsystem == "com.apple.controlcenter" AND category == "sensor-indicators" AND eventMessage BEGINSWITH "Active activity attributions changed"'], { timeout: 120_000 });
  let until = since;
  for (const line of r.stdout.split('\n')) {
    let e: { timestamp?: string; eventMessage?: string };
    try { e = JSON.parse(line); } catch { continue; }
    if (!e.eventMessage || !e.timestamp) continue;
    const ts = Date.parse(e.timestamp.replace(' ', 'T').replace(/(\.\d{3})\d*/, '$1').replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
    if (!ts || ts <= (prev?.until ?? 0)) continue;
    until = Math.max(until, ts);
    const active = new Set([...e.eventMessage.matchAll(/"(\w+):([^"]+)"/g)].map((m) => `${m[1]}|${m[2]}`));
    // Close sessions that are no longer active, open new ones.
    for (const s of sessions) if (s.end === null && !active.has(`${s.kind}|${s.app}`)) s.end = ts;
    for (const key of active) {
      const [kind, app] = key.split('|');
      if (sessions.some((s) => s.end === null && s.kind === kind && s.app === app)) continue;
      // Back on within 5 minutes counts as the same use, so a list is not twenty one-minute rows.
      const recent = sessions.find((s) => s.kind === kind && s.app === app && s.end !== null && ts - s.end < 5 * 60_000);
      if (recent) recent.end = null;
      else sessions.push({ kind, app, name: await nameOf(app), start: ts, end: null });
    }
  }
  sessions.sort((a, b) => b.start - a.start);
  putSnapshot('sensors', { at: Date.now(), until, sessions: sessions.slice(0, 500) });

  // Worth a look: the camera or microphone switched on in the middle of the night.
  const findings: FindingInput[] = [];
  for (const s of sessions) {
    const h = new Date(s.start).getHours();
    if (!['cam', 'mic'].includes(s.kind) || h >= 5 || Date.now() - s.start > 3 * 86_400_000) continue;
    findings.push({
      key: `sensors:night:${s.kind}:${s.app}`, category: 'sensors', severity: 'medium',
      title: `${s.name} used your ${SENSOR_LABEL[s.kind].toLowerCase()} at ${new Date(s.start).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`,
      summary: `${new Date(s.start).toLocaleString()}, for ${s.end ? Math.max(1, Math.round((s.end - s.start) / 60_000)) + ' min' : 'as long as it is still on'}.`,
      explanation: 'Apps sometimes use the camera or microphone in the background, but at night, when you were probably not using the Mac, it is worth checking that you know why.',
      recommendation: `If that was not you, check ${s.name}’s permission in Privacy and take it away if you are unsure.`,
      evidence: s as unknown as Record<string, unknown>,
    });
  }
  syncFindings('sensors', findings);
}
