/**
 * The security score. Pure: it takes findings and macOS setting checks and returns the score with
 * everything needed to explain it, so it can be tested without a Mac.
 *
 * How it works, in plain words:
 * 1. Seven areas each get a score from 0 to 100. Mac settings come from the setting checks (weighted:
 *    SIP and FileVault matter more than stealth mode). Every other area starts at 100 and loses points
 *    for each open warning, with diminishing returns, so ten small tips never weigh as much as one real problem.
 * 2. The overall score is the areas' weighted average, pulled toward the weakest area.
 * 3. Open problems cap the score, so the number never says "fine" while the verdict disagrees: something
 *    suspicious keeps it at 79 or below (59 if serious), anything worth fixing keeps it out of "Excellent",
 *    and a serious weakness (such as FileVault off) keeps it out of "Good".
 * Ignored warnings and checks that could not be read never cost points.
 */

export type Tier = 'suspicious' | 'risk' | 'hardening';
export interface ScoreFinding { id: string; key: string; category: string; severity: string; tier: Tier; title: string; last_seen?: number }
export interface ScoreCheck { id: string; label: string; status: string }

export const AREAS = {
  system: { label: 'Mac settings', weight: 22, categories: ['posture', 'updates'] },
  threats: { label: 'Malware & attacks', weight: 24, categories: ['malware', 'malware-artifacts', 'ransomware', 'pups', 'incidents', 'processes'] },
  agents: { label: 'AI agents', weight: 14, categories: ['agents'] },
  accounts: { label: 'Passwords & keys', weight: 12, categories: ['secrets', 'accounts', 'messages'] },
  apps: { label: 'Apps & startup', weight: 10, categories: ['persistence', 'downloads', 'notarization'] },
  network: { label: 'Network', weight: 10, categories: ['network', 'behavior', 'netsafety', 'webvisits'] },
  privacy: { label: 'Privacy & tracking', weight: 8, categories: ['permissions', 'webnotify', 'browser', 'sensors', 'trackers', 'location'] },
} as const;
export type AreaId = keyof typeof AREAS;

/** How much each macOS setting matters (same scale the settings check has always used). */
export const CHECK_WEIGHT: Record<string, number> = { sip: 20, gatekeeper: 15, filevault: 15, firewall: 8, 'security-updates': 10, 'pending-updates': 8, 'auto-login': 8, 'custom-roots': 6, proxy: 6, xprotect: 4, guest: 3, 'screen-lock': 4, stealth: 2, 'os-updates': 3, mdm: 1, profiles: 2, 'remote-apps': 2 };

const SEVERITY_POINTS: Record<string, number> = { critical: 25, high: 12, medium: 5, low: 1.5, info: 0 };
const TIER_FACTOR: Record<Tier, number> = { suspicious: 1.5, risk: 1, hardening: 0.25 };
/** Diminishing returns: an area holding this many points of warnings sits at about 37 out of 100. */
const AREA_SCALE = 40;
/** The overall score leans this much toward the weakest area. */
const WEAKEST_PULL = 0.25;
/** Ceilings while something suspicious is open, by its severity. */
const SUSPICIOUS_CAP: Record<string, number> = { critical: 39, high: 59, medium: 69, low: 79, info: 79 };
/** Open weaknesses keep the score out of the top grades: anything worth fixing out of "Excellent", a serious one out of "Good". */
const RISK_CAP = 89;
const SERIOUS_RISK_CAP = 74;
const STALE_MS = 3 * 86_400_000;

export const GRADES = [
  { min: 90, label: 'Excellent', tone: 'ok' },
  { min: 75, label: 'Good', tone: 'ok' },
  { min: 60, label: 'Fair', tone: 'warn' },
  { min: 40, label: 'Needs attention', tone: 'warn' },
  { min: 0, label: 'At risk', tone: 'bad' },
] as const;
export const gradeOf = (score: number) => GRADES.find((g) => score >= g.min)!;

/** Points one warning takes from its area before diminishing returns. Old sightings count half. */
export function findingCost(f: ScoreFinding, at = Date.now()): number {
  const base = (SEVERITY_POINTS[f.severity] ?? 0) * TIER_FACTOR[f.tier];
  return f.last_seen && at - f.last_seen > STALE_MS ? base / 2 : base;
}

export function areaOf(category: string): AreaId | null {
  for (const [id, a] of Object.entries(AREAS)) if ((a.categories as readonly string[]).includes(category)) return id as AreaId;
  return null;
}

export interface ScoreInput {
  findings: ScoreFinding[]; // open findings only (ignored ones left out)
  checks: ScoreCheck[] | null; // macOS setting checks, null if they have not run yet
  ignoredChecks?: string[]; // setting check ids the user chose to ignore
  partial?: Partial<Record<AreaId, string>>; // areas Hashling could not fully check, with the reason
  at?: number;
}

export interface AreaScore { id: AreaId; label: string; weight: number; score: number; open: number; worst: string | null; partial: string | null }

function compute(input: ScoreInput) {
  const at = input.at ?? Date.now();
  const ignored = new Set(input.ignoredChecks ?? []);
  const areas = {} as Record<AreaId, AreaScore>;
  for (const [id, a] of Object.entries(AREAS) as [AreaId, (typeof AREAS)[AreaId]][]) {
    // Setting checks already score Mac settings, so their own warnings are not counted a second time.
    const items = input.findings.filter((f) => f.category !== 'posture' && areaOf(f.category) === id);
    const points = items.reduce((n, f) => n + findingCost(f, at), 0);
    let score = 100 * Math.exp(-points / AREA_SCALE);
    if (id === 'system' && input.checks?.length) {
      let total = 0, got = 0;
      for (const c of input.checks) {
        if (c.status === 'unknown' || ignored.has(c.id)) continue; // not checked or ignored: no penalty
        const w = CHECK_WEIGHT[c.id] ?? 1;
        total += w;
        got += c.status === 'pass' ? w : c.status === 'warn' ? w / 2 : 0;
      }
      score = (total ? (100 * got) / total : 100) * Math.exp(-points / AREA_SCALE);
    }
    const worst = [...items].sort((x, y) => findingCost(y, at) - findingCost(x, at))[0];
    const failing = id === 'system' ? (input.checks ?? []).filter((c) => (c.status === 'fail' || c.status === 'warn') && !ignored.has(c.id)) : [];
    const worstCheck = [...failing].sort((x, y) => (CHECK_WEIGHT[y.id] ?? 1) - (CHECK_WEIGHT[x.id] ?? 1))[0];
    areas[id] = {
      id, label: a.label, weight: a.weight, score,
      open: items.length + failing.length,
      worst: worstCheck?.label ?? worst?.title ?? null,
      partial: input.partial?.[id] ?? (id === 'system' && !input.checks ? 'The settings check has not run yet' : null),
    };
  }
  const list = Object.values(areas);
  const avg = list.reduce((n, a) => n + a.weight * a.score, 0) / list.reduce((n, a) => n + a.weight, 0);
  const weakest = list.reduce((m, a) => (a.score < m.score ? a : m));
  const blended = (1 - WEAKEST_PULL) * avg + WEAKEST_PULL * weakest.score;
  // Caps: the score can't look healthy while something suspicious or worth fixing is open. Setting warnings
  // count here (FileVault off is serious) even though their points come from the checks.
  const open = input.findings.filter((f) => areaOf(f.category));
  let cap: { at: number; reason: 'suspicious' | 'serious' | 'fix'; count: number } | null = null;
  const sus = open.filter((f) => f.tier === 'suspicious');
  const risks = open.filter((f) => f.tier === 'risk');
  const serious = risks.filter((f) => f.severity === 'high' || f.severity === 'critical');
  if (sus.length) {
    const worstSev = sus.reduce((m, f) => ((SUSPICIOUS_CAP[f.severity] ?? 79) < (SUSPICIOUS_CAP[m] ?? 79) ? f.severity : m), 'low');
    cap = { at: SUSPICIOUS_CAP[worstSev] ?? 79, reason: 'suspicious', count: sus.length };
  } else if (serious.length) cap = { at: SERIOUS_RISK_CAP, reason: 'serious', count: serious.length };
  else if (risks.length) cap = { at: RISK_CAP, reason: 'fix', count: risks.length };
  const raw = Math.round(Math.max(0, Math.min(100, blended)));
  const score = cap ? Math.min(raw, cap.at) : raw;
  return { score, raw, areas: list, weakest: weakest.id, cap: cap && raw > cap.at ? cap : null };
}

/** Fixing one thing rarely lifts a cap on its own, so gains are measured before caps: what each fix is worth. */
function gainOf(base: number, changed: ScoreInput): number {
  return compute(changed).raw - base;
}

/** The score, the seven areas, any cap, and the fixes that would raise it most (each worked out exactly). */
export function computeScore(input: ScoreInput) {
  const base = compute(input);
  const gains: { id: string; title: string; points: number; kind: 'finding' | 'check' }[] = [];
  for (const f of input.findings) {
    if (f.category === 'posture' || !areaOf(f.category)) continue;
    const points = gainOf(base.raw, { ...input, findings: input.findings.filter((x) => x.id !== f.id) });
    if (points > 0) gains.push({ id: f.id, title: f.title, points, kind: 'finding' });
  }
  for (const c of input.checks ?? []) {
    if (c.status !== 'fail' && c.status !== 'warn') continue;
    if ((input.ignoredChecks ?? []).includes(c.id)) continue;
    const points = gainOf(base.raw, {
      ...input,
      checks: input.checks!.map((x) => (x.id === c.id ? { ...x, status: 'pass' } : x)),
      findings: input.findings.filter((x) => x.key !== `posture:${c.id}`),
    });
    if (points > 0) gains.push({ id: `posture:${c.id}`, title: c.label, points, kind: 'check' });
  }
  gains.sort((x, y) => y.points - x.points);
  const grade = gradeOf(base.score);
  return {
    score: base.score,
    grade: grade.label,
    tone: grade.tone,
    beforeCap: base.raw,
    cap: base.cap,
    weakest: base.weakest,
    areas: base.areas.map((a) => ({ ...a, score: Math.round(a.score) })),
    topGains: gains.slice(0, 5),
  };
}
