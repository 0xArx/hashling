/**
 * Breach watch: has an email address you use turned up in a data breach?
 *
 * The same job as "dark web monitoring" in paid suites. Hashling asks XposedOrNot, a free,
 * open breach database (xposedornot.com), about each address you add, once a day, and tells
 * you about any breach it has not told you about before: which site, when, and what leaked.
 * Off until you add an address. The address itself is sent to XposedOrNot to look it up;
 * nothing else is. Passwords are never sent anywhere (see /api/pwned-range for those).
 */
import { db, now, logEvent, syncFindings, toJson, parseJson, type FindingInput } from '../db.ts';
import { bus } from '../bus.ts';

db.exec(`CREATE TABLE IF NOT EXISTS breach_watch (
  email TEXT PRIMARY KEY,
  added_at INTEGER NOT NULL,
  last_check INTEGER,
  last_error TEXT,
  breaches TEXT NOT NULL DEFAULT '[]',
  told TEXT NOT NULL DEFAULT '[]'
)`);

export interface Breach { name: string; domain: string; year: string; records: number; data: string[]; passwords: string; industry: string; about: string }
interface Row { email: string; added_at: number; last_check: number | null; last_error: string | null; breaches: string; told: string }

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[a-z]{2,}$/i;
const DAY = 86_400_000;
const MAX = 5;

/** a•••@gmail.com, so screenshots and the timeline do not show the whole address. */
export const mask = (email: string) => email.replace(/^(.)[^@]*(@.*)$/, (_m, a, b) => `${a}•••${b}`);

export function listWatched(): { email: string; masked: string; addedAt: number; lastCheck: number | null; error: string | null; breaches: Breach[] }[] {
  return (db.prepare('SELECT * FROM breach_watch ORDER BY added_at').all() as unknown as Row[]).map((r) => ({
    email: r.email, masked: mask(r.email), addedAt: r.added_at, lastCheck: r.last_check, error: r.last_error, breaches: parseJson<Breach[]>(r.breaches, []),
  }));
}

export async function watchEmail(raw: string): Promise<{ ok: true } | { error: string }> {
  const email = String(raw ?? '').trim().toLowerCase();
  if (!EMAIL.test(email)) return { error: 'That doesn’t look like an email address.' };
  const n = (db.prepare('SELECT COUNT(*) AS n FROM breach_watch').get() as { n: number }).n;
  if (n >= MAX && !db.prepare('SELECT 1 FROM breach_watch WHERE email = ?').get(email)) return { error: `I can watch up to ${MAX} addresses.` };
  db.prepare('INSERT OR IGNORE INTO breach_watch (email, added_at) VALUES (?, ?)').run(email, now());
  await checkOne(email, true);
  return { ok: true };
}

export function unwatchEmail(email: string): boolean {
  const r = db.prepare('DELETE FROM breach_watch WHERE email = ?').run(String(email).toLowerCase());
  refreshFindings();
  bus.emit('change', { type: 'breaches' });
  return r.changes > 0;
}

/** Daily: look each address up again and report breaches I have not told you about. */
export async function checkBreaches(force = false): Promise<void> {
  for (const r of db.prepare('SELECT email, last_check FROM breach_watch').all() as unknown as Row[]) {
    if (!force && r.last_check && now() - r.last_check < DAY) continue;
    await checkOne(r.email, false);
    await new Promise((res) => setTimeout(res, 1200)); // the free service allows 2 a second, 25 an hour
  }
}

async function lookup(email: string): Promise<Breach[]> {
  const res = await fetch(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`, {
    headers: { 'user-agent': 'Hashling (open-source Mac security, github.com/0xArx/hashling)' },
    signal: AbortSignal.timeout(20_000),
  });
  if (res.status === 429) throw new Error('The breach database is busy. I’ll try again later.');
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`The breach database answered ${res.status}. I’ll try again later.`);
  const j = await res.json() as { ExposedBreaches?: { breaches_details?: Record<string, unknown>[] } | null };
  return (j.ExposedBreaches?.breaches_details ?? []).map((b) => ({
    name: String(b.breach ?? 'Unknown'),
    domain: String(b.domain ?? ''),
    year: String(b.xposed_date ?? ''),
    records: Number(b.xposed_records ?? 0),
    data: String(b.xposed_data ?? '').split(';').map((s) => s.trim()).filter(Boolean),
    passwords: String(b.password_risk ?? ''),
    industry: String(b.industry ?? ''),
    about: String(b.details ?? '').replace(/<[^>]+>/g, '').slice(0, 400),
  })).sort((a, b) => b.year.localeCompare(a.year));
}

async function checkOne(email: string, first: boolean): Promise<void> {
  try {
    const breaches = await lookup(email);
    const row = db.prepare('SELECT told FROM breach_watch WHERE email = ?').get(email) as { told: string } | undefined;
    const told = new Set(parseJson<string[]>(row?.told, []));
    const fresh = breaches.filter((b) => !told.has(b.name));
    // The first look reports what is already known as one line; after that, each new breach is news.
    if (fresh.length && !first) for (const b of fresh) logEvent('breach', 'high', `${mask(email)} was found in a new data breach: ${b.name}`, { email: mask(email), breach: b.name });
    if (first) logEvent('breach', breaches.length ? 'medium' : 'info', breaches.length ? `${mask(email)} is in ${breaches.length} known data ${breaches.length === 1 ? 'breach' : 'breaches'}` : `${mask(email)} is not in any known data breach`, { email: mask(email) });
    db.prepare('UPDATE breach_watch SET last_check = ?, last_error = NULL, breaches = ?, told = ? WHERE email = ?')
      .run(now(), toJson(breaches), toJson([...told, ...fresh.map((b) => b.name)]), email);
  } catch (e) {
    db.prepare('UPDATE breach_watch SET last_check = ?, last_error = ? WHERE email = ?').run(now(), String((e as Error).message).slice(0, 200), email);
  }
  refreshFindings();
  bus.emit('change', { type: 'breaches' });
}

const PLAIN: Record<string, string> = { 'plaintext': 'stored in plain text', 'easytocrack': 'stored in a way that is easy to crack', 'hardtocrack': 'stored in a way that is hard to crack', 'unknown': 'stored in an unknown way' };

function refreshFindings(): void {
  const findings: FindingInput[] = [];
  for (const w of listWatched()) {
    if (!w.breaches.length) continue;
    const latest = w.breaches[0];
    const pw = w.breaches.filter((b) => b.data.some((d) => /password/i.test(d)));
    findings.push({
      key: `breach:${w.email}`, category: 'accounts', severity: pw.some((b) => Number(b.year) >= new Date().getFullYear() - 2) ? 'medium' : 'low',
      title: `${w.masked} is in ${w.breaches.length} data ${w.breaches.length === 1 ? 'breach' : 'breaches'}`,
      summary: `Most recent: ${latest.name}${latest.year ? ` (${latest.year})` : ''}, where ${latest.data.slice(0, 4).join(', ').toLowerCase() || 'account details'} leaked.${pw.length ? ` Passwords leaked in ${pw.length === 1 ? '1 of them' : `${pw.length} of them`}.` : ''}`,
      explanation: 'When a company is hacked, the stolen details are often sold or shared online. Criminals try those email and password pairs on other sites, and use the personal details to make scam messages more convincing.',
      recommendation: `${pw.length ? `Change your password on ${pw.slice(0, 3).map((b) => b.domain || b.name).join(', ')}, and anywhere you used the same one. ` : ''}Turn on two-step sign-in for your email first. Expect scam emails that mention these sites, and use a password manager so every site gets its own password.`,
      evidence: { email: w.masked, breaches: w.breaches.slice(0, 12).map((b) => ({ ...b, passwordStorage: PLAIN[b.passwords.toLowerCase()] ?? b.passwords })) },
    });
  }
  syncFindings('accounts', findings, 'breach:');
}
