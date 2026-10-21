/**
 * A weekly summary in plain words, for the person who helps you with your tech.
 * No file paths, passwords or personal details: only how the Mac is doing and what changed.
 * The helper's name and email live here, outside the prefs agents can read.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { hostname } from 'node:os';
import { DATA_DIR } from './config.ts';
import { db, listEvents } from './db.ts';
import { overview } from './overview.ts';
import { scoreHistory } from './history.ts';
import { describe } from './actions.ts';

const FILE = join(DATA_DIR, 'helper.json');
export interface Helper { name: string; email: string }

export function loadHelper(): Helper | null {
  try { const h = JSON.parse(readFileSync(FILE, 'utf8')); return h?.email ? h : null; } catch { return null; }
}
export function saveHelper(b: { name?: unknown; email?: unknown }): Helper | null {
  const email = String(b.email ?? '').trim();
  if (!email) { writeFileSync(FILE, '{}', { mode: 0o600 }); return null; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('That email address does not look right.');
  const h = { name: String(b.name ?? '').trim().slice(0, 60), email: email.slice(0, 200) };
  writeFileSync(FILE, JSON.stringify(h), { mode: 0o600 });
  return h;
}

const DAY = 86_400_000;

export function weeklySummary(): { subject: string; body: string } {
  const since = Date.now() - 7 * DAY;
  const o = overview();
  const week = scoreHistory(7) as { score: number }[];
  const before = week[0]?.score;
  const mac = hostname().replace(/\.local$/, '').replace(/-/g, ' ');
  const lines: string[] = [];
  const day = new Date().toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long' });

  lines.push(`Hashling weekly summary for ${mac}, ${day}`, '');
  lines.push(`Overall: ${o.verdict}. Security score ${o.score} out of 100${before !== undefined && before !== o.score ? ` (it was ${before} a week ago)` : ''}.`, '');

  const attention = o.topFindings.filter((f: { severity: string }) => ['critical', 'high', 'medium'].includes(f.severity)).slice(0, 6);
  lines.push(attention.length ? 'Needs a look:' : 'Needs a look: nothing right now.');
  for (const f of attention) lines.push(`• ${f.title}`);
  lines.push('');

  const fixed = db.prepare(`SELECT title FROM findings WHERE status = 'resolved' AND resolved_at >= ? AND resolved_at - first_seen >= 3600000 AND severity IN ('critical','high','medium') ORDER BY resolved_at DESC LIMIT 6`).all(since) as { title: string }[];
  const done = db.prepare(`SELECT type, target FROM actions WHERE status = 'executed' AND decided_at >= ? ORDER BY decided_at DESC LIMIT 6`).all(since) as { type: string; target: string }[];
  if (fixed.length || done.length) {
    lines.push('Sorted out this week:');
    for (const a of done) { try { lines.push(`• ${describe(a.type as never, JSON.parse(a.target))}`); } catch { /* old row */ } }
    for (const f of fixed) lines.push(`• No longer a problem: ${f.title}`);
    lines.push('');
  }

  const events = listEvents(2000, since);
  const pasted = events.filter((e) => e.title.startsWith('Stopped a risky Terminal command')).length;
  const swaps = events.filter((e) => e.title.startsWith('A copied crypto wallet address was swapped')).length;
  const saves = [pasted && `stopped ${pasted === 1 ? 'a risky command' : `${pasted} risky commands`} copied from a website`, swaps && `caught ${swaps === 1 ? 'a swapped wallet address' : `${swaps} swapped wallet addresses`}`].filter(Boolean);
  if (saves.length) lines.push(`I protected you: I ${saves.join(' and ')}.`, '');

  lines.push('If anything above looks wrong, open Hashling on the Mac and press Ask Hashling. This summary has no passwords, files or personal details in it.');
  return { subject: `Hashling weekly summary: ${o.verdict}`, body: lines.join('\n') };
}
