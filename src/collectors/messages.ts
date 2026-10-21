/**
 * Text message scam watch: the job "Safe SMS" does in paid suites, done on this Mac.
 *
 * Messages keeps every text and iMessage this Mac receives in ~/Library/Messages/chat.db.
 * When the user switches this on, Hashling reads new incoming messages (read-only, needs Full
 * Disk Access), runs the same red-flag rules as Scam check and the scam-site lists over them,
 * and warns about the ones that look like scams. People you have written back to count as
 * known, so only strangers' texts are flagged (unless a link is on a scam list).
 * Nothing is sent anywhere, and message text is kept only for the texts it flags.
 */
import { DatabaseSync } from 'node:sqlite';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { HOME } from '../config.ts';
import { redFlags } from '../lib/scamflags.ts';
import { matchHost } from '../intel/feeds.ts';
import { loadPrefs } from '../prefs.ts';
import { logEvent, syncFindings, putSnapshot, getSnapshot, type FindingInput } from '../db.ts';

const CHAT_DB = join(HOME, 'Library/Messages/chat.db');
/** Messages stores dates as nanoseconds since 2001-01-01. */
const APPLE_EPOCH = Date.UTC(2001, 0, 1);
const KEEP_DAYS = 30;

interface Flagged { guid: string; at: number; from: string; text: string; flags: string[]; hosts: string[]; listed: boolean }
interface State { at: number; lastRowId: number; scanned: number; flagged: Flagged[]; error: string | null }

/**
 * Newer macOS versions keep the text only inside attributedBody, an archived NSAttributedString.
 * The plain string sits right after the "NSString" class name, behind a '+' marker and a length.
 */
export function textFromAttributedBody(buf: Uint8Array | null): string {
  if (!buf?.length) return '';
  const b = Buffer.from(buf);
  const at = b.indexOf('NSString');
  if (at < 0) return '';
  const plus = b.indexOf(0x2b, at + 8);
  if (plus < 0 || plus - at > 24) return '';
  let len = b[plus + 1];
  let start = plus + 2;
  if (len === 0x81) { len = b.readUInt16LE(plus + 2); start = plus + 4; }
  else if (len === 0x82) { len = b.readUInt32LE(plus + 2); start = plus + 6; }
  return b.subarray(start, Math.min(b.length, start + len)).toString('utf8');
}

const hostsIn = (text: string) => [...new Set([...text.matchAll(/\b(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/\S*)?/gi)].map((m) => m[1].toLowerCase()))];

function read(): State {
  return getSnapshot<State>('messageWatch')?.data ?? { at: 0, lastRowId: -1, scanned: 0, flagged: [], error: null };
}

export function messageWatchState(): State & { on: boolean } {
  return { ...read(), on: loadPrefs().messageWatch };
}

export async function collectMessages(): Promise<void> {
  if (!loadPrefs().messageWatch) return;
  const prev = read();
  if (!existsSync(CHAT_DB)) { putSnapshot('messageWatch', { ...prev, at: Date.now(), error: 'Messages has no texts on this Mac yet.' }); return; }
  let db: DatabaseSync;
  try { db = new DatabaseSync(CHAT_DB, { readOnly: true }); }
  catch { putSnapshot('messageWatch', { ...prev, at: Date.now(), error: 'I need Full Disk Access to read your texts. Turn it on for Hashling in System Settings.' }); return; }
  try {
    const since: { sql: string; arg: number | bigint } = prev.lastRowId >= 0
      ? { sql: 'm.ROWID > ?', arg: prev.lastRowId }
      // First run: look back a week, so switching it on gives an answer straight away.
      // Dates are nanoseconds since 2001, too big for a JavaScript number: compare and convert in SQL.
      : { sql: 'm.date > ?', arg: BigInt(Date.now() - 7 * 86_400_000 - APPLE_EPOCH) * 1_000_000n };
    const rows = db.prepare(`SELECT m.ROWID AS id, m.guid, m.text, m.attributedBody AS body, CAST(m.date / 1000000 AS INTEGER) AS date, m.handle_id AS hid, h.id AS sender
      FROM message m LEFT JOIN handle h ON h.ROWID = m.handle_id
      WHERE ${since.sql} AND m.is_from_me = 0 ORDER BY m.ROWID LIMIT 2000`).all(since.arg) as unknown as { id: number; guid: string; text: string | null; body: Uint8Array | null; date: number; hid: number; sender: string | null }[];
    const lastRowId = Math.max(prev.lastRowId, ...(rows.length ? rows.map((r) => r.id) : [(db.prepare('SELECT IFNULL(MAX(ROWID), 0) AS n FROM message').get() as { n: number }).n]));
    const known = new Set((db.prepare('SELECT DISTINCT handle_id AS h FROM message WHERE is_from_me = 1').all() as unknown as { h: number }[]).map((r) => r.h));
    const flagged: Flagged[] = [];
    for (const r of rows) {
      const text = (r.text || textFromAttributedBody(r.body)).trim();
      if (!text) continue;
      const hosts = hostsIn(text);
      const listed = hosts.some((h) => matchHost(h));
      const flags = redFlags(text).map((f) => f.label);
      const stranger = !known.has(r.hid);
      if (listed || (stranger && flags.length >= 2)) {
        flagged.push({ guid: r.guid, at: APPLE_EPOCH + Number(r.date), from: r.sender ?? 'Unknown sender', text: text.slice(0, 600), flags, hosts, listed });
      }
    }
    for (const f of flagged) logEvent('scam', f.listed ? 'high' : 'medium', `A text from ${f.from} looks like a scam: ${f.flags[0] ?? 'links to a known scam site'}`, { guid: f.guid });
    const keep = [...prev.flagged, ...flagged].filter((f) => Date.now() - f.at < KEEP_DAYS * 86_400_000).slice(-50);
    putSnapshot('messageWatch', { at: Date.now(), lastRowId, scanned: prev.scanned + rows.length, flagged: keep, error: null } satisfies State);
    publish(keep);
  } finally { db.close(); }
}

function publish(flagged: Flagged[]): void {
  syncFindings('messages', flagged.map((f): FindingInput => ({
    key: `msg:${f.guid}`, category: 'messages', severity: f.listed ? 'high' : 'medium',
    title: `A text from ${f.from} looks like a scam`,
    summary: `“${f.text.slice(0, 140)}${f.text.length > 140 ? '…' : ''}”`,
    explanation: `Warning signs: ${f.flags.join(', ') || 'none in the wording'}${f.listed ? `. It links to a site on a scam list (${f.hosts.join(', ')})` : ''}. Scam texts pretend to be a delivery company, bank, toll road or someone you know, and push you to tap a link or reply quickly.`,
    recommendation: 'Don’t tap the link or reply. If it claims to be a company you use, open their app or type their website yourself. Then delete the text and choose Report Junk in Messages.',
    evidence: f,
  })));
}

/** Switching it off forgets what it found. */
export function resetMessageWatch(): void {
  putSnapshot('messageWatch', { at: Date.now(), lastRowId: -1, scanned: 0, flagged: [], error: null } satisfies State);
  syncFindings('messages', []);
}
