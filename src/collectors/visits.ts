/**
 * "Did I visit a scam site?" Reads the last 7 days of browser history on this Mac and keeps only
 * the sites that are on a phishing or malware list. The rest of the history is never stored or sent.
 */
import { copyFileSync, existsSync, readdirSync, rmSync, mkdtempSync, statSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { HOME } from '../config.ts';
import { matchHost } from '../intel/feeds.ts';
import { putSnapshot, syncFindings, type FindingInput } from '../db.ts';

const AS = (p: string) => join(HOME, 'Library/Application Support', p);
const CHROMIUM: [string, string][] = [['Chrome', AS('Google/Chrome')], ['Edge', AS('Microsoft Edge')], ['Brave', AS('BraveSoftware/Brave-Browser')], ['Arc', AS('Arc/User Data')], ['Vivaldi', AS('Vivaldi')]];
const WEEK = 7 * 86_400_000;

/** Runs every 2 minutes, so a history file that has not changed is not copied and read again. */
const cache = new Map<string, { mtime: number; rows: unknown[] }>();
function readCopy<T>(file: string, query: string, params: (number | string)[]): T[] {
  const mtime = Math.max(...[file, `${file}-wal`].map((f) => { try { return statSync(f).mtimeMs; } catch { return 0; } }));
  const hit = cache.get(file);
  if (hit && hit.mtime === mtime) return hit.rows as T[];
  const rows = readFresh<T>(file, query, params);
  cache.set(file, { mtime, rows });
  return rows;
}

/** Browsers lock their history file, so read a copy. */
function readFresh<T>(file: string, query: string, params: (number | string)[]): T[] {
  const dir = mkdtempSync(join(tmpdir(), 'hashling-h-'));
  try {
    copyFileSync(file, join(dir, 'h.db'));
    // Browsers keep history in WAL mode; bring the -wal file along and open the throwaway copy normally.
    for (const ext of ['-wal']) if (existsSync(file + ext)) copyFileSync(file + ext, join(dir, 'h.db' + ext));
    const db = new DatabaseSync(join(dir, 'h.db'));
    try { return db.prepare(query).all(...params) as T[]; } finally { db.close(); }
  } catch (e) { console.error('[visits]', file.replace(HOME, '~'), (e as Error).message); return []; } finally { rmSync(dir, { recursive: true, force: true }); }
}

export interface Visit { browser: string; host: string; at: number; label: string; feed: string }

export async function collectVisits(): Promise<void> {
  const since = Date.now() - WEEK;
  const seen = new Map<string, Visit>();
  const checked = new Map<string, Set<string>>();
  const consider = (browser: string, url: string, at: number) => {
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch { return; }
    if (!host) return;
    (checked.get(browser) ?? checked.set(browser, new Set()).get(browser)!).add(host);
    if (seen.has(`${browser}|${host}`)) return;
    const hit = matchHost(host);
    if (hit) seen.set(`${browser}|${host}`, { browser, host: host.replace(/^www\./, ''), at, label: hit.label, feed: hit.feed });
  };
  // Chrome-family: microseconds since 1601, too big for a JS number, so the query works in milliseconds.
  const chromeSince = since + 11_644_473_600_000;
  for (const [name, dir] of CHROMIUM) {
    if (!existsSync(dir)) continue;
    let profiles: string[] = [];
    try { profiles = readdirSync(dir).filter((n) => n === 'Default' || /^Profile \d+$/.test(n)); } catch { continue; }
    for (const p of profiles) {
      const f = join(dir, p, 'History');
      if (!existsSync(f)) continue;
      for (const r of readCopy<{ url: string; t: number }>(f, 'SELECT url, last_visit_time / 1000 AS t FROM urls WHERE last_visit_time / 1000 > ?', [chromeSince])) consider(name, r.url, r.t - 11_644_473_600_000);
    }
  }
  // Safari: seconds since 2001.
  const safari = join(HOME, 'Library/Safari/History.db');
  if (existsSync(safari)) {
    for (const r of readCopy<{ url: string; t: number }>(safari, 'SELECT i.url AS url, MAX(v.visit_time) AS t FROM history_visits v JOIN history_items i ON i.id = v.history_item WHERE v.visit_time > ? GROUP BY i.url', [(since - 978_307_200_000) / 1000])) consider('Safari', r.url, r.t * 1000 + 978_307_200_000);
  }
  // Firefox: microseconds since 1970.
  const ff = join(HOME, 'Library/Application Support/Firefox/Profiles');
  if (existsSync(ff)) {
    for (const p of readdirSync(ff)) {
      const f = join(ff, p, 'places.sqlite');
      if (existsSync(f)) for (const r of readCopy<{ url: string; t: number }>(f, 'SELECT url, last_visit_date AS t FROM moz_places WHERE last_visit_date > ?', [since * 1000])) consider('Firefox', r.url, r.t / 1000);
    }
  }
  const visits = [...seen.values()].sort((a, b) => b.at - a.at);
  putSnapshot('visits', { at: Date.now(), visits, checked: Object.fromEntries([...checked].map(([b, h]) => [b, h.size])) });
  const findings: FindingInput[] = visits.map((v) => {
    const phishing = /phishing/.test(v.label);
    // Opened in the last 15 minutes: the page may still be open, so this pops up straight away.
    const justNow = Date.now() - v.at < 15 * 60_000;
    return {
      key: `visit:${v.host}`, category: 'webvisits', severity: justNow ? 'critical' : 'high',
      title: justNow ? (phishing ? `Stop: ${v.host} is a known phishing site` : `Stop: ${v.host} spreads malware`) : phishing ? `You visited a known phishing site: ${v.host}` : `You visited a site that spreads malware: ${v.host}`,
      summary: `In ${v.browser}, ${new Date(v.at).toLocaleString([], { weekday: 'short', day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' })}. Listed by ${v.feed}.`,
      explanation: phishing
        ? 'Phishing sites copy real login pages (banks, Apple, Microsoft, delivery companies) to steal what you type. Visiting is not a problem by itself; typing a password, card number or code there is.'
        : 'This site is known for serving malware. If you downloaded or opened anything from it, it may be harmful.',
      recommendation: justNow && phishing
        ? 'Close that tab now and do not type any password, card number or code on it. If you already did, change that password on the real website or app straight away, and call your bank if you entered card details.'
        : phishing
        ? 'If you typed a password there, change it now on the real website or app (and anywhere you reuse it). If you entered card details, call your bank using the number on your card. If you only looked, you are fine.'
        : 'If you downloaded anything from it, use Check a file before you open it on the Scam check page, or run a malware scan. Then delete it.',
      evidence: v as unknown as Record<string, unknown>,
    };
  });
  syncFindings('webvisits', findings);
}
