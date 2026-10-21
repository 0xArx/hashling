/**
 * File reputation by fingerprint, from two free open services. Only the SHA-1
 * hash leaves the Mac, never the file:
 * - Team Cymru Malware Hash Registry (DNS lookup): % of antivirus engines that
 *   flag this exact file, if any.
 * - CIRCL hashlookup: whether this exact file is known software (NIST NSRL and
 *   other known-good sets), or a known-malicious sample.
 * Set HASHLING_REPUTATION=0 to turn lookups off.
 */
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { Resolver } from 'node:dns/promises';
import { readPlist } from '../lib/exec.ts';
import { db, now } from '../db.ts';

export const REPUTATION_ON = process.env.HASHLING_REPUTATION !== '0';

db.exec('CREATE TABLE IF NOT EXISTS reputation (sha1 TEXT PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL)');

export interface Reputation {
  sha1: string;
  sha256: string;
  file: string;
  avDetectionPct: number | null;
  avLastSeen: number | null;
  knownGood: boolean;
  knownName?: string;
  knownMalicious?: string;
  verdict: 'malicious' | 'known-good' | 'unknown';
}

const resolver = new Resolver({ timeout: 3000, tries: 1 });

/** For an .app, the main executable is what gets fingerprinted. */
async function targetFile(path: string): Promise<string | null> {
  if (!existsSync(path)) return null;
  if (path.endsWith('.app')) {
    const info = await readPlist<Record<string, unknown>>(join(path, 'Contents/Info.plist'));
    const exe = info?.CFBundleExecutable as string | undefined;
    const p = exe ? join(path, 'Contents/MacOS', exe) : null;
    return p && existsSync(p) ? p : null;
  }
  return statSync(path).isFile() ? path : null;
}

function hashes(file: string): Promise<{ sha1: string; sha256: string }> {
  return new Promise((res, rej) => {
    const a = createHash('sha1');
    const b = createHash('sha256');
    createReadStream(file).on('data', (c) => { a.update(c); b.update(c); }).on('end', () => res({ sha1: a.digest('hex'), sha256: b.digest('hex') })).on('error', rej);
  });
}

export async function reputation(path: string): Promise<Reputation | null> {
  const file = await targetFile(path);
  if (!file || statSync(file).size > 2 * 1024 ** 3) return null;
  const { sha1, sha256 } = await hashes(file);
  const cached = db.prepare('SELECT ts, data FROM reputation WHERE sha1 = ?').get(sha1) as { ts: number; data: string } | undefined;
  if (cached && now() - cached.ts < 7 * 86_400_000) return { ...JSON.parse(cached.data), file };

  const rep: Reputation = { sha1, sha256, file, avDetectionPct: null, avLastSeen: null, knownGood: false, verdict: 'unknown' };
  if (REPUTATION_ON) {
    const [cymru, circl] = await Promise.allSettled([
      resolver.resolveTxt(`${sha1}.malware.hash.cymru.com`),
      fetch(`https://hashlookup.circl.lu/lookup/sha1/${sha1}`, { signal: AbortSignal.timeout(6000) }),
    ]);
    if (cymru.status === 'fulfilled' && cymru.value[0]) {
      const [ts, pct] = cymru.value[0].join('').split(' ').map(Number);
      rep.avLastSeen = ts * 1000;
      rep.avDetectionPct = pct;
    }
    if (circl.status === 'fulfilled' && circl.value.ok) {
      const j = await circl.value.json().catch(() => ({})) as Record<string, string>;
      if (j.KnownMalicious) rep.knownMalicious = j.KnownMalicious;
      else { rep.knownGood = true; rep.knownName = j.FileName || j.ProductName; }
    }
  }
  rep.verdict = (rep.avDetectionPct ?? 0) >= 10 || rep.knownMalicious ? 'malicious' : rep.knownGood ? 'known-good' : 'unknown';
  db.prepare('INSERT INTO reputation (sha1, ts, data) VALUES (?, ?, ?) ON CONFLICT(sha1) DO UPDATE SET ts = excluded.ts, data = excluded.data').run(sha1, now(), JSON.stringify(rep));
  return rep;
}
