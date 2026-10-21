import { statSync } from 'node:fs';
import { run } from './exec.ts';
import { db } from '../db.ts';

export type SignerKind = 'apple' | 'app-store' | 'developer-id' | 'development' | 'adhoc' | 'unsigned' | 'invalid' | 'missing' | 'unreadable';

export interface SignInfo {
  kind: SignerKind;
  identifier?: string;
  team?: string;
  authority?: string;
  notarized?: boolean;
  trusted: boolean;
  /** The full verify ran out of time (huge bundles like Xcode); it is finishing in the background. */
  unverified?: boolean;
}

const cache = new Map<string, { mtime: number; info: SignInfo }>();
const inflight = new Map<string, Promise<SignInfo>>();

// Verdicts survive restarts: verifying a large app bundle hashes hundreds of MB.
db.exec('CREATE TABLE IF NOT EXISTS sign_cache (path TEXT PRIMARY KEY, mtime REAL NOT NULL, info TEXT NOT NULL)');
const getCached = db.prepare('SELECT mtime, info FROM sign_cache WHERE path = ?');
const putCached = db.prepare('INSERT INTO sign_cache (path, mtime, info) VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET mtime = excluded.mtime, info = excluded.info');

/** Code-signing verdict for an executable or bundle, cached until the file changes. */
export async function signInfo(path: string): Promise<SignInfo> {
  let mtime = 0;
  try { mtime = statSync(path).mtimeMs; } catch { return { kind: 'missing', trusted: false }; }
  const hit = cache.get(path);
  if (hit && hit.mtime === mtime) return hit.info;
  const row = getCached.get(path) as { mtime: number; info: string } | undefined;
  if (row && row.mtime === mtime) {
    const info = JSON.parse(row.info) as SignInfo;
    cache.set(path, { mtime, info });
    return info;
  }
  const running = inflight.get(path);
  if (running) return running;
  const p = compute(path).then((info) => {
    cache.set(path, { mtime, info });
    if (info.unverified) deepVerify(path, mtime, info);
    else if (info.kind !== 'unreadable') putCached.run(path, mtime, JSON.stringify(info));
    return info;
  }).finally(() => inflight.delete(path));
  inflight.set(path, p);
  return p;
}

async function compute(path: string): Promise<SignInfo> {
  const d = await run('/usr/bin/codesign', ['-dv', '--verbose=2', path], { timeout: 8000 });
  const out = d.stderr;
  if (/Permission denied|Operation not permitted/.test(out)) return { kind: 'unreadable', trusted: false };
  if (/code object is not signed at all/.test(out)) return { kind: 'unsigned', trusted: false };
  const field = (k: string) => out.match(new RegExp(`^${k}=(.*)$`, 'm'))?.[1]?.trim();
  const authorities = [...out.matchAll(/^Authority=(.*)$/gm)].map((m) => m[1].trim());
  const identifier = field('Identifier');
  const team = field('TeamIdentifier');
  const leaf = authorities[0];
  const adhoc = /Signature=adhoc/.test(out) || /flags=.*adhoc/.test(out);

  // Not --strict: it also fails on harmless extended attributes left by updaters.
  const v = await run('/usr/bin/codesign', ['--verify', path], { timeout: 15000 });
  // A timeout (no exit code) means "not checked yet", never "broken": Xcode alone takes ~20 s.
  const timedOut = Boolean(v.timedOut);
  if (!timedOut && !v.ok && !adhoc && !/Permission denied|Operation not permitted/.test(v.stderr)) {
    return { kind: 'invalid', identifier, team, authority: leaf, trusted: false };
  }

  let kind: SignerKind;
  if (adhoc) kind = 'adhoc';
  else if (/^(macOS |iOS )?Software Signing$/.test(leaf ?? '') && authorities.includes('Apple Code Signing Certification Authority')) kind = 'apple';
  else if (leaf?.startsWith('Apple Mac OS Application Signing')) kind = 'app-store';
  else if (leaf?.startsWith('Developer ID Application')) kind = 'developer-id';
  else if (leaf?.startsWith('Apple Development') || leaf?.startsWith('Mac Developer')) kind = 'development';
  else kind = leaf ? 'developer-id' : 'unsigned';

  return {
    kind,
    identifier,
    team: team && team !== 'not set' ? team : undefined,
    authority: leaf,
    trusted: kind === 'apple' || kind === 'app-store' || kind === 'developer-id',
    ...(timedOut ? { unverified: true } : {}),
  };
}

/** Finish a verify that timed out, with a generous limit, then cache the real verdict. */
function deepVerify(path: string, mtime: number, info: SignInfo): void {
  if (inflight.has(`deep:${path}`)) return;
  const p = run('/usr/bin/codesign', ['--verify', path], { timeout: 300_000 }).then((v) => {
    if (v.timedOut) return info;
    const final: SignInfo = v.ok || /Permission denied|Operation not permitted/.test(v.stderr)
      ? { ...info, unverified: undefined }
      : { kind: 'invalid', identifier: info.identifier, team: info.team, authority: info.authority, trusted: false };
    cache.set(path, { mtime, info: final });
    putCached.run(path, mtime, JSON.stringify(final));
    return final;
  }).finally(() => inflight.delete(`deep:${path}`));
  inflight.set(`deep:${path}`, p);
}

export function describeSigner(s: SignInfo): string {
  switch (s.kind) {
    case 'apple': return 'Signed by Apple';
    case 'app-store': return 'Mac App Store';
    case 'developer-id': return s.authority?.replace('Developer ID Application: ', '').replace(/\s*\([A-Z0-9]{10}\)$/, '') ?? 'Identified developer'; // the team ID is in s.team
    case 'development': return 'Test build by a developer';
    case 'adhoc': return 'No verified developer';
    case 'unsigned': return 'Not signed';
    case 'invalid': return 'Signature broken or modified';
    case 'missing': return 'Couldn’t check';
    case 'unreadable': return 'Cannot check (needs administrator access)';
  }
}

/** Paths where legitimate software rarely runs from. */
export function riskyLocation(path: string): string | null {
  const p = path.toLowerCase();
  if (p.startsWith('/tmp/') || p.startsWith('/private/tmp/')) return 'a temporary folder';
  if (/^\/private\/var\/folders\/[^/]+\/[^/]+\/t\//.test(p)) return 'a temporary folder';
  if (p.includes('/downloads/')) return 'the Downloads folder';
  if (p.startsWith('/users/shared/')) return '/Users/Shared';
  if (/\/\.[^/]+\//.test(path) && !/\/\.(nvm|volta|cargo|rustup|bun|deno|local|npm|vscode|cursor|claude|codex|docker|orbstack|colima|pyenv|rbenv|asdf|sdkman|gradle|m2|hashling|config|swiftpm)\//i.test(path)) return 'a hidden folder';
  return null;
}
