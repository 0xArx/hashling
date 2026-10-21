/**
 * Open threat-intelligence feeds, downloaded every few hours and matched
 * locally. Nothing about this Mac is sent anywhere: Hashling downloads the public
 * lists and checks connections against them on-device.
 */
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { isIP } from 'node:net';
import { DATA_DIR } from '../config.ts';
import { putSnapshot } from '../db.ts';

const DIR = join(DATA_DIR, 'intel');

export interface Feed {
  id: string;
  name: string;
  url: string;
  kind: 'ip' | 'cidr' | 'ip-port' | 'domain';
  about: string;
  parse: (text: string) => { value: string; label?: string }[];
}

const lines = (t: string) => t.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
const csv = (l: string) => l.split('", "').map((c) => c.replace(/^"|"$/g, ''));

/** Big shared platforms: one phishing page there must not flag the whole platform. */
const SHARED_HOSTS = new Set(['google.com', 'docs.google.com', 'drive.google.com', 'sites.google.com', 'forms.gle', 'storage.googleapis.com', 'firebasestorage.googleapis.com',
  'dropbox.com', 'dl.dropboxusercontent.com', 'github.com', 'raw.githubusercontent.com', 'ipfs.io', 'cloudflare-ipfs.com', 'dweb.link', 'onedrive.live.com', '1drv.ms',
  'sharepoint.com', 'forms.office.com', 'office.com', 'microsoft.com', 'live.com', 'outlook.com', 't.me', 'telegra.ph', 'bit.ly', 'tinyurl.com', 'linktr.ee', 'canva.com',
  'notion.site', 'wixsite.com', 'weebly.com', 'blogspot.com', 'webflow.io', 'vercel.app', 'pages.dev', 'netlify.app', 'github.io', 'firebaseapp.com', 'web.app', 'herokuapp.com',
  'amazonaws.com', 's3.amazonaws.com', 'apple.com', 'icloud.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'youtube.com', 'mybluehost.me']);
const hostOfUrl = (u: string) => { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; } };
const notShared = (h: string) => h && !SHARED_HOSTS.has(h);

export const FEEDS: Feed[] = [
  {
    id: 'feodo', name: 'abuse.ch Feodo Tracker', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', kind: 'ip',
    about: 'Active botnet command-and-control servers (Emotet, QakBot, Dridex and similar).',
    parse: (t) => lines(t).filter((l) => isIP(l)).map((value) => ({ value, label: 'botnet C2 server' })),
  },
  {
    id: 'threatfox-ip', name: 'abuse.ch ThreatFox (IPs)', url: 'https://threatfox.abuse.ch/export/csv/ip-port/recent/', kind: 'ip-port',
    about: 'Malware infrastructure reported in the last days: C2 servers, payload hosts.',
    parse: (t) => lines(t).map(csv).filter((c) => c[2]?.includes(':')).map((c) => ({ value: c[2], label: `${c[7] || c[5] || c[4] || 'malware'}`.replace(/_/g, ' ') })),
  },
  {
    id: 'threatfox-domain', name: 'abuse.ch ThreatFox (domains)', url: 'https://threatfox.abuse.ch/export/csv/domains/recent/', kind: 'domain',
    about: 'Domains used by malware in the last days.',
    parse: (t) => lines(t).map(csv).filter((c) => c[2]).map((c) => ({ value: c[2].toLowerCase(), label: `${c[7] || c[5] || c[4] || 'malware'}`.replace(/_/g, ' ') })),
  },
  {
    id: 'urlhaus', name: 'abuse.ch URLhaus', url: 'https://urlhaus.abuse.ch/downloads/hostfile/', kind: 'domain',
    about: 'Hosts currently serving malware downloads.',
    parse: (t) => lines(t).map((l) => l.split(/\s+/)[1]).filter(Boolean).map((value) => ({ value: value.toLowerCase(), label: 'malware download host' })),
  },
  {
    id: 'phishing-db', name: 'Phishing.Database (active phishing domains)', url: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt', kind: 'domain',
    about: 'Phishing websites that are online right now: fake bank, delivery, Apple, Microsoft and crypto login pages. MIT licensed.',
    parse: (t) => lines(t).map((l) => l.toLowerCase().replace(/^www\./, '')).filter(notShared).map((value) => ({ value, label: 'phishing site' })),
  },
  {
    id: 'openphish', name: 'OpenPhish community feed', url: 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', kind: 'domain',
    about: 'Freshly reported phishing pages, refreshed through the day.',
    parse: (t) => lines(t).map(hostOfUrl).filter(notShared).map((value) => ({ value, label: 'phishing site' })),
  },
  {
    id: 'spamhaus-drop', name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop_v4.json', kind: 'cidr',
    about: 'Networks hijacked or run by criminals. Spamhaus says no legitimate traffic should go to them.',
    parse: (t) => lines(t).flatMap((l) => { try { const o = JSON.parse(l); return o.cidr ? [{ value: o.cidr, label: 'criminal network (Spamhaus DROP)' }] : []; } catch { return []; } }),
  },
  {
    id: 'et-compromised', name: 'Emerging Threats compromised IPs', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', kind: 'ip',
    about: 'Machines known to be compromised and attacking others.',
    parse: (t) => lines(t).filter((l) => isIP(l)).map((value) => ({ value, label: 'known compromised host' })),
  },
  {
    id: 'firehol-l1', name: 'FireHOL level 1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', kind: 'cidr',
    about: 'A curated, low-false-positive combination of major blocklists.',
    parse: (t) => lines(t).filter((l) => !/^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|22[4-9]\.|2[3-5]\d\.)/.test(l)).map((value) => ({ value, label: 'blocklisted network (FireHOL)' })),
  },
];

interface Range { start: number; end: number; label: string; feed: string }
let ipIndex = new Map<string, { label: string; feed: string }>();
let ipPortIndex = new Map<string, { label: string; feed: string }>();
let domainIndex = new Map<string, { label: string; feed: string }>();
let ranges: Range[] = [];
let loadedAt = 0;

const ipv4 = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0);

function cidrRange(cidr: string): [number, number] | null {
  const [base, bits] = cidr.split('/');
  if (isIP(base) !== 4) return null;
  const size = 2 ** (32 - Number(bits ?? 32));
  const start = Math.floor(ipv4(base) / size) * size;
  return [start, start + size - 1];
}

/** Rebuild the in-memory indexes from the files on disk. */
export function loadFeeds(): void {
  const ip = new Map<string, { label: string; feed: string }>();
  const ipPort = new Map<string, { label: string; feed: string }>();
  const dom = new Map<string, { label: string; feed: string }>();
  const rs: Range[] = [];
  for (const f of FEEDS) {
    const file = join(DIR, `${f.id}.txt`);
    if (!existsSync(file)) continue;
    const shared = new Map<string, { label: string; feed: string }>();
    for (const { value, label = f.name } of f.parse(readFileSync(file, 'utf8'))) {
      let entry = shared.get(label);
      if (!entry) { entry = { label, feed: f.name }; shared.set(label, entry); }
      if (f.kind === 'ip') ip.set(value, entry);
      else if (f.kind === 'ip-port') { ipPort.set(value, entry); ip.set(value.replace(/:\d+$/, ''), entry); }
      else if (f.kind === 'domain') dom.set(value.replace(/^www\./, ''), entry);
      else { const r = cidrRange(value); if (r) rs.push({ start: r[0], end: r[1], label, feed: f.name }); }
    }
  }
  rs.sort((a, b) => a.start - b.start);
  ipIndex = ip; ipPortIndex = ipPort; domainIndex = dom; ranges = rs; loadedAt = Date.now();
}

export interface IntelHit { feed: string; label: string; matched: string }

/** Is this IP (and optionally port) on any feed? */
export function matchIp(ip: string, port?: number): IntelHit | null {
  if (!loadedAt) loadFeeds();
  const exact = (port && ipPortIndex.get(`${ip}:${port}`)) || ipIndex.get(ip);
  if (exact) return { ...exact, matched: port ? `${ip}:${port}` : ip };
  if (isIP(ip) !== 4) return null;
  const n = ipv4(ip);
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = ranges[mid];
    if (n < r.start) hi = mid - 1;
    else if (n > r.end) lo = mid + 1;
    else return { feed: r.feed, label: r.label, matched: ip };
  }
  return null;
}

/** Is this host name (or a parent domain of it) on a feed? */
export function matchHost(host: string): IntelHit | null {
  if (!loadedAt) loadFeeds();
  let h = host.toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  while (h.includes('.')) {
    const hit = domainIndex.get(h);
    if (hit) return { ...hit, matched: h };
    h = h.slice(h.indexOf('.') + 1);
  }
  return null;
}

/** Download every feed (skipping fresh ones) and reload. */
export async function updateFeeds(force = false): Promise<void> {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const status: { id: string; name: string; about: string; entries: number; updated: number | null; error?: string }[] = [];
  for (const f of FEEDS) {
    const file = join(DIR, `${f.id}.txt`);
    let error: string | undefined;
    const fresh = existsSync(file) && Date.now() - statSync(file).mtimeMs < 5 * 3600_000;
    if (force || !fresh) {
      try {
        const res = await fetch(f.url, { signal: AbortSignal.timeout(30_000), headers: { 'user-agent': 'Hashling (local Mac security; github.com/0xArx/hashling)' } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (f.parse(text).length) writeFileSync(file, text);
        else throw new Error('empty or unexpected format');
      } catch (e) { error = String((e as Error).message); }
    }
    const entries = existsSync(file) ? f.parse(readFileSync(file, 'utf8')).length : 0;
    status.push({ id: f.id, name: f.name, about: f.about, entries, updated: existsSync(file) ? statSync(file).mtimeMs : null, ...(error ? { error } : {}) });
  }
  loadFeeds();
  putSnapshot('intel', { at: Date.now(), feeds: status, totals: { ips: ipIndex.size, networks: ranges.length, domains: domainIndex.size } });
}
