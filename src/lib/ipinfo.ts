import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import { ENRICH_NETWORK } from '../config.ts';

export interface IpInfo { host?: string; org?: string; asn?: string; country?: string }

const cache = new Map<string, IpInfo & { at: number }>();
const pending = new Set<string>();
const queue: string[] = [];
let active = 0;

const resolver = new Resolver({ timeout: 2500, tries: 1 });

export function isPrivate(ip: string): boolean {
  if (!ip || ip === '*') return true;
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a >= 224 || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('ff') || l.startsWith('::ffff:127.') || l.startsWith('::ffff:192.168.') || l.startsWith('::ffff:10.');
}

/** Cached owner info for an IP; schedules a lookup when unknown. */
export function ipInfo(ip: string): IpInfo {
  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < 6 * 3600_000) return hit;
  if (ENRICH_NETWORK && !isPrivate(ip) && !pending.has(ip)) {
    pending.add(ip);
    queue.push(ip);
    pump();
  }
  return hit ?? {};
}

function pump(): void {
  while (active < 6 && queue.length) {
    const ip = queue.shift()!;
    active++;
    lookup(ip).then((info) => cache.set(ip, { ...info, at: Date.now() })).catch(() => cache.set(ip, { at: Date.now() }))
      .finally(() => { active--; pending.delete(ip); pump(); });
  }
}

function reverseName(ip: string): string {
  if (isIP(ip) === 4) return ip.split('.').reverse().join('.');
  const full = expandV6(ip).replace(/:/g, '');
  return full.split('').reverse().join('.');
}

function expandV6(ip: string): string {
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail ? tail.split(':') : [];
  const fill = Array(8 - h.length - t.length).fill('0');
  return [...h, ...(ip.includes('::') ? fill : []), ...t].map((p) => p.padStart(4, '0')).join(':');
}

const asnCache = new Map<string, string>();

async function lookup(ip: string): Promise<IpInfo> {
  const info: IpInfo = {};
  const [ptr, origin] = await Promise.allSettled([
    resolver.reverse(ip),
    resolver.resolveTxt(`${reverseName(ip)}.${isIP(ip) === 4 ? 'origin' : 'origin6'}.asn.cymru.com`),
  ]);
  if (ptr.status === 'fulfilled' && ptr.value[0]) info.host = ptr.value[0];
  if (origin.status === 'fulfilled' && origin.value[0]) {
    const parts = origin.value[0].join('').split('|').map((s) => s.trim());
    info.asn = parts[0]?.split(' ')[0];
    info.country = parts[2];
    if (info.asn) {
      let org = asnCache.get(info.asn);
      if (!org) {
        try {
          const t = await resolver.resolveTxt(`AS${info.asn}.asn.cymru.com`);
          org = t[0]?.join('').split('|').pop()?.trim() ?? '';
          asnCache.set(info.asn, org);
        } catch { org = ''; }
      }
      info.org = prettyOrg(org);
    }
  }
  return info;
}

/** "AMAZON-02 - Amazon.com, Inc., US" -> "Amazon.com, Inc." */
function prettyOrg(raw: string): string | undefined {
  if (!raw) return undefined;
  let s = raw.replace(/,\s*[A-Z]{2}$/, '');
  const dash = s.indexOf(' - ');
  if (dash > 0) s = s.slice(dash + 3);
  return s.trim() || raw;
}
