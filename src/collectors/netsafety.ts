/**
 * Is the network this Mac is on safe to use?
 * - Wi-Fi security mode (open networks let anyone nearby see unencrypted traffic)
 * - Router identity: the gateway's hardware (MAC) address is remembered per
 *   network; if it suddenly changes, someone may be impersonating the router
 *   (ARP spoofing, the classic way to intercept traffic on shared Wi-Fi)
 * - DNS servers: a changed or unexpected DNS server can redirect sites you visit
 */
import { run } from '../lib/exec.ts';
import { isPrivate } from '../lib/ipinfo.ts';
import { db, now, putSnapshot, syncFindings, logEvent, type FindingInput } from '../db.ts';
import { createHash } from 'node:crypto';

db.exec(`CREATE TABLE IF NOT EXISTS networks (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  gateway_ip TEXT,
  gateway_mac TEXT,
  dns TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
)`);

const KNOWN_DNS: Record<string, string> = {
  '1.1.1.1': 'Cloudflare', '1.0.0.1': 'Cloudflare', '8.8.8.8': 'Google', '8.8.4.4': 'Google', '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9',
  '208.67.222.222': 'OpenDNS', '208.67.220.220': 'OpenDNS', '94.140.14.14': 'AdGuard', '94.140.15.15': 'AdGuard', '45.90.28.0': 'NextDNS', '45.90.30.0': 'NextDNS',
};

const SECURITY: Record<string, { label: string; level: 'open' | 'weak' | 'ok' | 'strong' }> = {
  none: { label: 'Open (no password)', level: 'open' },
  wep: { label: 'WEP (broken)', level: 'weak' },
  wpa_personal: { label: 'WPA (outdated)', level: 'weak' },
  wpa_personal_mixed: { label: 'WPA/WPA2 mixed', level: 'ok' },
  wpa2_personal: { label: 'WPA2 Personal', level: 'ok' },
  wpa2_enterprise: { label: 'WPA2 Enterprise', level: 'strong' },
  wpa3_personal: { label: 'WPA3 Personal', level: 'strong' },
  wpa3_transition: { label: 'WPA2/WPA3', level: 'strong' },
  wpa3_enterprise: { label: 'WPA3 Enterprise', level: 'strong' },
  owe: { label: 'Enhanced Open (encrypted, no password)', level: 'ok' },
};

export async function collectNetSafety(): Promise<void> {
  const [wifiOut, route, dnsOut] = await Promise.all([
    run('/usr/sbin/system_profiler', ['SPAirPortDataType', '-json'], { timeout: 30_000 }),
    run('/sbin/route', ['-n', 'get', 'default'], { timeout: 5000 }),
    run('/usr/sbin/scutil', ['--dns'], { timeout: 5000 }),
  ]);
  let wifi: { connected: boolean; security?: string; securityLevel?: string; phy?: string; channel?: string } = { connected: false };
  try {
    const d = JSON.parse(wifiOut.stdout);
    for (const iface of d.SPAirPortDataType?.[0]?.spairport_airport_interfaces ?? []) {
      const cur = iface.spairport_current_network_information;
      if (cur?.spairport_security_mode) {
        const mode = String(cur.spairport_security_mode).replace('spairport_security_mode_', '');
        const s = SECURITY[mode] ?? { label: mode.replace(/_/g, ' '), level: 'ok' };
        wifi = { connected: true, security: s.label, securityLevel: s.level, phy: cur.spairport_network_phymode, channel: cur.spairport_network_channel };
      }
    }
  } catch { /* no Wi-Fi */ }

  const gatewayIp = route.stdout.match(/gateway:\s*(\S+)/)?.[1];
  const iface = route.stdout.match(/interface:\s*(\S+)/)?.[1];
  let gatewayMac: string | undefined;
  if (gatewayIp) {
    const arp = await run('/usr/sbin/arp', ['-n', gatewayIp], { timeout: 5000 });
    gatewayMac = arp.stdout.match(/ at ([0-9a-f:]{11,17}) /i)?.[1]?.toLowerCase();
  }
  const dns = [...new Set([...dnsOut.stdout.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)].map((m) => m[1]))].filter((x) => !x.startsWith('fe80'));

  // A network's identity: interface + gateway IP + the first DNS server (stable across visits).
  const id = createHash('sha256').update(`${iface}|${gatewayIp}|${wifi.security ?? 'wired'}`).digest('hex').slice(0, 16);
  const label = wifi.connected ? `Wi-Fi (${wifi.security})` : iface ? `Wired (${iface})` : 'No network';
  const prev = db.prepare('SELECT * FROM networks WHERE id = ?').get(id) as Record<string, any> | undefined;
  const findings: FindingInput[] = [];

  if (wifi.securityLevel === 'open') {
    findings.push({ key: 'netsafe:open-wifi', category: 'netsafety', severity: 'medium', title: 'You are on open Wi-Fi',
      summary: 'This network has no password, so its traffic is not encrypted between your Mac and the router.',
      explanation: 'Anyone nearby can see traffic that is not protected by HTTPS, and can set up a fake hotspot with the same name. Apps that serve things to your local network (I list them under Network) are also reachable by strangers here.',
      recommendation: 'Use a VPN or your phone\'s hotspot on open Wi-Fi, and turn on the firewall.' });
  } else if (wifi.securityLevel === 'weak') {
    findings.push({ key: 'netsafe:weak-wifi', category: 'netsafety', severity: 'medium', title: `Wi-Fi uses ${wifi.security}`,
      summary: 'This Wi-Fi security can be cracked with freely available tools.',
      explanation: 'WEP and original WPA have been broken for years. Someone nearby can recover the key and read the network\'s traffic.',
      recommendation: 'If it is your router, switch it to WPA2 or WPA3 in its settings.' });
  }

  if (prev && gatewayMac && prev.gateway_mac && prev.gateway_mac !== gatewayMac) {
    findings.push({ key: `netsafe:gateway-changed:${id}`, category: 'netsafety', severity: 'high', title: 'Your router\'s identity changed',
      summary: `The router at ${gatewayIp} now answers from a different hardware address than before on this network.`,
      explanation: 'Every router has a hardware (MAC) address. If it changes on the same network, either the router was replaced or another device is pretending to be the router so it can intercept your traffic (ARP spoofing). On public Wi-Fi this is a real attack.',
      recommendation: 'If nobody replaced the router, disconnect from this network and use your phone\'s hotspot or a VPN.',
      evidence: { gatewayIp, before: prev.gateway_mac, now: gatewayMac } });
    logEvent('network', 'high', `Router identity changed on ${label}`, { gatewayIp });
  }
  const prevDns: string[] = prev?.dns ? JSON.parse(prev.dns) : [];
  const unknownDns = dns.filter((d) => !isPrivate(d) && !KNOWN_DNS[d]);
  if (prev && prevDns.length && dns.length && dns.join(',') !== prevDns.join(',') && unknownDns.length) {
    findings.push({ key: `netsafe:dns-changed:${id}`, category: 'netsafety', severity: 'medium', title: 'Your DNS servers changed',
      summary: `Now using ${dns.join(', ')} (was ${prevDns.join(', ')}).`,
      explanation: 'DNS turns names like apple.com into addresses. A rogue DNS server can quietly send you to fake sites. VPNs and network changes also change it legitimately.',
      recommendation: 'If you did not install a VPN or change settings, check System Settings > Network > Details > DNS.',
      evidence: { before: prevDns, now: dns } });
  }

  db.prepare(`INSERT INTO networks (id, label, gateway_ip, gateway_mac, dns, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET label = excluded.label, gateway_mac = COALESCE(networks.gateway_mac, excluded.gateway_mac), dns = excluded.dns, last_seen = excluded.last_seen`)
    .run(id, label, gatewayIp ?? null, gatewayMac ?? null, JSON.stringify(dns), now(), now());

  putSnapshot('netsafety', {
    at: now(), label, wifi, gatewayIp, gatewayKnown: Boolean(prev?.gateway_mac), gatewayStable: !prev?.gateway_mac || prev.gateway_mac === gatewayMac,
    dns: dns.map((d) => ({ ip: d, owner: KNOWN_DNS[d] ?? (isPrivate(d) ? 'Your router / local network' : 'Unknown provider') })),
    networksSeen: (db.prepare('SELECT COUNT(*) AS n FROM networks').get() as { n: number }).n,
  });
  syncFindings('netsafety', findings);
}
