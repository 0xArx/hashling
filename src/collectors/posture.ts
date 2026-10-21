import { plural } from '../lib/text.ts';
import { readdirSync, statSync } from 'node:fs';
import { run, readPlist } from '../lib/exec.ts';
import { XPROTECT_PLIST, XPROTECT_YARA } from '../config.ts';
import { REMOTE_ACCESS_APPS } from '../knowledge.ts';
import { putSnapshot, syncFindings, getSnapshot, type FindingInput, type Severity } from '../db.ts';

export interface Check {
  id: string;
  label: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  why: string;
  fix?: string;
}

const out = async (cmd: string, args: string[]) => {
  const r = await run(cmd, args, { timeout: 20_000 });
  return (r.stdout + '\n' + r.stderr).trim();
};

let lastUpdateCheck = 0;
let pendingUpdates: string[] | null = null;

export async function collectPosture(): Promise<void> {
  const checks: Check[] = [];
  const findings: FindingInput[] = [];
  const add = (c: Check, sev?: Severity) => {
    checks.push(c);
    // Every non-passing check becomes a finding (info if it has no severity) so it can be explained or ignored.
    // Stealth mode is a nice-to-have with little real protection; shown in the list, not raised as a warning.
    if ((c.status === 'fail' || c.status === 'warn') && c.id !== 'stealth') {
      findings.push({ key: `posture:${c.id}`, category: 'posture', severity: sev ?? 'info', title: c.label + ': ' + c.detail, summary: c.detail, explanation: c.why, recommendation: c.fix ?? '', evidence: { check: c.id } });
    }
  };

  const [sip, gk, fv, fw, stealth, swu, autoLogin, guest, proxy, trustUser, trustAdmin, mdm, profiles, lock, swVers] = await Promise.all([
    out('/usr/bin/csrutil', ['status']),
    out('/usr/sbin/spctl', ['--status']),
    out('/usr/bin/fdesetup', ['status']),
    out('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']),
    out('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getstealthmode']),
    readPlist<Record<string, unknown>>('/Library/Preferences/com.apple.SoftwareUpdate.plist'),
    out('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.loginwindow', 'autoLoginUser']),
    out('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.loginwindow', 'GuestEnabled']),
    out('/usr/sbin/scutil', ['--proxy']),
    out('/usr/bin/security', ['dump-trust-settings']),
    out('/usr/bin/security', ['dump-trust-settings', '-d']),
    out('/usr/bin/profiles', ['status', '-type', 'enrollment']),
    out('/usr/bin/profiles', ['list']),
    out('/usr/sbin/sysadminctl', ['-screenLock', 'status']),
    out('/usr/bin/sw_vers', []),
  ]);

  add({ id: 'sip', label: 'System Integrity Protection', status: /enabled\./.test(sip) ? 'pass' : 'fail', detail: /enabled\./.test(sip) ? 'On' : 'Off',
    why: 'SIP stops anything, even admin tools, from modifying macOS system files. Malware that gets root still cannot tamper with the OS while it is on.',
    fix: 'Boot into Recovery and run `csrutil enable`.' }, 'high');
  add({ id: 'gatekeeper', label: 'Gatekeeper', status: /assessments enabled/.test(gk) ? 'pass' : 'fail', detail: /assessments enabled/.test(gk) ? 'On' : 'Off',
    why: 'Gatekeeper blocks apps that are not signed and notarized by Apple from opening without your explicit approval.',
    fix: 'Run `sudo spctl --master-enable`.' }, 'high');
  add({ id: 'filevault', label: 'FileVault disk encryption', status: /FileVault is On/.test(fv) ? 'pass' : 'fail', detail: /FileVault is On/.test(fv) ? 'On' : 'Off',
    why: 'Without disk encryption, anyone with physical access to this Mac can read every file on it.',
    fix: 'System Settings > Privacy & Security > FileVault.' }, 'high');
  const fwOn = /enabled|State = [12]/.test(fw) && !/disabled/.test(fw);
  add({ id: 'firewall', label: 'Firewall', status: fwOn ? 'pass' : 'fail', detail: fwOn ? 'On' : 'Off',
    why: 'The macOS firewall blocks unwanted incoming connections to apps and services on this Mac. It matters most on public and shared Wi-Fi.',
    fix: 'System Settings > Network > Firewall.' }, 'medium');
  add({ id: 'stealth', label: 'Stealth mode', status: /is on/.test(stealth) ? 'pass' : 'warn', detail: /is on/.test(stealth) ? 'On' : 'Off',
    why: 'Stealth mode makes the Mac ignore pings and probes, so it is harder to discover on a network.',
    fix: 'System Settings > Network > Firewall > Options > Enable stealth mode.' });

  const xp = await readPlist<Record<string, string>>(XPROTECT_PLIST);
  let xpAge = -1;
  try { xpAge = Math.floor((Date.now() - statSync(XPROTECT_YARA).mtimeMs) / 86_400_000); } catch { /* ignore */ }
  add({ id: 'xprotect', label: 'Apple’s built-in malware protection (XProtect)', status: xpAge >= 0 && xpAge <= 45 ? 'pass' : 'warn',
    detail: `Version ${xp?.CFBundleShortVersionString ?? '?'}, updated ${xpAge >= 0 ? `${plural(xpAge, 'day')} ago` : 'unknown'}`,
    why: 'XProtect is Apple\'s built-in malware scanner. Apple pushes new definitions every couple of weeks; stale definitions miss new threats.',
    fix: 'Keep "Install Security Responses and system files" on in Software Update settings.' }, 'low');

  const crit = swu?.CriticalUpdateInstall, conf = swu?.ConfigDataInstall;
  const secAuto = crit !== 0 && conf !== 0 && crit !== false && conf !== false;
  add({ id: 'security-updates', label: 'Automatic security updates', status: secAuto ? 'pass' : 'fail', detail: secAuto ? 'On' : 'Off',
    why: 'Security responses and XProtect/system data updates install silently in the background when this is on.',
    fix: 'System Settings > General > Software Update > Automatic updates.' }, 'medium');
  const osAuto = swu?.AutomaticallyInstallMacOSUpdates;
  add({ id: 'os-updates', label: 'Automatic macOS updates', status: osAuto === 1 || osAuto === true ? 'pass' : 'warn', detail: osAuto === 1 || osAuto === true ? 'On' : 'Off',
    why: 'Most real-world Mac compromises use bugs that already have a patch. Automatic updates close that window.' });

  if (Date.now() - lastUpdateCheck > 6 * 3600_000) {
    lastUpdateCheck = Date.now();
    const r = await run('/usr/sbin/softwareupdate', ['-l'], { timeout: 120_000 });
    const text = r.stdout + r.stderr;
    pendingUpdates = [...text.matchAll(/^\s*\* Label: (.+)$/gm)].map((m) => m[1].trim());
  }
  if (pendingUpdates) {
    const security = pendingUpdates.filter((u) => /security|rapid|rsr|macos/i.test(u));
    add({ id: 'pending-updates', label: 'Pending updates', status: pendingUpdates.length ? (security.length ? 'fail' : 'warn') : 'pass',
      detail: pendingUpdates.length ? pendingUpdates.join(', ') : 'Up to date',
      why: 'Installed updates fix known security holes that attackers actively use.',
      fix: 'System Settings > General > Software Update.' }, security.length ? 'medium' : undefined);
  }

  const autoLoginOn = !/Could not find|does not exist/.test(autoLogin);
  add({ id: 'auto-login', label: 'Automatic login', status: autoLoginOn ? 'fail' : 'pass', detail: autoLoginOn ? `On (${autoLogin})` : 'Off',
    why: 'With automatic login, anyone who turns on the Mac gets straight into your account. It also weakens FileVault.',
    fix: 'System Settings > Users & Groups > Automatically log in as > Off.' }, 'medium');
  const guestOn = guest.trim() === '1';
  add({ id: 'guest', label: 'Guest account', status: guestOn ? 'warn' : 'pass', detail: guestOn ? 'On' : 'Off',
    why: 'The guest account lets anyone use this Mac without a password. Files are wiped on logout, but it still gives a stranger a foothold.',
    fix: 'System Settings > Users & Groups > Guest User > Off.' }, 'low');
  const lockImmediate = /immediate|delay is [0-5] seconds/.test(lock);
  add({ id: 'screen-lock', label: 'Password after sleep', status: lockImmediate ? 'pass' : 'warn', detail: lock.replace(/^.*\] /, '') || 'unknown',
    why: 'Requiring a password right after sleep or screen saver stops someone walking up to an unattended Mac.',
    fix: 'System Settings > Lock Screen > Require password after screen saver begins > Immediately.' }, 'low');

  const proxyOn = /(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable) : 1/.test(proxy);
  const proxyHosts = [...proxy.matchAll(/(HTTPProxy|HTTPSProxy|SOCKSProxy|ProxyAutoConfigURLString) : (.+)/g)].map((m) => `${m[1]}=${m[2]}`);
  add({ id: 'proxy', label: 'System proxy', status: proxyOn ? 'warn' : 'pass', detail: proxyOn ? `Set: ${proxyHosts.join(', ')}` : 'None',
    why: 'A system proxy routes your web traffic through another server. Debugging tools (Charles, Proxyman) and some VPNs set one; adware and traffic-stealing malware do too.',
    fix: 'If you did not set it, remove it in System Settings > Network > (your network) > Details > Proxies.' }, 'medium');

  const certCount = (s: string) => /No Trust Settings/.test(s) ? 0 : Number(s.match(/Number of trusted certs = (\d+)/)?.[1] ?? 0);
  const certNames = (s: string) => [...s.match(/^Cert \d+: (.+)$/gm) ?? []].map((l) => l.replace(/^Cert \d+: /, ''));
  const roots = certCount(trustUser) + certCount(trustAdmin);
  const rootNames = [...certNames(trustUser), ...certNames(trustAdmin)];
  add({ id: 'custom-roots', label: 'Custom trusted certificates', status: roots ? 'warn' : 'pass', detail: roots ? `${roots}: ${rootNames.join(', ')}` : 'None',
    why: 'A custom trusted root certificate lets whoever owns it read and modify your encrypted (HTTPS) traffic. Developer tools like mkcert, Charles and Proxyman add one on purpose; spyware does it silently.',
    fix: 'Open Keychain Access and remove certificates you do not recognise.' }, 'medium');

  const mdmOn = /MDM enrollment: Yes/.test(mdm);
  const profileCount = /There are no configuration profiles/.test(profiles) ? 0 : (profiles.match(/attribute: profileIdentifier/g)?.length ?? 0);
  add({ id: 'mdm', label: 'Device management (MDM)', status: mdmOn ? 'warn' : 'pass', detail: mdmOn ? 'Enrolled' : 'Not enrolled',
    why: 'An MDM server can install apps, certificates and settings and see device details. Expected on a work Mac, unexpected on a personal one.' }, 'low');
  add({ id: 'profiles', label: 'Configuration profiles', status: profileCount ? 'warn' : 'pass', detail: profileCount ? `${profileCount} installed` : 'None',
    why: 'Profiles can silently change DNS, proxies, VPNs and trusted certificates. Malicious profiles are a known adware and spyware technique.',
    fix: 'Review them in System Settings > General > Device Management.' }, 'low');

  let apps: string[] = [];
  try { apps = readdirSync('/Applications').map((a) => a.replace(/\.app$/, '')); } catch { /* ignore */ }
  const remote = apps.filter((a) => REMOTE_ACCESS_APPS.some((r) => a.toLowerCase().includes(r.toLowerCase())));
  add({ id: 'remote-apps', label: 'Remote-access software', status: remote.length ? 'warn' : 'pass', detail: remote.length ? remote.join(', ') : 'None installed',
    why: 'Remote-access apps let someone else see and control this Mac. Scammers ask victims to install them ("tech support" scams). Fine if you use them yourself.',
    fix: 'Uninstall the ones you do not use.' }, 'low');

  const version = swVers.match(/ProductVersion:\s*(.+)/)?.[1] ?? '';
  const score = scoreOf(checks);
  putSnapshot('posture', { at: Date.now(), os: version, build: swVers.match(/BuildVersion:\s*(.+)/)?.[1], score, checks, pendingUpdates });
  syncFindings('posture', findings);
}

function scoreOf(checks: Check[]): number {
  const weight: Record<string, number> = { sip: 20, gatekeeper: 15, filevault: 15, firewall: 8, 'security-updates': 10, 'pending-updates': 8, 'auto-login': 8, 'custom-roots': 6, proxy: 6, xprotect: 4, guest: 3, 'screen-lock': 4, stealth: 2, 'os-updates': 3, mdm: 1, profiles: 2, 'remote-apps': 2 };
  let total = 0, got = 0;
  for (const c of checks) {
    const w = weight[c.id] ?? 1;
    total += w;
    got += c.status === 'pass' ? w : c.status === 'warn' ? w * 0.5 : c.status === 'unknown' ? w * 0.5 : 0;
  }
  return total ? Math.round((got / total) * 100) : 0;
}

export function postureScore(): number | null {
  return getSnapshot<{ score: number }>('posture')?.data?.score ?? null;
}
