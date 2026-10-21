/**
 * Websites you let send notifications. Spam sites trick people into clicking "Allow"
 * ("press Allow to prove you are not a robot"), then push fake virus alerts and scam links
 * that look like they come from macOS. Read-only: Hashling lists them and shows where to remove them.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { HOME } from '../config.ts';
import { readPlist } from '../lib/exec.ts';
import { putSnapshot, syncFindings, type FindingInput } from '../db.ts';

const AS = (p: string) => join(HOME, 'Library/Application Support', p);
const CHROMIUM: { name: string; dir: string; settings: string }[] = [
  { name: 'Chrome', dir: AS('Google/Chrome'), settings: 'chrome://settings/content/notifications' },
  { name: 'Edge', dir: AS('Microsoft Edge'), settings: 'edge://settings/content/notifications' },
  { name: 'Brave', dir: AS('BraveSoftware/Brave-Browser'), settings: 'brave://settings/content/notifications' },
  { name: 'Arc', dir: AS('Arc/User Data'), settings: 'arc://settings/content/notifications' },
  { name: 'Vivaldi', dir: AS('Vivaldi'), settings: 'vivaldi://settings/content/notifications' },
];
const SAFARI = [join(HOME, 'Library/Safari/UserNotificationPermissions.plist'), join(HOME, 'Library/Containers/com.apple.Safari/Data/Library/Safari/UserNotificationPermissions.plist')];

/** Names that push-spam networks use: "click allow", captcha and prize lures, throwaway endings. */
const SPAMMY = /(captcha|robot|allow|verify|clean|virus|antivirus|prize|winner|reward|push|notif|alert|security-?check|deal|mp3|convert|download|stream|watch-?video|findmedia|free-?movie|\d{4,})|\.(top|xyz|click|icu|cfd|sbs|buzz|monster|cam|rest|quest|live|lol|online|site|space|fun|life|biz|info|pro|club|best|work|link|pw|cc|today|world|win|bid|download|review|racing|date|trade|party|loan|men|kim)$/i;

export interface SiteGrant { browser: string; site: string; spammy: boolean; settings: string }

export async function collectWebNotifications(): Promise<void> {
  const sites: SiteGrant[] = [];
  const blocked: string[] = [];
  for (const b of CHROMIUM) {
    if (!existsSync(b.dir)) continue;
    let profiles: string[] = [];
    try { profiles = readdirSync(b.dir).filter((n) => n === 'Default' || /^Profile \d+$/.test(n)); } catch { blocked.push(b.name); continue; }
    for (const p of profiles) {
      let prefs: any;
      try { prefs = JSON.parse(readFileSync(join(b.dir, p, 'Preferences'), 'utf8')); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'EPERM') blocked.push(b.name); continue; }
      const ex = prefs?.profile?.content_settings?.exceptions?.notifications ?? {};
      for (const [pattern, v] of Object.entries<any>(ex)) {
        if (v?.setting !== 1) continue;
        const site = pattern.split(',')[0].replace(/^https?:\/\//, '').replace(/:\d+$/, '').replace(/^\[\*\.\]/, '');
        if (site && site !== '*') sites.push({ browser: b.name, site, spammy: SPAMMY.test(site), settings: b.settings });
      }
    }
  }
  for (const f of SAFARI) {
    if (!existsSync(f)) continue;
    const pl = await readPlist<Record<string, any>>(f);
    for (const [origin, v] of Object.entries(pl ?? {})) {
      // Safari stores 1 for allowed, 2 for denied.
      if ((v?.Permission ?? v?.permission) !== 1) continue;
      const site = origin.replace(/^https?:\/\//, '').replace(/[:/].*$/, '');
      sites.push({ browser: 'Safari', site, spammy: SPAMMY.test(site), settings: 'Safari > Settings > Websites > Notifications' });
    }
  }
  const unique = [...new Map(sites.map((s) => [`${s.browser}|${s.site}`, s])).values()];
  putSnapshot('webnotify', { at: Date.now(), sites: unique, blocked: [...new Set(blocked)] });

  const findings: FindingInput[] = [];
  // One finding for all of them: it is one fix (a browser setting), not one problem per site.
  const spam = unique.filter((x) => x.spammy);
  if (spam.length) {
    const browsers = [...new Set(spam.map((x) => x.browser))];
    findings.push({
      key: 'webnotify:spam', category: 'permissions', severity: 'medium',
      title: spam.length === 1 ? `A spam website can send you notifications: ${spam[0].site}` : `${spam.length} spam websites can send you notifications`,
      summary: spam.map((x) => `${x.site} (${x.browser})`).join(', '),
      explanation: 'Spam sites trick people into pressing “Allow” (“prove you are not a robot”), then send fake virus warnings and scam links that look like real Mac alerts. They cannot harm your Mac by themselves, but the links they push can.',
      recommendation: `Remove them in ${browsers.join(' and ')}: the Privacy page has a button that opens the right setting. Never trust a notification that says your Mac is infected.`,
      evidence: { sites: spam },
    });
  }
  // A long list of ordinary sites is not worth a warning; the Privacy page lists them for anyone who wants to look.
  syncFindings('webnotify', findings);
}

// ---------- Browser hijacks ----------
// Adware changes your search engine and start page, or installs browser "policies" that force them
// (and force extensions) so you cannot change them back. Chrome then says "Managed by your organization".

const SEARCH_OK = /(google|bing|duckduckgo|yahoo|ecosia|brave|startpage|kagi|perplexity|qwant|yandex|baidu|naver|chatgpt|openai)\./i;
const POLICY_KEYS = ['ExtensionInstallForcelist', 'DefaultSearchProviderSearchURL', 'DefaultSearchProviderName', 'HomepageLocation', 'RestoreOnStartupURLs', 'NewTabPageLocation', 'ProxyServer', 'ProxyPacUrl'];
const POLICY_FILES: { browser: string; ids: string[] }[] = [
  { browser: 'Chrome', ids: ['com.google.Chrome'] }, { browser: 'Edge', ids: ['com.microsoft.Edge'] },
  { browser: 'Brave', ids: ['com.brave.Browser'] }, { browser: 'Arc', ids: ['company.thebrowser.Browser'] },
];
const hostOf = (u: string) => { try { return new URL(u.includes('://') ? u : `https://${u}`).hostname.replace(/^www\./, ''); } catch { return u.slice(0, 60); } };

export async function collectBrowserHijacks(): Promise<void> {
  const issues: { browser: string; kind: 'search' | 'startup' | 'policy'; detail: string }[] = [];
  for (const b of CHROMIUM) {
    if (!existsSync(b.dir)) continue;
    let profiles: string[] = [];
    try { profiles = readdirSync(b.dir).filter((n) => n === 'Default' || /^Profile \d+$/.test(n)); } catch { continue; }
    for (const p of profiles) {
      let prefs: any;
      try { prefs = JSON.parse(readFileSync(join(b.dir, p, 'Preferences'), 'utf8')); } catch { continue; }
      const search = prefs?.default_search_provider_data?.template_url_data?.url as string | undefined;
      if (search && !SEARCH_OK.test(hostOf(search))) issues.push({ browser: b.name, kind: 'search', detail: `Search engine: ${hostOf(search)}` });
      const startup = (prefs?.session?.startup_urls ?? []) as string[];
      const odd = startup.map(hostOf).filter((h) => h && !SEARCH_OK.test(h) && SPAMMY.test(h));
      if (odd.length) issues.push({ browser: b.name, kind: 'startup', detail: `Opens at startup: ${odd.join(', ')}` });
    }
  }
  for (const pf of POLICY_FILES) {
    for (const id of pf.ids) {
      for (const f of [`/Library/Managed Preferences/${id}.plist`, join(HOME, `Library/Preferences/${id}.plist`)]) {
        if (!existsSync(f)) continue;
        const pl = await readPlist<Record<string, unknown>>(f);
        const set = POLICY_KEYS.filter((k) => pl?.[k] !== undefined);
        if (set.length) issues.push({ browser: pf.browser, kind: 'policy', detail: `Forced settings (${set.join(', ')}) in ${f.replace(HOME, '~')}` });
      }
    }
  }
  putSnapshot('browserhijack', { at: Date.now(), issues });
  const findings: FindingInput[] = issues.map((i) => ({
    key: `browser:${i.kind}:${i.browser}`, category: 'browser', severity: i.kind === 'policy' ? 'high' : 'medium',
    title: i.kind === 'search' ? `${i.browser}’s search engine was changed` : i.kind === 'startup' ? `${i.browser} opens a suspicious page at startup` : `Something is forcing ${i.browser}’s settings`,
    summary: i.detail,
    explanation: i.kind === 'policy'
      ? 'Browser “policies” are meant for companies managing work computers. Adware installs them so it can force a search engine, start page or extension that you cannot remove. Chrome then shows “Managed by your organization”.'
      : 'Adware and fake “free” downloads change your search engine or start page so your searches go through their servers, where they show scam ads and can see what you search for.',
    recommendation: i.kind === 'policy'
      ? 'If this is not a work Mac, ask your AI to walk you through removing the policy file, then check Startup items and run a malware scan, because something installed it.'
      : `Set it back in ${i.browser}’s settings (Search engine and On startup), then check your browser extensions for anything you did not install.`,
    evidence: i as unknown as Record<string, unknown>,
  }));
  syncFindings('browser', findings);
}
