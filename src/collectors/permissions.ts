import { plural } from '../lib/text.ts';
import { DatabaseSync } from 'node:sqlite';
import { existsSync, copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { HOME } from '../config.ts';
import { run } from '../lib/exec.ts';
import { signInfo, describeSigner } from '../lib/codesign.ts';
import { putSnapshot, syncFindings, markSeen, baselineStart, logEvent, type FindingInput } from '../db.ts';

/** Where each permission lives in System Settings > Privacy & Security. */
export const SETTINGS_ANCHOR: Record<string, string> = {
  kTCCServiceSystemPolicyAllFiles: 'Privacy_AllFiles', kTCCServiceAccessibility: 'Privacy_Accessibility', kTCCServicePostEvent: 'Privacy_Accessibility',
  kTCCServiceScreenCapture: 'Privacy_ScreenCapture', kTCCServiceListenEvent: 'Privacy_ListenEvent', kTCCServiceCamera: 'Privacy_Camera',
  kTCCServiceMicrophone: 'Privacy_Microphone', kTCCServiceAppleEvents: 'Privacy_Automation', kTCCServicePhotos: 'Privacy_Photos',
  kTCCServiceSystemPolicyDesktopFolder: 'Privacy_FilesAndFolders', kTCCServiceSystemPolicyDocumentsFolder: 'Privacy_FilesAndFolders',
  kTCCServiceSystemPolicyDownloadsFolder: 'Privacy_FilesAndFolders', kTCCServiceSystemPolicyNetworkVolumes: 'Privacy_FilesAndFolders',
  kTCCServiceSystemPolicyRemovableVolumes: 'Privacy_FilesAndFolders', kTCCServiceAddressBook: 'Privacy_Contacts', kTCCServiceCalendar: 'Privacy_Calendars',
  kTCCServiceReminders: 'Privacy_Reminders', kTCCServiceBluetoothAlways: 'Privacy_Bluetooth', kTCCServiceDeveloperTool: 'Privacy_DevTools',
};

/** Steps for removing an app's entry by hand, used when macOS will not let Hashling do it. */
export const removeSteps = (label: string, name: string) =>
  `Open System Settings, then Privacy & Security, then ${label}. Select ${name} and click the minus (−) button. If ${name} is not in the list, there is nothing left to remove.`;

export const SERVICES: Record<string, { label: string; risk: 'high' | 'medium' | 'low'; why: string }> = {
  kTCCServiceSystemPolicyAllFiles: { label: 'Full Disk Access', risk: 'high', why: 'Can read every file, including mail, messages, browser data and other apps\' private data.' },
  kTCCServiceAccessibility: { label: 'Accessibility (control your Mac)', risk: 'high', why: 'Can see what is on screen and click and type as you, in any app.' },
  kTCCServiceScreenCapture: { label: 'Screen & system audio recording', risk: 'high', why: 'Can record everything on your screen.' },
  kTCCServiceListenEvent: { label: 'Input Monitoring (keystrokes)', risk: 'high', why: 'Can read every key you type, in every app. This is what keyloggers need.' },
  kTCCServicePostEvent: { label: 'Send keystrokes', risk: 'medium', why: 'Can type and click on your behalf.' },
  kTCCServiceCamera: { label: 'Camera', risk: 'medium', why: 'Can turn on the camera.' },
  kTCCServiceMicrophone: { label: 'Microphone', risk: 'medium', why: 'Can record audio.' },
  kTCCServiceAppleEvents: { label: 'Automation (control other apps)', risk: 'medium', why: 'Can script another app, e.g. read Safari tabs or send Messages.' },
  kTCCServiceSystemPolicyDesktopFolder: { label: 'Desktop folder', risk: 'low', why: 'Can read files on your Desktop.' },
  kTCCServiceSystemPolicyDocumentsFolder: { label: 'Documents folder', risk: 'low', why: 'Can read your Documents.' },
  kTCCServiceSystemPolicyDownloadsFolder: { label: 'Downloads folder', risk: 'low', why: 'Can read your Downloads.' },
  kTCCServiceSystemPolicyNetworkVolumes: { label: 'Network volumes', risk: 'low', why: 'Can read network drives.' },
  kTCCServiceSystemPolicyRemovableVolumes: { label: 'Removable volumes', risk: 'low', why: 'Can read USB drives.' },
  kTCCServicePhotos: { label: 'Photos', risk: 'medium', why: 'Can read your photo library, which often includes location metadata.' },
  kTCCServiceAddressBook: { label: 'Contacts', risk: 'medium', why: 'Can read your contacts.' },
  kTCCServiceCalendar: { label: 'Calendars', risk: 'low', why: 'Can read your calendar.' },
  kTCCServiceReminders: { label: 'Reminders', risk: 'low', why: 'Can read your reminders.' },
  kTCCServiceBluetoothAlways: { label: 'Bluetooth', risk: 'low', why: 'Can scan for nearby Bluetooth devices (which can reveal location).' },
  kTCCServiceDeveloperTool: { label: 'Developer tool', risk: 'low', why: 'Can run software that bypasses some Gatekeeper checks.' },
  kTCCServiceEndpointSecurityClient: { label: 'Endpoint security', risk: 'medium', why: 'Can watch every process and file event (security tools).' },
  kTCCServiceSystemPolicyAppBundles: { label: 'App Management', risk: 'medium', why: 'Can modify or delete other apps.' },
  kTCCServiceMediaLibrary: { label: 'Media library', risk: 'low', why: 'Can read Apple Music / media library.' },
  kTCCServiceSpeechRecognition: { label: 'Speech recognition', risk: 'low', why: 'Can send audio for speech recognition.' },
  kTCCServiceFocusStatus: { label: 'Focus status', risk: 'low', why: 'Can see your Focus status.' },
};

export interface Grant {
  service: string;
  label: string;
  risk: string;
  client: string;
  /** The app's real name when it can be found, for display. */
  name?: string;
  clientType: 'bundle' | 'path';
  path?: string;
  allowed: boolean;
  target?: string;
  scope: 'user' | 'system';
  modified: number;
  signer?: string;
  signerKind?: string;
}

const USER_DB = join(HOME, 'Library/Application Support/com.apple.TCC/TCC.db');
const SYSTEM_DB = '/Library/Application Support/com.apple.TCC/TCC.db';

/** Read the access table; if the live file will not open read-only (WAL mode), read a throwaway copy instead. */
function accessRows(path: string): Record<string, unknown>[] {
  const q = 'SELECT service, client, client_type, auth_value, indirect_object_identifier, last_modified FROM access';
  try {
    const db = new DatabaseSync(path, { readOnly: true });
    try { return db.prepare(q).all() as Record<string, unknown>[]; } finally { db.close(); }
  } catch (first) {
    if (!existsSync(path)) throw first;
    const dir = mkdtempSync(join(tmpdir(), 'hashling-tcc-'));
    try {
      copyFileSync(path, join(dir, 'TCC.db'));
      if (existsSync(`${path}-wal`)) copyFileSync(`${path}-wal`, join(dir, 'TCC.db-wal'));
      const db = new DatabaseSync(join(dir, 'TCC.db'));
      try { return db.prepare(q).all() as Record<string, unknown>[]; } finally { db.close(); }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
}

function readTcc(path: string, scope: 'user' | 'system'): { rows: Grant[]; error?: string } {
  // Newer macOS versions may not keep a per-user file at all; that is not an error, just nothing to read.
  if (scope === 'user' && !existsSync(path)) return { rows: [] };
  try {
    const rows = accessRows(path);
    return {
      rows: rows.map((r) => {
        const svc = String(r.service);
        const meta = SERVICES[svc];
        return {
          service: svc,
          label: meta?.label ?? svc.replace('kTCCService', ''),
          risk: meta?.risk ?? 'low',
          client: String(r.client),
          clientType: Number(r.client_type) === 1 ? 'path' : 'bundle',
          allowed: Number(r.auth_value) === 2 || Number(r.auth_value) === 3,
          target: r.indirect_object_identifier && r.indirect_object_identifier !== 'UNUSED' ? String(r.indirect_object_identifier) : undefined,
          scope,
          modified: Number(r.last_modified) * 1000,
        } as Grant;
      }),
    };
  } catch (e) {
    return { rows: [], error: String((e as Error).message) };
  }
}

const bundlePathCache = new Map<string, string | null>();
export async function bundlePath(id: string): Promise<string | null> {
  if (bundlePathCache.has(id)) return bundlePathCache.get(id)!;
  const safe = id.replace(/[^\w.-]/g, '');
  const r = await run('/usr/bin/mdfind', [`kMDItemCFBundleIdentifier == "${safe}"`], { timeout: 5000 });
  let p = r.stdout.split('\n').find((l) => l.endsWith('.app')) ?? null;
  // Spotlight misses some apps; LaunchServices (macOS's app registry) knows every registered one.
  if (!p && safe) {
    const ls = await run('/usr/bin/osascript', ['-e', `POSIX path of (path to application id "${safe}")`], { timeout: 5000 });
    const found = ls.ok ? ls.stdout.trim().replace(/\/$/, '') : '';
    p = found.endsWith('.app') ? found : null;
  }
  bundlePathCache.set(id, p);
  return p;
}

export async function collectPermissions(): Promise<void> {
  const u = readTcc(USER_DB, 'user');
  const s = readTcc(SYSTEM_DB, 'system');
  // Either database opening proves Full Disk Access (the system one needs it too); the user one can fail for other reasons.
  const fullDiskAccess = !u.error || !s.error;
  if (u.error && s.error) {
    putSnapshot('permissions', { at: Date.now(), grants: [], access: { user: false, system: false } },
      'I need Full Disk Access to read which apps have camera, microphone, screen, keystroke and file permissions. Turn on Hashling in System Settings > Privacy & Security > Full Disk Access.');
    syncFindings('permissions', []);
    return;
  }
  const grants = [...u.rows, ...s.rows].filter((g) => g.allowed);
  const findings: FindingInput[] = [];
  const baseline = baselineStart('tcc');

  const leftovers: { name: string; label: string; service: string }[] = [];
  for (const g of grants) {
    g.path = g.clientType === 'path' ? g.client : (await bundlePath(g.client)) ?? undefined;
    // An app ID that matches nothing on this Mac belongs to an app that was removed.
    g.name = g.path ? basename(g.path).replace(/\.app$/, '')
      : g.clientType === 'bundle' ? g.client.split('.').slice(1).map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') || g.client
      : g.client.split('/').pop() ?? g.client;
    if (g.path && existsSync(g.path)) {
      const si = await signInfo(g.path);
      g.signer = describeSigner(si);
      g.signerKind = si.kind;
    } else {
      g.signerKind = 'missing';
    }
    const seen = markSeen('tcc', `${g.service}|${g.client}|${g.target ?? ''}`, { label: g.label, client: g.client });
    if (seen.isNew && baseline !== null && g.risk !== 'low') {
      logEvent('permission', g.risk === 'high' ? 'medium' : 'low', `${g.client} was granted ${g.label}`, { service: g.service, client: g.client });
    }

    const name = g.name ?? g.client;
    if (g.risk === 'high' && g.signerKind === 'missing') { leftovers.push({ name, label: g.label, service: g.service }); continue; }
    if (g.risk === 'high' && g.signerKind && !['apple', 'app-store', 'developer-id'].includes(g.signerKind)) {
      findings.push({
        key: `tcc:${g.service}:${g.client}`, category: 'permissions', severity: 'medium',
        title: `${name} has ${g.label}, but its developer is not verified`,
        summary: `${g.signer ?? 'No verified developer'}. If you did not build or install ${name} yourself, take this permission away.`,
        explanation: `${SERVICES[g.service]?.why ?? ''} Powerful permissions belong to apps from identified developers. Unsigned tools you built or installed with Homebrew are a judgement call.`,
        recommendation: 'Revoke it unless you know why this tool needs it.',
        evidence: g as unknown as Record<string, unknown>,
        actions: g.clientType === 'bundle' ? [{ type: 'revoke_permission', target: { service: g.service, bundleId: g.client, label: g.label }, label: 'Revoke permission' }] : [],
      });
    }
  }
  // Apps that are gone but still listed: one tidy-up note, not one warning per app and permission.
  if (leftovers.length) {
    const apps = [...new Set(leftovers.map((l) => l.name))];
    findings.push({
      key: 'tcc-leftover:all', category: 'permissions', severity: 'low',
      title: `${leftovers.length} leftover permissions from apps you removed`,
      summary: leftovers.map((l) => `${l.name}: ${l.label}`).join(', '),
      explanation: `${apps.join(' and ')} ${apps.length === 1 ? 'was' : 'were'} removed, but macOS still lists ${apps.length === 1 ? 'it' : 'them'} as allowed. Harmless now, because the apps are gone; clearing them just keeps the list tidy.`,
      recommendation: `${removeSteps(leftovers[0].label, leftovers[0].name)} Repeat for each one. I can’t do this for you: macOS only lets other apps remove entries for apps that are still installed.`,
      evidence: { items: leftovers },
    });
  }

  const keyloggers = grants.filter((g) => g.service === 'kTCCServiceListenEvent');
  if (keyloggers.length) {
    findings.push({
      key: 'tcc:input-monitoring-summary', category: 'permissions', severity: 'info',
      title: `${plural(keyloggers.length, 'app')} can read your keystrokes`,
      summary: keyloggers.map((g) => g.name ?? g.client).join(', '),
      explanation: SERVICES.kTCCServiceListenEvent.why + ' Keyboard tools (Karabiner, launchers, macro apps) need it legitimately.',
      recommendation: 'Make sure every app in this list is one you use.',
      evidence: { clients: keyloggers.map((g) => g.client) },
    });
  }

  putSnapshot('permissions', { at: Date.now(), grants, access: { user: !u.error, system: !s.error }, fullDiskAccess }, s.error ? 'System-wide permissions (screen recording, accessibility, input monitoring) need Full Disk Access.' : null);
  syncFindings('permissions', findings);
}
