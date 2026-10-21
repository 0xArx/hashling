/**
 * Phone check-up: look inside a phone plugged into this Mac with a cable.
 *
 * iPhone and iPad through libimobiledevice and pymobiledevice3 (after the person taps
 * "Trust This Computer"), Android through adb (after they switch on USB debugging).
 * Optional deep check on iPhone: Amnesty International's Mobile Verification Toolkit (MVT)
 * on a local backup. Everything is read-only: it only asks the phone questions, never
 * installs, removes or changes anything, and nothing it reads leaves this Mac.
 *
 * Plugging a phone in is noticed by itself; a check only ever runs when the person presses
 * a button in the dashboard.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, statSync, statfsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { DATA_DIR, ENGINES_DIR, HOME, ROOT } from './config.ts';
import { run } from './lib/exec.ts';
import { bus } from './bus.ts';
import { getSnapshot, putSnapshot, syncFindings, logEvent, type FindingInput, type Severity } from './db.ts';

// ---------- tools ----------
const BREW_DIRS = ['/opt/homebrew/bin', '/usr/local/bin'];
const PY_DIR = join(ENGINES_DIR, 'phonetools');
const PY = join(PY_DIR, 'bin/python');
const PROBE = join(ROOT, 'helpers/phoneprobe.py');
const MVT = join(PY_DIR, 'bin/mvt-ios');
const PAIR_CACHE = join(PY_DIR, 'pairing');
const BACKUPS = join(DATA_DIR, 'phone-backups');
const IOC_CACHE = join(DATA_DIR, 'intel', 'stalkerware-ioc.json');
const IOC_URL = 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml';
const BREW_ENV = { HOMEBREW_NO_AUTO_UPDATE: '1', HOMEBREW_NO_ENV_HINTS: '1', HOMEBREW_NO_INSTALL_CLEANUP: '1', PATH: `/opt/homebrew/bin:/usr/local/bin:${process.env.PATH ?? '/usr/bin:/bin'}` };

const inBrew = (name: string) => BREW_DIRS.map((d) => join(d, name)).find((p) => existsSync(p)) ?? null;
const adbPath = () => [join(HOME, 'Library/Android/sdk/platform-tools/adb'), ...BREW_DIRS.map((d) => join(d, 'adb'))].find((p) => existsSync(p)) ?? null;

export function phoneTools() {
  return {
    ios: Boolean(inBrew('idevice_id') && inBrew('idevicepair') && existsSync(join(PY_DIR, 'bin/pymobiledevice3'))),
    libimobiledevice: Boolean(inBrew('idevice_id')),
    probe: existsSync(join(PY_DIR, 'bin/pymobiledevice3')),
    android: Boolean(adbPath()),
    mvt: existsSync(MVT),
    brew: Boolean(inBrew('brew')),
  };
}

// ---------- what is plugged in ----------
export type PhoneState = 'ready' | 'needs-trust' | 'trust-pending' | 'locked' | 'denied' | 'needs-tools' | 'needs-debugging' | 'needs-allow' | 'offline';
export interface PhoneDevice {
  id: string;
  platform: 'ios' | 'android';
  name: string;
  model: string;
  os: string;
  state: PhoneState;
  /** What the person should do next, in plain words. */
  hint: string;
  pluggedAt: number;
}

interface UsbDevice { name: string; vendor: number; serial: string; ifaces: { cls: number; sub: number; proto: number; name: string }[] }

/** USB devices from the I/O Registry. Works before any phone tool is installed. */
async function usbDevices(): Promise<UsbDevice[]> {
  const r = await run('/usr/sbin/ioreg', ['-r', '-c', 'IOUSBHostDevice', '-l', '-w0'], { timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
  const out: UsbDevice[] = [];
  let dev: UsbDevice | null = null;
  let iface: UsbDevice['ifaces'][number] | null = null;
  const num = (l: string) => Number(l.split('=').pop()?.trim() ?? NaN);
  const str = (l: string) => l.split('=').slice(1).join('=').trim().replace(/^"|"$/g, '');
  for (const line of r.stdout.split('\n')) {
    const node = line.match(/\+-o .*<class (\w+)/);
    if (node) {
      if (node[1] === 'IOUSBHostDevice') { dev = { name: '', vendor: 0, serial: '', ifaces: [] }; out.push(dev); iface = null; }
      else if (node[1] === 'IOUSBHostInterface' && dev) { iface = { cls: -1, sub: -1, proto: -1, name: '' }; dev.ifaces.push(iface); }
      else iface = null;
      continue;
    }
    const k = line.match(/"([^"]+)" = /)?.[1];
    if (!k) continue;
    if (iface) {
      if (k === 'bInterfaceClass') iface.cls = num(line);
      else if (k === 'bInterfaceSubClass') iface.sub = num(line);
      else if (k === 'bInterfaceProtocol') iface.proto = num(line);
      else if (k === 'USB Interface Name') iface.name = str(line);
    } else if (dev) {
      if (k === 'USB Product Name') dev.name = str(line);
      else if (k === 'idVendor') dev.vendor = num(line);
      else if (k === 'USB Serial Number' || k === 'kUSBSerialNumberString') dev.serial ||= str(line);
    }
  }
  return out;
}

const APPLE = 0x05ac;
// Phone makers. Only counted as a phone when it also offers file transfer or adb, so a Samsung SSD is not a phone.
const ANDROID_VENDORS = new Set([0x18d1, 0x04e8, 0x2717, 0x2a70, 0x22b8, 0x12d1, 0x22d9, 0x1004, 0x0fce, 0x0bb4, 0x2d95, 0x17ef, 0x19d2, 0x0b05, 0x1949, 0x2a45, 0x29a9, 0x1ebf]);
const hasAdb = (d: UsbDevice) => d.ifaces.some((i) => i.cls === 255 && i.sub === 66 && i.proto === 1);
const hasFiles = (d: UsbDevice) => d.ifaces.some((i) => i.cls === 6 || /mtp|ptp/i.test(i.name));

/** “Abdul’s iPhone” reads fine on its own; a plain “iPhone” becomes “your iPhone”. */
const yours = (name: string) => (/['’]s\b/.test(name) ? name : `your ${name}`);
const Yours = (name: string) => { const y = yours(name); return y[0].toUpperCase() + y.slice(1); };

const devices = new Map<string, PhoneDevice>();
const iosChecked = new Map<string, number>();
let lastShape = '';

const announced = new Map<string, number>();

function setDevice(d: PhoneDevice): void {
  const prev = devices.get(d.id);
  devices.set(d.id, { ...d, pluggedAt: prev?.pluggedAt ?? d.pluggedAt });
  // A phone can first show up under its USB name, then under its real id: say it once.
  const said = announced.get(d.platform);
  if (!prev && !(said && Date.now() - said < 120_000)) {
    announced.set(d.platform, Date.now());
    logEvent('phone', 'info', `${Yours(d.name)} is plugged in. I can check it for you in Phone check-up.`, { platform: d.platform });
  }
}

/** ideviceinfo's plain "Key: value" lines (its XML holds binary fields that JSON can't carry). */
function infoLines(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of text.matchAll(/^(\w+): (.*)$/gm)) out[m[1]] = m[2].trim();
  return out;
}

const IOS_HINT: Record<string, string> = {
  'needs-trust': 'Unlock your phone, then press Ask my phone to trust this Mac and tap Trust on the phone.',
  'trust-pending': 'Look at your phone: tap Trust, then enter your passcode.',
  locked: 'Unlock your phone (Face ID or passcode) so it can answer.',
  denied: 'The phone said Don’t Trust. Unplug it, plug it back in and try again.',
  'needs-tools': 'I need two free, open-source tools to talk to iPhones. Press Get the tools.',
  ready: 'Ready. Press Check my phone.',
};

async function refreshIos(udid: string, now: number): Promise<void> {
  const prev = devices.get(udid);
  // Ready phones stay ready until unplugged; others are re-checked every few seconds.
  if (prev?.state === 'ready') return;
  if (prev && now - (iosChecked.get(udid) ?? 0) < (prev.state === 'trust-pending' ? 3000 : 8000)) return;
  iosChecked.set(udid, now);
  const info = infoLines((await run(inBrew('ideviceinfo')!, ['-s', '-u', udid], { timeout: 8000 })).stdout);
  const cls = String(info.DeviceClass ?? 'iPhone');
  const name = String(info.DeviceName ?? '') || cls;
  let state: PhoneState;
  if (prev?.state === 'trust-pending') {
    // After "Trust" is tapped, pairing has to be asked again to finish.
    const p = await run(inBrew('idevicepair')!, ['-u', udid, 'pair'], { timeout: 15_000 });
    const out = p.stdout + p.stderr;
    state = p.ok ? 'ready' : /denied/i.test(out) ? 'denied' : /passcode|locked/i.test(out) ? 'trust-pending' : 'trust-pending';
  } else {
    const v = await run(inBrew('idevicepair')!, ['-u', udid, 'validate'], { timeout: 8000 });
    const out = v.stdout + v.stderr;
    state = v.ok ? 'ready' : /passcode|locked/i.test(out) ? 'locked' : 'needs-trust';
  }
  if (state === 'ready' && !phoneTools().probe) state = 'needs-tools';
  setDevice({ id: udid, platform: 'ios', name, model: modelName(String(info.ProductType ?? ''), cls), os: info.ProductVersion ? `${cls === 'iPad' ? 'iPadOS' : 'iOS'} ${info.ProductVersion}` : '', state, hint: IOS_HINT[state] ?? '', pluggedAt: now });
}

const ANDROID_HINT: Record<string, string> = {
  'needs-debugging': 'Turn on USB debugging on the phone (steps below), then pick File transfer when it asks how to use USB.',
  'needs-allow': 'Look at your phone: tap Allow on “Allow USB debugging?”.',
  'needs-tools': 'I need Google’s free adb tool to talk to Android phones. Press Get the tools.',
  offline: 'The phone stopped answering. Unplug it and plug it back in.',
  ready: 'Ready. Press Check my phone.',
};

/** Called every few seconds by the scheduler. Cheap when nothing is plugged in: one ioreg call. */
export async function watchPhones(): Promise<void> {
  const now = Date.now();
  const usb = await usbDevices();
  const present = new Set<string>();
  const applePhones = usb.filter((d) => d.vendor === APPLE && /iphone|ipad|ipod/i.test(d.name));
  if (applePhones.length) {
    if (inBrew('idevice_id') && inBrew('idevicepair') && inBrew('ideviceinfo')) {
      const ids = (await run(inBrew('idevice_id')!, ['-l'], { timeout: 5000 })).stdout.split('\n').map((s) => s.trim()).filter(Boolean);
      for (const udid of ids) { present.add(udid); await refreshIos(udid, now); }
      // Seen on USB but not by the phone service yet (it can take a moment after plugging in).
      if (!ids.length) for (const d of applePhones) { const id = `usb-${d.serial || d.name}`; present.add(id); setDevice({ id, platform: 'ios', name: d.name, model: d.name, os: '', state: 'locked', hint: 'Unlock your phone so this Mac can see it.', pluggedAt: now }); }
    } else {
      for (const d of applePhones) { const id = `usb-${d.serial || d.name}`; present.add(id); setDevice({ id, platform: 'ios', name: d.name, model: d.name, os: '', state: 'needs-tools', hint: IOS_HINT['needs-tools'], pluggedAt: now }); }
    }
  }
  const androids = usb.filter((d) => hasAdb(d) || (ANDROID_VENDORS.has(d.vendor) && hasFiles(d)));
  if (androids.length) {
    const adb = adbPath();
    const listed = new Map<string, { state: string; model: string }>();
    if (adb && androids.some(hasAdb)) {
      const r = await run(adb, ['devices', '-l'], { timeout: 10_000 });
      for (const line of r.stdout.split('\n').slice(1)) {
        const m = line.match(/^(\S+)\s+(device|unauthorized|offline|authorizing)\b(.*)$/);
        if (m) listed.set(m[1], { state: m[2], model: (m[3].match(/model:(\S+)/)?.[1] ?? '').replace(/_/g, ' ') });
      }
    }
    for (const d of androids) {
      const serial = d.serial || d.name;
      // adb names a phone by its USB serial; with a single phone plugged in, take adb's word for it.
      const id = listed.has(serial) ? serial : listed.size === 1 && androids.length === 1 ? [...listed.keys()][0] : serial;
      const a = listed.get(id);
      present.add(id);
      const prev = devices.get(id);
      const state: PhoneState = !adb ? 'needs-tools' : !hasAdb(d) ? 'needs-debugging' : !a ? 'needs-allow' : a.state === 'device' ? 'ready' : a.state === 'offline' ? 'offline' : 'needs-allow';
      setDevice({ id, platform: 'android', name: prev?.name && prev.name !== d.name ? prev.name : (a?.model || d.name || 'Android phone'), model: a?.model || d.name, os: prev?.os ?? '', state, hint: ANDROID_HINT[state] ?? '', pluggedAt: now });
    }
  }
  for (const id of [...devices.keys()]) if (!present.has(id)) { devices.delete(id); iosChecked.delete(id); }
  const shape = JSON.stringify([...devices.values()].map((d) => [d.id, d.state, d.name, d.os]));
  if (shape !== lastShape) { lastShape = shape; bus.emit('change', { type: 'phonecheck' }); }
}

/** Ask the iPhone to show "Trust This Computer?". The person's tap is what pairs it. */
export async function askToTrust(id: string): Promise<{ ok: boolean; message: string }> {
  const d = devices.get(id);
  if (!d || d.platform !== 'ios') return { ok: false, message: 'I don’t see that iPhone any more. Plug it in again.' };
  const pair = inBrew('idevicepair');
  if (!pair) return { ok: false, message: 'I need the iPhone tools first. Press Get the tools.' };
  const r = await run(pair, ['-u', id, 'pair'], { timeout: 15_000 });
  const out = r.stdout + r.stderr;
  if (r.ok) { setDevice({ ...d, state: phoneTools().probe ? 'ready' : 'needs-tools', hint: IOS_HINT.ready }); bus.emit('change', { type: 'phonecheck' }); return { ok: true, message: 'Your phone trusts this Mac now.' }; }
  if (/passcode|locked/i.test(out) && !/dialog/i.test(out)) return { ok: false, message: 'Unlock your phone first, then try again.' };
  setDevice({ ...d, state: 'trust-pending', hint: IOS_HINT['trust-pending'] });
  iosChecked.set(id, Date.now());
  bus.emit('change', { type: 'phonecheck' });
  return { ok: true, message: 'Look at your phone and tap Trust.' };
}

// ---------- jobs (one at a time) ----------
export interface Job { kind: 'install' | 'check' | 'deep'; what: string; deviceId?: string; step: number; total: number; label: string; pct?: number; startedAt: number }
let job: Job | null = null;
let lastError: { at: number; kind: string; message: string } | null = null;

function setStep(step: number, label: string, pct?: number): void {
  if (!job) return;
  job.step = step; job.label = label; job.pct = pct;
  bus.emit('change', { type: 'phonecheck' });
}

function begin(j: Omit<Job, 'startedAt' | 'step' | 'label'>, fn: () => Promise<void>): { ok: true } | { error: string } {
  if (job) return { error: 'I’m already busy with your phone. Wait for that to finish.' };
  job = { ...j, step: 0, label: 'Starting', startedAt: Date.now() };
  lastError = null;
  bus.emit('change', { type: 'phonecheck' });
  void fn().catch((e) => {
    lastError = { at: Date.now(), kind: j.kind, message: String((e as Error).message ?? e).slice(0, 400) };
    console.error('[phonecheck]', lastError.message);
  }).finally(() => { job = null; bus.emit('change', { type: 'phonecheck' }); void watchPhones(); });
  return { ok: true };
}

function bestPython(): string | null {
  for (const v of ['3.13', '3.12', '3.14', '3.11']) { const p = inBrew(`python${v}`); if (p) return p; }
  return null;
}

async function must(r: Promise<{ ok: boolean; stderr: string; stdout: string }>, what: string): Promise<void> {
  const x = await r;
  if (!x.ok) throw new Error(`${what} did not finish. ${(x.stderr || x.stdout).trim().split('\n').slice(-2).join(' ').slice(0, 240)}`);
}

/** Install the free tools a check needs. Homebrew installs never need the Mac password. */
export function installPhoneTools(kind: 'ios' | 'android' | 'mvt'): { ok: true } | { error: string } {
  const brew = inBrew('brew');
  if (!brew && kind !== 'mvt') return { error: 'I install these with Homebrew, which isn’t on this Mac. Reinstalling Hashling sets it up.' };
  return begin({ kind: 'install', what: kind, total: kind === 'ios' ? 3 : kind === 'mvt' ? 2 : 1 }, async () => {
    if (kind === 'android') {
      setStep(1, 'Getting Google’s adb tool (about 15 MB)');
      if (!adbPath()) await must(run(brew!, ['install', '--cask', 'android-platform-tools'], { timeout: 600_000, env: BREW_ENV }), 'Installing adb');
      return;
    }
    if (kind === 'ios' || !existsSync(PY)) {
      setStep(1, 'Getting libimobiledevice (about 10 MB)');
      if (!inBrew('idevice_id')) await must(run(brew!, ['install', 'libimobiledevice'], { timeout: 900_000, env: BREW_ENV }), 'Installing libimobiledevice');
      let py = bestPython();
      if (!py) { setStep(1, 'Getting Python (about 60 MB)'); await must(run(brew!, ['install', 'python@3.13'], { timeout: 900_000, env: BREW_ENV }), 'Installing Python'); py = bestPython(); }
      if (!py) throw new Error('Python did not install.');
      setStep(2, 'Getting pymobiledevice3 (about 190 MB)');
      if (!existsSync(PY)) await must(run(py, ['-m', 'venv', PY_DIR], { timeout: 120_000 }), 'Setting up Python');
      if (!existsSync(join(PY_DIR, 'bin/pymobiledevice3'))) await must(run(PY, ['-m', 'pip', 'install', '-q', '--disable-pip-version-check', 'pymobiledevice3'], { timeout: 1_200_000 }), 'Installing pymobiledevice3');
    }
    if (kind === 'mvt') {
      setStep(1, 'Getting MVT from Amnesty International (about 75 MB)');
      if (!existsSync(MVT)) await must(run(PY, ['-m', 'pip', 'install', '-q', '--disable-pip-version-check', 'mvt'], { timeout: 1_200_000 }), 'Installing MVT');
      setStep(2, 'Downloading the latest spyware indicators');
      await must(run(MVT, ['--disable-update-check', 'download-iocs'], { timeout: 300_000 }), 'Downloading indicators');
    } else setStep(3, 'Done');
  });
}

// ---------- reports ----------
export interface CheckItem { id: string; status: 'ok' | 'warn' | 'bad' | 'info'; title: string; detail: string; fix?: string; list?: { name: string; note: string; flag?: 'warn' | 'bad' }[] }
export interface PhoneReport {
  id: string;
  platform: 'ios' | 'android';
  name: string;
  model: string;
  os: string;
  checkedAt: number;
  verdict: 'clear' | 'look' | 'worry';
  headline: string;
  items: CheckItem[];
  counts: Record<string, number>;
  /** Space a deep check needs, and whether the phone's backups are encrypted (iPhone only). */
  deep?: { usedBytes: number | null; encrypted: boolean | null; result?: DeepResult };
  notes: string[];
  /** At a glance: numbers shown above the checks. */
  facts?: { storageUsed?: number; storageTotal?: number; lastBackup?: number | null; backupOn?: boolean; apps?: number };
}
export interface DeepResult { at: number; detections: number; modules: { module: string; count: number }[]; checked: string[]; error?: string }

const reports = (): Record<string, PhoneReport> => getSnapshot<{ reports: Record<string, PhoneReport> }>('phoneReports')?.data?.reports ?? {};
function saveReport(r: PhoneReport): void {
  const all = reports();
  all[r.id] = r;
  // Keep the five most recent phones.
  const keep = Object.values(all).sort((a, b) => b.checkedAt - a.checkedAt).slice(0, 5);
  putSnapshot('phoneReports', { reports: Object.fromEntries(keep.map((x) => [x.id, x])) });
}

export function forgetReport(id: string): boolean {
  const all = reports();
  if (!all[id]) return false;
  delete all[id];
  putSnapshot('phoneReports', { reports: all });
  syncFindings('phone', [], `phone:${short(id)}:`);
  return true;
}

const short = (id: string) => createHash('sha256').update(id).digest('hex').slice(0, 10);

function verdictOf(items: CheckItem[]): { verdict: PhoneReport['verdict']; headline: string } {
  const bad = items.filter((i) => i.status === 'bad').length;
  const warn = items.filter((i) => i.status === 'warn').length;
  if (bad) return { verdict: 'worry', headline: bad === 1 ? 'I found one thing that worries me' : `I found ${bad} things that worry me` };
  if (warn) return { verdict: 'look', headline: warn === 1 ? 'Mostly fine. One thing is worth a look' : `Mostly fine. ${warn} things are worth a look` };
  return { verdict: 'clear', headline: 'I didn’t find anything worrying' };
}

/** Each warning becomes a normal Hashling finding, so it shows up in Findings and Ask Hashling. */
function toFindings(r: PhoneReport, tierOf: (i: CheckItem) => 'sus' | 'risk' | 'tip'): void {
  const sevOf = (i: CheckItem): Severity => (i.status === 'bad' ? (tierOf(i) === 'sus' ? 'high' : 'medium') : tierOf(i) === 'tip' ? 'low' : 'medium');
  const inputs: FindingInput[] = r.items.filter((i) => i.status === 'warn' || i.status === 'bad').map((i) => ({
    key: `phone:${short(r.id)}:${tierOf(i)}:${i.id}`,
    category: 'phone',
    severity: sevOf(i),
    title: `${r.name}: ${i.title}`,
    summary: i.detail,
    explanation: `I found this when I checked your ${r.platform === 'ios' ? 'iPhone' : 'Android phone'} over the USB cable on ${new Date(r.checkedAt).toLocaleString()}. The phone itself has to be fixed on the phone; nothing on this Mac changes.`,
    recommendation: i.fix ?? '',
    evidence: { phone: r.name, model: r.model, os: r.os, checkedAt: r.checkedAt, items: i.list?.slice(0, 40) ?? [] },
  }));
  syncFindings('phone', inputs, `phone:${short(r.id)}:`);
}

// ---------- stalkerware indicators (Echap, open data) ----------
interface Ioc { name: string; packages: string[] }
async function stalkerwareList(): Promise<{ list: Ioc[]; fresh: boolean }> {
  let cached: Ioc[] | null = null;
  try { cached = JSON.parse(readFileSync(IOC_CACHE, 'utf8')); } catch { /* not yet */ }
  if (cached && Date.now() - statSync(IOC_CACHE).mtimeMs < 7 * 86_400_000) return { list: cached, fresh: true };
  try {
    const res = await fetch(IOC_URL, { signal: AbortSignal.timeout(20_000), headers: { 'user-agent': 'Hashling (local Mac security; github.com/0xArx/hashling)' } });
    if (!res.ok) throw new Error(String(res.status));
    const list = parseIocYaml(await res.text());
    if (list.length < 20) throw new Error('short list');
    mkdirSync(join(DATA_DIR, 'intel'), { recursive: true });
    writeFileSync(IOC_CACHE, JSON.stringify(list));
    return { list, fresh: true };
  } catch {
    return { list: cached ?? [], fresh: false };
  }
}

/** Just enough YAML for ioc.yaml: "- name:" entries with a "packages:" list. */
export function parseIocYaml(text: string): Ioc[] {
  const out: Ioc[] = [];
  let cur: Ioc | null = null;
  let inPackages = false;
  for (const line of text.split('\n')) {
    const top = line.match(/^- name:\s*(.+)$/);
    if (top) { cur = { name: top[1].trim().replace(/^['"]|['"]$/g, ''), packages: [] }; out.push(cur); inPackages = false; continue; }
    const key = line.match(/^ {2}(\w+):/);
    if (key) { inPackages = key[1] === 'packages'; continue; }
    const item = line.match(/^ {2}- (.+)$/);
    if (inPackages && item && cur) cur.packages.push(item[1].trim().replace(/^['"]|['"]$/g, ''));
  }
  return out.filter((i) => i.packages.length);
}

const matchIoc = (list: Ioc[], id: string) => list.find((i) => i.packages.includes(id));

// ---------- iPhone ----------
const IPHONES: Record<string, string> = {
  'iPhone12,1': 'iPhone 11', 'iPhone12,3': 'iPhone 11 Pro', 'iPhone12,5': 'iPhone 11 Pro Max', 'iPhone12,8': 'iPhone SE (2nd generation)',
  'iPhone13,1': 'iPhone 12 mini', 'iPhone13,2': 'iPhone 12', 'iPhone13,3': 'iPhone 12 Pro', 'iPhone13,4': 'iPhone 12 Pro Max',
  'iPhone14,4': 'iPhone 13 mini', 'iPhone14,5': 'iPhone 13', 'iPhone14,2': 'iPhone 13 Pro', 'iPhone14,3': 'iPhone 13 Pro Max', 'iPhone14,6': 'iPhone SE (3rd generation)',
  'iPhone14,7': 'iPhone 14', 'iPhone14,8': 'iPhone 14 Plus', 'iPhone15,2': 'iPhone 14 Pro', 'iPhone15,3': 'iPhone 14 Pro Max',
  'iPhone15,4': 'iPhone 15', 'iPhone15,5': 'iPhone 15 Plus', 'iPhone16,1': 'iPhone 15 Pro', 'iPhone16,2': 'iPhone 15 Pro Max',
  'iPhone17,3': 'iPhone 16', 'iPhone17,4': 'iPhone 16 Plus', 'iPhone17,1': 'iPhone 16 Pro', 'iPhone17,2': 'iPhone 16 Pro Max', 'iPhone17,5': 'iPhone 16e',
  'iPhone18,3': 'iPhone 17', 'iPhone18,1': 'iPhone 17 Pro', 'iPhone18,2': 'iPhone 17 Pro Max', 'iPhone18,4': 'iPhone Air',
};
const modelName = (type: string, cls: string) => IPHONES[type] ?? (type ? `${cls} (${type})` : cls);

const vparts = (v: string) => v.split('.').map((n) => Number(n) || 0);
const vcmp = (a: string, b: string) => { const x = vparts(a), y = vparts(b); for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0); return 0; };

/** Apple's public software catalog (the one iPhones use), cached for 12 hours. Sends nothing about the phone. */
async function iosReleases(): Promise<{ version: string; devices: string[] }[] | null> {
  const s = getSnapshot<{ assets: { version: string; devices: string[] }[] }>('iosReleases');
  if (s && Date.now() - s.updated_at < 12 * 3600_000) return s.data.assets;
  try {
    const j = await (await fetch('https://gdmf.apple.com/v2/pmv', { signal: AbortSignal.timeout(15_000) })).json() as { PublicAssetSets?: { iOS?: { ProductVersion: string; SupportedDevices: string[] }[] } };
    const assets = (j.PublicAssetSets?.iOS ?? []).map((a) => ({ version: a.ProductVersion, devices: a.SupportedDevices }));
    if (assets.length) putSnapshot('iosReleases', { assets });
    return assets;
  } catch { return s?.data.assets ?? null; }
}

const APP_STORE = 'Apple iPhone OS Application Signing';
/** Sold as "monitoring" but made to watch another adult's phone in secret. */
const SPY_NAMES = /\b(mspy|flexispy|eyezy|spyic|hoverwatch|cocospy|xnspy|umobix|spyzie|kidsguard|thetruthspy|spyhide|highster|clevguard|minspy|spyera)\b/i;
/** Family safety and location-sharing apps: fine when you chose them, and a favourite of stalkers because they look harmless. */
const WATCH_NAMES = /life360|find ?my ?kids|findmykids|qustodio|famisafe|norton ?family|familysafety|safe ?kids|safekids|isharing|glympse|geozilla|ourpact|mobicip|familytime|\bbark\b|family ?link|familylink|mmguardian|net ?nanny|zoemob|covenant ?eyes|covenanteyes|truple|kidslox|screentimelabs/i;
const appleSeconds = (v: unknown) => (typeof v === 'number' ? (v + 978_307_200) * 1000 : typeof v === 'string' && Date.parse(v) ? Date.parse(v) : null);
const MDM_WORDS = /\b(mdm|management|managed|enrol?l|intune|jamf|airwatch|workspace ?one|mobileiron|ivanti|kandji|mosyle|hexnode|meraki|manageengine|addigy|miradore|scalefusion|simplemdm|filewave|cisco)\b/i;

interface Probe {
  fatal?: string;
  errors?: Record<string, string>;
  device?: Record<string, unknown>;
  apps?: Record<string, unknown>[];
  profiles?: { ProfileMetadata?: Record<string, Record<string, unknown>>; ProfileManifest?: Record<string, { IsActive?: boolean; Description?: string }>; OrderedIdentifiers?: string[] };
  cloud?: Record<string, unknown> | null;
  provisioning?: { name: string; team: string; app: string; expires: string; allDevices: boolean; devices: number; getTaskAllow: boolean; betaReports: boolean }[];
}

export function evaluateIos(id: string, p: Probe, releases: { version: string; devices: string[] }[] | null, iocs: Ioc[]): PhoneReport {
  const d = p.device ?? {};
  const cls = String(d.DeviceClass ?? 'iPhone');
  const osName = cls === 'iPad' ? 'iPadOS' : 'iOS';
  const version = String(d.ProductVersion ?? '');
  const type = String(d.ProductType ?? '');
  const items: CheckItem[] = [];
  const notes: string[] = [];

  // 1. Software
  const forModel = (releases ?? []).filter((a) => a.devices.includes(type)).map((a) => a.version);
  if (version && forModel.length) {
    const newest = forModel.sort(vcmp).at(-1)!;
    const sameMajor = forModel.filter((v) => vparts(v)[0] === vparts(version)[0]).sort(vcmp).at(-1);
    if (sameMajor && vcmp(version, sameMajor) < 0) items.push({ id: 'os-update', status: 'warn', title: `A security update is waiting (${osName} ${sameMajor})`, detail: `Your ${cls} has ${osName} ${version}. Updates fix security holes that spyware uses, so this one matters.`, fix: 'On the phone: Settings > General > Software Update, then Update Now.' });
    else if (vcmp(version, newest) < 0) items.push({ id: 'os-major', status: 'info', title: `${osName} ${newest} is available`, detail: `You have ${osName} ${version}, which still gets security fixes. Moving to ${newest} gets you the newest protections.`, fix: 'When you are ready: Settings > General > Software Update.' });
    else items.push({ id: 'os', status: 'ok', title: `${osName} ${version} is up to date`, detail: `This is the newest ${osName} for your ${modelName(type, cls)}.` });
  } else if (version) {
    items.push({ id: 'os', status: 'info', title: `${osName} ${version}`, detail: 'I couldn’t reach Apple’s update list just now, so I can’t say if it is the newest. Check in Settings > General > Software Update.' });
  }

  // 2. Passcode. Only a "yes" is trusted: recent iOS reports "no passcode" over the cable even when one is set.
  if (d.PasswordProtected === true) items.push({ id: 'passcode', status: 'ok', title: 'Your phone has a passcode', detail: 'Good. Someone holding your phone can’t open it without it.' });

  // 3. Apps
  const apps = (p.apps ?? []).filter((a) => a.ApplicationType === 'User' || !a.ApplicationType);
  const appName = (a: Record<string, unknown>) => String(a.CFBundleDisplayName || a.CFBundleName || a.CFBundleIdentifier);
  const enterprise: CheckItem['list'] = [], developer: CheckItem['list'] = [], beta: CheckItem['list'] = [], known: CheckItem['list'] = [];
  const enterpriseTeams = new Set((p.provisioning ?? []).filter((x) => x.allDevices).map((x) => x.team));
  for (const a of apps) {
    const signer = String(a.SignerIdentity ?? '');
    const bundle = String(a.CFBundleIdentifier ?? '');
    const hit = matchIoc(iocs, bundle);
    if (hit) known!.push({ name: appName(a), note: `Matches known stalkerware: ${hit.name} (${bundle})`, flag: 'bad' });
    else if (SPY_NAMES.test(`${appName(a)} ${bundle}`)) known!.push({ name: appName(a), note: 'A spying app sold for watching someone else’s phone', flag: 'bad' });
    if (!signer || signer === APP_STORE) continue;
    // TestFlight betas are signed by Apple and come through Apple's own beta service.
    if (/TestFlight/i.test(signer)) { beta!.push({ name: appName(a), note: 'Beta from TestFlight' }); continue; }
    const who = signer.replace(/^(iPhone|Apple) (Distribution|Developer|Development):\s*/, '').replace(/\s*\([A-Z0-9]{10}\)$/, '');
    if (/Distribution/.test(signer)) enterprise!.push({ name: appName(a), note: `Signed by ${who}${enterpriseTeams.has(who) ? ', with a company certificate that works on any iPhone' : ''}`, flag: 'warn' });
    else developer!.push({ name: appName(a), note: `Signed by ${who} (a developer certificate)` });
  }
  if (known!.length) items.push({ id: 'stalkerware', status: 'bad', title: known!.length === 1 ? 'An app matches known stalkerware' : `${known!.length} apps match known stalkerware`, detail: 'Stalkerware secretly sends your messages, location and photos to someone else. If you did not install it, someone may be watching you.', fix: 'If you feel unsafe, talk to someone you trust or a domestic abuse helpline before removing it: the person may notice. Then delete the app and change your Apple Account password from a device they never touched.', list: known });
  if (enterprise!.length) items.push({ id: 'enterprise-apps', status: 'warn', title: enterprise!.length === 1 ? 'An app came from outside the App Store' : `${enterprise!.length} apps came from outside the App Store`, detail: 'These use a company certificate instead of the App Store. Work apps do this, but so do spy apps and fake “free” versions of paid apps. Apple did not review them.', fix: 'If you don’t know an app or the company named, delete it. Then check Settings > General > VPN & Device Management and remove the company you don’t know.', list: enterprise });
  if (developer!.length) items.push({ id: 'developer-apps', status: 'info', title: developer!.length === 1 ? 'One app was installed from a Mac' : `${developer!.length} apps were installed from a Mac`, detail: 'They are signed with a developer certificate, which happens when you build an app yourself or use a sideloading tool. If that is you, this is normal.', fix: 'If you don’t recognise one, delete it.', list: developer });
  if (!known!.length && !enterprise!.length && apps.length) items.push({ id: 'apps', status: 'ok', title: `All ${apps.length - developer!.length} apps came from Apple`, detail: beta!.length ? `${apps.length - developer!.length - beta!.length} from the App Store and ${beta!.length} test versions from Apple’s TestFlight. None came from a company certificate or a sideloading tool.` : 'Every one came from the App Store, which Apple reviews.', list: beta!.length ? beta : undefined });
  if (p.errors?.apps) notes.push('I couldn’t read the list of apps this time.');

  // 4. Configuration profiles
  const meta = p.profiles?.ProfileMetadata ?? {};
  const ids = Object.keys(meta);
  const cloud = p.cloud ?? null;
  const supervised = Boolean(cloud?.IsSupervised);
  const org = String(cloud?.OrganizationName ?? '');
  const profList: CheckItem['list'] = ids.map((pid) => {
    const m = meta[pid];
    const name = String(m.PayloadDisplayName ?? pid);
    const by = String(m.PayloadOrganization ?? '');
    const text = `${pid} ${name} ${by} ${m.PayloadDescription ?? ''}`;
    const beta = /beta software profile|seed|applebeta/i.test(text);
    const kind = MDM_WORDS.test(text) ? 'Remote management (MDM)' : /vpn/i.test(text) ? 'VPN' : /\b(root|ca|certificate|cert|ssl|trust)\b/i.test(text) ? 'Certificate (can read your secure web traffic if trusted)' : /proxy/i.test(text) ? 'Web proxy' : beta ? 'Apple beta updates' : 'Settings profile';
    return { name, note: `${kind}${by ? `, from ${by}` : ''}${m.PayloadRemovalDisallowed ? ', can’t be removed by you' : ''}`, flag: beta ? undefined : kind.startsWith('Remote') || kind.startsWith('Certificate') || kind === 'Web proxy' || m.PayloadRemovalDisallowed ? 'bad' as const : 'warn' as const };
  });
  const serious = profList.filter((x) => x.flag === 'bad').length;
  const plainProfiles = profList.filter((x) => x.flag);
  if (!ids.length && !p.errors?.profiles) items.push({ id: 'profiles', status: 'ok', title: 'No configuration profiles', detail: 'Nobody has added hidden settings, certificates or management to this phone.' });
  else if (plainProfiles.length) items.push({ id: 'profiles', status: serious && !supervised && !org ? 'bad' : 'warn', title: plainProfiles.length === 1 ? 'A configuration profile is installed' : `${plainProfiles.length} configuration profiles are installed`, detail: 'Profiles can route your traffic through someone else, trust their certificates, or hand control of the phone to a company. Normal on a work or school phone; on a personal phone, only keep ones you added yourself.', fix: 'On the phone: Settings > General > VPN & Device Management. Tap a profile you don’t recognise, then Remove Profile.', list: profList });
  else if (ids.length) items.push({ id: 'profiles', status: 'info', title: 'Only Apple beta profiles', detail: 'These just let your phone get Apple’s test versions of iOS.', list: profList });
  if (p.errors?.profiles) notes.push('I couldn’t read the configuration profiles this time.');

  // 5. Supervision and management
  if (supervised || org) items.push({ id: 'managed', status: supervised && !org ? 'bad' : 'warn', title: org ? `Your phone is managed by ${org}` : 'Your phone is supervised', detail: supervised ? 'Supervision gives whoever set it up deep control: they can install apps silently, restrict settings and see a lot about the phone. Normal for a work or school phone. On a personal phone it is a serious warning sign.' : 'An organisation set this phone up through Apple’s business enrollment.', fix: 'If this is your own phone and you don’t know why, back up your photos, then erase it: Settings > General > Transfer or Reset iPhone > Erase All Content and Settings.' });
  else if (!p.errors?.cloud) items.push({ id: 'managed', status: 'ok', title: 'Not managed by anyone else', detail: 'No company or person has remote control of this phone.' });

  // 6. Apps that can follow you or watch the phone (fine when you chose them).
  const watchers = apps.filter((a) => WATCH_NAMES.test(`${appName(a)} ${a.CFBundleIdentifier}`));
  if (watchers.length) items.push({ id: 'watchers', status: 'info', title: watchers.length === 1 ? 'An app can share your location or monitor this phone' : `${watchers.length} apps can share your location or monitor this phone`, detail: 'Family safety and location-sharing apps are fine when you chose them. People who stalk a partner install them too, because they look harmless.', fix: 'Open each one and check who can see you. Delete any you didn’t install yourself.', list: watchers.map((a) => ({ name: appName(a), note: 'Location sharing or monitoring app' })) });

  // 7. Keyboards from apps: with Full Access, a keyboard can see what you type.
  const kbApps = ((d.AppKeyboards as string[] | undefined) ?? []).map((k) => {
    const owner = apps.find((a) => k.startsWith(`${a.CFBundleIdentifier}.`));
    return { k, owner, store: !owner || !owner.SignerIdentity || owner.SignerIdentity === APP_STORE || /TestFlight/i.test(String(owner.SignerIdentity)) };
  });
  if (kbApps.length) items.push({ id: 'keyboards', status: kbApps.some((x) => !x.store) ? 'warn' : 'info', title: kbApps.length === 1 ? `${kbApps[0].owner ? appName(kbApps[0].owner) : 'An app'} adds its own keyboard` : `${kbApps.length} apps add their own keyboard`, detail: 'If you gave a keyboard Full Access, it can see what you type and send it to its maker. Keyboards from outside the App Store are a known way to steal passwords.', fix: 'Settings > General > Keyboard > Keyboards. Remove ones you don’t use, and only allow Full Access for ones you trust.', list: kbApps.map((x) => ({ name: x.owner ? appName(x.owner) : x.k, note: x.store ? 'Keyboard from an App Store app' : 'Keyboard from an app outside the App Store', flag: x.store ? undefined : 'warn' as const })) });

  // 8. Location in the background (only if you chose "Always").
  const bgLoc = apps.filter((a) => ((a.UIBackgroundModes as string[] | undefined) ?? []).includes('location'));
  if (bgLoc.length) items.push({ id: 'bg-location', status: 'info', title: `${bgLoc.length} app${bgLoc.length === 1 ? ' is' : 's are'} able to follow your location in the background`, detail: 'They can only do it if you chose “Always” for them. Worth a look: most apps only need your location while you use them.', fix: 'Settings > Privacy & Security > Location Services. Set apps to While Using the App or Never unless they really need Always.', list: bgLoc.map((a) => ({ name: appName(a), note: 'Can use location in the background if allowed' })) });

  // 9. Developer settings
  if (d.EnableWifiDebugging === true) items.push({ id: 'wifi-debug', status: 'warn', title: 'Wireless debugging is on', detail: 'A Mac that this phone trusts can install apps and debug it over Wi-Fi, without a cable. Turn it off unless you build apps for it.', fix: 'On the Mac: Xcode > Window > Devices and Simulators, select the phone and untick Connect via network.' });
  // Apps from Xcode, or Xcode's own developer profiles, mean someone builds apps on this phone.
  const builds = developer!.length > 0 || (p.provisioning ?? []).some((x) => x.getTaskAllow);
  if (d.DeveloperModeStatus === true) items.push({ id: 'devmode', status: builds ? 'info' : 'warn', title: 'Developer Mode is on', detail: builds ? 'It lets apps from Xcode and sideloading tools run. Fine while you build apps; turn it off when you don’t.' : 'It lets apps from outside the App Store run, and nothing on this phone needs it right now. Someone may have turned it on to install something.', fix: 'Settings > Privacy & Security > Developer Mode, then turn it off and restart.' });

  // 10. iCloud Backup: what you need if you ever have to erase a phone.
  const lastBackup = appleSeconds(d.LastCloudBackupDate);
  const backupDays = lastBackup ? Math.floor((Date.now() - lastBackup) / 86_400_000) : null;
  if (d.CloudBackupEnabled === false) items.push({ id: 'backup', status: 'info', title: 'iCloud Backup is off', detail: 'If you ever lose this phone, or have to erase it to get rid of spyware, your photos and messages could be gone.', fix: 'Settings > your name > iCloud > iCloud Backup, then turn on Back Up This iPhone. Or back it up to this Mac in Finder.' });
  else if (backupDays != null && backupDays > 14) items.push({ id: 'backup', status: 'info', title: `Last iCloud backup was ${backupDays} days ago`, detail: 'Backups run on Wi-Fi while the phone charges and is locked. If you ever have to erase it, you would lose everything since then.', fix: 'Settings > your name > iCloud > iCloud Backup > Back Up Now.' });
  else if (backupDays != null) items.push({ id: 'backup', status: 'ok', title: `Backed up to iCloud ${backupDays === 0 ? 'today' : backupDays === 1 ? 'yesterday' : `${backupDays} days ago`}`, detail: 'If you ever have to erase this phone, your things come back.' });

  // 11. Expiring company certificates without apps are harmless; still list leftovers for experts.
  const leftovers = (p.provisioning ?? []).filter((x) => x.allDevices && !enterprise!.length);
  if (leftovers.length) items.push({ id: 'certs', status: 'info', title: 'Old company app certificates', detail: 'Left behind by apps that were deleted. They do nothing on their own.', list: leftovers.map((x) => ({ name: x.team || x.name, note: `For ${x.app || 'an app'}, expires ${String(x.expires).slice(0, 10)}` })) });

  const used = Number(d.TotalDataCapacity ?? 0) - Number(d.TotalDataAvailable ?? 0);
  const { verdict, headline } = verdictOf(items);
  return {
    id, platform: 'ios', name: String(d.DeviceName ?? cls), model: modelName(type, cls), os: version ? `${osName} ${version}` : osName, checkedAt: Date.now(), verdict, headline, items, notes,
    counts: { apps: apps.length, outsideStore: enterprise!.length + developer!.length, profiles: ids.length },
    deep: { usedBytes: used > 0 ? used : null, encrypted: typeof d.WillEncrypt === 'boolean' ? d.WillEncrypt : null },
    facts: { storageUsed: used > 0 ? used : undefined, storageTotal: Number(d.TotalDataCapacity ?? 0) || undefined, lastBackup, backupOn: typeof d.CloudBackupEnabled === 'boolean' ? d.CloudBackupEnabled : undefined, apps: apps.length },
  };
}

const IOS_TIER = (i: CheckItem): 'sus' | 'risk' | 'tip' => (i.id === 'stalkerware' || i.id === 'mvt' || (i.status === 'bad' && (i.id === 'profiles' || i.id === 'managed')) ? 'sus' : i.id === 'os-major' || i.id === 'devmode' ? 'tip' : 'risk');

async function checkIos(id: string): Promise<void> {
  setStep(1, 'Asking your phone about itself');
  mkdirSync(PAIR_CACHE, { recursive: true });
  const r = await run(PY, ['-I', PROBE, id, PAIR_CACHE], { timeout: 240_000, maxBuffer: 64 * 1024 * 1024 });
  let probe: Probe;
  try { probe = JSON.parse(r.stdout.trim().split('\n').pop() ?? '{}'); } catch { throw new Error(`I couldn’t read the answer from your phone. ${r.stderr.trim().split('\n').pop() ?? ''}`.trim()); }
  if (probe.fatal) throw new Error(/NotPaired|Pair|Trust/i.test(probe.fatal) ? 'Your phone doesn’t trust this Mac yet. Unlock it and tap Trust.' : /Passcode|Locked/i.test(probe.fatal) ? 'Unlock your phone and try again.' : `Your phone didn’t answer: ${probe.fatal}`);
  setStep(2, 'Comparing with Apple’s latest software and known stalkerware');
  const [releases, iocs] = await Promise.all([iosReleases(), stalkerwareList()]);
  const report = evaluateIos(id, probe, releases, iocs.list);
  const prev = reports()[id];
  if (prev?.deep?.result && report.deep) report.deep.result = prev.deep.result;
  if (report.deep?.result) addDeepItem(report);
  saveReport(report);
  toFindings(report, IOS_TIER);
  logEvent('phone', report.verdict === 'worry' ? 'medium' : 'info', `Checked ${yours(report.name)}. ${report.headline}.`, { platform: 'ios' });
}

// ---------- Android ----------
const STORES: Record<string, string> = {
  'com.android.vending': 'Google Play', 'com.sec.android.app.samsungapps': 'Galaxy Store', 'com.huawei.appmarket': 'AppGallery', 'com.xiaomi.market': 'Xiaomi GetApps', 'com.xiaomi.mipicks': 'Xiaomi GetApps',
  'com.amazon.venezia': 'Amazon Appstore', 'com.heytap.market': 'OPPO App Market', 'com.oppo.market': 'OPPO App Market', 'com.bbk.appstore': 'vivo App Store', 'org.fdroid.fdroid': 'F-Droid', 'com.google.android.feedback': 'Google Play',
};
const SIDELOADERS: Record<string, string> = { 'com.google.android.packageinstaller': 'an APK file', 'com.android.packageinstaller': 'an APK file', 'com.android.shell': 'a computer', null: 'somewhere unknown' };
const SENSITIVE: Record<string, string> = {
  'android.permission.CAMERA': 'camera', 'android.permission.RECORD_AUDIO': 'microphone', 'android.permission.ACCESS_FINE_LOCATION': 'exact location', 'android.permission.ACCESS_BACKGROUND_LOCATION': 'location all the time',
  'android.permission.READ_SMS': 'text messages', 'android.permission.RECEIVE_SMS': 'incoming texts', 'android.permission.READ_CALL_LOG': 'call history', 'android.permission.PROCESS_OUTGOING_CALLS': 'outgoing calls',
  'android.permission.READ_CONTACTS': 'contacts', 'android.permission.READ_MEDIA_IMAGES': 'photos', 'android.permission.BODY_SENSORS': 'health sensors',
};
const SPY_PERMS = new Set(['android.permission.READ_SMS', 'android.permission.RECEIVE_SMS', 'android.permission.READ_CALL_LOG', 'android.permission.RECORD_AUDIO', 'android.permission.ACCESS_BACKGROUND_LOCATION', 'android.permission.ACCESS_FINE_LOCATION']);

export interface AndroidRaw {
  props: string;
  packages: string;
  accessibility: string;
  listeners: string;
  policy: string;
  launchers: string;
  perms: string;
  verifier: string;
  su: string;
  /** Newer checks; empty when a phone (or a test) doesn't provide them. */
  installers?: string;
  usage?: string;
  overlays?: string;
  sms?: string;
  vpn?: string;
  keyboards?: string;
  adbWifi?: string;
}

const pkgOfComponent = (c: string) => c.trim().split('/')[0];

export function evaluateAndroid(id: string, raw: AndroidRaw, iocs: Ioc[], today = Date.now()): PhoneReport {
  const props: Record<string, string> = {};
  for (const m of raw.props.matchAll(/^\[([^\]]+)\]: \[([^\]]*)\]/gm)) props[m[1]] = m[2];
  const maker = props['ro.product.manufacturer'] ?? '';
  const model = props['ro.product.marketname'] || props['ro.product.model'] || 'Android phone';
  const name = !maker || model.toLowerCase().includes(maker.toLowerCase()) ? model : `${maker[0].toUpperCase()}${maker.slice(1)} ${model}`;
  const release = props['ro.build.version.release'] ?? '';
  const items: CheckItem[] = [];
  const notes: string[] = [];

  // Third-party apps, where each came from, and whether it shows an icon.
  const apps = new Map<string, { pkg: string; path: string; installer: string }>();
  for (const line of raw.packages.split('\n')) {
    const first = line.trim().split(/\s+/)[0] ?? '';
    if (!first.startsWith('package:')) continue;
    const eq = first.lastIndexOf('=');
    const pkg = first.slice(eq + 1), path = first.slice(8, eq);
    const installer = line.match(/installer=(\S+)/)?.[1] ?? 'null';
    if (pkg) apps.set(pkg, { pkg, path, installer });
  }
  const launchable = new Set([...raw.launchers.matchAll(/^\s*([a-zA-Z][\w.]*)\/[\w.$]+/gm)].map((m) => m[1]));
  const canSeeLaunchers = launchable.size > 0;
  const sideloaded = (a: { path: string; installer: string }) => a.path.startsWith('/data/') && !STORES[a.installer];
  const from = (a: { installer: string }) => STORES[a.installer] ?? SIDELOADERS[a.installer] ?? a.installer;

  // Granted runtime permissions per app.
  const granted = new Map<string, Set<string>>();
  let cur: string | null = null;
  for (const line of raw.perms.split('\n')) {
    const head = line.match(/^ {2}Package \[([^\]]+)\]/);
    if (head) { cur = head[1]; continue; }
    const g = line.match(/^\s+(android\.permission\.[A-Z_]+): granted=true/);
    if (cur && g && apps.has(cur) && SENSITIVE[g[1]]) (granted.get(cur) ?? granted.set(cur, new Set()).get(cur)!).add(g[1]);
  }

  // 1. Security patch
  const patch = props['ro.build.version.security_patch'] ?? '';
  const age = patch ? Math.floor((today - Date.parse(patch)) / 86_400_000) : NaN;
  if (Number.isFinite(age)) {
    const when = new Date(Date.parse(patch)).toLocaleDateString([], { month: 'long', year: 'numeric' });
    if (age > 365) items.push({ id: 'patch', status: 'bad', title: 'Security updates stopped over a year ago', detail: `The last security fix on this phone is from ${when}. Spyware uses holes that have been fixed since then.`, fix: 'Settings > System > Software update (or Settings > Software update). If none is offered, this phone no longer gets fixes: think about replacing it.' });
    else if (age > 90) items.push({ id: 'patch', status: 'warn', title: 'Security updates are behind', detail: `The last security fix is from ${when}, more than three months ago.`, fix: 'Settings > System > Software update, and install anything waiting.' });
    else items.push({ id: 'patch', status: 'ok', title: 'Security updates are recent', detail: `Android ${release}, security fixes from ${when}.` });
  }

  // 2. Known stalkerware
  const known = [...apps.keys()].map((p) => [p, matchIoc(iocs, p)?.name ?? (SPY_NAMES.test(p) ? 'a spying app' : null)] as const).filter(([, h]) => h);
  if (known.length) items.push({ id: 'stalkerware', status: 'bad', title: known.length === 1 ? 'An app matches known stalkerware' : `${known.length} apps match known stalkerware`, detail: 'Stalkerware secretly sends your messages, calls, location and photos to someone else. If you did not install it, someone may be watching you.', fix: 'If you feel unsafe, talk to someone you trust or a domestic abuse helpline first: the person may notice if it stops. Then remove it in Settings > Apps, and change your Google password from a device they never touched.', list: known.map(([p, h]) => ({ name: p, note: `Known as ${h}`, flag: 'bad' as const })) });

  // 3. Apps from outside an app store
  const side = [...apps.values()].filter(sideloaded);
  if (side.length) items.push({ id: 'sideloaded', status: 'warn', title: side.length === 1 ? 'One app came from outside an app store' : `${side.length} apps came from outside an app store`, detail: 'Nobody checked these for malware. Spy apps are almost always installed this way, by someone who had the phone in their hands.', fix: 'Settings > Apps. Remove any you don’t recognise. Then run Play Protect: Play Store > your picture > Play Protect > Scan.', list: side.map((a) => ({ name: a.pkg, note: `Installed from ${from(a)}${canSeeLaunchers && !launchable.has(a.pkg) ? ', and it hides its icon' : ''}`, flag: canSeeLaunchers && !launchable.has(a.pkg) ? 'bad' as const : 'warn' as const })) });
  else items.push({ id: 'sideloaded', status: 'ok', title: `All ${apps.size} apps came from an app store`, detail: 'Every app you installed came through an app store that checks for malware.' });

  // 4. Accessibility: lets an app read the screen and tap for you. The favourite trick of stalkerware and banking trojans.
  const access = raw.accessibility.trim() === 'null' ? [] : raw.accessibility.split(':').map(pkgOfComponent).filter((p) => apps.has(p));
  if (access.length) {
    const worst = access.some((p) => sideloaded(apps.get(p)!) || matchIoc(iocs, p) || (canSeeLaunchers && !launchable.has(p)));
    items.push({ id: 'accessibility', status: worst ? 'bad' : 'warn', title: access.length === 1 ? 'An app can read your screen and tap for you' : `${access.length} apps can read your screen and tap for you`, detail: 'Accessibility access lets an app see everything on screen, including messages and passwords, and press buttons. Password managers and automation apps use it honestly; spy apps and banking malware use it too.', fix: 'Settings > Accessibility > Installed apps (or Downloaded apps). Turn off any you don’t recognise.', list: [...new Set(access)].map((p) => ({ name: p, note: `From ${from(apps.get(p)!)}`, flag: sideloaded(apps.get(p)!) ? 'bad' as const : 'warn' as const })) });
  } else items.push({ id: 'accessibility', status: 'ok', title: 'No app can read your screen', detail: 'None of your apps have accessibility access.' });

  // 5. Device admin and work profile owners
  const policy = raw.policy;
  const admins = new Set<string>();
  const adminBlock = policy.split(/Enabled Device Admins[^\n]*\n/).slice(1).map((b) => b.split(/\n\S|\n\n\s*\n/)[0]).join('\n');
  for (const m of adminBlock.matchAll(/^\s+([a-zA-Z][\w.]*)\/[\w.$]+:?\s*$/gm)) admins.add(m[1]);
  const owners = [...policy.matchAll(/(Device Owner|Profile Owner)[\s\S]{0,300}?ComponentInfo\{([^/}]+)\//g)].map((m) => ({ kind: m[1], pkg: m[2] }));
  const thirdAdmins = [...admins].filter((p) => apps.has(p));
  if (thirdAdmins.length) items.push({ id: 'device-admin', status: thirdAdmins.some((p) => sideloaded(apps.get(p)!) || matchIoc(iocs, p)) ? 'bad' : 'warn', title: thirdAdmins.length === 1 ? 'An app made itself a device admin' : `${thirdAdmins.length} apps made themselves device admins`, detail: 'Device admin apps can lock or wipe the phone and are harder to uninstall. Stalkerware uses this so it can’t be removed.', fix: 'Settings > Security > Device admin apps (or search Settings for “device admin”). Turn off any you don’t recognise, then uninstall them.', list: thirdAdmins.map((p) => ({ name: p, note: `From ${from(apps.get(p)!)}`, flag: 'warn' as const })) });
  else items.push({ id: 'device-admin', status: 'ok', title: 'No unusual device admin apps', detail: 'No app you installed has made itself hard to remove.' });
  if (owners.length) items.push({ id: 'managed', status: 'warn', title: 'Part of this phone is managed by an organisation', detail: 'A company or school manages this phone or a work profile on it. They can see and control what is in it.', fix: 'Normal for a work phone. If it is personal and you didn’t set this up, see Settings > Security > Device admin apps and Settings > Passwords & accounts.', list: owners.map((o) => ({ name: o.pkg, note: o.kind === 'Device Owner' ? 'Manages the whole phone' : 'Manages a work profile' })) });

  // 6. Notification access: reads every message preview.
  const listeners = raw.listeners.trim() === 'null' ? [] : raw.listeners.split(':').map(pkgOfComponent).filter((p) => apps.has(p) && sideloaded(apps.get(p)!));
  if (listeners.length) items.push({ id: 'notifications', status: 'warn', title: 'An app from outside a store reads your notifications', detail: 'It sees every message preview and code that arrives, which is how spy apps read chats.', fix: 'Settings > Notifications > Device & app notifications (or Notification access). Turn it off for apps you don’t know.', list: [...new Set(listeners)].map((p) => ({ name: p, note: `From ${from(apps.get(p)!)}`, flag: 'warn' as const })) });

  // 7. Apps outside a store that can listen, read texts or follow you.
  const spying = side.filter((a) => [...(granted.get(a.pkg) ?? [])].filter((x) => SPY_PERMS.has(x)).length >= 2);
  if (spying.length) items.push({ id: 'spy-permissions', status: 'warn', title: 'Apps from outside a store can watch you', detail: 'These apps can use things like your microphone, texts, call history or location. That is what spy apps ask for.', fix: 'Settings > Security & privacy > Privacy > Permission manager. Remove access you didn’t mean to give, or remove the app.', list: spying.map((a) => ({ name: a.pkg, note: [...(granted.get(a.pkg) ?? [])].map((x) => SENSITIVE[x]).join(', '), flag: 'warn' as const })) });
  const perApp = [...granted.entries()].filter(([, s]) => s.size).map(([p, s]) => ({ name: p, note: [...s].map((x) => SENSITIVE[x]).join(', ') })).sort((a, b) => b.note.length - a.note.length);
  if (perApp.length) items.push({ id: 'permissions', status: 'info', title: `${perApp.length} apps can use your camera, microphone, location or messages`, detail: 'For your own review. Most are normal (a camera app needs the camera). Look for ones that don’t need what they have.', list: perApp.slice(0, 40) });

  // 8. Play Protect
  const ver: Record<string, string> = {};
  for (const m of raw.verifier.matchAll(/^(\w+)=(.*)$/gm)) ver[m[1]] = m[2].trim();
  if (ver.package_verifier_user_consent === '-1' || ver.package_verifier_enable === '0') items.push({ id: 'play-protect', status: 'bad', title: 'Play Protect looks switched off', detail: 'Play Protect scans apps for malware. Stalkerware instructions tell people to turn it off first.', fix: 'Play Store > your picture > Play Protect > settings (gear) > turn on Scan apps with Play Protect.' });

  // 9. Lists of packages Android grants special powers to.
  const pkgList = (t = '') => [...new Set([...t.matchAll(/^\s*([a-zA-Z][\w]*(?:\.[\w]+)+)\s*$/gm)].map((m) => m[1]))].filter((p) => apps.has(p));
  const components = (t = '') => (t.trim() === 'null' ? [] : [...new Set(t.split(':').map(pkgOfComponent).filter((p) => apps.has(p)))]);
  const note = (p: string) => `From ${from(apps.get(p)!)}`;

  // Texting app: whoever it is reads every text, including login codes.
  const sms = (raw.sms ?? '').trim();
  if (apps.has(sms) && sideloaded(apps.get(sms)!)) items.push({ id: 'sms-app', status: 'bad', title: 'Your texting app came from outside an app store', detail: 'The default texting app sees every text you get, including login codes from your bank. Spy apps try to become it.', fix: 'Settings > Apps > Default apps > SMS app, and pick Messages. Then remove the other app if you don’t know it.', list: [{ name: sms, note: note(sms), flag: 'bad' }] });

  // Apps allowed to install other apps.
  const installers = pkgList(raw.installers).filter((p) => !STORES[p]);
  if (installers.length) items.push({ id: 'installers', status: installers.some((p) => sideloaded(apps.get(p)!)) ? 'warn' : 'info', title: installers.length === 1 ? 'An app is allowed to install other apps' : `${installers.length} apps are allowed to install other apps`, detail: 'This is how apps from outside the Play Store get onto a phone. Browsers and file managers ask for it; turn it off once you’re done with it.', fix: 'Settings > Apps > Special app access > Install unknown apps. Turn it off for each app.', list: installers.map((p) => ({ name: p, note: note(p), flag: sideloaded(apps.get(p)!) ? 'warn' as const : undefined })) });

  // Usage access and drawing over other apps, from apps outside a store: how spy and banking malware watch and trick you.
  const usage = pkgList(raw.usage).filter((p) => sideloaded(apps.get(p)!));
  const overlays = pkgList(raw.overlays).filter((p) => sideloaded(apps.get(p)!));
  if (usage.length || overlays.length) items.push({ id: 'special-access', status: 'warn', title: 'Apps from outside a store have special access', detail: 'Usage access shows an app everything you open and when. Drawing over other apps lets it put fake screens on top of your bank or email to steal passwords.', fix: 'Settings > Apps > Special app access. Check Usage access and Display over other apps, and turn them off for apps you don’t know.', list: [...usage.map((p) => ({ name: p, note: 'Can see which apps you use', flag: 'warn' as const })), ...overlays.map((p) => ({ name: p, note: 'Can draw over other apps', flag: 'warn' as const }))] });

  // Keyboards from apps.
  const kbs = components(raw.keyboards);
  if (kbs.length) items.push({ id: 'keyboards', status: kbs.some((p) => sideloaded(apps.get(p)!)) ? 'warn' : 'info', title: kbs.length === 1 ? 'An app adds its own keyboard' : `${kbs.length} apps add their own keyboard`, detail: 'A keyboard sees everything you type, including passwords. Keyboards from outside an app store are a known way to steal them.', fix: 'Settings > System > Keyboard > On-screen keyboard (or Languages & input). Turn off ones you don’t use.', list: kbs.map((p) => ({ name: p, note: note(p), flag: sideloaded(apps.get(p)!) ? 'warn' as const : undefined })) });

  // Always-on VPN: all traffic goes through that app.
  const vpn = (raw.vpn ?? '').trim();
  if (apps.has(vpn)) items.push({ id: 'vpn', status: sideloaded(apps.get(vpn)!) ? 'warn' : 'info', title: 'All your internet goes through a VPN app', detail: `${vpn} is set as an always-on VPN, so it can see where your phone connects. Fine if you chose it.`, fix: 'Settings > Network & internet > VPN. Remove it if you don’t know it.', list: [{ name: vpn, note: note(vpn) }] });

  // Family safety and location-sharing apps.
  const watchers = [...apps.keys()].filter((p) => WATCH_NAMES.test(p));
  if (watchers.length) items.push({ id: 'watchers', status: 'info', title: watchers.length === 1 ? 'An app can share your location or monitor this phone' : `${watchers.length} apps can share your location or monitor this phone`, detail: 'Family safety and location-sharing apps are fine when you chose them. People who stalk a partner install them too, because they look harmless.', fix: 'Open each one and check who can see you. Delete any you didn’t install yourself.', list: watchers.map((p) => ({ name: p, note: note(p) })) });

  // 10. How the phone itself is locked down.
  const boot = props['ro.boot.verifiedbootstate'];
  if (boot && boot !== 'green') items.push({ id: 'bootloader', status: 'warn', title: 'The phone’s bootloader is unlocked', detail: 'Android can’t check that its own system hasn’t been changed. That makes rooting and hidden spyware much easier.', fix: 'If you didn’t unlock it yourself, back up your photos and reset the phone. Re-locking needs the maker’s steps for your model.' });
  if (props['ro.crypto.state'] === 'unencrypted') items.push({ id: 'encryption', status: 'warn', title: 'The phone’s storage isn’t encrypted', detail: 'Someone with the phone could read its files without your PIN.', fix: 'Set a PIN or password in Settings > Security. Newer phones encrypt as soon as you do.' });
  if ((raw.adbWifi ?? '').trim() === '1') items.push({ id: 'wifi-debug', status: 'warn', title: 'Wireless debugging is on', detail: 'Computers on the same Wi-Fi that you paired can control this phone without a cable.', fix: 'Settings > System > Developer options > turn off Wireless debugging.' });
  if (boot === 'green' && props['ro.crypto.state'] !== 'unencrypted') items.push({ id: 'boot', status: 'ok', title: 'Android’s own system checks out', detail: 'The bootloader is locked, so Android can check its system hasn’t been changed, and storage is encrypted.' });

  // 11. Rooted
  if (raw.su.trim() || props['ro.build.tags'] === 'test-keys') items.push({ id: 'rooted', status: 'warn', title: 'This phone looks rooted', detail: 'Rooting removes Android’s safety walls, so any app could read everything. Some spy apps need it.', fix: 'If you didn’t root it yourself, back up your photos and reset the phone: Settings > System > Reset options > Erase all data.' });

  items.push({ id: 'usb-debugging', status: 'info', title: 'Turn USB debugging off when we’re done', detail: 'You switched it on so I could look. Leaving it on lets any computer you plug into ask questions too.', fix: 'Settings > System > Developer options > turn off USB debugging.' });

  const { verdict, headline } = verdictOf(items);
  return {
    id, platform: 'android', name, model, os: release ? `Android ${release}` : 'Android', checkedAt: today, verdict, headline, items, notes,
    counts: { apps: apps.size, outsideStore: side.length, accessibility: access.length },
    facts: { apps: apps.size },
  };
}

const ANDROID_TIER = (i: CheckItem): 'sus' | 'risk' | 'tip' => (i.id === 'stalkerware' || i.id === 'play-protect' || i.id === 'sms-app' || (i.status === 'bad' && ['sideloaded', 'accessibility', 'device-admin'].includes(i.id)) ? 'sus' : i.id === 'usb-debugging' ? 'tip' : 'risk');

async function checkAndroid(id: string): Promise<void> {
  const adb = adbPath();
  if (!adb) throw new Error('I need the adb tool first. Press Get the tools.');
  const sh = (args: string[], timeout = 30_000) => run(adb, ['-s', id, 'shell', ...args], { timeout, maxBuffer: 64 * 1024 * 1024 }).then((r) => r.stdout);
  setStep(1, 'Reading the phone’s software and apps');
  const props = await sh(['getprop']);
  if (!props.trim()) throw new Error('Your phone didn’t answer. Check it still says USB debugging is connected, then try again.');
  const packages = await sh(['pm', 'list', 'packages', '-3', '-f', '-i']);
  const launchers = await sh(['cmd', 'package', 'query-activities', '--brief', '-a', 'android.intent.action.MAIN', '-c', 'android.intent.category.LAUNCHER']);
  setStep(2, 'Checking which apps can watch you');
  const accessibility = await sh(['settings', 'get', 'secure', 'enabled_accessibility_services']);
  const listeners = await sh(['settings', 'get', 'secure', 'enabled_notification_listeners']);
  const policy = await sh(['dumpsys', 'device_policy']);
  const perms = await sh(['dumpsys', 'package', 'packages'], 120_000);
  const verifier = (await Promise.all(['package_verifier_user_consent', 'package_verifier_enable'].map(async (k) => `${k}=${(await sh(['settings', 'get', 'global', k])).trim()}`))).join('\n');
  const su = await sh(['command', '-v', 'su']);
  setStep(3, 'Checking keyboards, texting app and special access');
  const op = (name: string) => sh(['appops', 'query-op', '--user', '0', name, 'allow']);
  const [installers, usage, overlays] = [await op('REQUEST_INSTALL_PACKAGES'), await op('GET_USAGE_STATS'), await op('SYSTEM_ALERT_WINDOW')];
  const sms = await sh(['settings', 'get', 'secure', 'sms_default_application']);
  const vpn = await sh(['settings', 'get', 'secure', 'always_on_vpn_app']);
  const keyboards = await sh(['settings', 'get', 'secure', 'enabled_input_methods']);
  const adbWifi = await sh(['settings', 'get', 'global', 'adb_wifi_enabled']);
  setStep(4, 'Comparing with known stalkerware');
  const iocs = await stalkerwareList();
  const report = evaluateAndroid(id, { props, packages, accessibility, listeners, policy, launchers, perms, verifier, su, installers, usage, overlays, sms, vpn, keyboards, adbWifi }, iocs.list);
  if (!iocs.fresh && !iocs.list.length) report.notes.push('I couldn’t download the list of known stalkerware just now, so I only checked how apps behave.');
  saveReport(report);
  toFindings(report, ANDROID_TIER);
  const dev = devices.get(id);
  if (dev) setDevice({ ...dev, name: report.name, os: report.os });
  logEvent('phone', report.verdict === 'worry' ? 'medium' : 'info', `Checked ${yours(report.name)}. ${report.headline}.`, { platform: 'android' });
}

export function startCheck(id: string): { ok: true } | { error: string } {
  const d = devices.get(id);
  if (!d) return { error: 'I don’t see that phone any more. Plug it in again.' };
  if (d.state !== 'ready') return { error: d.hint || 'Your phone isn’t ready yet.' };
  return begin({ kind: 'check', what: d.platform, deviceId: id, total: d.platform === 'ios' ? 2 : 4 }, () => (d.platform === 'ios' ? checkIos(id) : checkAndroid(id)));
}

// ---------- deep check (MVT, iPhone) ----------
const GB = 1e9;
export function freeBytes(): number {
  try { const s = statfsSync(DATA_DIR); return Number(s.bavail) * Number(s.bsize); } catch { return 0; }
}

/** Space a backup can take: up to what the phone uses, twice that when it has to be decrypted, plus room to spare. */
export function deepNeeds(r: PhoneReport | undefined): { need: number; free: number; enough: boolean } {
  const used = r?.deep?.usedBytes ?? 0;
  const need = Math.round(used * (r?.deep?.encrypted ? 2 : 1) + 10 * GB);
  const free = freeBytes();
  return { need, free, enough: used > 0 && free > need };
}

function spawnProgress(cmd: string, args: string[], onText: (t: string) => void, env?: Record<string, string>, timeout = 6 * 3600_000): Promise<{ ok: boolean; tail: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
    let tail = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    const take = (c: Buffer) => { const s = c.toString('utf8'); tail = (tail + s).slice(-2000); for (const part of s.split(/[\r\n]+/)) if (part.trim()) onText(part); };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    child.on('error', (e) => { clearTimeout(timer); resolve({ ok: false, tail: String(e) }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ ok: code === 0, tail }); });
  });
}

function addDeepItem(r: PhoneReport): void {
  const res = r.deep?.result;
  if (!res) return;
  r.items = r.items.filter((i) => i.id !== 'mvt');
  if (res.error) r.items.push({ id: 'mvt', status: 'info', title: 'The deep spyware check didn’t finish', detail: res.error });
  else if (res.detections) r.items.push({ id: 'mvt', status: 'bad', title: `The deep check found ${res.detections === 1 ? 'one sign' : `${res.detections} signs`} of known spyware`, detail: 'Amnesty International’s Mobile Verification Toolkit matched traces on your phone to known spyware. A match can be a false alarm, but take it seriously.', fix: 'Don’t delete anything yet: the traces are evidence. Contact Amnesty Tech’s Security Lab or Access Now’s free Digital Security Helpline (accessnow.org/help) and tell them MVT found a match. Use a different device to contact them.', list: res.modules.map((m) => ({ name: m.module, note: `${m.count} match${m.count === 1 ? '' : 'es'}`, flag: 'bad' as const })) });
  else r.items.push({ id: 'mvt', status: 'ok', title: 'No signs of known spyware', detail: `Amnesty International’s Mobile Verification Toolkit checked a backup of your phone against public indicators of spyware like Pegasus and Predator on ${new Date(res.at).toLocaleDateString()}. No match.` });
  Object.assign(r, verdictOf(r.items));
}

export function startDeepCheck(id: string, password?: string): { ok: true } | { error: string } {
  const d = devices.get(id);
  const r = reports()[id];
  if (!d || d.platform !== 'ios') return { error: 'Plug in the iPhone you want to check.' };
  if (d.state !== 'ready') return { error: d.hint || 'Your phone isn’t ready yet.' };
  if (!r) return { error: 'Run the normal check first, so I know how much space the backup needs.' };
  if (!existsSync(MVT)) return { error: 'I need MVT first. Press Get MVT.' };
  if (!inBrew('idevicebackup2')) return { error: 'I need the iPhone tools first.' };
  const space = deepNeeds(r);
  if (!space.enough) return { error: `I need about ${Math.ceil(space.need / GB)} GB free for the backup and you have ${Math.floor(space.free / GB)} GB. Free up space in Storage & speed first.` };
  if (r.deep?.encrypted && !password) return { error: 'Your phone encrypts its backups, so I need that backup password to read the backup.' };
  return begin({ kind: 'deep', what: 'mvt', deviceId: id, total: r.deep?.encrypted ? 4 : 3 }, async () => {
    const dir = join(BACKUPS, short(id));
    const out = join(dir, 'results');
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(out, { recursive: true, mode: 0o700 });
    let result: DeepResult;
    try {
      setStep(1, 'Making a backup of your phone on this Mac. Keep it plugged in and unlocked', 0);
      const b = await spawnProgress(inBrew('idevicebackup2')!, ['-u', id, 'backup', '--full', dir], (t) => {
        const pct = Number(t.match(/(\d{1,3})% Finished/)?.[1] ?? t.match(/\]\s*(\d{1,3})%/)?.[1] ?? NaN);
        if (Number.isFinite(pct) && pct !== job?.pct) setStep(1, 'Making a backup of your phone on this Mac. Keep it plugged in and unlocked', pct);
      });
      if (!b.ok) throw new Error(/passcode|locked/i.test(b.tail) ? 'Your phone asked for its passcode or locked. Unlock it and try again.' : `The backup stopped. ${b.tail.trim().split('\n').pop()?.slice(0, 200) ?? ''}`);
      let target = join(dir, id);
      if (r.deep?.encrypted) {
        setStep(2, 'Unlocking the backup with your backup password');
        const dec = join(dir, 'decrypted');
        const x = await spawnProgress(MVT, ['--disable-update-check', 'decrypt-backup', '-d', dec, target], () => undefined, { MVT_IOS_BACKUP_PASSWORD: password! });
        if (!x.ok) throw new Error(/password|decrypt/i.test(x.tail) ? 'That backup password didn’t work. It is the one you chose when you turned on “Encrypt local backup”, not your phone passcode.' : `I couldn’t unlock the backup. ${x.tail.trim().split('\n').pop()?.slice(0, 200) ?? ''}`);
        rmSync(target, { recursive: true, force: true });
        target = dec;
      }
      const step = r.deep?.encrypted ? 3 : 2;
      setStep(step, 'Updating the spyware indicators');
      await run(MVT, ['--disable-update-check', 'download-iocs'], { timeout: 300_000 });
      setStep(step + 1, 'Looking for traces of known spyware (this can take a while)');
      const c = await spawnProgress(MVT, ['--disable-update-check', '--disable-indicator-update-check', 'check-backup', '--output', out, target], () => undefined);
      const detected = readdirSync(out).filter((f) => f.endsWith('_detected.json'));
      const modules = detected.map((f) => { let n = 0; try { const j = JSON.parse(readFileSync(join(out, f), 'utf8')); n = Array.isArray(j) ? j.length : Object.keys(j).length; } catch { /* unreadable */ } return { module: f.replace(/_detected\.json$/, ''), count: n }; }).filter((m) => m.count);
      const checked = readdirSync(out).filter((f) => f.endsWith('.json') && !f.endsWith('_detected.json')).map((f) => f.replace(/\.json$/, ''));
      if (!c.ok && !checked.length) throw new Error(`MVT stopped early. ${c.tail.trim().split('\n').pop()?.slice(0, 200) ?? ''}`);
      result = { at: Date.now(), detections: modules.reduce((n, m) => n + m.count, 0), modules, checked };
      // Keep MVT's findings as evidence when it matched something; otherwise nothing is kept.
      if (result.detections) { const keep = join(DATA_DIR, 'phone-evidence', `${short(id)}-${Date.now()}`); mkdirSync(keep, { recursive: true, mode: 0o700 }); for (const f of readdirSync(out)) writeFileSync(join(keep, f), readFileSync(join(out, f))); }
    } catch (e) {
      result = { at: Date.now(), detections: 0, modules: [], checked: [], error: String((e as Error).message ?? e).slice(0, 300) };
    } finally {
      // The backup holds your messages and photos: never leave it lying around.
      rmSync(dir, { recursive: true, force: true });
    }
    const latest = reports()[id] ?? r;
    latest.deep = { ...(latest.deep ?? { usedBytes: null, encrypted: null }), result };
    addDeepItem(latest);
    saveReport(latest);
    toFindings(latest, IOS_TIER);
    logEvent('phone', result.detections ? 'high' : 'info', result.error ? `Deep spyware check on ${yours(latest.name)} didn’t finish` : result.detections ? `Deep spyware check found ${result.detections} signs of known spyware on ${yours(latest.name)}` : `Deep spyware check: no known spyware on ${yours(latest.name)}`, { platform: 'ios' });
    if (result.error) throw new Error(result.error);
  });
}

// ---------- state for the dashboard and agents ----------
export function phoneCheckState() {
  const all = reports();
  return {
    devices: [...devices.values()].sort((a, b) => a.pluggedAt - b.pluggedAt),
    reports: Object.values(all).sort((a, b) => b.checkedAt - a.checkedAt),
    tools: phoneTools(),
    job,
    lastError,
    space: Object.fromEntries(Object.values(all).filter((r) => r.platform === 'ios').map((r) => [r.id, deepNeeds(r)])),
  };
}
