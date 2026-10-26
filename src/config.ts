import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const NAME = 'Hashling';
export const SLUG = 'hashling';
export const VERSION = '0.2.0';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const HOME = homedir();
export const DATA_DIR = process.env.HASHLING_HOME ?? join(HOME, '.hashling');
export const DB_PATH = join(DATA_DIR, 'hashling.db');
export const TOKEN_PATH = join(DATA_DIR, 'token');
export const QUARANTINE_DIR = join(DATA_DIR, 'quarantine');
export const RULES_DIR = join(DATA_DIR, 'rules');
export const ENGINES_DIR = join(DATA_DIR, 'engines');
export const CLAMAV_DB = join(DATA_DIR, 'clamav-db');
export const FRESHCLAM_CONF = join(DATA_DIR, 'freshclam.conf');

export const HOST = '127.0.0.1';
export const PORT = Number(process.env.HASHLING_PORT ?? 5750);
/** Phone mode: only open while the user has it switched on, and only speaks sealed messages. */
export const PHONE_PORT = Number(process.env.HASHLING_PHONE_PORT ?? PORT + 1);
/** The dashboard's friendly address. Every name ending in .localhost means this Mac, so it never leaves it. */
export const LOCAL_NAME = 'hashling.localhost';
export const DASHBOARD_URL = `http://${LOCAL_NAME}:${PORT}`;

export const APP_PATH = process.env.HASHLING_APP ?? join(HOME, 'Applications/Hashling.app');

/** Helpers run from inside Hashling.app when installed, so macOS attributes permissions to Hashling. */
function helper(name: string): string {
  const inApp = join(APP_PATH, 'Contents/MacOS', name);
  return existsSync(inApp) ? inApp : join(ROOT, 'helpers/build', name);
}

export const BIN = {
  osquery: process.env.HASHLING_OSQUERY ?? join(ENGINES_DIR, 'osquery/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd'),
  osqueryPacks: join(ENGINES_DIR, 'osquery/private/var/osquery/packs'),
  clamscan: process.env.HASHLING_CLAMSCAN ?? '/opt/homebrew/bin/clamscan',
  freshclam: process.env.HASHLING_FRESHCLAM ?? '/opt/homebrew/bin/freshclam',
  yr: process.env.HASHLING_YR ?? '/opt/homebrew/bin/yr',
  ble: helper('hashling-ble'),
  auth: helper('hashling-auth'),
  trash: helper('hashling-trash'),
  ocr: helper('hashling-ocr'),
};

export const XPROTECT_YARA = '/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara';
export const XPROTECT_PLIST = '/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist';

/** Seconds between collector runs. */
export const SCHEDULE = {
  network: 10,
  posture: 15 * 60,
  persistence: 5 * 60,
  permissions: 10 * 60,
  location: 30 * 60,
  trackers: 3 * 60,
  attackPacks: 60 * 60,
  agents: 5 * 60,
  projects: 30 * 60,
  processes: 2,
  behavior: 5 * 60,
  intel: 6 * 60 * 60,
  netsafety: 2 * 60,
  secrets: 30 * 60,
  notarization: 24 * 60 * 60,
  storage: 6 * 60 * 60,
  score: 60 * 60,
  routineScan: 24 * 60 * 60,
  signatures: 12 * 60 * 60,
};

/** Look up IP owners (reverse DNS + ASN over DNS). Sends remote IPs to your DNS resolver. */
export const ENRICH_NETWORK = process.env.HASHLING_ENRICH !== '0';
