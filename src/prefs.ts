/**
 * Dashboard preferences: how much detail to show (simple / standard / expert) and whether
 * the first-run setup has been completed. Stored next to the AI settings in config.json.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DATA_DIR } from './config.ts';

const CONFIG_PATH = join(DATA_DIR, 'config.json');
export const MODES = ['simple', 'standard', 'expert'] as const;
export type Mode = (typeof MODES)[number];
export interface Prefs { mode: Mode; setupDone: boolean; setupAt?: number; autoQuarantine: boolean }

const read = (): Record<string, unknown> => { try { return JSON.parse(readFileSync(CONFIG_PATH, 'utf8')); } catch { return {}; } };

export function loadPrefs(): Prefs {
  const ui = (read().ui ?? {}) as Partial<Prefs>;
  return { mode: MODES.includes(ui.mode as Mode) ? ui.mode as Mode : 'simple', setupDone: Boolean(ui.setupDone), ...(ui.setupAt ? { setupAt: ui.setupAt } : {}), autoQuarantine: Boolean(ui.autoQuarantine) };
}

export function savePrefs(patch: { mode?: unknown; setupDone?: unknown; autoQuarantine?: unknown }): Prefs {
  const next = loadPrefs();
  if (MODES.includes(patch.mode as Mode)) next.mode = patch.mode as Mode;
  if (typeof patch.autoQuarantine === 'boolean') next.autoQuarantine = patch.autoQuarantine;
  if (typeof patch.setupDone === 'boolean') { next.setupDone = patch.setupDone; if (patch.setupDone) next.setupAt = Date.now(); }
  writeFileSync(CONFIG_PATH, JSON.stringify({ ...read(), ui: next }, null, 2), { mode: 0o600 });
  return next;
}

/** How to pitch answers, from the detail level the user picked in setup or Settings. */
export const AUDIENCE: Record<Mode, string> = {
  simple: 'The user chose Simple mode: assume no technical background. Answer in at most 5 short sentences or bullets, plain everyday words, no jargon (if a technical word is unavoidable, explain it in a few words), no file paths, process IDs or commands unless they ask. Lead with whether they need to do anything.',
  standard: 'The user chose Standard mode: comfortable with computers but not a security expert. Explain plainly, name things precisely, and keep technical detail brief.',
  expert: 'The user chose Expert mode: technical detail is welcome. Include paths, signatures, process details and exact commands where useful, but stay concise.',
};
