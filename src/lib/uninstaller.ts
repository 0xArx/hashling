import { readdirSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

/**
 * Some vendors ship their own uninstaller next to the app (Adobe puts "Uninstall Adobe Illustrator 2024"
 * in the app's folder). It removes plug-ins and helpers that moving only the .app would leave behind.
 * Only apps that live in their own vendor folder count: a loose "Uninstall X" in /Applications is not tied to one app.
 */
export function findUninstaller(appPath: string): string | null {
  const dir = dirname(appPath);
  if (!appPath.endsWith('.app') || /\/Applications$/.test(dir)) return null;
  try {
    // "Uninstall Adobe Illustrator 2024", "Acrobat Uninstaller", "Uninstall Office.app"…
    const hit = readdirSync(dir).find((n) => n !== basename(appPath) && /(^|\s)uninstall(er)?(\s|\.app$|$)/i.test(n));
    return hit ? join(dir, hit) : null;
  } catch { return null; }
}
