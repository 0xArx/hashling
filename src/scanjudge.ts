/**
 * How worried to be about a scan match. Pure, so it can be tested without a Mac or any scanning engine.
 *
 * A signature for known malware is a verdict wherever the file is, even inside node_modules. A generic pattern
 * ("base64 that loads WebAssembly") is only a hint: normal developer packages and big signed apps match these
 * all the time, so where the file came from decides what it means.
 *
 *                     downloaded      package folder or signed app      anywhere else
 *   known malware     malware         malware                           malware
 *   generic pattern   suspicious      quiet                             review
 *   phishing email    quiet           quiet                             quiet
 *
 * A phishing email sitting in a file is not an infection, wherever it came from. Scam check is for the ones you got.
 */

export type SignatureKind = 'known' | 'pattern' | 'email';
export type Verdict = 'malware' | 'suspicious' | 'review' | 'quiet';

export interface SignatureInfo { engine: string; signature: string; ruleset?: string; score?: number; description?: string }
export interface FileContext { downloaded: boolean; devPackage: boolean; signedApp: boolean }

// Not the word "generic" by itself: real malware rules use it too (Elastic's MacOS_Trojan_Generic_...).
const PATTERN_NAME = /(^|_)(SUSP|HUNT|HUNTING|INDICATOR)(_|$)|smuggling|obfusc/i;
const PATTERN_TEXT = /\b(suspicious|hunting)\b/i;
/** Elastic's macOS malware rules: every one names a real Mac malware family. */
const ELASTIC_MAC = /^MacOS_/;
/** YARA-Forge scores its rules; it gives the guesswork ones 70 or below. */
const PATTERN_SCORE = 70;
const CLAM_EMAIL = /^(Email|Phishing|Html\.Phishing|Heuristics?\.Phishing)\b/i;
const CLAM_PATTERN = /^(Heuristics?|PUA)\./i;

export function signatureKind(d: SignatureInfo): SignatureKind {
  if (d.engine === 'clamav') return CLAM_EMAIL.test(d.signature) ? 'email' : CLAM_PATTERN.test(d.signature) ? 'pattern' : 'known';
  if (d.ruleset === 'xprotect' || ELASTIC_MAC.test(d.signature)) return 'known'; // Apple's own rules, and Elastic's Mac malware families
  const heuristic = PATTERN_NAME.test(d.signature) || PATTERN_TEXT.test(d.description ?? '') || (d.score !== undefined && d.score <= PATTERN_SCORE);
  return heuristic ? 'pattern' : 'known';
}

/** Folders package managers and build tools fill with other people's code. */
const DEV_PACKAGE = /\/(node_modules|bower_components|\.pnpm|\.yarn|\.npm|\.bun|\.nvm|site-packages|dist-packages|\.venv|venv|__pycache__|Pods|Carthage|DerivedData|\.gradle|\.m2|\.next|\.nuxt|\.cache)\/|\/\.cargo\/registry\/|\/go\/pkg\/mod\/|\/vendor\/bundle\//;
export const inDevPackage = (path: string): boolean => DEV_PACKAGE.test(path);

/** The outermost app a file sits inside, if any. */
export function appBundleOf(path: string): string | null {
  const i = path.indexOf('.app/');
  return i < 0 ? null : path.slice(0, i + 4);
}

export function judge(kind: SignatureKind, ctx: FileContext): Verdict {
  if (kind === 'known') return 'malware';
  if (kind === 'email') return 'quiet';
  if (ctx.downloaded) return 'suspicious';
  return ctx.devPackage || ctx.signedApp ? 'quiet' : 'review';
}

export function whyQuiet(kind: SignatureKind, ctx: FileContext): string {
  if (kind === 'email') return 'A phishing email saved in a file. It can’t do anything unless someone opens its links.';
  if (ctx.signedApp) return 'A general pattern inside an app its developer signed, and the signature is intact. This is almost always normal code.';
  return 'A general pattern inside a developer package you installed, not a known threat. Normal packages match this often.';
}

export const VERDICT_RANK: Record<Verdict, number> = { quiet: 0, review: 1, suspicious: 2, malware: 3 };
