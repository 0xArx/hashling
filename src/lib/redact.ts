/** Hide credentials that people pass on command lines. */
export function redact(s: string): string {
  return s
    .replace(/(sk-[a-z]{2,6}-|gh[pousr]_|github_pat_|xox[abprs]-|sk_live_|sk_test_|gsk_|re_|sb_secret_|vcp_|AKIA)[A-Za-z0-9_-]{6,}/g, '$1•••')
    .replace(/(--?(token|key|password|secret|api[-_]?key)[= ])\S+/gi, '$1•••')
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'eyJ•••')
    // Logins embedded in URLs: https://user:secret@host
    .replace(/([a-z][\w+.-]*:\/\/)([^/@\s:]+):([^/@\s]+)@/gi, '$1$2:•••@');
}
