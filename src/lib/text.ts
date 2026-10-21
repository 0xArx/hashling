/** "1 connection", "3 connections": never "connection(s)". */
export function plural(n: number, word: string, many?: string): string {
  return `${n} ${n === 1 ? word : many ?? (/(s|x|ch|sh)$/.test(word) ? `${word}es` : `${word}s`)}`;
}
