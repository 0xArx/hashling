import { existsSync } from 'node:fs';
import { BIN } from '../config.ts';
import { run } from './exec.ts';

export const osqueryAvailable = () => existsSync(BIN.osquery);

/** Tables that reach outside the machine or write data. Agents may not use them. */
const DENY = /\b(curl|curl_certificate|carves|carve|yara|file_events|augeas|ycloud_instance_metadata|ec2_instance_metadata|azure_instance_metadata)\b/i;

export function validateSql(sql: string): string | null {
  const s = sql.trim().replace(/;+\s*$/, '');
  if (!/^(select|with)\b/i.test(s)) return 'Only SELECT queries are allowed.';
  if (s.includes(';')) return 'Only one statement is allowed.';
  if (/\b(attach|pragma|insert|update|delete|create|drop|alter|replace)\b/i.test(s)) return 'Only read-only SELECT queries are allowed.';
  if (DENY.test(s)) return 'That table is not available through Hashling (it reaches the network or writes data).';
  return null;
}

export async function osquery<T = Record<string, string>>(sql: string, timeout = 30_000): Promise<{ rows: T[]; error?: string }> {
  if (!osqueryAvailable()) return { rows: [], error: 'osquery is not installed' };
  const r = await run(BIN.osquery, ['-S', '--json', '--disable_events', '--logger_min_status=3', sql], { timeout });
  const json = r.stdout.trim();
  try {
    return { rows: json ? JSON.parse(json) as T[] : [], error: r.ok ? undefined : r.stderr.split('\n').filter((l) => !/^[IW]\d{4}/.test(l)).join('\n').trim() || undefined };
  } catch {
    return { rows: [], error: (r.stderr || 'osquery returned invalid output').slice(0, 500) };
  }
}
