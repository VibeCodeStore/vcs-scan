import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { listFiles, secretsCheck, egressCheck, patternsCheck, permissionsCheck, dependencyCheck, policyCheck } from './checks.js';

export const WEIGHTS = { secrets: 25, egress: 20, dependencies: 15, permissions: 15, patterns: 15, policy: 10 };
export const DEFAULT_BAR = 80;

/** Each failed finding costs part of that check's weight; critical checks must pass outright. */
export function score(results) {
  let total = 0;
  for (const r of results) {
    const w = WEIGHTS[r.id] ?? 0;
    total += r.pass ? w : Math.max(0, w - w * 0.5 * r.findings.length);
  }
  return Math.round(total);
}

export function scanDir(dir, opts = {}) {
  const read = f => (existsSync(join(dir, f)) ? JSON.parse(readFileSync(join(dir, f), 'utf8')) : null);
  const manifest = read('vcs.json') || {};
  const pkg = read('package.json');
  const files = listFiles(dir);
  const results = [
    secretsCheck(files),
    egressCheck(files, manifest.connectors || []),
    dependencyCheck(pkg, opts.denylist || []),
    permissionsCheck(manifest),
    patternsCheck(files),
    policyCheck(manifest),
  ];
  const s = score(results);
  const bar = opts.bar ?? DEFAULT_BAR;
  const criticalFail = results.some(r => r.critical && !r.pass);
  return { score: s, bar, live: s >= bar && !criticalFail, criticalFail, results };
}
