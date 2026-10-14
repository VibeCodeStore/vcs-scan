#!/usr/bin/env node
import { scanDir } from '../src/index.js';

const dir = process.argv[2] || '.';
const bar = Number((process.argv.find(a => a.startsWith('--bar=')) || '').split('=')[1]) || undefined;
const json = process.argv.includes('--json');
const r = scanDir(dir, { bar });

if (json) {
  console.log(JSON.stringify(r, null, 2));
} else {
  console.log(`\nVCS security score: ${r.score}/100 (bar ${r.bar})\n`);
  for (const c of r.results) {
    console.log(`${c.pass ? '✓' : '✗'} ${c.id}${c.critical ? ' (critical)' : ''}`);
    for (const f of c.findings) console.log(`    ${f.file}: ${f.issue}`);
  }
  console.log(`\n${r.live ? 'Cleared to go live.' : 'Blocked: fix the items above.'}\n`);
}
process.exit(r.live ? 0 : 1);
