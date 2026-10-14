import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';

const SKIP = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);
const CODE = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.py', '.env', '.yml', '.yaml', '.html']);

export function listFiles(dir, root = dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name), st = statSync(p);
    if (st.isDirectory()) listFiles(p, root, out);
    else if (CODE.has(extname(name)) || name.startsWith('.env')) out.push({ path: relative(root, p), text: readFileSync(p, 'utf8') });
  }
  return out;
}

const SECRET_PATTERNS = [
  ['AWS access key', /AKIA[0-9A-Z]{16}/],
  ['Private key block', /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['Stripe live key', /sk_live_[0-9a-zA-Z]{20,}/],
  ['Slack token', /xox[baprs]-[0-9A-Za-z-]{10,}/],
  ['GitHub token', /gh[pousr]_[0-9A-Za-z]{30,}/],
  ['Generic secret assignment', /(api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"\s]{12,}['"]/i],
  ['Solana keypair array', /\[\s*(\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/],
];

/** Secrets must never be in code. Critical check. */
export function secretsCheck(files) {
  const findings = [];
  for (const f of files) for (const [name, re] of SECRET_PATTERNS) {
    if (re.test(f.text)) findings.push({ file: f.path, issue: name });
  }
  return { id: 'secrets', critical: true, pass: findings.length === 0, findings };
}

/** Apps may only reach the network through approved connectors. */
export function egressCheck(files, allowedHosts = []) {
  const findings = [];
  const url = /https?:\/\/([a-z0-9.-]+)/gi;
  for (const f of files) {
    if (f.path.endsWith('.json') || f.path.endsWith('.md')) continue;
    for (const m of f.text.matchAll(url)) {
      const host = m[1].toLowerCase();
      if (!allowedHosts.some(h => host === h || host.endsWith('.' + h))) findings.push({ file: f.path, issue: `unapproved host ${host}` });
    }
  }
  return { id: 'egress', critical: true, pass: findings.length === 0, findings };
}

const UNSAFE = [
  ['eval()', /\beval\s*\(/],
  ['new Function()', /new\s+Function\s*\(/],
  ['innerHTML assignment', /\.innerHTML\s*=/],
  ['child_process', /require\(['"]child_process['"]\)|from ['"]node:child_process['"]/],
  ['SQL string concatenation', /(SELECT|INSERT|UPDATE|DELETE)[^;'"]*['"]\s*\+\s*\w+/i],
];
export function patternsCheck(files) {
  const findings = [];
  for (const f of files) for (const [name, re] of UNSAFE) if (re.test(f.text)) findings.push({ file: f.path, issue: name });
  return { id: 'patterns', critical: false, pass: findings.length === 0, findings };
}

/** Scopes declared in vcs.json must be valid and must not include wildcards. */
export function permissionsCheck(manifest) {
  const findings = [];
  const scopes = manifest?.scopes || [];
  if (!Array.isArray(scopes)) findings.push({ file: 'vcs.json', issue: 'scopes must be an array' });
  for (const s of scopes) {
    if (!/^[a-z][a-z0-9_.-]*:(read|write)$/.test(s)) findings.push({ file: 'vcs.json', issue: `invalid scope ${s}` });
  }
  if (scopes.length > 8) findings.push({ file: 'vcs.json', issue: `asks for ${scopes.length} scopes; split the app` });
  return { id: 'permissions', critical: false, pass: findings.length === 0, findings };
}

/** Flags dependencies that are unpinned or on a denylist. */
export function dependencyCheck(pkg, denylist = []) {
  const findings = [];
  const deps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
  for (const [name, range] of Object.entries(deps)) {
    if (denylist.includes(name)) findings.push({ file: 'package.json', issue: `denied package ${name}` });
    if (/^[~^*]|latest|x/.test(String(range))) findings.push({ file: 'package.json', issue: `unpinned ${name}@${range}` });
  }
  return { id: 'dependencies', critical: false, pass: findings.length === 0, findings };
}

export function policyCheck(manifest) {
  const findings = [];
  if (!manifest?.name) findings.push({ file: 'vcs.json', issue: 'missing app name' });
  if (!manifest?.owner) findings.push({ file: 'vcs.json', issue: 'missing owner (who maintains this app)' });
  return { id: 'policy', critical: false, pass: findings.length === 0, findings };
}
