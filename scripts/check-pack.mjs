#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const violations = [];

const ALLOWED_ROOT_FILES = new Set(['package.json', 'README.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md']);
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb']);
const SECRET_MARKERS = ['token', 'secret', 'key', 'credential', '.env'];

function fail(message) {
  violations.push(message);
}

let output;
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--output') {
    const value = args[i + 1];
    if (value === undefined || value.length === 0) {
      console.error('check-pack: --output requires a path');
      process.exit(1);
    }
    i += 1;
    output = resolve(value);
  } else {
    console.error(`check-pack: unknown argument ${JSON.stringify(args[i])}`);
    process.exit(1);
  }
}

const temp = mkdtempSync(join(tmpdir(), 'omp-peers-pack-'));

function createTarball() {
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const result = spawnSync(npm, ['pack', '--json', '--pack-destination', temp], { cwd: root, encoding: 'utf8' });
  if (result.error) {
    fail(`npm pack failed: ${result.error.message}`);
    return undefined;
  }
  if (result.status !== 0) {
    const detail = result.stderr && result.stderr.trim().length > 0 ? result.stderr.trim() : `exit ${result.status}`;
    fail(`npm pack failed: ${detail}`);
    return undefined;
  }

  let filename;
  try {
    const parsed = JSON.parse(result.stdout);
    if (Array.isArray(parsed) && typeof parsed[0]?.filename === 'string' && parsed[0].filename.length > 0) {
      filename = parsed[0].filename;
    }
  } catch {
    // fall back to scanning the temporary destination below
  }
  if (filename === undefined) {
    const found = readdirSync(temp).filter((name) => name.endsWith('.tgz'));
    if (found.length !== 1) {
      fail(`npm pack: expected exactly one .tgz in the temporary destination, found ${found.length}`);
      return undefined;
    }
    filename = found[0];
  }

  const tarball = isAbsolute(filename) ? filename : join(temp, filename);
  if (!existsSync(tarball)) {
    fail(`npm pack: reported tarball ${JSON.stringify(filename)} is missing from the temporary destination`);
    return undefined;
  }
  return tarball;
}

function readString(header, start, length) {
  return header.subarray(start, start + length).toString('utf8').split('\0')[0];
}

function readNumber(header, start, length) {
  const field = header.subarray(start, start + length);
  if ((field[0] & 0x80) !== 0) {
    let value = BigInt(field[0] & 0x7f);
    for (let i = 1; i < length; i += 1) value = (value << 8n) | BigInt(field[i]);
    return Number(value);
  }
  const text = field.toString('latin1').replace(/\0.*$/, '').trim();
  return text.length === 0 ? 0 : Number.parseInt(text, 8);
}

function isZeroBlock(block) {
  for (const byte of block) {
    if (byte !== 0) return false;
  }
  return true;
}

function checksumOk(header) {
  const expected = Number.parseInt(header.subarray(148, 156).toString('latin1').replace(/\0.*$/, '').trim(), 8);
  if (!Number.isFinite(expected)) return false;
  let sum = 0;
  for (let i = 0; i < 512; i += 1) sum += i >= 148 && i < 156 ? 0x20 : header[i];
  return sum === expected;
}

function parsePaxPath(body) {
  const text = body.toString('utf8');
  let offset = 0;
  while (offset < text.length) {
    const space = text.indexOf(' ', offset);
    if (space === -1) return undefined;
    const length = Number.parseInt(text.slice(offset, space), 10);
    if (!Number.isFinite(length) || length <= 0) return undefined;
    const record = text.slice(space + 1, offset + length - 1);
    const eq = record.indexOf('=');
    if (eq > 0 && record.slice(0, eq) === 'path') return record.slice(eq + 1);
    offset += length;
  }
  return undefined;
}

function isSafePath(path) {
  if (path.length === 0 || path.startsWith('/') || /^[a-zA-Z]:/.test(path)) return false;
  return path.split('/').every((segment) => segment.length > 0 && segment !== '.' && segment !== '..');
}

function readEntries(tarball) {
  let data;
  try {
    data = gunzipSync(readFileSync(tarball));
  } catch (error) {
    fail(`tarball: could not decompress (${error.message})`);
    return undefined;
  }

  const entries = [];
  let offset = 0;
  let pendingPath;
  while (offset + 512 <= data.length) {
    const header = data.subarray(offset, offset + 512);
    if (isZeroBlock(header)) break;
    if (!checksumOk(header)) {
      fail('tarball: archive header checksum mismatch');
      return undefined;
    }
    const size = readNumber(header, 124, 12);
    const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    const name = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    let rawPath = prefix.length > 0 ? `${prefix}/${name}` : name;

    const bodyStart = offset + 512;
    const bodyEnd = bodyStart + size;
    if (bodyEnd > data.length) {
      fail('tarball: truncated archive entry');
      return undefined;
    }
    const body = data.subarray(bodyStart, bodyEnd);
    offset = bodyStart + Math.ceil(size / 512) * 512;

    if (type === 'x') {
      pendingPath = parsePaxPath(body) ?? pendingPath;
      continue;
    }
    if (type === 'L') {
      pendingPath = body.toString('utf8').replace(/\0+$/, '');
      continue;
    }
    if (type === 'g') continue;
    if (pendingPath !== undefined) {
      rawPath = pendingPath;
      pendingPath = undefined;
    }

    const cleanPath = rawPath.endsWith('/') ? rawPath.slice(0, -1) : rawPath;
    if (!isSafePath(cleanPath)) {
      fail(`entry ${JSON.stringify(rawPath)}: path escapes the extraction directory`);
      continue;
    }
    if (type === '0') {
      entries.push({ type: 'file', path: cleanPath, body });
    } else if (type === '5') {
      entries.push({ type: 'dir', path: cleanPath });
    } else {
      fail(`entry ${JSON.stringify(cleanPath)}: unsupported tar entry type ${JSON.stringify(type)}`);
      continue;
    }
  }

  if (entries.length === 0) {
    fail('tarball: archive contains no entries');
    return undefined;
  }
  return entries;
}

function checkEntry(entry) {
  const fullPath = entry.path;
  if (fullPath === 'package') return;
  const first = fullPath.indexOf('/');
  if (first === -1 || fullPath.slice(0, first) !== 'package') {
    fail(`entry ${JSON.stringify(fullPath)}: tarball entries must live under package/`);
    return;
  }
  const rel = fullPath.slice(first + 1);
  if (rel.length === 0) return;
  const segments = rel.split('/');

  for (const segment of segments) {
    const lower = segment.toLowerCase();
    if (SECRET_MARKERS.some((marker) => lower.includes(marker))) {
      fail(`entry ${JSON.stringify(fullPath)}: secret-shaped path segment ${JSON.stringify(segment)} is not allowed`);
      return;
    }
  }
  if (rel === '.github' || rel.startsWith('.github/')) {
    fail(`entry ${JSON.stringify(fullPath)}: CI files under .github/ are not allowed`);
    return;
  }
  const dot = segments.find((segment) => segment.startsWith('.'));
  if (dot !== undefined) {
    fail(`entry ${JSON.stringify(fullPath)}: dotfile ${JSON.stringify(dot)} is not allowed`);
    return;
  }
  if (rel === 'src' || rel.startsWith('src/')) {
    fail(`entry ${JSON.stringify(fullPath)}: source files under src/ are not allowed`);
    return;
  }
  if (rel === 'test' || rel.startsWith('test/') || rel === 'tests' || rel.startsWith('tests/')) {
    fail(`entry ${JSON.stringify(fullPath)}: test files are not allowed`);
    return;
  }
  if (LOCKFILES.has(rel)) {
    fail(`entry ${JSON.stringify(fullPath)}: lockfile ${JSON.stringify(rel)} is not allowed`);
    return;
  }
  if (ALLOWED_ROOT_FILES.has(rel) || rel === 'dist' || rel.startsWith('dist/')) return;
  fail(`entry ${JSON.stringify(fullPath)}: ${JSON.stringify(rel)} is not on the package allowlist (package.json, README.md, LICENSE, CHANGELOG.md, SECURITY.md, dist/**)`);
}

function extractEntries(entries, extractRoot) {
  for (const entry of entries) {
    const target = join(extractRoot, entry.path);
    try {
      if (entry.type === 'dir') {
        mkdirSync(target, { recursive: true });
        continue;
      }
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, entry.body);
    } catch (error) {
      fail(`extract ${JSON.stringify(entry.path)}: ${error.message}`);
      return;
    }
  }
}

function checkTarget(pkgRoot, field, target) {
  if (typeof target !== 'string' || target.length === 0) {
    fail(`package.json: ${field} must be a non-empty string path`);
    return;
  }
  const resolved = resolve(pkgRoot, target);
  if (resolved !== pkgRoot && !resolved.startsWith(pkgRoot + sep)) {
    fail(`package.json: ${field} target ${JSON.stringify(target)} resolves outside the extracted package`);
    return;
  }
  let stats;
  try {
    stats = statSync(resolved);
  } catch {
    fail(`package.json: ${field} target ${JSON.stringify(target)} does not resolve to a real file inside the extracted package`);
    return;
  }
  if (!stats.isFile()) {
    fail(`package.json: ${field} target ${JSON.stringify(target)} is not a regular file inside the extracted package`);
  }
}

function walkExports(node, path, out) {
  if (typeof node === 'string') {
    out.push([path, node]);
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((value, index) => walkExports(value, `${path}[${index}]`, out));
    return;
  }
  if (typeof node === 'object' && node !== null) {
    for (const [key, value] of Object.entries(node)) walkExports(value, `${path}["${key}"]`, out);
  }
}

function verifyTargets(pkgRoot) {
  let pkg;
  try {
    pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8'));
  } catch (error) {
    fail(`extracted package.json: not readable or not valid JSON (${error.message})`);
    return;
  }

  for (const field of ['main', 'types']) {
    if (pkg[field] === undefined) fail(`package.json: ${field} is missing`);
    else checkTarget(pkgRoot, field, pkg[field]);
  }

  if (pkg.exports === undefined) {
    fail('package.json: exports is missing');
  } else {
    const entries = [];
    walkExports(pkg.exports, 'exports', entries);
    if (entries.length === 0) fail('package.json: exports must declare at least one string target');
    for (const [field, target] of entries) checkTarget(pkgRoot, field, target);
  }

  if (!Array.isArray(pkg.omp?.extensions)) {
    fail('package.json: omp.extensions must be an array of file targets');
  } else if (pkg.omp.extensions.length === 0) {
    fail('package.json: omp.extensions must not be empty');
  } else {
    pkg.omp.extensions.forEach((target, index) => checkTarget(pkgRoot, `omp.extensions[${index}]`, target));
  }
}

function activate(pkgRoot) {
  const result = spawnSync(
    process.execPath,
    [join(root, 'scripts', 'smoke-host.mjs'), '--entry', join(pkgRoot, 'dist', 'extension.js'), '--scenario', 'all'],
    { cwd: root, stdio: 'inherit' },
  );
  if (result.error) {
    fail(`activation failed: smoke-host.mjs could not run (${result.error.message})`);
    return;
  }
  if (result.status !== 0) {
    fail(`activation failed: smoke-host.mjs exited with ${result.status === null ? 'no exit status' : `code ${result.status}`}`);
  }
}

function publish(tarball) {
  if (output === undefined) return;
  try {
    mkdirSync(dirname(output), { recursive: true });
    copyFileSync(tarball, output);
  } catch (error) {
    fail(`--output: could not write the validated tarball to ${JSON.stringify(output)} (${error.message})`);
  }
}

function run() {
  const tarball = createTarball();
  if (tarball === undefined) return;

  const entries = readEntries(tarball);
  if (entries === undefined) return;
  for (const entry of entries) checkEntry(entry);
  if (violations.length > 0) return;

  const extractRoot = join(temp, 'extract');
  extractEntries(entries, extractRoot);
  if (violations.length > 0) return;

  const pkgRoot = join(extractRoot, 'package');
  verifyTargets(pkgRoot);
  if (violations.length > 0) return;

  activate(pkgRoot);
  if (violations.length > 0) return;

  publish(tarball);
}

try {
  run();
} catch (error) {
  fail(`unexpected failure: ${error && error.message ? error.message : String(error)}`);
} finally {
  try {
    rmSync(temp, { recursive: true, force: true });
  } catch (error) {
    fail(`cleanup failed: could not remove the temporary directory ${JSON.stringify(temp)} (${error.message})`);
  }
}

if (violations.length > 0) {
  for (const line of violations) console.error(line);
  process.exit(1);
}
process.exit(0);
