#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const violations = [];

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
const EXACT_VERSION = /^\d+(\.\d+)*$/;

function fail(message) {
  violations.push(message);
}

function readJson(rel) {
  try {
    return JSON.parse(readFileSync(join(root, rel), 'utf8'));
  } catch (error) {
    fail(`${rel}: not readable or not valid JSON (${error.message})`);
    return undefined;
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFile(target) {
  try {
    return statSync(resolve(root, target)).isFile();
  } catch {
    return false;
  }
}

function checkTarget(field, target) {
  if (typeof target !== 'string' || target.length === 0) {
    fail(`package.json: ${field} must be a non-empty string path`);
    return;
  }
  if (!target.startsWith('./dist/')) {
    fail(`package.json: ${field} target "${target}" must point inside ./dist/`);
    return;
  }
  if (!isFile(target)) {
    fail(`package.json: ${field} target "${target}" does not resolve to a real file`);
  }
}

function walkExports(node, path, out) {
  if (typeof node === 'string') {
    out.push([path, node]);
    return;
  }
  if (isPlainObject(node)) {
    for (const [key, value] of Object.entries(node)) {
      walkExports(value, `${path}["${key}"]`, out);
    }
  }
}

const pkg = readJson('package.json');

let version;
if (pkg) {
  version = pkg.version;
  if (typeof version !== 'string' || !SEMVER.test(version)) {
    fail(`package.json: version ${JSON.stringify(version)} is not valid semver`);
    version = undefined;
  }

  if (Object.prototype.hasOwnProperty.call(pkg, 'pi')) {
    fail('package.json: field "pi" must be absent (OMP-only plugin, no pi manifest)');
  }

  if (!isPlainObject(pkg.omp) || !Array.isArray(pkg.omp.extensions)) {
    fail('package.json: omp.extensions must be an array');
  } else if (JSON.stringify(pkg.omp.extensions) !== JSON.stringify(['./dist/extension.js'])) {
    fail(`package.json: omp.extensions must be exactly ["./dist/extension.js"], found ${JSON.stringify(pkg.omp.extensions)}`);
  }

  if (!isPlainObject(pkg.dependencies)) {
    fail('package.json: dependencies must be an empty object');
  } else {
    const names = Object.keys(pkg.dependencies);
    if (names.length > 0) {
      fail(`package.json: dependencies must be empty, found ${names.join(', ')}`);
    }
  }

  const expectedDev = { typescript: '7.0.2', '@types/node': '22.20.4' };
  if (!isPlainObject(pkg.devDependencies)) {
    fail('package.json: devDependencies must be an object pinning typescript 7.0.2 and @types/node 22.20.4');
  } else {
    const found = Object.keys(pkg.devDependencies).sort();
    const expected = Object.keys(expectedDev).sort();
    for (const name of expected) {
      const value = pkg.devDependencies[name];
      if (value === undefined) {
        fail(`package.json: devDependencies.${name} must be pinned to ${expectedDev[name]}`);
      } else if (!EXACT_VERSION.test(value)) {
        fail(`package.json: devDependencies.${name} "${value}" has range characters; expected exact ${expectedDev[name]}`);
      } else if (value !== expectedDev[name]) {
        fail(`package.json: devDependencies.${name} "${value}" must be exactly ${expectedDev[name]}`);
      }
    }
    for (const name of found) {
      if (!(name in expectedDev)) {
        fail(`package.json: devDependencies.${name} is not allowed; only typescript and @types/node may be pinned`);
      }
    }
  }

  if (pkg.main !== undefined) checkTarget('main', pkg.main);
  if (pkg.types !== undefined) checkTarget('types', pkg.types);
  if (pkg.exports !== undefined) {
    const entries = [];
    walkExports(pkg.exports, 'exports', entries);
    if (entries.length === 0) {
      fail('package.json: exports must declare at least one string target');
    }
    for (const [field, target] of entries) checkTarget(field, target);
  }
  if (Array.isArray(pkg.omp?.extensions)) {
    pkg.omp.extensions.forEach((target, index) => checkTarget(`omp.extensions[${index}]`, target));
  }
}

const marketplace = readJson('.omp-plugin/marketplace.json');
if (marketplace) {
  const metaVersion = marketplace.metadata?.version;
  if (version) {
    if (metaVersion !== version) {
      fail(`.omp-plugin/marketplace.json: metadata.version ${JSON.stringify(metaVersion)} must equal package.json version ${JSON.stringify(version)}`);
    }
    const plugin = Array.isArray(marketplace.plugins) ? marketplace.plugins[0] : undefined;
    if (!isPlainObject(plugin)) {
      fail('.omp-plugin/marketplace.json: plugins[0] must be an object');
    } else {
      if (plugin.version !== version) {
        fail(`.omp-plugin/marketplace.json: plugins[0].version ${JSON.stringify(plugin.version)} must equal package.json version ${JSON.stringify(version)}`);
      }
      const source = plugin.source;
      const expectedSource = { source: 'github', repo: 'psilooo/omp-peers', ref: `v${version}` };
      if (!isPlainObject(source)) {
        fail(`.omp-plugin/marketplace.json: plugins[0].source must be exactly ${JSON.stringify(expectedSource)}`);
      } else {
        const keys = Object.keys(source).sort();
        const expectedKeys = Object.keys(expectedSource).sort();
        if (JSON.stringify(keys) !== JSON.stringify(expectedKeys) || expectedKeys.some((key) => source[key] !== expectedSource[key])) {
          fail(`.omp-plugin/marketplace.json: plugins[0].source must be exactly ${JSON.stringify(expectedSource)}, found ${JSON.stringify(source)}`);
        }
      }
    }
  }

  let changelog;
  try {
    changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
  } catch (error) {
    fail(`CHANGELOG.md: not readable (${error.message})`);
  }
  if (changelog !== undefined && version) {
    const heading = new RegExp(`^#{1,6}[ \\t]+[^\\n]*\\b${version.replace(/\./g, '\\.')}\\b`, 'm');
    if (!heading.test(changelog)) {
      fail(`CHANGELOG.md: no heading found for version ${version}`);
    }
  }
}

if (violations.length > 0) {
  for (const line of violations) console.error(line);
  process.exit(1);
}
process.exit(0);
