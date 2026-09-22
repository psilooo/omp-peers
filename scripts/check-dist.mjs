#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const result = spawnSync('git', ['status', '--porcelain', '--untracked-files=all', '--', 'dist'], {
  cwd: root,
  encoding: 'utf8',
});

if (result.error || result.status !== 0) {
  console.error(result.error ? `git status failed: ${result.error.message}` : `git status failed: ${result.stderr.trim() || `exit ${result.status}`}`);
  process.exit(1);
}

const lines = result.stdout.split('\n').filter((line) => line.length > 0);
if (lines.length > 0) {
  for (const line of lines) console.error(line);
  process.exit(1);
}
process.exit(0);
