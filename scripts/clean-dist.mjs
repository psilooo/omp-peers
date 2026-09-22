#!/usr/bin/env node
import { rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
try {
  await rm(dist, { recursive: true, force: true });
} catch (error) {
  console.error(`clean-dist: failed to remove ${dist}: ${error.message}`);
  process.exit(1);
}
process.exit(0);
