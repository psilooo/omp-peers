#!/usr/bin/env node
/**
 * Scripted fake host behind a spawned fixture child.
 *
 * Loads the built dist/extension.js on the contract fake host, arms it with
 * session_start, then serves stdio JSON lines from the parent fixture until
 * stop:
 *   {id, cmd: 'emit', eventType, payload?}  -> {id, ok, result}
 *   {id, cmd: 'tool', name, params?}        -> {id, ok, result}
 *   {id, cmd: 'stop'}                       -> {id, ok}, shutdown, exit
 * Unsolicited lines: {event: 'ready', armError?} and {event: 'fatal', error}.
 * Stdout carries protocol lines only; diagnostics go to stderr.
 */

import { createInterface } from 'node:readline';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createFakeHost } from './two-child.mjs';

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'extension.js');
const PEER_DIR = process.env.OMP_PEERS_DIR;
const LABEL = process.env.OMP_PEERS_LABEL;

function errorMessage(err) {
  return err instanceof Error ? err.message : String(err);
}

function send(line) {
  return new Promise((done) => {
    process.stdout.write(`${JSON.stringify(line)}\n`, done);
  });
}

if (typeof PEER_DIR !== 'string' || PEER_DIR === '' || !isAbsolute(PEER_DIR)) {
  process.stderr.write('child-runner: OMP_PEERS_DIR must be an absolute path\n');
  process.exit(2);
}

const fake = createFakeHost();
const tools = new Map();
const registerTool = fake.host.registerTool;
fake.host.registerTool = (tool) => {
  registerTool(tool);
  if (tool !== null && typeof tool === 'object' && typeof tool.name === 'string') {
    tools.set(tool.name, tool);
  }
};
if (typeof LABEL === 'string' && LABEL !== '') {
  fake.host.getSessionName = () => LABEL;
  fake.ctx.sessionManager.getSessionName = () => LABEL;
}

let toolSeq = 0;
let shuttingDown = false;

async function runTool(msg) {
  const name = typeof msg.name === 'string' ? msg.name : '';
  const tool = tools.get(name);
  if (tool === undefined) throw new Error(`no registered tool: ${name === '' ? String(msg.name) : name}`);
  toolSeq += 1;
  const params = msg.params !== null && typeof msg.params === 'object' ? msg.params : {};
  const result = await tool.execute(`fixture-${toolSeq}`, params);
  const content = result !== null && typeof result === 'object' && Array.isArray(result.content) ? result.content : [];
  const texts = [];
  for (const part of content) {
    if (part !== null && typeof part === 'object' && part.type === 'text' && typeof part.text === 'string') {
      texts.push(part.text);
    }
  }
  return texts.join('\n');
}

async function fatal(message) {
  await send({ event: 'fatal', error: message });
  process.exit(1);
}

async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    await fake.emit('session_shutdown', undefined);
  } catch {
    // Teardown must never block exit.
  }
  try {
    await new Promise((done) => process.stdout.write('', done));
  } catch {
    // Broken pipe; exit anyway.
  }
  process.exit(0);
}

async function boot() {
  let module;
  try {
    module = await import(pathToFileURL(ENTRY).href);
  } catch (err) {
    await fatal(`cannot load ${ENTRY}: ${errorMessage(err)}`);
    return;
  }
  if (typeof module.default !== 'function') {
    await fatal(`${ENTRY} has no default function export`);
    return;
  }
  try {
    await module.default(fake.host);
  } catch (err) {
    await fatal(`factory failed: ${errorMessage(err)}`);
    return;
  }
  let armError;
  try {
    await fake.emit('session_start', { reason: 'startup' });
  } catch (err) {
    armError = errorMessage(err);
  }
  await send(armError === undefined ? { event: 'ready' } : { event: 'ready', armError });
}

async function handleLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg === null || typeof msg !== 'object' || typeof msg.id !== 'number') return;
  const { id } = msg;
  try {
    if (msg.cmd === 'emit') {
      await send({ id, ok: true, result: await fake.emit(msg.eventType, msg.payload) });
    } else if (msg.cmd === 'tool') {
      await send({ id, ok: true, result: await runTool(msg) });
    } else if (msg.cmd === 'stop') {
      await send({ id, ok: true, result: null });
      await shutdown();
    } else {
      await send({ id, ok: false, error: `unknown cmd: ${String(msg.cmd)}` });
    }
  } catch (err) {
    await send({ id, ok: false, error: errorMessage(err) });
  }
}

const input = createInterface({ input: process.stdin });
let chain = boot();
input.on('line', (line) => {
  chain = chain.then(() => handleLine(line));
});
input.on('close', () => {
  chain = chain.then(() => shutdown());
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    chain = chain.then(() => shutdown());
  });
}
