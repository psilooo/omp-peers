#!/usr/bin/env node
/**
 * Public fake-host smoke harness for the built extension entry (plan section 5).
 *
 * Usage:
 *   node scripts/smoke-host.mjs [--entry <absolute path>] [--scenario <name>|all]
 *                               [--version <value>]
 *
 * --entry     absolute path to the built extension module (default:
 *             dist/extension.js resolved from this script's repository root).
 * --scenario  scenario name, its letter alias, or all (default: all).
 * --version   overrides scenario a's pi.VERSION (default: OMP_SMOKE_VERSION env,
 *             then 18.2.6). Scenario a arms only when the resolved version parses
 *             inside [18.2.6, 19.0.0); any other resolved value asserts inert
 *             fail-closed behavior instead.
 *
 * Scenarios (aliases a-h):
 *   a-supported                the resolved pi.VERSION arms at session_start when
 *                              supported: peer tools on both surfaces, peers command,
 *                              presence record under a fresh temporary OMP_PEERS_DIR
 *                              (removed afterwards); an unsupported resolved version
 *                              asserts inert.
 *   b-unknown-version          pi.VERSION is an unknown string.
 *   c-malformed-version        pi.VERSION is non-string, then unparseable.
 *   d-missing-factory-methods  no registerTool, no sendUserMessage, no registerCommand,
 *                              no on, no logger.warn; then a null, undefined and
 *                              string factory argument.
 *   e-missing-session-methods  sessionManager without getBranch/getEntries/getSessionId.
 *   f-restricted-tools         registerTool succeeds but neither tool surface shows the
 *                              peer names; then only getAllTools drops them; then only
 *                              getActiveTools drops them; then registerTool throws.
 *   g-version-19               pi.VERSION 19.0.0.
 *   h-below-floor-version      pi.VERSION 18.2.5, below the 18.2.6 floor.
 *
 * Every failure variant must finish without throwing, never converge the peer tools
 * on both tool surfaces (outside scenario f never expose a peer tool on either
 * surface and never call registerTool with a peer name), and leave its temporary
 * OMP_PEERS_DIR completely empty. One result line per scenario on stdout. Exit 0
 * when all pass, 1 when any fails, 2 on usage or environment errors.
 */

import { mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PEER_TOOLS = ['peer_send', 'peer_request', 'peer_status'];
const COMMAND_NAME = 'peers';

// Convergence polling is capped at 1 second inside the extension; the settle
// window must outlast it so a non-converged surface is observed as final.
const SETTLE_WITH_START_MS = 1600;
const SETTLE_WITHOUT_START_MS = 250;
const TOOLS_DEADLINE_MS = 3000;
const RECORD_DEADLINE_MS = 5000;
const POLL_MS = 50;

const USAGE =
  'usage: node scripts/smoke-host.mjs [--entry <absolute path>] [--scenario <name>|all] [--version <value>]';

class UsageError extends Error {}

const SCENARIO_NAMES = [
  'a-supported',
  'b-unknown-version',
  'c-malformed-version',
  'd-missing-factory-methods',
  'e-missing-session-methods',
  'f-restricted-tools',
  'g-version-19',
  'h-below-floor-version',
];

const BASE_KNOBS = {
  version: '18.2.6',
  registerTool: 'normal',
  sendUserMessage: 'present',
  sessionMethods: 'full',
  sessionName: 'smoke-alpha',
  sessionId: 'smoke-session-1',
  // Lazy top-level transcript path: no sibling `<dir>.jsonl` exists, so the
  // artifact-directory rule classifies it top-level, and the file need not exist.
  sessionFile: join(tmpdir(), 'omp-peers-smoke-classify', 'smoke-session.jsonl'),
  cwd: REPO_ROOT,
  registerCommand: 'present',
  on: 'present',
  logger: 'present',
  restrictedSurface: 'none',
};

function knobs(overrides) {
  return { ...BASE_KNOBS, ...overrides };
}

const SCENARIO_VARIANTS = {
  'a-supported': (version) => {
    const verdict = classifyVersion(version);
    if (verdict.supported) return [{ label: 'supported', knobs: knobs({ version }), armed: true }];
    return [{ label: 'fail-closed', knobs: knobs({ version }), ok: verdict.reason }];
  },
  'b-unknown-version': [
    { label: 'unknown string', knobs: knobs({ version: 'unknown' }), ok: 'inert: unknown version string' },
  ],
  'c-malformed-version': [
    { label: 'non-string', knobs: knobs({ version: 1826 }), ok: 'inert: non-string version' },
    { label: 'unparseable', knobs: knobs({ version: '18.2.6.7' }), ok: 'inert: unparseable version' },
  ],
  'd-missing-factory-methods': [
    { label: 'no registerTool', knobs: knobs({ registerTool: 'absent' }), ok: 'inert: registerTool missing' },
    { label: 'no sendUserMessage', knobs: knobs({ sendUserMessage: 'absent' }), ok: 'inert: sendUserMessage missing' },
    { label: 'no registerCommand', knobs: knobs({ registerCommand: 'absent' }), ok: 'inert: registerCommand missing' },
    { label: 'no on', knobs: knobs({ on: 'absent' }), ok: 'inert: on missing' },
    { label: 'no logger.warn', knobs: knobs({ logger: 'absent' }), ok: 'inert: logger.warn missing' },
    { label: 'null factory argument', knobs: knobs({}), factoryArg: null, ok: 'inert: factory argument is null' },
    {
      label: 'undefined factory argument',
      knobs: knobs({}),
      factoryArg: undefined,
      ok: 'inert: factory argument is undefined',
    },
    {
      label: 'string factory argument',
      knobs: knobs({}),
      factoryArg: 'peers',
      ok: 'inert: factory argument is a string',
    },
  ],
  'e-missing-session-methods': [
    {
      label: 'reduced manager',
      knobs: knobs({ sessionMethods: 'reduced' }),
      ok: 'inert: sessionManager lacks getBranch/getEntries/getSessionId',
    },
  ],
  'f-restricted-tools': [
    {
      label: 'surfaces drop tools',
      knobs: knobs({ registerTool: 'drop' }),
      allowAttempts: true,
      ok: 'inert: tool surfaces never converged',
    },
    {
      label: 'registerTool throws',
      knobs: knobs({ registerTool: 'throw' }),
      allowAttempts: true,
      ok: 'inert: registerTool threw',
    },
    {
      label: 'getAllTools drops',
      knobs: knobs({ restrictedSurface: 'live' }),
      allowAttempts: true,
      ok: 'inert: getAllTools never showed the peer tools',
    },
    {
      label: 'getActiveTools drops',
      knobs: knobs({ restrictedSurface: 'active' }),
      allowAttempts: true,
      ok: 'inert: getActiveTools never showed the peer tools',
    },
  ],
  'g-version-19': [{ label: '19.0.0', knobs: knobs({ version: '19.0.0' }), ok: 'inert: version 19.0.0 out of range' }],
  'h-below-floor-version': [
    { label: '18.2.5', knobs: knobs({ version: '18.2.5' }), ok: 'inert: version 18.2.5 below floor' },
  ],
};

function parseArgs(argv) {
  let entry;
  let scenario = 'all';
  let version;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg !== '--entry' && arg !== '--scenario' && arg !== '--version') {
      throw new UsageError(`unknown argument: ${arg}`);
    }
    const value = argv[i + 1];
    if (value === undefined) throw new UsageError(`missing value for ${arg}`);
    i += 1;
    if (arg === '--entry') entry = value;
    else if (arg === '--scenario') scenario = value;
    else version = value;
  }
  if (entry !== undefined && !isAbsolute(entry)) {
    throw new UsageError('--entry must be an absolute path');
  }
  let selected;
  if (scenario === 'all') {
    selected = SCENARIO_NAMES;
  } else {
    const exact = SCENARIO_NAMES.includes(scenario) ? scenario : undefined;
    const byLetter = SCENARIO_NAMES.find((name) => name.split('-')[0] === scenario);
    const name = exact ?? byLetter;
    if (name === undefined) throw new UsageError(`unknown scenario: ${scenario}`);
    selected = [name];
  }
  return { entry, selected, version };
}

function parseHostVersion(raw) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$/.exec(String(raw).trim());
  if (match === null) return undefined;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

// Mirrors the extension's version gate: supported means parseable [18.2.6, 19.0.0).
function classifyVersion(raw) {
  const parsed = parseHostVersion(raw);
  if (parsed === undefined) return { supported: false, reason: `inert: version ${raw} unparseable` };
  const [major, minor, patch] = parsed;
  if (major >= 19) return { supported: false, reason: `inert: version ${raw} out of range` };
  if (major !== 18 || minor < 2 || (minor === 2 && patch < 6)) {
    return { supported: false, reason: `inert: version ${raw} below floor` };
  }
  return { supported: true };
}

function errorMessage(err) {
  return err instanceof Error ? err.message : String(err);
}

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

async function until(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await predicate()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(POLL_MS);
  }
}

// Background extension failures land here instead of killing the run; each
// scenario claims whatever accumulated during its own window.
const backgroundErrors = [];
process.on('unhandledRejection', (reason) => backgroundErrors.push(errorMessage(reason)));
process.on('uncaughtException', (err) => backgroundErrors.push(errorMessage(err)));
function takeBackgroundErrors() {
  return backgroundErrors.splice(0, backgroundErrors.length);
}

// A short base keeps `<base>/peers/<pid>-<32 hex>.sock` under the 103-byte
// macOS pathname ceiling; the default macOS TMPDIR under /var/folders can
// overrun it. Windows named pipes have no pathname-length problem.
const STATE_BASE = process.platform === 'win32' ? tmpdir() : '/tmp';

async function makeStateDir() {
  return mkdtemp(join(STATE_BASE, 'omp-peers-smoke-'));
}

function setPeersDir(dir) {
  const previous = process.env.OMP_PEERS_DIR;
  process.env.OMP_PEERS_DIR = dir;
  return () => {
    if (previous === undefined) delete process.env.OMP_PEERS_DIR;
    else process.env.OMP_PEERS_DIR = previous;
  };
}

async function listState(dir) {
  try {
    return await readdir(dir, { recursive: true });
  } catch (err) {
    if (err !== null && typeof err === 'object' && err.code === 'ENOENT') return [];
    throw err;
  }
}

async function findRecord(dir) {
  const entries = await listState(dir);
  return entries.find((entry) => entry.endsWith('.json'));
}

/**
 * Structural fake host with per-scenario knobs. registerTool modes:
 * 'normal' records and surfaces, 'drop' records but never surfaces (restricted
 * host), 'throw' throws, 'absent' leaves the method off the object entirely.
 * registerCommand/on 'absent' leave the method off the object; logger 'absent'
 * omits the warn method; restrictedSurface 'live' or 'active' hides the peer
 * names from exactly that one tool view.
 */
function createFakeHost(knobs) {
  const attempted = [];
  const surfaced = new Set(['bash', 'read']);
  const commands = new Map();
  const handlers = new Map();
  const warnings = [];
  const sent = [];
  const visibleOn = (surface) =>
    [...surfaced].filter((name) => knobs.restrictedSurface !== surface || !PEER_TOOLS.includes(name));
  const liveNames = () => visibleOn('live');
  const activeNames = () => visibleOn('active');
  const logger = { info: () => {}, error: () => {} };
  if (knobs.logger !== 'absent') {
    logger.warn = (message) => {
      warnings.push(String(message));
    };
  }
  const host = {
    getAllTools: () => liveNames().map((name) => ({ name })),
    getActiveTools: () => activeNames(),
    getSessionName: () => knobs.sessionName,
    logger,
    pi: { VERSION: knobs.version },
  };
  if (knobs.on !== 'absent') {
    host.on = (event, handler) => {
      const list = handlers.get(event) ?? [];
      list.push(handler);
      handlers.set(event, list);
    };
  }
  if (knobs.registerCommand !== 'absent') {
    host.registerCommand = (name, opts) => {
      commands.set(name, opts);
    };
  }
  if (knobs.sendUserMessage !== 'absent') {
    host.sendUserMessage = (content, options) => {
      sent.push({ content, options });
    };
  }
  if (knobs.registerTool === 'absent') {
    // registerTool intentionally missing.
  } else if (knobs.registerTool === 'throw') {
    host.registerTool = () => {
      throw new Error('restricted host refused registerTool');
    };
  } else {
    host.registerTool = (tool) => {
      const name = tool !== null && typeof tool === 'object' && typeof tool.name === 'string' ? tool.name : '';
      attempted.push(name);
      if (knobs.registerTool !== 'drop') surfaced.add(name);
    };
  }
  return { host, attempted, surfaced, commands, handlers, warnings, sent, liveNames, activeNames };
}

function createFakeCtx(knobs) {
  const timers = new Set();
  const sessionManager =
    knobs.sessionMethods === 'reduced'
      ? { getSessionName: () => knobs.sessionName }
      : {
          getSessionId: () => knobs.sessionId,
          getSessionName: () => knobs.sessionName,
          getHeader: () => undefined,
          titleSource: undefined,
          getBranch: () => [],
          getEntries: () => [],
          // Present on the real host manager; supplies the lazy .jsonl path
          // origin classification reads.
          getSessionFile: () => knobs.sessionFile,
        };
  return {
    cwd: knobs.cwd,
    mode: 'interactive',
    ui: {
      notify: () => {},
      getEditorText: () => '',
      select: async () => undefined,
    },
    sessionManager,
    model: { id: 'smoke-model' },
    isIdle: () => true,
    setInterval(callback, ms) {
      const handle = setInterval(callback, ms);
      timers.add(handle);
      return handle;
    },
    setTimeout(callback, ms) {
      const handle = setTimeout(callback, ms);
      timers.add(handle);
      return handle;
    },
    clearTimer(handle) {
      timers.delete(handle);
      clearTimeout(handle);
      clearInterval(handle);
    },
    clearAllTimers() {
      for (const handle of timers) {
        clearTimeout(handle);
        clearInterval(handle);
      }
      timers.clear();
    },
  };
}

function handlersOf(faux, event) {
  return faux.handlers.get(event) ?? [];
}

async function shutdownQuietly(faux, ctx) {
  for (const handler of handlersOf(faux, 'session_shutdown')) {
    try {
      await handler(undefined, ctx);
    } catch {
      // Shutdown must not throw into the harness.
    }
  }
}

async function checkArmed(faux, ctx, dir, problems) {
  const startHandlers = handlersOf(faux, 'session_start');
  if (startHandlers.length === 0) {
    problems.push('no session_start handler wired');
    return;
  }
  try {
    for (const handler of startHandlers) await handler(undefined, ctx);
  } catch (err) {
    problems.push(`session_start threw: ${errorMessage(err)}`);
    return;
  }
  const converged = await until(() => {
    const live = faux.liveNames();
    const active = faux.activeNames();
    return PEER_TOOLS.every((name) => live.includes(name) && active.includes(name));
  }, TOOLS_DEADLINE_MS);
  if (!converged) {
    const attempted = faux.attempted.filter((name) => PEER_TOOLS.includes(name));
    problems.push(`peer tools never converged on both surfaces (attempted: ${attempted.join(', ') || 'none'})`);
  }
  if (converged) {
    const found = await until(async () => (await findRecord(dir)) !== undefined, RECORD_DEADLINE_MS);
    if (!found) {
      const entries = await listState(dir);
      problems.push(`no presence record under OMP_PEERS_DIR (entries: ${entries.join(', ') || 'none'})`);
    }
  }
  if (!faux.commands.has(COMMAND_NAME)) problems.push(`${COMMAND_NAME} command not registered`);
}

async function checkInert(variant, faux, ctx, dir, problems) {
  const startHandlers = handlersOf(faux, 'session_start');
  try {
    for (const handler of startHandlers) await handler(undefined, ctx);
  } catch (err) {
    problems.push(`session_start threw: ${errorMessage(err)}`);
    return;
  }
  await sleep(startHandlers.length > 0 ? SETTLE_WITH_START_MS : SETTLE_WITHOUT_START_MS);
  const live = faux.liveNames();
  const active = faux.activeNames();
  if (variant.knobs.restrictedSurface === 'none') {
    const exposed = PEER_TOOLS.filter((name) => live.includes(name) || active.includes(name));
    if (exposed.length > 0) problems.push(`peer tools exposed on tool surfaces: ${exposed.join(', ')}`);
  } else {
    const restricted = variant.knobs.restrictedSurface === 'live' ? live : active;
    const leaked = PEER_TOOLS.filter((name) => restricted.includes(name));
    if (leaked.length > 0) problems.push(`peer tools exposed on restricted surface: ${leaked.join(', ')}`);
    const open = variant.knobs.restrictedSurface === 'live' ? active : live;
    const missing = PEER_TOOLS.filter((name) => !open.includes(name));
    if (missing.length > 0) problems.push(`peer tools missing from unrestricted surface: ${missing.join(', ')}`);
  }
  if (!variant.allowAttempts) {
    const attempted = faux.attempted.filter((name) => PEER_TOOLS.includes(name));
    if (attempted.length > 0) problems.push(`peer tools registered: ${attempted.join(', ')}`);
  }
  if ('factoryArg' in variant) {
    if (faux.commands.size > 0) problems.push('peers command registered despite a rejected factory argument');
    if (faux.handlers.size > 0) problems.push('event handlers wired despite a rejected factory argument');
  }
  const entries = await listState(dir);
  if (entries.length > 0) problems.push(`peer state left in OMP_PEERS_DIR: ${entries.slice(0, 5).join(', ')}`);
}

async function runVariant(extension, variant) {
  const dir = await makeStateDir();
  const restore = setPeersDir(dir);
  const faux = createFakeHost(variant.knobs);
  const ctx = createFakeCtx(variant.knobs);
  const problems = [];
  try {
    try {
      const target = 'factoryArg' in variant ? variant.factoryArg : faux.host;
      await extension(target);
    } catch (err) {
      problems.push(`factory threw: ${errorMessage(err)}`);
    }
    if (problems.length === 0) {
      if (variant.armed) await checkArmed(faux, ctx, dir, problems);
      else await checkInert(variant, faux, ctx, dir, problems);
    }
    const background = takeBackgroundErrors();
    if (background.length > 0) problems.push(`background error: ${background.join(' | ')}`);
  } finally {
    await shutdownQuietly(faux, ctx);
    ctx.clearAllTimers();
    restore();
    try {
      await rm(dir, { recursive: true, force: true });
    } catch (err) {
      problems.push(`cleanup failed: ${errorMessage(err)}`);
    }
    try {
      await readdir(dir);
      problems.push('temporary OMP_PEERS_DIR survived cleanup');
    } catch (err) {
      if (err !== null && typeof err === 'object' && err.code !== 'ENOENT') {
        problems.push(`cleanup verify failed: ${errorMessage(err)}`);
      }
    }
    const late = takeBackgroundErrors();
    if (late.length > 0) problems.push(`background error: ${late.join(' | ')}`);
  }
  if (problems.length > 0) return { pass: false, reason: problems.join('; ') };
  if (variant.armed) {
    return {
      pass: true,
      reason: 'armed: peer tools converged on both surfaces, presence record written, peers command registered',
    };
  }
  return { pass: true, reason: variant.ok };
}

async function runScenario(name, extension, version) {
  const definition = SCENARIO_VARIANTS[name];
  const variants = typeof definition === 'function' ? definition(version) : definition;
  const labeled = variants.length > 1;
  const results = [];
  for (const variant of variants) {
    const outcome = await runVariant(extension, variant);
    results.push(labeled ? { ...outcome, reason: `[${variant.label}] ${outcome.reason}` } : outcome);
  }
  const failed = results.filter((result) => !result.pass);
  if (failed.length === 0) return { pass: true, reason: results.map((result) => result.reason).join('; ') };
  return { pass: false, reason: failed.map((result) => result.reason).join('; ') };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const override = [args.version, process.env.OMP_SMOKE_VERSION].find(
    (value) => value !== undefined && value.trim() !== ''
  );
  const version = override ?? BASE_KNOBS.version;
  const entry = args.entry ?? join(REPO_ROOT, 'dist', 'extension.js');
  try {
    await stat(entry);
  } catch {
    throw new UsageError(`entry not found: ${entry}`);
  }
  let module;
  try {
    module = await import(pathToFileURL(entry).href);
  } catch (err) {
    throw new UsageError(`cannot load entry ${entry}: ${errorMessage(err)}`);
  }
  if (typeof module.default !== 'function') {
    throw new UsageError(`entry has no default function export: ${entry}`);
  }
  const extension = module.default;
  let anyFailed = false;
  for (const name of args.selected) {
    const outcome = await runScenario(name, extension, version);
    console.log(`${outcome.pass ? 'pass' : 'fail'} ${name}: ${outcome.reason}`);
    if (!outcome.pass) anyFailed = true;
  }
  return anyFailed ? 1 : 0;
}

let exitCode = 0;
try {
  exitCode = await main();
} catch (err) {
  console.error(err instanceof UsageError ? err.message : `smoke-host internal error: ${errorMessage(err)}`);
  console.error(USAGE);
  exitCode = 2;
}
process.exit(exitCode);
