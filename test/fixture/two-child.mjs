/**
 * Two-child runtime fixture for the peers extension.
 *
 * createFakeHost exposes the contract ExtensionHostLike/CommandContextLike
 * surface in process: captured handlers, captured sendUserMessage calls and
 * notifications, and an emit() driver. startChild/startPair spawn real OS
 * processes running the built dist/extension.js behind the scripted fake
 * host in child-runner.mjs, driven over stdio JSON lines, so tests exercise
 * real Unix sockets end to end. macOS is the only target platform; win32 is
 * unsupported and fails closed.
 */

import { spawn } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readdir, rm, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const FIXTURE_DIR = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(FIXTURE_DIR, 'child-runner.mjs');
const RECORD_DIR = 'peers';
const READY_TIMEOUT_MS = 15_000;
const STOP_TIMEOUT_MS = 5_000;
const POLL_MS = 25;
const UNIX_ENDPOINT_CEILING = process.platform === 'darwin' ? 103 : 107;
// A short base keeps `<base>/peers/<pid>-<32 hex>.sock` under the 103-byte
// macOS pathname ceiling; the default macOS TMPDIR under /var/folders can
// overrun it.
const STATE_BASE = '/tmp';
const BASELINE_TOOLS = ['bash', 'read'];
const SUPPORTED_VERSION = '18.2.6';
const REGISTER_TOOL_MODES = ['ok', 'throw', 'drop'];
const SESSION_MODES = ['full', 'reduced'];

const liveChildren = new Set();
let exitHookInstalled = false;

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function errorMessage(err) {
  return err instanceof Error ? err.message : String(err);
}

/**
 * In-process scripted host. Knobs: version (pi.pi.VERSION, present when the
 * key is passed), registerTool 'ok' | 'throw' | 'drop', sendUserMessage
 * presence, and a 'full' (top-level classifiable) or 'reduced' session
 * manager.
 */
export function createFakeHost(options = {}) {
  const registerMode = options.registerTool ?? 'ok';
  if (!REGISTER_TOOL_MODES.includes(registerMode)) {
    throw new TypeError(`registerTool must be one of: ${REGISTER_TOOL_MODES.join(', ')}`);
  }
  const sessionMode = options.sessionManager ?? 'full';
  if (!SESSION_MODES.includes(sessionMode)) {
    throw new TypeError(`sessionManager must be one of: ${SESSION_MODES.join(', ')}`);
  }
  const sendPresent = options.sendUserMessage === undefined ? true : Boolean(options.sendUserMessage);
  const version = 'version' in options ? options.version : SUPPORTED_VERSION;

  const handlers = new Map();
  const calls = { sendUserMessage: [], notifies: [] };
  const commands = new Map();
  const tools = new Map();
  const surfaced = new Set(BASELINE_TOOLS);

  const host = {
    on(event, handler) {
      const list = handlers.get(event) ?? [];
      list.push(handler);
      handlers.set(event, list);
    },
    registerCommand(name, opts) {
      commands.set(name, opts);
    },
    registerTool(tool) {
      if (registerMode === 'throw') throw new Error('fixture host refused registerTool');
      tools.set(tool.name, tool);
      if (registerMode !== 'drop') surfaced.add(tool.name);
    },
    getAllTools: () => [...surfaced].map((name) => ({ name })),
    getActiveTools: () => [...surfaced],
    getSessionName: () => undefined,
    logger: { warn() {}, info() {}, error() {} },
    pi: { VERSION: version },
  };
  if (sendPresent) {
    host.sendUserMessage = (content, sendOptions) => {
      calls.sendUserMessage.push({ content, options: sendOptions });
    };
  }

  const ctx = {
    cwd: process.cwd(),
    mode: 'interactive',
    ui: {
      notify: (message) => {
        calls.notifies.push(String(message));
      },
      select: async () => undefined,
      getEditorText: () => '',
    },
    sessionManager:
      sessionMode === 'full'
        ? {
            getSessionId: () => 'fixture-session-1',
            getSessionName: () => undefined,
            getHeader: () => undefined,
            titleSource: undefined,
            getBranch: () => [],
            getEntries: () => [],
            // Lazy top-level transcript path: no sibling `<dir>.jsonl` exists,
            // so the artifact-directory rule classifies it top-level, and the
            // file need not exist.
            getSessionFile: () => join(tmpdir(), 'omp-peers-fixture-classify', 'fixture-session.jsonl'),
          }
        : { getSessionName: () => undefined },
    model: { id: 'fixture-model' },
    isIdle: () => true,
    setInterval(callback, ms) {
      return setInterval(callback, ms);
    },
    setTimeout(callback, ms) {
      return setTimeout(callback, ms);
    },
    clearTimer(timer) {
      clearTimeout(timer);
      clearInterval(timer);
    },
  };

  async function emit(eventType, payload) {
    const list = handlers.get(eventType) ?? [];
    let result;
    for (const handler of list) {
      const value = await handler(payload, ctx);
      if (value !== undefined) result = value;
    }
    return result;
  }

  return { host, ctx, handlers, calls, emit };
}

function assertSupportedPlatform() {
  if (process.platform === 'win32') {
    throw new TypeError('two-child fixture is POSIX-only (macOS); win32 is unsupported');
  }
}

function childDiagnostics(label, pid, stderrLines, noise) {
  const who = label === undefined ? `pid ${pid}` : `"${label}" pid ${pid}`;
  const parts = [`child ${who}`];
  if (stderrLines.length > 0) parts.push(`stderr: ${stderrLines.slice(-5).join(' | ')}`);
  if (noise.length > 0) parts.push(`stdout: ${noise.slice(-3).join(' | ')}`);
  return parts.join('; ');
}

async function withTimeout(promise, timeoutMs, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message())), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function trackChild(child) {
  liveChildren.add(child);
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.once('exit', () => {
    for (const tracked of liveChildren) {
      try {
        tracked.kill('SIGTERM');
      } catch {
        // Best effort during process exit.
      }
    }
  });
}

/**
 * Create/validate the fixture state root (POSIX). Never chmods a directory
 * it did not create: a shared parent (say /tmp itself) must not be touched,
 * and a wrong-mode directory fails fast with the same policy the extension
 * applies.
 */
async function preparePeerDir(dir) {
  let stats;
  let existed = true;
  try {
    stats = await lstat(dir);
  } catch {
    existed = false;
  }
  if (!existed) {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await chmod(dir, 0o700);
    return true;
  }
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new TypeError(`peerDir must be a real directory: ${dir}`);
  }
  if ((stats.mode & 0o077) !== 0) {
    const mode = (stats.mode & 0o777).toString(8);
    throw new TypeError(`peerDir must be owner-only (mode 0700), got ${mode}: ${dir}; pass a fresh mkdtemp directory`);
  }
  return false;
}

function assertEndpointFits(peerDir) {
  if (UNIX_ENDPOINT_CEILING === undefined) return;
  const longest = join(peerDir, RECORD_DIR, `${'9'.repeat(10)}-${'f'.repeat(32)}.sock`);
  if (longest.length > UNIX_ENDPOINT_CEILING) {
    throw new TypeError(
      `peerDir leaves no room for a ${UNIX_ENDPOINT_CEILING}-byte unix socket path (${longest.length} bytes): ${longest}`,
    );
  }
}

/** Remove only this child's exact record and endpoint leftovers by pid prefix. */
async function sweepPeerDir(peerDir, pid) {
  for (const dir of [join(peerDir, RECORD_DIR), peerDir]) {
    let entries;
    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.startsWith(`${pid}-`) && (entry.endsWith('.json') || entry.endsWith('.sock'))) {
        await rm(join(dir, entry), { force: true }).catch(() => undefined);
      }
    }
  }
}

async function removeDir(dir) {
  await rm(dir, { recursive: true, force: true }).catch(() => undefined);
}

/**
 * Spawn one real child process running dist/extension.js behind the scripted
 * fake host. `ready` settles once the child reports armed and its presence
 * record exists; stop() shuts the child down and sweeps its leftovers,
 * stopWithoutSweep() shuts down without sweeping so a test can observe the
 * plugin's own cleanup first, and the same cleanup runs when ready fails.
 */
export async function startChild(options) {
  assertSupportedPlatform();
  const opts = options ?? {};
  if (typeof opts.peerDir !== 'string' || opts.peerDir === '') {
    throw new TypeError('startChild requires options.peerDir');
  }
  const label = typeof opts.label === 'string' && opts.label !== '' ? opts.label : undefined;
  const peerDir = resolve(opts.peerDir);
  assertEndpointFits(peerDir);
  const createdDir = await preparePeerDir(peerDir);

  const child = spawn(process.execPath, [RUNNER], {
    env: {
      ...process.env,
      OMP_PEERS_DIR: peerDir,
      ...(label === undefined ? {} : { OMP_PEERS_LABEL: label }),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  trackChild(child);

  const pending = new Map();
  const stderrLines = [];
  const noise = [];
  let nextId = 1;
  let exited = false;
  let stopPromise;

  const diag = () => childDiagnostics(label, child.pid, stderrLines, noise);
  const pushNoise = (line) => {
    noise.push(line);
    if (noise.length > 10) noise.shift();
  };

  let bootResolve = () => {};
  let bootReject = () => {};
  const boot = new Promise((res, rej) => {
    bootResolve = res;
    bootReject = rej;
  });

  const stdout = createInterface({ input: child.stdout });
  stdout.on('line', (line) => {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      pushNoise(line);
      return;
    }
    if (msg === null || typeof msg !== 'object') {
      pushNoise(line);
      return;
    }
    if (msg.event === 'ready') {
      bootResolve(msg);
      return;
    }
    if (msg.event === 'fatal') {
      bootReject(new Error(String(msg.error ?? 'child reported fatal error')));
      return;
    }
    if (typeof msg.id === 'number') {
      const waiter = pending.get(msg.id);
      if (waiter === undefined) return;
      pending.delete(msg.id);
      if (msg.ok === true) waiter.resolve(msg.result);
      else waiter.reject(new Error(String(msg.error ?? 'child command failed')));
      return;
    }
    pushNoise(line);
  });

  const stderr = createInterface({ input: child.stderr });
  stderr.on('line', (line) => {
    stderrLines.push(line);
    if (stderrLines.length > 20) stderrLines.shift();
  });

  function failPending(reason) {
    for (const [, waiter] of pending) waiter.reject(reason);
    pending.clear();
  }

  child.on('error', (err) => {
    bootReject(err);
    failPending(err);
  });
  child.on('exit', (code, signal) => {
    exited = true;
    const outcome = `code ${code ?? 'null'} signal ${signal ?? 'null'}`;
    bootReject(new Error(`child exited before ready (${outcome}); ${diag()}`));
    failPending(new Error(`child exited (${outcome}); ${diag()}`));
  });
  child.stdin.on('error', (err) => {
    failPending(err);
  });

  function request(body) {
    return new Promise((resolveCall, rejectCall) => {
      if (exited) {
        rejectCall(new Error(`child not running; ${diag()}`));
        return;
      }
      const id = nextId;
      nextId += 1;
      pending.set(id, { resolve: resolveCall, reject: rejectCall });
      child.stdin.write(`${JSON.stringify({ id, ...body })}\n`, (err) => {
        if (err) {
          if (pending.delete(id)) rejectCall(err);
        }
      });
    });
  }

  function waitForExit(timeoutMs) {
    if (exited) return Promise.resolve();
    return new Promise((done) => {
      const timer = setTimeout(() => {
        child.removeListener('exit', onExit);
        done();
      }, timeoutMs);
      function onExit() {
        clearTimeout(timer);
        done();
      }
      child.once('exit', onExit);
    });
  }

  function killAndSweep() {
    try {
      child.kill('SIGKILL');
    } catch {
      // Already gone.
    }
  }

  async function runStop() {
    if (!exited) {
      try {
        child.stdin.write(`${JSON.stringify({ id: nextId, cmd: 'stop' })}\n`);
        nextId += 1;
      } catch {
        // stdin may already be gone; the kill below covers it.
      }
      await waitForExit(STOP_TIMEOUT_MS);
    }
    if (!exited) {
      killAndSweep();
      await waitForExit(STOP_TIMEOUT_MS);
    }
    liveChildren.delete(child);
  }

  async function sweepOwnLeftovers() {
    await sweepPeerDir(peerDir, child.pid);
    if (createdDir) await rmdir(peerDir).catch(() => undefined);
  }

  // Shuts the child down without sweeping so a test can inspect the plugin's
  // own record and socket cleanup first; stop() still sweeps.
  function stopWithoutSweep() {
    stopPromise ??= runStop();
    return stopPromise;
  }

  function stop() {
    stopPromise ??= runStop();
    return stopPromise.finally(sweepOwnLeftovers);
  }

  async function waitForRecord() {
    const dirs = [join(peerDir, RECORD_DIR), peerDir];
    const deadline = Date.now() + READY_TIMEOUT_MS;
    for (;;) {
      if (exited) throw new Error(`child exited before writing a record; ${diag()}`);
      for (const dir of dirs) {
        let entries;
        try {
          entries = await readdir(dir);
        } catch {
          continue;
        }
        const hit = entries.find((entry) => entry.startsWith(`${child.pid}-`) && entry.endsWith('.json'));
        if (hit !== undefined) return join(dir, hit);
      }
      if (Date.now() >= deadline) {
        throw new Error(`no presence record under ${peerDir} within ${READY_TIMEOUT_MS}ms; ${diag()}`);
      }
      await sleep(POLL_MS);
    }
  }

  let handle;
  const ready = (async () => {
    try {
      const bootMsg = await withTimeout(boot, READY_TIMEOUT_MS, () => `child never became ready; ${diag()}`);
      if (typeof bootMsg.armError === 'string') {
        throw new Error(`session_start failed in child; ${bootMsg.armError}`);
      }
      handle.recordPath = await waitForRecord();
    } catch (err) {
      killAndSweep();
      await waitForExit(STOP_TIMEOUT_MS);
      liveChildren.delete(child);
      await sweepPeerDir(peerDir, child.pid);
      if (createdDir) await rmdir(peerDir).catch(() => undefined);
      throw err;
    }
  })();

  handle = {
    pid: child.pid,
    recordPath: undefined,
    ready,
    invoke: (eventType, payload) => request({ cmd: 'emit', eventType, payload }),
    tool: (name, params) => request({ cmd: 'tool', name, params }),
    stop,
    stopWithoutSweep,
  };
  return handle;
}

/**
 * Start two labeled children (alpha, beta) sharing one peer dir so they can
 * talk over real sockets. When the fixture creates the dir, it is removed
 * once both children have stopped.
 */
export async function startPair(options = {}) {
  assertSupportedPlatform();
  const dirOption = options.peerDir;
  if (dirOption !== undefined && (typeof dirOption !== 'string' || dirOption === '')) {
    throw new TypeError('startPair options.peerDir must be a non-empty string');
  }
  const created = dirOption === undefined;
  const peerDir = created ? await mkdtemp(join(STATE_BASE, 'opf-')) : resolve(dirOption);

  let alpha;
  try {
    alpha = await startChild({ peerDir, label: 'alpha' });
  } catch (err) {
    if (created) await removeDir(peerDir);
    throw err;
  }

  let beta;
  try {
    beta = await startChild({ peerDir, label: 'beta' });
  } catch (err) {
    try {
      await alpha.stop();
    } catch {
      // Keep cleaning up.
    }
    if (created) await removeDir(peerDir);
    throw err;
  }

  if (created) attachPairCleanup(alpha, beta, peerDir);
  return { alpha, beta };
}

function attachPairCleanup(alpha, beta, peerDir) {
  const stopped = { alpha: false, beta: false };
  const wrap = (handle, key) => {
    const stop = handle.stop;
    handle.stop = async () => {
      await stop();
      if (stopped[key]) return;
      stopped[key] = true;
      if (stopped.alpha && stopped.beta) await removeDir(peerDir);
    };
  };
  wrap(alpha, 'alpha');
  wrap(beta, 'beta');
}
