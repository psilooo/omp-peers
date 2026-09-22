/**
 * Peers behavior suite: runs against the COMPILED package (dist) with
 * OMP_PEERS_DIR pointed at fresh temp roots. The suite never rebuilds.
 * Covers the plan section 6 automated bullets owned by this file:
 * handshake/transport (receiver proof, canonical encoding, refusal codes,
 * extra-byte and oversized framing, split replies), router/FIFO (ping/status
 * auth, correlated replies, [id] markers, held work, one terminal reply per
 * socket, safe A to B retargeting and the retry gates), bounds/replay (every
 * release-constant boundary, replay cache, directory/record/peer caps, wake
 * budgets and the shared process ring), and version compatibility (v1 and
 * future frames refused, never dispatched).
 * Plain Node ESM, no test-runner dependency (also runs under `node --test`).
 */

import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createConnection, createServer } from 'node:net';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';

const {
  PROTOCOL_VERSION,
  HELLO_MAX_BYTES,
  CHALLENGE_MAX_BYTES,
  REQUEST_MAX_BYTES,
  BODY_MAX_BYTES,
  REPLY_MAX_BYTES,
  RECORD_MAX_BYTES,
  MAX_DIR_ENTRIES,
  MAX_ROUTABLE_PEERS,
  PROJECT_MAX_BYTES,
  MAX_INBOUND_SOCKETS,
  MAX_OUTBOUND_SOCKETS,
  MAX_SENDER_QUEUES,
  MAX_BATCHES_PER_SENDER,
  MAX_BATCH_MESSAGES,
  MAX_BATCH_BYTES,
  COALESCE_MS,
  DRAIN_GRACE_MS,
  MAX_PENDING_REQUESTS,
  REPLAY_CACHE_SIZE,
  REPLAY_TTL_MS,
  MAX_PAST_MS,
  MAX_FUTURE_MS,
  HANDSHAKE_TIMEOUT_MS,
  RECEIPT_TIMEOUT_MS,
  REQUEST_TIMEOUT_DEFAULT_MS,
  REQUEST_TIMEOUT_MIN_MS,
  REQUEST_TIMEOUT_MAX_MS,
  HEARTBEAT_MS,
  PRESENCE_TTL_MS,
  MAX_HELD_BATCHES,
  HOLD_TIMEOUT_MS,
  STATUS_FANOUT,
  STATUS_BUDGET_MS,
  MAX_STATUS_FIELDS,
  MAX_STATUS_TODOS,
  MAX_STATUS_TEXT_BYTES,
  MAX_STATUS_ACTIVITY_BYTES,
  MAX_HOP,
  WAKES_PER_HOUR,
  MAX_WAKE_IDENTITIES,
  PROCESS_WAKES_PER_HOUR,
  WAKE_WINDOW_MS,
  ID_BYTES,
  TOKEN_BYTES,
  INSTANCE_HEX_CHARS,
  ID_B64_CHARS,
  TOKEN_B64_CHARS,
  generateInstance,
  generateToken,
  generateId,
  isCanonicalInstance,
  isCanonicalToken,
  isCanonicalId,
  isValidPeerName,
  normalizeNameInput,
  aliasNameFor,
  defaultNameFor,
  parseRecord,
  isRecordFresh,
  challengeMac,
  requestMac,
  replyMac,
  canonicalRequestPayload,
  canonicalStatus,
  verifyMac,
  parseHello,
  parseChallenge,
  parseRequest,
  parseReply,
  encodeLine,
  isFreshTimestamp,
  ReplayCache,
  isRetryableRefusal,
  isSuccessCode,
} = await import('../dist/peers/protocol.js');
const { startPeerServer } = await import('../dist/peers/server.js');
const {
  PendingStore,
  resolveTarget,
  sendMsg,
  requestMsg,
  statusOf,
  pingPeer,
} = await import('../dist/peers/outbound.js');
const {
  WakeLimiter,
  processWakeAllowed,
  createHostDelivery,
  formatPeerText,
} = await import('../dist/peers/inbound.js');
const { writeOwnRecord, scanPeers, readPeerRecord } = await import('../dist/peers/presence.js');
const { projectFor } = await import('../dist/peers/ids.js');
const { ensureStateRoots, peerEndpoint, peerRecordPath, rootHash, validateUnixEndpoint } = await import(
  '../dist/store/paths.js'
);
const { readJsonBounded } = await import('../dist/store/atomic.js');
const { createFakeHost, startChild, startPair } = await import('./fixture/two-child.mjs');

// A compact base keeps every derived endpoint under the 103-byte macOS
// sun_path ceiling: the default TMPDIR under /var/folders overruns it, the
// kernel truncates the instance hex that distinguishes sockets, and distinct
// paths systematically collide with EADDRINUSE.
const ROOT_TMP = join('/tmp', `p2-${process.pid}-${Date.now().toString(36)}`);
await mkdir(ROOT_TMP, { recursive: true });
after(() => rm(ROOT_TMP, { recursive: true, force: true }));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, { timeout = 5000, interval = 10, label = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    if (await predicate()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(interval);
  }
}

/** Fresh isolated state roots per describe block. */
async function makeRoots(label) {
  return ensureStateRoots({ OMP_PEERS_DIR: join(ROOT_TMP, label) });
}

/**
 * Controllable managed timers: every bound up to the default request timeout
 * (coalesce, drain grace, handshake, receipt, exchange, reply wait) runs on
 * real wall clocks so timeouts behave naturally and no awaited exchange can
 * hang forever, while the 120 s hold timeout is manual-only and fired by
 * tests instead of waiting it out.
 */
const AUTO_REAL_MS = REQUEST_TIMEOUT_DEFAULT_MS;
function makeTimers() {
  const pending = [];
  let seq = 0;
  return {
    managed: {
      setInterval(callback, ms) {
        const handle = { kind: 'interval', callback, ms, id: ++seq };
        pending.push(handle);
        if (ms <= AUTO_REAL_MS) handle.timer = setInterval(() => drop(handle), ms);
        return handle;
      },
      setTimeout(callback, ms) {
        const handle = { kind: 'timeout', callback, ms, id: ++seq };
        pending.push(handle);
        if (ms <= AUTO_REAL_MS) handle.timer = setTimeout(() => drop(handle), ms);
        return handle;
      },
      clearTimer(handle) {
        if (handle && handle.timer !== undefined) {
          handle.kind === 'interval' ? clearInterval(handle.timer) : clearTimeout(handle.timer);
        }
        remove(handle);
      },
    },
    armed(ms) {
      return pending.filter((handle) => handle.ms === ms).length;
    },
    /** Fire every currently armed manual timer once. */
    fireAll(rounds = 4) {
      let fired = 0;
      for (let round = 0; round < rounds; round += 1) {
        const due = pending.splice(0);
        if (due.length === 0) break;
        for (const handle of due) {
          fired += 1;
          if (handle.timer !== undefined) {
            handle.kind === 'interval' ? clearInterval(handle.timer) : clearTimeout(handle.timer);
          }
          handle.callback();
        }
      }
      return fired;
    },
    fire(ms) {
      const due = pending.filter((handle) => handle.ms === ms);
      for (const handle of due) remove(handle);
      for (const handle of due) {
        if (handle.timer !== undefined) {
          handle.kind === 'interval' ? clearInterval(handle.timer) : clearTimeout(handle.timer);
        }
        handle.callback();
      }
      return due.length;
    },
  };

  function remove(handle) {
    const at = pending.indexOf(handle);
    if (at >= 0) pending.splice(at, 1);
  }
  function drop(handle) {
    if (pending.indexOf(handle) < 0) return;
    remove(handle);
    handle.callback();
  }
}

/**
 * Scriptable HostDelivery: records every attempt/submission/consumption so
 * tests assert what the host side actually observed.
 */
function makeDelivery() {
  const state = {
    attempts: [],
    delivered: [],
    consumed: [],
    statusCalls: [],
    captures: 0,
    heldReserves: 0,
    releases: 0,
    acceptance: 'accepting',
    canSubmit: true,
    heldCapacity: true,
    submitCode: 'submitted',
    submitDetail: undefined,
    consume: () => false,
    status: { busy: false },
    epoch: { binding: 0, transcript: 0 },
  };
  const delivery = {
    async submitBatch(envelopes) {
      state.attempts.push(envelopes);
      // A non-accepting binding returns the exact AcceptanceState code
      // (amendment A): shutting_down stays shutting_down, never relabelled.
      if (state.acceptance !== 'accepting') return { code: state.acceptance };
      // Recheck the captured epoch immediately before the host call, exactly
      // as the contract requires: stale work must enter no transcript.
      if (envelopes.some((envelope) => !delivery.isEpochValid(envelope.epoch))) {
        return { code: 'session_transition' };
      }
      state.delivered.push(envelopes);
      return state.submitDetail === undefined
        ? { code: state.submitCode }
        : { code: state.submitCode, detail: state.submitDetail };
    },
    canSubmitNow: () => state.canSubmit,
    reserveHeld() {
      state.heldReserves += 1;
      return state.heldCapacity;
    },
    releaseHeld() {
      state.releases += 1;
    },
    statusSnapshot(fields) {
      state.statusCalls.push(fields);
      return state.status;
    },
    consumeReply(from, replyTo, body) {
      state.consumed.push({ from, replyTo, body });
      return state.consume(from, replyTo, body);
    },
    acceptance: () => state.acceptance,
    admissionCode() {
      return state.acceptance === 'accepting' ? undefined : { code: state.acceptance };
    },
    captureEpoch() {
      state.captures += 1;
      return { binding: state.epoch.binding, transcript: state.epoch.transcript };
    },
    isEpochValid(captured) {
      return (
        captured !== undefined
        && captured.binding === state.epoch.binding
        && captured.transcript === state.epoch.transcript
      );
    },
  };
  return { delivery, state };
}

function makeIdentity() {
  return { pid: process.pid, instance: generateInstance(), token: generateToken() };
}

async function putRecord(roots, identity, opts = {}) {
  await writeOwnRecord(roots, {
    v: 2,
    pid: identity.pid,
    instance: identity.instance,
    token: identity.token,
    name: opts.name ?? 'peer',
    project: opts.project ?? 'proj',
    harness: 'omp',
    startedAt: opts.startedAt ?? Date.now(),
    beatAt: opts.beatAt ?? Date.now(),
    busy: opts.busy ?? false,
  });
}

/** In-memory fresh v2 record for scan() seams. */
function memoryRecord(identity, opts = {}) {
  return {
    v: 2,
    pid: identity.pid,
    instance: identity.instance,
    token: identity.token,
    name: opts.name ?? 'target',
    project: opts.project ?? 'proj',
    harness: 'omp',
    startedAt: opts.startedAt ?? 1,
    beatAt: opts.beatAt ?? Date.now(),
    busy: false,
  };
}

function makeDeps({ roots, identity, timers, scan, acceptance = () => 'accepting' }) {
  const pending = new PendingStore();
  const logs = [];
  const deps = {
    identity,
    roots,
    managed: timers.managed,
    // resolveTarget reads a PeerScan ({ routable }); tests hand back a plain
    // record array, so normalize the seam to the contract shape here.
    scan: async () => {
      const result = await scan();
      return Array.isArray(result) ? { routable: result, incompatible: [] } : result;
    },
    pending,
    acceptance,
    log: (text) => logs.push(text),
  };
  return { deps, pending, logs };
}

/**
 * Give one server a never-before-bound endpoint: derive a fresh instance on
 * the shared identity object and move its presence record (when one exists)
 * onto the new instance, so record scans, handshake proofs, and record-path
 * dials all agree with the bound path. The endpoint is returned from the
 * instance this claim generated, never re-read from the shared object after
 * an await, so two interleaved claims on one identity resolve to two distinct
 * paths instead of racing onto one.
 */
async function claimFreshEndpoint(roots, identity) {
  const previous = identity.instance;
  const instance = generateInstance();
  identity.instance = instance;
  let record;
  try {
    record = await readPeerRecord(roots, identity.pid, previous);
  } catch {
    record = undefined;
  }
  if (record !== undefined) {
    await writeOwnRecord(roots, { ...record, instance });
    await rm(peerRecordPath(roots, identity.pid, previous), { force: true });
  }
  const endpoint = peerEndpoint(roots, identity.pid, instance);
  // Fail loudly at claim time if the path would exceed the macOS sun_path
  // ceiling: a truncated kernel-visible name silently collides distinct
  // sockets, which no amount of retrying can fix.
  validateUnixEndpoint(endpoint);
  return endpoint;
}

/**
 * One-bind-per-claim gate: claim, length-validate, and listen as one
 * serialized step. Concurrent subtests sharing an identity object must never
 * interleave claimFreshEndpoint, so every helper bind passes through here.
 *
 * Exactly one claim and one listen per bind, no retries: the ceiling check in
 * claimFreshEndpoint forbids the truncation collisions that retries only
 * masked. If a listen still collides, the rethrow names the claimed path and
 * the pre-listen lstat probe instead of silently re-claiming. `run(report)`
 * receives a report callback publishing { path, probe }.
 */
let bindGate = Promise.resolve();
function claimAndBind(run) {
  const done = bindGate.then(async () => {
    let reported;
    try {
      return await run((info) => { reported = info; });
    } catch (err) {
      if (err?.code !== 'EADDRINUSE') throw err;
      const where = reported?.path ?? 'unknown path';
      const probe = reported?.probe ?? 'no probe';
      const wrapped = new Error(`${err.message} (endpoint ${where}; pre-listen probe: ${probe})`);
      wrapped.code = 'EADDRINUSE';
      wrapped.cause = err;
      throw wrapped;
    }
  });
  bindGate = done.then(() => undefined, () => undefined);
  return done;
}

/** Pre-listen existence probe for the error report. */
async function pathProbe(path) {
  try {
    await stat(path);
    return 'path already existed before listen';
  } catch {
    return 'path was absent before listen';
  }
}

async function startTestServer({ roots, identity, delivery, timers, log = () => {} }) {
  return claimAndBind(async (report) => {
    const endpoint = await claimFreshEndpoint(roots, identity);
    const probe = await pathProbe(endpoint);
    report({ path: endpoint, probe });
    const handle = startPeerServer({ endpoint, roots, identity, delivery, managed: timers.managed, log });
    await handle.ready;
    return handle;
  });
}

/**
 * Raw v2 client over one socket: newline-framed reads with a cursor, so
 * tests observe exactly how many terminal replies a socket received.
 */
function openRaw(endpoint) {
  const socket = createConnection(endpoint);
  const lines = [];
  const waiters = [];
  let buffer = '';
  let cursor = 0;
  let ended = false;
  let failure;
  let connected = false;
  const wake = () => {
    while (waiters.length > 0) waiters.shift()();
  };
  socket.on('connect', () => {
    connected = true;
    wake();
  });
  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    for (;;) {
      const nl = buffer.indexOf('\n');
      if (nl < 0) break;
      lines.push(buffer.slice(0, nl));
      buffer = buffer.slice(nl + 1);
    }
    wake();
  });
  socket.on('close', () => {
    ended = true;
    wake();
  });
  socket.on('error', (err) => {
    failure = err;
    ended = true;
    wake();
  });
  const pump = () => new Promise((resolve) => {
    waiters.push(resolve);
    setTimeout(resolve, 20);
  });
  return {
    socket,
    lines,
    get ended() { return ended; },
    get failure() { return failure; },
    get remaining() { return buffer; },
    async connect(timeoutMs = 3000) {
      const deadline = Date.now() + timeoutMs;
      while (!connected) {
        if (ended || Date.now() > deadline) throw new Error(`connect failed: ${failure?.message ?? 'closed'}`);
        await pump();
      }
    },
    send(value) {
      socket.write(typeof value === 'string' ? value : encodeLine(value));
    },
    async nextLine(timeoutMs = 4000) {
      const deadline = Date.now() + timeoutMs;
      while (cursor >= lines.length) {
        if (Date.now() > deadline || (ended && cursor >= lines.length)) {
          throw new Error(`no reply line (ended=${ended}, failure=${failure?.message ?? 'none'})`);
        }
        await pump();
      }
      return lines[cursor++];
    },
    // Drop consumed frames (the handshake challenge) so lines.length counts
    // only post-handshake terminal replies.
    resetLines() {
      lines.length = 0;
      cursor = 0;
    },
    close() {
      socket.destroy();
    },
  };
}

function helloFrame(id, to, clientNonce) {
  return { v: 2, type: 'hello', id, to, clientNonce };
}

function requestFrame({
  id,
  clientNonce,
  serverNonce,
  sender,
  receiver,
  payload,
  sentAt = Date.now(),
  auth,
}) {
  const from = { pid: sender.pid, instance: sender.instance };
  const to = { pid: receiver.pid, instance: receiver.instance };
  return {
    v: 2,
    type: 'request',
    id,
    clientNonce,
    serverNonce,
    sentAt,
    from,
    to,
    payload,
    auth: auth
      ?? requestMac(sender.token, id, clientNonce, serverNonce, sentAt, from, to, canonicalRequestPayload(payload)),
  };
}

/** Complete and verify the receiver-proof handshake over a raw socket. */
async function verifiedHandshake(raw, receiver, timeoutMs) {
  const id = generateId();
  const clientNonce = generateId();
  raw.send(helloFrame(id, { pid: receiver.pid, instance: receiver.instance }, clientNonce));
  const challengeLine = await raw.nextLine(timeoutMs);
  const challenge = parseChallenge(challengeLine);
  assert.ok(challenge, `challenge did not parse: ${challengeLine}`);
  const expected = challengeMac(
    receiver.token,
    id,
    { pid: receiver.pid, instance: receiver.instance },
    clientNonce,
    challenge.serverNonce
  );
  assert.ok(verifyMac(expected, challenge.auth), 'challenge must prove the receiver holds the token');
  raw.resetLines();
  return { id, clientNonce, serverNonce: challenge.serverNonce };
}

/** Terminal reply lines are JSON objects tagged as replies with a code. */
const OBSERVED = new Set();
function terminalCode(line) {
  const frame = JSON.parse(line);
  assert.equal(frame.type, 'reply', `expected a terminal reply, got: ${line}`);
  assert.equal(frame.v, PROTOCOL_VERSION);
  assert.equal(typeof frame.code, 'string');
  OBSERVED.add(frame.code);
  return frame.code;
}

/** Assert an OutboundResult carries the exact machine code and record it. */
function expectCode(result, expected) {
  assert.equal(result.code, expected, `${expected} expected, got ${result.code}: ${result.detail ?? ''}`);
  OBSERVED.add(result.code);
  return result;
}

/** Net server bound to a derived peer endpoint, feeding whole lines to a script. */
async function makeOutboundServer(roots, receiver, opts = {}) {
  const accepted = [];
  const server = createServer((socket) => {
    accepted.push(socket);
    let buffer = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buffer += chunk;
      let nl;
      while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        opts.onLine?.(socket, line, accepted.length);
      }
    });
    socket.on('error', () => {});
  });
  return claimAndBind(async (report) => {
    const endpoint = await claimFreshEndpoint(roots, receiver);
    const probe = await pathProbe(endpoint);
    report({ path: endpoint, probe });
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(endpoint, () => {
        resolve({
          server,
          endpoint,
          accepted,
          get acceptedCount() { return accepted.length; },
          stop: () => new Promise((done) => server.close(() => done())),
        });
      });
    });
  });
}

/** Complete a server-side handshake: sign the challenge with the record token. */
function answerHello(socket, line, identity) {
  const hello = parseHello(line);
  if (!hello) return false;
  const serverNonce = generateId();
  socket.write(encodeLine({
    v: 2,
    type: 'challenge',
    id: hello.id,
    from: { pid: identity.pid, instance: identity.instance },
    clientNonce: hello.clientNonce,
    serverNonce,
    auth: challengeMac(identity.token, hello.id, { pid: identity.pid, instance: identity.instance }, hello.clientNonce, serverNonce),
  }));
  return { hello, serverNonce };
}

/** Write a line in several delayed slices to exercise client buffering. */
function writeSliced(socket, text, parts, delayMs = 15) {
  const size = Math.ceil(text.length / parts);
  for (let i = 0; i < parts; i += 1) {
    const slice = text.slice(i * size, (i + 1) * size);
    if (slice !== '') setTimeout(() => socket.write(slice), i * delayMs);
  }
}

/** A receiver-signed terminal reply frame, canonically MACed. */
function signedReply(identity, id, code, detail = null, status) {
  const from = { pid: identity.pid, instance: identity.instance };
  const frame = { v: 2, type: 'reply', id, from, code };
  if (detail !== null) frame.detail = detail;
  if (status !== undefined) frame.status = status;
  frame.auth = replyMac(
    identity.token,
    id,
    from,
    code,
    detail,
    status === undefined ? null : canonicalStatus(status)
  );
  return encodeLine(frame);
}

describe('handshake and transport', () => {
  let roots;
  let receiver;
  before(async () => {
    roots = await makeRoots('handshake');
    receiver = makeIdentity(48101);
    await putRecord(roots, receiver, { name: 'beta' });
  });

  it('rejects a fake or stale receiver proof before any body is sent', async () => {
    const sender = makeIdentity(48102);
    for (const mode of ['unknown-token', 'stale-token']) {
      // The client trusts a fresh record token; the squatter signs the
      // challenge with a token it does not actually hold (a random one, or a
      // stale one from before the record rotated). Both must fail identically.
      const squatter = { pid: mode === 'stale-token' ? 48103 : 48104, instance: generateInstance() };
      const trustedToken = generateToken();
      const signingToken = generateToken();
      await putRecord(roots, { ...squatter, token: trustedToken }, { name: 'fake' });
      const endpoint = peerEndpoint(roots, squatter.pid, squatter.instance);
      validateUnixEndpoint(endpoint);
      const seen = [];
      const fake = createServer((socket) => {
        let buffer = '';
        socket.setEncoding('utf8');
        socket.on('data', (chunk) => {
          buffer += chunk;
          let nl;
          while ((nl = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0, nl);
            buffer = buffer.slice(nl + 1);
            seen.push(line);
            const hello = parseHello(line);
            if (hello) {
              const serverNonce = generateId();
              const from = { pid: squatter.pid, instance: squatter.instance };
              socket.write(encodeLine({
                v: 2,
                type: 'challenge',
                id: hello.id,
                from,
                clientNonce: hello.clientNonce,
                serverNonce,
                auth: challengeMac(signingToken, hello.id, from, hello.clientNonce, serverNonce),
              }));
            }
          }
        });
        socket.on('error', () => {});
      });
      await new Promise((resolve, reject) => {
        fake.once('error', reject);
        fake.listen(endpoint, resolve);
      });
      try {
        const timers = makeTimers();
        const { deps } = makeDeps({
          roots,
          identity: sender,
          timers,
          scan: async () => [
            memoryRecord({ pid: squatter.pid, instance: squatter.instance, token: trustedToken }, { name: 'fake' }),
          ],
        });
        const result = await requestMsg(deps, 'fake', 'secret body');
        expectCode(result, 'receiver_auth_failed');
        assert.ok(
          !seen.some((line) => JSON.parse(line)?.type === 'request'),
          `${mode}: the body must never reach a receiver that cannot prove the token`
        );
      } finally {
        await new Promise((done) => fake.close(done));
      }
    }
  });

  it('refuses a case-variant instance so a case-folding squatter cannot pass proof', async () => {
    // Canonical identity is lowercase-only: a case-variant target fails
    // strict parsing, so a squatter behind any case-folding namespace never
    // sees a dispatchable frame. Dial the live receiver endpoint and carry
    // the case-variant identity inside the proof-bearing hello frame.
    const timers = makeTimers();
    const { delivery } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const upperInstance = receiver.instance.toUpperCase();
    assert.ok(upperInstance !== receiver.instance);
    assert.equal(isCanonicalInstance(upperInstance), false);
    const raw = openRaw(server.endpoint);
    await raw.connect();
    try {
      raw.send(helloFrame(generateId(), { pid: receiver.pid, instance: upperInstance }, generateId()));
      const line = await raw.nextLine();
      assert.equal(terminalCode(line), 'bad_frame');
      await sleep(50);
      assert.equal(raw.lines.length, 1, 'exactly one terminal refusal');
    } finally {
      raw.close();
      await server.close();
    }
  });

  it('holds canonical encodings to strict lowercase base64url and exact lengths', () => {
    const instance = generateInstance();
    const token = generateToken();
    const id = generateId();
    assert.equal(instance.length, INSTANCE_HEX_CHARS);
    assert.equal(token.length, TOKEN_B64_CHARS);
    assert.equal(id.length, ID_B64_CHARS);
    assert.ok(isCanonicalInstance(instance));
    assert.ok(isCanonicalToken(token));
    assert.ok(isCanonicalId(id));
    assert.equal(isCanonicalInstance(instance.toUpperCase()), false);
    assert.equal(isCanonicalToken(`${token}=`), false);
    assert.equal(isCanonicalToken(token.slice(0, TOKEN_B64_CHARS - 1)), false);
    assert.equal(isCanonicalId(id.slice(0, ID_B64_CHARS - 1)), false);
    assert.equal(isCanonicalId(`${id}A`), false);
    assert.equal(isCanonicalId(id.replace(/[A-Za-z]/, (ch) => (ch === 'a' ? '+' : '/'))), false);
    // Some replacement of the final base64url character breaks canonical
    // trailing bits; scan for one and require it to be rejected.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let rejected = false;
    for (const ch of alphabet) {
      if (ch === id[ID_B64_CHARS - 1]) continue;
      if (!isCanonicalId(`${id.slice(0, -1)}${ch}`)) {
        rejected = true;
        break;
      }
    }
    assert.ok(rejected, 'at least one non-canonical trailing character must be rejected');
    assert.equal(parseChallenge(encodeLine({
      v: 2,
      type: 'challenge',
      id,
      from: { pid: receiver.pid, instance: receiver.instance },
      clientNonce: id.slice(0, ID_B64_CHARS - 1),
      serverNonce: id,
      auth: 'a'.repeat(64),
    })), undefined, 'a 21-character nonce must fail strict parsing');
  });

  it('refuses malformed, unsupported, wrong-recipient, bad-MAC, stale, and replayed requests', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const sender = makeIdentity(48105);
    await putRecord(roots, sender, { name: 'alpha' });
    try {
      const raw1 = openRaw(server.endpoint);
      await raw1.connect();
      raw1.send('{not json\n');
      assert.equal(terminalCode(await raw1.nextLine()), 'bad_frame');
      raw1.close();

      for (const v of [1, 3]) {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        raw.send({ v, type: 'hello', id: generateId(), to: { pid: receiver.pid, instance: receiver.instance }, clientNonce: generateId() });
        assert.equal(terminalCode(await raw.nextLine()), 'unsupported_version');
        raw.close();
      }

      // Wrong recipient is checked wherever the server places the check: at
      // hello, or on the request frame itself.
      const other = { pid: receiver.pid, instance: generateInstance() };
      const raw2 = openRaw(server.endpoint);
      await raw2.connect();
      raw2.send(helloFrame(generateId(), other, generateId()));
      const first = await raw2.nextLine();
      let wrongCode;
      if (JSON.parse(first).type === 'challenge') {
        const echo = JSON.parse(first);
        raw2.send(requestFrame({
          id: echo.id,
          clientNonce: echo.clientNonce,
          serverNonce: echo.serverNonce,
          sender,
          receiver: other,
          payload: { type: 'ping' },
        }));
        wrongCode = terminalCode(await raw2.nextLine());
      } else {
        wrongCode = terminalCode(first);
      }
      assert.equal(wrongCode, 'wrong_recipient');
      raw2.close();

      const raw3 = openRaw(server.endpoint);
      await raw3.connect();
      const hs3 = await verifiedHandshake(raw3, receiver);
      raw3.send(requestFrame({ ...hs3, sender, receiver, payload: { type: 'ping' }, auth: '0'.repeat(64) }));
      assert.equal(terminalCode(await raw3.nextLine()), 'unauthenticated');
      raw3.close();

      const raw4 = openRaw(server.endpoint);
      await raw4.connect();
      const hs4 = await verifiedHandshake(raw4, receiver);
      raw4.send(requestFrame({
        ...hs4,
        sender,
        receiver,
        payload: { type: 'ping' },
        sentAt: Date.now() - MAX_PAST_MS - 1000,
      }));
      assert.equal(terminalCode(await raw4.nextLine()), 'stale_sender');
      raw4.close();

      const raw5 = openRaw(server.endpoint);
      await raw5.connect();
      const hs5 = await verifiedHandshake(raw5, receiver);
      const pingLine = encodeLine(requestFrame({ ...hs5, sender, receiver, payload: { type: 'ping' } }));
      raw5.send(pingLine);
      assert.equal(terminalCode(await raw5.nextLine()), 'pong');
      // The terminal reply pauses reads: a duplicate on the same socket
      // earns neither an answer nor a dispatch.
      raw5.send(pingLine);
      await sleep(100);
      assert.equal(raw5.lines.length, 1, 'one terminal reply per socket');
      raw5.close();

      // The replayed id is still caught on a fresh socket: same (sender, id)
      // pair, fresh challenge nonces, refused before any dispatch.
      const raw6 = openRaw(server.endpoint);
      await raw6.connect();
      const nonce6 = generateId();
      raw6.send(helloFrame(hs5.id, { pid: receiver.pid, instance: receiver.instance }, nonce6));
      const challenge6 = parseChallenge(await raw6.nextLine());
      assert.ok(challenge6, 'the replay proof socket must complete its handshake');
      raw6.send(requestFrame({
        id: hs5.id,
        clientNonce: nonce6,
        serverNonce: challenge6.serverNonce,
        sender,
        receiver,
        payload: { type: 'ping' },
      }));
      assert.equal(terminalCode(await raw6.nextLine()), 'replay');
      raw6.close();

      assert.equal(state.delivered.length, 0, 'refused and ping frames never reach host submission');
      assert.ok(isFreshTimestamp(Date.now() - MAX_PAST_MS, Date.now()), 'the past boundary is inclusive');
      assert.ok(isFreshTimestamp(Date.now() + MAX_FUTURE_MS, Date.now()), 'the future boundary is inclusive');
      assert.equal(isFreshTimestamp(Date.now() - MAX_PAST_MS - 1, Date.now()), false);
      assert.equal(isFreshTimestamp(Date.now() + MAX_FUTURE_MS + 1, Date.now()), false);
    } finally {
      await server.close();
    }
  });

  it('refuses extra bytes that follow the request in the same write before dispatch', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const sender = makeIdentity(48106);
    await putRecord(roots, sender, { name: 'alpha' });
    try {
      const raw = openRaw(server.endpoint);
      await raw.connect();
      const hs = await verifiedHandshake(raw, receiver);
      const line = encodeLine(requestFrame({ ...hs, sender, receiver, payload: { type: 'msg', body: 'once', hop: 0 } }));
      raw.send(line + line);
      assert.equal(terminalCode(await raw.nextLine()), 'bad_frame');
      await sleep(100);
      assert.equal(raw.lines.length, 1, 'exactly one terminal reply per socket');
      assert.equal(state.delivered.flat().length, 0, 'bytes after the request newline must refuse before dispatch');
      raw.close();
    } finally {
      await server.close();
    }
  });

  it('never dispatches or answers twice when bytes arrive after an accepted request', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const sender = makeIdentity(48107);
    await putRecord(roots, sender, { name: 'alpha' });
    try {
      const raw = openRaw(server.endpoint);
      await raw.connect();
      const hs = await verifiedHandshake(raw, receiver);
      const line = encodeLine(requestFrame({ ...hs, sender, receiver, payload: { type: 'msg', body: 'once', hop: 0 } }));
      raw.send(line);
      assert.equal(terminalCode(await raw.nextLine()), 'submitted');
      // The accepted boundary detaches the parser permanently: a second full
      // request line must not dispatch and must not earn a second reply.
      raw.send(line);
      await sleep(150);
      assert.equal(state.delivered.flat().length, 1, 'exactly one dispatch');
      assert.equal(raw.lines.length, 1, 'exactly one terminal reply');
      raw.close();
    } finally {
      await server.close();
    }
  });

  it('refuses an oversized client request before dialing', async () => {
    const dialTarget = makeIdentity(48108);
    const counter = await makeOutboundServer(roots, dialTarget, { onLine: () => {} });
    try {
      const sender = makeIdentity(48109);
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => [memoryRecord(dialTarget, { name: 'target' })],
      });
      const result = await requestMsg(deps, 'target', 'x'.repeat(REQUEST_MAX_BYTES));
      expectCode(result, 'oversized');
      await sleep(150);
      assert.equal(counter.acceptedCount, 0, 'an oversized request must never open a connection');
    } finally {
      await counter.stop();
    }
  });

  it('answers a raw oversized request with one bounded refusal and no EPIPE', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const sender = makeIdentity(48110);
    await putRecord(roots, sender, { name: 'alpha' });
    try {
      const raw = openRaw(server.endpoint);
      await raw.connect();
      const hs = await verifiedHandshake(raw, receiver);
      const huge = encodeLine(requestFrame({
        ...hs,
        sender,
        receiver,
        payload: { type: 'msg', body: 'x'.repeat(REQUEST_MAX_BYTES), hop: 0 },
      }));
      assert.ok(Buffer.byteLength(huge, 'utf8') > REQUEST_MAX_BYTES, 'the raw frame exceeds the request cap');
      raw.send(huge);
      const line = await raw.nextLine();
      const frame = JSON.parse(line);
      assert.equal(frame.type, 'reply', 'the refusal must be one complete line');
      assert.ok(Buffer.byteLength(line, 'utf8') <= REPLY_MAX_BYTES, 'the refusal is bounded by the reply cap');
      assert.ok(parseReply(line), 'the refusal must be a well-formed reply');
      assert.ok(!isSuccessCode(frame.code), `oversized refusal, got ${frame.code}`);
      await sleep(100);
      assert.equal(raw.failure, undefined, 'no EPIPE or reset while reading the refusal');
      assert.equal(raw.lines.length, 1, 'exactly one terminal reply');
      assert.equal(state.delivered.flat().length, 0, 'an oversized request never dispatches');
      raw.close();
    } finally {
      await server.close();
    }
  });

  it('buffers a challenge reply split across chunks', async () => {
    const remote = makeIdentity(48111);
    await putRecord(roots, remote, { name: 'remote' });
    const scripted = await makeOutboundServer(roots, remote, {
      onLine(socket, line) {
        if (line.startsWith('{"v":2,"type":"hello"')) {
          const hello = parseHello(line);
          const serverNonce = generateId();
          const challenge = encodeLine({
            v: 2,
            type: 'challenge',
            id: hello.id,
            from: { pid: remote.pid, instance: remote.instance },
            clientNonce: hello.clientNonce,
            serverNonce,
            auth: challengeMac(remote.token, hello.id, { pid: remote.pid, instance: remote.instance }, hello.clientNonce, serverNonce),
          });
          writeSliced(socket, challenge, 3);
        } else {
          const request = JSON.parse(line);
          socket.write(signedReply(remote, request.id, 'submitted'));
        }
      },
    });
    try {
      const sender = makeIdentity(48112);
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => [memoryRecord(remote, { name: 'remote' })],
      });
      const result = await sendMsg(deps, 'remote', 'split challenge');
      expectCode(result, 'submitted');
    } finally {
      await scripted.stop();
    }
  });

  it('buffers a terminal reply split across chunks', async () => {
    const remote = makeIdentity(48113);
    await putRecord(roots, remote, { name: 'remote2' });
    const scripted = await makeOutboundServer(roots, remote, {
      onLine(socket, line) {
        if (line.startsWith('{"v":2,"type":"hello"')) {
          answerHello(socket, line, remote);
        } else {
          const request = JSON.parse(line);
          writeSliced(socket, signedReply(remote, request.id, 'submitted'), 3);
        }
      },
    });
    try {
      const sender = makeIdentity(48114);
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => [memoryRecord(remote, { name: 'remote2' })],
      });
      const result = await sendMsg(deps, 'remote2', 'split terminal');
      expectCode(result, 'submitted');
    } finally {
      await scripted.stop();
    }
  });

  it('maps pre-write transport failures to their exact machine codes', async () => {
    const sender = makeIdentity(48115);

    // Nobody listens at the derived endpoint: connect phase.
    const dead = makeIdentity(48116);
    {
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => [memoryRecord(dead, { name: 'dead' })],
      });
      expectCode(await sendMsg(deps, 'dead', 'hi'), 'connect_timeout');
    }

    // Accepts, then never answers the hello: handshake phase.
    const silent = makeIdentity(48117);
    const silentServer = await makeOutboundServer(roots, silent, { onLine: () => {} });
    try {
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => [memoryRecord(silent, { name: 'silent' })],
      });
      expectCode(await sendMsg(deps, 'silent', 'hi'), 'handshake_timeout');
    } finally {
      await silentServer.stop();
    }

    // Closes before the challenge arrives: still pre-write.
    const closer = makeIdentity(48118);
    const closerServer = await makeOutboundServer(roots, closer, {
      onLine(socket) { socket.end(); },
    });
    try {
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => [memoryRecord(closer, { name: 'closer' })],
      });
      expectCode(await sendMsg(deps, 'closer', 'hi'), 'closed_before_reply');
    } finally {
      await closerServer.stop();
    }

    // Answers the hello with an unparseable line: malformed reply.
    const garbler = makeIdentity(48119);
    const garblerServer = await makeOutboundServer(roots, garbler, {
      onLine(socket) { socket.write('garbage not json\n'); },
    });
    try {
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => [memoryRecord(garbler, { name: 'garbler' })],
      });
      expectCode(await sendMsg(deps, 'garbler', 'hi'), 'malformed_reply');
    } finally {
      await garblerServer.stop();
    }
  });

  it('maps a post-write close to unknown_outcome with no retry', async () => {
    const dropAfter = makeIdentity(48120);
    await putRecord(roots, dropAfter, { name: 'dropper' });
    let scans = 0;
    const scripted = await makeOutboundServer(roots, dropAfter, {
      onLine(socket, line, index) {
        if (line.startsWith('{"v":2,"type":"hello"')) {
          answerHello(socket, line, dropAfter);
        } else {
          void index;
          socket.destroy();
        }
      },
    });
    try {
      const sender = makeIdentity(48121);
      const timers = makeTimers();
      const { deps } = makeDeps({
        roots,
        identity: sender,
        timers,
        scan: async () => {
          scans += 1;
          return [memoryRecord(dropAfter, { name: 'dropper' })];
        },
      });
      const result = await sendMsg(deps, 'dropper', 'written after challenge');
      expectCode(result, 'unknown_outcome');
      assert.equal(isRetryableRefusal('unknown_outcome'), false, 'unknown_outcome must never be retried');
      await sleep(150);
      assert.equal(scripted.acceptedCount, 1, 'post-write failures never redial');
      assert.ok(scans <= 2, 'a fresh scan is optional but bounded');
    } finally {
      await scripted.stop();
    }
  });

  it('answers a full replay cache with busy and never evicts an unexpired id', { timeout: 60000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const sender = makeIdentity(48122);
    await putRecord(roots, sender, { name: 'filler' });
    try {
      // One handshake plus one authenticated ping over a fresh socket. The
      // replay cache is created per server, so this server starts empty and
      // exactly REPLAY_CACHE_SIZE distinct (sender, id) pairs must fit.
      // Bun needs well over the 4 s default to answer within this suite.
      const waitMs = 15000;
      // Release server-side socket entries between batches: run the drain
      // grace destroy callbacks and yield so Bun delivers the close events
      // before more connections arrive (the server caps inbound sockets).
      const flushSockets = async () => {
        timers.fire(DRAIN_GRACE_MS);
        await new Promise((resolve) => setImmediate(resolve));
      };
      const pingOnce = async () => {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        const hs = await verifiedHandshake(raw, receiver, waitMs);
        const line = encodeLine(requestFrame({ ...hs, sender, receiver, payload: { type: 'ping' } }));
        raw.send(line);
        const code = terminalCode(await raw.nextLine(waitMs));
        return { raw, line, code };
      };

      const first = await pingOnce();
      assert.equal(first.code, 'pong', 'the first insert fits');
      for (let i = 1; i < REPLAY_CACHE_SIZE; i += 1) {
        const step = await pingOnce();
        assert.equal(step.code, 'pong', `insert ${i + 1} of ${REPLAY_CACHE_SIZE} must still fit`);
        step.raw.close();
        if (i % 32 === 0) await flushSockets();
      }
      await flushSockets();

      // The next distinct id finds the cache full: one bounded busy refusal.
      const overflow = await pingOnce();
      assert.equal(overflow.code, 'busy', 'a full replay cache refuses with busy');

      const firstId = JSON.parse(first.line).id;
      const overflowId = JSON.parse(overflow.line).id;
      first.raw.close();
      overflow.raw.close();
      await flushSockets();

      // Re-present an id on a fresh socket (fresh challenge, same
      // authenticated (sender, id) pair): the oldest id must still answer
      // replay, proving the full cache never evicted it, while the refused
      // id answers busy again, proving a refused insert left no trace.
      const replayProof = async (id, expected) => {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        const clientNonce = generateId();
        raw.send(helloFrame(id, { pid: receiver.pid, instance: receiver.instance }, clientNonce));
        const challengeLine = await raw.nextLine(waitMs);
        const challenge = parseChallenge(challengeLine);
        assert.ok(challenge, `replay proof handshake failed: ${challengeLine}`);
        raw.send(requestFrame({
          id,
          clientNonce,
          serverNonce: challenge.serverNonce,
          sender,
          receiver,
          payload: { type: 'ping' },
        }));
        assert.equal(terminalCode(await raw.nextLine(waitMs)), expected);
        raw.close();
      };
      await replayProof(firstId, 'replay');
      await replayProof(overflowId, 'busy');

      assert.equal(state.delivered.length, 0, 'pings never dispatch to the host');
    } finally {
      await server.close();
    }
  });
});

describe('router, replies, and FIFO batching', () => {
  let roots;
  let receiver;
  let senderIdent;
  before(async () => {
    roots = await makeRoots('router');
    receiver = makeIdentity(48201);
    senderIdent = makeIdentity(48202);
    await putRecord(roots, receiver, { name: 'beta' });
    await putRecord(roots, senderIdent, { name: 'alpha' });
  });

  it('answers ping and status only through the authenticated router', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    state.status = { busy: true, model: 'm' };
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const { deps } = makeDeps({
        roots,
        identity: senderIdent,
        timers,
        scan: async () => [memoryRecord(receiver, { name: 'beta' })],
      });
      expectCode(await pingPeer(deps, 'beta'), 'pong');
      expectCode(await statusOf(deps, 'beta', ['model', 'busy', 'todos', 'activity']), 'status');
      assert.equal(state.delivered.length, 0, 'ping and status never dispatch host messages');
      assert.equal(state.consumed.length, 0, 'ping and status never consume replies');
      assert.equal(state.statusCalls.length, 1, 'one status snapshot per status request');
      assert.ok(
        state.statusCalls[0].length <= MAX_STATUS_FIELDS,
        `at most ${MAX_STATUS_FIELDS} requested fields, got ${state.statusCalls[0].length}`
      );
    } finally {
      await server.close();
    }
  });

  it('consumes two correlated replies in one coalescing window without host submission', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const pending = new PendingStore();
    state.consume = (from, replyTo, body) => pending.settle(from, replyTo, body);
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const expected = { pid: senderIdent.pid, instance: senderIdent.instance };
      const ids = [generateId(), generateId()];
      assert.ok(pending.reserve(ids[0], expected));
      assert.ok(pending.reserve(ids[1], expected));
      const raws = [];
      for (const id of ids) {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        const hs = await verifiedHandshake(raw, receiver);
        raw.send(requestFrame({
          ...hs,
          sender: senderIdent,
          receiver,
          payload: { type: 'msg', body: `reply for ${id}`, replyTo: id, hop: 0 },
        }));
        raws.push(raw);
      }
      const codes = [];
      for (const raw of raws) codes.push(terminalCode(await raw.nextLine()));
      assert.deepEqual(codes, ['reply_consumed', 'reply_consumed']);
      assert.equal(state.delivered.length, 0, 'correlated replies bypass host batching entirely');
      assert.deepEqual(
        state.consumed.map((entry) => entry.body),
        [`reply for ${ids[0]}`, `reply for ${ids[1]}`],
        'consumed bodies stay raw'
      );
      for (const raw of raws) raw.close();
    } finally {
      await server.close();
    }
  });

  it('treats foreign and late replyTo values as ordinary messages', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const pending = new PendingStore();
    state.consume = (from, replyTo, body) => pending.settle(from, replyTo, body);
    const intruder = makeIdentity(48203);
    await putRecord(roots, intruder, { name: 'intruder' });
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const id = generateId();
      assert.ok(pending.reserve(id, { pid: senderIdent.pid, instance: senderIdent.instance }));

      // Foreign identity: settle refuses, so the frame becomes ordinary.
      const rawForeign = openRaw(server.endpoint);
      await rawForeign.connect();
      const hsForeign = await verifiedHandshake(rawForeign, receiver);
      rawForeign.send(requestFrame({
        ...hsForeign,
        sender: intruder,
        receiver,
        payload: { type: 'msg', body: 'foreign reply', replyTo: id, hop: 0 },
      }));
      assert.equal(terminalCode(await rawForeign.nextLine()), 'submitted');

      // Expected identity consumes it.
      const rawValid = openRaw(server.endpoint);
      await rawValid.connect();
      const hsValid = await verifiedHandshake(rawValid, receiver);
      rawValid.send(requestFrame({
        ...hsValid,
        sender: senderIdent,
        receiver,
        payload: { type: 'msg', body: 'real answer', replyTo: id, hop: 0 },
      }));
      assert.equal(terminalCode(await rawValid.nextLine()), 'reply_consumed');
      assert.equal(pending.size(), 0, 'the pending request settled');

      // Late: the same id after settlement is ordinary again.
      const rawLate = openRaw(server.endpoint);
      await rawLate.connect();
      const hsLate = await verifiedHandshake(rawLate, receiver);
      rawLate.send(requestFrame({
        ...hsLate,
        sender: senderIdent,
        receiver,
        payload: { type: 'msg', body: 'late answer', replyTo: id, hop: 0 },
      }));
      assert.equal(terminalCode(await rawLate.nextLine()), 'submitted');

      const bodies = state.delivered.flat().map((envelope) => envelope.body);
      assert.equal(bodies.length, 2, 'only foreign and late frames reach the host');
      assert.ok(bodies.some((body) => body.includes('foreign reply')));
      assert.ok(bodies.some((body) => body.includes('late answer')));
      for (const raw of [rawForeign, rawValid, rawLate]) raw.close();
    } finally {
      await server.close();
    }
  });

  it('renders [peer name] and [id value] markers into every batched envelope', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const ids = [];
      const raws = [];
      for (let i = 0; i < 2; i += 1) {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        const hs = await verifiedHandshake(raw, receiver);
        ids.push(hs.id);
        raw.send(requestFrame({
          ...hs,
          sender: senderIdent,
          receiver,
          payload: { type: 'msg', body: i === 0 ? 'one' : 'two', hop: 0 },
        }));
        raws.push(raw);
      }
      await waitFor(() => state.delivered.length >= 1, { label: 'one sealed batch' });
      await waitFor(() => state.delivered.flat().length >= 2, { label: 'both envelopes delivered' });
      const batches = state.delivered;
      assert.equal(batches.length, 1, 'both frames coalesce into one sealed batch');
      assert.equal(batches[0].length, 2, 'one host submission carries both frames');
      assert.deepEqual(
        batches[0].map((envelope) => envelope.body),
        [
          formatPeerText('alpha', 'one', { id: ids[0] }),
          formatPeerText('alpha', 'two', { id: ids[1] }),
        ],
        'each [id] marker renders the id of the request that carried it'
      );
      assert.match(batches[0][0].body, /^\[peer alpha\]: one \[id .+\]$/);
      for (const envelope of batches[0]) {
        assert.equal(typeof envelope.epoch.binding, 'number', 'envelopes carry the accept-time epoch');
        assert.equal(typeof envelope.epoch.transcript, 'number');
      }
      const codes = [];
      for (const raw of raws) codes.push(terminalCode(await raw.nextLine()));
      assert.deepEqual(codes, ['submitted', 'submitted']);
      for (const raw of raws) raw.close();
    } finally {
      await server.close();
    }
  });

  it('answers a wake-budget-exhausted batch with followup_submitted', async () => {
    const fake = createFakeHost();
    const pi = typeof fake.host?.sendUserMessage === 'function' ? fake.host : fake.host?.pi ?? fake.host;
    const ctx = fake.ctx;
    assert.equal(typeof pi.sendUserMessage, 'function', 'fixture host exposes sendUserMessage');
    const wakes = new WakeLimiter();
    for (let i = 0; i < WAKES_PER_HOUR; i += 1) {
      assert.equal(wakes.noteWake({ pid: senderIdent.pid, instance: senderIdent.instance }), true);
    }
    const realDelivery = createHostDelivery({
      getHost: () => ({ pi, ctx }),
      pending: new PendingStore(),
      wakes,
      heldCount: () => 0,
      acceptance: () => 'accepting',
      armed: () => true,
      notArmedDetail: () => 'peers: not armed',
      onSubmitted: () => {},
      captureEpoch: () => ({ binding: 0, transcript: 0 }),
      isEpochValid: () => true,
      getActivity: () => undefined,
    });
    const timers = makeTimers();
    const server = await startTestServer({ roots, identity: receiver, delivery: realDelivery, timers });
    try {
      const raw = openRaw(server.endpoint);
      await raw.connect();
      const hs = await verifiedHandshake(raw, receiver);
      raw.send(requestFrame({
        ...hs,
        sender: senderIdent,
        receiver,
        payload: { type: 'msg', body: 'over budget', hop: 0 },
      }));
      assert.equal(terminalCode(await raw.nextLine()), 'followup_submitted');
      assert.ok(fake.calls.sendUserMessage.length >= 1, 'the host call happened once');
      const call = fake.calls.sendUserMessage.at(-1);
      assert.equal(call.options.deliverAs, 'followUp');
      assert.equal(call.options.attribution, 'agent');
      assert.ok(call.content.includes('[peer alpha]'), 'rendered body reaches the host');
      assert.ok(call.content.includes('[id '), 'the [id] marker reaches the host');
      raw.close();
    } finally {
      await server.close();
    }
  });

  it('seals at eight messages without waiting for the coalesce window', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const ids = [];
      const raws = [];
      const started = Date.now();
      for (let i = 0; i < MAX_BATCH_MESSAGES; i += 1) {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        const hs = await verifiedHandshake(raw, receiver);
        ids.push(hs.id);
        raw.send(requestFrame({
          ...hs,
          sender: senderIdent,
          receiver,
          payload: { type: 'msg', body: `m${i}`, hop: 0 },
        }));
        raws.push(raw);
      }
      await waitFor(() => state.delivered.flat().length >= MAX_BATCH_MESSAGES, { label: 'eight-message seal' });
      const elapsed = Date.now() - started;
      assert.ok(elapsed < COALESCE_MS, `the count seal fired in ${elapsed}ms, before the ${COALESCE_MS}ms window`);
      assert.equal(state.delivered.length, 1, 'the first eight messages ride one sealed batch');
      assert.deepEqual(
        state.delivered[0].map((envelope) => envelope.body),
        ids.map((id, i) => formatPeerText('alpha', `m${i}`, { id })),
        'FIFO order survives the count seal'
      );

      // The ninth arrival opens the next batch instead of overflowing this one.
      const extra = openRaw(server.endpoint);
      await extra.connect();
      const hsExtra = await verifiedHandshake(extra, receiver);
      extra.send(requestFrame({
        ...hsExtra,
        sender: senderIdent,
        receiver,
        payload: { type: 'msg', body: 'm8', hop: 0 },
      }));
      await waitFor(() => state.delivered.flat().length >= MAX_BATCH_MESSAGES + 1, { label: 'ninth delivered' });
      assert.equal(state.delivered.length, 2, 'the ninth message seals into its own batch');
      assert.equal(state.delivered[1].length, 1);

      const codes = [];
      for (const raw of [...raws, extra]) codes.push(terminalCode(await raw.nextLine()));
      assert.deepEqual(codes, Array(MAX_BATCH_MESSAGES + 1).fill('submitted'));
      for (const raw of [...raws, extra]) raw.close();
    } finally {
      await server.close();
    }
  });

  it('seals when the batch reaches the 128 KiB payload ceiling', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      // Two 50 KB bodies sum under the 128 KiB ceiling; the third body would
      // exceed it, so the pre-append byte seal closes the current batch at
      // its two bodies and starts the next one, well before the 400 ms
      // window. Each payload carries a distinct marker so FIFO order across
      // the split is observable.
      const payloads = [0, 1, 2].map((i) => `m${i}-` + 'x'.repeat(49_997));
      const raws = [];
      const started = Date.now();
      for (const body of payloads) {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        const hs = await verifiedHandshake(raw, receiver);
        raw.send(requestFrame({
          ...hs,
          sender: senderIdent,
          receiver,
          payload: { type: 'msg', body, hop: 0 },
        }));
        raws.push(raw);
      }
      // The first sealed batch must land no later than the coalesce window
      // plus a small scheduling margin; a count seal cannot race here because
      // that needs MAX_BATCH_MESSAGES arrivals and only three sockets sent.
      await waitFor(() => state.delivered.length >= 1, { label: 'byte-ceiling seal' });
      const elapsed = Date.now() - started;
      assert.ok(
        elapsed <= COALESCE_MS + 50,
        `the byte seal fired in ${elapsed}ms, within the ${COALESCE_MS}ms window plus scheduling margin`
      );
      // The overflowing body rides the next batch, which its own coalesce
      // window delivers: together the batches must carry every body, in
      // order, and no batch may exceed the summed body-byte ceiling.
      await waitFor(() => state.delivered.flat().length >= 3, { label: 'overflow body delivered' });
      assert.equal(state.delivered.length, 2, 'the body that would cross the ceiling opens the next batch');
      assert.equal(state.delivered[0].length, 2, 'the ceiling seal closes the batch at its two bodies');
      assert.equal(state.delivered[1].length, 1, 'the overflowing body rides the next batch alone');
      for (const [index, batch] of state.delivered.entries()) {
        const bytes = batch.reduce((sum, envelope) => sum + Buffer.byteLength(envelope.body, 'utf8'), 0);
        assert.ok(
          bytes <= MAX_BATCH_BYTES,
          `batch ${index + 1} holds ${bytes} summed body bytes, at or under the ${MAX_BATCH_BYTES} byte ceiling`
        );
      }
      const bodies = state.delivered.flat().map((envelope) => envelope.body);
      for (let i = 0; i < payloads.length; i += 1) {
        assert.ok(bodies[i].includes(payloads[i]), `delivered slot ${i} carries body ${i} in FIFO order`);
      }
      const codes = [];
      for (const raw of raws) codes.push(terminalCode(await raw.nextLine()));
      assert.deepEqual(codes, ['submitted', 'submitted', 'submitted']);
      for (const raw of raws) raw.close();
    } finally {
      await server.close();
    }
  });

  it('submits one sealed batch as exactly one host call joining rendered bodies', { timeout: 30000 }, async () => {
    const fake = createFakeHost();
    const pi = typeof fake.host?.sendUserMessage === 'function' ? fake.host : fake.host?.pi ?? fake.host;
    const ctx = fake.ctx;
    assert.equal(typeof pi.sendUserMessage, 'function', 'fixture host exposes sendUserMessage');
    const delivery = createHostDelivery({
      getHost: () => ({ pi, ctx }),
      pending: new PendingStore(),
      wakes: new WakeLimiter(),
      heldCount: () => 0,
      acceptance: () => 'accepting',
      armed: () => true,
      notArmedDetail: () => 'peers: not armed',
      onSubmitted: () => {},
      captureEpoch: () => ({ binding: 0, transcript: 0 }),
      isEpochValid: () => true,
      getActivity: () => undefined,
    });
    const timers = makeTimers();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      // Complete both handshakes first so the two frames land back to back
      // inside one coalescing window, in a deterministic order.
      const bodies = ['join one', 'join two'];
      const ids = [];
      const frames = [];
      const raws = [];
      for (const body of bodies) {
        const raw = openRaw(server.endpoint);
        await raw.connect();
        const hs = await verifiedHandshake(raw, receiver);
        ids.push(hs.id);
        frames.push(requestFrame({ ...hs, sender: senderIdent, receiver, payload: { type: 'msg', body, hop: 0 } }));
        raws.push(raw);
      }
      for (let i = 0; i < raws.length; i += 1) raws[i].send(frames[i]);

      await waitFor(() => fake.calls.sendUserMessage.length >= 1, { label: 'host submission' });
      await sleep(COALESCE_MS + 150);
      assert.equal(fake.calls.sendUserMessage.length, 1, 'one sealed batch is exactly one host submission');
      const call = fake.calls.sendUserMessage[0];
      assert.equal(call.options.attribution, 'agent', 'every relayed submission is attributed to the agent');
      assert.equal(call.options.deliverAs, undefined, 'under the wake budget the call is immediate, not a followUp');
      // Two separate connections have no cross-arrival order: the batch
      // renders both bodies newline-joined in whichever order they arrived.
      const rendered = bodies.map((body, i) => formatPeerText('alpha', body, { id: ids[i] })).sort();
      const actual = call.content.split('\n').sort();
      assert.deepEqual(actual, rendered, 'rendered bodies are joined by exactly one newline');
      assert.equal(call.content.split('\n').length, 2, 'exactly one newline joins the two bodies');

      const codes = [];
      for (const raw of raws) codes.push(terminalCode(await raw.nextLine()));
      assert.deepEqual(codes, ['submitted', 'submitted']);
      for (const raw of raws) raw.close();
    } finally {
      await server.close();
    }
  });

  it('reports busy with the readBusy polarity of the live host context', async () => {
    const fake = createFakeHost();
    const pi = typeof fake.host?.sendUserMessage === 'function' ? fake.host : fake.host?.pi ?? fake.host;
    const ctx = fake.ctx;
    let idle = true;
    ctx.isIdle = () => idle;
    const delivery = createHostDelivery({
      getHost: () => ({ pi, ctx }),
      pending: new PendingStore(),
      wakes: new WakeLimiter(),
      heldCount: () => 0,
      acceptance: () => 'accepting',
      armed: () => true,
      notArmedDetail: () => 'peers: not armed',
      onSubmitted: () => {},
      captureEpoch: () => ({ binding: 0, transcript: 0 }),
      isEpochValid: () => true,
      getActivity: () => undefined,
    });
    const timers = makeTimers();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const pullStatus = async () => {
      const raw = openRaw(server.endpoint);
      await raw.connect();
      const hs = await verifiedHandshake(raw, receiver);
      raw.send(requestFrame({ ...hs, sender: senderIdent, receiver, payload: { type: 'status' } }));
      const line = await raw.nextLine();
      const code = terminalCode(line);
      const status = JSON.parse(line).status;
      raw.close();
      return { code, status };
    };
    try {
      // Mid-turn: the agent loop is NOT idle, so the peer is busy.
      idle = false;
      const busy = await pullStatus();
      assert.equal(busy.code, 'status');
      assert.equal(busy.status?.busy, true, 'isIdle() === false must report busy true');

      idle = true;
      const quiet = await pullStatus();
      assert.equal(quiet.code, 'status');
      assert.equal(quiet.status?.busy, false, 'isIdle() === true must report busy false');
      assert.equal(fake.calls.sendUserMessage.length, 0, 'status pulls never wake the host');
    } finally {
      await server.close();
    }
  });
});

describe('FIFO, held batches, and per-socket replies', () => {
  let roots;
  let receiver;
  let senderIdent;
  before(async () => {
    roots = await makeRoots('fifo');
    receiver = makeIdentity(48211);
    senderIdent = makeIdentity(48212);
    await putRecord(roots, receiver, { name: 'beta' });
    await putRecord(roots, senderIdent, { name: 'alpha' });
  });

  async function sendOne(server, body, opts = {}) {
    const raw = openRaw(server.endpoint);
    await raw.connect();
    const hs = await verifiedHandshake(raw, receiver);
    raw.send(requestFrame({
      ...hs,
      sender: opts.sender ?? senderIdent,
      receiver,
      payload: { type: 'msg', body, hop: 0 },
    }));
    return { raw, id: hs.id };
  }

  it('keeps arrivals behind held work FIFO and holds with exactly one reply', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    state.canSubmit = false;
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const first = await sendOne(server, 'first');
      await waitFor(() => state.heldReserves >= 1, { label: 'first batch held' });
      assert.equal(terminalCode(await first.raw.nextLine()), 'held');
      assert.equal(state.delivered.length, 0, 'nothing submitted while typing blocks');

      state.canSubmit = true;
      const second = await sendOne(server, 'second');
      assert.equal(terminalCode(await second.raw.nextLine()), 'submitted');
      await waitFor(() => state.delivered.flat().length >= 2, { label: 'both bodies delivered' });
      const bodies = state.delivered.flat().map((envelope) => envelope.body);
      const atFirst = bodies.findIndex((body) => body.includes('first'));
      const atSecond = bodies.findIndex((body) => body.includes('second'));
      assert.ok(atFirst >= 0 && atSecond >= 0, 'both bodies delivered');
      assert.ok(atFirst < atSecond, `FIFO: held 'first' must precede 'second', got ${JSON.stringify(bodies)}`);
      assert.equal(first.raw.lines.length, 1, 'one terminal reply for the held socket');
      assert.ok(state.releases >= 1, 'the held reservation is released once work flows');
      first.raw.close();
      second.raw.close();
    } finally {
      await server.close();
    }
  });

  it('refuses a new batch with busy when held capacity cannot be reserved', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    state.canSubmit = false;
    state.heldCapacity = false;
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const overflow = await sendOne(server, 'overflow');
      assert.equal(terminalCode(await overflow.raw.nextLine()), 'busy');
      assert.equal(state.heldReserves >= 1, true, 'the reservation was attempted');
      assert.equal(state.delivered.length, 0, 'a refused batch retains nothing');

      state.canSubmit = true;
      const later = await sendOne(server, 'later');
      assert.equal(terminalCode(await later.raw.nextLine()), 'submitted');
      await waitFor(() => state.delivered.flat().length >= 1, { label: 'later delivered' });
      const bodies = state.delivered.flat().map((envelope) => envelope.body);
      assert.ok(bodies.every((body) => !body.includes('overflow')), 'the refused batch never appears');
      assert.ok(bodies.some((body) => body.includes('later')));
      assert.equal(overflow.raw.lines.length, 1, 'one terminal reply for the refused socket');
      overflow.raw.close();
      later.raw.close();
    } finally {
      await server.close();
    }
  });

  it('submits a held batch exactly once when the hold timeout fires', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    state.canSubmit = false;
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const held = await sendOne(server, 'forced once');
      await waitFor(() => state.heldReserves >= 1, { label: 'batch held' });
      assert.equal(terminalCode(await held.raw.nextLine()), 'held');
      assert.ok(timers.armed(HOLD_TIMEOUT_MS) >= 1, 'the hold timeout is armed through managed timers');

      assert.ok(timers.fire(HOLD_TIMEOUT_MS) >= 1, 'the hold timeout fired');
      await waitFor(() => state.delivered.flat().length >= 1, { label: 'forced submission' });
      timers.fire(HOLD_TIMEOUT_MS);
      await sleep(100);
      const count = state.delivered.flat().filter((envelope) => envelope.body.includes('forced once')).length;
      assert.equal(count, 1, 'exactly one forced submission');
      assert.equal(state.releases, 1, 'the held reservation is released exactly once');
      assert.equal(held.raw.lines.length, 1, 'no second network reply after the forced submit');
      held.raw.close();
    } finally {
      await server.close();
    }
  });
});

describe('transcript commits purge stale server work', () => {
  let roots;
  let receiver;
  let senderIdent;
  before(async () => {
    roots = await makeRoots('epoch');
    receiver = makeIdentity(48221);
    senderIdent = makeIdentity(48222);
    await putRecord(roots, receiver, { name: 'beta' });
    await putRecord(roots, senderIdent, { name: 'alpha' });
  });

  async function openAndSend(server, body) {
    const raw = openRaw(server.endpoint);
    await raw.connect();
    const hs = await verifiedHandshake(raw, receiver);
    raw.send(requestFrame({
      ...hs,
      sender: senderIdent,
      receiver,
      payload: { type: 'msg', body, hop: 0 },
    }));
    return raw;
  }

  it('settles stale waiting sockets exactly once with session_transition and leaves fresh work untouched', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const logs = [];
    const server = await startTestServer({
      roots,
      identity: receiver,
      delivery,
      timers,
      log: (text) => logs.push(text),
    });
    assert.equal(typeof server.purgeStaleWork, 'function', 'ServerHandle exposes purgeStaleWork');
    try {
      const staleA = await openAndSend(server, 'stale one');
      const staleB = await openAndSend(server, 'stale two');
      // The commit may only overtake requests the server already accepted;
      // an accept captured after the new epoch stays fresh by contract.
      await waitFor(() => state.captures >= 2, { label: 'both requests accepted' });

      // A transcript commit advances the epoch, then purges with the exact
      // predicate the binding uses.
      state.epoch = { binding: 0, transcript: 1 };
      server.purgeStaleWork((epoch) => epoch.binding !== 0 || epoch.transcript !== 1);

      assert.equal(terminalCode(await staleA.nextLine()), 'session_transition');
      assert.equal(terminalCode(await staleB.nextLine()), 'session_transition');
      assert.equal(staleA.lines.length, 1, 'exactly one terminal reply per stale socket');
      assert.equal(staleB.lines.length, 1);

      // Dropped frames never reach the host, even after the coalesce window.
      await sleep(COALESCE_MS + 150);
      assert.equal(state.delivered.length, 0, 'stale frames were dropped, not submitted');

      // Fresh-epoch work on the same server still flows, on the same identity.
      const fresh = await openAndSend(server, 'fresh one');
      assert.equal(terminalCode(await fresh.nextLine()), 'submitted');
      await waitFor(() => state.delivered.flat().length >= 1, { label: 'fresh submission' });
      const envelope = state.delivered[0][0];
      assert.deepEqual(
        { binding: envelope.epoch.binding, transcript: envelope.epoch.transcript },
        { binding: 0, transcript: 1 },
        'fresh work carries the new epoch'
      );
      assert.match(envelope.body, /^\[peer alpha\]: fresh one \[id .+\]$/);
      for (const raw of [staleA, staleB, fresh]) raw.close();
    } finally {
      await server.close();
    }
  });

  it('drops a stale held copy silently and releases its reservation', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    state.canSubmit = false;
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const held = await openAndSend(server, 'held before commit');
      await waitFor(() => state.heldReserves >= 1, { label: 'batch held' });
      assert.equal(terminalCode(await held.nextLine()), 'held');

      state.epoch = { binding: 0, transcript: 1 };
      server.purgeStaleWork((epoch) => epoch.transcript !== 1);

      await sleep(80);
      assert.equal(held.lines.length, 1, 'an acknowledged held copy earns no second network reply');
      assert.ok(state.releases >= 1, 'the held reservation is released');

      // The stale copy is gone: even the armed hold timeout finds nothing.
      timers.fire(HOLD_TIMEOUT_MS);
      await sleep(80);
      const allBodies = state.delivered.flat().concat(state.attempts.flat()).map((envelope) => envelope.body);
      assert.ok(allBodies.every((body) => !body.includes('held before commit')), 'the stale copy never submits');
      held.close();
    } finally {
      await server.close();
    }
  });

  it('discards a forced hold-timeout submission at a stale epoch with one bounded warning', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const logs = [];
    state.canSubmit = false;
    const server = await startTestServer({
      roots,
      identity: receiver,
      delivery,
      timers,
      log: (text) => logs.push(text),
    });
    try {
      const held = await openAndSend(server, 'pump stale');
      await waitFor(() => state.heldReserves >= 1, { label: 'batch held' });
      assert.equal(terminalCode(await held.nextLine()), 'held');
      const logsBefore = logs.length;

      // Commit without purging first: the forced pump must recheck the epoch.
      state.epoch = { binding: 1, transcript: 0 };
      timers.fire(HOLD_TIMEOUT_MS);
      await sleep(100);

      const touched = state.delivered.concat(state.attempts)
        .flat()
        .filter((envelope) => envelope.body.includes('pump stale'));
      assert.equal(touched.length, 0, 'a stale pump copy never reaches the host');
      assert.equal(logs.length - logsBefore, 1, 'exactly one bounded local warning');
      assert.equal(held.lines.length, 1, 'no second network reply');
      held.close();
    } finally {
      await server.close();
    }
  });

  it('rechecks the captured epoch at submit time', { timeout: 30000 }, async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const raw = await openAndSend(server, 'commit mid-window');
      // Commit after accept but before the coalesce seal: wait until the
      // accept-time epoch capture exists, or the commit lands before the
      // request and there is nothing stale to recheck.
      await waitFor(() => state.captures >= 1, { label: 'request accepted' });
      state.epoch = { binding: 0, transcript: 7 };
      const code = terminalCode(await raw.nextLine());
      assert.equal(code, 'session_transition');
      await sleep(80);
      assert.equal(state.delivered.length, 0, 'the stale batch never reaches the host');
      assert.equal(state.attempts.length, 0, 'the stale batch is refused before any host call');
      raw.close();
    } finally {
      await server.close();
    }
  });
});

describe('non-accepting states settle sockets exactly once', () => {
  let roots;
  let receiver;
  let senderIdent;

  async function openAndSend(server, body) {
    const raw = openRaw(server.endpoint);
    await raw.connect();
    const hs = await verifiedHandshake(raw, receiver);
    raw.send(requestFrame({
      ...hs,
      sender: senderIdent,
      receiver,
      payload: { type: 'msg', body, hop: 0 },
    }));
    return raw;
  }

  before(async () => {
    roots = await makeRoots('acceptance');
    receiver = makeIdentity(48401);
    senderIdent = makeIdentity(48402);
    await putRecord(roots, receiver, { name: 'beta' });
    await putRecord(roots, senderIdent, { name: 'alpha' });
  });

  it('maps each non-accepting state to its exact refusal code with no cross-labelling', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      state.acceptance = 'shutting_down';
      const down = await openAndSend(server, 'while closing');
      assert.equal(terminalCode(await down.nextLine()), 'shutting_down');
      await sleep(50);
      assert.equal(down.lines.length, 1, 'the shut-down socket settles exactly once as shutting_down');

      state.acceptance = 'session_transition';
      const fenced = await openAndSend(server, 'while fenced');
      assert.equal(terminalCode(await fenced.nextLine()), 'session_transition');
      await sleep(50);
      assert.equal(fenced.lines.length, 1, 'the transition-fenced socket settles exactly once');

      assert.equal(state.delivered.length, 0, 'non-accepting work never reaches the host');

      // Re-opening resumes ordinary flow on the same server.
      state.acceptance = 'accepting';
      const fresh = await openAndSend(server, 'after reopening');
      assert.equal(terminalCode(await fresh.nextLine()), 'submitted');
      await waitFor(() => state.delivered.flat().length >= 1, { label: 'fresh submission after reopen' });
      assert.equal(fresh.lines.length, 1);
      for (const raw of [down, fenced, fresh]) raw.close();
    } finally {
      await server.close();
    }
  });

  it('settles a socket owed its reply at shutdown exactly once with shutting_down', async () => {
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    const owed = await openAndSend(server, 'in flight at close');
    // The accept-time epoch capture proves the request is owed before close.
    await waitFor(() => state.captures >= 1, { label: 'request accepted' });
    await server.close();
    assert.equal(terminalCode(await owed.nextLine()), 'shutting_down');
    await sleep(COALESCE_MS + 150);
    assert.equal(owed.lines.length, 1, 'close and the later seal cannot double-reply');
    assert.equal(state.delivered.length, 0, 'work owed at shutdown never reaches the host');
    owed.close();
  });

  it('refuses every outbound operation with the exact state code and never dials', async () => {
    const target = makeIdentity(48403);
    const counter = await makeOutboundServer(roots, target, { onLine: () => {} });
    try {
      const sender = makeIdentity(48404);
      for (const refusal of ['session_transition', 'shutting_down']) {
        const timers = makeTimers();
        const { deps } = makeDeps({
          roots,
          identity: sender,
          timers,
          scan: async () => [memoryRecord(target, { name: 'gated' })],
          acceptance: () => refusal,
        });
        expectCode(await sendMsg(deps, 'gated', 'refused before dial'), refusal);
        expectCode(await requestMsg(deps, 'gated', 'refused before dial'), refusal);
        expectCode(await pingPeer(deps, 'gated'), refusal);
        expectCode(await statusOf(deps, 'gated', ['busy']), refusal);
      }
      await sleep(150);
      assert.equal(counter.acceptedCount, 0, 'a non-accepting operation never opens a connection');
    } finally {
      await counter.stop();
    }
  });
});

describe('retry gates and pending slots', () => {
  let roots;
  let requester;

  function refusingServer(identity, code) {
    return makeOutboundServer(roots, identity, {
      onLine(socket, line) {
        if (line.startsWith('{"v":2,"type":"hello"')) {
          answerHello(socket, line, identity);
        } else {
          const request = JSON.parse(line);
          socket.write(signedReply(identity, request.id, code));
        }
      },
    });
  }

  before(async () => {
    roots = await makeRoots('retry');
    requester = makeIdentity(48231);
    await putRecord(roots, requester, { name: 'self' });
  });

  it('retargets a pending slot atomically and settles only the new identity', async () => {
    const pending = new PendingStore();
    const idA = generateId();
    const idB = generateId();
    const oldTarget = { pid: 48232, instance: generateInstance() };
    const newTarget = { pid: 48233, instance: generateInstance() };

    assert.notEqual(idA, idB, 'generated ids never collide');
    assert.ok(pending.reserve(idA, oldTarget));
    assert.ok(!pending.reserve(idA, oldTarget), 'a duplicate id never reserves a second slot');
    assert.equal(pending.retarget(idA, newTarget), true, 'unwritten slots retarget atomically');
    assert.equal(pending.settle(oldTarget, idA, 'late from old'), false, 'the old identity can no longer resolve it');
    assert.equal(pending.settle(newTarget, idA, 'answer from new'), true, 'the new identity resolves it');
    assert.equal(pending.size(), 0);

    // Pre-generate a collision-free fill set so a random id clash can never
    // masquerade as a reserve refusal.
    const fillIds = [];
    while (fillIds.length < MAX_PENDING_REQUESTS) {
      const id = generateId();
      if (id !== idA && id !== idB && !fillIds.includes(id)) fillIds.push(id);
    }
    for (let i = 0; i < fillIds.length; i += 1) {
      assert.ok(pending.reserve(fillIds[i], newTarget), `slot ${i + 1} reserves`);
    }
    assert.ok(!pending.reserve(generateId(), newTarget), 'the 17th pending request is refused');
    pending.rejectAll('session_transition');
    assert.equal(pending.size(), 0, 'a commit clears every pending slot');
  });

  it('rejects every in-flight request with session_transition when the binding commits', async () => {
    const responder = makeIdentity(48234);
    await putRecord(roots, responder, { name: 'responder' });
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: responder, delivery, timers });
    try {
      const { deps, pending } = makeDeps({
        roots,
        identity: requester,
        timers,
        scan: async () => [memoryRecord(responder, { name: 'responder' })],
      });
      const inFlight = requestMsg(deps, 'responder', 'question');
      await waitFor(() => state.attempts.length >= 1, { label: 'request delivered' });
      pending.rejectAll('session_transition');
      expectCode(await inFlight, 'session_transition');
      assert.equal(pending.size(), 0);
    } finally {
      await server.close();
    }
  });

  it('retries a pre-write failure against a freshly resolved replacement', async () => {
    const dead = makeIdentity(48235);
    const alive = makeIdentity(48236);
    await putRecord(roots, alive, { name: 'target' });
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const consumeState = makeDelivery();
    const target = await startTestServer({ roots, identity: alive, delivery, timers });
    // The requester answers inbound replies through its own server.
    const { deps, pending } = makeDeps({
      roots,
      identity: requester,
      timers,
      scan: async () => {
        deps.scanCalls = (deps.scanCalls ?? 0) + 1;
        return deps.scanCalls === 1
          ? [memoryRecord(dead, { name: 'target' })]
          : [memoryRecord(alive, { name: 'target' })];
      },
    });
    consumeState.state.consume = (from, replyTo, body) => pending.settle(from, replyTo, body);
    const home = await startTestServer({ roots, identity: requester, delivery: consumeState.delivery, timers });
    try {
      const inFlight = requestMsg(deps, 'target', 'question');
      await waitFor(() => state.attempts.length >= 1, { label: 'replacement accepted the request' });
      // The request envelope's correlation id is its id; replyTo belongs to
      // REPLY messages, which the replacement sends below with replyTo: slot.
      const slot = state.attempts[0][0].id;
      assert.equal(typeof slot, 'string', 'the request carries its correlation id');
      assert.equal(slot.length, ID_B64_CHARS, 'the correlation id is a 22-char canonical string');
      assert.ok(isCanonicalId(slot), 'the correlation id is canonical');

      // The replacement answers through the requester's server, resolving
      // the same pending slot the retry reused.
      const answer = openRaw(home.endpoint);
      await answer.connect();
      const hs = await verifiedHandshake(answer, requester);
      answer.send(requestFrame({
        ...hs,
        sender: alive,
        receiver: requester,
        payload: { type: 'msg', body: 'answer from b', replyTo: slot, hop: 0 },
      }));
      assert.equal(terminalCode(await answer.nextLine()), 'reply_consumed');
      answer.close();

      const result = await inFlight;
      expectCode(result, 'reply_consumed');
      assert.equal(result.replyBody, 'answer from b');
      assert.ok((deps.scanCalls ?? 0) >= 2, 'a fresh scan ran for the retry');
    } finally {
      await home.close();
      await target.close();
    }
  });

  it('retries an authenticated wrong_recipient once to a different unique identity', async () => {
    const stale = makeIdentity(48237);
    const replacement = makeIdentity(48238);
    await putRecord(roots, stale, { name: 'stale-a' });
    await putRecord(roots, replacement, { name: 'target' });
    const refusing = await refusingServer(stale, 'wrong_recipient');
    const targetTimers = makeTimers();
    const targetDelivery = makeDelivery();
    const target = await startTestServer({
      roots,
      identity: replacement,
      delivery: targetDelivery.delivery,
      timers: targetTimers,
    });
    const timers = makeTimers();
    let scans = 0;
    const { deps, pending } = makeDeps({
      roots,
      identity: requester,
      timers,
      scan: async () => {
        scans += 1;
        return scans === 1
          ? [memoryRecord(stale, { name: 'target' })]
          : [memoryRecord(replacement, { name: 'target' })];
      },
    });
    const consumeState = makeDelivery();
    consumeState.state.consume = (from, replyTo, body) => pending.settle(from, replyTo, body);
    const home = await startTestServer({ roots, identity: requester, delivery: consumeState.delivery, timers });
    try {
      const inFlight = requestMsg(deps, 'target', 'question after refusal');
      await waitFor(() => refusing.acceptedCount >= 1 && targetDelivery.state.attempts.length >= 1, {
        label: 'retry reached the replacement',
      });
      const slot = targetDelivery.state.attempts[0][0].id;
      assert.equal(typeof slot, 'string', 'the request carries its correlation id');
      assert.equal(slot.length, ID_B64_CHARS, 'the correlation id is a 22-char canonical string');
      assert.ok(isCanonicalId(slot), 'the correlation id is canonical');
      assert.equal(scans, 2, 'exactly one fresh scan decides the retry');
      assert.equal(refusing.acceptedCount, 1, 'the refusing target is dialed exactly once');

      const answer = openRaw(home.endpoint);
      await answer.connect();
      const hs = await verifiedHandshake(answer, requester);
      answer.send(requestFrame({
        ...hs,
        sender: replacement,
        receiver: requester,
        payload: { type: 'msg', body: 'answer from replacement', replyTo: slot, hop: 0 },
      }));
      assert.equal(terminalCode(await answer.nextLine()), 'reply_consumed');
      answer.close();

      expectCode(await inFlight, 'reply_consumed');

      // A late frame from the OLD identity resolves nothing and becomes
      // an ordinary host message instead.
      const late = openRaw(home.endpoint);
      await late.connect();
      const hsLate = await verifiedHandshake(late, requester);
      late.send(requestFrame({
        ...hsLate,
        sender: stale,
        receiver: requester,
        payload: { type: 'msg', body: 'late from old a', replyTo: slot, hop: 0 },
      }));
      assert.equal(terminalCode(await late.nextLine()), 'submitted');
      await waitFor(
        () => consumeState.state.delivered.flat().some((envelope) => envelope.body.includes('late from old a')),
        { label: 'late reply delivered as ordinary' }
      );
      late.close();
      assert.ok(isRetryableRefusal('wrong_recipient'), 'wrong_recipient is retryable only via a new identity');
    } finally {
      await home.close();
      await target.close();
      await refusing.stop();
    }
  });

  it('never retries the same identity', async () => {
    const same = makeIdentity(48239);
    await putRecord(roots, same, { name: 'target' });
    const refusing = await refusingServer(same, 'wrong_recipient');
    try {
      const timers = makeTimers();
      let scans = 0;
      const { deps } = makeDeps({
        roots,
        identity: requester,
        timers,
        scan: async () => {
          scans += 1;
          return [memoryRecord(same, { name: 'target' })];
        },
      });
      expectCode(await requestMsg(deps, 'target', 'question'), 'wrong_recipient');
      await sleep(150);
      assert.equal(refusing.acceptedCount, 1, 'the same identity is dialed exactly once');
      assert.ok(scans >= 1, 'a fresh scan ran and still resolved the same identity');
    } finally {
      await refusing.stop();
    }
  });

  it('never retries an ambiguous identity or a replay refusal', async () => {
    // Ambiguous: the fresh scan resolves two live records to one name.
    const first = makeIdentity(48240);
    const second = makeIdentity(48241);
    await putRecord(roots, first, { name: 'target' });
    await putRecord(roots, second, { name: 'target' });
    const refusing = await refusingServer(first, 'wrong_recipient');
    try {
      const timers = makeTimers();
      let scans = 0;
      const { deps } = makeDeps({
        roots,
        identity: requester,
        timers,
        scan: async () => {
          scans += 1;
          return scans === 1
            ? [memoryRecord(first, { name: 'target' })]
            : [memoryRecord(first, { name: 'target' }), memoryRecord(second, { name: 'target' })];
        },
      });
      expectCode(await requestMsg(deps, 'target', 'question'), 'wrong_recipient');
      await sleep(150);
      assert.equal(refusing.acceptedCount, 1, 'an ambiguous fresh scan never dials');
    } finally {
      await refusing.stop();
    }

    // Replay is never retryable, even when a fresh scan finds someone new.
    const replaying = makeIdentity(48242);
    const elsewhere = makeIdentity(48243);
    await putRecord(roots, replaying, { name: 'target' });
    const replayServer = await refusingServer(replaying, 'replay');
    try {
      const timers = makeTimers();
      let scans = 0;
      const { deps } = makeDeps({
        roots,
        identity: requester,
        timers,
        scan: async () => {
          scans += 1;
          return scans === 1
            ? [memoryRecord(replaying, { name: 'target' })]
            : [memoryRecord(elsewhere, { name: 'target' })];
        },
      });
      expectCode(await requestMsg(deps, 'target', 'question'), 'replay');
      await sleep(150);
      assert.equal(replayServer.acceptedCount, 1, 'a replay refusal never redials');
      assert.equal(isRetryableRefusal('replay'), false);
      assert.equal(isRetryableRefusal('unknown_outcome'), false);
      assert.equal(isRetryableRefusal('unauthenticated'), false);
      assert.equal(isRetryableRefusal('stale_sender'), false);
      assert.equal(isRetryableRefusal('bad_frame'), false);
      assert.equal(isRetryableRefusal('unsupported_version'), false);
      assert.equal(isRetryableRefusal('busy'), true);
      assert.equal(isRetryableRefusal('session_transition'), true);
      assert.equal(isRetryableRefusal('host_unavailable'), true);
    } finally {
      await replayServer.stop();
    }
  });
});

describe('release constants at their boundaries', () => {
  it('matches the plan section 3 table exactly', () => {
    assert.equal(PROTOCOL_VERSION, 2);
    assert.equal(HELLO_MAX_BYTES, 1024);
    assert.equal(CHALLENGE_MAX_BYTES, 1024);
    assert.equal(REQUEST_MAX_BYTES, 262144);
    assert.equal(BODY_MAX_BYTES, 65536);
    assert.equal(REPLY_MAX_BYTES, 8192);
    assert.equal(RECORD_MAX_BYTES, 8192);
    assert.equal(MAX_DIR_ENTRIES, 1024);
    assert.equal(MAX_ROUTABLE_PEERS, 256);
    assert.equal(PROJECT_MAX_BYTES, 64);
    assert.equal(MAX_INBOUND_SOCKETS, 64);
    assert.equal(MAX_OUTBOUND_SOCKETS, 32);
    assert.equal(MAX_SENDER_QUEUES, 32);
    assert.equal(MAX_BATCHES_PER_SENDER, 2);
    assert.equal(MAX_BATCH_MESSAGES, 8);
    assert.equal(MAX_BATCH_BYTES, 131072);
    assert.equal(COALESCE_MS, 400);
    assert.equal(DRAIN_GRACE_MS, 250);
    assert.equal(MAX_PENDING_REQUESTS, 16);
    assert.equal(REPLAY_CACHE_SIZE, 4096);
    assert.equal(REPLAY_TTL_MS, 120000);
    assert.equal(MAX_PAST_MS, 120000);
    assert.equal(MAX_FUTURE_MS, 30000);
    assert.equal(HANDSHAKE_TIMEOUT_MS, 2000);
    assert.equal(RECEIPT_TIMEOUT_MS, 8000);
    assert.equal(REQUEST_TIMEOUT_DEFAULT_MS, 30000);
    assert.equal(REQUEST_TIMEOUT_MIN_MS, 5000);
    assert.equal(REQUEST_TIMEOUT_MAX_MS, 120000);
    assert.equal(HEARTBEAT_MS, 15000, 'heartbeat cadence is 15 s');
    assert.equal(PRESENCE_TTL_MS, 45000, 'presence TTL is 45 s');
    assert.equal(MAX_HELD_BATCHES, 20);
    assert.equal(HOLD_TIMEOUT_MS, 120000);
    assert.equal(STATUS_FANOUT, 8);
    assert.equal(STATUS_BUDGET_MS, 1200, 'status fan-out budget is 1.2 s');
    assert.equal(MAX_STATUS_FIELDS, 3);
    assert.equal(MAX_STATUS_TODOS, 20);
    assert.equal(MAX_STATUS_TEXT_BYTES, 200);
    assert.equal(MAX_STATUS_ACTIVITY_BYTES, 256);
    assert.equal(MAX_HOP, 4);
    assert.equal(WAKES_PER_HOUR, 20);
    assert.equal(MAX_WAKE_IDENTITIES, 256);
    assert.equal(PROCESS_WAKES_PER_HOUR, 60);
    assert.equal(WAKE_WINDOW_MS, 3600000);
    assert.equal(ID_BYTES, 16);
    assert.equal(TOKEN_BYTES, 32);
    assert.equal(INSTANCE_HEX_CHARS, 32);
    assert.equal(ID_B64_CHARS, 22, 'ids and nonces are exactly 22 characters');
    assert.equal(TOKEN_B64_CHARS, 43);
  });

  it('accepts exactly at the frame byte ceilings and rejects one byte more', () => {
    const padTo = (text, bytes) => {
      const base = text.replace(/\n+$/, '');
      const size = Buffer.byteLength(base, 'utf8');
      assert.ok(size <= bytes, `fixture frame ${size} must fit ${bytes}`);
      return base + ' '.repeat(bytes - size);
    };
    const id = generateId();
    const nonce = generateId();
    const from = { pid: 48301, instance: generateInstance() };
    const to = { pid: 48302, instance: generateInstance() };

    const helloExact = padTo(encodeLine(helloFrame(id, to, nonce)), HELLO_MAX_BYTES);
    assert.ok(parseHello(helloExact), 'a 1024-byte hello parses');
    assert.equal(parseHello(`${helloExact} `), undefined, 'a 1025-byte hello is rejected');

    const challengeExact = padTo(encodeLine({
      v: 2,
      type: 'challenge',
      id,
      from: to,
      clientNonce: nonce,
      serverNonce: nonce,
      auth: 'a'.repeat(64),
    }), CHALLENGE_MAX_BYTES);
    assert.ok(parseChallenge(challengeExact), 'a 1024-byte challenge parses');
    assert.equal(parseChallenge(`${challengeExact} `), undefined, 'a 1025-byte challenge is rejected');

    const requestExact = padTo(encodeLine({
      v: 2,
      type: 'request',
      id,
      clientNonce: nonce,
      serverNonce: nonce,
      sentAt: Date.now(),
      from,
      to,
      payload: { type: 'msg', body: 'x', hop: 0 },
      auth: 'a'.repeat(64),
    }), REQUEST_MAX_BYTES);
    assert.ok(parseRequest(requestExact), 'a 262144-byte request parses');
    assert.equal(parseRequest(`${requestExact} `), undefined, 'a 262145-byte request is rejected');

    const replyExact = padTo(encodeLine({
      v: 2,
      type: 'reply',
      id,
      from: to,
      code: 'submitted',
      auth: 'a'.repeat(64),
    }), REPLY_MAX_BYTES);
    assert.ok(parseReply(replyExact), 'an 8192-byte reply parses');
    assert.equal(parseReply(`${replyExact} `), undefined, 'an 8193-byte reply is rejected');

    const record = JSON.stringify({
      v: 2,
      pid: 48303,
      instance: generateInstance(),
      token: generateToken(),
      name: 'padded',
      project: 'proj',
      harness: 'omp',
      startedAt: 1,
      beatAt: 1,
      busy: false,
    });
    const recordExact = padTo(record, RECORD_MAX_BYTES);
    assert.equal(parseRecord(recordExact).kind, 'v2', 'an 8192-byte record parses');
    assert.equal(parseRecord(`${recordExact} `).kind, 'malformed', 'an 8193-byte record is rejected');
    assert.equal(parseRecord('x'.repeat(RECORD_MAX_BYTES + 1)).kind, 'malformed');
  });

  it('holds the 64 KiB body, 64-byte project, and 45 s presence boundaries', () => {
    const id = generateId();
    const nonce = generateId();
    const from = { pid: 48304, instance: generateInstance() };
    const to = { pid: 48305, instance: generateInstance() };
    const bodyFrame = (body) => encodeLine({
      v: 2,
      type: 'request',
      id,
      clientNonce: nonce,
      serverNonce: nonce,
      sentAt: Date.now(),
      from,
      to,
      payload: { type: 'msg', body, hop: 0 },
      auth: 'a'.repeat(64),
    });
    assert.ok(parseRequest(bodyFrame('x'.repeat(BODY_MAX_BYTES))), 'a 65536-byte body parses');
    assert.equal(parseRequest(bodyFrame('x'.repeat(BODY_MAX_BYTES + 1))), undefined, 'a 65537-byte body is refused');

    const longProject = projectFor(`/tmp/${'p'.repeat(PROJECT_MAX_BYTES * 2)}`);
    assert.equal(Buffer.byteLength(longProject, 'utf8'), PROJECT_MAX_BYTES, 'the project clamps to exactly 64 bytes');
    assert.equal(projectFor('/'), 'peer', 'an unusable cwd falls back to peer');

    const now = Date.now();
    assert.equal(isRecordFresh(now - PRESENCE_TTL_MS, now), true, 'a beat stays fresh through exactly 45 s');
    assert.equal(isRecordFresh(now - PRESENCE_TTL_MS - 1, now), false, 'one ms past the TTL is stale');
  });

  it('fills the replay cache to exactly its capacity and expires by TTL', { timeout: 60000 }, () => {
    const cache = new ReplayCache();
    const now = Date.now();
    const sender = { pid: 48306, instance: generateInstance() };
    const ids = [];
    for (let i = 0; i < REPLAY_CACHE_SIZE; i += 1) {
      const fresh = generateId();
      ids.push(fresh);
      assert.equal(cache.tryInsert(sender, fresh, now), 'ok', `insert ${i + 1} of ${REPLAY_CACHE_SIZE} fits`);
    }
    const other = { pid: 48307, instance: generateInstance() };
    const overflowId = generateId();
    assert.equal(cache.tryInsert(other, overflowId, now), 'full', 'the 4097th entry is refused');
    assert.equal(cache.tryInsert(sender, ids[0], now), 'replay', 'a full cache never evicts an unexpired id');
    assert.equal(cache.tryInsert(other, overflowId, now), 'full', 'a refused id is never recorded');
    assert.equal(
      cache.tryInsert(sender, ids[0], now + REPLAY_TTL_MS + 1),
      'ok',
      'expired entries prune by TTL'
    );
  });

  // __APPEND__
});

describe('wake budgets, identity pressure, and the shared process ring', () => {
  it('caps each peer at its hourly wake budget and expires with the window', () => {
    const wakes = new WakeLimiter();
    const now = Date.now();
    const key = { pid: 58501, instance: generateInstance() };
    for (let i = 0; i < WAKES_PER_HOUR; i += 1) {
      assert.equal(wakes.noteWake(key, now), true, `wake ${i + 1} of ${WAKES_PER_HOUR} fits`);
    }
    assert.equal(wakes.noteWake(key, now), false, 'the 21st wake inside the window is refused');
    assert.equal(wakes.overBudget(key, now), true);
    assert.equal(wakes.overBudget(key, now + WAKE_WINDOW_MS + 1), false, 'stamps expire with the window');
    assert.equal(wakes.noteWake(key, now + WAKE_WINDOW_MS + 1), true, 'an expired budget starts fresh');
  });

  it('never lets a rename bypass the per-identity wake budget', () => {
    const wakes = new WakeLimiter();
    const now = Date.now();
    const key = { pid: 58502, instance: generateInstance() };
    for (let i = 0; i < WAKES_PER_HOUR; i += 1) {
      assert.equal(wakes.noteWake(key, now), true, `wake ${i + 1} of ${WAKES_PER_HOUR} fits`);
    }
    assert.equal(wakes.noteWake(key, now), false, 'the budget is exhausted');
    // A rename changes the display name only; the wake key is the identity,
    // so the renamed peer lands on the same exhausted bucket.
    const renamed = { pid: key.pid, instance: key.instance };
    assert.equal(wakes.noteWake(renamed, now), false, 'a rename never resets the budget');
    assert.equal(wakes.overBudget(renamed, now), true);
  });

  it('admits the 256th wake identity, refuses the 257th, and frees the slot on expiry', () => {
    const wakes = new WakeLimiter();
    const now = Date.now();
    const identities = [];
    for (let i = 0; i < MAX_WAKE_IDENTITIES; i += 1) {
      const key = { pid: 58600 + i, instance: generateInstance() };
      identities.push(key);
      assert.equal(wakes.noteWake(key, now), true, `identity ${i + 1} of ${MAX_WAKE_IDENTITIES} wakes`);
    }
    const late = { pid: 58600 + MAX_WAKE_IDENTITIES, instance: generateInstance() };
    assert.equal(wakes.noteWake(late, now), false, 'the 257th unseen identity is refused while the table is full');
    assert.equal(wakes.noteWake(identities[0], now), true, 'a tracked identity keeps waking while full');
    assert.equal(
      wakes.noteWake(late, now + WAKE_WINDOW_MS + 1),
      true,
      'expiry prunes stale identities and frees the slot'
    );
  });

  it('shares one 60-per-hour wake ring across two bindings', () => {
    // The process ring is the only module-global mutable state: each binding
    // owns a fresh WakeLimiter but both burn the same ring. A future instant
    // makes any stamps left by earlier submissions fall out of the window, so
    // the boundary is exact regardless of suite order.
    const base = Date.now() + WAKE_WINDOW_MS + 1;
    const bindingA = new WakeLimiter();
    const bindingB = new WakeLimiter();

    // Binding A burns the shared ring exactly as createHostDelivery combines
    // the gates: overBudget first, then processWakeAllowed, then noteWake.
    let admitted = 0;
    for (let i = 0; i < PROCESS_WAKES_PER_HOUR; i += 1) {
      const key = { pid: 58800 + i, instance: generateInstance() };
      if (bindingA.overBudget(key, base)) continue;
      if (!processWakeAllowed(base)) continue;
      assert.equal(bindingA.noteWake(key, base), true, 'fresh keys pass the identity gate');
      admitted += 1;
    }
    assert.equal(admitted, PROCESS_WAKES_PER_HOUR, `exactly ${PROCESS_WAKES_PER_HOUR} wakes fit in one window`);

    // The 61st is denied even though binding B's own limiter is fresh: the
    // ring is shared, so B cannot wake through it either.
    const keyB = { pid: 58901, instance: generateInstance() };
    assert.equal(bindingB.overBudget(keyB, base), false, 'binding B is not identity-limited');
    assert.equal(processWakeAllowed(base), false, 'binding B is refused by the shared exhausted ring');

    // Window expiry restores the ring for both bindings.
    assert.equal(processWakeAllowed(base + WAKE_WINDOW_MS + 1), true, 'the ring expires with the window');
  });
});

describe('real child processes over unix sockets', () => {
  it('starts a standalone child that writes a parseable record and binds its endpoint', { timeout: 30000 }, async () => {
    const peerDir = join('/tmp', `opf-solo-${process.pid}`);
    await rm(peerDir, { recursive: true, force: true });
    const child = await startChild({ peerDir, label: 'solo' });
    try {
      await child.ready;
      const parsed = parseRecord(await readFile(child.recordPath, 'utf8'));
      assert.equal(parsed.kind, 'v2', 'the child writes a strict v2 presence record');
      const childRoots = await ensureStateRoots({ OMP_PEERS_DIR: peerDir });
      const endpoint = peerEndpoint(childRoots, parsed.record.pid, parsed.record.instance);
      await waitFor(
        () => new Promise((resolve) => {
          const probe = createConnection(endpoint);
          const finish = (ok) => {
            probe.destroy();
            resolve(ok);
          };
          probe.once('connect', () => finish(true));
          probe.once('error', () => finish(false));
        }),
        { timeout: 5000, interval: 100, label: 'child endpoint accepts connections' }
      );
      const info = await stat(endpoint);
      assert.ok(info.isSocket(), 'the endpoint is a unix domain socket');
    } finally {
      await child.stop();
      await rm(peerDir, { recursive: true, force: true });
    }
  });

  it('exchanges status and send receipts between two paired children', { timeout: 30000 }, async () => {
    const { alpha, beta } = await startPair();
    try {
      await Promise.all([alpha.ready, beta.ready]);
      const alphaRecord = parseRecord(await readFile(alpha.recordPath, 'utf8'));
      const betaRecord = parseRecord(await readFile(beta.recordPath, 'utf8'));
      assert.equal(alphaRecord.kind, 'v2');
      assert.equal(betaRecord.kind, 'v2');
      const betaName = betaRecord.record.name;
      assert.notEqual(alphaRecord.record.name, betaName, 'paired children own distinct names');

      let statusReceipt;
      await waitFor(async () => {
        try {
          // Race the tool call against a bound so a child that never settles
          // cannot pin this predicate (and thus waitFor) forever.
          statusReceipt = await Promise.race([
            alpha.tool('peer_status', { to: betaName }),
            sleep(4000),
          ]);
          return (
            typeof statusReceipt === 'string'
            && statusReceipt.includes(`\`${betaName}\`: status`)
          );
        } catch {
          // Transient boot races retry until the window expires.
          return false;
        }
      }, { timeout: 20000, interval: 250, label: 'status receipt over a real socket' });
      assert.ok(!statusReceipt.includes('delivered'), 'receipts never claim delivery');

      const sendReceipt = await Promise.race([
        alpha.tool('peer_send', { to: betaName, message: 'e2e hello' }),
        sleep(4000),
      ]);
      assert.ok(
        typeof sendReceipt === 'string' && sendReceipt.includes(`\`${betaName}\`: submitted`),
        `expected a submitted receipt, got: ${sendReceipt}`
      );
      assert.ok(!sendReceipt.includes('delivered'), 'receipts never claim delivery');
      assert.ok(!sendReceipt.includes('accepted'), 'receipts never claim acceptance');
    } finally {
      await alpha.stop();
      await beta.stop();
    }
  });
});

describe('review-fix regressions', () => {
  let roots;
  let requester;

  before(async () => {
    roots = await makeRoots('review-fix');
    requester = makeIdentity(48600);
    await putRecord(roots, requester, { name: 'self' });
  });

  it('routes send to a generated alias name that resolves to one live record', async () => {
    // Regression: reserved-name validation wrongly rejected the p-<22hex>
    // aliases resolveName assigns to collision losers, so displayed peers
    // were unreachable through every outbound gate.
    const target = makeIdentity(48601);
    const alias = aliasNameFor(target.instance);
    assert.equal(isValidPeerName(alias), false, 'aliases stay reserved for name assignment');
    await putRecord(roots, target, { name: alias });
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    const server = await startTestServer({ roots, identity: target, delivery, timers });
    try {
      const { deps } = makeDeps({
        roots,
        identity: requester,
        timers,
        scan: async () => [memoryRecord(target, { name: alias })],
      });
      const inFlight = sendMsg(deps, alias, 'hello alias');
      await waitFor(() => state.delivered.length >= 1, { label: 'alias delivery' });
      expectCode(await inFlight, 'submitted');
    } finally {
      await server.close();
    }
  });

  it('retains an acknowledged held batch across a canceled transition', { timeout: 30000 }, async () => {
    // Regression: the held pump discarded acknowledged batches during a
    // pending (fenced but uncommitted) transition, losing them forever when
    // the transition was canceled or rolled back.
    const receiver = makeIdentity(48602);
    await putRecord(roots, receiver, { name: 'held-recv' });
    const timers = makeTimers();
    const { delivery, state } = makeDelivery();
    state.canSubmit = false;
    const server = await startTestServer({ roots, identity: receiver, delivery, timers });
    try {
      const sender = openRaw(server.endpoint);
      await sender.connect();
      const hs = await verifiedHandshake(sender, receiver);
      sender.send(
        requestFrame({
          ...hs,
          sender: requester,
          receiver,
          payload: { type: 'msg', body: 'held across cancel', hop: 0 },
        })
      );
      assert.equal(terminalCode(await sender.nextLine()), 'held', 'the blocked batch is acknowledged held exactly once');
      await waitFor(() => state.heldReserves >= 1, { label: 'held reservation' });

      state.acceptance = 'session_transition';
      await sleep(COALESCE_MS * 3);
      assert.equal(state.delivered.length, 0, 'nothing submits during the pending fence');
      assert.equal(state.releases, 0, 'the held reservation survives the pending fence');

      state.acceptance = 'accepting';
      state.canSubmit = true;
      // The harness's real intervals are one-shot: fire the remaining manual
      // drivers (the hold-timeout force) to run the pump after the cancel.
      timers.fireAll();
      await waitFor(() => state.delivered.length >= 1, { timeout: 8000, label: 'held batch delivered after cancel' });
      assert.equal(state.delivered.length, 1, 'the acknowledged batch submits exactly once');
      sender.close();
    } finally {
      await server.close();
    }
  });

  it('retries exactly one torn presence read and keeps persistent garbage unusable', async () => {
    // Regression: records are overwritten in place, so a concurrent heartbeat
    // can expose a torn body; the reader must reread once after 50 ms and
    // only then give up.
    const target = makeIdentity(48603);
    const path = peerRecordPath(roots, target.pid, target.instance);
    await putRecord(roots, target, { name: 'torn' });
    await writeFile(path, '{"v":2,"pid":');
    const heal = (async () => {
      await sleep(10);
      await putRecord(roots, target, { name: 'torn' });
    })();
    const recovered = await readPeerRecord(roots, target.pid, target.instance);
    await heal;
    assert.ok(recovered !== undefined && recovered.name === 'torn', 'the bounded reread picks up the healed body');
    await writeFile(path, '{"v":2,"pid":');
    assert.equal(
      await readPeerRecord(roots, target.pid, target.instance),
      undefined,
      'a second unusable read stays unusable'
    );
  });

  it('computes the hop per attempt against the actually resolved record', async () => {
    // Regression: the hop was computed in a throwaway resolution, so a
    // retargeted retry could send under another identity's hop level.
    const dead = makeIdentity(48604);
    const alive = makeIdentity(48605);
    await putRecord(roots, alive, { name: 'hop-target' });
    const hops = [];
    const sink = await makeOutboundServer(roots, alive, {
      onLine(socket, line) {
        if (line.startsWith('{"v":2,"type":"hello"')) {
          answerHello(socket, line, alive);
          return;
        }
        const request = JSON.parse(line);
        hops.push(request.payload.hop);
        socket.write(signedReply(alive, request.id, 'submitted'));
      },
    });
    try {
      const timers = makeTimers();
      let calls = 0;
      const { deps } = makeDeps({
        roots,
        identity: requester,
        timers,
        scan: async () => {
          calls += 1;
          return calls === 1 ? [memoryRecord(dead, { name: 'hop-target' })] : [memoryRecord(alive, { name: 'hop-target' })];
        },
      });
      const result = await sendMsg(deps, 'hop-target', 'hop check', {
        hopFor: (record) => (record.instance === alive.instance ? 1 : 2),
      });
      expectCode(result, 'submitted');
      assert.deepEqual(hops, [1], 'the surviving attempt carries its own resolved record hop');
    } finally {
      await sink.stop();
    }
  });

  it('keeps hop state for peer-sourced entries and resets it for human entries', { timeout: 30000 }, async () => {
    // Regression: peer-injected entries reset the relay-hop chain (loop
    // protection bypass) and the same-peer reply exemption compared a
    // pid:instance key against a peer name (never matching). The real
    // extension drives the classification from each host entry's fields.
    const hopRoots = await ensureStateRoots({ OMP_PEERS_DIR: join(ROOT_TMP, 'hop-origin') });
    const peer = makeIdentity();
    const sinkIdent = makeIdentity();
    await putRecord(hopRoots, peer, { name: 'sender' });
    await putRecord(hopRoots, sinkIdent, { name: 'sink' });
    const hops = [];
    const scripted = (identity, label) => ({
      onLine(socket, line) {
        if (line.startsWith('{"v":2,"type":"hello"')) {
          answerHello(socket, line, identity);
          return;
        }
        const request = JSON.parse(line);
        hops.push({ to: label, hop: request.payload.hop });
        socket.write(signedReply(identity, request.id, 'submitted'));
      },
    });
    const sinkServer = await makeOutboundServer(hopRoots, sinkIdent, scripted(sinkIdent, 'sink'));
    const peerServer = await makeOutboundServer(hopRoots, peer, scripted(peer, 'sender'));
    const previousDir = process.env.OMP_PEERS_DIR;
    process.env.OMP_PEERS_DIR = join(ROOT_TMP, 'hop-origin');
    const extension = (await import('../dist/extension.js')).default;
    const fake = createFakeHost();
    const registered = new Map();
    const originalRegister = fake.host.registerTool;
    fake.host.registerTool = (tool) => {
      originalRegister(tool);
      registered.set(tool.name, tool);
    };
    try {
      extension(fake.host);
      await fake.emit('session_start', { reason: 'startup' });
      await waitFor(
        async () => {
          const scan = await scanPeers(hopRoots, { pid: 999999, instance: generateInstance() });
          return scan.routable.length >= 3 && registered.has('peer_send');
        },
        { label: 'the extension armed and registered the peer tools' }
      );

      const selfRecord = (await scanPeers(hopRoots, { pid: 999999, instance: generateInstance() })).routable
        .find((record) => record.name !== 'sender' && record.name !== 'sink');
      assert.ok(selfRecord !== undefined, 'the binding published its own record');

      // Each seed delivers one peer message at hop 3 to the binding's own
      // endpoint, so lastInboundFrom is the sender identity at level 3.
      const seed = async () => {
        const inbound = openRaw(peerEndpoint(hopRoots, selfRecord.pid, selfRecord.instance));
        await inbound.connect();
        const hs = await verifiedHandshake(inbound, selfRecord);
        inbound.send(
          requestFrame({
            ...hs,
            sender: peer,
            receiver: selfRecord,
            payload: { type: 'msg', body: 'seeding hop state', hop: 3 },
          })
        );
        assert.equal(terminalCode(await inbound.nextLine()), 'submitted', 'the seeding message is submitted');
        inbound.close();
      };
      const runSend = (to, message, extra = {}) =>
        registered.get('peer_send').execute(`fixture-${hops.length}`, { to, message, ...extra });

      await seed();
      await fake.emit('input', { source: 'extension', prompt: '[peer sender]: relayed' });
      await runSend('sink', 'relayed on');
      await fake.emit('input', { source: 'interactive', text: '[peer sender]: quoted by a human' });
      await runSend('sink', 'human one');
      await seed();
      await fake.emit('before_agent_start', { prompt: '[peer sender]: injected turn' });
      await runSend('sink', 'relayed again');
      await fake.emit('before_agent_start', { prompt: 'ordinary human turn' });
      await runSend('sink', 'human two');
      await seed();
      await fake.emit('input', { source: 'extension', prompt: '[peer sender]: injected again' });
      await runSend('sender', 'same peer keeps level');
      await runSend('sink', 'replyTo does not bypass', { replyTo: generateId() });

      assert.deepEqual(
        hops,
        [
          { to: 'sink', hop: 4 },
          { to: 'sink', hop: 0 },
          { to: 'sink', hop: 4 },
          { to: 'sink', hop: 0 },
          { to: 'sender', hop: 3 },
          { to: 'sink', hop: 4 },
        ],
        'only human entries reset the chain; identity and hop comparisons are exact'
      );
    } finally {
      if (previousDir === undefined) delete process.env.OMP_PEERS_DIR;
      else process.env.OMP_PEERS_DIR = previousDir;
      await fake.emit('session_shutdown', undefined);
      await sinkServer.stop();
      await peerServer.stop();
    }
  });
});



