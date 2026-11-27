#!/usr/bin/env node
'use strict';

/*
 * zen-node single-file deployment (generated)
 *
 * Template: vpngate
 * Version:  2026.11.27.1
 *
 * Deploy:
 *   1) Put this file on the host as index.js
 *   2) Set PORT (platform-provided), NODE_TOKEN, optional PUBLIC_URL
 *   3) node index.js
 *
 * Public:
 *   GET /healthz              platform liveness
 *   GET /health               gateway health (run_id / egress_ip / stats)
 *   /v1/*                     OpenAI-compatible data plane (SSE passthrough)
 *   GET /                     tiny status page
 *
 * Management (Bearer NODE_TOKEN):
 *   GET  /_zen/node/v1/manifest
 *   GET  /_zen/node/v1/status
 *   GET  /_zen/node/v1/logs?tail=200
 *   POST /_zen/node/v1/start
 *   POST /_zen/node/v1/stop
 *   POST /_zen/node/v1/restart
 *   POST /_zen/node/v1/rotate
 *   POST /_zen/node/v1/apply
 *   POST /_zen/node/v1/update      self-update from base64 or https URL
 *   POST /_zen/node/v1/rollback    restore index.js.bak
 */

const http = require('http');
const net = require('net');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { Readable, Transform } = require('stream');
const { pipeline } = require('stream/promises');

const TEMPLATE = 'vpngate';
const VERSION = '2026.11.27.8';
const DEFAULT_NODE_ID = 'vpngate-1';
const DEFAULT_ALLOW_FALLBACK = true;
const DEFAULT_ASSETS_BASE = 'https://github.com/2061969365/zen-node-assets/releases/download/v2026.11.27';

const env = process.env;
// PORT 是通用约定；Pterodactyl/KataBump 一类面板用 SERVER_PORT。
const PORT = Number(env.PORT || env.SERVER_PORT || env.P_SERVER_PORT || env.KATABUMP_PORT || 0);
if (!Number.isInteger(PORT) || PORT <= 0 || PORT > 65535) {
  console.error('PORT is required: set PORT or SERVER_PORT to the platform-provided port');
  process.exit(1);
}

const NODE_ID = env.NODE_ID || DEFAULT_NODE_ID;

function distinctPort(value, exclude) {
  let p = Number(value);
  if (!Number.isInteger(p) || p <= 0 || p > 65535) p = 18080;
  while (exclude.includes(p)) p = p >= 65000 ? p - 1 : p + 1;
  return p;
}

let ZEN_PORT = distinctPort(env.ZEN_PORT || 18081, [PORT]);
let EGRESS_PORT = distinctPort(env.EGRESS_PORT || 18080, [PORT, ZEN_PORT]);
const EGRESS_MODE = String(env.EGRESS_MODE || 'auto').toLowerCase() === 'direct' ? 'direct' : 'auto';
let ALLOW_DIRECT_FALLBACK = env.ALLOW_DIRECT_FALLBACK == null ? DEFAULT_ALLOW_FALLBACK : env.ALLOW_DIRECT_FALLBACK !== '0';
let MAX_RUN_SEC = Number(env.MAX_RUN_SEC || 0);
let PROBE_INTERVAL_SEC = Math.max(30, Number(env.PROBE_INTERVAL_SEC || 300));
// Automatic rotate policy. ROTATE_429_THRESHOLD=0 disables 429 rotation.
let ROTATE_429_THRESHOLD = Math.max(0, Number(env.ROTATE_429_THRESHOLD == null ? 1 : env.ROTATE_429_THRESHOLD));
let ROTATE_EGRESS_FAILS = Math.max(1, Number(env.ROTATE_EGRESS_FAILS || 3));
let ROTATE_INTERVAL_SEC = Math.max(0, Number(env.ROTATE_INTERVAL_SEC || 0));
const LOG_DIR = path.resolve(env.LOG_DIR || '.zen');
const ASSET_DIR = path.join(LOG_DIR, 'assets');
const SCRIPT_DIR = path.join(LOG_DIR, 'scripts');
const ASSETS_BASE_URL = String(env.ASSETS_BASE_URL || DEFAULT_ASSETS_BASE).replace(/\/+$/, '');
let ZEN_DIRECT_PATH = env.ZEN_DIRECT_PATH ? path.resolve(env.ZEN_DIRECT_PATH) : path.join(ASSET_DIR, 'zen-direct');
let SINGBOX_PATH = env.SINGBOX_PATH ? path.resolve(env.SINGBOX_PATH) : path.join(ASSET_DIR, 'sing-box');
const LOG_MAX_MB = Number(env.LOG_MAX_MB || 10);
const LOG_KEEP = Number(env.LOG_KEEP || 3);
const BOOT_ID = crypto.randomUUID();

// 固定默认管理口令，重启不变；多节点部署用 NODE_TOKEN 环境变量按节点覆盖。
const DEFAULT_NODE_TOKEN = '3f9a7c1e5b2d8460a1c9e7f3b5d28064e6a4c2f8d1b7e93a';
let NODE_TOKEN = String(env.NODE_TOKEN || DEFAULT_NODE_TOKEN).trim() || DEFAULT_NODE_TOKEN;
fs.mkdirSync(LOG_DIR, { recursive: true });
fs.writeFileSync(path.join(LOG_DIR, 'node-token'), NODE_TOKEN + '\n', { mode: 0o600 });

function resolvePublicUrl() {
  const clean = (v) => String(v || '').replace(/\/+$/, '');
  if (env.PUBLIC_URL) return clean(env.PUBLIC_URL);
  if (env.RENDER_EXTERNAL_URL) return clean(env.RENDER_EXTERNAL_URL);
  if (env.RAILWAY_PUBLIC_DOMAIN) return 'https://' + clean(env.RAILWAY_PUBLIC_DOMAIN).replace(/^https?:\/\//, '');
  if (env.KOYEB_PUBLIC_DOMAIN) return 'https://' + clean(env.KOYEB_PUBLIC_DOMAIN).replace(/^https?:\/\//, '');
  if (env.FLY_APP_NAME) return 'https://' + env.FLY_APP_NAME + '.fly.dev';
  if (env.ZEABUR_WEB_URL) return clean(env.ZEABUR_WEB_URL);
  return '';
}
const PUBLIC_URL = resolvePublicUrl();

const LOG_FILE = path.join(LOG_DIR, 'node.log');
const ring = [];
let logBytes = 0;
let logOps = 0;

function redact(line) {
  let s = String(line);
  if (NODE_TOKEN) s = s.split(NODE_TOKEN).join('***');
  s = s.replace(/(Bearer\s+)[A-Za-z0-9._~+\/=-]+/gi, '$1***');
  s = s.replace(/(private_key|PrivateKey|privatekey)(["'\s:=]+)[^\s"',]+/g, '$1$2***');
  return s;
}

function rotateLog() {
  try {
    if (fs.statSync(LOG_FILE).size <= LOG_MAX_MB * 1024 * 1024) return;
    for (let i = LOG_KEEP - 1; i >= 1; i--) {
      const a = `${LOG_FILE}.${i}`;
      const b = `${LOG_FILE}.${i + 1}`;
      if (fs.existsSync(a)) fs.renameSync(a, b);
    }
    fs.renameSync(LOG_FILE, `${LOG_FILE}.1`);
  } catch {}
}

// 子进程日志（gateway/sing-box/wireproxy/命令输出）不受 node.log 轮转覆盖，
// 这里定期按大小截断并按天数清理，避免长期运行把磁盘写满。
const LOG_SWEEP_INTERVAL_SEC = Math.max(60, Number(env.LOG_SWEEP_INTERVAL_SEC || 600));
const LOG_CHILD_MAX_MB = Math.max(1, Number(env.LOG_CHILD_MAX_MB || LOG_MAX_MB));
const LOG_MAX_AGE_DAYS = Math.max(0, Number(env.LOG_MAX_AGE_DAYS || 7));
let lastLogSweepAt = 0;
let logSweepTimer = null;

function sweepLogs() {
  const maxBytes = LOG_CHILD_MAX_MB * 1024 * 1024;
  const maxAgeMs = LOG_MAX_AGE_DAYS * 86400000;
  let names;
  try { names = fs.readdirSync(LOG_DIR); } catch { return; }
  const now = Date.now();
  let trimmed = 0;
  let removed = 0;
  for (const name of names) {
    if (name === 'node.log' || !/\.log(\.\d+)?$/.test(name)) continue;
    const p = path.join(LOG_DIR, name);
    let st;
    try { st = fs.statSync(p); } catch { continue; }
    if (!st.isFile()) continue;
    if (maxAgeMs > 0 && now - st.mtimeMs > maxAgeMs) {
      try { fs.unlinkSync(p); removed++; } catch {}
      continue;
    }
    if (st.size <= maxBytes) continue;
    try {
      const keep = Math.min(st.size, 256 * 1024);
      const fd = fs.openSync(p, 'r');
      const buf = Buffer.alloc(keep);
      try { fs.readSync(fd, buf, 0, keep, st.size - keep); } finally { fs.closeSync(fd); }
      fs.writeFileSync(p, `--- truncated ${new Date().toISOString()} was=${st.size}B ---\n` + buf.toString('utf8'));
      trimmed++;
    } catch {
      try { fs.truncateSync(p, 0); trimmed++; } catch {}
    }
  }
  lastLogSweepAt = now;
  if (trimmed || removed) log(`logs swept: trimmed=${trimmed} removed=${removed}`);
}

function startLogSweeper() {
  if (logSweepTimer) return;
  sweepLogs();
  logSweepTimer = setInterval(sweepLogs, LOG_SWEEP_INTERVAL_SEC * 1000);
  if (logSweepTimer.unref) logSweepTimer.unref();
}

function log(...args) {
  const line = `${new Date().toISOString()} ${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}`;
  const safe = redact(line);
  console.log(safe);
  ring.push(safe);
  if (ring.length > 500) ring.shift();
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.appendFileSync(LOG_FILE, safe + '\n');
    logBytes += safe.length + 1;
    if (++logOps % 50 === 0 && logBytes > LOG_MAX_MB * 1024 * 1024) {
      logBytes = 0;
      rotateLog();
    }
  } catch {}
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function fetchBuffer(url, timeoutMs = 180000) {
  const res = await fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'user-agent': `zen-node/${VERSION}` },
  });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function fetchText(url, timeoutMs = 30000) {
  return (await fetchBuffer(url, timeoutMs)).toString('utf8');
}

let checksums = null;
async function loadChecksums() {
  if (checksums) return checksums;
  try {
    const text = await fetchText(`${ASSETS_BASE_URL}/sha256sums.txt`, 30000);
    const map = {};
    for (const line of text.split(/\r?\n/)) {
      const m = line.trim().match(/^([0-9a-f]{64})\s+\*?(.+)$/i);
      if (m) map[m[2]] = m[1].toLowerCase();
    }
    checksums = map;
    log(`checksums loaded (${Object.keys(map).length})`);
  } catch (e) {
    log('checksums unavailable:', e.message);
    checksums = {};
  }
  return checksums;
}

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(file);
    stream.on('data', (c) => hash.update(c));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

async function downloadToFile(url, dest, want, executable) {
  const res = await fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(600000),
    headers: { 'user-agent': `zen-node/${VERSION}` },
  });
  if (!res.ok || !res.body) throw new Error(`GET ${url} -> ${res.status}`);
  const tmp = `${dest}.part-${process.pid}-${Date.now()}`;
  const hash = crypto.createHash('sha256');
  const hasher = new Transform({
    transform(chunk, _enc, cb) {
      hash.update(chunk);
      cb(null, chunk);
    },
  });
  try {
    await pipeline(
      Readable.fromWeb(res.body),
      hasher,
      fs.createWriteStream(tmp, { mode: executable ? 0o755 : 0o644 }),
    );
    const got = hash.digest('hex');
    if (want && got !== want) {
      throw new Error(`checksum mismatch for ${path.basename(dest)}: got ${got} want ${want}`);
    }
    await fsp.rename(tmp, dest);
    if (executable) fs.chmodSync(dest, 0o755);
    return { bytes: fs.statSync(dest).size, sha: got };
  } catch (e) {
    try { await fsp.rm(tmp, { force: true }); } catch {}
    throw e;
  }
}

async function ensureAsset(name, url, executable, dir = ASSET_DIR) {
  const dest = path.join(dir, name);
  const sums = await loadChecksums();
  const want = sums[name];
  if (fs.existsSync(dest)) {
    if (!want) {
      if (executable) {
        try { fs.chmodSync(dest, 0o755); } catch {}
      }
      return dest;
    }
    const got = await sha256File(dest);
    if (got === want) {
      if (executable) {
        try { fs.chmodSync(dest, 0o755); } catch {}
      }
      return dest;
    }
    log(`asset ${name} checksum mismatch, redownloading`);
  }
  fs.mkdirSync(dir, { recursive: true });
  log(`downloading ${url}`);
  const { bytes, sha } = await downloadToFile(url, dest, want, executable);
  log(`asset ${name} ready (${bytes} bytes sha=${sha.slice(0, 12)})`);
  return dest;
}

function findZenDirect() {
  const candidates = [env.ZEN_DIRECT_PATH, path.resolve('zen-direct'), path.resolve('bin/zen-direct')].filter(Boolean);
  for (const c of candidates) {
    try { if (fs.existsSync(c) && fs.statSync(c).isFile()) return path.resolve(c); } catch {}
  }
  return '';
}

async function ensureZenDirect() {
  const local = findZenDirect();
  if (local) {
    try { fs.chmodSync(local, 0o755); } catch {}
    return local;
  }
  if (env.ZEN_DIRECT_URL) return ensureAsset('zen-direct', env.ZEN_DIRECT_URL, true);
  return ensureAsset('zen-direct', `${ASSETS_BASE_URL}/zen-direct`, true);
}

function runCommand(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const logPath = opts.logFile || path.join(LOG_DIR, 'command.log');
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const fd = fs.openSync(logPath, 'a');
    let p;
    try {
      p = spawn(cmd, args, {
        cwd: opts.cwd || LOG_DIR,
        env: opts.env || process.env,
        stdio: ['ignore', fd, fd],
      });
    } catch (e) {
      try { fs.closeSync(fd); } catch {}
      log(`command ${cmd} spawn failed: ${e.message}`);
      resolve(1);
      return;
    }
    try { fs.closeSync(fd); } catch {}
    let settled = false;
    const done = (code) => {
      if (settled) return;
      settled = true;
      resolve(code == null ? 1 : code);
    };
    let timer = null;
    if (opts.timeoutMs) {
      timer = setTimeout(() => {
        log(`command ${cmd} timeout after ${opts.timeoutMs}ms`);
        try { p.kill('SIGKILL'); } catch {}
      }, opts.timeoutMs);
    }
    p.on('exit', (code) => {
      if (timer) clearTimeout(timer);
      done(code);
    });
    p.on('error', (err) => {
      if (timer) clearTimeout(timer);
      log(`command ${cmd} error: ${err.message}`);
      done(1);
    });
  });
}

class Child {
  constructor(name, cmd, args, opts = {}) {
    this.name = name;
    this.cmd = cmd;
    this.args = args;
    this.opts = opts;
    this.proc = null;
    this.exited = false;
    this.exitInfo = null;
  }

  start() {
    if (this.proc) return;
    this.exited = false;
    this.exitInfo = null;
    const logPath = this.opts.logFile || path.join(LOG_DIR, `${this.name}.log`);
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const fd = fs.openSync(logPath, 'a');
    try {
      this.proc = spawn(this.cmd, this.args, {
        cwd: this.opts.cwd || LOG_DIR,
        env: this.opts.env || process.env,
        stdio: ['ignore', fd, fd],
      });
    } catch (e) {
      try { fs.closeSync(fd); } catch {}
      log(`${this.name} spawn failed: ${e.message}`);
      this.exited = true;
      return;
    }
    try { fs.closeSync(fd); } catch {}
    this.proc.on('exit', (code, signal) => {
      this.exited = true;
      this.exitInfo = { code, signal };
      log(`${this.name} exited code=${code} signal=${signal}`);
    });
    this.proc.on('error', (err) => {
      this.exited = true;
      log(`${this.name} error: ${err.message}`);
    });
    log(`${this.name} started pid=${this.proc.pid}`);
  }

  async stop(timeoutMs = 10000) {
    if (!this.proc || this.exited) {
      this.proc = null;
      return;
    }
    const p = this.proc;
    try { p.kill('SIGTERM'); } catch {}
    const deadline = Date.now() + timeoutMs;
    while (!this.exited && Date.now() < deadline) await sleep(200);
    if (!this.exited) {
      try { p.kill('SIGKILL'); } catch {}
      await sleep(500);
    }
    this.proc = null;
  }

  get pid() {
    return this.proc && !this.exited ? this.proc.pid : 0;
  }

  get alive() {
    return !!this.proc && !this.exited;
  }
}

function httpGetJson(port, pathname, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method: 'GET', timeout: timeoutMs }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, json: data ? JSON.parse(data) : null, body: data });
        } catch {
          resolve({ status: res.statusCode, json: null, body: data });
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

function proxyHttpGet(proxyPort, targetUrl, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const req = http.request({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: targetUrl,
      headers: { Host: u.host, 'User-Agent': `zen-node/${VERSION}` },
      timeout: timeoutMs,
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

function waitTcp(port, timeoutMs = 30000) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      const s = net.connect({ host: '127.0.0.1', port });
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => {
        s.destroy();
        if (Date.now() < deadline) setTimeout(tick, 300);
        else resolve(false);
      });
    };
    tick();
  });
}

async function waitGatewayHealth(timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await httpGetJson(ZEN_PORT, '/health', 3000);
      if (r.status === 200 && r.json && (r.json.run_id || r.json.egress_ip)) return r.json;
    } catch {}
    await sleep(1000);
  }
  return null;
}

const state = {
  phase: 'starting',
  startedAt: Date.now(),
  startedAtGateway: 0,
  lastError: '',
  gateway: null,
  singbox: null,
  gatewayHealth: null,
  egress: { type: TEMPLATE, state: 'stopped', lastCheck: '', ip: '' },
  runId: '',
  egressIp: '',
  up429: 0,
  up429Base: 0,
  lastRotateAt: 0,
  rotateInFlight: false,
  lastBootstrapAt: 0,
  lastEgressCheck: 0,
  updating: false,
  restarting: false,
};

let bootstrapInFlight = false;

async function startSingbox() {
  const cfg = path.join(LOG_DIR, 'sb.json');
  if (!fs.existsSync(cfg)) throw new Error('missing sb.json');
  if (state.singbox) {
    await state.singbox.stop();
    state.singbox = null;
  }
  state.singbox = new Child('sing-box', SINGBOX_PATH, ['run', '-c', cfg], {
    logFile: path.join(LOG_DIR, 'sing-box.log'),
    cwd: LOG_DIR,
    env: {
      ...process.env,
      NO_PROXY: '127.0.0.1,localhost',
      no_proxy: '127.0.0.1,localhost',
      GOMEMLIMIT: env.SINGBOX_GOMEMLIMIT || '64MiB',
      GOGC: env.SINGBOX_GOGC || '50',
    },
  });
  state.singbox.start();
}

async function stopEgress() {
  const sb = state.singbox;
  if (sb) {
    await sb.stop();
    if (state.singbox === sb) state.singbox = null;
  }
  if (!state.singbox) state.egress.state = 'stopped';
}

const EGRESS_CHECK_URLS = [
  'http://api.ipify.org',
  'http://icanhazip.com',
  'http://checkip.amazonaws.com',
  'http://ipinfo.io/ip',
];

async function verifyEgress(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no attempt';
  while (Date.now() < deadline) {
    for (const url of EGRESS_CHECK_URLS) {
      try {
        const r = await proxyHttpGet(EGRESS_PORT, url, 6000);
        const ip = String(r.body || '').trim().split(/\s+/)[0];
        if (r.status === 200 && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
          state.egress.ip = ip;
          state.egress.state = 'running';
          state.egress.lastCheck = new Date().toISOString();
          state.lastEgressCheck = Date.now();
          return true;
        }
        last = `${url} status=${r.status} body=${String(r.body || '').slice(0, 40)}`;
      } catch (e) {
        last = `${url} ${e.message}`;
      }
    }
    await sleep(2000);
  }
  log(`egress check failed: ${last}`);
  state.egress.state = 'error';
  state.egress.lastCheck = new Date().toISOString();
  return false;
}

function startGateway(useProxy) {
  try { fs.chmodSync(ZEN_DIRECT_PATH, 0o755); } catch {}
  const gatewayRunId = crypto.randomUUID();
  const gatewayEnv = {
    ...process.env,
    PORT: String(ZEN_PORT),
    LOG_FILE: path.join(LOG_DIR, 'gateway.log'),
    SHIM_SESSION_FILE: path.join(LOG_DIR, 'shim_sessions.json'),
    DIRECT_DIAG: '1',
    DIRECT_DEBUG: '0',
    DIRECT_CONCURRENCY: '16',
    DIRECT_FREELIMIT_COOLDOWN: '0',
    DIRECT_FRESH_PER_TURN: '0',
    ZEN_TLS: 'bun',
    ZEN_RUN_ID: gatewayRunId,
    GITHUB_RUN_ID: gatewayRunId,
    GITHUB_REPOSITORY: `node/${NODE_ID}`,
    DIRECT_SIDECAR: 'off',
    NO_PROXY: '127.0.0.1,localhost',
    no_proxy: '127.0.0.1,localhost',
  };
  for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'https_proxy', 'http_proxy', 'all_proxy']) {
    delete gatewayEnv[k];
  }
  if (useProxy) {
    gatewayEnv.HTTPS_PROXY = `http://127.0.0.1:${EGRESS_PORT}`;
    gatewayEnv.HTTP_PROXY = `http://127.0.0.1:${EGRESS_PORT}`;
    gatewayEnv.https_proxy = gatewayEnv.HTTPS_PROXY;
    gatewayEnv.http_proxy = gatewayEnv.HTTP_PROXY;
  }
  state.gateway = new Child('gateway', ZEN_DIRECT_PATH, [], {
    logFile: path.join(LOG_DIR, 'gateway.stdio.log'),
    cwd: LOG_DIR,
    env: gatewayEnv,
  });
  state.gateway.start();
  state.startedAtGateway = Date.now();
}

async function prepareAssets() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  fs.mkdirSync(ASSET_DIR, { recursive: true });
  ZEN_DIRECT_PATH = await ensureZenDirect();
  if (EGRESS_MODE === 'auto') {
    SINGBOX_PATH = await ensureAsset('sing-box', `${ASSETS_BASE_URL}/sing-box`, true);
    await ensureTemplateAssets();
  }
}

async function startAll() {
  if (bootstrapInFlight) return;
  bootstrapInFlight = true;
  state.lastBootstrapAt = Date.now();
  state.phase = 'starting';
  state.lastError = '';
  try {
    if (state.gateway) {
      await state.gateway.stop();
      state.gateway = null;
    }
    await prepareAssets();
    let useProxy = false;
    if (EGRESS_MODE === 'auto') {
      try {
        await bootstrapEgress();
        useProxy = true;
      } catch (e) {
        state.lastError = e.message;
        log('egress failed:', e.message);
        if (!ALLOW_DIRECT_FALLBACK) throw e;
        log('falling back to direct egress');
        await stopEgress();
      }
    }
    startGateway(useProxy);
    const health = await waitGatewayHealth(120000);
    if (!health) throw new Error('gateway health timeout');
    state.gatewayHealth = health;
    state.runId = health.run_id || '';
    state.egressIp = health.egress_ip || state.egress.ip || '';
    state.up429 = Number((health.stats && health.stats.up429) || 0);
    state.up429Base = state.up429;
    state.lastRotateAt = Date.now();
    state.phase = 'running';
    log(`running template=${TEMPLATE} node=${NODE_ID} egress=${useProxy ? state.egress.ip : 'direct'} run=${state.runId}`);
  } catch (e) {
    state.phase = 'error';
    state.lastError = e.message;
    log('start failed:', e.message);
    throw e;
  } finally {
    bootstrapInFlight = false;
  }
}

async function stopAll() {
  state.phase = 'stopped';
  const gw = state.gateway;
  if (gw) {
    await gw.stop();
    if (state.gateway === gw) state.gateway = null;
  }
  await stopEgress();
  if (!state.gateway) state.gatewayHealth = null;
}

async function restartAll() {
  await stopAll();
  await startAll();
}

async function restartGatewayOnly() {
  const useProxy = EGRESS_MODE === 'auto' && state.egress.state === 'running';
  if (state.gateway) await state.gateway.stop();
  startGateway(useProxy);
  const health = await waitGatewayHealth(120000);
  if (health) {
    state.gatewayHealth = health;
    state.runId = health.run_id || state.runId;
    state.egressIp = health.egress_ip || state.egressIp;
  }
}

async function rotate(reason = 'manual') {
  if (state.rotateInFlight) return;
  state.rotateInFlight = true;
  try {
    log(`rotate start reason=${reason}`);
    if (EGRESS_MODE === 'auto') {
      await rotateEgress(reason);
      if (!(await verifyEgress(60000))) throw new Error('egress check after rotate failed');
    }
    if (state.gateway) await state.gateway.stop();
    startGateway(EGRESS_MODE === 'auto');
    const health = await waitGatewayHealth(120000);
    if (!health) throw new Error('gateway health after rotate timeout');
    state.gatewayHealth = health;
    state.runId = health.run_id || state.runId;
    state.egressIp = health.egress_ip || state.egress.ip || '';
    state.up429 = Number((health.stats && health.stats.up429) || 0);
    state.up429Base = state.up429;
    state.lastRotateAt = Date.now();
    log(`rotate done reason=${reason} egress=${state.egress.ip || state.egressIp}`);
  } catch (e) {
    state.lastError = e.message;
    log('rotate failed:', e.message);
  } finally {
    state.rotateInFlight = false;
  }
}

let watchdogTimer = null;
let gwFails = 0;
let egressFails = 0;

function startWatchdog() {
  if (watchdogTimer) return;
  watchdogTimer = setInterval(async () => {
    if (state.rotateInFlight || bootstrapInFlight) return;
    if (state.phase === 'error' && Date.now() - state.lastBootstrapAt > 60000) {
      log('watchdog: retrying bootstrap after error');
      startAll().catch((e) => log('retry failed:', e.message));
      return;
    }
    if (state.phase !== 'running') return;

    const h = await httpGetJson(ZEN_PORT, '/health', 5000).catch(() => null);
    if (!h || h.status !== 200 || !h.json) {
      gwFails++;
      log(`watchdog: gateway health fail ${gwFails}/3`);
      if (gwFails >= 3) {
        gwFails = 0;
        await restartGatewayOnly();
      }
    } else {
      gwFails = 0;
      state.gatewayHealth = h.json;
      state.runId = h.json.run_id || state.runId;
      state.egressIp = h.json.egress_ip || state.egressIp;
      const up429 = Number((h.json.stats && h.json.stats.up429) || 0);
      state.up429 = up429;
      if (ROTATE_429_THRESHOLD > 0 && up429 - state.up429Base >= ROTATE_429_THRESHOLD) {
        log(`watchdog: up429 ${state.up429Base} -> ${up429} (threshold ${ROTATE_429_THRESHOLD}), rotating`);
        await rotate('429');
      }
    }

    if (EGRESS_MODE === 'auto' && state.egress.state === 'running' && Date.now() - state.lastEgressCheck >= PROBE_INTERVAL_SEC * 1000) {
      const ok = await verifyEgress();
      if (!ok) {
        egressFails++;
        log(`watchdog: egress fail ${egressFails}/${ROTATE_EGRESS_FAILS}`);
        if (egressFails >= ROTATE_EGRESS_FAILS) {
          egressFails = 0;
          await rotate('egress');
        }
      } else {
        egressFails = 0;
      }
    }

    if (ROTATE_INTERVAL_SEC > 0 && state.lastRotateAt && Date.now() - state.lastRotateAt >= ROTATE_INTERVAL_SEC * 1000) {
      log(`watchdog: rotate interval ${ROTATE_INTERVAL_SEC}s reached, rotating`);
      await rotate('interval');
    }

    if (MAX_RUN_SEC > 0 && state.startedAtGateway && Date.now() - state.startedAtGateway > MAX_RUN_SEC * 1000) {
      log('watchdog: max run reached, rotating');
      await rotate('maxrun');
    }
  }, 15000);
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}

function authOk(req) {
  if (!NODE_TOKEN) return false;
  const h = String(req.headers['authorization'] || '');
  const t = String(req.headers['x-zen-node-token'] || '');
  const got = h.toLowerCase().startsWith('bearer ') ? h.slice(7).trim() : t;
  const a = Buffer.from(got);
  const b = Buffer.from(NODE_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function readJson(req, limit = 65536) {
  return new Promise((resolve) => {
    let data = '';
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) {
        req.destroy();
        resolve(null);
        return;
      }
      data += c;
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch { resolve(null); }
    });
    req.on('error', () => resolve(null));
  });
}

function manifest() {
  return {
    apiVersion: '1',
    kind: 'zen-node',
    nodeId: NODE_ID,
    templateType: TEMPLATE,
    version: VERSION,
    publicUrl: PUBLIC_URL,
    capabilities: ['start', 'stop', 'restart', 'rotate', 'logs', 'update', 'rollback'],
    update: { protocol: '1', maxBytes: UPDATE_MAX_BYTES, restartModes: ['exec', 'exit', 'crash'] },
    healthPath: '/health',
    dataPath: '/v1',
  };
}

async function status() {
  let gateway = null;
  try {
    const r = await httpGetJson(ZEN_PORT, '/health', 3000);
    if (r.status === 200) gateway = r.json;
  } catch {}
  return {
    state: state.phase,
    pid: state.gateway ? state.gateway.pid : 0,
    uptimeSec: Math.round((Date.now() - state.startedAt) / 1000),
    runId: state.runId || '',
    egressIp: state.egressIp || state.egress.ip || '',
    templateType: TEMPLATE,
    version: VERSION,
    lastError: state.lastError,
    rotate: {
      on429Threshold: ROTATE_429_THRESHOLD,
      egressFails: ROTATE_EGRESS_FAILS,
      intervalSec: ROTATE_INTERVAL_SEC,
      lastAt: state.lastRotateAt ? new Date(state.lastRotateAt).toISOString() : '',
    },
    logs: {
      lastSweepAt: lastLogSweepAt ? new Date(lastLogSweepAt).toISOString() : '',
      sweepIntervalSec: LOG_SWEEP_INTERVAL_SEC,
      childMaxMB: LOG_CHILD_MAX_MB,
      maxAgeDays: LOG_MAX_AGE_DAYS,
    },
    gateway,
    egress: state.egress,
  };
}

async function handleControl(req, res, u) {
  if (!authOk(req)) {
    json(res, 401, { error: 'unauthorized' });
    return;
  }
  const p = u.pathname.slice('/_zen/node/v1'.length) || '/';
  try {
    if (state.updating && req.method === 'POST' && p !== '/update') {
      return json(res, 409, { error: 'update in progress' });
    }
    if (req.method === 'GET' && p === '/manifest') return json(res, 200, manifest());
    if (req.method === 'GET' && p === '/status') return json(res, 200, await status());
    if (req.method === 'GET' && p === '/logs') {
      const tail = Math.min(1000, Math.max(1, Number(u.searchParams.get('tail') || 200)));
      return json(res, 200, { lines: ring.slice(-tail) });
    }
    if (req.method === 'POST' && p === '/start') {
      if (state.phase === 'running' || state.phase === 'starting') return json(res, 409, { error: 'already running' });
      startAll().catch((e) => log('start error:', e.message));
      return json(res, 202, { ok: true });
    }
    if (req.method === 'POST' && p === '/stop') {
      stopAll().catch((e) => log('stop error:', e.message));
      return json(res, 202, { ok: true });
    }
    if (req.method === 'POST' && p === '/restart') {
      restartAll().catch((e) => log('restart error:', e.message));
      return json(res, 202, { ok: true });
    }
    if (req.method === 'POST' && p === '/rotate') {
      rotate('manual').catch((e) => log('rotate error:', e.message));
      return json(res, 202, { ok: true });
    }
    if (req.method === 'POST' && p === '/update') return handleUpdate(req, res);
    if (req.method === 'POST' && p === '/rollback') return handleRollback(req, res);
    if (req.method === 'POST' && p === '/apply') {
      const body = await readJson(req);
      if (!body || typeof body !== 'object') return json(res, 400, { error: 'bad json' });
      if (body.MAX_RUN_SEC != null) MAX_RUN_SEC = Number(body.MAX_RUN_SEC) || 0;
      if (body.PROBE_INTERVAL_SEC != null) PROBE_INTERVAL_SEC = Math.max(30, Number(body.PROBE_INTERVAL_SEC) || 300);
      if (body.ROTATE_429_THRESHOLD != null) ROTATE_429_THRESHOLD = Math.max(0, Number(body.ROTATE_429_THRESHOLD) || 0);
      if (body.ROTATE_EGRESS_FAILS != null) ROTATE_EGRESS_FAILS = Math.max(1, Number(body.ROTATE_EGRESS_FAILS) || 3);
      if (body.ROTATE_INTERVAL_SEC != null) ROTATE_INTERVAL_SEC = Math.max(0, Number(body.ROTATE_INTERVAL_SEC) || 0);
      if (body.ALLOW_DIRECT_FALLBACK != null) ALLOW_DIRECT_FALLBACK = !!body.ALLOW_DIRECT_FALLBACK;
      return json(res, 202, {
        ok: true,
        maxRunSec: MAX_RUN_SEC,
        probeIntervalSec: PROBE_INTERVAL_SEC,
        rotate429Threshold: ROTATE_429_THRESHOLD,
        rotateEgressFails: ROTATE_EGRESS_FAILS,
        rotateIntervalSec: ROTATE_INTERVAL_SEC,
        allowDirectFallback: ALLOW_DIRECT_FALLBACK,
      });
    }
    json(res, 404, { error: 'not found' });
  } catch (e) {
    json(res, 500, { error: e.message });
  }
}

function proxyToGateway(req, res, timeoutMs) {
  if (!state.gateway || !state.gateway.alive) {
    json(res, 503, { status: 'starting', error: 'gateway not ready' });
    return;
  }
  const headers = { ...req.headers };
  for (const h of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
    delete headers[h];
  }
  headers.host = `127.0.0.1:${ZEN_PORT}`;
  const p = http.request({
    host: '127.0.0.1',
    port: ZEN_PORT,
    method: req.method,
    path: req.url,
    headers,
  }, (pr) => {
    const outHeaders = { ...pr.headers };
    for (const h of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
      delete outHeaders[h];
    }
    res.writeHead(pr.statusCode || 502, outHeaders);
    pr.pipe(res);
  });
  p.on('error', (err) => {
    if (!res.headersSent) json(res, 502, { error: 'bad gateway', detail: err.message });
    else res.destroy();
  });
  if (timeoutMs > 0) p.setTimeout(timeoutMs, () => p.destroy(new Error('upstream timeout')));
  res.on('close', () => {
    if (!res.writableEnded) p.destroy();
  });
  req.pipe(p);
}

function statusPage(req, res) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>zen-node ${TEMPLATE}</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0b0d10;color:#e6edf3;margin:0;padding:32px}
main{max-width:760px;margin:0 auto}h1{font-size:22px;margin:0 0 8px}
p{color:#8b949e;margin:0 0 20px}code{color:#7ee787}
.row{display:flex;gap:12px;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid #1e242b}
.k{color:#8b949e;min-width:140px}
</style></head><body><main>
<h1>zen-node · ${TEMPLATE}</h1>
<p>node <code>${NODE_ID}</code> · version <code>${VERSION}</code></p>
<div id="s">loading…</div>
<script>
async function tick(){
  const el=document.getElementById('s');
  try{
    const h=await fetch('/health',{cache:'no-store'});
    const j=await h.json().catch(()=>({}));
    el.innerHTML=
      '<div class="row"><span class="k">health</span><code>'+h.status+'</code></div>'+
      '<div class="row"><span class="k">run_id</span><code>'+(j.run_id||'')+'</code></div>'+
      '<div class="row"><span class="k">egress_ip</span><code>'+(j.egress_ip||'')+'</code></div>'+
      '<div class="row"><span class="k">uptime</span><code>'+(j.uptime_sec||0)+'s</code></div>'+
      '<div class="row"><span class="k">up429</span><code>'+((j.stats&&j.stats.up429)||0)+'</code></div>';
  }catch(e){el.textContent='health unavailable: '+e.message;}
}
tick();setInterval(tick,5000);
</script>
</main></body></html>`);
}

const server = http.createServer((req, res) => {
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch { json(res, 400, { error: 'bad url' }); return; }
  if (u.pathname === '/healthz') {
    json(res, 200, { ok: true, state: state.phase });
    return;
  }
  if (u.pathname.startsWith('/_zen/node/v1/')) {
    handleControl(req, res, u);
    return;
  }
  if (u.pathname === '/') {
    statusPage(req, res);
    return;
  }
  if (u.pathname === '/health') {
    proxyToGateway(req, res, 5000);
    return;
  }
  if (u.pathname === '/v1' || u.pathname.startsWith('/v1/')) {
    proxyToGateway(req, res, 0);
    return;
  }
  json(res, 404, { error: 'not found' });
});
server.requestTimeout = 0;
server.headersTimeout = 65000;
server.keepAliveTimeout = 65000;

async function shutdown(signal) {
  log(`${signal} received, shutting down`);
  try { await stopAll(); } catch {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.listen(PORT, '0.0.0.0', () => {
  log(`zen-node ${TEMPLATE} ${VERSION} node=${NODE_ID} listening on 0.0.0.0:${PORT} ports zen=${ZEN_PORT} egress=${EGRESS_PORT} mode=${EGRESS_MODE}`);
  if (!PUBLIC_URL) log('PUBLIC_URL not detected; set it for console node registration');
  startWatchdog();
  startLogSweeper();
  startAll().catch((e) => log('bootstrap failed:', e.message));
});

// Self-update: stage a new index.js, verify it, atomically replace, restart.
// Protocol (Bearer NODE_TOKEN):
//   POST /_zen/node/v1/update   {template,version,sha256,content|url,restart,restartMode}
//   POST /_zen/node/v1/rollback {restart}

const UPDATE_MAX_BYTES = 1024 * 1024;
const UPDATE_BODY_LIMIT = 2 * 1024 * 1024;

const SCRIPT_PATH = (() => {
  try {
    const p = process.argv[1];
    if (!p) return '';
    return fs.realpathSync(path.resolve(p));
  } catch {
    return '';
  }
})();

function updateRestartMode() {
  const explicit = String(env.ZEN_UPDATE_RESTART_MODE || '').toLowerCase();
  if (explicit === 'exec' || explicit === 'exit' || explicit === 'crash') return explicit;
  // Cloud hosts restart the service on a clean exit.
  if (env.RENDER || env.RAILWAY_ENVIRONMENT || env.KOYEB_APP || env.FLY_APP_NAME || env.ZEABUR) {
    return 'exit';
  }
  // Pterodactyl/KataBump only restarts a non-zero exit; spawning a child would
  // be killed when the panel stops the container, so use a controlled crash.
  if (env.SERVER_PORT || env.P_SERVER_PORT || env.KATABUMP_PORT) {
    return 'crash';
  }
  return 'exec';
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function reEscape(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function closeServer(timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const fin = () => {
      if (done) return;
      done = true;
      resolve();
    };
    try { server.close(fin); } catch { fin(); }
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections(); } catch {}
    }
    setTimeout(fin, timeoutMs);
  });
}

async function checkScript(buf) {
  const tmp = `${SCRIPT_PATH}.check-${process.pid}.js`;
  await fsp.writeFile(tmp, buf, { mode: 0o755 });
  try {
    await new Promise((resolve, reject) => {
      const ch = spawn(process.execPath, ['--check', tmp], { stdio: ['ignore', 'ignore', 'pipe'] });
      let err = '';
      ch.stderr.setEncoding('utf8');
      ch.stderr.on('data', (c) => { err += c; });
      const timer = setTimeout(() => {
        try { ch.kill('SIGKILL'); } catch {}
        reject(new Error('syntax check timeout'));
      }, 10000);
      ch.on('error', (e) => { clearTimeout(timer); reject(e); });
      ch.on('exit', (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error('syntax check failed: ' + err.trim().slice(0, 300)));
      });
    });
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
}

async function readUpdatePayload(body) {
  let buf;
  if (body.content != null) {
    const s = String(body.content).replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) {
      throw new Error('content is not valid base64');
    }
    buf = Buffer.from(s, 'base64');
  } else if (body.url) {
    let u;
    try { u = new URL(String(body.url)); } catch { throw new Error('bad url'); }
    const local = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(u.hostname);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) {
      throw new Error('update url must be https');
    }
    const r = await fetch(u.toString(), {
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
      headers: { 'user-agent': `zen-node/${VERSION}` },
    });
    if (!r.ok) throw new Error(`download status ${r.status}`);
    const len = Number(r.headers.get('content-length') || 0);
    if (len > UPDATE_MAX_BYTES) throw new Error('update too large');
    buf = Buffer.from(await r.arrayBuffer());
  } else {
    throw new Error('content or url required');
  }
  if (buf.length < 1000 || buf.length > UPDATE_MAX_BYTES) {
    throw new Error(`update size ${buf.length} out of range`);
  }
  return buf;
}

function scheduleRestart(mode) {
  if (state.restarting) return;
  state.restarting = true;
  const timer = setTimeout(() => {
    doRestart(mode).catch((e) => {
      log('self-update restart failed:', e.message);
      state.restarting = false;
    });
  }, 300);
  timer.unref();
}

async function waitBootstrap(timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 120000);
  while (bootstrapInFlight && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 250));
  }
}

async function doRestart(mode) {
  log(`self-update restart (${mode})`);
  await waitBootstrap(120000);
  try { await stopAll(); } catch {}
  await closeServer(mode === 'exec' ? 5000 : 3000);
  if (mode === 'exit') {
    process.exit(0);
  }
  if (mode === 'crash') {
    // Panel supervisors (Pterodactyl/KataBump) restart non-zero exits.
    process.exit(1);
  }
  const child = spawn(process.execPath, [SCRIPT_PATH], {
    detached: true,
    stdio: 'inherit',
    cwd: process.cwd(),
    env: process.env,
  });
  child.unref();
  setTimeout(() => process.exit(0), 200);
}

async function handleUpdate(req, res) {
  if (state.updating || state.restarting) return json(res, 409, { error: 'update already in progress' });
  if (!SCRIPT_PATH || !SCRIPT_PATH.endsWith('.js')) {
    return json(res, 409, { error: 'script path unavailable; start with node /path/to/index.js' });
  }
  const body = await readJson(req, UPDATE_BODY_LIMIT);
  if (!body || typeof body !== 'object') return json(res, 400, { error: 'bad json' });

  const targetVersion = String(body.version || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(targetVersion)) {
    return json(res, 400, { error: 'bad version' });
  }
  if (body.template != null && String(body.template) !== TEMPLATE) {
    return json(res, 400, { error: `template mismatch: expected ${TEMPLATE}` });
  }
  const sha = String(body.sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) return json(res, 400, { error: 'bad sha256' });
  const restart = body.restart !== false;
  const requestedMode = String(body.restartMode || '').toLowerCase();
  if (requestedMode && requestedMode !== 'exec' && requestedMode !== 'exit' && requestedMode !== 'crash') {
    return json(res, 400, { error: 'restartMode must be exec, exit or crash' });
  }

  state.updating = true;
  try {
    const buf = await readUpdatePayload(body);
    const got = sha256Hex(buf);
    if (got !== sha) return json(res, 400, { error: `sha256 mismatch: got ${got}` });
    const text = buf.toString('utf8');
    if (!new RegExp(`const\\s+TEMPLATE\\s*=\\s*['"]${reEscape(TEMPLATE)}['"]`).test(text)) {
      return json(res, 400, { error: 'template marker mismatch' });
    }
    if (!new RegExp(`const\\s+VERSION\\s*=\\s*['"]${reEscape(targetVersion)}['"]`).test(text)) {
      return json(res, 400, { error: 'version marker mismatch' });
    }
    await checkScript(buf);

    const bak = `${SCRIPT_PATH}.bak`;
    const tmp = `${SCRIPT_PATH}.new`;
    await fsp.copyFile(SCRIPT_PATH, bak);
    await fsp.writeFile(tmp, buf, { mode: 0o755 });
    await fsp.chmod(tmp, 0o755).catch(() => {});
    try {
      await fsp.rename(tmp, SCRIPT_PATH);
    } catch {
      await fsp.unlink(SCRIPT_PATH).catch(() => {});
      await fsp.rename(tmp, SCRIPT_PATH);
    }

    const mode = requestedMode || updateRestartMode();
    log(`self-update staged ${VERSION} -> ${targetVersion} sha=${got.slice(0, 12)} restart=${restart ? mode : 'no'}`);
    json(res, restart ? 202 : 200, {
      ok: true,
      from: VERSION,
      to: targetVersion,
      sha256: got,
      restart,
      restartMode: restart ? mode : 'none',
    });
    if (restart) scheduleRestart(mode);
  } catch (e) {
    json(res, 400, { error: e.message });
  } finally {
    if (!state.restarting) state.updating = false;
  }
}

async function handleRollback(req, res) {
  if (state.updating || state.restarting) return json(res, 409, { error: 'update already in progress' });
  if (!SCRIPT_PATH || !SCRIPT_PATH.endsWith('.js')) {
    return json(res, 409, { error: 'script path unavailable' });
  }
  const bak = `${SCRIPT_PATH}.bak`;
  if (!fs.existsSync(bak)) return json(res, 404, { error: 'no backup' });
  const body = await readJson(req, 65536);
  const restart = !body || body.restart !== false;

  state.updating = true;
  try {
    const buf = await fsp.readFile(bak);
    await checkScript(buf);
    const tmp = `${SCRIPT_PATH}.new`;
    await fsp.writeFile(tmp, buf, { mode: 0o755 });
    await fsp.chmod(tmp, 0o755).catch(() => {});
    await fsp.rename(tmp, SCRIPT_PATH);
    const v = (buf.toString('utf8').match(/const\s+VERSION\s*=\s*['"]([^'"]+)['"]/) || [])[1] || '';
    log(`self-update rollback -> ${v || 'backup'} restart=${restart}`);
    json(res, restart ? 202 : 200, { ok: true, version: v, restart, restartMode: restart ? updateRestartMode() : 'none' });
    if (restart) scheduleRestart(updateRestartMode());
  } catch (e) {
    json(res, 400, { error: e.message });
  } finally {
    if (!state.restarting) state.updating = false;
  }
}


// ---- vpngate bootstrap -------------------------------------------------

const PYTHON_BIN = env.PYTHON_BIN || 'python3';
const VPNGATE_CSV_URL = env.VPNGATE_CSV_URL || 'https://www.vpngate.net/api/iphone/';
// Pterodactyl/KataBump containers have a low thread/process limit; keep the
// probe pool small there. Override with VPNGATE_* when the host allows more.
const PANEL_HOST = !!(env.SERVER_PORT || env.P_SERVER_PORT || env.KATABUMP_PORT);
const VPNGATE_MAX_CANDIDATES = Math.max(1, Number(env.VPNGATE_MAX_CANDIDATES || (PANEL_HOST ? 10 : 35)));
const VPNGATE_CONCURRENCY = Math.max(1, Number(env.VPNGATE_CONCURRENCY || (PANEL_HOST ? 4 : 20)));
const VPNGATE_PHASE1_CONCURRENCY = Math.max(1, Number(env.VPNGATE_PHASE1_CONCURRENCY || (PANEL_HOST ? 12 : 50)));
const VPNGATE_KEEP_NODES = Math.max(1, Number(env.VPNGATE_KEEP_NODES || 3));

let vpngatePreflightDone = false;
let vpngateIdx = 0;
let vpngateBurned = new Set();

function vpngateKey(node) {
  return `${node.server}:${node.server_port}`;
}

function loadVpngateIdx() {
  for (const p of [path.join(LOG_DIR, 'vpngate.idx'), '/tmp/vpngate_current_idx.txt']) {
    try {
      const n = Number(fs.readFileSync(p, 'utf8').trim());
      if (Number.isInteger(n) && n >= 0) return n;
    } catch {}
  }
  return 0;
}

function saveVpngateIdx() {
  try { fs.writeFileSync(path.join(LOG_DIR, 'vpngate.idx'), String(vpngateIdx)); } catch {}
}

async function preflightVpngate() {
  if (vpngatePreflightDone) return;
  const py = await runCommand(PYTHON_BIN, ['--version'], {
    logFile: path.join(LOG_DIR, 'preflight.log'),
    timeoutMs: 10000,
  });
  if (py !== 0) throw new Error(`${PYTHON_BIN} is required for vpngate mode`);
  const curl = await runCommand('curl', ['--version'], {
    logFile: path.join(LOG_DIR, 'preflight.log'),
    timeoutMs: 10000,
  });
  if (curl !== 0) throw new Error('curl is required for vpngate mode');
  vpngatePreflightDone = true;
}

async function ensureTemplateAssets() {
  await ensureAsset('vpngate_to_singbox.py', `${ASSETS_BASE_URL}/vpngate_to_singbox.py`, false, SCRIPT_DIR);
  await ensureAsset('probe_and_select_vpngate.py', `${ASSETS_BASE_URL}/probe_and_select_vpngate.py`, false, SCRIPT_DIR);
}

async function runVpngateSelect() {
  await preflightVpngate();
  const csvPath = path.join(LOG_DIR, 'vpngate.csv');
  log('fetching VPNGate CSV');
  const csv = await fetchBuffer(VPNGATE_CSV_URL, 60000);
  await fsp.writeFile(csvPath, csv);
  log(`VPNGate CSV ${csv.length} bytes`);

  const outPath = path.join(LOG_DIR, 'sb.json');
  const args = [
    path.join(SCRIPT_DIR, 'probe_and_select_vpngate.py'),
    '--csv', csvPath,
    '--output', outPath,
    '--zen-bin', ZEN_DIRECT_PATH,
    '--singbox-bin', SINGBOX_PATH,
    '--concurrency', String(VPNGATE_CONCURRENCY),
    '--phase1-concurrency', String(VPNGATE_PHASE1_CONCURRENCY),
    '--max-candidates', String(VPNGATE_MAX_CANDIDATES),
    '--keep-nodes', String(VPNGATE_KEEP_NODES),
    '--mixed-port', String(EGRESS_PORT),
  ];
  log('selecting VPNGate nodes');
  const code = await runCommand(PYTHON_BIN, args, {
    cwd: SCRIPT_DIR,
    env: { ...process.env, PYTHONPATH: SCRIPT_DIR, PYTHONUNBUFFERED: '1' },
    logFile: path.join(LOG_DIR, 'vpngate-select.log'),
    timeoutMs: 15 * 60 * 1000,
  });
  if (code !== 0) throw new Error(`vpngate select exited ${code}`);
  if (!fs.existsSync(outPath)) throw new Error('vpngate select produced no sb.json');
  vpngateBurned.clear();
  vpngateIdx = 0;
  saveVpngateIdx();
  log(`VPNGate nodes selected, idx=${vpngateIdx}`);
}

async function bootstrapEgress() {
  await runVpngateSelect();
  await sleep(5000);
  await startSingbox();
  if (!(await waitTcp(EGRESS_PORT, 30000))) throw new Error('sing-box did not listen');
  if (!(await verifyEgress(60000))) throw new Error('egress check failed');
}

async function rotateVpngate(reason) {
  const verifiedPath = '/tmp/verified_nodes.json';
  if (!fs.existsSync(verifiedPath)) return false;
  let nodes;
  try {
    nodes = JSON.parse(await fsp.readFile(verifiedPath, 'utf8'));
  } catch {
    return false;
  }
  if (!Array.isArray(nodes) || nodes.length === 0) return false;

  if (reason === '429' || reason === 'egress') {
    const cur = nodes[vpngateIdx % nodes.length];
    if (cur) vpngateBurned.add(vpngateKey(cur));
  }

  let next = -1;
  for (let step = 1; step <= nodes.length; step++) {
    const idx = (vpngateIdx + step) % nodes.length;
    if (!vpngateBurned.has(vpngateKey(nodes[idx]))) {
      next = idx;
      break;
    }
  }
  if (next < 0) {
    log(`VPNGate all ${nodes.length} verified nodes burned, re-selecting`);
    vpngateBurned.clear();
    return false;
  }

  vpngateIdx = next;
  saveVpngateIdx();
  const node = nodes[vpngateIdx];
  const endpoint = { ...node.endpoint, tag: 'vpngate-active' };
  const cfg = {
    log: { level: 'info' },
    endpoints: [endpoint],
    outbounds: [{ type: 'direct', tag: 'direct' }],
    inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: EGRESS_PORT }],
    route: { final: 'vpngate-active' },
  };
  await fsp.writeFile(path.join(LOG_DIR, 'sb.json'), JSON.stringify(cfg, null, 2));
  if (state.singbox) {
    await state.singbox.stop();
    state.singbox = null;
  }
  await sleep(2000);
  await startSingbox();
  const ok = await waitTcp(EGRESS_PORT, 30000);
  log(`VPNGate switched to #${vpngateIdx} ${vpngateKey(node)} reason=${reason || 'manual'} ok=${ok}`);
  return ok;
}

async function rotateEgress(reason) {
  const ok = await rotateVpngate(reason);
  if (ok) return;
  log(`VPNGate pool exhausted (reason=${reason || 'manual'}), re-selecting fresh nodes`);
  vpngateBurned.clear();
  vpngateIdx = 0;
  await runVpngateSelect();
  await startSingbox();
  if (!(await waitTcp(EGRESS_PORT, 30000))) throw new Error('sing-box did not listen after reselect');
}

