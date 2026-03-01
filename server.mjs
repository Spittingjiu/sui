import express from 'express';
import crypto from 'crypto';
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { execSync } from 'node:child_process';
import QRCode from 'qrcode';

const app = express();
const PORT = Number(process.env.PORT || 8810);
const ENV_PANEL_TOKEN = process.env.PANEL_TOKEN || '';
const XRAY_PUBLIC_HOST = process.env.XRAY_PUBLIC_HOST || '';
const PANEL_SERVICE = process.env.PANEL_SERVICE || 'sui-panel.service';
const PANEL_TLS_ENABLE = ['1', 'true', 'yes', 'on'].includes(String(process.env.PANEL_TLS_ENABLE || '').toLowerCase());
const PANEL_TLS_CERT = process.env.PANEL_TLS_CERT || '';
const PANEL_TLS_KEY = process.env.PANEL_TLS_KEY || '';

const DATA_DIR = '/opt/sui-panel/data';
const DATA_FILE = path.join(DATA_DIR, 'inbounds.json');
const FORWARDS_FILE = path.join(DATA_DIR, 'forwards.json');
const PANEL_SETTINGS_FILE = path.join(DATA_DIR, 'panel-settings.json');
const XRAY_DIR = '/etc/sui-xray';
const XRAY_CONFIG = path.join(XRAY_DIR, 'config.json');
const XRAY_BIN = fs.existsSync('/usr/local/bin/xray') ? '/usr/local/bin/xray' : '/usr/local/x-ui/bin/xray-linux-amd64';
const XRAY_SERVICE = 'sui-xray-core.service';

const sessions = new Map();
let state = { seq: 1, inbounds: [] };
let forwardState = { seq: 1, rules: [] };
let panelSettings = {
  username: process.env.PANEL_USER || 'admin',
  password: process.env.PANEL_PASS || 'admin123',
  panelPath: normalizePanelPath(process.env.PANEL_PATH || '/'),
  panelToken: ENV_PANEL_TOKEN || crypto.randomBytes(18).toString('hex'),
  e2eePrivateKeyPem: '',
  e2eePublicKeyB64: '',
  forceResetPassword: true
};


const WRITE_DEBOUNCE_MS = Number(process.env.SUI_WRITE_DEBOUNCE_MS || 400);
let stateFlushTimer = null;
let forwardFlushTimer = null;
let panelSettingsFlushTimer = null;

function writeTextAtomic(file, content) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, file);
}

function writeJsonAtomic(file, obj) {
  writeTextAtomic(file, JSON.stringify(obj, null, 2));
}

app.use(express.json());

function j(v) { return JSON.stringify(v); }
function parseJ(v, d = {}) { try { return typeof v === 'string' ? JSON.parse(v) : (v ?? d); } catch { return d; } }
function b64(s){ return Buffer.from(String(s)).toString('base64'); }
function b64u(s){ return Buffer.from(String(s)).toString('base64url'); }
function normalizePanelPath(v = '/') {
  let p = String(v || '/').trim();
  if (!p || p === '/') return '/';
  if (!p.startsWith('/')) p = '/' + p;
  p = p.replace(/\/+/g, '/').replace(/\/$/, '');
  return p || '/';
}
function savePanelSettings(force = false) {
  if (force) {
    if (panelSettingsFlushTimer) { clearTimeout(panelSettingsFlushTimer); panelSettingsFlushTimer = null; }
    writeJsonAtomic(PANEL_SETTINGS_FILE, panelSettings);
    return;
  }
  if (panelSettingsFlushTimer) clearTimeout(panelSettingsFlushTimer);
  panelSettingsFlushTimer = setTimeout(() => {
    panelSettingsFlushTimer = null;
    writeJsonAtomic(PANEL_SETTINGS_FILE, panelSettings);
  }, WRITE_DEBOUNCE_MS);
}

function ensurePanelE2EEKeys(){
  if (panelSettings.e2eePrivateKeyPem && panelSettings.e2eePublicKeyB64) return;
  const kp = crypto.generateKeyPairSync('x25519');
  panelSettings.e2eePrivateKeyPem = kp.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  panelSettings.e2eePublicKeyB64 = kp.publicKey.export({type:'spki',format:'der'}).toString('base64url');
}

function encryptForSub(subPubB64, payloadObj){
  const subPub = crypto.createPublicKey({ key: Buffer.from(String(subPubB64||''), 'base64url'), format: 'der', type: 'spki' });
  const pri = crypto.createPrivateKey(panelSettings.e2eePrivateKeyPem);
  const secret = crypto.diffieHellman({ privateKey: pri, publicKey: subPub });
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(12);
  const nonce = crypto.randomBytes(16).toString('hex');
  const ts = Date.now();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(payloadObj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    e2ee: 1,
    alg: 'x25519+aes-256-gcm',
    senderPub: panelSettings.e2eePublicKeyB64,
    ts,
    nonce,
    iv: iv.toString('base64url'),
    tag: tag.toString('base64url'),
    ciphertext: ct.toString('base64url')
  };
}

function loadPanelSettings() {
  if (fs.existsSync(PANEL_SETTINGS_FILE)) {
    const o = parseJ(fs.readFileSync(PANEL_SETTINGS_FILE, 'utf8'), {});
    panelSettings.username = String(o.username || panelSettings.username || 'admin');
    panelSettings.password = String(o.password || panelSettings.password || 'admin123');
    panelSettings.panelPath = normalizePanelPath(o.panelPath || panelSettings.panelPath || '/');
    panelSettings.panelToken = String(o.panelToken || panelSettings.panelToken || ENV_PANEL_TOKEN || crypto.randomBytes(18).toString('hex'));
    panelSettings.e2eePrivateKeyPem = String(o.e2eePrivateKeyPem || panelSettings.e2eePrivateKeyPem || '');
    panelSettings.e2eePublicKeyB64 = String(o.e2eePublicKeyB64 || panelSettings.e2eePublicKeyB64 || '');
    ensurePanelE2EEKeys();
    panelSettings.forceResetPassword = o.forceResetPassword !== undefined ? !!o.forceResetPassword : false;
  } else {
    // 仅全新安装（无历史节点）时强制首次改密；老环境升级不拦截节点列表
    const hasHistory = fs.existsSync(DATA_FILE) || fs.existsSync('/etc/x-ui/x-ui.db');
    panelSettings.forceResetPassword = hasHistory ? false : true;
    panelSettings.panelToken = String(panelSettings.panelToken || ENV_PANEL_TOKEN || crypto.randomBytes(18).toString('hex'));
    ensurePanelE2EEKeys();
    savePanelSettings();
  }
}


function ensureDirs() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(XRAY_DIR, { recursive: true });
}

function mountPanelStatic() {
  const staticDir = path.join(process.cwd(), 'public');
  app.use((req, res, next) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/auth')) return next();
    const pp = panelSettings.panelPath || '/';
    if (pp === '/') return next();
    if (req.path === '/') return res.redirect(pp);
    if (req.path === pp || req.path.startsWith(pp + '/')) return next();
    return res.status(404).send('Not Found');
  });
  if ((panelSettings.panelPath || '/') === '/') {
    app.use(express.static(staticDir));
  } else {
    app.use(panelSettings.panelPath, express.static(staticDir));
  }
}

function shell(cmd) {
  return execSync(cmd, { shell: '/bin/bash', stdio: 'pipe' }).toString().trim();
}

const SYSTEMCTL_DEDUP_MS = Number(process.env.SUI_SYSTEMCTL_DEDUP_MS || 1000);
const systemctlRecent = new Map();
function runSystemctl(args, opts = {}) {
  const { dedupKey = args, dedupMs = SYSTEMCTL_DEDUP_MS, ignoreError = false } = opts;
  const now = Date.now();
  const last = systemctlRecent.get(dedupKey) || 0;
  if (dedupMs > 0 && now - last < dedupMs) return '';
  systemctlRecent.set(dedupKey, now);
  try {
    return shell(`systemctl ${args}`);
  } catch (e) {
    if (ignoreError) return '';
    throw e;
  }
}


function normalizeForwardRule(x = {}) {
  const protocol = String(x.protocol || 'tcp').toLowerCase();
  return {
    id: Number(x.id || 0),
    listenPort: Number(x.listenPort || 0),
    targetHost: String(x.targetHost || '').trim(),
    targetPort: Number(x.targetPort || 0),
    protocol: ['tcp','udp','both'].includes(protocol) ? protocol : 'tcp',
    enabled: x.enabled !== false,
    remark: String(x.remark || '')
  };
}

function writeForwardState(force = false){
  if (force) {
    if (forwardFlushTimer) { clearTimeout(forwardFlushTimer); forwardFlushTimer = null; }
    writeJsonAtomic(FORWARDS_FILE, forwardState);
    return;
  }
  if (forwardFlushTimer) clearTimeout(forwardFlushTimer);
  forwardFlushTimer = setTimeout(() => {
    forwardFlushTimer = null;
    writeJsonAtomic(FORWARDS_FILE, forwardState);
  }, WRITE_DEBOUNCE_MS);
}

function stopAndDisableForwardUnit(name){
  try { runSystemctl(`stop ${name}`, { dedupKey: `stop:${name}`, ignoreError: true }); } catch {}
  try { runSystemctl(`disable ${name}`, { dedupKey: `disable:${name}`, ignoreError: true }); } catch {}
  try { fs.unlinkSync(`/etc/systemd/system/${name}`); } catch {}
}

function ensureForwardService() {
  const unitPath = '/etc/systemd/system/sui-forward.service';
  const unit = `[Unit]\nDescription=SUI Forward Daemon\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory=/opt/sui-panel\nEnvironment=SUI_FORWARD_RULES_FILE=/opt/sui-panel/data/forwards.json\nExecStart=/usr/bin/node /opt/sui-panel/forwarder.mjs\nRestart=always\nRestartSec=1\nUser=root\n\n[Install]\nWantedBy=multi-user.target\n`;
  if (!fs.existsSync(unitPath) || fs.readFileSync(unitPath, 'utf8') !== unit) {
    fs.writeFileSync(unitPath, unit);
    runSystemctl('daemon-reload', { dedupKey: 'daemon-reload', dedupMs: 300, ignoreError: true });
  }
  runSystemctl('enable sui-forward.service', { dedupKey: 'enable:sui-forward.service', ignoreError: true });
}

function cleanupLegacyForwardUnits() {
  for (const f of fs.readdirSync('/etc/systemd/system')) {
    if (!f.startsWith('sui-forward-') || !f.endsWith('.service')) continue;
    stopAndDisableForwardUnit(f);
  }
  runSystemctl('daemon-reload', { dedupKey: 'daemon-reload', dedupMs: 300, ignoreError: true });
}

function syncForwardServices(){
  ensureForwardService();
  cleanupLegacyForwardUnits();
  const active = shell('systemctl is-active sui-forward.service || true');
  if (active === 'active') {
    try { shell('systemctl kill -s HUP sui-forward.service'); } catch {}
  } else {
    runSystemctl('restart sui-forward.service', { dedupKey: 'restart:sui-forward.service', dedupMs: 500, ignoreError: true });
  }
}

function loadForwardState(){
  if (fs.existsSync(FORWARDS_FILE)) {
    const o = parseJ(fs.readFileSync(FORWARDS_FILE, 'utf8'), {});
    const rules = Array.isArray(o.rules) ? o.rules.map(normalizeForwardRule) : [];
    const seq = Number(o.seq || 1);
    forwardState = { seq: seq > 0 ? seq : 1, rules };
  } else {
    forwardState = { seq: 1, rules: [] };
    writeForwardState(true);
  }
  syncForwardServices();
}

function flushPendingWrites() {
  try { savePanelSettings(true); } catch {}
  try { writeState(true); } catch {}
  try { writeForwardState(true); } catch {}
  try {
    if (xrayApplyTimer) {
      clearTimeout(xrayApplyTimer);
      flushXrayApplyQueue();
    }
  } catch {}
}

process.on('SIGINT', () => { flushPendingWrites(); process.exit(0); });
process.on('SIGTERM', () => { flushPendingWrites(); process.exit(0); });
process.on('beforeExit', () => { flushPendingWrites(); });

function ensureCoreService() {
  const unitPath = '/etc/systemd/system/sui-xray-core.service';
  const unit = `[Unit]\nDescription=SUI Self-hosted Xray Core\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=${XRAY_BIN} run -c ${XRAY_CONFIG}\nRestart=always\nRestartSec=2\nUser=root\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n`;
  if (!fs.existsSync(unitPath) || fs.readFileSync(unitPath, 'utf8') !== unit) {
    fs.writeFileSync(unitPath, unit);
    runSystemctl('daemon-reload', { dedupKey: 'daemon-reload', dedupMs: 300, ignoreError: true });
  }
  try { runSystemctl(`enable ${XRAY_SERVICE}`, { dedupKey: `enable:${XRAY_SERVICE}`, ignoreError: true }); } catch {}
}

function nextFreePort(used = new Set(), start = 20000, end = 40000){

  for(let i=0;i<1000;i++){
    const p = Math.floor(Math.random()*(end-start+1))+start;
    if(!used.has(p)) return p;
  }
  for(let p=start;p<=end;p++) if(!used.has(p)) return p;
  return 0;
}

function randomRemark(prefix = 'reality') {
  const a = ['azure','silver','golden','velvet','gentle','silent','noble','lunar','solar','crystal','autumn','spring','winter','summer','amber','royal','misty','swift','stellar','aurora'];
  const b = ['harbor','meadow','horizon','breeze','falcon','voyage','garden','river','forest','castle','valley','comet','phoenix','echo','whisper','oasis','bridge','summit','island','lantern'];
  return `${prefix}-${a[Math.floor(Math.random()*a.length)]}-${b[Math.floor(Math.random()*b.length)]}`;
}

function normalizeInbound(x = {}) {
  return {
    id: Number(x.id || 0),
    up: Number(x.up || 0),
    down: Number(x.down || 0),
    total: Number(x.total || 0),
    remark: String(x.remark || ''),
    enable: !!x.enable,
    expiryTime: Number(x.expiryTime || x.expiry_time || 0),
    listen: String(x.listen || ''),
    port: Number(x.port || 0),
    protocol: String(x.protocol || 'vless'),
    settings: typeof x.settings === 'string' ? x.settings : j(x.settings || {}),
    streamSettings: typeof x.streamSettings === 'string' ? x.streamSettings : (typeof x.stream_settings === 'string' ? x.stream_settings : j(x.streamSettings || {})),
    tag: String(x.tag || `inbound-${Date.now()}-${Math.random().toString(16).slice(2,8)}`),
    sniffing: typeof x.sniffing === 'string' ? x.sniffing : j(x.sniffing || { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false, routeOnly: false }),
    allocate: typeof x.allocate === 'string' ? x.allocate : j(x.allocate || { strategy: 'always', refresh: 5, concurrency: 3 }),
    chain: (typeof x.chain === 'string' ? parseJ(x.chain, {}) : (x.chain || {}))
  };
}

function buildInbound(form = {}) {
  const protocol = String(form.protocol || 'vless');
  const port = Number(form.port || 0);
  const remark = String(form.remark || protocol);
  const network = String(form.network || 'tcp');
  const security = String(form.security || 'none');
  const email = String(form.email || `${Date.now()}@xray.com`);
  const uuid = String(form.uuid || crypto.randomUUID());
  const password = String(form.password || crypto.randomBytes(8).toString('hex'));
  const method = String(form.method || 'aes-128-gcm');

  let settings = {};
  const flow = (form.flow !== undefined && form.flow !== null) ? String(form.flow) : '';
  if (protocol === 'vless') settings = { clients: [{ id: uuid, email, flow }], decryption: 'none', fallbacks: [] };
  if (protocol === 'vmess') settings = { clients: [{ id: uuid, alterId: 0, email }], disableInsecureEncryption: false };
  if (protocol === 'trojan') settings = { clients: [{ password, email }], fallbacks: [] };
  if (protocol === 'shadowsocks') settings = { clients: [{ method, password, email }], network: 'tcp,udp' };

  const stream = { network, security };
  if (network === 'ws') stream.wsSettings = { path: form.path || '/', headers: { Host: form.host || '' } };
  if (network === 'tcp') stream.tcpSettings = { acceptProxyProtocol: false, header: { type: 'none' } };
  if (security === 'tls') stream.tlsSettings = { serverName: form.sni || '', certificates: [] };
  if (security === 'reality') stream.realitySettings = { show: false, dest: form.realityDest || 'www.cloudflare.com:443', xver: 0, serverNames: [form.sni || 'www.cloudflare.com'], privateKey: form.privateKey || '', shortIds: [form.shortId || ''] };

  return normalizeInbound({
    up: 0, down: 0, total: Number(form.total || 0), remark,
    enable: true, expiryTime: Number(form.expiryTime || 0), listen: '', port, protocol,
    settings: j(settings), streamSettings: j(stream), tag: `inbound-${Date.now()}`,
    sniffing: j({ enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false, routeOnly: false }),
    allocate: j({ strategy: 'always', refresh: 5, concurrency: 3 }),
    chain: form.chain || {}
  });
}

function writeState(force = false) {
  if (force) {
    if (stateFlushTimer) { clearTimeout(stateFlushTimer); stateFlushTimer = null; }
    writeJsonAtomic(DATA_FILE, state);
    return;
  }
  if (stateFlushTimer) clearTimeout(stateFlushTimer);
  stateFlushTimer = setTimeout(() => {
    stateFlushTimer = null;
    writeJsonAtomic(DATA_FILE, state);
  }, WRITE_DEBOUNCE_MS);
}

function shellQ(v) {
  return `'${String(v).replace(/'/g, `'"'"'`)}'`;
}

function toRuntimeInbound(ib) {
  const o = {
    tag: ib.tag || `in-${ib.id}`,
    listen: ib.listen || undefined,
    port: Number(ib.port),
    protocol: ib.protocol,
    settings: parseJ(ib.settings, {}),
    streamSettings: parseJ(ib.streamSettings, {}),
    sniffing: parseJ(ib.sniffing, { enabled: true, destOverride: ['http', 'tls', 'quic'] })
  };
  if (!o.listen) delete o.listen;
  return o;
}

let lastXrayConfigHash = '';
let xrayApplyLock = false;

function xrayConfigHash(cfg) {
  const raw = JSON.stringify(cfg);
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function writeRenderedXrayConfigOnly() {
  const cfg = renderXrayConfig();
  const hash = xrayConfigHash(cfg);
  if (hash === lastXrayConfigHash) return { changed: false, hash };

  const bak = `${XRAY_CONFIG}.bak`;
  try {
    if (fs.existsSync(XRAY_CONFIG)) fs.copyFileSync(XRAY_CONFIG, bak);
    writeJsonAtomic(XRAY_CONFIG, cfg);
    shell(`${XRAY_BIN} run -test -c ${XRAY_CONFIG}`);
    lastXrayConfigHash = hash;
    return { changed: true, hash };
  } catch (e) {
    if (fs.existsSync(bak)) {
      try { fs.copyFileSync(bak, XRAY_CONFIG); } catch {}
    }
    throw e;
  }
}

function xrayApiAddInbound(ib) {
  const tmpDir = fs.mkdtempSync('/tmp/sui-adi-');
  const tmpFile = path.join(tmpDir, 'inbound.json');
  fs.writeFileSync(tmpFile, JSON.stringify({ inbounds: [toRuntimeInbound(ib)] }, null, 2));
  try {
    shell(`${XRAY_BIN} api adi --server=127.0.0.1:10085 ${shellQ(tmpFile)}`);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

function xrayApiRemoveInboundByTag(tag) {
  if (!tag) return;
  shell(`${XRAY_BIN} api rmi --server=127.0.0.1:10085 ${shellQ(tag)}`);
}

function parseDomainFilter(raw = '') {
  return String(raw || '')
    .split(/[\n,]+/)
    .map(s => s.trim().toLowerCase())
    .filter(Boolean)
    .map((d) => {
      // 规则：
      // 1) .example.com -> 子域泛匹配（domain:example.com）
      // 2) example.com  -> 根域+子域（domain:example.com）
      // 3) a.b.com      -> 精确匹配（full:a.b.com）
      const clean = d.replace(/^\.+/, '');
      const labels = clean.split('.').filter(Boolean);
      if (d.startsWith('.')) return `domain:${clean}`;
      if (labels.length <= 2) return `domain:${clean}`;
      return `full:${clean}`;
    });
}

function buildChainOutbound(ib) {
  const c = ib.chain || {};
  if (!c?.enabled || !c?.type || !c?.host || !c?.port) return null;
  const tag = `chain-out-${ib.id}`;
  const port = Number(c.port);
  if (!port) return null;

  if (c.type === 'socks5') {
    return {
      tag,
      protocol: 'socks',
      settings: { servers: [{ address: String(c.host), port, users: c.user ? [{ user: String(c.user), pass: String(c.pass || '') }] : [] }] }
    };
  }
  if (c.type === 'http') {
    return {
      tag,
      protocol: 'http',
      settings: { servers: [{ address: String(c.host), port, users: c.user ? [{ user: String(c.user), pass: String(c.pass || '') }] : [] }] }
    };
  }
  if (c.type === 'shadowsocks') {
    return {
      tag,
      protocol: 'shadowsocks',
      settings: { servers: [{ address: String(c.host), port, method: String(c.method || 'aes-128-gcm'), password: String(c.password || '') }] }
    };
  }
  if (c.type === 'reality') {
    return {
      tag,
      protocol: 'vless',
      settings: {
        vnext: [{
          address: String(c.host),
          port,
          users: [{ id: String(c.uuid || ''), encryption: 'none', flow: String(c.flow || 'xtls-rprx-vision') }]
        }]
      },
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: {
          serverName: String(c.serverName || ''),
          publicKey: String(c.publicKey || ''),
          shortId: String(c.shortId || ''),
          fingerprint: String(c.fingerprint || 'chrome')
        }
      }
    };
  }
  return null;
}

function renderXrayConfig() {
  const enabledInbounds = state.inbounds.filter(x => x.enable);
  const inbounds = [];
  const outbounds = [
    { protocol: 'freedom', tag: 'direct' },
    { protocol: 'blackhole', tag: 'blocked' }
  ];
  const rules = [
    { type: 'field', inboundTag: ['api-in'], outboundTag: 'api' }
  ];

  for (const ib of enabledInbounds) {
    const rt = toRuntimeInbound(ib);
    const domains = parseDomainFilter(ib.chain?.domainFilter || '');
    const enhance = ib.chain?.enhanceDomainRouting !== false;
    if (enhance && domains.length) {
      rt.sniffing = {
        ...(rt.sniffing || {}),
        enabled: true,
        destOverride: ['http', 'tls'],
        routeOnly: true
      };
    }
    inbounds.push(rt);

    const ob = buildChainOutbound(ib);
    if (!ob) continue;
    outbounds.push(ob);

    if (domains.length) {
      if (enhance) {
        const udpPolicy = String(ib.chain?.udp443Policy || 'block').toLowerCase() === 'direct' ? 'direct' : 'blocked';
        rules.push({ type: 'field', inboundTag: [ib.tag], network: 'udp', port: '443', outboundTag: udpPolicy });
      }
      rules.push({ type: 'field', inboundTag: [ib.tag], domain: domains, outboundTag: ob.tag });
      rules.push({ type: 'field', inboundTag: [ib.tag], outboundTag: 'direct' });
    } else {
      rules.push({ type: 'field', inboundTag: [ib.tag], outboundTag: ob.tag });
    }
  }

  // xray api stats inlet (local only)
  inbounds.push({
    tag: 'api-in',
    listen: '127.0.0.1',
    port: 10085,
    protocol: 'dokodemo-door',
    settings: { address: '127.0.0.1' }
  });

  return {
    log: { loglevel: 'warning' },
    api: { tag: 'api', services: ['StatsService', 'HandlerService'] },
    stats: {},
    policy: {
      levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
      system: { statsInboundUplink: true, statsInboundDownlink: true }
    },
    inbounds,
    outbounds,
    routing: { domainStrategy: 'IPIfNonMatch', rules }
  };
}

function restartXrayService() {
  try { runSystemctl(`restart ${XRAY_SERVICE}`, { dedupKey: `restart:${XRAY_SERVICE}`, dedupMs: 500 }); }
  catch { runSystemctl(`start ${XRAY_SERVICE}`, { dedupKey: `start:${XRAY_SERVICE}`, dedupMs: 500 }); }
}

function applyAndRestart() {
  writeRenderedXrayConfigOnly();
  restartXrayService();
}

const XRAY_APPLY_DEBOUNCE_MS = Number(process.env.SUI_XRAY_APPLY_DEBOUNCE_MS || 300);
let xrayApplyTimer = null;
let xrayPendingOps = [];

function flushXrayApplyQueue() {
  if (xrayApplyLock) return;
  const ops = xrayPendingOps;
  xrayPendingOps = [];
  xrayApplyTimer = null;
  if (!ops.length) return;

  xrayApplyLock = true;
  try {
    const changed = writeRenderedXrayConfigOnly().changed;
    if (!changed && !ops.some(x => x.type === 'restart')) {
      return;
    }

    for (const op of ops) {
      if (op.type === 'add') xrayApiAddInbound(op.ib);
      else if (op.type === 'remove') xrayApiRemoveInboundByTag(op.tag);
      else if (op.type === 'replace') {
        if (op.oldTag) xrayApiRemoveInboundByTag(op.oldTag);
        xrayApiAddInbound(op.newIb);
      } else if (op.type === 'restart') {
        restartXrayService();
      }
    }
  } catch {
    restartXrayService();
  } finally {
    xrayApplyLock = false;
    if (xrayPendingOps.length && !xrayApplyTimer) {
      xrayApplyTimer = setTimeout(flushXrayApplyQueue, XRAY_APPLY_DEBOUNCE_MS);
    }
  }
}

function scheduleXrayApply(op) {
  xrayPendingOps.push(op);
  if (xrayApplyTimer) clearTimeout(xrayApplyTimer);
  xrayApplyTimer = setTimeout(flushXrayApplyQueue, XRAY_APPLY_DEBOUNCE_MS);
}

function applyHotAddOrRestart(ib) {
  scheduleXrayApply({ type: 'add', ib });
}

function applyHotRemoveOrRestart(tag) {
  scheduleXrayApply({ type: 'remove', tag });
}

function applyHotReplaceOrRestart(oldTag, newIb) {
  scheduleXrayApply({ type: 'replace', oldTag, newIb });
}

function applyBbrFq() {
  const conf = [
    'net.core.default_qdisc=fq',
    'net.ipv4.tcp_congestion_control=bbr'
  ].join('\n') + '\n';
  fs.writeFileSync('/etc/sysctl.d/99-sui-bbr.conf', conf);
  shell('modprobe tcp_bbr || true');
  shell('sysctl --system >/dev/null');
  return {
    qdisc: shell('sysctl -n net.core.default_qdisc || true'),
    cc: shell('sysctl -n net.ipv4.tcp_congestion_control || true')
  };
}

function applyNetSysctlProfile() {
  const conf = [
    'fs.file-max = 1048576',
    'net.core.somaxconn = 65535',
    'net.core.netdev_max_backlog = 32768',
    'net.ipv4.tcp_max_syn_backlog = 8192',
    'net.ipv4.ip_local_port_range = 1024 65535',
    'net.ipv4.tcp_fin_timeout = 15',
    'net.ipv4.tcp_tw_reuse = 1',
    'net.core.rmem_max = 67108864',
    'net.core.wmem_max = 67108864',
    'net.ipv4.tcp_rmem = 4096 87380 33554432',
    'net.ipv4.tcp_wmem = 4096 65536 33554432',
    'net.ipv4.tcp_mtu_probing = 1'
  ].join('\n') + '\n';
  fs.writeFileSync('/etc/sysctl.d/99-sui-net.conf', conf);
  shell('sysctl --system >/dev/null');
  return { ok: true };
}

function applyDnsProfile() {
  const dir = '/etc/systemd/resolved.conf.d';
  fs.mkdirSync(dir, { recursive: true });
  const conf = [
    '[Resolve]',
    'DNS=1.1.1.1 8.8.8.8 2606:4700:4700::1111 2001:4860:4860::8888',
    'FallbackDNS=9.9.9.9 1.0.0.1 2620:fe::fe 2606:4700:4700::1001',
    'DNSStubListener=yes',
    'DNSSEC=no'
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(dir, '99-sui-dns.conf'), conf);
  try { runSystemctl('restart systemd-resolved', { dedupKey: 'restart:systemd-resolved', dedupMs: 1000, ignoreError: true }); } catch {}
  return { ok: true };
}

function migrateFromXuiDb() {
  try {
    if (!fs.existsSync('/etc/x-ui/x-ui.db')) return false;
    const raw = shell(`python3 - <<'PY'\nimport sqlite3, json\nconn=sqlite3.connect('/etc/x-ui/x-ui.db')\nconn.row_factory=sqlite3.Row\ncur=conn.cursor()\ncur.execute('select * from inbounds order by id asc')\nrows=[dict(r) for r in cur.fetchall()]\nprint(json.dumps(rows, ensure_ascii=False))\nconn.close()\nPY`);
    const rows = JSON.parse(raw || '[]');
    if (!Array.isArray(rows) || !rows.length) return false;
    state.inbounds = rows.map((r, idx) => normalizeInbound({
      ...r,
      id: Number(r.id || idx + 1),
      streamSettings: r.stream_settings,
      expiryTime: r.expiry_time
    }));
    state.seq = Math.max(1, ...state.inbounds.map(x => x.id)) + 1;
    return true;
  } catch {
    return false;
  }
}

function loadState() {
  ensureDirs();
  loadPanelSettings();
  ensureCoreService();
  loadForwardState();
  if (fs.existsSync(DATA_FILE)) {
    state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    state.seq ||= 1;
    state.inbounds ||= [];
    applyAndRestart();
    return;
  }
  const migrated = migrateFromXuiDb();
  if (!migrated) state = { seq: 1, inbounds: [] };
  writeState(true);
  applyAndRestart();
}

function auth(req, res, next) {
  if (req.headers['x-panel-token'] === panelSettings.panelToken) return next();
  const authz = String(req.headers.authorization || '');
  const tk = authz.startsWith('Bearer ') ? authz.slice(7).trim() : '';
  const sess = sessions.get(tk);
  if (!tk || !sess || !sess.exp || sess.exp <= Date.now()) return res.status(401).json({ success: false, msg: 'unauthorized' });
  if (sess.mustReset) {
    const allow = req.path === '/panel/settings'
      || req.path === '/panel/change-password'
      || req.path.startsWith('/system/');
    if (!allow) return res.status(403).json({ success: false, msg: '首次登录请先重置密码', code: 'RESET_REQUIRED' });
  }
  req.sessionToken = tk;
  req.session = sess;
  return next();
}

mountPanelStatic();
app.get('/api/health', (_req, res) => res.json({ ok: true, mode: 'self-hosted' }));
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (String(username) !== panelSettings.username || String(password) !== panelSettings.password) return res.status(401).json({ success: false, msg: '账号或密码错误' });
  const token = crypto.randomBytes(24).toString('hex');
  const mustReset = !!panelSettings.forceResetPassword;
  sessions.set(token, { exp: Date.now() + 1000 * 60 * 60 * 24 * 7, mustReset });
  res.json({ success: true, token, user: panelSettings.username, mustReset, panelPath: panelSettings.panelPath || '/' });
});
app.post('/auth/logout', (req, res) => {
  const authz = String(req.headers.authorization || '');
  const tk = authz.startsWith('Bearer ') ? authz.slice(7).trim() : '';
  if (tk) sessions.delete(tk);
  res.json({ success: true });
});
app.get('/auth/me', (req, res) => {
  const authz = String(req.headers.authorization || '');
  const tk = authz.startsWith('Bearer ') ? authz.slice(7).trim() : '';
  const sess = sessions.get(tk);
  if (tk && sess && sess.exp > Date.now()) return res.json({ success: true, user: panelSettings.username, mustReset: !!sess.mustReset, panelPath: panelSettings.panelPath || '/' });
  res.status(401).json({ success: false });
});

app.use('/api', auth);

app.get('/api/panel/settings', (req, res) => {
  res.json({ success: true, obj: { username: panelSettings.username, panelPath: panelSettings.panelPath || '/', forceResetPassword: !!panelSettings.forceResetPassword, panelTokenMasked: (panelSettings.panelToken||'').slice(0,6)+'...'+(panelSettings.panelToken||'').slice(-6) } });
});

app.post('/api/panel/settings', (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const panelPath = normalizePanelPath(req.body?.panelPath || '/');
    if (username) panelSettings.username = username;
    panelSettings.panelPath = panelPath;
    savePanelSettings();
    res.json({ success: true, obj: { username: panelSettings.username, panelPath: panelSettings.panelPath }, msg: '设置已保存，路径修改重启后生效' });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/panel/change-password', (req, res) => {
  try {
    const oldPassword = String(req.body?.oldPassword || '');
    const newPassword = String(req.body?.newPassword || '');
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ success: false, msg: '新密码至少6位' });
    const needOld = !req.session?.mustReset;
    if (needOld && oldPassword !== panelSettings.password) return res.status(400).json({ success: false, msg: '旧密码错误' });
    panelSettings.password = newPassword;
    panelSettings.forceResetPassword = false;
    savePanelSettings();
    if (req.sessionToken) {
      const s = sessions.get(req.sessionToken) || {};
      s.mustReset = false;
      sessions.set(req.sessionToken, s);
    }
    res.json({ success: true, msg: '密码已更新' });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});


app.get('/api/panel/token', (_req, res) => {
  res.json({ success: true, obj: { token: panelSettings.panelToken || '' } });
});

app.post('/api/panel/token/rotate', (_req, res) => {
  panelSettings.panelToken = crypto.randomBytes(24).toString('hex');
  savePanelSettings(true);
  res.json({ success: true, obj: { token: panelSettings.panelToken }, msg: 'API Token 已更新' });
});

app.post('/api/panel/connect-sub', async (req, res) => {
  try {
    const subUrl = String(req.body?.subUrl || '').trim().replace(/\/$/, '');
    const subUsername = String(req.body?.subUsername || '').trim();
    const subPassword = String(req.body?.subPassword || '');
    const sourceName = String(req.body?.sourceName || 'sui-panel').trim() || 'sui-panel';
    if (!subUrl || !subUsername || !subPassword) return res.status(400).json({ success: false, msg: 'subUrl / subUsername / subPassword 必填' });

    const panelBase = `${req.protocol}://${req.get('host')}`;
    const mr = await fetch(`${subUrl}/api/bridge/e2ee-meta`);
    if (!mr.ok) return res.status(500).json({ success: false, msg: `获取 sub 公钥失败 HTTP ${mr.status}` });
    const mj = await mr.json();
    if (!mj?.ok || !mj?.publicKey) return res.status(500).json({ success: false, msg: 'sub 公钥无效' });
    const envelope = encryptForSub(mj.publicKey, {
      username: subUsername,
      password: subPassword,
      name: sourceName,
      panel_url: panelBase,
      panel_token: panelSettings.panelToken
    });
    const r = await fetch(`${subUrl}/api/bridge/push-source`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope)
    });
    const txt = await r.text();
    let j = null;
    try { j = txt ? JSON.parse(txt) : null; } catch {}
    if (!r.ok || !j?.ok) return res.status(500).json({ success: false, msg: j?.error || `对接失败 HTTP ${r.status}` });
    res.json({ success: true, msg: '已写入到 sui-sub' });
  } catch (e) {
    res.status(500).json({ success: false, msg: e.message });
  }
});

const TRAFFIC_REFRESH_INTERVAL_MS = Number(process.env.SUI_TRAFFIC_REFRESH_MS || 8000);
let lastTrafficRefreshAt = 0;
let trafficRefreshRunning = false;

function refreshInboundTraffic() {
  try {
    const out = shell(`${XRAY_BIN} api statsquery --server=127.0.0.1:10085 -pattern 'inbound>>>' 2>/dev/null || true`);
    if (!out) return;
    let arr = [];
    try { arr = JSON.parse(out)?.stat || []; } catch { arr = []; }
    const map = new Map();
    for (const item of arr) {
      const name = String(item?.name || '');
      const m = name.match(/^inbound>>>(.+?)>>>traffic>>>(uplink|downlink)$/);
      if (!m) continue;
      const tag = m[1];
      const dir = m[2];
      if (!map.has(tag)) map.set(tag, { up: 0, down: 0 });
      map.get(tag)[dir === 'uplink' ? 'up' : 'down'] = Number(item?.value || 0);
    }
    for (const ib of state.inbounds) {
      const t = map.get(ib.tag || '');
      if (!t) continue;
      ib.up = Number(t.up || 0);
      ib.down = Number(t.down || 0);
    }
  } catch {}
}

function scheduleTrafficRefresh(force = false) {
  const now = Date.now();
  if (trafficRefreshRunning) return;
  if (!force && (now - lastTrafficRefreshAt) < TRAFFIC_REFRESH_INTERVAL_MS) return;
  trafficRefreshRunning = true;
  setImmediate(() => {
    try { refreshInboundTraffic(); } finally {
      lastTrafficRefreshAt = Date.now();
      trafficRefreshRunning = false;
    }
  });
}

app.get('/api/inbounds', async (_req, res) => {
  scheduleTrafficRefresh(false);
  res.json({ success: true, obj: state.inbounds.sort((a,b)=>a.id-b.id) });
});
app.get('/api/inbounds/next-port', async (_req, res) => {
  const used = new Set(state.inbounds.map(x => Number(x.port)).filter(Boolean));
  res.json({ success: true, obj: nextFreePort(used) });
});
app.post('/api/inbounds/add', async (req, res) => {
  const payload = buildInbound(req.body || {});
  if (!payload.port) return res.status(400).json({ success: false, msg: 'port required' });
  payload.id = state.seq++;
  state.inbounds.push(payload);
  writeState();
  applyHotAddOrRestart(payload);
  res.json({ success: true, obj: payload });
});
app.post('/api/inbounds/add-reality-quick', async (req, res) => {
  const used = new Set(state.inbounds.map(x => Number(x.port)).filter(Boolean));
  const port = Number(req.body?.port || nextFreePort(used));
  if (!port) return res.status(400).json({ success: false, msg: 'no free port' });
  const keyOut = shell(`${XRAY_BIN} x25519`);
  const privateKey = (keyOut.match(/Private(?:\s*key|Key):\s*([^\n\r]+)/i) || [,''])[1].trim();
  const publicKey = (keyOut.match(/(?:Public\s*key|Password):\s*([^\n\r]+)/i) || [,''])[1].trim();
  const shortId = crypto.randomBytes(8).toString('hex');
  const pickedSni = String(req.body?.sni || 'www.cloudflare.com');
  const payload = buildInbound({
    protocol: 'vless', network: 'tcp', security: 'reality',
    port, remark: req.body?.remark || randomRemark('reality'),
    email: req.body?.email || `reality-${port}@xray.com`,
    sni: pickedSni,
    realityDest: req.body?.realityDest || `${pickedSni}:443`,
    privateKey, shortId, flow: req.body?.flow || 'xtls-rprx-vision'
  });
  payload.id = state.seq++;
  state.inbounds.push(payload);
  writeState();
  applyHotAddOrRestart(payload);
  res.json({ success: true, obj: payload, extra: { privateKey, publicKey, shortId, port } });
});
app.put('/api/inbounds/:id', async (req, res) => {
  const id = Number(req.params.id);
  const target = state.inbounds.find(i => i.id === id);
  if (!target) return res.status(404).json({ success: false });
  const old = JSON.parse(JSON.stringify(target));
  if (req.body.remark !== undefined) target.remark = String(req.body.remark);
  if (req.body.port !== undefined && String(req.body.port).trim()) target.port = Number(req.body.port);
  writeState();
  applyHotReplaceOrRestart(old.tag || `in-${id}`, target);
  res.json({ success: true, obj: target });
});
app.put('/api/inbounds/:id/full', async (req, res) => {
  const id = Number(req.params.id);
  const idx = state.inbounds.findIndex(i => i.id === id);
  if (idx < 0) return res.status(404).json({ success: false, msg: 'not found' });
  const old = state.inbounds[idx];
  const payload = buildInbound(req.body || {});
  if (!payload.port) return res.status(400).json({ success: false, msg: 'port required' });
  payload.id = id;
  payload.up = old.up || 0;
  payload.down = old.down || 0;
  payload.enable = req.body.enable !== undefined ? !!req.body.enable : old.enable;
  state.inbounds[idx] = payload;
  writeState();
  try {
    if (!old.enable && !payload.enable) {
      writeRenderedXrayConfigOnly();
    } else if (!old.enable && payload.enable) {
      applyHotAddOrRestart(payload);
    } else if (old.enable && !payload.enable) {
      applyHotRemoveOrRestart(old.tag || `in-${id}`);
    } else {
      applyHotReplaceOrRestart(old.tag || `in-${id}`, payload);
    }
    return res.json({ success: true, obj: payload });
  } catch (e) {
    return res.json({ success: true, obj: payload, msg: '已保存，但热更新失败并已回退重启：' + (e?.message || 'unknown') });
  }
});
app.post('/api/inbounds/:id/toggle', async (req, res) => {
  const id = Number(req.params.id);
  const target = state.inbounds.find(i => i.id === id);
  if (!target) return res.status(404).json({ success: false });
  const oldEnable = !!target.enable;
  target.enable = !target.enable;
  writeState();
  if (oldEnable && !target.enable) applyHotRemoveOrRestart(target.tag || `in-${id}`);
  else if (!oldEnable && target.enable) applyHotAddOrRestart(target);
  else writeRenderedXrayConfigOnly();
  res.json({ success: true, obj: target });
});
app.delete('/api/inbounds/:id', async (req, res) => {
  const id = Number(req.params.id);
  const old = state.inbounds.find(x => x.id === id);
  state.inbounds = state.inbounds.filter(x => x.id !== id);
  writeState();
  if (old?.enable) applyHotRemoveOrRestart(old.tag || `in-${id}`);
  else writeRenderedXrayConfigOnly();
  res.json({ success: true });
});
app.post('/api/inbounds/batch-toggle', async (req, res) => {
  const { ids = [], enable } = req.body || {};
  const idset = new Set(ids.map(Number));
  const out = [];
  const toAdd = [];
  const toRemove = [];
  for (const item of state.inbounds) {
    if (!idset.has(item.id)) continue;
    const prev = !!item.enable;
    item.enable = typeof enable === 'boolean' ? enable : !item.enable;
    if (!prev && item.enable) toAdd.push(item);
    if (prev && !item.enable) toRemove.push(item.tag || `in-${item.id}`);
    out.push({ id: item.id, success: true });
  }
  writeState();
  writeRenderedXrayConfigOnly();
  try {
    for (const tag of toRemove) xrayApiRemoveInboundByTag(tag);
    for (const ib of toAdd) xrayApiAddInbound(ib);
  } catch {
    applyAndRestart();
  }
  res.json({ success: true, obj: out });
});


app.get('/api/forwards', async (_req, res) => {
  res.json({ success: true, obj: (forwardState.rules || []).sort((a,b)=>a.id-b.id) });
});

app.post('/api/forwards', async (req, res) => {
  try {
    const payload = normalizeForwardRule(req.body || {});
    if (!payload.listenPort || !payload.targetHost || !payload.targetPort) return res.status(400).json({ success: false, msg: 'listenPort/targetHost/targetPort required' });
    if ((forwardState.rules || []).some(x => x.listenPort === payload.listenPort && x.enabled)) return res.status(400).json({ success: false, msg: '监听端口已被占用' });
    payload.id = forwardState.seq++;
    payload.enabled = true;
    forwardState.rules.push(payload);
    writeForwardState();
    syncForwardServices();
    res.json({ success: true, obj: payload });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.put('/api/forwards/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const idx = (forwardState.rules || []).findIndex(x => x.id === id);
    if (idx < 0) return res.status(404).json({ success: false, msg: 'not found' });
    const old = forwardState.rules[idx];
    const next = normalizeForwardRule({ ...old, ...(req.body || {}), id });
    if (!next.listenPort || !next.targetHost || !next.targetPort) return res.status(400).json({ success: false, msg: 'listenPort/targetHost/targetPort required' });
    const clash = (forwardState.rules || []).some(x => x.id !== id && x.enabled && x.listenPort === next.listenPort);
    if (clash) return res.status(400).json({ success: false, msg: '监听端口已被占用' });
    forwardState.rules[idx] = next;
    writeForwardState();
    syncForwardServices();
    res.json({ success: true, obj: next });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/forwards/:id/toggle', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const t = (forwardState.rules || []).find(x => x.id === id);
    if (!t) return res.status(404).json({ success: false, msg: 'not found' });
    t.enabled = !t.enabled;
    writeForwardState();
    syncForwardServices();
    res.json({ success: true, obj: t });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.delete('/api/forwards/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    forwardState.rules = (forwardState.rules || []).filter(x => x.id !== id);
    writeForwardState();
    syncForwardServices();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/system/restart-panel', async (_req, res) => {
  try { runSystemctl(`restart ${PANEL_SERVICE}`, { dedupKey: `restart:${PANEL_SERVICE}`, dedupMs: 500 }); res.json({ success: true, msg: 'panel restarted' }); }
  catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/system/chain/test', async (req, res) => {
  try {
    const host = String(req.body?.host || '').trim();
    const port = Number(req.body?.port || 0);
    if (!host || !port) return res.status(400).json({ success: false, msg: 'host/port required' });
    const cmd = `timeout 6 bash -lc 'cat < /dev/null > /dev/tcp/${host}/${port}'`;
    shell(cmd);
    res.json({ success: true, msg: '连接成功' });
  } catch (e) {
    res.status(500).json({ success: false, msg: '连接失败: ' + (e.message || 'unknown') });
  }
});

app.post('/api/system/restart-xray', async (_req, res) => {
  try { runSystemctl(`restart ${XRAY_SERVICE}`, { dedupKey: `restart:${XRAY_SERVICE}`, dedupMs: 500 }); res.json({ success: true, msg: 'xray restarted' }); }
  catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

// backward compatibility
app.post('/api/system/restart-xui', async (_req, res) => {
  try { runSystemctl(`restart ${XRAY_SERVICE}`, { dedupKey: `restart:${XRAY_SERVICE}`, dedupMs: 500 }); res.json({ success: true, msg: 'xray restarted' }); }
  catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/system/optimize/bbr', async (_req, res) => {
  try { const obj = applyBbrFq(); res.json({ success: true, obj, msg: 'BBR + fq 已应用' }); }
  catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/system/optimize/dns', async (_req, res) => {
  try { const obj = applyDnsProfile(); res.json({ success: true, obj, msg: 'DNS 配置已应用' }); }
  catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/system/optimize/sysctl', async (_req, res) => {
  try { const obj = applyNetSysctlProfile(); res.json({ success: true, obj, msg: '网络栈参数已应用' }); }
  catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/system/optimize/all', async (_req, res) => {
  try {
    const bbr = applyBbrFq();
    const dns = applyDnsProfile();
    const sysctl = applyNetSysctlProfile();
    res.json({ success: true, obj: { bbr, dns, sysctl }, msg: '全部优化已应用' });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.get('/api/system/status', async (_req, res) => {
  try {
    const svc = (name) => {
      let active = 'unknown', enabled = 'unknown';
      try { active = shell(`systemctl is-active ${name}`); } catch { active = 'inactive'; }
      try { enabled = shell(`systemctl is-enabled ${name}`); } catch { enabled = 'disabled'; }
      return { name, active, enabled };
    };
    let panel = svc(PANEL_SERVICE);
    // Docker/非systemd场景：当前进程在线就算 active
    if (panel.active !== 'active') panel = { ...panel, active: 'active' };
    const xray = svc(XRAY_SERVICE);
    let version = '';
    try {
      const out = shell(`${XRAY_BIN} version 2>/dev/null | head -n 1`);
      const m = out.match(/Xray\s+([\w.\-]+)/i);
      version = m ? m[1] : out;
    } catch {}
    const inboundsTotal = state.inbounds.length;
    const inboundsEnabled = state.inbounds.filter(x => x.enable).length;
    res.json({ success: true, obj: { panel, xray, xrayVersion: version, inboundsTotal, inboundsEnabled } });
  } catch (e) {
    res.status(500).json({ success: false, msg: e.message });
  }
});

function buildLinksForInbound(ib, reqHeaders = {}) {
  const settings = parseJ(ib.settings, {});
  const stream = parseJ(ib.streamSettings, {});
  const protocol = ib.protocol;
  let host = XRAY_PUBLIC_HOST;
  if (!host) {
    const rawHost = reqHeaders['x-forwarded-host'] || reqHeaders.host || '';
    host = String(rawHost).split(',')[0].trim().replace(/:\d+$/, '');
  }
  if (!host) {
    try { host = shell('curl -s4 ifconfig.me'); } catch {}
  }
  if (!host) host = 'jp.zzao.de';
  const sni = stream?.tlsSettings?.serverName || stream?.realitySettings?.serverNames?.[0] || 'www.cloudflare.com';
  const network = stream?.network || 'tcp';
  const security = stream?.security || 'none';
  const pth = stream?.wsSettings?.path || '/';
  const wsHost = stream?.wsSettings?.headers?.Host || host;
  let realityPbK = stream?.realitySettings?.settings?.publicKey || stream?.realitySettings?.publicKey || '';
  const realitySid = (stream?.realitySettings?.shortIds || [])[0] || '';
  if (security === 'reality' && !realityPbK) {
    const pri = stream?.realitySettings?.privateKey || '';
    if (pri) {
      try {
        const out = shell(`${XRAY_BIN} x25519 -i '${pri}'`);
        realityPbK = (out.match(/(?:Public\s*key|Password):\s*([^\n\r]+)/i) || [,''])[1].trim();
      } catch {}
    }
  }
  const links = [];
  const clients = settings.clients || [];
  for (const c of clients) {
    const email = c.email || 'user';
    if (protocol === 'vless') {
      const params = new URLSearchParams();
      params.set('type', network);
      if (network === 'ws') { params.set('path', pth); params.set('host', wsHost); }
      if (security !== 'none') params.set('security', security);
      if (sni) params.set('sni', sni);
      if (security === 'reality') {
        if (realityPbK) params.set('pbk', realityPbK);
        if (realitySid) params.set('sid', realitySid);
        if (c.flow || 'xtls-rprx-vision') params.set('flow', c.flow || 'xtls-rprx-vision');
        params.set('fp', 'chrome');
      } else if (c.flow) params.set('flow', c.flow);
      links.push(`vless://${c.id}@${host}:${ib.port}?${params.toString()}#${encodeURIComponent(ib.remark || email)}`);
    } else if (protocol === 'vmess') {
      const obj = { v: '2', ps: ib.remark || email, add: host, port: String(ib.port), id: c.id, aid: String(c.alterId || 0), scy: 'auto', net: network, type: 'none', host: network === 'ws' ? wsHost : '', path: network === 'ws' ? pth : '', tls: security === 'none' ? '' : 'tls', sni };
      links.push(`vmess://${b64(JSON.stringify(obj))}`);
    } else if (protocol === 'trojan') {
      const params = new URLSearchParams();
      params.set('type', network);
      if (network === 'ws') { params.set('path', pth); params.set('host', wsHost); }
      if (security !== 'none') params.set('security', security);
      if (sni) params.set('sni', sni);
      links.push(`trojan://${encodeURIComponent(c.password)}@${host}:${ib.port}?${params.toString()}#${encodeURIComponent(ib.remark || email)}`);
    } else if (protocol === 'shadowsocks') {
      const method = c.method || 'aes-128-gcm';
      const pwd = c.password || '';
      links.push(`ss://${b64u(`${method}:${pwd}`)}@${host}:${ib.port}#${encodeURIComponent(ib.remark || email)}`);
    }
  }
  return links;
}

app.get('/api/inbounds/:id/links', async (req, res) => {
  const id = Number(req.params.id);
  const ib = state.inbounds.find(i => i.id === id);
  if (!ib) return res.status(404).json({ success: false, msg: 'not found' });
  res.json({ success: true, obj: buildLinksForInbound(ib, req.headers || {}) });
});


app.get('/api/system/xray/version-current', async (_req, res) => {
  try {
    const out = shell(`${XRAY_BIN} version 2>/dev/null | head -n 1`);
    const m = out.match(/Xray\s+([\w.\-]+)/i);
    const binVer = m ? m[1] : out;
    res.json({ success: true, obj: { binary: binVer, panel: 'self-hosted' } });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.get('/api/system/xray/reality-gen', async (_req, res) => {
  try {
    const out = shell(`${XRAY_BIN} x25519`);
    const pri = (out.match(/Private(?:\s*key|Key):\s*([^\n\r]+)/i) || [,''])[1].trim();
    const pub = (out.match(/(?:Public\s*key|Password):\s*([^\n\r]+)/i) || [,''])[1].trim();
    const shortId = crypto.randomBytes(8).toString('hex');
    res.json({ success: true, obj: { privateKey: pri, publicKey: pub, shortId, spiderX: '/' } });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.get('/api/system/xray/config', async (_req, res) => {
  try {
    const content = fs.readFileSync(XRAY_CONFIG, 'utf8');
    res.json({ success: true, obj: { path: XRAY_CONFIG, content } });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.post('/api/system/xray/config', async (req, res) => {
  let tmp = '';
  try {
    const content = String(req.body?.content || '');
    if (!content.trim()) return res.status(400).json({ success: false, msg: '配置内容不能为空' });
    let parsed = null;
    try { parsed = JSON.parse(content); }
    catch { return res.status(400).json({ success: false, msg: 'JSON 格式错误' }); }

    tmp = `${XRAY_CONFIG}.tmp-${Date.now()}`;
    fs.writeFileSync(tmp, JSON.stringify(parsed, null, 2));
    shell(`${XRAY_BIN} run -test -c ${shellQ(tmp)}`);
    fs.renameSync(tmp, XRAY_CONFIG);
    res.json({ success: true, msg: '配置已保存并通过校验（未自动重启）' });
  } catch (e) {
    if (tmp && fs.existsSync(tmp)) { try { fs.unlinkSync(tmp); } catch {} }
    res.status(500).json({ success: false, msg: e.message });
  }
});

app.get('/api/system/xray/versions', async (_req, res) => {
  try {
    const r = await fetch('https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20', { headers: { 'User-Agent': 'sui-self-panel' } });
    const arr = await r.json();
    res.json({ success: true, obj: (arr || []).map(x => x.tag_name).filter(Boolean) });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});
app.post('/api/system/xray/switch', async (req, res) => {
  const version = String(req.body.version || '').trim();
  if (!version) return res.status(400).json({ success: false, msg: 'version required' });
  try {
    const cmd = [
      'set -e',
      'TMP=$(mktemp -d)',
      `curl -fL --retry 3 -o "$TMP/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip"`,
      'unzip -o "$TMP/xray.zip" -d "$TMP" >/dev/null',
      'install -m 0755 "$TMP/xray" /usr/local/bin/xray',
      '[ -f "$TMP/geoip.dat" ] && install -m 0644 "$TMP/geoip.dat" /usr/local/share/xray-geoip.dat || true',
      '[ -f "$TMP/geosite.dat" ] && install -m 0644 "$TMP/geosite.dat" /usr/local/share/xray-geosite.dat || true',
      'rm -rf "$TMP"'
    ].join(' && ');
    shell(cmd);
    ensureCoreService();
    runSystemctl('daemon-reload', { dedupKey: 'daemon-reload', dedupMs: 300, ignoreError: true });
    runSystemctl(`restart ${XRAY_SERVICE}`, { dedupKey: `restart:${XRAY_SERVICE}`, dedupMs: 500 });
    const now = shell('/usr/local/bin/xray version 2>/dev/null | head -n 1');
    res.json({ success: true, msg: `switched to ${version}`, current: now });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

app.get('/api/inbounds/:id/qr', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const ib = state.inbounds.find(x => x.id === id);
    if (!ib) return res.status(404).json({ success: false, msg: 'not found' });
    const link = (buildLinksForInbound(ib, req.headers || {}) || [])[0];
    if (!link) return res.status(404).json({ success: false, msg: 'no link' });
    const qrDataUrl = await QRCode.toDataURL(link, { width: 512, margin: 1 });
    res.json({ success: true, obj: { link, qrDataUrl } });
  } catch (e) { res.status(500).json({ success: false, msg: e.message }); }
});

loadState();
// 后台刷新流量统计，避免首屏节点列表被阻塞
scheduleTrafficRefresh(true);
setInterval(() => scheduleTrafficRefresh(true), TRAFFIC_REFRESH_INTERVAL_MS);

const canUseTls = PANEL_TLS_ENABLE && PANEL_TLS_CERT && PANEL_TLS_KEY && fs.existsSync(PANEL_TLS_CERT) && fs.existsSync(PANEL_TLS_KEY);
if (canUseTls) {
  const tlsOptions = {
    cert: fs.readFileSync(PANEL_TLS_CERT),
    key: fs.readFileSync(PANEL_TLS_KEY)
  };
  https.createServer(tlsOptions, app).listen(PORT, () => {
    console.log(`sui-panel https on :${PORT}`);
    console.log(`tls_cert=${PANEL_TLS_CERT}`);
    console.log(`PANEL_TOKEN=${panelSettings.panelToken}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`sui-panel on :${PORT}`);
    if (PANEL_TLS_ENABLE) console.log('WARN: PANEL_TLS_ENABLE=1 but cert/key missing, fallback to HTTP');
    console.log(`PANEL_TOKEN=${panelSettings.panelToken}`);
  });
}
