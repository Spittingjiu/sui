import fs from 'node:fs';
import { spawn } from 'node:child_process';

const RULES_FILE = process.env.SUI_FORWARD_RULES_FILE || '/opt/sui-panel/data/forwards.json';
const SOCAT_BIN = process.env.SUI_SOCAT_BIN || '/usr/bin/socat';
const RELOAD_INTERVAL_MS = Number(process.env.SUI_FORWARD_RELOAD_MS || 5000);

const procs = new Map(); // key => child

function log(...args) { console.log('[forwarder]', ...args); }

function normalizeRule(r = {}) {
  const protocol = String(r.protocol || 'tcp').toLowerCase();
  return {
    id: Number(r.id || 0),
    listenPort: Number(r.listenPort || 0),
    targetHost: String(r.targetHost || '').trim(),
    targetPort: Number(r.targetPort || 0),
    protocol: ['tcp', 'udp', 'both'].includes(protocol) ? protocol : 'tcp',
    enabled: r.enabled !== false,
  };
}

function ruleKeys(rule) {
  const base = `${rule.id}:${rule.listenPort}:${rule.targetHost}:${rule.targetPort}`;
  if (rule.protocol === 'both') return [`${base}:tcp`, `${base}:udp`];
  return [`${base}:${rule.protocol}`];
}

function loadRules() {
  try {
    if (!fs.existsSync(RULES_FILE)) return [];
    const raw = JSON.parse(fs.readFileSync(RULES_FILE, 'utf8'));
    const rules = Array.isArray(raw?.rules) ? raw.rules : [];
    return rules.map(normalizeRule).filter(r => r.id && r.listenPort && r.targetHost && r.targetPort && r.enabled);
  } catch (e) {
    log('load rules failed:', e.message);
    return [];
  }
}

function spawnSocat(rule, proto) {
  const listen = proto === 'udp'
    ? `UDP-LISTEN:${rule.listenPort},reuseaddr,fork`
    : `TCP-LISTEN:${rule.listenPort},reuseaddr,fork`;
  const target = `${proto.toUpperCase()}:${rule.targetHost}:${rule.targetPort}`;
  const child = spawn(SOCAT_BIN, ['-T60', listen, target], { stdio: ['ignore', 'pipe', 'pipe'] });

  child.stdout.on('data', d => log(`${rule.id}/${proto}`, String(d).trim()));
  child.stderr.on('data', d => log(`${rule.id}/${proto}`, String(d).trim()));
  child.on('exit', (code, sig) => {
    log(`exit ${rule.id}/${proto} code=${code} sig=${sig}`);
  });
  return child;
}

function reconcile() {
  const rules = loadRules();
  const desired = new Map();

  for (const rule of rules) {
    for (const key of ruleKeys(rule)) desired.set(key, rule);
  }

  // stop removed
  for (const [key, child] of procs.entries()) {
    if (!desired.has(key)) {
      try { child.kill('SIGTERM'); } catch {}
      procs.delete(key);
      log('stopped', key);
    }
  }

  // start missing
  for (const [key, rule] of desired.entries()) {
    if (procs.has(key)) continue;
    const proto = key.endsWith(':udp') ? 'udp' : 'tcp';
    const child = spawnSocat(rule, proto);
    procs.set(key, child);
    log('started', key);
  }
}

function shutdown() {
  for (const child of procs.values()) {
    try { child.kill('SIGTERM'); } catch {}
  }
  procs.clear();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('SIGHUP', () => { log('reload by SIGHUP'); reconcile(); });

log('boot with rules:', RULES_FILE);
reconcile();
setInterval(reconcile, RELOAD_INTERVAL_MS);
