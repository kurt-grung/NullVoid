/**
 * Trust Network for package and publisher reputation
 *
 * Stores verification and scan results locally. Trust propagates from
 * verified CIDs and clean scan history.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_TRUST_STORE_PATH = path.join(os.homedir(), '.nullvoid', 'trust-store.json');

let trustStorePath = DEFAULT_TRUST_STORE_PATH;
const inMemoryCache = new Map();

function getStorePath() {
  const expanded = trustStorePath.startsWith('~')
    ? path.join(os.homedir(), trustStorePath.slice(1))
    : trustStorePath;
  return path.resolve(expanded);
}

function loadStore() {
  const storePath = getStorePath();
  try {
    if (fs.existsSync(storePath)) {
      const content = fs.readFileSync(storePath, 'utf8');
      const data = JSON.parse(content);
      if (data && typeof data === 'object' && !Array.isArray(data)) return data;
    }
  } catch {
    /* ignore */
  }
  return {};
}

function saveStore(store) {
  const storePath = getStorePath();
  const dir = path.dirname(storePath);
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(storePath, JSON.stringify(store, null, 2), 'utf8');
  } catch {
    /* ignore */
  }
}

function key(pkg, version) {
  return `${pkg}@${version}`;
}

function setTrustStorePath(p) {
  trustStorePath = p;
}

async function getTrustScore(pkg, version) {
  const k = key(pkg, version);
  const cached = inMemoryCache.get(k);
  if (cached != null) return cached.trustScore;

  const store = loadStore();
  const record = store[k];
  if (record) {
    inMemoryCache.set(k, record);
    return record.trustScore;
  }
  return null;
}

async function recordVerification(pkg, version, cid, publisher) {
  const k = key(pkg, version);
  const store = loadStore();
  const record = {
    packageName: pkg,
    version,
    cid,
    verifiedAt: new Date().toISOString(),
    lastScanOk: true,
    publisher,
    trustScore: 1,
  };
  store[k] = record;
  inMemoryCache.set(k, record);
  saveStore(store);
}

async function recordScanResult(pkg, version, ok, publisher) {
  const k = key(pkg, version);
  const store = loadStore();
  const existing = store[k];
  const trustScore = ok ? (existing ? Math.min(1, existing.trustScore + 0.1) : 0.8) : 0.3;
  const record = {
    packageName: pkg,
    version,
    lastScanOk: ok,
    publisher: publisher ?? existing?.publisher,
    trustScore: Math.max(0, Math.min(1, trustScore)),
    ...(existing?.cid && { cid: existing.cid }),
    ...(existing?.verifiedAt && { verifiedAt: existing.verifiedAt }),
  };
  store[k] = record;
  inMemoryCache.set(k, record);
  saveStore(store);
}

function computeTransitiveTrust(pkg, version, depGraph, trustScores, weight = 0.3) {
  const k = key(pkg, version);
  const direct = trustScores.get(k);
  if (direct != null) return direct;

  const deps = depGraph.dependencies ?? [];
  if (deps.length === 0) return 0;

  let sum = 0;
  let count = 0;
  for (const dep of deps) {
    const depKey = key(dep.name, dep.version);
    const depTrust = trustScores.get(depKey);
    if (depTrust != null) {
      sum += depTrust;
      count++;
    } else {
      const childTrust = computeTransitiveTrust(dep.name, dep.version, dep, trustScores, weight);
      if (childTrust > 0) {
        sum += childTrust;
        count++;
      }
    }
  }
  if (count === 0) return 0;
  return Math.min(1, (sum / count) * weight);
}

async function getTrustRecord(pkg, version) {
  const k = key(pkg, version);
  const cached = inMemoryCache.get(k);
  if (cached != null) return cached;

  const store = loadStore();
  const record = store[k] ?? null;
  if (record) inMemoryCache.set(k, record);
  return record;
}

module.exports = {
  setTrustStorePath,
  getTrustScore,
  recordVerification,
  recordScanResult,
  computeTransitiveTrust,
  getTrustRecord,
};
