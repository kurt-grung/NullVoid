/**
 * Trust Network for package and publisher reputation
 *
 * Stores verification and scan results locally. Trust propagates from
 * verified CIDs and clean scan history.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface TrustRecord {
  packageName: string;
  version: string;
  cid?: string;
  verifiedAt?: string;
  lastScanOk: boolean;
  publisher?: string;
  trustScore: number;
}

export interface DepGraphNode {
  name: string;
  version: string;
  dependencies?: DepGraphNode[];
}

const DEFAULT_TRUST_STORE_PATH = path.join(os.homedir(), '.nullvoid', 'trust-store.json');

let trustStorePath = DEFAULT_TRUST_STORE_PATH;
const inMemoryCache = new Map<string, TrustRecord>();

function getStorePath(): string {
  const expanded = trustStorePath.startsWith('~')
    ? path.join(os.homedir(), trustStorePath.slice(1))
    : trustStorePath;
  return path.resolve(expanded);
}

function loadStore(): Record<string, TrustRecord> {
  const storePath = getStorePath();
  try {
    if (fs.existsSync(storePath)) {
      const content = fs.readFileSync(storePath, 'utf8');
      const data = JSON.parse(content);
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return data;
      }
    }
  } catch {
    /* ignore */
  }
  return {};
}

function saveStore(store: Record<string, TrustRecord>): void {
  const storePath = getStorePath();
  const dir = path.dirname(storePath);
  try {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(storePath, JSON.stringify(store, null, 2), 'utf8');
  } catch {
    /* ignore write errors */
  }
}

function key(pkg: string, version: string): string {
  return `${pkg}@${version}`;
}

/**
 * Configure the trust store path
 */
export function setTrustStorePath(p: string): void {
  trustStorePath = p;
}

/**
 * Get trust score for a package (0-1), or null if unknown
 */
export async function getTrustScore(pkg: string, version: string): Promise<number | null> {
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

/**
 * Record a successful CID verification
 */
export async function recordVerification(
  pkg: string,
  version: string,
  cid: string,
  publisher?: string
): Promise<void> {
  const k = key(pkg, version);
  const store = loadStore();
  const record: TrustRecord = {
    packageName: pkg,
    version,
    cid,
    verifiedAt: new Date().toISOString(),
    lastScanOk: true,
    trustScore: 1,
    ...(publisher != null && { publisher }),
  };
  store[k] = record;
  inMemoryCache.set(k, record);
  saveStore(store);
}

/**
 * Record scan result (ok = no high-severity threats)
 */
export async function recordScanResult(
  pkg: string,
  version: string,
  ok: boolean,
  publisher?: string
): Promise<void> {
  const k = key(pkg, version);
  const store = loadStore();
  const existing = store[k];
  const trustScore = ok ? (existing ? Math.min(1, existing.trustScore + 0.1) : 0.8) : 0.3;
  const pub = publisher ?? existing?.publisher;
  const record: TrustRecord = {
    packageName: pkg,
    version,
    lastScanOk: ok,
    trustScore: Math.max(0, Math.min(1, trustScore)),
    ...(pub != null && { publisher: pub }),
    ...(existing?.cid && { cid: existing.cid }),
    ...(existing?.verifiedAt && { verifiedAt: existing.verifiedAt }),
  };
  store[k] = record;
  inMemoryCache.set(k, record);
  saveStore(store);
}

/**
 * Compute transitive trust from dependency graph
 * If package A depends on trusted packages B, C, partial trust propagates upward
 */
export function computeTransitiveTrust(
  pkg: string,
  version: string,
  depGraph: DepGraphNode,
  trustScores: Map<string, number>,
  weight: number = 0.3
): number {
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
  const avg = sum / count;
  return Math.min(1, avg * weight);
}

/**
 * Get full trust record for a package
 */
export async function getTrustRecord(pkg: string, version: string): Promise<TrustRecord | null> {
  const k = key(pkg, version);
  const cached = inMemoryCache.get(k);
  if (cached != null) return cached;

  const store = loadStore();
  const record = store[k] ?? null;
  if (record) inMemoryCache.set(k, record);
  return record;
}
