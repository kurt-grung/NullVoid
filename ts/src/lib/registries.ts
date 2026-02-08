/**
 * Multi-registry provider (Phase 2)
 *
 * Fetches package metadata from npm, GitHub Packages, and configurable
 * private registries. Supports cross-registry comparison for dependency
 * confusion detection and registry health monitoring.
 */

import https from 'https';
import { DEPENDENCY_CONFUSION_CONFIG } from './config';

const REGISTRY_ENDPOINTS = DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS ?? {};
const REGISTRIES = DEPENDENCY_CONFUSION_CONFIG.REGISTRIES ?? {
  DEFAULT_ORDER: ['npm'],
  CUSTOM: [],
};
const TIMEOUT = DEPENDENCY_CONFUSION_CONFIG.ANALYSIS_SETTINGS?.TIMEOUT_MS ?? 10000;
const HEALTH_CHECK_TIMEOUT = 5000;

export interface RegistryMetadata {
  created: Date | null;
  modified: Date | null;
  versions: string[];
  registry: string;
}

export interface RegistryHealthResult {
  registryName: string;
  ok: boolean;
  latencyMs: number;
  statusCode?: number | undefined;
  error?: string | undefined;
}

export interface CustomRegistry {
  name: string;
  url: string;
  auth?: string;
}

interface RegistryBase {
  url: string;
  auth?: string | undefined;
}

interface FetchOptions {
  headers?: Record<string, string>;
  timeout?: number;
}

/**
 * Fetch JSON from a URL (GET)
 */
function fetchJson(
  url: string,
  options: FetchOptions = {}
): Promise<Record<string, unknown> | null> {
  const { headers = {}, timeout = TIMEOUT } = options;
  return new Promise((resolve) => {
    const req = https.get(
      url,
      {
        headers: {
          'User-Agent': 'NullVoid-Security-Scanner/2.0',
          Accept: 'application/json',
          ...headers,
        },
        timeout,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            resolve(data ? (JSON.parse(data) as Record<string, unknown>) : null);
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on('error', () => resolve(null));
    req.setTimeout(timeout, () => {
      req.destroy();
      resolve(null);
    });
  });
}

/**
 * Get list of registry names to query (built-in + custom order)
 */
export function getRegistryOrder(): string[] {
  const order = Array.from(REGISTRIES.DEFAULT_ORDER ?? ['npm']);
  const custom = REGISTRIES.CUSTOM ?? [];
  const names: string[] = [...order];
  custom.forEach((r: CustomRegistry) => {
    if (r.name && !names.includes(r.name)) names.push(r.name);
  });
  return names;
}

/**
 * Resolve registry base URL by name
 */
function getRegistryBase(name: string): RegistryBase | null {
  const endpoints = REGISTRY_ENDPOINTS as Record<string, string>;
  if (endpoints[name]) {
    return { url: endpoints[name].replace(/\/$/, '') };
  }
  const custom = (REGISTRIES.CUSTOM ?? []).find((r: CustomRegistry) => r.name === name);
  if (custom?.url) {
    const base: RegistryBase = { url: custom.url.replace(/\/$/, '') };
    if (custom.auth) base.auth = custom.auth;
    return base;
  }
  return null;
}

/**
 * npm registry: package metadata at GET /:packageName
 */
async function fetchNpmStyleMetadata(
  baseUrl: string,
  packageName: string,
  options: FetchOptions = {}
): Promise<RegistryMetadata | null> {
  const encoded = encodeURIComponent(packageName).replace(/^%40/, '@');
  const url = `${baseUrl}/${encoded}`;
  const json = await fetchJson(url, options);
  if (!json || typeof json !== 'object') return null;
  const time = json['time'] as Record<string, string> | undefined;
  const created = time?.['created'] ? new Date(time['created']) : null;
  const modified = time?.['modified'] ? new Date(time['modified']) : null;
  const versions = json['versions'] ? Object.keys(json['versions'] as Record<string, unknown>) : [];
  return {
    created,
    modified,
    versions,
    registry: baseUrl,
  };
}

/**
 * GitHub Packages: scoped packages live under owner; URL format differs.
 */
async function fetchGitHubPackagesMetadata(
  baseUrl: string,
  packageName: string,
  options: FetchOptions & { auth?: string } = {}
): Promise<RegistryMetadata | null> {
  if (!packageName.startsWith('@')) return null;
  const encoded = encodeURIComponent(packageName).replace(/^%40/, '@');
  const url = `${baseUrl}/${encoded}`;
  const headers: Record<string, string> = {};
  if (options.auth) headers['Authorization'] = options.auth;
  const json = await fetchJson(url, { ...options, headers });
  if (!json || typeof json !== 'object') return null;
  const time = json['time'] as Record<string, string> | undefined;
  const created = time?.['created'] ? new Date(time['created']) : null;
  const modified = time?.['modified'] ? new Date(time['modified']) : null;
  const versions = json['versions'] ? Object.keys(json['versions'] as Record<string, unknown>) : [];
  return {
    created,
    modified,
    versions,
    registry: baseUrl,
  };
}

/**
 * Fetch package metadata from a named registry
 */
export async function fetchFromRegistry(
  registryName: string,
  packageName: string,
  options: FetchOptions = {}
): Promise<(RegistryMetadata & { registryName: string }) | null> {
  const base = getRegistryBase(registryName);
  if (!base) return null;
  const auth = base.auth ? { auth: base.auth } : {};
  let meta;
  if (registryName === 'github') {
    meta = await fetchGitHubPackagesMetadata(base.url, packageName, { ...options, ...auth });
  } else {
    meta = await fetchNpmStyleMetadata(base.url, packageName, { ...options, ...auth });
  }
  if (!meta) return null;
  return { ...meta, registryName };
}

/**
 * Get package creation date from the first available registry (Phase 2 multi-registry)
 */
export async function getPackageCreationDateMulti(
  packageName: string,
  options: { registryOrder?: string[]; timeout?: number } = {}
): Promise<{
  created: Date;
  registryName: string;
  allResults: Array<{
    registryName: string;
    created: Date | null;
    modified: Date | null;
    versions: string[];
  }>;
} | null> {
  const order = options.registryOrder ?? getRegistryOrder();
  const allResults: Array<{
    registryName: string;
    created: Date | null;
    modified: Date | null;
    versions: string[];
  }> = [];
  for (const name of order) {
    const meta = await fetchFromRegistry(name, packageName, {
      timeout: options.timeout ?? TIMEOUT,
    });
    if (meta) {
      allResults.push({
        registryName: name,
        created: meta.created,
        modified: meta.modified,
        versions: meta.versions,
      });
      if (meta.created) {
        return {
          created: meta.created,
          registryName: name,
          allResults,
        };
      }
    }
  }
  const firstWithCreated = allResults.find((r) => r.created != null);
  return firstWithCreated
    ? {
        created: firstWithCreated.created!,
        registryName: firstWithCreated.registryName,
        allResults,
      }
    : null;
}

/**
 * Cross-registry comparison: fetch from all configured registries and compare
 */
export async function compareRegistries(
  packageName: string
): Promise<
  Array<{ registryName: string; created: Date | null; modified: Date | null; versions: string[] }>
> {
  const order = getRegistryOrder();
  const results: Array<{
    registryName: string;
    created: Date | null;
    modified: Date | null;
    versions: string[];
  }> = [];
  for (const name of order) {
    const meta = await fetchFromRegistry(name, packageName);
    if (meta) {
      results.push({
        registryName: name,
        created: meta.created,
        modified: meta.modified,
        versions: meta.versions,
      });
    }
  }
  return results;
}

/**
 * Registry health check: ping registry root and measure latency (Phase 2).
 */
export function checkRegistryHealth(
  registryName: string,
  options: { timeout?: number } = {}
): Promise<RegistryHealthResult> {
  const base = getRegistryBase(registryName);
  const timeout = options.timeout ?? HEALTH_CHECK_TIMEOUT;
  return new Promise((resolve) => {
    if (!base?.url) {
      resolve({ registryName, ok: false, latencyMs: 0, error: 'Unknown registry' });
      return;
    }
    const start = Date.now();
    const url = `${base.url}/`;
    const req = https.get(
      url,
      {
        headers: { 'User-Agent': 'NullVoid-Security-Scanner/2.0' },
        timeout,
      },
      (res) => {
        const latencyMs = Date.now() - start;
        const ok = res.statusCode != null && res.statusCode >= 200 && res.statusCode < 400;
        const result: RegistryHealthResult = { registryName, ok, latencyMs };
        if (res.statusCode != null) result.statusCode = res.statusCode;
        resolve(result);
      }
    );
    req.on('error', (err) => {
      resolve({ registryName, ok: false, latencyMs: Date.now() - start, error: err.message });
    });
    req.setTimeout(timeout, () => {
      req.destroy();
      resolve({ registryName, ok: false, latencyMs: Date.now() - start, error: 'Timeout' });
    });
  });
}

/**
 * Check health of all configured registries (Phase 2).
 */
export async function checkAllRegistriesHealth(
  options: { timeout?: number } = {}
): Promise<RegistryHealthResult[]> {
  const order = getRegistryOrder();
  const results: RegistryHealthResult[] = [];
  for (const name of order) {
    const health = await checkRegistryHealth(name, options);
    results.push(health);
  }
  return results;
}
