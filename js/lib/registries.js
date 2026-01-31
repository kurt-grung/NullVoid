/**
 * Multi-registry provider (Phase 2)
 *
 * Fetches package metadata from npm, GitHub Packages, and configurable
 * private registries. Supports cross-registry comparison for dependency
 * confusion detection.
 */

const https = require('https');
const { DEPENDENCY_CONFUSION_CONFIG } = require('./config');

const REGISTRY_ENDPOINTS = DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS || {};
const REGISTRIES = DEPENDENCY_CONFUSION_CONFIG.REGISTRIES || { defaultOrder: ['npm'], custom: [] };
const TIMEOUT = DEPENDENCY_CONFUSION_CONFIG.ANALYSIS_SETTINGS?.TIMEOUT ?? 10000;

/**
 * Fetch JSON from a URL (GET)
 * @param {string} url - Full URL
 * @param {Object} [options] - { headers, timeout }
 * @returns {Promise<Object|null>} Parsed JSON or null
 */
function fetchJson(url, options = {}) {
  const { headers = {}, timeout = TIMEOUT } = options;
  return new Promise((resolve) => {
    const req = https.get(
      url,
      {
        headers: {
          'User-Agent': 'NullVoid-Security-Scanner/2.0',
          Accept: 'application/json',
          ...headers
        },
        timeout
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            resolve(data ? JSON.parse(data) : null);
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
 * @returns {string[]} Registry names in query order
 */
function getRegistryOrder() {
  const order = REGISTRIES.DEFAULT_ORDER || ['npm'];
  const custom = REGISTRIES.CUSTOM || [];
  const names = [...order];
  custom.forEach((r) => {
    if (r.name && !names.includes(r.name)) names.push(r.name);
  });
  return names;
}

/**
 * Resolve registry base URL by name
 * @param {string} name - Registry name (npm, github, or custom name)
 * @returns {{ url: string, auth?: string }|null}
 */
function getRegistryBase(name) {
  if (REGISTRY_ENDPOINTS[name]) {
    return { url: REGISTRY_ENDPOINTS[name].replace(/\/$/, '') };
  }
  const custom = (REGISTRIES.CUSTOM || []).find((r) => r.name === name);
  if (custom?.url) {
    return { url: custom.url.replace(/\/$/, ''), auth: custom.auth };
  }
  return null;
}

/**
 * npm registry: package metadata at GET /:packageName
 * @param {string} baseUrl - e.g. https://registry.npmjs.org
 * @param {string} packageName - Full package name
 * @param {Object} [options] - fetch options
 * @returns {Promise<{ created: Date|null, modified: Date|null, versions: string[], registry: string }|null>}
 */
async function fetchNpmStyleMetadata(baseUrl, packageName, options = {}) {
  const encoded = encodeURIComponent(packageName).replace(/^%40/, '@');
  const url = `${baseUrl}/${encoded}`;
  const json = await fetchJson(url, options);
  if (!json || typeof json !== 'object') return null;
  const created = json.time?.created ? new Date(json.time.created) : null;
  const modified = json.time?.modified ? new Date(json.time.modified) : null;
  const versions = json.versions ? Object.keys(json.versions) : [];
  return {
    created,
    modified,
    versions,
    registry: baseUrl
  };
}

/**
 * GitHub Packages: scoped packages live under owner; URL format differs.
 * npm.pkg.github.com uses npm protocol: GET /@scope%2Fname
 * @param {string} baseUrl - e.g. https://npm.pkg.github.com
 * @param {string} packageName - Full package name (e.g. @owner/name)
 * @param {Object} [options] - { auth, timeout }
 * @returns {Promise<{ created: Date|null, modified: Date|null, versions: string[], registry: string }|null>}
 */
async function fetchGitHubPackagesMetadata(baseUrl, packageName, options = {}) {
  if (!packageName.startsWith('@')) return null;
  const encoded = encodeURIComponent(packageName).replace(/^%40/, '@');
  const url = `${baseUrl}/${encoded}`;
  const headers = {};
  if (options.auth) headers.Authorization = options.auth;
  const json = await fetchJson(url, { ...options, headers });
  if (!json || typeof json !== 'object') return null;
  const created = json.time?.created ? new Date(json.time.created) : null;
  const modified = json.time?.modified ? new Date(json.time.modified) : null;
  const versions = json.versions ? Object.keys(json.versions) : [];
  return {
    created,
    modified,
    versions,
    registry: baseUrl
  };
}

/**
 * Fetch package metadata from a named registry
 * @param {string} registryName - npm, github, or custom name
 * @param {string} packageName - Full package name
 * @param {Object} [options] - { timeout }
 * @returns {Promise<{ created: Date|null, modified: Date|null, versions: string[], registry: string, registryName: string }|null>}
 */
async function fetchFromRegistry(registryName, packageName, options = {}) {
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
 * @param {string} packageName - Package name
 * @param {Object} [options] - { registryOrder, timeout }
 * @returns {Promise<{ created: Date, registryName: string, allResults: Array }|null>}
 */
async function getPackageCreationDateMulti(packageName, options = {}) {
  const order = options.registryOrder || getRegistryOrder();
  const allResults = [];
  for (const name of order) {
    const meta = await fetchFromRegistry(name, packageName, { timeout: options.timeout ?? TIMEOUT });
    if (meta) {
      allResults.push({
        registryName: name,
        created: meta.created,
        modified: meta.modified,
        versions: meta.versions
      });
      if (meta.created) {
        return {
          created: meta.created,
          registryName: name,
          allResults
        };
      }
    }
  }
  return allResults.length ? { created: allResults[0].created, registryName: order[0], allResults } : null;
}

/**
 * Cross-registry comparison: fetch from all configured registries and compare
 * creation/modified dates. Useful for detecting conflicting or duplicated packages.
 * @param {string} packageName - Package name
 * @returns {Promise<Array<{ registryName: string, created: Date|null, modified: Date|null, versions: string[] }>>}
 */
async function compareRegistries(packageName) {
  const order = getRegistryOrder();
  const results = [];
  for (const name of order) {
    const meta = await fetchFromRegistry(name, packageName);
    if (meta)
      results.push({
        registryName: name,
        created: meta.created,
        modified: meta.modified,
        versions: meta.versions
      });
  }
  return results;
}

module.exports = {
  getRegistryOrder,
  getRegistryBase,
  fetchFromRegistry,
  getPackageCreationDateMulti,
  compareRegistries,
  fetchJson
};
