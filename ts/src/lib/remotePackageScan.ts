import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as https from 'https';
import * as tar from 'tar';
import { createLogger } from './logger';
import { assertSafeTarballEntry, validatePackageName } from './pathSecurity';

const logger = createLogger('remotePackageScan');

const PACKAGE_SPEC_RE = /^(@[^/]+\/[^@]+|[^@/\s]+)(?:@(.+))?$/;

export interface PackageSpec {
  name: string;
  version: string;
}

export function isNpmPackageSpec(target: string): boolean {
  const trimmed = target?.trim();
  if (!trimmed || trimmed.startsWith('.') || trimmed.startsWith('/') || trimmed.includes('\\')) {
    return false;
  }
  if (!PACKAGE_SPEC_RE.test(trimmed)) return false;
  if (trimmed.startsWith('@')) return true;
  return !trimmed.includes('/') && !trimmed.includes(path.sep);
}

export function parsePackageSpec(spec: string): PackageSpec | null {
  const trimmed = spec.trim();
  const match = trimmed.match(PACKAGE_SPEC_RE);
  if (!match) return null;
  return {
    name: match[1] as string,
    version: (match[2] as string | undefined)?.trim() || 'latest',
  };
}

function fetchBuffer(url: string, timeoutMs = 15000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        headers: {
          'User-Agent': 'NullVoid-Security-Scanner/2.1',
          Accept: '*/*',
        },
        timeout: timeoutMs,
      },
      (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          const location = res.headers.location;
          if (location) {
            fetchBuffer(location, timeoutMs).then(resolve).catch(reject);
            return;
          }
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      }
    );
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error(`Timeout fetching ${url}`));
    });
  });
}

function fetchJson(url: string, timeoutMs = 15000): Promise<Record<string, unknown> | null> {
  return fetchBuffer(url, timeoutMs)
    .then((buf) => JSON.parse(buf.toString('utf8')) as Record<string, unknown>)
    .catch(() => null);
}

export async function fetchRegistryMetadata(
  packageName: string
): Promise<Record<string, unknown> | null> {
  const encoded = packageName.startsWith('@')
    ? `@${encodeURIComponent(packageName.slice(1))}`
    : encodeURIComponent(packageName);
  return fetchJson(`https://registry.npmjs.org/${encoded}`);
}

export function resolveVersion(metadata: Record<string, unknown>, version: string): string | null {
  if (version === 'latest') {
    const distTags = metadata['dist-tags'] as Record<string, string> | undefined;
    if (distTags?.['latest']) return distTags['latest'];
  }
  const versions = metadata['versions'] as Record<string, unknown> | undefined;
  if (versions && versions[version]) return version;
  if (versions) {
    const keys = Object.keys(versions).sort();
    return keys[keys.length - 1] ?? null;
  }
  return null;
}

export interface ResolvedRemotePackage {
  extractDir: string;
  packageName: string;
  version: string;
  cleanup: () => void;
}

export async function downloadPackageToTemp(
  packageName: string,
  version = 'latest'
): Promise<ResolvedRemotePackage | null> {
  if (!validatePackageName(packageName)) {
    logger.warn(`Rejected invalid package name: ${packageName}`);
    return null;
  }

  const metadata = await fetchRegistryMetadata(packageName);
  if (!metadata) return null;

  const resolvedVersion = resolveVersion(metadata, version);
  if (!resolvedVersion) return null;

  const versions = metadata['versions'] as Record<string, Record<string, unknown>> | undefined;
  const versionMeta = versions?.[resolvedVersion];
  const dist = versionMeta?.['dist'] as { tarball?: string } | undefined;
  const tarballUrl = dist?.tarball;
  if (!tarballUrl) return null;

  const tarball = await fetchBuffer(tarballUrl);
  const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nullvoid-pkg-'));
  const tarballPath = path.join(os.tmpdir(), `nullvoid-dl-${Date.now()}.tgz`);
  const cleanup = () => {
    try {
      fs.rmSync(extractDir, { recursive: true, force: true });
    } catch (error) {
      logger.warn(`Failed to remove temp package dir: ${(error as Error).message}`);
    }
  };

  try {
    fs.writeFileSync(tarballPath, tarball);
    await tar.extract({
      file: tarballPath,
      cwd: extractDir,
      strip: 1,
      onentry(entry) {
        try {
          assertSafeTarballEntry(entry.path, extractDir);
        } catch (error) {
          entry.destroy(error as Error);
        }
      },
    });
  } catch (error) {
    cleanup();
    try {
      fs.unlinkSync(tarballPath);
    } catch {
      /* ignore */
    }
    logger.warn(`Failed to extract package tarball: ${(error as Error).message}`);
    return null;
  }

  try {
    fs.unlinkSync(tarballPath);
  } catch {
    /* ignore */
  }

  return {
    extractDir,
    packageName,
    version: resolvedVersion,
    cleanup,
  };
}
