/**
 * Consensus verification - multi-source package integrity
 *
 * Fetches package from npm, GitHub Packages, and optionally IPFS.
 * Compares CIDs across sources for consensus.
 */

import axios from 'axios';
import { computePackageCID, fetchFromIPFS } from './ipfsVerification';

export interface ConsensusConfig {
  ENABLED?: boolean;
  SOURCES?: ('npm' | 'github' | 'ipfs')[];
  MIN_AGREEMENT?: number;
  GITHUB_TOKEN?: string | null;
  GATEWAY_URL?: string;
}

export interface ConsensusSourceResult {
  name: string;
  cid: string;
  match: boolean;
}

export interface ConsensusResult {
  agreed: boolean;
  cid: string | null;
  sources: ConsensusSourceResult[];
  consensusCount: number;
  totalSources: number;
}

const DEFAULT_CONFIG: ConsensusConfig = {
  ENABLED: false,
  SOURCES: ['npm', 'github', 'ipfs'],
  MIN_AGREEMENT: 2,
  GITHUB_TOKEN: null,
  GATEWAY_URL: 'https://ipfs.io',
};

async function fetchTarballFromNpm(
  packageName: string,
  version: string,
  timeout: number = 60000
): Promise<Buffer | null> {
  try {
    const metaRes = await axios.get(
      `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
      { timeout: 10000 }
    );
    const data = metaRes.data as {
      versions?: Record<string, { dist?: { tarball?: string } }>;
      'dist-tags'?: { latest?: string };
    };
    let versionData = data.versions?.[version];
    if (!versionData && version === 'latest') {
      const latest = data['dist-tags']?.latest;
      versionData = latest ? data.versions?.[latest] : undefined;
    }
    if (!versionData?.dist?.tarball) return null;
    const tarballRes = await axios.get(versionData.dist.tarball, {
      responseType: 'arraybuffer',
      timeout,
    });
    return Buffer.from(tarballRes.data);
  } catch {
    return null;
  }
}

async function fetchTarballFromGitHub(
  packageName: string,
  _version: string,
  repoUrl: string,
  token: string | null,
  timeout: number = 60000
): Promise<Buffer | null> {
  const m = repoUrl.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!m || !m[1] || !m[2]) return null;
  const owner = m[1];
  const repo = m[2];
  const cleanRepo = repo.replace(/\.git$/, '');
  try {
    const scope = owner.startsWith('@') ? owner.slice(1) : owner;
    const pkgName = packageName.includes('/') ? packageName.split('/')[1] : packageName;
    const url = `https://npm.pkg.github.com/@${scope}/${cleanRepo}/-/${pkgName}-${_version}.tgz`;
    const headers: Record<string, string> = {
      Accept: 'application/octet-stream',
      'User-Agent': 'NullVoid-Security-Scanner/2.1.0',
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await axios.get(url, {
      responseType: 'arraybuffer',
      timeout,
      headers,
      validateStatus: (s) => s === 200,
    });
    return Buffer.from(res.data);
  } catch {
    return null;
  }
}

async function getRepoUrl(packageName: string, version: string): Promise<string | null> {
  try {
    const metaRes = await axios.get(
      `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
      { timeout: 10000 }
    );
    const data = metaRes.data as {
      versions?: Record<string, { repository?: string | { url?: string } }>;
      repository?: string | { url?: string };
      'dist-tags'?: { latest?: string };
    };
    let versionData = data.versions?.[version];
    if (!versionData && version === 'latest') {
      const latest = data['dist-tags']?.latest;
      versionData = latest ? data.versions?.[latest] : undefined;
    }
    const repo = versionData?.repository ?? data.repository;
    if (!repo) return null;
    const url = typeof repo === 'string' ? repo : repo?.url;
    if (!url) return null;
    return url.replace(/^git\+/, '').replace(/\.git$/, '');
  } catch {
    return null;
  }
}

/**
 * Verify package integrity via multi-source consensus
 */
export async function verifyPackageConsensus(
  packageName: string,
  version: string,
  knownCid: string | null,
  config: Partial<ConsensusConfig> = {}
): Promise<ConsensusResult> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const sources = cfg.SOURCES ?? ['npm', 'github', 'ipfs'];
  const minAgreement = cfg.MIN_AGREEMENT ?? 2;
  const timeout = 60000;

  const results: ConsensusSourceResult[] = [];
  const cids: string[] = [];

  if (sources.includes('npm')) {
    const buf = await fetchTarballFromNpm(packageName, version, timeout);
    if (buf) {
      const { cid } = await computePackageCID(buf);
      cids.push(cid);
      results.push({
        name: 'npm',
        cid,
        match: false,
      });
    }
  }

  if (sources.includes('github')) {
    const repoUrl = await getRepoUrl(packageName, version);
    if (repoUrl && repoUrl.includes('github.com')) {
      const buf = await fetchTarballFromGitHub(
        packageName,
        version,
        repoUrl,
        cfg.GITHUB_TOKEN ?? null,
        timeout
      );
      if (buf) {
        const { cid } = await computePackageCID(buf);
        cids.push(cid);
        results.push({
          name: 'github',
          cid,
          match: false,
        });
      }
    }
  }

  if (sources.includes('ipfs') && knownCid) {
    const buf = await fetchFromIPFS(knownCid, {
      GATEWAY_URL: cfg.GATEWAY_URL ?? 'https://ipfs.io',
    });
    if (buf) {
      const { cid } = await computePackageCID(buf);
      cids.push(cid);
      results.push({
        name: 'ipfs',
        cid,
        match: false,
      });
    }
  }

  const countByCid = new Map<string, number>();
  for (const c of cids) {
    countByCid.set(c, (countByCid.get(c) ?? 0) + 1);
  }
  let majorityCid: string | null = null;
  let maxCount = 0;
  for (const [cid, count] of countByCid) {
    if (count > maxCount) {
      maxCount = count;
      majorityCid = cid;
    }
  }
  const consensusCount = maxCount;
  const agreed = consensusCount >= minAgreement;

  for (const r of results) {
    r.match = r.cid === majorityCid;
  }

  return {
    agreed,
    cid: majorityCid,
    sources: results,
    consensusCount,
    totalSources: results.length,
  };
}
