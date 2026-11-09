/**
 * IoC providers against recorded HTTP responses (no network).
 * Fixtures: test/fixtures/http/*.json; harness: test/helpers/recordedHttp.ts.
 */
import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../src/lib/providers/fetchWithTimeout');

import { useRecordedHttp } from '../helpers/recordedHttp';
import { createNpmAdvisoriesProvider } from '../../src/lib/providers/npmAdvisories';
import { createGHSAProvider } from '../../src/lib/providers/ghsa';
import { createCVEProvider } from '../../src/lib/providers/cve';
import { createSnykProvider } from '../../src/lib/providers/snyk';
import { providerFetch } from '../../src/lib/providers/providerHttpClient';

const http = useRecordedHttp();

beforeEach(() => http.reset());

describe('npm advisories provider', () => {
  const provider = createNpmAdvisoriesProvider({ enabled: true, timeout: 1000 });

  it('maps advisories to IoC results and filters by version', async () => {
    http.on('registry.npmjs.org/-/npm/v1/security/advisories', 'npm-advisories-lodash');

    const all = await provider.query({ packageName: 'lodash' });
    expect(all.results).toHaveLength(2);
    expect(all.results.map((r) => r.vulnerabilityId)).toEqual(['CVE-2020-8203', 'CVE-2019-10744']);
    expect(all.results[0]).toMatchObject({
      packageName: 'lodash',
      severity: 'HIGH',
      affectedVersions: '<4.17.19',
      source: 'npm',
    });
    expect(all.results[1]?.severity).toBe('CRITICAL');

    // 4.17.15: in <4.17.19 but not in <4.17.12
    const v = await provider.query({ packageName: 'lodash', version: '4.17.15' });
    expect(v.results.map((r) => r.vulnerabilityId)).toEqual(['CVE-2020-8203']);

    const fixed = await provider.query({ packageName: 'lodash', version: '4.17.21' });
    expect(fixed.results).toHaveLength(0);
    expect(http.calls.every((c) => c.url.includes('package=lodash'))).toBe(true);
  });

  it('treats 404 as no advisories, not an error', async () => {
    http.on('registry.npmjs.org', 'http-404');
    const r = await provider.query({ packageName: 'nothing-here' });
    expect(r.results).toEqual([]);
    expect(r.metadata.error).toBeUndefined();
  });

  it('reports other HTTP errors in metadata and returns no results', async () => {
    http.on('registry.npmjs.org', 'http-429');
    const r = await provider.query({ packageName: 'lodash' });
    expect(r.results).toEqual([]);
    expect(r.metadata.error).toMatch(/429/);
  });

  it('returns nothing when disabled, without touching the network', async () => {
    const off = createNpmAdvisoriesProvider({ enabled: false });
    const r = await off.query({ packageName: 'lodash' });
    expect(r.results).toEqual([]);
    expect(http.calls).toHaveLength(0);
  });
});

describe('GHSA provider', () => {
  it('posts a GraphQL query and maps advisories per vulnerable range', async () => {
    http.on('api.github.com/graphql', 'ghsa-minimist');
    const provider = createGHSAProvider({ enabled: true, apiKey: 'ghp_test', timeout: 1000 });

    const r = await provider.query({ packageName: 'minimist', version: '1.2.5' });
    expect(http.calls[0]?.method).toBe('POST');
    expect(JSON.parse(http.calls[0]?.body ?? '{}')).toMatchObject({
      variables: { packageName: 'minimist' },
    });
    expect(r.results.length).toBeGreaterThanOrEqual(1);
    expect(r.results[0]).toMatchObject({
      packageName: 'minimist',
      severity: 'CRITICAL',
      source: 'ghsa',
    });
    expect(r.results[0]?.vulnerabilityId).toMatch(/GHSA-xvch-5gv4-984h|CVE-2021-44906/);
    expect(r.results[0]?.cvss?.baseScore).toBe(9.8);
  });

  it('surfaces a 403 as a rate-limit error', async () => {
    http.on('api.github.com/graphql', 'ghsa-rate-limit');
    const provider = createGHSAProvider({ enabled: true, timeout: 1000 });
    const r = await provider.query({ packageName: 'minimist' });
    expect(r.results).toEqual([]);
    expect(r.metadata.error).toMatch(/rate limit/i);
    expect((await provider.getHealth()).healthy).toBe(false);
  });
});

describe('NVD CVE provider', () => {
  it('keeps CVEs whose CPE or description names the package and drops keyword noise', async () => {
    http.on('services.nvd.nist.gov', 'nvd-node-forge');
    const provider = createCVEProvider({ enabled: true, timeout: 1000 });

    const r = await provider.query({ packageName: 'node-forge', version: '1.2.0' });
    expect(http.calls[0]?.url).toContain('keywordSearch=node-forge');
    // CVE-2019-99999 ("Total Commander ... forge file names") is a substring hit and must go.
    expect(r.results.map((x) => x.vulnerabilityId)).toEqual(['CVE-2022-24771']);
    expect(r.results[0]).toMatchObject({ severity: 'CRITICAL', source: 'cve' });
    expect(r.results[0]?.cvss?.baseScore).toBe(9.8);
    expect(r.results[0]?.references).toContain('https://nvd.nist.gov/vuln/detail/CVE-2022-24771');
  });

  it('returns an empty result with the error recorded when NVD rate-limits', async () => {
    http.on('services.nvd.nist.gov', 'http-429');
    const provider = createCVEProvider({ enabled: true, timeout: 1000 });
    const r = await provider.query({ packageName: 'lodash' });
    expect(r.results).toEqual([]);
    expect(r.metadata.error).toMatch(/429/);
  });
});

describe('Snyk provider', () => {
  it('is unavailable without an API key and never calls the network', async () => {
    const provider = createSnykProvider({ enabled: true });
    expect(provider.isAvailable()).toBe(false);
    const r = await provider.query({ packageName: 'lodash' });
    expect(r.results).toEqual([]);
    expect(http.calls).toHaveLength(0);
  });

  it('sends the token and maps vulnerabilities with semver filtering', async () => {
    http.on('api.snyk.io/v1/vuln/npm/lodash', 'snyk-lodash');
    const provider = createSnykProvider({ enabled: true, apiKey: 'snyk-token', timeout: 1000 });

    const vulnerable = await provider.query({ packageName: 'lodash', version: '4.17.20' });
    expect(vulnerable.results).toHaveLength(1);
    expect(vulnerable.results[0]).toMatchObject({
      vulnerabilityId: 'CVE-2020-28500',
      severity: 'MEDIUM',
      source: 'snyk',
    });

    const fixed = await provider.query({ packageName: 'lodash', version: '4.17.21' });
    expect(fixed.results).toHaveLength(0);
  });
});

describe('providerFetch', () => {
  it('passes the URL and options through to fetchWithTimeout', async () => {
    http.on('example.test', { status: 200, body: { ok: true } });
    const res = await providerFetch('https://example.test/x', { timeout: 123 });
    expect(res.ok).toBe(true);
    expect(await res.json()).toEqual({ ok: true });
    expect(http.calls).toEqual([{ url: 'https://example.test/x', method: 'GET', body: undefined }]);
  });
});
