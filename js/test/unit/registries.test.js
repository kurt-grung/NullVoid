/**
 * Unit tests for multi-registry and registry health
 */

const https = require('https');

jest.mock('https');

const {
  getRegistryOrder,
  getRegistryBase,
  checkRegistryHealth,
  checkAllRegistriesHealth
} = require('../../lib/registries');

describe('Registries', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getRegistryOrder', () => {
    test('should return default registry order including npm', () => {
      const order = getRegistryOrder();
      expect(Array.isArray(order)).toBe(true);
      expect(order).toContain('npm');
    });
  });

  describe('getRegistryBase', () => {
    test('should resolve npm registry URL', () => {
      const base = getRegistryBase('npm');
      expect(base).not.toBeNull();
      expect(base.url).toMatch(/registry\.npmjs\.org/);
    });

    test('should resolve github registry URL', () => {
      const base = getRegistryBase('github');
      expect(base).not.toBeNull();
      expect(base.url).toMatch(/npm\.pkg\.github\.com/);
    });

    test('should return null for unknown registry', () => {
      const base = getRegistryBase('unknown-registry-xyz');
      expect(base).toBeNull();
    });
  });

  describe('checkRegistryHealth', () => {
    test('should return ok and latency for successful response', async () => {
      https.get.mockImplementation((url, opts, cb) => {
        const res = { statusCode: 200, on: (e, fn) => e === 'data' && setImmediate(fn) };
        setImmediate(() => cb(res));
        res.on('end', () => {});
        return { on: () => {}, setTimeout: () => {} };
      });
      const result = await checkRegistryHealth('npm');
      expect(result.registryName).toBe('npm');
      expect(result.ok).toBe(true);
      expect(typeof result.latencyMs).toBe('number');
      expect(result.statusCode).toBe(200);
    });

    test('should return ok false for 5xx response', async () => {
      https.get.mockImplementation((url, opts, cb) => {
        const res = { statusCode: 503, on: (e, fn) => e === 'data' && setImmediate(fn) };
        setImmediate(() => cb(res));
        return { on: () => {}, setTimeout: () => {} };
      });
      const result = await checkRegistryHealth('npm');
      expect(result.ok).toBe(false);
      expect(result.statusCode).toBe(503);
    });

    test('should return ok false for unknown registry', async () => {
      const result = await checkRegistryHealth('unknown-xyz');
      expect(result.ok).toBe(false);
      expect(result.error).toBe('Unknown registry');
    });
  });

  describe('checkAllRegistriesHealth', () => {
    test('should return array of health results', async () => {
      https.get.mockImplementation((url, opts, cb) => {
        const res = { statusCode: 200, on: (e, fn) => e === 'data' && setImmediate(fn) };
        setImmediate(() => cb(res));
        return { on: () => {}, setTimeout: () => {} };
      });
      const results = await checkAllRegistriesHealth();
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThanOrEqual(1);
      results.forEach((r) => {
        expect(r).toHaveProperty('registryName');
        expect(r).toHaveProperty('ok');
        expect(r).toHaveProperty('latencyMs');
      });
    });
  });
});
