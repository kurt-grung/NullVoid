/**
 * Unit tests for multi-registry and registry health
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import https from 'https';
import {
  getRegistryOrder,
  checkRegistryHealth,
  checkAllRegistriesHealth,
} from '../../src/lib/registries';

jest.mock('https');

describe('Registries', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getRegistryOrder', () => {
    it('should return default registry order including npm', () => {
      const order = getRegistryOrder();
      expect(Array.isArray(order)).toBe(true);
      expect(order).toContain('npm');
    });

    it('should include yarn and github in default order', () => {
      const order = getRegistryOrder();
      expect(order).toContain('yarn');
      expect(order).toContain('github');
    });
  });

  describe('checkRegistryHealth', () => {
    it('should return ok and latency for successful response', async () => {
      (https.get as jest.Mock).mockImplementation(
        (_url: string, _opts: unknown, cb: (res: unknown) => void) => {
          const res = {
            statusCode: 200,
            on: () => {},
          };
          setImmediate(() => cb(res));
          return { on: () => {}, setTimeout: () => {} };
        }
      );
      const result = await checkRegistryHealth('npm');
      expect(result.registryName).toBe('npm');
      expect(result.ok).toBe(true);
      expect(typeof result.latencyMs).toBe('number');
      expect(result.statusCode).toBe(200);
    });

    it('should return ok false for 5xx response', async () => {
      (https.get as jest.Mock).mockImplementation(
        (_url: string, _opts: unknown, cb: (res: unknown) => void) => {
          const res = {
            statusCode: 503,
            on: () => {},
          };
          setImmediate(() => cb(res));
          return { on: () => {}, setTimeout: () => {} };
        }
      );
      const result = await checkRegistryHealth('npm');
      expect(result.ok).toBe(false);
      expect(result.statusCode).toBe(503);
    });

    it('should return ok false for unknown registry', async () => {
      const result = await checkRegistryHealth('unknown-xyz');
      expect(result.ok).toBe(false);
      expect(result.error).toBe('Unknown registry');
    });
  });

  describe('checkAllRegistriesHealth', () => {
    it('should return array of health results', async () => {
      (https.get as jest.Mock).mockImplementation(
        (_url: string, _opts: unknown, cb: (res: unknown) => void) => {
          const res = {
            statusCode: 200,
            on: () => {},
          };
          setImmediate(() => cb(res));
          return { on: () => {}, setTimeout: () => {} };
        }
      );
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
