/**
 * Connection Pool Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { ConnectionPool, getConnectionPool } from '../../src/lib/network/connectionPool';

describe('Connection Pool', () => {
  let pool: ConnectionPool;

  beforeEach(() => {
    pool = new ConnectionPool();
  });

  it('should create pool instance', () => {
    expect(pool).toBeDefined();
  });

  it('should get agent for HTTP URL', () => {
    const agent = pool.getAgent('http://example.com');
    expect(agent).toBeDefined();
  });

  it('should get agent for HTTPS URL', () => {
    const agent = pool.getAgent('https://example.com');
    expect(agent).toBeDefined();
  });

  it('should track connections', () => {
    pool.trackConnection('http://example.com', true);
    pool.trackConnection('https://example.com', false);
    
    const stats = pool.getStats();
    expect(stats).toBeDefined();
    expect(typeof stats.activeConnections).toBe('number');
    expect(typeof stats.idleConnections).toBe('number');
  });

  it('should record errors', () => {
    pool.recordError();
    const stats = pool.getStats();
    expect(stats.errors).toBe(1);
  });

  it('should record timeouts', () => {
    pool.recordTimeout();
    const stats = pool.getStats();
    expect(stats.timeouts).toBe(1);
  });

  it('should get statistics', () => {
    const stats = pool.getStats();
    
    expect(stats).toBeDefined();
    expect(typeof stats.activeConnections).toBe('number');
    expect(typeof stats.idleConnections).toBe('number');
    expect(typeof stats.totalConnections).toBe('number');
    expect(stats.connectionsPerDomain).toBeDefined();
    expect(typeof stats.errors).toBe('number');
    expect(typeof stats.timeouts).toBe('number');
  });

  it('should close pool', () => {
    pool.close();
    const stats = pool.getStats();
    expect(stats.totalConnections).toBe(0);
  });

  it('should get global pool instance', () => {
    const globalPool = getConnectionPool();
    expect(globalPool).toBeDefined();
    expect(globalPool).toBeInstanceOf(ConnectionPool);
  });
});

