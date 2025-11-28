/**
 * HTTP Connection Pooling
 * Reuses HTTP connections for better performance
 */

import type {
  ConnectionPoolConfig,
  ConnectionPoolStats,
  HTTPConnection
} from '../../types/network-types';
import { NETWORK_OPTIMIZATION_CONFIG } from '../config';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';

/**
 * HTTP connection pool manager
 */
export class ConnectionPool {
  private config: ConnectionPoolConfig;
  private connections: Map<string, HTTPConnection[]> = new Map();
  private agents: Map<string, http.Agent | https.Agent> = new Map();
  private stats: ConnectionPoolStats;
  private cleanupTimer: ReturnType<typeof setTimeout> | null = null;
  
  constructor(config?: Partial<ConnectionPoolConfig>) {
    this.config = {
      ...NETWORK_OPTIMIZATION_CONFIG.CONNECTION_POOL,
      ...config
    };
    
    this.stats = {
      activeConnections: 0,
      idleConnections: 0,
      totalConnections: 0,
      connectionsPerDomain: {},
      errors: 0,
      timeouts: 0
    };
    
    if (this.config.enabled) {
      this.startCleanup();
    }
  }
  
  /**
   * Get or create HTTP agent for domain
   */
  getAgent(url: string): http.Agent | https.Agent {
    if (!this.config.enabled) {
      // Return default agent without pooling
      return url.startsWith('https:') ? new https.Agent() : new http.Agent();
    }
    
    const parsedUrl = new URL(url);
    const domain = parsedUrl.origin;
    
    // Return cached agent if exists
    if (this.agents.has(domain)) {
      return this.agents.get(domain)!;
    }
    
    const isHttps = parsedUrl.protocol === 'https:';
    
    // Create agent with keep-alive
    const agentOptions = {
      keepAlive: true,
      keepAliveMsecs: this.config.keepAliveTimeout,
      maxSockets: this.config.maxConnectionsPerDomain,
      maxFreeSockets: this.config.maxConnectionsPerDomain,
      timeout: this.config.connectTimeout
    };
    
    const agent = isHttps 
      ? new https.Agent(agentOptions)
      : new http.Agent(agentOptions);
    
    // Cache agent for reuse
    this.agents.set(domain, agent);
    
    return agent;
  }
  
  /**
   * Track connection usage
   */
  trackConnection(url: string, active: boolean): void {
    if (!this.config.enabled) {
      return;
    }
    
    const parsedUrl = new URL(url);
    const domain = parsedUrl.hostname;
    
    if (!this.connections.has(domain)) {
      this.connections.set(domain, []);
    }
    
    const domainConnections = this.connections.get(domain)!;
    
    // Find or create connection entry
    let connection = domainConnections.find(c => c.active === active);
    if (!connection) {
      connection = {
        id: `${domain}-${Date.now()}-${Math.random()}`,
        domain,
        createdAt: Date.now(),
        lastUsed: Date.now(),
        requestCount: 0,
        active
      };
      domainConnections.push(connection);
      this.stats.totalConnections++;
    }
    
    connection.lastUsed = Date.now();
    connection.requestCount++;
    connection.active = active;
    
    // Update stats
    this.updateStats();
  }
  
  /**
   * Record connection error
   */
  recordError(): void {
    this.stats.errors++;
  }
  
  /**
   * Record connection timeout
   */
  recordTimeout(): void {
    this.stats.timeouts++;
  }
  
  /**
   * Get connection pool statistics
   */
  getStats(): ConnectionPoolStats {
    this.updateStats();
    return { ...this.stats };
  }
  
  /**
   * Update statistics
   */
  private updateStats(): void {
    let activeCount = 0;
    let idleCount = 0;
    const perDomain: Record<string, number> = {};
    
    for (const [domain, connections] of this.connections.entries()) {
      const domainActive = connections.filter(c => c.active).length;
      const domainIdle = connections.filter(c => !c.active).length;
      
      perDomain[domain] = domainActive + domainIdle;
      activeCount += domainActive;
      idleCount += domainIdle;
    }
    
    this.stats.activeConnections = activeCount;
    this.stats.idleConnections = idleCount;
    this.stats.connectionsPerDomain = perDomain;
  }
  
  /**
   * Start cleanup timer
   */
  private startCleanup(): void {
    if (this.cleanupTimer) {
      return;
    }
    
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, this.config.idleTimeout);
    
    // Don't keep process alive
    if (this.cleanupTimer && this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }
  
  /**
   * Cleanup idle connections
   */
  private cleanup(): void {
    const now = Date.now();
    const maxIdleTime = this.config.idleTimeout;
    
    for (const [domain, connections] of this.connections.entries()) {
      const activeConnections = connections.filter(c => {
        if (!c.active && (now - c.lastUsed) > maxIdleTime) {
          // Connection idle too long, remove it
          return false;
        }
        return true;
      });
      
      if (activeConnections.length === 0) {
        this.connections.delete(domain);
      } else {
        this.connections.set(domain, activeConnections);
      }
    }
    
    this.updateStats();
  }
  
  /**
   * Close all connections
   */
  close(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    
    // Destroy all agents
    for (const agent of this.agents.values()) {
      agent.destroy();
    }
    
    this.connections.clear();
    this.agents.clear();
    this.stats = {
      activeConnections: 0,
      idleConnections: 0,
      totalConnections: 0,
      connectionsPerDomain: {},
      errors: 0,
      timeouts: 0
    };
  }
}

/**
 * Global connection pool instance
 */
let globalConnectionPool: ConnectionPool | null = null;

/**
 * Get or create global connection pool
 */
export function getConnectionPool(config?: Partial<ConnectionPoolConfig>): ConnectionPool {
  if (!globalConnectionPool) {
    globalConnectionPool = new ConnectionPool(config);
  }
  return globalConnectionPool;
}

