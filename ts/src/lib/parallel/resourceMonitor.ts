/**
 * Resource Monitoring for Dynamic Worker Scaling
 * Monitors CPU, memory, network I/O and provides recommendations
 */

import * as os from 'os';

/**
 * System resource metrics
 */
export interface SystemMetrics {
  /** CPU usage percentage (0-100) */
  cpuUsage: number;
  /** Memory usage percentage (0-100) */
  memoryUsage: number;
  /** System load average (1 minute) */
  loadAverage: number;
  /** Available memory in bytes */
  availableMemory: number;
  /** Total memory in bytes */
  totalMemory: number;
  /** Number of CPU cores */
  cpuCores: number;
  /** Network I/O (simplified - would need more complex monitoring) */
  networkLatency?: number;
}

/**
 * Resource monitoring recommendations
 */
export interface ResourceRecommendations {
  /** Recommended worker count */
  recommendedWorkers: number;
  /** Recommended chunk size */
  recommendedChunkSize: number;
  /** Whether to scale up */
  scaleUp: boolean;
  /** Whether to scale down */
  scaleDown: boolean;
  /** Reason for recommendation */
  reason: string;
}

/**
 * Resource monitor implementation
 */
export class ResourceMonitor {
  private previousCpuUsage: number[] = [];
  private monitoringInterval: ReturnType<typeof setInterval> | null = null;
  private currentMetrics: SystemMetrics | null = null;
  
  /**
   * Get current system metrics
   */
  getMetrics(): SystemMetrics {
    const cpus = os.cpus();
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const usedMemory = totalMemory - freeMemory;
    const loadAvg = os.loadavg()[0] || 0;
    
    // Calculate CPU usage
    let cpuUsage = 0;
    if (this.previousCpuUsage.length > 0) {
      const currentCpuTotals = cpus.map(cpu => {
        return Object.values(cpu.times).reduce((a, b) => a + b, 0);
      });
      
      const currentCpuIdles = cpus.map(cpu => cpu.times.idle);
      
      let totalDiff = 0;
      let idleDiff = 0;
      
      for (let i = 0; i < Math.min(currentCpuTotals.length, this.previousCpuUsage.length); i++) {
        const prevTotal = this.previousCpuUsage[i];
        if (prevTotal !== undefined) {
          totalDiff += (currentCpuTotals[i] || 0) - prevTotal;
          idleDiff += (currentCpuIdles[i] || 0) - (this.previousCpuUsage[i] || 0);
        }
      }
      
      if (totalDiff > 0) {
        cpuUsage = ((totalDiff - idleDiff) / totalDiff) * 100;
      }
      
      // Store current CPU totals for next calculation
      this.previousCpuUsage = currentCpuTotals;
    } else {
      // First call - initialize
      this.previousCpuUsage = cpus.map(cpu => {
        return Object.values(cpu.times).reduce((a, b) => a + b, 0);
      });
      cpuUsage = 0;
    }
    
    const metrics: SystemMetrics = {
      cpuUsage: Math.min(100, Math.max(0, cpuUsage)),
      memoryUsage: (usedMemory / totalMemory) * 100,
      loadAverage: loadAvg,
      availableMemory: freeMemory,
      totalMemory,
      cpuCores: cpus.length
    };
    
    this.currentMetrics = metrics;
    return metrics;
  }
  
  /**
   * Get resource recommendations
   */
  getRecommendations(
    currentWorkers: number,
    queueDepth: number,
    currentChunkSize: number
  ): ResourceRecommendations {
    const metrics = this.getMetrics();
    
    // Base recommendation on current workers
    let recommendedWorkers = currentWorkers;
    let scaleUp = false;
    let scaleDown = false;
    let reason = 'System stable';
    
    // Check if we should scale up
    if (queueDepth > currentWorkers * 2 && 
        metrics.cpuUsage < 70 && 
        metrics.memoryUsage < 80 &&
        metrics.loadAverage < metrics.cpuCores * 0.7) {
      // System has capacity and queue is backing up
      recommendedWorkers = Math.min(
        currentWorkers + 1,
        metrics.cpuCores,
        Math.floor(metrics.availableMemory / (100 * 1024 * 1024)) // ~100MB per worker
      );
      scaleUp = recommendedWorkers > currentWorkers;
      if (scaleUp) {
        reason = `Queue depth (${queueDepth}) high, system has capacity`;
      }
    }
    
    // Check if we should scale down
    if (queueDepth < currentWorkers &&
        (metrics.cpuUsage > 85 || 
         metrics.memoryUsage > 90 ||
         metrics.loadAverage > metrics.cpuCores * 0.9)) {
      // System under stress, reduce workers
      recommendedWorkers = Math.max(
        1,
        Math.floor(currentWorkers * 0.7)
      );
      scaleDown = recommendedWorkers < currentWorkers;
      if (scaleDown) {
        reason = `High system load (CPU: ${metrics.cpuUsage.toFixed(1)}%, Memory: ${metrics.memoryUsage.toFixed(1)}%)`;
      }
    }
    
    // Adjust chunk size based on system load
    let recommendedChunkSize = currentChunkSize;
    if (metrics.cpuUsage > 80) {
      // Reduce chunk size to allow more frequent load balancing
      recommendedChunkSize = Math.max(1, Math.floor(currentChunkSize * 0.8));
    } else if (metrics.cpuUsage < 50 && queueDepth > 0) {
      // Increase chunk size for better throughput
      recommendedChunkSize = Math.min(50, Math.floor(currentChunkSize * 1.2));
    }
    
    return {
      recommendedWorkers,
      recommendedChunkSize,
      scaleUp,
      scaleDown,
      reason
    };
  }
  
  /**
   * Start continuous monitoring
   */
  startMonitoring(intervalMs: number = 5000): void {
    if (this.monitoringInterval) {
      return;
    }
    
    this.monitoringInterval = setInterval(() => {
      this.getMetrics();
    }, intervalMs);
    
    // Don't keep process alive
    if (this.monitoringInterval.unref) {
      this.monitoringInterval.unref();
    }
  }
  
  /**
   * Stop monitoring
   */
  stopMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
  }
  
  /**
   * Get current metrics (cached)
   */
  getCurrentMetrics(): SystemMetrics | null {
    return this.currentMetrics;
  }
}

/**
 * Global resource monitor instance
 */
let globalResourceMonitor: ResourceMonitor | null = null;

/**
 * Get or create global resource monitor
 */
export function getResourceMonitor(): ResourceMonitor {
  if (!globalResourceMonitor) {
    globalResourceMonitor = new ResourceMonitor();
  }
  return globalResourceMonitor;
}

