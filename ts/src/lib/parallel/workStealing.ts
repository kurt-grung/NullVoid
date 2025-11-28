/**
 * Work Stealing Algorithm
 * Advanced task distribution for load balancing
 */

import type { WorkerJob } from '../parallel';
import { logger } from '../logger';

/**
 * Work queue with stealing support
 */
export class WorkStealingQueue<T> {
  private queues: Array<Array<WorkerJob<T>>> = [];
  private queueLocks: Array<boolean> = [];
  private totalJobs = 0;
  
  constructor(numWorkers: number) {
    // Create one queue per worker
    for (let i = 0; i < numWorkers; i++) {
      this.queues.push([]);
      this.queueLocks.push(false);
    }
  }
  
  /**
   * Push job to worker's queue
   */
  push(workerId: number, job: WorkerJob<T>): void {
    if (workerId < 0 || workerId >= this.queues.length) {
      logger.warn(`Invalid worker ID ${workerId}, using worker 0`);
      workerId = 0;
    }
    
    this.queues[workerId]!.push(job);
    this.totalJobs++;
  }
  
  /**
   * Pop job from worker's queue (LIFO for better cache locality)
   */
  pop(workerId: number): WorkerJob<T> | null {
    if (workerId < 0 || workerId >= this.queues.length) {
      return null;
    }
    
    const queue = this.queues[workerId]!;
    if (queue.length === 0) {
      return null;
    }
    
    const job = queue.pop()!;
    this.totalJobs--;
    return job;
  }
  
  /**
   * Steal job from another worker's queue (FIFO to reduce contention)
   */
  steal(workerId: number): WorkerJob<T> | null {
    if (workerId < 0 || workerId >= this.queues.length) {
      return null;
    }
    
    // Try to steal from other workers
    const numWorkers = this.queues.length;
    for (let i = 1; i < numWorkers; i++) {
      const targetWorkerId = (workerId + i) % numWorkers;
      const targetQueue = this.queues[targetWorkerId]!;
      
      // Skip if queue is locked or empty
      if (this.queueLocks[targetWorkerId] || targetQueue.length === 0) {
        continue;
      }
      
      // Try to steal from the front (FIFO)
      const job = targetQueue.shift();
      if (job) {
        this.totalJobs--;
        logger.debug(`Worker ${workerId} stole job from worker ${targetWorkerId}`);
        return job;
      }
    }
    
    return null;
  }
  
  /**
   * Get job for worker (tries own queue first, then steals)
   */
  getJob(workerId: number): WorkerJob<T> | null {
    // Try own queue first
    const ownJob = this.pop(workerId);
    if (ownJob) {
      return ownJob;
    }
    
    // Try to steal from others
    return this.steal(workerId);
  }
  
  /**
   * Check if queue is empty
   */
  isEmpty(): boolean {
    return this.totalJobs === 0;
  }
  
  /**
   * Get total number of jobs
   */
  size(): number {
    return this.totalJobs;
  }
  
  /**
   * Get queue size for specific worker
   */
  queueSize(workerId: number): number {
    if (workerId < 0 || workerId >= this.queues.length) {
      return 0;
    }
    return this.queues[workerId]!.length;
  }
  
  /**
   * Lock queue (prevent stealing)
   */
  lockQueue(workerId: number): void {
    if (workerId >= 0 && workerId < this.queueLocks.length) {
      this.queueLocks[workerId] = true;
    }
  }
  
  /**
   * Unlock queue (allow stealing)
   */
  unlockQueue(workerId: number): void {
    if (workerId >= 0 && workerId < this.queueLocks.length) {
      this.queueLocks[workerId] = false;
    }
  }
  
  /**
   * Get queue statistics
   */
  getStats(): {
    totalJobs: number;
    jobsPerQueue: number[];
    averageQueueSize: number;
    maxQueueSize: number;
    minQueueSize: number;
  } {
    const jobsPerQueue = this.queues.map(q => q.length);
    const total = jobsPerQueue.reduce((sum, size) => sum + size, 0);
    const average = jobsPerQueue.length > 0 ? total / jobsPerQueue.length : 0;
    const max = Math.max(...jobsPerQueue, 0);
    const min = Math.min(...jobsPerQueue, 0);
    
    return {
      totalJobs: this.totalJobs,
      jobsPerQueue,
      averageQueueSize: average,
      maxQueueSize: max,
      minQueueSize: min
    };
  }
  
  /**
   * Clear all queues
   */
  clear(): void {
    for (const queue of this.queues) {
      queue.length = 0;
    }
    this.totalJobs = 0;
  }
}

/**
 * Work stealing scheduler
 */
export class WorkStealingScheduler<T> {
  private queue: WorkStealingQueue<T>;
  private workerStats: Array<{
    jobsProcessed: number;
    jobsStolen: number;
    idleTime: number;
    busyTime: number;
  }> = [];
  
  constructor(numWorkers: number) {
    this.queue = new WorkStealingQueue<T>(numWorkers);
    
    // Initialize worker stats
    for (let i = 0; i < numWorkers; i++) {
      this.workerStats.push({
        jobsProcessed: 0,
        jobsStolen: 0,
        idleTime: 0,
        busyTime: 0
      });
    }
  }
  
  /**
   * Add job to queue
   */
  addJob(workerId: number, job: WorkerJob<T>): void {
    this.queue.push(workerId, job);
  }
  
  /**
   * Get next job for worker
   */
  getNextJob(workerId: number): WorkerJob<T> | null {
    const job = this.queue.getJob(workerId);
    
    if (job) {
      this.workerStats[workerId]!.jobsProcessed++;
      
      // Check if job was stolen (heuristic: if it came from steal)
      // In a real implementation, we'd track this more precisely
      if (this.queue.queueSize(workerId) === 0) {
        this.workerStats[workerId]!.jobsStolen++;
      }
    } else {
      // Worker is idle
      this.workerStats[workerId]!.idleTime++;
    }
    
    return job;
  }
  
  /**
   * Get scheduler statistics
   */
  getStats(): {
    queueStats: ReturnType<WorkStealingQueue<T>['getStats']>;
    workerStats: Array<{
      workerId: number;
      jobsProcessed: number;
      jobsStolen: number;
      idleTime: number;
      busyTime: number;
      utilization: number;
    }>;
    overallUtilization: number;
  } {
    const queueStats = this.queue.getStats();
    
    const workerStatsWithUtil = this.workerStats.map((stats, workerId) => {
      const totalTime = stats.idleTime + stats.busyTime;
      const utilization = totalTime > 0 ? stats.busyTime / totalTime : 0;
      
      return {
        workerId,
        ...stats,
        utilization
      };
    });
    
    const overallUtilization = workerStatsWithUtil.length > 0
      ? workerStatsWithUtil.reduce((sum, stats) => sum + stats.utilization, 0) / workerStatsWithUtil.length
      : 0;
    
    return {
      queueStats,
      workerStats: workerStatsWithUtil,
      overallUtilization
    };
  }
  
  /**
   * Check if scheduler is idle
   */
  isIdle(): boolean {
    return this.queue.isEmpty();
  }
  
  /**
   * Clear scheduler
   */
  clear(): void {
    this.queue.clear();
    for (const stats of this.workerStats) {
      stats.jobsProcessed = 0;
      stats.jobsStolen = 0;
      stats.idleTime = 0;
      stats.busyTime = 0;
    }
  }
}

/**
 * Create work stealing scheduler
 */
export function createWorkStealingScheduler<T>(numWorkers: number): WorkStealingScheduler<T> {
  return new WorkStealingScheduler<T>(numWorkers);
}

