/**
 * Work Stealing Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { WorkStealingQueue, WorkStealingScheduler, createWorkStealingScheduler } from '../../src/lib/parallel/workStealing';
import type { WorkerJob } from '../../src/lib/parallel';

describe('Work Stealing', () => {
  describe('WorkStealingQueue', () => {
    let queue: WorkStealingQueue<string>;

    beforeEach(() => {
      queue = new WorkStealingQueue<string>(4);
    });

    it('should create queue instance', () => {
      expect(queue).toBeDefined();
    });

    it('should push and pop jobs', () => {
      const job: WorkerJob<string> = {
        id: 'test-1',
        data: 'test-data',
        priority: 1
      };
      
      queue.push(0, job);
      const popped = queue.pop(0);
      
      expect(popped).toBeDefined();
      expect(popped?.id).toBe('test-1');
      expect(popped?.data).toBe('test-data');
    });

    it('should steal jobs from other workers', () => {
      const job1: WorkerJob<string> = { id: 'job-1', data: 'data1' };
      const job2: WorkerJob<string> = { id: 'job-2', data: 'data2' };
      
      queue.push(1, job1);
      queue.push(1, job2);
      
      const stolen = queue.steal(0);
      
      expect(stolen).toBeDefined();
      expect(stolen?.id).toBe('job-1');
    });

    it('should check if queue is empty', () => {
      expect(queue.isEmpty()).toBe(true);
      
      const job: WorkerJob<string> = { id: 'test', data: 'data' };
      queue.push(0, job);
      
      expect(queue.isEmpty()).toBe(false);
    });

    it('should get queue size', () => {
      expect(queue.size()).toBe(0);
      
      const job: WorkerJob<string> = { id: 'test', data: 'data' };
      queue.push(0, job);
      
      expect(queue.size()).toBe(1);
    });

    it('should get queue statistics', () => {
      const stats = queue.getStats();
      
      expect(stats).toBeDefined();
      expect(typeof stats.totalJobs).toBe('number');
      expect(Array.isArray(stats.jobsPerQueue)).toBe(true);
      expect(typeof stats.averageQueueSize).toBe('number');
    });
  });

  describe('WorkStealingScheduler', () => {
    let scheduler: WorkStealingScheduler<string>;

    beforeEach(() => {
      scheduler = new WorkStealingScheduler<string>(4);
    });

    it('should create scheduler instance', () => {
      expect(scheduler).toBeDefined();
    });

    it('should add and get jobs', () => {
      const job: WorkerJob<string> = {
        id: 'test-1',
        data: 'test-data',
        priority: 1
      };
      
      scheduler.addJob(0, job);
      const nextJob = scheduler.getNextJob(0);
      
      expect(nextJob).toBeDefined();
      expect(nextJob?.id).toBe('test-1');
    });

    it('should check if scheduler is idle', () => {
      expect(scheduler.isIdle()).toBe(true);
      
      const job: WorkerJob<string> = { id: 'test', data: 'data' };
      scheduler.addJob(0, job);
      
      expect(scheduler.isIdle()).toBe(false);
    });

    it('should get scheduler statistics', () => {
      const stats = scheduler.getStats();
      
      expect(stats).toBeDefined();
      expect(stats.queueStats).toBeDefined();
      expect(Array.isArray(stats.workerStats)).toBe(true);
      expect(typeof stats.overallUtilization).toBe('number');
    });
  });

  it('should create scheduler via factory', () => {
    const scheduler = createWorkStealingScheduler<string>(4);
    expect(scheduler).toBeDefined();
    expect(scheduler).toBeInstanceOf(WorkStealingScheduler);
  });
});

