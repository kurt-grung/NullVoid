import { Threat, createThreat } from '../types/core';
import { Worker } from 'worker_threads';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { DETECTION_PATTERNS } from './config';

export interface PackageInfo {
  name: string;
  path: string;
  version?: string;
}

export interface WorkerJob<T> {
  id: string;
  data: T;
  priority?: number;
}

export interface WorkerPoolOptions {
  maxWorkers?: number;
  taskTimeout?: number;
  retryAttempts?: number;
  queueSize?: number;
}

export interface WorkerPoolStats {
  activeWorkers: number;
  queuedJobs: number;
  completedJobs: number;
  failedJobs: number;
  averageExecutionTime: number;
}

export interface PackageScanResult {
  packageName: string;
  threats: Threat[];
  executionTime: number;
  success: boolean;
  error?: string;
}

export interface WorkerError {
  code: string;
  message: string;
  stack?: string;
}

export interface WorkerMessage<R> {
  type: 'result' | 'error' | 'progress';
  jobId: string;
  data?: R;
  error?: WorkerError;
  progress?: number;
}

export interface ParallelScanMetrics {
  totalPackages: number;
  processedPackages: number;
  threatsFound: number;
  averageProcessingTime: number;
  totalProcessingTime: number;
  workerUtilization: number;
}

/**
 * Get optimal number of workers based on system resources
 * Enhanced with dynamic resource monitoring
 */
export function getOptimalWorkerCount(): number {
  const cpuCount = os.cpus().length;
  const totalMemory = os.totalmem();
  const loadAverage = os.loadavg()[0] || 0;

  // Base worker count on CPU cores, but consider system load and memory
  let workerCount = Math.max(1, Math.floor(cpuCount * 0.8));

  // Reduce workers if system is under high load
  if (loadAverage > cpuCount * 0.8) {
    workerCount = Math.max(1, Math.floor(workerCount * 0.6));
  }

  // Limit workers based on available memory (assume ~100MB per worker)
  const memoryLimitedWorkers = Math.floor(totalMemory / (100 * 1024 * 1024));
  workerCount = Math.min(workerCount, memoryLimitedWorkers);

  // Cap at reasonable maximum
  return Math.min(workerCount, 8);
}

/**
 * Get dynamic optimal worker count based on current system state
 * Uses resource monitoring for real-time adjustments
 */
export function getDynamicOptimalWorkerCount(currentWorkers: number, queueDepth: number): number {
  try {
    // Import resource monitor
    const { getResourceMonitor } = require('./parallel/resourceMonitor');
    const monitor = getResourceMonitor();
    const recommendations = monitor.getRecommendations(
      currentWorkers,
      queueDepth,
      10 // Default chunk size
    );

    return recommendations.recommendedWorkers;
  } catch {
    // Fallback to static calculation if resource monitor not available
    return getOptimalWorkerCount();
  }
}

/**
 * Get optimal chunk size for parallel processing
 */
export function getOptimalChunkSize(totalItems: number, workerCount: number): number {
  if (totalItems <= workerCount) {
    return 1;
  }

  // Aim for 2-4 chunks per worker to allow for load balancing
  const targetChunksPerWorker = 3;
  const totalChunks = workerCount * targetChunksPerWorker;
  const chunkSize = Math.ceil(totalItems / totalChunks);

  // Ensure minimum and maximum chunk sizes
  return Math.max(1, Math.min(chunkSize, 50));
}

/**
 * Chunk packages into smaller groups for parallel processing
 */
export function chunkPackages<T>(packages: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];

  for (let i = 0; i < packages.length; i += chunkSize) {
    chunks.push(packages.slice(i, i + chunkSize));
  }

  return chunks;
}

/**
 * Secure parallel scan results aggregator
 */
export class SecureParallelScanResults {
  private results: Map<string, PackageScanResult> = new Map();
  private startTime: number = Date.now();
  public metrics: ParallelScanMetrics;

  constructor(totalPackages: number) {
    this.metrics = {
      totalPackages,
      processedPackages: 0,
      threatsFound: 0,
      averageProcessingTime: 0,
      totalProcessingTime: 0,
      workerUtilization: 0,
    };
  }

  addResult(result: PackageScanResult): void {
    this.results.set(result.packageName, result);
    this.updateMetrics(result);
  }

  private updateMetrics(result: PackageScanResult): void {
    this.metrics.processedPackages++;
    this.metrics.threatsFound += result.threats.length;
    this.metrics.totalProcessingTime += result.executionTime;
    this.metrics.averageProcessingTime =
      this.metrics.totalProcessingTime / this.metrics.processedPackages;

    // Calculate worker utilization (simplified)
    const elapsedTime = Date.now() - this.startTime;
    this.metrics.workerUtilization = (this.metrics.totalProcessingTime / elapsedTime) * 100;
  }

  getAllResults(): PackageScanResult[] {
    return Array.from(this.results.values());
  }

  getAllThreats(): Threat[] {
    const allThreats: Threat[] = [];
    for (const result of this.results.values()) {
      allThreats.push(...result.threats);
    }
    return allThreats;
  }

  getFailedPackages(): string[] {
    return Array.from(this.results.values())
      .filter((result) => !result.success)
      .map((result) => result.packageName);
  }

  getMetrics(): ParallelScanMetrics {
    return { ...this.metrics };
  }
}

/**
 * Worker Pool for managing parallel execution
 */
export class WorkerPool<T, R> {
  private workers: Worker[] = [];
  private jobQueue: Array<WorkerJob<T>> = [];
  private activeJobs: Map<
    string,
    {
      resolve: (value: R) => void;
      reject: (error: Error) => void;
      timeout?: ReturnType<typeof setTimeout>;
    }
  > = new Map();
  private stats: WorkerPoolStats;
  private options: Required<WorkerPoolOptions>;

  constructor(workerScript: string, options: WorkerPoolOptions = {}) {
    this.options = {
      maxWorkers: options.maxWorkers || getOptimalWorkerCount(),
      taskTimeout: options.taskTimeout || 30000,
      retryAttempts: options.retryAttempts || 2,
      queueSize: options.queueSize || 1000,
    };

    this.stats = {
      activeWorkers: 0,
      queuedJobs: 0,
      completedJobs: 0,
      failedJobs: 0,
      averageExecutionTime: 0,
    };

    this.initializeWorkers(workerScript);
  }

  private initializeWorkers(workerScript: string): void {
    for (let i = 0; i < this.options.maxWorkers; i++) {
      this.createWorker(workerScript);
    }
  }

  private createWorker(workerScript: string): void {
    const worker = new Worker(workerScript);

    worker.on('message', (message: WorkerMessage<R>) => {
      this.handleWorkerMessage(message);
    });

    worker.on('error', (error) => {
      this.handleWorkerError(error);
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        // Worker crashed, create a new one
        this.createWorker(workerScript);
      }
    });

    this.workers.push(worker);
    this.stats.activeWorkers++;
  }

  private handleWorkerMessage(message: WorkerMessage<R>): void {
    const job = this.activeJobs.get(message.jobId);
    if (!job) return;

    if (message.type === 'result') {
      if (job.timeout) clearTimeout(job.timeout);
      this.activeJobs.delete(message.jobId);
      this.stats.completedJobs++;
      job.resolve(message.data!);
      this.processNextJob();
    } else if (message.type === 'error') {
      if (job.timeout) clearTimeout(job.timeout);
      this.activeJobs.delete(message.jobId);
      this.stats.failedJobs++;
      job.reject(new Error(message.error?.message || 'Worker error'));
      this.processNextJob();
    }
  }

  private handleWorkerError(error: Error): void {
    // Handle worker errors
    console.error('Worker error:', error);
  }

  private processNextJob(): void {
    if (this.jobQueue.length === 0) return;

    const job = this.jobQueue.shift()!;
    this.stats.queuedJobs--;
    this.executeJob(job);
  }

  private executeJob(job: WorkerJob<T>): void {
    const availableWorker = this.workers.find(
      (worker) => !worker.threadId || this.activeJobs.size < this.options.maxWorkers
    );

    if (!availableWorker) {
      // No available workers, put job back in queue
      this.jobQueue.unshift(job);
      this.stats.queuedJobs++;
      return;
    }

    setTimeout(() => {
      const activeJob = this.activeJobs.get(job.id);
      if (activeJob) {
        this.activeJobs.delete(job.id);
        this.stats.failedJobs++;
        activeJob.reject(new Error('Job timeout'));
      }
    }, this.options.taskTimeout);

    availableWorker.postMessage({ jobId: job.id, data: job.data });
  }

  async execute(data: T): Promise<R> {
    return new Promise((resolve, reject) => {
      const jobId = `job_${Date.now()}_${Math.random()}`;
      const job: WorkerJob<T> = { id: jobId, data };

      if (this.jobQueue.length >= this.options.queueSize) {
        reject(new Error('Job queue is full'));
        return;
      }

      this.activeJobs.set(jobId, { resolve, reject });

      if (this.activeJobs.size <= this.options.maxWorkers) {
        this.executeJob(job);
      } else {
        this.jobQueue.push(job);
        this.stats.queuedJobs++;
      }
    });
  }

  getStats(): WorkerPoolStats {
    return { ...this.stats };
  }

  async terminate(): Promise<void> {
    const terminationPromises = this.workers.map((worker) => worker.terminate());
    await Promise.all(terminationPromises);
    this.workers = [];
    this.stats.activeWorkers = 0;
  }
}

/**
 * Scan packages in parallel
 */
export async function scanPackagesInParallel(
  packages: string[],
  options: { maxWorkers?: number; chunkSize?: number } = {}
): Promise<Threat[]> {
  if (packages.length === 0) {
    return [];
  }

  const workerCount = options.maxWorkers || getOptimalWorkerCount();
  const chunkSize = options.chunkSize || getOptimalChunkSize(packages.length, workerCount);
  const chunks = chunkPackages(packages, chunkSize);

  const results = new SecureParallelScanResults(packages.length);
  const threats: Threat[] = [];

  try {
    // Process chunks in parallel
    const chunkPromises = chunks.map(async (chunk, index) => {
      const startTime = Date.now();

      try {
        // Simulate package scanning (in real implementation, this would use actual scanning logic)
        const chunkThreats: Threat[] = [];

        for (const packageName of chunk) {
          // Simulate threat detection
          if (packageName.includes('malware') || packageName.includes('virus')) {
            chunkThreats.push(
              createThreat(
                'MALICIOUS_CODE',
                `Suspicious package detected: ${packageName}`,
                packageName,
                packageName,
                'HIGH',
                'Package name contains suspicious keywords',
                { packageName, confidence: 0.8 }
              )
            );
          }
        }

        const executionTime = Date.now() - startTime;

        // Add results for each package in chunk
        for (const packageName of chunk) {
          const packageThreats = chunkThreats.filter((t) => t.package === packageName);
          results.addResult({
            packageName,
            threats: packageThreats,
            executionTime: executionTime / chunk.length,
            success: true,
          });
        }

        return chunkThreats;
      } catch (error: unknown) {
        // Handle chunk processing error
        for (const packageName of chunk) {
          results.addResult({
            packageName,
            threats: [],
            executionTime: Date.now() - startTime,
            success: false,
            error: error instanceof Error ? error.message : String(error),
          });
        }

        return [
          createThreat(
            'PARALLEL_PROCESSING_ERROR',
            `Error processing package chunk ${index}: ${error instanceof Error ? error.message : String(error)}`,
            'parallel',
            'parallel',
            'MEDIUM',
            'Failed to process packages in parallel',
            {
              chunkIndex: index,
              error: error instanceof Error ? error.message : String(error),
              confidence: 0.9,
            }
          ),
        ];
      }
    });

    const chunkResults = await Promise.all(chunkPromises);

    // Flatten results
    for (const chunkThreats of chunkResults) {
      threats.push(...chunkThreats);
    }
  } catch (error: unknown) {
    threats.push(
      createThreat(
        'PARALLEL_PROCESSING_ERROR',
        `Parallel processing failed: ${error instanceof Error ? error.message : String(error)}`,
        'parallel',
        'parallel',
        'HIGH',
        'Critical failure in parallel processing system',
        { error: error instanceof Error ? error.message : String(error), confidence: 0.9 }
      )
    );
  }

  return threats;
}

/**
 * Analyze files in parallel
 */
export async function analyzeFilesInParallel(
  filePaths: string[],
  options: { maxWorkers?: number; chunkSize?: number } = {}
): Promise<Threat[]> {
  if (filePaths.length === 0) {
    return [];
  }

  const workerCount = options.maxWorkers || getOptimalWorkerCount();
  const chunkSize = options.chunkSize || getOptimalChunkSize(filePaths.length, workerCount);
  const chunks = chunkPackages(filePaths, chunkSize);

  const threats: Threat[] = [];

  try {
    // Process file chunks in parallel
    const chunkPromises = chunks.map(async (chunk) => {
      const chunkThreats: Threat[] = [];

      for (const filePath of chunk) {
        try {
          // Check if file exists and is readable
          if (!fs.existsSync(filePath)) {
            chunkThreats.push(
              createThreat(
                'FILE_ACCESS_ERROR',
                `File not found: ${filePath}`,
                filePath,
                path.basename(filePath),
                'LOW',
                'File could not be accessed for analysis',
                { filePath, confidence: 0.9 }
              )
            );
            continue;
          }

          const stats = fs.statSync(filePath);

          // Check for suspicious file sizes
          if (stats.size > 10 * 1024 * 1024) {
            // > 10MB
            chunkThreats.push(
              createThreat(
                'SUSPICIOUS_FILE_SIZE',
                `Unusually large file: ${filePath} (${Math.round(stats.size / 1024 / 1024)}MB)`,
                filePath,
                path.basename(filePath),
                'MEDIUM',
                'Large files may contain malicious content or be used for resource exhaustion',
                { filePath, fileSize: stats.size, confidence: 0.6 }
              )
            );
          }

          // Check file extension
          const ext = path.extname(filePath).toLowerCase();
          const suspiciousExtensions = DETECTION_PATTERNS.SUSPICIOUS_EXTENSIONS;

          if (suspiciousExtensions.includes(ext)) {
            chunkThreats.push(
              createThreat(
                'SUSPICIOUS_FILE_TYPE',
                `Potentially dangerous file type: ${filePath}`,
                filePath,
                path.basename(filePath),
                'MEDIUM',
                `File extension '${ext}' is commonly used for malicious files`,
                { filePath, extension: ext, confidence: 0.7 }
              )
            );
          }
        } catch (error: unknown) {
          chunkThreats.push(
            createThreat(
              'FILE_ANALYSIS_ERROR',
              `Error analyzing file ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
              filePath,
              path.basename(filePath),
              'LOW',
              'Failed to analyze file',
              {
                filePath,
                error: error instanceof Error ? error.message : String(error),
                confidence: 0.8,
              }
            )
          );
        }
      }

      return chunkThreats;
    });

    const chunkResults = await Promise.all(chunkPromises);

    // Flatten results
    for (const chunkThreats of chunkResults) {
      threats.push(...chunkThreats);
    }
  } catch (error: unknown) {
    threats.push(
      createThreat(
        'PARALLEL_FILE_ANALYSIS_ERROR',
        `Parallel file analysis failed: ${error instanceof Error ? error.message : String(error)}`,
        'parallel',
        'parallel',
        'HIGH',
        'Critical failure in parallel file analysis system',
        { error: error instanceof Error ? error.message : String(error), confidence: 0.9 }
      )
    );
  }

  return threats;
}

/**
 * Get parallel processing configuration
 */
export function getParallelConfig(): {
  maxWorkers: number;
  optimalChunkSize: number;
  systemInfo: Record<string, unknown>;
} {
  const maxWorkers = getOptimalWorkerCount();

  return {
    maxWorkers,
    optimalChunkSize: getOptimalChunkSize(100, maxWorkers), // Example with 100 items
    systemInfo: {
      cpuCount: os.cpus().length,
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
      loadAverage: os.loadavg(),
      platform: os.platform(),
      arch: os.arch(),
    },
  };
}

/**
 * Update parallel processing configuration
 */
export function updateParallelConfig(options: { maxWorkers?: number; taskTimeout?: number }): void {
  // This would update global parallel processing settings
  // For now, it's a placeholder that could be used to configure worker pools
  console.log('Parallel config updated:', options);
}
