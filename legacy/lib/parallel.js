/**
 * Secure Parallel Scanning Engine for NullVoid
 * Implements multi-threaded package scanning with proper synchronization
 */

const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const path = require('path');
const { Mutex } = require('async-mutex');

/**
 * Configuration for parallel scanning
 */
const PARALLEL_CONFIG = {
  maxWorkers: Math.min(os.cpus().length, 8), // Cap at 8 workers
  chunkSize: 10, // Packages per worker chunk
  timeout: 30000, // 30 second timeout per worker
  retryAttempts: 2,
  minChunkSize: 5,
  maxChunkSize: 20
};

/**
 * Dynamic worker allocation based on system resources
 * @returns {number} Optimal number of workers
 */
function getOptimalWorkerCount() {
  const cpuCount = os.cpus().length;
  const memoryGB = os.totalmem() / (1024 * 1024 * 1024);
  const loadAvg = os.loadavg()[0];
  
  // Base calculation on CPU cores
  let optimalWorkers = Math.min(cpuCount, PARALLEL_CONFIG.maxWorkers);
  
  // Adjust based on memory (reduce if low memory)
  if (memoryGB < 4) {
    optimalWorkers = Math.max(1, Math.floor(optimalWorkers / 2));
  } else if (memoryGB < 8) {
    optimalWorkers = Math.max(2, Math.floor(optimalWorkers * 0.75));
  }
  
  // Adjust based on system load (reduce if high load)
  if (loadAvg > cpuCount * 0.8) {
    optimalWorkers = Math.max(1, Math.floor(optimalWorkers * 0.5));
  } else if (loadAvg > cpuCount * 0.5) {
    optimalWorkers = Math.max(2, Math.floor(optimalWorkers * 0.75));
  }
  
  return Math.max(1, optimalWorkers);
}

/**
 * Dynamic chunk sizing based on package complexity and worker count
 * @param {Array} packages - Packages to process
 * @param {number} workerCount - Number of workers
 * @returns {number} Optimal chunk size
 */
function getOptimalChunkSize(packages, workerCount) {
  const baseChunkSize = PARALLEL_CONFIG.chunkSize;
  
  // Adjust based on package count
  if (packages.length < 10) {
    return Math.max(PARALLEL_CONFIG.minChunkSize, Math.ceil(packages.length / workerCount));
  }
  
  // Adjust based on worker count
  const adjustedChunkSize = Math.max(
    PARALLEL_CONFIG.minChunkSize,
    Math.min(
      PARALLEL_CONFIG.maxChunkSize,
      Math.ceil(packages.length / workerCount)
    )
  );
  
  return adjustedChunkSize;
}

/**
 * Secure parallel scanning results with thread-safe operations
 */
class SecureParallelScanResults {
  constructor() {
    this.mutex = new Mutex();
    this.threats = [];
    this.packages = [];
    this.errors = [];
    this.metrics = {
      totalPackages: 0,
      scannedPackages: 0,
      failedPackages: 0,
      startTime: Date.now(),
      endTime: null,
      workerCount: 0
    };
  }

  async addResults(workerResults) {
    const release = await this.mutex.acquire();
    try {
      this.threats.push(...workerResults.threats);
      this.packages.push(...workerResults.packages);
      this.errors.push(...workerResults.errors);
      this.metrics.scannedPackages += workerResults.packages.length;
      this.metrics.failedPackages += workerResults.errors.length;
    } finally {
      release();
    }
  }

  finalize() {
    this.metrics.endTime = Date.now();
    this.metrics.duration = this.metrics.endTime - this.metrics.startTime;
    this.metrics.packagesPerSecond = this.metrics.scannedPackages / (this.metrics.duration / 1000);
  }
}

/**
 * Split packages into chunks for parallel processing
 * @param {Array} packages - Array of packages to scan
 * @param {number} chunkSize - Size of each chunk
 * @returns {Array} Array of package chunks
 */
function chunkPackages(packages, chunkSize = PARALLEL_CONFIG.chunkSize) {
  const chunks = [];
  for (let i = 0; i < packages.length; i += chunkSize) {
    chunks.push(packages.slice(i, i + chunkSize));
  }
  return chunks;
}

/**
 * Worker thread for scanning packages
 */
if (!isMainThread) {
  // Worker thread code
  const { scanPackage } = require('../scan');
  
  async function scanPackageChunk(packages, options) {
    const results = {
      threats: [],
      packages: [],
      errors: []
    };

    for (const packageInfo of packages) {
      try {
        const packageThreats = await scanPackage(
          packageInfo.name,
          packageInfo.version,
          options,
          packageInfo.path
        );
        
        results.threats.push(...packageThreats);
        results.packages.push({
          name: packageInfo.name,
          version: packageInfo.version,
          path: packageInfo.path,
          threatCount: packageThreats.length
        });
      } catch (error) {
        results.errors.push({
          package: packageInfo.name,
          error: error.message
        });
      }
    }

    return results;
  }

  // Handle worker messages
  parentPort.on('message', async (message) => {
    try {
      const results = await scanPackageChunk(message.packages, message.options);
      parentPort.postMessage({ success: true, results });
    } catch (error) {
      parentPort.postMessage({ 
        success: false, 
        error: error.message,
        results: { threats: [], packages: [], errors: [] }
      });
    }
  });
}

/**
 * Secure parallel scanning function with proper synchronization
 * @param {Array} packages - Packages to scan
 * @param {object} options - Scan options
 * @returns {Promise<SecureParallelScanResults>} Parallel scan results
 */
async function scanPackagesInParallel(packages, options = {}) {
  if (!isMainThread) {
    throw new Error('scanPackagesInParallel must be called from main thread');
  }

  const results = new SecureParallelScanResults();
  results.metrics.totalPackages = packages.length;
  
  if (packages.length === 0) {
    results.finalize();
    return results;
  }

  // Determine optimal number of workers
  const workerCount = options.workers === 'auto' ? getOptimalWorkerCount() : 
                     Math.min(options.workers || PARALLEL_CONFIG.maxWorkers, PARALLEL_CONFIG.maxWorkers);
  
  results.metrics.workerCount = workerCount;

  // Determine optimal chunk size
  const chunkSize = getOptimalChunkSize(packages, workerCount);
  
  // Split packages into chunks
  const chunks = chunkPackages(packages, chunkSize);
  
  // Create workers and process chunks with proper synchronization
  const workers = new Map();
  const workerPromises = [];

  for (let i = 0; i < workerCount && i < chunks.length; i++) {
    const worker = new Worker(__filename, {
      workerData: { workerId: i },
      resourceLimits: {
        maxOldGenerationSizeMb: 128,
        maxYoungGenerationSizeMb: 48
      }
    });

    workers.set(worker.threadId, worker);
    
    const promise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error(`Worker ${i} timed out`));
      }, PARALLEL_CONFIG.timeout);
      timeout.unref(); // Don't keep process alive

      worker.on('message', async (message) => {
        clearTimeout(timeout);
        if (message.success) {
          await results.addResults(message.results);
          resolve(message.results);
        } else {
          reject(new Error(message.error));
        }
      });

      worker.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });

      worker.on('exit', (code) => {
        clearTimeout(timeout);
        if (code !== 0) {
          reject(new Error(`Worker ${i} exited with code ${code}`));
        }
      });
    });

    workerPromises.push(promise);
    
    // Send chunk to worker
    worker.postMessage({
      packages: chunks[i],
      options: options
    });
  }

  // Wait for all workers to complete
  try {
    await Promise.allSettled(workerPromises);
  } catch (error) {
    console.warn(`Warning: Some workers failed: ${error.message}`);
  } finally {
    // Clean up workers safely
    for (const [threadId, worker] of workers) {
      try {
        if (!worker.threadId) continue; // Worker already terminated
        worker.terminate();
      } catch (error) {
        console.warn(`Warning: Error terminating worker ${threadId}: ${error.message}`);
      }
    }
  }

  results.finalize();
  return results;
}

/**
 * Parallel file analysis for directory scanning
 * @param {Array} files - Files to analyze
 * @param {object} options - Analysis options
 * @returns {Promise<Array>} Analysis results
 */
async function analyzeFilesInParallel(files, options = {}) {
  if (!isMainThread) {
    throw new Error('analyzeFilesInParallel must be called from main thread');
  }

  const results = [];
  const workerCount = Math.min(PARALLEL_CONFIG.maxWorkers, files.length);
  
  if (files.length === 0) {
    return results;
  }

  // Split files into chunks
  const chunks = chunkPackages(files, Math.ceil(files.length / workerCount));
  
  // Create workers for file analysis
  const workers = [];
  const workerPromises = [];

  for (let i = 0; i < workerCount && i < chunks.length; i++) {
    const worker = new Worker(__filename, {
      workerData: { workerId: i, mode: 'fileAnalysis' }
    });

    workers.push(worker);
    
    const promise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error(`File analysis worker ${i} timed out`));
      }, PARALLEL_CONFIG.timeout);
      timeout.unref(); // Don't keep process alive

      const cleanup = () => {
        clearTimeout(timeout);
      };

      worker.on('message', (message) => {
        cleanup();
        if (message.success) {
          resolve(message.results);
        } else {
          reject(new Error(message.error));
        }
      });

      worker.on('error', (error) => {
        cleanup();
        reject(error);
      });

      worker.on('exit', (code) => {
        cleanup();
        if (code !== 0) {
          reject(new Error(`Worker ${i} exited with code ${code}`));
        }
      });
    });

    workerPromises.push(promise);
    
    // Send file chunk to worker
    worker.postMessage({
      files: chunks[i],
      options: options
    });
  }

  // Wait for all workers to complete
  try {
    const workerResults = await Promise.all(workerPromises);
    workerResults.forEach(workerResult => {
      results.push(...workerResult);
    });
  } catch (error) {
    console.warn(`Warning: Some file analysis workers failed: ${error.message}`);
  } finally {
    // Clean up workers with timeout
    const cleanupPromises = workers.map(worker => {
      if (!worker.threadId) return Promise.resolve();
      
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          worker.kill(); // Force kill if terminate doesn't work
          resolve();
        }, 1000);
        timeout.unref(); // Don't keep process alive
        
        worker.terminate();
        
        worker.on('exit', () => {
          clearTimeout(timeout);
          resolve();
        });
      });
    });
    
    await Promise.all(cleanupPromises);
  }

  return results;
}

/**
 * Get parallel scanning configuration
 * @returns {object} Configuration object
 */
function getParallelConfig() {
  return { ...PARALLEL_CONFIG };
}

/**
 * Update parallel scanning configuration
 * @param {object} config - New configuration
 */
function updateParallelConfig(config) {
  Object.assign(PARALLEL_CONFIG, config);
}

module.exports = {
  scanPackagesInParallel,
  analyzeFilesInParallel,
  getParallelConfig,
  updateParallelConfig,
  SecureParallelScanResults,
  chunkPackages,
  getOptimalWorkerCount,
  getOptimalChunkSize
};
