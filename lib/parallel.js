/**
 * Parallel Scanning Engine for NullVoid
 * Implements multi-threaded package scanning for performance improvements
 */

const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const path = require('path');

/**
 * Configuration for parallel scanning
 */
const PARALLEL_CONFIG = {
  maxWorkers: Math.min(os.cpus().length, 8), // Cap at 8 workers
  chunkSize: 10, // Packages per worker chunk
  timeout: 30000, // 30 second timeout per worker
  retryAttempts: 2
};

/**
 * Parallel scanning results
 */
class ParallelScanResults {
  constructor() {
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

  addResults(workerResults) {
    this.threats.push(...workerResults.threats);
    this.packages.push(...workerResults.packages);
    this.errors.push(...workerResults.errors);
    this.metrics.scannedPackages += workerResults.packages.length;
    this.metrics.failedPackages += workerResults.errors.length;
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
 * Main thread parallel scanning function
 * @param {Array} packages - Packages to scan
 * @param {object} options - Scan options
 * @returns {Promise<ParallelScanResults>} Parallel scan results
 */
async function scanPackagesInParallel(packages, options = {}) {
  if (!isMainThread) {
    throw new Error('scanPackagesInParallel must be called from main thread');
  }

  const results = new ParallelScanResults();
  results.metrics.totalPackages = packages.length;
  
  if (packages.length === 0) {
    results.finalize();
    return results;
  }

  // Determine number of workers
  const workerCount = Math.min(
    PARALLEL_CONFIG.maxWorkers,
    Math.ceil(packages.length / PARALLEL_CONFIG.chunkSize)
  );
  
  results.metrics.workerCount = workerCount;

  // Split packages into chunks
  const chunks = chunkPackages(packages, PARALLEL_CONFIG.chunkSize);
  
  // Create workers and process chunks
  const workers = [];
  const workerPromises = [];

  for (let i = 0; i < workerCount && i < chunks.length; i++) {
    const worker = new Worker(__filename, {
      workerData: { workerId: i }
    });

    workers.push(worker);
    
    const promise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error(`Worker ${i} timed out`));
      }, PARALLEL_CONFIG.timeout);

      worker.on('message', (message) => {
        clearTimeout(timeout);
        if (message.success) {
          results.addResults(message.results);
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
    await Promise.all(workerPromises);
  } catch (error) {
    console.warn(`Warning: Some workers failed: ${error.message}`);
  } finally {
    // Clean up workers
    workers.forEach(worker => {
      if (!worker.threadId) return; // Worker already terminated
      worker.terminate();
    });
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

      worker.on('message', (message) => {
        clearTimeout(timeout);
        if (message.success) {
          resolve(message.results);
        } else {
          reject(new Error(message.error));
        }
      });

      worker.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
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
    // Clean up workers
    workers.forEach(worker => {
      if (!worker.threadId) return;
      worker.terminate();
    });
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
  ParallelScanResults,
  chunkPackages
};
