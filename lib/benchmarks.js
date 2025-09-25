/**
 * Performance Benchmarks for NullVoid
 * Provides comprehensive performance testing and benchmarking utilities
 */

const { performance } = require('perf_hooks');
const fs = require('fs');
const path = require('path');
const { logger, createLogger } = require('./lib/logger');
const { PERFORMANCE_CONFIG } = require('./lib/config');

const perfLogger = createLogger('Benchmark');

/**
 * Benchmark result class
 */
class BenchmarkResult {
  constructor(name, duration, iterations, metadata = {}) {
    this.name = name;
    this.duration = duration;
    this.iterations = iterations;
    this.metadata = metadata;
    this.timestamp = new Date().toISOString();
    this.avgDuration = duration / iterations;
    this.opsPerSecond = iterations / (duration / 1000);
  }

  /**
   * Get formatted result string
   * @returns {string} Formatted result
   */
  toString() {
    return `${this.name}: ${this.iterations} iterations in ${this.duration.toFixed(2)}ms (${this.opsPerSecond.toFixed(2)} ops/sec)`;
  }

  /**
   * Get result as object
   * @returns {object} Result object
   */
  toObject() {
    return {
      name: this.name,
      duration: this.duration,
      iterations: this.iterations,
      avgDuration: this.avgDuration,
      opsPerSecond: this.opsPerSecond,
      timestamp: this.timestamp,
      metadata: this.metadata
    };
  }
}

/**
 * Benchmark suite class
 */
class BenchmarkSuite {
  constructor(name) {
    this.name = name;
    this.benchmarks = [];
    this.results = [];
  }

  /**
   * Add a benchmark to the suite
   * @param {string} name - Benchmark name
   * @param {Function} fn - Benchmark function
   * @param {object} options - Benchmark options
   */
  add(name, fn, options = {}) {
    this.benchmarks.push({
      name,
      fn,
      iterations: options.iterations || 1000,
      warmup: options.warmup || 100,
      timeout: options.timeout || 30000,
      metadata: options.metadata || {}
    });
  }

  /**
   * Run all benchmarks in the suite
   * @returns {Promise<Array>} Array of benchmark results
   */
  async run() {
    perfLogger.info(`Starting benchmark suite: ${this.name}`);
    this.results = [];

    for (const benchmark of this.benchmarks) {
      try {
        const result = await this.runBenchmark(benchmark);
        this.results.push(result);
        perfLogger.info(result.toString());
      } catch (error) {
        perfLogger.error(`Benchmark ${benchmark.name} failed`, { error: error.message });
      }
    }

    perfLogger.info(`Benchmark suite ${this.name} completed`);
    return this.results;
  }

  /**
   * Run a single benchmark
   * @param {object} benchmark - Benchmark configuration
   * @returns {Promise<BenchmarkResult>} Benchmark result
   */
  async runBenchmark(benchmark) {
    const { name, fn, iterations, warmup, timeout, metadata } = benchmark;
    
    perfLogger.debug(`Running benchmark: ${name}`, { iterations, warmup });

    // Warmup phase
    for (let i = 0; i < warmup; i++) {
      try {
        await fn();
      } catch (error) {
        // Ignore warmup errors
      }
    }

    // Actual benchmark
    const startTime = performance.now();
    let completedIterations = 0;
    let errors = 0;

    for (let i = 0; i < iterations; i++) {
      try {
        await fn();
        completedIterations++;
      } catch (error) {
        errors++;
        if (errors > iterations * 0.1) { // Stop if more than 10% errors
          throw new Error(`Too many errors in benchmark ${name}: ${errors}/${i + 1}`);
        }
      }

      // Check timeout
      if (performance.now() - startTime > timeout) {
        perfLogger.warn(`Benchmark ${name} timed out after ${timeout}ms`);
        break;
      }
    }

    const endTime = performance.now();
    const duration = endTime - startTime;

    return new BenchmarkResult(name, duration, completedIterations, {
      ...metadata,
      errors,
      timeout: endTime - startTime > timeout
    });
  }

  /**
   * Get benchmark results as JSON
   * @returns {string} JSON string of results
   */
  toJSON() {
    return JSON.stringify({
      suite: this.name,
      timestamp: new Date().toISOString(),
      results: this.results.map(r => r.toObject())
    }, null, 2);
  }

  /**
   * Save results to file
   * @param {string} filePath - File path to save results
   */
  saveResults(filePath) {
    try {
      fs.writeFileSync(filePath, this.toJSON());
      perfLogger.info(`Benchmark results saved to ${filePath}`);
    } catch (error) {
      perfLogger.error(`Failed to save benchmark results`, { error: error.message });
    }
  }
}

/**
 * Performance profiler class
 */
class PerformanceProfiler {
  constructor() {
    this.marks = new Map();
    this.measures = new Map();
  }

  /**
   * Mark a point in time
   * @param {string} name - Mark name
   */
  mark(name) {
    const timestamp = performance.now();
    this.marks.set(name, timestamp);
    performance.mark(name);
  }

  /**
   * Measure time between two marks
   * @param {string} name - Measure name
   * @param {string} startMark - Start mark name
   * @param {string} endMark - End mark name
   */
  measure(name, startMark, endMark) {
    const startTime = this.marks.get(startMark);
    const endTime = this.marks.get(endMark);
    
    if (startTime && endTime) {
      const duration = endTime - startTime;
      this.measures.set(name, duration);
      performance.measure(name, startMark, endMark);
      return duration;
    }
    
    return null;
  }

  /**
   * Get all measures
   * @returns {object} All measures
   */
  getMeasures() {
    return Object.fromEntries(this.measures);
  }

  /**
   * Clear all marks and measures
   */
  clear() {
    this.marks.clear();
    this.measures.clear();
    performance.clearMarks();
    performance.clearMeasures();
  }
}

/**
 * Memory usage tracker
 */
class MemoryTracker {
  constructor() {
    this.snapshots = [];
  }

  /**
   * Take a memory snapshot
   * @param {string} label - Snapshot label
   */
  snapshot(label) {
    const usage = process.memoryUsage();
    this.snapshots.push({
      label,
      timestamp: Date.now(),
      rss: usage.rss,
      heapTotal: usage.heapTotal,
      heapUsed: usage.heapUsed,
      external: usage.external,
      arrayBuffers: usage.arrayBuffers
    });
  }

  /**
   * Get memory usage difference between snapshots
   * @param {string} startLabel - Start snapshot label
   * @param {string} endLabel - End snapshot label
   * @returns {object} Memory usage difference
   */
  getDifference(startLabel, endLabel) {
    const start = this.snapshots.find(s => s.label === startLabel);
    const end = this.snapshots.find(s => s.label === endLabel);
    
    if (!start || !end) {
      return null;
    }
    
    return {
      rss: end.rss - start.rss,
      heapTotal: end.heapTotal - start.heapTotal,
      heapUsed: end.heapUsed - start.heapUsed,
      external: end.external - start.external,
      arrayBuffers: end.arrayBuffers - start.arrayBuffers,
      duration: end.timestamp - start.timestamp
    };
  }

  /**
   * Get all snapshots
   * @returns {Array} All snapshots
   */
  getSnapshots() {
    return this.snapshots;
  }

  /**
   * Clear all snapshots
   */
  clear() {
    this.snapshots = [];
  }
}

/**
 * Predefined benchmark suites
 */
const benchmarkSuites = {
  /**
   * Cache performance benchmarks
   */
  cache: () => {
    const suite = new BenchmarkSuite('Cache Performance');
    const { PackageCache } = require('./cache');
    const cache = new PackageCache({ maxSize: 1000 });

    suite.add('cache-set', () => {
      const key = `package-${Math.random()}`;
      const value = { data: 'test', timestamp: Date.now() };
      cache.set(key, value);
    }, { iterations: 10000 });

    suite.add('cache-get', () => {
      const key = `package-${Math.floor(Math.random() * 100)}`;
      cache.get(key);
    }, { iterations: 10000 });

    suite.add('cache-has', () => {
      const key = `package-${Math.floor(Math.random() * 100)}`;
      cache.has(key);
    }, { iterations: 10000 });

    return suite;
  },

  /**
   * Validation performance benchmarks
   */
  validation: () => {
    const suite = new BenchmarkSuite('Validation Performance');
    const { validatePackageName, validateScanOptions } = require('./validation');

    suite.add('validate-package-name', () => {
      validatePackageName('test-package-name');
    }, { iterations: 10000 });

    suite.add('validate-scan-options', () => {
      validateScanOptions({ maxDepth: 3, workers: 4 });
    }, { iterations: 10000 });

    return suite;
  },

  /**
   * Rate limiting performance benchmarks
   */
  rateLimiting: () => {
    const suite = new BenchmarkSuite('Rate Limiting Performance');
    const { RateLimiter } = require('./rateLimiter');
    const limiter = new RateLimiter({ maxRequests: 1000, windowSize: 60000 });

    suite.add('rate-limiter-check', () => {
      limiter.isAllowed('test');
    }, { iterations: 10000 });

    return suite;
  }
};

/**
 * Run all benchmark suites
 * @param {object} options - Options
 * @returns {Promise<object>} All benchmark results
 */
async function runAllBenchmarks(options = {}) {
  const results = {};
  const outputDir = options.outputDir || './benchmarks';
  
  // Create output directory if it doesn't exist
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  for (const [name, suiteFactory] of Object.entries(benchmarkSuites)) {
    try {
      const suite = suiteFactory();
      const suiteResults = await suite.run();
      results[name] = suiteResults;
      
      // Save individual suite results
      const filePath = path.join(outputDir, `${name}-benchmark.json`);
      suite.saveResults(filePath);
    } catch (error) {
      perfLogger.error(`Benchmark suite ${name} failed`, { error: error.message });
    }
  }

  // Save combined results
  const combinedPath = path.join(outputDir, 'all-benchmarks.json');
  fs.writeFileSync(combinedPath, JSON.stringify(results, null, 2));
  
  perfLogger.info(`All benchmarks completed. Results saved to ${outputDir}`);
  return results;
}

module.exports = {
  BenchmarkResult,
  BenchmarkSuite,
  PerformanceProfiler,
  MemoryTracker,
  benchmarkSuites,
  runAllBenchmarks
};
