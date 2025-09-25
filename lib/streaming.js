/**
 * Streaming File Analysis for NullVoid
 * Provides streaming analysis for large files to prevent memory issues
 */

const fs = require('fs');
const path = require('path');
const { Transform } = require('stream');
const { logger, createLogger } = require('./logger');
const { FILE_CONFIG } = require('./config');

const streamLogger = createLogger('Streaming');

/**
 * File stream analyzer for large files
 */
class FileStreamAnalyzer extends Transform {
  constructor(options = {}) {
    super({
      objectMode: true,
      highWaterMark: options.highWaterMark || 16
    });
    
    this.maxFileSize = options.maxFileSize || FILE_CONFIG.MAX_FILE_SIZE;
    this.chunkSize = options.chunkSize || 64 * 1024; // 64KB chunks
    this.threats = [];
    this.filePath = options.filePath || '';
    this.fileSize = 0;
    this.processedBytes = 0;
    this.buffer = Buffer.alloc(0);
    this.lineBuffer = '';
    this.lineNumber = 0;
    
    // Threat detection patterns
    this.patterns = {
      walletHijacking: [
        /window\.ethereum/gi,
        /ethereum\.request/gi,
        /stealthProxyControl/gi,
        /_0x[a-f0-9]+/gi
      ],
      networkManipulation: [
        /fetch.*override/gi,
        /XMLHttpRequest.*intercept/gi,
        /response\.json.*replace/gi
      ],
      obfuscatedCode: [
        /eval\s*\(/gi,
        /new\s+Function\s*\(/gi,
        /atob\s*\(/gi,
        /fromCharCode/gi
      ],
      suspiciousScripts: [
        /postinstall.*curl/gi,
        /postinstall.*wget/gi,
        /bash\s+-c.*rm/gi
      ]
    };
  }

  /**
   * Transform chunk of data
   * @param {Buffer} chunk - Data chunk
   * @param {string} encoding - Encoding
   * @param {Function} callback - Callback function
   */
  _transform(chunk, encoding, callback) {
    this.processedBytes += chunk.length;
    
    // Check if file is too large
    if (this.processedBytes > this.maxFileSize) {
      this.push({
        type: 'FILE_TOO_LARGE',
        message: `File exceeds maximum size limit of ${this.maxFileSize} bytes`,
        filePath: this.filePath,
        severity: 'MEDIUM',
        details: `File size: ${this.processedBytes} bytes`
      });
      return callback();
    }
    
    // Add chunk to buffer
    this.buffer = Buffer.concat([this.buffer, chunk]);
    
    // Process complete lines
    this.processLines();
    
    callback();
  }

  /**
   * Process complete lines from buffer
   */
  processLines() {
    const lines = this.buffer.toString('utf8').split('\n');
    
    // Keep the last incomplete line in buffer
    this.buffer = Buffer.from(lines.pop() || '', 'utf8');
    
    // Process each complete line
    for (const line of lines) {
      this.lineNumber++;
      this.lineBuffer += line + '\n';
      
      // Analyze line for threats
      this.analyzeLine(line, this.lineNumber);
      
      // Keep only recent lines in buffer (for context)
      if (this.lineBuffer.length > 10000) { // 10KB context
        const lines = this.lineBuffer.split('\n');
        this.lineBuffer = lines.slice(-50).join('\n'); // Keep last 50 lines
      }
    }
  }

  /**
   * Analyze a line for threats
   * @param {string} line - Line to analyze
   * @param {number} lineNumber - Line number
   */
  analyzeLine(line, lineNumber) {
    for (const [category, patterns] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(line)) {
          this.threats.push({
            type: this.getThreatType(category),
            message: this.getThreatMessage(category),
            filePath: this.filePath,
            lineNumber: lineNumber,
            severity: this.getThreatSeverity(category),
            details: `Pattern: ${pattern.source}`,
            sampleCode: line.trim()
          });
        }
      }
    }
  }

  /**
   * Get threat type from category
   * @param {string} category - Threat category
   * @returns {string} Threat type
   */
  getThreatType(category) {
    const typeMap = {
      walletHijacking: 'WALLET_HIJACKING',
      networkManipulation: 'NETWORK_MANIPULATION',
      obfuscatedCode: 'OBFUSCATED_CODE',
      suspiciousScripts: 'SUSPICIOUS_SCRIPTS'
    };
    return typeMap[category] || 'UNKNOWN_THREAT';
  }

  /**
   * Get threat message from category
   * @param {string} category - Threat category
   * @returns {string} Threat message
   */
  getThreatMessage(category) {
    const messageMap = {
      walletHijacking: 'Potential wallet hijacking code detected',
      networkManipulation: 'Potential network manipulation code detected',
      obfuscatedCode: 'Potential obfuscated code detected',
      suspiciousScripts: 'Potential suspicious script detected'
    };
    return messageMap[category] || 'Unknown threat detected';
  }

  /**
   * Get threat severity from category
   * @param {string} category - Threat category
   * @returns {string} Threat severity
   */
  getThreatSeverity(category) {
    const severityMap = {
      walletHijacking: 'CRITICAL',
      networkManipulation: 'HIGH',
      obfuscatedCode: 'MEDIUM',
      suspiciousScripts: 'HIGH'
    };
    return severityMap[category] || 'LOW';
  }

  /**
   * Flush remaining data
   * @param {Function} callback - Callback function
   */
  _flush(callback) {
    // Process any remaining data in buffer
    if (this.buffer.length > 0) {
      this.processLines();
    }
    
    // Emit all collected threats
    for (const threat of this.threats) {
      this.push(threat);
    }
    
    callback();
  }
}

/**
 * Stream-based file analyzer
 */
class StreamFileAnalyzer {
  constructor(options = {}) {
    this.maxFileSize = options.maxFileSize || FILE_CONFIG.MAX_FILE_SIZE;
    this.chunkSize = options.chunkSize || 64 * 1024;
    this.timeout = options.timeout || 30000;
  }

  /**
   * Analyze a file using streaming
   * @param {string} filePath - Path to file
   * @param {object} options - Analysis options
   * @returns {Promise<Array>} Array of threats
   */
  async analyzeFile(filePath, options = {}) {
    return new Promise((resolve, reject) => {
      const threats = [];
      const analyzer = new FileStreamAnalyzer({
        filePath,
        maxFileSize: this.maxFileSize,
        chunkSize: this.chunkSize
      });

      // Set timeout
      const timeout = setTimeout(() => {
        analyzer.destroy();
        reject(new Error(`File analysis timeout: ${filePath}`));
      }, this.timeout);

      // Handle analyzer data
      analyzer.on('data', (threat) => {
        threats.push(threat);
      });

      // Handle analyzer errors
      analyzer.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });

      // Handle analyzer completion
      analyzer.on('end', () => {
        clearTimeout(timeout);
        resolve(threats);
      });

      // Create read stream and pipe to analyzer
      const readStream = fs.createReadStream(filePath, {
        highWaterMark: this.chunkSize
      });

      readStream.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });

      readStream.pipe(analyzer);
    });
  }

  /**
   * Analyze multiple files using streaming
   * @param {Array} filePaths - Array of file paths
   * @param {object} options - Analysis options
   * @returns {Promise<Array>} Array of all threats
   */
  async analyzeFiles(filePaths, options = {}) {
    const allThreats = [];
    const concurrency = options.concurrency || 5;
    
    // Process files in batches to avoid overwhelming the system
    for (let i = 0; i < filePaths.length; i += concurrency) {
      const batch = filePaths.slice(i, i + concurrency);
      const batchPromises = batch.map(filePath => 
        this.analyzeFile(filePath, options).catch(error => {
          streamLogger.warn(`Failed to analyze file ${filePath}`, { error: error.message });
          return [];
        })
      );
      
      const batchResults = await Promise.all(batchPromises);
      allThreats.push(...batchResults.flat());
    }
    
    return allThreats;
  }
}

/**
 * Large file detector
 */
class LargeFileDetector {
  constructor(options = {}) {
    this.maxFileSize = options.maxFileSize || FILE_CONFIG.MAX_FILE_SIZE;
    this.sampleSize = options.sampleSize || 1024 * 1024; // 1MB sample
  }

  /**
   * Check if file is too large for normal processing
   * @param {string} filePath - Path to file
   * @returns {Promise<boolean>} True if file is too large
   */
  async isLargeFile(filePath) {
    try {
      const stats = await fs.promises.stat(filePath);
      return stats.size > this.maxFileSize;
    } catch (error) {
      streamLogger.warn(`Could not check file size for ${filePath}`, { error: error.message });
      return false;
    }
  }

  /**
   * Get file size
   * @param {string} filePath - Path to file
   * @returns {Promise<number>} File size in bytes
   */
  async getFileSize(filePath) {
    try {
      const stats = await fs.promises.stat(filePath);
      return stats.size;
    } catch (error) {
      streamLogger.warn(`Could not get file size for ${filePath}`, { error: error.message });
      return 0;
    }
  }

  /**
   * Sample file content for quick analysis
   * @param {string} filePath - Path to file
   * @returns {Promise<string>} Sampled content
   */
  async sampleFile(filePath) {
    try {
      const fd = await fs.promises.open(filePath, 'r');
      const buffer = Buffer.alloc(this.sampleSize);
      const { bytesRead } = await fd.read(buffer, 0, this.sampleSize, 0);
      await fd.close();
      
      return buffer.toString('utf8', 0, bytesRead);
    } catch (error) {
      streamLogger.warn(`Could not sample file ${filePath}`, { error: error.message });
      return '';
    }
  }
}

/**
 * Memory-efficient file processor
 */
class MemoryEfficientProcessor {
  constructor(options = {}) {
    this.maxMemoryUsage = options.maxMemoryUsage || 100 * 1024 * 1024; // 100MB
    this.chunkSize = options.chunkSize || 64 * 1024;
    this.processedFiles = new Set();
  }

  /**
   * Process files with memory management
   * @param {Array} filePaths - Array of file paths
   * @param {Function} processor - File processor function
   * @param {object} options - Processing options
   * @returns {Promise<Array>} Processing results
   */
  async processFiles(filePaths, processor, options = {}) {
    const results = [];
    const batchSize = options.batchSize || 10;
    
    for (let i = 0; i < filePaths.length; i += batchSize) {
      const batch = filePaths.slice(i, i + batchSize);
      
      // Check memory usage
      const memoryUsage = process.memoryUsage();
      if (memoryUsage.heapUsed > this.maxMemoryUsage) {
        streamLogger.warn('High memory usage detected, forcing garbage collection');
        if (global.gc) {
          global.gc();
        }
      }
      
      // Process batch
      const batchPromises = batch.map(async (filePath) => {
        if (this.processedFiles.has(filePath)) {
          return null; // Skip already processed files
        }
        
        try {
          const result = await processor(filePath);
          this.processedFiles.add(filePath);
          return result;
        } catch (error) {
          streamLogger.warn(`Failed to process file ${filePath}`, { error: error.message });
          return null;
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults.filter(result => result !== null));
      
      // Small delay to allow garbage collection
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    return results;
  }
}

module.exports = {
  FileStreamAnalyzer,
  StreamFileAnalyzer,
  LargeFileDetector,
  MemoryEfficientProcessor
};
