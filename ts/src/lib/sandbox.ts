import { Threat, createThreat, SeverityLevel } from '../types/core';
import * as vm from 'vm';
import * as path from 'path';
import * as fs from 'fs';
import { isNullVoidCode } from './nullvoidDetection';
import { DETECTION_PATTERNS } from './config';

/**
 * Security configuration for sandbox
 */
export const SANDBOX_CONFIG = {
  timeout: 100, // 100ms timeout for code execution
  maxMemory: 128 * 1024 * 1024, // 128MB memory limit
  maxExecutionTime: 1000, // 1 second max execution time
  allowCodeGeneration: false,
  allowCodeGenerationFromStrings: false,
};

export interface SandboxResult {
  threats: Threat[];
  executionResult: unknown;
  executionError: Error | null;
  executionTime: number;
  safe: boolean;
}

export interface FileAnalysisResult {
  filePath: string;
  threats: Threat[];
  safe: boolean;
  executionTime: number;
  error: Error | null;
}

export interface WalletPattern {
  type: string;
  patterns: RegExp[];
  severity: SeverityLevel;
}

export interface WalletThreat {
  type: string;
  severity: SeverityLevel;
  message: string;
  details: string;
  confidence: number;
  filename: string;
}

export interface EntropyAnalysisResult {
  hasHighEntropy: boolean;
  entropyScore: number;
  highEntropyLines: number;
  totalLines: number;
}

/**
 * Create a secure sandbox context for code analysis
 */
export function createSecureSandbox(): vm.Context {
  const sandbox = {
    // Mock console to prevent output manipulation
    console: {
      log: () => {},
      error: () => {},
      warn: () => {},
      info: () => {},
      debug: () => {},
    },

    // Mock process to prevent system access
    process: {
      exit: () => {},
      env: {},
      platform: 'sandbox',
      version: 'sandbox',
      versions: { node: 'sandbox' },
      cwd: () => '/sandbox',
      chdir: () => {},
      nextTick: () => {},
      setImmediate: () => {},
      setTimeout: () => {},
      clearTimeout: () => {},
      setInterval: () => {},
      clearInterval: () => {},
    },

    // Block require to prevent module loading
    require: () => {
      throw new Error('require() is not allowed in sandbox');
    },

    // Block import to prevent ES module loading
    import: () => {
      throw new Error('import() is not allowed in sandbox');
    },

    // Mock global objects
    global: {},
    globalThis: {},

    // Mock common globals
    Buffer: undefined,
    __dirname: '/sandbox',
    __filename: '/sandbox/analysis.js',

    // Block dangerous functions
    eval: () => {
      throw new Error('eval() is not allowed in sandbox');
    },

    Function: () => {
      throw new Error('Function() constructor is not allowed in sandbox');
    },

    // Block file system access
    fs: undefined,

    // Block child process access
    child_process: undefined,

    // Block network access
    http: undefined,
    https: undefined,
    net: undefined,
    tls: undefined,

    // Block crypto access (except for analysis)
    crypto: {
      // Only allow safe crypto functions for analysis
      createHash: () => ({
        update: () => ({ digest: () => 'sandbox-hash' }),
      }),
    },

    // Mock other dangerous modules
    os: undefined,
    path: undefined,
    url: undefined,
    querystring: undefined,
    util: undefined,
  };

  return vm.createContext(sandbox, {
    codeGeneration: SANDBOX_CONFIG.allowCodeGeneration ? {} : { strings: false, wasm: false },
    microtaskMode: 'afterEvaluate',
  });
}

/**
 * Safely analyze malicious code in sandbox
 */
export function analyzeCodeInSandbox(
  code: string,
  filename: string = 'analysis.js'
): SandboxResult {
  // Skip analysis for NullVoid's own code
  if (isNullVoidCode(filename)) {
    return {
      threats: [],
      executionResult: null,
      executionError: null,
      executionTime: 0,
      safe: true,
    };
  }

  const context = createSecureSandbox();
  const threats: Threat[] = [];
  let executionResult: unknown = null;
  let executionError: Error | null = null;
  let executionTime = 0;

  try {
    // Create script with timeout
    const script = new vm.Script(code, {
      filename: filename,
    });

    const startTime = Date.now();

    // Run in sandbox with additional timeout
    executionResult = script.runInContext(context, {
      timeout: SANDBOX_CONFIG.timeout,
      breakOnSigint: true,
      displayErrors: false,
    });

    executionTime = Date.now() - startTime;

    // Check for suspicious execution patterns
    if (executionTime > SANDBOX_CONFIG.timeout) {
      threats.push(
        createThreat(
          'SANDBOX_TIMEOUT',
          'Code execution exceeded timeout limit',
          filename,
          filename,
          'HIGH',
          `Execution took ${executionTime}ms, limit is ${SANDBOX_CONFIG.timeout}ms`,
          { executionTime: executionTime, timeout: SANDBOX_CONFIG.timeout }
        )
      );
    }
  } catch (error: unknown) {
    executionError = error instanceof Error ? error : new Error(String(error));
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorCode =
      error instanceof Error && 'code' in error ? (error as Error & { code: string }).code : '';

    // Analyze error types for threat detection
    if (errorMessage.includes('require')) {
      threats.push(
        createThreat(
          'SANDBOX_SECURITY_VIOLATION',
          'Code attempted to load modules',
          filename,
          filename,
          'HIGH',
          'Malicious code tried to use require() or import()',
          { error: errorMessage }
        )
      );
    }

    if (errorMessage.includes('eval') || errorMessage.includes('Function')) {
      threats.push(
        createThreat(
          'SANDBOX_SECURITY_VIOLATION',
          'Code attempted dynamic code generation',
          filename,
          filename,
          'CRITICAL',
          'Malicious code tried to use eval() or Function() constructor',
          { error: errorMessage }
        )
      );
    }

    if (errorMessage.includes('timeout') || errorCode === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
      threats.push(
        createThreat(
          'SANDBOX_TIMEOUT',
          'Code execution timed out',
          filename,
          filename,
          'HIGH',
          'Code may contain infinite loops or blocking operations',
          { error: errorMessage }
        )
      );
    }

    if (errorMessage.includes('memory')) {
      threats.push(
        createThreat(
          'SANDBOX_MEMORY_LIMIT',
          'Code attempted memory exhaustion',
          filename,
          filename,
          'HIGH',
          'Code may contain memory-intensive operations',
          { error: errorMessage }
        )
      );
    }
  }

  return {
    threats,
    executionResult,
    executionError,
    executionTime,
    safe: threats.length === 0, // Only consider unsafe if threats are detected
  };
}

/**
 * Analyze code for wallet hijacking patterns safely
 */
export function analyzeWalletThreats(code: string, filename: string = 'analysis.js'): Threat[] {
  const threats: Threat[] = [];

  // Check if this is NullVoid's own code - if so, return empty threats
  if (isNullVoidCode(filename)) {
    return threats;
  }

  // Advanced wallet hijacking patterns
  const walletPatterns: Record<string, RegExp[]> = {
    // Direct wallet hijacking
    ethereumHijack: [
      /window\s*\.\s*ethereum\s*=\s*new\s+Proxy/gi,
      /Object\.defineProperty\s*\(\s*window\s*,\s*['"`]ethereum/gi,
      /window\.__defineGetter__\s*\(\s*['"`]ethereum/gi,
      /window\.ethereum\s*=\s*.*?proxy/gi,
    ],

    // Transaction manipulation
    transactionRedirect: [
      /eth_sendTransaction.*?params.*?to\s*[:=]/gi,
      /params\[0\]\.to\s*=\s*['"`]0x[a-fA-F0-9]{40}/gi,
      /transaction\.to\s*=.*?attacker/gi,
      /sendTransaction.*?replace.*?address/gi,
    ],

    // Address replacement
    addressSwap: [
      /replace\s*\(\s*\/0x[a-fA-F0-9]{40}\/.*?,\s*['"`]0x/gi,
      /0x[a-fA-F0-9]{40}.*?\/\/.*?(attacker|wallet|address)/gi,
      /\.replace\s*\(\s*['"`]0x[a-fA-F0-9]{40}/gi,
    ],

    // Multi-chain targeting
    multiChain: [
      /bitcoin.*?address.*?replace/gi,
      /litecoin.*?L[a-km-zA-HJ-NP-Z1-9]{26,33}/gi,
      /tron.*?T[a-km-zA-HJ-NP-Z1-9]{33}/gi,
      /solana.*?[1-9A-HJ-NP-Za-km-z]{32,44}/gi,
      /polygon.*?0x[a-fA-F0-9]{40}/gi,
      /bsc.*?0x[a-fA-F0-9]{40}/gi,
    ],

    // Obfuscation detection
    obfuscation: [
      /eval\s*\(\s*String\.fromCharCode/gi,
      /Function\s*\(\s*['"`]return/gi,
      /_0x[a-f0-9]{4,6}\s*\(/gi,
      /\[\s*['"`]\\x[0-9a-f]{2}/gi,
      /atob\s*\(\s*['"`][A-Za-z0-9+/=]+['"`]/gi,
    ],

    // Network interception
    networkHooks: [
      /XMLHttpRequest\.prototype\.open\s*=/gi,
      /fetch\s*=\s*.*?function/gi,
      /Response\.prototype\.json\s*=/gi,
      /axios\.interceptors/gi,
    ],
  };

  // Check each pattern category
  for (const [threatType, patterns] of Object.entries(walletPatterns)) {
    for (const pattern of patterns) {
      if (pattern.test(code)) {
        const severity = calculateSeverity(threatType);
        const confidence = calculateConfidence(code, pattern);

        threats.push(
          createThreat(
            'WALLET_HIJACKING',
            `Detected ${threatType} pattern`,
            filename,
            filename,
            severity,
            `Pattern matched: ${pattern.toString()}`,
            { confidence, pattern: pattern.toString(), threatType }
          )
        );
      }
    }
  }

  // Advanced heuristics
  if (hasHighEntropy(code) && hasWalletKeywords(code)) {
    threats.push(
      createThreat(
        'OBFUSCATED_WALLET_CODE',
        'Detected obfuscated wallet manipulation code',
        filename,
        filename,
        'HIGH',
        'High entropy code contains wallet-related keywords',
        { confidence: 0.85 }
      )
    );
  }

  return threats;
}

/**
 * Calculate threat severity based on pattern type
 */
function calculateSeverity(threatType: string): SeverityLevel {
  const severityMap: Record<string, SeverityLevel> = {
    ethereumHijack: 'CRITICAL',
    transactionRedirect: 'CRITICAL',
    addressSwap: 'HIGH',
    multiChain: 'HIGH',
    obfuscation: 'MEDIUM',
    networkHooks: 'HIGH',
  };

  return severityMap[threatType] || 'MEDIUM';
}

/**
 * Calculate confidence score for threat detection
 */
function calculateConfidence(code: string, pattern: RegExp): number {
  const matches = code.match(pattern);
  if (!matches) return 0;

  // Higher confidence for multiple matches
  const matchCount = matches.length;
  const baseConfidence = 0.7;

  return Math.min(0.95, baseConfidence + matchCount * 0.1);
}

/**
 * Check if code has high entropy (indicating obfuscation)
 */
export function hasHighEntropy(code: string): boolean {
  // Simple entropy calculation
  const lines = code.split('\n');
  let highEntropyLines = 0;

  for (const line of lines) {
    if (line.length > 100) {
      // Check for random-looking character sequences
      const randomPattern = /[a-zA-Z0-9]{20,}/g;
      const matches = line.match(randomPattern);

      if (matches && matches.length > 2) {
        highEntropyLines++;
      }
    }
  }

  return highEntropyLines > lines.length * 0.3;
}

/**
 * Check if code contains wallet-related keywords
 */
export function hasWalletKeywords(code: string): boolean {
  const walletKeywords = DETECTION_PATTERNS.WALLET_KEYWORDS;

  const lowerCode = code.toLowerCase();
  return walletKeywords.some((keyword) => lowerCode.includes(keyword));
}

/**
 * Safe file analysis with sandbox protection
 */
export function analyzeFileSafely(filePath: string): FileAnalysisResult {
  try {
    // Validate file path first
    const normalizedPath = path.normalize(filePath);
    const absolutePath = path.resolve(normalizedPath);

    // Check if file exists and is readable
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`File does not exist: ${absolutePath}`);
    }

    const stats = fs.statSync(absolutePath);
    if (!stats.isFile()) {
      throw new Error(`Path is not a file: ${absolutePath}`);
    }

    // Check if this is NullVoid's own code - if so, return safe analysis
    if (isNullVoidCode(absolutePath)) {
      return {
        filePath: absolutePath,
        threats: [],
        safe: true,
        executionTime: 0,
        error: null,
      };
    }

    // Read file content
    const content = fs.readFileSync(absolutePath, 'utf8');

    // Analyze in sandbox
    const sandboxResult = analyzeCodeInSandbox(content, path.basename(filePath));

    // Additional static analysis
    const walletThreats = analyzeWalletThreats(content, path.basename(filePath));

    return {
      filePath: absolutePath,
      threats: [...sandboxResult.threats, ...walletThreats],
      safe: sandboxResult.safe,
      executionTime: sandboxResult.executionTime,
      error: sandboxResult.executionError,
    };
  } catch (error: unknown) {
    return {
      filePath: filePath,
      threats: [
        createThreat(
          'ANALYSIS_ERROR',
          'Failed to analyze file safely',
          filePath,
          filePath,
          'MEDIUM',
          error instanceof Error ? error.message : String(error),
          { error: error instanceof Error ? error.message : String(error) }
        ),
      ],
      safe: false,
      executionTime: 0,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}
