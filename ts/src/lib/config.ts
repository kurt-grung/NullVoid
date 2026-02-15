/**
 * Configuration Constants for NullVoid
 * Centralizes all configuration values and magic numbers
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanConfig, SecurityConfig, PerformanceConfig } from '../types';

/** Scan options from .nullvoidrc (depth, defaultTarget) */
export interface RcScanOptions {
  depth?: number;
  defaultTarget?: string;
}

function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): void {
  if (!source || typeof source !== 'object') return;
  for (const key of Object.keys(source)) {
    const srcVal = source[key];
    if (srcVal != null && typeof srcVal === 'object' && !Array.isArray(srcVal)) {
      if (!target[key] || typeof target[key] !== 'object') {
        (target as Record<string, unknown>)[key] = {};
      }
      deepMerge((target[key] as Record<string, unknown>) || {}, srcVal as Record<string, unknown>);
    } else if (srcVal !== undefined) {
      (target as Record<string, unknown>)[key] = srcVal;
    }
  }
}

function loadNullvoidRc(): void {
  const rcPaths = [
    path.join(process.cwd(), '.nullvoidrc.json'),
    path.join(process.cwd(), '.nullvoidrc'),
  ];
  for (const rcPath of rcPaths) {
    try {
      if (fs.existsSync(rcPath)) {
        const content = fs.readFileSync(rcPath, 'utf8');
        const rc = JSON.parse(content) as Record<string, unknown>;
        if (rc['DEPENDENCY_CONFUSION_CONFIG']) {
          deepMerge(
            DEPENDENCY_CONFUSION_CONFIG as unknown as Record<string, unknown>,
            rc['DEPENDENCY_CONFUSION_CONFIG'] as Record<string, unknown>
          );
        }
        break;
      }
    } catch {
      /* ignore */
    }
  }
}

/** Load scan options from .nullvoidrc (depth, defaultTarget) */
export function getRcScanOptions(): RcScanOptions {
  const rcPaths = [
    path.join(process.cwd(), '.nullvoidrc.json'),
    path.join(process.cwd(), '.nullvoidrc'),
  ];
  for (const rcPath of rcPaths) {
    try {
      if (fs.existsSync(rcPath)) {
        const content = fs.readFileSync(rcPath, 'utf8');
        const rc = JSON.parse(content) as Record<string, unknown>;
        const opts: RcScanOptions = {};
        if (typeof rc['depth'] === 'number') opts.depth = rc['depth'];
        if (typeof rc['defaultTarget'] === 'string') opts.defaultTarget = rc['defaultTarget'];
        return opts;
      }
    } catch {
      /* ignore */
    }
  }
  return {};
}

/**
 * Cache configuration
 */
export const CACHE_CONFIG = {
  TTL: 5 * 60 * 1000, // 5 minutes
  MAX_SIZE: 1000, // Maximum number of cached items
  CLEANUP_INTERVAL: 60 * 1000, // 1 minute cleanup interval
} as const;

/**
 * Network configuration
 */
export const NETWORK_CONFIG = {
  TIMEOUT: 5000, // 5 seconds
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000, // 1 second
  RATE_LIMIT: {
    MAX_REQUESTS: 100, // per minute
    WINDOW_SIZE: 60 * 1000, // 1 minute window
  },
} as const;

/**
 * Parallel processing configuration
 */
export const PARALLEL_CONFIG = {
  MAX_WORKERS: 8,
  CHUNK_SIZE: 10,
  TIMEOUT: 30000, // 30 seconds
  RETRY_ATTEMPTS: 2,
  MIN_CHUNK_SIZE: 5,
  MAX_CHUNK_SIZE: 20,
} as const;

/**
 * File processing configuration
 */
export const FILE_CONFIG = {
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_FILES_PER_PACKAGE: 1000,
  SCAN_TIMEOUT: 30000, // 30 seconds per file
} as const;

/**
 * Risk scoring configuration (composite C/I/A model)
 */
export const RISK_CONFIG = {
  SEVERITY_SCORES: {
    CRITICAL: 1.0,
    HIGH: 0.75,
    MEDIUM: 0.5,
    LOW: 0.25,
  } as Record<string, number>,
  CATEGORY_WEIGHTS: {
    confidentiality: 0.35,
    integrity: 0.45,
    availability: 0.2,
  } as Record<string, number>,
} as const;

/**
 * Entropy thresholds for different content types
 */
export const ENTROPY_THRESHOLDS = {
  JAVASCRIPT: 4.5,
  JSON: 3.0,
  TEXT: 2.5,
  BINARY: 6.0,
  DEFAULT: 4.0,
} as const;

/**
 * Detection patterns and configurations
 */
export const DETECTION_PATTERNS = {
  // Config file patterns
  CONFIG_FILE_PATTERNS: [
    '.eslintrc.js',
    '.eslintrc.json',
    '.eslintrc.yaml',
    '.eslintrc.yml',
    'jest.config.js',
    'jest.config.json',
    'webpack.config.js',
    'rollup.config.js',
    'vite.config.js',
    'babel.config.js',
    '.babelrc.js',
    'tsconfig.json',
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    '.gitignore',
    '.gitattributes',
    'Dockerfile',
    'docker-compose.yml',
    'docker-compose.yaml',
    '.dockerignore',
    'Makefile',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CODE_OF_CONDUCT.md',
  ] as string[],

  // Additional config file patterns (dot files, config extensions, etc.)
  DOT_FILE_PATTERNS: [
    '.env',
    '.env.local',
    '.env.development',
    '.env.production',
    '.env.test',
    '.gitignore',
    '.gitattributes',
    '.editorconfig',
    '.prettierrc',
    '.prettierrc.js',
    '.prettierrc.json',
    '.prettierrc.yaml',
    '.prettierrc.yml',
    '.eslintignore',
    '.npmignore',
    '.dockerignore',
    '.gitkeep',
    '.keep',
  ] as string[],

  // Config file extensions
  CONFIG_EXTENSIONS: ['.config.js', '.config.json', '.config.yaml', '.config.yml'] as string[],

  // Graphics/WebGL related file patterns
  GRAPHICS_FILE_PATTERNS: ['three', 'webgl', 'shader', 'graphics', 'render', 'canvas'] as string[],

  // Directory patterns to exclude
  EXCLUDED_DIRECTORIES: ['node_modules/', '.git/'] as string[],

  // Legitimate code patterns
  LEGITIMATE_PATTERNS: [
    /module\.exports\s*=\s*[^;]+;\s*/, // module.exports = ...;
    /exports\s*=\s*[^;]+;\s*/, // exports = ...;
    /return\s+[^;]+;\s*/, // return ...;
    /const\s+\w+\s*=\s*[^;]+;\s*/, // const ... = ...;
    /let\s+\w+\s*=\s*[^;]+;\s*/, // let ... = ...;
    /var\s+\w+\s*=\s*[^;]+;\s*/, // var ... = ...;
    /module\.exports\s*=\s*\w+;?\s*/, // module.exports = router; (with optional semicolon)
    /exports\s*=\s*\w+;?\s*/, // exports = router; (with optional semicolon)
  ],

  // Malware detection patterns
  MALWARE_PATTERNS: {
    // Variable mangling patterns
    VARIABLE_MANGLING: /const\s+[a-z]+\d*\s*=\s*[A-Za-z0-9]+\s*,\s*[a-z]+\d*\s*=\s*[A-Za-z0-9]+/,
    VARIABLE_MANGLING_SIMPLE: /const\s+[a-z]\d+\s*=\s*[A-Z]/, // const b3=I
    VAR_MANGLING: /var\s+[a-z]\d+\s*=\s*[A-Z]/, // var b3=I
    LET_MANGLING: /let\s+[a-z]\d+\s*=\s*[A-Z]/, // let b3=I

    // Obfuscation patterns
    HEX_ARRAYS: /\[(0x[0-9a-fA-F]+,\s*){3,}/g,
    BASE64_ARRAYS: /\[('[A-Za-z0-9+/=]{8,}',\s*){5,}/,
    STRING_FROM_CHARCODE: /String\.fromCharCode\s*\(/,
    BASE64_DECODE: /atob\s*\(/,
    BASE64_ENCODE: /btoa\s*\(/,

    // Module export patterns
    MODULE_EXPORT_MALICIOUS: /module\.exports\s*=\s*[^;]+;\s*const\s+[a-z]\d+\s*=\s*[A-Z]/g,
    MASSIVE_BLOB: /.{5000,}/,
    MODULE_APPEND: /module\.exports\s*=\s*[^;]+;\s*[^;]{1000,}/,
  },

  // Suspicious function patterns
  SUSPICIOUS_FUNCTIONS: [
    /function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{\s*const\s+\w+\s*=\s*\w+/, // Suspicious functions
    /eval\s*\(/, // eval calls
    /new\s+Function\s*\(/, // Function constructor
    /setTimeout\s*\(\s*['"`]/, // setTimeout with string
    /setInterval\s*\(\s*['"`]/, // setInterval with string
  ],

  // Dynamic module loading patterns
  DYNAMIC_REQUIRES: [
    /require\s*\(\s*['"`][^'"`]*['"`]\s*\)/, // Dynamic requires
    /import\s*\(\s*['"`][^'"`]*['"`]\s*\)/, // Dynamic imports
    /__webpack_require__\s*\(/, // Webpack requires
    /System\.import\s*\(/, // System.import
  ],

  // Wallet hijacking patterns
  WALLET_HIJACKING: [
    /window\.ethereum\s*=\s*new\s+Proxy/, // Ethereum proxy
    /Object\.defineProperty\s*\(\s*window\s*,\s*['"`]ethereum/, // Ethereum property override
    /window\.__defineGetter__\s*\(\s*['"`]ethereum/, // Ethereum getter override
    /eth_sendTransaction.*?params.*?to\s*[:=]/, // Transaction manipulation
    /eth_requestAccounts.*?params.*?from\s*[:=]/, // Account request manipulation
    /web3\.eth\.sendTransaction/, // Web3 transaction sending
    /ethereum\.request.*?method.*?['"`]eth_sendTransaction['"`]/, // Ethereum RPC calls
    /wallet.*?address.*?replace/, // Address replacement
    /private.*?key.*?extract/, // Private key extraction
    /mnemonic.*?phrase.*?steal/, // Mnemonic phrase theft
    /seed.*?phrase.*?extract/, // Seed phrase extraction
  ],

  // IOC (Indicators of Compromise) patterns
  IOC_PATTERNS: {
    URLS: /https?:\/\/[^\s'"]+/g,
    IPS: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    DOMAINS: /\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g,
  },

  // Shader patterns for GLSL detection
  SHADER_PATTERNS: [
    // Vertex shader patterns
    /attribute\s+\w+\s+\w+;/g,
    /uniform\s+\w+\s+\w+;/g,
    /varying\s+\w+\s+\w+;/g,
    /gl_Position\s*=/g,
    /gl_PointSize\s*=/g,

    // Fragment shader patterns
    /precision\s+\w+\s+\w+;/g,
    /gl_FragColor\s*=/g,
    /gl_FragCoord/g,
    /gl_FragDepth\s*=/g,

    // Common GLSL functions
    /texture2D\s*\(/g,
    /textureCube\s*\(/g,
    /mix\s*\(/g,
    /smoothstep\s*\(/g,
    /clamp\s*\(/g,
    /normalize\s*\(/g,
    /dot\s*\(/g,
    /cross\s*\(/g,
    /reflect\s*\(/g,
    /refract\s*\(/g,

    // GLSL types
    /vec[234]\s/g,
    /mat[234]\s/g,
    /sampler2D/g,
    /samplerCube/g,
    /sampler2DShadow/g,
  ],

  // Three.js patterns for WebGL framework detection
  THREE_JS_PATTERNS: [
    // Three.js imports
    /import\s+.*\s+from\s+['"]three['"]/g,
    /import\s+\*\s+as\s+THREE\s+from\s+['"]three['"]/g,
    /require\s*\(\s*['"]three['"]\s*\)/g,

    // Three.js class usage patterns
    /new\s+THREE\.\w+\(/g,
    /THREE\.\w+\.prototype/g,
    /extends\s+THREE\.\w+/g,

    // Three.js specific methods and properties
    /\.add\s*\(/g, // scene.add, group.add
    /\.position\s*=/g,
    /\.rotation\s*=/g,
    /\.scale\s*=/g,
    /\.material\s*=/g,
    /\.geometry\s*=/g,
    /\.render\s*\(/g,
    /\.setSize\s*\(/g,
    /\.setClearColor\s*\(/g,
  ],

  // Other graphics framework patterns
  OTHER_FRAMEWORK_PATTERNS: [
    /import.*from\s+['"]babylonjs['"]/g,
    /import.*from\s+['"]@babylonjs['"]/g,
    /import.*from\s+['"]pixi\.js['"]/g,
    /import.*from\s+['"]@pixi['"]/g,
    /import.*from\s+['"]aframe['"]/g,
    /import.*from\s+['"]react-three-fiber['"]/g,
  ],

  // React patterns for framework detection
  REACT_PATTERNS: [
    // React imports
    /import\s+.*\s+from\s+['"]react['"]/g,
    /import\s+.*\s+from\s+['"]react-router-dom['"]/g,
    /import\s+.*\s+from\s+['"]react-dom['"]/g,
    /import\s+.*\s+from\s+['"]@reduxjs\/toolkit['"]/g,
    /import\s+.*\s+from\s+['"]react-redux['"]/g,

    // React hooks
    /useState\s*\(/g,
    /useEffect\s*\(/g,
    /useNavigate\s*\(/g,
    /useLocation\s*\(/g,
    /useParams\s*\(/g,
    /useCallback\s*\(/g,
    /useMemo\s*\(/g,
    /useRef\s*\(/g,
    /useContext\s*\(/g,

    // React component patterns
    /className\s*=/g,
    /onClick\s*=/g,
    /onChange\s*=/g,
    /onSubmit\s*=/g,
    /onKeyDown\s*=/g,
    /onKeyUp\s*=/g,
    /style\s*=\s*{/g,

    // JSX patterns
    /<[A-Z]\w+/g, // JSX components
    /<\/[A-Z]\w+>/g, // JSX closing tags
    /<div\s/g,
    /<span\s/g,
    /<p\s/g,
    /<button\s/g,
    /<input\s/g,

    // React patterns
    /\.map\s*\(/g,
    /return\s*\(/g,
    /export\s+default/g,
    /React\.createElement/g,
    /React\.Component/g,

    // Simple React component patterns
    /export\s+const\s+\w+\s*=\s*\(\)\s*=>/g, // export const Component = () =>
    /export\s+default\s+\w+/g, // export default Component
    /<[A-Z]\w+\s*\/>/g, // <Component />
    /<[A-Z]\w+>/g, // <Component>
    /<\/[A-Z]\w+>/g, // </Component>
  ],

  // Shader string pattern for detecting GLSL in strings
  SHADER_STRING_PATTERN:
    /['"`]([^'"`]*\b(?:attribute|uniform|varying|precision|gl_Position|gl_FragColor|texture2D|vec[234]|mat[234])\b[^'"`]*)['"`]/g,

  // Utility/Math function patterns for legitimate code detection
  UTILITY_FUNCTION_PATTERNS: [
    // Math utility functions
    /Math\.(random|ceil|floor|round|abs|sin|cos|tan|sqrt|pow|PI|E)/g,
    // Random number generation patterns
    /Math\.random\s*\(\s*\)\s*\*\s*\d+/g,
    /Math\.ceil\s*\(\s*Math\.random/g,
    /Math\.floor\s*\(\s*Math\.random/g,
    // Common utility patterns
    /export\s+const\s+\w+\s*=\s*\([^)]*\)\s*=>/g,
    /const\s+\w+\s*=\s*\([^)]*\)\s*=>/g,
    // Angle/radian conversions
    /rad\s*\*\s*180\s*\/\s*Math\.PI/g,
    /ang\s*\*\s*Math\.PI\s*\/\s*180/g,
    // Matrix/index calculations
    /indexOf\s*\(/g,
    /rowIndex|colIndex/g,
    // Point/mesh calculations
    /point[12]\.(x|y|z)/g,
    /meshPosition|tileSize/g,
  ],

  // React/Testing patterns for legitimate code detection
  REACT_TESTING_PATTERNS: [
    // React performance monitoring
    /web-vitals/g,
    /getCLS|getFID|getFCP|getLCP|getTTFB/g,
    /reportWebVitals/g,
    /onPerfEntry/g,
    // Jest testing patterns
    /@testing-library/g,
    /jest-dom/g,
    /setupTests/g,
    /expect\s*\(/g,
    /toHaveTextContent/g,
    // React testing patterns
    /testing-library\/jest-dom/g,
    /github\.com\/testing-library/g,
  ],

  // Blockchain/Contract patterns for legitimate code detection
  BLOCKCHAIN_PATTERNS: [
    // Contract addresses
    /0x[a-fA-F0-9]{40}/g,
    /contractAddress/g,
    /chainId/g,
    /export const \w+ContractAddress/g,
    /export const \w+RewardContractAddress/g,
    // Blockchain patterns
    /ethereum|ethers|web3/g,
    /blockchain|crypto/g,
    /wallet|metamask/g,
  ],

  // Node.js/Socket.IO server patterns for legitimate code detection
  SERVER_PATTERNS: [
    // Socket.IO patterns
    /socket\.on\s*\(\s*['"`]\w+['"`]/g,
    /socket\.emit\s*\(\s*['"`]\w+['"`]/g,
    /socket\.broadcast/g,
    /socket\.join\s*\(/g,
    /socket\.leave\s*\(/g,
    /io\.sockets/g,
    /io\.sockets\.on\s*\(\s*['"`]connection['"`]/g,
    /io\.sockets\.to\s*\(/g,
    /io\.sockets\.emit/g,
    // Express.js patterns
    /app\.use\s*\(/g,
    /app\.set\s*\(/g,
    /app\.get\s*\(/g,
    /express\.static/g,
    /require\s*\(\s*['"`]express['"`]/g,
    /require\s*\(\s*['"`]socket\.io['"`]/g,
    // HTTP server patterns
    /http\.createServer/g,
    /\.listen\s*\(/g,
    // Database patterns
    /mongoose\.connect/g,
    /mongoose\.connection/g,
    /\.connection\.on\s*\(/g,
    /config\.get\s*\(/g,
    /require\s*\(\s*['"`]config['"`]/g,
    /require\s*\(\s*['"`]mongoose['"`]/g,
    /MongoDB|mongodb/g,
    /database|db\./g,
    // Mongoose schema patterns
    /mongoose\.Schema/g,
    /mongoose\.model/g,
    /Schema\s*\(/g,
    /\.methods\s*=/g,
    /\.authenticate\s*\(/g,
    /encrypt\s*\(/g,
    /plainText|password/g,
    // Common server event names
    /['"`](join|move|disconnect|resign|set-piece|remove-piece|ai-move|moves)['"`]/g,
    // Object manipulation patterns
    /Object\.keys\s*\(/g,
    /Object\.values\s*\(/g,
    /Object\.entries\s*\(/g,
    // Game/room management
    /games\[/g,
    /room\s*in\s*games/g,
    /players\[/g,
    /\.status\s*=/g,
    /\.socket\s*=/g,
  ],

  // Socket/Network event mapping patterns
  SOCKET_EVENT_PATTERNS: [
    // Socket event mappings with hex values
    /['"`]\w+['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    // Common socket event prefixes
    /['"`](CS_|SC_|WS_|WS_|EVENT_|MSG_)\w+['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    // Network protocol constants
    /['"`]\w*[Ss]ocket\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    /['"`]\w*[Ee]vent\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    /['"`]\w*[Mm]essage\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    /['"`]\w*[Pp]acket\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    // Game-specific patterns
    /['"`]\w*[Gg]ame\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    /['"`]\w*[Rr]oom\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    /['"`]\w*[Mm]ove\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
    /['"`]\w*[Pp]iece\w*['"`]\s*:\s*0x[0-9a-fA-F]+/g,
  ],

  // React library imports for framework detection
  REACT_IMPORTS: [
    'react',
    'react-dom',
    'react-router-dom',
    '@reduxjs/toolkit',
    'react-redux',
    'react-router',
    'react-hook-form',
    'styled-components',
    '@emotion/react',
    '@emotion/styled',
  ],

  // Graphics library imports for legitimate code detection
  GRAPHICS_IMPORTS: [
    'three',
    'babylonjs',
    '@babylonjs',
    'pixi.js',
    '@pixi',
    'aframe',
    'react-three-fiber',
    'webgl-utils',
    'gl-matrix',
    'regl',
    'twgl',
  ],

  // Suspicious modules that might indicate malicious code
  SUSPICIOUS_MODULES: ['fs', 'child_process', 'eval', 'vm'] as string[],

  // Wallet-related keywords for crypto threat detection
  WALLET_KEYWORDS: [
    'ethereum',
    'bitcoin',
    'wallet',
    'crypto',
    'blockchain',
    'metamask',
    'web3',
    'transaction',
    'address',
    'private',
    'key',
    'seed',
    'mnemonic',
    'hdwallet',
    'trezor',
    'ledger',
  ] as string[],

  // Suspicious file extensions
  SUSPICIOUS_EXTENSIONS: [
    '.exe',
    '.scr',
    '.bat',
    '.cmd',
    '.com',
    '.pif',
    '.vbs',
    '.js',
  ] as string[],

  // Popular packages for dependency confusion detection
  POPULAR_PACKAGES: ['react', 'lodash', 'express', 'axios', 'moment'] as string[],

  // NullVoid project files to exclude from detection
  NULLVOID_FILES: [
    'scan.js',
    'scan.ts',
    'rules.js',
    'rules.ts',
    'benchmarks.js',
    'benchmarks.ts',
    'cache.js',
    'cache.ts',
    'detection.js',
    'detection.ts',
    'validation.js',
    'validation.ts',
    'logger.js',
    'logger.ts',
    'config.js',
    'config.ts',
    'nullvoid.js',
    'nullvoid.ts',
    'errorHandler.js',
    'errorHandler.ts',
    'parallel.js',
    'parallel.ts',
    'rateLimiter.js',
    'rateLimiter.ts',
    'sandbox.js',
    'sandbox.ts',
    'pathSecurity.js',
    'pathSecurity.ts',
    'dependencyConfusion.js',
    'dependencyConfusion.ts',
    'nullvoidDetection.js',
    'nullvoidDetection.ts',
    'sarif.js',
    'sarif.ts',
    'secureErrorHandler.js',
    'secureErrorHandler.ts',
    'streaming.js',
    'streaming.ts',
    'colors.js',
    'colors.ts',
    'generate-badge.js',
    'generate-badge.ts',
    'package.json',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CODE_OF_CONDUCT.md',
    'TYPESCRIPT_MIGRATION_TODO.md',
    'TYPESCRIPT_MIGRATION_GUIDE.md',
    'dependencyTree.ts',
    'package.ts',
    'analysis-types.ts',
    'config-types.ts',
    'core.ts',
    'error-types.ts',
    'index.ts',
    'package-types.ts',
    'threat-types.ts',
    'jest.config.js',
  ] as string[],

  // Security patterns
  SECURITY_PATTERNS: {
    // Suspicious code patterns
    SUSPICIOUS_CODE: [
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /setTimeout\s*\(\s*['"`]/gi,
      /setInterval\s*\(\s*['"`]/gi,
      /document\.write\s*\(/gi,
      /innerHTML\s*=/gi,
      /outerHTML\s*=/gi,
      /insertAdjacentHTML\s*\(/gi,
    ],

    // Dangerous function names
    DANGEROUS_FUNCTIONS: [
      'eval',
      'Function',
      'setTimeout',
      'setInterval',
      'setImmediate',
      'process.nextTick',
      'require',
      'import',
      'exec',
      'spawn',
      'execFile',
    ],

    // Network-related patterns
    NETWORK_PATTERNS: [
      /fetch\s*\(/gi,
      /XMLHttpRequest/gi,
      /axios/gi,
      /request/gi,
      /http\./gi,
      /https\./gi,
      /net\./gi,
      /tls\./gi,
    ],

    // File system patterns
    FILE_SYSTEM_PATTERNS: [
      /fs\./gi,
      /readFile/gi,
      /writeFile/gi,
      /unlink/gi,
      /mkdir/gi,
      /rmdir/gi,
      /chmod/gi,
      /chown/gi,
    ],

    // Malicious patterns (consolidated from VALIDATION_CONFIG)
    MALICIOUS_PATTERNS: [
      /malware/gi,
      /virus/gi,
      /trojan/gi,
      /backdoor/gi,
      /keylogger/gi,
      /spyware/gi,
      /rootkit/gi,
      /botnet/gi,
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /document\.write/gi,
      /innerHTML\s*=/gi,
      /outerHTML\s*=/gi,
      /insertAdjacentHTML/gi,
      /setTimeout\s*\(\s*['"`]/gi,
      /setInterval\s*\(\s*['"`]/gi,
    ],

    // Dangerous patterns (consolidated from VALIDATION_CONFIG)
    DANGEROUS_PATTERNS: [
      /<script/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /data:text\/html/gi,
      /onload\s*=/gi,
      /onerror\s*=/gi,
      /onclick\s*=/gi,
    ],

    // Dangerous file names
    DANGEROUS_FILES: [
      'malware.js',
      'virus.js',
      'trojan.js',
      'backdoor.js',
      'keylogger.js',
      'spyware.js',
      'rootkit.js',
      'botnet.js',
    ],

    // Suspicious scripts
    SUSPICIOUS_SCRIPTS: [
      'curl http',
      'wget http',
      'rm -rf',
      'chmod 777',
      'chown root',
      'sudo',
      'su -',
      'passwd',
      'useradd',
      'userdel',
    ],
  },

  // Validation patterns
  VALIDATION_PATTERNS: {
    PACKAGE_NAME: /^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/,
    LOCAL_PATH: /^[a-zA-Z0-9._/-]+$/,
    SEMVER:
      /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,

    // Path traversal patterns
    TRAVERSAL_PATTERNS: [
      /\.\.\//g,
      /\.\.\\/g,
      /\.\.%2f/gi,
      /\.\.%5c/gi,
      /\.\.%252f/gi,
      /\.\.%255c/gi,
    ],
  },

  // Validation configuration
  VALIDATION_CONFIG: {
    PACKAGE_NAME_MAX_LENGTH: 214,
    PACKAGE_NAME_MIN_LENGTH: 1,
    VALID_FORMATS: ['json', 'table', 'yaml', 'sarif'],
    VALID_OUTPUT_FORMATS: ['json', 'table', 'yaml', 'sarif', 'html', 'markdown'],
    ALLOWED_EXTENSIONS: ['.js', '.mjs', '.ts', '.jsx', '.tsx', '.json'],
  },
} as const;

/**
 * Test patterns configuration
 */
export const TEST_PATTERNS_CONFIG = {
  JEST_OUTPUT_PATTERNS: {
    PASSED: /✓ (.+)/g,
    FAILED: /✗ (.+)/g,
    SKIPPED: /○ (.+)/g,
    TOTAL: /Tests:\s*(\d+)\s*(?:passed|failed|skipped)/g,
    SUMMARY: /Test Suites: (.+)\s*Tests: (.+)\s*Snapshots: (.+)\s*Time: (.+)/,
  },

  BADGE_REGEX: /!\[([^\]]*)\]\(([^)]+)\)/g,
} as const;

/**
 * Dependency confusion configuration
 */
export const DEPENDENCY_CONFUSION_CONFIG = {
  TIMELINE_THRESHOLDS: {
    SUSPICIOUS_AGE_DAYS: 7,
    RAPID_PUBLISHING_HOURS: 24,
    VERSION_GAP_DAYS: 30,
    CRITICAL: 1,
    HIGH_RISK: 3,
    SUSPICIOUS: 7,
  },

  SIMILARITY_THRESHOLDS: {
    HIGH_SIMILARITY: 0.8,
    MEDIUM_SIMILARITY: 0.6,
    LOW_SIMILARITY: 0.4,
  },

  SCOPE_PATTERNS: {
    PRIVATE_SCOPES: [/^@[a-z0-9-]+\/[a-z0-9._-]+$/, /^@[a-z0-9-]+$/],
    PUBLIC_SCOPES: [/^[a-z0-9._-]+$/],
  },

  SUSPICIOUS_NAME_PATTERNS: [
    /^[a-z0-9]{32,}$/, // Random-looking names
    /malware/i,
    /virus/i,
    /trojan/i,
    /backdoor/i,
    /keylogger/i,
    /spyware/i,
    /rootkit/i,
    /botnet/i,
  ],

  REGISTRY_ENDPOINTS: {
    npm: 'https://registry.npmjs.org',
    yarn: 'https://registry.yarnpkg.com',
    github: 'https://npm.pkg.github.com',
  },

  REGISTRIES: {
    DEFAULT_ORDER: ['npm', 'yarn', 'github'],
    CUSTOM: [] as Array<{ name: string; url: string; auth?: string }>,
  },

  ANALYSIS_SETTINGS: {
    MAX_GIT_COMMITS: 100,
    MAX_PACKAGE_VERSIONS: 50,
    TIMEOUT_MS: 10000,
    RETRY_ATTEMPTS: 3,
  },

  ML_DETECTION: {
    MULTI_REGISTRY: true,
    TIMELINE_ANOMALY: true,
    ML_SCORING: true,
    ML_ANOMALY_THRESHOLD: 0.7,
    ML_WEIGHTS: {
      timelineAnomaly: 0.4,
      scopePrivate: 0.15,
      suspiciousPatterns: 0.15,
      lowActivityRecent: 0.08,
      commitPatternAnomaly: 0.08,
      nlpSecurityScore: 0.08,
      crossPackageAnomaly: 0.03,
      behavioralAnomaly: 0.03,
      reviewSecurityScore: 0.05,
      popularityScore: 0.02,
      trustScore: 0.05,
    },
    ML_MODEL_URL: null,
    ML_MODEL_PATH: null,
    BEHAVIORAL_MODEL_URL: null as string | null,
    COMMIT_PATTERN_ANALYSIS: true,
  },
} as const;

/**
 * Popular frameworks and libraries
 */
export const POPULAR_FRAMEWORKS = [
  'react',
  'vue',
  'angular',
  'express',
  'koa',
  'fastify',
  'next',
  'nuxt',
  'gatsby',
  'webpack',
  'rollup',
  'vite',
  'parcel',
  'babel',
  'typescript',
  'eslint',
  'prettier',
  'jest',
  'mocha',
  'cypress',
  'playwright',
  'puppeteer',
] as const;

/**
 * Main configuration objects
 */
export const SCAN_CONFIG: ScanConfig = {
  maxFileSize: FILE_CONFIG.MAX_FILE_SIZE,
  maxTimeout: FILE_CONFIG.SCAN_TIMEOUT,
  enableSandbox: true,
  sandboxTimeout: 100,
  maxMemory: 128 * 1024 * 1024, // 128MB
  enableParallel: true,
  maxWorkers: PARALLEL_CONFIG.MAX_WORKERS,
};

export const SECURITY_CONFIG: SecurityConfig = {
  allowedExtensions: [...DETECTION_PATTERNS.VALIDATION_CONFIG.ALLOWED_EXTENSIONS],
  blockedPatterns: DETECTION_PATTERNS.SECURITY_PATTERNS.MALICIOUS_PATTERNS.map((p) => p.source),
  suspiciousPatterns: DETECTION_PATTERNS.SECURITY_PATTERNS.MALICIOUS_PATTERNS.map((p) => p.source),
  dangerousFunctions: [...DETECTION_PATTERNS.SECURITY_PATTERNS.DANGEROUS_FUNCTIONS],
  networkPatterns: DETECTION_PATTERNS.SECURITY_PATTERNS.NETWORK_PATTERNS.map((p) => p.source),
  fileSystemPatterns: DETECTION_PATTERNS.SECURITY_PATTERNS.FILE_SYSTEM_PATTERNS.map(
    (p) => p.source
  ),
};

export const PERFORMANCE_CONFIG: PerformanceConfig = {
  cacheTtl: CACHE_CONFIG.TTL,
  maxCacheSize: CACHE_CONFIG.MAX_SIZE,
  rateLimit: {
    requests: NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS,
    window: NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE,
  },
  timeouts: {
    network: NETWORK_CONFIG.TIMEOUT,
    file: FILE_CONFIG.SCAN_TIMEOUT,
    analysis: FILE_CONFIG.SCAN_TIMEOUT,
  },
};

/**
 * IoC Integration Configuration
 */
export const IOC_CONFIG = {
  // Provider enable/disable flags
  PROVIDERS: {
    snyk: {
      enabled: false, // Requires API key
      apiKey: process.env['SNYK_API_KEY'],
      rateLimit: 60,
      cacheTTL: 60 * 60 * 1000, // 1 hour
      timeout: 10000,
      maxRetries: 3,
      retryDelay: 1000,
    },
    npm: {
      enabled: true, // Public API
      rateLimit: 100,
      cacheTTL: 60 * 60 * 1000, // 1 hour
      timeout: 10000,
      maxRetries: 3,
      retryDelay: 1000,
    },
    ghsa: {
      enabled: true, // Public API (better rate limits with token)
      apiKey: process.env['GITHUB_TOKEN'],
      rateLimit: 60, // 60/hour without auth, 5000/hour with auth
      cacheTTL: 60 * 60 * 1000, // 1 hour
      timeout: 15000,
      maxRetries: 3,
      retryDelay: 1000,
    },
    cve: {
      enabled: true, // Public API
      apiKey: process.env['NVD_API_KEY'], // Optional, increases rate limits
      rateLimit: 50, // 50 per 30 seconds
      cacheTTL: 24 * 60 * 60 * 1000, // 24 hours
      timeout: 15000,
      maxRetries: 3,
      retryDelay: 2000,
    },
  },
  // Default query options
  DEFAULT_QUERY_OPTIONS: {
    includeHistory: false,
    maxResults: 50,
  },
  // Aggregation settings
  AGGREGATION: {
    // Deduplicate results from multiple providers
    deduplicate: true,
    // Prefer provider order (first provider's result takes precedence)
    providerPriority: ['snyk', 'npm', 'ghsa', 'cve'] as const,
  },
  // Use multi-layer cache (L1+L2, optional L3 Redis) for IoC results when true; else single LRU
  USE_MULTI_LAYER_CACHE: process.env['NULLVOID_IOC_MULTI_LAYER_CACHE']?.toLowerCase() === 'true',
} as const;

/**
 * Multi-Layer Cache Configuration
 */
export const CACHE_LAYER_CONFIG = {
  // L1 (Memory) cache
  L1: {
    enabled: true,
    maxSize: 1000, // Maximum number of items
    defaultTTL: 5 * 60 * 1000, // 5 minutes
    cleanupInterval: 60 * 1000, // 1 minute
  },
  // L2 (File) cache
  L2: {
    enabled: true,
    cacheDir: process.env['NULLVOID_CACHE_DIR'] || '.nullvoid-cache',
    maxSize: 100 * 1024 * 1024, // 100MB
    defaultTTL: 60 * 60 * 1000, // 1 hour
    cleanupInterval: 5 * 60 * 1000, // 5 minutes
    compression: true,
  },
  // L3 (Redis) cache
  L3: {
    enabled: false, // Disabled by default
    redisUrl: process.env['REDIS_URL'],
    host: process.env['REDIS_HOST'] || 'localhost',
    port: parseInt(process.env['REDIS_PORT'] || '6379', 10),
    password: process.env['REDIS_PASSWORD'],
    db: parseInt(process.env['REDIS_DB'] || '0', 10),
    poolSize: 10,
    connectTimeout: 5000,
    defaultTTL: 24 * 60 * 60 * 1000, // 24 hours
    cleanupInterval: 60 * 60 * 1000, // 1 hour
  },
  // Promotion/demotion strategy
  PROMOTION_STRATEGY: {
    promoteAfterAccesses: 3,
    demoteAfterMisses: 5,
    timeBasedPromotion: true,
  },
  // Cache warming
  WARMING: {
    enabled: false,
    warmOnStartup: false,
    preloadPatterns: [] as string[],
    strategy: 'on-demand' as 'aggressive' | 'conservative' | 'on-demand',
  },
} as const;

/**
 * Network Optimization Configuration
 */
export const NETWORK_OPTIMIZATION_CONFIG = {
  // Connection pooling
  CONNECTION_POOL: {
    enabled: true,
    maxConnectionsPerDomain: 10,
    keepAliveTimeout: 60000, // 60 seconds
    connectTimeout: 5000, // 5 seconds
    idleTimeout: 30000, // 30 seconds
  },
  // Request batching
  REQUEST_BATCHING: {
    enabled: true,
    maxBatchSize: 20,
    maxWaitTime: 100, // 100ms
    batchTimeout: 5000, // 5 seconds
    priorityLevels: 3,
  },
  // Compression
  COMPRESSION: {
    enabled: true,
    algorithms: ['gzip', 'brotli'] as const,
    minSize: 1024, // 1KB
    level: 6, // Compression level 1-9
  },
  // CDN integration
  CDN: {
    enabled: false,
    baseUrl: undefined,
    fallbackToOrigin: true,
    respectCacheHeaders: true,
  },
} as const;

/**
 * Update configuration from environment variables
 */
export function updateConfigFromEnv(): void {
  // Update cache TTL from environment
  if (process.env['NULLVOID_CACHE_TTL']) {
    const ttl = parseInt(process.env['NULLVOID_CACHE_TTL'], 10);
    if (!isNaN(ttl) && ttl > 0) {
      (CACHE_CONFIG as Record<string, unknown>)['TTL'] = ttl;
    }
  }

  // Update network timeout from environment
  if (process.env['NULLVOID_NETWORK_TIMEOUT']) {
    const timeout = parseInt(process.env['NULLVOID_NETWORK_TIMEOUT'], 10);
    if (!isNaN(timeout) && timeout > 0) {
      (NETWORK_CONFIG as Record<string, unknown>)['TIMEOUT'] = timeout;
    }
  }

  // Update max workers from environment
  if (process.env['NULLVOID_MAX_WORKERS']) {
    const workers = parseInt(process.env['NULLVOID_MAX_WORKERS'], 10);
    if (!isNaN(workers) && workers > 0 && workers <= 32) {
      (PARALLEL_CONFIG as Record<string, unknown>)['MAX_WORKERS'] = workers;
    }
  }

  // Update dependency confusion settings
  if (process.env['NULLVOID_DEP_CONFUSION_ENABLED']) {
    const enabled = process.env['NULLVOID_DEP_CONFUSION_ENABLED'].toLowerCase() === 'true';
    (DEPENDENCY_CONFUSION_CONFIG as Record<string, unknown>)['ENABLED'] = enabled;
  }

  // Update IoC provider settings
  if (process.env['NULLVOID_IOC_SNYK_ENABLED']) {
    const enabled = process.env['NULLVOID_IOC_SNYK_ENABLED'].toLowerCase() === 'true';
    (IOC_CONFIG.PROVIDERS as Record<string, unknown>)['snyk'] = {
      ...IOC_CONFIG.PROVIDERS['snyk'],
      enabled,
    };
  }

  if (process.env['NULLVOID_IOC_NPM_ENABLED']) {
    const enabled = process.env['NULLVOID_IOC_NPM_ENABLED'].toLowerCase() === 'true';
    (IOC_CONFIG.PROVIDERS as Record<string, unknown>)['npm'] = {
      ...IOC_CONFIG.PROVIDERS['npm'],
      enabled,
    };
  }

  if (process.env['NULLVOID_IOC_GHSA_ENABLED']) {
    const enabled = process.env['NULLVOID_IOC_GHSA_ENABLED'].toLowerCase() === 'true';
    (IOC_CONFIG.PROVIDERS as Record<string, unknown>)['ghsa'] = {
      ...IOC_CONFIG.PROVIDERS['ghsa'],
      enabled,
    };
  }

  if (process.env['NULLVOID_IOC_CVE_ENABLED']) {
    const enabled = process.env['NULLVOID_IOC_CVE_ENABLED'].toLowerCase() === 'true';
    (IOC_CONFIG.PROVIDERS as Record<string, unknown>)['cve'] = {
      ...IOC_CONFIG.PROVIDERS['cve'],
      enabled,
    };
  }

  // Update cache layer settings
  if (process.env['NULLVOID_CACHE_L2_ENABLED']) {
    const enabled = process.env['NULLVOID_CACHE_L2_ENABLED'].toLowerCase() === 'true';
    (CACHE_LAYER_CONFIG.L2 as Record<string, unknown>)['enabled'] = enabled;
  }

  if (process.env['NULLVOID_CACHE_L3_ENABLED']) {
    const enabled = process.env['NULLVOID_CACHE_L3_ENABLED'].toLowerCase() === 'true';
    (CACHE_LAYER_CONFIG.L3 as Record<string, unknown>)['enabled'] = enabled;
  }

  // Update network optimization settings
  if (process.env['NULLVOID_CONNECTION_POOL_ENABLED']) {
    const enabled = process.env['NULLVOID_CONNECTION_POOL_ENABLED'].toLowerCase() === 'true';
    (NETWORK_OPTIMIZATION_CONFIG.CONNECTION_POOL as Record<string, unknown>)['enabled'] = enabled;
  }

  if (process.env['NULLVOID_REQUEST_BATCHING_ENABLED']) {
    const enabled = process.env['NULLVOID_REQUEST_BATCHING_ENABLED'].toLowerCase() === 'true';
    (NETWORK_OPTIMIZATION_CONFIG.REQUEST_BATCHING as Record<string, unknown>)['enabled'] = enabled;
  }

  if (process.env['NULLVOID_COMPRESSION_ENABLED']) {
    const enabled = process.env['NULLVOID_COMPRESSION_ENABLED'].toLowerCase() === 'true';
    (NETWORK_OPTIMIZATION_CONFIG.COMPRESSION as Record<string, unknown>)['enabled'] = enabled;
  }
}

// Export VALIDATION_CONFIG for backward compatibility
export const VALIDATION_CONFIG = {
  PACKAGE_NAME_PATTERN: DETECTION_PATTERNS.VALIDATION_PATTERNS.PACKAGE_NAME,
  PACKAGE_NAME_MAX_LENGTH: DETECTION_PATTERNS.VALIDATION_CONFIG.PACKAGE_NAME_MAX_LENGTH,
  PACKAGE_NAME_MIN_LENGTH: DETECTION_PATTERNS.VALIDATION_CONFIG.PACKAGE_NAME_MIN_LENGTH,
  VALID_FORMATS: DETECTION_PATTERNS.VALIDATION_CONFIG.VALID_FORMATS,
  VALID_OUTPUT_FORMATS: DETECTION_PATTERNS.VALIDATION_CONFIG.VALID_OUTPUT_FORMATS,
  SEMVER_PATTERN: DETECTION_PATTERNS.VALIDATION_PATTERNS.SEMVER,
  ALLOWED_EXTENSIONS: DETECTION_PATTERNS.VALIDATION_CONFIG.ALLOWED_EXTENSIONS,

  SUSPICIOUS_PATTERNS: DETECTION_PATTERNS.SECURITY_PATTERNS.MALICIOUS_PATTERNS,
  VALID_PACKAGE_NAME: DETECTION_PATTERNS.VALIDATION_PATTERNS.PACKAGE_NAME,
  VALID_LOCAL_PATH: DETECTION_PATTERNS.VALIDATION_PATTERNS.LOCAL_PATH,

  TRAVERSAL_PATTERNS: DETECTION_PATTERNS.VALIDATION_PATTERNS.TRAVERSAL_PATTERNS,

  DANGEROUS_PATTERNS: DETECTION_PATTERNS.SECURITY_PATTERNS.DANGEROUS_PATTERNS,

  MALICIOUS_PATTERNS: DETECTION_PATTERNS.SECURITY_PATTERNS.MALICIOUS_PATTERNS,

  DANGEROUS_FILES: DETECTION_PATTERNS.SECURITY_PATTERNS.DANGEROUS_FILES,

  SUSPICIOUS_SCRIPTS: DETECTION_PATTERNS.SECURITY_PATTERNS.SUSPICIOUS_SCRIPTS,
};

// Display/UI patterns for threat output formatting
export const DISPLAY_PATTERNS = {
  // Severity level patterns for coloring
  SEVERITY_PATTERNS: {
    CRITICAL: /CRITICAL/g,
    HIGH: /HIGH/g,
    MEDIUM: /MEDIUM/g,
    LOW: /LOW/g,
  },

  // Text cleaning patterns for threat details
  DETAILS_CLEANING_PATTERNS: {
    MALICIOUS_PREFIX: /MALICIOUS CODE DETECTED:\s*/g,
    CONFIDENCE: /Confidence: \d+%/g,
    THREAT_COUNT: /\(\d+ threats?\)/g,
    WHITESPACE: /\s+/g,
  },

  // Regex patterns for extracting specific information
  EXTRACTION_PATTERNS: {
    CONFIDENCE: /Confidence: \d+%/,
    THREAT_COUNT: /\(\d+ threats?\)/,
  },
};

/**
 * NLP Configuration (AI/ML)
 */
export const NLP_CONFIG = {
  ENABLED: process.env['NULLVOID_NLP_ENABLED']?.toLowerCase() === 'true',
  GITHUB_TOKEN: process.env['GITHUB_TOKEN'] || process.env['NULLVOID_GITHUB_TOKEN'] || null,
  MAX_ISSUES: 30,
  SKIP_IF_NO_REPO: true,
  TIMEOUT_MS: 10000,
} as const;

/**
 * IPFS Verification Configuration (Blockchain)
 */
export const IPFS_CONFIG = {
  ENABLED: process.env['NULLVOID_IPFS_ENABLED']?.toLowerCase() === 'true',
  GATEWAY_URL: process.env['NULLVOID_IPFS_GATEWAY'] || 'https://ipfs.io',
  PIN_SERVICE_URL: process.env['NULLVOID_IPFS_PIN_SERVICE_URL'] || null,
  PIN_SERVICE_TOKEN: process.env['NULLVOID_IPFS_PIN_SERVICE_TOKEN'] || null,
  ALGORITHM: 'sha2-256' as const,
} as const;

/**
 * Community Analysis Configuration (downloads, stars, maintenance)
 */
export const COMMUNITY_CONFIG = {
  ENABLED: process.env['NULLVOID_COMMUNITY_ENABLED']?.toLowerCase() === 'true',
  GITHUB_TOKEN: process.env['GITHUB_TOKEN'] || process.env['NULLVOID_GITHUB_TOKEN'] || null,
  TIMEOUT_MS: 10000,
  USE_DOWNLOADS: true,
  USE_GITHUB_STARS: true,
  USE_DEPENDENTS: false,
} as const;

/**
 * Trust Network Configuration
 */
export const TRUST_CONFIG = {
  ENABLED: process.env['NULLVOID_TRUST_ENABLED']?.toLowerCase() === 'true',
  TRUST_STORE_PATH: process.env['NULLVOID_TRUST_STORE_PATH'] || '~/.nullvoid/trust-store.json',
  TRANSITIVE_TRUST_WEIGHT: 0.3,
} as const;

/**
 * Blockchain Verification Configuration
 */
export const BLOCKCHAIN_CONFIG = {
  ENABLED: process.env['NULLVOID_BLOCKCHAIN_ENABLED']?.toLowerCase() === 'true',
  RPC_URL: process.env['NULLVOID_BLOCKCHAIN_RPC_URL'] || 'https://polygon-rpc.com',
  CONTRACT_ADDRESS: process.env['NULLVOID_BLOCKCHAIN_CONTRACT_ADDRESS'] || null,
  PRIVATE_KEY: process.env['NULLVOID_BLOCKCHAIN_PRIVATE_KEY'] || null,
  CHAIN_ID: parseInt(process.env['NULLVOID_BLOCKCHAIN_CHAIN_ID'] || '137', 10),
} as const;

/**
 * Consensus Verification Configuration
 */
export const CONSENSUS_CONFIG = {
  ENABLED: process.env['NULLVOID_CONSENSUS_ENABLED']?.toLowerCase() === 'true',
  SOURCES: ['npm', 'github', 'ipfs'] as const,
  MIN_AGREEMENT: 2,
  GITHUB_TOKEN: process.env['GITHUB_TOKEN'] || process.env['NULLVOID_GITHUB_TOKEN'] || null,
  GATEWAY_URL: process.env['NULLVOID_IPFS_GATEWAY'] || 'https://ipfs.io',
} as const;

// Initialize configuration from environment
updateConfigFromEnv();

// Load .nullvoidrc (project-specific overrides for DEPENDENCY_CONFUSION_CONFIG)
loadNullvoidRc();
