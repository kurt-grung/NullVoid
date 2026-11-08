# 🔄 TypeScript Migration Guide

## 📖 Overview

This guide provides a comprehensive roadmap for migrating the NullVoid project from JavaScript to TypeScript. The migration involves converting 11 critical modules from the legacy JavaScript codebase to TypeScript while maintaining full functionality and improving type safety.

---

## 🎯 Migration Goals

### Primary Objectives
- **Type Safety**: Add comprehensive TypeScript types throughout the codebase
- **Code Quality**: Improve maintainability and reduce runtime errors
- **Performance**: Maintain or improve performance compared to legacy version
- **Developer Experience**: Enhanced IDE support and better debugging
- **Future-Proofing**: Modern JavaScript/TypeScript ecosystem compatibility

### Success Metrics
- ✅ 100% TypeScript compilation success
- ✅ All existing functionality preserved
- ✅ Performance within 10% of legacy version
- ✅ Test coverage > 90%
- ✅ Zero runtime errors
- ✅ Full CLI functionality

---

## 🏗️ Architecture Overview

### Current State Analysis
```
Legacy JavaScript (Complete)          TypeScript (Partial)
├── scan.js (3,525 lines)           ├── scan.ts (685 lines)
├── lib/ (18 modules)                ├── src/lib/ (13 modules)
│   ├── logger.js ✅                 │   ├── config.ts ✅
│   ├── cache.js ✅                  │   ├── detection.ts ✅
│   ├── errorHandler.js ✅           │   ├── nullvoidDetection.ts ⚠️
│   ├── parallel.js ✅                │   ├── sarif.ts ✅
│   ├── rateLimiter.js ✅            │   ├── secureErrorHandler.ts ⚠️
│   ├── validation.js ✅             │   └── [8 new modules] ✅
│   ├── sandbox.js ✅                └── dist/ (compiled output)
│   ├── pathSecurity.js ✅
│   ├── dependencyConfusion.js ✅
│   ├── benchmarks.js ✅
│   ├── streaming.js ✅
│   ├── rules.js ✅
│   └── [5 other modules] ✅
```

### Target Architecture
```
TypeScript Project (Complete)
├── src/
│   ├── scan.ts (full functionality)
│   ├── bin/nullvoid.ts
│   ├── colors.ts
│   ├── package.ts
│   ├── lib/ (24 modules)
│   │   ├── logger.ts ✅
│   │   ├── cache.ts ✅
│   │   ├── errorHandler.ts ✅
│   │   ├── parallel.ts ✅
│   │   ├── rateLimiter.ts ✅
│   │   ├── validation.ts ✅
│   │   ├── sandbox.ts ✅
│   │   ├── pathSecurity.ts ✅
│   │   ├── dependencyConfusion.ts ✅
│   │   ├── benchmarks.ts ✅
│   │   ├── streaming.ts ✅
│   │   ├── rules.ts ✅
│   │   └── [existing modules] ✅
│   ├── types/ (type definitions)
│   └── test/ (TypeScript tests)
├── dist/ (compiled JavaScript)
└── package.json (TypeScript configuration)
```

---

## 📋 Migration Stages

### Stage 1: Critical Infrastructure (Week 1)
**Priority**: 🚨 CRITICAL  
**Estimated Time**: 15-21 hours  
**Dependencies**: None

#### 1.1 Logger Module (`logger.js` → `logger.ts`)
```typescript
// Target Structure
export interface LogLevel {
  ERROR: 0;
  WARN: 1;
  INFO: 2;
  DEBUG: 3;
  VERBOSE: 4;
}

export interface LoggerOptions {
  level?: keyof LogLevel | number;
  enableColors?: boolean;
  prefix?: string;
  timestamp?: boolean;
}

export class Logger {
  constructor(options?: LoggerOptions);
  setLevel(level: keyof LogLevel | number): void;
  error(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  debug(message: string, meta?: Record<string, unknown>): void;
  verbose(message: string, meta?: Record<string, unknown>): void;
  security(event: string, message: string, meta?: Record<string, unknown>): void;
}

export function createLogger(prefix: string, options?: LoggerOptions): Logger;
```

**Migration Steps**:
1. Create TypeScript interface definitions
2. Convert Logger class with proper typing
3. Add generic type support for metadata
4. Implement color support with type safety
5. Add child logger functionality
6. Write comprehensive tests

#### 1.2 Cache Module (`cache.js` → `cache.ts`)
```typescript
// Target Structure
export interface CacheOptions {
  maxSize?: number;
  defaultTTL?: number;
  cleanupInterval?: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  size: number;
}

export class LRUCache<T = any> {
  constructor(options?: CacheOptions);
  get(key: string): T | null;
  set(key: string, value: T, ttl?: number): boolean;
  delete(key: string): boolean;
  clear(): void;
  getStats(): CacheStats;
}

export class PackageCache<T = any> extends LRUCache<T> {
  getPackage(packageName: string, version: string): T | null;
  setPackage(packageName: string, version: string, result: T, ttl?: number): boolean;
  invalidatePackage(packageName: string, version?: string): boolean;
}
```

**Migration Steps**:
1. Add generic type support for cache values
2. Convert LRU implementation with TypeScript
3. Implement PackageCache with type safety
4. Add comprehensive error handling
5. Implement TTL and cleanup functionality
6. Add cache statistics and monitoring

#### 1.3 Error Handler (`errorHandler.js` → `errorHandler.ts`)
```typescript
// Target Structure
export interface ErrorDetails {
  [key: string]: unknown;
}

export class NullVoidError extends Error {
  readonly code: string;
  readonly details: ErrorDetails;
  readonly timestamp: string;
  
  constructor(message: string, code: string, details?: ErrorDetails);
  toJSON(): object;
  toString(): string;
}

export class NetworkError extends NullVoidError {
  constructor(message: string, details?: ErrorDetails);
}

export class FileSystemError extends NullVoidError {
  constructor(message: string, details?: ErrorDetails);
}

export class TimeoutError extends NullVoidError {
  constructor(message: string, details?: ErrorDetails);
}

export class CacheError extends NullVoidError {
  constructor(message: string, details?: ErrorDetails);
}

export class ValidationError extends NullVoidError {
  constructor(message: string, field: string, value: unknown);
}

export class SecurityError extends NullVoidError {
  constructor(message: string, details?: ErrorDetails);
}

export function globalErrorHandler(error: Error, context?: string): void;
```

**Migration Steps**:
1. Create comprehensive error type hierarchy
2. Add proper error serialization/deserialization
3. Implement error recovery mechanisms
4. Add context-aware error handling
5. Integrate with logging system
6. Add error reporting and monitoring

### Stage 2: Security & Performance (Week 2)
**Priority**: 🔧 HIGH  
**Estimated Time**: 18-24 hours  
**Dependencies**: Stage 1 complete

#### 2.1 Parallel Processing (`parallel.js` → `parallel.ts`)
```typescript
// Target Structure
export interface WorkerJob<T = any, R = any> {
  id: string;
  data: T;
  priority?: number;
  timeout?: number;
}

export interface WorkerPoolOptions {
  maxWorkers?: number;
  timeout?: number;
  retries?: number;
}

export class WorkerPool<T = any, R = any> {
  constructor(options?: WorkerPoolOptions);
  execute(job: WorkerJob<T, R>): Promise<R>;
  executeBatch(jobs: WorkerJob<T, R>[]): Promise<R[]>;
  shutdown(): Promise<void>;
  getStats(): WorkerPoolStats;
}
```

#### 2.2 Rate Limiter (`rateLimiter.js` → `rateLimiter.ts`)
```typescript
// Target Structure
export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export class RateLimiter {
  constructor(options: RateLimitOptions);
  isAllowed(identifier: string): boolean;
  reset(identifier: string): void;
  getStats(): RateLimitStats;
}

export async function rateLimitedRequest<T>(
  requestFn: () => Promise<T>,
  options?: RateLimitOptions
): Promise<T>;
```

#### 2.3 Validation (`validation.js` → `validation.ts`)
```typescript
// Target Structure
export interface ValidationRule<T = any> {
  validate(value: T): boolean;
  message: string;
}

export class InputValidator {
  static validatePackageName(name: string): string;
  static validateScanOptions(options: ScanOptions): ScanOptions;
  static validateAndSanitizePackageName(name: string): string;
  static validateOutputFormat(format: string): string;
  static validateDepth(depth: number): number;
  static validateWorkers(workers: number): number;
}
```

### Stage 3: Advanced Security (Week 3)
**Priority**: 🛡️ MEDIUM  
**Estimated Time**: 24-30 hours  
**Dependencies**: Stage 2 complete

#### 3.1 Sandbox (`sandbox.js` → `sandbox.ts`)
```typescript
// Target Structure
export interface SandboxOptions {
  timeout?: number;
  memoryLimit?: number;
  allowNetwork?: boolean;
  allowFileSystem?: boolean;
}

export interface AnalysisResult {
  isMalicious: boolean;
  confidence: number;
  threats: Threat[];
  metadata: Record<string, unknown>;
}

export class SecureSandbox {
  constructor(options?: SandboxOptions);
  analyzeFileSafely(filePath: string): Promise<AnalysisResult>;
  analyzeWalletThreats(code: string): Promise<Threat[]>;
  cleanup(): Promise<void>;
}
```

#### 3.2 Path Security (`pathSecurity.js` → `pathSecurity.ts`)
```typescript
// Target Structure
export class PathValidationError extends Error {
  readonly code: string;
  readonly path: string;
  readonly details: Record<string, unknown>;
}

export function validatePath(path: string, basePath?: string): string;
export function safeReadFile(filePath: string, encoding?: BufferEncoding, basePath?: string): string;
export function safeReadDir(dirPath: string, basePath?: string): string[];
export function safeJoinPaths(basePath: string, ...paths: string[]): string;
export function isAllowedFileType(filePath: string): boolean;
export function getSafeFilePaths(dirPath: string, basePath?: string): string[];
```

#### 3.3 Dependency Confusion (`dependencyConfusion.js` → `dependencyConfusion.ts`)
```typescript
// Target Structure
export interface PackageSimilarity {
  packageName: string;
  similarity: number;
  namespace: string;
  isConfusionRisk: boolean;
}

export interface DependencyConfusionResult {
  threats: Threat[];
  similarities: PackageSimilarity[];
  recommendations: string[];
}

export function detectDependencyConfusion(
  packageName: string,
  dependencies: Record<string, string>
): Promise<DependencyConfusionResult>;

export function calculateSimilarity(str1: string, str2: string): number;
export function checkNamespaceCollision(packageName: string): boolean;
```

### Stage 4: Utility Modules (Week 4)
**Priority**: 🔧 LOW  
**Estimated Time**: 15-21 hours  
**Dependencies**: Stage 3 complete

#### 4.1 Benchmarks (`benchmarks.js` → `benchmarks.ts`)
```typescript
// Target Structure
export interface BenchmarkResult {
  name: string;
  duration: number;
  iterations: number;
  metadata: Record<string, unknown>;
  memoryUsage: MemoryUsage;
}

export class BenchmarkSuite {
  constructor(name: string);
  add(name: string, fn: () => void | Promise<void>): void;
  run(): Promise<BenchmarkResult[]>;
  getStats(): BenchmarkStats;
}
```

#### 4.2 Streaming (`streaming.js` → `streaming.ts`)
```typescript
// Target Structure
export interface StreamAnalysisOptions {
  chunkSize?: number;
  encoding?: BufferEncoding;
  maxFileSize?: number;
}

export class FileStreamAnalyzer extends Transform {
  constructor(options?: StreamAnalysisOptions);
  _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback): void;
  getAnalysisResults(): StreamAnalysisResult;
}
```

#### 4.3 Rules (`rules.js` → `rules.ts`)
```typescript
// Target Structure
export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: SeverityLevel;
  pattern: RegExp | string;
  action: 'block' | 'warn' | 'allow';
}

export class RuleEngine {
  constructor(rules: Rule[]);
  evaluate(code: string, context?: Record<string, unknown>): RuleEvaluationResult;
  addRule(rule: Rule): void;
  removeRule(ruleId: string): void;
  getRules(): Rule[];
}
```

---

## 🛠️ Technical Implementation Guide

### TypeScript Configuration

#### tsconfig.json Updates
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": false,
    "noImplicitAny": true,
    "noImplicitReturns": true,
    "noImplicitThis": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noPropertyAccessFromIndexSignature": true,
    "noUncheckedIndexedAccess": true,
    "allowUnusedLabels": false,
    "allowUnreachableCode": false,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "moduleResolution": "node",
    "baseUrl": "./src",
    "paths": {
      "@/*": ["*"],
      "@/lib/*": ["lib/*"],
      "@/types/*": ["types/*"],
      "@/utils/*": ["utils/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": [
    "node_modules",
    "dist",
    "test",
    "**/*.test.ts",
    "**/*.spec.ts"
  ]
}
```

### Package.json Configuration

#### Dependencies Management
```json
{
  "dependencies": {
    "@babel/parser": "^7.23.0",
    "@babel/traverse": "^7.23.0",
    "@babel/types": "^7.23.0",
    "acorn": "^8.10.0",
    "acorn-walk": "^8.2.0",
    "async-mutex": "^0.5.0",
    "axios": "^1.6.0",
    "commander": "^11.1.0",
    "fs-extra": "^11.1.0",
    "glob": "^10.3.0",
    "js-yaml": "^4.1.0",
    "node-fetch": "^2.7.0",
    "ora": "^5.4.1",
    "tar": "^6.2.0"
  },
  "devDependencies": {
    "@jest/globals": "^29.7.0",
    "@types/jest": "^30.0.0",
    "@types/node": "^24.5.2",
    "@typescript-eslint/eslint-plugin": "^8.44.1",
    "@typescript-eslint/parser": "^8.44.1",
    "eslint": "^8.57.1",
    "jest": "^29.7.0",
    "ts-jest": "^29.4.4",
    "ts-node": "^10.9.2",
    "typescript": "^5.9.2"
  }
}
```

### Testing Strategy

#### Jest Configuration for TypeScript
```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: [
    '**/test/**/*.test.ts',
    '**/test/**/*.test.js'
  ],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.json'
    }],
    '^.+\\.js$': 'babel-jest'
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/types/**',
    '!**/node_modules/**',
    '!**/test/**'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/test/setup.js'],
  globalTeardown: '<rootDir>/test/teardown.js',
  detectOpenHandles: false
};
```

---

## 🧪 Testing & Quality Assurance

### Testing Checklist
- [ ] **Unit Tests**: Each migrated module has comprehensive unit tests
- [ ] **Integration Tests**: End-to-end functionality testing
- [ ] **Performance Tests**: Benchmark against legacy version
- [ ] **Type Tests**: Verify TypeScript type safety
- [ ] **Error Handling Tests**: Test error scenarios and recovery
- [ ] **Security Tests**: Verify security functionality
- [ ] **Memory Tests**: Check for memory leaks
- [ ] **Concurrency Tests**: Test parallel execution

### Quality Gates
- [ ] **ESLint**: Zero errors, zero warnings
- [ ] **TypeScript**: Strict mode compilation success
- [ ] **Test Coverage**: > 90% coverage
- [ ] **Performance**: Within 10% of legacy performance
- [ ] **Memory Usage**: Within 20% of legacy memory usage
- [ ] **Security**: All security tests passing

---

## 🚀 Deployment Strategy

### Build Process
```bash
# Development
npm run dev                    # Run with ts-node
npm run build:watch          # Watch mode compilation

# Production
npm run build                # Compile TypeScript
npm run test                # Run test suite
npm run lint                # Code quality checks
npm run type-check          # TypeScript validation
npm run prepublishOnly      # Pre-publish validation
```

### Distribution
- **Main Entry**: `dist/scan.js`
- **CLI Entry**: `dist/bin/nullvoid.js`
- **Types**: `dist/types/index.d.ts`
- **Source Maps**: Included for debugging

---

## 📊 Progress Tracking

### Migration Status Dashboard
```
Stage 1: Critical Infrastructure    [░░░░░░░░░░] 0/3 modules
Stage 2: Security & Performance      [░░░░░░░░░░] 0/3 modules  
Stage 3: Advanced Security          [░░░░░░░░░░] 0/3 modules
Stage 4: Utility Modules            [░░░░░░░░░░] 0/3 modules
Stage 5: Dependencies                [░░░░░░░░░░] 0/2 tasks
Stage 6: Testing                     [░░░░░░░░░░] 0/2 tasks
Stage 7: Main Migration              [░░░░░░░░░░] 0/2 tasks
Stage 8: Validation                  [░░░░░░░░░░] 0/3 tasks

Overall Progress: 0% Complete
Estimated Completion: 3-4 weeks
```

### Milestone Tracking
- [ ] **Week 1**: Complete Stage 1 (Critical Infrastructure)
- [ ] **Week 2**: Complete Stage 2 (Security & Performance)
- [ ] **Week 3**: Complete Stage 3 (Advanced Security)
- [ ] **Week 4**: Complete Stage 4 (Utility Modules)
- [ ] **Week 5**: Complete Stages 5-8 (Testing & Validation)

---

## 🎯 Success Criteria

### Technical Requirements
- ✅ All 11 missing modules successfully migrated
- ✅ 100% TypeScript compilation success
- ✅ Zero runtime errors
- ✅ All existing tests passing
- ✅ Performance within acceptable limits
- ✅ Memory usage optimized

### Quality Requirements
- ✅ Code coverage > 90%
- ✅ ESLint passes with zero errors
- ✅ TypeScript strict mode enabled
- ✅ All security tests passing
- ✅ Documentation updated

### Functional Requirements
- ✅ CLI functionality fully working
- ✅ All scanning features operational
- ✅ Error handling comprehensive
- ✅ Logging system functional
- ✅ Caching system operational

---

## 📚 Resources & References

### Documentation
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Node.js TypeScript Guide](https://nodejs.org/en/docs/guides/typescript/)
- [Jest TypeScript Setup](https://jestjs.io/docs/getting-started#using-typescript)

### Tools
- **TypeScript Compiler**: `tsc`
- **Type Checking**: `tsc --noEmit`
- **Testing**: `jest`
- **Linting**: `eslint`
- **Formatting**: `prettier`

### Best Practices
- Use strict TypeScript configuration
- Implement comprehensive error handling
- Write tests for all migrated functionality
- Maintain performance parity with legacy
- Document all API changes

---

*This migration guide should be updated as progress is made and new requirements are discovered.*

**Last Updated**: $(date)  
**Version**: 1.0  
**Status**: Ready for Implementation
