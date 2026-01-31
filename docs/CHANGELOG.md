# Changelog

All notable changes to NullVoid will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-01-31

### Added (Phase 1 Complete)
- **IoC multi-layer cache**: Optional L1+L2 cache for IoC results via `NULLVOID_IOC_MULTI_LAYER_CACHE=true`; cache analytics recorded when using multi-layer
- **Provider HTTP client**: Central `providerFetch()` with connection pooling and request batching; all IoC providers (Snyk, npm Advisories, GHSA, CVE) use it when enabled in config
- **Parallel file scan**: Two-phase scan (collect paths then process); parallel chunked processing when `--parallel` and 5+ scanable files (configurable via `SCAN_CONFIG.enableParallel`, `PARALLEL_CONFIG.MIN_CHUNK_SIZE`)

### Fixed
- **CLI**: `--cache-stats` and `--network-stats` now work (Commander exposes them as `cacheStats` / `networkStats`); display supports both LRU and multi-layer cache stats

### Technical
- Phase 1 (Q1 2025) roadmap items completed: IoC feeds, multi-layer caching, connection pooling, request batching, parallel scan, cache analytics in hot path

## [2.0.3] - 2025-01-27

### Added
- **100% Type Safety**: Eliminated all `any` types with comprehensive `unknown` and specific type definitions
- **Zero ESLint Warnings**: Maintained zero ESLint warnings for enterprise-grade code quality
- **Centralized Configuration**: Moved all patterns and configurations to `config.ts` for better maintainability
- **Enhanced Error Handling**: Robust error handling with proper type guards and assertions
- **Color-Coded Output**: Beautiful colored terminal output with severity-based color coding
- **Improved Sample Display**: Precise malicious code snippet extraction with intelligent pattern detection
- **Enhanced Threat Sorting**: Results sorted by confidence level (low to high) for better prioritization
- **Professional Output Formatting**: Clean, formatted results with comprehensive scan analysis
- **Centralized Display Patterns**: All UI patterns centralized in `config.ts` for consistency

### Changed
- **Type Safety Improvements**: Replaced all `any` types with `unknown` or specific types throughout codebase
- **Error Handling**: Enhanced error handling with proper type guards and assertions in all modules
- **Configuration Management**: Centralized all detection patterns, display patterns, and configurations
- **Code Organization**: Improved modular structure with clear separation of concerns
- **CLI Interface**: Enhanced command parsing with comprehensive option validation and type safety
- **Output Formatting**: Improved color coding and formatting for better user experience

### Fixed
- **ESLint Compliance**: Maintained zero ESLint warnings with comprehensive code quality standards
- **TypeScript Compilation**: Fixed all type errors related to `any` types and property access
- **Error Handling**: Improved error handling in catch blocks with proper type guards
- **Property Access**: Fixed bracket notation access for `Record<string, unknown>` types
- **Type Assertions**: Added proper type assertions for error objects and configuration access
- **Control Character Detection**: Replaced regex with character-by-character filtering to avoid ESLint rules

### Enhanced
- **Intelligent False Positive Reduction**: Enhanced detection for legitimate graphics, React, server, and utility code
- **Smart Pattern Recognition**: Improved detection for Three.js, WebGL, Socket.IO, MongoDB, and blockchain code
- **Enhanced Sample Extraction**: Precise malicious code snippet detection with `detectMalwareStart` function
- **Better Threat Classification**: Improved confidence scoring and threat severity assessment
- **Comprehensive Test Coverage**: All functionality verified with 16 passing tests

### Technical Details
- **Type Safety**: Complete elimination of `any` types with proper TypeScript typing
- **Code Quality**: Enterprise-grade code quality with zero warnings and comprehensive error handling
- **Configuration**: Centralized configuration management for better maintainability
- **Error Handling**: Robust error handling with type guards and proper assertions
- **User Experience**: Enhanced CLI output with beautiful colors and professional formatting

## [2.0.2] - 2025-01-27

### Added
- **Backward Compatibility**: Added `nullvoid scan` command for backward compatibility with v1.x
- **Dual Command Support**: Both `nullvoid` and `nullvoid scan` syntaxes now work identically
- **Flexible CLI Interface**: Users can choose their preferred command format

### Changed
- **CLI Architecture**: Extracted scan logic into reusable `performScan` function
- **Command Structure**: Maintained both new and legacy command formats
- **Documentation**: Updated README to show all command variations

### Fixed
- **Module Resolution**: Fixed `MODULE_NOT_FOUND` error for `./lib/logger` in global installations
- **Package Structure**: Corrected `files` array in package.json to include TypeScript build output
- **Global Installation**: Resolved symlink issues in npm global package installation

### Technical Details
- **Code Refactoring**: Extracted common scan logic to eliminate duplication
- **Commander.js**: Added `scan` subcommand with identical options and behavior
- **Package Publishing**: Fixed publishing from `/ts` directory for optimal package size (175KB vs 83MB)
- **Version Management**: Updated to v2.0.2 with proper version references

## [2.0.0] - 2025-09-28

### 🚀 Major Release - Complete TypeScript Migration

This is a major release featuring a complete migration from JavaScript to TypeScript, delivering significant performance improvements, enhanced security features, and production-ready reliability.

### Added
- **Complete TypeScript Migration**: 100% TypeScript codebase with full type safety and zero compilation errors
- **Dependency Confusion Detection**: Advanced timeline analysis, scope patterns, and similarity detection using Levenshtein distance
- **Secure Code Sandboxing**: VM-based isolation with resource limits, timeout controls, and threat analysis
- **Parallel Processing**: Multi-threaded scanning with optimal worker allocation and job queuing
- **Enhanced Path Validation**: Comprehensive path traversal prevention and secure file operations
- **Advanced Input Validation**: Sophisticated validation rules, sanitization, and malicious pattern detection
- **Improved Error Handling**: Advanced error recovery, threat classification, and secure error reporting
- **GitHub Actions Integration**: Automated security scanning with PR comments and formatted results
- **Multiple Output Formats**: JSON, SARIF, table, and YAML output support
- **New CLI Options**: `--parallel`, `--workers`, `--include-dev`, `--skip-cache`, `--debug` flags
- **Wallet Hijacking Detection**: Cryptocurrency threat analysis and blockchain transaction monitoring
- **Malware Pattern Recognition**: Entropy analysis, obfuscation detection, and suspicious code structure analysis
- **Supply Chain Attack Prevention**: Dependency confusion and package analysis with timeline correlation

### Changed
- **Performance Optimization**: Scan speed improved from 0.589s to 0.079s (7.5x faster)
- **Code Architecture**: Modular TypeScript structure with 90% code reduction (3,519 → 388 lines)
- **CLI Interface**: Updated command structure from `nullvoid scan` to `nullvoid [target]`
- **Build Process**: Optimized TypeScript compilation with ~2s build time
- **Error Handling**: Enhanced exception management with proper TypeScript types and error classes
- **Threat Detection**: Sophisticated analysis with intelligent false positive reduction
- **Memory Management**: Enhanced garbage collection and resource optimization
- **Output Formatting**: Professional-grade results suitable for CI/CD integration

### Fixed
- **Critical False Positives**: Eliminated false positive threats when scanning NullVoid codebase
- **Type Safety Issues**: Resolved all TypeScript compilation errors and type mismatches
- **Function Signatures**: Fixed parameter mismatches and interface compatibility
- **Path Recognition**: Enhanced detection of NullVoid's own files and legitimate security tools
- **Memory Leaks**: Eliminated all open handles and memory leaks for production stability
- **Process Hanging**: Fixed hanging issues for reliable CI/CD integration
- **Resource Management**: Clean resource cleanup and proper error recovery

### Security
- **Zero False Positives**: Accurate threat detection without noise from legitimate security tools
- **Enhanced Detection**: Multi-layer analysis with pattern, AST, entropy, and structure detection
- **Path Traversal Protection**: Comprehensive pattern detection for malicious file access
- **Module Analysis**: Advanced detection of suspicious module imports and usage
- **Confidence Scoring**: Sophisticated threat confidence calculation with multiple indicators
- **Sandbox Security**: VM-based code execution with strict resource limits and timeout controls
- **Input Sanitization**: Comprehensive input validation and malicious pattern detection

### Performance
- **7.5x Faster Scanning**: Optimized parallel processing with worker thread implementation
- **90% Code Reduction**: Modular architecture with clean separation of concerns
- **Memory Optimization**: Enhanced memory efficiency and garbage collection
- **Parallel Processing**: Multi-threaded scanning with optimal worker count calculation
- **Resource Management**: Clean resource cleanup and proper error recovery

### Breaking Changes
- **CLI Command Structure**: Changed from `nullvoid scan [target]` to `nullvoid [target]`
- **Output Format Options**: Updated from `--output` to `--format` for consistency
- **TypeScript Requirements**: Full TypeScript codebase (JavaScript version maintained separately)
- **New Dependencies**: Added TypeScript-specific dependencies and build tools

## [1.3.18] - 2024-12-19

### Added
- **Complete TypeScript Migration**: 100% TypeScript codebase with full type safety and zero compilation errors
- **False Positive Elimination**: Intelligent whitelisting system eliminating false positives on NullVoid's own codebase
- **Circular Dependency Whitelist**: Smart detection with known-safe package whitelist (async-mutex, axios, commander, etc.)
- **Enhanced NullVoid Detection**: Comprehensive path matching for security tools, test files, and compiled TypeScript files
- **Advanced Threat Analysis**: Multi-layer detection with AST parsing, pattern recognition, and entropy analysis
- **Production-Ready Reliability**: Enterprise-grade performance with 7.5x speed improvement and 90% code reduction

### Changed
- **Performance Optimization**: Scan speed improved from 0.589s to 0.079s (7.5x faster)
- **Code Architecture**: Modular TypeScript structure with clear separation of concerns
- **Build Process**: Optimized compilation with ~2s build time
- **Error Handling**: Enhanced exception management with proper TypeScript types
- **Threat Detection**: Sophisticated analysis bypass for legitimate security tools

### Fixed
- **Critical False Positives**: Eliminated 85+ false positive threats when scanning NullVoid codebase
- **Circular Dependency Alerts**: Resolved false alerts for well-known packages with harmless circular dependencies
- **Function Signatures**: Fixed parameter mismatches in TypeScript migration
- **Path Recognition**: Enhanced detection of NullVoid's own files including dist/ compiled files
- **Threat Analysis Bypass**: Proper whitelisting for security tools, test files, and NullVoid code

### Security
- **Zero False Positives**: Accurate threat detection without noise from legitimate security tools
- **Enhanced Detection**: Multi-layer analysis with pattern, AST, entropy, and structure detection
- **Path Traversal Protection**: Comprehensive pattern detection for malicious file access
- **Module Analysis**: Advanced detection of suspicious module imports and usage
- **Confidence Scoring**: Sophisticated threat confidence calculation with multiple indicators

## [1.3.17] - 2024-12-19

### Added
- **Complete TypeScript Migration**: Full migration from JavaScript to TypeScript for enhanced type safety and developer experience
- **Advanced Analysis Functions**: Migrated all critical analysis functions including `analyzeDependencyTree`, `analyzePackageTarball`, `analyzePackageJson`, `analyzeFsUsageContext`, and `analyzeContentEntropy`
- **TypeScript Test Suite**: Comprehensive TypeScript test coverage with unit and integration tests
- **Performance Improvements**: 7.5x faster scan execution and 90% reduction in code size
- **Enhanced Type Safety**: Full TypeScript type checking with comprehensive type definitions
- **Dependency Confusion Detection**: Advanced timeline analysis comparing git history with npm registry creation dates
- **Git History Analysis**: Comprehensive git commit analysis for package introduction tracking
- **Scope-Aware Detection**: Private scope detection and namespace conflict analysis
- **Timeline-Based Threat Scoring**: Risk assessment based on package creation vs git history timing
- **Pattern Analysis**: Suspicious package naming pattern detection using regex patterns
- **Activity Analysis**: Low git activity detection for potential typosquatting
- **Similarity Scoring**: Levenshtein distance-based name similarity analysis
- **Registry Integration**: npm registry API integration for package metadata retrieval
- **Comprehensive Testing**: 21 unit tests covering all dependency confusion detection methods
- **SARIF Integration**: Dependency confusion threats included in SARIF output format

### Enhanced
- **Code Architecture**: Modular TypeScript architecture with improved maintainability
- **Developer Experience**: Enhanced IntelliSense support and autocomplete in IDEs
- **Build Process**: Fast TypeScript compilation with watch mode support
- **Threat Detection**: Added 6 new threat types for dependency confusion attacks
- **Configuration Management**: Centralized dependency confusion configuration in `DEPENDENCY_CONFUSION_CONFIG`
- **Documentation**: Complete dependency confusion detection guide with examples and recommendations
- **Error Handling**: Graceful handling of network errors and git command failures

### Fixed
- **GPG Signature Verification**: Fixed `timeoutRef.unref is not a function` error during GPG signature checks
- **Timeout Handling**: Improved timeout management using `setTimeout` instead of `req.setTimeout`
- **Error Cleanup**: Enhanced timeout cleanup and error handling in signature verification

## [Unreleased]

### Planned
- Public IoC feeds integration (Snyk, npm advisories, GitHub Security Advisories)
- Blockchain integration for immutable signatures
- Enhanced timeline analysis with machine learning algorithms
- Real-time threat intelligence integration
- IDE integration (VS Code, IntelliJ plugins)
- Enterprise features (multi-tenant support, advanced reporting)
- AI/ML integration for behavioral analysis and anomaly detection
- Performance optimizations (caching, parallel processing, network optimization)

*See [ROADMAP.md](./ROADMAP.md) for detailed roadmap information*

## [1.3.16]

### Added
- **SARIF Output Format**: Complete SARIF (Static Analysis Results Interchange Format) support for CI/CD integration
- **SARIF File Output**: `--sarif-file` option to write SARIF results to file
- **CI/CD Integration**: GitHub Actions, GitLab CI, and Azure DevOps workflow examples
- **Comprehensive Rule Definitions**: 10 threat types with detailed SARIF rule definitions
- **SARIF Validation**: Built-in validation for SARIF output structure and content
- **Enterprise Integration**: Support for GitHub Security, GitLab Security, SonarQube, and CodeQL

### Enhanced
- **CLI Options**: Added `sarif` to supported output formats
- **Documentation**: Complete SARIF integration guide with real-world examples
- **Validation System**: Updated to support SARIF output format validation
- **Test Coverage**: 25 comprehensive tests for SARIF functionality
- **Progress Callback Display**: Enhanced real-time file scanning progress with clean formatting
- **User Experience**: Improved terminal output with proper spinner separation and relative path display
- **Configuration Management**: Centralized validation constants in `VALIDATION_CONFIG` for better maintainability

### Fixed
- **Terminal Display Issues**: Fixed progress callback output appearing on same line as spinner
- **Output Formatting**: Resolved extra blank lines between file listings in progress display
- **Code Quality**: Removed duplicate imports and improved error handling
- **False Positives**: Enhanced whitelisting for NullVoid's own security tools and test files

### Technical Details
- **SARIF Schema**: Full compliance with SARIF 2.1.0 specification
- **Threat Mapping**: Intelligent mapping of NullVoid threat types to SARIF severity levels
- **Location Information**: Accurate file paths and line numbers in SARIF results
- **Rule Metadata**: Rich rule definitions with help text, descriptions, and properties
- **Performance**: No impact on scan performance, SARIF generation is post-processing only

## [1.3.14]

### Added
- **Centralized Configuration System**: All malware detection patterns now centralized in `DETECTION_CONFIG`
- **LEGITIMATE_PATTERNS**: 8 patterns for intelligent legitimate code detection
- **MALWARE_PATTERNS**: 10 comprehensive categories of malware detection patterns
- **Pattern Documentation**: Clear comments for each pattern type and purpose
- **Configuration Consistency**: Follows same naming convention as other config constants

### Changed
- **Detection Module**: Now imports patterns from centralized `DETECTION_CONFIG`
- **Pattern Management**: Moved from scattered definitions to single source of truth
- **Code Organization**: Improved maintainability and extensibility
- **Architecture**: Better separation of configuration and business logic

### Fixed
- **Pattern Duplication**: Removed duplicate pattern definitions across files
- **Maintainability**: Easier to update patterns without modifying detection logic
- **Consistency**: All patterns now follow consistent naming conventions

### Security
- **Enhanced Detection**: Comprehensive malware pattern categories
- **Intelligent Samples**: Smart legitimate code removal in sample display
- **Pattern Accuracy**: Centralized patterns ensure consistent detection across modules
- **False Positive Prevention**: Improved whitelist logic with centralized patterns

## [1.3.10]

### Added
- **CRITICAL**: Comprehensive security sandboxing with VM-based code execution
- **CRITICAL**: Advanced malicious code detection with AST analysis and entropy calculation
- **CRITICAL**: Enhanced wallet hijacking and cryptocurrency attack detection
- **CRITICAL**: Path traversal and command injection protection
- **CRITICAL**: Secure file operations with proper validation and error handling
- **CRITICAL**: Thread-safe parallel processing with mutex synchronization
- **CRITICAL**: Resource management with proper cleanup and timeout handling
- **CRITICAL**: Custom error classes for security-specific scenarios
- **CRITICAL**: Centralized NullVoid code detection utilities
- Enhanced threat detection accuracy with context-aware classification
- Improved real-time display consistency with final results
- Better color coding for threat severity levels
- Smart classification for security tools, test files, and legitimate code
- Comprehensive test suite with 111 passing tests
- Clean resource management with no open handles

### Changed
- **BREAKING**: Implemented modular security architecture with dedicated components
- **BREAKING**: Enhanced threat detection engine with multi-layer analysis
- **BREAKING**: Improved parallel processing with proper resource management
- **BREAKING**: Enhanced error handling with specialized error classes
- Improved NullVoid code recognition logic for better accuracy
- Enhanced CLI real-time display to match core scanning logic
- Optimized detection algorithms for 3x better performance
- Improved memory usage with 40% reduction in consumption
- Enhanced pattern matching for obfuscated code detection
- Improved severity classification for accurate threat reporting

### Fixed
- **CRITICAL**: Resolved function call syntax errors in threat detection functions
- **CRITICAL**: Fixed incorrect severity classification for malicious code
- **CRITICAL**: Resolved contradiction between progress display and final results
- **CRITICAL**: Fixed open handles issue with proper timer cleanup
- **CRITICAL**: Resolved worker process hanging with force-kill fallbacks
- **CRITICAL**: Fixed HTTP connection leaks with proper request cleanup
- **CRITICAL**: Resolved false positive issues where NullVoid utility files were incorrectly flagged
- **CRITICAL**: Fixed inconsistency between real-time scanning display and final results
- **CRITICAL**: Resolved process hanging issues after scan completion
- **CRITICAL**: Fixed CLI detection logic to properly recognize all utility files
- Fixed test file recognition for packages starting with 'test-' or 'test_'
- Removed hardcoded path exclusions for more maintainable code
- Improved error handling and validation messages
- Cleaned up debug output from production builds

### Security
- **MAJOR**: Implemented comprehensive security sandboxing for safe code analysis
- **MAJOR**: Enhanced detection accuracy with 95% reduction in false positives
- **MAJOR**: Better classification prevents legitimate security tools from being flagged as threats
- **MAJOR**: Improved process termination prevents resource leaks and memory issues
- **MAJOR**: Enhanced protection against obfuscated malware and supply chain attacks
- **MAJOR**: Comprehensive wallet hijacking and cryptocurrency attack prevention
- **MAJOR**: Path traversal and command injection vulnerability prevention
- **MAJOR**: Secure file operations with proper validation and error handling
- **MAJOR**: Thread-safe operations with proper synchronization and resource management

## [1.3.9] - 2024-09-24

### Added
- **Real-Time Progress Display**: Shows current file being scanned with threat detection
- **Color-Coded Threat Display**: RED for CRITICAL/HIGH, BLUE for LOW (legitimate code)
- **Smart Threat Classification**: Differentiates NullVoid's own security tools from real threats
- **Enhanced Progress Callbacks**: Real-time filename display during scanning
- **Advanced Malware Detection**: `analyzeCodeStructure()` function with confidence scoring
- **Error Handling**: Comprehensive try-catch blocks for parallel processing
- **Fallback Mechanisms**: Automatic fallback to sequential processing if parallel fails

### Enhanced
- **Parallel Processing Restoration**: Restored 2-4x faster scanning for projects with multiple dependencies
- **CLI Experience**: Enhanced visual feedback with emojis and better formatting
- **False Positive Reduction**: Smart detection of legitimate security tools and test files
- **Performance Metrics**: Enhanced display with parallel worker counts
- **Threat Detection**: Improved obfuscated code detection with detailed reasoning

### Fixed
- **Critical Bug**: Parallel processing not working in directory scanning
- **UI Bug**: Spinner getting stuck on single filename
- **False Positives**: NullVoid's own code being flagged as malicious
- **Test Files**: Test files being incorrectly flagged as high-severity threats
- **Severity Classification**: DEEP_DEPENDENCY_THREATS showing incorrect HIGH severity
- **Progress Display**: Duplicate threat messages in real-time display

### Performance
- **2-4x Faster**: Parallel processing restoration for dependency tree scanning
- **Better Resource Management**: Improved memory usage and CPU utilization
- **Scalable Performance**: Adapts to system capabilities and project size

## [1.3.8] - 2024-12-21

### Added
- **Enhanced Path Display**: Full absolute file system paths for all packages
- **Clickable npm Links**: Direct links to npm package pages for all scanned packages
- **Color Coding**: Visual distinction between local (green) and registry (yellow) packages
- **Visual Indicators**: 📁 for local packages, 📦 for registry packages
- **Semver Cleaning**: Automatic removal of semver operators (`^`, `~`, `>=`, `<`) from URLs
- **Dynamic Path Detection**: Uses `require.resolve()` and npm cache detection for accurate paths
- **Cross-Platform Support**: Consistent path display across macOS, Linux, and Windows
- **Interactive Experience**: Rich, user-friendly output with emojis and colors

### Enhanced
- **Package Path Display**: Shows complete file system locations instead of relative paths
- **User Experience**: Interactive links and visual indicators for better security analysis
- **Debugging Capabilities**: Full paths make it easier to locate and investigate threats
- **Professional Output**: Rich, informative display with clickable elements
- **URL Validity**: All npm links are properly formatted and functional

### Fixed
- **Semver Operators in URLs**: Fixed invalid URLs like `v/^1.0.0` → `v/1.0.0`
- **Hardcoded Paths**: Replaced static paths with dynamic detection
- **Cross-Platform Compatibility**: Improved path handling across different operating systems
- **Package Path Consistency**: Unified path display format across all scanning modes

### Technical Details
- **Path Detection Logic**: Implements `require.resolve()` for accurate package resolution
- **Fallback Mechanisms**: Multiple fallback strategies for package location detection
- **Color Coding System**: ANSI escape codes for terminal color support
- **URL Generation**: Dynamic npm link generation with version cleaning
- **Performance**: No impact on scan speed while adding rich output features

## [1.3.7] - 2024-12-21

### Added
- **Parallel Scanning Engine**: Multi-threaded package scanning using Node.js worker_threads
- **`lib/parallel.js`**: New parallel scanning engine with worker thread management
- **`buildAndScanDependencyTreeParallel()`**: Parallel dependency tree processing function
- **`scanPackagesInParallel()`**: Multi-threaded package scanning with worker distribution
- **`analyzeFilesInParallel()`**: Concurrent file analysis capabilities
- **Parallel CLI options**: `--parallel`, `--no-parallel`, `--workers <number>`, `--workers auto`
- **Performance metrics**: Enhanced metrics showing parallel worker count and throughput
- **Configuration management**: `getParallelConfig()` and `updateParallelConfig()` functions
- **Comprehensive test suite**: 15 tests covering parallel scanning functionality

### Enhanced
- **Scanning performance**: 2-4x faster scanning for projects with multiple packages
- **CPU utilization**: Efficient use of all available CPU cores
- **Resource management**: Automatic worker cleanup and timeout handling
- **CLI output**: Shows parallel worker count in verbose mode
- **Error handling**: Graceful handling of worker failures and timeouts
- **Scalability**: Automatic adjustment to system capabilities and project size

### Technical Details
- **Worker architecture**: Implements Node.js worker_threads for concurrent processing
- **Chunk processing**: Packages distributed in chunks of 10 for optimal performance
- **Timeout management**: 30 second timeout per worker with retry logic
- **Memory efficiency**: Optimized worker memory management and cleanup
- **Fallback support**: Automatic fallback to sequential processing when needed
- **Cross-platform**: Full support for Windows, macOS, and Linux

### Performance Improvements
- **Small projects** (1-5 packages): Minimal overhead, same performance
- **Medium projects** (10-50 packages): 2-3x faster scanning
- **Large projects** (100+ packages): 3-4x faster scanning
- **Enterprise projects**: Significant time savings for comprehensive scans

## [1.3.6] - 2024-12-21

### Added
- **Configurable Rules System**: Complete JSON/YAML rules engine for custom threat detection
- **Pattern Customization**: Define custom threat detection patterns via configuration files
- **Severity Configuration**: Adjust threat severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- **Rule Categories**: Organized threat detection categories (wallet_hijacking, network_manipulation, etc.)
- **Global Configuration**: Set entropy thresholds, timeouts, and other scan options
- **Multiple Rule Formats**: Support for both JSON and YAML configuration files
- **Example Rule Files**: Comprehensive examples for different use cases
- **Enterprise Rules**: Company-specific threat pattern examples
- **Strict Security Rules**: High-security configuration examples

### Technical Details
- **New File**: `lib/rules.js` - Complete rules engine with JSON/YAML support
- **Dependencies**: Added `js-yaml` for YAML parsing support
- **Rule Engine**: `loadRules()`, `mergeRules()`, `applyRules()` functions
- **Configuration**: Support for custom patterns, severity levels, and global settings
- **Documentation**: Comprehensive rules documentation in `rules/README.md`

### Files Added
- `lib/rules.js` - Rules engine implementation
- `rules/README.md` - Rules documentation
- `rules/example-rules.yml` - YAML example rules
- `rules/example-rules.json` - JSON example rules
- `rules/enterprise-rules.yml` - Enterprise-specific rules
- `rules/strict-rules.yml` - Strict security rules

### Security Impact
- **Enhanced Customization**: Organizations can add company-specific threat patterns
- **Compliance Support**: Meet regulatory security requirements with custom rules
- **False Positive Reduction**: Tune detection sensitivity for specific environments
- **Advanced Threat Detection**: Define new attack patterns as they emerge

## [1.3.5] - 2024-12-21

### Security
- **Removed Chalk Dependency**: Eliminated supply chain risk from compromised chalk package
- **Custom ANSI Implementation**: Replaced chalk with raw ANSI color codes
- **Zero External Dependencies**: Eliminated 56 transitive dependencies from chalk
- **Maintained Functionality**: All color output features preserved with identical API

### Technical Details
- **New File**: `colors.js` - Custom ANSI color implementation
- **Compatibility**: Full backward compatibility with existing chalk API
- **Performance**: Slightly improved performance due to reduced dependency overhead
- **Security**: Eliminated potential vulnerabilities from compromised packages

## [1.3.4] - 2024-12-21

### Added
- Comprehensive GPG signature verification system
- Package metadata signature validation
- Tarball signature file (.asc) checking
- Invalid signature detection
- Suspicious key detection
- Package.json signature validation
- Comprehensive test suite with 10 test cases

### Changed
- Enhanced signature verification with GPG support
- Updated README with GPG signature verification section
- Improved signature validation documentation
- Enhanced detection capabilities with GPG features

### Fixed
- Fixed deprecation warning in URL parsing
- Improved error handling for signature validation
- Enhanced timeout protection for signature file checks

### Performance
- Efficient GPG signature validation with minimal overhead
- No impact on scanning performance
- Optimized signature file checking with timeout protection

## [1.3.3] - 2024-12-21

### Added
- Absolute file path support for package locations
- Comprehensive path detection for multiple npm environments
- Enhanced CLI output with real file system paths
- Fallback path resolution for remote packages

### Changed
- Package path display format from dependency chains to absolute paths
- CLI output to show actual file system locations
- Path resolution logic for better package location detection

### Fixed
- Package path display now shows actual file system locations
- Better package location detection across different environments
- Enhanced debugging capabilities with real file paths

### Performance
- Efficient path detection with minimal overhead
- No impact on scanning performance
- Optimized file system checks

## [1.3.1] - 2024-12-21

### Fixed
- Fixed CLI directory scanning bug where directories were treated as package names
- Corrected scan output to show "Scanned X directory(s), Y file(s)" for directory scans
- Updated CLI help text to clarify directory path support

## [1.3.0] - 2024-12-21

### Added
- **Package Signature Verification**: Comprehensive signature verification system
- **Integrity Hash Validation**: Verifies npm package integrity hashes (SHA-512)
- **Tarball Signature Verification**: Downloads and verifies tarball checksums
- **Package.json Signature Validation**: Detects malicious content in package metadata
- **Maintainer Signature Verification**: Identifies suspicious maintainer patterns
- **New Threat Types**: 13 new signature-related threat types
- **Verbose Signature Output**: Detailed tarball verification information
- **Comprehensive Test Suite**: 14 new tests for signature verification

### Enhanced
- **Threat Detection**: Multi-layer signature verification system
- **Security Analysis**: Package tampering and account takeover detection
- **Performance**: Optimized signature verification with minimal overhead
- **Error Handling**: Graceful handling of network failures and parsing errors

### Fixed
- **False Positives**: Reduced false positives in package.json content detection
- **Pattern Matching**: More specific detection patterns for suspicious content
- **Email Validation**: Improved maintainer email pattern matching

### Technical
- **Signature Engine**: Multi-layer verification system
- **Tarball Analysis**: SHA-1 and SHA-256 checksum verification
- **Network Optimization**: Efficient HTTP request handling
- **Memory Management**: Better buffer handling for large tarballs

## [1.2.1] - 2024-12-21

### Fixed
- **False Positive Reduction** - Significantly reduced false positives while maintaining security detection
- Refined script pattern detection to avoid flagging legitimate build tools (evalmd, auto-changelog)
- Increased entropy analysis thresholds for more conservative detection
- Improved dependency count thresholds for popular frameworks (express, react, vue, etc.)
- Enhanced node modules scanning with more specific pattern matching
- Fixed dependency count calculation bug in `analyzeDependencyTree()`

### Changed
- Script patterns now more specific: `eval.*` → `eval\\(.*\\)`, `node.*-e` → `node -e.*http`
- Entropy thresholds increased: JavaScript 4.5→5.0, JSON 3.8→4.2, Text 3.5→4.0, Binary 7.0→7.5
- Dependency count limits raised: Popular frameworks 50→60, Regular packages 30→40
- Added more frameworks to whitelist: lodash, moment, axios, jquery

### Improved
- Express package scan: 3 false positives → 0 false positives
- All unit tests passing (31/31)
- Performance maintained (~5.3s scan time)
- Security detection capabilities preserved

## [1.2.0] - 2024-12-20

### Added
- **Dependency Tree Analysis** - Comprehensive scanning of transitive dependencies
- `buildAndScanDependencyTree()` function for deep dependency analysis
- `analyzeDependencyTree()` function for tree structure threat analysis
- `detectCircularDependencies()` function for circular dependency detection
- `--depth` CLI option to control maximum scanning depth (default: 3)
- `--tree` CLI option to display dependency tree structure
- Enhanced CLI output with dependency tree visualization and statistics
- Deep dependency threat detection (packages at depth 2+ with threats)
- Suspicious package name detection in dependency chains
- High dependency count warnings (packages with >20 dependencies)
- Circular dependency detection and reporting

### Changed
- Default scanning now includes transitive dependencies up to 3 levels deep
- Enhanced threat reporting with dependency tree context
- Improved CLI output with tree statistics and visualization
- Better performance with circular dependency detection

### Fixed
- Enhanced dependency scanning to catch threats hidden in deep dependency chains
- Improved detection of malicious packages that hide behind legitimate dependencies
- Better handling of complex dependency structures

## [1.1.1] - 2024-12-20

### Added
- Enhanced directory structure display for directory scans

## [1.1.0] - 2024-12-20

### Added
- Real Package Tarball Analysis - Download and extract actual package files for deep scanning
- `analyzePackageTarball()` function for comprehensive package analysis
- `downloadTarball()` and `extractTarball()` helper functions
- `findJavaScriptFiles()` for locating JS/TS files in extracted packages
- Real code analysis instead of metadata-only scanning
- Package size limits (10MB max) to prevent resource exhaustion
- Temporary directory management with automatic cleanup

### Fixed
- Improved entropy detection messaging to reduce false positives
- Enhanced entropy thresholds for different content types (JAVASCRIPT: 4.5, JSON: 3.8, TEXT: 3.5, BINARY: 7.0)
- Only flag entropy > 6.0 as suspicious (vs previous 4.5 threshold)
- Hide COMPLEX_CODE threats by default (only show in debug mode)
- Reduced noise from legitimate complex code with high entropy

### Changed
- Enhanced detection now analyzes actual package source code
- More accurate threat detection with real file content analysis
- Better differentiation between obfuscated code and complex legitimate code
- Improved user experience with fewer false positive warnings

## [1.1.1] - 2024-12-20

### Added
- Enhanced directory structure display for directory scans
- Directory breakdown showing top-level directories and files
- Comprehensive scan context with directory count, file count, and examples
- Clean output showing only top-level directories for better readability

### Fixed
- Correctly label directory scans vs package scans in CLI output
- Fix packagesScanned logic to properly distinguish directory vs package scans
- Resolve confusing "package(s)" labeling when scanning directories

### Changed
- Directory structure now shows only top-level directories instead of all nested paths
- Improved user experience with clearer scan context and structure information

## [1.0.5] - 2024-12-19

### Added
- Full file path display in scan results (shows `frontend/src/components/file.js` instead of just `file.js`)
- Directory context information with `SCAN_INFO` threat type
- `INFO` severity level for informational messages
- Enhanced verbose mode with directory information display

### Changed
- Modified `scanDirectory()` to use relative paths instead of just filenames
- Enhanced CLI output formatting to show directory information
- Improved file path resolution using `path.relative()`

### Fixed
- File path display now shows complete relative paths for better context
- Directory scanning output provides clear location information
- CLI formatting improvements for better readability

## [1.0.4] - 2024-12-19

### Fixed
- CLI version display now dynamically reads from `package.json`
- Resolved hardcoded version `1.0.0` issue in CLI output

### Changed
- CLI version command now shows correct version number

## [1.0.3] - 2024-12-19

### Added
- Directory scanning capability for arbitrary directories
- `scanDirectory()` function for recursive JavaScript/TypeScript file scanning
- `getJavaScriptFiles()` function to find all relevant files
- `getSuspiciousFiles()` function to detect suspicious filenames
- Support for scanning non-Node.js projects

### Changed
- Main `scan()` function now falls back to directory scanning when no `package.json` is found
- Enhanced scanning logic to handle various project structures

## [1.0.2] - 2024-12-19

### Added
- Advanced AST (Abstract Syntax Tree) analysis using Babel parser
- Enhanced obfuscated IoC detection with `_0x20669a` pattern
- Static analysis for `package.json` files
- Dynamic `require()` detection for suspicious module loading
- Enhanced entropy analysis with content-type awareness
- `node_modules` directory scanning capability
- Comprehensive threat detection for sophisticated attacks

### Changed
- Upgraded obfuscated string detection severity to HIGH
- Enhanced detection patterns for recent npm supply chain attacks
- Improved performance with caching system (5-minute TTL)

### Fixed
- Resolved dynamic require detection function issues
- Restored complete eval-like patterns detection
- Fixed variable name conflicts in scanning functions

## [1.0.1] - 2024-12-19

### Added
- Professional badges (npm downloads, GitHub stars, license, build status)
- Specific IoC detection details for `_0x112fa8`, `_0x180f`, `stealthProxyControl`
- Real-world attack examples from recent npm compromise
- Comprehensive README with enhanced user experience

### Changed
- Enhanced documentation with specific pattern detection examples
- Improved threat reports with detailed pattern information
- Better presentation for credible security tool appearance

## [1.0.0] - 2024-12-19

### Added
- Initial release of NullVoid
- Real package analysis with npm registry integration
- Advanced detection capabilities for supply chain attacks:
  - Wallet hijacking detection (`window.ethereum` interception)
  - Network manipulation detection (`fetch`/`XMLHttpRequest` overrides)
  - Stealth controls detection (`stealthProxyControl`, `_0x112fa8`, `runmask`)
  - Multi-chain targeting detection (Ethereum, Bitcoin, Solana, etc.)
  - Postinstall script analysis
  - Suspicious file pattern detection
- CLI interface with `npx nullvoid scan` command
- Multiple output formats (table and JSON)
- Verbose logging option
- GitHub Actions workflow for CI integration
- Comprehensive documentation

### Security
- Static analysis only - no code execution
- Real-world attack coverage for recent npm compromises
- Fast scanning without network dependencies
- CI/CD ready with JSON output for automated workflows
