# Changelog

All notable changes to NullVoid will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- SARIF output format for CI/CD integration
- Configurable rules system (JSON/YAML)
- Parallel scanning for performance improvements
- Public IoC feeds integration (Snyk, npm advisories)
- GPG signature support
- Blockchain integration for immutable signatures

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
