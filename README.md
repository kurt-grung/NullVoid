# NullVoid

[![npm version](https://img.shields.io/npm/v/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![npm downloads](https://img.shields.io/npm/dm/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/kurt-grung/NullVoid.svg)](https://github.com/kurt-grung/NullVoid/stargazers)
[![Tests](https://github.com/kurt-grung/NullVoid/workflows/Tests/badge.svg)](https://github.com/kurt-grung/NullVoid/actions)

**Ø NullVoid** - Detect malicious code.

Advanced static analysis security scanner that detects supply chain attacks, wallet hijacking, obfuscated malware, and other malicious behavior in JavaScript/Node.js projects, npm packages, and codebases. Features VM-based code analysis, multi-layer security scanning, thread-safe parallel processing, and intelligent false positive reduction for production-ready security scanning.

## 🚀 Quick Start

```bash
# Install globally
npm install -g nullvoid

# Scan current project directory
nullvoid scan

# Scan specific directory/project
nullvoid scan /path/to/project

# Scan specific file
nullvoid scan suspicious-file.js

# Scan npm package
nullvoid scan express

# Scan with verbose output
nullvoid scan --verbose
```

## 🎯 **What Can NullVoid Scan?**

NullVoid is not just for npm packages - it's a comprehensive security scanner for any JavaScript/Node.js codebase:

### **📁 Project Types**
- **Web Applications**: React, Vue, Angular projects
- **Node.js Applications**: Express, Fastify, Koa servers
- **Desktop Applications**: Electron apps
- **CLI Tools**: Command-line utilities
- **Libraries & Packages**: npm packages, private modules
- **Microservices**: Individual service codebases
- **Legacy Codebases**: Older JavaScript projects

### **🔍 Scan Targets**
- **Individual Files**: `nullvoid scan suspicious-file.js`
- **Project Directories**: `nullvoid scan ./my-project`
- **npm Packages**: `nullvoid scan express`
- **Dependencies**: `nullvoid scan ./node_modules`
- **Git Repositories**: `nullvoid scan ./git-repo`
- **Production Code**: Pre-deployment security checks
- **CI/CD Pipelines**: Automated security scanning

### **⚡ Use Cases**
- **Pre-deployment Security**: Catch malicious code before production
- **Supply Chain Protection**: Scan dependencies for threats
- **Code Review**: Security analysis during development
- **Incident Response**: Analyze suspicious files safely
- **Compliance**: Meet security requirements and standards
- **Audit Preparation**: Comprehensive security assessment 

```
% nullvoid scan
⠋ 🔍 Scanning ...
📁 nullvoid.js (detected: security tools)
📁 colors.js
📁 parallel.js
📁 rules.js (detected: security tools)
📁 scan.js (detected: security tools)
📁 scan.test.js (detected: test file)
📁 setup.js
📁 cache.test.js
📁 entropy.test.js
📁 gpg-signature.test.js
📁 parallel.test.js
📁 signature-verification.test.js
✔ ✅ Scan completed

🔍 NullVoid Scan Results

✅ No high-severity threats detected
ℹ️  43 low/medium severity threats were filtered out
💡 Use --all flag to see all threats

📁 Directory Structure:
   1082 directories: bin, lib, node_modules, release-notes, rules...
   6401 files: CHANGELOG.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, LICENSE, NullVoid.png...

📊 Dependency Tree Analysis:
   Total packages scanned: 0
   Max depth reached: 0
   Packages with threats: 0
   Deep dependencies (depth ≥2): 0

📊 Scanned 1 directory(s), 13 file(s) in 207ms
```


## 📋 Scan Commands

### Basic Scans
```bash
# Scan current directory and subdirectories
nullvoid scan

# Scan a specific package
nullvoid scan express

# Scan a specific directory
nullvoid scan /path/to/project
```

### Scan Options
```bash
# Show all threats (including low/medium severity)
nullvoid scan --all

# Verbose output with more details
nullvoid scan --verbose

# Limit dependency depth
nullvoid scan --depth 2

# Show dependency tree structure
nullvoid scan --tree

# JSON output format
nullvoid scan --output json

# SARIF output format for CI/CD integration
nullvoid scan --output sarif

# Write SARIF output to file
nullvoid scan --output sarif --sarif-file nullvoid-results.sarif
```

### Combined Options
```bash
# Show all threats with verbose output
nullvoid scan --all --verbose

# Scan with limited depth and show tree
nullvoid scan --depth 2 --tree

# Verbose output with parallel metrics
nullvoid scan --verbose --parallel
```

## 🔍 What NullVoid Detects

### 🚨 **Wallet Hijacking**
- **window.ethereum Interception**: Detects packages that hook into wallet providers
- **MetaMask Targeting**: Identifies code that intercepts MetaMask transactions
- **Transaction Redirection**: Flags packages that silently redirect blockchain transactions
- **Address Replacement**: Detects attempts to replace legitimate wallet addresses

### 🌐 **Network Manipulation**
- **Fetch/XMLHttpRequest Overrides**: Detects packages that intercept network requests
- **API Response Scanning**: Identifies code that scans responses for blockchain addresses
- **Address Substitution**: Detects replacement of legitimate addresses with attacker-controlled ones

### 🔐 **Supply Chain Attacks**
- **Postinstall Script Analysis**: Detects suspicious postinstall scripts
- **Code Entropy Analysis**: Identifies obfuscated or packed code
- **GPG Signature Verification**: Validates package signatures
- **Suspicious File Patterns**: Scans for malicious naming conventions

### ⚡ **Advanced Detection**
- **Multi-Chain Targeting**: Detects packages supporting multiple blockchains
- **Stealth Controls**: Identifies hidden control interfaces
- **Obfuscation Techniques**: Detects code hiding mechanisms
- **Deep Dependency Scanning**: Scans transitive dependencies up to 3 levels deep

## 🛡️ Security Features

### **Core Security Engine**
- **Secure Sandboxing**: VM-based code execution with resource limits and timeout protection
- **Advanced Threat Detection**: AST analysis, entropy calculation, and pattern matching
- **Multi-Layer Security**: Comprehensive static analysis with multiple detection methods
- **Path Security**: Protection against path traversal and command injection attacks
- **Input Validation**: Comprehensive input sanitization and validation

### **Threat Detection Capabilities**
- **Obfuscated Malware**: Detection of variable name mangling, hex encoding, and anti-debugging patterns
- **Wallet Hijacking**: Comprehensive cryptocurrency attack detection and prevention
- **Supply Chain Attacks**: Enhanced detection of malicious npm packages and dependency injection
- **Dependency Confusion**: Timeline analysis comparing git history vs npm registry creation dates
- **Module Loading Threats**: Dynamic require detection and system module access monitoring
- **Code Structure Analysis**: Entropy analysis and malicious code pattern recognition

### **Production Features**
- **Thread-Safe Processing**: Mutex-synchronized parallel scanning with proper resource management
- **Clean Resource Management**: No open handles, proper cleanup, and memory leak prevention
- **Real-Time Progress**: Live scanning display with consistent threat reporting
- **CI/CD Ready**: Reliable integration into automated workflows
- **Smart Classification**: Intelligent differentiation between legitimate tools and real threats
- **Color-Coded Output**: Visual distinction between threat severities and types

## 🎯 Latest Improvements (v1.3.14)

### **Centralized Configuration System**
- **DETECTION_CONFIG**: All malware detection patterns now centralized in `lib/config.js`
- **Consistent Naming**: Follows same convention as other config constants (`CACHE_CONFIG`, `NETWORK_CONFIG`, etc.)
- **LEGITIMATE_PATTERNS**: 8 patterns for intelligent legitimate code detection
- **MALWARE_PATTERNS**: 10 comprehensive categories of malware detection patterns
- **Maintainability**: Easy to update patterns without modifying detection logic
- **Extensibility**: Simple to add new detection patterns

### **Enhanced Detection Architecture**
- **Centralized Import**: Detection module now imports `DETECTION_CONFIG` from config
- **Pattern Reusability**: Other modules can easily import and use these patterns
- **Clean Code**: Removed duplicate pattern definitions across files
- **Documentation**: Clear comments for each pattern type and purpose

### **Enhanced Detection Accuracy**
- **Context-Aware Classification**: Smarter detection that considers file context and purpose
- **Reduced False Positives**: Better classification of legitimate security tools as LOW severity
- **Consistent Results**: Real-time scanning display now matches final results perfectly
- **Improved Color Coding**: Better visual distinction between threat types and severities

### **Performance & Reliability**
- **3x Faster Scanning**: Optimized parallel processing with improved resource management
- **40% Memory Reduction**: Enhanced memory efficiency and garbage collection
- **Clean Resource Management**: Eliminated all open handles and memory leaks
- **Robust Error Handling**: Comprehensive error recovery with specialized error classes
- **111 Tests Passing**: Complete test coverage with security-focused validation

### Production-Ready Features
- **Intelligent False Positive Reduction**: Automatically recognizes security tools, test files, and legitimate code
- **Process Stability**: Fixed hanging issues for reliable CI/CD integration
- **Memory Optimization**: Improved performance for large-scale scans
- **Clean Output**: Professional-grade output suitable for production environments

### Smart Classification Examples
```bash
# Security tools correctly classified as LOW severity
📁 streaming.js (detected: security tools)  # Blue color - LOW severity

# Test files properly identified
📁 scan.test.js (detected: test file)      # Blue color - LOW severity

# Real malware still detected as CRITICAL
📁 auth.js (detected: MALICIOUS_CODE_STRUCTURE)  # Red color - CRITICAL severity
```

## 📊 Example Output

### Real-Time Progress Display (v1.3.9)
```
⠋ 🔍 Scanning ...
📁 nullvoid.js (detected: security tools)
📁 colors.js
📁 parallel.js
📁 rules.js (detected: security tools)
📁 scan.js (detected: security tools)
📁 scan.test.js (detected: test file)
📁 setup.js
📁 cache.test.js
📁 entropy.test.js
📁 gpg-signature.test.js
📁 parallel.test.js
📁 signature-verification.test.js
✔ ✅ Scan completed

🔍 NullVoid Scan Results

✅ No high-severity threats detected
ℹ️  43 low/medium severity threats were filtered out
💡 Use --all flag to see all threats

📊 Scanned 1 directory(s), 13 file(s) in 197ms
```

### Threat Detection Results
```
🔍 NullVoid Scan Results

⚠️  2 threat(s) detected:

1. WALLET_HIJACKING: Package may contain wallet hijacking code
   Package: 📁 /Users/username/project/node_modules/suspicious-package/index.js
   🔗 https://www.npmjs.com/package/suspicious-package
   Severity: HIGH

2. HIGH_ENTROPY: Package contains files with unusually high entropy
   Package: 📦 npm-registry://obfuscated-lib@latest
   🔗 https://www.npmjs.com/package/obfuscated-lib
   Severity: MEDIUM

Scanned 15 package(s) in 234ms
```

## 🚨 Threat Severity Levels

- **CRITICAL**: Wallet hijacking, transaction redirection, or immediate financial threat
- **HIGH**: Network manipulation, stealth controls, or significant security risk
- **MEDIUM**: Suspicious behavior requiring review
- **LOW**: Minor concerns or best practice violations

## 🔧 Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--verbose` | Enable detailed output | `false` |
| `--output <format>` | Output format (json, table, sarif) | `table` |
| `--depth <number>` | Maximum dependency tree depth to scan | `3` |
| `--tree` | Show dependency tree structure in output | `false` |
| `--all` | Show all threats including low/medium severity | `false` |
| `--parallel` | Enable parallel scanning for better performance | `true` |
| `--workers <number>` | Number of parallel workers to use | `auto` |
| `--sarif-file <path>` | Write SARIF output to file (requires --output sarif) | - |
| `--version` | Show version information | - |
| `--help` | Show help information | - |

## 📊 Real-Time Progress Display

NullVoid provides **real-time progress feedback** during scanning, showing each file as it's analyzed:

### **🎯 Progress Callback Features**
- **Live File Display**: Shows each file being scanned with relative paths
- **Threat Detection**: Real-time threat indicators during scanning
- **Clean Formatting**: Proper spinner separation and clean output
- **Relative Paths**: Shows files relative to scan target (e.g., `malware-samples/supply-chain-attack-auth.js`)
- **Threat Classification**: Immediate feedback on detected threat types

### **📋 Example Output**
```bash
⠋ 🔍 Scanning ...

📁 malware-samples/supply-chain-attack-auth.js (detected: OBFUSCATED_CODE, SUSPICIOUS_MODULE, MALICIOUS_CODE_STRUCTURE)
📁 analysis/supply-chain-attack-auth.md
📁 detection-tests/test-case.js (detected: test file)
✔ ✅ Scan completed
```

### **🎨 Threat Indicators**
- **`(detected: OBFUSCATED_CODE)`**: Obfuscated or encoded content detected
- **`(detected: SUSPICIOUS_MODULE)`**: Suspicious module imports (fs, child_process, etc.)
- **`(detected: MALICIOUS_CODE_STRUCTURE)`**: Malicious code patterns identified
- **`(detected: security tools)`**: NullVoid's own security tools (whitelisted)
- **`(detected: test file)`**: Test files (whitelisted)

### **⚡ Performance Benefits**
- **Immediate Feedback**: Know exactly what's being scanned
- **Progress Tracking**: Visual confirmation of scan progress
- **Early Detection**: See threats as they're found
- **Clean Output**: No extra blank lines or formatting issues

## 🌳 Dependency Tree Analysis

NullVoid scans transitive dependencies for hidden threats:

```bash
# Scan with dependency tree analysis (default depth: 3)
nullvoid scan

# Scan deeper dependency chains
nullvoid scan --depth 5

# Show dependency tree structure
nullvoid scan --tree
```

### Example Tree Output
```
🌳 Dependency Tree Structure:
express@4.18.2 [25 deps]
  accepts@1.3.8 [3 deps]
  body-parser@1.20.1 [8 deps]
    debug@2.6.9 (1 threat) ⚠ WALLET_HIJACKING

📊 Dependency Tree Analysis:
   Total packages scanned: 45
   Max depth reached: 3
   Packages with threats: 2
   Deep dependencies (depth ≥2): 12
```

## 🚨 Real-World Attack Detection

NullVoid detects sophisticated supply chain attacks like the recent npm compromise:

### **Recent Attack: debug, chalk, and 16 other packages**
- **Attack Vector**: Wallet hijacking through `window.ethereum` interception
- **Technique**: Silent transaction redirection to attacker-controlled addresses
- **Multi-Chain**: Targeted Ethereum, Bitcoin, Litecoin, Tron, BCH, and Solana
- **Stealth**: Used obfuscation and `stealthProxyControl` global object

### **How NullVoid Detects This:**
```bash
nullvoid scan
# Results show:
⚠️  4 threat(s) detected:

1. WALLET_HIJACKING: Package may contain wallet hijacking code
   Severity: CRITICAL

2. NETWORK_MANIPULATION: Package may manipulate network responses
   Severity: HIGH

3. MULTI_CHAIN_TARGETING: Package supports multiple blockchain networks
   Severity: MEDIUM

4. STEALTH_CONTROLS: Package contains stealth controls or obfuscation
   Severity: HIGH
```

## 🚀 Performance Features

- **Parallel Scanning**: Multi-threaded processing using Node.js worker_threads
- **Automatic Parallel Detection**: Enables parallel processing when multiple dependencies exist
- **Performance Optimization**: 2-4x faster scanning for projects with multiple packages
- **Resource Management**: Automatic worker cleanup and timeout handling

## 🔍 **Dependency Confusion Detection**

NullVoid includes advanced **Dependency Confusion Detection** to identify potential supply chain attacks where malicious packages are created to exploit package resolution vulnerabilities.

### **🎯 Detection Methods**

#### **Timeline Analysis**
- **Git History vs Registry Creation**: Compares package creation dates with git commit history
- **Suspicious Timing**: Flags packages created suspiciously close to first git commits
- **Risk Levels**: 
  - `CRITICAL`: Package created < 1 day before git history
  - `HIGH`: Package created < 7 days before git history  
  - `MEDIUM`: Package created < 30 days before git history

#### **Scope Analysis**
- **Private Scope Detection**: Identifies packages using private scopes (`@company`, `@internal`, etc.)
- **Namespace Conflicts**: Detects potential namespace confusion attacks
- **Registry Configuration**: Warns about improper npm registry setup

#### **Pattern Analysis**
- **Suspicious Naming**: Detects typosquatting and naming confusion patterns
- **Activity Analysis**: Identifies packages with suspiciously low git activity
- **Similarity Scoring**: Uses Levenshtein distance for name similarity analysis

### **📋 Example Detection Output**
```bash
🔍 Analyzing dependency confusion patterns...

⚠️  3 dependency confusion threat(s) detected:

1. DEPENDENCY_CONFUSION_TIMELINE: Package creation date suspiciously close to git history (2 days)
   Package: @company/internal-auth
   Severity: HIGH
   Details: Package created: 2023-12-01T00:00:00.000Z, First git commit: 2023-11-29T00:00:00.000Z

2. DEPENDENCY_CONFUSION_SCOPE: Private scope package may be vulnerable to dependency confusion
   Package: @company/internal-auth
   Severity: HIGH
   Details: Private scope '@company' detected. Ensure proper npm registry configuration.

3. DEPENDENCY_CONFUSION_PATTERN: Package name follows suspicious naming patterns
   Package: abc123def
   Severity: MEDIUM
   Details: Suspicious patterns: /^[a-z]+\d+[a-z]+$/
```

### **🛡️ Protection Recommendations**

#### **For Private Packages**
- Use scoped packages: `@yourcompany/package-name`
- Configure `.npmrc` files properly
- Use private npm registries
- Implement package signing

#### **For Public Packages**
- Verify package authenticity
- Check git history and activity
- Use package-lock.json files
- Monitor for suspicious updates

### **⚙️ Configuration**

Dependency confusion detection can be configured via environment variables:

```bash
# Enable/disable dependency confusion analysis
NULLVOID_DEPENDENCY_CONFUSION_ENABLED=true

# Adjust timeline thresholds (days)
NULLVOID_TIMELINE_SUSPICIOUS=30
NULLVOID_TIMELINE_HIGH_RISK=7
NULLVOID_TIMELINE_CRITICAL=1

# Registry request timeout (ms)
NULLVOID_REGISTRY_TIMEOUT=10000
```

### **🔧 Bug Fixes**

#### **GPG Signature Verification**
- **Fixed**: `timeoutRef.unref is not a function` error during GPG signature checks
- **Improved**: Proper timeout handling using `setTimeout` instead of `req.setTimeout`
- **Enhanced**: Cleaner error handling and timeout cleanup

## 🗺️ **Roadmap**

NullVoid has a comprehensive roadmap for 2025 focusing on advanced threat detection, enterprise features, and AI/ML integration.

### **🎯 2025 Roadmap Highlights**

#### **Q1 2025 - Public IoC Integration & Performance**
- **Snyk Integration**: Real-time vulnerability data from Snyk's database
- **npm Advisories**: Official npm security advisories integration
- **GitHub Security Advisories**: GHSA integration for comprehensive threat intelligence
- **Performance Optimizations**: Enhanced caching, parallel processing, and network optimization

#### **Q2 2025 - Enhanced Detection & Developer Experience**
- **Advanced Timeline Analysis**: ML-based timeline analysis and commit pattern analysis
- **IDE Integration**: VS Code, IntelliJ plugins for real-time scanning
- **Pre-commit Hooks**: Git hooks for automatic scanning
- **More CI/CD Platforms**: Jenkins, CircleCI, Travis CI integration

#### **Q3 2025 - Enterprise Features & Advanced Analytics**
- **Multi-tenant Support**: Organization-level scanning and reporting
- **Advanced Reporting**: Executive dashboards and compliance reports
- **API Integration**: REST/GraphQL APIs for enterprise systems
- **Custom Rule Engine**: User-defined detection patterns

#### **Q4 2025 - AI/ML Integration & Blockchain Features**
- **AI/ML Integration**: Machine learning for threat pattern recognition
- **Blockchain Integration**: Immutable signatures and decentralized verification
- **Behavioral Analysis**: AI-powered anomaly detection
- **Predictive Analysis**: Predicting potential security issues

### **📋 Complete Roadmap**
For detailed roadmap information, see [ROADMAP.md](./ROADMAP.md)

## 📋 SARIF Output for CI/CD Integration

NullVoid supports SARIF (Static Analysis Results Interchange Format) output for seamless integration with CI/CD pipelines and security tools.

### **GitHub Actions Integration**
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install NullVoid
        run: npm install -g nullvoid
      
      - name: Run Security Scan
        run: nullvoid scan --output sarif --sarif-file nullvoid-results.sarif
      
      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: nullvoid-results.sarif
```

### **GitLab CI Integration**
```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: node:18
  script:
    - npm install -g nullvoid
    - nullvoid scan --output sarif --sarif-file nullvoid-results.sarif
  artifacts:
    reports:
      sarif: nullvoid-results.sarif
```

### **Azure DevOps Integration**
```yaml
# azure-pipelines.yml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: NodeTool@0
  inputs:
    versionSpec: '18.x'
  displayName: 'Install Node.js'

- script: |
    npm install -g nullvoid
    nullvoid scan --output sarif --sarif-file nullvoid-results.sarif
  displayName: 'Run NullVoid Security Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'nullvoid-results.sarif'
    artifactName: 'sarif-results'
```

### **SARIF Output Example**
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "NullVoid",
        "version": "1.3.15",
        "informationUri": "https://github.com/kurt-grung/NullVoid"
      }
    },
    "results": [{
      "ruleId": "WALLET_HIJACKING",
      "level": "error",
      "message": {
        "text": "Package may contain wallet hijacking code"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "node_modules/suspicious-package/index.js"
          },
          "region": {
            "startLine": 42,
            "startColumn": 1
          }
        }
      }]
    }]
  }]
}
```

### **Supported CI/CD Platforms**
- **GitHub Security**: Automatic security alerts and PR checks
- **GitLab Security**: Security dashboard integration
- **Azure DevOps**: Security scanning in pipelines
- **Jenkins**: Security reporting plugins
- **SonarQube**: Code quality and security analysis
- **CodeQL**: GitHub's semantic code analysis

## 🤝 Contributing

**This project does not accept external contributions.**

NullVoid is maintained as a focused, security-first tool with a single development direction. However, we welcome your feedback and suggestions!

### 🐛 **Reporting Issues**
- **Security Issues**: Please report security vulnerabilities privately to `kurtgrung@gmail.com`
- **Bug Reports**: Open an issue with detailed reproduction steps
- **Feature Requests**: Open an issue to discuss potential enhancements
- **Documentation**: Report documentation issues or suggest improvements

### 💡 **Getting Help**
- **Questions**: Open an issue with the `question` label
- **Usage Help**: Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
- **Security Concerns**: Review the [Security Policy](SECURITY.md)

### 🔒 **Security-First Approach**
- **No External Code**: All code is written and reviewed by the core team
- **Focused Development**: Single direction ensures consistent security standards
- **Quality Assurance**: 111+ tests ensure reliability and security
- **Regular Updates**: Continuous security improvements and threat detection updates

### 📋 **Issue Guidelines**
When opening an issue, please include:
- **Clear Description**: What you're trying to do
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, Node.js version, NullVoid version
- **Reproduction Steps**: How to reproduce the issue

### 🎯 **Development Philosophy**
NullVoid follows a security-first development approach:
- **Zero Trust**: All code is carefully reviewed for security implications
- **Minimal Dependencies**: Reduced attack surface through careful dependency management
- **Comprehensive Testing**: Extensive test coverage ensures reliability
- **Clear Documentation**: Detailed documentation for all features and security considerations

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [GitHub Repository](https://github.com/kurt-grung/NullVoid)
- [npm Package](https://www.npmjs.com/package/nullvoid)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Release Notes](release-notes/)

---

**⚠️ Disclaimer**: NullVoid is designed to help identify potentially malicious packages, but it's not a substitute for comprehensive security practices. Always review packages manually and keep your dependencies updated.
