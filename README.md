# NullVoid

[![npm version](https://img.shields.io/npm/v/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![npm downloads](https://img.shields.io/npm/dm/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/kurt-grung/NullVoid.svg)](https://github.com/kurt-grung/NullVoid/stargazers)

**Ø NullVoid** - Detect malicious code before they reach production.

Static analysis security scanner for npm packages that detects supply chain attacks, wallet hijacking, and other malicious behavior without executing unsafe code. Features real-time progress display and parallel processing for enhanced performance.

## 🚀 Quick Start

```bash
# Install globally
npm install -g nullvoid

# Basic scan (current directory and subdirectories)
nullvoid scan

# Scan specific package
nullvoid scan express

# Scan specific directory
nullvoid scan /path/to/project
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

- **Static Analysis Only**: Never executes potentially malicious code
- **Multiple Detection Methods**: Combines various heuristics for comprehensive coverage
- **Real-time Scanning**: Fast analysis without network dependencies
- **CI/CD Ready**: Easy integration into automated workflows
- **Real-Time Progress Display**: Shows current file being scanned with threat detection
- **Parallel Processing**: 2-4x faster scanning for projects with multiple dependencies
- **Smart Threat Classification**: Differentiates legitimate security tools from real threats
- **Color-Coded Output**: Visual distinction between threat severities
- **Enhanced Path Display**: Full absolute file system paths for all packages
- **Clickable npm Links**: Direct links to npm package pages for verification

## 📊 Example Output

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
| `--output <format>` | Output format (json, table) | `table` |
| `--depth <number>` | Maximum dependency tree depth to scan | `3` |
| `--tree` | Show dependency tree structure in output | `false` |
| `--all` | Show all threats including low/medium severity | `false` |
| `--parallel` | Enable parallel scanning for better performance | `true` |
| `--workers <number>` | Number of parallel workers to use | `auto` |
| `--version` | Show version information | - |
| `--help` | Show help information | - |

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

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/kurt-grung/NullVoid.git
cd NullVoid

# Install dependencies
npm install

# Run tests
npm test

# Test the CLI
node bin/nullvoid.js scan
```

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