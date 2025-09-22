# NullVoid

[![npm version](https://img.shields.io/npm/v/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![npm downloads](https://img.shields.io/npm/dm/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/kurt-grung/NullVoid.svg)](https://github.com/kurt-grung/NullVoid/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/kurt-grung/NullVoid.svg)](https://github.com/kurt-grung/NullVoid/network)
[![GitHub issues](https://img.shields.io/github/issues/kurt-grung/NullVoid.svg)](https://github.com/kurt-grung/NullVoid/issues)
[![GitHub Actions](https://github.com/kurt-grung/NullVoid/workflows/NullVoid%20Security%20Scan/badge.svg)](https://github.com/kurt-grung/NullVoid/actions)

**Ø NullVoid** - Detect and invalidate malicious npm packages before they reach prod.

Detect malicious or compromised npm packages and flag risky code before it reaches production — without executing unsafe code.

## 🚀 Quick Start

```bash
# Install globally
npm i -g nullvoid

# Scan current project dependencies
npx nullvoid scan

# Scan a specific package
npx nullvoid scan suspicious-package

# Get verbose output
npx nullvoid scan --verbose

# Output results as JSON
npx nullvoid scan --output json
```

## 🔍 What NullVoid Detects

NullVoid uses multiple heuristic checks to identify potentially malicious packages, including sophisticated supply chain attacks:

### 1. **Postinstall Script Analysis**
- Detects packages with suspicious postinstall scripts
- Flags scripts that download or execute external code
- Identifies commands that could modify system files

### 2. **Code Entropy Analysis**
- Analyzes JavaScript files for unusually high entropy
- Detects obfuscated or packed code that might hide malicious intent
- Uses Shannon entropy to identify suspicious patterns

### 3. **Suspicious File Patterns**
- Scans for files with malicious naming conventions
- Detects executable files in npm packages
- Identifies hidden or obfuscated file structures

### 4. **Wallet Hijacking Detection** 🚨
- **window.ethereum Interception**: Detects packages that hook into wallet providers
- **MetaMask Targeting**: Identifies code that intercepts MetaMask transactions
- **Transaction Redirection**: Flags packages that silently redirect blockchain transactions
- **Address Replacement**: Detects attempts to replace legitimate wallet addresses

### 5. **Network Response Manipulation** 🚨
- **Fetch/XMLHttpRequest Overrides**: Detects packages that intercept network requests
- **API Response Scanning**: Identifies code that scans responses for blockchain addresses
- **Levenshtein Algorithm Detection**: Flags packages using "nearest match" algorithms
- **Address Substitution**: Detects replacement of legitimate addresses with attacker-controlled ones

### 6. **Multi-Chain Targeting** 🚨
- **Cross-Chain Support**: Detects packages supporting multiple blockchains
- **Ethereum, Bitcoin, Litecoin, Tron, BCH, Solana**: Identifies multi-chain attack capabilities
- **Broader Attack Coverage**: Flags packages that could target multiple cryptocurrency networks

### 7. **Stealth Controls & Obfuscation** 🚨
- **stealthProxyControl Detection**: Identifies hidden developer-like control interfaces
- **Obfuscation Techniques**: Detects code hiding mechanisms
- **Hidden Control Mechanisms**: Flags packages with concealed malicious functionality
- **Eval/Decode Patterns**: Identifies dynamic code execution attempts

### 8. **Traditional Malicious Patterns**
- Searches for crypto-mining code patterns
- Detects credential theft attempts
- Identifies data exfiltration mechanisms

### 9. **GPG Signature Verification** 🔐
- **Package Signature Validation**: Verifies GPG signatures in package metadata
- **Tarball Signature Files**: Checks for accompanying .asc signature files
- **Invalid Signature Detection**: Flags packages with invalid or corrupted GPG signatures
- **Suspicious Key Detection**: Identifies packages using suspiciously short or weak GPG keys
- **Package.json Signature Check**: Validates GPG signature information in package.json

## 📋 Usage Examples

### Scan Your Project
```bash
# Navigate to your project directory
cd my-project

# Scan all dependencies in package.json
npx nullvoid scan
```

### Scan Specific Packages
```bash
# Scan a single package
npx nullvoid scan express

# Scan with verbose output
npx nullvoid scan lodash --verbose
```

### CI/CD Integration
```bash
# In your CI pipeline
npx nullvoid scan --output json > security-report.json
```

## 🚨 Real-World Attack Examples

NullVoid is designed to detect sophisticated supply chain attacks like the recent npm compromise:

### **Recent Attack: debug, chalk, and 16 other packages**
- **Attack Vector**: Wallet hijacking through `window.ethereum` interception
- **Technique**: Silent transaction redirection to attacker-controlled addresses
- **Multi-Chain**: Targeted Ethereum, Bitcoin, Litecoin, Tron, BCH, and Solana
- **Stealth**: Used obfuscation and `stealthProxyControl` global object
- **Network Manipulation**: Overrode fetch/XMLHttpRequest to replace addresses
- **Obfuscated IoCs**: `_0x112fa8`, `_0x180f`, `runmask`, `newdlocal`, `checkethereumw`

### **How NullVoid Would Detect This Attack:**
```bash
# Scan would detect multiple threat types:
npx nullvoid scan

# Results would show:
⚠️  4 threat(s) detected:

1. WALLET_HIJACKING: Package may contain wallet hijacking code
   Severity: CRITICAL
   Details: Detected pattern '_0x112fa8' that could redirect transactions

2. NETWORK_MANIPULATION: Package may manipulate network responses
   Severity: HIGH
   Details: Detected pattern 'fetch.*override' for address replacement

3. MULTI_CHAIN_TARGETING: Package supports multiple blockchain networks
   Severity: MEDIUM
   Details: Detected multi-chain capabilities for broader attack coverage

4. STEALTH_CONTROLS: Package contains stealth controls or obfuscation
   Severity: HIGH
   Details: Detected pattern 'stealthProxyControl' hidden control mechanisms
```

### **Specific IoC Detection:**
NullVoid detects the exact obfuscated strings and patterns used in the recent attack:
- **`_0x112fa8`** - Primary obfuscated function identifier
- **`_0x180f`** - Secondary obfuscated string pattern  
- **`stealthProxyControl`** - Hidden developer control interface
- **`runmask`** - Malicious function name
- **`newdlocal`** - Attack-specific variable
- **`checkethereumw`** - Ethereum wallet checking function

## 🛡️ Security Features

- **Static Analysis Only**: Never executes potentially malicious code
- **Multiple Detection Methods**: Combines various heuristics for comprehensive coverage
- **Real-time Scanning**: Fast analysis without network dependencies
- **CI/CD Ready**: Easy integration into automated workflows
- **Supply Chain Focus**: Specifically designed to detect npm package compromises

## 🔧 Configuration

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--verbose` | Enable detailed output | `false` |
| `--output <format>` | Output format (json, table) | `table` |
| `--depth <number>` | Maximum dependency tree depth to scan | `3` |
| `--tree` | Show dependency tree structure in output | `false` |
| `--version` | Show version information | - |
| `--help` | Show help information | - |

### Example Output

```
🔍 NullVoid Scan Results

⚠️  2 threat(s) detected:

1. POSTINSTALL_SCRIPT: Package contains postinstall script with suspicious commands
   Package: suspicious-package
   Severity: HIGH

2. HIGH_ENTROPY: Package contains files with unusually high entropy
   Package: obfuscated-lib
   Severity: MEDIUM

Scanned 15 package(s) in 234ms
```

## 🚨 Threat Severity Levels

- **CRITICAL**: Wallet hijacking, transaction redirection, or immediate financial threat
- **HIGH**: Network manipulation, stealth controls, or significant security risk
- **MEDIUM**: Suspicious behavior requiring review
- **LOW**: Minor concerns or best practice violations

## 🌳 Dependency Tree Analysis

NullVoid now includes comprehensive **Dependency Tree Analysis** to scan transitive dependencies for hidden threats:

### **Deep Dependency Scanning**
- **Transitive Dependencies**: Scans all dependencies up to 3 levels deep by default
- **Hidden Threats**: Detects malicious packages buried deep in dependency chains
- **Circular Dependencies**: Identifies circular dependency patterns that could hide attacks
- **Suspicious Package Names**: Flags packages with randomly generated or suspicious names

### **Tree Structure Analysis**
- **Depth Controls**: Configure maximum scanning depth with `--depth` option
- **Tree Visualization**: View complete dependency tree with `--tree` flag
- **Threat Mapping**: See exactly where threats are located in the dependency chain
- **Statistics**: Get comprehensive analysis of your dependency tree

### **Usage Examples**

```bash
# Scan with dependency tree analysis (default depth: 3)
npx nullvoid scan

# Scan deeper dependency chains
npx nullvoid scan --depth 5

# Show dependency tree structure
npx nullvoid scan --tree

# Verbose output with tree details
npx nullvoid scan --tree --verbose

# JSON output with full tree data
npx nullvoid scan --output json
```

### **Example Output**

```
🌳 Dependency Tree Structure:
express@4.18.2 [25 deps]
  accepts@1.3.8 [3 deps]
  array-flatten@1.1.1
  body-parser@1.20.1 [8 deps]
    bytes@3.1.2
    content-type@1.0.4
    debug@2.6.9 (1 threat) ⚠ WALLET_HIJACKING: Package may contain wallet hijacking code
    depd@2.0.0

📊 Dependency Tree Analysis:
   Total packages scanned: 45
   Max depth reached: 3
   Packages with threats: 2
   Deep dependencies (depth ≥2): 12
```

## 🚀 Upcoming Features

### High Priority
- **SARIF Output Format** - Better CI/CD integration with standardized security reporting
- **Configurable Rules System** - JSON/YAML configuration for custom detection patterns
- **Parallel Scanning** - Multi-threaded analysis for faster results

### Performance & Integration
- **Parallel Scanning** - Multi-threaded analysis for faster results
- **Public IoC Feeds** - Integration with Snyk, npm advisories, and other threat intelligence
- **Signature Verification** - Detect package tampering and verify integrity with GPG signatures
- **Structured Logging** - Comprehensive reporting and audit trails

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
