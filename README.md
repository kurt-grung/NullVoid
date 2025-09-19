# NullVoid

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

NullVoid uses multiple heuristic checks to identify potentially malicious packages:

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

### 4. **Malicious Code Patterns**
- Searches for crypto-mining code patterns
- Detects credential theft attempts
- Identifies data exfiltration mechanisms

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

## 🛡️ Security Features

- **Static Analysis Only**: Never executes potentially malicious code
- **Multiple Detection Methods**: Combines various heuristics for comprehensive coverage
- **Real-time Scanning**: Fast analysis without network dependencies
- **CI/CD Ready**: Easy integration into automated workflows

## 🔧 Configuration

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--verbose` | Enable detailed output | `false` |
| `--output <format>` | Output format (json, table) | `table` |
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

- **HIGH**: Immediate threat requiring action
- **MEDIUM**: Suspicious behavior requiring review
- **LOW**: Minor concerns or best practice violations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/nullvoid/nullvoid.git
cd nullvoid

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

- [GitHub Repository](https://github.com/nullvoid/nullvoid)
- [npm Package](https://www.npmjs.com/package/nullvoid)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

**⚠️ Disclaimer**: NullVoid is designed to help identify potentially malicious packages, but it's not a substitute for comprehensive security practices. Always review packages manually and keep your dependencies updated.
