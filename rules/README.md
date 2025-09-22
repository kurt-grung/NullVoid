# NullVoid Configurable Rules

This directory contains example configuration files for customizing NullVoid's detection rules.

## 📁 Files

- `example-rules.yml` - YAML format example rules
- `example-rules.json` - JSON format example rules
- `enterprise-rules.yml` - Enterprise-specific rules example
- `strict-rules.yml` - Strict security rules example

## 🚀 Usage

### Basic Usage
```bash
# Use custom rules file
nullvoid scan --rules ./rules/example-rules.yml

# Use JSON rules
nullvoid scan --rules ./rules/example-rules.json
```

### Rule File Structure

#### YAML Format
```yaml
detection_rules:
  wallet_hijacking:
    patterns:
      - '_0x112fa8'
      - 'stealthProxyControl'
    severity: HIGH
    description: 'Detects wallet hijacking patterns'
    
  custom_threats:
    patterns:
      - 'my-custom-pattern'
      - 'company-specific-threat'
    severity: MEDIUM
    description: 'Custom threat detection'

global_config:
  entropy_threshold: 5.0
  max_file_size: '10MB'
  scan_timeout: 30000

severity_overrides:
  wallet_hijacking: CRITICAL
  network_manipulation: HIGH
```

#### JSON Format
```json
{
  "detection_rules": {
    "wallet_hijacking": {
      "patterns": ["_0x112fa8", "stealthProxyControl"],
      "severity": "HIGH",
      "description": "Detects wallet hijacking patterns"
    }
  },
  "global_config": {
    "entropy_threshold": 5.0,
    "max_file_size": "10MB"
  }
}
```

## 🎯 Rule Types

### Built-in Rule Categories
- **wallet_hijacking** - Detects crypto wallet manipulation
- **network_manipulation** - Detects network response tampering
- **obfuscated_code** - Detects obfuscated or suspicious code
- **suspicious_scripts** - Detects malicious package scripts
- **crypto_mining** - Detects cryptocurrency mining code

### Custom Rules
You can add your own rule categories with custom patterns and severity levels.

## ⚙️ Configuration Options

### Global Config
- `entropy_threshold` - Entropy threshold for obfuscation detection
- `max_file_size` - Maximum file size to scan
- `scan_timeout` - Timeout for scan operations
- `enable_verbose` - Enable verbose output

### Severity Levels
- `CRITICAL` - Immediate threat, block installation
- `HIGH` - Significant security risk
- `MEDIUM` - Moderate concern
- `LOW` - Minor issue or best practice violation

## 📝 Examples

### Enterprise Rules
```yaml
detection_rules:
  internal_tools:
    patterns:
      - 'company-internal-api'
      - 'staging-environment'
    severity: LOW
    description: 'Internal company tools'
    
  competitor_analysis:
    patterns:
      - 'competitor-data-scraper'
      - 'market-analysis-tool'
    severity: HIGH
    description: 'Competitor analysis tools'
```

### Strict Security Rules
```yaml
detection_rules:
  strict_wallet_protection:
    patterns:
      - 'ethereum'
      - 'bitcoin'
      - 'wallet'
      - 'crypto'
    severity: CRITICAL
    description: 'Strict crypto-related pattern detection'
    
severity_overrides:
  wallet_hijacking: CRITICAL
  network_manipulation: CRITICAL
  obfuscated_code: HIGH
```

## 🔧 Integration

Rules are automatically loaded and applied during scanning. Custom rules extend the default detection patterns without replacing them.

## 📚 Documentation

For more information, see:
- [Main README](../README.md)
- [Changelog](../CHANGELOG.md)
- [Contributing Guide](../CONTRIBUTING.md)
