# Using NullVoid

Everything the CLI accepts, what the output looks like and how to configure it. The [README](../README.md) has the short version.

## Scan Commands

### Scan
```bash
# Scan current directory and subdirectories
nullvoid

# Scan a specific package
nullvoid express

# Scan a specific directory (recursively finds all package.json subdirs)
nullvoid /path/to/project
```

### GitHub CI Actions Integration
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install NullVoid
        run: npm install -g nullvoid
      
      - name: Run Security Scan
        run: nullvoid . --output sarif --sarif-file nullvoid-results.sarif
      
      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nullvoid-results.sarif
```

### Pre-commit hooks (optional)

Run NullVoid before each commit and block the commit if threats are found. Requires [Husky](https://typicode.github.io/husky/) (or any git hook runner).

1. **Enable NullVoid in pre-commit** by setting the environment variable (e.g. in your shell or `.env`):
   ```bash
   export NULLVOID_PRE_COMMIT=1
   ```

2. **Example `.husky/pre-commit`** (Husky runs this on `git commit`):
   ```bash
   npx lint-staged

   # Optional: run NullVoid and block commit if threats found
   if [ "$NULLVOID_PRE_COMMIT" = "1" ]; then
     npm run build && node scripts/nullvoid-pre-commit.js
   fi
   ```

   The pre-commit script runs a fast scan (`--depth 1`, `--no-ioc`) and exits with code 1 if any threats are detected, so the commit is aborted.    Omit the `if` block or leave `NULLVOID_PRE_COMMIT` unset to skip NullVoid on commit.

### GitLab CI

Add a job to run NullVoid on push/merge. Example `.gitlab-ci.yml` (or copy from [ci-examples/gitlab-ci.yml](ci-examples/gitlab-ci.yml)):

```yaml
# .gitlab-ci.yml
stages:
  - test

nullvoid-scan:
  stage: test
  image: node:20
  before_script:
    - npm ci
  script:
    - npx nullvoid . --output json --sarif-file nullvoid-results.sarif
  artifacts:
    when: always
    paths:
      - nullvoid-results.sarif
    reports:
      sast: nullvoid-results.sarif
```

Use `npm ci && npm run build && node ts/dist/bin/nullvoid.js . ...` if building from the NullVoid repo (root `npm ci` installs all workspaces). **CircleCI**, **Travis CI** and **Azure DevOps** examples: [ci-examples/](ci-examples/). For IntelliJ, Sublime, and Vim integration, see [docs/IDE_INTEGRATION.md](IDE_INTEGRATION.md).


### Scan Options
```bash
# Show all threats (including low/medium severity)
nullvoid --all
# or
nullvoid . --all

# Verbose output with more details
nullvoid --verbose
# or
nullvoid . --verbose

# Limit dependency depth
nullvoid --depth 2
# or
nullvoid . --depth 2

# JSON output format
nullvoid --format json
# or
nullvoid . --format json

# Output to file
nullvoid --output results.json
# or
nullvoid . --output results.json

# SARIF output format for CI/CD integration
nullvoid --format sarif
# or
nullvoid . --format sarif

# Write SARIF output to file
nullvoid --sarif nullvoid-results.sarif
# or
nullvoid . --sarif nullvoid-results.sarif

# Include development dependencies
nullvoid --include-dev
# or
nullvoid . --include-dev

# Skip cache
nullvoid --skip-cache
# or
nullvoid . --skip-cache

# Debug mode
nullvoid --debug
# or
nullvoid . --debug

# IoC provider selection (v2.1.0+)
nullvoid --ioc-providers npm,ghsa,cve
# or
nullvoid . --ioc-providers snyk,npm,ghsa,cve

# Disable IoC scanning
nullvoid --no-ioc
# or
nullvoid . --no-ioc

# View cache statistics (v2.1.0+)
nullvoid --cache-stats
# or
nullvoid . --cache-stats

# Enable Redis cache (v2.1.0+)
nullvoid --enable-redis
# or
nullvoid . --enable-redis

# View network statistics (v2.1.0+)
nullvoid --network-stats
# or
nullvoid . --network-stats
```

### Registry Health
```bash
# Check health of configured package registries (npm, yarn, github)
nullvoid registry-health

# JSON output
nullvoid registry-health --json

# Custom timeout (ms)
nullvoid registry-health -t 10000
```

### Trust & Verification (AI/ML & Blockchain)
```bash
# Show trust score and verification status for a package
nullvoid trust-status lodash@4.17.21

# Verify package integrity against CID (single-source)
nullvoid verify-package lodash@4.17.21 --cid bafy...

# Multi-source consensus verification (npm + GitHub + IPFS)
nullvoid verify-package lodash@4.17.21 --cid bafy... --consensus
nullvoid verify-consensus lodash@4.17.21

# Register package CID on blockchain (requires viem, deployed contract)
nullvoid register-on-chain nullvoid-2.1.0.tgz

# Verify package against blockchain
nullvoid verify-on-chain lodash@4.17.21 --cid bafy...
```

Enable features via `.nullvoidrc.json` or environment: `TRUST_CONFIG`, `CONSENSUS_CONFIG`, `BLOCKCHAIN_CONFIG`. See [docs/TRUST_NETWORK.md](TRUST_NETWORK.md), [docs/CONSENSUS.md](CONSENSUS.md), [docs/BLOCKCHAIN.md](BLOCKCHAIN.md).

### Combined Options
```bash
# Show all threats with verbose output
nullvoid --all --verbose
# or
nullvoid . --all --verbose

# Scan with limited depth
nullvoid --depth 2
# or
nullvoid . --depth 2

# Verbose output with JSON output to file
nullvoid --verbose --format json --output scan-results.json
# or
nullvoid . --verbose --format json --output scan-results.json
```

## Example Output

### Real-Time Progress Display
```
⠋ 🔍 Scanning ...
📁 nullvoid.js (detected: security tools)
📁 colors.js
📁 rules.js (detected: security tools)
📁 scan.js (detected: security tools)
📁 scan.test.js (detected: test file)
📁 setup.js
📁 cache.test.js
📁 entropy.test.js
📁 gpg-signature.test.js
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

## Threat Severity Levels

- **CRITICAL**: Wallet hijacking, transaction redirection, or immediate financial threat
- **HIGH**: Network manipulation, stealth controls, or significant security risk
- **MEDIUM**: Suspicious behavior requiring review
- **LOW**: Minor concerns or best practice violations

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No threats at or above the `--fail-on` severity (default `high`) |
| `1` | At least one threat at or above `--fail-on` |
| `2` | The scan did not complete: bad flag value, target not found, internal error |

`--fail-on <critical|high|medium|low|none>` sets the threshold; `--fail-on none` always exits `0` on a completed scan. Output files (`--output`, `--sarif`) are written before the process exits, so CI can read the report either way.

```bash
nullvoid . --fail-on critical || echo "critical threat found"
```

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--verbose` | Enable detailed output | `false` |
| `--output <format>` | Output format (json, table, sarif) | `table` |
| `--depth <number>` | Maximum dependency tree depth to scan | `3` |
| `--tree` | Show dependency tree structure in output | `false` |
| `--all` | Show all threats including low/medium severity | `false` |
| `--sarif-file <path>` | Write SARIF output to file (requires --output sarif) | - |
| `--ioc-providers <providers>` | Comma-separated list of IoC providers (npm,ghsa,cve,snyk) | `npm,ghsa,cve` |
| `--no-ioc` | Disable IoC provider queries | `false` |
| `--train` | Shorthand for `--export-training ml-model/train.jsonl` | - |
| `--export-training <file>` | Append feature vectors for packages with threats to JSONL (label 1) | - |
| `--export-training-good <file>` | Append feature vectors for packages with no threats to JSONL (label 0) for balanced training | - |
| `--cache-stats` | Show cache statistics | `false` |
| `--enable-redis` | Enable Redis distributed cache | `false` |
| `--network-stats` | Show network performance metrics | `false` |
| `nullvoid registry-health` | Check health of configured package registries | - |
| `nullvoid trust-status <spec>` | Show trust score and verification status | - |
| `nullvoid verify-consensus <spec>` | Multi-source consensus verification | - |
| `nullvoid register-on-chain <path>` | Register package CID on blockchain | - |
| `nullvoid verify-on-chain <spec> --cid <cid>` | Verify package against blockchain | - |
| `--version` | Show version information | - |
| `--help` | Show help information | - |

### Threat Indicators
- **`(detected: OBFUSCATED_CODE)`**: Obfuscated or encoded content detected
- **`(detected: SUSPICIOUS_MODULE)`**: Suspicious module imports (fs, child_process, etc.)
- **`(detected: MALICIOUS_CODE_STRUCTURE)`**: Malicious code patterns identified
- **`(detected: security tools)`**: NullVoid's own security tools (whitelisted)
- **`(detected: test file)`**: Test files (whitelisted)

## Dependency Tree Analysis

NullVoid scans transitive dependencies for hidden threats:

```bash
# Scan with dependency tree analysis (default depth: 3)
nullvoid .

# Scan deeper dependency chains
nullvoid . --depth 5

# Show dependency tree structure
nullvoid . --tree
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
