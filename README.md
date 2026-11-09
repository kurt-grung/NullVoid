# NullVoid

[![npm version](https://img.shields.io/npm/v/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![npm downloads](https://img.shields.io/npm/dm/nullvoid.svg)](https://www.npmjs.com/package/nullvoid)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/kurt-grung/NullVoid/workflows/Tests/badge.svg)](https://github.com/kurt-grung/NullVoid/actions)

**Ø NullVoid** — detect malicious code in JavaScript/Node.js projects and npm packages.

Static analysis only: NullVoid never executes the code it scans. It combines AST-based structural and capability analysis, built-in and custom detection rules, lifecycle-script analysis (including scripts that hand off to `node x.js`), dependency-confusion analysis and public IoC lookups (npm advisories, GHSA, NVD, optionally Snyk). Detection quality is measured on every change: the [benchmark corpus](ts/benchmark/README.md) currently sits at **92% precision / 96% recall** at HIGH+, and CI fails if either regresses.

## What it detects

| Category | Examples | Typical severity |
| --- | --- | --- |
| Credential theft & exfiltration | reads `~/.npmrc`, `.ssh`, cloud credentials or `process.env` and has network access; host fingerprinting | CRITICAL / HIGH |
| Remote code execution | downloads piped into `eval` / `Function` / `child_process`; dynamic `require` of decoded strings | CRITICAL / HIGH |
| Wallet hijacking | `window.ethereum` / provider hooks, transaction and address swapping, multi-chain drainers | CRITICAL |
| Obfuscation | obfuscator identifier patterns, hex/base64 string arrays with rotators, byte-array decoders, code after `module.exports` | HIGH / MEDIUM |
| Lifecycle-script payloads | `preinstall`/`postinstall` running shells, downloads, or a referenced script file that does | CRITICAL / HIGH |
| Supply-chain signals | dependency confusion (timeline, scope, name patterns), typosquats, suspicious dependency specs (`http://`, `git://`) | HIGH / MEDIUM |
| Known vulnerabilities | npm advisories, GitHub Security Advisories, NVD, Snyk (with key) for each declared dependency | per advisory |

Full detail, including what each signal means and what it has caught: [docs/DETECTION.md](docs/DETECTION.md).

## Install

```bash
npm install -g nullvoid        # Node.js 20+
# or run without installing
npx nullvoid .
```

## Three commands

```bash
nullvoid                       # scan the current project (files, installed dependencies, lifecycle scripts)
nullvoid express@4.19.2        # download and scan an npm package
nullvoid . --format sarif --output nullvoid.sarif --fail-on high   # CI: SARIF report, exit 1 on HIGH+
```

Useful flags: `--all` (include LOW/MEDIUM), `--format json|sarif|html|markdown|text`, `--output <file>`, `--rules <file>` (custom rules; `nullvoid rules init` writes an example), `--no-ioc` (offline), `--depth`, `--max-dir-depth`. Everything else: [docs/USAGE.md](docs/USAGE.md).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No threats at or above the `--fail-on` severity (default `high`) |
| `1` | At least one threat at or above `--fail-on` |
| `2` | The scan did not complete: bad flag value, target not found, internal error |

`--fail-on <critical|high|medium|low|none>` sets the threshold; output files are written before the process exits, so CI can read the report either way.

## CI

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  nullvoid:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g nullvoid
      - run: nullvoid . --format sarif --output nullvoid.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: nullvoid.sarif
```

GitLab, Azure DevOps, Jenkins, Travis and CircleCI examples: [docs/CI_INTEGRATION.md](docs/CI_INTEGRATION.md) and [docs/ci-examples/](docs/ci-examples/).

## Configuration

A `.nullvoidrc.json` in the project root sets defaults (`depth`, `maxDirDepth`, `defaultTarget`); a `.nullvoidignore` lists directory names to skip. Custom rules are JSON or YAML (`nullvoid rules validate <file>`). See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) and [docs/USAGE.md](docs/USAGE.md#configuration).

## Experimental features

The following are shipped but experimental and **off by default**; their output should not gate a build:

- `--ml` — XGBoost scores for dependency-confusion and behavioral risk. Models are trained on ground-truth labels with held-out metrics recorded in `ml-model/metadata.json` ([ml-model/README.md](ml-model/README.md)).
- `sign-package`, `verify-package`, `trust-status`, `verify-consensus`, `register-on-chain`, `verify-on-chain`, `registry-health` — IPFS / blockchain / trust-network verification ([docs/TRUST_NETWORK.md](docs/TRUST_NETWORK.md), [docs/CONSENSUS.md](docs/CONSENSUS.md), [docs/BLOCKCHAIN.md](docs/BLOCKCHAIN.md)).

## Documentation

| | |
| --- | --- |
| [docs/USAGE.md](docs/USAGE.md) | all CLI options, output formats, example output, configuration, dependency tree |
| [docs/DETECTION.md](docs/DETECTION.md) | what is detected and how, real-world cases, dependency confusion |
| [docs/CI_INTEGRATION.md](docs/CI_INTEGRATION.md) | SARIF and pipeline recipes |
| [docs/IOC_USAGE.md](docs/IOC_USAGE.md) | IoC providers, caching, network settings |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | `.nullvoidrc.json`, environment variables, custom rules |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | building from source, workspace layout, Makefile, dashboard and API |
| [docs/API.md](docs/API.md) · [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | REST API and hosting the dashboard |
| [ml-model/README.md](ml-model/README.md) | ML pipeline, training data, held-out metrics |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) · [docs/ROADMAP.md](docs/ROADMAP.md) | what changed, what is planned |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | common problems |

## Contributing and security

This repository does not accept external pull requests; bug reports and feature requests are welcome as [issues](https://github.com/kurt-grung/NullVoid/issues) — see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
