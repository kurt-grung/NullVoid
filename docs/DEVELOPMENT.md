# Developing NullVoid

Building from source, the TypeScript workspace, Makefile targets, the dashboard and API, and performance notes. Contribution rules are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Install and run

```bash
# Install globally
npm install -g nullvoid

# Scan current project directory
nullvoid
# or
nullvoid .
# or (backward compatibility)
nullvoid scan

# Scan specific directory/project
nullvoid /path/to/project
# or
nullvoid scan /path/to/project

# Scan specific file
nullvoid suspicious-file.js
# or
nullvoid scan suspicious-file.js

# Scan npm package
nullvoid express
# or
nullvoid scan express

# Scan with verbose output
nullvoid --verbose
# or
nullvoid . --verbose


# Output to JSON file
nullvoid --format json --output results.json
# or
nullvoid . --format json --output results.json
```

**Build from source:**
```bash
git clone https://github.com/kurt-grung/NullVoid.git && cd NullVoid
make install && make build && make test
# or: npm ci && npm run build && npm test
```

### Try in GitHub Codespaces

Run NullVoid (including the ML pipeline) in the cloud—no local install. Click **Code** → **Codespaces** → **Create codespace on main**. After the container builds, API and Dashboard start automatically. Open the forwarded port **5174** (Dashboard). Use the ML page to export features and train models. See [docs/DEPLOYMENT.md](DEPLOYMENT.md#github-codespaces-demo) for details.

## TypeScript Support

NullVoid is built with **TypeScript** for enhanced type safety and developer experience. The project uses **Turborepo** for the monorepo build pipeline (workspaces: `packages/*`, `ts`, `js`). **Node 20+** is required for building (some dependencies require it).

### Development
```bash
# Install dependencies (root npm ci installs all workspaces)
npm install
# or
make install

# Build TypeScript and packages
npm run build
# or
make build

# Development mode with TypeScript
npm run dev -- scan --help
# or
make dev

# Type checking
npm run type-check

# Development with file watching
npm run build:watch
```

### Makefile targets
| Target | Description |
|--------|-------------|
| `make` | Start dashboard (default) |
| `make build` | Build TypeScript scanner and packages |
| `make build-api` | Build API package |
| `make api` | Start API (port 3001) |
| `make dashboard` | Start dashboard dev server (port 5174) |
| `make dev` | Start scanner in dev mode |
| `make test` | Run tests |
| `make lint` | Run linter |
| `make install` | Install dependencies |
| `make kill` | Stop API, dashboard, and ML server (ports 3001, 5174, 8000) |
| `make serve` | Start ML model server (port 8000) |
| `make train` | Train ML model |

### Dashboard

The web dashboard provides a UI for scans, compliance, reports, and ML commands.

```bash
# Terminal 1: Start API (required for dashboard)
make api

# Terminal 2: Start dashboard
make dashboard
# Open http://localhost:5174
```

| Page | Description |
|------|-------------|
| **Executive** | Overview: scan counts, threats, severity distribution, top packages |
| **Scans** | Run scans, view recent scans, link to scan details |
| **Compliance** | Control coverage (C/I/A), gap analysis for SOC 2 / ISO 27001 |
| **Reports** | View HTML or download Markdown reports for completed scans |
| **ML** | Run export/train for dependency confusion and behavioral models (API must run locally) |

- **Reports**: `GET /api/report/:scanId?format=html|markdown&compliance=soc2|iso27001`
- **API Docs**: Swagger UI at `http://localhost:3001/api-docs`; OpenAPI JSON at `/api-docs.json`
- **Stop all**: `make kill` stops API, dashboard, and ML server

### ML Model (optional)
See [ML Training Pipeline](#-ml-training-pipeline) above for the full setup. Quick reference:
```bash
nullvoid export --out train.jsonl
node ml-model/export-features.js --from-ghsa --out ml-model/train.jsonl
nullvoid scan /path/to/malware --no-ioc --train
nullvoid train --input train.jsonl --output-dir .
nullvoid serve --port 8000
```

### Type Definitions
- Full TypeScript type definitions included
- IntelliSense support in VS Code and other IDEs  
- Comprehensive type safety for all APIs
- Strict type checking enabled

## Performance

NullVoid's TypeScript migration and v2.1.0 optimizations deliver significant performance improvements:

| Metric | JavaScript | TypeScript | v2.1.0 | Improvement |
|--------|------------|------------|--------|-------------|
| **Scan Speed** | 0.589s | 0.079s | 0.026s | ⚡ **22.7x faster** |
| **Code Size** | 3,519 lines | 388 lines | 388 lines | 📦 **90% smaller** |
| **Type Safety** | ❌ None | ✅ Full | ✅ Full | 🛡️ **Type-safe** |
| **Cache Hit Rate** | N/A | N/A | 85%+ | 📦 **60-80% API reduction** |
| **Network Efficiency** | N/A | N/A | 70%+ reuse | 🌐 **30-50% latency reduction** |
| **ESLint Warnings** | 0 warnings | 0 warnings | 0 warnings | ✅ **Zero warnings** |
| **Code Quality** | Basic | Enterprise | Enterprise | 🏆 **Production-ready** |

### Key Benefits
- **🚀 Faster Execution**: 22.7x performance improvement with caching and network optimizations
- **📦 Smaller Bundle**: 90% reduction in code size through modular architecture
- **🛡️ Type Safety**: Full TypeScript type checking prevents runtime errors
- **💾 Intelligent Caching**: Multi-layer cache system reduces API calls by 60-80%
- **🌐 Network Optimization**: Connection pooling and request batching reduce latency by 30-50%
- **🔧 Better DX**: Enhanced developer experience with IntelliSense and autocomplete
- **🏗️ Maintainable**: Modular codebase easier to maintain and extend
- **✅ Zero Warnings**: Enterprise-grade code quality with comprehensive error handling
- **🎨 Enhanced UX**: Beautiful colored output with professional formatting
- **🔒 Security Hardened**: Fixed memory leaks and enhanced security measures
- **Tested**: Unit and integration suites run in CI on Node 20, 22 and 24

## Publishing

The npm package `nullvoid` is the `ts/` workspace; the repository root (`nullvoid-monorepo`) is private and never published.

```bash
npm version <patch|minor|major> --workspace=nullvoid   # bump ts/package.json
npm publish --workspace=nullvoid                        # prepack builds and copies README/LICENSE in
```

CI's "Verify publish contents" step dry-runs the pack and fails if `dist/bin/nullvoid.js` or the README is missing or any `src/`/`test/` file is included.
