# NullVoid Configuration Guide

Complete guide to configuring NullVoid for optimal performance and security scanning.

## Table of Contents

1. [Environment Variables](#environment-variables)
2. [IoC Provider Configuration](#ioc-provider-configuration)
3. [Cache Configuration](#cache-configuration)
4. [Network Configuration](#network-configuration)
5. [Performance Tuning](#performance-tuning)
6. [CLI Configuration](#cli-configuration)
7. [Programmatic Configuration](#programmatic-configuration)
8. [Pre-commit Integration](#pre-commit-integration)

## Environment Variables

### General Configuration

```bash
# Logging
export NULLVOID_LOG_LEVEL=info          # debug, info, warn, error
export NULLVOID_TIMESTAMP=true          # Include timestamps in logs

# Cache
export NULLVOID_CACHE_DIR=.nullvoid-cache  # Cache directory path
export NULLVOID_CACHE_TTL=300000       # Default cache TTL (5 minutes)
export NULLVOID_CACHE_MAX_SIZE=1000    # Maximum cache entries

# Network
export NULLVOID_NETWORK_TIMEOUT=10000  # Network timeout in ms
export NULLVOID_MAX_RETRIES=3         # Maximum retry attempts
```

## IoC Provider Configuration

### Snyk

```bash
# Required: API Key
export SNYK_API_KEY=your-snyk-api-key

# Optional: Custom configuration
export NULLVOID_IOC_SNYK_ENABLED=true
export NULLVOID_IOC_SNYK_RATE_LIMIT=60
export NULLVOID_IOC_SNYK_CACHE_TTL=3600000  # 1 hour
```

**Getting a Snyk API Key:**
1. Sign up at [Snyk.io](https://snyk.io/)
2. Navigate to Account Settings → API Token
3. Copy your API token
4. Set `SNYK_API_KEY` environment variable

### npm Advisories

```bash
# npm Advisories is public, no API key needed
export NULLVOID_IOC_NPM_ENABLED=true
export NULLVOID_IOC_NPM_RATE_LIMIT=100
export NULLVOID_IOC_NPM_CACHE_TTL=3600000  # 1 hour
```

### GitHub Security Advisories (GHSA)

```bash
# Optional: GitHub token for better rate limits (5000/hour vs 60/hour)
export GITHUB_TOKEN=your-github-token

# Configuration
export NULLVOID_IOC_GHSA_ENABLED=true
export NULLVOID_IOC_GHSA_RATE_LIMIT=60  # 60/hour without token, 5000/hour with token
export NULLVOID_IOC_GHSA_CACHE_TTL=3600000
```

**Getting a GitHub Token:**
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate a new token with `public_repo` scope
3. Set `GITHUB_TOKEN` environment variable

### NVD/CVE Database

```bash
# Optional: NVD API key for higher rate limits
export NVD_API_KEY=your-nvd-api-key

# Configuration
export NULLVOID_IOC_CVE_ENABLED=true
export NULLVOID_IOC_CVE_RATE_LIMIT=50  # 50 per 30 seconds
export NULLVOID_IOC_CVE_CACHE_TTL=86400000  # 24 hours
```

**Getting an NVD API Key:**
1. Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill out the form and submit
3. Receive API key via email
4. Set `NVD_API_KEY` environment variable

## Cache Configuration

### Multi-Layer Cache

NullVoid uses a 3-layer cache system:

- **L1 (Memory)**: Fast in-memory LRU cache
- **L2 (File)**: Persistent file-based cache
- **L3 (Redis)**: Optional distributed cache

### L1 Memory Cache

```bash
# L1 is always enabled, no configuration needed
# Automatically manages memory usage
```

### L2 File Cache

```bash
# Cache directory
export NULLVOID_CACHE_DIR=.nullvoid-cache

# Enable/disable L2
export NULLVOID_CACHE_L2_ENABLED=true

# Cache size limit
export NULLVOID_CACHE_L2_MAX_SIZE=1000
```

### L3 Redis Cache

```bash
# Enable Redis
export NULLVOID_CACHE_L3_ENABLED=true

# Redis connection (choose one method)
export REDIS_URL=redis://localhost:6379
# OR
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=your-password  # Optional
export REDIS_DB=0                    # Optional, default 0
```

**Redis Setup:**
```bash
# Install Redis (macOS)
brew install redis
brew services start redis

# Install Redis (Linux)
sudo apt-get install redis-server
sudo systemctl start redis

# Verify Redis is running
redis-cli ping  # Should return "PONG"
```

### Cache TTL Configuration

```bash
# Global cache TTL
export NULLVOID_CACHE_TTL=300000  # 5 minutes

# Provider-specific TTL
export NULLVOID_IOC_SNYK_CACHE_TTL=3600000      # 1 hour
export NULLVOID_IOC_NPM_CACHE_TTL=3600000        # 1 hour
export NULLVOID_IOC_GHSA_CACHE_TTL=3600000      # 1 hour
export NULLVOID_IOC_CVE_CACHE_TTL=86400000       # 24 hours
```

## Network Configuration

### Connection Pooling

```bash
# Enable connection pooling (default: true)
export NULLVOID_CONNECTION_POOL_ENABLED=true

# Connection pool size
export NULLVOID_CONNECTION_POOL_MAX_SIZE=10
```

### Request Batching

```bash
# Enable request batching (default: true)
export NULLVOID_REQUEST_BATCHING_ENABLED=true

# Batch size
export NULLVOID_REQUEST_BATCH_SIZE=10

# Batch timeout (ms)
export NULLVOID_REQUEST_BATCH_TIMEOUT=100
```

### Compression

```bash
# Enable compression (default: true)
export NULLVOID_COMPRESSION_ENABLED=true

# Compression algorithms (gzip, brotli)
export NULLVOID_COMPRESSION_ALGORITHM=gzip
```

### Timeouts and Retries

```bash
# Network timeout
export NULLVOID_NETWORK_TIMEOUT=10000  # 10 seconds

# Maximum retries
export NULLVOID_MAX_RETRIES=3

# Retry delay (ms)
export NULLVOID_RETRY_DELAY=1000
```

## Performance Tuning

### Parallel Processing

```bash
# Enable parallel processing (default: true)
export NULLVOID_PARALLEL_ENABLED=true

# Number of workers (auto = CPU cores)
export NULLVOID_WORKERS=auto
# OR specify number
export NULLVOID_WORKERS=4

# Chunk size for parallel processing
export NULLVOID_CHUNK_SIZE=10
```

### Memory Management

```bash
# Maximum memory usage (MB)
export NULLVOID_MAX_MEMORY=512

# Enable memory pool
export NULLVOID_MEMORY_POOL_ENABLED=true
```

### Rate Limiting

```bash
# Global rate limit
export NULLVOID_RATE_LIMIT_MAX_REQUESTS=100
export NULLVOID_RATE_LIMIT_WINDOW_SIZE=60000  # 1 minute
```

## CLI Configuration

### Configuration File

Create a `.nullvoidrc` file in your project root:

```json
{
  "iocEnabled": true,
  "iocProviders": ["npm", "ghsa", "cve"],
  "cache": {
    "enabled": true,
    "dir": ".nullvoid-cache",
    "ttl": 300000
  },
  "network": {
    "timeout": 10000,
    "retries": 3
  },
  "parallel": {
    "enabled": true,
    "workers": "auto"
  }
}
```

### CLI Options

```bash
# Basic scan
nullvoid /path/to/project

# With IoC providers
nullvoid /path/to/project --ioc-providers npm,ghsa,cve

# Enable Redis cache
nullvoid /path/to/project --enable-redis

# Show statistics
nullvoid /path/to/project --cache-stats --network-stats

# Verbose output
nullvoid /path/to/project --verbose

# Show all threats
nullvoid /path/to/project --all
```

## Programmatic Configuration

### TypeScript/JavaScript

```typescript
import { scan } from 'nullvoid';

const results = await scan('./my-project', {
  iocEnabled: true,
  iocProviders: 'npm,ghsa,cve',
  skipCache: false,
  verbose: true,
  parallel: true,
  workers: 4
});
```

### Advanced Configuration

```typescript
import { getIoCManager } from 'nullvoid/lib/iocIntegration';
import { getCacheAnalytics } from 'nullvoid/lib/cache/cacheAnalytics';
import { getConnectionPool } from 'nullvoid/lib/network/connectionPool';

// Configure IoC manager
const ioCManager = getIoCManager();
// Providers are automatically registered from environment variables

// Monitor cache performance
const analytics = getCacheAnalytics();
const summary = analytics.getSummary('ioc-cache');

// Configure connection pool
const pool = getConnectionPool();
const stats = pool.getStats();
```

## Best Practices

### Production Configuration

```bash
# Production settings
export NULLVOID_LOG_LEVEL=warn
export NULLVOID_CACHE_L3_ENABLED=true
export REDIS_URL=redis://your-redis-server:6379
export SNYK_API_KEY=your-production-key
export GITHUB_TOKEN=your-production-token
export NVD_API_KEY=your-production-key
```

### Development Configuration

```bash
# Development settings
export NULLVOID_LOG_LEVEL=debug
export NULLVOID_CACHE_L2_ENABLED=true
export NULLVOID_VERBOSE=true
```

### CI/CD Configuration

```bash
# CI/CD settings
export NULLVOID_LOG_LEVEL=info
export NULLVOID_CACHE_L2_ENABLED=false  # Disable file cache in CI
export NULLVOID_SKIP_CACHE=true          # Always fetch fresh data
```

## Troubleshooting

### Cache Issues

**Problem**: Cache not working
```bash
# Solution: Clear cache directory
rm -rf .nullvoid-cache

# Or disable cache
export NULLVOID_CACHE_L2_ENABLED=false
```

**Problem**: Redis connection failed
```bash
# Verify Redis is running
redis-cli ping

# Check connection string
export REDIS_URL=redis://localhost:6379

# Test connection
redis-cli -u $REDIS_URL ping
```

### Network Issues

**Problem**: Timeout errors
```bash
# Increase timeout
export NULLVOID_NETWORK_TIMEOUT=30000  # 30 seconds
```

**Problem**: Rate limit errors
```bash
# Add API keys for better rate limits
export GITHUB_TOKEN=your-token
export NVD_API_KEY=your-key
```

### Performance Issues

**Problem**: Slow scans
```bash
# Enable caching
export NULLVOID_CACHE_L2_ENABLED=true

# Enable parallel processing
export NULLVOID_PARALLEL_ENABLED=true

# Increase workers
export NULLVOID_WORKERS=8
```

## Configuration Validation

Validate your configuration:

```bash
nullvoid --config-check
```

Or programmatically:

```typescript
import { validateConfig } from 'nullvoid/lib/config';

const errors = validateConfig();
if (errors.length > 0) {
  console.error('Configuration errors:', errors);
}
```

## Pre-commit Integration

You can run a NullVoid security scan automatically before each commit using the optional pre-commit hook.

### Enable

Set the environment variable to turn on the scan in the existing Husky pre-commit hook:

```bash
export NULLVOID_PRE_COMMIT=1
```

Or run it once for a single commit:

```bash
NULLVOID_PRE_COMMIT=1 git commit -m "your message"
```

### Behavior

- When `NULLVOID_PRE_COMMIT=1`, the hook runs `npm run build` then `npx nullvoid . --format text --depth 2` from the repository root.
- `--depth 2` keeps the scan shallow so commits stay quick.
- The commit is blocked if the build fails or if the scanner throws an error; otherwise the commit proceeds (the CLI does not exit non-zero when threats are found, only on exceptions).

### Disable

- Unset the variable: `unset NULLVOID_PRE_COMMIT`, or do not set it (default is off).
- The pre-commit hook still runs `lint-staged`; only the NullVoid scan is optional.

## Next Steps

- See [IoC Usage Guide](IOC_USAGE.md) for IoC provider details
- See [Performance Tuning Guide](PERFORMANCE.md) for optimization tips
- See [API Documentation](API.md) for programmatic usage

