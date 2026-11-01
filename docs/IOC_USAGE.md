# IoC Integration & Performance Features Usage Guide

This guide explains how to use Public IoC Integration and Performance Optimizations.

## Table of Contents

1. [IoC (Indicators of Compromise) Integration](#ioc-integration)
2. [Cache Features](#cache-features)
3. [Network Optimizations](#network-optimizations)
4. [CLI Options](#cli-options)
5. [Configuration](#configuration)
6. [Examples](#examples)

## IoC Integration

### Overview

NullVoid now integrates with multiple vulnerability databases to check packages for known security issues:

- **Snyk**: Commercial vulnerability database (requires API key)
- **npm Advisories**: npm's official security advisories (public)
- **GitHub Security Advisories (GHSA)**: GitHub's security database (public, better rate limits with token)
- **NVD/CVE**: National Vulnerability Database (public, optional API key for higher rate limits)

### Basic Usage

#### Enable IoC Scanning (Default)

IoC scanning is enabled by default. Simply scan a directory with a `package.json`:

```bash
nullvoid /path/to/project
```

This will automatically query enabled IoC providers for all dependencies in `package.json`.

#### Disable IoC Scanning

To disable IoC provider queries:

```bash
nullvoid /path/to/project --no-ioc
```

#### Select Specific Providers

Choose which providers to use:

```bash
# Use only npm advisories
nullvoid /path/to/project --ioc-providers npm

# Use multiple providers
nullvoid /path/to/project --ioc-providers npm,ghsa,cve

# Use all providers (including Snyk if configured)
nullvoid /path/to/project --ioc-providers snyk,npm,ghsa,cve
```

### Provider Configuration

#### Snyk (Requires API Key)

1. Get a Snyk API key from [Snyk](https://snyk.io/)
2. Set environment variable:

```bash
export SNYK_API_KEY=your-api-key-here
```

3. Enable Snyk in configuration or use `--ioc-providers snyk`

#### GitHub Security Advisories (Optional Token)

For better rate limits (5000 requests/hour vs 60/hour):

```bash
export GITHUB_TOKEN=your-github-token-here
```

#### NVD/CVE (Optional API Key)

For higher rate limits:

```bash
export NVD_API_KEY=your-nvd-api-key-here
```

Get your API key from [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)

### Example Output

When vulnerabilities are found, they appear as threats:

```
⚠️  2 high-severity threat(s) detected:

1. VULNERABLE_PACKAGE (HIGH)
   Vulnerability found: Prototype Pollution in lodash (CVE-2021-23337)
   Details: Affected versions: <4.17.21
            Fixed in: 4.17.21
            CVSS Score: 7.2 (3.1)
            References: https://nvd.nist.gov/vuln/detail/CVE-2021-23337
   File: package.json
```

## Cache Features

### Multi-Layer Cache

NullVoid uses a 3-layer cache system:

- **L1 (Memory)**: Fast in-memory LRU cache
- **L2 (File)**: Persistent file-based cache (`.nullvoid-cache/`)
- **L3 (Redis)**: Optional distributed cache

### View Cache Statistics

```bash
nullvoid /path/to/project --cache-stats
```

Output example:
```
📊 Cache Statistics:
   L1 (Memory) Cache:
     Hit Rate: 85.50%
     Utilization: 45.20%
     Size: 452 items
```

### Enable Redis Cache (L3)

1. Install and start Redis
2. Set environment variables:

```bash
export REDIS_URL=redis://localhost:6379
# OR
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=your-password  # Optional
export REDIS_DB=0  # Optional, default 0
```

3. Enable Redis:

```bash
nullvoid /path/to/project --enable-redis
```

Or set environment variable:
```bash
export NULLVOID_CACHE_L3_ENABLED=true
```

### Cache Configuration

Customize cache directory:

```bash
export NULLVOID_CACHE_DIR=/custom/cache/path
```

## Network Optimizations

### View Network Statistics

```bash
nullvoid /path/to/project --network-stats
```

Output example:
```
🌐 Network Statistics:
   Active Connections: 3
   Idle Connections: 2
   Total Connections: 5
   Connection Errors: 0
   Connection Timeouts: 0
```

### Network Features (Automatic)

The following optimizations are enabled by default:

- **Connection Pooling**: Reuses HTTP connections for better performance
- **Request Batching**: Batches multiple API requests together
- **Compression**: Automatically uses Gzip/Brotli when available

### Disable Network Optimizations

Set environment variables:

```bash
# Disable connection pooling
export NULLVOID_CONNECTION_POOL_ENABLED=false

# Disable request batching
export NULLVOID_REQUEST_BATCHING_ENABLED=false

# Disable compression
export NULLVOID_COMPRESSION_ENABLED=false
```

## CLI Options

### New Options Summary

| Option | Description | Default |
|--------|-------------|---------|
| `--ioc-providers <providers>` | Comma-separated list of IoC providers | `npm,ghsa,cve` |
| `--no-ioc` | Disable IoC provider queries | `false` |
| `--cache-stats` | Show cache statistics | `false` |
| `--enable-redis` | Enable Redis distributed cache | `false` |
| `--network-stats` | Show network performance metrics | `false` |

### Complete Example

```bash
# Full scan with all features
nullvoid /path/to/project \
  --ioc-providers snyk,npm,ghsa,cve \
  --cache-stats \
  --network-stats \
  --verbose \
  --all
```

## Configuration

### Environment Variables

#### IoC Providers

```bash
# Enable/disable providers
export NULLVOID_IOC_SNYK_ENABLED=true
export NULLVOID_IOC_NPM_ENABLED=true
export NULLVOID_IOC_GHSA_ENABLED=true
export NULLVOID_IOC_CVE_ENABLED=true

# API Keys
export SNYK_API_KEY=your-key
export GITHUB_TOKEN=your-token
export NVD_API_KEY=your-key
```

#### Cache

```bash
# Cache directory
export NULLVOID_CACHE_DIR=.nullvoid-cache

# Enable cache layers
export NULLVOID_CACHE_L2_ENABLED=true
export NULLVOID_CACHE_L3_ENABLED=true

# Redis configuration
export REDIS_URL=redis://localhost:6379
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=password
export REDIS_DB=0
```

#### Network

```bash
# Network timeout
export NULLVOID_NETWORK_TIMEOUT=10000

# Connection pooling
export NULLVOID_CONNECTION_POOL_ENABLED=true

# Request batching
export NULLVOID_REQUEST_BATCHING_ENABLED=true

# Compression
export NULLVOID_COMPRESSION_ENABLED=true
```

## Examples

### Example 1: Basic Scan with IoC

```bash
# Scan a project and check for vulnerabilities
nullvoid ./my-project
```

### Example 2: Scan with Specific Providers

```bash
# Only use npm advisories (fastest, no API keys needed)
nullvoid ./my-project --ioc-providers npm
```

### Example 3: Full Security Audit

```bash
# Complete scan with all providers and statistics
nullvoid ./my-project \
  --ioc-providers snyk,npm,ghsa,cve \
  --cache-stats \
  --network-stats \
  --all \
  --verbose \
  --output security-report.json \
  --sarif security-report.sarif
```

### Example 4: CI/CD Integration

```bash
# In your CI pipeline
export SNYK_API_KEY=$SNYK_API_KEY
export GITHUB_TOKEN=$GITHUB_TOKEN

nullvoid . \
  --ioc-providers snyk,npm,ghsa \
  --format json \
  --output security-scan.json

# Check exit code
if [ $? -ne 0 ]; then
  echo "Security vulnerabilities found!"
  exit 1
fi
```

### Example 5: Performance Monitoring

```bash
# Monitor cache and network performance
nullvoid ./my-project \
  --cache-stats \
  --network-stats \
  --verbose
```

### Example 6: Disable IoC for Faster Scans

```bash
# Quick scan without vulnerability checks
nullvoid ./my-project --no-ioc
```

## Troubleshooting

### Rate Limit Errors

If you see rate limit errors:

1. **GHSA**: Add a GitHub token: `export GITHUB_TOKEN=your-token`
2. **NVD**: Add an NVD API key: `export NVD_API_KEY=your-key`
3. **Snyk**: Ensure your API key is valid

### Cache Issues

If cache isn't working:

1. Check cache directory permissions
2. Verify cache directory exists: `.nullvoid-cache/`
3. Clear cache: Delete `.nullvoid-cache/` directory

### Redis Connection Issues

If Redis isn't connecting:

1. Verify Redis is running: `redis-cli ping`
2. Check connection string: `export REDIS_URL=redis://localhost:6379`
3. Check authentication if required
4. Review logs with `--verbose` flag

## Best Practices

1. **Use API Keys**: For production, always configure API keys for better rate limits
2. **Enable Caching**: Keep cache enabled for faster repeated scans
3. **Monitor Performance**: Use `--cache-stats` and `--network-stats` to optimize
4. **CI/CD Integration**: Use JSON/SARIF output formats for automation
5. **Selective Providers**: Use only needed providers to reduce API calls

## Performance Tips

- **First Scan**: May be slower as cache is populated
- **Subsequent Scans**: Much faster due to caching
- **Redis Cache**: Use for distributed environments or multiple scans
- **Provider Selection**: Use fewer providers for faster scans
- **Network Stats**: Monitor to identify bottlenecks

## Next Steps

- Review the [API Documentation](API.md) for programmatic usage
- Check [Troubleshooting Guide](TROUBLESHOOTING.md) for common issues
- See [Configuration Guide](CONTRIBUTING.md) for advanced setup

