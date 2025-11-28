# NullVoid Performance Tuning Guide

Complete guide to optimizing NullVoid performance for your environment.

## Table of Contents

1. [Performance Metrics](#performance-metrics)
2. [Cache Optimization](#cache-optimization)
3. [Network Optimization](#network-optimization)
4. [Parallel Processing Tuning](#parallel-processing-tuning)
5. [Memory Management](#memory-management)
6. [Benchmarking](#benchmarking)
7. [Performance Best Practices](#performance-best-practices)

## Performance Metrics

### Key Metrics to Monitor

- **Scan Duration**: Total time to complete scan
- **Files Per Second**: Number of files processed per second
- **Packages Per Second**: Number of packages scanned per second
- **Cache Hit Rate**: Percentage of cache hits vs misses
- **Network Requests**: Total number of API requests made
- **Memory Usage**: Peak memory consumption during scan

### Viewing Performance Metrics

```bash
# Show cache statistics
nullvoid /path/to/project --cache-stats

# Show network statistics
nullvoid /path/to/project --network-stats

# Show both
nullvoid /path/to/project --cache-stats --network-stats --verbose
```

### Programmatic Access

```typescript
import { scan } from 'nullvoid';
import { getCacheAnalytics } from 'nullvoid/lib/cache/cacheAnalytics';
import { getConnectionPool } from 'nullvoid/lib/network/connectionPool';

const results = await scan('./my-project');

// Cache metrics
const analytics = getCacheAnalytics();
const cacheSummary = analytics.getSummary('ioc-cache');
console.log(`Cache hit rate: ${cacheSummary.hitRate * 100}%`);

// Network metrics
const pool = getConnectionPool();
const networkStats = pool.getStats();
console.log(`Active connections: ${networkStats.activeConnections}`);

// Scan metrics
console.log(`Duration: ${results.metrics.duration}ms`);
console.log(`Files/sec: ${results.metrics.filesPerSecond}`);
console.log(`Packages/sec: ${results.metrics.packagesPerSecond}`);
```

## Cache Optimization

### Cache Layer Strategy

**L1 (Memory) Cache:**
- **Use Case**: Fast, temporary storage
- **Best For**: Frequently accessed data during single scan
- **Configuration**: Automatic, no configuration needed
- **Performance**: ~0.1ms access time

**L2 (File) Cache:**
- **Use Case**: Persistent cache across scans
- **Best For**: Repeated scans of same projects
- **Configuration**: `export NULLVOID_CACHE_DIR=.nullvoid-cache`
- **Performance**: ~1-5ms access time

**L3 (Redis) Cache:**
- **Use Case**: Distributed caching
- **Best For**: Multiple machines, CI/CD pipelines
- **Configuration**: `export REDIS_URL=redis://localhost:6379`
- **Performance**: ~2-10ms access time (network dependent)

### Optimizing Cache Hit Rate

**Target**: >80% cache hit rate

```bash
# Increase cache TTL for stable data
export NULLVOID_IOC_CVE_CACHE_TTL=86400000  # 24 hours (CVE data changes slowly)

# Increase cache size
export NULLVOID_CACHE_MAX_SIZE=5000  # More entries = better hit rate

# Enable all cache layers
export NULLVOID_CACHE_L2_ENABLED=true
export NULLVOID_CACHE_L3_ENABLED=true
```

### Cache Warming

Warm up cache before production scans:

```typescript
import { MultiLayerCache } from 'nullvoid/lib/cache/multiLayerCache';
import { queryIoCProviders } from 'nullvoid/lib/iocScanIntegration';

const cache = new MultiLayerCache('ioc-cache');

// Pre-populate cache with common packages
const commonPackages = ['express', 'lodash', 'axios', 'react'];
for (const pkg of commonPackages) {
  await queryIoCProviders(pkg);
}
```

### Cache Invalidation Strategy

```bash
# Clear cache when needed
rm -rf .nullvoid-cache

# Or programmatically
import { MultiLayerCache } from 'nullvoid/lib/cache/multiLayerCache';
const cache = new MultiLayerCache('my-cache');
await cache.clear();
```

## Network Optimization

### Connection Pooling

**Benefits**: Reuse HTTP connections, reduce overhead

```bash
# Enable connection pooling (default: true)
export NULLVOID_CONNECTION_POOL_ENABLED=true

# Increase pool size for high concurrency
export NULLVOID_CONNECTION_POOL_MAX_SIZE=20
```

**Performance Impact**:
- Without pooling: ~100-200ms per request
- With pooling: ~50-100ms per request
- **Improvement**: 50% faster

### Request Batching

**Benefits**: Reduce API calls, improve throughput

```bash
# Enable request batching (default: true)
export NULLVOID_REQUEST_BATCHING_ENABLED=true

# Optimize batch size
export NULLVOID_REQUEST_BATCH_SIZE=10  # Adjust based on provider limits
```

**Performance Impact**:
- Without batching: 1 request per package
- With batching: 10 packages per request
- **Improvement**: 90% reduction in API calls

### Compression

**Benefits**: Reduce bandwidth, faster transfers

```bash
# Enable compression (default: true)
export NULLVOID_COMPRESSION_ENABLED=true
export NULLVOID_COMPRESSION_ALGORITHM=gzip  # or brotli
```

**Performance Impact**:
- Without compression: Full payload size
- With compression: 60-80% size reduction
- **Improvement**: 2-3x faster transfers

### Rate Limiting Optimization

**Provider-Specific Limits**:

```bash
# npm: 100 requests/minute (no key needed)
export NULLVOID_IOC_NPM_RATE_LIMIT=100

# GHSA: 60/hour without token, 5000/hour with token
export GITHUB_TOKEN=your-token
export NULLVOID_IOC_GHSA_RATE_LIMIT=5000

# NVD: 50 per 30 seconds without key, 50 per 30 seconds with key
export NVD_API_KEY=your-key
export NULLVOID_IOC_CVE_RATE_LIMIT=50
```

**Strategy**: Use API keys for better rate limits

## Parallel Processing Tuning

### Worker Configuration

```bash
# Auto-detect CPU cores (recommended)
export NULLVOID_WORKERS=auto

# Or specify manually
export NULLVOID_WORKERS=4  # For 4-core system
```

**Optimal Worker Count**:
- **CPU-bound tasks**: Number of CPU cores
- **I/O-bound tasks**: 2x CPU cores
- **Mixed**: Start with CPU cores, adjust based on performance

### Chunk Size Optimization

```bash
# Adjust chunk size for work distribution
export NULLVOID_CHUNK_SIZE=10  # Default

# For large projects: increase chunk size
export NULLVOID_CHUNK_SIZE=20

# For small projects: decrease chunk size
export NULLVOID_CHUNK_SIZE=5
```

### Dynamic Scaling

NullVoid automatically scales workers based on:
- System load
- Memory availability
- Queue depth
- Network latency

Monitor with:

```bash
nullvoid /path/to/project --verbose
# Look for worker scaling messages
```

## Memory Management

### Memory Pool

```bash
# Enable memory pool for efficient allocation
export NULLVOID_MEMORY_POOL_ENABLED=true
```

**Benefits**:
- Reduced memory allocations
- Lower garbage collection pressure
- More consistent performance

### Memory Limits

```bash
# Set maximum memory usage
export NULLVOID_MAX_MEMORY=512  # MB

# Monitor memory usage
nullvoid /path/to/project --verbose
# Check memory metrics in output
```

### Memory Optimization Tips

1. **Reduce scan depth** for large projects:
   ```bash
   nullvoid /path/to/project --depth 3  # Instead of default 5
   ```

2. **Disable unnecessary features**:
   ```bash
   nullvoid /path/to/project --no-ioc  # Skip IoC if not needed
   ```

3. **Use streaming for large files**:
   - Automatic for files > 10MB
   - No configuration needed

## Benchmarking

### Performance Baseline

Establish baseline performance:

```bash
# First scan (cold cache)
time nullvoid /path/to/project --no-cache

# Second scan (warm cache)
time nullvoid /path/to/project
```

### Benchmark Script

```bash
#!/bin/bash
# benchmark.sh

echo "=== NullVoid Performance Benchmark ==="

# Cold cache
echo "1. Cold cache scan:"
time nullvoid /path/to/project --skip-cache > /dev/null

# Warm cache
echo "2. Warm cache scan:"
time nullvoid /path/to/project > /dev/null

# With all optimizations
echo "3. Optimized scan:"
export NULLVOID_CACHE_L3_ENABLED=true
export REDIS_URL=redis://localhost:6379
time nullvoid /path/to/project --cache-stats --network-stats > /dev/null
```

### Expected Performance

**Small Project** (< 50 packages):
- Cold scan: 2-5 seconds
- Warm scan: 0.5-1 second
- **Cache improvement**: 4-5x faster

**Medium Project** (50-200 packages):
- Cold scan: 10-30 seconds
- Warm scan: 2-5 seconds
- **Cache improvement**: 5-6x faster

**Large Project** (> 200 packages):
- Cold scan: 30-120 seconds
- Warm scan: 5-15 seconds
- **Cache improvement**: 6-8x faster

## Performance Best Practices

### 1. Enable All Cache Layers

```bash
export NULLVOID_CACHE_L2_ENABLED=true
export NULLVOID_CACHE_L3_ENABLED=true
export REDIS_URL=redis://localhost:6379
```

### 2. Use API Keys

```bash
export GITHUB_TOKEN=your-token      # 5000/hour vs 60/hour
export NVD_API_KEY=your-key         # Better reliability
export SNYK_API_KEY=your-key        # Required for Snyk
```

### 3. Optimize Provider Selection

```bash
# Use only needed providers
nullvoid /path/to/project --ioc-providers npm  # Fastest, no keys needed

# Or use all for comprehensive scan
nullvoid /path/to/project --ioc-providers npm,ghsa,cve
```

### 4. Parallel Processing

```bash
# Always enable parallel processing
export NULLVOID_PARALLEL_ENABLED=true
export NULLVOID_WORKERS=auto
```

### 5. Network Optimizations

```bash
# Enable all network optimizations
export NULLVOID_CONNECTION_POOL_ENABLED=true
export NULLVOID_REQUEST_BATCHING_ENABLED=true
export NULLVOID_COMPRESSION_ENABLED=true
```

### 6. CI/CD Optimization

```bash
# CI/CD specific settings
export NULLVOID_CACHE_L2_ENABLED=false  # No file cache in CI
export NULLVOID_CACHE_L3_ENABLED=true   # Use Redis for shared cache
export NULLVOID_SKIP_CACHE=false        # Use cache for speed
export NULLVOID_WORKERS=4                # Fixed workers for consistency
```

### 7. Production Settings

```bash
# Production configuration
export NULLVOID_LOG_LEVEL=warn
export NULLVOID_CACHE_L3_ENABLED=true
export REDIS_URL=redis://production-redis:6379
export GITHUB_TOKEN=production-token
export NVD_API_KEY=production-key
export NULLVOID_WORKERS=8
```

## Performance Troubleshooting

### Slow Scans

**Diagnosis**:
```bash
nullvoid /path/to/project --cache-stats --network-stats --verbose
```

**Solutions**:
1. Check cache hit rate (should be >80%)
2. Verify network optimizations are enabled
3. Check for rate limiting errors
4. Increase workers if CPU-bound
5. Enable Redis for distributed caching

### High Memory Usage

**Solutions**:
1. Reduce scan depth: `--depth 3`
2. Disable unnecessary features: `--no-ioc`
3. Increase memory limit: `export NULLVOID_MAX_MEMORY=1024`
4. Enable memory pool: `export NULLVOID_MEMORY_POOL_ENABLED=true`

### Network Timeouts

**Solutions**:
1. Increase timeout: `export NULLVOID_NETWORK_TIMEOUT=30000`
2. Add retries: `export NULLVOID_MAX_RETRIES=5`
3. Check network connectivity
4. Use API keys for better reliability

### Low Cache Hit Rate

**Solutions**:
1. Increase cache TTL for stable data
2. Increase cache size: `export NULLVOID_CACHE_MAX_SIZE=5000`
3. Enable all cache layers
4. Warm up cache before production scans

## Performance Monitoring

### Continuous Monitoring

```typescript
import { scan } from 'nullvoid';
import { getCacheAnalytics } from 'nullvoid/lib/cache/cacheAnalytics';

async function monitorPerformance() {
  const startTime = Date.now();
  const results = await scan('./my-project');
  const duration = Date.now() - startTime;

  const analytics = getCacheAnalytics();
  const summary = analytics.getSummary('ioc-cache');

  console.log({
    duration,
    filesPerSecond: results.metrics.filesPerSecond,
    packagesPerSecond: results.metrics.packagesPerSecond,
    cacheHitRate: summary.hitRate,
    memoryUsage: results.metrics.memoryUsage
  });
}
```

### Performance Alerts

Set up alerts for:
- Scan duration > threshold
- Cache hit rate < 80%
- Memory usage > limit
- Network errors > threshold

## Next Steps

- See [Configuration Guide](CONFIGURATION.md) for detailed settings
- See [IoC Usage Guide](IOC_USAGE.md) for IoC optimization
- See [API Documentation](API.md) for programmatic usage

