# NullVoid API Documentation

## Overview

NullVoid provides both a CLI interface and a programmatic API for detecting malicious npm packages. This document covers the programmatic API for integrating NullVoid into your applications.

## Installation

```bash
npm install nullvoid
```

## Basic Usage

```javascript
const { scan } = require('nullvoid');

// Scan current directory
const results = await scan();

// Scan specific package
const results = await scan('express');

// Scan with options
const results = await scan('lodash', {
  maxDepth: 2,
  verbose: true,
  parallel: true
});
```

## API Reference

### `scan(packageName?, options?, progressCallback?)`

Main scanning function that performs security analysis on npm packages.

#### Parameters

- **packageName** `(string, optional)` - Package name to scan. If not provided, scans current directory.
- **options** `(object, optional)` - Scan configuration options.
- **progressCallback** `(function, optional)` - Callback function for progress updates.

#### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxDepth` | `number` | `3` | Maximum dependency tree depth to scan |
| `verbose` | `boolean` | `false` | Enable verbose output |
| `output` | `string` | `'table'` | Output format (`'json'`, `'table'`, `'yaml'`) |
| `parallel` | `boolean` | `true` | Enable parallel processing |
| `workers` | `number` | `'auto'` | Number of parallel workers |
| `all` | `boolean` | `false` | Show all threats including low severity |

#### Returns

`Promise<object>` - Scan results object with the following structure:

```javascript
{
  threats: [
    {
      type: 'WALLET_HIJACKING',
      message: 'Package may contain wallet hijacking code',
      package: 'package-name@1.0.0',
      severity: 'HIGH',
      details: 'Additional threat details',
      lineNumber: 42,
      sampleCode: 'window.ethereum.request(...)'
    }
  ],
  packagesScanned: 15,
  filesScanned: 42,
  duration: 1234,
  dependencyTree: {
    'package-name': {
      version: '1.0.0',
      threats: [...],
      dependencies: {...}
    }
  },
  performance: {
    packagesPerSecond: 12.5,
    cacheHitRate: 0.85,
    networkRequests: 8,
    errors: 0
  }
}
```

#### Example

```javascript
const { scan } = require('nullvoid');

async function scanPackage() {
  try {
    const results = await scan('express', {
      maxDepth: 2,
      verbose: true,
      all: true
    });
    
    console.log(`Found ${results.threats.length} threats`);
    console.log(`Scanned ${results.packagesScanned} packages in ${results.duration}ms`);
    
    // Process threats
    results.threats.forEach(threat => {
      if (threat.severity === 'HIGH' || threat.severity === 'CRITICAL') {
        console.log(`⚠️  ${threat.type}: ${threat.message}`);
      }
    });
    
  } catch (error) {
    console.error('Scan failed:', error.message);
  }
}
```

## Utility Functions

### `validatePackageName(name)`

Validates a package name according to npm naming conventions.

#### Parameters

- **name** `(string)` - Package name to validate

#### Returns

`boolean` - True if valid

#### Throws

`ValidationError` - If validation fails

#### Example

```javascript
const { validatePackageName } = require('nullvoid/lib/validation');

try {
  validatePackageName('my-package');
  console.log('Package name is valid');
} catch (error) {
  console.error('Invalid package name:', error.message);
}
```

### `validateScanOptions(options)`

Validates scan options object.

#### Parameters

- **options** `(object)` - Options to validate

#### Returns

`boolean` - True if valid

#### Throws

`ValidationError` - If validation fails

### `createLogger(prefix, options?)`

Creates a logger instance with a specific prefix.

#### Parameters

- **prefix** `(string)` - Logger prefix
- **options** `(object, optional)` - Logger options

#### Returns

`Logger` - Logger instance

#### Example

```javascript
const { createLogger } = require('nullvoid/lib/logger');

const logger = createLogger('MyApp');
logger.info('Application started');
logger.error('Something went wrong', { error: 'details' });
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NULLVOID_LOG_LEVEL` | Logging level | `INFO` |
| `NULLVOID_NO_COLOR` | Disable colored output | `false` |
| `NULLVOID_TIMESTAMP` | Include timestamps in logs | `false` |
| `NULLVOID_CACHE_TTL` | Cache TTL in milliseconds | `300000` |
| `NULLVOID_CACHE_MAX_SIZE` | Maximum cache size | `1000` |
| `NULLVOID_MAX_WORKERS` | Maximum parallel workers | `8` |
| `NULLVOID_MAX_FILE_SIZE` | Maximum file size to scan | `10485760` |

### Configuration Object

```javascript
const { CACHE_CONFIG, NETWORK_CONFIG, PARALLEL_CONFIG } = require('nullvoid/lib/config');

// Access configuration values
console.log(CACHE_CONFIG.TTL); // 300000
console.log(NETWORK_CONFIG.TIMEOUT); // 5000
console.log(PARALLEL_CONFIG.MAX_WORKERS); // 8
```

## Advanced Usage

### Custom Threat Detection

```javascript
const { scan, createLogger } = require('nullvoid');
const logger = createLogger('CustomScanner');

async function customScan() {
  const results = await scan('my-package', {
    maxDepth: 1,
    verbose: true
  });
  
  // Custom threat processing
  const criticalThreats = results.threats.filter(t => t.severity === 'CRITICAL');
  
  if (criticalThreats.length > 0) {
    logger.security('CRITICAL_THREATS_DETECTED', `Found ${criticalThreats.length} critical threats`);
    
    // Send alerts, block deployment, etc.
    await sendSecurityAlert(criticalThreats);
  }
  
  return results;
}
```

### Progress Monitoring

```javascript
const { scan } = require('nullvoid');

async function scanWithProgress() {
  const results = await scan('large-package', {
    maxDepth: 3
  }, (filePath) => {
    console.log(`Scanning: ${filePath}`);
  });
  
  return results;
}
```

### Batch Processing

```javascript
const { scan } = require('nullvoid');

async function scanMultiplePackages(packages) {
  const results = [];
  
  for (const packageName of packages) {
    try {
      const result = await scan(packageName, { maxDepth: 2 });
      results.push({ package: packageName, result });
    } catch (error) {
      console.error(`Failed to scan ${packageName}:`, error.message);
    }
  }
  
  return results;
}
```

### Performance Monitoring

```javascript
const { scan, PerformanceProfiler, MemoryTracker } = require('nullvoid');

async function scanWithPerformanceMonitoring() {
  const profiler = new PerformanceProfiler();
  const memoryTracker = new MemoryTracker();
  
  profiler.mark('scan-start');
  memoryTracker.snapshot('before-scan');
  
  const results = await scan('express', { verbose: true });
  
  profiler.mark('scan-end');
  memoryTracker.snapshot('after-scan');
  
  const duration = profiler.measure('scan-duration', 'scan-start', 'scan-end');
  const memoryDiff = memoryTracker.getDifference('before-scan', 'after-scan');
  
  console.log(`Scan completed in ${duration}ms`);
  console.log(`Memory usage: ${memoryDiff.heapUsed} bytes`);
  
  return results;
}
```

## Error Handling

### Validation Errors

```javascript
const { scan, ValidationError } = require('nullvoid');

async function safeScan(packageName) {
  try {
    return await scan(packageName);
  } catch (error) {
    if (error instanceof ValidationError) {
      console.error('Validation error:', error.message);
      console.error('Field:', error.field);
      console.error('Value:', error.value);
    } else {
      console.error('Scan error:', error.message);
    }
    throw error;
  }
}
```

### Network Errors

```javascript
const { scan } = require('nullvoid');

async function scanWithRetry(packageName, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await scan(packageName);
    } catch (error) {
      if (error.message.includes('timeout') && i < maxRetries - 1) {
        console.log(`Retry ${i + 1}/${maxRetries} after timeout`);
        await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        continue;
      }
      throw error;
    }
  }
}
```

## Integration Examples

### CI/CD Pipeline

```javascript
const { scan } = require('nullvoid');

async function ciSecurityCheck() {
  const results = await scan('.', {
    maxDepth: 3,
    all: true
  });
  
  const criticalThreats = results.threats.filter(t => t.severity === 'CRITICAL');
  const highThreats = results.threats.filter(t => t.severity === 'HIGH');
  
  if (criticalThreats.length > 0) {
    console.error('❌ Critical threats detected - blocking deployment');
    process.exit(1);
  }
  
  if (highThreats.length > 0) {
    console.warn('⚠️  High severity threats detected - review required');
  }
  
  console.log('✅ Security check passed');
}
```

### Express.js Middleware

```javascript
const express = require('express');
const { scan } = require('nullvoid');

const app = express();

app.post('/scan', async (req, res) => {
  try {
    const { packageName, options = {} } = req.body;
    const results = await scan(packageName, options);
    res.json(results);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

### Webhook Integration

```javascript
const { scan } = require('nullvoid');

async function handlePackageUpdate(packageName, version) {
  const results = await scan(packageName, {
    maxDepth: 2,
    verbose: true
  });
  
  if (results.threats.length > 0) {
    await sendSlackNotification({
      text: `Security threats detected in ${packageName}@${version}`,
      threats: results.threats
    });
  }
}
```

## Best Practices

1. **Always validate inputs** before calling scan functions
2. **Use appropriate log levels** for different environments
3. **Implement retry logic** for network operations
4. **Monitor performance** in production environments
5. **Cache results** when scanning the same packages repeatedly
6. **Handle errors gracefully** with proper error messages
7. **Use parallel processing** for large dependency trees
8. **Set appropriate timeouts** for long-running scans

## Troubleshooting

### Common Issues

1. **Network timeouts**: Increase `NETWORK_CONFIG.TIMEOUT`
2. **Memory issues**: Reduce `maxDepth` or enable parallel processing
3. **Rate limiting**: Implement proper rate limiting for npm registry
4. **Cache issues**: Clear cache or reduce `CACHE_CONFIG.MAX_SIZE`

### Debug Mode

```javascript
process.env.NULLVOID_LOG_LEVEL = 'DEBUG';
process.env.NULLVOID_TIMESTAMP = 'true';

const { scan } = require('nullvoid');
// Now all operations will include detailed logging
```

## Support

For issues, feature requests, or questions:

- GitHub Issues: https://github.com/kurt-grung/NullVoid/issues
- Documentation: https://github.com/kurt-grung/NullVoid#readme
- Security: kurtgrung@gmail.com
