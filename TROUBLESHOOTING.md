# NullVoid Troubleshooting Guide

This guide helps you diagnose and resolve common issues with NullVoid.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Scan Failures](#scan-failures)
3. [Performance Issues](#performance-issues)
4. [Network Issues](#network-issues)
5. [Memory Issues](#memory-issues)
6. [Permission Issues](#permission-issues)
7. [Configuration Issues](#configuration-issues)
8. [Debug Mode](#debug-mode)
9. [Common Error Messages](#common-error-messages)
10. [Getting Help](#getting-help)

## Installation Issues

### Issue: `npm install -g nullvoid` fails

**Symptoms:**
- Permission denied errors
- Package not found errors
- Installation hangs

**Solutions:**

1. **Permission Issues:**
   ```bash
   # Use sudo (Linux/macOS)
   sudo npm install -g nullvoid
   
   # Or configure npm to use a different directory
   mkdir ~/.npm-global
   npm config set prefix '~/.npm-global'
   export PATH=~/.npm-global/bin:$PATH
   npm install -g nullvoid
   ```

2. **Network Issues:**
   ```bash
   # Use a different registry
   npm install -g nullvoid --registry https://registry.npmjs.org/
   
   # Or use yarn
   yarn global add nullvoid
   ```

3. **Node.js Version:**
   ```bash
   # Check Node.js version
   node --version
   
   # NullVoid requires Node.js >= 14.0.0
   # Update Node.js if needed
   ```

### Issue: Command not found after installation

**Symptoms:**
- `nullvoid: command not found`
- `zsh: command not found: nullvoid`

**Solutions:**

1. **Check PATH:**
   ```bash
   # Check if nullvoid is in PATH
   which nullvoid
   
   # Add npm global bin to PATH
   export PATH=$(npm config get prefix)/bin:$PATH
   ```

2. **Restart Terminal:**
   ```bash
   # Close and reopen terminal
   # Or reload shell configuration
   source ~/.bashrc  # or ~/.zshrc
   ```

## Scan Failures

### Issue: Scan hangs or times out

**Symptoms:**
- Scan starts but never completes
- No output for extended periods
- Process becomes unresponsive

**Solutions:**

1. **Increase Timeout:**
   ```bash
   # Set environment variable
   export NULLVOID_TIMEOUT=60000  # 60 seconds
   nullvoid scan
   ```

2. **Reduce Scan Depth:**
   ```bash
   # Limit dependency depth
   nullvoid scan --depth 1
   ```

3. **Disable Parallel Processing:**
   ```bash
   # Disable parallel processing
   nullvoid scan --no-parallel
   ```

4. **Check for Large Files:**
   ```bash
   # Enable verbose mode to see progress
   nullvoid scan --verbose
   ```

### Issue: "Package not found" errors

**Symptoms:**
- `Package 'package-name' not found`
- `HTTP 404: Not Found`

**Solutions:**

1. **Check Package Name:**
   ```bash
   # Verify package exists on npm
   npm view package-name
   ```

2. **Check Network Connection:**
   ```bash
   # Test npm registry access
   curl https://registry.npmjs.org/express
   ```

3. **Use Different Registry:**
   ```bash
   # Set npm registry
   npm config set registry https://registry.npmjs.org/
   ```

### Issue: Invalid package.json errors

**Symptoms:**
- `Could not parse package.json`
- `Invalid JSON in package.json`

**Solutions:**

1. **Validate JSON:**
   ```bash
   # Check package.json syntax
   node -e "console.log(JSON.parse(require('fs').readFileSync('package.json')))"
   ```

2. **Fix Common Issues:**
   - Remove trailing commas
   - Fix unescaped quotes
   - Ensure proper JSON structure

3. **Backup and Recreate:**
   ```bash
   # Backup current package.json
   cp package.json package.json.backup
   
   # Recreate with npm init
   npm init
   ```

## Performance Issues

### Issue: Slow scanning

**Symptoms:**
- Scan takes very long to complete
- High CPU usage
- Slow progress updates

**Solutions:**

1. **Enable Parallel Processing:**
   ```bash
   # Use parallel processing (default)
   nullvoid scan --parallel
   
   # Adjust worker count
   nullvoid scan --workers 4
   ```

2. **Optimize Cache:**
   ```bash
   # Clear cache
   rm -rf ~/.nullvoid-cache
   
   # Increase cache size
   export NULLVOID_CACHE_MAX_SIZE=2000
   ```

3. **Limit Scan Scope:**
   ```bash
   # Scan specific packages only
   nullvoid scan package-name
   
   # Limit depth
   nullvoid scan --depth 2
   ```

4. **Use Streaming for Large Files:**
   ```bash
   # Enable streaming mode
   export NULLVOID_STREAMING=true
   nullvoid scan
   ```

### Issue: High Memory Usage

**Symptoms:**
- Process uses excessive memory
- System becomes slow
- Out of memory errors

**Solutions:**

1. **Reduce Memory Usage:**
   ```bash
   # Limit file size
   export NULLVOID_MAX_FILE_SIZE=5242880  # 5MB
   
   # Reduce cache size
   export NULLVOID_CACHE_MAX_SIZE=500
   ```

2. **Use Streaming Mode:**
   ```bash
   # Enable streaming for large files
   export NULLVOID_STREAMING=true
   nullvoid scan
   ```

3. **Process in Batches:**
   ```bash
   # Scan packages individually
   for package in $(cat package-list.txt); do
     nullvoid scan $package
   done
   ```

## Network Issues

### Issue: Network timeouts

**Symptoms:**
- `Request timeout` errors
- `ECONNRESET` errors
- Slow network requests

**Solutions:**

1. **Increase Timeout:**
   ```bash
   # Set network timeout
   export NULLVOID_NETWORK_TIMEOUT=30000  # 30 seconds
   ```

2. **Check Network Connection:**
   ```bash
   # Test connectivity
   ping registry.npmjs.org
   curl -I https://registry.npmjs.org/
   ```

3. **Use Proxy:**
   ```bash
   # Set npm proxy
   npm config set proxy http://proxy.company.com:8080
   npm config set https-proxy http://proxy.company.com:8080
   ```

4. **Disable Rate Limiting:**
   ```bash
   # Disable rate limiting (use with caution)
   export NULLVOID_RATE_LIMIT=false
   ```

### Issue: Rate limiting errors

**Symptoms:**
- `Rate limit exceeded` messages
- `HTTP 429: Too Many Requests`

**Solutions:**

1. **Wait and Retry:**
   ```bash
   # Wait a few minutes and retry
   sleep 300
   nullvoid scan
   ```

2. **Reduce Request Rate:**
   ```bash
   # Use fewer workers
   nullvoid scan --workers 1
   ```

3. **Use Local Cache:**
   ```bash
   # Enable aggressive caching
   export NULLVOID_CACHE_TTL=3600000  # 1 hour
   ```

## Memory Issues

### Issue: Out of memory errors

**Symptoms:**
- `JavaScript heap out of memory`
- Process crashes
- System becomes unresponsive

**Solutions:**

1. **Increase Node.js Memory:**
   ```bash
   # Increase heap size
   node --max-old-space-size=4096 $(which nullvoid) scan
   ```

2. **Use Streaming Mode:**
   ```bash
   # Enable streaming
   export NULLVOID_STREAMING=true
   nullvoid scan
   ```

3. **Process Smaller Batches:**
   ```bash
   # Scan fewer packages at once
   nullvoid scan --depth 1 --workers 1
   ```

4. **Clear System Memory:**
   ```bash
   # Clear system cache (Linux)
   sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
   ```

## Permission Issues

### Issue: Permission denied errors

**Symptoms:**
- `EACCES: permission denied`
- `Cannot read file`
- `Cannot write to directory`

**Solutions:**

1. **Fix File Permissions:**
   ```bash
   # Fix package.json permissions
   chmod 644 package.json
   
   # Fix directory permissions
   chmod 755 node_modules
   ```

2. **Use Different User:**
   ```bash
   # Run as different user
   sudo -u username nullvoid scan
   ```

3. **Change Working Directory:**
   ```bash
   # Use a writable directory
   cd /tmp
   nullvoid scan /path/to/project
   ```

## Configuration Issues

### Issue: Configuration not loading

**Symptoms:**
- Default values used instead of custom config
- Configuration errors
- Settings not applied

**Solutions:**

1. **Check Configuration File:**
   ```bash
   # Verify configuration syntax
   node -e "console.log(require('./nullvoid.config.js'))"
   ```

2. **Use Environment Variables:**
   ```bash
   # Set configuration via environment
   export NULLVOID_MAX_DEPTH=2
   export NULLVOID_WORKERS=4
   nullvoid scan
   ```

3. **Check File Location:**
   ```bash
   # Configuration should be in project root
   ls -la nullvoid.config.js
   ```

### Issue: Invalid configuration values

**Symptoms:**
- `Invalid configuration value` errors
- Unexpected behavior
- Validation errors

**Solutions:**

1. **Validate Configuration:**
   ```bash
   # Check configuration values
   nullvoid scan --help
   ```

2. **Reset to Defaults:**
   ```bash
   # Remove custom configuration
   rm nullvoid.config.js
   ```

3. **Use Valid Values:**
   ```bash
   # Check valid options
   nullvoid scan --help
   ```

## Debug Mode

### Enable Debug Logging

```bash
# Set debug level
export NULLVOID_LOG_LEVEL=DEBUG

# Enable timestamps
export NULLVOID_TIMESTAMP=true

# Run scan with debug info
nullvoid scan --verbose
```

### Debug Output Examples

```bash
# Debug network requests
export NULLVOID_LOG_LEVEL=DEBUG
nullvoid scan express

# Debug cache operations
export NULLVOID_CACHE_DEBUG=true
nullvoid scan lodash

# Debug parallel processing
export NULLVOID_PARALLEL_DEBUG=true
nullvoid scan --parallel
```

## Common Error Messages

### `ValidationError: Package name contains invalid characters`

**Cause:** Invalid package name format
**Solution:** Use valid npm package names (letters, numbers, hyphens, underscores only)

### `NetworkError: Request timeout`

**Cause:** Network request timed out
**Solution:** Increase timeout or check network connection

### `CacheError: Cache operation failed`

**Cause:** Cache system error
**Solution:** Clear cache or disable caching

### `WorkerError: Worker process failed`

**Cause:** Parallel worker process error
**Solution:** Disable parallel processing or reduce workers

### `FileError: File too large`

**Cause:** File exceeds size limit
**Solution:** Enable streaming mode or increase file size limit

## Getting Help

### Before Asking for Help

1. **Check this troubleshooting guide**
2. **Enable debug mode and collect logs**
3. **Try with minimal configuration**
4. **Check for known issues on GitHub**

### Collecting Debug Information

```bash
# Collect system information
node --version
npm --version
nullvoid --version

# Collect debug logs
export NULLVOID_LOG_LEVEL=DEBUG
export NULLVOID_TIMESTAMP=true
nullvoid scan --verbose > debug.log 2>&1

# Collect system resources
top -n 1
df -h
free -h
```

### Reporting Issues

When reporting issues, include:

1. **NullVoid version:** `nullvoid --version`
2. **Node.js version:** `node --version`
3. **Operating system:** `uname -a`
4. **Debug logs:** Output from debug mode
5. **Steps to reproduce:** Exact commands used
6. **Expected vs actual behavior**

### Support Channels

- **GitHub Issues:** https://github.com/kurt-grung/NullVoid/issues
- **Documentation:** https://github.com/kurt-grung/NullVoid#readme
- **Security Issues:** security@nullvoid.dev

### Community Support

- **Discord:** [NullVoid Community](https://discord.gg/nullvoid)
- **Reddit:** r/nullvoid
- **Stack Overflow:** Tag questions with `nullvoid`

## Performance Optimization Tips

### For Large Projects

1. **Use streaming mode:**
   ```bash
   export NULLVOID_STREAMING=true
   ```

2. **Limit scan depth:**
   ```bash
   nullvoid scan --depth 2
   ```

3. **Process in batches:**
   ```bash
   # Split large dependency lists
   nullvoid scan package1 package2 package3
   ```

### For CI/CD Pipelines

1. **Use caching:**
   ```bash
   export NULLVOID_CACHE_TTL=3600000  # 1 hour
   ```

2. **Set appropriate timeouts:**
   ```bash
   export NULLVOID_TIMEOUT=300000  # 5 minutes
   ```

3. **Use parallel processing:**
   ```bash
   nullvoid scan --parallel --workers 4
   ```

### For Development

1. **Enable verbose mode:**
   ```bash
   nullvoid scan --verbose
   ```

2. **Use JSON output:**
   ```bash
   nullvoid scan --output json
   ```

3. **Show all threats:**
   ```bash
   nullvoid scan --all
   ```

## Advanced Troubleshooting

### Profiling Performance

```bash
# Profile with Node.js built-in profiler
node --prof $(which nullvoid) scan

# Analyze profile
node --prof-process isolate-*.log
```

### Memory Analysis

```bash
# Generate heap snapshot
node --heapsnapshot-signal=SIGUSR2 $(which nullvoid) scan

# Analyze with Chrome DevTools
# Load .heapsnapshot file in Chrome DevTools
```

### Network Analysis

```bash
# Monitor network requests
tcpdump -i any host registry.npmjs.org

# Check DNS resolution
nslookup registry.npmjs.org
```

This troubleshooting guide should help you resolve most common issues with NullVoid. If you encounter issues not covered here, please report them on GitHub with the debug information collected using the methods described above.
