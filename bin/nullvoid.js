#!/usr/bin/env node

const { program } = require('commander');
const colors = require('../colors');
const ora = require('ora');
const path = require('path');
const { scan } = require('../scan');
const packageJson = require('../package.json');

program
  .name('nullvoid')
  .description('Detect and invalidate malicious npm packages before they reach prod')
  .version(packageJson.version);

program
  .command('scan')
  .description('Scan npm packages for malicious behavior')
  .argument('[package]', 'Package name or directory path to scan (default: scan current directory)')
  .option('-v, --verbose', 'Enable verbose output')
  .option('-o, --output <format>', 'Output format (json, table)', 'table')
  .option('-d, --depth <number>', 'Maximum dependency tree depth to scan', '3')
  .option('--tree', 'Show dependency tree structure in output')
  .option('--parallel', 'Enable parallel scanning for better performance', true)
  .option('--no-parallel', 'Disable parallel scanning')
  .option('--workers <number>', 'Number of parallel workers to use', 'auto')
  .option('--all', 'Show all threats including low/medium severity')
  .action(async (packageName, options) => {
    const spinner = ora('🔍 Scanning ...').start();
    
    try {
      // Parse depth option
      const scanOptions = {
        ...options,
        maxDepth: parseInt(options.depth) || 3,
        parallel: options.parallel !== false, // Default to true unless explicitly disabled
        workers: options.workers === 'auto' ? undefined : parseInt(options.workers) || undefined
      };
      
      // Progress callback to show current file with threat detection
      const progressCallback = (filePath) => {
        const fileName = path.basename(filePath);
        const fs = require('fs');
        
        try {
          // Check if this is NullVoid's own code or test files
          const isNullVoidCode = fileName && (
            fileName === 'scan.js' ||
            fileName === 'rules.js' ||
            fileName === 'benchmarks.js' ||
            fileName === 'cache.js' ||
            fileName === 'config.js' ||
            fileName === 'errorHandler.js' ||
            fileName === 'logger.js' ||
            fileName === 'parallel.js' ||
            fileName === 'rateLimiter.js' ||
            fileName === 'streaming.js' ||
            fileName === 'validation.js' ||
            fileName === 'nullvoid.js' ||
            fileName === 'colors.js' ||
            fileName === 'package.json' ||
            fileName === 'README.md' ||
            fileName === 'CHANGELOG.md' ||
            fileName === 'LICENSE' ||
            fileName === 'CONTRIBUTING.md' ||
            fileName === 'SECURITY.md' ||
            fileName === 'CODE_OF_CONDUCT.md'
          );
          
          const isTestFile = fileName && (
            fileName.endsWith('.test.js') ||
            fileName.endsWith('.spec.js') ||
            fileName.includes('test/') ||
            fileName.includes('__tests__/')
          );
          
          // Quick threat check for this file
          const content = fs.readFileSync(filePath, 'utf8');
          const threats = [];
          let maxSeverity = 'LOW';
          let hasThreats = false;
          
          // Check for obfuscated patterns (HIGH severity)
          if (content.includes('_0x') || content.match(/const\s+[a-z]\d+\s*=\s*[A-Z]/)) {
            hasThreats = true;
            if (isNullVoidCode) {
              if (!threats.includes('security tools')) threats.push('security tools');
              maxSeverity = 'LOW';
            } else if (isTestFile) {
              if (!threats.includes('test file')) threats.push('test file');
              maxSeverity = 'LOW';
            } else {
              threats.push('OBFUSCATED_CODE');
              maxSeverity = 'HIGH';
            }
          }
          
          // Check for suspicious modules (CRITICAL severity)
          if (content.includes('require(\'fs\')') || content.includes('require(\'child_process\')') || 
              content.includes('require(\'eval\')') || content.includes('require(\'vm\')')) {
            hasThreats = true;
            if (isNullVoidCode) {
              if (!threats.includes('security tools')) threats.push('security tools');
              maxSeverity = 'LOW';
            } else if (isTestFile) {
              if (!threats.includes('test file')) threats.push('test file');
              maxSeverity = 'LOW';
            } else {
              threats.push('SUSPICIOUS_MODULE');
              maxSeverity = 'CRITICAL';
            }
          }
          
          // Check for malicious code structure (CRITICAL severity)
          if (content.match(/const\s+[a-z]\d+\s*=\s*[A-Z]\s*,\s*[a-z]\d+\s*=\s*[A-Z]/) ||
              content.split('\n').some(line => line.length > 1000)) {
            hasThreats = true;
            if (isNullVoidCode) {
              if (!threats.includes('security tools')) threats.push('security tools');
              maxSeverity = 'LOW';
            } else if (isTestFile) {
              if (!threats.includes('test file')) threats.push('test file');
              maxSeverity = 'LOW';
            } else {
              threats.push('MALICIOUS_CODE_STRUCTURE');
              maxSeverity = 'CRITICAL';
            }
          }
          
          // Display filename with threat info using severity-based colors
          if (hasThreats) {
            // Remove duplicates and join
            const uniqueThreats = [...new Set(threats)];
            const threatText = uniqueThreats.join(', ');
            let colorFunc;
            
            // Color code based on severity (same as results display)
            if (maxSeverity === 'CRITICAL') {
              colorFunc = colors.red; // Red for CRITICAL
            } else if (maxSeverity === 'HIGH') {
              colorFunc = colors.red; // Red for HIGH
            } else if (maxSeverity === 'MEDIUM') {
              colorFunc = colors.yellow; // Yellow for MEDIUM
            } else {
              colorFunc = colors.blue; // Blue for LOW
            }
            
            process.stdout.write(`\n📁 ${fileName} ${colorFunc(`(detected: ${threatText})`)}`);
          } else {
            process.stdout.write(`\n📁 ${fileName}`);
          }
          
          // Debug: Log progress updates
          if (process.env.NULLVOID_DEBUG) {
            console.log(`\nDEBUG: Scanning file: ${fileName}`);
          }
        } catch (error) {
          // If we can't read the file, just show the filename
          process.stdout.write(`\n📁 ${fileName}`);
        }
      };
      
      const results = await scan(packageName, scanOptions, progressCallback);
      spinner.succeed('✅ Scan completed');
      
      if (options.output === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        displayResults(results, options);
      }
      
      // Properly exit after successful completion
      process.exit(0);
    } catch (error) {
      spinner.fail('❌ Scan failed');
      console.error(colors.red('Error:'), error.message);
      process.exit(1);
    }
  });

program.parse();

function displayResults(results, options = {}) {
  // Use the enhanced output from scan.js instead of custom logic
  // The scan.js file already handles severity filtering and sorting
  console.log(colors.bold('\n🔍 NullVoid Scan Results\n'));
  
  if (results.threats.length === 0) {
    console.log(colors.green('✅ No threats detected'));
  } else {
    // Sort threats by severity (HIGH first, then MEDIUM, then LOW)
    const severityOrder = { 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'CRITICAL': 0 };
    const sortedThreats = results.threats.sort((a, b) => {
      const aOrder = severityOrder[a.severity] || 4;
      const bOrder = severityOrder[b.severity] || 4;
      return aOrder - bOrder;
    });
    
    // Filter to only show HIGH and above severity (unless --all flag is used)
    const showAllThreats = options.all;
    const highSeverityThreats = showAllThreats ? sortedThreats : sortedThreats.filter(threat => 
      threat.severity === 'HIGH' || threat.severity === 'CRITICAL'
    );
    
    if (highSeverityThreats.length === 0) {
        console.log(colors.green('✅ No high-severity threats detected'));
        if (!showAllThreats) {
          console.log(colors.blue(`ℹ️  ${results.threats.length - highSeverityThreats.length} low/medium severity threats were filtered out`));
          console.log(colors.blue('💡 Use --all flag to see all threats'));
        }
    } else {
      const threatCount = showAllThreats ? results.threats.length : highSeverityThreats.length;
      const severityText = showAllThreats ? 'threat(s)' : 'high-severity threat(s)';
      console.log(colors.red(`⚠️  ${threatCount} ${severityText} detected:\n`));
      
      highSeverityThreats.forEach((threat, index) => {
        // Color code based on severity
        let severityColor = '';
        if (threat.severity === 'CRITICAL') {
          severityColor = '\x1b[31m'; // Red for CRITICAL
        } else if (threat.severity === 'HIGH') {
          severityColor = '\x1b[31m'; // Red for HIGH
        } else if (threat.severity === 'MEDIUM') {
          severityColor = '\x1b[33m'; // Yellow for MEDIUM
        } else if (threat.severity === 'LOW') {
          severityColor = '\x1b[34m'; // Blue for LOW
        }
        
        console.log(`${index + 1}. ${threat.type}: ${threat.message}`);
        if (threat.package) {
          // Color code package paths
          let packageColor = '';
          if (threat.package.includes('📁')) {
            packageColor = '\x1b[32m'; // Green for local packages
          } else if (threat.package.includes('📦')) {
            packageColor = '\x1b[33m'; // Yellow for registry packages
          }
          console.log(`   Package: ${packageColor}${threat.package}\x1b[0m`);
        }
        if (threat.lineNumber) {
          console.log(`   Line: ${threat.lineNumber}`);
        }
        if (threat.sampleCode) {
          console.log(`   Sample: ${threat.sampleCode}`);
        }
        if (threat.severity) {
          console.log(`   Severity: ${severityColor}${threat.severity}\x1b[0m`);
        }
        if (threat.details) {
          console.log(`   Details: ${threat.details}`);
        }
        console.log('');
      });
    }
  }
  
  // Display directory structure for directory scans
  if (results.directoryStructure && results.packagesScanned === 0) {
    console.log(colors.blue(`\n📁 Directory Structure:`));
    console.log(colors.gray(`   ${results.directoryStructure.totalDirectories} directories: ${results.directoryStructure.directories.slice(0, 5).join(', ')}${results.directoryStructure.directories.length > 5 ? '...' : ''}`));
    console.log(colors.gray(`   ${results.directoryStructure.totalFiles} files: ${results.directoryStructure.files.slice(0, 5).join(', ')}${results.directoryStructure.files.length > 5 ? '...' : ''}`));
  }
  
  // Display dependency tree structure for package scans
  if (results.dependencyTree && options.tree) {
    console.log(colors.blue(`\n🌳 Dependency Tree Structure:`));
    displayDependencyTree(results.dependencyTree, 0, options.verbose);
  }
  
  // Show dependency tree summary
  if (results.dependencyTree) {
    const treeStats = analyzeTreeStats(results.dependencyTree);
    console.log(colors.blue(`\n📊 Dependency Tree Analysis:`));
    console.log(colors.gray(`   Total packages scanned: ${treeStats.totalPackages}`));
    console.log(colors.gray(`   Max depth reached: ${treeStats.maxDepth}`));
    console.log(colors.gray(`   Packages with threats: ${treeStats.packagesWithThreats}`));
    console.log(colors.gray(`   Deep dependencies (depth ≥2): ${treeStats.deepDependencies}`));
  }
  
  // Show performance metrics
  if (results.performance && options.verbose) {
    console.log(colors.blue(`\n⚡ Performance Metrics:`));
    console.log(colors.gray(`   Cache hit rate: ${(results.performance.cacheHitRate * 100).toFixed(1)}%`));
    console.log(colors.gray(`   Packages per second: ${results.performance.packagesPerSecond.toFixed(1)}`));
    console.log(colors.gray(`   Network requests: ${results.performance.networkRequests}`));
    console.log(colors.gray(`   Errors: ${results.performance.errors}`));
    if (results.metrics && results.metrics.parallelWorkers > 0) {
      console.log(colors.gray(`   Parallel workers: ${results.metrics.parallelWorkers}`));
    }
    console.log(colors.gray(`   Duration: ${results.performance.duration}ms`));
  }
  
  console.log(colors.gray(`\n📊 Scanned ${results.packagesScanned > 0 ? results.packagesScanned : 1} ${results.packagesScanned > 0 ? 'package' : 'directory'}(s)${results.filesScanned ? `, ${results.filesScanned} file(s)` : ''} in ${results.duration}ms`));
}

/**
 * Display dependency tree structure
 * @param {object} tree - Dependency tree
 * @param {number} depth - Current depth
 * @param {boolean} verbose - Show verbose information
 */
function displayDependencyTree(tree, depth = 0, verbose = false) {
  const indent = '  '.repeat(depth);
  
  for (const [packageName, packageInfo] of Object.entries(tree)) {
    const threatCount = Array.isArray(packageInfo.threats) ? packageInfo.threats.length : 0;
    const depCount = packageInfo.dependencies && typeof packageInfo.dependencies === 'object' ? Object.keys(packageInfo.dependencies).length : 0;
    
    // Color based on threat level
    let packageColor = colors.gray;
    if (threatCount > 0 && Array.isArray(packageInfo.threats)) {
      const maxSeverity = Math.max(...packageInfo.threats.map(t => 
        t.severity === 'CRITICAL' ? 4 : 
        t.severity === 'HIGH' ? 3 : 
        t.severity === 'MEDIUM' ? 2 : 1
      ));
      
      packageColor = maxSeverity === 4 ? colors.red.bold :
                    maxSeverity === 3 ? colors.red :
                    maxSeverity === 2 ? colors.yellow : colors.gray;
    }
    
    // Display package info
    let packageDisplay = `${indent}${packageColor(packageName)}@${packageInfo.version}`;
    if (threatCount > 0) {
      packageDisplay += colors.red(` (${threatCount} threat${threatCount > 1 ? 's' : ''})`);
    }
    if (depCount > 0) {
      packageDisplay += colors.gray(` [${depCount} deps]`);
    }
    
    console.log(packageDisplay);
    
    // Show threats in verbose mode
    if (verbose && threatCount > 0) {
      packageInfo.threats.forEach(threat => {
        const severityColor = threat.severity === 'CRITICAL' ? colors.red.bold :
                             threat.severity === 'HIGH' ? colors.red :
                             threat.severity === 'MEDIUM' ? colors.yellow : colors.gray;
        console.log(`${indent}  ${severityColor('⚠')} ${threat.type}: ${threat.message}`);
      });
    }
    
    // Recursively display dependencies
    if (packageInfo.dependencies && typeof packageInfo.dependencies === 'object' && Object.keys(packageInfo.dependencies).length > 0) {
      displayDependencyTree(packageInfo.dependencies, depth + 1, verbose);
    }
  }
}

/**
 * Analyze dependency tree statistics
 * @param {object} tree - Dependency tree
 * @returns {object} Tree statistics
 */
function analyzeTreeStats(tree) {
  let totalPackages = 0;
  let maxDepth = 0;
  let packagesWithThreats = 0;
  let deepDependencies = 0;
  
  function analyzeNode(node, depth = 0) {
    totalPackages++;
    maxDepth = Math.max(maxDepth, depth);
    
    if (node.threats && Array.isArray(node.threats) && node.threats.length > 0) {
      packagesWithThreats++;
    }
    
    if (depth >= 2) {
      deepDependencies++;
    }
    
    if (node.dependencies && typeof node.dependencies === 'object') {
      for (const dep of Object.values(node.dependencies)) {
        analyzeNode(dep, depth + 1);
      }
    }
  }
  
  for (const packageInfo of Object.values(tree)) {
    analyzeNode(packageInfo);
  }
  
  return {
    totalPackages,
    maxDepth,
    packagesWithThreats,
    deepDependencies
  };
}
