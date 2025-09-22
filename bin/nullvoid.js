#!/usr/bin/env node

const { program } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const { scan } = require('../scan');
const packageJson = require('../package.json');

program
  .name('nullvoid')
  .description('Detect and invalidate malicious npm packages before they reach prod')
  .version(packageJson.version);

program
  .command('scan')
  .description('Scan npm packages for malicious behavior')
  .argument('[package]', 'Package name or directory path to scan (default: scan package.json)')
  .option('-v, --verbose', 'Enable verbose output')
  .option('-o, --output <format>', 'Output format (json, table)', 'table')
  .option('-d, --depth <number>', 'Maximum dependency tree depth to scan', '3')
  .option('--tree', 'Show dependency tree structure in output')
  .action(async (packageName, options) => {
    const spinner = ora('Scanning packages...').start();
    
    try {
      // Parse depth option
      const scanOptions = {
        ...options,
        maxDepth: parseInt(options.depth) || 3
      };
      
      const results = await scan(packageName, scanOptions);
      spinner.succeed('Scan completed');
      
      if (options.output === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        displayResults(results, options);
      }
    } catch (error) {
      spinner.fail('Scan failed');
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

program.parse();

function displayResults(results, options = {}) {
  console.log(chalk.bold('\n🔍 NullVoid Scan Results\n'));
  
  if (results.threats.length === 0) {
    console.log(chalk.green('✅ No threats detected'));
  } else {
    console.log(chalk.red(`⚠️  ${results.threats.length} threat(s) detected:\n`));
    
    results.threats.forEach((threat, index) => {
      const severityColor = threat.severity === 'CRITICAL' ? chalk.red.bold :
                           threat.severity === 'HIGH' ? chalk.red :
                           threat.severity === 'MEDIUM' ? chalk.yellow :
                           threat.severity === 'INFO' ? chalk.blue :
                           chalk.green;
      
      // Skip INFO threats in normal output, show them in verbose mode
      if (threat.severity === 'INFO' && !options.verbose) {
        return;
      }
      
      console.log(severityColor(`${index + 1}. ${threat.type}: ${threat.message}`));
      if (threat.package) {
        const packageDisplay = threat.packagePath || threat.package;
        console.log(chalk.gray(`   Package: ${packageDisplay}`));
      }
      if (threat.severity) {
        console.log(severityColor(`   Severity: ${threat.severity}`));
      }
      if (threat.directory) {
        console.log(chalk.gray(`   Directory: ${threat.directory}`));
      }
      console.log('');
    });
  }
  
  // Display directory structure for directory scans
  if (results.directoryStructure && results.packagesScanned === 0) {
    console.log(chalk.blue(`\n📁 Directory Structure:`));
    console.log(chalk.gray(`   ${results.directoryStructure.totalDirectories} directories: ${results.directoryStructure.directories.slice(0, 5).join(', ')}${results.directoryStructure.directories.length > 5 ? '...' : ''}`));
    console.log(chalk.gray(`   ${results.directoryStructure.totalFiles} files: ${results.directoryStructure.files.slice(0, 5).join(', ')}${results.directoryStructure.files.length > 5 ? '...' : ''}`));
  }
  
  // Display dependency tree structure for package scans
  if (results.dependencyTree && options.tree) {
    console.log(chalk.blue(`\n🌳 Dependency Tree Structure:`));
    displayDependencyTree(results.dependencyTree, 0, options.verbose);
  }
  
  // Show dependency tree summary
  if (results.dependencyTree) {
    const treeStats = analyzeTreeStats(results.dependencyTree);
    console.log(chalk.blue(`\n📊 Dependency Tree Analysis:`));
    console.log(chalk.gray(`   Total packages scanned: ${treeStats.totalPackages}`));
    console.log(chalk.gray(`   Max depth reached: ${treeStats.maxDepth}`));
    console.log(chalk.gray(`   Packages with threats: ${treeStats.packagesWithThreats}`));
    console.log(chalk.gray(`   Deep dependencies (depth ≥2): ${treeStats.deepDependencies}`));
  }
  
  // Show performance metrics
  if (results.performance && options.verbose) {
    console.log(chalk.blue(`\n⚡ Performance Metrics:`));
    console.log(chalk.gray(`   Cache hit rate: ${(results.performance.cacheHitRate * 100).toFixed(1)}%`));
    console.log(chalk.gray(`   Packages per second: ${results.performance.packagesPerSecond.toFixed(1)}`));
    console.log(chalk.gray(`   Network requests: ${results.performance.networkRequests}`));
    console.log(chalk.gray(`   Errors: ${results.performance.errors}`));
    console.log(chalk.gray(`   Duration: ${results.performance.duration}ms`));
  }
  
  console.log(chalk.gray(`\nScanned ${results.packagesScanned > 0 ? results.packagesScanned : 1} ${results.packagesScanned > 0 ? 'package' : 'directory'}(s)${results.filesScanned ? `, ${results.filesScanned} file(s)` : ''} in ${results.duration}ms`));
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
    let packageColor = chalk.gray;
    if (threatCount > 0 && Array.isArray(packageInfo.threats)) {
      const maxSeverity = Math.max(...packageInfo.threats.map(t => 
        t.severity === 'CRITICAL' ? 4 : 
        t.severity === 'HIGH' ? 3 : 
        t.severity === 'MEDIUM' ? 2 : 1
      ));
      
      packageColor = maxSeverity === 4 ? chalk.red.bold :
                    maxSeverity === 3 ? chalk.red :
                    maxSeverity === 2 ? chalk.yellow : chalk.gray;
    }
    
    // Display package info
    let packageDisplay = `${indent}${packageColor(packageName)}@${packageInfo.version}`;
    if (threatCount > 0) {
      packageDisplay += chalk.red(` (${threatCount} threat${threatCount > 1 ? 's' : ''})`);
    }
    if (depCount > 0) {
      packageDisplay += chalk.gray(` [${depCount} deps]`);
    }
    
    console.log(packageDisplay);
    
    // Show threats in verbose mode
    if (verbose && threatCount > 0) {
      packageInfo.threats.forEach(threat => {
        const severityColor = threat.severity === 'CRITICAL' ? chalk.red.bold :
                             threat.severity === 'HIGH' ? chalk.red :
                             threat.severity === 'MEDIUM' ? chalk.yellow : chalk.gray;
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
