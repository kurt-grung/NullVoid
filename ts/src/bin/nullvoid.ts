#!/usr/bin/env node

import { program } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import ora from 'ora';
import { scan } from '../scan';
import { ScanOptions, ScanResult } from '../types/core';
import { generateSarifOutput } from '../lib/sarif';
import { detectMalware } from '../lib/detection';
import * as packageJson from '../../package.json';

program
  .name('nullvoid')
  .description('NullVoid Security Scanner')
  .version(packageJson.version);

// Main scan command (default action)
program
  .argument('[target]', 'Package name, directory, or file to scan (defaults to current directory)')
  .option('-d, --depth <number>', 'Maximum depth for dependency scanning', '5')
  .option('-p, --parallel', 'Enable parallel processing')
  .option('-w, --workers <number>', 'Number of workers for parallel processing', 'auto')
  .option('--include-dev', 'Include development dependencies')
  .option('--skip-cache', 'Skip cache')
  .option('-o, --output <file>', 'Output file path')
  .option('-f, --format <format>', 'Output format', 'json')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--debug', 'Enable debug mode')
  .option('-r, --rules <file>', 'Custom rules file')
  .option('--sarif <file>', 'SARIF output file')
  .option('--all', 'Show all threats including low severity')
  .action(async (target: string | undefined, options: any) => {
    await performScan(target, options);
  });

// Backward compatibility: "nullvoid scan" command
program
  .command('scan')
  .description('Scan for security threats (backward compatibility)')
  .argument('[target]', 'Package name, directory, or file to scan (defaults to current directory)')
  .option('-d, --depth <number>', 'Maximum depth for dependency scanning', '5')
  .option('-p, --parallel', 'Enable parallel processing')
  .option('-w, --workers <number>', 'Number of workers for parallel processing', 'auto')
  .option('--include-dev', 'Include development dependencies')
  .option('--skip-cache', 'Skip cache')
  .option('-o, --output <file>', 'Output file path')
  .option('-f, --format <format>', 'Output format', 'json')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--debug', 'Enable debug mode')
  .option('-r, --rules <file>', 'Custom rules file')
  .option('--sarif <file>', 'SARIF output file')
  .option('--all', 'Show all threats including low severity')
  .action(async (target: string | undefined, options: any) => {
    await performScan(target, options);
  });

async function performScan(target: string | undefined, options: any) {
    const spinner = ora('🔍 Scanning ...').start();
    
    try {
      const scanOptions: ScanOptions = {
        depth: parseInt(options.depth),
        parallel: options.parallel,
        workers: options.workers === 'auto' ? undefined : (options.workers ? parseInt(options.workers) : undefined),
        includeDevDependencies: options.includeDev,
        skipCache: options.skipCache,
        outputFile: options.output,
        format: options.format,
        verbose: options.verbose,
        debug: options.debug,
        rulesFile: options.rules,
        sarifFile: options.sarif,
        all: options.all
      };

      // Progress callback to show current file with threat detection
      let isFirstFile = true;
      const progressCallback = (progress: { current: number; total: number; message: string; packageName?: string }) => {
        const filePath = progress.packageName || progress.message;
        const originalScanTarget = target || process.cwd();
        const relativePath = path.relative(originalScanTarget, filePath);
        const displayPath = relativePath || path.basename(filePath);
        
        try {
          // Quick threat check for this file (only show HIGH/CRITICAL)
          const content = fs.readFileSync(filePath, 'utf8');
          const threats: string[] = [];
          let hasHighSeverityThreats = false;
          
          // Use the same detection logic as the main scanner
          const fileThreats = detectMalware(content, filePath);
          const highSeverityThreats = fileThreats.filter((threat: any) => 
            threat.severity === 'HIGH' || threat.severity === 'CRITICAL'
          );
          
          if (highSeverityThreats.length > 0) {
            hasHighSeverityThreats = true;
            highSeverityThreats.forEach((threat: any) => {
              if (!threats.includes(threat.type)) {
                threats.push(threat.type);
              }
            });
          }
          
          if (hasHighSeverityThreats) {
            const threatText = threats.join(', ');
            const prefix = isFirstFile ? '\n' : '';
            console.log(`${prefix}📁 ${displayPath} (detected: ${threatText})`);
            isFirstFile = false;
          } else {
            const prefix = isFirstFile ? '\n' : '';
            console.log(`${prefix}📁 ${displayPath}`);
            isFirstFile = false;
          }
        } catch {
          // If we can't read the file, just show the relative path
          const prefix = isFirstFile ? '\n' : '';
          console.log(`${prefix}📁 ${displayPath}`);
          isFirstFile = false;
        }
      };

      const result = await scan(target || '.', scanOptions, progressCallback);
      spinner.succeed('✅ Scan completed');
      
      // Display results
      displayResults(result, options);
      
      if (options.output) {
        fs.writeFileSync(options.output, JSON.stringify(result, null, 2));
        console.log(`Results written to ${options.output}`);
      }

      if (options.sarif) {
        const sarifOutput = generateSarifOutput(result.threats);
        fs.writeFileSync(options.sarif, JSON.stringify(sarifOutput, null, 2));
        console.log(`✅ SARIF output written to: ${options.sarif}`);
      }
    } catch (error) {
      spinner.fail('❌ Scan failed');
      console.error('Error:', (error as Error).message);
      process.exit(1);
    }
}

program.parse();

function displayResults(results: ScanResult, options: any) {
  console.log('\n🔍 NullVoid Scan Results\n');
  
  if (results.threats.length === 0) {
    console.log('✅ No threats detected');
  } else {
    // Sort threats by severity (HIGH first, then MEDIUM, then LOW)
    const severityOrder: Record<string, number> = { 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'CRITICAL': 0 };
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
        console.log('✅ No high-severity threats detected');
        if (!showAllThreats) {
          console.log(`ℹ️  ${results.threats.length - highSeverityThreats.length} low/medium severity threats were filtered out`);
          console.log('💡 Use --all flag to see all threats');
        }
    } else {
      const threatCount = showAllThreats ? results.threats.length : highSeverityThreats.length;
      const severityText = showAllThreats ? 'threat(s)' : 'high-severity threat(s)';
      console.log(`⚠️  ${threatCount} ${severityText} detected:\n`);
      
      highSeverityThreats.forEach((threat, index) => {
        // Color code based on severity
        let severityColor = '';
        if (threat.severity === 'CRITICAL') {
          severityColor = '\x1b[31m'; // Red for CRITICAL
        } else if (threat.severity === 'HIGH') {
          severityColor = '\x1b[31m'; // Red for HIGH
        } else if (threat.severity === 'MEDIUM') {
          severityColor = '\x1b[33m'; // Yellow for MEDIUM
        } else {
          severityColor = '\x1b[36m'; // Cyan for LOW
        }
        
        const resetColor = '\x1b[0m';
        console.log(`${severityColor}${index + 1}. ${threat.type} (${threat.severity})${resetColor}`);
        console.log(`   ${threat.message}`);
        if (threat.details) {
          console.log(`   Details: ${threat.details}`);
        }
        if (threat.filePath) {
          console.log(`   File: ${threat.filePath}`);
        }
        if (threat.lineNumber) {
          console.log(`   Line: ${threat.lineNumber}`);
        }
        console.log('');
      });
    }
  }
  
  // Display directory structure for directory scans
  if (results.directoryStructure) {
    console.log(`\n📁 Directory Structure:`);
    console.log(`   ${results.directoryStructure.totalDirectories || results.directoryStructure.directories.length} directories: ${results.directoryStructure.directories.slice(0, 5).join(', ')}${results.directoryStructure.directories.length > 5 ? '...' : ''}`);
    console.log(`   ${results.directoryStructure.totalFiles || results.directoryStructure.files.length} files: ${results.directoryStructure.files.slice(0, 5).join(', ')}${results.directoryStructure.files.length > 5 ? '...' : ''}`);
  }
  
  // Show dependency tree summary
  if (results.dependencyTree || (results.packagesScanned && results.packagesScanned > 0)) {
    console.log(`\n📊 Dependency Tree Analysis:`);
    console.log(`   Total packages scanned: ${results.dependencyTree?.totalPackages || results.packagesScanned}`);
    console.log(`   Max depth reached: ${results.dependencyTree?.maxDepth || options.depth || 5}`);
    console.log(`   Packages with threats: ${results.dependencyTree?.packagesWithThreats || results.threats.filter(t => t.package).length}`);
    console.log(`   Deep dependencies (depth ≥2): ${results.dependencyTree?.deepDependencies || 0}`);
  }
  
  // Show performance metrics
  if (results.performance && options.verbose) {
    console.log(`\n⚡ Performance Metrics:`);
    console.log(`   Files per second: ${results.performance.filesPerSecond}`);
    console.log(`   Packages per second: ${results.performance.packagesPerSecond}`);
    console.log(`   Memory usage: ${results.performance.memoryUsage.toFixed(2)}MB`);
    console.log(`   CPU usage: ${results.performance.cpuUsage.toFixed(2)}%`);
    console.log(`   Duration: ${results.performance.duration}ms`);
  }
  
  const scanTarget = results.packagesScanned && results.packagesScanned > 0 ? 'package' : 'directory';
  const scanCount = results.packagesScanned || 1;
  console.log(`\n📊 Scanned ${scanCount} ${scanTarget}(s)${results.filesScanned ? `, ${results.filesScanned} file(s)` : ''} in ${results.performance?.duration || 0}ms`);
}