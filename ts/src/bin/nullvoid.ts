#!/usr/bin/env node

import { program } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import ora from 'ora';
import { scan } from '../scan';
import { ScanOptions, ScanResult } from '../types/core';
import { generateSarifOutput } from '../lib/sarif';
import { detectMalware, filterThreatsBySeverity } from '../lib/detection';
import { DISPLAY_PATTERNS } from '../lib/config';
import colors from '../colors';
import * as packageJson from '../../package.json';

interface CliOptions {
  depth?: number;
  parallel?: boolean;
  workers?: string;
  'include-dev'?: boolean;
  'skip-cache'?: boolean;
  output?: string;
  format?: 'json' | 'sarif' | 'text';
  verbose?: boolean;
  debug?: boolean;
  rules?: string;
  sarif?: string;
  all?: boolean;
}

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
  .action(async (target: string | undefined, options: CliOptions) => {
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
  .action(async (target: string | undefined, options: CliOptions) => {
    await performScan(target, options);
  });

async function performScan(target: string | undefined, options: CliOptions) {
    const spinner = ora('🔍 Scanning ...').start();
    
    try {
      const scanOptions: ScanOptions = {
        depth: options.depth ? parseInt(options.depth.toString()) : 5,
        parallel: options.parallel || false,
        workers: options.workers === 'auto' ? undefined : (options.workers ? parseInt(options.workers) : undefined),
        includeDevDependencies: options['include-dev'] || false,
        skipCache: options['skip-cache'] || false,
        verbose: options.verbose || false,
        debug: options.debug || false,
        all: options.all || false
      };

      // Add optional properties only if they exist
      if (options.output) {
        scanOptions.outputFile = options.output;
      }
      if (options.format) {
        scanOptions.format = options.format;
      }
      if (options.rules) {
        scanOptions.rulesFile = options.rules;
      }
      if (options.sarif) {
        scanOptions.sarifFile = options.sarif;
      }

      // Progress callback to show current file with threat detection
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
          const highSeverityThreats = filterThreatsBySeverity(fileThreats, false);
          
          if (highSeverityThreats.length > 0) {
            hasHighSeverityThreats = true;
            highSeverityThreats.forEach((threat) => {
              if (!threats.includes(threat.type)) {
                threats.push(threat.type);
              }
            });
          }
          
          if (hasHighSeverityThreats) {
            const threatText = threats.join(', ');
            console.log(`📁 ${displayPath} (detected: ${threatText})`);
          } else {
            console.log(`📁 ${displayPath}`);
          }
        } catch {
          // If we can't read the file, just show the relative path
          console.log(`📁 ${displayPath}`);
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

function displayResults(results: ScanResult, options: CliOptions) {
  console.log('\n🔍 NullVoid Scan Results\n');
  
  if (results.threats.length === 0) {
    console.log('✅ No threats detected');
  } else {
    // Sort threats by confidence level (low to high)
    const sortedThreats = results.threats.sort((a, b) => {
      const aConfidence = a.confidence || 0;
      const bConfidence = b.confidence || 0;
      return aConfidence - bConfidence;
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
          // Color code specific parts of the details using centralized patterns
          let coloredDetails = threat.details
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.CRITICAL, colors.red('CRITICAL'))
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.HIGH, colors.yellow('HIGH'))
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.MEDIUM, colors.blue('MEDIUM'))
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.LOW, colors.green('LOW'));
          
          // Extract confidence and threat count for separate line using centralized patterns
          const confidenceMatch = threat.details.match(DISPLAY_PATTERNS.EXTRACTION_PATTERNS.CONFIDENCE);
          const threatsMatch = threat.details.match(DISPLAY_PATTERNS.EXTRACTION_PATTERNS.THREAT_COUNT);
          
          // Remove confidence, threats, and MALICIOUS CODE DETECTED prefix from main details using centralized patterns
          let mainDetails = coloredDetails
            .replace(DISPLAY_PATTERNS.DETAILS_CLEANING_PATTERNS.MALICIOUS_PREFIX, '')
            .replace(DISPLAY_PATTERNS.DETAILS_CLEANING_PATTERNS.CONFIDENCE, '')
            .replace(DISPLAY_PATTERNS.DETAILS_CLEANING_PATTERNS.THREAT_COUNT, '')
            .replace(DISPLAY_PATTERNS.DETAILS_CLEANING_PATTERNS.WHITESPACE, ' ')
            .trim();
          
          console.log(`   ${colors.whiteOnBlack('Details:')} ${mainDetails}`);
          
          // Add confidence and threats on new line
          if (confidenceMatch || threatsMatch) {
            let statsLine = '';
            if (confidenceMatch) {
              statsLine += colors.magenta(confidenceMatch[0]);
            }
            if (threatsMatch) {
              if (statsLine) statsLine += ' ';
              statsLine += colors.red(threatsMatch[0]);
            }
            console.log(`   ${statsLine}`);
          }
        }
        if (threat.filePath) {
          console.log(`   ${colors.blue('File:')} ${colors.blue(threat.filePath)}`);
        }
        if (threat.lineNumber) {
          console.log(`   ${colors.green('Line:')} ${colors.green(threat.lineNumber.toString())}`);
        }
        if (threat.sampleCode) {
          console.log(`   ${colors.cyan('Sample:')} ${colors.cyan(threat.sampleCode)}`);
        }
        console.log('');
      });
    }
  }
  
  // Display scan analysis (merged summary and dependency tree)
  console.log(`\n📊 Scan Analysis:`);
  const totalFiles = results.filesScanned || 0;
  const totalPackages = results.packagesScanned || 0;
  const threatCount = results.threats.length;
  const filesWithThreats = new Set(results.threats.map(t => t.filePath)).size;
  const scanDuration = results.performance?.duration || 0;
  
  console.log(`   Total files scanned: ${totalFiles} files`);
  console.log(`   Total packages scanned: ${totalPackages} packages`);
  console.log(`   Threats detected: ${threatCount} ${threatCount === 1 ? 'threat' : 'threats'}`);
  console.log(`   Scan duration: ${scanDuration}ms`);
  console.log(`   Files with threats: ${filesWithThreats} out of ${totalFiles} files`);
  
  // Add dependency tree information if available
  if (results.dependencyTree || (results.packagesScanned && results.packagesScanned > 0)) {
    console.log(`   Max depth reached: ${results.dependencyTree?.maxDepth || options.depth || 5}`);
    console.log(`   Packages with threats: ${results.dependencyTree?.packagesWithThreats || results.threats.filter(t => t.package).length}`);
    console.log(`   Deep dependencies (depth ≥2): ${results.dependencyTree?.deepDependencies || 0}`);
  }
  
  // Display directory structure for directory scans
  if (results.directoryStructure) {
    console.log(`\n📁 Directory Structure:`);
    console.log(`   ${results.directoryStructure.totalDirectories || results.directoryStructure.directories.length} directories: ${results.directoryStructure.directories.slice(0, 5).join(', ')}${results.directoryStructure.directories.length > 5 ? '...' : ''}`);
    console.log(`   ${results.directoryStructure.totalFiles || results.directoryStructure.files.length} files: ${results.directoryStructure.files.slice(0, 5).join(', ')}${results.directoryStructure.files.length > 5 ? '...' : ''}`);
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