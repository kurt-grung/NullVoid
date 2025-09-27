#!/usr/bin/env node

import { program } from 'commander';
import colors from '../colors';
import ora from 'ora';
import path from 'path';
import fs from 'fs';
import { scan } from '../scan';
import packageJson from '../package';
import { generateSarifOutput, writeSarifFile } from '../lib/sarif';

// Import secure validation
import { InputValidator, SecurityError, ValidationError } from '../lib/secureErrorHandler';
import { isNullVoidCode, isTestFile } from '../lib/nullvoidDetection';

// Import types
import { ScanOptions, ProgressCallback, Threat } from '../types';

program
  .name('nullvoid')
  .description('Detect and invalidate malicious npm packages before they reach prod')
  .version(packageJson.version);

program
  .command('scan')
  .description('Scan npm packages for malicious behavior')
  .argument('[package]', 'Package name or directory path to scan (default: scan current directory)')
  .option('-v, --verbose', 'Enable verbose output')
  .option('-o, --output <format>', 'Output format (json, table, sarif)', 'table')
  .option('-d, --depth <number>', 'Maximum dependency tree depth to scan', '3')
  .option('--tree', 'Show dependency tree structure in output')
  .option('--parallel', 'Enable parallel scanning for better performance', true)
  .option('--no-parallel', 'Disable parallel scanning')
  .option('--workers <number>', 'Number of parallel workers to use', 'auto')
  .option('--all', 'Show all threats including low/medium severity')
  .option('--sarif-file <path>', 'Write SARIF output to file (requires --output sarif)')
  .action(async (packageName: string | undefined, options: any) => {
    const spinner = ora('🔍 Scanning ...').start();
    
    try {
      // Validate input parameters securely
      let validatedPackageName = packageName;
      if (packageName) {
        try {
          validatedPackageName = InputValidator.validatePackageName(packageName);
        } catch (error: any) {
          if (error instanceof SecurityError) {
            spinner.fail('🚨 Security Error');
            console.error(colors.red('Security Error:'), error.message);
            console.error(colors.red('Details:'), error.message);
            process.exit(1);
          } else if (error instanceof ValidationError) {
            spinner.fail('❌ Validation Error');
            console.error(colors.red('Validation Error:'), error.message);
            process.exit(1);
          }
        }
      }
      
      // Validate scan options
      let validatedOptions;
      try {
        validatedOptions = InputValidator.validateScanOptions(options);
      } catch (error: any) {
        spinner.fail('❌ Invalid Options');
        console.error(colors.red('Invalid Options:'), error.message);
        process.exit(1);
      }
      
      // Parse depth option
      const scanOptions: ScanOptions = {
        ...validatedOptions,
        maxDepth: parseInt(validatedOptions.depth) || 3,
        parallel: validatedOptions.parallel !== false, // Default to true unless explicitly disabled
        workers: validatedOptions.workers === 'auto' ? undefined : parseInt(validatedOptions.workers) || undefined
      };
      
      // Progress callback to show current file with threat detection
      let isFirstFile = true;
      const progressCallback: ProgressCallback = (filePath: string) => {
        // Get relative path from the original scan target directory
        const originalScanTarget = packageName || process.cwd();
        const relativePath = path.relative(originalScanTarget, filePath);
        const displayPath = relativePath || path.basename(filePath);
        
        try {
          // Check if this is NullVoid's own code or test files
          
          // Quick threat check for this file
          const content = fs.readFileSync(filePath, 'utf8');
          const threats: string[] = [];
          let maxSeverity = 'LOW';
          let hasThreats = false;
          
          // Check for obfuscated patterns (HIGH severity)
          if (content.includes('_0x') || content.match(/const\s+[a-z]\d+\s*=\s*[A-Z]/)) {
            hasThreats = true;
            if (isNullVoidCode(filePath)) {
              if (!threats.includes('security tools')) threats.push('security tools');
              maxSeverity = 'LOW';
            } else if (isTestFile(filePath)) {
              if (!threats.includes('test file')) threats.push('test file');
              maxSeverity = 'LOW';
            } else {
              if (!threats.includes('OBFUSCATED_CODE')) threats.push('OBFUSCATED_CODE');
              maxSeverity = 'HIGH';
            }
          }
          
          // Check for suspicious modules (CRITICAL severity)
          if (content.includes('require(') || content.includes('import ')) {
            const suspiciousModules = ['fs', 'child_process', 'http', 'https', 'net', 'tls', 'crypto', 'os', 'path'];
            const hasSuspiciousModule = suspiciousModules.some(module => 
              content.includes(`require('${module}')`) || 
              content.includes(`require("${module}")`) ||
              content.includes(`import ${module}`) ||
              content.includes(`from '${module}'`) ||
              content.includes(`from "${module}"`)
            );
            
            if (hasSuspiciousModule) {
              hasThreats = true;
              if (isNullVoidCode(filePath)) {
                if (!threats.includes('security tools')) threats.push('security tools');
                maxSeverity = 'LOW';
              } else if (isTestFile(filePath)) {
                if (!threats.includes('test file')) threats.push('test file');
                maxSeverity = 'LOW';
              } else {
                if (!threats.includes('SUSPICIOUS_MODULE')) threats.push('SUSPICIOUS_MODULE');
                maxSeverity = 'CRITICAL';
              }
            }
          }
          
          // Check for malicious code structure (CRITICAL severity)
          if (content.length > 5000 && (content.includes('eval(') || content.includes('Function('))) {
            hasThreats = true;
            if (isNullVoidCode(filePath)) {
              if (!threats.includes('security tools')) threats.push('security tools');
              maxSeverity = 'LOW';
            } else if (isTestFile(filePath)) {
              if (!threats.includes('test file')) threats.push('test file');
              maxSeverity = 'LOW';
            } else {
              if (!threats.includes('MALICIOUS_CODE_STRUCTURE')) threats.push('MALICIOUS_CODE_STRUCTURE');
              maxSeverity = 'CRITICAL';
            }
          }
          
           // Display the file with threat information (exact match to original JavaScript)
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
             
             const prefix = isFirstFile ? '\n' : '';
             console.log(`${prefix}📁 ${displayPath} ${colorFunc(`(detected: ${threatText})`)}`);
             isFirstFile = false;
           } else {
             const prefix = isFirstFile ? '\n' : '';
             console.log(`${prefix}📁 ${displayPath}`);
             isFirstFile = false;
           }
        } catch {
          // If we can't read the file, just show the path
          if (isFirstFile) {
            console.log(`\n📁 ${displayPath}`);
            isFirstFile = false;
          } else {
            console.log(`📁 ${displayPath}`);
          }
        }
      };
      
      // Perform the scan
      const result = await scan(validatedPackageName, scanOptions, progressCallback);
      
      spinner.succeed('✔ ✅ Scan completed');
      
      // Handle SARIF output
      if (scanOptions.output === 'sarif') {
        const sarifOutput = generateSarifOutput(result);
        
        if (options.sarifFile) {
          try {
            await writeSarifFile(options.sarifFile, sarifOutput);
            console.log(`\n📄 SARIF output written to: ${options.sarifFile}`);
          } catch (error: any) {
            console.error(colors.red('Error writing SARIF file:'), error.message);
            process.exit(1);
          }
        } else {
          console.log('\n📄 SARIF Output:');
          console.log(JSON.stringify(sarifOutput, null, 2));
        }
        return;
      }
      
      // Display results
      console.log('\n🔍 NullVoid Scan Results\n');
      
      if (result.threats.length === 0) {
        console.log(colors.green('✅ No threats detected!'));
      } else {
        // Filter threats based on severity if --all is not specified
        const filteredThreats = scanOptions.all ? result.threats : 
          result.threats.filter(threat => 
            threat.severity === 'CRITICAL' || threat.severity === 'HIGH'
          );
        
        if (filteredThreats.length === 0) {
          console.log(colors.green('✅ No high-severity threats detected!'));
          if (!scanOptions.all && result.threats.length > 0) {
            console.log(colors.yellow(`ℹ️  ${result.threats.length} lower-severity threat(s) found. Use --all to see them.`));
          }
        } else {
          console.log(colors.red(`⚠️  ${filteredThreats.length} high-severity threat(s) detected:\n`));
          
          filteredThreats.forEach((threat: Threat, index: number) => {
            // Use raw ANSI color codes like the original JavaScript version
            let severityColor = '';
            if (threat.severity === 'CRITICAL') {
              severityColor = '\x1b[31m'; // Red for CRITICAL
            } else if (threat.severity === 'HIGH') {
              severityColor = '\x1b[31m'; // Red for HIGH
            } else if (threat.severity === 'MEDIUM') {
              severityColor = '\x1b[33m'; // Yellow for MEDIUM
            } else {
              severityColor = '\x1b[34m'; // Blue for LOW
            }
            
            console.log(`${index + 1}. ${threat.type}: ${threat.message}`);
            console.log(`   Package: ${threat.package}`);
            if (threat.lineNumber) {
              console.log(`   Line: ${threat.lineNumber}`);
            }
            if (threat.sampleCode) {
              console.log(`   Sample: ${threat.sampleCode.substring(0, 100)}${threat.sampleCode.length > 100 ? '...' : ''}`);
            }
            console.log(`   Severity: ${severityColor}${threat.severity}\x1b[0m`);
            console.log(`   Details: ${threat.details}`);
            console.log('');
          });
        }
      }
      
      // Show directory structure if requested
      if (options.tree && result.directoryStructure) {
        console.log('\n📁 Directory Structure:');
        console.log(`   ${result.directoryStructure.totalDirectories} directories: ${result.directoryStructure.directories.slice(0, 5).join(', ')}${result.directoryStructure.directories.length > 5 ? '...' : ''}`);
        console.log(`   ${result.directoryStructure.totalFiles} files: ${result.directoryStructure.files.slice(0, 5).join(', ')}${result.directoryStructure.files.length > 5 ? '...' : ''}`);
      }
      
      // Show dependency tree analysis if available
      if (result.packagesScanned > 0) {
        console.log('\n📊 Dependency Tree Analysis:');
        console.log(`   Total packages scanned: ${result.packagesScanned}`);
        console.log(`   Max depth reached: ${scanOptions.maxDepth}`);
        console.log(`   Packages with threats: ${result.threats.filter((t: Threat) => t.package.includes('node_modules')).length}`);
      }
      
      // Show performance metrics
      console.log(`\n📊 Scanned ${result.directoryStructure?.totalDirectories || 0} directory(s), ${result.filesScanned} file(s) in ${result.performance.scanTime}ms`);
      
      // Exit with error code if high-severity threats found
      const highSeverityThreats = result.threats.filter((threat: Threat) => 
        threat.severity === 'CRITICAL' || threat.severity === 'HIGH'
      );
      
      if (highSeverityThreats.length > 0) {
        process.exit(1);
      }
      
    } catch (error: any) {
      spinner.fail('❌ Scan failed');
      console.error(colors.red('Error:'), error.message);
      if (options.verbose) {
        console.error(colors.red('Stack trace:'), error.stack);
      }
      process.exit(1);
    }
  });

program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(`NullVoid v${packageJson.version}`);
    console.log(`Node.js ${process.version}`);
    console.log(`Platform: ${process.platform}`);
  });

program
  .command('info')
  .description('Show detailed information about NullVoid')
  .action(() => {
    console.log(colors.cyan('🔍 NullVoid - Malicious Package Detection'));
    console.log(`Version: ${packageJson.version}`);
    console.log(`Description: ${packageJson.description}`);
    console.log(`License: ${packageJson.license}`);
    console.log(`Repository: ${packageJson.repository?.url || 'N/A'}`);
    console.log(`Homepage: ${packageJson.homepage || 'N/A'}`);
    console.log('\n📊 Features:');
    console.log('  • Static analysis for malicious code patterns');
    console.log('  • Sandbox execution for suspicious code');
    console.log('  • Dependency tree scanning');
    console.log('  • Wallet hijacking detection');
    console.log('  • Network manipulation detection');
    console.log('  • Obfuscation detection');
    console.log('  • SARIF output support');
    console.log('  • Parallel processing');
    console.log('  • CI/CD integration');
  });

// Parse command line arguments
program.parse();
