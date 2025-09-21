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
  .argument('[package]', 'Package name to scan (default: scan package.json)')
  .option('-v, --verbose', 'Enable verbose output')
  .option('-o, --output <format>', 'Output format (json, table)', 'table')
  .action(async (packageName, options) => {
    const spinner = ora('Scanning packages...').start();
    
    try {
      const results = await scan(packageName, options);
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
        console.log(chalk.gray(`   Package: ${threat.package}`));
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
  
  console.log(chalk.gray(`\nScanned ${results.packagesScanned > 0 ? results.packagesScanned : 1} ${results.packagesScanned > 0 ? 'package' : 'directory'}(s)${results.filesScanned ? `, ${results.filesScanned} file(s)` : ''} in ${results.duration}ms`));
}
