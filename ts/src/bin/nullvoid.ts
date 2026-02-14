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
import { getIoCManager } from '../lib/iocIntegration';
import { getCacheAnalytics } from '../lib/cache/cacheAnalytics';
import { getConnectionPool } from '../lib/network/connectionPool';
import { checkAllRegistriesHealth } from '../lib/registries';
import { computePackageCID, verifyPackageCID, publishToIPFS } from '../lib/ipfsVerification';
import { PHASE4_IPFS_CONFIG } from '../lib/config';
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
  'ioc-providers'?: string;
  'cache-stats'?: boolean;
  cacheStats?: boolean;
  'enable-redis'?: boolean;
  'network-stats'?: boolean;
  networkStats?: boolean;
  'no-ioc'?: boolean;
}

program.name('nullvoid').description('NullVoid Security Scanner').version(packageJson.version);

// Phase 4: Sign package (compute CID, optional pin)
program
  .command('sign-package <path>')
  .description('Compute IPFS CID for a package tarball (Phase 4)')
  .option('--pin', 'Pin to IPFS (requires PIN_SERVICE_URL and PIN_SERVICE_TOKEN)')
  .option('-o, --output <file>', 'Write verification record JSON to file')
  .option('--update-package-json <file>', 'Write nullvoid.verification.cid into package.json')
  .action(
    async (
      pathArg: string,
      options: { pin?: boolean; output?: string; updatePackageJson?: string }
    ) => {
      try {
        const resolved = path.resolve(pathArg);
        if (!fs.existsSync(resolved)) {
          console.error(colors.red('Error:'), `Path not found: ${resolved}`);
          process.exit(1);
        }
        const stat = fs.statSync(resolved);
        const isTarball = resolved.endsWith('.tgz') || resolved.endsWith('.tar.gz');
        let tarballPath = resolved;
        if (stat.isDirectory() && !isTarball) {
          console.error(
            colors.red('Error:'),
            'Path must be a .tgz tarball file. Run "npm pack" first.'
          );
          process.exit(1);
        }
        const spinner = ora('Computing CID...').start();
        const { cid, algorithm } = await computePackageCID(tarballPath);
        spinner.succeed(`CID: ${cid}`);

        let pinned = false;
        if (
          options.pin &&
          PHASE4_IPFS_CONFIG.PIN_SERVICE_URL &&
          PHASE4_IPFS_CONFIG.PIN_SERVICE_TOKEN
        ) {
          const pinSpinner = ora('Pinning to IPFS...').start();
          const pinResult = await publishToIPFS(tarballPath, {
            PIN_SERVICE_URL: PHASE4_IPFS_CONFIG.PIN_SERVICE_URL,
            PIN_SERVICE_TOKEN: PHASE4_IPFS_CONFIG.PIN_SERVICE_TOKEN,
          });
          if (pinResult.pinned) {
            pinSpinner.succeed('Pinned to IPFS');
            pinned = true;
          } else {
            pinSpinner.fail(pinResult.error || 'Pin failed');
          }
        }

        const record = {
          packageName: path.basename(tarballPath, '.tgz').replace(/\.tar\.gz$/, ''),
          version: undefined as string | undefined,
          cid,
          algorithm,
          timestamp: new Date().toISOString(),
          pinned,
        };
        console.log(JSON.stringify(record, null, 2));

        if (options.output) {
          fs.writeFileSync(options.output, JSON.stringify(record, null, 2));
          console.log(colors.green(`Verification record written to ${options.output}`));
        }
        if (options.updatePackageJson) {
          const pkgPath = path.resolve(options.updatePackageJson);
          if (fs.existsSync(pkgPath)) {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
            if (!pkg.nullvoid) pkg.nullvoid = {};
            pkg.nullvoid.verification = { cid, algorithm, timestamp: record.timestamp };
            fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
            console.log(colors.green(`Updated nullvoid.verification in ${pkgPath}`));
          } else {
            console.error(colors.red('Error:'), `package.json not found: ${pkgPath}`);
            process.exit(1);
          }
        }
        process.exit(0);
      } catch (error) {
        console.error(colors.red('Error:'), (error as Error).message);
        process.exit(1);
      }
    }
  );

// Phase 4: Verify package (compare CID)
program
  .command('verify-package <spec>')
  .description(
    'Verify package integrity against CID (Phase 4). Use <name>@<version> or path to .tgz. CID from --cid or package nullvoid.verification'
  )
  .option('--cid <cid>', 'Expected CID (overrides nullvoid.verification from package)')
  .option('-j, --json', 'Output as JSON')
  .action(async (spec: string, options: { cid?: string; json?: boolean }) => {
    try {
      let expectedCID = options.cid;
      let tarballPath: string;

      const resolvedSpec = path.resolve(spec);
      const isLocalTarball =
        fs.existsSync(resolvedSpec) &&
        (resolvedSpec.endsWith('.tgz') || resolvedSpec.endsWith('.tar.gz'));

      if (isLocalTarball) {
        tarballPath = resolvedSpec;
        if (!expectedCID) {
          try {
            const tar = (await import('tar')).default;
            const tmpDir = (await import('os')).default.tmpdir();
            const extractDir = path.join(tmpDir, `nullvoid-verify-extract-${Date.now()}`);
            fs.mkdirSync(extractDir, { recursive: true });
            await tar.extract({ file: resolvedSpec, cwd: extractDir });
            const entries = fs.readdirSync(extractDir);
            const pkgDir = entries.find((e) => fs.statSync(path.join(extractDir, e)).isDirectory());
            const pkgPath = pkgDir
              ? path.join(extractDir, pkgDir, 'package.json')
              : path.join(extractDir, 'package.json');
            if (fs.existsSync(pkgPath)) {
              const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
              const nv = pkg.nullvoid?.verification;
              expectedCID = typeof nv === 'string' ? nv : nv?.cid;
            }
            fs.rmSync(extractDir, { recursive: true, force: true });
          } catch {
            /* ignore */
          }
        }
        if (!expectedCID) {
          console.error(
            colors.red('Error:'),
            '--cid <cid> is required for local tarball (no nullvoid.verification in package.json)'
          );
          process.exit(1);
        }
      } else {
        const match = spec.match(/^(.+?)@(.+)$/);
        const packageName: string = match && match[1] ? match[1] : spec;
        const version: string = match && match[2] ? match[2] : 'latest';

        const spinner = ora('Fetching package from npm...').start();
        const axios = (await import('axios')).default;
        const metaRes = await axios.get(
          `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
          { timeout: 10000 }
        );
        const data = metaRes.data as {
          versions?: Record<
            string,
            { dist?: { tarball?: string }; nullvoid?: { verification?: string | { cid?: string } } }
          >;
          'dist-tags'?: { latest?: string };
        };
        let versionData = data.versions?.[version];
        if (!versionData && version === 'latest') {
          const latest = data['dist-tags']?.latest;
          versionData = latest ? data.versions?.[latest] : undefined;
        }
        if (!versionData) {
          spinner.fail(`Version ${version} not found`);
          process.exit(1);
        }
        if (!expectedCID) {
          const nv = versionData.nullvoid?.verification;
          expectedCID = typeof nv === 'string' ? nv : nv?.cid;
        }
        if (!expectedCID) {
          spinner.fail('No CID found. Use --cid or add nullvoid.verification to package.json');
          process.exit(1);
        }
        const tarballUrl = versionData.dist?.tarball;
        if (!tarballUrl) {
          spinner.fail('No tarball URL');
          process.exit(1);
        }
        const tarballRes = await axios.get(tarballUrl, {
          responseType: 'arraybuffer',
          timeout: 60000,
        });
        const tmpDir = (await import('os')).default.tmpdir();
        tarballPath = path.join(tmpDir, `nullvoid-verify-${Date.now()}.tgz`);
        fs.writeFileSync(tarballPath, tarballRes.data);
        spinner.succeed('Downloaded');
      }

      let result: { cid: string; algorithm: string; verified: boolean };
      try {
        result = await verifyPackageCID(tarballPath, expectedCID!);
      } finally {
        const tmpDir = (await import('os')).default.tmpdir();
        if (tarballPath.startsWith(tmpDir) && fs.existsSync(tarballPath)) {
          try {
            fs.unlinkSync(tarballPath);
          } catch {
            /* ignore cleanup errors */
          }
        }
      }

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.verified) {
          console.log(colors.green('✓ Verified:'), result.cid);
        } else {
          console.log(colors.red('✗ Mismatch:'), `Expected ${expectedCID}, got ${result.cid}`);
          process.exit(1);
        }
      }
      process.exit(result.verified ? 0 : 1);
    } catch (error) {
      console.error(colors.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// Phase 2: Registry health command (must be before default to match "nullvoid registry-health")
program
  .command('registry-health')
  .description('Check health and availability of configured package registries (Phase 2)')
  .option('-j, --json', 'Output as JSON')
  .option('-t, --timeout <ms>', 'Health check timeout in ms', '5000')
  .action(async function (this: { opts: () => { json?: boolean; timeout?: string } }) {
    const options = this.opts();
    try {
      const timeout = parseInt(options.timeout ?? '5000', 10) || 5000;
      const results = await checkAllRegistriesHealth({ timeout });
      const outputJson = options.json === true;
      if (outputJson) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log(colors.bold('\n📡 Registry Health\n'));
        results.forEach((r) => {
          const status = r.ok ? colors.green('✓') : colors.red('✗');
          const latency = r.latencyMs != null ? ` ${r.latencyMs}ms` : '';
          const extra =
            r.statusCode != null ? ` (${r.statusCode})` : r.error ? ` (${r.error})` : '';
          console.log(`  ${status} ${r.registryName}${latency}${extra}`);
        });
        console.log('');
      }
      process.exit(0);
    } catch (error) {
      console.error(colors.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

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
  .option(
    '--ioc-providers <providers>',
    'Comma-separated list of IoC providers to use (snyk,npm,ghsa,cve)',
    'npm,ghsa,cve'
  )
  .option('--cache-stats', 'Show cache statistics')
  .option('--enable-redis', 'Enable Redis distributed cache (L3)')
  .option('--network-stats', 'Show network performance metrics')
  .option('--no-ioc', 'Disable IoC provider queries')
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
  .option(
    '--ioc-providers <providers>',
    'Comma-separated list of IoC providers to use (snyk,npm,ghsa,cve)',
    'npm,ghsa,cve'
  )
  .option('--cache-stats', 'Show cache statistics')
  .option('--enable-redis', 'Enable Redis distributed cache (L3)')
  .option('--network-stats', 'Show network performance metrics')
  .option('--no-ioc', 'Disable IoC provider queries')
  .action(async (target: string | undefined, options: CliOptions) => {
    await performScan(target, options);
  });

async function performScan(target: string | undefined, options: CliOptions) {
  const spinner = ora('🔍 Scanning ...').start();

  try {
    const scanOptions: ScanOptions = {
      depth: options.depth ? parseInt(options.depth.toString()) : 5,
      parallel: options.parallel || false,
      workers:
        options.workers === 'auto'
          ? undefined
          : options.workers
            ? parseInt(options.workers)
            : undefined,
      includeDevDependencies: options['include-dev'] || false,
      skipCache: options['skip-cache'] || false,
      verbose: options.verbose || false,
      debug: options.debug || false,
      all: options.all || false,
      iocEnabled: (options as { ioc?: boolean }).ioc !== false, // Commander stores --no-ioc as options.ioc = false
    };

    // Add optional properties only if they exist
    if (options['ioc-providers']) {
      scanOptions.iocProviders = options['ioc-providers'];
    }

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

    // Progress callback: use stderr when format is json/sarif so stdout is machine-readable
    const progressOut =
      options.format === 'json' || options.format === 'sarif' ? process.stderr : process.stdout;
    const progressCallback = (progress: {
      current: number;
      total: number;
      message: string;
      packageName?: string;
    }) => {
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
          progressOut.write(`📁 ${displayPath} (detected: ${threatText})\n`);
        } else {
          progressOut.write(`📁 ${displayPath}\n`);
        }
      } catch {
        // If we can't read the file, just show the relative path
        progressOut.write(`📁 ${displayPath}\n`);
      }
    };

    const result = await scan(target || '.', scanOptions, progressCallback);
    spinner.succeed('✅ Scan completed');

    // When format is json and no output file, print JSON only to stdout (machine-readable)
    if (options.format === 'json' && !options.output) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    // Display results
    displayResults(result, options);

    // Display cache statistics if requested (Commander exposes --cache-stats as cacheStats)
    if (options['cache-stats'] ?? options.cacheStats) {
      try {
        const ioCManager = getIoCManager();
        const cacheStats = ioCManager.getCacheStats();
        const cacheAnalytics = getCacheAnalytics();
        // IoC may use LRU (CacheStats) or MultiLayerCache (MultiLayerCacheStats)
        const statsForSummary =
          'layers' in cacheStats
            ? cacheStats
            : {
                layers: {
                  L1: {
                    layer: 'L1' as const,
                    size: cacheStats.size,
                    maxSize: cacheStats.maxSize,
                    hits: cacheStats.hits,
                    misses: cacheStats.misses,
                    evictions: cacheStats.evictions ?? 0,
                    hitRate: cacheStats.hitRate,
                    missRate: cacheStats.missRate,
                    utilization: cacheStats.maxSize ? cacheStats.size / cacheStats.maxSize : 0,
                  },
                  L2: {
                    layer: 'L2' as const,
                    size: 0,
                    maxSize: 0,
                    hits: 0,
                    misses: 0,
                    evictions: 0,
                    hitRate: 0,
                    missRate: 0,
                    utilization: 0,
                  },
                  L3: {
                    layer: 'L3' as const,
                    size: 0,
                    maxSize: 0,
                    hits: 0,
                    misses: 0,
                    evictions: 0,
                    hitRate: 0,
                    missRate: 0,
                    utilization: 0,
                  },
                },
                totalHits: cacheStats.hits,
                totalMisses: cacheStats.misses,
                overallHitRate: cacheStats.hitRate,
                warming: false,
              };
        const multiLayerStats = cacheAnalytics.getSummary(statsForSummary);

        console.log('\n📊 Cache Statistics:');
        console.log(`   L1 (Memory) Cache:`);
        const l1Stats = multiLayerStats.layers['L1'];
        if (l1Stats) {
          console.log(`     Hit Rate: ${(l1Stats.hitRate * 100).toFixed(2)}%`);
          console.log(`     Utilization: ${(l1Stats.utilization * 100).toFixed(2)}%`);
          console.log(`     Size: ${l1Stats.size} items`);
        }
        if (multiLayerStats.recommendations.length > 0) {
          console.log(`   Recommendations:`);
          multiLayerStats.recommendations.forEach((rec) => console.log(`     - ${rec}`));
        }
      } catch (error) {
        if (options.verbose) {
          console.log(`   Cache stats unavailable: ${(error as Error).message}`);
        }
      }
    }

    // Display network statistics if requested (Commander exposes --network-stats as networkStats)
    if (options['network-stats'] ?? options.networkStats) {
      try {
        const connectionPool = getConnectionPool();
        const poolStats = connectionPool.getStats();

        console.log('\n🌐 Network Statistics:');
        console.log(`   Active Connections: ${poolStats.activeConnections}`);
        console.log(`   Idle Connections: ${poolStats.idleConnections}`);
        console.log(`   Total Connections: ${poolStats.totalConnections}`);
        console.log(`   Connection Errors: ${poolStats.errors}`);
        console.log(`   Connection Timeouts: ${poolStats.timeouts}`);
      } catch (error) {
        if (options.verbose) {
          console.log(`   Network stats unavailable: ${(error as Error).message}`);
        }
      }
    }

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
    // Sort threats by severity (descending: CRITICAL > HIGH > MEDIUM > LOW)
    // Most critical threats will appear at the bottom
    const severityOrder: Record<string, number> = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      INFO: 0,
    };

    const sortedThreats = results.threats.sort((a, b) => {
      const aSeverity = severityOrder[a.severity] || 0;
      const bSeverity = severityOrder[b.severity] || 0;

      // Primary sort: by severity (ascending, so CRITICAL appears last)
      if (aSeverity !== bSeverity) {
        return aSeverity - bSeverity;
      }

      // Secondary sort: by confidence (higher confidence first within same severity)
      const aConfidence = a.confidence || 0;
      const bConfidence = b.confidence || 0;
      return bConfidence - aConfidence;
    });

    // Filter to only show HIGH and above severity (unless --all flag is used)
    const showAllThreats = options.all;
    let highSeverityThreats = showAllThreats
      ? sortedThreats
      : sortedThreats.filter(
          (threat) => threat.severity === 'HIGH' || threat.severity === 'CRITICAL'
        );

    // Ensure HIGH threats appear before CRITICAL threats (HIGH=3, CRITICAL=4)
    // Re-sort the filtered list to guarantee correct order
    highSeverityThreats = highSeverityThreats.sort((a, b) => {
      const aSeverity = severityOrder[a.severity] || 0;
      const bSeverity = severityOrder[b.severity] || 0;
      if (aSeverity !== bSeverity) {
        return aSeverity - bSeverity; // HIGH (3) before CRITICAL (4)
      }
      // Secondary sort by confidence
      const aConfidence = a.confidence || 0;
      const bConfidence = b.confidence || 0;
      return bConfidence - aConfidence;
    });

    if (highSeverityThreats.length === 0) {
      console.log('✅ No high-severity threats detected');
      if (!showAllThreats) {
        console.log(
          `ℹ️  ${results.threats.length - highSeverityThreats.length} low/medium severity threats were filtered out`
        );
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
        console.log(
          `${severityColor}${index + 1}. ${threat.type} (${threat.severity})${resetColor}`
        );
        console.log(`   ${threat.message}`);
        if (threat.details) {
          // Color code specific parts of the details using centralized patterns
          let coloredDetails = threat.details
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.CRITICAL, colors.red('CRITICAL'))
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.HIGH, colors.yellow('HIGH'))
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.MEDIUM, colors.blue('MEDIUM'))
            .replace(DISPLAY_PATTERNS.SEVERITY_PATTERNS.LOW, colors.green('LOW'));

          // Extract confidence and threat count for separate line using centralized patterns
          const confidenceMatch = threat.details.match(
            DISPLAY_PATTERNS.EXTRACTION_PATTERNS.CONFIDENCE
          );
          const threatsMatch = threat.details.match(
            DISPLAY_PATTERNS.EXTRACTION_PATTERNS.THREAT_COUNT
          );

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
  const filesWithThreats = new Set(results.threats.map((t) => t.filePath)).size;
  const scanDuration = results.performance?.duration || 0;

  console.log(`   Total files scanned: ${totalFiles} files`);
  console.log(`   Total packages scanned: ${totalPackages} packages`);
  console.log(`   Threats detected: ${threatCount} ${threatCount === 1 ? 'threat' : 'threats'}`);
  console.log(`   Scan duration: ${scanDuration}ms`);
  console.log(`   Files with threats: ${filesWithThreats} out of ${totalFiles} files`);

  // Add dependency tree information if available
  if (results.dependencyTree || (results.packagesScanned && results.packagesScanned > 0)) {
    console.log(`   Max depth reached: ${results.dependencyTree?.maxDepth || options.depth || 5}`);
    console.log(
      `   Packages with threats: ${results.dependencyTree?.packagesWithThreats || results.threats.filter((t) => t.package).length}`
    );
    console.log(
      `   Deep dependencies (depth ≥2): ${results.dependencyTree?.deepDependencies || 0}`
    );
  }

  // Display directory structure for directory scans
  if (results.directoryStructure) {
    console.log(`\n📁 Directory Structure:`);
    console.log(
      `   ${results.directoryStructure.totalDirectories || results.directoryStructure.directories.length} directories: ${results.directoryStructure.directories.slice(0, 5).join(', ')}${results.directoryStructure.directories.length > 5 ? '...' : ''}`
    );
    console.log(
      `   ${results.directoryStructure.totalFiles || results.directoryStructure.files.length} files: ${results.directoryStructure.files.slice(0, 5).join(', ')}${results.directoryStructure.files.length > 5 ? '...' : ''}`
    );
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

  const scanTarget =
    results.packagesScanned && results.packagesScanned > 0 ? 'package' : 'directory';
  const scanCount = results.packagesScanned || 1;
  console.log(
    `\n📊 Scanned ${scanCount} ${scanTarget}(s)${results.filesScanned ? `, ${results.filesScanned} file(s)` : ''} in ${results.performance?.duration || 0}ms`
  );
}
