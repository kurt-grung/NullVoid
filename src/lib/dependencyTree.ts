import { Threat, ThreatType } from '../types/core';
import { ScanOptions } from '../types/core';
import * as fs from 'fs';
import * as path from 'path';
import { scanPackage } from './packageAnalysis';
import { getNpmGlobalPrefix } from './packageAnalysis';

/**
 * Detect circular dependencies in a dependency tree
 */
export function detectCircularDependencies(tree: Record<string, any>): Threat[] {
  const threats: Threat[] = [];
  const visited = new Set<string>();
  const recursionStack = new Set<string>();

  // Whitelist of well-known packages with harmless circular dependencies
  const safeCircularDependencyPackages = new Set([
    'async-mutex', 'axios', 'commander', '@typescript-eslint/parser', 
    'ts-jest', 'ts-node', 'typescript', 'lodash', 'moment', 'react',
    'vue', 'angular', 'express', 'koa', 'webpack', 'babel', 'jest'
  ]);

  function hasCycle(node: string): boolean {
    if (recursionStack.has(node)) {
      return true;
    }
    
    if (visited.has(node)) {
      return false;
    }

    visited.add(node);
    recursionStack.add(node);

    const dependencies = tree[node]?.dependencies || {};
    for (const dep of Object.keys(dependencies)) {
      if (hasCycle(dep)) {
        return true;
      }
    }

    recursionStack.delete(node);
    return false;
  }

  for (const node of Object.keys(tree)) {
    if (!visited.has(node)) {
      if (hasCycle(node)) {
        // Only flag as threat if it's not a known safe package
        if (!safeCircularDependencyPackages.has(node)) {
          threats.push({
            type: 'CIRCULAR_DEPENDENCY' as ThreatType,
            severity: 'MEDIUM', // Reduced from HIGH to MEDIUM
            package: node,
            message: 'Circular dependency detected',
            details: `Package ${node} has circular dependencies which can cause runtime issues`
          });
        }
      }
    }
  }

  return threats;
}

/**
 * Find package path in various locations
 */
function findPackagePath(packageName: string): string | null {
  const possiblePaths = [];
  
  // 1. Local project node_modules (highest priority)
  possiblePaths.push(
    path.join(process.cwd(), 'node_modules', packageName),
    path.join(process.cwd(), 'node_modules', packageName, 'package.json')
  );
  
  // 2. Get npm global prefix and use it
  try {
    const npmGlobalPrefix = getNpmGlobalPrefix();
    if (npmGlobalPrefix && npmGlobalPrefix !== 'undefined') {
      possiblePaths.push(
        path.join(npmGlobalPrefix, 'lib', 'node_modules', packageName),
        path.join(npmGlobalPrefix, 'lib', 'node_modules', packageName, 'package.json')
      );
    }
  } catch (error) {
    // Fallback to common locations if npm config fails
    if (process.env['HOME']) {
      possiblePaths.push(
        path.join(process.env['HOME'], '.npm-global', 'lib', 'node_modules', packageName),
        path.join(process.env['HOME'], '.npm-global', 'lib', 'node_modules', packageName, 'package.json')
      );
    }
  }
  
  // 3. Check npm cache locations
  if (process.env['HOME']) {
    possiblePaths.push(
      path.join(process.env['HOME'], '.npm', 'packages', packageName),
      path.join(process.env['HOME'], '.npm', 'packages', packageName, 'package.json')
    );
  }

  // Find the first existing path
  for (const possiblePath of possiblePaths) {
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    }
  }

  return null;
}

/**
 * Build and scan dependency tree (sequential version)
 */
export async function buildAndScanDependencyTree(
  dependencies: Record<string, string>,
  maxDepth: number,
  options: ScanOptions
): Promise<{ threats: Threat[]; tree: Record<string, any>; packagesScanned: number }> {
  const threats: Threat[] = [];
  const tree: Record<string, any> = {};
  const scannedPackages = new Set<string>();
  let packagesScanned = 0;

  // Process dependencies level by level
  let currentLevel = Object.entries(dependencies).map(([name, version]) => {
    const packagePath = findPackagePath(name);
    return { name, version, packagePath };
  });

  let depth = 0;

  while (currentLevel.length > 0 && depth < maxDepth) {
    const nextLevel: Array<{ name: string; version: string; packagePath: string | null }> = [];

    for (const { name, version, packagePath } of currentLevel) {
      if (scannedPackages.has(name)) {
        continue;
      }

      scannedPackages.add(name);
      packagesScanned++;

      // Add to tree
      tree[name] = {
        version,
        packagePath,
        dependencies: {}
      };

      try {
        // Scan the package
        const packageThreats = await scanPackage(name, version, options, packagePath || undefined);
        threats.push(...packageThreats);

        // Try to get package.json to find dependencies
        let packageJsonPath = packagePath;
        if (packageJsonPath && fs.existsSync(packageJsonPath)) {
          if (fs.statSync(packageJsonPath).isDirectory()) {
            packageJsonPath = path.join(packageJsonPath, 'package.json');
          }
        } else {
          // Try to find package.json in various locations
          const possiblePaths = [
            path.join(process.cwd(), 'node_modules', name, 'package.json'),
            path.join(getNpmGlobalPrefix(), 'lib', 'node_modules', name, 'package.json')
          ];

          for (const possiblePath of possiblePaths) {
            if (fs.existsSync(possiblePath)) {
              packageJsonPath = possiblePath;
              break;
            }
          }
        }

        if (packageJsonPath && fs.existsSync(packageJsonPath)) {
          try {
            const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
            const packageDependencies = {
              ...packageJson.dependencies,
              ...packageJson.devDependencies,
              ...packageJson.peerDependencies
            };

            // Add dependencies to tree
            tree[name].dependencies = packageDependencies;

            // Add to next level for processing
            for (const [depName, depVersion] of Object.entries(packageDependencies)) {
              if (!scannedPackages.has(depName)) {
                nextLevel.push({
                  name: depName,
                  version: depVersion as string,
                  packagePath: findPackagePath(depName)
                });
              }
            }
          } catch {
            if (options.verbose) {
              console.warn(`Warning: Could not parse package.json for ${name}`);
            }
          }
        }
      } catch {
        if (options.verbose) {
          console.warn(`Warning: Could not scan package ${name}`);
        }
      }
    }

    currentLevel = nextLevel;
    depth++;
  }

  // Check for circular dependencies
  const circularThreats = detectCircularDependencies(tree);
  threats.push(...circularThreats);

  return { threats, tree, packagesScanned };
}

/**
 * Build and scan dependency tree (parallel version)
 */
export async function buildAndScanDependencyTreeParallel(
  dependencies: Record<string, string>,
  _maxDepth: number,
  options: ScanOptions,
  _rootPackage: string = 'root',
  parallelConfig: any = {}
): Promise<{ threats: Threat[]; tree: Record<string, any>; packagesScanned: number }> {
  const threats: Threat[] = [];
  const tree: Record<string, any> = {};
  let packagesScanned = 0;
  const scannedPackages = new Set<string>();

  // Convert dependencies to array for parallel processing
  const dependencyArray = Object.entries(dependencies).map(([name, version]) => {
    const packagePath = findPackagePath(name);
    return { name, version, packagePath };
  });

  // Process dependencies in parallel batches
  const batchSize = parallelConfig.batchSize || 5;
  const batches = [];
  
  for (let i = 0; i < dependencyArray.length; i += batchSize) {
    batches.push(dependencyArray.slice(i, i + batchSize));
  }

  for (const batch of batches) {
    const batchPromises = batch.map(async ({ name, version, packagePath }) => {
      if (scannedPackages.has(name)) {
        return { name, threats: [], dependencies: {} };
      }

      scannedPackages.add(name);
      packagesScanned++;

      // Add to tree
      tree[name] = {
        version,
        packagePath,
        dependencies: {}
      };

      try {
        // Scan the package
        const packageThreats = await scanPackage(name, version, options, packagePath || undefined);
        
        // Try to get dependencies
        let packageDependencies = {};
        let packageJsonPath = packagePath;
        
        if (packageJsonPath && fs.existsSync(packageJsonPath)) {
          if (fs.statSync(packageJsonPath).isDirectory()) {
            packageJsonPath = path.join(packageJsonPath, 'package.json');
          }
        } else {
          // Try to find package.json in various locations
          const possiblePaths = [
            path.join(process.cwd(), 'node_modules', name, 'package.json'),
            path.join(getNpmGlobalPrefix(), 'lib', 'node_modules', name, 'package.json')
          ];

          for (const possiblePath of possiblePaths) {
            if (fs.existsSync(possiblePath)) {
              packageJsonPath = possiblePath;
              break;
            }
          }
        }

        if (packageJsonPath && fs.existsSync(packageJsonPath)) {
          try {
            const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
            packageDependencies = {
              ...packageJson.dependencies,
              ...packageJson.devDependencies,
              ...packageJson.peerDependencies
            };
          } catch {
            if (options.verbose) {
              console.warn(`Warning: Could not parse package.json for ${name}`);
            }
          }
        }

        return { name, threats: packageThreats, dependencies: packageDependencies };
      } catch {
        if (options.verbose) {
          console.warn(`Warning: Could not scan package ${name}`);
        }
        return { name, threats: [], dependencies: {} };
      }
    });

    const batchResults = await Promise.all(batchPromises);
    
    for (const { name, threats: packageThreats, dependencies } of batchResults) {
      threats.push(...packageThreats);
      tree[name].dependencies = dependencies;
    }
  }

  // Check for circular dependencies
  const circularThreats = detectCircularDependencies(tree);
  threats.push(...circularThreats);

  return { threats, tree, packagesScanned };
}
