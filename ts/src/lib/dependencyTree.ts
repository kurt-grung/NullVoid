import { Threat, createThreat, DependencyTree } from '../types/core';
import * as fs from 'fs';
import * as path from 'path';

export interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export interface DependencyAnalysisOptions {
  includeDevDependencies?: boolean;
  includePeerDependencies?: boolean;
  includeOptionalDependencies?: boolean;
  maxDepth?: number;
  detectCircular?: boolean;
  analyzeVersions?: boolean;
}

/**
 * Read and parse package.json file
 */
export function readPackageJson(packagePath: string): PackageJson | null {
  try {
    const packageJsonPath = path.join(packagePath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return null;
    }
    
    const content = fs.readFileSync(packageJsonPath, 'utf8');
    return JSON.parse(content) as PackageJson;
  } catch {
    return null;
  }
}

/**
 * Build dependency tree analysis
 */
export function buildDependencyTree(packagePath: string): { tree: DependencyTree; threats: Threat[] } {
  const packageJson = readPackageJson(packagePath);
  if (!packageJson) {
    return {
      tree: { name: 'unknown', version: 'unknown', dependencies: [], devDependencies: [], totalDependencies: 0 },
      threats: [createThreat(
        'DEPENDENCY_CONFUSION',
        'Could not read package.json',
        packagePath,
        'package.json',
        'MEDIUM',
        'Unable to analyze dependencies without package.json',
        { confidence: 0.9 }
      )]
    };
  }
  
  const tree: DependencyTree = {
    name: packageJson.name || 'unknown',
    version: packageJson.version || 'unknown',
    dependencies: [],
    devDependencies: [],
    totalDependencies: 0
  };
  
  const threats: Threat[] = [];
  
  // Count dependencies
  const depCount = Object.keys(packageJson.dependencies || {}).length;
  const devDepCount = Object.keys(packageJson.devDependencies || {}).length;
  tree.totalDependencies = depCount + devDepCount;
  
  // Check for suspicious dependency patterns
  if (packageJson.dependencies) {
    for (const [depName, depVersion] of Object.entries(packageJson.dependencies)) {
      // Check for suspicious package names
      if (depName.includes('malware') || depName.includes('virus') || depName.includes('trojan')) {
        threats.push(createThreat(
          'DEPENDENCY_CONFUSION',
          `Suspicious dependency name: ${depName}`,
          packagePath,
          'package.json',
          'HIGH',
          `Package name '${depName}' contains suspicious keywords`,
          { packageName: depName, version: depVersion, confidence: 0.8 }
        ));
      }
      
      // Check for version ranges that might be too permissive
      if (depVersion.startsWith('*') || depVersion.startsWith('^0.') || depVersion.startsWith('~0.')) {
        threats.push(createThreat(
          'DEPENDENCY_CONFUSION',
          `Potentially unsafe version range for ${depName}: ${depVersion}`,
          packagePath,
          'package.json',
          'MEDIUM',
          `Version range '${depVersion}' may allow unexpected updates`,
          { packageName: depName, version: depVersion, confidence: 0.6 }
        ));
      }
    }
  }
  
  return { tree, threats };
}