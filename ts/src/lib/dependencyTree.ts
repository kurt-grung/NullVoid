import { Threat, createThreat, DependencyTree } from '../types/core';
import { SUPPLY_CHAIN_CONFIG } from './config';
import * as fs from 'fs';
import * as path from 'path';

const NODE_MODULES_DIR = 'node_modules';
const VALID_PACKAGE_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const UNSAFE_VERSION_RANGE_PREFIXES = ['*', '^0.', '~0.'];
const SUSPICIOUS_NAME_KEYWORDS = ['malware', 'virus', 'trojan'];
const MAX_PACKAGE_NAME_LENGTH = 214;
const MAX_VERSION_LENGTH = 64;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_TRAVERSAL_DEPTH = 50;

export interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export interface DependencyAnalysisOptions {
  includeDevDependencies?: boolean | undefined;
  includePeerDependencies?: boolean | undefined;
  includeOptionalDependencies?: boolean | undefined;
  maxDepth?: number | undefined;
  maxNodes?: number | undefined;
  detectCircular?: boolean | undefined;
  analyzeVersions?: boolean | undefined;
}

export interface DependencyTreeStats {
  totalPackages: number;
  maxDepth: number;
  deepDependencies: number;
  resolvedPackages: number;
  unresolvedPackages: number;
  truncated: boolean;
}

interface TraversalFrame {
  dir: string;
  declared: Record<string, string> | undefined;
  depth: number;
  owner: DependencyTree | null;
  target: DependencyTree[];
}

export function readPackageJson(packagePath: string): PackageJson | null {
  try {
    const packageJsonPath = path.join(packagePath, 'package.json');
    const stats = fs.statSync(packageJsonPath, { throwIfNoEntry: false });
    if (!stats?.isFile() || stats.size > MAX_MANIFEST_BYTES) {
      return null;
    }

    const content = fs.readFileSync(packageJsonPath, 'utf8');
    return JSON.parse(content) as PackageJson;
  } catch {
    return null;
  }
}

export function isValidPackageName(name: string): boolean {
  return name.length > 0 && name.length <= MAX_PACKAGE_NAME_LENGTH && VALID_PACKAGE_NAME.test(name);
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function resolveVersion(manifestVersion: string | undefined, declaredRange: string): string {
  if (
    typeof manifestVersion === 'string' &&
    manifestVersion.length > 0 &&
    manifestVersion.length <= MAX_VERSION_LENGTH
  ) {
    return manifestVersion;
  }
  return declaredRange.slice(0, MAX_VERSION_LENGTH);
}

function resolveDependencyDir(fromDir: string, depName: string, rootDir: string): string | null {
  if (!isValidPackageName(depName)) return null;

  const root = path.resolve(rootDir);
  let current = path.resolve(fromDir);

  for (;;) {
    const candidate = path.join(current, NODE_MODULES_DIR, depName);
    if (fs.existsSync(path.join(candidate, 'package.json'))) {
      return candidate;
    }
    if (current === root) return null;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function traverse(
  rootDir: string,
  frames: TraversalFrame[],
  maxDepth: number,
  maxNodes: number
): DependencyTreeStats {
  const depthByPackage = new Map<string, number>();
  const resolvedPackages = new Set<string>();
  const queue = frames;
  let cursor = 0;
  let emittedNodes = 0;
  let maxDepthSeen = 0;
  let truncated = false;

  while (cursor < queue.length) {
    const frame = queue[cursor];
    cursor += 1;
    if (!frame) continue;

    const declared = Object.entries(frame.declared ?? {});
    if (declared.length > 0 && frame.depth > maxDepth) {
      truncated = true;
      continue;
    }

    for (const [name, range] of declared) {
      if (!isValidPackageName(name)) continue;

      if (emittedNodes >= maxNodes) {
        truncated = true;
        break;
      }
      emittedNodes += 1;

      const resolvedDir = resolveDependencyDir(frame.dir, name, rootDir);
      const manifest = resolvedDir ? readPackageJson(resolvedDir) : null;
      const version = resolveVersion(manifest?.version, range);
      const key = `${name}@${version}`;

      maxDepthSeen = Math.max(maxDepthSeen, frame.depth);
      const firstEncounter = !depthByPackage.has(key);
      if (firstEncounter) {
        depthByPackage.set(key, frame.depth);
      }
      if (resolvedDir && manifest) {
        resolvedPackages.add(key);
      }

      const node: DependencyTree = {
        name,
        version,
        dependencies: [],
        devDependencies: [],
        totalDependencies: 0,
      };
      frame.target.push(node);

      if (firstEncounter && resolvedDir && manifest) {
        queue.push({
          dir: resolvedDir,
          declared: manifest.dependencies,
          depth: frame.depth + 1,
          owner: node,
          target: node.dependencies,
        });
      }
    }

    if (frame.owner) {
      frame.owner.totalDependencies = frame.owner.dependencies.length;
    }
  }

  let deepDependencies = 0;
  for (const depth of depthByPackage.values()) {
    if (depth >= SUPPLY_CHAIN_CONFIG.DEEP_DEPENDENCY_DEPTH) {
      deepDependencies += 1;
    }
  }

  return {
    totalPackages: depthByPackage.size,
    maxDepth: maxDepthSeen,
    deepDependencies,
    resolvedPackages: resolvedPackages.size,
    unresolvedPackages: depthByPackage.size - resolvedPackages.size,
    truncated,
  };
}

function analyzeDeclaredDependencies(
  packagePath: string,
  dependencies: Record<string, string>
): Threat[] {
  const threats: Threat[] = [];

  for (const [depName, depVersion] of Object.entries(dependencies)) {
    if (SUSPICIOUS_NAME_KEYWORDS.some((keyword) => depName.includes(keyword))) {
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION',
          `Suspicious dependency name: ${depName}`,
          packagePath,
          'package.json',
          'HIGH',
          `Package name '${depName}' contains suspicious keywords`,
          { packageName: depName, version: depVersion, confidence: 0.8 }
        )
      );
    }

    if (UNSAFE_VERSION_RANGE_PREFIXES.some((prefix) => depVersion.startsWith(prefix))) {
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION',
          `Potentially unsafe version range for ${depName}: ${depVersion}`,
          packagePath,
          'package.json',
          'MEDIUM',
          `Version range '${depVersion}' may allow unexpected updates`,
          { packageName: depName, version: depVersion, confidence: 0.6 }
        )
      );
    }
  }

  return threats;
}

export function buildDependencyTree(
  packagePath: string,
  options: DependencyAnalysisOptions = {}
): {
  tree: DependencyTree;
  threats: Threat[];
  stats: DependencyTreeStats;
} {
  const emptyStats: DependencyTreeStats = {
    totalPackages: 0,
    maxDepth: 0,
    deepDependencies: 0,
    resolvedPackages: 0,
    unresolvedPackages: 0,
    truncated: false,
  };

  const packageJson = readPackageJson(packagePath);
  if (!packageJson) {
    return {
      tree: {
        name: 'unknown',
        version: 'unknown',
        dependencies: [],
        devDependencies: [],
        totalDependencies: 0,
      },
      threats: [
        createThreat(
          'DEPENDENCY_CONFUSION',
          'Could not read package.json',
          packagePath,
          'package.json',
          'MEDIUM',
          'Unable to analyze dependencies without package.json',
          { confidence: 0.9 }
        ),
      ],
      stats: emptyStats,
    };
  }

  const rootDir = path.resolve(packagePath);
  const maxDepth = clamp(options.maxDepth ?? SUPPLY_CHAIN_CONFIG.MAX_DEPTH, 1, MAX_TRAVERSAL_DEPTH);
  const maxNodes = clamp(
    options.maxNodes ?? SUPPLY_CHAIN_CONFIG.MAX_NODES,
    0,
    Number.MAX_SAFE_INTEGER
  );

  const tree: DependencyTree = {
    name: packageJson.name || 'unknown',
    version: packageJson.version || 'unknown',
    dependencies: [],
    devDependencies: [],
    totalDependencies: 0,
  };

  const frames: TraversalFrame[] = [
    {
      dir: rootDir,
      declared: packageJson.dependencies,
      depth: 1,
      owner: null,
      target: tree.dependencies,
    },
  ];
  if (options.includeDevDependencies !== false) {
    frames.push({
      dir: rootDir,
      declared: packageJson.devDependencies,
      depth: 1,
      owner: null,
      target: tree.devDependencies,
    });
  }

  const stats = traverse(rootDir, frames, maxDepth, maxNodes);
  tree.totalDependencies = tree.dependencies.length + tree.devDependencies.length;

  return {
    tree,
    threats: analyzeDeclaredDependencies(packagePath, packageJson.dependencies ?? {}),
    stats,
  };
}
