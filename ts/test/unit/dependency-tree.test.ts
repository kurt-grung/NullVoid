import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { buildDependencyTree, isValidPackageName } from '../../src/lib/dependencyTree';
import { buildSupplyChainGraph } from '../../src/lib/supplyChainGraph';
import type { DependencyTree, Threat } from '../../src/types/core';

let rootDir: string;

function writePackage(
  dir: string,
  manifest: { name: string; version: string; dependencies?: Record<string, string> }
): void {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest));
}

function installed(name: string): string {
  return path.join(rootDir, 'node_modules', name);
}

function findNode(nodes: DependencyTree[], name: string): DependencyTree | undefined {
  for (const node of nodes) {
    if (node.name === name) return node;
    const nested = findNode(node.dependencies, name);
    if (nested) return nested;
  }
  return undefined;
}

beforeEach(() => {
  rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nullvoid-deptree-'));
});

afterEach(() => {
  fs.rmSync(rootDir, { recursive: true, force: true });
});

describe('buildDependencyTree', () => {
  it('resolves transitive dependencies from node_modules', () => {
    writePackage(rootDir, {
      name: 'app',
      version: '1.0.0',
      dependencies: { direct: '^1.0.0' },
    });
    writePackage(installed('direct'), {
      name: 'direct',
      version: '1.2.0',
      dependencies: { nested: '^2.0.0' },
    });
    writePackage(installed('nested'), { name: 'nested', version: '2.1.0' });

    const { tree, stats } = buildDependencyTree(rootDir);

    const direct = tree.dependencies.find((d) => d.name === 'direct');
    expect(direct?.version).toBe('1.2.0');
    expect(direct?.dependencies.map((d) => d.name)).toEqual(['nested']);
    expect(stats.totalPackages).toBe(2);
    expect(stats.maxDepth).toBe(2);
    expect(stats.deepDependencies).toBe(1);
    expect(stats.unresolvedPackages).toBe(0);
  });

  it('resolves scoped packages', () => {
    writePackage(rootDir, {
      name: 'app',
      version: '1.0.0',
      dependencies: { '@scope/pkg': '^1.0.0' },
    });
    writePackage(installed('@scope/pkg'), { name: '@scope/pkg', version: '3.0.0' });

    const { tree } = buildDependencyTree(rootDir);

    expect(tree.dependencies[0]?.name).toBe('@scope/pkg');
    expect(tree.dependencies[0]?.version).toBe('3.0.0');
  });

  it('terminates on circular dependencies', () => {
    writePackage(rootDir, { name: 'app', version: '1.0.0', dependencies: { a: '^1.0.0' } });
    writePackage(installed('a'), { name: 'a', version: '1.0.0', dependencies: { b: '^1.0.0' } });
    writePackage(installed('b'), { name: 'b', version: '1.0.0', dependencies: { a: '^1.0.0' } });

    const { tree, stats } = buildDependencyTree(rootDir);

    const b = findNode(tree.dependencies, 'b');
    expect(b?.dependencies.find((d) => d.name === 'a')?.dependencies).toEqual([]);
    expect(stats.totalPackages).toBe(2);
  });

  it('stops descending past maxDepth', () => {
    writePackage(rootDir, { name: 'app', version: '1.0.0', dependencies: { a: '^1.0.0' } });
    writePackage(installed('a'), { name: 'a', version: '1.0.0', dependencies: { b: '^1.0.0' } });
    writePackage(installed('b'), { name: 'b', version: '1.0.0', dependencies: { c: '^1.0.0' } });
    writePackage(installed('c'), { name: 'c', version: '1.0.0' });

    const { tree, stats } = buildDependencyTree(rootDir, { maxDepth: 2 });

    expect(findNode(tree.dependencies, 'b')).toBeDefined();
    expect(findNode(tree.dependencies, 'c')).toBeUndefined();
    expect(stats.truncated).toBe(true);
    expect(stats.maxDepth).toBe(2);
  });

  it('stops emitting nodes past maxNodes', () => {
    writePackage(rootDir, {
      name: 'app',
      version: '1.0.0',
      dependencies: { a: '^1.0.0', b: '^1.0.0', c: '^1.0.0' },
    });

    const { tree, stats } = buildDependencyTree(rootDir, { maxNodes: 2 });

    expect(tree.dependencies).toHaveLength(2);
    expect(stats.truncated).toBe(true);
  });

  it('records declared dependencies that are not installed', () => {
    writePackage(rootDir, { name: 'app', version: '1.0.0', dependencies: { ghost: '^1.0.0' } });

    const { tree, stats } = buildDependencyTree(rootDir);

    expect(tree.dependencies[0]?.version).toBe('^1.0.0');
    expect(stats.unresolvedPackages).toBe(1);
    expect(stats.resolvedPackages).toBe(0);
  });

  it('ignores dependency names that could escape the scan root', () => {
    writePackage(rootDir, {
      name: 'app',
      version: '1.0.0',
      dependencies: { '../../../etc': '^1.0.0', ok: '^1.0.0' },
    });

    const { tree } = buildDependencyTree(rootDir);

    expect(tree.dependencies.map((d) => d.name)).toEqual(['ok']);
  });

  it('excludes dev dependencies when disabled', () => {
    const manifest = {
      name: 'app',
      version: '1.0.0',
      dependencies: { runtime: '^1.0.0' },
      devDependencies: { tooling: '^1.0.0' },
    };
    fs.mkdirSync(rootDir, { recursive: true });
    fs.writeFileSync(path.join(rootDir, 'package.json'), JSON.stringify(manifest));

    const included = buildDependencyTree(rootDir);
    expect(included.tree.devDependencies.map((d) => d.name)).toEqual(['tooling']);

    const excluded = buildDependencyTree(rootDir, { includeDevDependencies: false });
    expect(excluded.tree.devDependencies).toEqual([]);
  });

  it('reports empty stats when package.json is missing', () => {
    const { tree, threats, stats } = buildDependencyTree(rootDir);

    expect(tree.name).toBe('unknown');
    expect(threats).toHaveLength(1);
    expect(stats.totalPackages).toBe(0);
    expect(stats.maxDepth).toBe(0);
  });

  it('propagates risk from a transitive dependency into the built graph', () => {
    writePackage(rootDir, { name: 'app', version: '1.0.0', dependencies: { direct: '^1.0.0' } });
    writePackage(installed('direct'), {
      name: 'direct',
      version: '1.0.0',
      dependencies: { nested: '^1.0.0' },
    });
    writePackage(installed('nested'), { name: 'nested', version: '1.0.0' });

    const { tree } = buildDependencyTree(rootDir);
    const threats: Threat[] = [
      {
        type: 'MALICIOUS_CODE',
        message: 'malicious postinstall',
        filePath: path.join(rootDir, 'node_modules', 'nested', 'index.js'),
        filename: 'index.js',
        severity: 'CRITICAL',
        details: '',
        confidence: 0.95,
      },
    ];

    const graph = buildSupplyChainGraph(tree, threats);
    const direct = graph.root.children[0];
    const nested = direct?.children[0];

    expect(nested?.name).toBe('nested');
    expect(nested?.riskScore).toBeGreaterThan(0);
    expect(direct?.riskScore).toBe(0);
    expect(direct?.inheritedRisk).toBeGreaterThan(0);
    expect(graph.root.inheritedRisk).toBeGreaterThan(0);
    expect(graph.impactedPackages).toEqual(
      expect.arrayContaining(['nested@1.0.0', 'direct@1.0.0', 'app@1.0.0'])
    );
    expect(graph.packagesWithThreats).toBe(1);
  });
});

describe('isValidPackageName', () => {
  it('accepts npm package names', () => {
    expect(isValidPackageName('lodash')).toBe(true);
    expect(isValidPackageName('@scope/pkg')).toBe(true);
    expect(isValidPackageName('some.pkg-name_2')).toBe(true);
  });

  it('rejects traversal and separator abuse', () => {
    expect(isValidPackageName('../evil')).toBe(false);
    expect(isValidPackageName('a/b/c')).toBe(false);
    expect(isValidPackageName('/abs')).toBe(false);
    expect(isValidPackageName('')).toBe(false);
  });
});
