import { describe, it, expect } from '@jest/globals';
import {
  buildSupplyChainGraph,
  countPackagesWithThreats,
  threatPackageName,
} from '../../src/lib/supplyChainGraph';
import type { DependencyTree, Threat } from '../../src/types/core';

function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    type: 'MALICIOUS_CODE',
    message: 'malicious code detected',
    filePath: 'index.js',
    filename: 'index.js',
    severity: 'HIGH',
    details: '',
    confidence: 0.9,
    ...overrides,
  };
}

function makeNode(name: string, children: DependencyTree[] = []): DependencyTree {
  return {
    name,
    version: '1.0.0',
    dependencies: children,
    devDependencies: [],
    totalDependencies: children.length,
  };
}

describe('supplyChainGraph', () => {
  it('propagates risk from a dependency up to the packages that depend on it', () => {
    const tree = makeNode('root', [makeNode('child-a')]);
    const graph = buildSupplyChainGraph(tree, [
      makeThreat({ filePath: 'node_modules/child-a/index.js' }),
    ]);

    expect(graph.root.riskScore).toBe(0);
    expect(graph.root.inheritedRisk).toBeGreaterThan(0);
    expect(graph.root.propagatedRisk).toBeLessThan(graph.root.children[0]?.propagatedRisk ?? 0);
  });

  it('does not push a package risk down onto its own dependencies', () => {
    const tree = makeNode('root', [makeNode('clean-child')]);
    const graph = buildSupplyChainGraph(tree, [
      makeThreat({ message: 'bad code in root', filePath: 'root/index.js' }),
    ]);

    expect(graph.root.riskScore).toBeGreaterThan(0);
    expect(graph.root.children[0]?.propagatedRisk).toBe(0);
    expect(graph.root.children[0]?.inheritedRisk).toBe(0);
  });

  it('decays inherited risk with each level of depth', () => {
    const tree = makeNode('root', [makeNode('level-1', [makeNode('level-2')])]);
    const graph = buildSupplyChainGraph(tree, [
      makeThreat({ filePath: 'node_modules/level-2/index.js' }),
    ]);

    const levelOne = graph.root.children[0];
    const levelTwo = levelOne?.children[0];

    expect(levelTwo?.riskScore).toBeGreaterThan(0);
    expect(levelOne?.propagatedRisk).toBeLessThan(levelTwo?.propagatedRisk ?? 0);
    expect(graph.root.propagatedRisk).toBeLessThan(levelOne?.propagatedRisk ?? 0);
    expect(graph.root.propagatedRisk).toBeGreaterThan(0);
  });

  it('attributes a threat to the package that owns the file', () => {
    const tree = makeNode('root', [makeNode('left-pkg'), makeNode('right-pkg')]);
    const graph = buildSupplyChainGraph(tree, [
      makeThreat({ filePath: 'app/node_modules/right-pkg/lib/index.js' }),
    ]);

    expect(graph.root.riskScore).toBe(0);
    expect(graph.root.children.find((c) => c.name === 'left-pkg')?.riskScore).toBe(0);
    expect(graph.root.children.find((c) => c.name === 'right-pkg')?.riskScore).toBeGreaterThan(0);
  });

  it('does not attribute threats to unrelated packages with substring names', () => {
    const tree = makeNode('root', [makeNode('ms'), makeNode('is')]);
    const graph = buildSupplyChainGraph(tree, [
      makeThreat({
        message: 'obfuscated code in transmission handler',
        details: 'this mismatches nothing',
        filePath: 'node_modules/left-pad/index.js',
      }),
    ]);

    expect(graph.root.children.every((child) => child.riskScore === 0)).toBe(true);
    expect(graph.root.children.every((child) => child.threatCount === 0)).toBe(true);
  });

  it('prefers explicit package metadata over the file path', () => {
    const threat = makeThreat({
      packageName: 'declared-pkg',
      filePath: 'node_modules/path-pkg/index.js',
    });

    expect(threatPackageName(threat)).toBe('declared-pkg');
  });

  it('extracts the innermost package from a nested node_modules path', () => {
    const threat = makeThreat({
      filePath: 'node_modules/outer/node_modules/@scope/inner/dist/index.js',
    });

    expect(threatPackageName(threat)).toBe('@scope/inner');
  });

  it('treats threats outside node_modules as owned by the scanned project', () => {
    const threat = makeThreat({ filePath: '/tmp/project/src/index.js' });

    expect(threatPackageName(threat)).toBeNull();
  });

  it('scores dev dependencies of the scanned project', () => {
    const tree: DependencyTree = {
      name: 'root',
      version: '1.0.0',
      dependencies: [],
      devDependencies: [makeNode('dev-pkg')],
      totalDependencies: 1,
    };
    const graph = buildSupplyChainGraph(tree, [
      makeThreat({ filePath: 'node_modules/dev-pkg/index.js' }),
    ]);

    expect(graph.root.children.find((c) => c.name === 'dev-pkg')?.riskScore).toBeGreaterThan(0);
  });

  it('reports impacted packages without duplicates', () => {
    const shared = makeNode('shared-pkg');
    const tree = makeNode('root', [makeNode('a', [shared]), makeNode('b', [shared])]);
    const graph = buildSupplyChainGraph(tree, [
      makeThreat({ filePath: 'node_modules/shared-pkg/index.js' }),
    ]);

    expect(graph.impactedPackages).toEqual([...new Set(graph.impactedPackages)]);
    expect(graph.impactedPackages).toContain('shared-pkg@1.0.0');
    expect(graph.impactedPackages).toContain('root@1.0.0');

    const sharedNode = graph.root.children[0]?.children[0];
    expect(sharedNode?.name).toBe('shared-pkg');
    expect(graph.maxPropagatedRisk).toBe(sharedNode?.riskScore);
  });

  it('counts distinct packages with threats', () => {
    const threats = [
      makeThreat({ filePath: 'node_modules/a/index.js' }),
      makeThreat({ filePath: 'node_modules/a/other.js' }),
      makeThreat({ filePath: 'node_modules/b/index.js' }),
      makeThreat({ filePath: 'src/local.js' }),
    ];

    expect(countPackagesWithThreats(threats)).toBe(3);
    expect(countPackagesWithThreats([])).toBe(0);
  });
});
