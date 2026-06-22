import { describe, it, expect } from '@jest/globals';
import { buildSupplyChainGraph } from '../../src/lib/supplyChainGraph';
import type { DependencyTree, Threat } from '../../src/types/core';

describe('supplyChainGraph', () => {
  it('propagates risk to children', () => {
    const tree: DependencyTree = {
      name: 'root',
      version: '1.0.0',
      dependencies: [
        {
          name: 'child-a',
          version: '1.0.0',
          dependencies: [],
          devDependencies: [],
          totalDependencies: 0,
        },
      ],
      devDependencies: [],
      totalDependencies: 1,
    };
    const threats: Threat[] = [
      {
        type: 'MALICIOUS_CODE',
        message: 'bad code in root',
        filePath: 'root/index.js',
        filename: 'index.js',
        severity: 'HIGH',
        details: 'root package',
        confidence: 90,
      },
    ];
    const graph = buildSupplyChainGraph(tree, threats);
    expect(graph.root.riskScore).toBeGreaterThan(0);
    expect(graph.root.children[0]?.propagatedRisk).toBeGreaterThan(0);
  });
});
