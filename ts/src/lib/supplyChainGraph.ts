import type { Threat, DependencyTree } from '../types/core';
import { computeCompositeRisk, type RiskAssessment } from './riskScoring';

export interface DependencyNodeRisk {
  name: string;
  version: string;
  riskScore: number;
  threatCount: number;
  propagatedRisk: number;
  children: DependencyNodeRisk[];
}

export interface SupplyChainGraph {
  root: DependencyNodeRisk;
  maxPropagatedRisk: number;
  impactedPackages: string[];
}

function threatMatchesPackage(threat: Threat, packageName: string): boolean {
  const haystack =
    `${threat.message} ${threat.details ?? ''} ${threat.filePath ?? ''}`.toLowerCase();
  return haystack.includes(packageName.toLowerCase());
}

function nodeBaseRisk(threats: Threat[], packageName: string): number {
  const matched = threats.filter((t) => threatMatchesPackage(t, packageName));
  if (matched.length === 0) return 0;
  const assessment = computeCompositeRisk(matched);
  return assessment.overall;
}

function walkTree(tree: DependencyTree, threats: Threat[], parentRisk: number): DependencyNodeRisk {
  const base = nodeBaseRisk(threats, tree.name);
  const propagatedRisk = Math.min(1, Math.max(base, parentRisk * 0.85));
  const children = (tree.dependencies ?? []).map((dep) => {
    const childTree: DependencyTree = {
      name: dep.name,
      version: dep.version,
      dependencies: dep.dependencies ?? [],
      devDependencies: [],
      totalDependencies: dep.dependencies?.length ?? 0,
    };
    return walkTree(childTree, threats, propagatedRisk);
  });

  return {
    name: tree.name,
    version: tree.version,
    riskScore: base,
    threatCount: threats.filter((t) => threatMatchesPackage(t, tree.name)).length,
    propagatedRisk,
    children,
  };
}

function collectImpacted(node: DependencyNodeRisk, out: string[], threshold: number): number {
  let max = node.propagatedRisk;
  if (node.propagatedRisk >= threshold) {
    out.push(`${node.name}@${node.version}`);
  }
  for (const child of node.children) {
    max = Math.max(max, collectImpacted(child, out, threshold));
  }
  return max;
}

export function buildSupplyChainGraph(
  dependencyTree: DependencyTree,
  threats: Threat[],
  propagationThreshold = 0.3
): SupplyChainGraph {
  const root = walkTree(dependencyTree, threats, 0);
  const impactedPackages: string[] = [];
  const maxPropagatedRisk = collectImpacted(root, impactedPackages, propagationThreshold);
  return { root, maxPropagatedRisk, impactedPackages };
}

export function enrichDependencyTreeWithRisk(
  tree: DependencyTree,
  threats: Threat[]
): DependencyTree & { riskScore?: number; propagatedRisk?: number } {
  const graph = buildSupplyChainGraph(tree, threats);
  return {
    ...tree,
    riskScore: graph.root.riskScore,
    propagatedRisk: graph.root.propagatedRisk,
  };
}

export function riskAssessmentToReportSection(assessment: RiskAssessment): string {
  const lines = [
    `Overall risk: ${(assessment.overall * 100).toFixed(1)}%`,
    `Confidentiality: ${(assessment.byCategory.confidentiality * 100).toFixed(1)}%`,
    `Integrity: ${(assessment.byCategory.integrity * 100).toFixed(1)}%`,
    `Availability: ${(assessment.byCategory.availability * 100).toFixed(1)}%`,
  ];
  return lines.join('\n');
}
