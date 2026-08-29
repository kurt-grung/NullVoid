import type { Threat, DependencyTree } from '../types/core';
import { SUPPLY_CHAIN_CONFIG } from './config';
import { computeCompositeRisk, type RiskAssessment } from './riskScoring';

const NODE_MODULES_SEGMENT = /(?:^|[\\/])node_modules[\\/](@[^\\/]+[\\/][^\\/]+|[^\\/]+)/g;
const PATH_SEPARATOR = /[\\/]/;

export interface DependencyNodeRisk {
  name: string;
  version: string;
  riskScore: number;
  threatCount: number;
  inheritedRisk: number;
  propagatedRisk: number;
  children: DependencyNodeRisk[];
}

export interface SupplyChainGraph {
  root: DependencyNodeRisk;
  maxPropagatedRisk: number;
  impactedPackages: string[];
  packagesWithThreats: number;
}

interface ThreatIndex {
  byPackage: Map<string, Threat[]>;
  unattributed: Threat[];
}

function packageNameFromPath(value: string | undefined): string | null {
  if (!value) return null;
  let last: string | null = null;
  for (const match of value.matchAll(NODE_MODULES_SEGMENT)) {
    last = match[1] ?? last;
  }
  return last ? last.replace(/\\/g, '/') : null;
}

function asPackageName(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  const isScoped = trimmed.startsWith('@');
  const separatorCount = trimmed.split(PATH_SEPARATOR).length - 1;
  if (separatorCount > (isScoped ? 1 : 0)) {
    return packageNameFromPath(trimmed);
  }
  return trimmed;
}

export function threatPackageName(threat: Threat): string | null {
  const metadata = threat.metadata ?? {};
  const candidates = [
    threat['packageName'],
    metadata['packageName'],
    metadata['package'],
    threat.package,
  ];

  for (const candidate of candidates) {
    const name = asPackageName(candidate);
    if (name) return name;
  }

  return packageNameFromPath(threat.filePath);
}

function buildThreatIndex(threats: Threat[]): ThreatIndex {
  const byPackage = new Map<string, Threat[]>();
  const unattributed: Threat[] = [];

  for (const threat of threats) {
    const name = threatPackageName(threat);
    if (!name) {
      unattributed.push(threat);
      continue;
    }
    const key = name.toLowerCase();
    const existing = byPackage.get(key);
    if (existing) {
      existing.push(threat);
    } else {
      byPackage.set(key, [threat]);
    }
  }

  return { byPackage, unattributed };
}

function threatsForNode(index: ThreatIndex, packageName: string, isRoot: boolean): Threat[] {
  const direct = index.byPackage.get(packageName.toLowerCase()) ?? [];
  if (!isRoot || index.unattributed.length === 0) return direct;
  return [...direct, ...index.unattributed];
}

function scoreNode(
  tree: DependencyTree,
  index: ThreatIndex,
  isRoot: boolean,
  decay: number
): DependencyNodeRisk {
  const matched = threatsForNode(index, tree.name, isRoot);
  const ownRisk = matched.length > 0 ? computeCompositeRisk(matched).overall : 0;

  const childTrees = isRoot
    ? [...(tree.dependencies ?? []), ...(tree.devDependencies ?? [])]
    : (tree.dependencies ?? []);

  const children = childTrees.map((dep) => scoreNode(dep, index, false, decay));

  const worstChildRisk = children.reduce(
    (worst, child) => Math.max(worst, child.propagatedRisk),
    0
  );
  const inheritedRisk = Math.min(1, worstChildRisk * decay);

  return {
    name: tree.name,
    version: tree.version,
    riskScore: ownRisk,
    threatCount: matched.length,
    inheritedRisk,
    propagatedRisk: Math.min(1, Math.max(ownRisk, inheritedRisk)),
    children,
  };
}

function collectImpacted(node: DependencyNodeRisk, out: Set<string>, threshold: number): number {
  let max = node.propagatedRisk;
  if (node.propagatedRisk >= threshold) {
    out.add(`${node.name}@${node.version}`);
  }
  for (const child of node.children) {
    max = Math.max(max, collectImpacted(child, out, threshold));
  }
  return max;
}

function countIndexedPackages(index: ThreatIndex): number {
  return index.byPackage.size + (index.unattributed.length > 0 ? 1 : 0);
}

export function countPackagesWithThreats(threats: Threat[]): number {
  return countIndexedPackages(buildThreatIndex(threats));
}

export function buildSupplyChainGraph(
  dependencyTree: DependencyTree,
  threats: Threat[],
  propagationThreshold = SUPPLY_CHAIN_CONFIG.PROPAGATION_THRESHOLD
): SupplyChainGraph {
  const index = buildThreatIndex(threats);
  const root = scoreNode(dependencyTree, index, true, SUPPLY_CHAIN_CONFIG.PROPAGATION_DECAY);
  const impacted = new Set<string>();
  const maxPropagatedRisk = collectImpacted(root, impacted, propagationThreshold);
  return {
    root,
    maxPropagatedRisk,
    impactedPackages: [...impacted],
    packagesWithThreats: countIndexedPackages(index),
  };
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
