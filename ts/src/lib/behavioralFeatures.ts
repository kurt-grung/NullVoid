/**
 * Behavioral feature vector built from a package manifest (package.json).
 *
 * One implementation for the scanner (dependencyConfusion.ts) and the training
 * exporter (ml-model/export-behavioral-features.js via ts/dist) so that what the
 * model is trained on is exactly what it is scored on. Keys must match the
 * `behavioral` list in ml-model/feature-keys.json.
 */

import { extractBehavioralCountsFromScripts } from './anomalyDetection';
import { analyzeLifecycleScriptsForPackageJson } from './lifecycleScriptAnalysis';

export interface ManifestLike {
  scripts?: Record<string, unknown> | undefined;
  dependencies?: Record<string, unknown> | undefined;
  devDependencies?: Record<string, unknown> | undefined;
}

export interface BehavioralFeatures {
  scriptCount: number;
  scriptTotalLength: number;
  hasPostinstall: number;
  postinstallLength: number;
  preinstallLength: number;
  postuninstallLength: number;
  networkScriptCount: number;
  evalUsageCount: number;
  childProcessCount: number;
  fileSystemAccessCount: number;
  base64DecodeCount: number;
  obfuscationMarkerCount: number;
  socketDnsCount: number;
  dependencyCount: number;
  devDependencyCount: number;
  /** Highest lifecycle-script rule severity: 0 none, .25 LOW, .5 MEDIUM, .75 HIGH, 1 CRITICAL */
  lifecycleThreatScore: number;
  /** Number of lifecycle scripts that matched a shell-payload rule */
  lifecycleThreatCount: number;
}

const SEVERITY_SCORE: Record<string, number> = { LOW: 0.25, MEDIUM: 0.5, HIGH: 0.75, CRITICAL: 1 };

function stringScripts(scripts: unknown): Record<string, string> {
  if (!scripts || typeof scripts !== 'object' || Array.isArray(scripts)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(scripts as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

export function behavioralFeaturesFromManifest(
  manifest: ManifestLike | null | undefined,
  packageJsonPath = 'package.json'
): BehavioralFeatures {
  const scripts = stringScripts(manifest?.scripts);
  const scriptKeys = Object.keys(scripts);
  const postinstall = scripts['postinstall'] ?? scripts['install'];
  const preinstall = scripts['preinstall'];
  const postuninstall = scripts['postuninstall'];
  const counts = extractBehavioralCountsFromScripts(Object.values(scripts).join('\n'));

  const lifecycleThreats = analyzeLifecycleScriptsForPackageJson(scripts, packageJsonPath);
  let lifecycleThreatScore = 0;
  for (const t of lifecycleThreats) {
    lifecycleThreatScore = Math.max(lifecycleThreatScore, SEVERITY_SCORE[t.severity] ?? 0);
  }

  return {
    scriptCount: scriptKeys.length,
    scriptTotalLength: scriptKeys.reduce((sum, k) => sum + (scripts[k] ?? '').length, 0),
    hasPostinstall: postinstall ? 1 : 0,
    postinstallLength: postinstall ? postinstall.length : 0,
    preinstallLength: preinstall ? preinstall.length : 0,
    postuninstallLength: postuninstall ? postuninstall.length : 0,
    networkScriptCount: counts.networkScriptCount,
    evalUsageCount: counts.evalUsageCount,
    childProcessCount: counts.childProcessCount,
    fileSystemAccessCount: counts.fileSystemAccessCount,
    base64DecodeCount: counts.base64DecodeCount,
    obfuscationMarkerCount: counts.obfuscationMarkerCount,
    socketDnsCount: counts.socketDnsCount,
    dependencyCount: Object.keys(manifest?.dependencies ?? {}).length,
    devDependencyCount: Object.keys(manifest?.devDependencies ?? {}).length,
    lifecycleThreatScore,
    lifecycleThreatCount: lifecycleThreats.length,
  };
}
