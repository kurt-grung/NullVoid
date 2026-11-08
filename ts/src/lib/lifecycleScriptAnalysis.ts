import * as fs from 'fs';
import * as path from 'path';
import type { ScanOptions, Threat } from '../types/core';
import { createThreat } from '../types/core';
import { LIFECYCLE_SCRIPT_ANALYSIS_CONFIG } from './config';
import { discoverInstalledPackageRoots } from './dependencySourceScan';
import { detectMalware } from './detection';

export const NPM_LIFECYCLE_SCRIPT_KEYS = new Set([
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'uninstall',
  'postuninstall',
  'preprepare',
  'prepare',
  'postprepare',
  'prepack',
  'postpack',
  'prepublishOnly',
  'prepublish',
  'publish',
  'postpublish',
]);

export interface ShellPayloadFinding {
  ruleId: string;
  description: string;
  severity: 'HIGH' | 'CRITICAL';
}

const SHELL_PAYLOAD_RULES: Array<{
  id: string;
  regex: RegExp;
  severity: 'HIGH' | 'CRITICAL';
  description: string;
}> = [
  {
    id: 'curl_pipe_shell',
    regex: /\bcurl\b[^|\n]*\|\s*(ba)?sh\b/i,
    severity: 'HIGH',
    description: 'curl piped into a shell',
  },
  {
    id: 'wget_pipe_shell',
    regex: /\bwget\b[^|\n]*\|\s*(ba)?sh\b/i,
    severity: 'HIGH',
    description: 'wget piped into a shell',
  },
  {
    id: 'pipe_shell_generic',
    regex: /\|\s*(ba)?sh\b/i,
    severity: 'HIGH',
    description: 'command piped into a shell',
  },
  {
    id: 'bash_c_remote',
    regex: /\bbash\s+-c\s+['"][^'"]*\b(curl|wget|rm\s+-rf|chmod\s+777)\b/i,
    severity: 'HIGH',
    description: 'bash -c with remote fetch or destructive command',
  },
  {
    id: 'eval_in_script',
    regex: /\beval\s+(\$|\(|`)/i,
    severity: 'CRITICAL',
    description: 'eval with dynamic input',
  },
  {
    id: 'destructive_rm',
    regex: /\brm\s+-rf\s+(\/|~|\$HOME|\$\{HOME\})/i,
    severity: 'CRITICAL',
    description: 'recursive delete of root or home',
  },
  {
    id: 'chmod_world_writable',
    regex: /\bchmod\s+777\b/i,
    severity: 'HIGH',
    description: 'world-writable permissions',
  },
  {
    id: 'powershell-encoded',
    regex: /\bpowershell(\.exe)?\b[^\n]*\s-(e|enc|encodedcommand)\b/i,
    severity: 'CRITICAL',
    description: 'PowerShell with an encoded command',
  },
  {
    id: 'powershell-download-exec',
    regex:
      /\bpowershell(\.exe)?\b[^\n]*\b(IEX|Invoke-Expression|DownloadString|Net\.WebClient|Invoke-WebRequest|iwr)\b/i,
    severity: 'CRITICAL',
    description: 'PowerShell downloading or evaluating remote content',
  },
  {
    id: 'node-eval-inline',
    regex: /\bnode(\.exe)?\s+(-e|--eval|-p|--print)\s/i,
    severity: 'HIGH',
    description: 'inline node -e payload in a lifecycle script',
  },
  {
    id: 'command-substitution-download',
    regex: /\$\([^)]*\b(curl|wget|base64)\b[^)]*\)/i,
    severity: 'HIGH',
    description: 'command substitution with a download or decode',
  },
  {
    id: 'download-then-execute',
    regex: /\b(curl|wget)\b[^\n]*\s-o\s*\S+[^\n]*(&&|;)\s*(sh|bash|node|chmod)\b/i,
    severity: 'CRITICAL',
    description: 'download to disk followed by execution',
  },
  {
    id: 'hex_encoded_shell',
    regex: /\bxxd\s+-r\s+-p\b|\bbase64\s+-d\b.*\|\s*(ba)?sh\b/i,
    severity: 'HIGH',
    description: 'decoded payload piped into shell',
  },
];

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

export function isLikelyBenignLifecycleScript(body: string): boolean {
  const trimmed = body.trim();
  if (trimmed.length === 0) return true;

  const hasShellMetachar = /[`$]|\|\s*(ba)?sh\b|&&|\|\||;\s*(curl|wget|bash|sh|rm|chmod)\b/i.test(
    trimmed
  );
  if (hasShellMetachar) return false;

  // `node ./script.js` is the normal way to run an install step; `node -e`
  // / `-p` with an inline program is not, so those fall through to the rules.
  if (
    /^node(\.exe)?(\s|$)/.test(trimmed) &&
    !/^node(\.exe)?\s+(-e|--eval|-p|--print)\b/.test(trimmed)
  ) {
    return true;
  }
  if (/^(npm|pnpm|yarn)\s+(run|exec)\s+/i.test(trimmed)) return true;
  if (
    /^(tsc|vite|webpack|rollup|esbuild|next|nuxt|turbo|rimraf|mkdirp|cpy-cli|lerna|nx)\b/i.test(
      trimmed
    )
  ) {
    return true;
  }
  if (/^husky(\s|$)/i.test(trimmed) || /^patch-package(\s|$)/i.test(trimmed)) return true;
  if (/^node-gyp\b/i.test(trimmed)) return true;
  if (/^electron-builder\b/i.test(trimmed)) return true;
  if (/^only-allow\s+(npm|pnpm|yarn)\b/i.test(trimmed)) return true;

  return false;
}

export function detectShellPayloadInScript(scriptBody: string): ShellPayloadFinding[] {
  if (!scriptBody || typeof scriptBody !== 'string') return [];
  if (isLikelyBenignLifecycleScript(scriptBody)) return [];

  const findings: ShellPayloadFinding[] = [];

  for (const rule of SHELL_PAYLOAD_RULES) {
    if (!rule.regex.test(scriptBody)) continue;
    findings.push({
      ruleId: rule.id,
      description: rule.description,
      severity: rule.severity,
    });
  }

  if (findings.length === 0) return [];

  const severityRank = (s: ShellPayloadFinding['severity']) => (s === 'CRITICAL' ? 2 : 1);
  const specificPipe = findings.some(
    (f) => f.ruleId === 'curl_pipe_shell' || f.ruleId === 'wget_pipe_shell'
  );
  const filtered = findings.filter((f) => !(specificPipe && f.ruleId === 'pipe_shell_generic'));
  filtered.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  return [filtered[0] as ShellPayloadFinding];
}

/** Max bytes of a referenced install script we will read and analyze. */
const MAX_REFERENCED_SCRIPT_BYTES = 2 * 1024 * 1024;

export interface ReferencedScript {
  kind: 'node' | 'shell';
  /** Path relative to the package directory as written in the script */
  relPath: string;
  absPath: string;
}

/**
 * Work out which local file a lifecycle script executes, if any.
 *   node ./setup.js            node scripts/postinstall.js --flag
 *   node --no-warnings x.js    sh ./install.sh        bash scripts/x.sh
 * Chains (&&, ;, |) are split and each segment checked; the first match wins.
 * Only paths inside the package directory are followed.
 */
export function resolveReferencedScript(
  body: string,
  packageDir: string
): ReferencedScript | undefined {
  const segments = body.split(/&&|\|\||;|\|/).map((s) => s.trim());
  for (const seg of segments) {
    const nodeMatch =
      /^(?:node|nodejs)(?:\.exe)?\s+(?:-{1,2}[\w-]+(?:=\S+)?\s+)*(?!-)(\S+\.(?:c|m)?js)\b/i.exec(
        seg
      );
    const shMatch = /^(?:sh|bash|zsh)\s+(?:-\w+\s+)*(\S+\.sh)\b/i.exec(seg);
    const m = nodeMatch ?? shMatch;
    if (!m) continue;
    const kind: ReferencedScript['kind'] = nodeMatch ? 'node' : 'shell';
    const relPath = (m[1] ?? '').replace(/^['"]|['"]$/g, '');
    if (!relPath || path.isAbsolute(relPath)) continue;
    const absPath = path.resolve(packageDir, relPath);
    const rel = path.relative(path.resolve(packageDir), absPath);
    if (rel.startsWith('..')) continue; // outside the package
    return { kind, relPath, absPath };
  }
  return undefined;
}

/**
 * Analyze the file a lifecycle script runs and attribute its findings to the
 * script. A `node ./setup.js` postinstall whose setup.js exfiltrates the
 * environment is reported as a LIFECYCLE_PAYLOAD on package.json, with the
 * original file-level threats kept in metadata.
 */
export function analyzeReferencedScript(
  scriptName: string,
  body: string,
  ref: ReferencedScript,
  packageJsonPath: string
): Threat[] {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(ref.absPath);
  } catch {
    return [];
  }
  if (!stat.isFile() || stat.size > MAX_REFERENCED_SCRIPT_BYTES) return [];

  let content: string;
  try {
    content = fs.readFileSync(ref.absPath, 'utf8');
  } catch {
    return [];
  }

  const findings: Array<{
    type: string;
    severity: Threat['severity'];
    message: string;
    line?: number | undefined;
  }> = [];
  if (ref.kind === 'node') {
    for (const t of detectMalware(content, ref.absPath)) {
      if (t.severity === 'HIGH' || t.severity === 'CRITICAL') {
        findings.push({
          type: String(t.type),
          severity: t.severity,
          message: t.message,
          line: t.lineNumber ?? undefined,
        });
      }
    }
  } else {
    for (const f of detectShellPayloadInScript(content)) {
      findings.push({
        type: `SHELL_${f.ruleId.toUpperCase()}`,
        severity: f.severity,
        message: f.description,
      });
    }
  }
  if (findings.length === 0) return [];

  const worst = findings.some((f) => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
  const summary = [...new Set(findings.map((f) => f.type))].join(', ');
  return [
    createThreat(
      'LIFECYCLE_PAYLOAD',
      `${scriptName} script runs ${ref.relPath}, which contains ${summary}`,
      path.resolve(packageJsonPath),
      'package.json',
      worst,
      `npm script "${scriptName}" executes ${ref.relPath} at install time; that file was flagged: ${findings
        .map((f) => `${f.type}${f.line ? ` (line ${f.line})` : ''}: ${f.message}`)
        .join('; ')}`,
      {
        confidence: worst === 'CRITICAL' ? 0.95 : 0.85,
        sampleCode: body.length > 120 ? `${body.slice(0, 120)}...` : body,
        metadata: { scriptName, referencedScript: ref.relPath, findings },
      }
    ),
  ];
}

export function analyzeLifecycleScriptsForPackageJson(
  scripts: unknown,
  packageJsonPath: string
): Threat[] {
  if (!scripts || typeof scripts !== 'object' || Array.isArray(scripts)) return [];

  const record = scripts as Record<string, unknown>;
  const threats: Threat[] = [];
  const resolvedPath = path.resolve(packageJsonPath);

  for (const [scriptName, rawBody] of Object.entries(record)) {
    if (!NPM_LIFECYCLE_SCRIPT_KEYS.has(scriptName)) continue;
    if (typeof rawBody !== 'string' || rawBody.trim().length === 0) continue;

    // Follow `node ./x.js` / `sh ./x.sh` into the file it runs.
    const ref = resolveReferencedScript(rawBody, path.dirname(resolvedPath));
    if (ref) {
      threats.push(...analyzeReferencedScript(scriptName, rawBody, ref, resolvedPath));
    }

    const finding = detectShellPayloadInScript(rawBody)[0];
    if (!finding) continue;

    threats.push(
      createThreat(
        'SUSPICIOUS_SCRIPT',
        `Suspicious ${scriptName} lifecycle script: ${finding.description}`,
        resolvedPath,
        'package.json',
        finding.severity,
        `npm script "${scriptName}" matches shell-payload rule "${finding.ruleId}"`,
        {
          confidence: finding.severity === 'CRITICAL' ? 0.95 : 0.88,
          sampleCode: rawBody.length > 120 ? `${rawBody.slice(0, 120)}...` : rawBody,
          metadata: { scriptName, ruleId: finding.ruleId },
        }
      )
    );
  }

  return threats;
}

export interface LifecycleScriptScanStats {
  packageJsonFilesAnalyzed: number;
  packageJsonFilesEligible: number;
  packageLimit: number;
  lifecycleScriptsChecked: number;
  threatsFound: number;
  truncatedByPackageBudget: boolean;
}

function countLifecycleScripts(scripts: unknown): number {
  if (!scripts || typeof scripts !== 'object' || Array.isArray(scripts)) return 0;
  const record = scripts as Record<string, unknown>;
  return Object.entries(record).filter(
    ([key, value]) =>
      NPM_LIFECYCLE_SCRIPT_KEYS.has(key) && typeof value === 'string' && value.trim().length > 0
  ).length;
}

function readPackageJsonScripts(packageJsonPath: string): unknown {
  try {
    const parsed = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as { scripts?: unknown };
    return parsed.scripts;
  } catch {
    return undefined;
  }
}

export function collectLifecycleScriptThreatsForProject(
  projectRoot: string,
  options: ScanOptions,
  projectPackageDirs: string[]
): { threats: Threat[]; stats: LifecycleScriptScanStats } {
  const enabled = options.scanLifecycleScripts !== false;
  if (!enabled) {
    return {
      threats: [],
      stats: {
        packageJsonFilesAnalyzed: 0,
        packageJsonFilesEligible: 0,
        packageLimit: 0,
        lifecycleScriptsChecked: 0,
        threatsFound: 0,
        truncatedByPackageBudget: false,
      },
    };
  }

  const maxPackages = clampInt(
    options.maxLifecycleScriptPackages,
    LIFECYCLE_SCRIPT_ANALYSIS_CONFIG.MAX_PACKAGES,
    1,
    500
  );

  const seenDirs = new Set<string>();
  const queue: string[] = [];

  for (const dir of projectPackageDirs) {
    queue.push(path.resolve(dir));
  }

  for (const pkgRoot of discoverInstalledPackageRoots(projectRoot)) {
    queue.push(path.resolve(pkgRoot));
  }

  const threats: Threat[] = [];
  let packageJsonFilesAnalyzed = 0;
  let lifecycleScriptsChecked = 0;
  const uniqueQueued = new Set(queue);
  const packageJsonFilesEligible = uniqueQueued.size;
  let truncatedByPackageBudget = packageJsonFilesEligible > maxPackages;

  for (const dir of queue) {
    if (packageJsonFilesAnalyzed >= maxPackages) break;
    if (seenDirs.has(dir)) continue;
    seenDirs.add(dir);

    const packageJsonPath = path.join(dir, 'package.json');
    if (!fs.existsSync(packageJsonPath)) continue;

    packageJsonFilesAnalyzed += 1;
    const scripts = readPackageJsonScripts(packageJsonPath);
    lifecycleScriptsChecked += countLifecycleScripts(scripts);
    threats.push(...analyzeLifecycleScriptsForPackageJson(scripts, packageJsonPath));
  }

  return {
    threats,
    stats: {
      packageJsonFilesAnalyzed,
      packageJsonFilesEligible,
      packageLimit: maxPackages,
      lifecycleScriptsChecked,
      threatsFound: threats.length,
      truncatedByPackageBudget,
    },
  };
}
