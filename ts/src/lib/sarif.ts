import * as crypto from 'crypto';
import * as path from 'path';
import type { SeverityLevel, Threat, ThreatType } from '../types/core';
import { RISK_CONFIG } from './config';
import { computeCompositeRisk, getRiskCategory, type RiskAssessment } from './riskScoring';

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const TOOL_NAME = 'NullVoid';
const TOOL_INFORMATION_URI = 'https://github.com/kurt-grung/NullVoid';
const DEFAULT_URI = 'package.json';
const UNKNOWN_RULE_ID = 'UNKNOWN_THREAT';
const ANSI_ESCAPE = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g');
const LEADING_ICON = /^\s*[\p{Emoji_Presentation}\p{Extended_Pictographic}]\s*/u;
const SEVERITY_RANK: Record<SeverityLevel, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const SEVERITY_LEVELS: Record<SeverityLevel, SarifLevel> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
};

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export interface SarifRegion {
  startLine: number;
  startColumn: number;
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: SarifRegion;
  };
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: {
    tags: string[];
    'security-severity': string;
    riskCategory: string;
  };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints: { nullvoidThreat: string };
  properties: {
    riskCategory: string;
    severity: string;
    confidence?: number;
  };
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      fullName: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  invocations: {
    executionSuccessful: boolean;
    exitCode: number;
    exitCodeDescription: string;
  }[];
  results: SarifResult[];
  properties: {
    riskAssessment: RiskAssessment;
  };
}

export interface SarifLog {
  $schema: string;
  version: typeof SARIF_VERSION;
  runs: SarifRun[];
}

export interface SarifOptions {
  riskAssessment?: RiskAssessment | undefined;
  toolVersion?: string | undefined;
  workspaceRoot?: string | undefined;
}

function normalizeConfidence(confidence: number | undefined): number | undefined {
  if (typeof confidence !== 'number' || !Number.isFinite(confidence)) return undefined;
  const normalized = confidence > 1 ? confidence / 100 : confidence;
  return Math.min(1, Math.max(0, normalized));
}

function securitySeverity(severity: SeverityLevel): string {
  const score = RISK_CONFIG.SEVERITY_SCORES[severity] ?? 0.5;
  return (Math.min(1, Math.max(0, score)) * 10).toFixed(1);
}

function threatSeverity(threat: Threat): SeverityLevel {
  return threat.severity in SEVERITY_LEVELS ? threat.severity : 'MEDIUM';
}

function artifactUri(threat: Threat, workspaceRoot: string | undefined): string {
  const raw = threat.filePath || threat.package || DEFAULT_URI;
  let uri = String(raw).replace(ANSI_ESCAPE, '').replace(LEADING_ICON, '').trim();

  if (workspaceRoot && path.isAbsolute(uri)) {
    const relative = path.relative(workspaceRoot, uri);
    uri = relative && !relative.startsWith('..') ? relative : path.basename(uri);
  }

  return uri ? uri.split(path.sep).join('/') : DEFAULT_URI;
}

function threatLocation(threat: Threat, workspaceRoot: string | undefined): SarifLocation {
  const location: SarifLocation = {
    physicalLocation: { artifactLocation: { uri: artifactUri(threat, workspaceRoot) } },
  };

  if (typeof threat.lineNumber === 'number' && threat.lineNumber >= 1) {
    location.physicalLocation.region = { startLine: threat.lineNumber, startColumn: 1 };
  }

  return location;
}

function fingerprint(ruleId: string, location: SarifLocation, message: string): string {
  const region = location.physicalLocation.region;
  const parts = [
    ruleId,
    location.physicalLocation.artifactLocation.uri,
    region ? String(region.startLine) : '',
    message,
  ];
  return crypto.createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 32);
}

function buildRules(threats: Threat[]): SarifRule[] {
  const worstByType = new Map<string, SeverityLevel>();

  for (const threat of threats) {
    const ruleId = threat.type || UNKNOWN_RULE_ID;
    const severity = threatSeverity(threat);
    const current = worstByType.get(ruleId);
    if (!current || SEVERITY_RANK[severity] > SEVERITY_RANK[current]) {
      worstByType.set(ruleId, severity);
    }
  }

  return [...worstByType.entries()].map(([ruleId, severity]) => {
    const category = getRiskCategory(ruleId as ThreatType);
    return {
      id: ruleId,
      name: ruleId,
      shortDescription: { text: ruleId.replace(/_/g, ' ').toLowerCase() },
      fullDescription: {
        text: `NullVoid ${ruleId} finding affecting ${category} of the supply chain.`,
      },
      defaultConfiguration: { level: SEVERITY_LEVELS[severity] },
      properties: {
        tags: ['security', `risk/${category}`],
        'security-severity': securitySeverity(severity),
        riskCategory: category,
      },
    };
  });
}

function buildResults(threats: Threat[], workspaceRoot: string | undefined): SarifResult[] {
  return threats.map((threat) => {
    const ruleId = threat.type || UNKNOWN_RULE_ID;
    const severity = threatSeverity(threat);
    const message = threat.details ? `${threat.message} — ${threat.details}` : threat.message;
    const location = threatLocation(threat, workspaceRoot);
    const confidence = normalizeConfidence(threat.confidence);

    return {
      ruleId,
      level: SEVERITY_LEVELS[severity],
      message: { text: message },
      locations: [location],
      partialFingerprints: { nullvoidThreat: fingerprint(ruleId, location, message) },
      properties: {
        riskCategory: getRiskCategory(ruleId as ThreatType),
        severity,
        ...(confidence === undefined ? {} : { confidence }),
      },
    };
  });
}

export function generateSarifOutput(threats: Threat[], options: SarifOptions = {}): SarifLog {
  const riskAssessment = options.riskAssessment ?? computeCompositeRisk(threats);

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: options.toolVersion ?? '0.0.0',
            fullName: 'NullVoid Security Scanner',
            informationUri: TOOL_INFORMATION_URI,
            rules: buildRules(threats),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            exitCode: threats.length > 0 ? 1 : 0,
            exitCodeDescription: threats.length > 0 ? 'Threats detected' : 'No threats detected',
          },
        ],
        results: buildResults(threats, options.workspaceRoot),
        properties: { riskAssessment },
      },
    ],
  };
}
