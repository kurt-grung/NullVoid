import * as path from 'path';

const tsDist = path.resolve(__dirname, '../../../ts/dist');

type EnhancedRules = Record<
  string,
  {
    patterns: string[];
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
    confidence_threshold: number;
  }
>;

type RulesModule = {
  parseRulesObject: (value: unknown) => EnhancedRules;
  validateRules: (rules: EnhancedRules) => { valid: boolean; errors: string[] };
  loadRules: (
    rulesPath: string,
    options?: { mergeWithDefaults?: boolean; validateRules?: boolean }
  ) => EnhancedRules;
  createExampleRules: (outputPath: string, format: 'json' | 'yaml') => void;
};

type ScanRulesOptions = {
  rulesFile?: string;
  rules?: Record<string, unknown>;
  mergeRulesWithDefaults?: boolean;
  validateRules?: boolean;
};

let rulesModule: RulesModule | null = null;

function getRulesModule(): RulesModule {
  if (!rulesModule) {
    rulesModule = require(path.join(tsDist, 'lib/rules')) as RulesModule;
  }
  return rulesModule;
}

export type ScanRulesInput = {
  rulesFile?: string;
  rules?: unknown;
  mergeRulesWithDefaults?: boolean;
};

export function buildScanRulesOptions(
  body: ScanRulesInput | undefined,
  scanRoot: string
): ScanRulesOptions {
  if (!body?.rulesFile && body?.rules === undefined) {
    return {};
  }

  const options: ScanRulesOptions = {
    mergeRulesWithDefaults: body.mergeRulesWithDefaults !== false,
    validateRules: true,
  };

  if (body.rulesFile) {
    const { sanitizeRulesFilePath } = require('./scanTarget') as {
      sanitizeRulesFilePath: (raw: unknown, root: string) => string;
    };
    options.rulesFile = sanitizeRulesFilePath(body.rulesFile, scanRoot);
    const fs = require('fs') as typeof import('fs');
    if (!fs.existsSync(options.rulesFile)) {
      throw new Error(`Rules file not found: ${body.rulesFile}`);
    }
    const { loadRules, validateRules } = getRulesModule();
    const parsed = loadRules(options.rulesFile, {
      mergeWithDefaults: options.mergeRulesWithDefaults !== false,
    });
    const { valid, errors } = validateRules(parsed);
    if (!valid) {
      throw new Error(errors.join('; '));
    }
  }

  if (body.rules !== undefined) {
    const { parseRulesObject, validateRules } = getRulesModule();
    const parsed = parseRulesObject(body.rules);
    const { valid, errors } = validateRules(parsed);
    if (!valid) {
      throw new Error(errors.join('; '));
    }
    options.rules = parsed as unknown as Record<string, unknown>;
  }

  return options;
}

export function validateRulesPayload(body: unknown): { valid: boolean; errors: string[] } {
  const { parseRulesObject, validateRules } = getRulesModule();
  try {
    const parsed = parseRulesObject(body);
    return validateRules(parsed);
  } catch (error) {
    return { valid: false, errors: [(error as Error).message] };
  }
}

export function rulesTemplate(format: 'json' | 'yaml'): string {
  const fs = require('fs') as typeof import('fs');
  const os = require('os') as typeof import('os');
  const tmpPath = path.join(
    os.tmpdir(),
    `nullvoid-rules-template-${Date.now()}.${format === 'json' ? 'json' : 'yml'}`
  );
  getRulesModule().createExampleRules(tmpPath, format);
  const content = fs.readFileSync(tmpPath, 'utf8');
  fs.rmSync(tmpPath, { force: true });
  return content;
}
