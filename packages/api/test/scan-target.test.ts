import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { sanitizeScanTarget, sanitizeRulesFilePath } from '../src/scanTarget';

const scanRoot = path.join(os.tmpdir(), 'nullvoid-scan-target-root');

beforeAll(() => {
  fs.mkdirSync(scanRoot, { recursive: true });
});

describe('sanitizeScanTarget', () => {
  it('accepts npm package specs without resolving under scan root', () => {
    const result = sanitizeScanTarget('lodash@4.17.21', scanRoot);
    expect(result).toEqual({ display: 'lodash@4.17.21', resolved: 'lodash@4.17.21' });
  });

  it('accepts scoped npm package specs', () => {
    const result = sanitizeScanTarget('@types/node@20.0.0', scanRoot);
    expect(result).toEqual({ display: '@types/node@20.0.0', resolved: '@types/node@20.0.0' });
  });

  it('rejects path traversal for filesystem targets', () => {
    expect(() => sanitizeScanTarget('../outside', scanRoot)).toThrow(
      'inside configured scan root'
    );
  });

  it('rejects invalid npm package names', () => {
    expect(() => sanitizeScanTarget('evil;curl', scanRoot)).toThrow('Invalid npm package name');
  });
});

describe('sanitizeRulesFilePath', () => {
  it('accepts rules files inside scan root', () => {
    const rulesPath = path.join(scanRoot, 'custom-rules.json');
    fs.writeFileSync(rulesPath, '{}');
    expect(sanitizeRulesFilePath('custom-rules.json', scanRoot)).toBe(rulesPath);
    fs.rmSync(rulesPath, { force: true });
  });

  it('rejects path traversal', () => {
    expect(() => sanitizeRulesFilePath('../outside/rules.json', scanRoot)).toThrow(
      'inside configured scan root'
    );
  });

  it('rejects non-rules extensions', () => {
    expect(() => sanitizeRulesFilePath('rules.txt', scanRoot)).toThrow(
      'must be a .json, .yaml, or .yml file'
    );
  });
});
