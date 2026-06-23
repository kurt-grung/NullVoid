import * as path from 'path';

const tsDist = path.resolve(__dirname, '../../../ts/dist');

type RemoteScanHelpers = {
  isNpmPackageSpec: (target: string) => boolean;
  parsePackageSpec: (spec: string) => { name: string; version: string } | null;
  validatePackageName: (name: string) => boolean;
};

let remoteScanHelpers: RemoteScanHelpers | null = null;

function getRemoteScanHelpers(): RemoteScanHelpers {
  if (!remoteScanHelpers) {
    const remote = require(path.join(tsDist, 'lib/remotePackageScan')) as {
      isNpmPackageSpec: RemoteScanHelpers['isNpmPackageSpec'];
      parsePackageSpec: RemoteScanHelpers['parsePackageSpec'];
    };
    const pathSec = require(path.join(tsDist, 'lib/pathSecurity')) as {
      validatePackageName: RemoteScanHelpers['validatePackageName'];
    };
    remoteScanHelpers = {
      isNpmPackageSpec: remote.isNpmPackageSpec,
      parsePackageSpec: remote.parsePackageSpec,
      validatePackageName: pathSec.validatePackageName,
    };
  }
  return remoteScanHelpers;
}

export function sanitizeScanTarget(
  rawTarget: unknown,
  scanRoot: string
): { display: string; resolved: string } {
  const candidate = typeof rawTarget === 'string' ? rawTarget.trim() : '.';
  const normalizedInput = candidate.length > 0 ? candidate : '.';
  if (normalizedInput.includes('\0')) {
    throw new Error('Target contains invalid null byte');
  }

  const { isNpmPackageSpec, parsePackageSpec, validatePackageName } = getRemoteScanHelpers();
  if (isNpmPackageSpec(normalizedInput)) {
    const spec = parsePackageSpec(normalizedInput);
    if (!spec || !validatePackageName(spec.name)) {
      throw new Error('Invalid npm package name');
    }
    return { display: normalizedInput, resolved: normalizedInput };
  }

  const resolved = path.isAbsolute(normalizedInput)
    ? path.resolve(normalizedInput)
    : path.resolve(scanRoot, normalizedInput);
  const relative = path.relative(scanRoot, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Target must resolve inside configured scan root: ${scanRoot}`);
  }
  return { display: normalizedInput, resolved };
}
