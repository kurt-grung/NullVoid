# Detection benchmark

Package-level precision / recall for the scanner, run by CI (`benchmark` job in
`.github/workflows/tests.yml`) and locally with `npm run benchmark`.

- `malicious/` — 24 fixture packages, each reconstructing the *technique* of a
  real npm incident (env/credential exfiltration, install-script droppers,
  obfuscated loaders, wallet drainers, DNS tunnelling, cryptojacking). None
  contains a live payload or a working C2. `manifest.json` names the incident
  each one models and the threat families expected.
- `benign.json` — 40 widely used packages pinned by version, fetched with
  `npm pack` into `.cache/` (gitignored, cached in CI). `knownFlagged` lists
  benign packages whose behaviour is indistinguishable from malware (esbuild's
  installer, pm2's host monitor); they count against precision on purpose.
- `baseline.json` — the floor CI enforces. A run that drops below it fails.

A package counts as detected when any threat at or above `--threshold`
(default HIGH) is reported.

```
npm run benchmark                       # full run, writes results.json
npm run benchmark -- --offline          # cached benign packages only
npm run benchmark -- --verbose          # per-package lines for everything
npm run benchmark -- --update-baseline  # accept the current numbers as the new floor
```

When you change detection logic, run the benchmark before and after. Lower
precision means new false positives on real packages; lower recall means a
technique that used to be caught no longer is. `results.json` lists every
package with its max severity and threat types.
