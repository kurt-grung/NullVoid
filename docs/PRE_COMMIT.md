# Pre-commit Integration

Run NullVoid automatically before each commit so you catch security issues before they land in history. The hook can **block the commit** when threats are found.

---

## Quick start (NullVoid repo)

This repository already includes an optional pre-commit hook.

1. **Enable** the NullVoid scan before commit:
   ```bash
   export NULLVOID_PRE_COMMIT=1
   ```
2. Commit as usual. The hook runs `lint-staged` first, then (if enabled) a NullVoid scan with `--depth 1` for speed.
3. If **any threats** are found, the commit is **blocked** and you see the scan output. Fix or accept the findings, then commit again.
4. **Disable** when you don’t want the scan:
   ```bash
   unset NULLVOID_PRE_COMMIT
   ```

One-off run for a single commit:

```bash
NULLVOID_PRE_COMMIT=1 git commit -m "your message"
```

---

## How it works

- The hook lives in [.husky/pre-commit](../.husky/pre-commit).
- When `NULLVOID_PRE_COMMIT=1`, it runs [scripts/nullvoid-pre-commit.js](../scripts/nullvoid-pre-commit.js), which:
  - Runs `nullvoid . --output <temp> --depth 1 --no-ioc` (shallow scan, **no IoC lookups**).
  - Reads the JSON result and **exits with code 1** if `threats.length > 0`.
- **`--no-ioc`** disables NVD/GHSA/npm/Snyk vulnerability lookups. That avoids CVE keyword false positives (e.g. the "husky" package matching unrelated "HUSKY RTU" firmware CVEs). Pre-commit therefore only blocks on **static analysis** findings (obfuscation, wallet hijacking, suspicious scripts, etc.).
- The commit **fails** when the scanner reports one or more threats; it **succeeds** when the scan passes or the scanner errors (e.g. build failure).

---

## Speed and scope: `--depth 1` and `--no-ioc`

Pre-commit uses **`--depth 1`** so only the top-level directory and immediate dependencies are scanned. It also uses **`--no-ioc`** so it does not query NVD/GHSA/npm/Snyk (avoids slow API calls and CVE keyword false positives). That keeps commits fast while still catching **static analysis** issues (obfuscation, wallet hijacking, suspicious scripts, etc.) in the code you’re about to commit.

For a full scan (e.g. in CI), run NullVoid without `--depth` or with a higher value:

```bash
nullvoid . --depth 5
```

---

## Adding NullVoid to any project

### Option A: Husky + script (recommended)

1. **Install NullVoid** (global or local):
   ```bash
   npm install -g nullvoid
   # or
   npm install --save-dev nullvoid
   ```

2. **Install Husky** and add a pre-commit hook:
   ```bash
   npm install --save-dev husky
   npx husky init
   ```

3. **Pre-commit script** that fails when threats are found:
   - Create `scripts/nullvoid-pre-commit.js` (or copy from this repo) and make it executable, or
   - Use a shell one-liner that runs NullVoid and checks output (see Option B).

4. In **`.husky/pre-commit`**:
   ```bash
   # your other hooks (e.g. lint-staged)
   npx lint-staged

   # NullVoid: block commit if threats found
   node scripts/nullvoid-pre-commit.js
   ```
   If you don’t have the script, use the **generic shell** approach below.

### Option B: Generic shell (no Node script)

Use a temp file and `jq` (or Node) to check for threats:

```bash
# In .husky/pre-commit
OUTPUT=$(mktemp).json
npx nullvoid . --output "$OUTPUT" --depth 1
THREATS=$(jq '.threats | length' "$OUTPUT")
rm -f "$OUTPUT"
[ "$THREATS" -eq 0 ] || { echo "NullVoid: $THREATS threat(s) found. Commit blocked."; exit 1; }
```

Without `jq`, use Node:

```bash
OUTPUT=$(mktemp).json
npx nullvoid . --output "$OUTPUT" --depth 1
node -e "const r=require('$OUTPUT'); require('fs').unlinkSync('$OUTPUT'); process.exit((r.threats&&r.threats.length)>0?1:0)"
```

### Option C: pre-commit (Python framework)

If you use [pre-commit](https://pre-commit.com/), add a local hook:

**.pre-commit-config.yaml**:

```yaml
- repo: local
  hooks:
    - id: nullvoid
      name: NullVoid security scan
      entry: bash -c 'npx nullvoid . --output /tmp/nullvoid-out.json --depth 1 && (node -e "const r=require(\"/tmp/nullvoid-out.json\"); process.exit((r.threats&&r.threats.length)>0?1:0)" || exit 1)'
      language: system
```

---

## Customizing behavior

| Goal | Approach |
|------|----------|
| **Faster pre-commit** | Use `--depth 1` (default in the repo script). |
| **Only block on high severity** | Change the script to exit 1 only when e.g. `threats.some(t => t.severity === 'CRITICAL' \|\| t.severity === 'HIGH')`. |
| **Optional scan** | Run the NullVoid step only when e.g. `NULLVOID_PRE_COMMIT=1` (as in this repo). |
| **Include IoC in pre-commit** | Remove `--no-ioc` from the script to run NVD/GHSA/npm/Snyk; expect more false positives (e.g. "husky" → HUSKY RTU CVEs). |
| **Full scan in CI** | Run `nullvoid .` (or with `--depth 5`) and optionally `--format sarif` in GitHub Actions / CircleCI. |

---

## See also

- [Configuration](CONFIGURATION.md#pre-commit-integration) — Pre-commit section and env var.
- [ROADMAP](ROADMAP.md) — Phase 2 Developer Experience (pre-commit hooks).
