# Consensus Verification

NullVoid's consensus verification compares package integrity across multiple sources: npm, GitHub Packages, and IPFS.

## Overview

- **Sources**: npm registry, GitHub Packages (when repo is GitHub), IPFS (when CID known)
- **Consensus**: Majority agreement on CID (configurable: default 2/3)
- **Use case**: Detect supply chain tampering when one source differs

## Configuration

```json
{
  "DEPENDENCY_CONFUSION_CONFIG": {
    "CONSENSUS_CONFIG": {
      "ENABLED": true,
      "SOURCES": ["npm", "github", "ipfs"],
      "MIN_AGREEMENT": 2,
      "GITHUB_TOKEN": null,
      "GATEWAY_URL": "https://ipfs.io"
    }
  }
}
```

Environment variables:
- `NULLVOID_CONSENSUS_ENABLED=true`
- `GITHUB_TOKEN` - for GitHub Packages access
- `NULLVOID_IPFS_GATEWAY` - IPFS gateway URL

## CLI Commands

### verify-consensus

Run consensus verification for a package:

```bash
nullvoid verify-consensus lodash@4.17.21
nullvoid verify-consensus express@4.18.2 --cid bafy... --json
```

### verify-package --consensus

Use `--consensus` with verify-package to run consensus instead of single-source verification:

```bash
nullvoid verify-package lodash@4.17.21 --consensus
```

## Output

```
Consensus: lodash@4.17.21

  ✓ npm: bafy...
  ✓ github: bafy...
  ✓ ipfs: bafy...

  Consensus: 3/3
  Agreed: Yes
```

## How It Works

1. Fetch tarball from npm registry
2. If repo is GitHub, fetch from GitHub Packages
3. If CID provided, fetch from IPFS
4. Compute CID for each fetched tarball
5. Compare: consensus = majority agreement (e.g. 2 of 3 match)
