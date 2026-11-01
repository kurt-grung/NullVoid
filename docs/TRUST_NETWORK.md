# Trust Network

NullVoid's Trust Network enables local reputation tracking for packages and publishers. Trust propagates from verified CIDs and clean scan history.

## Overview

- **Trust Store**: Local JSON file at `~/.nullvoid/trust-store.json`
- **Trust Score**: 0-1 (higher = more trusted)
- **Verification**: Successful `nullvoid verify-package` records trust
- **ML Integration**: Low trust score increases threat score in dependency confusion detection

## Configuration

Enable via config or environment:

```json
{
  "DEPENDENCY_CONFUSION_CONFIG": {
    "TRUST_CONFIG": {
      "ENABLED": true,
      "TRUST_STORE_PATH": "~/.nullvoid/trust-store.json",
      "TRANSITIVE_TRUST_WEIGHT": 0.3
    }
  }
}
```

Environment variables:
- `NULLVOID_TRUST_ENABLED=true`
- `NULLVOID_TRUST_STORE_PATH` - path to trust store JSON

## CLI Commands

### trust-status

Show trust score and verification status for a package:

```bash
nullvoid trust-status lodash@4.17.21
nullvoid trust-status express --json
```

## Automatic Recording

When `TRUST_CONFIG.ENABLED` is true:

- **verify-package**: On successful verification, records the package with trust score 1
- **ML scoring**: `getTrustScore` is used in dependency confusion detection; low trust increases risk

## Trust Store Format

```json
{
  "lodash@4.17.21": {
    "packageName": "lodash",
    "version": "4.17.21",
    "cid": "bafy...",
    "verifiedAt": "2024-01-15T12:00:00.000Z",
    "lastScanOk": true,
    "trustScore": 1
  }
}
```
