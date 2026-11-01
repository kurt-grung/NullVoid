# On-chain policy enforcement (Phase 5)

Extend `NullVoidRegistry.sol` with allow/deny policy hooks tied to scan consensus scores.

Planned CLI:

```bash
nullvoid policy-check lodash@4.17.21
nullvoid policy-enforce --cid <cid> --min-trust 0.8
```

See [docs/BLOCKCHAIN.md](../../docs/BLOCKCHAIN.md) and [docs/ADVANCED_ROADMAP.md](../../docs/ADVANCED_ROADMAP.md).
