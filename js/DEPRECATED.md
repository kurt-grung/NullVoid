# Deprecated: `@nullvoid/js` workspace

The JavaScript mirror is **deprecated**. Use the TypeScript implementation:

- **CLI:** `nullvoid` → `ts/dist/bin/nullvoid.js`
- **Programmatic API:** `require('nullvoid')` → `ts/dist/scan.js`
- **Development:** `cd ts && npm run build`

## Migration timeline (Phase 0)

1. All new features land in `ts/` only
2. `js/` tests remain until parity is verified, then removed
3. Root `npm test` will drop `test:js` when retirement completes

See [docs/ADVANCED_ROADMAP.md](../docs/ADVANCED_ROADMAP.md) Phase 0.
