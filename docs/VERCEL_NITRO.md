# Vercel + Nitro (Future Phase)

This document outlines how to deploy the NullVoid API to Vercel using Nitro as an optional future phase.

## Current Limitation

The API uses **better-sqlite3** and a writable filesystem. Vercel serverless has a read-only filesystem (except `/tmp`), so SQLite will not work as-is.

## Migration Path

### 1. Nitro API Package

- Create `packages/api-nitro/` with Nitro server config
- Port Express routes to Nitro handlers (file-based routes in `server/routes/`)
- Replace better-sqlite3 with **Turso** (libSQL, SQLite-compatible, serverless) or PlanetScale/Supabase

### 2. Database Migration

- Current: [packages/api/src/db/](../packages/api/src/db/) uses better-sqlite3 with file path
- Turso: Use `@libsql/client` with `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`
- Schema stays the same; only the driver changes

### 3. Scan Integration

- API loads scan from `ts/dist`. On Vercel serverless, options:
  - Bundle the scan module (complex, native deps)
  - Call an external scan service
  - Use Vercel Edge with WASM-based scan (if available)

### 4. Deployment

- `vercel.json` or Nitro preset for Vercel
- Set `VITE_API_URL` to the Vercel deployment URL in the Pages workflow

## Recommendation

Defer Phase 3 until needed. Railway/Render remain simpler for the current Express + SQLite setup.
