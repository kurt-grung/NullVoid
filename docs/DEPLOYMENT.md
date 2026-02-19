# Deployment

Both the **Dashboard** and **API** deploy to **Vercel** when you connect this repository. For API + ML services with ML commands, you can also deploy to **Railway** alongside Vercel.

## Vercel (Dashboard + API)

A single Vercel project serves the **Dashboard** at `/` and the **API** at `/api`. The API deploys when you connect this repository. Vercel uses **Turso** (serverless SQLite) for the database—SQLite files do not work on Vercel's read-only filesystem.

### Setup

1. **Create a Turso database** at [turso.tech](https://turso.tech)
   - Create a database and get the URL and auth token
2. **Connect the repo to Vercel** at [vercel.com](https://vercel.com)
   - Import this repository
   - Vercel will use [vercel.json](../vercel.json) for build config
3. **Add environment variables** in the Vercel project (Settings → Environment Variables):
   | Variable | Description |
   |----------|-------------|
   | `TURSO_DATABASE_URL` | Turso database URL (e.g. `libsql://your-db.turso.io`) |
   | `TURSO_AUTH_TOKEN` | Turso auth token |

   See [.env.example](../.env.example) for reference.
4. The dashboard uses `/api` (same origin) by default—no extra config needed.

### Local development

Local development uses SQLite (no Turso needed). The API switches to Turso only when `TURSO_DATABASE_URL` is set.

### Vercel config

The repo includes [vercel.json](../vercel.json) and [api/index.js](../api/index.js). The build runs `npm run api:build` (to produce `packages/api/dist`) then `npm run dashboard:build`; the dashboard is at `/`, the API at `/api`.

### Diagnosing 503 on /api/scans

1. **Check `/api/health`** – If `https://your-app.vercel.app/api/health` returns `{"ok":true}`, the API loaded. The 503 is from the database layer.
2. **Check `/api/`** – If the root returns JSON with endpoints, the API loaded.
3. **If both 503** – The API failed to load (e.g. missing `packages/api/dist`). Check Vercel build logs; ensure `api:build` runs and succeeds.
4. **If health OK but /scans 503** – Turso config issue:
   - Ensure `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` are set for **Production** (and Preview if using preview deployments).
   - No leading/trailing spaces; values must be non-empty.
   - Create a database at [turso.tech](https://turso.tech) and use the libSQL URL + auth token.
5. **Vercel Function logs** – Deployments → your deployment → Functions → `api` to see the actual error.

## Railway (API + ML)

Railway runs the API and ML scoring service as long-running processes. ML commands (`/ml/export`, `/ml/train`, etc.) are available on Railway but not on Vercel serverless.

See [RAILWAY.md](RAILWAY.md) for full setup: project creation, adding API and ML services, env vars, and troubleshooting.
