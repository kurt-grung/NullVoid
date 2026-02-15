# Deployment

Both the **Dashboard** and **API** deploy to **Vercel** when you connect this repository.

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

The repo includes [vercel.json](../vercel.json) and [api/index.js](../api/index.js). The build runs `npm ci && npm run build`; the dashboard is at `/`, the API at `/api`.

### GitHub Pages (optional)

To deploy the dashboard to GitHub Pages instead, use [pages.yml](../.github/workflows/pages.yml) with `VITE_BASE=/NullVoid/` and set `NULLVOID_API_URL` to your API.
