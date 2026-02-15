# Deployment

Both the **Frontend** (dashboard) and **API** deploy automatically when changes are merged to `main`.

## Frontend (GitHub Pages)

The dashboard deploys to `https://<user>.github.io/NullVoid/` via the [pages.yml](../.github/workflows/pages.yml) workflow. No setup required.

To show real scan data instead of "No API connected", set the `NULLVOID_API_URL` repository variable (Settings → Secrets and variables → Actions → Variables) to your deployed API URL.

## API (Vercel)

The API deploys to Vercel when you connect this repository. Vercel uses **Turso** (serverless SQLite) for the database—SQLite files do not work on Vercel’s read-only filesystem.

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
4. **Set `NULLVOID_API_URL`** in GitHub repo variables to your Vercel API URL (e.g. `https://your-project.vercel.app/api`)

### Local development

Local development uses SQLite (no Turso needed). The API switches to Turso only when `TURSO_DATABASE_URL` is set.

### Vercel config

The repo includes [vercel.json](../vercel.json) and [api/index.js](../api/index.js). The build runs `npm ci && npm run build`; the API is served from `/api`.
