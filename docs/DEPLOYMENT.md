# Deployment

## Vercel + Railway (recommended)

Deploy the **Dashboard** on Vercel and the **API** on Railway. The dashboard calls the Railway API over HTTPS.

### Prerequisites

- [Railway](https://railway.app) – API already deployed (see [RAILWAY.md](RAILWAY.md))
- [Vercel](https://vercel.com) account

### Setup

1. **Connect the repo to Vercel** at [vercel.com](https://vercel.com)
   - Import this repository
   - Vercel uses [vercel.json](../vercel.json) for build config

2. **Add environment variable** in Vercel (Settings → Environment Variables):

   | Variable        | Description                                                                 |
   |-----------------|-----------------------------------------------------------------------------|
   | `VITE_API_URL`  | Railway API URL, e.g. `https://nullvoidapi-production.up.railway.app/api`   |

   Set this for **Production**, **Preview**, and **Development** so all deployments use the Railway API.

3. **Deploy** – Push to your branch; Vercel builds the dashboard and deploys it.

4. **(Optional) Restrict CORS on Railway** – In Railway, add `CORS_ORIGIN` = `https://your-app.vercel.app` to limit API access to your dashboard. Default is `*` (any origin).

### Result

- **Dashboard**: `https://your-app.vercel.app` (Vercel)
- **API**: `https://nullvoidapi-production.up.railway.app` (Railway)

---

## GitHub Codespaces (Demo)

Run NullVoid in the cloud for demos or development—100% free (60 hours/month), no credit card. The `.devcontainer` config installs Node, Python, and dependencies automatically.

### Setup

1. Open the repo on GitHub → **Code** → **Codespaces** → **Create codespace on main**
2. Wait for the container to build (postCreateCommand runs `npm install`, `pip install`, `npm run build`)
3. API and Dashboard start automatically (postStartCommand). Open the forwarded port **5174** (Dashboard) in your browser

### ML Pipeline

The ML page (Export, Train) works in Codespaces. Use SQLite (no Turso needed). Optional: `make ml-serve` for the scoring API on port 8000.

### Notes

- Codespaces is ephemeral—not for 24/7 production
- For production deployment, use [Vercel + Railway](#vercel--railway-recommended).

## Railway (API + ML)

Deploy the **API** and **ML** scoring service on [Railway](https://railway.app) with branch-based deployments. Both services run as separate Railway services; the API uses Turso, and the ML service serves risk scores via FastAPI.

See **[docs/RAILWAY.md](RAILWAY.md)** for full setup: creating the project, adding API and ML services, configuring branch triggers, and environment variables.

### API environment variables (Railway)

| Variable              | Description                                      |
|-----------------------|--------------------------------------------------|
| `TURSO_DATABASE_URL`  | Turso database URL (e.g. `libsql://your-db.turso.io`) |
| `TURSO_AUTH_TOKEN`    | Turso auth token                                 |
| `CORS_ORIGIN`         | (Optional) Restrict CORS, e.g. `https://your-app.vercel.app`. Default `*` |
