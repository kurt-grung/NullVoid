# Railway Deployment

Railway runs the **API** and **ML** services alongside Vercel. The API detects Railway via `RAILWAY_PROJECT_ID` / `RAILWAY_ENVIRONMENT_ID` and enables ML commands, platform-specific error messages, and Turso support.

## Overview

| Service | Root | Config | Purpose |
|---------|------|--------|---------|
| API | `/` | [railway.json](../railway.json) | REST API, scans, organizations, teams, ML commands |
| ML | `ml-model` | [ml-model/railway.json](../ml-model/railway.json) | Risk scoring (`/score`, `/behavioral-score`, etc.) |

## Setup

### 1. Create a Railway Project

1. Go to [railway.app](https://railway.app) and create a project
2. Deploy from GitHub: connect your repo and select the branch (e.g. `main` or `feat/railway`)

### 2. Add the API Service

1. In the project, add a new service → **Deploy from GitHub repo**
2. Select the same repo and branch
3. **Root directory**: `/` (repository root)
4. Build/start: [railpack.json](../railpack.json) configures:
   - Install: `npm ci`
   - Build: `npm run api:build` (builds @nullvoid/ts + @nullvoid/api)
   - Start: `node packages/api/dist/index.js`
   - Health: `GET /health`

   **Note:** Railway uses Nixpacks. [nixpacks.toml](../nixpacks.toml) overrides the build to `npm run api:build`. Or in Railway → API service → Settings → Build, set **Build Command** to `npm run api:build`.
5. Add **Variables**:
   | Variable | Description |
   |----------|-------------|
   | `TURSO_DATABASE_URL` | Turso database URL (e.g. `libsql://your-db.turso.io`) |
   | `TURSO_AUTH_TOKEN` | Turso auth token |
   | `NULLVOID_API_KEY` | Optional: require `X-API-Key` header for protected routes |

6. Generate a **public domain** for the API (Settings → Networking → Generate Domain)

### 3. Add the ML Service

1. Add another service → **Deploy from GitHub repo**
2. Same repo and branch
3. **Root directory**: `ml-model`
4. Railway uses [ml-model/railway.json](../ml-model/railway.json):
   - Build: `pip install -r requirements.txt`
   - Start: `python serve.py` (reads `PORT` from env automatically)
   - Health: `GET /health`
5. Generate a **public domain** for the ML service
6. No extra variables required unless you use a custom model path

### 4. Branch Triggers (Optional)

In each service’s Settings → Source, set the branch to deploy (e.g. `main` or `feat/railway`). Railway deploys on push to that branch.

## Environment Variables

### API Service

| Variable | Required | Description |
|----------|----------|-------------|
| `TURSO_DATABASE_URL` | Yes | Turso libSQL URL |
| `TURSO_AUTH_TOKEN` | Yes | Turso auth token |
| `NULLVOID_API_KEY` | No | If set, `X-API-Key` required for POST /scan, /ml/*, etc. |

### ML Service

Railway sets `PORT` automatically. No additional variables needed for basic deployment.

## Platform Detection

The API detects Railway when `RAILWAY_PROJECT_ID` or `RAILWAY_ENVIRONMENT_ID` is set (Railway sets these automatically). When detected:

- ML commands (`/ml/export`, `/ml/train`, etc.) are available
- Error messages reference Railway logs and Variables
- `GET /health?platform=1` returns `{ "ok": true, "platform": "railway" }`

## Vercel vs Railway

| | Vercel | Railway |
|---|--------|---------|
| Dashboard | Yes (at `/`) | No (use Vercel dashboard or point to Railway API) |
| API | Yes (serverless at `/api`) | Yes (long-running) |
| ML commands | No | Yes |
| ML service | No | Yes (separate service) |
| Database | Turso | Turso |

Both can share the same Turso database. Vercel config ([vercel.json](../vercel.json)) is unchanged.

## Troubleshooting

### API returns 503 on /scans

- Ensure `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` are set in Railway → Variables
- Check Railway logs for `TURSO_CONFIG_MISSING` or connection errors

### ML service fails to start

- Verify `ml-model/requirements.txt` installs successfully
- Ensure `model.pkl` exists (train locally first: `npm run ml:train`) or the service will start but return `{"ok": false}` from `/health` until a model is present

### Health check fails

- API: `GET /health` must return `{"ok": true}`
- ML: `GET /health` returns `{"ok": true, "behavioral_loaded": ...}` when model is loaded
