# Deploying NullVoid API and ML on Railway

This guide explains how to deploy the NullVoid API and ML scoring service on [Railway](https://railway.app) using branch-based deployments.

## Overview

- **API service**: Node.js REST API (Express) for scans, organizations, teams, and ML commands
- **ML service**: Python FastAPI server for risk scoring (`/score`, `/behavioral-score`, etc.)

Both services run as separate Railway services in the same project. You can deploy a specific git branch (e.g. `feat/codespaces` or `main`) to a Railway environment.

## Prerequisites

- [Railway account](https://railway.app)
- GitHub repo connected to Railway
- Turso database (for API) – [create one](https://turso.tech) if needed

## Setup

### 1. Create a Railway project

1. Go to [railway.app/new](https://railway.app/new)
2. Choose **Deploy from GitHub repo**
3. Select your NullVoid repository
4. Railway will detect the monorepo; you’ll add two services manually

### 2. Add the API service

1. In your project, click **+ New** → **GitHub Repo**
2. Select the same repo again (or use **+ New** → **Empty Service** and connect the repo in settings)
3. For the API service:
   - **Root Directory**: leave empty (uses repo root)
   - **Config file path**: `/railway.json` (or leave default if `railway.json` is at root)
   - **Branch**: choose the branch to deploy (e.g. `feat/codespaces` or `main`)

4. Add environment variables:
   - `TURSO_DATABASE_URL` – your Turso database URL
   - `TURSO_AUTH_TOKEN` – your Turso auth token
   - `NULLVOID_API_KEY` (optional) – API key for protected endpoints
   - `PORT` – set by Railway automatically

5. Generate a domain: **Settings** → **Networking** → **Generate Domain**

### 3. Add the ML service

1. Click **+ New** → **GitHub Repo** (or **Empty Service**)
2. Select the same repo
3. For the ML service:
   - **Root Directory**: `ml-model`
   - **Config file path**: `/ml-model/railway.json`
   - **Branch**: same branch as the API

4. Add environment variables:
   - `PORT` – set by Railway automatically

5. Generate a domain: **Settings** → **Networking** → **Generate Domain**

### 4. Connect API to ML (optional)

If the API should call the ML service for scoring, set the ML service URL in the API:

- `ML_SERVICE_URL` – e.g. `https://your-ml-service.up.railway.app`

(Only needed if you wire the API to call the ML service; the API’s ML endpoints run commands locally when not on Vercel.)

## Branch deployments

Railway uses **environments** (e.g. Production, Staging) and **branch triggers**:

1. **Settings** → **Environments** → create or edit an environment
2. Under **Source**, set **Branch** to the git branch to deploy (e.g. `feat/codespaces`)
3. Pushes to that branch will deploy both services

To deploy a different branch:

- Create a new environment (e.g. `staging`) and set its branch
- Or change the branch in the existing environment

## Config files

| Service | Config path       | Root directory |
|---------|-------------------|----------------|
| API     | `/railway.json`   | `/` (default)  |
| ML      | `/ml-model/railway.json` | `ml-model` |

## ML model files

The ML service expects `model.pkl` (and optionally `behavioral-model.pkl`) in `ml-model/`. If they’re missing, the service starts but returns a default score of 0.5.

To train and include models:

1. Train locally: `npm run ml:train` and `npm run ml:train-behavioral`
2. Commit `model.pkl`, `feature_keys.pkl`, `metadata.json` (and behavioral equivalents) to the repo
3. Or use a build step / artifact to produce them before deploy

## Health checks

- API: `GET /health` → `{"ok": true}`
- ML: `GET /health` → `{"ok": true, "behavioral_loaded": true/false}`

## Troubleshooting

- **API build fails**: Ensure `npm run build` completes (Turbo builds `ts` and other packages). Check Node version (≥18).
- **ML build fails**: Ensure `requirements.txt` is valid and Python 3.9+ is used.
- **Database errors**: Verify `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` in the API service.
- **ML returns "Model not loaded"**: Train the model and commit the `.pkl` files, or accept the default score.
