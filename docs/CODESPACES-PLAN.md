# GitHub Codespaces Plan

**Goal:** Enable NullVoid to run as a demo in GitHub Codespaces (100% free, no credit card) so contributors and reviewers can try the ML pipeline without local setup.

---

## Phase 1: Dev Container Setup

### 1.1 Create `.devcontainer` directory

```
.devcontainer/
├── devcontainer.json
└── Dockerfile (optional; use image if sufficient)
```

### 1.2 Base image

- Use `mcr.microsoft.com/devcontainers/javascript-node` (Node 20 LTS) or
- `ghcr.io/devcontainers/javascript-node` with Python feature
- Alternative: `mcr.microsoft.com/devcontainers/universal` (Node + Python + common tools)

### 1.3 Features to add

| Feature | Purpose |
|---------|---------|
| `ghcr.io/devcontainers/features/python` | Python 3.11+ for ML (scikit-learn, xgboost, fastapi) |
| `ghcr.io/devcontainers/features/git` | Already in base; ensure Git available |

### 1.4 `devcontainer.json` config

- **postCreateCommand:** Run once when Codespace is created
  - `npm install`
  - `pip install -r ml-model/requirements.txt`
  - `npm run build` (builds ts, api, dashboard)
- **forwardPorts:** `[3001, 5174, 8000]`
- **customizations:** VS Code extensions (optional: ESLint, Prettier, Python)
- **postStartCommand:** (optional) Echo reminder: "Run `make api` and `make dashboard` to start"

---

## Phase 2: Documentation

### 2.1 Add Codespaces section to README

- "Try in Codespaces" button (GitHub provides this when `.devcontainer` exists)
- Short "Codespaces demo" subsection:
  - Open repo in Codespaces
  - Run `make api` (terminal 1), `make dashboard` (terminal 2)
  - Open port 5174
  - ML page: Export → Train

### 2.2 Update `docs/DEPLOYMENT.md`

- Add "GitHub Codespaces (Demo)" section
- Clarify: Codespaces = demo/dev; Vercel = production deployment

---

## Phase 3: Optional Improvements

### 3.1 Startup script (optional)

- `scripts/codespaces-start.sh`: Start API + dashboard in background, print URLs
- Reduces manual steps for first-time users

### 3.2 Pre-commit / CI check (optional)

- Ensure `.devcontainer` is valid (e.g. `devcontainer validate` in CI)
- Low priority for demo use case

### 3.3 ML pre-trained models

- `train.jsonl` and `train-behavioral.jsonl` already in repo
- `model.pkl` / `behavioral-model.pkl` could be committed (if small) so demo works without running train
- Or: document that first Export+Train takes ~1–2 min

---

## Phase 4: Verification

### 4.1 Manual test

1. Push `.devcontainer` to repo
2. Click "Code" → "Codespaces" → "Create codespace on main"
3. Wait for postCreateCommand to finish
4. Run `make api` and `make dashboard`
5. Open forwarded port 5174
6. Verify: Scans page, ML page (Export, Train), Reports

### 4.2 Checklist

- [ ] `npm install` succeeds (better-sqlite3 compiles)
- [ ] `pip install -r ml-model/requirements.txt` succeeds
- [ ] `npm run build` succeeds
- [ ] API starts on 3001
- [ ] Dashboard proxies to API, loads on 5174
- [ ] ML Export / Train buttons work
- [ ] Port 5174 accessible via Codespaces URL

---

## File Changes Summary

| File | Action |
|------|--------|
| `.devcontainer/devcontainer.json` | Create |
| `.devcontainer/Dockerfile` | Optional (use features if image sufficient) |
| `README.md` | Add Codespaces subsection |
| `docs/DEPLOYMENT.md` | Add Codespaces section |
| `docs/CODESPACES-PLAN.md` | This plan |

---

## Effort Estimate

| Phase | Effort |
|-------|--------|
| Phase 1 (devcontainer) | 30–60 min |
| Phase 2 (docs) | 15 min |
| Phase 3 (optional) | 30 min |
| Phase 4 (verification) | 15 min |
| **Total** | ~1–2 hours |

---

## Out of Scope

- Production deployment on Codespaces (ephemeral, not 24/7)
- Turso in Codespaces (SQLite is fine for demo)
- Vercel config changes (unchanged)
