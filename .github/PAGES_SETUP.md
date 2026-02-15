# GitHub Pages Setup for NullVoid

This guide configures [GitHub Pages](https://docs.github.com/en/pages/quickstart) for the NullVoid project site.

## Enable GitHub Pages

1. Go to **Settings** → **Pages** in the NullVoid repository.
2. Under **Build and deployment** → **Source**, select **GitHub Actions**.

Once enabled, the [pages.yml](.github/workflows/pages.yml) workflow will build and deploy the dashboard on every push to `main` or `master`.

## Site URL

After the first successful deployment:

- **Project site**: `https://kurt-grung.github.io/NullVoid/`

## What Gets Deployed

The **NullVoid Dashboard** (React + Vite) from `packages/dashboard/` is built and deployed. It includes:

- Executive overview
- Scans list and detail
- Compliance view

## API Configuration

The dashboard on GitHub Pages is static. API calls use `/api` by default (for local dev with proxy). On Pages, there is no backend, so:

- **Without API**: The UI loads but scan/org/team requests will fail (expected).
- **With API**: Set `VITE_API_URL` in the workflow to your deployed API URL to connect to a live NullVoid API.

To use a deployed API, add to the workflow:

```yaml
- name: Build dashboard for Pages
  run: npm run dashboard:build
  env:
    VITE_BASE: /NullVoid/
    VITE_API_URL: https://your-api.example.com  # optional
```

## Manual Deploy

Trigger a deploy manually: **Actions** → **Deploy to GitHub Pages** → **Run workflow**.

## Troubleshooting

- **404 on refresh**: Client-side routing is handled; ensure `base` is `/NullVoid/` in the build.
- **Assets not loading**: Check that `VITE_BASE` is set correctly in the workflow.
- **First deploy**: It may take a few minutes. Check the **Actions** tab for status.
