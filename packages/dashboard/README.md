# NullVoid Dashboard

Web dashboard for NullVoid security scans. Consumes the REST API for executive metrics, scan details, and compliance views.

## Setup

1. Start the NullVoid API (from repo root):
   ```bash
   npm run api:start
   ```
   The API runs on port 3000 by default. Use `NULLVOID_API_PORT=3003` if 3000 is in use.

2. Start the dashboard:
   ```bash
   npm run dashboard:dev
   ```
   If the API runs on a different port, set the proxy target:
   ```bash
   API_PROXY_TARGET=http://localhost:3003 npm run dashboard:dev
   ```

3. Open http://localhost:5174 (or the port Vite prints if 5174 is in use)

## Views

- **Executive**: High-level metrics (total scans, threats, severity distribution, top packages)
- **Scans**: List scans, trigger new scans
- **Scan Detail**: Per-scan results, threat list, risk breakdown
- **Compliance**: Control coverage by C/I/A category, gap analysis for SOC 2 / ISO 27001
