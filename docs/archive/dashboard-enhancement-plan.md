# NullVoid Dashboard Enhancement Plan

A phased plan to extend the dashboard with the suggested features. Each phase is ordered by impact and effort.

---

## Phase 1: Quick Wins (1–2 days)

### 1.1 Report link on Scan Detail
**Effort:** ~30 min  
**Files:** `packages/dashboard/src/views/ScanDetail.tsx`, `packages/dashboard/src/api.ts`

- Add "View HTML" and "Download MD" buttons when `scan.status === 'completed'`
- Use existing `getReportUrl(scan.id, format, compliance?)`
- Optional: compliance dropdown (None, SOC 2, ISO 27001)

### 1.2 Threat type breakdown on Executive
**Effort:** ~1 hr  
**Files:** `packages/dashboard/src/views/Executive.tsx`

- Aggregate threat types from completed scans (e.g. `DEPENDENCY_CONFUSION`, `WALLET_HIJACKING`)
- Add a card "Threats by Type" with top 8–10 types and counts
- Reuse existing `getScans` + `getScan` pattern

### 1.3 Scan filters
**Effort:** ~1 hr  
**Files:** `packages/dashboard/src/views/Scans.tsx`

- Add filter controls: status (all/completed/failed/running), date range (last 7/30/90 days), target search
- Filter client-side from `scans` state
- Optional: persist filter in URL query params

### 1.4 Threat detail expansion
**Effort:** ~1 hr  
**Files:** `packages/dashboard/src/views/ScanDetail.tsx`

- Make each threat row expandable (click or chevron)
- Show: `filePath`, `lineNumber`, `confidence`, `details`, `sampleCode` when expanded
- Use `<details>` or collapsible div with Tailwind

---

## Phase 2: Multi-tenant & Settings (1–2 days)

### 2.1 Organizations & Teams selector
**Effort:** ~2 hr  
**Files:** `packages/dashboard/src/App.tsx`, new `OrgTeamContext.tsx`, `api.ts`

- Create context for `organizationId` and `teamId`
- Add dropdown(s) in nav or a header bar
- Pass headers to `getScans`, `getScan`, `triggerScan`, etc.
- Show "All" option when no org/team selected

### 2.2 Settings page
**Effort:** ~2 hr  
**Files:** new `packages/dashboard/src/views/Settings.tsx`, `App.tsx`, `api.ts`

- Route: `/settings`
- Sections:
  - **API Key** (optional): input, stored in `localStorage`, sent as `X-API-Key` when set
  - **Default scan target**: e.g. `.` or custom path
  - **Theme**: already exists; move to Settings or keep in nav
- Add nav link "Settings"

### 2.3 API health / connection status
**Effort:** ~45 min  
**Files:** `packages/dashboard/src/api.ts`, `App.tsx` or shared layout

- Add `getHealth(): Promise<{ ok: boolean }>` calling `GET /health`
- Poll every 30–60s or show on load
- Display: green dot + "Connected" or red + "API unavailable" in nav/footer

---

## Phase 3: Analytics & Export (1–2 days)

### 3.1 Scan trends chart
**Effort:** ~2 hr  
**Files:** new `packages/dashboard/src/views/Trends.tsx`, `App.tsx`

- Route: `/trends`
- Data: scans over time (group by day), threats per scan
- Use a simple chart lib (e.g. Recharts, Chart.js) or CSS bar chart
- Fetch `getScans` with higher limit, aggregate by date

### 3.2 Export scans to CSV
**Effort:** ~1 hr  
**Files:** `packages/dashboard/src/views/Scans.tsx`

- Button "Export CSV"
- Columns: id, target, status, createdAt, completedAt, threatsFound (from detail if needed)
- Client-side CSV generation and download

### 3.3 Search across scans and threats
**Effort:** ~2 hr  
**Files:** new `packages/dashboard/src/components/Search.tsx`, or integrate into Scans/Executive

- Global search bar in nav
- Search: scan target, threat message, threat type, package name
- Results: list of matching scans and threats with links

---

## Phase 4: Advanced Features (2–3 days)

### 4.1 Scan comparison
**Effort:** ~3 hr  
**Files:** new `packages/dashboard/src/views/ScanCompare.tsx`, `App.tsx`

- Route: `/scans/compare?id1=xxx&id2=yyy` or picker UI
- Side-by-side: metrics, risk, threat counts by type/severity
- Diff-style view: threats only in A, only in B, in both

### 4.2 Dependency tree view
**Effort:** ~3 hr  
**Files:** `packages/dashboard/src/views/ScanDetail.tsx` or new `DependencyTree.tsx`

- Use `scan.result.dependencyTree` if available
- Render tree (collapsible nodes) or simple indented list
- Link nodes to threats when applicable

### 4.3 Notifications / alerts
**Effort:** ~2 hr (UI only; backend TBD)  
**Files:** new `packages/dashboard/src/components/NotificationBell.tsx`

- Poll for recent scans; show badge when new completed/failed
- Optional: toast when scan completes (if user triggered it in same session)
- Backend: would need webhooks or SSE for real-time

### 4.4 Scheduled scans (API + UI)
**Effort:** ~1 day  
**Files:** `packages/api`, new `packages/dashboard/src/views/Schedules.tsx`

- **API:** `POST /schedule`, `GET /schedules`, `DELETE /schedule/:id` (cron-like or queue)
- **Dashboard:** list schedules, add/edit/delete, show next run
- Requires background job runner (e.g. node-cron, Bull, or Vercel cron)

---

## Phase 5: Polish & UX (1 day)

### 5.1 Breadcrumbs
**Effort:** ~30 min  
**Files:** new `packages/dashboard/src/components/Breadcrumbs.tsx`, each view

- Scans → Scan: foo  
- Reports, etc.

### 5.2 Loading skeletons
**Effort:** ~1 hr  
**Files:** `packages/dashboard/src/index.css`, each view

- Replace "Loading..." with skeleton placeholders
- Match card/metric layout

### 5.3 Empty states
**Effort:** ~30 min  
**Files:** each view

- Consistent empty state: icon, message, CTA (e.g. "Run your first scan")

### 5.4 Keyboard shortcuts
**Effort:** ~45 min  
**Files:** `packages/dashboard/src/App.tsx` or `useKeyboardShortcuts.ts`

- `g` then `e` → Executive, `g` `s` → Scans, etc.
- `?` to show shortcuts modal

---

## Implementation Order (Recommended)

| # | Feature                    | Phase | Est. |
|---|----------------------------|-------|------|
| 1 | Report link on Scan Detail | 1     | 30m  |
| 2 | Threat type breakdown      | 1     | 1h   |
| 3 | Scan filters               | 1     | 1h   |
| 4 | Threat detail expansion    | 1     | 1h   |
| 5 | API health status          | 2     | 45m  |
| 6 | Settings page              | 2     | 2h   |
| 7 | Org/Team selector         | 2     | 2h   |
| 8 | Export CSV                 | 3     | 1h   |
| 9 | Scan trends                | 3     | 2h   |
|10 | Search                     | 3     | 2h   |
|11 | Scan comparison            | 4     | 3h   |
|12 | Dependency tree            | 4     | 3h   |
|13 | Breadcrumbs                | 5     | 30m  |
|14 | Loading skeletons          | 5     | 1h   |
|15 | Empty states               | 5     | 30m  |

---

## Dependencies

- **Chart library** (Phase 3): Add `recharts` or `chart.js` + `react-chartjs-2`
- **Scheduled scans** (Phase 4): Backend job runner; consider Vercel Cron for serverless

---

## API Additions (if needed)

| Endpoint              | Purpose                    | Phase |
|-----------------------|----------------------------|-------|
| `GET /health`         | Health check               | 2     |
| `GET /schedules`      | List scheduled scans       | 4     |
| `POST /schedule`      | Create schedule            | 4     |
| `DELETE /schedule/:id`| Remove schedule            | 4     |

---

## Notes

- All Phase 1–2 features use existing API; no backend changes.
- Phase 3–4 may need minor API tweaks (e.g. `limit` for trends).
- Phase 4.4 (scheduled scans) is the only feature requiring significant backend work.
