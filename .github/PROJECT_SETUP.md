# GitHub Project Setup for NullVoid

Use [GitHub Projects](https://docs.github.com/en/issues/planning-and-tracking-with-projects) to track the [Advanced Roadmap](../docs/ADVANCED_ROADMAP.md).

## Create the project

1. **Open Projects**
   - Repo: https://github.com/kurt-grung/NullVoid/projects
   - Or: Repo → **Projects** tab → **New project**

2. **Choose a template**
   - **Board** – Kanban-style (recommended)

3. **Columns (Kanban)**

   | Column        | Purpose                          |
   |---------------|-----------------------------------|
   | **Backlog**   | Ideas, future work                |
   | **Roadmap**   | Planned for upcoming phases       |
   | **In progress** | Actively being worked on       |
   | **In review** | PR open, awaiting review          |
   | **Done**      | Shipped or closed                 |

4. **Custom fields**

   | Field | Values |
   |-------|--------|
   | **Phase** | `0`, `1`, `2`, `3`, `4`, `5` |
   | **Pillar** | `detection`, `ml`, `enterprise`, `dashboard`, `trust`, `tech-debt`, `test` |
   | **Exit criterion** | Free text from [ADVANCED_ROADMAP.md](../docs/ADVANCED_ROADMAP.md) |

5. **Project views**
   - **By phase** — group by Phase field
   - **By pillar** — group by Pillar field
   - **Priority** — filter `priority: high` label

6. **Connect to repository**
   - Project settings → **Manage** → Add **NullVoid** repository

## Automation (Cursor)

In Cursor, run **`/do`** to list open project tasks, or **`/do next`** to pick the next epic, implement, and open a PR. Commits from `/do` include `Co-authored-by: Kurt Grüng <krgrung@gmail.com>`.

Scripts (from repo root):

```bash
bash .github/scripts/roadmap/list-open-tasks.sh
bash .github/scripts/roadmap/pick-next-task.sh
```

Requires `gh auth refresh -h github.com -s project,read:project`.

## Labels

| Label | Color | Use for |
|-------|-------|---------|
| `bug` | #d73a4a | Bug reports |
| `enhancement` | #a2eeef | Feature requests |
| `roadmap` | #7057ff | Roadmap epics |
| `documentation` | #0075ca | Docs only |
| `test` | #0e8a16 | Tests / perf / E2E |
| `tech-debt` | #fbca04 | Foundation / cleanup |
| `detection` | #1d76db | Phase 1 detection |
| `ml` | #5319e7 | Phase 2 ML |
| `enterprise` | #006b75 | Phase 3 platform |
| `dashboard` | #c5def5 | Phase 4 UX |
| `trust` | #bfe5bf | Phase 5 trust/policy |
| `phase:0` … `phase:5` | #7057ff | Phase tag |
| `priority: high` | #b60205 | Urgent |
| `priority: low` | #0e8a16 | Low priority |
| `good first issue` | #7057ff | Beginner-friendly |

## Epic issues (batch)

Create one issue per row; add to project **Roadmap** column.

| Epic | Phase | Pillar | Labels |
|------|-------|--------|--------|
| Retire js/ workspace | 0 | tech-debt | `roadmap`, `phase:0`, `tech-debt` |
| Implement Redis L3 cache | 0 | tech-debt | `roadmap`, `phase:0`, `enhancement` |
| Remote npm package scanning | 0 | detection | `roadmap`, `phase:0`, `detection` |
| E2E tests (dashboard + API) | 0 | test | `roadmap`, `phase:0`, `test` |
| Performance regression suite | 0 | test | `roadmap`, `phase:0`, `test` |
| Custom rule engine | 1 | detection | `roadmap`, `phase:1`, `detection` |
| Supply chain risk propagation | 1 | detection | `roadmap`, `phase:1`, `detection` |
| Interactive dependency tree enrichment | 1 | detection | `roadmap`, `phase:1`, `detection` |
| Zero-day heuristic fusion | 1 | detection | `roadmap`, `phase:1`, `detection` |
| Composite C/I/A risk in reports | 1 | detection | `roadmap`, `phase:1`, `enterprise` |
| Embedded ML scoring | 2 | ml | `roadmap`, `phase:2`, `ml` |
| Model versioning & registry | 2 | ml | `roadmap`, `phase:2`, `ml` |
| ML drift alerts in dashboard | 2 | ml | `roadmap`, `phase:2`, `ml`, `dashboard` |
| Feedback → retrain pipeline | 2 | ml | `roadmap`, `phase:2`, `ml` |
| Behavioral enterprise analytics | 2 | ml | `roadmap`, `phase:2`, `ml` |
| NLP review analysis | 2 | ml | `roadmap`, `phase:2`, `ml` |
| Background job runner | 3 | enterprise | `roadmap`, `phase:3`, `enterprise` |
| Scheduled scans API + UI | 3 | enterprise | `roadmap`, `phase:3`, `enterprise`, `dashboard` |
| Webhooks for scan events | 3 | enterprise | `roadmap`, `phase:3`, `enterprise` |
| SSE real-time scan status | 3 | enterprise | `roadmap`, `phase:3`, `enterprise`, `dashboard` |
| Audit log + RBAC | 3 | enterprise | `roadmap`, `phase:3`, `enterprise` |
| GraphQL API | 3 | enterprise | `roadmap`, `phase:3`, `enterprise` |
| Client SDKs (TypeScript + Python) | 3 | enterprise | `roadmap`, `phase:3`, `enterprise` |
| Scan comparison view | 4 | dashboard | `roadmap`, `phase:4`, `dashboard` |
| Dependency tree visualization | 4 | dashboard | `roadmap`, `phase:4`, `dashboard`, `detection` |
| Notifications / alerts UI | 4 | dashboard | `roadmap`, `phase:4`, `dashboard` |
| Dashboard UX polish (Phase 5) | 4 | dashboard | `roadmap`, `phase:4`, `dashboard` |
| Web configuration UI | 4 | dashboard | `roadmap`, `phase:4`, `dashboard` |
| VS Code extension v2 | 4 | dashboard | `roadmap`, `phase:4`, `enhancement` |
| Rule marketplace | 4 | dashboard | `roadmap`, `phase:4`, `enhancement` |
| On-chain policy enforcement | 5 | trust | `roadmap`, `phase:5`, `trust` |
| Trust network expansion | 5 | trust | `roadmap`, `phase:5`, `trust` |
| Plugin API | 5 | trust | `roadmap`, `phase:5`, `enhancement` |
| Compliance automation | 5 | enterprise | `roadmap`, `phase:5`, `enterprise` |

## Issue template (copy per epic)

```markdown
## Summary
<one-line goal>

## Phase
<0–5> — <phase name from ADVANCED_ROADMAP.md>

## Pillar
<detection | ml | enterprise | dashboard | trust | tech-debt | test>

## Exit criterion
<from ADVANCED_ROADMAP.md phase section>

## Key files
- `path/to/file`

## Depends on
- #issue or none
```

### Example: Phase 0 — Retire js/ workspace

```markdown
## Summary
Retire the legacy `js/` workspace; consumers use `ts/dist` only.

## Phase
0 — Foundation

## Pillar
tech-debt

## Exit criterion
- `js/` removed or archived
- `npm test` runs ts + api only
- README and publish config point to TypeScript build

## Key files
- `js/`, `package.json`, `turbo.json`, `docs/TYPESCRIPT_MIGRATION_TODO.md`
```

### Example: Phase 3 — Webhooks

```markdown
## Summary
Add webhook delivery for scan lifecycle events with HMAC signing.

## Phase
3 — Enterprise platform

## Pillar
enterprise

## Exit criterion
- `POST /webhooks` register endpoint
- Events: scan.completed, scan.failed, threat.critical
- Retries with exponential backoff
- Documented in API.md

## Key files
- `packages/api/src/enterprise/`
```

## Workflow

1. **Bugs** — [Bug report](.github/ISSUE_TEMPLATE/bug_report.md)
2. **Features** — [Feature request](.github/ISSUE_TEMPLATE/feature_request.md)
3. **Roadmap epics** — template above + `roadmap` label + project column
4. **PRs** — [PR template](.github/PULL_REQUEST_TEMPLATE.md); link issues

## Quick links

- **Create project**: https://github.com/kurt-grung/NullVoid/projects/new
- **Issues**: https://github.com/kurt-grung/NullVoid/issues (epics #22–#41)
- **Advanced roadmap**: [docs/ADVANCED_ROADMAP.md](../docs/ADVANCED_ROADMAP.md)
- **Release roadmap**: [docs/ROADMAP.md](../docs/ROADMAP.md)

### GitHub CLI project board

**Why the projects page is empty:** GitHub Projects v2 requires the `project` OAuth scope. Epic issues **#22–#41** were created, but the board itself could not be created from CI/automation without that scope.

**One-time setup (run in your terminal — opens browser for auth):**

```bash
gh auth refresh -h github.com -s project,read:project
bash .github/scripts/setup-roadmap-project.sh
```

Or manually:

```bash
gh auth refresh -h github.com -s project,read:project
gh project create --owner kurt-grung --title "NullVoid Advanced Roadmap"
gh project link <NUMBER> --owner kurt-grung --repo kurt-grung/NullVoid
```

Then add issues [#22–#41](https://github.com/kurt-grung/NullVoid/issues?q=label%3Aroadmap) to columns: Backlog → Roadmap → In progress → In review → Done.
