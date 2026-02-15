# GitHub Project Setup for NullVoid

Use [GitHub Projects](https://docs.github.com/en/issues/planning-and-tracking-with-projects) to track roadmap items, bugs, and updates.

## Create the project

1. **Open Projects**
   - Repo: https://github.com/kurt-grung/NullVoid/projects
   - Or: Repo → **Projects** tab → **New project**

2. **Choose a template**
   - **Board** – Kanban-style (recommended)
   - Or start from scratch

3. **Suggested columns (Kanban)**

   | Column        | Purpose                          |
   |---------------|-----------------------------------|
   | **Backlog**   | Ideas, future work                |
   | **Roadmap**   | Planned for upcoming releases     |
   | **In progress** | Actively being worked on       |
   | **In review** | PR open, awaiting review          |
   | **Done**      | Shipped or closed                 |

4. **Connect to repository**
   - Project settings → **Manage** → Add **NullVoid** repository
   - New issues and PRs will appear in the project

5. **Add roadmap items**
   - Create issues from [docs/ROADMAP.md](../docs/ROADMAP.md)
   - Label: `roadmap`, `enhancement`, `bug`, etc.
   - Add to the appropriate column

## Suggested labels

Create these labels in **Settings → Labels**:

| Label       | Color   | Use for                    |
|------------|---------|----------------------------|
| `bug`      | #d73a4a | Bug reports                |
| `enhancement` | #a2eeef | Feature requests         |
| `roadmap`  | #7057ff | Roadmap items              |
| `documentation` | #0075ca | Docs only              |
| `good first issue` | #7057ff | Beginner-friendly     |
| `priority: high` | #b60205 | Urgent                 |
| `priority: low` | #0e8a16 | Low priority           |

## Workflow

1. **Bugs** – Use the [Bug report](.github/ISSUE_TEMPLATE/bug_report.md) template.
2. **Features** – Use the [Feature request](.github/ISSUE_TEMPLATE/feature_request.md) template.
3. **Roadmap** – Create issues for roadmap items and add them to the project.
4. **PRs** – Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md); link to issues.

## Quick links

- **Create project**: https://github.com/kurt-grung/NullVoid/projects/new
- **Issues**: https://github.com/kurt-grung/NullVoid/issues
- **Roadmap**: [docs/ROADMAP.md](../docs/ROADMAP.md)
