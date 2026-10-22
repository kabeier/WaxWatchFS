# WaxWatchFS

WaxWatch helps record collectors discover good listings faster: users save watch rules, the backend searches supported marketplaces, and the web app shows matches and notifications.

This is the full-stack monorepo. Each project keeps its own README, tooling, and changelog.

| Folder | What | Stack | Details |
| --- | --- | --- | --- |
| [`backend/`](backend/) | WaxWatch API | Python 3.12, FastAPI, Postgres, Redis/Celery | [backend/README.md](backend/README.md), [CONTRIBUTING](backend/CONTRIBUTING.md) |
| [`frontend/`](frontend/) | WaxWatch Web | Next.js, TypeScript | [frontend/README.md](frontend/README.md) |

## Local development

Backend (API docs at `http://localhost:8000/docs`):

```bash
cd backend
python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt && .venv/bin/pip install -e .
make up        # API + Redis + Postgres via Docker Compose
make migrate
```

Frontend:

```bash
cd frontend
cp .env.example .env
npm install    # also installs the repo's git hooks
npm run dev
```

## Git hooks

Hooks live in [`.husky/`](.husky/) and are installed by `npm install` in `frontend/` (or `make pre-commit-install` in `backend/`). They only run checks for the side of the repo you touched:

- **pre-commit**: `lint-staged` for staged `frontend/` files; `make lint fmt-check typecheck` for staged `backend/` files.
- **pre-push**: `make ci-local` when the pushed commits touch `backend/` (needs Docker).

Skip once with `HUSKY=0 git commit ...` or `HUSKY=0 git push ...`.

## CI

Workflows live in [`.github/workflows/`](.github/workflows/) and are path-filtered, so each project's CI runs only when its folder changes:

| Workflow | Runs on |
| --- | --- |
| `backend-ci.yml` | `backend/**` changes: static/policy checks, then DB-backed tests with coverage |
| `backend-security.yml` | CodeQL for Python |
| `backend-dependency-audit.yml` | `pip-audit` on requirements changes and weekly |
| `backend-smoke.yml`, `backend-release-gates.yml` | Manual or scheduled k6 performance smoke and release gates |
| `frontend-ci.yml` | `frontend/**` changes: typecheck, lint, unit, build, e2e, a11y |
| `secrets-scan.yml` | Every push and PR, whole repo (Gitleaks) |

Dependabot ([`.github/dependabot.yml`](.github/dependabot.yml)) covers pip in `backend/`, npm in `frontend/`, and GitHub Actions.

## History

This repo combines [kabeier/WaxWatch-api](https://github.com/kabeier/WaxWatch-api) (now `backend/`) and [kabeier/WaxWatch-web](https://github.com/kabeier/WaxWatch-web) (now `frontend/`), with both projects' full `main` history preserved. Use `git log --follow <path>` to trace a file back through the original repos.
