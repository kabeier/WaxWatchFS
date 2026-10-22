# Contracts

Place the following in this folder (committed):

- `openapi.snapshot.json` (pinned backend schema snapshot)
- optionally: `openapi.yaml` or `openapi.json` if you maintain a non-snapshot “current” copy

Everything in the frontend should reference the snapshot to avoid drift.

`openapi.snapshot.json` is a verbatim copy of `backend/docs/openapi.snapshot.json` (as is
`reference/openapi.snapshot.json`). Refresh it by running `make openapi-snapshot` in `backend/`
and copying the file here unchanged. It is excluded from Prettier, and the repo-root
`.github/workflows/contract-sync.yml` fails if it drifts from the backend file.

Companion behavior contract:

- `docs/FRONTEND_API_CONTRACT.md`
