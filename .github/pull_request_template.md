<!-- Fill in the section for the side(s) of the repo this PR touches; delete the other. -->

# Backend (`backend/`)

### Summary

- Describe the change.
- Link related issues/tickets.

### Validation

- [ ] I ran relevant local checks (lint/tests/typecheck/CI parity targets).
- [ ] `make lint` and `make fmt-check` both passed locally (or in equivalent CI-parity workflow).

### Governance sync checklist (required when tests/CI/Make/env vars are affected)

- [ ] `.env.sample` updated with non-secret defaults and environment notes (required only when env vars are added/removed or defaults change).
- [ ] `Makefile` updated to reflect command/test workflow changes.
- [ ] `.github/workflows/backend-ci.yml` updated to reflect CI workflow changes.
- [ ] `CONTRIBUTING.md` updated with policy/process changes.
- [ ] `CHANGELOG.md` updated for API/runtime/migration-affecting behavior changes (or N/A with reason: `...`).
- [ ] `docs/DEPLOYMENT.md` updated (or N/A).
- [ ] `docs/FRONTEND_API_CONTRACT.md` updated (or N/A).

### Notes

- Include rollout, migration, or follow-up tasks if needed.

# Frontend (`frontend/`)

### Summary

- Describe what changed and why.

### Validation checklist

- [ ] Added or updated tests for every behavior change.
- [ ] `npm run format:check`
- [ ] `npm run lint`
- [ ] `npm run test:coverage`

### Route matrix status-change evidence (required when `README.md` route statuses change)

- Routes changed:
  - [ ] Listed each affected route path exactly as shown in `README.md`.
- Status transition:
  - [ ] Documented current status -> target status for each route.
- Status criteria evidence (map to `README.md` definitions):
  - [ ] `scaffold`: Route is placeholder-first/synthetic-state driven and not yet API-wired.
  - [ ] `wired-minimum`: Real query/mutation wiring exists, with baseline validation + pending/error handling.
  - [ ] `production-ready`: Complete UX polish demonstrated.
  - [ ] `production-ready`: Robust error + retry behavior (including cooldown handling where applicable) demonstrated.
  - [ ] `production-ready`: Accessibility coverage validated.
  - [ ] `production-ready`: Route-level tests were added/updated in this PR.

### Design-guide intake checklist (required when UI/design guide updates are included)

- [ ] Source design links captured:
  - [ ] Figma/library/component spec links
  - [ ] Token dictionary/source links
  - [ ] Accessibility/content standards links
  - [ ] Design/engineering changelog links
- [ ] Token mapping documented (spacing/typography/colors).
- [ ] Affected shared primitives/components listed (`src/components/ui/primitives/state` and `src/components/ui/primitives/shell`).
- [ ] Rollout order documented and followed: tokens -> shared primitives -> route pages -> cleanup.

### SSE merge requirements (only if this PR touches SSE behavior)

Reference: `docs/SSE_MODEL.md` -> **SSE done criteria**

- [ ] Requests include `Authorization: Bearer <jwt>` and `Accept: text/event-stream`.
- [ ] Client keeps a singleton SSE connection per authenticated session.
- [ ] Reconnect uses exponential backoff with jitter after transient disconnects.
- [ ] Reconnect stops when auth token is missing or server returns 401/403.

### Risk and rollout

- [ ] Low risk
- [ ] Requires special rollout steps (describe below)

### Notes

- Any follow-up tasks or known limitations.
