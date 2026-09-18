# ADCP Controller

ADCP (AI Development Control Plane) is a cross-project Development Execution
Controller.

## Current operational state

The MVP-A Control Store cutover is complete. The current production authority
baseline, verified on 2026-08-13, is:

- Machine Development State Authority: Development Control Store
- Authority mode: `CONTROL_STORE_AUTHORITY`
- Authority generation: `2`
- Production schema version: `3`
- Cutover ID: `adcp-cut-3-20260813-r5-go-v1`

Git remains the implementation source of truth. GitHub is the remote, review,
and CI evidence plane. Notion remains the governance, specification, decision,
and human-readable projection plane; Registry or Handoff content is not an
alternative machine-state authority.

The repository now includes the MVP-A controller and SQLite Control Store,
leases and fencing, idempotent transitions, runner/evaluator boundaries,
recovery/resume behavior, authority transition guards, and forward-only Notion
projection support. Frozen bootstrap and cutover records remain historical
evidence and must not be rewritten to look current.

## Out of scope

ADCP does not own the following business runtimes or domains:

- PropertyAI business runtime
- Cleaner business domain
- Application Gate business commands
- DKATE scanning runtime
- Telegram operational actions
- Gmail operational actions

Historical note: during the initial repository bootstrap phase, the package
contained only the bootstrap baseline. At that time, the MVP-A Controller,
Control Store, SQLite persistence, leases, fencing, agent runners, evaluators,
and Notion projection had not yet been implemented.
