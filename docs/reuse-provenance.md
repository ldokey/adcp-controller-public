# Reuse provenance

ADCP is a standalone runtime. The repositories below are pattern provenance
only and are never runtime import dependencies.

## Primary pattern reference

- Repository: `/Users/kate/PropertyAI/openclaw-workspace`
- Commit: `7bf113f1938fc91d3bb9321e32b25514a47b211f`
- Usage: `PATTERN_PROVENANCE_ONLY`

Patterns that may be evaluated in a later frozen contract:

- transaction boundary
- idempotency
- lease
- state transition audit
- migration registry
- recovery
- deterministic tests

No PropertyAI package, schema, or business-domain code is a runtime dependency
of ADCP.

## Secondary pattern reference

- Repository: `/Users/kate/DKATE/dkate-control-python`
- Committed reference: `099f8cf4afcbc36636b541390c36ced5158221c0`
- Usage: `SECONDARY_PATTERN_PROVENANCE`

Phase 8P-3 dirty/untracked worktree content is **not reproducible committed
provenance**. Dirty-only source must not be copied into ADCP.
