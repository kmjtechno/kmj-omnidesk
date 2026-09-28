# Contributing to KMJ OmniDesk

All implementation work must map to `ROADMAP.yaml`.

## Before changing code

1. Identify the milestone and exit criterion the change advances.
2. Preserve the direct-first, relay-fallback architecture.
3. Keep authentication, authorization, entitlement, and transport reachability separate.
4. Add or update tests for security-sensitive state transitions.
5. Do not introduce production secrets or signing material.
6. Do not publish performance or security claims without reproducible evidence.

## Change discipline

- Prefer small reviewable commits with one architectural purpose.
- Protocol changes must be version-aware.
- Permission expansion must be explicit and tested.
- New dependencies require maintenance, security, and license review.
- Performance changes require before/after measurement once the benchmark harness exists.
- Release-enabling changes remain fail-closed until the relevant roadmap gates pass.

## Definition of complete

Compilation alone is not completion. A roadmap item is complete only when its required artifact exists and every declared gate for that item passes.
