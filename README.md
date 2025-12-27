# server-migration-readiness

A framework to assess **server migration readiness** by collecting signals across compute, storage, network, identity, application dependencies, and operational riskthen producing a standardized **readiness score**, **blockers list**, and **migration recommendations**.

## What this repo is (and is not)

- **Is:** Read-only assessment + reporting framework (safe for production).
- **Is not:** A migration tool. It does not move workloads or make changes by default.

## Outputs (deliverables)

- Per-server readiness score with explanation
- Blockers list (hard stops vs. risks)
- Dependency summary (what the server depends on / what depends on it)
- Exportable artifacts: CSV / JSON / Markdown summaries

## Repository layout

- docs/ Architecture, scoring model, workflows
- configs/ Weights, rules, signatures (example config files)
- src/ Collectors, analyzers, scoring, exporters, orchestration
- samples/ Sample inputs/outputs to review without running
- 	ests/ Unit and integration tests

## Design principles

- Config-driven rules (avoid hardcoded logic)
- Explainable scoring (no black box)
- Separation of concerns: collect  analyze  score  export
- Read-only by default