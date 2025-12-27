# Architecture

## Modules
- Collectors: gather raw facts without interpretation
- Analyzers: infer dependencies and risk signals
- Blockers Engine: rules-based findings (hard stops vs risks)
- Scoring: explainable readiness scoring
- Exporters: CSV/JSON/MD outputs (optional graphs)

## Data flow
Collector output  analyzers  blockers + scoring  exporters