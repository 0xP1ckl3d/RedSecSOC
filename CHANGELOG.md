# Changelog

## 0.4.0 — 23 October 2026

- Classify multicast, private, loopback, link-local, shared, documentation, special-purpose and public-unicast addresses independently of inventory membership.
- Reject whole-rule Safe scopes. Require recorded host/behavior conditions, preserve changed/missing conditions for review, expose policy history, and audit disabling legacy overly broad Safe policies.
- Separate occurrences, estimated distinct patterns, bounded correlation candidates and open analyst investigations.
- Add evidence-backed process/session/flow components, bounded forward retrieval, cross-host session candidates, source-field proof and explicit atomic sequence preservation.
- Add host/rule/severity/disposition/assessment/protocol/port/address/time filters to Patterns & Indicators.
- Add an independent network-destination time slider, default 24 hours, exact UTC ranges and matching drill-through links.

## 0.3.0 — 23 October 2026

- Add an Overview landing page with activity/severity charts, prioritized records, recurring detections, network destinations and collection health.
- Make overview and topology record-type counts navigable; preserve exact time, severity, rule and endpoint filters on drill-through.
- Replace latest-event pattern cards with full-window rule aggregates and nested host/file/signature/check breakdowns. Retain sampled stable activity and changing hashes as evidence.
- Add destination flow/byte/source concentration, service/port/name summaries and source fan-out.
- Add audited persistent Safe/Suspicious scopes, Include safe, revocation and suspicious-over-safe precedence; preserve source records and original severity.

## 0.2.0 — 23 October 2026

- Preserve queue state, pagination and scroll when returning from detail views; refresh rows without resetting controls.
- Add field-based contextual assessment, explicit caveats and source references.
- Add bounded recurring-pattern grouping, material variant separation and audited analyst assessments.
- Add evidence stages, strengthen process-GUID validation and expose source-type coverage observations.
- Recompute preserved source digests and reject conflicting duplicate snapshots.
- Replace lab-specific topology and frontend links with external deployment configuration and a generic graph.
- Add a reusable Ubuntu/systemd installer, explicit account setup, locked dependencies, tests, documentation, CI and publication checks.

## 0.1.0

Initial investigation console over Wazuh alert/archive indices, with cases, source preservation, normalized evidence, process views, search, network enrichment/filtering, container image summaries, clear/Undo actions, themes and an initial lab-specific topology.
