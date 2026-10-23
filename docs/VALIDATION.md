# Version 0.4 validation

65 Python tests cover address categories, narrow Safe scopes, changed/missing conditions, audited legacy-scope disabling, exact query construction, positive multi-host process/session/network reconstruction, wrong-port/time/host/protocol negatives, PID/GUID namespace isolation, builtin-session and conflicting Logon GUID rejection, shared-broker boundaries, tuple reuse and atomic digest preservation.

Four frontend tests include an App component workflow covering the independent network slider and fixed ranges, filter propagation to network patterns, correlation candidate drill-through, sequence-preservation requests and existing queue navigation/Back state. Production assets build successfully. Browser automation is disabled on this host; component rendering and live API checks do not substitute for a visual browser review.

Live API checks on retained evidence confirmed multicast classification, exact 15/60-minute network drill-through totals, matching network/detection filters, rejection of a whole-rule Safe request and agreement between the real index regexp and Python policy-test matching. No real detection was marked Safe. A retained endpoint process was linked to sensor flow observations; its missing retained creation/remote-execution evidence was not invented. The bounded candidate review returned evidence-linked components and remained explicitly partial. All existing SOC services were healthy, with console memory observed below 100 MB. Deployment-specific counts/reports remain outside Git.

A complete independent end-to-end attack sequence has **not** been proven on live data. Synthetic positive and negative sequences verify the matching logic; retained-data checks verify the available process/network associations. Further controlled purple-team validation must document expected links and gaps rather than equate a connected component with compromise.

## Previous releases

# UX and pattern validation — 0.3.0

The 23 October 2026 UX pass adds an overview, exact drill-through links, full-window recurring summaries, network traffic concentration and persistent Safe/Suspicious scopes. Fifty-two backend tests and four frontend tests cover the current source. Component navigation checks include landing-page record-type links, queue state retention, a single aggregated integrity-change row and explicit dismissal scope. Live checks validated record-type counts for all 17 observed types, exact severity bands, exact destination flow links, ranking orders, and policy behavior.

In the checked window, thousands of rule-550 changes appeared as one summary rather than one card per changing checksum. Stable activity detail remained separately sampled and labelled. A labelled benign validation alert was temporarily marked Safe, included via Include safe, marked Suspicious, and restored; no real detections were marked safe for testing. A viewer policy write was denied. Original severity was retained. Scope boundary tests cover changed hashes, other hosts/files, sensor signatures, configuration checks, IP/port/source constraints and revocation.

Deployment-specific acceptance reports remain outside Git. Browser automation is disabled in this environment; component rendering, build and live API validation do not replace a fresh visual/browser review. Network volume, signature detections and analyst decisions are review signals, not automatic confirmed-compromise verdicts. See Investigation semantics for count, sampling, policy and attribution limits.

## Previous investigation validation


Version 0.2 was validated on 23 October 2026 with an existing Ubuntu/Wazuh deployment. No new offensive sequence or endpoint execution was required for the review changes.

## Automated checks

- 42 Python unit tests cover normalization, GUID host scoping/PID reuse, source preservation, static decoding, task/script handling, container/network summaries, query construction, disposition conflicts/Undo, contextual assessments, material grouping variants, digest tampering and duplicate conflicts, topology portability and source coverage semantics.
- Four frontend tests cover theme/selection helpers and actual App component navigation. The navigation regression opens details from alert and network queues and checks search, severity/disposition/host, protocol/port, page and scroll retention on Back.
- Production Vite build and pinned dependency installation.
- Systemd unit validation and an in-place installer upgrade with preserved users/database/configuration.

## Live acceptance evidence

API checks on existing retained events verified:

- A PowerShell policy-test alert kept its original level 15 while receiving field-based contextual interpretation.
- `sdbinst.exe` alerts retained level 12 and were separated into material variants; 24 matching records formed eight groups in the checked window.
- Retrieved GUID process graphs contained recorded parent links and explicitly missing creation records. Authentication, process, network and object stages had observations; managed-runtime observations were absent in these examples and were not invented.
- Coverage returned 16 known source hosts, six identified Windows hosts and separate source-type observations.
- Configured topology produced 14 nodes / 12 configured flows, with observation provenance exposed independently.
- The existing pinned benign validation case's source digest verified on export.
- A deliberately labelled validation pattern assessment was saved and restored. Real detections were not classified expected for testing.
- Earlier checks verified clear/Undo on labelled validation alerts, viewer write denial, source digests unchanged, partial EXE-title search, named SMB endpoints and protocol/port filtering.

Counts describe the queried time windows, not permanent platform totals. Deployment-specific raw reports remain outside repository source. The console process remained below 100 MB observed memory during these checks; limits and workload size matter.

## Limits requiring further work

- No complete tool-driven purple-team campaign is claimed. A full independent end-to-end exercise remains a useful next validation milestone, with named expected signals and explicit gaps.
- Contextual assessments cover selected recognizable patterns and family-level baselines; arbitrary future sources cannot receive perfect interpretation automatically.
- Full-window rule summaries and bounded activity detail are deterministic review aids, not a historical behavioral baseline or a full incident correlation engine.
- Process reconstruction depends on retained GUID-backed events and query limits. Missing creation records are common and remain visible.
- Evidence stages show supported observations and association strengths; they do not infer causation, decryption or successful exploitation.
- Topology requires operator configuration for remote architecture; automatic discovery is limited to exported local metadata and indexed observations.
- Browser automation was disabled during this work. Component navigation and live APIs were tested, but a new automated visual/browser review was unavailable. Review the live interface in the supported browser.
- Fresh installation on every possible Wazuh/OpenSearch topology is not claimed. Validate field mappings, index naming, archive ingestion, restricted permissions, TLS and metadata export in the target environment.
