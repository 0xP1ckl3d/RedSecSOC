# Evidence correlation and review scope

Version 0.4 adds bounded evidence correlation. It does not declare an attack from a rule name, high severity, shared address or temporal proximity.

## Relationships

| Relationship | Required evidence | Interpretation |
| --- | --- | --- |
| Same process | Recorded Process GUID and reporting host | One process identity; PID reuse is excluded |
| Parent / child | Sysmon creation event, recorded parent GUID, matching parent identity on that host | A recorded process relationship |
| Session | Non-builtin logon ID on the same host, at most two hours apart; incompatible recorded Logon GUIDs reject a link | Session association within a bounded window; missing boot/session evidence remains a limitation |
| Endpoint / sensor flow | Complete protocol/source IP/source port/destination IP/destination port tuple, with overlapping recorded event/flow time (5-second tolerance) | Flow association; not proof that every sensor record describes a distinct connection |
| Source connection / target logon | Initiated TCP Sysmon connection from the reporting host, a supported remote-service port, destination matching the target's recorded agent IP, exact source IP/port in target event 4624, logon type 3 or 10, and event clocks within 10 seconds | Candidate session association; not proof the connection caused remote execution |
| Target execution | Target process telemetry with the target logon's host-local session ID | Execution observed in the associated session; not automatically attributed to a remote tool |

Each link exposes both original index/document references and supporting recorded field paths/values. Event content is never executed. [Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) describes Process GUIDs and process-linked network telemetry.

Common service/desktop broker parents are component boundaries so unrelated sibling programs do not become one candidate. The process-tree view can still show the recorded ancestry. Sensor names appear as **evidence reporters**, never as an implied lateral-movement destination.

## Retrieval and limits

Opening an event performs bounded identifier, address and reporting-host queries. Up to three forward-expansion rounds follow connected process identities, child GUIDs, native sensor tuples and destination sessions. Each round has clause/result caps. Ancestry can include separately labelled retained creation records from the preceding three days. The graph considers at most 700 records; a flow spanning set avoids a duplicate-event clique.

The Overview's **Run evidence correlation** samples up to four distinct process seeds from the highest-severity/recent 80 matching active alert occurrences. It inspects ±5 minutes around each seed and deduplicates overlapping process identities. The displayed candidate count describes this bounded review, not all incidents in the selected window. Different alert-only, Linux or unsupported sources may have no process-GUID seed. Open another alert or use the Event explorer to investigate other evidence.

Missing retained creation events, disabled sources, NAT, clock skew, host/address reassignment, restarted hosts and reused session identifiers can prevent or complicate reconstruction. The graph describes observed associations, not malicious intent or universal causal attribution. A shared user, PID, IP or timestamp alone is never a component edge. Exact network tuples without compatible recorded time do not join. A full independent purple-team campaign remains an outstanding validation milestone; no new campaign is executed by this feature.

## Preserve an investigation

Open a candidate directly in **Evidence links**, inspect source records and select **Preserve linked sequence in one investigation**. This is an explicit analyst action; candidates never create cases automatically. At most 60 source records, 2 MB per record/proof and 8 MB total are allowed per batch. Narrow the context for larger components.

Source copies and SHA-256 digests are preserved atomically. Relationships, fields, source references, normalizer version, partial-retrieval flag and query window accompany the evidence. The full graph is retained once in evidence and in case history; subsequent source copies refer to that history. A conflicting existing source digest cancels the entire new evidence batch.

## Detection counts

- **Detection occurrences:** all native alert records in the chosen window, including repetitions and closed/Safe records.
- **Active review occurrences:** native records still New/Investigating, excluding exact Safe matches.
- **Distinct detection patterns:** a cardinality estimate of native rule plus sensor signature or configuration-check identity among active review records. This is distinct from both rule count and detailed behavior variants.
- **Correlated candidates:** components established by the explicitly run, bounded evidence review. These are not confirmed incidents.
- **Open investigations:** analyst-created New/Investigating cases across all retained case state, independently of the telemetry window. Cases may document benign activity.

No automatic confirmed-incident count is fabricated from detection occurrences.
