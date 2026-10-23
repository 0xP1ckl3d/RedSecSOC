# Investigation semantics

## Contextual interpretation

Normalized observations, original detection descriptions and contextual assessments are distinct. Assessments are deterministic code with recorded-field bases, caveats and source references. They never rewrite Wazuh's severity or automatically declare an alert benign.

PowerShell policy-test interpretation requires both a matching temporary filename and an expected recorded creator path. It describes compatibility with normal application-control testing, not proof of a trusted binary or benign session. An unfamiliar creator remains unresolved. Microsoft documents the temporary policy-test behavior in [PowerShell application control](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control).

The `sdbinst.exe` assessment identifies a dual-use Windows compatibility utility. It does not infer successful database installation, persistence or maliciousness from a process name. See [Microsoft's compatibility database documentation](https://learn.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database) and [MITRE Application Shimming](https://attack.mitre.org/techniques/T1546/011/). Other families retain source-specific observations and explicit generic assessment limits.

## Recurring patterns and persistent decisions

The top-level recurrence view uses index aggregations over the selected time window, with one row per Wazuh detection rule. Host, file, sensor signature and configuration-check breakdowns sit underneath. Counts are not limited to the newest 500 events. If a rule covers multiple source descriptions, the summary uses a family description and lists its signatures/checks rather than presenting the latest description as the entire group.

Activity drill-down retrieves a bounded source sample and groups stable objects, executables, commands and identities. Changing file checksums, timestamps and counters do not create new top-level cards. Hashes and source references remain evidence. The interface distinguishes full-window rule counts from sampled activity detail and makes truncation visible.

An analyst can save a **Safe** or **Suspicious** scope with rationale. **Safe never permits a whole rule or directory.** It requires an exact reporting host and either an exact configuration check, a signature with source/destination/port/protocol, a bounded PowerShell policy-test template with recorded creator/user, or an exact object with checksum or creator/user/command. Destination Safe scopes require source, destination, port and protocol. The server checks that Safe criteria match retained evidence before saving; it does not verify that the underlying session/binary is trusted. Broad Suspicious watch scopes remain possible.

The policy-test template permits generated .ps1/.psm1 basenames only under one recorded Temp directory prefix, with rule 92213, Sysmon event 11, the Sysmon channel, exact creator image, user and host. A different executable suffix, creator, identity or missing condition stays visible. This is a conditional analyst decision about those records, not a whitelist for the process/session. Other detections and explicitly Suspicious scopes retain priority. No field-based exemption can prove that an attacker did not imitate all its conditions.

Near matches to a Safe rule/host or endpoint scope carry a changed-condition badge and can be reviewed with the Changed from Safe scope filter. The badge denotes a difference from saved conditions, not proof of chronological drift or maliciousness. Invalid legacy broad Safe scopes are disabled at startup with a review reason in audit history. Decisions expose their history and can be revoked.
Safe matches leave default alert and pattern views. **Include safe** makes them visible again; their evidence is never deleted. Suspicious matches receive badges and inbox priority. Suspicious overrides Safe if both match. These policies apply at query time to current and future records. They do not modify Wazuh rules or source severity and do not perform firewall blocking. Policies can be revoked; active and revoked policy history remains audited. Viewers cannot create or revoke decisions. Up to 100 active scopes keep query expansion bounded.

Earlier 0.2 exact-material annotations are retained for compatibility; they are not silently converted into broad dismissal policies. New behavior uses explicit saved scopes.

## Network patterns and overview drill-through

The Overview landing page shows active detections, exact severity bands, analyst-marked suspicious counts, sensor record types, an alert time histogram, priority source events, leading recurring detections, host counts, leading destinations and collection freshness. Record-type, severity-band, rule, time and destination links preserve exact filter criteria and time boundaries rather than using an approximate free-text search. Back retains the originating view.

Network destination summaries aggregate indexed Suricata **flow** events. They show flow-record counts, approximate distinct flow IDs/source IPs, reported bytes to/from the destination, ports, protocols, collector names and observed server names/signatures. Rank by record count, bytes sent to the destination or number of contacting sources. A source fan-out summary highlights hosts contacting many destinations/ports.

Byte values are sums reported in flow records. Repeated flow updates and mirrored copies can inflate totals; they are not guaranteed unique wire-byte measurements. Cardinalities are estimates and are bounded by their record counts. HTTP Host/TLS SNI describe names observed for an IP in the time window, not ownership of the IP or proof every connection used the name. Internal asset names are inventory enrichment. Address labels explicitly separate public unicast, RFC 1918 private, IPv6 unique-local, loopback, link-local, multicast, CGNAT/shared, unspecified, limited broadcast, documentation and other special-purpose ranges. A current asset name never changes the address class. The special-use checks follow the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry) and [IPv6 registries](https://www.iana.org/assignments/iana-ipv6-special-registry); multicast is excluded from public unicast before any global-address fallback. These labels are not ASN, hosting-provider or threat-reputation assertions. No external reputation feed is configured. High traffic volume is a review lead, not proof of compromise.

The leading-destination panel has its own 15-minute to 48-hour trailing slider, defaulting to 24 hours, and exact UTC From/To controls (up to the API's 31-day limit). Its displayed range and links are independent of the overview window. The Patterns view supports custom ranges too. Sensor application-protocol values such as failed mean unidentified parsing, not necessarily a failed connection; original ports remain visible.

See [Correlation and count semantics](CORRELATION.md) for evidence-backed reconstruction and explicit investigation preservation.

## Process relationships and evidence stages

Process identities use recorded GUIDs scoped to a host. Parent edges require a recorded parent GUID; reused PIDs are never joined as persistent identities. A node is shown as creation-observed only for a Sysmon creation record. Other records can reference an identity whose creation event is unavailable; these placeholders are explicit. Commands come from retrieved source events, not reconstructed shell execution.

The bounded context window includes identifier, address and same-host searches. Ancestor lookups can retrieve retained creation events outside the displayed time window and are labelled separately. Node/response limits and incomplete retrievals remain visible. Different parent references are marked ambiguous rather than treated as a verified single ancestry.

File, registry and network observations with a recorded process GUID attach to that process. Logon IDs are scoped to one host. Community ID/sensor flow IDs and full network-tuple matches describe flow associations, not successful exploitation. Time/address proximity is contextual only.

Evidence stages organize authentication/remote-session, process, managed-runtime, network and object observations. Stages are tool-independent; a purple-team framework is an example producer of test activity, not a platform requirement. Stage evidence can be identifier-linked or merely contextual, and missing stages explicitly say Not observed in retrieved evidence. A DLL/image-load record does not prove managed assembly execution. These stages are not an automatic confirmed attack chain or causal sequence.

## Source and detection coverage

Registration, manager connection state, raw reporting, observed event source types and triggered alerts are separate fields. The source checklist uses a 24-hour query and distinguishes Windows, Linux and common checks when OS metadata is available. It is an observation checklist, not a configured policy asserting every listed source must exist. Missing activity can reflect a quiet host, collection gaps, retention, query limits or source configuration.

Detection validation searches an operator-specified marker/time window. It does not execute tests on endpoints. Use an independently controlled activity with known scope and expected sources to evaluate collection and detection behavior. Preserve its evidence and record gaps explicitly.

## Evidence integrity

Pinning saves the original decoded/indexed source JSON plus normalized evidence, rule context and version. It records source index/document identity and SHA-256 over sorted-key compact UTF-8 JSON (`ensure_ascii=false`). Case reads and exports recompute the digest. Exact duplicates are idempotent; a different source under the same preserved event identity raises a conflict and keeps the original copy.

A matching digest verifies consistency against the recorded snapshot hash. It is not a signature, immutable evidence store, forensic acquisition of the endpoint or independent proof that the original event was truthful. Runtime database access must remain controlled.
