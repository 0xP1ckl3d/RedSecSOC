# Security model

RedSecSOC is an internal, authenticated investigation interface. It processes untrusted telemetry as data. It never evaluates event scripts, runs commands from alerts or executes decoded payloads. Static Base64 decoding is bounded and labelled separately from execution evidence.

The search client verifies TLS and uses a restricted indexer account for alert/archive reads. The console's own state and pinned evidence live in SQLite. Sessions use secure HttpOnly SameSite cookies, expiry and revocation. Mutations require a trusted Origin, CSRF token and appropriate role. Same-origin UI rendering escapes event content. Query/body/response/concurrency limits protect the constrained runtime.

Do not expose a default loopback bind inadvertently, change trust checks to accept arbitrary origins, or give the console indexer/manager administrator credentials. Choose the actual internal interface, certificate SANs and firewall access explicitly. The systemd service has no root privileges and is constrained to its writable data path.

Keep configuration, TLS private keys, optional CA keys, databases, source snapshots, evidence exports and operational access guides outside the repository. Public example values use reserved documentation domains/addresses and synthetic events. `tools/check_source.py` checks the Git publication set for private keys, real deployment address leakage and secret-shaped runtime files; it supplements review rather than proving absence of secrets.

Digest checks detect inconsistency between the preserved source and its stored hash. They are not immutable storage or a digital signature. Protect database access and apply your evidence retention/backup policy.

No external issue-reporting destination is configured yet. Report vulnerabilities privately to the repository owner using its chosen contact; never include raw production telemetry or credentials in a public issue.
