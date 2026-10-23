# Configured topology and observed discovery

Topology is a hybrid. It is deliberately not an automatic network scanner.

| Information | Source |
|---|---|
| Agent registration / connection state | Local manager metadata export |
| Current host addresses and OS | Selected manager database columns; no transport keys exported |
| Indexed hosts, event source types and last timestamps | Queries against the existing indexer |
| Local service status and listeners | Exported systemd unit properties and `ss` observations |
| Remote service placement, dashboard URLs, API descriptions | Operator's topology manifest |
| Network mirror, syslog and forwarding paths | Operator's topology manifest; indexed evidence corroborates collection separately |
| Remote service status | Optional dated metadata file, otherwise explicitly not observed |

The first lab version embedded its inventory and diagram layout in code. Version 0.2 loads a topology manifest outside the repository, draws nodes and flows from that manifest, and labels state observations separately. Empty configuration produces an empty/unknown architecture rather than fictitious lab hosts. Tests use an unrelated example domain to validate this behavior.

Start from `deploy/topology.example.json`, then set `topology_file` in the console config. Each service has an ID, name, host, optional placement, purpose, authentication description and safe HTTP(S) URL. `unit` names the systemd unit in `observation`, a JSON filename under the configured metadata directory. Local observations usually use `services.json`. Remote snapshots can use names such as `sensor-status.json`. `lane` controls diagram placement; it is a layout choice, not a discovered network zone.

Nodes represent non-service sources or datastores. Flows reference `source_id` and `target_id`, with display names, transport and data descriptions. Flows referencing absent nodes are omitted. Services without an available status export display **Not observed**, never assumed running or absent.

Optional remote snapshot schema:

```json
{
  "updated": 1792713600,
  "units": {"suricata": {"ActiveState":"active","SubState":"running","Result":"success"}}
}
```

An operator-controlled exporter must securely transport remote snapshots into the metadata directory. The console does not receive SSH passwords or log into Proxmox, firewalls or endpoints. Timestamps remain visible; a past observation is not a live health guarantee.

An optional `asset_aliases_file` maps IP strings to approved infrastructure names, for example `{"192.0.2.5":"ExampleConsole"}`. This overrides current agent inventory for those addresses and is labelled as approved asset inventory. Duplicate agent IP/name ambiguity is excluded. Event-recorded hostnames take precedence. HTTP Host/TLS SNI identify requested server names and keep that provenance. Current inventory enrichment must not be mistaken for historical DNS truth.

The diagram does not prove forwarding configuration, packet mirroring completeness or full coverage. Use the separate freshness/source checklist and a known expected-action validation to verify the deployment.
