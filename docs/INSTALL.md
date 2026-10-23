# Installation and updates

## Prerequisites

Use Ubuntu with systemd, Python 3.12+, `python3-venv`, OpenSSL and an existing TLS-enabled Wazuh indexer. The installer targets `/opt/redsec-soc-console` by convention and supports paths without whitespace. The console requires compatible `wazuh-alerts-*` and optionally `wazuh-archives-*` indices. Archive ingestion must already be enabled for rich timelines.

Run metadata export on a Wazuh manager only if local rule/agent access is intended. It exports selected non-secret metadata to readable JSON. The unprivileged web service does not receive the manager database or administrative API credentials. For remote deployments, disable `local_metadata` and provide trusted metadata exports separately.

## 1. Source and frontend

Place the source in `/opt/redsec-soc-console`. Build the frontend with a compatible Node installation, preferably in CI or as a non-root user:

```sh
cd /opt/redsec-soc-console/frontend
npm ci
npm test
npm run build
```

The deployed console serves `frontend/dist`; Node is not required at runtime. Source paths and files must be readable by `redsec-console`, while secrets and data remain outside this directory.

## 2. Restricted indexer account

Use a dedicated user permitted to read only `wazuh-alerts-*` and `wazuh-archives-*`, with no cluster-management, index-write or tenant permissions. An existing suitably restricted account can be used.

Alternatively, the explicit provisioning helper uses your indexer's existing security-administrator certificate:

```sh
sudo python3 deploy/provision_indexer.py \
  --url https://127.0.0.1:9200 \
  --ca /PATH/TO/root-ca.pem \
  --admin-cert /PATH/TO/admin.pem \
  --admin-key /PATH/TO/admin-key.pem \
  --output /root/redsecsoc-indexer-access.json
```

This creates the account and its narrow role/mapping. It refuses to implicitly rotate an existing user or overwrite its secret output. The output is mode 0600; copy its account fields into the console config using your normal secret-handling process. Neither this file nor the admin certificate/key belongs in the repository. Keep administrator credentials away from the web account. If provisioning fails partway, inspect the created account/role with the indexer administrator before rerunning.

## 3. Deployment config and TLS

```sh
sudo install -d -m 0755 /etc/redsec-soc-console
sudo install -m 0600 deploy/config.example.json /etc/redsec-soc-console/config.json
sudo install -m 0644 deploy/topology.example.json /etc/redsec-soc-console/topology.json
```

Edit the examples. Set the indexer URL/CA/credentials, absolute paths, HTTPS origins, listening address and port, site label, dashboard links, topology file and metadata policy. The origins must match the browser URL exactly, including a non-default port. Bind to the intended internal interface; the example binds to loopback and requires an appropriate reverse proxy or tunnel for remote use.

Install a valid server certificate and key at `tls_cert` and `tls_key`. Include the actual browser hostname/IP in its SANs. Install the indexer's public CA at `indexer_ca`. The installer never disables TLS verification and does not create a public tunnel or modify firewall rules. Permit the chosen HTTPS port only through your intended access path.

The daily certificate timer checks for expiry within thirty days. By default, renewal remains with your certificate provider. If you deliberately operate a local CA, optional configuration can enable local signing:

```json
"certificate_renewal": {
  "ca_cert": "/etc/your-ca/public-ca.pem",
  "ca_key": "/etc/your-ca/private-signing-key.pem",
  "sans": ["soc.example.test"]
}
```

The signing key must be root-only, outside repository source and inaccessible to the web account. No CA key is required to run the console. The certificate timer logs an actionable failure when expiry approaches and no renewal provider is configured.

## 4. Install and create the first administrator

```sh
cd /opt/redsec-soc-console
sudo bash deploy/install.sh
sudo /opt/redsec-soc-console/venv/bin/python deploy/init_admin.py
```

The administrator helper prompts for a 12+ character password and does not create a password file. The installer creates an unprivileged service user, a virtual environment from the dependency lock, metadata/certificate timers and a constrained web service. It preserves existing users, database, evidence and deployment settings. It does not change Wazuh services or firewall policy.

The default database directory is owned by the service account, mode 0700. Config and server key are mode 0640 for root/service group. The first-administrator helper assigns SQLite files to the service account when invoked as root. Metadata is readable because it contains non-secret rule/inventory/status information.

## 5. Verify

```sh
systemctl status redsec-soc-console --no-pager
systemctl status redsec-soc-metadata.timer --no-pager
systemd-analyze verify /etc/systemd/system/redsec-soc-console.service
journalctl -u redsec-soc-console -n 30 --no-pager
```

Open your configured HTTPS URL and sign in. Check Endpoints & coverage against a known recent event, inspect raw and alert counts, open an investigation and verify a pinned source digest. A healthy service or registered agent alone does not establish detection coverage.

Service resource bounds are currently 512 MB maximum / 384 MB high memory, 150% CPU quota and 24 in-process request slots. Queries separately limit indexer concurrency and response sizes. Validate these limits against your workload; they are not sizing guarantees.

## Updates

Build/test the new frontend, review dependency changes, and install source over the existing installation. Keep `/etc/redsec-soc-console`, `/var/lib/redsec-soc-console` and metadata outside the checkout. Run the installer again; schemas use additive creation and existing workflows remain. The installer restarts only this console, not Wazuh or sensors. Test before removing your normal recovery point; database backup/retention is an operator policy.

## Uninstall

Stop/disable the console and its two timers, then remove only the installed source and generated unit files after confirming their paths. Preserve or explicitly export/delete the database according to your evidence retention needs. Uninstalling the console does not require removing Wazuh, agents, sensors, indexer accounts used elsewhere or external dashboards.
