# Check Point Logging Health Dashboard

A read-only web dashboard for reviewing how Check Point firewall gateways send logs. It supports Security Management Server (SMS), MDS single-domain, and MDS all-domain scans.

## What it does

- Shows configured primary, secondary, and backup log destinations alongside device-aware connection probes.
- Reports gateway NTP and clock evidence. On Gaia ClusterXL, it reports member logging, clocks, cluster state, and route differences.
- Provides a per-domain log-server page with free space on the log and index volumes, configured thresholds, indexing mode and status, and dependent gateways.
- Shows Management API reachability, domain coverage, and HA synchronization when configured.
- Provides fleet filters, CSV export, and change history scoped to the Management endpoint, operator, and scan settings.
- Uses domain-scoped, sequential sessions for MDS all-domain scans.

## Security model

- Check Point credentials and session IDs remain in process memory only.
- Scan history keeps compact snapshots for change comparison. Credentials, Check Point SIDs, raw API replies, and raw command output are excluded.
- The app exposes only its fixed read-only workflow. It has no generic Management API command explorer and no arbitrary Gaia script endpoint.
- The bundled `compose.yaml` runs as a non-root user, with a read-only root filesystem and no host-published port.

**Do not expose this service directly to the internet.** Put it behind HTTPS, strong authentication, authorization, CSRF protection, rate limits, and a network access policy appropriate to your environment. Use a least-privilege, read-only Check Point account.

## Run locally

Requires Node.js 22 or later.

```bash
npm install
npm run check
npm start
```

Open `http://127.0.0.1:3000` and enter your Management host and credentials.

## Container deployment

The Compose file intentionally does not expose a host port. Deploy it behind a secured reverse proxy on an internal network.

```bash
docker compose up -d --build
```

Runtime scan history is written to `./data/`, which is ignored by Git. Keep this directory private. It can contain internal object names and destinations.

### Live checks

Live checks use a fixed set of read-only Management API calls and Gaia commands. The account needs access to the requested domains and objects, plus permission to run the applicable monitoring commands on managed targets. Server disk and indexer evidence requires a confirmed Check Point log server visible to the account. Clearing **Include live checks** collects configuration only.

The self-signed certificate option is checked by default. Clear it to verify the Management endpoint’s certificate when the dashboard can validate its certificate chain.

### Scheduled scans

Scheduling is off by default. After validating the checks on your appliances, set `ENABLE_SCHEDULED_SCANS=true` and restart the dashboard. Complete a live scan, then choose a 15-, 30-, or 60-minute interval. A schedule runs for up to eight hours and stops when the operator logs out or the dashboard restarts.

Alerts appear in the dashboard after consecutive observations of a destination change, low log-volume headroom, or multiple previously active gateways with no recent indexed logs on the same server. Quiet-gateway alerts also require permission to query indexed logs. An unavailable query cannot confirm silence.

## Management modes

- **SMS** — scans one Security Management Server.
- **MDS — one domain** — scans one selected CMA/domain.
- **MDS — all domains** — discovers active domains, scans sequentially, and logs out each temporary domain session.

## Responsible disclosure

See [SECURITY.md](SECURITY.md). Please do not file public issues containing credentials, Management addresses, gateway output, or customer data.

## License and attribution

Licensed under the [MIT License](LICENSE). This project uses and extends the Check Point API Framework with the framework owner's explicit MIT permission; see [NOTICE.md](NOTICE.md).
