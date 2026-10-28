# Check Point Logging Health Dashboard

A read-only web dashboard for reviewing how Check Point firewall gateways send logs. It supports Security Management Server (SMS), MDS single-domain, and MDS all-domain scans.

## What it does

- Lists firewall gateway/cluster objects only; management, log, SmartEvent, and generic hosts are excluded.
- Shows configured primary, secondary, and backup log destinations.
- Separates configured logging from a fixed runtime probe: `cpstat -f log_connection fw`.
- Marks local logging red and off-box logging green.
- Provides log-server coverage, minimal state-change history, filtering, and filtered CSV export.
- Uses domain-scoped, sequential sessions for MDS all-domain scans.

## Security model

- Check Point credentials and session IDs remain in process memory only.
- Scan history stores only compact status deltas: no credentials, SIDs, raw API responses, or raw gateway command output.
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

Runtime scan history is written to `./data/`, which is ignored by Git.

## Management modes

- **SMS** — scans one Security Management Server.
- **MDS — one domain** — scans one selected CMA/domain.
- **MDS — all domains** — discovers active domains, scans sequentially, and logs out each temporary domain session.

## Responsible disclosure

See [SECURITY.md](SECURITY.md). Please do not file public issues containing credentials, Management addresses, gateway output, or customer data.

## License and attribution

Licensed under the [MIT License](LICENSE). This project uses and extends the Check Point API Framework with the framework owner's explicit MIT permission; see [NOTICE.md](NOTICE.md).
