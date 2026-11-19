const INTERVALS = [15, 30, 60];
const HORIZONS = ["last-hour", "last-24-hours"];
const MAX_AGE_MS = 8 * 60 * 60 * 1000;
const MAX_SCHEDULES = 4;

function key(...values) {
  return JSON.stringify(values);
}

export function updateAlerts(state, scan, horizon) {
  const checkedAt = scan.checkedAt;
  const alerts = [];
  const currentDestinations = new Map();
  const currentFreshness = new Map();
  const currentStorage = new Set();
  const serversByDomain = new Map();
  for (const server of scan.logServerHealth) {
    if (!serversByDomain.has(server.domain)) serversByDomain.set(server.domain, []);
    serversByDomain.get(server.domain).push(server);
  }
  for (const row of scan.firewalls) {
    const domain = row.domain || scan.management[0]?.domain || "SMS";
    const recordId = key(domain, row.uid || row.name);
    const observed = row.runtime?.state === "connected" ? row.runtime.observedDestination : "";
    if (!observed) continue;
    const matching = (serversByDomain.get(row.domain || scan.management[0]?.domain || "") || [])
      .filter(server => server.aliases.includes(observed));
    if (matching.length > 1) continue;
    const destination = matching[0]?.name || observed;
    const previous = state.destinations.get(recordId);
    const baseline = previous?.baseline || destination;
    currentDestinations.set(recordId, { baseline, destination });
    if (destination !== baseline && previous?.destination === destination) {
      alerts.push({
        type: "Destination changed", domain, target: row.name, checkedAt,
        evidence: `Expected ${baseline} from the scheduled baseline. The gateway reported ${destination} in consecutive scans.`
      });
    }
  }
  // Keep the expected destination through a missed or ambiguous probe, while
  // breaking consecutive confirmation.
  for (const [id, previous] of state.destinations) {
    if (!currentDestinations.has(id)) currentDestinations.set(id, { baseline: previous.baseline, destination: "" });
  }
  const failedDomains = new Set((scan.domainFailures || []).map(failure => failure.domain));
  for (const [id, previous] of state.freshness) {
    const [domain] = JSON.parse(id);
    if (failedDomains.has(domain)) currentFreshness.set(id, { lastRecent: previous.lastRecent, streak: 0 });
  }
  for (const server of scan.logServerHealth) {
    const domain = server.domain || "SMS";
    const quiet = [];
    for (const gateway of server.dependencies) {
      const id = key(domain, server.key, gateway.id);
      const previous = state.freshness.get(id);
      const lastRecent = gateway.freshness === "recent" ? checkedAt : previous?.lastRecent;
      const streak = gateway.freshness === "quiet" && lastRecent ? (previous?.streak || 0) + 1 : 0;
      currentFreshness.set(id, { lastRecent, streak });
      if (streak >= 2) quiet.push(`${gateway.name} (last confirmed recent at ${lastRecent})`);
    }
    if (quiet.length >= 2) alerts.push({
      type: "Multiple gateways went quiet", domain, target: server.name, checkedAt,
      evidence: `No indexed logs in the ${horizon === "last-hour" ? "previous hour" : "previous 24 hours"} on consecutive checks. ${quiet.join(", ")}.`
    });
    for (const finding of server.storageFindings || []) {
      const id = key(domain, server.key, finding.key, finding.threshold, finding.unit);
      currentStorage.add(id);
      if (!state.storage.has(id)) continue;
      const units = finding.unit === "percent" ? "%" : " MiB";
      alerts.push({
        type: "Low log-volume headroom", domain, target: server.name, checkedAt,
        evidence: `${finding.free.toFixed(1)}${units} free. ${finding.label} threshold is ${finding.threshold}${units}. ${finding.state === "approaching" ? "Near" : "At or below"} threshold on latest check.`
      });
    }
  }
  state.destinations = currentDestinations;
  state.freshness = currentFreshness;
  state.storage = currentStorage;
  return alerts;
}

export class ScanScheduler {
  constructor({ scan, enabled = false, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout }) {
    this.jobs = new Map();
    Object.assign(this, { scan, enabled, now, setTimer, clearTimer });
  }

  status(id) {
    const job = this.jobs.get(id);
    if (!job) return { enabled: this.enabled, active: false };
    const { active, interval, horizon, expiresAt, nextAt, lastSuccess, error, alerts, running } = job;
    return { enabled: this.enabled, active, interval, horizon, expiresAt, nextAt, lastSuccess, error, alerts, running };
  }

  start(id, interval, horizon) {
    if (!this.enabled) throw new Error("Scheduled scanning is disabled on this dashboard.");
    if (!INTERVALS.includes(interval) || !HORIZONS.includes(horizon)) throw new Error("Choose a supported scan interval and log lookback.");
    if (this.jobs.get(id)?.active) throw new Error("Stop the current schedule before starting another.");
    if ([...this.jobs.values()].filter(job => job.active).length >= MAX_SCHEDULES) {
      throw new Error("The dashboard has reached its concurrent schedule limit.");
    }
    const job = {
      active: true, interval, horizon, expiresAt: this.now() + MAX_AGE_MS, lastSuccess: "",
      alerts: [], error: "", nextAt: this.now(), running: false,
      evidence: { destinations: new Map(), freshness: new Map(), storage: new Set() }
    };
    this.jobs.set(id, job);
    this.queue(id, job);
    return this.status(id);
  }

  stop(id) {
    const job = this.jobs.get(id);
    if (job) this.clearTimer(job.timer);
    this.jobs.delete(id);
    return this.status(id);
  }

  queue(id, job) {
    const wakeAt = Math.min(job.nextAt, job.expiresAt);
    if (wakeAt === job.expiresAt) job.nextAt = null;
    job.timer = this.setTimer(() => {
      if (this.now() >= job.expiresAt) {
        job.active = false;
        job.nextAt = null;
        return;
      }
      void this.tick(id, job);
    }, Math.max(0, wakeAt - this.now()));
    job.timer?.unref?.();
  }

  async tick(id, job) {
    job.running = true;
    job.nextAt = null;
    try {
      const result = await this.scan(id, job.horizon);
      if (this.jobs.get(id) !== job) return;
      const complete = !result.domainFailures?.length;
      const alerts = updateAlerts(job.evidence, result, job.horizon);
      if (complete) job.lastSuccess = result.checkedAt;
      const failedDomains = new Set((result.domainFailures || []).map(failure => failure.domain));
      job.alerts = [...alerts, ...job.alerts.filter(alert => failedDomains.has(alert.domain))];
      job.error = complete ? "" : "Some domains could not be scanned. Alerts for those domains show their previous evidence.";
    } catch (error) {
      job.error = error.message;
      for (const gateway of job.evidence.destinations.values()) gateway.destination = "";
      job.evidence.storage.clear();
      for (const gateway of job.evidence.freshness.values()) gateway.streak = 0;
    } finally {
      job.running = false;
      if (this.jobs.get(id) === job) {
        job.nextAt = this.now() + job.interval * 60_000;
        this.queue(id, job);
      }
    }
  }
}
