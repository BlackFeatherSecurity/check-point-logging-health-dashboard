import { readFileSync } from "node:fs";
import { isIP } from "node:net";

const SECTIONS = /(?:^|\r?\n)__([A-Z_]+)__(?=\r?\n|$)/;
const CHECK_POINT_HOST_TYPES = new Set(["checkpoint-host", "CpmiHostCkp"]);
const THRESHOLDS = [
  ["alert-when-free-disk-space-below", "Low-space alert"],
  ["delete-when-free-disk-space-below", "Delete old logs"],
  ["stop-logging-when-free-disk-space-below", "Stop logging"]
];

const { presets } = JSON.parse(readFileSync(new URL("../../public/data/gateway-run-script-presets.json", import.meta.url), "utf8"));

export function monitoringPreset(id) {
  const preset = presets.find(entry => entry.id === id && entry.risk === "safe");
  if (!preset) throw new Error(`Read-only preset is missing: ${id}`);
  return preset.script;
}

const LOG_SERVER_SCRIPT = monitoringPreset("log-server-storage");

export function probeSections(output = "") {
  const parts = String(output).split(SECTIONS);
  const sections = new Map();
  for (let i = 1; i < parts.length; i += 2) sections.set(parts[i], parts[i + 1].trim());
  return sections;
}

function diskVolume(raw) {
  const line = raw.split(/\r?\n/).at(-1);
  const match = /^(.+?)\s+(\d+)\s+\d+\s+(\d+)\s+\d+%\s+(.+)$/.exec(line);
  if (!match || Number(match[2]) <= 0 || Number(match[3]) > Number(match[2])) return null;
  const totalKiB = Number(match[2]);
  const availableKiB = Number(match[3]);
  return { device: match[1], mount: match[4], totalKiB, availableKiB, percentFree: 100 * availableKiB / totalKiB };
}

function thresholdsFor(settings = {}) {
  return THRESHOLDS.map(([key, label]) => {
    const enabled = settings[key];
    const value = settings[`${key}-threshold`];
    const metric = settings[`${key}-metrics`] ?? settings["free-disk-space-metrics"];
    return {
      key, label,
      enabled: typeof enabled === "boolean" ? enabled : null,
      value: Number.isFinite(value) && value >= 0 ? value : null,
      metric: ["percent", "mbytes"].includes(metric) ? metric : ""
    };
  });
}

export function storageConditions(volumes, thresholds) {
  const findings = [];
  // Disk-management thresholds apply to the log partition. An independent
  // index mount still has measurements, but needs its own configured limit.
  const volume = volumes?.log;
  if (!volume) return findings;
  for (const threshold of thresholds || []) {
    if (!threshold.enabled || threshold.value === null || !threshold.metric) continue;
    const free = threshold.metric === "percent" ? volume.percentFree : volume.availableKiB / 1024;
    const margin = threshold.metric === "percent" ? 5 : threshold.value * 0.1;
    if (free <= threshold.value + margin) findings.push({
      key: threshold.key, label: threshold.label, free, threshold: threshold.value, unit: threshold.metric,
      state: free <= threshold.value ? "at-threshold" : "approaching"
    });
  }
  return findings;
}

export function parseLogServerProbe(output, indexingMode) {
  const sections = probeSections(output);
  const volumes = {
    log: diskVolume(sections.get("LOG_VOLUME") || ""),
    index: diskVolume(sections.get("INDEX_VOLUME") || "")
  };
  const raw = sections.get("INDEXER") || "";
  const status = /^(?:log\s+)?index(?:er|ing)\s+(?:status|state)\s*:\s*(.+)$/im.exec(raw)?.[1]?.trim() ||
    /^\s*(?:status|state)\s*:\s*(.+)$/im.exec(raw)?.[1]?.trim();
  const indexedRate = /^\s*Updates and Logs Indexed Rate[ \t]*:[ \t]*(\d+(?:\.\d+)?)[ \t]*$/im.exec(raw)?.[1];
  const activity = indexedRate === undefined ? "Reported · review evidence"
    : Number(indexedRate) > 0 ? "Indexing activity observed" : "No indexing activity in this sample";
  const indexer = indexingMode === "disabled" ? "Disabled in configuration"
    : sections.has("INDEXER_FAILED") || !raw ? "Unavailable" : status || activity;
  return { volumes, indexer };
}

export function executionsByTarget(result) {
  const executions = new Map();
  for (const task of result.taskSummary || []) {
    for (const execution of task.executions || []) {
      if (execution.target) executions.set(execution.target, execution);
    }
  }
  return executions;
}

export async function collectManagementHealth({ sessions, sessionId, context, domain, checkedAt, inventoryMs }) {
  const management = {
    domain, checkedAt, inventoryMs,
    reachability: "reachable",
    ha: { state: "unavailable", peers: [] }
  };
  try {
    const reply = await sessions.command(sessionId, "show-ha-status", {}, context);
    const peers = Array.isArray(reply?.servers) ? reply.servers.map(server => ({
      name: server.name, ip: server["ip-address"], role: server["ha-state"], sync: server["sync-state"],
      lastSync: server["last-successful-sync"]?.["iso-8601"],
      managementServer: server["multi-domain-server"]
    })) : [];
    const state = reply?.["successfully-synced"] === true ? "synchronized"
      : reply?.["successfully-synced"] === false ? "not-synchronized"
      : Array.isArray(reply?.servers) ? (peers.length ? "reported" : "no-peer-reported") : "unavailable";
    management.ha = { state, peers };
  } catch (error) {
    if (/\bHigh Availability is not configured\b/i.test(error.message)) management.ha.state = "not-configured";
    management.ha.detail = error.message;
  }
  return management;
}

function hostAliases(host) {
  return [...new Set([host.name, host.uid, host["ipv4-address"], host["ipv6-address"]].filter(Boolean))];
}

export async function collectLogServerHealth({ sessions, sessionId, context, domain, rows, objects, includeRuntime, checkedAt }) {
  const hosts = objects.filter(object => CHECK_POINT_HOST_TYPES.has(object.type) && object.uid && object.name);
  const details = new Map();
  for (const host of hosts) {
    try {
      const detail = await sessions.command(sessionId, "show-checkpoint-host", { uid: host.uid, "details-level": "full" }, context);
      details.set(host.uid, { ...host, ...detail });
    } catch (error) {
      details.set(host.uid, { ...host, configurationError: error.message });
    }
  }

  const byAlias = new Map();
  for (const host of details.values()) {
    for (const alias of hostAliases(host)) {
      if (byAlias.has(alias)) byAlias.set(alias, null);
      else byAlias.set(alias, host);
    }
  }
  const reports = new Map();
  const dependencies = new Map();
  const add = (reference, configured, row) => {
    const host = details.get(reference) || byAlias.get(reference);
    const name = host?.name || reference;
    const key = host?.uid || reference;
    if (!reports.has(key)) {
      const settings = host?.["logs-settings"];
      const indexed = settings?.["enable-log-indexing"];
      const confirmed = host?.["management-blades"]?.["logging-and-status"] === true;
      reports.set(key, {
        key, domain, name, checkedAt, confirmed, version: host?.version || "",
        aliases: host ? hostAliases(host) : [reference],
        configurationError: host?.configurationError || (!confirmed ? "Management did not confirm a Logging & Status server object." : ""),
        indexingMode: indexed === true ? "enabled" : indexed === false ? "disabled" : "unavailable",
        thresholds: thresholdsFor(settings),
        probeState: includeRuntime ? "unavailable" : "not-checked",
        volumes: { log: null, index: null },
        indexer: includeRuntime ? "Unavailable" : "Not checked",
        dependencies: []
      });
    }
    const report = reports.get(key);
    if (!report.aliases.includes(reference)) report.aliases.push(reference);
    if (!row) return;
    const id = row.uid || row.name;
    const dependencyKey = JSON.stringify([key, id]);
    let dependency = dependencies.get(dependencyKey);
    if (!dependency) {
      dependency = { id, name: row.name, members: row.clusterMembers || [], roles: [], observed: false };
      report.dependencies.push(dependency);
      dependencies.set(dependencyKey, dependency);
    }
    if (configured && !dependency.roles.includes(configured)) dependency.roles.push(configured);
    if (!configured) dependency.observed = true;
  };

  for (const host of details.values()) {
    if (host["management-blades"]?.["logging-and-status"] === true) add(host.uid);
  }
  for (const row of rows) {
    if (row.primary) add(row.primary, "Primary", row);
    for (const name of row.secondary) add(name, "Secondary", row);
    for (const name of row.backup) add(name, "Backup", row);
    const destination = row.runtime?.observedDestination || row.runtime?.destination;
    if (row.runtime?.state === "connected" && destination) add(destination, null, row);
  }

  const targets = [...reports.values()].filter(report => {
    const os = details.get(report.key)?.os;
    if (report.confirmed && os && !/gaia/i.test(os)) {
      report.probeError = "Volume and indexer probes are available for Gaia servers.";
      return false;
    }
    return report.confirmed;
  });
  if (includeRuntime && targets.length) {
    let executions = new Map();
    let error = "";
    try {
      executions = executionsByTarget(await sessions.runScript(sessionId, {
        "script-name": "check-log-server-storage",
        script: LOG_SERVER_SCRIPT,
        targets: targets.map(target => target.name)
      }, context));
    } catch (failure) {
      error = failure.message;
    }
    for (const report of targets) {
      const execution = executions.get(report.name);
      const raw = execution?.output || "";
      report.probeError = execution?.error || error || (!raw ? "No per-server probe output was returned." : "");
      if (report.probeError) continue;
      report.checkedAt = new Date().toISOString();
      Object.assign(report, parseLogServerProbe(raw, report.indexingMode));
      report.probeState = report.volumes.log || report.volumes.index || report.indexer !== "Unavailable" ? "reported" : "unavailable";
      report.raw = raw;
      report.storageFindings = storageConditions(report.volumes, report.thresholds);
    }
  }
  return [...reports.values()].sort((left, right) => left.name.localeCompare(right.name));
}

export async function collectIndexedFreshness({ sessions, sessionId, context, reports, horizon }) {
  for (const report of reports) {
    if (report.indexingMode !== "enabled" || !report.confirmed) continue;
    const serverAddress = report.aliases?.find(address => isIP(address));
    for (const gateway of report.dependencies) {
      if (!gateway.observed && !gateway.roles.includes("Primary")) continue;
      const origins = [...new Set([gateway.name, ...(gateway.members || [])])];
      if (!serverAddress || origins.some(name => !/^[a-zA-Z0-9][a-zA-Z0-9_. -]*$/.test(name))) {
        gateway.freshness = "unavailable";
        continue;
      }
      const filter = origins.map(name => `origin:"${name}"`).join(" OR ");
      try {
        const reply = await sessions.command(sessionId, "show-logs", {
          "new-query": {
            filter, "time-frame": horizon, type: "logs",
            "log-servers": [serverAddress], "max-logs-per-request": 1, "returned-fields": ["time"]
          }
        }, context);
        const count = reply["logs-count"];
        const logs = reply.logs;
        const incidents = reply.incidents;
        const incident = incidents && (typeof incidents !== "object" || Object.keys(incidents).length);
        if (!incident && Number.isInteger(count) && count >= 0 &&
            ((Array.isArray(logs) && logs.length === count) || (count === 0 && logs == null))) {
          gateway.freshness = count > 0 ? "recent" : "quiet";
        } else {
          gateway.freshness = "unavailable";
        }
      } catch {
        gateway.freshness = "unavailable";
      }
    }
  }
}
