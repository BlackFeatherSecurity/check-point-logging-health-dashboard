const FIREWALL_TYPES = new Set([
  "simple-gateway",
  "simple-cluster",
  "cloudguard-gateway"
]);

const RUNTIME_SCRIPT = "cpstat -f log_connection fw";
const SHOW_COMMANDS = {
  "simple-gateway": "show-simple-gateway",
  "simple-cluster": "show-simple-cluster",
  "cloudguard-gateway": "show-simple-gateway"
};

function asArray(value) {
  return Array.isArray(value) ? value : value === undefined || value === null || value === "" ? [] : [value];
}

function referenceName(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return "";
  return String(value.name || value["display-name"] || value.uid || "");
}

function references(value) {
  return asArray(value).map(referenceName).filter(Boolean);
}

function text(value) {
  return String(value || "").trim();
}

function configuredStatus(gateway) {
  const remote = references(gateway["send-logs-to-server"]);
  const backup = references(gateway["send-logs-to-backup-server"]);
  const local = gateway["save-logs-locally"] === true;
  const primary = remote[0] || "";
  const secondary = remote.slice(1);
  const destinations = [...new Set([...remote, ...backup])];
  // The fleet table is deliberately strict: any local logging gets a red
  // outcome, even when a remote destination also exists. That prevents a
  // local-and-remote configuration from being mistaken for off-box-only.
  const mode = local
    ? "local"
    : destinations.length
      ? "off-box"
      : "not configured";
  return { local, primary, secondary, backup, remoteDestinations: remote, destinations, mode };
}

function runtimeDestination(output, configuredDestinations = []) {
  const raw = text(output);
  if (!raw) return "";
  const known = new Map(configuredDestinations.map((value) => [value.toLowerCase(), value]));
  for (const match of raw.matchAll(/(?:log\s*server|logging\s+to|connected\s+to)\s*(?:name|ip|address)?\s*[:=]?\s*([^\r\n|]+)/gi)) {
    const candidate = text(match[1]).replace(/\s{2,}.*/, "");
    const exact = known.get(candidate.toLowerCase());
    if (exact) return exact;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate)) return candidate;
  }
  const ips = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  if (ips.length === 1) return ips[0];
  return "";
}

function parseRuntime(output, error = "", configuredDestinations = []) {
  const raw = text(output);
  if (error) return { state: "unavailable", detail: text(error), raw, destination: "" };
  if (!raw) return { state: "unknown", detail: "The gateway did not return log-connection output.", raw, destination: "" };
  const lower = raw.toLowerCase();
  const destination = runtimeDestination(raw, configuredDestinations);
  if (/not connected|disconnected|connection failed|failed to connect|unreachable/.test(lower)) {
    return { state: "disconnected", detail: "Gateway reported a disconnected log connection.", raw, destination };
  }
  if (/connected|established|connection.*up|status\s*[:=]\s*ok/.test(lower)) {
    // Gaia may report an IP while Management configuration reports an object
    // name. With one configured off-box destination, the configuration is the
    // authoritative name for that active connection; do not split one log
    // server into two dashboard rows just because the representations differ.
    const correlatedDestination = configuredDestinations.length === 1 ? configuredDestinations[0] : destination;
    return {
      state: "connected",
      detail: correlatedDestination ? "Gateway reported an active log connection." : "Gateway reported an active log connection; target was not identified.",
      raw,
      destination: correlatedDestination
    };
  }
  return { state: "reported", detail: "Gateway returned log-connection output; review raw output for release-specific details.", raw, destination };
}

function executionsByTarget(runResult) {
  const map = new Map();
  for (const task of runResult.taskSummary || []) {
    for (const execution of task.executions || []) {
      if (execution.target) map.set(execution.target, execution);
    }
  }
  return map;
}

function summarizeLogServers(rows) {
  const servers = new Map();
  const ensure = (name) => {
    if (!name) return null;
    if (!servers.has(name)) servers.set(name, { name, configuredFirewalls: 0, activeFirewalls: 0 });
    return servers.get(name);
  };
  for (const row of rows) {
    for (const destination of row.destinations) ensure(destination).configuredFirewalls += 1;
    if (row.runtime?.state === "connected" && row.runtime.destination) {
      const server = ensure(row.runtime.destination);
      server.activeFirewalls += 1;
    }
  }
  return [...servers.values()].sort((left, right) =>
    right.activeFirewalls - left.activeFirewalls || right.configuredFirewalls - left.configuredFirewalls || left.name.localeCompare(right.name)
  );
}

/**
 * Collect gateway log configuration and, when requested, run one read-only
 * Gaia command through the Management API's task flow. No Management or
 * gateway setting is changed by this workflow.
 */
export async function collectLoggingStatus({ sessions, sessionId, context = "primary", includeRuntime = true, domain = "" }) {
  const startedAt = Date.now();
  const objects = await sessions.list(sessionId, "show-gateways-and-servers", {}, context);
  // `show-gateways-and-servers` also returns Management, Log, SmartEvent,
  // and generic Check Point host objects. This dashboard is intentionally a
  // firewall fleet view, so only gateway and cluster firewall object types
  // are eligible for collection or the fixed Gaia runtime probe.
  const firewalls = objects.filter((object) => FIREWALL_TYPES.has(object.type));
  const rows = [];
  for (const gateway of firewalls) {
    const command = SHOW_COMMANDS[gateway.type];
    let detail = gateway;
    let configurationError = "";
    if (command && gateway.uid) {
      try {
        detail = await sessions.command(sessionId, command, { uid: gateway.uid, "details-level": "full" }, context);
      } catch (error) {
        configurationError = "Could not retrieve full logging configuration; using inventory data.";
      }
    }
    rows.push({
      domain: text(domain),
      name: text(gateway.name) || text(detail.name) || "Unnamed firewall",
      type: text(gateway.type) || text(detail.type) || "gateway",
      uid: text(gateway.uid),
      ...configuredStatus(detail),
      configurationError,
      runtime: { state: "not checked", detail: "Runtime probe was not requested.", raw: "", destination: "" }
    });
  }

  if (includeRuntime && rows.length) {
    const runResult = await sessions.runScript(sessionId, {
      "script-name": "check-log-connection",
      script: RUNTIME_SCRIPT,
      targets: rows.map((row) => row.name)
    }, context);
    const executions = executionsByTarget(runResult);
    for (const row of rows) {
      const execution = executions.get(row.name);
      row.runtime = execution
        ? parseRuntime(execution.output || execution.message, execution.error, row.remoteDestinations)
        : { state: "unknown", detail: "No per-gateway task result was returned.", raw: "", destination: "" };
    }
  }

  return {
    checkedAt: new Date().toISOString(),
    scanDurationMs: Date.now() - startedAt,
    runtimeCommand: includeRuntime ? RUNTIME_SCRIPT : "",
    count: rows.length,
    logServers: summarizeLogServers(rows),
    firewalls: rows
  };
}

export async function collectAllDomainLoggingStatus({ sessions, sessionId, includeRuntime = true }) {
  const startedAt = Date.now();
  const root = sessions.describe(sessionId);
  if (!root.allDomains || !root.mdsMode) throw new Error("This session is not configured for an all-domain MDS scan.");
  const firewalls = [];
  const domainFailures = [];
  for (const domain of root.domains) {
    let childId = "";
    try {
      childId = await sessions.openDomainSession(sessionId, domain.name);
      const result = await collectLoggingStatus({ sessions, sessionId: childId, includeRuntime, domain: domain.name });
      firewalls.push(...result.firewalls);
    } catch (error) {
      domainFailures.push({ domain: domain.name, error: error.message });
    } finally {
      if (childId) await sessions.logout(childId).catch(() => {});
    }
  }
  return {
    checkedAt: new Date().toISOString(),
    scanDurationMs: Date.now() - startedAt,
    runtimeCommand: includeRuntime ? RUNTIME_SCRIPT : "",
    count: firewalls.length,
    domains: root.domains,
    domainFailures,
    logServers: summarizeLogServers(firewalls),
    firewalls
  };
}

export const loggingStatusInternals = { configuredStatus, parseRuntime, references, runtimeDestination, summarizeLogServers };
