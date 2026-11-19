import {
  collectIndexedFreshness, collectLogServerHealth, collectManagementHealth, executionsByTarget, monitoringPreset, probeSections
} from "./infrastructure-health.js";

const FIREWALL_TYPES = new Set([
  "simple-gateway",
  "simple-cluster",
  "cloudguard-gateway"
]);

const GAIA_RUNTIME_SCRIPT = "cpstat -f log_connection fw";
// NTP configuration is read through Gaia Clish, while the epoch is emitted in
// a marker that survives Management API task wrapping.  The commands are
// read-only and intentionally fixed; user-provided text never reaches a
// gateway shell.
const TIME_EPOCH_SCRIPT = "printf '__TIME_EPOCH__='; date -u +%s";
const GAIA_TIME_SCRIPT = `${TIME_EPOCH_SCRIPT}; printf '\\n__NTP_ACTIVE__='; clish -c 'show ntp active' 2>&1; printf '\\n__NTP_CURRENT__='; clish -c 'show ntp current' 2>&1`;
const GAIA_MEMBER_SCRIPT = monitoringPreset("cluster-member-logging-health");
// Gaia's Clish route monitor is the authoritative route view. Do not use
// `ip route`: Check Point documents cases where it omits interface routes.
const GAIA_ROUTE_SCRIPT = "clish -c 'show route all'";
// Keep the user's proven SMB detection command intact while returning a
// deterministic result when no fw socket is present. Without the marker,
// grep's exit code can turn a healthy Management task into an opaque error.
const SMB_RUNTIME_SCRIPT = "netstat -tnp | grep ':257' | grep fw || echo 'NO_FW_LOG_CONNECTION'";
const DEVICE_PROFILES = {
  gaia: {
    id: "gaia",
    family: "Gaia gateway / cluster",
    label: "cpstat log connection",
    script: GAIA_RUNTIME_SCRIPT,
    timeScript: GAIA_TIME_SCRIPT,
    timeLabel: "Gaia NTP + UTC clock"
  },
  smb: {
    id: "smb",
    family: "SMB / Quantum Spark",
    label: "netstat TCP/257",
    script: SMB_RUNTIME_SCRIPT,
    // SMB appliances use a separate, release-dependent NTP surface.  Collect
    // their UTC clock without pretending their NTP enablement is known.
    timeScript: TIME_EPOCH_SCRIPT,
    timeLabel: "UTC clock (NTP state unavailable)"
  },
  unknown: {
    id: "unknown",
    family: "Unsupported / unknown",
    label: "No runtime probe",
    script: "",
    timeScript: "",
    timeLabel: "No time probe"
  }
};
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

function isTrue(value) {
  return value === true || String(value).toLowerCase() === "true";
}

function deviceFingerprint(gateway) {
  return [
    gateway.type,
    gateway["allow-smb"],
    gateway.hardware,
    gateway.platform,
    gateway["platform-name"],
    gateway.version,
    gateway["os-name"],
    gateway["product-name"]
  ].map(text).join(" ").toLowerCase();
}

/**
 * Select from a deliberately small, read-only probe allowlist using fields
 * from the fully fetched Management object. Never infer a device family from
 * its display name or spray fallback commands at an unfamiliar platform.
 */
function deviceProfile(gateway) {
  const fingerprint = deviceFingerprint(gateway);
  if (isTrue(gateway["allow-smb"]) || /\b(?:smb|quantum\s+spark|spark)\b/.test(fingerprint)) return DEVICE_PROFILES.smb;
  // Maestro/scalable platforms require an SG/member-aware implementation.
  // Do not run a gateway-level Gaia probe until that behavior is tested.
  if (/\b(?:maestro|scalable|hyperscale|chassis)\b/.test(fingerprint)) return DEVICE_PROFILES.unknown;
  if (gateway.type === "simple-gateway" || gateway.type === "simple-cluster") return DEVICE_PROFILES.gaia;
  return DEVICE_PROFILES.unknown;
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
  const tcp257 = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}:257\b/);
  if (tcp257) return tcp257[0].slice(0, -4);
  const ips = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  if (ips.length === 1) return ips[0];
  return "";
}

function observedDestinations(raw, profile) {
  if (profile.id === "smb") {
    const endpoints = [...new Set([...raw.matchAll(/^tcp\S*\s+\d+\s+\d+\s+\S+\s+(\S+):257\s+ESTABLISHED\b/gim)]
      .map(match => match[1]))];
    return endpoints;
  }
  const destinations = new Set();
  for (const line of raw.split(/\r?\n/)) {
    const named = /^\s*(?:connected to|logging to)\s*[:=]?\s+([^\s|]+)\s*$/i.exec(line);
    if (named) destinations.add(named[1]);
    const fields = line.trim().replace(/^\||\|$/g, "").split("|").map(value => value.trim());
    if (fields.length >= 3 && /^0$/.test(fields[1]) && /^(?:log.server )?connected$/i.test(fields[2])) destinations.add(fields[0]);
  }
  return [...destinations];
}

function parseRuntime(output, error = "", configuredDestinations = [], profile = DEVICE_PROFILES.gaia) {
  const raw = text(output);
  if (error) return { state: "unavailable", detail: text(error), raw, destination: "" };
  const observed = observedDestinations(raw, profile);
  const observedDestination = observed.length === 1 ? observed[0] : "";
  if (profile.id === "smb") {
    if (/NO_FW_LOG_CONNECTION/.test(raw)) {
      return { state: "disconnected", detail: "SMB appliance has no active fw connection to TCP/257.", raw, destination: "" };
    }
    if (!observed.length) {
      return /^tcp\S*\s+\d+/im.test(raw)
        ? { state: "disconnected", detail: "The reported TCP/257 connection is not established.", raw, destination: "" }
        : { state: "unknown", detail: "The SMB appliance did not return recognizable TCP/257 connection output.", raw, destination: "" };
    }
    const destination = runtimeDestination(raw, configuredDestinations);
    const correlatedDestination = configuredDestinations.length === 1 ? configuredDestinations[0] : destination;
    return {
      state: "connected",
      detail: correlatedDestination ? "SMB appliance reported an active fw connection to TCP/257." : "SMB appliance reported an active fw connection; target was not identified.",
      raw,
      destination: correlatedDestination,
      observedDestination
    };
  }
  if (!raw) return { state: "unknown", detail: "The gateway did not return log-connection output.", raw, destination: "" };
  const lower = raw.toLowerCase();
  const destination = runtimeDestination(raw, configuredDestinations);
  if (!observed.length && /not connected|disconnected|connection failed|failed to connect|unreachable/.test(lower)) {
    return { state: "disconnected", detail: "Gateway reported a disconnected log connection.", raw, destination };
  }
  if (observed.length || /connected|established|connection.*up|status\s*[:=]\s*ok/.test(lower)) {
    // Gaia may report an IP while Management configuration reports an object
    // name. With one configured off-box destination, the configuration is the
    // authoritative name for that active connection; do not split one log
    // server into two dashboard rows just because the representations differ.
    const correlatedDestination = configuredDestinations.length === 1 ? configuredDestinations[0] : destination;
    return {
      state: "connected",
      detail: correlatedDestination ? "Gateway reported an active log connection." : "Gateway reported an active log connection; target was not identified.",
      raw,
      destination: correlatedDestination,
      observedDestination
    };
  }
  return { state: "reported", detail: "Gateway returned log-connection output; review raw output for release-specific details.", raw, destination };
}

function epochFromOutput(output) {
  const match = String(output || "").match(/__TIME_EPOCH__=(\d{9,12})/);
  if (!match) return 0;
  const epoch = Number(match[1]);
  return Number.isFinite(epoch) ? epoch * 1000 : 0;
}

function ntpFromOutput(output) {
  const raw = String(output || "");
  const active = raw.match(/__NTP_ACTIVE__=([\s\S]*?)(?=\n__NTP_CURRENT__=|$)/);
  const current = raw.match(/__NTP_CURRENT__=([\s\S]*)$/);
  const activeText = text(active?.[1]);
  const peer = text(current?.[1]);
  // Gaia releases phrase this differently ("Yes", "active: true", or
  // "NTP is enabled").  Keep the result deliberately conservative: only a
  // clear affirmative/negative becomes a dashboard verdict.
  const state = /^\s*(?:(?:NTP(?:\s+(?:status|state|active|enabled))?|active)\s*(?::|=|is)\s*)?(yes|on|enabled|true|active|no|off|disabled|false|inactive)[.!]?\s*$/im
    .exec(activeText)?.[1].toLowerCase();
  if (state) return { enabled: ["yes", "on", "enabled", "true", "active"].includes(state), peer, activeText };
  return { enabled: null, peer, activeText };
}

function evaluateTimeHealth({ profile, firewallEpoch = 0, logServerEpoch = 0, ntpEnabled = null, peer = "", raw = "", error = "", comparisonError = "", logServer = "" }) {
  if (error) return { state: "unavailable", label: "Unavailable", detail: text(error), ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs: null, logServer };
  if (!firewallEpoch) return { state: "unavailable", label: "Unavailable", detail: "The gateway did not return a UTC clock value.", ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs: null, logServer };
  const offsetMs = logServerEpoch ? firewallEpoch - logServerEpoch : null;
  const offsetSeconds = offsetMs === null ? null : Math.abs(offsetMs) / 1000;
  const comparisonDetail = comparisonError
    ? ` Log-server comparison was unavailable: ${text(comparisonError)}`
    : logServer
      ? " The active log-server clock was unavailable for comparison."
      : " No active log-server clock was available for comparison.";
  if (ntpEnabled === false) {
    return { state: "ntp-off", label: "NTP off", detail: logServerEpoch ? "NTP is disabled; offset is measured against the active log server." : `NTP is disabled.${comparisonDetail}`, ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs, logServer, comparisonError };
  }
  if (offsetSeconds === null) {
    if (ntpEnabled === true) {
      return { state: "ntp-active", label: "NTP active", detail: `NTP is enabled.${comparisonDetail}`, ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs, logServer, comparisonError };
    }
    const state = profile.id === "smb" ? "not-supported" : "unknown";
    return { state, label: profile.id === "smb" ? "NTP not reported" : "NTP unknown", detail: comparisonDetail.trim(), ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs, logServer, comparisonError };
  }
  if (offsetSeconds < 30 && ntpEnabled === true) {
    return { state: "synced", label: "NTP active · synced", detail: "NTP is enabled and clocks are within the healthy threshold.", ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs, logServer };
  }
  if (offsetSeconds > 300) {
    return { state: "drift-critical", label: "Clock drift", detail: ntpEnabled === null ? "Clock offset exceeds five minutes; NTP state was not reported." : "Clock offset exceeds five minutes.", ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs, logServer };
  }
  if (offsetSeconds >= 30) {
    return { state: "drift", label: "Drift", detail: ntpEnabled === null ? "Clock offset is outside the healthy threshold; NTP state was not reported." : "Clock offset is outside the healthy threshold.", ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs, logServer };
  }
  return { state: "unknown", label: "NTP unknown", detail: "Clocks are close, but this device did not report NTP enablement.", ntpEnabled, peer, raw, firewallEpoch, logServerEpoch, offsetMs, logServer };
}

function initialTimeHealth(profile, includeRuntime) {
  if (!includeRuntime) return { state: "not checked", label: "Not checked", detail: "Time health was not requested.", ntpEnabled: null, peer: "", raw: "", firewallEpoch: 0, logServerEpoch: 0, offsetMs: null, logServer: "" };
  if (!profile.timeScript) return { state: "not-supported", label: "Not supported", detail: "No approved time probe is available for this device family.", ntpEnabled: null, peer: "", raw: "", firewallEpoch: 0, logServerEpoch: 0, offsetMs: null, logServer: "" };
  return { state: "pending", label: "Checking", detail: "Time health is being collected.", ntpEnabled: null, peer: "", raw: "", firewallEpoch: 0, logServerEpoch: 0, offsetMs: null, logServer: "" };
}

function memberNames(cluster) {
  const members = references(cluster?.["cluster-members"]);
  return [...new Set(members.length ? members : references(cluster?.members))];
}

function normalizeRouteLine(value) {
  return text(value).replace(/\s+/g, " ").replace(/\s+$/g, "");
}

function routeLines(output) {
  return [...new Set(String(output || "").split(/\r?\n/).map(normalizeRouteLine).filter((line) => {
    if (!line || /^[-=]+$/.test(line)) return false;
    if (/^(?:flags?|destination|route|network|prefix|gateway|next[ -]?hop|protocol|type|code)\b/i.test(line)) return false;
    // Clearly member-local host/broadcast rows are intentionally excluded.
    // Everything else is compared verbatim after whitespace normalization so
    // protocol, metric, next-hop, and interface differences remain visible.
    if (/\b(?:local|broadcast)\b/i.test(line)) return false;
    return /\bdefault\b|\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/.test(line);
  }))].sort((left, right) => left.localeCompare(right));
}

function routeDiff(memberRoutes) {
  const entries = Object.entries(memberRoutes || {}).filter(([, routes]) => Array.isArray(routes));
  if (entries.length < 2) return { matched: false, onlyByMember: {}, counts: {}, baseline: "" };
  const [baselineMember, baselineRoutes] = entries[0];
  const baselineSet = new Set(baselineRoutes);
  const onlyByMember = {};
  const counts = {};
  for (const [member, routes] of entries) {
    const routeSet = new Set(routes);
    counts[member] = routeSet.size;
    const only = [...routeSet].filter((route) => !baselineSet.has(route));
    const missing = [...baselineSet].filter((route) => !routeSet.has(route));
    if (only.length || missing.length) onlyByMember[member] = { only, missing };
  }
  return { matched: Object.keys(onlyByMember).length === 0, onlyByMember, counts, baseline: baselineMember };
}

function initialRouteHealth(type, includeRuntime) {
  if (type !== "simple-cluster") return { state: "not-applicable", label: "Not a cluster", detail: "Route comparison applies only to ClusterXL objects.", members: [], memberRoutes: {}, counts: {}, differences: {} };
  if (!includeRuntime) return { state: "not checked", label: "Not checked", detail: "Cluster route health was not requested.", members: [], memberRoutes: {}, counts: {}, differences: {} };
  return { state: "pending", label: "Checking", detail: "Cluster-member routes are being collected.", members: [], memberRoutes: {}, counts: {}, differences: {} };
}

async function collectClusterRoutes({ sessions, sessionId, context, rows }) {
  for (const row of rows) {
    if (row.type !== "simple-cluster") continue;
    if (row.probe.id !== "gaia") {
      row.routes = { ...row.routes, state: "unavailable", label: "Unavailable", detail: "Gaia ClusterXL is required." };
      continue;
    }
    const members = row.clusterMembers || [];
    row.routes.members = members;
    if (!members.length) {
      row.routes = { ...row.routes, state: "unavailable", label: "Unavailable", detail: "No cluster members were returned by the Management object." };
      continue;
    }
    if (members.length < 2) {
      row.routes = { ...row.routes, state: "unavailable", label: "Unavailable", detail: "At least two cluster members are required for route comparison." };
      continue;
    }
    try {
      const runResult = await sessions.runScript(sessionId, {
        "script-name": "check-cluster-routes",
        script: GAIA_ROUTE_SCRIPT,
        targets: members
      }, context);
      const executions = executionsByTarget(runResult);
      const memberRoutes = {};
      const errors = [];
      for (const member of members) {
        const execution = executions.get(member);
        if (!execution) {
          errors.push(`${member}: no task result`);
          continue;
        }
        if (execution.error) {
          errors.push(`${member}: ${execution.error}`);
          continue;
        }
        const routes = routeLines(execution.output || execution.message || "");
        if (!routes.length) {
          errors.push(`${member}: no comparable IPv4 routes were returned`);
          continue;
        }
        memberRoutes[member] = routes;
      }
      if (errors.length || Object.keys(memberRoutes).length !== members.length) {
        row.routes = { ...row.routes, state: "unavailable", label: "Unavailable", detail: `Could not collect all member route tables: ${errors.join("; ")}`, memberRoutes, counts: Object.fromEntries(Object.entries(memberRoutes).map(([member, routes]) => [member, routes.length])) };
        continue;
      }
      const compared = routeDiff(memberRoutes);
      row.routes = {
        state: compared.matched ? "matched" : "mismatch",
        label: compared.matched ? "Matched" : "Mismatch",
        detail: compared.matched ? `${members.length} members returned the same ${Object.values(compared.counts)[0] || 0} normalized routes.` : "Member route tables differ. Expand for the exact routes.",
        members,
        memberRoutes,
        counts: compared.counts,
        differences: compared.onlyByMember,
        baseline: compared.baseline
      };
    } catch (error) {
      row.routes = { ...row.routes, state: "unavailable", label: "Unavailable", detail: `Cluster route probe could not run: ${error.message}` };
    }
  }
}

async function collectClusterMemberHealth({ sessions, sessionId, context, rows }) {
  const clusters = rows.filter(row => row.type === "simple-cluster" && row.probe.id === "gaia");
  const names = [...new Set(clusters.flatMap(row => row.clusterMembers))];
  if (!names.length) return;
  let executions = new Map();
  let error = "";
  try {
    executions = executionsByTarget(await sessions.runScript(sessionId, {
      "script-name": "check-cluster-member-health",
      script: GAIA_MEMBER_SCRIPT,
      targets: names
    }, context));
  } catch (failure) {
    error = failure.message;
  }
  for (const row of clusters) {
    row.memberHealth = row.clusterMembers.map(name => {
      const execution = executions.get(name);
      const failure = execution?.error || error || (!execution?.output ? "No member output was returned." : "");
      const sections = probeSections(execution?.output);
      const raw = sections.get("CLOCK") || "";
      const ntp = ntpFromOutput(raw);
      const stateEvidence = sections.get("CLUSTER_STATE") || "";
      const role = /^\s*\d+\s+\(local\)\s+\S+\s+\S+\s+(ACTIVE(?:\(!\))?|STANDBY|DOWN|READY|LOST|INIT)(?:\s|$)/im.exec(stateEvidence)?.[1] || "";
      return {
        name, role, stateEvidence,
        runtime: parseRuntime(sections.get("LOG_CONNECTION"), failure, row.remoteDestinations),
        time: evaluateTimeHealth({
          profile: DEVICE_PROFILES.gaia, firewallEpoch: epochFromOutput(raw),
          ntpEnabled: ntp.enabled, peer: ntp.peer, raw, error: failure
        })
      };
    });
  }
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

async function collectTimeHealth({ sessions, sessionId, context, rows, objects }) {
  const profileGroups = new Map();
  for (const row of rows) {
    const profile = DEVICE_PROFILES[row.probe?.id] || DEVICE_PROFILES.unknown;
    if (!profile.timeScript) continue;
    if (!profileGroups.has(profile.id)) profileGroups.set(profile.id, []);
    profileGroups.get(profile.id).push(row);
  }

  // Keep each platform family in its own Management task.  That avoids
  // sending a Gaia Clish command to an SMB appliance and mirrors the runtime
  // logging-probe safety boundary.
  for (const [profileId, targets] of profileGroups) {
    const profile = DEVICE_PROFILES[profileId];
    try {
      const runResult = await sessions.runScript(sessionId, {
        "script-name": `check-time-health-${profileId}`,
        script: profile.timeScript,
        targets: targets.map((row) => row.name)
      }, context);
      const executions = executionsByTarget(runResult);
      for (const row of targets) {
        const execution = executions.get(row.name);
        if (!execution) {
          row.time = evaluateTimeHealth({ profile, error: "No per-gateway time result was returned." });
          continue;
        }
        const raw = execution.output || execution.message || "";
        const ntp = profile.id === "gaia" ? ntpFromOutput(raw) : { enabled: null, peer: "", activeText: "" };
        row.time = evaluateTimeHealth({
          profile,
          firewallEpoch: epochFromOutput(raw),
          ntpEnabled: ntp.enabled,
          peer: ntp.peer,
          raw,
          error: execution.error || ""
        });
      }
    } catch (error) {
      for (const row of targets) row.time = evaluateTimeHealth({ profile, error: `Time probe could not run: ${error.message}` });
    }
  }

  // Compare only an actively connected firewall with a configured destination
  // present in the Management inventory.  The comparison is one fixed UTC
  // read-only command per unique log server; unresolved names never become
  // gateway-shell targets.
  const objectsByName = new Map(objects.map((object) => [text(object.name), object]).filter(([name]) => name));
  const rowsByLogServer = new Map();
  for (const row of rows) {
    const destination = row.runtime?.state === "connected" ? text(row.runtime.destination) : "";
    if (!destination || !objectsByName.has(destination) || !row.time?.firewallEpoch) continue;
    if (!rowsByLogServer.has(destination)) rowsByLogServer.set(destination, []);
    rowsByLogServer.get(destination).push(row);
  }
  if (!rowsByLogServer.size) return;
  try {
    const targets = [...rowsByLogServer.keys()];
    const runResult = await sessions.runScript(sessionId, {
      "script-name": "check-active-log-server-time",
      script: TIME_EPOCH_SCRIPT,
      targets
    }, context);
    const executions = executionsByTarget(runResult);
    for (const [logServer, relatedRows] of rowsByLogServer) {
      const execution = executions.get(logServer);
      const raw = execution?.output || execution?.message || "";
      const logServerEpoch = execution && !execution.error ? epochFromOutput(raw) : 0;
      for (const row of relatedRows) {
        const profile = DEVICE_PROFILES[row.probe?.id] || DEVICE_PROFILES.unknown;
        row.time = evaluateTimeHealth({
          profile,
          firewallEpoch: row.time.firewallEpoch,
          logServerEpoch,
          ntpEnabled: row.time.ntpEnabled,
          peer: row.time.peer,
          raw: row.time.raw,
          // A log-server clock probe is supporting evidence.  Its failure
          // must never erase a successful gateway NTP/UTC result.
          comparisonError: execution?.error || "",
          logServer
        });
      }
    }
  } catch (error) {
    // Firewall results remain useful when a log-server execution is not
    // permitted on a particular release.  Preserve the explicit comparison
    // gap instead of converting it into a guessed time result.
    for (const [logServer, relatedRows] of rowsByLogServer) {
      for (const row of relatedRows) {
        const profile = DEVICE_PROFILES[row.probe?.id] || DEVICE_PROFILES.unknown;
        const time = evaluateTimeHealth({
          profile,
          firewallEpoch: row.time.firewallEpoch,
          ntpEnabled: row.time.ntpEnabled,
          peer: row.time.peer,
          raw: row.time.raw,
          logServer
        });
        time.detail = `Active log-server time could not be read: ${error.message}`;
        row.time = time;
      }
    }
  }
}

/**
 * Collect gateway log configuration and, when requested, run one read-only
 * device-appropriate read-only command through the Management API's task
 * flow. No Management or gateway setting is changed by this workflow.
 */
export async function collectLoggingStatus({
  sessions, sessionId, context = "primary", includeRuntime = true, domain = "", managementDomain = domain,
  includeInfrastructure = false, freshnessHorizon = ""
}) {
  const startedAt = Date.now();
  const objects = await sessions.list(sessionId, "show-gateways-and-servers", {}, context);
  const inventoryCheckedAt = new Date().toISOString();
  const inventoryMs = Date.now() - startedAt;
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
        detail = { ...gateway, ...await sessions.command(sessionId, command, { uid: gateway.uid, "details-level": "full" }, context) };
      } catch (error) {
        configurationError = "Could not retrieve full logging configuration; using inventory data.";
      }
    }
    const profile = deviceProfile(detail);
    rows.push({
      domain: text(domain),
      name: text(gateway.name) || text(detail.name) || "Unnamed firewall",
      type: text(gateway.type) || text(detail.type) || "gateway",
      uid: text(gateway.uid),
      clusterMembers: memberNames(detail),
      deviceFamily: profile.family,
      probe: { id: profile.id, label: profile.label, command: profile.script },
      ...configuredStatus(detail),
      configurationError,
      runtime: { state: "not checked", detail: "Runtime probe was not requested.", raw: "", destination: "" },
      time: initialTimeHealth(profile, includeRuntime),
      routes: initialRouteHealth(text(gateway.type) || text(detail.type), includeRuntime)
    });
  }

  if (includeRuntime && rows.length) {
    const groups = new Map();
    for (const row of rows) {
      if (!row.probe.command) {
        row.runtime = { state: "unknown", detail: "No approved runtime probe is available for this device family. Configuration is still shown.", raw: "", destination: "" };
        continue;
      }
      if (!groups.has(row.probe.id)) groups.set(row.probe.id, []);
      groups.get(row.probe.id).push(row);
    }
    // Run one allowlisted command per device profile. Groups are serialized to
    // reduce pressure on mixed estates and avoid one platform's task failures
    // obscuring another's result.
    for (const [profileId, targets] of groups) {
      const profile = DEVICE_PROFILES[profileId];
      try {
        const runResult = await sessions.runScript(sessionId, {
          "script-name": `check-log-connection-${profileId}`,
          script: profile.script,
          targets: targets.map((row) => row.name)
        }, context);
        const executions = executionsByTarget(runResult);
        for (const row of targets) {
          const execution = executions.get(row.name);
          row.runtime = execution
            ? parseRuntime(execution.output || execution.message, execution.error, row.remoteDestinations, profile)
            : { state: "unknown", detail: "No per-gateway task result was returned.", raw: "", destination: "" };
        }
      } catch (error) {
        for (const row of targets) {
          row.runtime = { state: "unavailable", detail: `Runtime probe could not run: ${error.message}`, raw: "", destination: "" };
        }
      }
    }
    await collectTimeHealth({ sessions, sessionId, context, rows, objects });
    await collectClusterRoutes({ sessions, sessionId, context, rows });
    if (includeInfrastructure) await collectClusterMemberHealth({ sessions, sessionId, context, rows });
  }

  let infrastructure = {};
  if (includeInfrastructure) {
    const management = await collectManagementHealth({
      sessions, sessionId, context, domain: managementDomain, checkedAt: inventoryCheckedAt, inventoryMs
    });
    const logServerHealth = await collectLogServerHealth({
      sessions, sessionId, context, domain: managementDomain, rows, objects, includeRuntime, checkedAt: new Date().toISOString()
    });
    if (freshnessHorizon) {
      await collectIndexedFreshness({ sessions, sessionId, context, reports: logServerHealth, horizon: freshnessHorizon });
    }
    infrastructure = { management: [management], logServerHealth };
  }
  return {
    checkedAt: new Date().toISOString(),
    scanDurationMs: Date.now() - startedAt,
    runtimeCommand: includeRuntime ? "Device-aware logging and time probes" : "",
    count: rows.length,
    logServers: summarizeLogServers(rows),
    firewalls: rows,
    ...infrastructure
  };
}

export async function collectAllDomainLoggingStatus({
  sessions, sessionId, includeRuntime = true, includeInfrastructure = false, freshnessHorizon = ""
}) {
  const startedAt = Date.now();
  const root = sessions.describe(sessionId);
  if (!root.allDomains || !root.mdsMode) throw new Error("This session is not configured for an all-domain MDS scan.");
  const firewalls = [];
  const domainFailures = [];
  const management = [];
  const logServerHealth = [];
  const domains = includeInfrastructure && !freshnessHorizon ? await sessions.discoverDomains(sessionId) : root.domains;
  if (!domains.length) throw new Error("No active MDS domains were available to scan.");
  const managementEndpoint = { checkedAt: new Date().toISOString(), inventoryMs: Date.now() - startedAt };
  const systemHealth = includeInfrastructure && root.contexts?.["system-data"]?.available
    ? await collectManagementHealth({
      sessions, sessionId, context: "system-data", domain: "System Data", ...managementEndpoint
    }) : null;
  for (const domain of domains) {
    let childId = "";
    try {
      childId = await sessions.openDomainSession(sessionId, domain.name);
      const result = await collectLoggingStatus({
        sessions, sessionId: childId, includeRuntime, domain: domain.name, includeInfrastructure, freshnessHorizon
      });
      firewalls.push(...result.firewalls);
      if (includeInfrastructure) {
        management.push(...result.management);
        logServerHealth.push(...result.logServerHealth);
      }
    } catch (error) {
      domainFailures.push({ domain: domain.name, error: error.message });
    } finally {
      if (childId) await sessions.logout(childId).catch(() => {});
    }
  }
  if (systemHealth) management.push(systemHealth);
  return {
    checkedAt: new Date().toISOString(),
    scanDurationMs: Date.now() - startedAt,
    runtimeCommand: includeRuntime ? "Device-aware logging and time probes" : "",
    count: firewalls.length,
    domains,
    domainFailures,
    logServers: summarizeLogServers(firewalls),
    firewalls,
    ...(includeInfrastructure ? { management, logServerHealth, managementEndpoint } : {})
  };
}

export const loggingStatusInternals = { configuredStatus, deviceProfile, parseRuntime, references, runtimeDestination, summarizeLogServers, epochFromOutput, ntpFromOutput, evaluateTimeHealth, memberNames, routeLines, routeDiff, DEVICE_PROFILES };
